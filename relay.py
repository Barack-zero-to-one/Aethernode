"""
AetherNode Relay — Zero-Knowledge Decentralized Message Relay

The relay is a dumb bulletin board. It stores encrypted, signed blobs and
returns them on request. It cannot decrypt messages and cannot forge signatures —
any tampered payload is rejected by the client's verification step.

Architecture:
  ThreadingHTTPServer (stdlib)  — concurrent request handling
  SQLite (stdlib)               — persistent message storage
  cryptography lib              — RSA-PSS signature verification (anti-spam)
"""

import http.server
import socketserver
import sqlite3
import json
import base64
import threading
import argparse
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# Maximum bytes accepted from a single POST body — guards against memory exhaustion
_MAX_BODY_BYTES: int = 64 * 1024  # 64 KB; far exceeds any valid AetherNode message

# ─── Required fields every published message must carry ──────────────────────
REQUIRED_FIELDS = {
    "version", "sender_pubkey", "recipient_pubkey",
    "encrypted_key", "nonce", "ciphertext", "timestamp", "signature"
}

# Serialize all SQLite access through one lock (connection is not thread-safe)
DB_LOCK = threading.Lock()


# ─── Database ─────────────────────────────────────────────────────────────────

def init_db(path: str) -> sqlite3.Connection:
    """Initialize SQLite schema. Pass ':memory:' for an ephemeral relay."""
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_pubkey TEXT NOT NULL,
            sender_pubkey    TEXT NOT NULL,
            payload          TEXT NOT NULL,
            received_at      TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient_pubkey)"
    )
    conn.commit()
    return conn


# ─── Signature Verification ───────────────────────────────────────────────────

def verify_signature(payload: dict) -> bool:
    """
    Verify the RSA-PSS signature embedded in the payload.

    This is zero-knowledge: we only check that the signature is valid for the
    embedded public key. We never attempt decryption and learn nothing about
    message content. Used as an anti-spam gate on /publish.
    """
    try:
        signature  = base64.b64decode(payload["signature"])
        pub_der    = base64.b64decode(payload["sender_pubkey"])
        public_key = serialization.load_der_public_key(pub_der)

        # Canonical form: all fields except 'signature', sorted keys, no spaces
        canonical      = {k: v for k, v in payload.items() if k != "signature"}
        canonical_bytes = json.dumps(
            canonical, sort_keys=True, separators=(',', ':')
        ).encode()

        public_key.verify(
            signature,
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, Exception):
        return False


# ─── HTTP Request Handler ─────────────────────────────────────────────────────

class RelayHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"  [{ts}] {fmt % args}", file=sys.stderr)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _send_json(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self, content_length: int) -> bytes | None:
        if content_length == 0:
            return None
        return self.rfile.read(content_length)

    # ── GET ───────────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send_json(200, {"status": "alive", "node": "AetherNode/1.0"})
            return

        if parsed.path == "/fetch":
            params    = parse_qs(parsed.query)
            pubkey_list = params.get("pubkey", [])
            if not pubkey_list:
                self._send_json(400, {"error": "Missing 'pubkey' query parameter"})
                return

            pubkey = pubkey_list[0]
            with DB_LOCK:
                rows = self.server.db.execute(
                    "SELECT payload FROM messages "
                    "WHERE recipient_pubkey = ? ORDER BY id ASC",
                    (pubkey,)
                ).fetchall()

            messages = [json.loads(row[0]) for row in rows]
            self._send_json(200, {"messages": messages, "count": len(messages)})
            return

        self._send_json(404, {"error": "Not found"})

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self):
        if self.path != "/publish":
            self._send_json(404, {"error": "Not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            content_length = 0
        if content_length > _MAX_BODY_BYTES:
            self._send_json(413, {"error": f"Request body exceeds {_MAX_BODY_BYTES} bytes"})
            return

        raw = self._read_body(content_length)
        if not raw:
            self._send_json(400, {"error": "Empty request body"})
            return

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": f"Invalid JSON: {exc}"})
            return

        missing = REQUIRED_FIELDS - set(payload.keys())
        if missing:
            self._send_json(400, {"error": f"Missing fields: {', '.join(sorted(missing))}"})
            return

        # Anti-spam gate: reject structurally invalid / forged submissions
        if not verify_signature(payload):
            self._send_json(400, {"error": "Signature verification failed — message rejected"})
            return

        received_at = datetime.now(timezone.utc).isoformat()
        with DB_LOCK:
            cur = self.server.db.execute(
                "INSERT INTO messages "
                "(recipient_pubkey, sender_pubkey, payload, received_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    payload["recipient_pubkey"],
                    payload["sender_pubkey"],
                    json.dumps(payload),
                    received_at,
                )
            )
            self.server.db.commit()

        self._send_json(200, {"status": "ok", "id": cur.lastrowid})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()


# ─── Threaded HTTP Server ─────────────────────────────────────────────────────

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """One thread per connection — keeps the relay responsive under load."""
    daemon_threads = True


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AetherNode Relay — Zero-Knowledge Decentralized Message Relay"
    )
    parser.add_argument("--port", type=int, default=8888,
                        help="Port to listen on (default: 8888)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Interface to bind to (default: 0.0.0.0)")
    parser.add_argument("--db", default="aether.db",
                        help="SQLite database path; use ':memory:' for ephemeral (default: aether.db)")
    args = parser.parse_args()

    db = init_db(args.db)

    server = ThreadingHTTPServer((args.host, args.port), RelayHandler)
    server.db = db

    print("  ╔══════════════════════════════════════╗")
    print("  ║       AetherNode Relay  v1.0         ║")
    print("  ╚══════════════════════════════════════╝")
    print(f"  Listening   : http://{args.host}:{args.port}")
    print(f"  Storage     : {args.db}")
    print(f"  Zero-Knowledge: relay cannot decrypt stored payloads")
    print(f"  Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Relay stopped cleanly.")
    finally:
        server.shutdown()
        db.close()


if __name__ == "__main__":
    main()
