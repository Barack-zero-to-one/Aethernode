"""
AetherNode Relay — Zero-Knowledge Decentralized Message Relay

The relay is a dumb bulletin board. It stores encrypted, signed blobs and
returns them on request. It cannot decrypt messages and cannot forge signatures —
any tampered payload is rejected by the client's verification step.

The relay has no public network presence: it binds a Unix domain socket only.
Tor (configured manually via torrc — see README § Deployment) forwards a v3
onion service's HiddenServicePort directly to that socket file.

Architecture:
  RelayUnixHTTPServer (stdlib)  — concurrent request handling over AF_UNIX
  SQLite (stdlib)               — persistent message storage
  cryptography lib              — RSA-PSS signature verification (anti-spam)
"""

import argparse
import base64
import fcntl
import http.server
import json
import os
import socket
import socketserver
import sqlite3
import stat
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from protocol import MAX_PUBLISH_BODY_BYTES

# Maximum bytes accepted from a single POST body — guards against memory
# exhaustion. Derived from protocol.MAX_PUBLISH_BODY_BYTES (the worst-case
# payload size for client.py's largest padding bucket) with roughly 50%
# headroom, so this cap can never silently fall out of sync with the
# client's padding scheme the way a hand-copied constant could.
_MAX_BODY_BYTES: int = MAX_PUBLISH_BODY_BYTES + MAX_PUBLISH_BODY_BYTES // 2

# ─── Required fields every published message must carry ──────────────────────
REQUIRED_FIELDS = {
    "version", "sender_pubkey", "recipient_id",
    "encrypted_key", "nonce", "ciphertext", "timestamp", "signature"
}

# recipient_id is a SHA-256 hex digest (64 chars); cap generously above that to
# reject junk without hardcoding a specific hash algorithm into the relay.
_MAX_RECIPIENT_ID_LEN = 128

# Serialize all SQLite access through one lock (connection is not thread-safe)
DB_LOCK = threading.Lock()


# ─── Unix Socket Path ─────────────────────────────────────────────────────────

def _acquire_relay_lock(socket_path: str):
    """
    Hold an exclusive advisory lock (flock) on "<socket_path>.lock" for the
    lifetime of this process, so a second relay instance accidentally started
    against the same socket path refuses to start instead of silently
    stealing or deleting the first instance's live socket. The OS releases
    the lock automatically if this process dies or is killed, so — unlike a
    plain PID file — the lock can never go stale and never needs cleanup.

    The caller must keep the returned file object alive for as long as the
    relay is running; closing it (including via process exit) releases the
    lock.
    """
    lock_path = f"{socket_path}.lock"
    lock_file = open(lock_path, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print(f"  ERROR: another relay instance is already running on {socket_path}", file=sys.stderr)
        print(f"  (held by whichever process holds a lock on {lock_path})", file=sys.stderr)
        sys.exit(1)
    lock_file.write(str(os.getpid()))
    lock_file.flush()
    return lock_file


def _prepare_socket_path(path: str) -> None:
    """
    Remove a stale socket file left behind by a crashed/killed relay process —
    bind() fails with "address already in use" otherwise — while refusing to
    touch anything that isn't actually a socket. Must only be called after
    _acquire_relay_lock() has succeeded, so the file being inspected here is
    guaranteed to belong to a dead process rather than a live one.
    """
    p = Path(path)
    if p.exists():
        if not stat.S_ISSOCK(p.stat().st_mode):
            print(f"  ERROR: {p} already exists and is not a Unix socket.", file=sys.stderr)
            print(f"  Refusing to delete it automatically — remove or rename it, then restart.", file=sys.stderr)
            sys.exit(1)
        try:
            p.unlink()
        except OSError as exc:
            print(f"  ERROR: could not remove stale socket {p}: {exc}", file=sys.stderr)
            print(f"  Check its ownership/permissions, then restart.", file=sys.stderr)
            sys.exit(1)
    p.parent.mkdir(parents=True, exist_ok=True)


# ─── Database ─────────────────────────────────────────────────────────────────

def init_db(path: str) -> sqlite3.Connection:
    """Initialize SQLite schema. Pass ':memory:' for an ephemeral relay."""
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id TEXT NOT NULL,
            sender_pubkey TEXT NOT NULL,
            signature    TEXT NOT NULL UNIQUE,
            payload      TEXT NOT NULL,
            received_at  TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient_id)"
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
    except Exception:
        return False


# ─── HTTP Request Handler ─────────────────────────────────────────────────────

class RelayHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"  [{ts}] {fmt % args}", file=sys.stderr)

    def address_string(self):
        # AF_UNIX client_address is '' — the default implementation
        # (self.client_address[0]) would raise IndexError on that.
        return "unix-socket"

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
            params = parse_qs(parsed.query)
            id_list = params.get("id", [])
            if not id_list:
                self._send_json(400, {"error": "Missing 'id' query parameter"})
                return

            recipient_id = id_list[0]
            with DB_LOCK:
                rows = self.server.db.execute(
                    "SELECT payload FROM messages "
                    "WHERE recipient_id = ? ORDER BY id ASC",
                    (recipient_id,)
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

        recipient_id = payload["recipient_id"]
        if not isinstance(recipient_id, str) or not (0 < len(recipient_id) <= _MAX_RECIPIENT_ID_LEN):
            self._send_json(400, {"error": "Invalid 'recipient_id'"})
            return

        # Anti-spam gate: reject structurally invalid / forged submissions
        if not verify_signature(payload):
            self._send_json(400, {"error": "Signature verification failed — message rejected"})
            return

        received_at = datetime.now(timezone.utc).isoformat()
        try:
            with DB_LOCK:
                cur = self.server.db.execute(
                    "INSERT INTO messages "
                    "(recipient_id, sender_pubkey, signature, payload, received_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        recipient_id,
                        payload["sender_pubkey"],
                        payload["signature"],
                        json.dumps(payload),
                        received_at,
                    )
                )
                self.server.db.commit()
        except sqlite3.IntegrityError:
            # Same signature already stored — a replayed or re-submitted message.
            self._send_json(409, {"error": "Message already published (duplicate signature)"})
            return

        self._send_json(200, {"status": "ok", "id": cur.lastrowid})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()


# ─── Threaded HTTP Server (Unix Domain Socket) ────────────────────────────────

class RelayUnixHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """
    One thread per connection, bound to a Unix domain socket instead of a
    TCP/IP socket — the relay has no public network presence at all.
    """
    address_family = socket.AF_UNIX
    daemon_threads  = True

    def server_bind(self):
        # HTTPServer.server_bind() assumes server_address is an (host, port)
        # tuple — it calls socket.getfqdn(host) to set self.server_name. For
        # AF_UNIX, server_address is a filesystem path string, so that logic
        # is meaningless; skip straight to TCPServer's plain bind.
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address)  # cosmetic only, unused for routing
        self.server_port = 0


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AetherNode Relay — Zero-Knowledge Decentralized Message Relay"
    )
    parser.add_argument("--socket-path", default="./aether-relay.sock",
                        help="Unix domain socket path to bind (default: ./aether-relay.sock). "
                             "Point Tor's 'HiddenServicePort 80 unix:<this path>' at it.")
    parser.add_argument("--db", default="aether.db",
                        help="SQLite database path; use ':memory:' for ephemeral (default: aether.db)")
    args = parser.parse_args()

    db = init_db(args.db)

    # Held for the lifetime of the process — guarantees only one relay
    # instance can ever bind/unlink this socket path at a time.
    _lock = _acquire_relay_lock(args.socket_path)

    _prepare_socket_path(args.socket_path)

    server = None
    try:
        server = RelayUnixHTTPServer(args.socket_path, RelayHandler)
        os.chmod(args.socket_path, 0o660)  # local-only; group access needed by the Tor process — see README
        server.db = db

        print("  ╔══════════════════════════════════════╗")
        print("  ║       AetherNode Relay  v1.0         ║")
        print("  ╚══════════════════════════════════════╝")
        print(f"  Listening   : unix:{args.socket_path}")
        print(f"  Storage     : {args.db}")
        print(f"  Zero-Knowledge: relay cannot decrypt stored payloads")
        print(f"  No public network interface — reachable only via a Tor onion service.")
        print(f"  Press Ctrl+C to stop.\n")

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  Relay stopped cleanly.")
    finally:
        # Each cleanup step is independently guarded so a failure in one
        # (e.g. a handler thread still touching `db` when close() runs, since
        # daemon_threads=True means in-flight threads are never joined first)
        # can never prevent the others from running.
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
        try:
            db.close()
        except Exception:
            pass
        try:
            os.unlink(args.socket_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
