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

import gossip
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
    try:
        import fcntl  # POSIX-only; imported lazily so this module stays
                        # importable on platforms without it (e.g. Windows),
                        # for pure-logic testing — only actually calling this
                        # function requires a real POSIX host.
    except ImportError:
        print("  ERROR: process locking requires fcntl, which is not available "
              "on this platform. AetherNode's relay requires Linux, macOS, or WSL.",
              file=sys.stderr)
        sys.exit(1)

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


def _validate_publish_payload(payload: dict) -> str | None:
    """
    Shared shape/signature validation for a published message, used by both
    this relay's client-facing /publish handler and gossip.py's peer-facing
    /gossip/publish handler (passed to it by reference in main(), so
    gossip.py never has to import this module). Returns None if the payload
    passes, or an error string describing why it doesn't.
    """
    missing = REQUIRED_FIELDS - set(payload.keys())
    if missing:
        return f"Missing fields: {', '.join(sorted(missing))}"

    recipient_id = payload.get("recipient_id")
    if not isinstance(recipient_id, str) or not (0 < len(recipient_id) <= _MAX_RECIPIENT_ID_LEN):
        return "Invalid 'recipient_id'"

    if not verify_signature(payload):
        return "Signature verification failed — message rejected"

    return None


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

        error = _validate_publish_payload(payload)
        if error:
            self._send_json(400, {"error": error})
            return

        received_at = datetime.now(timezone.utc).isoformat()
        is_new, row_id = gossip.insert_message_and_maybe_gossip(
            self.server.db, DB_LOCK, payload, payload["recipient_id"], received_at, self.server.gossip_ctx,
        )
        if is_new:
            self._send_json(200, {"status": "ok", "id": row_id})
        else:
            # Same signature already stored — a replayed or re-submitted message.
            self._send_json(409, {"error": "Message already published (duplicate signature)"})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()


# ─── Threaded HTTP Server (Unix Domain Socket) ────────────────────────────────

# socket.AF_UNIX doesn't exist on native Windows. Referencing socket.AF_UNIX
# directly in the class body below would raise AttributeError at class
# *definition* time, making this whole module (and anything that imports it,
# including gossip.py-free pure-logic testing) unimportable on a platform
# that merely lacks Unix sockets. getattr() keeps the module importable
# everywhere; instantiating the class is what raises a clear, actionable
# error on unsupported platforms — see __init__ below.
_AF_UNIX = getattr(socket, "AF_UNIX", None)


class RelayUnixHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """
    One thread per connection, bound to a Unix domain socket instead of a
    TCP/IP socket — the relay has no public network presence at all.
    """
    address_family = _AF_UNIX if _AF_UNIX is not None else socket.AF_INET  # never actually used; see __init__
    daemon_threads  = True

    def __init__(self, server_address, RequestHandlerClass):
        if _AF_UNIX is None:
            raise OSError(
                "AF_UNIX sockets are not available on this platform. "
                "AetherNode's relay requires Linux, macOS, or WSL."
            )
        super().__init__(server_address, RequestHandlerClass)

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
    parser.add_argument("--relay-identity-dir", default="./aether-relay-identity",
                        help="Directory holding this relay's own X.509 gossip identity "
                             "(relay_key.pem / relay_cert.pem), distinct from any end-user "
                             "identity. Auto-generated on first launch "
                             "(default: ./aether-relay-identity).")
    parser.add_argument("--gossip-socket-path", default="./aether-relay-gossip.sock",
                        help="Unix domain socket for the mTLS gossip listener (default: "
                             "./aether-relay-gossip.sock). Point a SECOND torrc "
                             "'HiddenServicePort <port> unix:<this path>' at it.")
    parser.add_argument("--peers-file", default="./peers.json",
                        help="Trusted-peer list for gossip (default: ./peers.json). A missing "
                             "file is valid and means zero peers — the relay still runs, it "
                             "just doesn't gossip to or accept forwards from anyone yet.")
    parser.add_argument("--blacklist-file", default="./blacklist.json",
                        help="Blacklisted peer fingerprints, hot-reloaded on every gossip "
                             "connection (default: ./blacklist.json).")
    parser.add_argument("--gossip-anti-entropy-interval", type=int,
                        default=gossip.DEFAULT_ANTI_ENTROPY_INTERVAL,
                        help="Seconds between anti-entropy reconciliation passes with each "
                             f"peer (default: {gossip.DEFAULT_ANTI_ENTROPY_INTERVAL}).")
    parser.add_argument("--gossip-transport", choices=["tor", "direct"], default="tor",
                        help="Transport used for OUTBOUND gossip (default: tor). 'direct' opens "
                             "same-host Unix sockets to peers with NO Tor/SOCKS5 involved, and "
                             "exists ONLY for same-host simulation/testing (see "
                             "simulate_partition.py) — using it against a real remote peer "
                             "defeats AetherNode's no-public-IP guarantee. Requires "
                             f"${gossip.DIRECT_TRANSPORT_ENV_VAR}=1 to also be set, or the "
                             "relay refuses to start.")
    args = parser.parse_args()

    direct_transport_unlocked = args.gossip_transport == "direct"
    if direct_transport_unlocked and os.environ.get(gossip.DIRECT_TRANSPORT_ENV_VAR) != "1":
        print(f"  ERROR: --gossip-transport direct requires ${gossip.DIRECT_TRANSPORT_ENV_VAR}=1 "
              f"to be set explicitly. This bypasses Tor entirely for gossip and must NEVER be "
              f"used outside same-host testing — see README § Federation.", file=sys.stderr)
        sys.exit(1)

    db = init_db(args.db)

    # Held for the lifetime of the process — guarantees only one relay
    # instance can ever bind/unlink each socket path at a time.
    _lock = _acquire_relay_lock(args.socket_path)
    _prepare_socket_path(args.socket_path)
    _gossip_lock = _acquire_relay_lock(args.gossip_socket_path)
    _prepare_socket_path(args.gossip_socket_path)

    relay_identity_dir = Path(args.relay_identity_dir)
    own_key_path, own_cert_path = gossip.load_or_generate_relay_identity(relay_identity_dir)
    own_fingerprint = gossip.relay_fingerprint(gossip.load_cert(own_cert_path))

    trust_store = gossip.TrustStore(Path(args.peers_file), Path(args.blacklist_file))
    gossip_ctx = gossip.GossipContext(
        own_cert_path=own_cert_path,
        own_key_path=own_key_path,
        trust_store=trust_store,
        direct_transport_unlocked=direct_transport_unlocked,
    )
    anti_entropy = gossip.AntiEntropySync(
        db=db, db_lock=DB_LOCK, trust_store=trust_store,
        validate_publish=_validate_publish_payload, gossip_ctx=gossip_ctx,
        own_cert_path=own_cert_path, own_key_path=own_key_path,
        direct_transport_unlocked=direct_transport_unlocked,
        interval_s=args.gossip_anti_entropy_interval,
    )

    server = gossip_server = gossip_thread = None
    try:
        server = RelayUnixHTTPServer(args.socket_path, RelayHandler)
        os.chmod(args.socket_path, 0o660)  # local-only; group access needed by the Tor process — see README
        server.db = db
        server.gossip_ctx = gossip_ctx

        server_ssl_ctx = gossip.build_server_ssl_context(own_cert_path, own_key_path, trust_store)
        gossip_server = gossip.GossipUnixTLSServer(
            args.gossip_socket_path, gossip.GossipHandler, server_ssl_ctx, trust_store,
        )
        os.chmod(args.gossip_socket_path, 0o660)
        gossip_server.db = db
        gossip_server.db_lock = DB_LOCK
        gossip_server.gossip_ctx = gossip_ctx
        gossip_server.validate_publish = _validate_publish_payload
        gossip_server.max_body_bytes = _MAX_BODY_BYTES

        gossip_thread = threading.Thread(target=gossip_server.serve_forever, daemon=True, name="gossip-listener")
        gossip_thread.start()
        anti_entropy.start()

        peer_count = len(trust_store.active_peers())
        print("  ╔══════════════════════════════════════╗")
        print("  ║       AetherNode Relay  v1.0         ║")
        print("  ╚══════════════════════════════════════╝")
        print(f"  Listening         : unix:{args.socket_path}")
        print(f"  Gossip            : unix:{args.gossip_socket_path}  ({args.gossip_transport} transport)")
        print(f"  Relay fingerprint : {own_fingerprint}")
        print(f"  Trusted peers     : {peer_count}")
        print(f"  Storage           : {args.db}")
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
        try:
            anti_entropy.stop()
        except Exception:
            pass
        try:
            gossip_ctx.shutdown()
        except Exception:
            pass
        if gossip_server is not None:
            try:
                gossip_server.shutdown()
            except Exception:
                pass
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
        try:
            os.unlink(args.gossip_socket_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
