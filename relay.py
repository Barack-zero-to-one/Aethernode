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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import gossip
import ratelimit
from protocol import MAX_PUBLISH_BODY_BYTES

# Maximum bytes accepted from a single POST body — guards against memory
# exhaustion. Derived from protocol.MAX_PUBLISH_BODY_BYTES (the worst-case
# payload size for client.py's largest padding bucket) with roughly 50%
# headroom, so this cap can never silently fall out of sync with the
# client's padding scheme the way a hand-copied constant could.
_MAX_BODY_BYTES: int = MAX_PUBLISH_BODY_BYTES + MAX_PUBLISH_BODY_BYTES // 2

# ─── Required fields every published message must carry ──────────────────────
REQUIRED_FIELDS = {
    "version", "sender_pubkey", "recipient_id", "expires_at",
    "encrypted_key", "nonce", "ciphertext", "timestamp", "signature"
}

# ─── Required fields every delete request must carry ──────────────────────────
DELETE_REQUIRED_FIELDS = {
    "version", "action", "target_signature", "recipient_pubkey", "timestamp", "signature"
}

# recipient_id is a SHA-256 hex digest (64 chars); cap generously above that to
# reject junk without hardcoding a specific hash algorithm into the relay.
_MAX_RECIPIENT_ID_LEN = 128

# target_signature is a base64-encoded RSA-2048 PSS signature (~344 chars);
# cap generously above that to reject junk cheaply.
_MAX_SIGNATURE_LEN = 512

# TTL bounds enforced in _validate_publish_payload. Set once in main() from
# CLI flags before any request-serving thread starts — read-only thereafter,
# so no lock is needed around these module globals (mirrors _MAX_BODY_BYTES'
# already-established "fixed for the process lifetime" pattern, just made
# CLI-configurable instead of a hardcoded constant).
DEFAULT_MIN_TTL_SECONDS = 60
DEFAULT_MAX_TTL_SECONDS = 30 * 24 * 3600
_MIN_TTL_SECONDS = DEFAULT_MIN_TTL_SECONDS
_MAX_TTL_SECONDS = DEFAULT_MAX_TTL_SECONDS

# A rotating-id fetch legitimately needs one id per day within the relay's
# retention window (plus a small clock-skew buffer) -- a FIXED cap here
# would silently break every /fetch once an operator sets --max-ttl above
# whatever that fixed number covers (--max-ttl has no upper bound in
# argparse). Instead this is computed in main() from the same formula
# client.py's/gossip.py's _candidate_recipient_ids use
# (ceil(max_ttl_seconds/86400) + 1-day buffer + 1 for today), so it can
# never fall out of sync with the actual lookback window regardless of how
# --max-ttl is configured. Read-only after main() sets it; a conservative
# default here only matters for pure-logic testing that never calls main().
_MAX_FETCH_IDS = -(-DEFAULT_MAX_TTL_SECONDS // 86400) + 2

DEFAULT_CLEANUP_INTERVAL_SECONDS = 5 * 60
DEFAULT_RECIPIENT_QUOTA_MAX_MESSAGES = 1000
DEFAULT_RECIPIENT_QUOTA_MAX_BYTES = 50 * 1024 * 1024

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
    """
    Initialize SQLite schema. Pass ':memory:' for an ephemeral relay.

    Three PRAGMAs, two independent justifications that must not be conflated:
    secure_delete + journal_mode=TRUNCATE serve the FORENSIC goal (deleted
    content is overwritten in the main file, and the rollback journal that
    would otherwise hold a recoverable pre-image is truncated to zero length
    at commit instead of merely unlinked) — this project is a single-writer,
    fully DB_LOCK-serialized relay, so WAL mode's concurrent-reader benefit is
    moot and TRUNCATE is the right choice, not a compromise. auto_vacuum=
    INCREMENTAL serves the separate DISK-RECLAIM goal (the file actually
    shrinks as the periodic cleanup job frees pages) and has nothing to do
    with forensic recoverability. Honest limitation: this protects against
    ordinary on-disk-file examination, not SSD wear-leveling/block remapping,
    OS filesystem journaling, swap, snapshot-style backups, or raw
    block-device access catching an in-flight transaction.
    """
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode = TRUNCATE")
    conn.execute("PRAGMA secure_delete = ON")
    conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id TEXT NOT NULL,
            sender_pubkey TEXT NOT NULL,
            signature    TEXT NOT NULL UNIQUE,
            payload      TEXT NOT NULL,
            expires_at   TEXT NOT NULL,
            received_at  TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recipient_expires ON messages(recipient_id, expires_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_expires_at ON messages(expires_at)"
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS deletion_requests (
            target_signature       TEXT PRIMARY KEY,
            requester_pubkey       TEXT NOT NULL,
            requester_recipient_id TEXT NOT NULL,
            confirmed               INTEGER NOT NULL,
            requested_at            TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_deletion_requested_at ON deletion_requests(requested_at)"
    )
    conn.commit()
    return conn


# ─── Signature Verification ───────────────────────────────────────────────────

def verify_signature(payload: dict, pubkey_field: str = "sender_pubkey") -> bool:
    """
    Verify the RSA-PSS signature embedded in the payload.

    This is zero-knowledge: we only check that the signature is valid for the
    embedded public key. We never attempt decryption and learn nothing about
    message content. Used as an anti-spam gate on /publish, and (with
    pubkey_field="recipient_pubkey") on /delete — the field name differs
    because a delete request is signed by the recipient proving ownership of
    an address, not by a sender proving authorship of a message.
    """
    try:
        signature  = base64.b64decode(payload["signature"])
        pub_der    = base64.b64decode(payload[pubkey_field])
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

    expires_at_raw = payload.get("expires_at")
    if not isinstance(expires_at_raw, str):
        return "Invalid 'expires_at'"
    try:
        expires_at = datetime.fromisoformat(expires_at_raw)
    except ValueError:
        return "Invalid 'expires_at': not a valid ISO8601 timestamp"
    if expires_at.tzinfo is None:
        return "Invalid 'expires_at': must be timezone-aware"
    if expires_at.utcoffset() != timedelta(0):
        # The stored expires_at column is later compared via plain SQL
        # string ordering against a UTC isoformat() "now" (see /fetch's
        # query and _CleanupJob) — ISO8601 string comparison is only
        # guaranteed monotonic when every compared string uses the same,
        # zero, UTC offset. A non-UTC offset (e.g. "+05:00") can parse to a
        # valid, in-bounds instant here while sorting incorrectly against a
        # UTC "now" string later, letting a message silently outlive its
        # real expiry by up to the offset's magnitude.
        return "Invalid 'expires_at': must use a UTC offset ('+00:00' or 'Z')"

    now = datetime.now(timezone.utc)
    if expires_at < now + timedelta(seconds=_MIN_TTL_SECONDS):
        return f"'expires_at' must be at least {_MIN_TTL_SECONDS}s in the future"
    if expires_at > now + timedelta(seconds=_MAX_TTL_SECONDS):
        return f"'expires_at' must not exceed {_MAX_TTL_SECONDS}s in the future"

    if not verify_signature(payload):
        return "Signature verification failed — message rejected"

    return None


def _validate_delete_payload(payload: dict) -> str | None:
    """
    Shared shape/signature validation for a delete request, mirroring
    _validate_publish_payload's role: used by both this relay's client-facing
    /delete handler and gossip.py's peer-facing /gossip/delete handler.
    Returns None if the payload passes, or an error string describing why it
    doesn't. Does NOT perform the authorization check (does the requester
    actually own the target message) — that requires a database lookup and
    lives in gossip.handle_delete_request instead.
    """
    missing = DELETE_REQUIRED_FIELDS - set(payload.keys())
    if missing:
        return f"Missing fields: {', '.join(sorted(missing))}"

    if payload.get("action") != "delete":
        return "Invalid 'action'"

    target_signature = payload.get("target_signature")
    if not isinstance(target_signature, str) or not (0 < len(target_signature) <= _MAX_SIGNATURE_LEN):
        return "Invalid 'target_signature'"

    if not verify_signature(payload, pubkey_field="recipient_pubkey"):
        return "Signature verification failed — delete request rejected"

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
            self._send_json(200, {
                "status": "alive", "node": "AetherNode/1.0",
                "min_ttl_seconds": _MIN_TTL_SECONDS, "max_ttl_seconds": _MAX_TTL_SECONDS,
            })
            return

        self._send_json(404, {"error": "Not found"})

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self):
        if self.path == "/publish":
            self._do_publish()
        elif self.path == "/fetch":
            self._do_fetch()
        elif self.path == "/delete":
            self._do_delete()
        else:
            self._send_json(404, {"error": "Not found"})

    def _do_publish(self):
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

        # Cheap, indexed short-circuit: skip signature verification and
        # rate-limit budget entirely for a message that was always going
        # to be rejected by insert_message_and_maybe_gossip's own
        # UNIQUE-constraint dedup anyway (a re-submitted or replayed publish).
        signature = payload.get("signature")
        if isinstance(signature, str) and gossip.message_exists(self.server.db, DB_LOCK, signature):
            self._send_json(409, {"error": "Message already published (duplicate signature)"})
            return

        # Global check next, before ANY database work — an identity-
        # independent flood of garbage is rejected at the cheapest possible
        # point (pure in-memory token-bucket arithmetic, no DB_LOCK
        # acquisition at all). This must run before the quota check below:
        # unlike message_exists (which only ever helps with an EXACT
        # duplicate resubmission), a distinct-signature flood can hit
        # check_recipient_quota at whatever rate an attacker chooses, so
        # placing it before this cheap, lock-free gate would let a quota-
        # exhausted-recipient flood force unlimited DB_LOCK-serialized
        # queries with no throttling at all.
        if not self.server.client_publish_limiter.check_global():
            self._send_json(429, {"error": "rate limit exceeded"})
            return

        # Per-recipient storage quota — cheap (indexed COUNT/SUM queries)
        # relative to the signature verification below, and, like
        # message_exists above, uses the raw, not-yet-verified recipient_id:
        # the relay never verifies ownership of a recipient_id regardless of
        # validation status, so checking it this early introduces no new
        # spoofing concern. This is a non-atomic pre-filter only — the
        # authoritative, race-free check happens inside
        # insert_message_and_maybe_gossip, atomically with the insert.
        recipient_id_raw = payload.get("recipient_id")
        if isinstance(recipient_id_raw, str) and not gossip.check_recipient_quota(
            self.server.db, DB_LOCK, recipient_id_raw,
            self.server.recipient_quota_max_messages, self.server.recipient_quota_max_bytes,
        ):
            self._send_json(429, {"error": "recipient storage quota exceeded"})
            return

        error = _validate_publish_payload(payload)
        if error:
            self._send_json(400, {"error": error})
            return

        if not self.server.client_publish_limiter.check_identity(payload["sender_pubkey"]):
            self.server.client_publish_limiter.refund_global()
            self._send_json(429, {"error": "rate limit exceeded"})
            return

        # Last gate before insert, now that the signature (and therefore
        # recipient_id) is verified genuine: was this exact signature
        # already the target of a confirmed or pending delete? See
        # gossip.resolve_deletion_request for why this must run AFTER
        # signature verification, not before.
        if gossip.resolve_deletion_request(self.server.db, DB_LOCK, payload["signature"], payload["recipient_id"], _MAX_TTL_SECONDS):
            self._send_json(200, {"status": "discarded", "reason": "message was the target of a prior deletion request"})
            return

        received_at = datetime.now(timezone.utc).isoformat()
        is_new, row_id, quota_exceeded = gossip.insert_message_and_maybe_gossip(
            self.server.db, DB_LOCK, payload, payload["recipient_id"], received_at, self.server.gossip_ctx,
            self.server.recipient_quota_max_messages, self.server.recipient_quota_max_bytes,
        )
        if quota_exceeded:
            # Lost a last-moment race against the earlier, non-atomic
            # pre-filter — this authoritative recheck is what actually
            # enforces the cap; see insert_message_and_maybe_gossip.
            self._send_json(429, {"error": "recipient storage quota exceeded"})
        elif is_new:
            self._send_json(200, {"status": "ok", "id": row_id})
        else:
            # Same signature already stored — a replayed or re-submitted message.
            self._send_json(409, {"error": "Message already published (duplicate signature)"})

    def _do_fetch(self):
        """
        POST, not GET-with-query-string: a rotating recipient_id means a
        client must ask for up to ~30 candidate day-buckets at once (see
        client.py's _candidate_recipient_ids), and BaseHTTPRequestHandler's
        inherited log_request() logs the full request line — including any
        query string — through RelayHandler's own log_message override. A
        GET with 30 ids in the query string would hand anyone with log
        access the complete linkage across all of them in one line, which
        is a WORSE leak than the static id it replaces. Request bodies are
        never included in the logged request line, so POST closes this.
        """
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

        ids = payload.get("ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            self._send_json(400, {"error": "'ids' must be a non-empty list of strings"})
            return
        if len(ids) > _MAX_FETCH_IDS:
            self._send_json(400, {"error": f"'ids' exceeds {_MAX_FETCH_IDS} entries"})
            return
        if any(not (0 < len(i) <= _MAX_RECIPIENT_ID_LEN) for i in ids):
            self._send_json(400, {"error": "one or more 'ids' entries has an invalid length"})
            return

        now = datetime.now(timezone.utc).isoformat()
        placeholders = ",".join("?" * len(ids))
        with DB_LOCK:
            rows = self.server.db.execute(
                f"SELECT payload FROM messages "
                f"WHERE recipient_id IN ({placeholders}) AND expires_at > ? ORDER BY id ASC",
                (*ids, now)
            ).fetchall()

        messages = [json.loads(row[0]) for row in rows]
        self._send_json(200, {"messages": messages, "count": len(messages)})

    def _do_delete(self):
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

        if not self.server.client_publish_limiter.check_global():
            self._send_json(429, {"error": "rate limit exceeded"})
            return

        error = _validate_delete_payload(payload)
        if error:
            self._send_json(400, {"error": error})
            return

        recipient_pubkey = payload["recipient_pubkey"]
        if not self.server.client_publish_limiter.check_identity(recipient_pubkey):
            self.server.client_publish_limiter.refund_global()
            self._send_json(429, {"error": "rate limit exceeded"})
            return

        response, did_confirm = gossip.handle_delete_request(self.server.db, DB_LOCK, payload, _MAX_TTL_SECONDS)
        self._send_json(200, response)

        if did_confirm and self.server.gossip_ctx is not None:
            try:
                self.server.gossip_ctx.schedule_fanout(payload, target_path="/gossip/delete")
            except Exception as exc:
                print(f"  [gossip] failed to schedule delete fan-out: {exc}", file=sys.stderr)

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


# ─── Background Retention Sweep ────────────────────────────────────────────────

class _CleanupJob:
    """
    Periodic TTL sweep and tombstone reaping, mirroring gossip.AntiEntropySync's
    threading.Event-based start/stop pattern. Runs three things every pass,
    all under db_lock: purge expired messages (the TTL contract), purge
    deletion_requests rows old enough that no live message could still
    reference them (requested_at + MAX_TTL is a safe, if slightly
    conservative, upper bound — a deletion_requests row can only meaningfully
    apply to a message whose expires_at is at most MAX_TTL after publish, and
    requested_at is always >= that publish time), and reclaim the freed pages
    via incremental_vacuum so the file actually shrinks. This last step is
    the DISK-RECLAIM goal, independent of secure_delete's FORENSIC goal
    (already achieved the instant each DELETE runs) — see init_db.
    """

    def __init__(self, db: sqlite3.Connection, db_lock: threading.Lock,
                 max_ttl_seconds: int, interval_s: int):
        self.db = db
        self.db_lock = db_lock
        self.max_ttl_seconds = max_ttl_seconds
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="relay-cleanup")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._run_once()
            except Exception as exc:
                print(f"  [cleanup] sweep failed: {exc}", file=sys.stderr)
            self._stop.wait(self.interval_s)

    def _run_once(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        tombstone_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=self.max_ttl_seconds)).isoformat()
        with self.db_lock:
            self.db.execute("DELETE FROM messages WHERE expires_at <= ?", (now,))
            self.db.execute("DELETE FROM deletion_requests WHERE requested_at <= ?", (tombstone_cutoff,))
            self.db.commit()
            self.db.execute("PRAGMA incremental_vacuum")


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
    parser.add_argument("--publish-rate-limit", type=float, default=60,
                        help="Global /publish messages per minute, across all senders combined "
                             "— the Sybil-resistant backstop (default: 60).")
    parser.add_argument("--publish-rate-limit-per-sender", type=float, default=10,
                        help="Per-sender_pubkey /publish messages per minute — fairness only, "
                             "not by itself Sybil-resistant (default: 10).")
    parser.add_argument("--gossip-push-rate-limit", type=float, default=180,
                        help="Global /gossip/publish messages per minute, across all peers "
                             "combined (default: 180).")
    parser.add_argument("--gossip-push-rate-limit-per-peer", type=float, default=60,
                        help="Per-peer /gossip/publish messages per minute (default: 60).")
    parser.add_argument("--gossip-pull-rate-limit", type=float, default=3000,
                        help="Global anti-entropy pull-acceptance messages per minute, across "
                             "all peers combined — sized well above a single batch so several "
                             "peers' legitimate catch-up bursts can proceed concurrently "
                             "(default: 3000).")
    parser.add_argument("--gossip-pull-rate-limit-per-peer", type=float, default=500,
                        help="Per-peer anti-entropy pull-acceptance messages per minute — "
                             "matches the anti-entropy page size (500) so one full legitimate "
                             "catch-up page always fits in a fresh bucket (default: 500).")
    parser.add_argument("--min-ttl", type=int, default=DEFAULT_MIN_TTL_SECONDS,
                        help="Minimum accepted seconds-until-expiry on a published message's "
                             f"'expires_at' field (default: {DEFAULT_MIN_TTL_SECONDS}).")
    parser.add_argument("--max-ttl", type=int, default=DEFAULT_MAX_TTL_SECONDS,
                        help="Maximum accepted seconds-until-expiry on a published message's "
                             "'expires_at' field, and the retention window for deletion-request "
                             f"tombstones (default: {DEFAULT_MAX_TTL_SECONDS}, 30 days).")
    parser.add_argument("--cleanup-interval", type=int, default=DEFAULT_CLEANUP_INTERVAL_SECONDS,
                        help="Seconds between background TTL-sweep/tombstone-reap passes "
                             f"(default: {DEFAULT_CLEANUP_INTERVAL_SECONDS}).")
    parser.add_argument("--recipient-quota-max-messages", type=int, default=DEFAULT_RECIPIENT_QUOTA_MAX_MESSAGES,
                        help="Maximum messages physically stored per recipient_id, regardless "
                             f"of expiry status (default: {DEFAULT_RECIPIENT_QUOTA_MAX_MESSAGES}). "
                             "recipient_id now rotates daily (see README, Data Retention), so this "
                             "is effectively a PER-DAY cap per recipient, not a lifetime one — the "
                             "real worst case for one recipient is this value multiplied by "
                             "ceil(--max-ttl / 1 day); keep --max-ttl small if you're relying on "
                             "this as a DoS backstop.")
    parser.add_argument("--recipient-quota-max-bytes", type=int, default=DEFAULT_RECIPIENT_QUOTA_MAX_BYTES,
                        help="Maximum total payload bytes physically stored per recipient_id, "
                             f"regardless of expiry status (default: {DEFAULT_RECIPIENT_QUOTA_MAX_BYTES}, 50 MiB). "
                             "Same per-day-not-lifetime caveat as --recipient-quota-max-messages applies.")
    args = parser.parse_args()

    global _MIN_TTL_SECONDS, _MAX_TTL_SECONDS, _MAX_FETCH_IDS
    _MIN_TTL_SECONDS = args.min_ttl
    _MAX_TTL_SECONDS = args.max_ttl
    # Same formula as client.py's/gossip.py's _candidate_recipient_ids, so
    # a /fetch request built for THIS relay's actual retention window can
    # never be rejected for exceeding a cap sized for a different one.
    _MAX_FETCH_IDS = -(-args.max_ttl // 86400) + 2

    if args.socket_path == args.gossip_socket_path:
        # _acquire_relay_lock is called once per path below; flock() locks
        # are scoped per open-file-description, not per process, so a
        # second open()+flock() on the SAME lock file from THIS SAME
        # process is denied by the OS exactly like a genuine second
        # instance would be — producing a factually wrong "another relay
        # instance is already running" error instead of this clear one.
        print("  ERROR: --socket-path and --gossip-socket-path must be different.", file=sys.stderr)
        sys.exit(1)

    direct_transport_unlocked = args.gossip_transport == "direct"
    if direct_transport_unlocked and os.environ.get(gossip.DIRECT_TRANSPORT_ENV_VAR) != "1":
        print(f"  ERROR: --gossip-transport direct requires ${gossip.DIRECT_TRANSPORT_ENV_VAR}=1 "
              f"to be set explicitly. This bypasses Tor entirely for gossip and must NEVER be "
              f"used outside same-host testing — see README § Federation.", file=sys.stderr)
        sys.exit(1)

    db = None
    server = gossip_server = gossip_thread = None
    anti_entropy = gossip_ctx = cleanup_job = None
    server_started = gossip_server_started = False
    try:
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
            max_body_bytes=_MAX_BODY_BYTES,
        )

        # Kept fully independent (no shared global bucket) rather than one
        # unified pool: push and pull are legitimately different traffic
        # shapes (push arrives one message at a time; pull is explicitly
        # designed to return up to GOSSIP_PULL_BATCH_LIMIT=500 in a single
        # burst), so each needs its own appropriately-sized backstop rather
        # than a single budget sized for the union of both patterns.
        client_publish_limiter = ratelimit.RateLimiter(
            global_capacity=args.publish_rate_limit,
            global_refill_per_second=ratelimit.per_minute(args.publish_rate_limit),
            per_identity_capacity=args.publish_rate_limit_per_sender,
            per_identity_refill_per_second=ratelimit.per_minute(args.publish_rate_limit_per_sender),
        )
        gossip_push_limiter = ratelimit.RateLimiter(
            global_capacity=args.gossip_push_rate_limit,
            global_refill_per_second=ratelimit.per_minute(args.gossip_push_rate_limit),
            per_identity_capacity=args.gossip_push_rate_limit_per_peer,
            per_identity_refill_per_second=ratelimit.per_minute(args.gossip_push_rate_limit_per_peer),
        )
        gossip_pull_limiter = ratelimit.RateLimiter(
            global_capacity=args.gossip_pull_rate_limit,
            global_refill_per_second=ratelimit.per_minute(args.gossip_pull_rate_limit),
            per_identity_capacity=args.gossip_pull_rate_limit_per_peer,
            per_identity_refill_per_second=ratelimit.per_minute(args.gossip_pull_rate_limit_per_peer),
        )

        anti_entropy = gossip.AntiEntropySync(
            db=db, db_lock=DB_LOCK, trust_store=trust_store,
            validate_publish=_validate_publish_payload, gossip_ctx=gossip_ctx,
            own_cert_path=own_cert_path, own_key_path=own_key_path,
            direct_transport_unlocked=direct_transport_unlocked,
            max_body_bytes=_MAX_BODY_BYTES,
            gossip_pull_limiter=gossip_pull_limiter,
            interval_s=args.gossip_anti_entropy_interval,
            recipient_quota_max_messages=args.recipient_quota_max_messages,
            recipient_quota_max_bytes=args.recipient_quota_max_bytes,
            max_ttl_seconds=args.max_ttl,
        )

        cleanup_job = _CleanupJob(
            db=db, db_lock=DB_LOCK, max_ttl_seconds=args.max_ttl, interval_s=args.cleanup_interval,
        )

        server = RelayUnixHTTPServer(args.socket_path, RelayHandler)
        os.chmod(args.socket_path, 0o660)  # local-only; group access needed by the Tor process — see README
        server.db = db
        server.gossip_ctx = gossip_ctx
        server.client_publish_limiter = client_publish_limiter
        server.recipient_quota_max_messages = args.recipient_quota_max_messages
        server.recipient_quota_max_bytes = args.recipient_quota_max_bytes

        server_ssl_ctx = gossip.build_server_ssl_context(own_cert_path, own_key_path, trust_store)
        gossip_server = gossip.GossipUnixTLSServer(
            args.gossip_socket_path, gossip.GossipHandler, server_ssl_ctx, trust_store,
        )
        os.chmod(args.gossip_socket_path, 0o660)
        gossip_server.db = db
        gossip_server.db_lock = DB_LOCK
        gossip_server.gossip_ctx = gossip_ctx
        gossip_server.validate_publish = _validate_publish_payload
        gossip_server.validate_delete = _validate_delete_payload
        gossip_server.max_body_bytes = _MAX_BODY_BYTES
        gossip_server.gossip_push_limiter = gossip_push_limiter
        gossip_server.recipient_quota_max_messages = args.recipient_quota_max_messages
        gossip_server.recipient_quota_max_bytes = args.recipient_quota_max_bytes
        gossip_server.max_ttl_seconds = args.max_ttl

        gossip_thread = threading.Thread(target=gossip_server.serve_forever, daemon=True, name="gossip-listener")
        gossip_thread.start()
        gossip_server_started = True
        anti_entropy.start()
        cleanup_job.start()

        peer_count = len(trust_store.active_peers())
        print("  ╔══════════════════════════════════════╗")
        print("  ║       AetherNode Relay  v1.0         ║")
        print("  ╚══════════════════════════════════════╝")
        print(f"  Listening         : unix:{args.socket_path}")
        print(f"  Gossip            : unix:{args.gossip_socket_path}  ({args.gossip_transport} transport)")
        print(f"  Relay fingerprint : {own_fingerprint}")
        print(f"  Trusted peers     : {peer_count}")
        print(f"  Storage           : {args.db}")
        print(f"  TTL bounds        : {args.min_ttl}s – {args.max_ttl}s")
        _quota_days = -(-args.max_ttl // 86400)  # ceil(max_ttl / 1 day)
        print(f"  Recipient quota   : {args.recipient_quota_max_messages} messages / "
              f"{args.recipient_quota_max_bytes} bytes PER DAY (recipient_id rotates daily — "
              f"real worst case per recipient over the {args.max_ttl}s retention window is "
              f"{args.recipient_quota_max_messages * _quota_days} messages / "
              f"{args.recipient_quota_max_bytes * _quota_days} bytes)")
        print(f"  Zero-Knowledge: relay cannot decrypt stored payloads")
        print(f"  No public network interface — reachable only via a Tor onion service.")
        print(f"  Press Ctrl+C to stop.\n")

        try:
            server_started = True
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  Relay stopped cleanly.")
    finally:
        # Each cleanup step is independently guarded so a failure in one
        # (e.g. a handler thread still touching `db` when close() runs, since
        # daemon_threads=True means in-flight threads are never joined first)
        # can never prevent the others from running.
        if anti_entropy is not None:
            try:
                anti_entropy.stop()
            except Exception:
                pass
        if cleanup_job is not None:
            try:
                cleanup_job.stop()
            except Exception:
                pass
        if gossip_ctx is not None:
            try:
                gossip_ctx.shutdown()
            except Exception:
                pass
        if gossip_server is not None:
            try:
                # .shutdown() blocks until serve_forever()'s loop notices and
                # exits — it deadlocks forever if that loop never started
                # (e.g. a startup failure between construction and
                # gossip_thread.start()). server_close() just releases the
                # listening socket directly and is always safe to call.
                if gossip_server_started:
                    gossip_server.shutdown()
                else:
                    gossip_server.server_close()
            except Exception:
                pass
        if server is not None:
            try:
                if server_started:
                    server.shutdown()
                else:
                    server.server_close()
            except Exception:
                pass
        if db is not None:
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
