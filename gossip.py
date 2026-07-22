"""
AetherNode Gossip — Inter-Relay Federation, Replication, and Peer Authentication

Replaces the star topology (client -> relay X, recipient must fetch from X)
with a mesh: when a relay stores a genuinely new message, it pushes it to its
trusted peers, and periodically pulls from each peer to reconcile anything a
push missed (e.g. because this relay, or the peer, was offline). Consistency
is eventual, not immediate — the client-facing /publish response is never
delayed by gossip.

Peer connections are authenticated with mutual TLS: every relay has its own
self-signed X.509 identity, entirely separate from any end-user identity.
There is no certificate authority — each relay is its own trust anchor, and
operators explicitly pin which peer certificates they trust (peers.json) and
may revoke that trust at any time (blacklist.json, hot-reloaded).

This module is relay-side only. It is imported by relay.py and must never be
imported by client.py or protocol.py; it must never import relay.py.
"""

import hashlib
import http.client
import json
import socket
import socketserver
import ssl
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# ─── Constants ──────────────────────────────────────────────────────────────

RELAY_KEY_FILE  = "relay_key.pem"
RELAY_CERT_FILE = "relay_cert.pem"
RELAY_CERT_VALIDITY_DAYS = 3650  # self-signed + fingerprint-pinned, so rotation
                                   # means re-pinning at every peer — optimize
                                   # for "practically permanent", not short-lived
                                   # cert hygiene (there is no CA to auto-renew from)

DEFAULT_ANTI_ENTROPY_INTERVAL = 30   # seconds between per-peer reconciliation passes
DEFAULT_FANOUT_WORKERS        = 8    # concurrent push connections
GOSSIP_HTTP_TIMEOUT           = 30   # seconds
GOSSIP_PULL_BATCH_LIMIT       = 500  # rows per anti-entropy page

DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050  # Tor's default SocksPort

# Two independent things must both be true for a relay to accept same-host,
# Tor-bypassing gossip connections: --gossip-transport direct on the CLI, and
# this environment variable. The name is deliberately loud and specific so it
# can never be mistaken for a normal config toggle.
DIRECT_TRANSPORT_ENV_VAR = "AETHERNODE_UNSAFE_DIRECT_GOSSIP_TEST_ONLY"


# ─── Relay Identity (X.509, distinct from end-user identity) ──────────────────

def generate_relay_identity(identity_dir: Path) -> None:
    """
    Generate this relay's own RSA-2048 keypair and a self-signed X.509
    certificate, persisted to <identity_dir>/relay_key.pem and relay_cert.pem.

    Mirrors client.py's key-generation bootstrap, but writes to a directory
    that is never ~/.aether or $AETHER_HOME — a relay's gossip identity and
    an end user's messaging identity must never be confused or shared.
    """
    identity_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Fixed, non-identifying subject: identity comes from the certificate's
    # fingerprint (pinned out of band by peer operators), never from its
    # contents — consistent with the project's "no usernames" stance elsewhere.
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aethernode-relay")])
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=RELAY_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            # A relay is both a TLS server (accepting inbound gossip) and a
            # TLS client (pushing/pulling to peers) — one cert covers both roles.
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_path  = identity_dir / RELAY_KEY_FILE
    cert_path = identity_dir / RELAY_CERT_FILE

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    try:
        key_path.chmod(0o600)
    except (AttributeError, NotImplementedError, OSError):
        pass

    print(f"  New relay identity generated. Key stored in {identity_dir}")


def load_or_generate_relay_identity(identity_dir: Path) -> tuple[Path, Path]:
    """Bootstraps a relay identity on first launch. Returns (key_path, cert_path)."""
    key_path  = identity_dir / RELAY_KEY_FILE
    cert_path = identity_dir / RELAY_CERT_FILE
    if not (key_path.exists() and cert_path.exists()):
        generate_relay_identity(identity_dir)
    return key_path, cert_path


def load_cert(cert_path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_path.read_bytes())


def relay_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 hex digest of the DER-encoded cert — this relay's pinnable identity."""
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def relay_fingerprint_from_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


# ─── Peer Trust Store & Blacklist ──────────────────────────────────────────────

@dataclass
class PeerConfig:
    label: str
    transport: str            # "tor" | "direct"
    onion: str | None
    gossip_port: int | None
    unix_socket_path: str | None
    cert_pem_text: str
    fingerprint: str


def load_peers(peers_file: Path) -> list[PeerConfig]:
    """
    Load trusted peers from peers.json. Missing file is valid and means zero
    peers. Each entry's declared fingerprint is checked against the actual
    fingerprint of its cert_file at load time — a mismatch is a loud, logged,
    fail-closed rejection of that one peer entry (catches an operator pointing
    a label at the wrong cert file), not a silent trust of unverified data.
    """
    if not peers_file.exists():
        return []

    data = json.loads(peers_file.read_text())
    base_dir = peers_file.parent
    peers: list[PeerConfig] = []

    for entry in data.get("peers", []):
        label = entry.get("label", "<unlabeled>")
        try:
            cert_path = (base_dir / entry["cert_file"]).resolve()
            cert_pem_text = cert_path.read_text()
            cert = x509.load_pem_x509_certificate(cert_pem_text.encode())
            actual_fp = relay_fingerprint(cert)
        except (KeyError, OSError, ValueError) as exc:
            print(f"  WARNING: peer '{label}' cert could not be loaded ({exc}) — skipping.", file=sys.stderr)
            continue

        declared_fp = entry.get("fingerprint")
        if declared_fp != actual_fp:
            print(
                f"  WARNING: peer '{label}' cert fingerprint mismatch "
                f"(declared {declared_fp!r}, actual {actual_fp!r}) — skipping this peer.",
                file=sys.stderr,
            )
            continue

        if any(p.label == label for p in peers):
            # Not fatal — internal state (e.g. AntiEntropySync's per-peer
            # catch-up cursor) is keyed by fingerprint, the value actually
            # validated as unique above, not by this free-text label. Still
            # worth surfacing: a duplicate label is almost always an
            # operator mistake (copy-paste during cert rotation).
            print(f"  WARNING: peer label '{label}' is used by more than one peers.json entry.", file=sys.stderr)

        peers.append(PeerConfig(
            label=label,
            transport=entry.get("transport", "tor"),
            onion=entry.get("onion"),
            gossip_port=entry.get("gossip_port"),
            unix_socket_path=entry.get("unix_socket"),
            cert_pem_text=cert_pem_text,
            fingerprint=actual_fp,
        ))

    return peers


def load_blacklist(blacklist_file: Path) -> set[str]:
    if not blacklist_file.exists():
        return set()
    data = json.loads(blacklist_file.read_text())
    return {entry["fingerprint"] for entry in data.get("blacklisted", [])}


class TrustStore:
    """
    Loads peers.json once at startup (adding a new trusted peer requires a
    restart). blacklist.json is re-read fresh on every call to active_peers()
    or is_blacklisted() — cheap (a small local file) and means an operator
    revoking a peer's trust takes effect immediately, without a restart.
    """
    def __init__(self, peers_file: Path, blacklist_file: Path):
        self._blacklist_file = blacklist_file
        self._peers = load_peers(peers_file)

    def active_peers(self) -> list[PeerConfig]:
        blacklist = load_blacklist(self._blacklist_file)
        return [p for p in self._peers if p.fingerprint not in blacklist]

    def is_blacklisted(self, fingerprint: str) -> bool:
        return fingerprint in load_blacklist(self._blacklist_file)

    def trusted_cadata(self) -> str:
        """
        Concatenated PEM text of every statically configured peer's cert
        (peers.json), for use as an ssl.SSLContext trust bundle (self-signed
        certs pinned as trust anchors) — deliberately NOT filtered by
        blacklist status.

        The TLS handshake and the blacklist check are two separate
        questions and must stay that way: this bundle answers "is this a
        peer I've ever configured" (static; changing it requires a
        restart, same as adding a peer does), while GossipUnixTLSServer.
        finish_request()'s post-handshake is_blacklisted() check — already
        hot-reloaded — answers "is this specific peer currently allowed."
        Filtering the bundle itself by blacklist status would make that
        second question unrecoverable without a restart: a peer blacklisted
        at boot would be permanently excluded from the trust anchors, so
        un-blacklisting it later could never let it complete a handshake
        again. Keeping the bundle static and doing the only dynamic check
        in one place (post-handshake) makes revocation AND restoration both
        take effect immediately, symmetrically.
        """
        return "\n".join(p.cert_pem_text for p in self._peers)


# ─── TLS Contexts (mutual authentication, no CA — pinning by cert identity) ────

# Gossip TLS is pinned to exactly 1.2, not "1.2 and up". Verified directly
# (real handshakes over a loopback socket, mirroring GossipUnixTLSServer's
# synchronous per-connection wrap_socket() pattern): with TLS 1.3 allowed,
# the client-side handshake can report success while the server-side
# wrap_socket() call — which is supposed to be atomic, either a fully
# verified connection or a raised exception — intermittently aborts instead,
# even for a correctly-pinned, trusted peer. TLS 1.3's client-certificate
# authentication is handled differently from 1.2's (its CertificateVerify
# can be processed as part of a more complex exchange), and that difference
# is evidently not reliable in this synchronous, thread-per-connection
# server pattern. TLS 1.2's mutual-auth handshake is a single, simple,
# extremely well-tested flight with no such ambiguity, and forcing it
# resolved the failures in direct testing. There is no feature this project
# needs from TLS 1.3, so the conservative, verified-working version is used
# instead of the newest one.
_GOSSIP_TLS_VERSION = ssl.TLSVersion.TLSv1_2


def build_server_ssl_context(cert_path: Path, key_path: Path, trust_store: TrustStore) -> ssl.SSLContext:
    """
    verify_mode=CERT_REQUIRED makes this mutual TLS: the server refuses any
    connection whose peer doesn't present a certificate matching one of the
    pinned trust anchors below. Because every peer cert is self-signed, chain
    validation only succeeds when the presented cert IS one of the bundled
    anchors — this is fingerprint pinning enforced natively by OpenSSL during
    the handshake itself, before any request is ever read.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _GOSSIP_TLS_VERSION
    ctx.maximum_version = _GOSSIP_TLS_VERSION
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.check_hostname = False  # pinning is by cert identity, not hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    cadata = trust_store.trusted_cadata()
    if cadata.strip():
        ctx.load_verify_locations(cadata=cadata)
    # else: zero trusted peers configured yet — verify_mode=CERT_REQUIRED with
    # an empty trust store correctly rejects every connection (default-deny).
    return ctx


def build_client_ssl_context(cert_path: Path, key_path: Path, peer: "PeerConfig") -> ssl.SSLContext:
    """Per-peer context: trusts ONLY that one peer's pinned cert when dialing out."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _GOSSIP_TLS_VERSION
    ctx.maximum_version = _GOSSIP_TLS_VERSION
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=peer.cert_pem_text)
    return ctx


# ─── Gossip Listener (Unix socket, mTLS) ───────────────────────────────────────

# socket.AF_UNIX doesn't exist on native Windows. Referencing socket.AF_UNIX
# directly in the class body below would raise AttributeError at class
# *definition* time, making this whole module unimportable anywhere the
# platform lacks it — including for pure-logic testing that never touches a
# real socket. getattr() keeps the module importable everywhere; instantiating
# the class is what raises a clear, actionable error on unsupported platforms.
_AF_UNIX = getattr(socket, "AF_UNIX", None)


class GossipUnixTLSServer(socketserver.ThreadingMixIn, HTTPServer):
    """
    A TLS-wrapped twin of relay.py's RelayUnixHTTPServer. The TLS handshake
    happens inside finish_request() — which ThreadingMixIn already runs on a
    per-connection worker thread — rather than in the shared accept loop, so
    a slow or hostile handshake can only ever stall the one connection it
    belongs to, never block new connections from being accepted.
    """
    address_family = _AF_UNIX if _AF_UNIX is not None else socket.AF_INET  # never actually used; see __init__
    daemon_threads  = True

    def __init__(self, server_address, RequestHandlerClass, ssl_context: ssl.SSLContext, trust_store: TrustStore):
        if _AF_UNIX is None:
            raise OSError(
                "AF_UNIX sockets are not available on this platform. "
                "AetherNode's relay requires Linux, macOS, or WSL."
            )
        self.ssl_context = ssl_context
        self.trust_store = trust_store
        super().__init__(server_address, RequestHandlerClass)

    def server_bind(self):
        # Deliberate twin of relay.py's RelayUnixHTTPServer.server_bind().
        # Duplicated intentionally, not imported: gossip.py must never import
        # relay.py (relay.py imports FROM gossip.py, not the other way around).
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address)
        self.server_port = 0

    def finish_request(self, request, client_address):
        try:
            tls_request = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            # A failed handshake (untrusted/missing client cert, protocol
            # mismatch, or the peer aborting once verification fails) can
            # surface as either ssl.SSLError or a plain OSError/
            # ConnectionAbortedError depending on platform and timing —
            # both are just "this connection never became a valid gossip
            # session," not a bug, so both are handled the same way here.
            try:
                request.close()
            except OSError:
                pass
            return

        # ssl.SSLContext.wrap_socket() detach()es the raw socket's file
        # descriptor and transfers ownership to tls_request. The framework's
        # own post-finish_request cleanup (ThreadingMixIn.process_request_
        # thread's `finally: self.shutdown_request(request)`) still operates
        # on the original, now-detached `request` object — closing an
        # already-detached socket is a no-op — and BaseHTTPRequestHandler.
        # finish() only closes its buffered rfile/wfile wrappers, never the
        # underlying connection object itself. Nothing else in this call
        # chain ever closes the real fd, so it must be done explicitly here.
        try:
            der = tls_request.getpeercert(binary_form=True)
            fingerprint = relay_fingerprint_from_der(der) if der else None

            # Handshake-time trust (the cadata bundle) already excludes
            # blacklisted fingerprints. This is a hot-reload freshness
            # re-check: blacklist.json may have changed since the bundle
            # was built at startup.
            if fingerprint is None or self.trust_store.is_blacklisted(fingerprint):
                return

            self.RequestHandlerClass(tls_request, client_address, self)
        finally:
            try:
                tls_request.close()
            except OSError:
                pass


class GossipHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"  [gossip {ts}] {fmt % args}", file=sys.stderr)

    def address_string(self):
        return "unix-socket"

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

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/gossip/peers":
            peers = self.server.trust_store.active_peers()
            self._send_json(200, {
                "peers": [{"label": p.label, "transport": p.transport, "fingerprint": p.fingerprint} for p in peers],
                "count": len(peers),
            })
            return

        if parsed.path == "/gossip/messages":
            params = parse_qs(parsed.query)
            raw_since = params.get("since_id", ["0"])[0]
            since_id = int(raw_since) if raw_since.isdigit() else 0
            with self.server.db_lock:
                rows = self.server.db.execute(
                    "SELECT id, payload FROM messages WHERE id > ? ORDER BY id ASC LIMIT ?",
                    (since_id, GOSSIP_PULL_BATCH_LIMIT),
                ).fetchall()
            messages = [{"id": row[0], "payload": json.loads(row[1])} for row in rows]
            self._send_json(200, {"messages": messages, "count": len(messages)})
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/gossip/publish":
            self._send_json(404, {"error": "Not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            content_length = 0
        if content_length > self.server.max_body_bytes:
            self._send_json(413, {"error": f"Request body exceeds {self.server.max_body_bytes} bytes"})
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

        error = self.server.validate_publish(payload)
        if error:
            self._send_json(400, {"error": error})
            return

        received_at = datetime.now(timezone.utc).isoformat()
        is_new, row_id = insert_message_and_maybe_gossip(
            self.server.db, self.server.db_lock, payload,
            payload["recipient_id"], received_at, self.server.gossip_ctx,
        )
        if is_new:
            self._send_json(200, {"status": "ok", "id": row_id})
        else:
            # Expected steady state as the flood converges across the mesh —
            # not an error the pushing peer should treat as a failure.
            self._send_json(200, {"status": "duplicate"})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()


# ─── Shared Insert + Dedup-Gated Re-Gossip ─────────────────────────────────────

def insert_message_and_maybe_gossip(
    db: sqlite3.Connection,
    db_lock: threading.Lock,
    payload: dict,
    recipient_id: str,
    received_at: str,
    gossip_ctx: "GossipContext | None",
) -> tuple[bool, int | None]:
    """
    The single insert path used by all three ways a relay can learn about a
    message: a client's direct POST /publish, a peer's POST /gossip/publish,
    and a peer's response to an anti-entropy pull. Returns (is_new, row_id).

    A message this relay already has is a silent no-op (IntegrityError on the
    UNIQUE signature constraint) — no re-gossip. Re-gossip fires only on a
    genuinely new insert, which is what keeps a mesh's total gossip traffic
    bounded instead of reflooding forever.
    """
    try:
        with db_lock:
            cur = db.execute(
                "INSERT INTO messages (recipient_id, sender_pubkey, signature, payload, received_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (recipient_id, payload["sender_pubkey"], payload["signature"], json.dumps(payload), received_at),
            )
            db.commit()
    except sqlite3.IntegrityError:
        return False, None

    row_id = cur.lastrowid
    if gossip_ctx is not None:
        # Fan-out is fire-and-forget by design and must never be allowed to
        # affect the response to a write that has already succeeded — e.g.
        # if blacklist.json is transiently malformed mid-edit,
        # schedule_fanout()'s blacklist read would otherwise raise here,
        # after the commit, and take the caller's HTTP response down with
        # it even though the message is already durably stored.
        try:
            gossip_ctx.schedule_fanout(payload)
        except Exception as exc:
            print(f"  [gossip] failed to schedule fan-out for message {row_id}: {exc}", file=sys.stderr)
    return True, row_id


# ─── Outbound Transports (Tor-tunnelled in production, direct for testing) ────

class _UnixHTTPSConnection(http.client.HTTPConnection):
    """Same-host Unix domain socket, TLS-wrapped. Test-only transport (peer.transport == 'direct')."""

    def __init__(self, unix_socket_path: str, ssl_context: ssl.SSLContext, timeout=GOSSIP_HTTP_TIMEOUT):
        super().__init__("localhost", timeout=timeout)
        self._unix_socket_path = unix_socket_path
        self._ssl_context = ssl_context

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._unix_socket_path)
            self.sock = self._ssl_context.wrap_socket(sock)
        except Exception:
            # wrap_socket() only takes ownership of sock's fd on success
            # (via detach()); on failure (handshake rejected, protocol
            # mismatch) the raw socket is still ours to close.
            sock.close()
            raise


class _TorHTTPSConnection(http.client.HTTPConnection):
    """
    Dials a peer's .onion address through the local Tor SOCKS5 proxy, then
    layers the mTLS handshake on top of that tunnel. rdns=True forces .onion
    hostname resolution to happen inside Tor rather than via local DNS,
    exactly as in client.py's own SOCKS5 transport.
    """

    def __init__(self, onion_host: str, port: int, ssl_context: ssl.SSLContext, timeout=GOSSIP_HTTP_TIMEOUT):
        super().__init__(onion_host, port, timeout=timeout)
        self._ssl_context = ssl_context

    def connect(self):
        import socks  # imported lazily: a relay running purely in direct/test
                        # mode never needs PySocks importable at all.
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, DEFAULT_SOCKS_HOST, DEFAULT_SOCKS_PORT, rdns=True)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            self.sock = self._ssl_context.wrap_socket(sock)
        except Exception:
            sock.close()
            raise


def _open_connection(peer: PeerConfig, ssl_ctx: ssl.SSLContext) -> http.client.HTTPConnection:
    if peer.transport == "direct":
        return _UnixHTTPSConnection(peer.unix_socket_path, ssl_ctx)
    if peer.transport == "tor":
        return _TorHTTPSConnection(peer.onion, peer.gossip_port, ssl_ctx)
    raise ValueError(f"unknown peer transport {peer.transport!r}")


def _refuse_if_direct_locked(peer: PeerConfig, direct_transport_unlocked: bool) -> bool:
    """Returns True (refuse) if peer wants 'direct' transport but this relay
    was not explicitly unlocked for it — the safety gate applies per-connection,
    not just at relay startup, so a peers.json mistake can't silently bypass Tor."""
    if peer.transport == "direct" and not direct_transport_unlocked:
        print(
            f"  [gossip] refusing to contact peer '{peer.label}': configured for 'direct' "
            f"transport but this relay was not started with --gossip-transport direct "
            f"(+ ${DIRECT_TRANSPORT_ENV_VAR}=1) — see README § Federation.",
            file=sys.stderr,
        )
        return True
    return False


def _read_bounded_response(resp: http.client.HTTPResponse, max_bytes: int) -> bytes:
    """
    Read an outbound gossip response with the same size discipline
    GossipHandler.do_POST already applies to inbound bodies — a peer holding
    a validly pinned mTLS cert says nothing about its disk/memory being
    uncompromised, so an unbounded read of its response is a memory-
    exhaustion vector on a path the rest of this codebase is careful to
    close everywhere else. Checks the declared Content-Length first (reject
    before reading anything), then caps the actual read as a backstop
    against a peer that lies about or omits it.
    """
    content_length = resp.getheader("Content-Length")
    if content_length is not None and int(content_length) > max_bytes:
        raise ValueError(f"peer response declares {content_length} bytes, exceeds {max_bytes}")
    body = resp.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"peer response exceeded {max_bytes} bytes")
    return body


def _push_to_peer(peer: PeerConfig, body: bytes, own_cert_path: Path, own_key_path: Path,
                   direct_transport_unlocked: bool, max_body_bytes: int) -> None:
    if _refuse_if_direct_locked(peer, direct_transport_unlocked):
        return
    conn = None
    try:
        ssl_ctx = build_client_ssl_context(own_cert_path, own_key_path, peer)
        conn = _open_connection(peer, ssl_ctx)
        conn.request("POST", "/gossip/publish", body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        _read_bounded_response(resp, max_body_bytes)
    except Exception as exc:
        # An unreachable peer is expected steady state under eventual
        # consistency, not a fatal condition — log and move on.
        print(f"  [gossip] push to peer '{peer.label}' failed: {exc}", file=sys.stderr)
    finally:
        if conn is not None:
            conn.close()


class GossipContext:
    """Async push fan-out: schedules a POST /gossip/publish to every trusted,
    non-blacklisted peer whenever a genuinely new message is inserted locally,
    on a background thread pool so it never delays the caller."""

    def __init__(self, own_cert_path: Path, own_key_path: Path, trust_store: TrustStore,
                 direct_transport_unlocked: bool, max_body_bytes: int,
                 max_workers: int = DEFAULT_FANOUT_WORKERS):
        self.own_cert_path = own_cert_path
        self.own_key_path = own_key_path
        self.trust_store = trust_store
        self.direct_transport_unlocked = direct_transport_unlocked
        self.max_body_bytes = max_body_bytes
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="gossip-fanout")

    def schedule_fanout(self, payload: dict) -> None:
        # Serialized once here rather than once per peer inside _push_to_peer
        # — in a full mesh this fans out to dozens of worker threads that
        # would otherwise each re-encode the identical dict.
        body = json.dumps(payload).encode()
        for peer in self.trust_store.active_peers():
            self._pool.submit(
                _push_to_peer, peer, body, self.own_cert_path, self.own_key_path,
                self.direct_transport_unlocked, self.max_body_bytes,
            )

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


# ─── Anti-Entropy (periodic pull sync) ─────────────────────────────────────────

class AntiEntropySync:
    """
    Periodically pulls any messages a peer has that this relay doesn't,
    complementing push gossip (which handles the common case immediately) by
    catching up anything missed while this relay, or a peer, was offline.
    This is what makes replication genuinely converge — "synchronize database
    state" — rather than only propagate forward from whoever was online at
    publish time.
    """

    def __init__(self, db: sqlite3.Connection, db_lock: threading.Lock, trust_store: TrustStore,
                 validate_publish, gossip_ctx: GossipContext, own_cert_path: Path, own_key_path: Path,
                 direct_transport_unlocked: bool, max_body_bytes: int,
                 interval_s: int = DEFAULT_ANTI_ENTROPY_INTERVAL):
        self.db = db
        self.db_lock = db_lock
        self.trust_store = trust_store
        self.validate_publish = validate_publish
        self.gossip_ctx = gossip_ctx
        self.own_cert_path = own_cert_path
        self.own_key_path = own_key_path
        self.direct_transport_unlocked = direct_transport_unlocked
        self.max_body_bytes = max_body_bytes
        self.interval_s = interval_s
        # Keyed by peer.fingerprint (the value load_peers() actually
        # validates as unique), not peer.label — a free-text field two
        # distinct peers.json entries could share, which would otherwise
        # make them silently overwrite each other's catch-up cursor.
        self._last_seen_id: dict[str, int] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="gossip-anti-entropy")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            for peer in self.trust_store.active_peers():
                try:
                    self._sync_with_peer(peer)
                except Exception as exc:
                    print(f"  [gossip] anti-entropy sync with '{peer.label}' failed: {exc}", file=sys.stderr)
            self._stop.wait(self.interval_s)

    def _sync_with_peer(self, peer: PeerConfig) -> None:
        if _refuse_if_direct_locked(peer, self.direct_transport_unlocked):
            return

        since_id = self._last_seen_id.get(peer.fingerprint, 0)
        conn = None
        try:
            ssl_ctx = build_client_ssl_context(self.own_cert_path, self.own_key_path, peer)
            conn = _open_connection(peer, ssl_ctx)
            conn.request("GET", f"/gossip/messages?since_id={since_id}")
            resp = conn.getresponse()
            body = _read_bounded_response(resp, self.max_body_bytes)
            if resp.status != 200:
                return

            data = json.loads(body)
            max_id = since_id
            for item in data.get("messages", []):
                # The cursor must advance for every item this peer reports,
                # whether or not it validates — otherwise a single
                # unparseable batch (a Byzantine peer, or a future
                # version-skew mismatch) makes every future round re-request
                # the exact same since_id and get the exact same stuck page,
                # forever. "How far I've paged through this peer's log" and
                # "did I accept this particular item" are separate questions.
                max_id = max(max_id, item["id"])
                payload = item["payload"]
                if self.validate_publish(payload) is not None:
                    continue  # malformed/unsigned data from a peer — skip it, don't crash the loop
                received_at = datetime.now(timezone.utc).isoformat()
                insert_message_and_maybe_gossip(
                    self.db, self.db_lock, payload, payload["recipient_id"], received_at, self.gossip_ctx,
                )
            self._last_seen_id[peer.fingerprint] = max_id
        finally:
            if conn is not None:
                conn.close()
