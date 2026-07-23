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

import base64
import getpass
import hashlib
import http.client
import json
import os
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

import protocol
import ratelimit

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

def _resolve_key_passphrase(env_var_name: str | None, *, required: bool = False,
                              confirm: bool = False) -> bytes | None:
    """
    Relay-side twin of client.py's _resolve_passphrase (duplicated, not
    imported — gossip.py must never import client.py). Same semantics:
    required=False (generation time) returns None outright if no env var
    name was given, preserving the original unencrypted-by-default
    behavior; required=True (loading an already-encrypted key) always
    resolves an actual passphrase, since the on-disk key's own format is
    authoritative regardless of this invocation's flags. Checks the named
    environment variable first — the only way to keep a relay usable under
    unattended restart (systemd, a process manager), since an interactive
    prompt would hang a non-interactive service start — falling back to an
    interactive getpass() prompt for foreground/manual runs.
    """
    if not required and env_var_name is None:
        return None
    raw = os.environ.get(env_var_name) if env_var_name else None
    if raw is not None:
        return raw.encode()
    passphrase = getpass.getpass("  Enter the relay identity key passphrase: ")
    if confirm:
        again = getpass.getpass("  Confirm passphrase: ")
        if passphrase != again:
            print("  ERROR: passphrases did not match.", file=sys.stderr)
            sys.exit(1)
    return passphrase.encode()


def generate_relay_identity(identity_dir: Path, key_passphrase_env: str | None = None) -> bytes | None:
    """
    Generate this relay's own RSA-2048 keypair and a self-signed X.509
    certificate, persisted to <identity_dir>/relay_key.pem and relay_cert.pem.

    Mirrors client.py's key-generation bootstrap, but writes to a directory
    that is never ~/.aether or $AETHER_HOME — a relay's gossip identity and
    an end user's messaging identity must never be confused or shared.

    Returns the resolved passphrase (or None if generated unencrypted), so
    the caller can reuse it for every later ssl.SSLContext.load_cert_chain()
    call (the relay's key is never parsed into a Python key object the way
    client.py's is — OpenSSL loads the PEM file directly, once at server
    startup and again for every single outbound gossip connection) without
    prompting more than once per process.
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

    passphrase = _resolve_key_passphrase(key_passphrase_env, confirm=True)
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase is not None else serialization.NoEncryption()
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    try:
        key_path.chmod(0o600)
    except (AttributeError, NotImplementedError, OSError):
        pass

    if passphrase is None:
        print(f"  WARNING: relay identity key stored unencrypted on disk. Use "
              f"--relay-key-passphrase-env to protect it — see README § Key Storage.",
              file=sys.stderr)
    print(f"  New relay identity generated. Key stored in {identity_dir}")
    return passphrase


def load_or_generate_relay_identity(identity_dir: Path,
                                      key_passphrase_env: str | None = None) -> tuple[Path, Path, bytes | None]:
    """Bootstraps a relay identity on first launch. Returns (key_path, cert_path, key_password)."""
    key_path  = identity_dir / RELAY_KEY_FILE
    cert_path = identity_dir / RELAY_CERT_FILE
    if not (key_path.exists() and cert_path.exists()):
        passphrase = generate_relay_identity(identity_dir, key_passphrase_env)
        return key_path, cert_path, passphrase

    # Existing identity — detect whether it's encrypted the same way
    # client.py does (try password=None, catch the specific "encrypted but
    # no password given" error), so an already-encrypted key still works
    # even if this particular invocation didn't pass
    # --relay-key-passphrase-env.
    key_data = key_path.read_bytes()
    try:
        serialization.load_pem_private_key(key_data, password=None)
        return key_path, cert_path, None
    except TypeError:
        passphrase = _resolve_key_passphrase(key_passphrase_env, required=True)
        try:
            serialization.load_pem_private_key(key_data, password=passphrase)
        except (ValueError, TypeError) as exc:
            print(f"  ERROR: could not decrypt relay identity key: {exc}", file=sys.stderr)
            sys.exit(1)
        return key_path, cert_path, passphrase


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


def build_server_ssl_context(cert_path: Path, key_path: Path, trust_store: TrustStore,
                               key_password: bytes | None = None) -> ssl.SSLContext:
    """
    verify_mode=CERT_REQUIRED makes this mutual TLS: the server refuses any
    connection whose peer doesn't present a certificate matching one of the
    pinned trust anchors below. Because every peer cert is self-signed, chain
    validation only succeeds when the presented cert IS one of the bundled
    anchors — this is fingerprint pinning enforced natively by OpenSSL during
    the handshake itself, before any request is ever read.

    key_password is passed straight through to OpenSSL's own PEM parsing in
    load_cert_chain (None is the correct, safe value for an unencrypted
    key — this project's original, still-default behavior).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _GOSSIP_TLS_VERSION
    ctx.maximum_version = _GOSSIP_TLS_VERSION
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path), password=key_password)
    ctx.check_hostname = False  # pinning is by cert identity, not hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    cadata = trust_store.trusted_cadata()
    if cadata.strip():
        ctx.load_verify_locations(cadata=cadata)
    # else: zero trusted peers configured yet — verify_mode=CERT_REQUIRED with
    # an empty trust store correctly rejects every connection (default-deny).
    return ctx


def build_client_ssl_context(cert_path: Path, key_path: Path, peer: "PeerConfig",
                               key_password: bytes | None = None) -> ssl.SSLContext:
    """Per-peer context: trusts ONLY that one peer's pinned cert when dialing out.
    key_password: see build_server_ssl_context — same OpenSSL-level pass-through."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _GOSSIP_TLS_VERSION
    ctx.maximum_version = _GOSSIP_TLS_VERSION
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path), password=key_password)
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

    def __init__(self, server_address, RequestHandlerClass, ssl_context: ssl.SSLContext, trust_store: TrustStore,
                 max_concurrent_connections: int = 100):
        if _AF_UNIX is None:
            raise OSError(
                "AF_UNIX sockets are not available on this platform. "
                "AetherNode's relay requires Linux, macOS, or WSL."
            )
        self.ssl_context = ssl_context
        self.trust_store = trust_store
        # Same connection-flood cap as relay.py's RelayUnixHTTPServer (see
        # its __init__ for the full rationale), doubly important here: the
        # expensive part — mTLS handshake, certificate verification, inside
        # finish_request() below — runs *inside* the worker thread, after
        # acceptance but before any authentication succeeds. Gating at
        # process_request()/process_request_thread() (not finish_request()
        # itself) covers the handshake too, since ThreadingMixIn always
        # calls finish_request() from inside process_request_thread().
        self._connection_semaphore = threading.BoundedSemaphore(max_concurrent_connections)
        super().__init__(server_address, RequestHandlerClass)

    def server_bind(self):
        # Deliberate twin of relay.py's RelayUnixHTTPServer.server_bind().
        # Duplicated intentionally, not imported: gossip.py must never import
        # relay.py (relay.py imports FROM gossip.py, not the other way around).
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address)
        self.server_port = 0

    def process_request(self, request, client_address):
        if not self._connection_semaphore.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            # ThreadingMixIn.process_request's only realistic failure mode
            # is Thread.start() itself raising (e.g. RuntimeError: can't
            # start new thread -- exactly the resource-exhaustion scenario
            # this cap exists to mitigate). When that happens,
            # process_request_thread's own finally-release is never
            # reached, since the thread never started running at all;
            # release here instead so a thread-spawn failure doesn't
            # permanently shrink the effective cap by one, then re-raise
            # so the underlying error surfaces exactly as it always did.
            self._connection_semaphore.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_semaphore.release()

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

            # Stashed on the socket itself (not a server-wide attribute,
            # since this is per-connection) so GossipHandler can read the
            # already-verified peer identity back via self.connection.
            # peer_fingerprint — BaseHTTPRequestHandler's inherited
            # StreamRequestHandler.setup() sets self.connection = self.request.
            tls_request.peer_fingerprint = fingerprint

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

        if parsed.path == "/gossip/deletions":
            # Anti-entropy reconciliation for deletions, mirroring
            # /gossip/messages exactly. Only CONFIRMED tombstones are ever
            # returned — pending rows are relay-local bookkeeping that
            # already resolve on their own once the target message arrives
            # via ordinary message gossip (see resolve_deletion_request);
            # syncing them separately would risk a peer treating an
            # unverified pending claim as authoritative.
            params = parse_qs(parsed.query)
            raw_since = params.get("since_id", ["0"])[0]
            since_id = int(raw_since) if raw_since.isdigit() else 0
            with self.server.db_lock:
                rows = self.server.db.execute(
                    "SELECT id, target_signature, requester_pubkey, requester_recipient_id, requested_at "
                    "FROM deletion_requests WHERE id > ? AND confirmed = 1 ORDER BY id ASC LIMIT ?",
                    (since_id, GOSSIP_PULL_BATCH_LIMIT),
                ).fetchall()
            deletions = [
                {
                    "id": row[0], "target_signature": row[1], "requester_pubkey": row[2],
                    "requester_recipient_id": row[3], "requested_at": row[4],
                }
                for row in rows
            ]
            self._send_json(200, {"deletions": deletions, "count": len(deletions)})
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path == "/gossip/publish":
            self._do_publish()
        elif self.path == "/gossip/delete":
            self._do_delete()
        else:
            self._send_json(404, {"error": "Not found"})

    def _do_publish(self):
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

        # Cheap, indexed short-circuit for the common case in a mesh: most
        # incoming pushes are duplicates of something already delivered by
        # another peer. Skips signature verification and rate-limit budget
        # entirely for messages that were always going to be rejected by
        # insert_message_and_maybe_gossip's own UNIQUE-constraint dedup.
        signature = payload.get("signature")
        if isinstance(signature, str) and message_exists(self.server.db, self.server.db_lock, signature):
            self._send_json(200, {"status": "duplicate"})
            return

        # The connecting peer's mTLS identity is already trustworthy at
        # this point (established by the handshake itself, before any
        # application data was even read), unlike a client's self-declared
        # sender_pubkey — so global and per-peer budget are checked together,
        # and BEFORE the quota check below: this is pure in-memory token-
        # bucket arithmetic, cheaper than any DB query, so it must run first
        # or a distinct-signature flood aimed at a full-quota recipient could
        # force unlimited DB_LOCK-serialized quota queries with no throttling.
        peer_fingerprint = getattr(self.connection, "peer_fingerprint", None)
        if peer_fingerprint is None or not self.server.gossip_push_limiter.allow(peer_fingerprint):
            self._send_json(429, {"error": "rate limit exceeded"})
            return

        # Per-recipient storage quota — routing a flood through a compliant
        # or malicious peer via gossip is just as capable of filling a
        # target's inbox as publishing directly, so this must be enforced
        # here too, not only on the client-facing /publish path. Non-atomic
        # pre-filter only — see insert_message_and_maybe_gossip for the
        # authoritative, race-free recheck.
        recipient_id_raw = payload.get("recipient_id")
        if isinstance(recipient_id_raw, str) and not check_recipient_quota(
            self.server.db, self.server.db_lock, recipient_id_raw,
            self.server.recipient_quota_max_messages, self.server.recipient_quota_max_bytes,
        ):
            self._send_json(429, {"error": "recipient storage quota exceeded"})
            return

        error = self.server.validate_publish(payload)
        if error:
            self._send_json(400, {"error": error})
            return

        # Last gate before insert, now that the signature (and therefore
        # recipient_id) is verified genuine — see resolve_deletion_request.
        if resolve_deletion_request(self.server.db, self.server.db_lock, payload["signature"],
                                     payload["recipient_id"], self.server.max_ttl_seconds):
            self._send_json(200, {"status": "discarded"})
            return

        received_at = datetime.now(timezone.utc).isoformat()
        is_new, row_id, quota_exceeded = insert_message_and_maybe_gossip(
            self.server.db, self.server.db_lock, payload,
            payload["recipient_id"], received_at, self.server.gossip_ctx,
            self.server.recipient_quota_max_messages, self.server.recipient_quota_max_bytes,
        )
        if quota_exceeded:
            self._send_json(429, {"error": "recipient storage quota exceeded"})
        elif is_new:
            self._send_json(200, {"status": "ok", "id": row_id})
        else:
            # Expected steady state as the flood converges across the mesh —
            # not an error the pushing peer should treat as a failure.
            self._send_json(200, {"status": "duplicate"})

    def _do_delete(self):
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

        peer_fingerprint = getattr(self.connection, "peer_fingerprint", None)
        if peer_fingerprint is None or not self.server.gossip_push_limiter.allow(peer_fingerprint):
            self._send_json(429, {"error": "rate limit exceeded"})
            return

        error = self.server.validate_delete(payload)
        if error:
            self._send_json(400, {"error": error})
            return

        response, did_confirm = handle_delete_request(self.server.db, self.server.db_lock, payload,
                                                        self.server.max_ttl_seconds)
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


# ─── Shared Insert + Dedup-Gated Re-Gossip ─────────────────────────────────────

def message_exists(db: sqlite3.Connection, db_lock: threading.Lock, signature: str) -> bool:
    """
    Cheap, indexed (signature already has a UNIQUE constraint) existence
    check, used to short-circuit the common case in a mesh — a duplicate
    arriving via gossip flood — before paying for signature verification
    or consuming rate-limit budget on a message that was always going to
    be rejected by insert_message_and_maybe_gossip's own UNIQUE-constraint
    dedup anyway. That INSERT-time check remains the authoritative one
    (it's atomic; this pre-check has a narrow, harmless race window
    against a concurrent identical insert, which just means occasionally
    paying the full validation+insert cost for what turns out to be a
    duplicate).
    """
    with db_lock:
        return db.execute(
            "SELECT 1 FROM messages WHERE signature = ? LIMIT 1", (signature,)
        ).fetchone() is not None


def insert_message_and_maybe_gossip(
    db: sqlite3.Connection,
    db_lock: threading.Lock,
    payload: dict,
    recipient_id: str,
    received_at: str,
    gossip_ctx: "GossipContext | None",
    quota_max_messages: int | None = None,
    quota_max_bytes: int | None = None,
) -> tuple[bool, int | None, bool]:
    """
    The single insert path used by all three ways a relay can learn about a
    message: a client's direct POST /publish, a peer's POST /gossip/publish,
    and a peer's response to an anti-entropy pull. Returns (is_new, row_id,
    quota_exceeded).

    A message this relay already has is a silent no-op (IntegrityError on the
    UNIQUE signature constraint) — no re-gossip. Re-gossip fires only on a
    genuinely new insert, which is what keeps a mesh's total gossip traffic
    bounded instead of reflooding forever.

    When quota_max_messages/quota_max_bytes are given, the quota is
    re-checked HERE, atomically with the INSERT, under the same db_lock
    acquisition — this is the AUTHORITATIVE check. check_recipient_quota()
    is a separate, non-atomic, cheap pre-filter callers run earlier (before
    the expensive signature verification) purely to reject the common case
    fast. Without an atomic re-check here, concurrent requests under
    ThreadingMixIn could all pass that earlier, separately-locked check
    before any of them inserts, collectively overshooting the cap — the same
    relationship message_exists() (cheap pre-filter) already has with the
    UNIQUE constraint below (authoritative).
    """
    quota_exceeded = False
    try:
        with db_lock:
            if quota_max_messages is not None:
                count = db.execute(
                    "SELECT COUNT(*) FROM messages WHERE recipient_id = ?", (recipient_id,)
                ).fetchone()[0]
                if count >= quota_max_messages:
                    quota_exceeded = True
                else:
                    total_bytes = db.execute(
                        "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM messages WHERE recipient_id = ?",
                        (recipient_id,)
                    ).fetchone()[0]
                    if total_bytes >= quota_max_bytes:
                        quota_exceeded = True
            if quota_exceeded:
                return False, None, True

            cur = db.execute(
                "INSERT INTO messages (recipient_id, sender_pubkey, signature, payload, expires_at, received_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (recipient_id, payload["sender_pubkey"], payload["signature"], json.dumps(payload),
                 payload["expires_at"], received_at),
            )
            db.commit()
    except sqlite3.IntegrityError:
        return False, None, False

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
    return True, row_id, False


def check_recipient_quota(db: sqlite3.Connection, db_lock: threading.Lock, recipient_id: str,
                            max_messages: int, max_bytes: int) -> bool:
    """
    True if `recipient_id` has room for one more message under both the
    message-count and total-byte ceilings. Deliberately counts every
    PHYSICALLY STORED row, with no expires_at filter: if quota accounting
    excluded expired-but-not-yet-swept rows (the natural choice, to stay
    consistent with what /fetch returns), an attacker could set expires_at
    to the minimum allowed value and get effectively unlimited inserts
    accepted against one recipient — each message "expires" and drops out
    of quota accounting almost immediately while still occupying real disk
    until the next periodic sweep. Quota tracks what is physically stored;
    only the periodic cleanup sweep or an explicit delete frees headroom.

    Two short-circuiting queries, not one combined aggregate: COUNT(*) is
    answerable from idx_recipient_expires without touching the payload
    column, while SUM(LENGTH(payload)) cannot be — so the cheaper check
    runs first and skips the more expensive one whenever it already fails.
    """
    with db_lock:
        count = db.execute(
            "SELECT COUNT(*) FROM messages WHERE recipient_id = ?", (recipient_id,)
        ).fetchone()[0]
        if count >= max_messages:
            return False
        total_bytes = db.execute(
            "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM messages WHERE recipient_id = ?", (recipient_id,)
        ).fetchone()[0]
        return total_bytes < max_bytes


def _candidate_recipient_ids(pubkey_der: bytes, max_ttl_seconds: int) -> list[str]:
    """
    Relay-side twin of client.py's _candidate_recipient_ids: every
    blind_recipient_id a message from this pubkey could still legitimately
    be using — today's, plus one for every day back through the relay's own
    retention window, plus a one-day buffer for clock skew. Used to
    authorize a delete request (and to resolve a pending one) without the
    relay ever needing to be told which specific day a message was actually
    addressed with — it just tries the small, bounded set of possibilities
    itself. Pure in-memory HMAC work; callers must compute this BEFORE
    acquiring db_lock, not inside it, so a delete request's day-search never
    extends the critical section that serializes every other in-flight
    relay operation.
    """
    lookback_days = -(-max_ttl_seconds // 86400) + 1  # ceil(max_ttl/86400) + 1-day buffer
    now = datetime.now(timezone.utc)
    return [
        protocol.blind_recipient_id(pubkey_der, protocol.day_bucket(now - timedelta(days=offset)))
        for offset in range(lookback_days + 1)  # inclusive of today
    ]


def resolve_deletion_request(db: sqlite3.Connection, db_lock: threading.Lock,
                               signature: str, recipient_id: str, max_ttl_seconds: int) -> bool:
    """
    Checked as the LAST gate before inserting a genuinely new message —
    after signature verification, not before. A delete request can outrun
    the message it targets (arrives at a relay before the message itself,
    via a different, faster gossip path); if this relay did nothing for an
    unknown signature, the message would slip in moments later and the
    delete would be lost forever. handle_delete_request records that as a
    PENDING deletion_requests row when the target isn't found yet; this
    function is where that pending request gets resolved once the message
    actually arrives and its real, cryptographically-verified recipient_id
    becomes available to check against.

    This MUST run only after the caller has already verified the payload's
    signature (so `recipient_id` is trustworthy) — running it earlier, on an
    unverified recipient_id, would let an attacker who merely observed a
    real (plaintext-visible) signature value forge a bogus message carrying
    that signature and a recipient_id they choose, tricking this function
    into confirming a tombstone for a message they don't own. That is
    exactly the authorization hole the two-phase pending/confirmed design
    exists to close for handle_delete_request itself; the same care is
    needed here on the resolution side.

    Returns True if the message must be discarded (already confirmed
    deleted, or a pending request's claim just matched and was promoted),
    False if it should proceed to normal insertion (no request exists, or a
    pending request's claim didn't match and was cleaned up).
    """
    with db_lock:
        row = db.execute(
            "SELECT confirmed, requester_pubkey FROM deletion_requests WHERE target_signature = ?",
            (signature,)
        ).fetchone()
    if row is None:
        return False

    confirmed, requester_pubkey = row
    if confirmed:
        return True

    # Computed outside db_lock, between the read above and the write below —
    # same lock-discipline reasoning as handle_delete_request.
    candidate_ids = _candidate_recipient_ids(base64.b64decode(requester_pubkey), max_ttl_seconds)
    matched = recipient_id in candidate_ids

    with db_lock:
        if matched:
            # _apply_confirmed_deletion (INSERT OR REPLACE, a fresh
            # autoincrement id), not a plain UPDATE that would preserve
            # this row's original id: a peer's /gossip/deletions cursor
            # only advances based on ids it has actually seen returned
            # (confirmed=1 rows only), so if other, higher-id rows were
            # confirmed and synced before this pending row got resolved, a
            # plain UPDATE would leave this row's id permanently below
            # that peer's cursor — confirmed here, but invisible to that
            # peer's anti-entropy sync forever. The message itself was
            # never inserted (this function is the last gate BEFORE
            # insertion), so _apply_confirmed_deletion's DELETE FROM
            # messages is a harmless no-op here.
            _apply_confirmed_deletion(db, signature, requester_pubkey, recipient_id,
                                       datetime.now(timezone.utc).isoformat())
        else:
            db.execute("DELETE FROM deletion_requests WHERE target_signature = ?", (signature,))
        db.commit()
    return matched


def _apply_confirmed_deletion(db: sqlite3.Connection, target_signature: str, requester_pubkey: str,
                                requester_recipient_id: str, requested_at: str) -> None:
    """
    Must be called with db_lock already held, and does not commit-and-return
    on its own (callers wrap it in whatever else their transaction needs and
    commit once). Secure-deletes the message row if this relay currently
    holds it — a no-op DELETE affecting 0 rows otherwise, which SQLite
    handles fine — and writes or upgrades a confirmed tombstone either way.

    Shared by two callers that reach a confirmed deletion through different
    paths: handle_delete_request, where THIS relay is the one performing
    the authorization check against the requester's signed request; and
    AntiEntropySync's deletion-sync pass, reconciling a deletion a peer
    already confirmed, where no fresh authorization check is needed or
    possible — the peer already performed it, and this relay trusts that
    peer the same way it already trusts it for ordinary message gossip.
    """
    db.execute("DELETE FROM messages WHERE signature = ?", (target_signature,))
    db.execute(
        "INSERT OR REPLACE INTO deletion_requests "
        "(target_signature, requester_pubkey, requester_recipient_id, confirmed, requested_at) "
        "VALUES (?, ?, ?, 1, ?)",
        (target_signature, requester_pubkey, requester_recipient_id, requested_at),
    )


def handle_delete_request(db: sqlite3.Connection, db_lock: threading.Lock, payload: dict,
                           max_ttl_seconds: int) -> tuple[dict, bool]:
    """
    Processes an already-validated (structural fields + the request's own
    self-signature) delete request. Used by both this relay's client-facing
    POST /delete and the peer-facing POST /gossip/delete, which forward the
    identical payload verbatim (mirroring how /gossip/publish forwards an
    original client-signed publish unchanged).

    recipient_id now rotates daily (see protocol.blind_recipient_id), so a
    single static equality check against the row's recipient_id is no
    longer possible — the relay doesn't know which day the target message
    was addressed with. Since the row is already found by target_signature
    (unique, day-independent), authorization instead tries every day the
    requester's own pubkey could plausibly have produced within the
    retention window (a small, bounded set — see _candidate_recipient_ids)
    and checks the found row's recipient_id against that set.

    Returns (response_body, did_confirm) — did_confirm tells the caller
    whether to schedule mesh-wide fan-out of this same request to trusted
    peers; only a locally-confirmed delete needs to propagate.
    """
    target_signature = payload["target_signature"]
    requester_pubkey = payload["recipient_pubkey"]
    now = datetime.now(timezone.utc).isoformat()

    # Computed BEFORE acquiring db_lock — pure in-memory HMAC work over a
    # small, bounded set of candidate days, must not extend the critical
    # section that serializes every other in-flight relay operation.
    candidate_ids = set(_candidate_recipient_ids(base64.b64decode(requester_pubkey), max_ttl_seconds))

    with db_lock:
        row = db.execute(
            "SELECT recipient_id FROM messages WHERE signature = ?", (target_signature,)
        ).fetchone()

        if row is not None and row[0] in candidate_ids:
            # Authorized: secure-delete the message (PRAGMA secure_delete +
            # journal_mode=TRUNCATE, set in init_db, make this an actual
            # overwrite, not just a freed page) and write a confirmed
            # tombstone. requester_recipient_id is stored as the actually-
            # matched recipient_id for reference; nothing reads this column
            # back — authorization for a FUTURE lookup on this same
            # signature is decided by target_signature/confirmed alone.
            _apply_confirmed_deletion(db, target_signature, requester_pubkey, row[0], now)
            db.commit()
            return {"status": "deleted", "propagation": "async"}, True

        # Either not found locally, or found but the requester doesn't own
        # it: identical, non-committal handling for both — no distinguishable
        # signal for "exists but isn't yours" vs. "doesn't exist", which
        # would otherwise be an oracle for probing which signatures belong
        # to which likely victims.
        if row is None:
            # Record a PENDING request (unverified — there's nothing to
            # check ownership against yet) so a later arrival is still
            # caught by resolve_deletion_request, which redoes this same
            # day-search once the real recipient_id is known. INSERT OR
            # IGNORE: a confirmed or pending row may already exist for this
            # exact signature (a repeat request, or the echo of this
            # relay's own earlier fan-out); never downgrade an existing
            # confirmed row.
            db.execute(
                "INSERT OR IGNORE INTO deletion_requests "
                "(target_signature, requester_pubkey, requester_recipient_id, confirmed, requested_at) "
                "VALUES (?, ?, ?, 0, ?)",
                (target_signature, requester_pubkey, "", now),
            )
            db.commit()
        return {"status": "delete_requested"}, False


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
                   direct_transport_unlocked: bool, max_body_bytes: int,
                   target_path: str = "/gossip/publish", own_key_password: bytes | None = None) -> None:
    if _refuse_if_direct_locked(peer, direct_transport_unlocked):
        return
    conn = None
    try:
        ssl_ctx = build_client_ssl_context(own_cert_path, own_key_path, peer, own_key_password)
        conn = _open_connection(peer, ssl_ctx)
        conn.request("POST", target_path, body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        _read_bounded_response(resp, max_body_bytes)
        if resp.status == 429:
            # No retry here by design (push is fire-and-forget) — the
            # peer's own next anti-entropy round will naturally re-offer
            # what a 429'd push never got inserted anywhere: for
            # /gossip/publish via _sync_with_peer, for /gossip/delete via
            # _sync_deletions_with_peer. Logged either way for operator
            # visibility into fan-out throttling.
            print(f"  [gossip] push to peer '{peer.label}' ({target_path}) was rate-limited", file=sys.stderr)
    except Exception as exc:
        # An unreachable peer is expected steady state under eventual
        # consistency, not a fatal condition — log and move on.
        print(f"  [gossip] push to peer '{peer.label}' ({target_path}) failed: {exc}", file=sys.stderr)
    finally:
        if conn is not None:
            conn.close()


class GossipContext:
    """Async push fan-out: schedules a POST to every trusted, non-blacklisted
    peer whenever a genuinely new message is inserted (or deleted) locally,
    on a background thread pool so it never delays the caller."""

    def __init__(self, own_cert_path: Path, own_key_path: Path, trust_store: TrustStore,
                 direct_transport_unlocked: bool, max_body_bytes: int,
                 max_workers: int = DEFAULT_FANOUT_WORKERS, own_key_password: bytes | None = None):
        self.own_cert_path = own_cert_path
        self.own_key_path = own_key_path
        self.own_key_password = own_key_password
        self.trust_store = trust_store
        self.direct_transport_unlocked = direct_transport_unlocked
        self.max_body_bytes = max_body_bytes
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="gossip-fanout")

    def schedule_fanout(self, payload: dict, target_path: str = "/gossip/publish") -> None:
        # Serialized once here rather than once per peer inside _push_to_peer
        # — in a full mesh this fans out to dozens of worker threads that
        # would otherwise each re-encode the identical dict.
        body = json.dumps(payload).encode()
        for peer in self.trust_store.active_peers():
            self._pool.submit(
                _push_to_peer, peer, body, self.own_cert_path, self.own_key_path,
                self.direct_transport_unlocked, self.max_body_bytes, target_path,
                self.own_key_password,
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
                 gossip_pull_limiter: "ratelimit.RateLimiter",
                 recipient_quota_max_messages: int, recipient_quota_max_bytes: int,
                 max_ttl_seconds: int,
                 interval_s: int = DEFAULT_ANTI_ENTROPY_INTERVAL,
                 own_key_password: bytes | None = None):
        self.db = db
        self.db_lock = db_lock
        self.trust_store = trust_store
        self.validate_publish = validate_publish
        self.gossip_ctx = gossip_ctx
        self.own_cert_path = own_cert_path
        self.own_key_path = own_key_path
        self.own_key_password = own_key_password
        self.direct_transport_unlocked = direct_transport_unlocked
        self.max_body_bytes = max_body_bytes
        self.gossip_pull_limiter = gossip_pull_limiter
        self.recipient_quota_max_messages = recipient_quota_max_messages
        self.recipient_quota_max_bytes = recipient_quota_max_bytes
        self.max_ttl_seconds = max_ttl_seconds
        self.interval_s = interval_s
        # Keyed by peer.fingerprint (the value load_peers() actually
        # validates as unique), not peer.label — a free-text field two
        # distinct peers.json entries could share, which would otherwise
        # make them silently overwrite each other's catch-up cursor.
        self._last_seen_id: dict[str, int] = {}
        # Separate cursor for the deletion-reconciliation pass below — a
        # distinct table with its own id sequence, so it must not share a
        # cursor with message sync.
        self._last_seen_deletion_id: dict[str, int] = {}
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
                try:
                    self._sync_deletions_with_peer(peer)
                except Exception as exc:
                    print(f"  [gossip] anti-entropy deletion sync with '{peer.label}' failed: {exc}", file=sys.stderr)
            self._stop.wait(self.interval_s)

    def _sync_with_peer(self, peer: PeerConfig) -> None:
        if _refuse_if_direct_locked(peer, self.direct_transport_unlocked):
            return

        since_id = self._last_seen_id.get(peer.fingerprint, 0)
        conn = None
        try:
            ssl_ctx = build_client_ssl_context(self.own_cert_path, self.own_key_path, peer, self.own_key_password)
            conn = _open_connection(peer, ssl_ctx)
            conn.request("GET", f"/gossip/messages?since_id={since_id}")
            resp = conn.getresponse()
            body = _read_bounded_response(resp, self.max_body_bytes)
            if resp.status != 200:
                return

            data = json.loads(body)
            max_id = since_id
            for item in data.get("messages", []):
                payload = item["payload"]
                signature = payload.get("signature")

                if isinstance(signature, str) and message_exists(self.db, self.db_lock, signature):
                    # Already have it — permanent fact, safe to page past.
                    max_id = max(max_id, item["id"])
                    continue

                # Global budget checked before the quota query below — pure
                # in-memory token-bucket arithmetic, cheaper than any DB
                # query, so it must run first or a distinct-signature flood
                # aimed at a full-quota recipient could force unlimited
                # DB_LOCK-serialized quota queries with no throttling at all.
                if not self.gossip_pull_limiter.check_global():
                    # Budget exhausted for this round. Unlike a validation
                    # failure below, this is a TEMPORARY condition — the
                    # message is still wanted, just not right now. Do NOT
                    # advance max_id past this point, so the next round
                    # (interval_s later) re-requests from here and retries,
                    # instead of silently and permanently losing it the way
                    # advancing past it would.
                    break

                recipient_id_raw = payload.get("recipient_id")
                if isinstance(recipient_id_raw, str) and not check_recipient_quota(
                    self.db, self.db_lock, recipient_id_raw,
                    self.recipient_quota_max_messages, self.recipient_quota_max_bytes,
                ):
                    # Quota is a capacity ceiling, not a pacing problem —
                    # retrying later doesn't inherently create room, unlike
                    # the rate-limit exhaustion above/below. Treated like a
                    # validation failure: permanent skip, advance past it.
                    # The recipient can still obtain this message from any
                    # other, non-quota-constrained relay in the mesh. Must
                    # NEVER write to deletion_requests — "this relay happened
                    # to be full" is not "the recipient deleted this."
                    max_id = max(max_id, item["id"])
                    continue

                # The cursor must advance past a PERMANENTLY invalid item
                # (whether or not it validates), or a single unparseable
                # batch (a Byzantine peer, or a future version-skew
                # mismatch) would make every future round re-request the
                # exact same since_id and get the exact same stuck page,
                # forever. "How far I've paged through this peer's log" and
                # "did I accept this particular item" are separate questions
                # — but only for permanent outcomes; see the rate-limit
                # check above and below for the temporary case.
                if self.validate_publish(payload) is not None:
                    max_id = max(max_id, item["id"])
                    continue  # malformed/unsigned data from a peer — skip it, don't crash the loop

                if not self.gossip_pull_limiter.check_identity(peer.fingerprint):
                    self.gossip_pull_limiter.refund_global()
                    break  # per-peer budget exhausted — same temporary treatment as above

                max_id = max(max_id, item["id"])

                # Last gate before insert, now that the signature is
                # verified genuine — see resolve_deletion_request.
                if resolve_deletion_request(self.db, self.db_lock, signature,
                                             payload["recipient_id"], self.max_ttl_seconds):
                    continue

                received_at = datetime.now(timezone.utc).isoformat()
                insert_message_and_maybe_gossip(
                    self.db, self.db_lock, payload, payload["recipient_id"], received_at, self.gossip_ctx,
                    self.recipient_quota_max_messages, self.recipient_quota_max_bytes,
                )
                # Return value ignored: if the authoritative recheck inside
                # loses a last-moment race against the pre-filter above, the
                # cursor has already been advanced past this item (permanent
                # skip either way — consistent with the quota-continue
                # handling above).
            self._last_seen_id[peer.fingerprint] = max_id
        finally:
            if conn is not None:
                conn.close()

    def _sync_deletions_with_peer(self, peer: PeerConfig) -> None:
        """
        Anti-entropy backstop for deletion propagation, mirroring
        _sync_with_peer's structure and shape for messages. Deletions
        otherwise only ever propagate via one-shot async fan-out
        (GossipContext.schedule_fanout, from handle_delete_request); if
        that single push fails for a peer that already holds the target
        message (a brief network blip, the peer restarting mid-fan-out),
        that peer would never learn the message was deleted through any
        other mechanism. This closes that gap the same way message
        anti-entropy already does: periodically pull what a peer has that
        this relay doesn't.

        No fresh authorization check is performed on the pulled rows — a
        confirmed=1 row on the source peer already passed
        handle_delete_request's day-search authorization check when it was
        created there, and this relay already trusts that peer via the
        same mTLS-pinned mechanism it trusts for ordinary message gossip.

        Purely passive: this only writes the reconciled tombstone into
        THIS relay's own deletion_requests table, the same table
        GossipHandler's /gossip/deletions endpoint reads from — so once
        applied here, it becomes available to whichever of THIS relay's
        own peers pull from it next, achieving the same transitive,
        multi-hop convergence message anti-entropy gets "for free" from
        peers re-sharing their own already-accumulated messages table. No
        active re-fan-out is attempted: doing so would require a validly
        re-signable delete request, but only the request's decomposed,
        already-verified fields are stored, not its original signature —
        reconstructing a fresh signed envelope isn't possible without the
        requester's private key, and isn't needed for correctness here.
        """
        if _refuse_if_direct_locked(peer, self.direct_transport_unlocked):
            return

        since_id = self._last_seen_deletion_id.get(peer.fingerprint, 0)
        conn = None
        try:
            ssl_ctx = build_client_ssl_context(self.own_cert_path, self.own_key_path, peer, self.own_key_password)
            conn = _open_connection(peer, ssl_ctx)
            conn.request("GET", f"/gossip/deletions?since_id={since_id}")
            resp = conn.getresponse()
            body = _read_bounded_response(resp, self.max_body_bytes)
            if resp.status != 200:
                return

            data = json.loads(body)
            max_id = since_id
            for item in data.get("deletions", []):
                target_signature = item.get("target_signature")
                item_id = item.get("id", max_id)
                if not isinstance(target_signature, str):
                    max_id = max(max_id, item_id)
                    continue

                if not self.gossip_pull_limiter.check_global():
                    break  # temporary — retry from here next round
                if not self.gossip_pull_limiter.check_identity(peer.fingerprint):
                    self.gossip_pull_limiter.refund_global()
                    break

                max_id = max(max_id, item_id)
                with self.db_lock:
                    already_confirmed = self.db.execute(
                        "SELECT 1 FROM deletion_requests WHERE target_signature = ? AND confirmed = 1",
                        (target_signature,)
                    ).fetchone()
                    if already_confirmed is None:
                        _apply_confirmed_deletion(
                            self.db, target_signature,
                            item.get("requester_pubkey", ""), item.get("requester_recipient_id", ""),
                            item.get("requested_at") or datetime.now(timezone.utc).isoformat(),
                        )
                        self.db.commit()
            self._last_seen_deletion_id[peer.fingerprint] = max_id
        finally:
            if conn is not None:
                conn.close()
