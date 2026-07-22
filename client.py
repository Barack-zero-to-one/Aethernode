"""
AetherNode Client — Cryptographic CLI

Identity   : RSA-2048 keypair stored in ~/.aether/ (or $AETHER_HOME)
Encryption : AES-256-GCM (message, padded to a fixed-size bucket) + RSA-OAEP
             (AES key wrap) = hybrid E2E
Signing    : RSA-PSS + SHA-256 over canonical payload
Transport  : Tor v3 .onion hidden services ONLY, over a local SOCKS5 proxy
             (PySocks). Direct IP connections are refused.

Commands:
  register                           — Show your public identity key
  send <relay> <recipient_key> <msg> — Encrypt, sign, and broadcast a message
  fetch <relay>                      — Fetch, verify, and decrypt your inbox
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import socks  # PySocks — SOCKS5 client used to route all relay traffic through Tor
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── Terminal Colors (ANSI — no external dependencies) ───────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ─── Identity Paths ───────────────────────────────────────────────────────────
# Override with AETHER_HOME env var to test multiple identities on one machine
_KEY_DIR      = Path(os.environ.get("AETHER_HOME", Path.home() / ".aether"))
PRIV_KEY_FILE = _KEY_DIR / "identity.pem"
PUB_KEY_FILE  = _KEY_DIR / "identity.pub"


# ─── Key Management ───────────────────────────────────────────────────────────

def _generate_keypair():
    """
    Generate RSA-2048 keypair and persist to KEY_DIR.
    Called automatically on first launch — no manual setup required.
    """
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    PRIV_KEY_FILE.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    PUB_KEY_FILE.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # Restrict private key file permissions on POSIX
    try:
        PRIV_KEY_FILE.chmod(0o600)
    except (AttributeError, NotImplementedError, OSError):
        pass

    print(f"  {GREEN}New identity generated.{RESET}  Key stored in {_KEY_DIR}")
    return private_key


def load_or_generate_identity():
    """Load existing keypair or generate one on first launch."""
    if PRIV_KEY_FILE.exists() and PUB_KEY_FILE.exists():
        return serialization.load_pem_private_key(
            PRIV_KEY_FILE.read_bytes(), password=None
        )
    return _generate_keypair()


def pubkey_to_b64(public_key) -> str:
    """Serialize RSA public key to base64-encoded DER (compact, shareable string)."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode()


def b64_to_pubkey(b64: str):
    """Deserialize base64-encoded DER string back to an RSA public key object."""
    return serialization.load_der_public_key(base64.b64decode(b64))


def pubkey_address(pubkey_b64: str) -> str:
    """
    Derive a routing address (SHA-256 hex digest of the DER-encoded key) from a
    base64 public key. The relay indexes and serves messages by this address —
    it never sees a recipient's raw public key, only a one-way hash of it.
    """
    return hashlib.sha256(base64.b64decode(pubkey_b64)).hexdigest()


# ─── Padding (Traffic Analysis Resistance) ────────────────────────────────────
# Every plaintext is padded to one of a small set of standardized sizes before
# AES-GCM encryption, so ciphertext length alone can't be used to distinguish
# message types (e.g. a one-byte read receipt vs. a multi-KB document) from
# observed traffic — neither by the relay nor by a network observer.

PAD_BUCKETS = (4 * 1024, 16 * 1024, 64 * 1024)  # 4 KB / 16 KB / 64 KB
_LEN_PREFIX_SIZE = 4  # bytes; big-endian uint32 original-length prefix


def pad_plaintext(plaintext: bytes) -> bytes:
    """
    Pad `plaintext` to the smallest bucket in PAD_BUCKETS that fits a 4-byte
    big-endian length prefix plus the plaintext itself.

    Padding is cryptographically random, not null bytes: the padded buffer is
    encrypted with AES-256-GCM (authenticated encryption), so padding content
    contributes nothing exploitable either way cryptographically — but random
    bytes avoid leaving a recognizable repeated-byte run in the pre-ciphertext
    buffer, which is cheap defense-in-depth against any future code that might
    touch that buffer before encryption (e.g. compression, logging).

    Raises ValueError if `plaintext` doesn't fit even the largest bucket.
    """
    needed = _LEN_PREFIX_SIZE + len(plaintext)
    for bucket in PAD_BUCKETS:
        if needed <= bucket:
            prefix = len(plaintext).to_bytes(_LEN_PREFIX_SIZE, "big")
            return prefix + plaintext + os.urandom(bucket - needed)
    raise ValueError(
        f"Message too large: {len(plaintext)} bytes exceeds the largest "
        f"padding bucket ({PAD_BUCKETS[-1]} bytes, "
        f"~{PAD_BUCKETS[-1] - _LEN_PREFIX_SIZE} usable bytes)."
    )


def unpad_plaintext(padded: bytes) -> bytes:
    """Reverse of pad_plaintext: read the length prefix, return only the original bytes."""
    if len(padded) < _LEN_PREFIX_SIZE:
        raise ValueError("Padded plaintext shorter than the length prefix — corrupt data.")
    orig_len = int.from_bytes(padded[:_LEN_PREFIX_SIZE], "big")
    if orig_len > len(padded) - _LEN_PREFIX_SIZE:
        raise ValueError("Corrupt padding: encoded length exceeds available data.")
    return padded[_LEN_PREFIX_SIZE:_LEN_PREFIX_SIZE + orig_len]


# ─── Hybrid Encryption ────────────────────────────────────────────────────────

def encrypt_message(plaintext: str, recipient_public_key) -> dict:
    """
    Hybrid encryption:
      1. Plaintext is padded to a fixed-size bucket (traffic analysis resistance)
      2. AES-256-GCM encrypts the padded message (handles arbitrary length)
      3. RSA-OAEP encrypts the ephemeral AES key (only recipient can unwrap)

    The AES-GCM auth tag is appended to the ciphertext by the AESGCM primitive,
    so integrity is verified automatically on decrypt.

    Returns dict with base64-encoded: encrypted_key, nonce, ciphertext.
    """
    aes_key = os.urandom(32)   # ephemeral 256-bit key, never reused
    nonce   = os.urandom(12)   # 96-bit GCM nonce (NIST SP 800-38D recommendation)

    aesgcm              = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, pad_plaintext(plaintext.encode("utf-8")), None)

    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "nonce":         base64.b64encode(nonce).decode(),
        "ciphertext":    base64.b64encode(ciphertext_with_tag).decode(),
    }


def decrypt_message(payload: dict, private_key) -> str:
    """
    Reverse of encrypt_message:
      1. RSA-OAEP unwraps the AES key using the recipient's private key
      2. AES-256-GCM decrypts (auth tag verified automatically — raises if tampered)
      3. Padding is stripped to recover the original plaintext
    """
    encrypted_key       = base64.b64decode(payload["encrypted_key"])
    nonce               = base64.b64decode(payload["nonce"])
    ciphertext_with_tag = base64.b64decode(payload["ciphertext"])

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(aes_key)
    padded_plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return unpad_plaintext(padded_plaintext).decode("utf-8")


# ─── Signing & Verification ───────────────────────────────────────────────────

def sign_payload(payload: dict, private_key) -> str:
    """
    Sign the canonical form of the payload (all fields except 'signature')
    using RSA-PSS with SHA-256.

    Canonical form: JSON with sorted keys and no whitespace — deterministic
    regardless of insertion order or Python dict implementation.
    """
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(',', ':')
    ).encode()

    signature = private_key.sign(
        canonical_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def verify_payload_signature(payload: dict) -> bool:
    """
    Verify RSA-PSS signature.
    Returns True if the payload is authentic and unmodified, False otherwise.
    """
    try:
        sig_bytes  = base64.b64decode(payload["signature"])
        public_key = b64_to_pubkey(payload["sender_pubkey"])
        canonical  = {k: v for k, v in payload.items() if k != "signature"}
        canonical_bytes = json.dumps(
            canonical, sort_keys=True, separators=(',', ':')
        ).encode()

        public_key.verify(
            sig_bytes,
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ─── Tor Transport (.onion enforcement + SOCKS5) ──────────────────────────────
# AetherNode refuses to talk to anything but a Tor v3 hidden service. Connecting
# directly to a bare IP/hostname would expose real network locations to any
# observer on the link, defeating the protocol's core guarantee.

_ONION_V3_RE = re.compile(r"^[a-z2-7]{56}\.onion$")

DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050  # Tor's default SocksPort
_HTTP_TIMEOUT       = 45   # seconds — Tor circuit builds add real latency

SOCKS_HOST = DEFAULT_SOCKS_HOST
SOCKS_PORT = DEFAULT_SOCKS_PORT


def normalize_relay_url(raw: str) -> str:
    """
    Validate that `raw` names a Tor v3 .onion address and return a normalized
    'http://<onion>[:port]' URL.

    This is a client-side guardrail, not a security boundary: it only checks
    the *shape* of a v3 onion address (56 lowercase base32 chars + '.onion'),
    not the embedded ed25519 key/checksum. Tor itself will simply fail to
    resolve/connect to anything malformed or nonexistent. This check exists
    purely to reject plaintext IPs/hostnames/https:// *before* any network
    call, so a typo or a leftover TCP-era command can never silently leak
    real IP metadata.

    Raises ValueError (never sys.exit — this is a pure, unit-testable function).
    """
    candidate = raw.strip().rstrip("/")

    if "://" in candidate:
        scheme, _, rest = candidate.partition("://")
        if scheme.lower() != "http":
            raise ValueError(
                f"unsupported scheme '{scheme}://' — only bare .onion addresses "
                f"or 'http://<onion>' are accepted (not https:// — Tor already "
                f"provides the encrypted transport)"
            )
        candidate = rest

    host_part = candidate.split("/", 1)[0]
    host, _, port = host_part.partition(":")

    if not _ONION_V3_RE.match(host.lower()):
        raise ValueError(
            "not a valid Tor v3 .onion address "
            "(expected 56 base32 chars + '.onion', e.g. '<56chars>.onion')"
        )
    if port and not port.isdigit():
        raise ValueError(f"invalid port '{port}'")

    return f"http://{host.lower()}" + (f":{port}" if port else "")


def _require_onion_relay(raw: str) -> str:
    """CLI boundary wrapper: pretty-print rejection + exit, reusing the ANSI helpers."""
    try:
        return normalize_relay_url(raw)
    except ValueError as exc:
        print(f"\n  {RED}{BOLD}✗ Invalid relay address: {raw!r}{RESET}")
        print(f"  {RED}  {exc}{RESET}")
        print(f"  {DIM}  AetherNode only connects to Tor v3 .onion hidden services via SOCKS5.{RESET}\n")
        sys.exit(1)


class _SocksHTTPConnection(http.client.HTTPConnection):
    """
    HTTPConnection that tunnels through a local Tor SOCKS5 proxy.

    rdns=True is critical: it forces .onion hostname "resolution" to happen
    *inside* Tor over the SOCKS protocol, instead of via a local DNS lookup
    before the SOCKS handshake. .onion names are not real DNS names — a local
    resolver would either fail outright or, on a misconfigured system, leak
    the .onion hostname to whatever DNS resolver the OS is configured with.
    Never set rdns=False here.
    """
    def connect(self):
        self.sock = socks.socksocket()
        self.sock.set_proxy(socks.SOCKS5, SOCKS_HOST, SOCKS_PORT, rdns=True)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))


class _SocksHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_SocksHTTPConnection, req)


_opener = None


def _get_opener():
    global _opener
    if _opener is None:
        # ProxyHandler({}) explicitly disables urllib's automatic
        # environment-variable proxy detection (http_proxy/https_proxy). If
        # left default, an env-configured HTTP proxy could silently intercept
        # traffic ahead of our SOCKS5/_SocksHTTPHandler — a real leak vector
        # this feature exists to close.
        _opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SocksHTTPHandler)
    return _opener


# ─── Network Helpers ──────────────────────────────────────────────────────────

def _http_post(url: str, body: dict) -> dict:
    """POST JSON to relay over Tor. Raises ConnectionError with a human-readable message."""
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "AetherNode/1.0",
        },
        method="POST",
    )
    try:
        with _get_opener().open(req, timeout=_HTTP_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise ConnectionError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(
            f"Cannot reach relay via Tor SOCKS5 proxy {SOCKS_HOST}:{SOCKS_PORT} "
            f"({exc.reason}). Is Tor running and listening on that port?"
        ) from exc
    except (socket.timeout, http.client.RemoteDisconnected) as exc:
        raise ConnectionError(
            "Connection timed out or was dropped (Tor circuit build can take "
            "longer than a direct connection — try again)"
        ) from exc


def _http_get(url: str) -> dict:
    """GET JSON from relay over Tor. Raises ConnectionError with a human-readable message."""
    req = urllib.request.Request(url, headers={"User-Agent": "AetherNode/1.0"})
    try:
        with _get_opener().open(req, timeout=_HTTP_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise ConnectionError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(
            f"Cannot reach relay via Tor SOCKS5 proxy {SOCKS_HOST}:{SOCKS_PORT} "
            f"({exc.reason}). Is Tor running and listening on that port?"
        ) from exc
    except (socket.timeout, http.client.RemoteDisconnected) as exc:
        raise ConnectionError(
            "Connection timed out or was dropped (Tor circuit build can take "
            "longer than a direct connection — try again)"
        ) from exc


# ─── Command: register ────────────────────────────────────────────────────────

def cmd_register(private_key):
    """
    Display the user's public identity key.
    This base64 string is the user's "address" — share it to receive messages.
    """
    pubkey_b64 = pubkey_to_b64(private_key.public_key())
    print(f"\n{BOLD}{CYAN}  ╔══════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}  ║       AetherNode Identity            ║{RESET}")
    print(f"{BOLD}{CYAN}  ╚══════════════════════════════════════╝{RESET}")
    print(f"\n  {DIM}Your public key is your decentralized address.{RESET}")
    print(f"  {DIM}Share it with anyone who wants to send you a message.{RESET}")
    print(f"\n  {BOLD}Public Key (base64 DER):{RESET}")
    print(f"\n  {GREEN}{pubkey_b64}{RESET}")
    print(f"\n  {DIM}Private key : {PRIV_KEY_FILE}{RESET}")
    print(f"  {DIM}Public key  : {PUB_KEY_FILE}{RESET}\n")


# ─── Command: send ────────────────────────────────────────────────────────────

def cmd_send(private_key, relay_url: str, recipient_b64: str, message: str):
    """Encrypt the message for the recipient, sign it, and POST to the relay."""
    print(f"\n{BOLD}{CYAN}  AetherNode — Sending Message{RESET}")
    print(f"  {'─' * 50}")

    # Load recipient public key from the base64 argument
    try:
        recipient_public_key = b64_to_pubkey(recipient_b64)
    except Exception as exc:
        print(f"\n  {RED}✗ Invalid recipient public key: {exc}{RESET}\n")
        sys.exit(1)

    # Step 1: Hybrid encrypt
    print(f"  {DIM}[1/3] Encrypting  (AES-256-GCM + RSA-OAEP)...{RESET}", end=" ", flush=True)
    try:
        enc = encrypt_message(message, recipient_public_key)
    except ValueError as exc:
        print(f"{RED}failed{RESET}")
        print(f"\n  {RED}✗ {exc}{RESET}\n")
        sys.exit(1)
    print(f"{GREEN}done{RESET}")

    # Step 2: Build and sign payload
    print(f"  {DIM}[2/3] Signing     (RSA-PSS + SHA-256)...{RESET}", end=" ", flush=True)
    sender_b64 = pubkey_to_b64(private_key.public_key())
    payload = {
        "version":       "1",
        "sender_pubkey": sender_b64,
        "recipient_id":  pubkey_address(recipient_b64),
        "encrypted_key": enc["encrypted_key"],
        "nonce":         enc["nonce"],
        "ciphertext":    enc["ciphertext"],
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }
    payload["signature"] = sign_payload(payload, private_key)
    print(f"{GREEN}done{RESET}")

    # Step 3: Broadcast to relay
    print(f"  {DIM}[3/3] Broadcasting to {relay_url}...{RESET}", end=" ", flush=True)
    try:
        result = _http_post(f"{relay_url}/publish", payload)
        print(f"{GREEN}done{RESET}")
        relay_id = result.get("id", "?")
        print(f"\n  {GREEN}{BOLD}✓ Message delivered  (relay ID: {relay_id}){RESET}\n")
    except ConnectionError as exc:
        print(f"{RED}failed{RESET}")
        print(f"\n  {RED}✗ {exc}{RESET}\n")
        sys.exit(1)


# ─── Command: fetch ───────────────────────────────────────────────────────────

def cmd_fetch(private_key, relay_url: str):
    """Fetch messages from the relay, verify signatures, and decrypt."""
    print(f"\n{BOLD}{CYAN}  AetherNode — Inbox{RESET}")
    print(f"  {'─' * 50}")

    my_pubkey_b64 = pubkey_to_b64(private_key.public_key())
    my_address    = pubkey_address(my_pubkey_b64)
    url           = f"{relay_url}/fetch?id={my_address}"

    try:
        result = _http_get(url)
    except ConnectionError as exc:
        print(f"\n  {RED}✗ {exc}{RESET}\n")
        sys.exit(1)

    messages = result.get("messages", [])

    if not messages:
        print(f"\n  {DIM}No messages found for this identity.{RESET}\n")
        return

    print(f"\n  {DIM}{len(messages)} message(s) found.{RESET}\n")

    for idx, msg in enumerate(messages, 1):
        ts           = msg.get("timestamp", "unknown time")
        sender_short = msg.get("sender_pubkey", "")[:24] + "..."

        print(f"  {BOLD}Message {idx}{RESET}")
        print(f"  {DIM}From : {sender_short}{RESET}")
        print(f"  {DIM}Time : {ts}{RESET}")

        # Verify the sender's signature before trusting any content
        if verify_payload_signature(msg):
            print(f"  {GREEN}{BOLD}✓ Signature verified — message is authentic and unmodified{RESET}")
        else:
            print(f"  {RED}{BOLD}✗ Signature INVALID — possible forgery or relay tampering{RESET}")
            print(f"  {RED}  Refusing to decrypt untrusted message.{RESET}")
            print(f"  {'─' * 50}")
            continue

        # Decrypt using our private key
        try:
            plaintext = decrypt_message(msg, private_key)
            print(f"  {BOLD}Content :{RESET} {plaintext}")
        except Exception as exc:
            print(f"  {RED}✗ Decryption failed (message may not be addressed to you): {exc}{RESET}")

        print(f"  {'─' * 50}")

    print()


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="aether",
        description=f"{BOLD}AetherNode{RESET} — Zero-trust decentralized messaging",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python client.py register
  python client.py send http://<56charbase32>.onion <BOB_PUBKEY> "Hello, free world"
  python client.py fetch http://<56charbase32>.onion

  # Two identities on one machine (testing Alice ↔ Bob):
  AETHER_HOME=~/.aether_alice python client.py register
  AETHER_HOME=~/.aether_bob   python client.py register
        """,
    )

    sub = parser.add_subparsers(dest="command", metavar="command")

    sub.add_parser(
        "register",
        help="Display your decentralized public identity key",
    )

    _socks_parent = argparse.ArgumentParser(add_help=False)
    _socks_parent.add_argument(
        "--socks-host", default=os.environ.get("AETHER_SOCKS_HOST", DEFAULT_SOCKS_HOST),
        help=f"Tor SOCKS5 proxy host (default: {DEFAULT_SOCKS_HOST}, or $AETHER_SOCKS_HOST)")
    _socks_parent.add_argument(
        "--socks-port", type=int, default=int(os.environ.get("AETHER_SOCKS_PORT", DEFAULT_SOCKS_PORT)),
        help=f"Tor SOCKS5 proxy port (default: {DEFAULT_SOCKS_PORT}, or $AETHER_SOCKS_PORT)")

    p_send = sub.add_parser("send", parents=[_socks_parent], help="Encrypt, sign, and broadcast a message")
    p_send.add_argument("relay",         help="Relay .onion address (e.g. http://<56chars>.onion)")
    p_send.add_argument("recipient_key", help="Recipient's base64 public key")
    p_send.add_argument("message",       help="Plaintext message to send")

    p_fetch = sub.add_parser("fetch", parents=[_socks_parent], help="Fetch, verify, and decrypt your inbox")
    p_fetch.add_argument("relay", help="Relay .onion address (e.g. http://<56chars>.onion)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    global SOCKS_HOST, SOCKS_PORT
    SOCKS_HOST = getattr(args, "socks_host", DEFAULT_SOCKS_HOST)
    SOCKS_PORT = getattr(args, "socks_port", DEFAULT_SOCKS_PORT)

    # Bootstrap identity — generates keys on first launch, silent on subsequent runs
    private_key = load_or_generate_identity()

    if args.command == "register":
        cmd_register(private_key)
    elif args.command == "send":
        cmd_send(private_key, _require_onion_relay(args.relay), args.recipient_key, args.message)
    elif args.command == "fetch":
        cmd_fetch(private_key, _require_onion_relay(args.relay))


if __name__ == "__main__":
    main()
