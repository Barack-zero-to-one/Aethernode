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
  delete <relay> <target_signature>  — Send a signed deletion request for one message
"""

import argparse
import base64
import getpass
import http.client
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import socks  # PySocks — SOCKS5 client used to route all relay traffic through Tor
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from protocol import PAD_BUCKETS, blind_recipient_id, day_bucket

# Every status line below uses ANSI color codes and a few Unicode symbols
# (checkmarks, crosses). A legacy 8-bit console encoding (cp1252, still the
# DEFAULT on native Windows -- including GitHub Actions' own windows-latest
# runners, confirmed by an actual CI failure, not a theoretical concern)
# cannot represent those symbols at all, and a bare print() crashes with
# UnicodeEncodeError instead of just looking wrong. Reconfiguring at import
# time, not only inside main(), because tests and other code can call this
# module's functions directly without ever going through main().
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass  # reconfigure() unavailable, or this stream doesn't support it — best effort only

# Default lifetime of a sent message before the relay purges it, in seconds
# (7 days). Overridable per-send with --ttl-seconds; the relay independently
# enforces its own --min-ttl/--max-ttl bounds regardless of what a client
# requests.
DEFAULT_TTL_SECONDS = 7 * 24 * 3600

# Fallback lookback bound used by cmd_fetch if a relay's /health response
# doesn't include max_ttl_seconds (an older, unupgraded relay) -- matches
# relay.py's own DEFAULT_MAX_TTL_SECONDS so behavior against a current-
# version relay that simply omitted the field for some other reason is
# still correct.
DEFAULT_MAX_TTL_SECONDS_FALLBACK = 30 * 24 * 3600

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

def _resolve_passphrase(env_var_name: str | None, *, required: bool = False,
                          confirm: bool = False) -> bytes | None:
    """
    Resolves a passphrase for encrypting/decrypting the identity key file.

    required=False (used at generation time): returns None outright if
    env_var_name is None -- "no --key-passphrase-env given" means the user
    is opting out of encryption entirely, preserving this project's
    original zero-friction default (a CLI tool re-invoked as a fresh
    process on every command has no session/agent to cache a passphrase
    across, so defaulting to *requiring* one on every single invocation
    would be a real usability regression for what has always been a
    low-friction tool -- this stays opt-in, like --delete-after-read and
    the direct gossip transport before it).

    required=True (used when loading a key already on disk that turns out
    to be encrypted): always resolves an actual passphrase regardless of
    what this particular invocation's flags said, since the key's own
    on-disk format is authoritative, not this run's arguments.

    Either way, checks the named environment variable first (so scripted/
    automated use never has to prompt) and falls back to an interactive,
    unechoed getpass() prompt -- a passphrase must never appear in shell
    history or `ps` output, which is why this is an env-var *name* to look
    up, never a literal CLI argument value.
    """
    if not required and env_var_name is None:
        return None
    raw = os.environ.get(env_var_name) if env_var_name else None
    if raw is not None:
        return raw.encode()
    passphrase = getpass.getpass("  Enter your identity key passphrase: ")
    if confirm:
        again = getpass.getpass("  Confirm passphrase: ")
        if passphrase != again:
            print(f"\n  {RED}✗ Passphrases did not match.{RESET}\n")
            sys.exit(1)
    return passphrase.encode()


def _generate_keypair(key_passphrase_env: str | None = None):
    """
    Generate RSA-2048 keypair and persist to KEY_DIR.
    Called automatically on first launch — no manual setup required.
    """
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    passphrase = _resolve_passphrase(key_passphrase_env, confirm=True)
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase is not None else serialization.NoEncryption()
    )
    PRIV_KEY_FILE.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
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

    if passphrase is None:
        print(f"  {YELLOW}! Private key stored unencrypted on disk. Anyone with filesystem "
              f"access to it has your full identity. Use --key-passphrase-env to protect it "
              f"with a passphrase — see README § Key Storage.{RESET}")
    print(f"  {GREEN}New identity generated.{RESET}  Key stored in {_KEY_DIR}")
    return private_key


def load_or_generate_identity(key_passphrase_env: str | None = None):
    """Load existing keypair or generate one on first launch."""
    if PRIV_KEY_FILE.exists() and PUB_KEY_FILE.exists():
        data = PRIV_KEY_FILE.read_bytes()
        try:
            return serialization.load_pem_private_key(data, password=None)
        except TypeError:
            # "Password was not given but private key is encrypted" -- the
            # on-disk key needs a passphrase regardless of what this
            # invocation's own flags said.
            passphrase = _resolve_passphrase(key_passphrase_env, required=True)
            try:
                return serialization.load_pem_private_key(data, password=passphrase)
            except (ValueError, TypeError) as exc:
                print(f"\n  {RED}✗ Could not decrypt identity key: {exc}{RESET}\n")
                sys.exit(1)
    return _generate_keypair(key_passphrase_env)


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


# ─── Padding (Traffic Analysis Resistance) ────────────────────────────────────
# Every plaintext is padded to one of a small set of standardized sizes before
# AES-GCM encryption, so ciphertext length alone can't be used to distinguish
# message types (e.g. a one-byte read receipt vs. a multi-KB document) from
# observed traffic — neither by the relay nor by a network observer.
#
# PAD_BUCKETS lives in protocol.py, shared with relay.py, so the relay's POST
# body-size cap can never silently fall out of sync with this file's padding
# scheme.

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


def _env_int(name: str, default: int) -> int:
    """
    Parse an integer environment variable, exiting with a clean CLI error on
    a bad value instead of letting a stray/mistyped env var crash argument
    parsing with a raw traceback — even for subcommands like `register` that
    don't use SOCKS/Tor at all.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"\n  {RED}{BOLD}✗ Invalid {name}={raw!r} — must be an integer.{RESET}\n")
        sys.exit(1)


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


def _assert_onion_host(url: str) -> None:
    """
    Defense-in-depth re-check of the .onion-only invariant, run again here at
    the actual network-call boundary. The CLI entry point already validates
    the relay address via _require_onion_relay before this is ever reached
    through main(), but _http_post/_http_get are ordinary importable
    functions — any caller that reaches them without going through main()
    (a test harness, a future library/GUI wrapper) must not be able to make
    this module send a request anywhere but a Tor v3 hidden service.
    """
    host = urllib.parse.urlsplit(url).hostname or ""
    if not _ONION_V3_RE.match(host.lower()):
        raise ValueError(f"refusing to contact a non-.onion host: {host!r}")


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
    try:
        _assert_onion_host(url)
    except ValueError as exc:
        raise ConnectionError(str(exc)) from exc
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
    try:
        _assert_onion_host(url)
    except ValueError as exc:
        raise ConnectionError(str(exc)) from exc
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

def cmd_send(private_key, relay_url: str, recipient_b64: str, message: str, ttl_seconds: int = DEFAULT_TTL_SECONDS):
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
    now = datetime.now(timezone.utc)
    payload = {
        "version":       "1",
        "sender_pubkey": sender_b64,
        "recipient_id":  blind_recipient_id(base64.b64decode(recipient_b64), day_bucket(now)),
        "encrypted_key": enc["encrypted_key"],
        "nonce":         enc["nonce"],
        "ciphertext":    enc["ciphertext"],
        "timestamp":     now.isoformat(),
        "expires_at":    (now + timedelta(seconds=ttl_seconds)).isoformat(),
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

def _candidate_recipient_ids(pubkey_der: bytes, max_ttl_seconds: int) -> list:
    """
    Every blind_recipient_id a message addressed to this identity could
    still legitimately be using: today's, plus one for every day back
    through the relay's own retention window (a message sent up to
    max_ttl_seconds ago and not yet expired could have been addressed with
    any of those days' identifiers), plus one extra buffer day for clock
    skew between this client and whoever sent the message.
    """
    lookback_days = -(-max_ttl_seconds // 86400) + 1  # ceil(max_ttl/86400) + 1-day buffer
    now = datetime.now(timezone.utc)
    return [
        blind_recipient_id(pubkey_der, day_bucket(now - timedelta(days=offset)))
        for offset in range(lookback_days + 1)  # inclusive of today
    ]


def cmd_fetch(private_key, relay_url: str, delete_after_read: bool = False):
    """Fetch messages from the relay, verify signatures, and decrypt."""
    print(f"\n{BOLD}{CYAN}  AetherNode — Inbox{RESET}")
    print(f"  {'─' * 50}")

    if delete_after_read:
        print(f"  {YELLOW}! --delete-after-read reveals your permanent public key to the "
              f"relay and its trusted peers for every message deleted this run — see README "
              f"§ Data Retention.{RESET}")

    my_pubkey_b64 = pubkey_to_b64(private_key.public_key())
    my_pubkey_der = base64.b64decode(my_pubkey_b64)

    try:
        health = _http_get(f"{relay_url}/health")
    except ConnectionError as exc:
        print(f"\n  {RED}✗ {exc}{RESET}\n")
        sys.exit(1)
    max_ttl_seconds = health.get("max_ttl_seconds", DEFAULT_MAX_TTL_SECONDS_FALLBACK)

    candidate_ids = _candidate_recipient_ids(my_pubkey_der, max_ttl_seconds)

    try:
        result = _http_post(f"{relay_url}/fetch", {"ids": candidate_ids})
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
        decrypted = False
        try:
            plaintext = decrypt_message(msg, private_key)
            print(f"  {BOLD}Content :{RESET} {plaintext}")
            decrypted = True
        except Exception as exc:
            print(f"  {RED}✗ Decryption failed (message may not be addressed to you): {exc}{RESET}")

        # A 4th, explicit status line whenever --delete-after-read is set —
        # a network failure here must never be silent, or the user could be
        # left believing sanitization happened when it didn't.
        if delete_after_read and decrypted:
            target_signature = msg.get("signature", "")
            try:
                delete_result = _http_post(f"{relay_url}/delete", _build_delete_payload(private_key, target_signature))
                if delete_result.get("status") == "deleted":
                    print(f"  {GREEN}✓ Deleted from relay (propagating across mesh){RESET}")
                else:
                    print(f"  {YELLOW}~ Delete not yet confirmed (status: {delete_result.get('status', 'unknown')}){RESET}")
            except ConnectionError as exc:
                print(f"  {RED}✗ Delete-after-read failed: {exc}{RESET}")

        print(f"  {'─' * 50}")

    print()


# ─── Command: delete ──────────────────────────────────────────────────────────

def _build_delete_payload(private_key, target_signature: str) -> dict:
    payload = {
        "version":          "1",
        "action":           "delete",
        "target_signature": target_signature,
        "recipient_pubkey": pubkey_to_b64(private_key.public_key()),
        "timestamp":        datetime.now(timezone.utc).isoformat(),
    }
    payload["signature"] = sign_payload(payload, private_key)
    return payload


def cmd_delete(private_key, relay_url: str, target_signature: str):
    """Send a signed, recipient-authorized deletion request for one message."""
    print(f"\n{BOLD}{CYAN}  AetherNode — Delete Request{RESET}")
    print(f"  {'─' * 50}")
    print(f"  {YELLOW}! This reveals your permanent public key to the relay and its "
          f"trusted peers, tied to this message — see README § Data Retention.{RESET}")

    payload = _build_delete_payload(private_key, target_signature)

    print(f"  {DIM}Requesting deletion of {target_signature[:24]}...{RESET}", end=" ", flush=True)
    try:
        result = _http_post(f"{relay_url}/delete", payload)
    except ConnectionError as exc:
        print(f"{RED}failed{RESET}")
        print(f"\n  {RED}✗ {exc}{RESET}\n")
        sys.exit(1)

    status = result.get("status")
    if status == "deleted":
        print(f"{GREEN}done{RESET}")
        print(f"\n  {GREEN}{BOLD}✓ Message deleted and propagating across the mesh{RESET}\n")
    elif status == "delete_requested":
        print(f"{YELLOW}pending{RESET}")
        print(f"\n  {YELLOW}{BOLD}~ Delete request recorded — this relay hasn't seen a matching, "
              f"owned message yet; it will be purged automatically if and when it arrives{RESET}\n")
    else:
        print(f"{RED}unexpected{RESET}")
        print(f"\n  {RED}✗ Unexpected response: {result}{RESET}\n")
        sys.exit(1)


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
    parser.add_argument(
        "--key-passphrase-env", metavar="ENV_VAR", default=None,
        help="Name of an environment variable holding a passphrase to encrypt/decrypt your "
             "identity key at rest (e.g. --key-passphrase-env AETHER_KEY_PASSPHRASE). If the "
             "named variable is unset, you'll be prompted interactively. Omitted by default, "
             "which keeps the original unencrypted key file — see README § Key Storage.")

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
        "--socks-port", type=int, default=_env_int("AETHER_SOCKS_PORT", DEFAULT_SOCKS_PORT),
        help=f"Tor SOCKS5 proxy port (default: {DEFAULT_SOCKS_PORT}, or $AETHER_SOCKS_PORT)")

    p_send = sub.add_parser("send", parents=[_socks_parent], help="Encrypt, sign, and broadcast a message")
    p_send.add_argument("relay",         help="Relay .onion address (e.g. http://<56chars>.onion)")
    p_send.add_argument("recipient_key", help="Recipient's base64 public key")
    p_send.add_argument("message",       help="Plaintext message to send")
    p_send.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS,
                        help=f"Seconds until the relay purges this message (default: "
                             f"{DEFAULT_TTL_SECONDS}, 7 days). The relay independently enforces "
                             f"its own min/max bounds regardless of this value.")

    p_fetch = sub.add_parser("fetch", parents=[_socks_parent], help="Fetch, verify, and decrypt your inbox")
    p_fetch.add_argument("relay", help="Relay .onion address (e.g. http://<56chars>.onion)")
    p_fetch.add_argument("--delete-after-read", action="store_true",
                        help="Send a deletion request for each message immediately after it is "
                             "successfully verified and decrypted.")

    p_delete = sub.add_parser("delete", parents=[_socks_parent],
                              help="Send a signed deletion request for one message")
    p_delete.add_argument("relay",           help="Relay .onion address (e.g. http://<56chars>.onion)")
    p_delete.add_argument("target_signature", help="The 'signature' field of the message to delete")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    global SOCKS_HOST, SOCKS_PORT
    SOCKS_HOST = getattr(args, "socks_host", DEFAULT_SOCKS_HOST)
    SOCKS_PORT = getattr(args, "socks_port", DEFAULT_SOCKS_PORT)

    # Bootstrap identity — generates keys on first launch, silent on subsequent runs
    private_key = load_or_generate_identity(args.key_passphrase_env)

    if args.command == "register":
        cmd_register(private_key)
    elif args.command == "send":
        cmd_send(private_key, _require_onion_relay(args.relay), args.recipient_key, args.message, args.ttl_seconds)
    elif args.command == "fetch":
        cmd_fetch(private_key, _require_onion_relay(args.relay), args.delete_after_read)
    elif args.command == "delete":
        cmd_delete(private_key, _require_onion_relay(args.relay), args.target_signature)


if __name__ == "__main__":
    main()
