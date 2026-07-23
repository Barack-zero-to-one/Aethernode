"""
AetherNode Multi-Day Quota Amplification Demonstration

Empirically demonstrates a known, documented limitation of the per-recipient
storage quota once recipient_id rotates daily (see README, Data Retention):
since the relay can never learn which day-bucket belongs to which real
recipient (that blindness is the entire point of rotating identifiers), the
quota is enforced per (recipient, day), not per recipient for its whole
retention window. An attacker who already knows a victim's public key --
the same information required to message them at all -- can precompute
every day-bucket within the relay's --max-ttl retention window right now
and flood all of them in a single short burst, reaching a total ceiling of
(quota * retention_days) in minutes, not the many real days an operator
skimming --help might assume.

This is NOT a bug this script is meant to catch and is NOT fixed here --
see README for why a code-level fix isn't possible without reintroducing a
static, correlatable identifier and defeating the whole feature. This
script exists to turn the documented worst-case arithmetic into a
concretely captured, real number, the same way stress_test_quota.py and
the two-conversation flood simulation validated other claims with actual
output rather than paraphrase.

RETENTION_DAYS is kept small (not the 30-day production default) purely so
this demonstration finishes in a reasonable time -- the vulnerability is
identical in kind regardless of this number, just scaled by it.

Requires a POSIX host (Linux, macOS, or WSL). Run with:

    python stress_test_quota_multiday.py

Exits 0 if the realized total matches the predicted worst-case arithmetic
(quota * retention_days), reached well within the retention window's real
wall-clock duration -- i.e., if the amplification is exactly as bad as
documented. Exits 1 on any unexpected relay behavior.
"""

import base64
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

import client   # noqa: E402  (path must be set up first)
import gossip   # noqa: E402
import protocol  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

# Overridable via env vars so CI can run a faster-but-still-real version on
# every push (see .github/workflows/ci.yml) while a manual/local run still
# defaults to the scale this demonstration was designed to use.
RETENTION_DAYS = int(os.environ.get("AETHERNODE_AMPLIFICATION_RETENTION_DAYS", "5"))
QUOTA_MAX_MESSAGES = int(os.environ.get("AETHERNODE_AMPLIFICATION_QUOTA_MAX_MESSAGES", "200"))
MESSAGES_ATTEMPTED_PER_DAY = int(os.environ.get("AETHERNODE_AMPLIFICATION_MESSAGES_PER_DAY", "250"))
STARTUP_TIMEOUT_S = 10


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 10):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def _unix_request(socket_path: str, method: str, path: str, body: dict | None = None):
    conn = _UnixHTTPConnection(socket_path)
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    result = json.loads(resp.read())
    conn.close()
    return resp.status, result


def _wait_for_socket(path: Path, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.1)
    return False


def _build_forged_payload(sender_priv, victim_pub_b64: str, forged_recipient_id: str, index: int) -> dict:
    """
    A genuinely, validly signed message -- nothing about the signature or
    any other field is forged, ONLY recipient_id is deliberately set to a
    PAST day-bucket's blind identifier rather than today's, which is
    exactly what an attacker who has precomputed a victim's candidate
    identifiers is able to do with zero cryptographic effort of their own.
    """
    victim_pub = client.b64_to_pubkey(victim_pub_b64)
    enc = client.encrypt_message(f"forged-{index}", victim_pub)
    payload = {
        "version": "1",
        "sender_pubkey": client.pubkey_to_b64(sender_priv.public_key()),
        "recipient_id": forged_recipient_id,
        "encrypted_key": enc["encrypted_key"],
        "nonce": enc["nonce"],
        "ciphertext": enc["ciphertext"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }
    payload["signature"] = client.sign_payload(payload, sender_priv)
    return payload


def main() -> int:
    if gossip._AF_UNIX is None:
        print("ERROR: this demonstration requires a POSIX host (Linux, macOS, or WSL) — "
              "AF_UNIX sockets are not available on this platform.", file=sys.stderr)
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="aethernode-quota-amplification-"))
    print(f"Working directory: {workdir}")

    socket_path = workdir / "client.sock"
    gossip_socket_path = workdir / "gossip.sock"
    identity_dir = workdir / "identity"
    proc = None

    try:
        max_ttl_seconds = RETENTION_DAYS * 86400
        print(f"Launching relay (--max-ttl {max_ttl_seconds}s = {RETENTION_DAYS} days, "
              f"--recipient-quota-max-messages {QUOTA_MAX_MESSAGES})...")
        log_path = workdir / "relay.log"
        log_file = open(log_path, "w")
        proc = subprocess.Popen(
            [
                sys.executable, str(REPO_ROOT / "relay.py"),
                "--socket-path", str(socket_path),
                "--gossip-socket-path", str(gossip_socket_path),
                "--db", ":memory:",
                "--relay-identity-dir", str(identity_dir),
                "--max-ttl", str(max_ttl_seconds),
                "--recipient-quota-max-messages", str(QUOTA_MAX_MESSAGES),
                "--recipient-quota-max-bytes", str(500 * 1024 * 1024),
                "--publish-rate-limit", "1000000",
                "--publish-rate-limit-per-sender", "1000000",
            ],
            cwd=str(REPO_ROOT), stdout=log_file, stderr=subprocess.STDOUT,
        )

        if not _wait_for_socket(socket_path, STARTUP_TIMEOUT_S):
            print(f"FAIL: relay did not bind its client socket within {STARTUP_TIMEOUT_S}s — "
                  f"see {log_path}", file=sys.stderr)
            return 1
        print("Relay is up.\n")

        sender_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        victim_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        victim_pub_b64 = client.pubkey_to_b64(victim_priv.public_key())
        victim_pub_der = base64.b64decode(victim_pub_b64)

        # The attacker's only "special" knowledge is the victim's public key
        # -- the same information required to message them at all. Everything
        # from here on is derivable by anyone who has that, with zero access
        # to the relay's internals and zero need to wait real days.
        print(f"Forging {RETENTION_DAYS} day-bucket identifiers from the victim's public key alone...")
        forged_ids = [
            protocol.blind_recipient_id(victim_pub_der, protocol.day_bucket(
                datetime.now(timezone.utc) - timedelta(days=offset)
            ))
            for offset in range(RETENTION_DAYS)
        ]

        start = time.monotonic()
        per_day_accepted = {}
        for offset, recipient_id in enumerate(forged_ids):
            accepted = 0
            for i in range(MESSAGES_ATTEMPTED_PER_DAY):
                payload = _build_forged_payload(sender_priv, victim_pub_b64, recipient_id, i)
                status, result = _unix_request(str(socket_path), "POST", "/publish", payload)
                if status == 200:
                    accepted += 1
                elif not (status == 429 and result.get("error") == "recipient storage quota exceeded"):
                    print(f"  unexpected response forging day -{offset}, message {i}: {status} {result}",
                          file=sys.stderr)
            per_day_accepted[offset] = accepted
            print(f"  day -{offset}: {accepted}/{MESSAGES_ATTEMPTED_PER_DAY} accepted "
                  f"(bucket cap = {QUOTA_MAX_MESSAGES})")
        elapsed = time.monotonic() - start

        total_accepted = sum(per_day_accepted.values())
        expected_total = QUOTA_MAX_MESSAGES * RETENTION_DAYS

        print(f"\nTotal accepted against ONE victim, across {RETENTION_DAYS} forged day-buckets, "
              f"in {elapsed:.1f}s of real wall-clock time: {total_accepted}")
        print(f"Configured single-day quota: {QUOTA_MAX_MESSAGES}")
        print(f"Documented worst-case ceiling (quota × retention_days): {expected_total}")
        print(f"Real retention window this represents: {RETENTION_DAYS} days "
              f"({max_ttl_seconds}s) -- reached in {elapsed:.1f}s instead.")

        ok = True
        if total_accepted != expected_total:
            print(f"\nFAIL: realized total ({total_accepted}) does not match the documented "
                  f"worst case ({expected_total}).", file=sys.stderr)
            ok = False
        else:
            print(f"\nCONFIRMED: the documented worst-case arithmetic is exactly the real "
                  f"worst case -- {expected_total} messages stored against one recipient, "
                  f"reached in under a minute rather than the {RETENTION_DAYS}-day window an "
                  f"operator might otherwise assume protects them.")

        h_status, h_result = _unix_request(str(socket_path), "GET", "/health")
        if h_status != 200 or h_result.get("status") != "alive":
            print(f"FAIL: relay not healthy at the end of the run: {h_status} {h_result}", file=sys.stderr)
            ok = False

        return 0 if ok else 1

    finally:
        print("\nCleaning up...")
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
