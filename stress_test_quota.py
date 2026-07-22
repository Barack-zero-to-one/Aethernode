"""
AetherNode Quota Stress Test

Validates the per-recipient storage quota's core claims: a relay flooded
with junk messages addressed to one recipient starts rejecting further
publishes for THAT recipient with 429 once its cap is hit, a DIFFERENT
recipient's independent quota is unaffected by the first one being full,
and the relay stays responsive throughout rather than degrading or
crashing under the flood.

--recipient-quota-max-messages is a single relay-wide setting applied
identically to every recipient_id (there is no per-recipient override in
this system) -- so BOTH identities below hit the SAME cap. The property
under test is ISOLATION, not "one capped, one unlimited": recipient A's
inbox being full must never consume or block recipient B's own,
independent room under that same shared ceiling.

Launches one real relay.py subprocess with a deliberately small quota
(--recipient-quota-max-messages) and generous rate limits (so rate-limit
429s never get confused with quota 429s in this test's accounting), then
posts NUM_MESSAGES validly-signed junk messages over its Unix socket,
round-robining between two recipient identities.

Requires a POSIX host (Linux, macOS, or WSL) — relay.py's AF_UNIX socket
binding and process-locking are not available on native Windows. Run with:

    python stress_test_quota.py

Exits 0 if the quota was enforced correctly (both recipients independently
capped at the same relay-wide limit with zero cross-interference, relay
stayed responsive throughout), 1 otherwise.
"""

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
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

NUM_MESSAGES         = 10_000
QUOTA_MAX_MESSAGES   = 200     # deliberately small so the cap is reached well before NUM_MESSAGES
STARTUP_TIMEOUT_S    = 10
HEALTH_CHECK_EVERY   = 500     # messages between /health liveness checks


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


def _build_junk_payload(sender_priv, recipient_pub_b64: str, index: int) -> dict:
    recipient_pub = client.b64_to_pubkey(recipient_pub_b64)
    enc = client.encrypt_message(f"junk-{index}", recipient_pub)
    payload = {
        "version": "1",
        "sender_pubkey": client.pubkey_to_b64(sender_priv.public_key()),
        "recipient_id": client.pubkey_address(recipient_pub_b64),
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
        print("ERROR: this stress test requires a POSIX host (Linux, macOS, or WSL) — "
              "AF_UNIX sockets are not available on this platform.", file=sys.stderr)
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="aethernode-quota-stress-"))
    print(f"Working directory: {workdir}")

    socket_path = workdir / "client.sock"
    gossip_socket_path = workdir / "gossip.sock"
    identity_dir = workdir / "identity"
    proc = None

    try:
        print("Launching relay (single node, no peers, small recipient quota)...")
        log_path = workdir / "relay.log"
        log_file = open(log_path, "w")
        proc = subprocess.Popen(
            [
                sys.executable, str(REPO_ROOT / "relay.py"),
                "--socket-path", str(socket_path),
                "--gossip-socket-path", str(gossip_socket_path),
                "--db", ":memory:",
                "--relay-identity-dir", str(identity_dir),
                "--recipient-quota-max-messages", str(QUOTA_MAX_MESSAGES),
                "--recipient-quota-max-bytes", str(500 * 1024 * 1024),  # large — count is the binding constraint
                "--publish-rate-limit", "1000000",
                "--publish-rate-limit-per-sender", "1000000",
            ],
            cwd=str(REPO_ROOT), stdout=log_file, stderr=subprocess.STDOUT,
        )

        if not _wait_for_socket(socket_path, STARTUP_TIMEOUT_S):
            print(f"FAIL: relay did not bind its client socket within {STARTUP_TIMEOUT_S}s — "
                  f"see {log_path}", file=sys.stderr)
            return 1
        print("Relay is up.")

        sender_priv    = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        recipient_a_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        recipient_b_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        recipient_a_pub_b64 = client.pubkey_to_b64(recipient_a_priv.public_key())
        recipient_b_pub_b64 = client.pubkey_to_b64(recipient_b_priv.public_key())

        # Tracked PER RECIPIENT, not combined — the property under test is
        # that each recipient's cap is enforced independently of the
        # other's, which a combined counter can't distinguish from one
        # recipient silently starving the other.
        stats = {
            "a": {"accepted": 0, "quota_rejected": 0, "cap_first_hit_at": None},
            "b": {"accepted": 0, "quota_rejected": 0, "cap_first_hit_at": None},
        }
        other_errors = 0

        print(f"Posting {NUM_MESSAGES} junk messages, round-robin between two recipients, "
              f"both subject to the same relay-wide quota={QUOTA_MAX_MESSAGES}...")
        for i in range(NUM_MESSAGES):
            which = "a" if i % 2 == 0 else "b"
            target_pub_b64 = recipient_a_pub_b64 if which == "a" else recipient_b_pub_b64
            payload = _build_junk_payload(sender_priv, target_pub_b64, i)
            status, result = _unix_request(str(socket_path), "POST", "/publish", payload)

            if status == 200:
                stats[which]["accepted"] += 1
            elif status == 429 and result.get("error") == "recipient storage quota exceeded":
                stats[which]["quota_rejected"] += 1
                if stats[which]["cap_first_hit_at"] is None:
                    stats[which]["cap_first_hit_at"] = i
            else:
                other_errors += 1
                if other_errors <= 5:
                    print(f"  unexpected response at message {i} (recipient {which}): {status} {result}",
                          file=sys.stderr)

            if (i + 1) % HEALTH_CHECK_EVERY == 0:
                try:
                    h_status, h_result = _unix_request(str(socket_path), "GET", "/health")
                except OSError as exc:
                    print(f"FAIL: relay became unresponsive after {i + 1} messages: {exc}", file=sys.stderr)
                    return 1
                if h_status != 200 or h_result.get("status") != "alive":
                    print(f"FAIL: relay health check failed after {i + 1} messages: "
                          f"{h_status} {h_result}", file=sys.stderr)
                    return 1
                if proc.poll() is not None:
                    print(f"FAIL: relay process exited (code {proc.returncode}) after {i + 1} "
                          f"messages — see {log_path}", file=sys.stderr)
                    return 1

        expected_per_recipient = NUM_MESSAGES // 2
        for which, label in (("a", "Recipient A"), ("b", "Recipient B")):
            s = stats[which]
            print(f"{label}: {s['accepted']} accepted, {s['quota_rejected']} quota-rejected "
                  f"(cap first hit at message index {s['cap_first_hit_at']})")

        # ── Assertions ──
        ok = True

        if other_errors > 0:
            print(f"FAIL: {other_errors} messages got an unexpected status/error (see log above).", file=sys.stderr)
            ok = False

        for which, label, pub_b64 in (("a", "Recipient A", recipient_a_pub_b64),
                                       ("b", "Recipient B", recipient_b_pub_b64)):
            s = stats[which]
            if s["cap_first_hit_at"] is None:
                print(f"FAIL: {label}'s quota was never enforced (expected 429s never happened).", file=sys.stderr)
                ok = False

            # Verified directly via /fetch rather than derived from the
            # accepted/rejected counters above, so this also exercises the
            # real read path, not just the write path.
            status, fetch_result = _unix_request(
                str(socket_path), "GET", f"/fetch?id={client.pubkey_address(pub_b64)}"
            )
            if status != 200:
                print(f"FAIL: could not fetch {label}'s inbox for verification: {status}", file=sys.stderr)
                ok = False
                continue

            stored_count = fetch_result.get("count", -1)
            if stored_count != QUOTA_MAX_MESSAGES:
                print(f"FAIL: {label} has {stored_count} stored messages, "
                      f"expected exactly {QUOTA_MAX_MESSAGES} (the shared relay-wide cap).", file=sys.stderr)
                ok = False
            else:
                print(f"PASS: {label} stored exactly {stored_count} messages (== quota cap).")

            if s["accepted"] != QUOTA_MAX_MESSAGES:
                print(f"FAIL: {label} had {s['accepted']} publishes accepted, expected exactly "
                      f"{QUOTA_MAX_MESSAGES}.", file=sys.stderr)
                ok = False
            if s["quota_rejected"] != expected_per_recipient - QUOTA_MAX_MESSAGES:
                print(f"FAIL: {label} had {s['quota_rejected']} quota rejections, expected exactly "
                      f"{expected_per_recipient - QUOTA_MAX_MESSAGES}.", file=sys.stderr)
                ok = False

        # The actual isolation property: both recipients independently
        # reached the SAME shared cap. If one recipient's fullness had
        # leaked into or blocked the other's accounting, they would not
        # both land exactly on QUOTA_MAX_MESSAGES.
        if stats["a"]["accepted"] == QUOTA_MAX_MESSAGES and stats["b"]["accepted"] == QUOTA_MAX_MESSAGES:
            print("PASS: both recipients independently reached the same relay-wide cap with "
                  "zero cross-interference.")
        else:
            print("FAIL: recipients did not isolate correctly — see per-recipient results above.",
                  file=sys.stderr)
            ok = False

        h_status, h_result = _unix_request(str(socket_path), "GET", "/health")
        if h_status != 200 or h_result.get("status") != "alive":
            print(f"FAIL: relay not healthy at the end of the run: {h_status} {h_result}", file=sys.stderr)
            ok = False
        else:
            print("PASS: relay remained responsive throughout and is still healthy.")

        if ok:
            print("\nPASS — quota enforcement is correct and the relay survived the flood.")
            return 0
        else:
            print("\nFAIL — see above.", file=sys.stderr)
            return 1

    finally:
        print("Cleaning up...")
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
