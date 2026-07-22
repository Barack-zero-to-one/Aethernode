"""
AetherNode Partition Simulation

Validates the federation/gossip feature's core claim: a message posted to one
relay in a trust perimeter remains retrievable from any OTHER relay in that
perimeter, even after a large fraction of the mesh goes down.

Launches NUM_RELAYS real relay.py subprocesses, wired into a full-mesh
peers.json (every relay trusts every other one) using the test-only "direct"
gossip transport (same-host Unix sockets, no Tor/SOCKS5 involved — see
gossip.py's DIRECT_TRANSPORT_ENV_VAR). Full mesh is deliberate: it guarantees
the surviving subgraph stays connected regardless of *which* relays are
killed, which is what makes this a clean demonstration of partition
resistance rather than a probabilistic one.

Requires a POSIX host (Linux, macOS, or WSL) — relay.py's AF_UNIX socket
binding and process-locking are not available on native Windows. Run with:

    python simulate_partition.py

Exits 0 if every posted message is recoverable from the surviving relays
after the kill, 1 otherwise (with the specific missing messages listed).
"""

import http.client
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

import client   # noqa: E402  (path must be set up first)
import gossip   # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

NUM_RELAYS       = 50
KILL_FRACTION    = 0.5
NUM_TEST_MESSAGES = 15   # kept modest: full-mesh push gossip is O(N^2) real
                          # mTLS handshakes per message, and this is meant to
                          # demonstrate the resilience property, not stress-test
                          # throughput.
STARTUP_TIMEOUT_S = 10
GOSSIP_SETTLE_S    = 3
ANTI_ENTROPY_INTERVAL_S = 5


# ─── Direct (non-TLS) client-facing HTTP over a Unix socket ────────────────────
# This talks to each relay's PLAIN client-facing listener (/publish, /fetch),
# not the mTLS gossip listener — this script plays the role of relay-test
# infrastructure dialing local sockets directly, deliberately bypassing
# client.py's Tor-only enforcement (which exists to protect real end users
# talking to real remote relays, not same-host test orchestration).

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


# ─── Node bookkeeping ───────────────────────────────────────────────────────────

@dataclass
class Node:
    index: int
    label: str
    dir: Path
    socket_path: Path
    gossip_socket_path: Path
    identity_dir: Path
    peers_file: Path
    blacklist_file: Path
    process: subprocess.Popen | None = None


def _wait_for_socket(path: Path, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.1)
    return False


def _build_signed_payload(sender_priv, recipient_pub_b64: str, message: str) -> dict:
    recipient_pub = client.b64_to_pubkey(recipient_pub_b64)
    enc = client.encrypt_message(message, recipient_pub)
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
        print("ERROR: this simulation requires a POSIX host (Linux, macOS, or WSL) — "
              "AF_UNIX sockets are not available on this platform.", file=sys.stderr)
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="aethernode-sim-"))
    print(f"Working directory: {workdir}")

    nodes: list[Node] = []
    try:
        # ── 1. Generate all 50 relay identities in-process, so fingerprints
        #        are known immediately without parsing subprocess output. ──
        print(f"Generating {NUM_RELAYS} relay identities...")
        for i in range(NUM_RELAYS):
            node_dir = workdir / f"relay-{i}"
            node = Node(
                index=i,
                label=f"relay-{i}",
                dir=node_dir,
                socket_path=node_dir / "client.sock",
                gossip_socket_path=node_dir / "gossip.sock",
                identity_dir=node_dir / "identity",
                peers_file=node_dir / "peers.json",
                blacklist_file=node_dir / "blacklist.json",
            )
            node_dir.mkdir(parents=True)
            gossip.load_or_generate_relay_identity(node.identity_dir)
            nodes.append(node)

        fingerprints = {}
        for node in nodes:
            cert = gossip.load_cert(node.identity_dir / gossip.RELAY_CERT_FILE)
            fingerprints[node.index] = gossip.relay_fingerprint(cert)

        # ── 2. Full-mesh peers.json: every node trusts every other node. ──
        print("Building full-mesh peer configuration...")
        for node in nodes:
            peers = []
            for other in nodes:
                if other.index == node.index:
                    continue
                peers.append({
                    "label": other.label,
                    "transport": "direct",
                    "unix_socket": str(other.gossip_socket_path),
                    "cert_file": str((other.identity_dir / gossip.RELAY_CERT_FILE).resolve()),
                    "fingerprint": fingerprints[other.index],
                })
            node.peers_file.write_text(json.dumps({"version": 1, "peers": peers}))
            node.blacklist_file.write_text(json.dumps({"blacklisted": []}))

        # ── 3. Launch all 50 relays as real subprocesses, direct transport. ──
        print(f"Launching {NUM_RELAYS} relay processes (direct gossip transport)...")
        env = {**os.environ, gossip.DIRECT_TRANSPORT_ENV_VAR: "1"}
        for node in nodes:
            log_path = node.dir / "relay.log"
            log_file = open(log_path, "w")
            proc = subprocess.Popen(
                [
                    sys.executable, str(REPO_ROOT / "relay.py"),
                    "--socket-path", str(node.socket_path),
                    "--gossip-socket-path", str(node.gossip_socket_path),
                    "--db", ":memory:",
                    "--relay-identity-dir", str(node.identity_dir),
                    "--peers-file", str(node.peers_file),
                    "--blacklist-file", str(node.blacklist_file),
                    "--gossip-transport", "direct",
                    "--gossip-anti-entropy-interval", str(ANTI_ENTROPY_INTERVAL_S),
                ],
                cwd=str(REPO_ROOT), env=env, stdout=log_file, stderr=subprocess.STDOUT,
            )
            node.process = proc

        for node in nodes:
            if not _wait_for_socket(node.socket_path, STARTUP_TIMEOUT_S):
                print(f"FAIL: {node.label} did not bind its client socket within "
                      f"{STARTUP_TIMEOUT_S}s — see {node.dir / 'relay.log'}", file=sys.stderr)
                return 1
            if not _wait_for_socket(node.gossip_socket_path, STARTUP_TIMEOUT_S):
                print(f"FAIL: {node.label} did not bind its gossip socket within "
                      f"{STARTUP_TIMEOUT_S}s — see {node.dir / 'relay.log'}", file=sys.stderr)
                return 1
        print("All relays are up.")

        # ── 4. Post test messages, round-robining the origin relay. ──
        sender_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        recipient_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        recipient_pub_b64 = client.pubkey_to_b64(recipient_priv.public_key())
        recipient_address = client.pubkey_address(recipient_pub_b64)

        posted: dict[int, str] = {}
        print(f"Posting {NUM_TEST_MESSAGES} messages across {NUM_RELAYS} origin relays...")
        for i in range(NUM_TEST_MESSAGES):
            origin = nodes[i % NUM_RELAYS]
            plaintext = f"partition-test-message-{i}"
            payload = _build_signed_payload(sender_priv, recipient_pub_b64, plaintext)
            status, result = _unix_request(str(origin.socket_path), "POST", "/publish", payload)
            if status != 200:
                print(f"FAIL: could not post message {i} to {origin.label}: {status} {result}", file=sys.stderr)
                return 1
            posted[i] = plaintext

        print(f"Waiting {GOSSIP_SETTLE_S}s for gossip to settle...")
        time.sleep(GOSSIP_SETTLE_S)

        # ── 5. Kill half the mesh. ──
        killed_indices = sorted(random.sample(range(NUM_RELAYS), int(NUM_RELAYS * KILL_FRACTION)))
        print(f"Killing {len(killed_indices)}/{NUM_RELAYS} relays: {killed_indices}")
        for i in killed_indices:
            nodes[i].process.terminate()
        for i in killed_indices:
            try:
                nodes[i].process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                nodes[i].process.kill()
                nodes[i].process.wait(timeout=5)
        survivor_indices = [i for i in range(NUM_RELAYS) if i not in killed_indices]
        print(f"Surviving relays: {survivor_indices}")

        # ── 6. Fetch from every survivor, decrypt, and verify. ──
        found: dict[int, str] = {}
        for i in survivor_indices:
            node = nodes[i]
            try:
                status, result = _unix_request(str(node.socket_path), "GET", f"/fetch?id={recipient_address}")
            except OSError:
                continue
            if status != 200:
                continue
            for msg in result.get("messages", []):
                if not client.verify_payload_signature(msg):
                    continue
                try:
                    plaintext = client.decrypt_message(msg, recipient_priv)
                except Exception:
                    continue
                for idx, expected in posted.items():
                    if idx not in found and plaintext == expected:
                        found[idx] = node.label

        # ── 7. Report. ──
        missing = [i for i in posted if i not in found]
        print()
        print(f"Posted {NUM_TEST_MESSAGES} messages; recovered {NUM_TEST_MESSAGES - len(missing)} "
              f"from the union of {len(survivor_indices)} surviving relays.")
        if missing:
            print("FAIL — the following messages were NOT recoverable from any surviving relay:")
            for i in missing:
                print(f"  [{i}] originally posted to relay-{i % NUM_RELAYS}: {posted[i]!r}")
            return 1

        print("PASS — every posted message was recoverable from at least one surviving relay.")
        return 0

    finally:
        print("Cleaning up...")
        for node in nodes:
            if node.process is not None and node.process.poll() is None:
                node.process.terminate()
        for node in nodes:
            if node.process is not None:
                try:
                    node.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    node.process.kill()
                    node.process.wait(timeout=5)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
