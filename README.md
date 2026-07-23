# AetherNode

[![CI](https://github.com/Barack-zero-to-one/Aethernode/actions/workflows/ci.yml/badge.svg)](https://github.com/Barack-zero-to-one/Aethernode/actions/workflows/ci.yml)

> Zero-trust decentralized messaging. Your identity is a key. Your words are unreadable to the network.

---

## The Problem

Centralized messaging infrastructure concentrates an extraordinary amount of trust in a small number of operators. A centralized server can suspend an account without appeal, read the content of private conversations, hand user data to a government on request, or erase an entire conversation history overnight. Users of such systems do not own their communications; the operator does. AetherNode is designed to remove that operator from the trust model entirely.

## The Solution

AetherNode achieves this by eliminating the trusted third party at every layer of the system. Identity is represented by a cryptographic keypair rather than a username, an account, or a phone number; possession of the private key is the only form of authentication the protocol recognizes. Every message is encrypted end to end with AES-256 before it ever leaves the sender's machine, so the relay that transports it handles nothing but ciphertext. Because the relay functions as a blind bulletin board with no ability to read what it stores, and because anyone is free to operate one, no single party is in a position to censor the network. The network layer itself is anonymized, since all traffic between clients and relays travels exclusively over Tor v3 hidden services, meaning there is no public IP address to seize, block, or subpoena, and no network observer can determine who is communicating with whom. Every message is padded to a fixed size before encryption, so the length of the resulting ciphertext cannot be used to distinguish a short acknowledgment from a lengthy document. And relays are no longer isolated: a relay that receives a message gossips it to the peers it trusts, so a recipient can retrieve a message from any relay within that trust perimeter, not only the one it was originally sent to, meaning the loss of any single relay no longer breaks delivery.

---

## Cryptographic Flow

```
  Barack                          Relay                           Mbondo
  ─────                            ─────                           ───

  "Hello, Mbondo"
       │
       ▼
  ┌─────────────────┐
  │  Pad plaintext  │ ◄─ fixed-size bucket
  │  (4/16/64 KB)   │    (traffic-size unlinkability)
  └────────┬────────┘
           │  padded plaintext
           ▼
  ┌─────────────────┐
  │  AES-256-GCM    │ ◄─ random 256-bit key
  │  Encrypt msg    │    + 96-bit nonce
  └────────┬────────┘
           │  ciphertext + auth_tag
           ▼
  ┌─────────────────┐
  │  RSA-OAEP       │ ◄─ Mbondo Public Key
  │  Wrap AES key   │
  └────────┬────────┘
           │  encrypted_key
           ▼
  ┌─────────────────┐
  │  RSA-PSS Sign   │ ◄─ Barack Private Key, over the
  │  Full payload   │    full payload incl. expires_at
  └────────┬────────┘
           │
           ▼
  POST /publish              Verify sig, TTL bounds,          POST /fetch
  (via Tor SOCKS5) ─────────► and recipient quota    ───────► (via Tor SOCKS5)
                              Store + fan out to peers               │
                              (cannot read, cannot forge)             ▼
                                                            Verify RSA-PSS ✓
                                                                       │
                                                            RSA-OAEP unwrap AES key
                                                                       │
                                                            AES-256-GCM decrypt
                                                                       │
                                                            Strip padding
                                                                       │
                                                                       ▼
                                                                 "Hello, Mbondo"
```

The relay's TTL, quota, and deletion enforcement, and the mesh-wide propagation of both new messages and deletion requests to trusted peers, are covered in full in the Data Retention and Federation sections below; this diagram shows only the client-to-client cryptographic path itself, unchanged in shape since the relay still never touches anything but ciphertext it cannot read and cannot forge. One field's meaning has changed without changing this diagram's shape: `recipient_id`, computed here exactly as before, is no longer a permanent address but a value that also depends on the calendar day, covered in full in Metadata-Hiding below.

---

## Quick Start

`relay.py` binds a Unix domain socket and requires Linux, macOS, or WSL, since it has no public network interface at all. `client.py` runs anywhere Python and Tor are available, including native Windows, as long as it is pointed at a relay's `.onion` address. Tor must already be installed with its SocksPort running, on `127.0.0.1:9050` by default, before the client can be used; see the Deployment section below for setting up the relay's hidden service.

```bash
pip install -r requirements.txt

# Terminal 1 — start the relay (Linux/macOS/WSL; requires Tor's torrc already
# pointing a HiddenServicePort at this socket — see Deployment)
python relay.py --socket-path ./aether-relay.sock

# Terminal 2 — Alice registers her identity
python client.py register
# → copy the base64 public key shown

# Terminal 3 — Bob registers (different identity dir for local testing)
AETHER_HOME=~/.aether_bob python client.py register
# → copy Bob's public key

# Alice sends an encrypted message to Bob (via Tor, over the relay's .onion address)
python client.py send http://<56charbase32>.onion <BOB_PUBLIC_KEY> "Hello, free world"

# Bob fetches and decrypts his inbox
AETHER_HOME=~/.aether_bob python client.py fetch http://<56charbase32>.onion
# → ✓ Signature verified  (green)
# → Content : Hello, free world
```

On Windows, replace `AETHER_HOME=~/.aether_bob` with `set AETHER_HOME=%USERPROFILE%\.aether_bob` before the command.

---

## Command Reference

| Command | Description |
|---------|-------------|
| `python client.py register` | Print your public identity key |
| `python client.py send <relay.onion> <pubkey> <msg>` | Encrypt, sign, and broadcast a message |
| `--ttl-seconds` (on `send`) | Seconds until the relay purges this message (default 7 days; see Data Retention) |
| `python client.py fetch <relay.onion>` | Fetch, verify, and decrypt your inbox (automatically queries every rotating identifier your address could have used within the relay's retention window; see Metadata-Hiding) |
| `--delete-after-read` (on `fetch`) | Delete each message from the relay immediately after it is verified and decrypted |
| `python client.py delete <relay.onion> <signature>` | Send a signed deletion request for one specific message |
| `--socks-host` / `--socks-port` (on `send`/`fetch`/`delete`) | Tor SOCKS5 proxy to use (default `127.0.0.1:9050`, or `$AETHER_SOCKS_HOST`/`$AETHER_SOCKS_PORT`) |
| `python relay.py --socket-path ./aether-relay.sock` | Start a relay node (persists to `aether.db`) |
| `python relay.py --socket-path ./aether-relay.sock --db :memory:` | Ephemeral in-memory relay |
| `--peers-file` / `--blacklist-file` | Gossip trust configuration (default `./peers.json`, `./blacklist.json`; see Federation) |
| `--gossip-socket-path` / `--gossip-transport` | Gossip listener socket and outbound transport (default `./aether-relay-gossip.sock`, `tor`; see Federation) |
| `--min-ttl` / `--max-ttl` / `--cleanup-interval` | TTL bounds enforced on every publish, and the background sweep interval that reaps expired messages (see Data Retention) |
| `--recipient-quota-max-messages` / `--recipient-quota-max-bytes` | Per-recipient storage ceiling, independent of any sender's rate limit (see Data Retention) |
| `python simulate_partition.py` | Run the 50-relay partition-resilience simulation (see Federation) |
| `python stress_test_quota.py` | Flood a relay with junk to validate per-recipient quota enforcement (see Data Retention) |
| `python stress_test_quota_multiday.py` | Demonstrate the per-day quota amplification with real captured numbers (see Data Retention) |
| `GET /health` | Relay liveness check; also reports `min_ttl_seconds`/`max_ttl_seconds` so clients can size their fetch lookback window (see Metadata-Hiding) |

---

## Why This Is Censorship-Resistant

AetherNode's resistance to censorship follows from its design rather than from any policy commitment. There are no accounts to suspend, since a user's identity consists of nothing more than two files stored locally in `~/.aether/`. The relay itself is blind: it stores encrypted bytes it has no ability to interpret, so no content policy can be applied to content nobody can read. Because anyone can operate a relay, the failure or seizure of a single node no longer breaks delivery at all: relays gossip what they receive to their trusted peers, so a message posted to a now-unreachable relay is very likely already sitting on several others, and a client only has to point at a different `.onion` address to keep going. The protocol itself constitutes the network, rather than any particular server within it. And because a relay has no public address at all, reachable only through its Tor hidden service, there is no IP address to filter and no server to seize in order to take it offline.

---

## Security Properties

| Property | Implementation |
|----------|----------------|
| End-to-end encryption | AES-256-GCM; only the recipient's RSA private key can decrypt |
| Tamper-evident | RSA-PSS signature covers the entire payload; any modification breaks verification |
| Zero-knowledge relay | Relay stores ciphertext blobs; signature check reveals nothing about content |
| Integrity of AES plaintext | GCM auth tag detects any ciphertext corruption before decryption |
| Identity portability | Keypair is a PEM file, easy to back up, move, and run on any machine |
| No metadata leakage | No usernames, emails, or phone numbers. The relay never receives or stores a recipient's raw public key on the publish path |
| Rotating recipient addressing | Recipients are addressed by `HMAC-SHA256(pubkey, UTC calendar day)`, not a static hash, so a passive observer with database access and no specific user's public key can only ever cluster one day's traffic, not a user's whole retention-window history. See Metadata-Hiding for the precise, honestly-scoped threat model — what this does and does not protect against |
| Replay/duplicate protection | `signature` is `UNIQUE` in the relay's database; re-submitting a captured payload is rejected with `409` instead of duplicating the message |
| Transport anonymity | The relay has no public IP or port; it binds a Unix socket only, reachable exclusively through a Tor v3 hidden service. The client hard-rejects any target that isn't a `.onion` address, and routes every request through Tor's SOCKS5 proxy with remote, in-Tor hostname resolution |
| Traffic-size unlinkability | Every plaintext is padded to one of `{4 KB, 16 KB, 64 KB}` before AES-256-GCM encryption, so ciphertext length alone can't distinguish a short message from a long one |
| Defense-in-depth transport enforcement | The `.onion`-only requirement is checked both at the command-line entry point and again immediately before any network request is made, so importing `client.py` as a library cannot bypass it |
| Concurrency safety | The relay holds an exclusive lock on its socket path for its entire lifetime; a second instance started against the same path refuses to run rather than silently taking over, or deleting, the first instance's socket |
| Peer authentication (mutual TLS) | Every relay has its own self-signed X.509 identity, entirely separate from any end-user identity. Gossip connections require both sides to present a certificate matching a pinned peer entry; there is no certificate authority, so trust is explicit and operator-curated rather than delegated |
| Peer blacklisting | A relay's blacklist is checked immediately after every gossip handshake, before any request is processed, and is re-read fresh on every connection, so revoking a peer's trust takes effect without restarting the relay |
| Bounded gossip propagation | The same `UNIQUE` constraint on `signature` that gates client-facing replay protection also gates re-gossip: a relay that already holds a message is a silent no-op on receipt and propagates nothing further, which is what keeps total mesh traffic bounded instead of reflooding indefinitely |
| Publish rate limiting | A valid signature only proves some keypair signed a message, and keypairs are free to generate, so nothing about signing bounds volume. `/publish` and `/gossip/publish` are each gated by a global token bucket (a Sybil-resistant backstop, since minting new identities doesn't grow it) plus a smaller per-identity bucket (fairness, so one sender or peer can't consume the whole shared budget). Every rejection returns the same generic `429` regardless of which layer tripped, so a response can't be used as an oracle for how close the global budget is to exhausted |
| Cryptographic TTL enforcement | Every message carries a signed `expires_at` field; the relay independently bounds it with `--min-ttl`/`--max-ttl`, `POST /fetch` filters out anything already past expiry on every request, and a background sweep purges expired rows from disk on `--cleanup-interval` |
| Per-recipient storage quotas | `--recipient-quota-max-messages`/`--recipient-quota-max-bytes` bound one recipient's inbox independently of the sender-facing rate limiter, so a flood spread across many Sybil senders but addressed to a single victim is still capped; exceeding either returns `429` with a quota-specific error distinct from the rate limiter's |
| Recipient-authorized secure deletion | A message can only be deleted by a request signed with the private key matching its `recipient_id`; deletion propagates mesh-wide to trusted peers, and a delete that arrives before its target message is held as a pending request and resolved once the message's real, verified recipient is known, so a peer that merely observed a signature in transit cannot delete a message it doesn't own |
| Forensic-resistant delete (bounded) | `PRAGMA secure_delete` with a truncating journal mode overwrites deleted rows and journal pre-images at the SQLite level, defeating ordinary examination of the database file; this does not defend against SSD wear-leveling, filesystem journaling, swap, snapshot backups, or raw block-device access during an in-flight write |

---

## Architecture

```
relay.py      RelayUnixHTTPServer  (Python stdlib), AF_UNIX only, no TCP listener
                                    and no public interface. Tor forwards its onion
                                    service's HiddenServicePort to this socket file.
                                    An exclusive process lock prevents two instances
                                    from ever binding the same socket path.
              SQLite storage       (Python stdlib) — the single source of truth,
                                    shared by the client-facing and gossip listeners
              POST /publish  →  verify RSA-PSS sig → reject dup signature →
                                    enforce TTL bounds + recipient quota → store
                                    encrypted blob → fan out to trusted peers
              POST /fetch    →  return unexpired blobs matching any of a list of
                                    candidate rotating recipient_ids (POST, not GET
                                    with a query string, so a multi-day lookback
                                    never appears in a request log line)
              POST /delete   →  verify requester's signature → confirm-delete if
                                    owned, else record a pending request →
                                    fan out to trusted peers
              Background cleanup thread — purges expired messages and stale
                                    deletion_requests rows on --cleanup-interval,
                                    reclaims freed disk via incremental_vacuum

gossip.py     GossipUnixTLSServer  (Python stdlib + cryptography), a second AF_UNIX
                                    listener, TLS-wrapped for mutual authentication.
                                    Relay identity generation, peer trust store and
                                    blacklist, push fan-out on new inserts, and
                                    periodic anti-entropy pulls to reconcile state
                                    with peers that were offline for a push round

client.py     RSA-2048 keypair     (cryptography)
              AES-256-GCM encrypt  (cryptography — AESGCM), on padded plaintext
              RSA-OAEP key wrap    (cryptography)
              RSA-PSS sign/verify  (cryptography)
              ANSI terminal output (zero dependencies)
              SOCKS5-over-Tor      (PySocks) — all HTTP traffic to .onion relays,
                                    with the .onion address re-validated at the
                                    point of the network call itself

protocol.py   Shared constants     (Python stdlib) — padding bucket sizes and the
                                    derived maximum request size, imported by both
                                    relay.py and client.py so the two can never drift
                                    out of sync with each other
```

---

## Federation (Gossip)

Earlier versions of AetherNode were a star: a client published to one relay, and the recipient had to fetch from that same relay. If that relay went offline or was seized, the message was unreachable, and relays had no way to share what they held. AetherNode now replaces that star with a mesh. Each relay maintains a list of peers it trusts, and whenever it stores a genuinely new message, it forwards that message to every one of those peers in the background, without delaying its response to the client that published it. Consistency across the mesh is eventual rather than immediate: a relay is not required to have a message the instant it is published, only to converge on having it soon after. To make that convergence actually happen, and not merely propagate forward from whoever happened to be online at the time, each relay also periodically asks each of its peers for anything published since the last time they spoke, so a relay that was offline during a push round catches up rather than being permanently behind. A single deduplication mechanism drives all of this: every message carries a signature that is unique in each relay's database, and a relay that already holds a message is a silent no-op on receipt, which is what keeps the mesh's total traffic bounded instead of reflooding forever.

Gossip connections between relays are authenticated with genuine mutual TLS. Every relay generates its own self-signed X.509 certificate on first launch, stored separately from any end-user identity, and there is no certificate authority anywhere in the system: each relay is its own trust anchor, and an operator explicitly pins the certificates of the peers they choose to trust. A connecting relay that cannot present a certificate matching one of those pinned entries is refused during the handshake itself, before any request is ever read. An operator can revoke a peer's trust at any time by adding its certificate's fingerprint to a blacklist file, which every relay re-reads on each incoming connection, so the change takes effect immediately rather than requiring a restart.

Configuring federation means generating a relay identity, publishing a second Tor hidden service for gossip traffic, and hand-building a `peers.json` listing the relays to trust:

```bash
# Start the relay once so it generates its own gossip identity and prints its fingerprint
python relay.py --socket-path ./aether-relay.sock

# Hand the printed fingerprint and ./aether-relay-identity/relay_cert.pem to a peer
# operator out of band, and receive theirs in return, then build peers.json:
cat > peers.json <<'EOF'
{
  "version": 1,
  "peers": [
    {
      "label": "relay-partner",
      "transport": "tor",
      "onion": "<their 56-char onion address>",
      "gossip_port": 8443,
      "cert_file": "peers/relay-partner.pem",
      "fingerprint": "<the fingerprint they gave you>"
    }
  ]
}
EOF
```

A relay's own gossip transport defaults to `tor`, dialing peers through the same local SOCKS5 proxy the client uses, which keeps the "no public IP anywhere in the system" guarantee intact for relay-to-relay traffic as well as client-to-relay traffic. There is a second transport, `direct`, which opens same-host Unix sockets to peers with no Tor or SOCKS5 involved at all. It exists solely for `simulate_partition.py` and equivalent same-host testing, and it is deliberately hard to enable by accident: choosing it requires both the `--gossip-transport direct` flag and the environment variable `AETHERNODE_UNSAFE_DIRECT_GOSSIP_TEST_ONLY=1` to be set at the same time, and a relay refuses to start if only one of the two is present. Using `direct` transport against any real, remote peer defeats the entire point of routing everything through Tor and must never be done outside a same-host simulation.

A relay signing a message only proves that some keypair produced it, and keypairs cost nothing to generate, so publishing itself has to be rate limited independently of trust. Six flags tune this: `--publish-rate-limit` and `--publish-rate-limit-per-sender` govern client-facing `/publish`, `--gossip-push-rate-limit` and `--gossip-push-rate-limit-per-peer` govern incoming `/gossip/publish` pushes, and `--gossip-pull-rate-limit` and `--gossip-pull-rate-limit-per-peer` govern anti-entropy catch-up, which is deliberately given a much larger budget since a single legitimate reconciliation pass can legitimately return hundreds of messages at once. The defaults are conservative starting points for a small deployment; an operator running a busier relay should raise them, and can watch the relay's own log output for rate-limit rejections to tell whether the defaults are too tight for their traffic.

A 50-relay simulation, `simulate_partition.py`, validates the resilience this section describes: it launches 50 relays wired into a full mesh over the `direct` test transport, posts messages spread across many different origin relays, kills half of the mesh at random, and confirms every posted message is still recoverable from the surviving half. It requires a Linux, macOS, or WSL host, for the same reason the relay itself does, and is run with `python simulate_partition.py`; it prints a pass or fail table and exits with a matching status code.

---

## Data Retention (TTL, Quotas, and Deletion)

Every message a client sends carries a signed expiration timestamp, `expires_at`, chosen by the sender through `--ttl-seconds` on `send` (seven days by default) and covered by the same RSA-PSS signature that protects every other field, so a relay or an on-path party cannot extend a message's lifetime without invalidating its signature. The relay independently enforces its own bounds on that value through `--min-ttl` and `--max-ttl`, rejecting anything that expires sooner than the minimum or later than the maximum regardless of what the client requested, and `POST /fetch` filters out anything already past its expiration on every single request rather than trusting a periodic sweep to have already caught it. That sweep runs anyway, on a background thread governed by `--cleanup-interval`, purging expired rows and reclaiming their disk space so the database does not merely stop returning old messages but actually shrinks over time.

Storage is additionally bounded per recipient rather than only in aggregate, since a flood of messages addressed to one victim is a meaningfully different attack from a flood spread across many recipients, and the existing publish rate limiting protects the relay's overall ingestion rate without protecting any single inbox's capacity. `--recipient-quota-max-messages` and `--recipient-quota-max-bytes` are a single ceiling an operator sets once for the whole relay, applied identically to every `recipient_id` it ever sees rather than configured per address, counting every physically stored row regardless of whether it has expired yet, since counting only unexpired rows would let a sender request the shortest allowed TTL repeatedly and slip past the cap between sweeps while still consuming real disk in the meantime. A publish or gossip push that would exceed either limit is rejected with `429` and a quota-specific error message, distinct from the rate limiter's own `429`, so operators and tooling can tell the two apart; an anti-entropy pull that encounters a full recipient simply skips that one message rather than stalling the whole reconciliation pass, on the reasoning that the recipient can still obtain it from any other relay in the mesh that still has room. Because the ceiling is shared, the property that actually matters is isolation rather than any one recipient being exempt: one recipient's inbox filling up must never consume or block a completely unrelated recipient's own, independent headroom under that same limit.

Recipient addressing rotates daily (see Metadata-Hiding below), and the relay is deliberately never told which rotating value belongs to which real recipient — which means this quota, keyed on that same rotating value, is honestly a per-(recipient, day) ceiling rather than a lifetime one. An attacker who knows a victim's public key, the same information required to message them at all, can precompute every day-bucket within the retention window right now and flood all of them in one short burst; there is no need to wait out real days. The realizable worst case for one recipient is `--recipient-quota-max-messages` (or `--recipient-quota-max-bytes`) multiplied by `ceil(--max-ttl / 1 day)`, reachable in a matter of hours at the default rate limits rather than the full `--max-ttl` window an operator skimming `--help` might otherwise assume. This is not fixed here — doing so would require reintroducing a second, non-rotating identifier for quota purposes, which would let a passive observer correlate a recipient's history through that field instead and defeat the entire point of rotation. The relay prints the computed worst-case bound in its own startup banner so this number is never buried in documentation alone, and keeping `--max-ttl` small is the direct lever an operator has if this quota needs to function as a meaningful DoS backstop rather than a loose one. `stress_test_quota_multiday.py`, in the results table further below, demonstrates this precisely with real captured numbers.

A recipient can also force deletion of a specific message directly, using `python client.py delete <relay.onion> <target_signature>` or the `--delete-after-read` flag on `fetch`, which issues the same request automatically for every message immediately after it is successfully verified and decrypted. The request is signed by the recipient's own private key, proving ownership of the address the message was sent to without revealing anything the relay could not already see, and a relay that confirms a deletion propagates the same request to every peer it trusts, so the message is removed mesh-wide rather than only from the relay that happened to receive the request. Because a delete can arrive at a relay before the message it targets does, given gossip's eventual consistency, a request for a signature the relay does not yet hold is recorded as pending rather than ignored, and is resolved the moment the message actually arrives and its real recipient can be checked against the request's claimed identity; only a match results in the message being discarded, so a relay or peer that merely observed a signature in transit cannot use that alone to delete a message it does not own. Deletion at the SQLite level uses `secure_delete` together with a truncating journal mode, so a deleted row's bytes are overwritten in the database file itself rather than left in a freed-but-unreclaimed page or a recoverable journal pre-image. This protects against ordinary examination of the database file; it does not protect against recovery from SSD wear-leveling or block remapping, filesystem journaling, swap, snapshot-style backups, or an examiner with raw block-device access catching an in-flight write.

Three scripts validate the claims above against a real relay rather than leaving them as assertions: `simulate_partition.py` confirms the mesh keeps delivering after a partition; `stress_test_quota.py` confirms the storage quota's isolation property; `stress_test_quota_multiday.py` confirms the per-day amplification arithmetic is the real worst case, not just the documented one. All three require a Linux, macOS, or WSL host for `AF_UNIX`, run as `python <script>.py`, and also run automatically in CI on every push (see Continuous Integration) — the results below are that CI run's own captured output, at the reduced-but-real scale CI uses by default.

| Script | Scale | Result |
|---|---|---|
| `simulate_partition.py` | 12 relays, full mesh, 15 messages, 6 killed at random | All 15 messages recovered from the 6 survivors — `PASS` |
| `stress_test_quota.py` | 600 messages, two recipients, quota = 200 | Recipient A: 200 accepted / 100 rejected. Recipient B: 200 accepted / 100 rejected. Zero cross-interference — `PASS` |
| `stress_test_quota_multiday.py` | 5 forged day-buckets, quota = 40/day | 40/40 accepted on each of 5 days; 200 total against the documented worst case of 200 — exact match — `CONFIRMED` |

Running any of these at production scale (`workflow_dispatch` with `full_scale`, or directly and manually) reproduces the same properties against ten thousand messages and a fifty-relay mesh instead; `stress_test_quota_multiday.py`'s five-day retention window is a deliberately fixed demonstration size at both scales, kept short so the run finishes quickly rather than scaled with the others, with only its per-day message count and quota rising to 250 and 200. The numbers above are proof the mechanism works, not the ceiling of what it was built to handle.

---

## Metadata-Hiding (Rotating Recipient Identifiers)

Every message was previously addressed with `recipient_id = SHA-256(recipient_pubkey)`, a static, unkeyed hash that never changed. Anyone who ever learned a user's public key could compute this once, and anyone with access to the relay's database, logs, or a seized or backed-up copy of either could then trivially cluster every message ever sent to that recipient just by grouping rows on the repeated value, with no cryptographic effort and no need to have ever been told any specific person's key. The relay still could not read message content, and still cannot; what was exposed was the shape of who receives how much, how often, and for how long. `recipient_id` is now computed as `HMAC-SHA256(key=recipient_pubkey_der, msg=<UTC calendar day, "YYYY-MM-DD">)`, computed independently by sender and recipient from their own clocks, with no server involvement in the derivation.

Stated precisely, since a mechanism like this is easy to oversell: this protects a passive observer with database or log access who has never been given any specific user's public key. Under the previous static scheme such an observer could cluster a recipient's entire retained message history for free; under rotation, the same passive grouping only ever reveals that messages sent on the same UTC day belong to the same recipient, collapsing correlation to a single day instead of the whole retention window. It does not protect against an active adversary who already has, or later obtains, the target's public key. A public key is not a secret — sharing it is how anyone messages that person in the first place — so such an adversary can always recompute every candidate day within a relay's retention window, at most a few dozen fast HMAC calls, and fully reconstruct history regardless of rotation. Rotation raises the bar only for someone who never had the key to begin with, never for someone who does.

Three further limitations are deliberately not solved by this mechanism, because solving any of them would require a materially larger, separate design, and each is stated here rather than left to be discovered:

Using `client.py delete` or `fetch --delete-after-read` reveals your permanent public key to the relay and, through mesh propagation, to every trusted peer, because authorizing a deletion requires verifying a signature made with that same real key — there is no way to prove ownership of a rotating address without revealing the key it was derived from. Both commands print an explicit warning to this effect before sending anything.

`sender_pubkey` is stored in the clear and never rotates. A passive observer can group by it and reconstruct which day-buckets a given sender touched across the full retention window, which for an ongoing two-party conversation, the common case, substantially reconstructs who is talking to whom even though the recipient's address rotates — the observer does not need the recipient's public key at all if the sender's is doing the correlating for them. Hiding `sender_pubkey` from the relay is a separate, larger problem: the relay's own anti-spam rate limiter depends on seeing it, and RSA-PSS verification fundamentally requires the real signing key as input. There is no rotating pseudonym scheme for a signer that does not also break either the relay's spam defense or the recipient's ability to verify who sent a message.

Rotation happens at a synchronized UTC-day boundary for every user at once, rather than staggered per user, deliberately: everyone's addresses changing at the same instant is better for anonymity-set mixing than would be leaking each individual's own rotation-timing pattern. This has two honest costs worth naming rather than glossing over. A predictable bump in request volume clusters right after 00:00 UTC as active clients recompute their addresses and re-fetch, a coarse traffic-timing signal at the level of overall relay load. And the realized protection window for any given message ranges from nearly zero, for a message sent at 23:59:59 UTC, to nearly a full day, for one sent a second after midnight — "about a day" is an average, not a guaranteed minimum.

A message can live up to `--max-ttl` after being sent, but its address still only rotates daily, so retrieving a full inbox means asking for every day's candidate identifier within that window, not just today's. `POST /fetch` accepts a JSON body of candidate `recipient_id` values rather than a single one, capped at whatever the relay's own configured `--max-ttl` actually requires (one per day in the window, plus a one-day buffer) rather than a fixed number — a fixed cap would silently break every fetch the moment an operator configured a longer retention window than that cap anticipated. `client.py fetch` discovers how far back to look the same way, by calling `GET /health`, which now reports the relay's configured `--min-ttl`/`--max-ttl`, and computes one candidate identifier for every day back through that window plus a one-day buffer for clock skew, all in a single request. This had to be a `POST` with a JSON body rather than a `GET` with a query string carrying all those candidates: `RelayHandler`'s inherited request logging prints the full request line, and a `GET` with dozens of candidate identifiers in the query string would hand anyone with log access the complete linkage across all of them in one line — a worse leak than the static address it replaces, which at least required noticing recurrence across many separate log lines over the whole retention window. Deleting a specific message has the same day-search problem in reverse: since a message is looked up by its unique `signature`, not by `recipient_id`, authorizing a delete tries every day the requester's own key could plausibly have produced within the retention window and checks the found row against that small, bounded set, rather than the relay ever being told which day was used.

This release breaks the wire format again, consistent with every earlier one: `recipient_id` values computed under the old static scheme will never be recomputed by any client again, so messages already stored under it become permanently unfetchable. Delete any existing `aether.db` before running this version, same as every prior schema-touching release.

---

## Deployment (Tor Hidden Service)

`relay.py` never communicates with Tor directly; it does nothing more than bind Unix domain sockets. Tor itself, configured through `torrc`, is responsible for publishing them as a v3 hidden service — one `HiddenServicePort` for the client-facing socket, and a second one, on a different virtual port, for the gossip socket. Both live under the same `.onion` address.

```
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/aethernode/
HiddenServicePort 80 unix:/path/to/aether-relay.sock
HiddenServicePort 8443 unix:/path/to/aether-relay-gossip.sock
```

```bash
sudo systemctl restart tor
cat /var/lib/tor/aethernode/hostname   # your relay's <56chars>.onion address
```

Both socket files must exist before Tor attempts to forward to them, which means `relay.py` needs to have started at least once, and each must be readable and writable by whichever user Tor runs as, such as `debian-tor` on Debian and Ubuntu or `_tor` on macOS installed via Homebrew. The simplest way to satisfy this is to place the relay process and the Tor process in the same group, or to adjust the permission bits `relay.py` sets on each socket accordingly. If both services are managed by systemd, order the relay's unit before Tor's so the sockets already exist by the time Tor starts.

On startup, `relay.py` acquires an exclusive advisory lock tied to each socket path before it binds anything. If a previous instance is still running against the same path, whether because of an accidental double launch or because a process manager restarted the relay while the old instance was still shutting down, the new process refuses to start rather than silently taking over, or deleting, a socket that another instance still depends on. Because each lock is held by the operating system for the lifetime of the process, it is released automatically if the relay crashes or is killed, so it can never go stale and never requires manual cleanup.

---

## Dependency

```
pip install -r requirements.txt
```

AetherNode depends on two third-party packages, both listed in `requirements.txt`. The `cryptography` library provides every cryptographic primitive used across the project: signature verification in `relay.py`, the full encryption and signing pipeline in `client.py`, and relay identity and certificate generation in `gossip.py`. `PySocks` is used by `client.py` to speak the SOCKS5 protocol to Tor, and, since a relay now dials its own peers over Tor to gossip, by `relay.py` as well when running in the default `tor` gossip transport; a relay running purely in the test-only `direct` transport never needs it. `protocol.py`, which holds the padding bucket sizes and the derived request-size limit shared between `client.py` and `relay.py`, depends on nothing beyond the Python standard library. Everything else involved, including the HTTP server, SQLite storage, JSON handling, TLS, and socket plumbing, comes from the standard library that ships with Python. Python 3.11 or newer is required, since the codebase uses the `X | Y` union-type annotation syntax throughout and relies on 3.11's more permissive `datetime.fromisoformat` parsing; this is enforced in practice by the CI matrix described below rather than a version check anywhere in the code itself.

---

## Continuous Integration

Every push and pull request against `main` runs two jobs, defined in `.github/workflows/ci.yml`. The first, smoke, runs `smoke_test.py` across a matrix of Linux, macOS, and Windows on Python 3.11 through 3.13; this is pure logic and real on-disk SQLite with no sockets involved, so it genuinely runs everywhere and finishes in seconds, and it is what actually caught this project's Windows-importability requirements being honest rather than aspirational. The second, integration, runs only on Linux, because it is the first environment in this project's history able to actually execute the AF_UNIX-dependent scripts that Windows sandboxes throughout this project's development could only ever compile-check: `simulate_partition.py`, `stress_test_quota.py`, and `stress_test_quota_multiday.py`, all launching real `relay.py` subprocesses over real Unix domain sockets. These run at a reduced scale by default so a normal push gets feedback in a few minutes rather than the better part of an hour; the same workflow accepts a manual `workflow_dispatch` run with `full_scale` set to exercise the full 50-relay, 10,000-message, 250-message-per-day-bucket versions these scripts were originally designed around. Both the reduced and full scale exercise the identical code paths and assertions — only the volume changes, controlled by environment variables (`AETHERNODE_SIM_NUM_RELAYS`, `AETHERNODE_STRESS_NUM_MESSAGES`, `AETHERNODE_AMPLIFICATION_MESSAGES_PER_DAY`) each script reads with its documented full-scale default preserved as the fallback for anyone running them directly and manually.

---

AetherNode is a reference implementation of the protocol rather than a hardened, production-ready deployment. A production deployment would additionally benefit from a retry queue for gossip pushes that fail on the first attempt rather than relying solely on the next anti-entropy pass to recover them, and from an anti-entropy backstop for deletion requests themselves, which today propagate mesh-wide only through the same best-effort fan-out as everything else and have no periodic reconciliation pass behind them the way messages do.

This release adds rotating, HMAC-based recipient addressing on top of earlier breaking changes: cryptographic TTL enforcement, per-recipient storage quotas, and recipient-authorized secure deletion; a relay no longer reachable over plain TCP/IP under any circumstance; padded message payloads; and a second socket for mutually-authenticated gossip between relays. `recipient_id` is no longer a permanent address, `GET /fetch` is now `POST /fetch` accepting a list of candidate identifiers, and `GET /health` reports the relay's TTL bounds. The `messages` table still has its `expires_at` column and the `deletion_requests` table from the prior release, unchanged in shape; only the meaning of `recipient_id`'s stored value has changed. Anyone upgrading from an earlier version should delete any existing `aether.db`, `aether-relay.sock`, and `aether-relay-gossip.sock`, and reconfigure Tor according to the Deployment section above, before running this version — messages addressed under the old static scheme will never be recomputed by any client again and are permanently unfetchable regardless.
