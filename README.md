# AetherNode

> Zero-trust decentralized messaging. Your identity is a key. Your words are unreadable to the network.

---

## The Problem

Centralized messaging infrastructure concentrates an extraordinary amount of trust in a small number of operators. A centralized server can suspend an account without appeal, read the content of private conversations, hand user data to a government on request, or erase an entire conversation history overnight. Users of such systems do not own their communications; the operator does. AetherNode is designed to remove that operator from the trust model entirely.

## The Solution

AetherNode achieves this by eliminating the trusted third party at every layer of the system. Identity is represented by a cryptographic keypair rather than a username, an account, or a phone number; possession of the private key is the only form of authentication the protocol recognizes. Every message is encrypted end to end with AES-256 before it ever leaves the sender's machine, so the relay that transports it handles nothing but ciphertext. Because the relay functions as a blind bulletin board with no ability to read what it stores, and because anyone is free to operate one, no single party is in a position to censor the network. The network layer itself is anonymized, since all traffic between clients and relays travels exclusively over Tor v3 hidden services, meaning there is no public IP address to seize, block, or subpoena, and no network observer can determine who is communicating with whom. Finally, every message is padded to a fixed size before encryption, so the length of the resulting ciphertext cannot be used to distinguish a short acknowledgment from a lengthy document.

---

## Cryptographic Flow

```
  Barack                          Relay                           Mbondo
  ─────                            ─────                           ───

  "Hello, Mbondo"
       │
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
  │  RSA-PSS Sign   │ ◄─ Barack Private Key
  │  Full payload   │
  └────────┬────────┘
           │
           ▼
      POST /publish ──────────────► Verify signature only    ──────► GET /fetch
                                    Store encrypted blob                  │
                                    (cannot read, cannot forge)           ▼
                                                                 Verify RSA-PSS ✓
                                                                          │
                                                                 RSA-OAEP unwrap AES key
                                                                          │
                                                                 AES-256-GCM decrypt
                                                                          │
                                                                          ▼
                                                                    "Hello, Mbondo"
```

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
| `python client.py fetch <relay.onion>` | Fetch, verify, and decrypt your inbox |
| `--socks-host` / `--socks-port` (on `send`/`fetch`) | Tor SOCKS5 proxy to use (default `127.0.0.1:9050`, or `$AETHER_SOCKS_HOST`/`$AETHER_SOCKS_PORT`) |
| `python relay.py --socket-path ./aether-relay.sock` | Start a relay node (persists to `aether.db`) |
| `python relay.py --socket-path ./aether-relay.sock --db :memory:` | Ephemeral in-memory relay |
| `GET /health` | Relay liveness check |

---

## Why This Is Censorship-Resistant

AetherNode's resistance to censorship follows from its design rather than from any policy commitment. There are no accounts to suspend, since a user's identity consists of nothing more than two files stored locally in `~/.aether/`. The relay itself is blind: it stores encrypted bytes it has no ability to interpret, so no content policy can be applied to content nobody can read. Because anyone can operate a relay, the failure or seizure of a single node simply means pointing a client at a different `.onion` address; the protocol itself constitutes the network, rather than any particular server within it. And because a relay has no public address at all, reachable only through its Tor hidden service, there is no IP address to filter and no server to seize in order to take it offline.

---

## Security Properties

| Property | Implementation |
|----------|----------------|
| End-to-end encryption | AES-256-GCM; only the recipient's RSA private key can decrypt |
| Tamper-evident | RSA-PSS signature covers the entire payload; any modification breaks verification |
| Zero-knowledge relay | Relay stores ciphertext blobs; signature check reveals nothing about content |
| Integrity of AES plaintext | GCM auth tag detects any ciphertext corruption before decryption |
| Identity portability | Keypair is a PEM file, easy to back up, move, and run on any machine |
| No metadata leakage | No usernames, emails, or phone numbers. Recipients are addressed by `SHA-256(recipient_pubkey)`, so the relay never receives or stores a recipient's raw public key |
| Replay/duplicate protection | `signature` is `UNIQUE` in the relay's database; re-submitting a captured payload is rejected with `409` instead of duplicating the message |
| Transport anonymity | The relay has no public IP or port; it binds a Unix socket only, reachable exclusively through a Tor v3 hidden service. The client hard-rejects any target that isn't a `.onion` address, and routes every request through Tor's SOCKS5 proxy with remote, in-Tor hostname resolution |
| Traffic-size unlinkability | Every plaintext is padded to one of `{4 KB, 16 KB, 64 KB}` before AES-256-GCM encryption, so ciphertext length alone can't distinguish a short message from a long one |
| Defense-in-depth transport enforcement | The `.onion`-only requirement is checked both at the command-line entry point and again immediately before any network request is made, so importing `client.py` as a library cannot bypass it |
| Concurrency safety | The relay holds an exclusive lock on its socket path for its entire lifetime; a second instance started against the same path refuses to run rather than silently taking over, or deleting, the first instance's socket |

---

## Architecture

```
relay.py      RelayUnixHTTPServer  (Python stdlib), AF_UNIX only, no TCP listener
                                    and no public interface. Tor forwards its onion
                                    service's HiddenServicePort to this socket file.
                                    An exclusive process lock prevents two instances
                                    from ever binding the same socket path.
              SQLite storage       (Python stdlib)
              POST /publish  →  verify RSA-PSS sig → reject dup signature → store encrypted blob
              GET  /fetch    →  return blobs by recipient_id (SHA-256 of recipient pubkey)

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

## Deployment (Tor Hidden Service)

`relay.py` never communicates with Tor directly; it does nothing more than bind a Unix domain socket. Tor itself, configured through `torrc`, is responsible for publishing that socket as a v3 hidden service.

```
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/aethernode/
HiddenServicePort 80 unix:/path/to/aether-relay.sock
```

```bash
sudo systemctl restart tor
cat /var/lib/tor/aethernode/hostname   # your relay's <56chars>.onion address
```

The socket file must exist before Tor attempts to forward to it, which means `relay.py` needs to have started at least once, and it must be readable and writable by whichever user Tor runs as, such as `debian-tor` on Debian and Ubuntu or `_tor` on macOS installed via Homebrew. The simplest way to satisfy this is to place the relay process and the Tor process in the same group, or to adjust the permission bits `relay.py` sets on the socket file accordingly. If both services are managed by systemd, order the relay's unit before Tor's so the socket already exists by the time Tor starts.

On startup, `relay.py` acquires an exclusive advisory lock tied to its socket path before it binds anything. If a previous instance is still running against the same path, whether because of an accidental double launch or because a process manager restarted the relay while the old instance was still shutting down, the new process refuses to start rather than silently taking over, or deleting, a socket that another instance still depends on. Because the lock is held by the operating system for the lifetime of the process, it is released automatically if the relay crashes or is killed, so it can never go stale and never requires manual cleanup.

---

## Dependency

```
pip install -r requirements.txt
```

AetherNode depends on two third-party packages, both listed in `requirements.txt`. The `cryptography` library provides every cryptographic primitive used by `relay.py`, for signature verification, and by `client.py`, for the full encryption and signing pipeline. `PySocks` is used exclusively by `client.py` to speak the SOCKS5 protocol to Tor; the relay makes no outbound network connections of its own and does not require it. `protocol.py`, which holds the padding bucket sizes and the derived request-size limit shared by both programs, depends on nothing beyond the Python standard library. Everything else involved, including the HTTP server, SQLite storage, JSON handling, and socket plumbing, comes from the standard library that ships with Python.

---

AetherNode is a reference implementation of the protocol rather than a hardened, production-ready deployment. A production deployment would additionally benefit from relay-to-relay gossip for redundancy and from a message expiry policy bounding how long a relay retains undelivered messages.

This release contains two breaking changes relative to earlier versions. The relay is no longer reachable over plain TCP/IP under any circumstance; it is reachable exclusively through its Tor `.onion` address. Message payloads are now padded before encryption, which changes their size on the wire. Anyone upgrading from an earlier version should delete any existing `aether.db` and `aether-relay.sock`, and reconfigure Tor according to the Deployment section above, before running this version.
