# AetherNode

> Zero-trust decentralized messaging. Your identity is a key. Your words are unreadable to the network.

---

## The Problem

Big Tech controls the pipes. Centralized servers can silence accounts, read private messages, hand data to governments, and erase entire conversations overnight. You do not own your communicationsthey do.

## The Solution

AetherNode removes the trusted third party entirely:

- **Identity is a keypair.** No username. No account. No phone number. Your RSA key *is* you.
- **Encryption is end-to-end.** Messages are AES-256 encrypted before they leave your machine. The relay sees ciphertext — always.
- **Censorship is structurally impossible.** The relay is a dumb bulletin board. It cannot read what it stores. Anyone can run one.
- **The network layer is anonymous.** All traffic runs over Tor v3 hidden services — there is no public IP to seize, block, or subpoena, and no network observer can see who is talking to whom.
- **Traffic looks uniform.** Every message is padded to a fixed size before encryption, so ciphertext length can't be used to guess whether it's a one-line reply or a document.

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

`relay.py` binds a Unix domain socket and requires Linux, macOS, or WSL — it has no public network interface at all. `client.py` runs anywhere Python + Tor are available (including native Windows) as long as it's pointed at a relay's `.onion` address. Tor must be installed and its SocksPort running (default `127.0.0.1:9050`) before using the client; see **Deployment** below for setting up the relay's hidden service.

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

> **Windows:** replace `AETHER_HOME=~/.aether_bob` with `set AETHER_HOME=%USERPROFILE%\.aether_bob` before the command.

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

- **No accounts.** There is nothing to ban. Your identity is two files in `~/.aether/`.
- **The relay is blind.** It stores encrypted bytes it cannot interpret. No content policy can apply to content no one can read.
- **Anyone can run a relay.** One node goes down? Point your client at another `.onion` address. The protocol *is* the network.
- **No IP to block.** The relay has no public address — it's only reachable through its Tor hidden service, which can't be blocked by filtering an IP or seizing a server.

---

## Security Properties

| Property | Implementation |
|----------|----------------|
| End-to-end encryption | AES-256-GCM; only the recipient's RSA private key can decrypt |
| Tamper-evident | RSA-PSS signature covers the entire payload; any modification breaks verification |
| Zero-knowledge relay | Relay stores ciphertext blobs; signature check reveals nothing about content |
| Integrity of AES plaintext | GCM auth tag detects any ciphertext corruption before decryption |
| Identity portability | Keypair is a PEM file — back it up, move it, run it on any machine |
| No metadata leakage | No usernames, emails, or phone numbers. Recipients are addressed by `SHA-256(recipient_pubkey)` — the relay never receives or stores a recipient's raw public key |
| Replay/duplicate protection | `signature` is `UNIQUE` in the relay's database; re-submitting a captured payload is rejected with `409` instead of duplicating the message |
| Transport anonymity | The relay has no public IP/port — it binds a Unix socket only, reachable exclusively through a Tor v3 hidden service. The client hard-rejects any target that isn't a `.onion` address, and routes every request through Tor's SOCKS5 proxy with remote (in-Tor) hostname resolution |
| Traffic-size unlinkability | Every plaintext is padded to one of `{4 KB, 16 KB, 64 KB}` before AES-256-GCM encryption, so ciphertext length alone can't distinguish a short message from a long one |

---

## Architecture

```
relay.py      RelayUnixHTTPServer  (Python stdlib), AF_UNIX only — no TCP listener,
                                    no public interface. Tor forwards its onion
                                    service's HiddenServicePort to this socket file.
              SQLite storage       (Python stdlib)
              POST /publish  →  verify RSA-PSS sig → reject dup signature → store encrypted blob
              GET  /fetch    →  return blobs by recipient_id (SHA-256 of recipient pubkey)

client.py     RSA-2048 keypair     (cryptography)
              AES-256-GCM encrypt  (cryptography — AESGCM), on padded plaintext
              RSA-OAEP key wrap    (cryptography)
              RSA-PSS sign/verify  (cryptography)
              ANSI terminal output (zero dependencies)
              SOCKS5-over-Tor      (PySocks) — all HTTP traffic to .onion relays
```

---

## Deployment (Tor Hidden Service)

`relay.py` never talks to Tor directly — it only binds a Unix socket. You configure Tor itself (via `torrc`) to publish that socket as a v3 hidden service:

```
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/aethernode/
HiddenServicePort 80 unix:/path/to/aether-relay.sock
```

```bash
sudo systemctl restart tor
cat /var/lib/tor/aethernode/hostname   # → your relay's <56chars>.onion address
```

The socket file must exist (i.e. `relay.py` must have started at least once) and be readable/writable by whichever user Tor runs as (e.g. `debian-tor` on Debian/Ubuntu, `_tor` on macOS Homebrew) — put the relay process and the Tor process in the same group, or adjust `os.chmod` in `relay.py` accordingly. Start `relay.py` before (or via the same systemd unit ordered before) Tor, so the socket exists when Tor tries to forward to it.

---

## Dependency

```
pip install -r requirements.txt
```

`cryptography` is used by both `relay.py` (signature verification) and `client.py` (all crypto). `PySocks` is used only by `client.py`, to speak SOCKS5 to Tor — the relay makes no outbound network calls and doesn't need it. Everything else — HTTP server, SQLite, JSON, base64, sockets — is Python standard library.

---

*AetherNode is a protocol reference implementation. For production: relay-to-relay gossip for redundancy, and message TTL / expiry policies.*

> **Note:** this is a breaking change from earlier versions — the relay is no longer reachable over plain TCP/IP at all, only via its Tor `.onion` address, and message payloads are now padded before encryption. Delete any pre-existing `aether.db` and `aether-relay.sock`, and reconfigure Tor per **Deployment** above, before running this version.
