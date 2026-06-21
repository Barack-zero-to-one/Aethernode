# AetherNode

> Zero-trust decentralized messaging. Your identity is a key. Your words are unreadable to the network.

---

## The Problem

Big Tech controls the pipes. Centralized servers can silence accounts, read private messages, hand data to governments, and erase entire conversations overnight. You do not own your communications — they do.

## The Solution

AetherNode removes the trusted third party entirely:

- **Identity is a keypair.** No username. No account. No phone number. Your RSA key *is* you.
- **Encryption is end-to-end.** Messages are AES-256 encrypted before they leave your machine. The relay sees ciphertext — always.
- **Censorship is structurally impossible.** The relay is a dumb bulletin board. It cannot read what it stores. Anyone can run one.

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

```bash
pip install cryptography

# Terminal 1 — start the relay
python relay.py --port 8888

# Terminal 2 — Alice registers her identity
python client.py register
# → copy the base64 public key shown

# Terminal 3 — Bob registers (different identity dir for local testing)
AETHER_HOME=~/.aether_bob python client.py register
# → copy Bob's public key

# Alice sends an encrypted message to Bob
python client.py send http://localhost:8888 <BOB_PUBLIC_KEY> "Hello, free world"

# Bob fetches and decrypts his inbox
AETHER_HOME=~/.aether_bob python client.py fetch http://localhost:8888
# → ✓ Signature verified  (green)
# → Content : Hello, free world
```

> **Windows:** replace `AETHER_HOME=~/.aether_bob` with `set AETHER_HOME=%USERPROFILE%\.aether_bob` before the command.

---

## Command Reference

| Command | Description |
|---------|-------------|
| `python client.py register` | Print your public identity key |
| `python client.py send <relay> <pubkey> <msg>` | Encrypt, sign, and broadcast a message |
| `python client.py fetch <relay>` | Fetch, verify, and decrypt your inbox |
| `python relay.py --port 8888` | Start a relay node (persists to `aether.db`) |
| `python relay.py --port 8888 --db :memory:` | Ephemeral in-memory relay |
| `GET /health` | Relay liveness check |

---

## Why This Is Censorship-Resistant

- **No accounts.** There is nothing to ban. Your identity is two files in `~/.aether/`.
- **The relay is blind.** It stores encrypted bytes it cannot interpret. No content policy can apply to content no one can read.
- **Anyone can run a relay.** One node goes down? Point your client at another with `--relay`. The protocol *is* the network.

---

## Security Properties

| Property | Implementation |
|----------|----------------|
| End-to-end encryption | AES-256-GCM; only the recipient's RSA private key can decrypt |
| Tamper-evident | RSA-PSS signature covers the entire payload; any modification breaks verification |
| Zero-knowledge relay | Relay stores ciphertext blobs; signature check reveals nothing about content |
| Integrity of AES plaintext | GCM auth tag detects any ciphertext corruption before decryption |
| Identity portability | Keypair is a PEM file — back it up, move it, run it on any machine |
| No metadata leakage | No usernames, emails, or phone numbers — only public key hashes as addresses |

---

## Architecture

```
relay.py      ThreadingHTTPServer  (Python stdlib)
              SQLite storage       (Python stdlib)
              POST /publish  →  verify RSA-PSS sig → store encrypted blob
              GET  /fetch    →  return blobs by recipient pubkey

client.py     RSA-2048 keypair     (cryptography)
              AES-256-GCM encrypt  (cryptography — AESGCM)
              RSA-OAEP key wrap    (cryptography)
              RSA-PSS sign/verify  (cryptography)
              ANSI terminal output (zero dependencies)
              urllib HTTP client   (Python stdlib)
```

---

## Dependency

```
pip install cryptography
```

Everything else — HTTP server, SQLite, JSON, base64, sockets — is Python standard library.

---

*AetherNode is a protocol reference implementation. For production: add TLS on the relay, relay-to-relay gossip for redundancy, and message TTL / expiry policies.*
