# Keep — Project Plan

**An encrypted secrets vault designed for AI agents and the humans who run them.**

---

## Why

Every agent needs credentials. API keys, tokens, cookies, passwords. Right now they live in `.env` files, config files, or plaintext in scripts. Your security brief flags this every time. Keep is the remediation — a single encrypted vault with one master password.

## Security

- **AES-256-GCM** — authenticated encryption, tamper-proof, NIST-standard
- **Argon2id** — memory-hard key derivation, OWASP-recommended minimum (19MB memory, 3 iterations)
- **Per-secret unique nonce** — every encryption uses a fresh random nonce
- **Audit log** — every access recorded (who, what, when)
- **Auto-lock** — master key wiped from memory after 15min inactivity
- **Key never written to disk** — derived at unlock, held only in RAM
- **Vault file locked to 0600** — owner-only permissions
- **Wrong password detection** — Argon2id + AES-GCM auth tag prevents brute force

## Architecture

```
~/.keep/vault.enc

File format:
  [salt: 16 bytes][nonce: 12 bytes][AES-256-GCM encrypted SQLite DB: rest]

In-memory (unlocked):
  SQLite database with encrypted_blob column
  Each secret value encrypted with its own nonce
  Audit log inside the same database
```

## CLI

| Command | Description |
|---|---|
| `keep init` | Create a new vault (prompts for master password) |
| `keep unlock` | Unlock vault (derives key, holds in memory) |
| `keep lock` | Lock vault (wipes key from memory) |
| `keep status` | Show vault stats (secret count, lock state) |
| `keep set <name> <value>` | Encrypt and store a secret |
| `keep get <name>` | Decrypt and retrieve a secret |
| `keep list` | List secret names (values stay encrypted) |
| `keep delete <name>` | Remove a secret |
| `keep rotate <name>` | Generate + store a new random secret |
| `keep audit` | Show access log |
| `keep env` | Export as `export KEY=value` pairs |
| `keep serve` | Start REST API on localhost:7391 |

## REST API (agent mode)

```
POST /init          — Create vault
POST /unlock        — Unlock with password
POST /lock          — Lock and wipe key
GET  /secrets       — List names
GET  /secrets/:name — Get value
POST /secrets/:name — Set value
DELETE /secrets/:name
POST /secrets/:name/rotate
GET  /audit         — Access log
GET  /env           — All secrets as JSON
GET  /status        — Vault state
GET  /health        — Liveness
```

## Status

- **Python vault core:** ✅ AES-256-GCM, Argon2id, SQLite persistence, lock/unlock, audit
- **CLI:** ✅ All 12 commands implemented
- **REST API:** ✅ FastAPI server with 11 endpoints
- **Hermes skill:** Pending
- **GitHub repo:** Pending
- **Docker:** Not needed (single file, no server deps for CLI mode)

## Files

```
/Users/rotaryphone/fromthescope-actors/keep/
├── README.md
├── LICENSE (MIT)
├── pyproject.toml
├── test_vault.py
└── keep/
    ├── __init__.py
    ├── vault.py     # Core encryption, Argon2id, AES-256-GCM
    ├── cli.py       # CLI interface (argparse)
    └── server.py    # FastAPI REST API
```
