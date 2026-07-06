# Keep Security Design

## The Vault File

Everything lives in one file: `~/.keep/vault.enc`

```
+------------------------------------------------------------------+
| salt (16 bytes) -- stored in the clear                            |
+------------------------------------------------------------------+
| AES-256-GCM sealed box                                            |
| +----------------------------------------------------------------+ |
| | nonce (12 bytes)                                                | |
| | ciphertext (encrypted SQLite database, variable size)           | |
| | GCM auth tag (16 bytes)                                        | |
| +----------------------------------------------------------------+ |
+------------------------------------------------------------------+
```

The salt is in the clear by design. Salt prevents rainbow table attacks --
it is not a secret. Anyone can read the salt from the file. They just
cannot do anything with it without the password.

## The Key Derivation Chain

```
Password (what you type)
    |
    v
Argon2id(password + salt)
  - 19 MB memory cost (fills CPU cache, kills GPU/ASIC attacks)
  - 3 iterations
  - OWASP-recommended minimum parameters
    |
    v
256-bit symmetric key
  - held in RAM only
  - NEVER written to disk
  - wiped on lock / auto-lock timeout
    |
    v
AES-256-GCM decrypts the outer envelope
    |
    v
SQLite database (decrypted, in memory only)
  +----------------------------------+
  | secrets table                    |
  | +------------------------------+ |
  | | name: "gh_token"             | |
  | | blob: [unique nonce +        | |
  | |        AES-256-GCM encrypted | |
  | |        secret value]         | |
  | +------------------------------+ |
  |                                  |
  | audit_log table                  |
  | +------------------------------+ |
  | | every get/set/list/delete    | |
  | | logged with timestamp + PID  | |
  | +------------------------------+ |
  +----------------------------------+
```

## Why Keep Is Secure

### 1. Password brute-forcing is impractical

Argon2id requires 19 MB of memory per single attempt. A high-end GPU
can do billions of SHA-256 attempts per second. With Argon2id at these
parameters, even an expensive GPU manages roughly 100-200 attempts per
second. And each attempt must also decrypt AES-GCM to verify success --
AES-GCM will return an authentication failure for any wrong key, and
there is no way to distinguish "wrong password" from "corrupt file"
without the correct key.

### 2. The key never touches disk

The 256-bit AES key is derived in memory when you unlock the vault. It
is held in RAM only. When you lock the vault or the auto-lock timer
fires, the key is overwritten in memory and released. If someone steals
your laptop while it is locked, they get the vault file and nothing
else. Without the password, the vault file is useless.

### 3. Every secret gets its own encryption

Each secret value is encrypted with a unique AES nonce (12 random bytes).
Even if two secrets have identical values -- for example, you store
"password123" under two different names -- their ciphertexts will be
completely different. An attacker cannot tell which secrets share the
same value, or even which secrets have been updated.

### 4. The audit log is inside the encrypted envelope

To see who accessed what and when, you must unlock the vault. An
attacker who only has the vault file cannot read the audit log because
it is encrypted alongside the secrets. The audit records every get,
set, list, delete, rotate, export, and env call with a timestamp and
process ID.

### 5. Auto-lock on inactivity

The AES key is held in memory with a 15-minute timer that resets on
every vault access (get, set, list, etc). If you walk away from your
computer, the vault locks itself and wipes the key from memory. The
timer runs inside the app process -- no external daemon, no polling.

### 6. Shared file format across app and CLI

The Swift macOS app and the Python CLI use the exact same file format.
You can run `keep set db_pass x` in a terminal, open the app, and see
the secret there. Or set a secret in the app and retrieve it from a
script with `keep get`. The vault file is byte-for-byte compatible
between the two implementations.

## What Keep Does NOT Protect Against

- **Keylogging while the vault is unlocked.** If an attacker has remote
  access to your running machine, they can read secrets through the app
  UI or the REST API.

- **Physical memory capture (cold boot attacks).** The AES key lives in
  RAM while the vault is unlocked. Freezing RAM chips to read them is a
  known attack vector. Mitigation would require mlock() to prevent the
  key from being paged to swap (not yet implemented in the Swift app).

- **A weak master password.** Argon2id makes brute-force expensive but
  not impossible. A dictionary-word password with 4-5 characters can
  still be cracked given enough time and hardware. Pick a strong
  password.

## Why Not Use the macOS Keychain?

The macOS Keychain ties secrets to a specific Apple ID, machine, and
user login session. Keep is portable:

- Same vault file works on macOS, Linux, or any Unix
- Python CLI works headless on a server via SSH
- The macOS app gives you a GUI for the same local file
- The Keychain cannot be accessed from cron jobs or automated scripts
- Keep's vault file can be backed up, synced, or moved between machines

Keep is designed for the specific use case of AI agents and automation
scripts that need credentials at runtime without human interaction.
