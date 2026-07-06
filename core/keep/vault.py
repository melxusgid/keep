"""Keep vault — AES-256-GCM encrypted secrets database with Argon2id key derivation.

Vault file format:
  [salt: 16 bytes][nonce: 12 bytes][encrypted SQLite DB: rest]

The salt is stored in the clear (it's not a secret — it prevents rainbow tables).
The key is derived from password + salt using Argon2id.
Each secret inside the DB gets its own unique nonce on encryption.
"""

from __future__ import annotations

import io
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

VAULT_DIR = Path.home() / ".keep"
VAULT_PATH = VAULT_DIR / "vault.enc"
CONFIG_PATH = VAULT_DIR / "config.yaml"
DEFAULT_AUTO_LOCK = 900  # 15 minutes

NONCE_SIZE = 12
SALT_SIZE = 16
KEY_SIZE = 32   # 256-bit


class Error(Exception):
    pass

class LockedError(Error):
    pass

class CryptoError(Error):
    pass


def _derive_key(password: str, salt: bytes) -> bytes:
    if not HAS_CRYPTO:
        raise CryptoError("Install: pip install agent-keep[crypto]")
    return Argon2id(
        salt=salt,
        length=KEY_SIZE,
        memory_cost=19456,     # 19 MB — OWASP minimum
        iterations=3,          # 3 passes
        lanes=1,               # single thread
    ).derive(password.encode("utf-8"))


def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _decrypt(key: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], None)


class Vault:
    """Encrypted secrets vault backed by SQLite.

    File format on disk:
        [salt: 16B][nonce: 12B][encrypted SQLite dump: rest]

    The key is derived from password + salt via Argon2id and held
    in memory only while unlocked. Each secret inside the DB is
    individually AES-256-GCM encrypted with its own nonce.
    """

    def __init__(self, path: Optional[Path] = None):
        if path is None:
            path = VAULT_PATH
        if isinstance(path, str):
            path = Path(path)
        self.path = path
        self._key: Optional[bytes] = None
        self._conn: Optional[sqlite3.Connection] = None
        self._lock_timer: Optional[threading.Timer] = None
        self._auto_lock_seconds = DEFAULT_AUTO_LOCK
        self._audit_buffer: list[dict] = []
        self._init_dirs()

    def _init_dirs(self):
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Initialization ──────────────────────────────────────────────

    def init(self, password: str, name: str = "default") -> bool:
        """Create a new encrypted vault. Overwrites any existing vault."""
        if not HAS_CRYPTO:
            raise CryptoError("Install: pip install agent-keep[crypto]")

        salt = secrets.token_bytes(SALT_SIZE)
        key = _derive_key(password, salt)

        # Build the database in memory
        conn = sqlite3.connect(":memory:")
        conn.execute("PRAGMA journal_mode=OFF")
        conn.executescript(f"""
            CREATE TABLE meta (
                key TEXT PRIMARY KEY, value TEXT
            );
            INSERT INTO meta VALUES ('name', '{name}');
            INSERT INTO meta VALUES ('created', '{time.time()}');
            INSERT INTO meta VALUES ('version', '1');

            CREATE TABLE secrets (
                name TEXT PRIMARY KEY,
                encrypted_blob BLOB NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                metadata TEXT DEFAULT '{{}}'
            );

            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                secret_name TEXT,
                context TEXT,
                timestamp REAL NOT NULL
            );
        """)

        # Serialize DB, encrypt with outer envelope
        plaintext = self._dump_db(conn)
        encrypted = _encrypt(key, plaintext)
        self.path.write_bytes(salt + encrypted)
        self.path.chmod(0o600)

        conn.close()
        self._key = key
        self._load(plaintext)  # Load into memory
        self._log("init", "_vault")
        return True

    # ── Lock / Unlock ──────────────────────────────────────────────

    def unlock(self, password: str) -> bool:
        """Decrypt the vault and hold the key in memory."""
        if not self.path.exists():
            raise Error("No vault found at " + str(self.path))

        data = self.path.read_bytes()
        if len(data) < SALT_SIZE + NONCE_SIZE + 1:
            raise Error("Vault file is too small or corrupt")

        salt = data[:SALT_SIZE]
        key = _derive_key(password, salt)

        try:
            plaintext = _decrypt(key, data[SALT_SIZE:])
        except Exception as e:
            raise Error("Decryption failed — wrong password or corrupt vault") from e

        self._key = key
        self._load(plaintext)
        self._log("unlock", "_vault")
        self._bump_timer()
        return True

    def lock(self):
        """Lock the vault and wipe the master key from memory."""
        self._cancel_lock_timer()
        if self._conn:
            self._flush_audit()
            self._sync_to_disk()  # Persist audit entries
            self._conn.close()
            self._conn = None
        # Wipe key from memory
        if self._key:
            self._key = bytearray(len(self._key))
        self._key = None

    @property
    def locked(self) -> bool:
        return self._key is None

    # ── Secret operations ──────────────────────────────────────────

    def set(self, name: str, value: str, note: str = ""):
        """Encrypt and store a secret."""
        self._require_unlocked()
        now = time.time()
        meta = json.dumps({"note": note, "created": now})
        plaintext = json.dumps({"v": value, "note": note}).encode("utf-8")
        blob = _encrypt(self._key, plaintext)

        # Check if exists to preserve created_at
        existing = self._conn.execute(
            "SELECT created_at FROM secrets WHERE name=?", (name,)
        ).fetchone()
        created = existing[0] if existing else now

        self._conn.execute(
            "INSERT OR REPLACE INTO secrets "
            "(name, encrypted_blob, created_at, updated_at, metadata) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, blob, created, now, meta),
        )
        self._conn.commit()
        self._log("set", name)
        self._bump_timer()

    def get(self, name: str) -> Optional[str]:
        """Retrieve and decrypt a secret by name."""
        self._require_unlocked()
        row = self._conn.execute(
            "SELECT encrypted_blob FROM secrets WHERE name=?", (name,)
        ).fetchone()
        if not row:
            return None
        data = json.loads(_decrypt(self._key, row[0]).decode("utf-8"))
        self._log("get", name)
        self._bump_timer()
        return data["v"]

    def list(self) -> list[dict]:
        """List all secrets with metadata (values stay encrypted)."""
        self._require_unlocked()
        rows = self._conn.execute(
            "SELECT name, created_at, updated_at, metadata FROM secrets ORDER BY name"
        ).fetchall()
        self._log("list", "_all")
        self._bump_timer()
        return [
            {"name": r[0], "created_at": r[1], "updated_at": r[2], "metadata": json.loads(r[3])}
            for r in rows
        ]

    def delete(self, name: str) -> bool:
        """Delete a secret by name."""
        self._require_unlocked()
        cur = self._conn.execute("DELETE FROM secrets WHERE name=?", (name,))
        self._conn.commit()
        self._log("delete", name)
        self._bump_timer()
        return cur.rowcount > 0

    def rotate(self, name: str, length: int = 32) -> Optional[str]:
        """Generate a random secret and store it under the given name."""
        new_value = secrets.token_hex(max(length // 2, 16))
        self.set(name, new_value)
        self._log("rotate", name)
        return new_value

    def env(self) -> dict[str, str]:
        """Return all secrets as a flat dict (for exporting to environment)."""
        self._require_unlocked()
        result = {}
        for row in self._conn.execute("SELECT name FROM secrets").fetchall():
            val = self.get(row[0])
            if val is not None:
                result[row[0]] = val
        self._log("env", "_vault")
        return result

    def export(self) -> dict[str, str]:
        """Export all secrets in plaintext (use with extreme caution)."""
        return self.env()

    def import_secrets(self, secrets: dict[str, str]):
        """Bulk import secrets from a dict."""
        self._require_unlocked()
        for name, value in secrets.items():
            self.set(name, value)
        self._log("import", "_vault")

    # ── Audit ──────────────────────────────────────────────────────

    def _log(self, action: str, target: str, context: Optional[str] = None):
        self._audit_buffer.append({
            "action": action, "target": target,
            "context": context or f"pid:{os.getpid()}",
            "timestamp": time.time(),
        })
        if len(self._audit_buffer) >= 10:
            self._flush_audit()

    def _flush_audit(self):
        if not self._conn or not self._audit_buffer:
            return
        for e in self._audit_buffer:
            self._conn.execute(
                "INSERT INTO audit_log (action, secret_name, context, timestamp) "
                "VALUES (?, ?, ?, ?)",
                (e["action"], e["target"], e["context"], e["timestamp"]),
            )
        self._conn.commit()
        self._audit_buffer.clear()

    def audit(self, limit: int = 50) -> list[dict]:
        self._require_unlocked()
        rows = self._conn.execute(
            "SELECT action, secret_name, context, timestamp FROM audit_log "
            "ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            {"action": r[0], "secret_name": r[1], "context": r[2], "timestamp": r[3]}
            for r in rows
        ]

    def stats(self) -> dict:
        self._require_unlocked()
        secret_count = self._conn.execute(
            "SELECT COUNT(*) FROM secrets"
        ).fetchone()[0]
        audit_count = self._conn.execute(
            "SELECT COUNT(*) FROM audit_log"
        ).fetchone()[0]
        name = self._conn.execute(
            "SELECT value FROM meta WHERE key='name'"
        ).fetchone()
        return {
            "vault_name": name[0] if name else "default",
            "secret_count": secret_count,
            "audit_entries": audit_count,
            "locked": self.locked,
            "path": str(self.path),
        }

    # ── Internal ───────────────────────────────────────────────────

    def _load(self, plaintext: bytes):
        """Load a serialized SQLite DB into memory."""
        import tempfile
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            with open(tmp.name, "wb") as f:
                f.write(plaintext)
            src = sqlite3.connect(tmp.name)
            self._conn = sqlite3.connect(":memory:")
            self._conn.execute("PRAGMA journal_mode=OFF")
            src.backup(self._conn)
            src.close()
        finally:
            os.unlink(tmp.name)

    def _dump_db(self, conn: sqlite3.Connection) -> bytes:
        """Serialize an in-memory SQLite DB to bytes."""
        import tempfile
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            dest = sqlite3.connect(tmp.name)
            conn.backup(dest)
            dest.close()
            with open(tmp.name, "rb") as f:
                return f.read()
        finally:
            os.unlink(tmp.name)

    def _sync_to_disk(self):
        """Write the current in-memory state back to disk encrypted."""
        if not self._key or not self._conn:
            return
        self._flush_audit()
        plaintext = self._dump_db(self._conn)
        # We need the salt — read it from the existing vault file
        data = self.path.read_bytes()
        salt = data[:SALT_SIZE]
        encrypted = _encrypt(self._key, plaintext)
        self.path.write_bytes(salt + encrypted)

    def _require_unlocked(self):
        if self.locked:
            raise LockedError("Vault is locked. Run 'keep unlock' first.")

    def _bump_timer(self):
        self._cancel_lock_timer()
        if self._auto_lock_seconds > 0:
            self._lock_timer = threading.Timer(self._auto_lock_seconds, self.lock)
            self._lock_timer.daemon = True
            self._lock_timer.start()

    def _cancel_lock_timer(self):
        if self._lock_timer:
            self._lock_timer.cancel()
            self._lock_timer = None
