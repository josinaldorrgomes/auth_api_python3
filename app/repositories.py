"""Padrão Repository: o domínio depende de interfaces; a implementação usa SQLite."""
import sqlite3
import threading
from datetime import datetime
from typing import Protocol

from .domain import ApiKey, OtpChallenge, OtpPurpose, Role, User


class UserRepository(Protocol):
    def add(self, user: User) -> None: ...
    def by_id(self, user_id: str) -> User | None: ...
    def by_username(self, username: str) -> User | None: ...
    def update(self, user: User) -> None: ...


class ApiKeyRepository(Protocol):
    def add(self, key: ApiKey) -> None: ...
    def get(self, key_id: str) -> ApiKey | None: ...


class OtpRepository(Protocol):
    def add(self, challenge: OtpChallenge) -> None: ...
    def latest(self, user_id: str, purpose: OtpPurpose) -> OtpChallenge | None: ...
    def increment_attempts(self, challenge_id: str) -> None: ...
    def mark_consumed(self, challenge_id: str) -> None: ...


class DuplicateError(Exception):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    role TEXT NOT NULL, phone TEXT NOT NULL, email TEXT,
    phone_verified INTEGER NOT NULL DEFAULT 0, mfa_enabled INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, owner_id TEXT NOT NULL,
    scopes TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS otp_challenges (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_otp_user ON otp_challenges (user_id, purpose, created_at);
"""


class Database:
    """Conexão única e thread-safe. Todas as queries são parametrizadas (sem SQL injection)."""

    def __init__(self, url: str) -> None:
        self._conn = sqlite3.connect(url, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock, self._conn:            # commit automático ou rollback
            return self._conn.execute(sql, params).fetchall()


class SqliteUserRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    @staticmethod
    def _to_user(r: sqlite3.Row | None) -> User | None:
        if r is None:
            return None
        return User(id=r["id"], username=r["username"], password_hash=r["password_hash"],
                    role=Role(r["role"]), phone=r["phone"], email=r["email"],
                    phone_verified=bool(r["phone_verified"]),
                    mfa_enabled=bool(r["mfa_enabled"]), active=bool(r["active"]))

    def add(self, u: User) -> None:
        try:
            self._db.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?)",
                (u.id, u.username, u.password_hash, u.role.value, u.phone, u.email,
                 int(u.phone_verified), int(u.mfa_enabled), int(u.active)))
        except sqlite3.IntegrityError as exc:
            raise DuplicateError("username already exists") from exc

    def by_id(self, user_id: str) -> User | None:
        rows = self._db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return self._to_user(rows[0] if rows else None)

    def by_username(self, username: str) -> User | None:
        rows = self._db.execute("SELECT * FROM users WHERE username = ?", (username,))
        return self._to_user(rows[0] if rows else None)

    def update(self, u: User) -> None:
        self._db.execute(
            "UPDATE users SET phone=?, email=?, phone_verified=?, mfa_enabled=?, active=? "
            "WHERE id=?",
            (u.phone, u.email, int(u.phone_verified), int(u.mfa_enabled), int(u.active), u.id))


class SqliteApiKeyRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def add(self, k: ApiKey) -> None:
        self._db.execute("INSERT INTO api_keys VALUES (?,?,?,?,?)",
                         (k.key_id, k.secret_hash, k.owner_id,
                          " ".join(sorted(k.scopes)), int(k.revoked)))

    def get(self, key_id: str) -> ApiKey | None:
        rows = self._db.execute("SELECT * FROM api_keys WHERE key_id = ?", (key_id,))
        if not rows:
            return None
        r = rows[0]
        return ApiKey(key_id=r["key_id"], secret_hash=r["secret_hash"], owner_id=r["owner_id"],
                      scopes=frozenset(r["scopes"].split()), revoked=bool(r["revoked"]))


class SqliteOtpRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def add(self, c: OtpChallenge) -> None:
        self._db.execute(
            "INSERT INTO otp_challenges VALUES (?,?,?,?,?,?,?,?)",
            (c.id, c.user_id, c.purpose.value, c.code_hash, c.created_at.isoformat(),
             c.expires_at.isoformat(), c.attempts, int(c.consumed)))

    def latest(self, user_id: str, purpose: OtpPurpose) -> OtpChallenge | None:
        rows = self._db.execute(
            "SELECT * FROM otp_challenges WHERE user_id=? AND purpose=? "
            "ORDER BY created_at DESC LIMIT 1", (user_id, purpose.value))
        if not rows:
            return None
        r = rows[0]
        return OtpChallenge(id=r["id"], user_id=r["user_id"], purpose=OtpPurpose(r["purpose"]),
                            code_hash=r["code_hash"],
                            created_at=datetime.fromisoformat(r["created_at"]),
                            expires_at=datetime.fromisoformat(r["expires_at"]),
                            attempts=r["attempts"], consumed=bool(r["consumed"]))

    def increment_attempts(self, challenge_id: str) -> None:
        self._db.execute("UPDATE otp_challenges SET attempts = attempts + 1 WHERE id=?",
                         (challenge_id,))

    def mark_consumed(self, challenge_id: str) -> None:
        self._db.execute("UPDATE otp_challenges SET consumed = 1 WHERE id=?", (challenge_id,))
