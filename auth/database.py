"""SQLite user database."""

from __future__ import annotations
import sqlite3
import logging
from pathlib import Path
from typing import Optional

from passlib.context import CryptContext

from .models import User

logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserDB:
    """Simple SQLite-backed user store."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT,
                    name TEXT,
                    provider TEXT DEFAULT 'local',
                    provider_id TEXT,
                    avatar_url TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_id
                ON users(provider, provider_id)
                WHERE provider_id IS NOT NULL
            """)

    def get_by_email(self, email: str) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email.lower(),)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def get_by_id(self, user_id: int) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def get_by_provider(self, provider: str, provider_id: str) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE provider = ? AND provider_id = ?",
                (provider, provider_id),
            ).fetchone()
        return self._row_to_user(row) if row else None

    def create_local(self, email: str, password: str, name: str = None) -> User:
        hashed = pwd_context.hash(password)
        with self._conn() as conn:
            cursor = conn.execute(
                "INSERT INTO users (email, password_hash, name, provider) VALUES (?, ?, ?, 'local')",
                (email.lower(), hashed, name),
            )
        return self.get_by_id(cursor.lastrowid)

    def create_or_update_oauth(
        self, provider: str, provider_id: str, email: str,
        name: str = None, avatar_url: str = None,
    ) -> User:
        """Create or update an OAuth user. Links by provider+provider_id."""
        existing = self.get_by_provider(provider, provider_id)
        if existing:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE users SET email=?, name=?, avatar_url=? WHERE id=?",
                    (email.lower(), name, avatar_url, existing.id),
                )
            return self.get_by_id(existing.id)

        # Check if email exists with different provider — link accounts
        by_email = self.get_by_email(email)
        if by_email:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE users SET provider=?, provider_id=?, avatar_url=? WHERE id=?",
                    (provider, provider_id, avatar_url, by_email.id),
                )
            return self.get_by_id(by_email.id)

        with self._conn() as conn:
            cursor = conn.execute(
                "INSERT INTO users (email, provider, provider_id, name, avatar_url) VALUES (?, ?, ?, ?, ?)",
                (email.lower(), provider, provider_id, name, avatar_url),
            )
        return self.get_by_id(cursor.lastrowid)

    def get_all(self) -> list[User]:
        """Return all registered users."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM users ORDER BY id"
            ).fetchall()
        return [self._row_to_user(r) for r in rows]

    def delete(self, user_id: int) -> bool:
        """Delete a user by ID. Returns True if a row was removed."""
        with self._conn() as conn:
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0

    def verify_password(self, email: str, password: str) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ? AND provider = 'local'",
                (email.lower(),),
            ).fetchone()
        if not row or not row["password_hash"]:
            return None
        if pwd_context.verify(password, row["password_hash"]):
            return self._row_to_user(row)
        return None

    @staticmethod
    def _row_to_user(row) -> User:
        return User(
            id=row["id"],
            email=row["email"],
            name=row["name"],
            provider=row["provider"],
            avatar_url=row["avatar_url"],
        )


# Global instance
_db: Optional[UserDB] = None


def init_db(db_path: str):
    global _db
    _db = UserDB(db_path)
    logger.info(f"Auth database initialized: {db_path}")


def get_db() -> UserDB:
    if _db is None:
        raise RuntimeError("Auth database not initialized. Call init_db() first.")
    return _db
