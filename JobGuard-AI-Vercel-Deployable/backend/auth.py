"""Local secure account authentication using SQLite with WAL mode, indexes, and pooled cleanup."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from base64 import urlsafe_b64encode
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

_DEFAULT_DATABASE_PATH = (
    Path("/tmp/jobguard.db")
    if os.getenv("VERCEL") == "1"
    else Path(__file__).resolve().parent.parent / "jobguard.db"
)
DATABASE_PATH = Path(os.getenv("JOBGUARD_DATABASE_PATH", str(_DEFAULT_DATABASE_PATH)))
SESSION_SECONDS = 60 * 60 * 24 * 7
_PRAGMA_STATEMENTS = (
    "PRAGMA foreign_keys = ON",
    "PRAGMA journal_mode = WAL",
    "PRAGMA synchronous = NORMAL",
    "PRAGMA temp_store = MEMORY",
    "PRAGMA cache_size = -16000",
)


_DB_INIT_LOCK = threading.Lock()
_INITIALIZED_DB_PATH: Optional[Path] = None


@contextmanager
def _raw_connect() -> Iterator[sqlite3.Connection]:
    """Yield a tuned SQLite connection without triggering lazy schema initialization."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        for stmt in _PRAGMA_STATEMENTS:
            conn.execute(stmt)
        with conn:
            yield conn
    finally:
        conn.close()


def _ensure_auth_database() -> None:
    """Lazily initialize the SQLite schema so serverless cold starts never fail if lifespan is skipped."""
    global _INITIALIZED_DB_PATH
    if _INITIALIZED_DB_PATH == DATABASE_PATH and DATABASE_PATH.exists():
        return
    with _DB_INIT_LOCK:
        if _INITIALIZED_DB_PATH == DATABASE_PATH and DATABASE_PATH.exists():
            return
        init_auth_database()


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Yield a tuned SQLite connection that always commits/rolls back and closes cleanly."""
    _ensure_auth_database()
    with _raw_connect() as conn:
        yield conn


def init_auth_database() -> None:
    global _INITIALIZED_DB_PATH
    with _raw_connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              full_name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              mobile TEXT,
              password_hash TEXT NOT NULL,
              email_verified INTEGER NOT NULL DEFAULT 0,
              notifications INTEGER NOT NULL DEFAULT 1,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_tokens (
              token_hash TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              kind TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_kind
              ON auth_tokens(user_id, kind, expires_at);
            CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires
              ON auth_tokens(expires_at);
            CREATE TABLE IF NOT EXISTS saved_reports (
              id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              report_json TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_saved_reports_user_created
              ON saved_reports(user_id, created_at DESC);
            """
        )
    _INITIALIZED_DB_PATH = DATABASE_PATH


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 390000)
    return (
        "pbkdf2_sha256$390000$"
        + urlsafe_b64encode(salt).decode().rstrip("=")
        + "$"
        + urlsafe_b64encode(digest).decode().rstrip("=")
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_text, digest_text = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt_bytes = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        digest = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, int(iterations))
        return hmac.compare_digest(actual, digest)
    except (ValueError, UnicodeDecodeError):
        return False


def public_user(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "full_name": row["full_name"],
        "email": row["email"],
        "mobile": row["mobile"] or "",
        "email_verified": bool(row["email_verified"]),
        "notifications": bool(row["notifications"]),
        "created_at": row["created_at"],
    }


def create_user(full_name: str, email: str, mobile: str, password: str) -> dict:
    clean_name = full_name.strip()
    clean_email = email.strip().lower()
    clean_mobile = mobile.strip()
    user_id = secrets.token_urlsafe(16)
    now = int(time.time())
    with _connect() as conn:
        try:
            conn.execute(
                "INSERT INTO users(id,full_name,email,mobile,password_hash,email_verified,notifications,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (user_id, clean_name, clean_email, clean_mobile, hash_password(password), 0, 1, now, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("An account with this email already exists.") from exc
    return {
        "id": user_id,
        "full_name": clean_name,
        "email": clean_email,
        "mobile": clean_mobile,
        "email_verified": False,
        "notifications": True,
        "created_at": now,
    }


def authenticate(email: str, password: str) -> Optional[dict]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    if row is None or not verify_password(password, row["password_hash"]):
        return None
    return public_user(row)


def get_user(user_id: str) -> Optional[dict]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return public_user(row) if row else None


def get_user_id_by_email(email: str) -> Optional[str]:
    with _connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    return row["id"] if row else None


def update_profile(user_id: str, full_name: str, mobile: str, notifications: bool) -> Optional[dict]:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET full_name=?, mobile=?, notifications=?, updated_at=? WHERE id=?",
            (full_name.strip(), mobile.strip(), int(notifications), int(time.time()), user_id),
        )
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return public_user(row) if row else None


def change_password(user_id: str, current_password: str, new_password: str) -> bool:
    with _connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None or not verify_password(current_password, row["password_hash"]):
            return False
        conn.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (hash_password(new_password), int(time.time()), user_id),
        )
    return True


def delete_user(user_id: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))


def issue_auth_token(user_id: str, kind: str, lifetime_seconds: int) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    with _connect() as conn:
        conn.execute("DELETE FROM auth_tokens WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO auth_tokens(token_hash,user_id,kind,expires_at) VALUES(?,?,?,?)",
            (token_hash, user_id, kind, now + lifetime_seconds),
        )
    return token


def _consume_token_in_conn(conn: sqlite3.Connection, token: str, kind: str) -> Optional[str]:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = conn.execute(
        "SELECT user_id, expires_at FROM auth_tokens WHERE token_hash=? AND kind=?",
        (token_hash, kind),
    ).fetchone()
    if row is None:
        return None
    conn.execute("DELETE FROM auth_tokens WHERE token_hash=?", (token_hash,))
    if int(row["expires_at"]) < int(time.time()):
        return None
    return row["user_id"]


def consume_auth_token(token: str, kind: str) -> Optional[str]:
    with _connect() as conn:
        return _consume_token_in_conn(conn, token, kind)


def reset_password(token: str, new_password: str) -> bool:
    with _connect() as conn:
        user_id = _consume_token_in_conn(conn, token, "password_reset")
        if user_id is None:
            return False
        conn.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (hash_password(new_password), int(time.time()), user_id),
        )
    return True


def verify_email(token: str) -> bool:
    with _connect() as conn:
        user_id = _consume_token_in_conn(conn, token, "email_verify")
        if user_id is None:
            return False
        conn.execute("UPDATE users SET email_verified=1, updated_at=? WHERE id=?", (int(time.time()), user_id))
    return True


def validate_session(token: str) -> Optional[dict]:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with _connect() as conn:
        row = conn.execute(
            "SELECT u.* FROM auth_tokens t JOIN users u ON u.id=t.user_id "
            "WHERE t.token_hash=? AND t.kind='session' AND t.expires_at>=?",
            (token_hash, int(time.time())),
        ).fetchone()
    return public_user(row) if row else None


def revoke_session(token: str) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with _connect() as conn:
        conn.execute("DELETE FROM auth_tokens WHERE token_hash=?", (token_hash,))


def revoke_other_sessions(user_id: str, keep_token: str) -> None:
    keep_hash = hashlib.sha256(keep_token.encode()).hexdigest()
    with _connect() as conn:
        conn.execute(
            "DELETE FROM auth_tokens WHERE user_id=? AND kind='session' AND token_hash<>?",
            (user_id, keep_hash),
        )


def save_user_report(user_id: str, report_data: dict, report_id: Optional[str] = None) -> dict:
    """Save an evidence-based verification report in user's isolated evidence locker."""
    rep_id = report_id or f"jg-{secrets.token_urlsafe(8)}"
    now = int(time.time())
    report_str = json.dumps(report_data, ensure_ascii=False, separators=(",", ":"))
    with _connect() as conn:
        existing = conn.execute(
            "SELECT user_id FROM saved_reports WHERE id=?",
            (rep_id,),
        ).fetchone()
        if existing and existing["user_id"] != user_id:
            raise PermissionError("A report with this identifier belongs to another account.")
        conn.execute(
            "INSERT OR REPLACE INTO saved_reports(id, user_id, report_json, created_at) VALUES(?,?,?,?)",
            (rep_id, user_id, report_str, now),
        )
    return {"id": rep_id, "created_at": now, "report": report_data}


def get_user_reports(user_id: str, limit: int = 50) -> list[dict]:
    """Retrieve saved reports belonging strictly to the specified user."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, report_json, created_at FROM saved_reports "
            "WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    results = []
    for r in rows:
        try:
            parsed = json.loads(r["report_json"])
        except (ValueError, TypeError):
            parsed = {}
        results.append({"id": r["id"], "created_at": r["created_at"], "report": parsed})
    return results


def delete_user_report(user_id: str, report_id: str) -> bool:
    """Delete a user report with strict ownership verification."""
    with _connect() as conn:
        cur = conn.execute("DELETE FROM saved_reports WHERE id=? AND user_id=?", (report_id, user_id))
        return cur.rowcount > 0


def get_user_report_by_id(user_id: str, report_id: str) -> Optional[dict]:
    """Retrieve a single report ensuring the user owns it."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, report_json, created_at FROM saved_reports WHERE id=? AND user_id=?",
            (report_id, user_id),
        ).fetchone()
    if not row:
        return None
    try:
        parsed = json.loads(row["report_json"])
    except (ValueError, TypeError):
        parsed = {}
    return {"id": row["id"], "created_at": row["created_at"], "report": parsed}
