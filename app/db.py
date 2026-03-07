"""
app/db.py
---------
SQLite data access layer for LogGuard user management.
"""

from __future__ import annotations

import sqlite3
import os

from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# DB path helpers
# ---------------------------------------------------------------------------

def _db_path(instance_path: str) -> str:
    """Return the absolute path to the SQLite database file."""
    return os.path.join(instance_path, "logguard.db")


# ---------------------------------------------------------------------------
# Schema init
# ---------------------------------------------------------------------------

def init_db(instance_path: str) -> None:
    """Create tables if they don't exist yet."""
    os.makedirs(instance_path, exist_ok=True)
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                role     TEXT    NOT NULL DEFAULT 'auditor'
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def create_user(
    instance_path: str,
    username: str,
    password: str,
    role: str = "auditor",
) -> int:
    """Hash *password* and insert a new user row. Returns the new row id."""
    hashed = generate_password_hash(password)
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed, role),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_user_by_username(instance_path: str, username: str) -> dict | None:
    """Return user row as dict or *None* if not found."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(instance_path: str, user_id: int) -> dict | None:
    """Return user row as dict or *None* if not found."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, username, password, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def count_users(instance_path: str) -> int:
    """Return the total number of users."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        (n,) = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return n
    finally:
        conn.close()


def verify_password(stored_hash: str, password: str) -> bool:
    """Return True if *password* matches *stored_hash*."""
    return check_password_hash(stored_hash, password)
