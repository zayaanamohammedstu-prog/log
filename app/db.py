"""
app/db.py
---------
SQLite data access layer for LogGuard user management.
"""

from __future__ import annotations

import sqlite3
import os
import json
from datetime import datetime, timezone

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
    """Create all application tables if they don't exist yet."""
    os.makedirs(instance_path, exist_ok=True)
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                username       TEXT    NOT NULL UNIQUE,
                password       TEXT    NOT NULL,
                role           TEXT    NOT NULL DEFAULT 'auditor',
                status         TEXT    NOT NULL DEFAULT 'active',
                email          TEXT,
                email_verified INTEGER DEFAULT 0,
                user_type      TEXT    DEFAULT 'auditor',
                verify_token   TEXT,
                display_name   TEXT,
                avatar_url     TEXT,
                preferences_json TEXT,
                deleted_at     TEXT,
                deleted_by     TEXT
            );

            CREATE TABLE IF NOT EXISTS analysis_runs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                username     TEXT    NOT NULL,
                input_type   TEXT    NOT NULL,
                input_hash   TEXT    NOT NULL,
                filename     TEXT    NOT NULL DEFAULT '',
                summary_json TEXT,
                deleted_at   TEXT,
                deleted_by   TEXT
            );

            CREATE TABLE IF NOT EXISTS analysis_results (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id            INTEGER NOT NULL,
                ip_address        TEXT,
                hour_bucket       TEXT,
                features_json     TEXT,
                anomaly_score     REAL,
                is_anomaly        INTEGER,
                ensemble_score    REAL,
                model_scores_json TEXT,
                ensemble_label    TEXT,
                explanations_json TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE TABLE IF NOT EXISTS attack_chains (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id     INTEGER NOT NULL,
                chain_json TEXT    NOT NULL,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE TABLE IF NOT EXISTS ledger_entries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                prev_hash    TEXT    NOT NULL,
                timestamp    TEXT    NOT NULL,
                actor        TEXT    NOT NULL,
                input_hash   TEXT    NOT NULL,
                results_hash TEXT    NOT NULL,
                config_hash  TEXT    NOT NULL,
                entry_hash   TEXT    NOT NULL
            );
            """
        )
        conn.commit()
        # Migrate existing DBs: add new columns if they don't exist yet
        for alter_sql in [
            "ALTER TABLE analysis_runs ADD COLUMN filename TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE analysis_runs ADD COLUMN summary_json TEXT",
            "ALTER TABLE analysis_runs ADD COLUMN deleted_at TEXT",
            "ALTER TABLE analysis_runs ADD COLUMN deleted_by TEXT",
            "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE users ADD COLUMN deleted_at TEXT",
            "ALTER TABLE users ADD COLUMN deleted_by TEXT",
            "ALTER TABLE users ADD COLUMN email TEXT",
            "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN user_type TEXT DEFAULT 'auditor'",
            "ALTER TABLE users ADD COLUMN verify_token TEXT",
            "ALTER TABLE users ADD COLUMN display_name TEXT",
            "ALTER TABLE users ADD COLUMN avatar_url TEXT",
            "ALTER TABLE users ADD COLUMN preferences_json TEXT",
        ]:
            try:
                conn.execute(alter_sql)
                conn.commit()
            except sqlite3.OperationalError:
                pass  # Column already present
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
    status: str = "active",
    email: str = "",
    user_type: str = "",
    email_verified: int = 0,
    verify_token: str | None = None,
    display_name: str = "",
) -> int:
    """Hash *password* and insert a new user row. Returns the new row id."""
    # Normalise role: strip whitespace and lowercase to prevent mismatch bugs
    role = (role or "auditor").strip().lower()
    if role not in ("admin", "auditor", "administrator", "super_admin", "viewer"):
        role = "auditor"
    hashed = generate_password_hash(password)
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password, role, status, email, user_type, email_verified, verify_token, display_name)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                username,
                hashed,
                role,
                status,
                email or "",
                user_type or "",
                int(bool(email_verified)),
                verify_token,
                (display_name or username or "").strip(),
            ),
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
            "SELECT id, username, password, role, status, email, email_verified, user_type, verify_token,"
            " display_name, avatar_url, preferences_json, deleted_at, deleted_by"
            " FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(
    instance_path: str,
    user_id: int,
    include_deleted: bool = False,
) -> dict | None:
    """Return user row as dict or *None* if not found."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        if include_deleted:
                row = conn.execute(
                "SELECT id, username, password, role, status, email, email_verified, user_type, verify_token,"
                " display_name, avatar_url, preferences_json, deleted_at, deleted_by"
                " FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, username, password, role, status, email, email_verified, user_type, verify_token,"
                " display_name, avatar_url, preferences_json, deleted_at, deleted_by"
                " FROM users WHERE id = ? AND deleted_at IS NULL",
                (user_id,),
            ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def count_users(instance_path: str) -> int:
    """Return the total number of non-deleted users."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        (n,) = conn.execute(
            "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL"
        ).fetchone()
        return n
    finally:
        conn.close()


def list_users(instance_path: str, include_deleted: bool = False) -> list[dict]:
    """Return all users (id, username, role, status) – password excluded."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        if include_deleted:
            rows = conn.execute(
                "SELECT id, username, role, status, email, email_verified, display_name, avatar_url, deleted_at, deleted_by"
                " FROM users ORDER BY id"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, username, role, status, email, email_verified, display_name, avatar_url, deleted_at, deleted_by"
                " FROM users WHERE deleted_at IS NULL ORDER BY id"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_pending_users(instance_path: str) -> list[dict]:
    """Return users with status='pending' that are not deleted."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, username, role, status, email, email_verified, deleted_at, deleted_by"
            " FROM users WHERE status = 'pending' AND deleted_at IS NULL ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def approve_user(instance_path: str, user_id: int, approved_by: str) -> bool:
    """Set status='active' for the given user. Returns True if a row was updated."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE users SET status = 'active', deleted_by = ?"
            " WHERE id = ? AND deleted_at IS NULL",
            (f"approved_by:{approved_by}", user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def reject_user(instance_path: str, user_id: int, rejected_by: str) -> bool:
    """Set status='suspended' for the given user. Returns True if a row was updated."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE users SET status = 'suspended', deleted_by = ?"
            " WHERE id = ? AND deleted_at IS NULL",
            (f"rejected_by:{rejected_by}", user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def soft_delete_user(instance_path: str, user_id: int, deleted_by: str) -> bool:
    """Soft-delete a user by setting deleted_at/deleted_by. Returns True if updated."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        ts = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "UPDATE users SET deleted_at = ?, deleted_by = ?"
            " WHERE id = ? AND deleted_at IS NULL",
            (ts, deleted_by, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def restore_user(instance_path: str, user_id: int) -> bool:
    """Restore a soft-deleted user. Returns True if a row was updated."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE users SET deleted_at = NULL, deleted_by = NULL WHERE id = ?",
            (user_id,),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_deleted_users(instance_path: str) -> list[dict]:
    """Return users where deleted_at IS NOT NULL."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, username, role, status, deleted_at, deleted_by"
            " FROM users WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_user_role(instance_path: str, user_id: int, new_role: str) -> bool:
    """Update the role for a user. Returns True if a row was updated."""
    new_role = (new_role or "auditor").strip().lower()
    if new_role not in ("admin", "auditor", "administrator", "super_admin", "viewer"):
        new_role = "auditor"
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE users SET role = ? WHERE id = ? AND deleted_at IS NULL",
            (new_role, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def count_super_admins(instance_path: str) -> int:
    """Return the number of users with role='super_admin'."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        (n,) = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'super_admin' AND deleted_at IS NULL"
        ).fetchone()
        return n
    finally:
        conn.close()


def delete_user(instance_path: str, user_id: int) -> bool:
    """Hard-delete a user by id. Returns True if a row was deleted."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def verify_password(stored_hash: str, password: str) -> bool:
    """Return True if *password* matches *stored_hash*."""
    return check_password_hash(stored_hash, password)


def count_admins(instance_path: str) -> int:
    """Return the number of users with role='admin' or 'administrator' (not deleted)."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        (n,) = conn.execute(
            "SELECT COUNT(*) FROM users"
            " WHERE role IN ('admin', 'administrator') AND deleted_at IS NULL"
        ).fetchone()
        return n
    finally:
        conn.close()


def promote_user_to_admin(instance_path: str, username: str) -> bool:
    """Set role='admin' for the given username. Returns True if a row was updated."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE users SET role = 'admin' WHERE username = ?",
            (username,),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_user_by_email(instance_path: str, email: str) -> dict | None:
    """Return user row as dict or None if not found by email."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, username, password, role, status, email, email_verified, user_type, deleted_at, deleted_by"
            " FROM users WHERE email = ? AND deleted_at IS NULL",
            (email,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def mark_email_verified(instance_path: str, user_id: int) -> bool:
    """Set email_verified=1 for the given user. Returns True if a row was updated."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE users"
            " SET email_verified = 1,"
            "     verify_token = NULL,"
            "     status = CASE WHEN status = 'email_verification_pending' THEN 'pending' ELSE status END"
            " WHERE id = ? AND deleted_at IS NULL",
            (user_id,),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def set_email_verification_token(instance_path: str, user_id: int, token: str) -> None:
    """Store a verification token for the given user."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        conn.execute(
            "UPDATE users SET verify_token = ? WHERE id = ?",
            (token, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_user_by_verification_token(instance_path: str, token: str) -> dict | None:
    """Return the user row for the given verification token, or None."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, username, role, status, email, email_verified, user_type"
            " FROM users WHERE verify_token = ? AND deleted_at IS NULL",
            (token,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_profile(instance_path: str, user_id: int) -> dict | None:
    """Return profile-safe fields for the given user."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, username, role, status, email, email_verified, user_type, display_name, avatar_url, preferences_json"
            " FROM users WHERE id = ? AND deleted_at IS NULL",
            (user_id,),
        ).fetchone()
        if not row:
            return None
        out = dict(row)
        try:
            out["preferences"] = json.loads(out.get("preferences_json") or "{}")
        except Exception:
            out["preferences"] = {}
        return out
    finally:
        conn.close()


def update_user_profile(
    instance_path: str,
    user_id: int,
    *,
    display_name: str | None = None,
    email: str | None = None,
) -> bool:
    """Update mutable profile fields for a user."""
    updates = []
    params: list[object] = []
    if display_name is not None:
        updates.append("display_name = ?")
        params.append(display_name.strip())
    if email is not None:
        updates.append("email = ?")
        params.append(email.strip())
    if not updates:
        return False
    params.append(user_id)

    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ? AND deleted_at IS NULL",
            params,
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def update_user_password(instance_path: str, user_id: int, new_password: str) -> bool:
    """Update password hash for a user."""
    hashed = generate_password_hash(new_password)
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE users SET password = ? WHERE id = ? AND deleted_at IS NULL",
            (hashed, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def update_user_avatar(instance_path: str, user_id: int, avatar_url: str) -> bool:
    """Update avatar URL for a user."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE users SET avatar_url = ? WHERE id = ? AND deleted_at IS NULL",
            (avatar_url, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Run soft-delete helpers
# ---------------------------------------------------------------------------

def soft_delete_run(instance_path: str, run_id: int, deleted_by: str) -> bool:
    """Soft-delete an analysis run. Returns True if a row was updated."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        ts = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "UPDATE analysis_runs SET deleted_at = ?, deleted_by = ?"
            " WHERE id = ? AND deleted_at IS NULL",
            (ts, deleted_by, run_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def restore_run(instance_path: str, run_id: int) -> bool:
    """Restore a soft-deleted analysis run. Returns True if a row was updated."""
    conn = sqlite3.connect(_db_path(instance_path))
    try:
        cur = conn.execute(
            "UPDATE analysis_runs SET deleted_at = NULL, deleted_by = NULL WHERE id = ?",
            (run_id,),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_deleted_runs(instance_path: str) -> list[dict]:
    """Return analysis runs where deleted_at IS NOT NULL."""
    conn = sqlite3.connect(_db_path(instance_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, timestamp, username, input_type, input_hash, filename,"
            " deleted_at, deleted_by"
            " FROM analysis_runs WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
