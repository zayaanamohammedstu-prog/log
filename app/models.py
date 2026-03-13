"""
app/models.py
-------------
Flask-Login User model for LogGuard.
"""

from __future__ import annotations

from flask_login import UserMixin


class User(UserMixin):
    """Lightweight user object that wraps a DB row dict."""

    def __init__(self, row: dict) -> None:
        self.id       = row["id"]
        self.username = row["username"]
        self.role     = row["role"]
        # Do NOT store hashed password in session-persisted object

    # Flask-Login expects get_id() to return a string
    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_admin(self) -> bool:
        return (self.role or "").strip().lower() == "admin"
