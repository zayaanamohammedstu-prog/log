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
        self.status   = row.get("status", "active") or "active"
        # Do NOT store hashed password in session-persisted object

    # Flask-Login expects get_id() to return a string
    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_super_admin(self) -> bool:
        return (self.role or "").strip().lower() == "super_admin"

    @property
    def is_admin(self) -> bool:
        """Return True for admin, administrator, or super_admin roles."""
        return (self.role or "").strip().lower() in (
            "admin", "administrator", "super_admin"
        )

    @property
    def is_auditor(self) -> bool:
        return (self.role or "").strip().lower() in (
            "auditor", "admin", "administrator", "super_admin"
        )

    @property
    def is_viewer(self) -> bool:
        return True  # all roles can view

    @property
    def can_access_auditor_portal(self) -> bool:
        """Return True for roles that may access the Auditor Portal."""
        return (self.role or "").strip().lower() in (
            "auditor", "admin", "administrator", "super_admin"
        )
