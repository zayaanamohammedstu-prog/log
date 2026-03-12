"""
tests/test_auth.py
------------------
Authentication and authorisation tests for LogGuard.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.app import app as flask_app
from app.db import create_user, init_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_instance(tmp_path):
    """Return a temporary instance directory with an empty, initialised DB."""
    init_db(str(tmp_path))
    return str(tmp_path)


@pytest.fixture
def client(tmp_instance):
    """Flask test client with an isolated SQLite DB."""
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    # Point the app's instance path at the temp dir
    flask_app.instance_path = tmp_instance  # type: ignore[assignment]
    with flask_app.test_client() as c:
        yield c


@pytest.fixture
def admin_client(tmp_instance, client):
    """Logged-in test client with an admin user."""
    create_user(tmp_instance, "testadmin", "adminpass", role="admin")
    client.post(
        "/login",
        data={"username": "testadmin", "password": "adminpass"},
        follow_redirects=True,
    )
    return client


@pytest.fixture
def auditor_client(tmp_instance, client):
    """Logged-in test client with an auditor user."""
    create_user(tmp_instance, "testauditor", "auditorpass", role="auditor")
    client.post(
        "/login",
        data={"username": "testauditor", "password": "auditorpass"},
        follow_redirects=True,
    )
    return client


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------

class TestLogin:
    def test_login_page_loads(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Sign in" in resp.data

    def test_login_success(self, tmp_instance, client):
        create_user(tmp_instance, "alice", "secret123", role="auditor")
        resp = client.post(
            "/login",
            data={"username": "alice", "password": "secret123"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # After login, auditor should see the audit workbench
        assert b"LogGuard" in resp.data

    def test_login_redirects_auditor_to_auditor_portal(self, tmp_instance, client):
        create_user(tmp_instance, "auditor1", "pass1", role="auditor")
        resp = client.post(
            "/login",
            data={"username": "auditor1", "password": "pass1"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/auditor" in resp.headers["Location"]

    def test_login_redirects_admin_to_admin_portal(self, tmp_instance, client):
        create_user(tmp_instance, "admin1", "pass1", role="admin")
        resp = client.post(
            "/login",
            data={"username": "admin1", "password": "pass1"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/admin" in resp.headers["Location"]

    def test_login_wrong_password(self, tmp_instance, client):
        create_user(tmp_instance, "bob", "correct", role="auditor")
        resp = client.post(
            "/login",
            data={"username": "bob", "password": "wrong"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid username or password" in resp.data

    def test_login_unknown_user(self, client):
        resp = client.post(
            "/login",
            data={"username": "nobody", "password": "anything"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid username or password" in resp.data

    def test_logout(self, auditor_client):
        resp = auditor_client.post("/logout", follow_redirects=True)
        assert resp.status_code == 200
        assert b"Sign in" in resp.data


# ---------------------------------------------------------------------------
# Protected route tests
# ---------------------------------------------------------------------------

class TestProtectedRoutes:
    def test_index_public_when_not_logged_in(self, client):
        """GET / is now a public landing page – must return 200 with landing content."""
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 200
        assert b"LogGuard" in resp.data
        assert b"Sign In" in resp.data

    def test_index_redirects_to_auditor_when_logged_in_as_auditor(self, auditor_client):
        """Authenticated auditor hitting / is redirected to /auditor."""
        resp = auditor_client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auditor" in resp.headers["Location"]

    def test_index_redirects_to_admin_when_logged_in_as_admin(self, admin_client):
        """Authenticated admin hitting / is redirected to /admin."""
        resp = admin_client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/admin" in resp.headers["Location"]

    def test_auditor_requires_auth(self, client):
        """GET /auditor without auth should redirect to login (302)."""
        resp = client.get("/auditor", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_auditor_accessible_for_auditor(self, auditor_client):
        """Auditor user can access /auditor (200)."""
        resp = auditor_client.get("/auditor")
        assert resp.status_code == 200
        assert b"LogGuard" in resp.data

    def test_auditor_forbidden_for_admin(self, admin_client):
        """Admin user accessing /auditor gets 403."""
        resp = admin_client.get("/auditor")
        assert resp.status_code == 403
        assert b"Access Denied" in resp.data

    def test_api_status_requires_auth(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert "error" in data

    def test_api_analyze_requires_auth(self, client):
        resp = client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert "error" in data

    def test_api_results_requires_auth(self, client):
        resp = client.get("/api/results")
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert "error" in data

    def test_api_status_accessible_when_logged_in(self, auditor_client):
        resp = auditor_client.get("/api/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# Admin role enforcement tests
# ---------------------------------------------------------------------------

class TestAdminRole:
    def test_admin_page_requires_auth(self, client):
        resp = client.get("/admin", follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_admin_page_forbidden_for_non_admin(self, auditor_client):
        resp = auditor_client.get("/admin")
        assert resp.status_code == 403
        assert b"Access Denied" in resp.data

    def test_admin_page_accessible_for_admin(self, admin_client):
        resp = admin_client.get("/admin")
        assert resp.status_code == 200
        assert b"Administration" in resp.data

    # Admin API endpoints
    def test_admin_stats_requires_admin(self, auditor_client):
        resp = auditor_client.get("/api/admin/stats")
        assert resp.status_code == 403

    def test_admin_stats_accessible_for_admin(self, admin_client):
        resp = admin_client.get("/api/admin/stats")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "user_count" in data
        assert "total_runs" in data

    def test_admin_list_users_requires_admin(self, auditor_client):
        resp = auditor_client.get("/api/admin/users")
        assert resp.status_code == 403

    def test_admin_list_users(self, admin_client):
        resp = admin_client.get("/api/admin/users")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "users" in data
        assert any(u["username"] == "testadmin" for u in data["users"])

    def test_admin_create_user(self, admin_client):
        resp = admin_client.post(
            "/api/admin/users",
            data=json.dumps({"username": "newuser", "password": "pass123", "role": "auditor"}),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert data["username"] == "newuser"

    def test_admin_create_user_duplicate(self, admin_client):
        resp = admin_client.post(
            "/api/admin/users",
            data=json.dumps({"username": "testadmin", "password": "pass", "role": "auditor"}),
            content_type="application/json",
        )
        assert resp.status_code == 409

    def test_admin_create_user_missing_fields(self, admin_client):
        resp = admin_client.post(
            "/api/admin/users",
            data=json.dumps({"username": "user2"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_admin_delete_user_requires_admin(self, auditor_client):
        resp = auditor_client.delete("/api/admin/users/1")
        assert resp.status_code == 403

    def test_admin_cannot_delete_self(self, tmp_instance, admin_client):
        from app.db import get_user_by_username
        admin_row = get_user_by_username(tmp_instance, "testadmin")
        resp = admin_client.delete(f"/api/admin/users/{admin_row['id']}")
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert "own account" in data["error"]

    def test_admin_delete_user(self, tmp_instance, admin_client):
        from app.db import create_user, get_user_by_username
        create_user(tmp_instance, "deleteme", "pass", role="auditor")
        user = get_user_by_username(tmp_instance, "deleteme")
        resp = admin_client.delete(f"/api/admin/users/{user['id']}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["deleted"] is True
