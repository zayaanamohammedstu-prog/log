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

    def test_auditor_accessible_for_admin(self, admin_client):
        """Admin user can access /auditor (admin implies auditor privileges)."""
        resp = admin_client.get("/auditor")
        assert resp.status_code == 200
        assert b"LogGuard" in resp.data

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


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_register_page_accessible_when_no_users(self, client):
        """GET /register returns 200 when no users exist."""
        resp = client.get("/register")
        assert resp.status_code == 200
        assert b"Create" in resp.data

    def test_register_disabled_when_users_exist_and_no_flag(self, tmp_instance, client):
        """GET /register returns 403 when users exist and public signup is off."""
        create_user(tmp_instance, "existing", "pass123", role="auditor")
        resp = client.get("/register")
        assert resp.status_code == 403
        assert b"disabled" in resp.data.lower()

    def test_register_enabled_by_env_flag(self, tmp_instance, client, monkeypatch):
        """GET /register returns 200 when LOGGUARD_ENABLE_PUBLIC_SIGNUP=true."""
        create_user(tmp_instance, "existing", "pass123", role="auditor")
        monkeypatch.setenv("LOGGUARD_ENABLE_PUBLIC_SIGNUP", "true")
        resp = client.get("/register")
        assert resp.status_code == 200
        assert b"Create" in resp.data

    def test_first_registered_user_becomes_admin(self, tmp_instance, client):
        """When no users exist, the first registered user gets the admin role."""
        resp = client.post(
            "/register",
            data={
                "username": "firstuser",
                "password": "password1",
                "confirm_password": "password1",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        from app.db import get_user_by_username
        row = get_user_by_username(tmp_instance, "firstuser")
        assert row is not None
        assert row["role"] == "admin"

    def test_subsequent_registered_user_becomes_auditor(self, tmp_instance, client, monkeypatch):
        """When users already exist and signup is enabled, new users become auditors."""
        monkeypatch.setenv("LOGGUARD_ENABLE_PUBLIC_SIGNUP", "true")
        create_user(tmp_instance, "existing_admin", "adminpass", role="admin")
        resp = client.post(
            "/register",
            data={
                "username": "newauditor",
                "password": "password1",
                "confirm_password": "password1",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        from app.db import get_user_by_username
        row = get_user_by_username(tmp_instance, "newauditor")
        assert row is not None
        assert row["role"] == "auditor"

    def test_register_redirects_to_login_on_success(self, client):
        """Successful registration redirects to /login."""
        resp = client.post(
            "/register",
            data={
                "username": "newuser",
                "password": "pass123",
                "confirm_password": "pass123",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_register_duplicate_username(self, tmp_instance, client, monkeypatch):
        """Registering with an existing username shows an error."""
        create_user(tmp_instance, "taken", "pass123", role="auditor")
        # Ensure signup is allowed even though a user exists
        monkeypatch.setenv("LOGGUARD_ENABLE_PUBLIC_SIGNUP", "true")
        resp = client.post(
            "/register",
            data={
                "username": "taken",
                "password": "pass123",
                "confirm_password": "pass123",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"already taken" in resp.data

    def test_register_password_mismatch(self, client):
        """Mismatched passwords show an error."""
        resp = client.post(
            "/register",
            data={
                "username": "user1",
                "password": "pass123",
                "confirm_password": "different",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"do not match" in resp.data

    def test_register_short_password(self, client):
        """Password shorter than 6 characters is rejected."""
        resp = client.post(
            "/register",
            data={
                "username": "user1",
                "password": "abc",
                "confirm_password": "abc",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"6 characters" in resp.data

    def test_register_short_username(self, client):
        """Username shorter than 3 characters is rejected."""
        resp = client.post(
            "/register",
            data={
                "username": "ab",
                "password": "pass123",
                "confirm_password": "pass123",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"3 characters" in resp.data


# ---------------------------------------------------------------------------
# Admin recovery (bootstrap) tests
# ---------------------------------------------------------------------------

class TestAdminRecovery:
    def test_bootstrap_promotes_existing_user_to_admin(self, tmp_instance):
        """When users exist but no admin, bootstrap with env vars promotes the named user."""
        from app.db import count_admins, get_user_by_username, promote_user_to_admin
        # Create a regular user first (no admin)
        create_user(tmp_instance, "recovery_user", "pass123", role="auditor")
        assert count_admins(tmp_instance) == 0
        # Simulate the promotion
        result = promote_user_to_admin(tmp_instance, "recovery_user")
        assert result is True
        row = get_user_by_username(tmp_instance, "recovery_user")
        assert row["role"] == "admin"
        assert count_admins(tmp_instance) == 1

    def test_promote_nonexistent_user_returns_false(self, tmp_instance):
        """promote_user_to_admin returns False for a username that doesn't exist."""
        from app.db import promote_user_to_admin
        result = promote_user_to_admin(tmp_instance, "ghost")
        assert result is False

    def test_count_admins(self, tmp_instance):
        """count_admins returns 0 initially and increments after creating an admin."""
        from app.db import count_admins
        assert count_admins(tmp_instance) == 0
        create_user(tmp_instance, "an_admin", "pass", role="admin")
        assert count_admins(tmp_instance) == 1
        create_user(tmp_instance, "auditor2", "pass", role="auditor")
        assert count_admins(tmp_instance) == 1


# ---------------------------------------------------------------------------
# Role normalisation tests
# ---------------------------------------------------------------------------

class TestRoleNormalisation:
    """Ensure roles are stored normalised and comparisons are robust."""

    def test_create_user_lowercases_role(self, tmp_instance):
        """create_user normalises an uppercase role to lowercase."""
        from app.db import get_user_by_username
        create_user(tmp_instance, "upperadmin", "pass", role="Admin")
        row = get_user_by_username(tmp_instance, "upperadmin")
        assert row["role"] == "admin"

    def test_create_user_strips_role_whitespace(self, tmp_instance):
        """create_user strips leading/trailing whitespace from role."""
        from app.db import get_user_by_username
        create_user(tmp_instance, "spaceauditor", "pass", role=" auditor ")
        row = get_user_by_username(tmp_instance, "spaceauditor")
        assert row["role"] == "auditor"

    def test_create_user_normalises_mixed_case_auditor(self, tmp_instance):
        """create_user stores 'AUDITOR' as 'auditor'."""
        from app.db import get_user_by_username
        create_user(tmp_instance, "capsauditor", "pass", role="AUDITOR")
        row = get_user_by_username(tmp_instance, "capsauditor")
        assert row["role"] == "auditor"

    def test_admin_with_uppercase_role_redirected_to_admin_portal(self, tmp_instance, client):
        """Admin user created with 'Admin' role is redirected to /admin on login, not /auditor."""
        create_user(tmp_instance, "mixedadmin", "pass", role="Admin")
        resp = client.post(
            "/login",
            data={"username": "mixedadmin", "password": "pass"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/admin" in resp.headers["Location"]

    def test_admin_login_redirect_yields_200_not_403(self, tmp_instance, client):
        """Following the login redirect for an admin user gives HTTP 200, not 403."""
        create_user(tmp_instance, "adminok", "pass", role="admin")
        resp = client.post(
            "/login",
            data={"username": "adminok", "password": "pass"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Administration" in resp.data

    def test_auditor_login_redirect_yields_200_not_403(self, tmp_instance, client):
        """Following the login redirect for an auditor user gives HTTP 200, not 403."""
        create_user(tmp_instance, "auditorok", "pass", role="auditor")
        resp = client.post(
            "/login",
            data={"username": "auditorok", "password": "pass"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"LogGuard" in resp.data

    def test_admin_can_access_auditor_portal(self, admin_client):
        """Admin is allowed into /auditor (admin implies auditor privileges)."""
        resp = admin_client.get("/auditor")
        assert resp.status_code == 200
        assert b"LogGuard" in resp.data

    def test_auditor_forbidden_from_admin_portal_with_role_hint(self, auditor_client):
        """When auditor is denied /admin, the 403 page mentions the Auditor Portal."""
        resp = auditor_client.get("/admin")
        assert resp.status_code == 403
        assert b"Access Denied" in resp.data
        assert b"Auditor Portal" in resp.data


# ---------------------------------------------------------------------------
# Administrator role tests
# ---------------------------------------------------------------------------

class TestAdministratorRole:
    """Ensure users with 'administrator' role have admin-equivalent access."""

    @pytest.fixture
    def administrator_client(self, tmp_instance, client):
        """Logged-in test client with an administrator-role user."""
        from app.db import create_user
        create_user(tmp_instance, "testadministrator", "adminpass", role="administrator")
        client.post(
            "/login",
            data={"username": "testadministrator", "password": "adminpass"},
            follow_redirects=True,
        )
        return client

    def test_administrator_is_admin(self, tmp_instance):
        """User with 'administrator' role has is_admin == True."""
        from app.db import get_user_by_username, create_user
        from app.models import User
        create_user(tmp_instance, "adm", "pass", role="administrator")
        row = get_user_by_username(tmp_instance, "adm")
        user = User(row)
        assert user.is_admin is True

    def test_administrator_can_access_auditor_portal(self, administrator_client):
        """Administrator can access /auditor (admin implies auditor privileges)."""
        resp = administrator_client.get("/auditor")
        assert resp.status_code == 200
        assert b"LogGuard" in resp.data

    def test_administrator_can_access_admin_portal(self, administrator_client):
        """Administrator can access /admin."""
        resp = administrator_client.get("/admin")
        assert resp.status_code == 200
        assert b"Administration" in resp.data

    def test_administrator_can_list_users(self, administrator_client):
        """Administrator can call the admin user-list API."""
        resp = administrator_client.get("/api/admin/users")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "users" in data

    def test_administrator_can_create_user(self, administrator_client):
        """Administrator can create users via the admin API."""
        resp = administrator_client.post(
            "/api/admin/users",
            data=json.dumps({"username": "newauditor", "password": "pass123", "role": "auditor"}),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert data["username"] == "newauditor"

    def test_administrator_login_redirects_to_admin_portal(self, tmp_instance, client):
        """Administrator role is redirected to /admin on login."""
        from app.db import create_user
        create_user(tmp_instance, "adm2", "pass", role="administrator")
        resp = client.post(
            "/login",
            data={"username": "adm2", "password": "pass"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/admin" in resp.headers["Location"]

    def test_administrator_can_access_admin_stats(self, administrator_client):
        """Administrator can view admin stats API."""
        resp = administrator_client.get("/api/admin/stats")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "user_count" in data
