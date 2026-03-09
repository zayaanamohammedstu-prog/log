"""
tests/test_app.py
-----------------
Integration tests for the Flask application.
"""

import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.app import app
from app.db import create_user, init_db


@pytest.fixture
def tmp_instance(tmp_path):
    """Return a temporary instance directory with an empty, initialised DB."""
    init_db(str(tmp_path))
    return str(tmp_path)


@pytest.fixture
def client(tmp_instance):
    """Authenticated Flask test client (auditor user)."""
    app.config["TESTING"] = True
    app.instance_path = tmp_instance  # type: ignore[assignment]
    create_user(tmp_instance, "testuser", "testpass", role="auditor")
    with app.test_client() as c:
        # Log in before yielding so all tests start authenticated
        c.post(
            "/login",
            data={"username": "testuser", "password": "testpass"},
            follow_redirects=True,
        )
        yield c


class TestRoutes:
    def test_index_returns_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"LogGuard" in resp.data

    def test_status_endpoint(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "status" in data
        assert data["status"] == "ok"

    def test_analyze_sample(self, client):
        """POST to /api/analyze with use_sample=True should return results."""
        resp = client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "error" not in data
        assert "total_requests" in data
        assert data["total_requests"] > 0
        assert "anomaly_count" in data
        assert "top_anomalies" in data

    def test_analyze_log_text(self, client):
        """POST with raw log_text should work."""
        log_text = (
            '10.0.0.1 - - [15/Jan/2024:08:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
            '10.0.0.1 - - [15/Jan/2024:08:05:00 +0000] "GET /about HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
            '192.168.99.1 - - [15/Jan/2024:03:00:00 +0000] "POST /login HTTP/1.1" 401 128 "-" "Nikto/2.1.6"\n'
        )
        resp = client.post(
            "/api/analyze",
            data=json.dumps({"log_text": log_text}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "error" not in data
        assert data["total_requests"] == 3

    def test_analyze_file_upload(self, client):
        """POST with a file upload should work."""
        log_bytes = (
            b'10.0.0.1 - - [15/Jan/2024:08:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
            b'10.0.0.2 - - [15/Jan/2024:08:01:00 +0000] "GET /page HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
        )
        resp = client.post(
            "/api/analyze",
            data={"logfile": (log_bytes, "test.log")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "total_requests" in data

    def test_results_returns_404_before_analysis(self, client):
        """Fresh client should get 404 from /api/results if no analysis done."""
        # Reset global cache manually
        import app.app as app_module
        app_module._last_results = {}
        resp = client.get("/api/results")
        assert resp.status_code == 404

    def test_results_after_analysis(self, client):
        """After an analysis, /api/results should return cached data."""
        client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        resp = client.get("/api/results")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "total_requests" in data

    def test_analyze_timeline_structure(self, client):
        resp = client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        data = json.loads(resp.data)
        assert "timeline" in data
        if data["timeline"]:
            entry = data["timeline"][0]
            assert "hour_bucket" in entry
            assert "mean_risk_score" in entry

    def test_analyze_returns_extended_analytics(self, client):
        """Analysis result should include new analytics fields."""
        resp = client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "top_ips" in data
        assert "hourly_distribution" in data
        assert "risk_distribution" in data
        assert "top_anomalous_ips" in data
        assert "top_endpoints" in data
        # risk_distribution values should be valid risk levels
        for key in data["risk_distribution"]:
            assert key in {"Critical", "High", "Medium", "Low"}

    def test_export_csv_after_analysis(self, client):
        """Export CSV endpoint should return CSV data after an analysis."""
        client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        resp = client.get("/api/export/csv")
        assert resp.status_code == 200
        assert resp.content_type.startswith("text/csv")
        body = resp.data.decode("utf-8")
        assert "ip_address" in body or "anomaly_score" in body

    def test_export_json_after_analysis(self, client):
        """Export JSON endpoint should return JSON data after an analysis."""
        client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        resp = client.get("/api/export/json")
        assert resp.status_code == 200
        assert "json" in resp.content_type
        data = json.loads(resp.data)
        assert "total_requests" in data

    def test_export_returns_404_before_analysis(self, client):
        """Export endpoint should return 404 if no analysis has been run."""
        import app.app as app_module
        app_module._last_results = {}
        resp = client.get("/api/export/csv")
        assert resp.status_code == 404

    def test_export_unsupported_format(self, client):
        """Export with unsupported format should return 400."""
        client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        resp = client.get("/api/export/xml")
        assert resp.status_code == 400

    def test_analyze_stores_filename(self, client):
        """File upload should store the original filename in the run."""
        log_bytes = io.BytesIO(
            b'10.0.0.1 - - [15/Jan/2024:08:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
        )
        resp = client.post(
            "/api/analyze",
            data={"logfile": (log_bytes, "myfile.log")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data.get("filename") == "myfile.log"

    def test_analyze_stores_summary_and_history_reload(self, client):
        """After analysis, /api/runs/<id>/summary should return a reloadable summary."""
        resp = client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        run_data = json.loads(resp.data)
        run_id = run_data.get("run_id")
        assert run_id is not None

        # The history reload endpoint should return the summary
        summary_resp = client.get(f"/api/runs/{run_id}/summary")
        assert summary_resp.status_code == 200
        summary = json.loads(summary_resp.data)
        assert summary["run_id"] == run_id
        assert "total_requests" in summary
        assert "anomaly_count" in summary

    def test_run_summary_not_found(self, client):
        """Non-existent run should return 404."""
        resp = client.get("/api/runs/99999/summary")
        assert resp.status_code == 404

    def test_history_list(self, client):
        """After running analyses, /api/runs should list them."""
        client.post(
            "/api/analyze",
            data=json.dumps({"use_sample": True}),
            content_type="application/json",
        )
        resp = client.get("/api/runs")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "runs" in data
        assert len(data["runs"]) >= 1
        # Runs listing should not include summary_json (too large)
        for run in data["runs"]:
            assert "summary_json" not in run

