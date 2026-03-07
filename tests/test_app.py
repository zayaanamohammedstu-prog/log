"""
tests/test_app.py
-----------------
Integration tests for the Flask application.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
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
