"""
tests/test_runs.py
------------------
Unit tests for app/run_store.py.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.run_store import (
    init_run_store,
    save_run,
    save_results,
    get_run,
    list_runs,
    get_run_results,
    get_run_summary,
    save_chains,
    get_chains,
    get_chain,
)


@pytest.fixture
def store(tmp_path):
    """Initialised run-store directory."""
    init_run_store(str(tmp_path))
    return str(tmp_path)


class TestRunCRUD:
    def test_save_and_get_run(self, store):
        run_id = save_run(store, "alice", "sample", "abc123")
        assert isinstance(run_id, int)
        run = get_run(store, run_id)
        assert run is not None
        assert run["username"] == "alice"
        assert run["input_type"] == "sample"
        assert run["input_hash"] == "abc123"
        assert "timestamp" in run

    def test_save_run_with_filename(self, store):
        run_id = save_run(store, "alice", "upload", "abc123", filename="access.log")
        run = get_run(store, run_id)
        assert run["filename"] == "access.log"

    def test_save_run_defaults_filename_empty(self, store):
        run_id = save_run(store, "alice", "sample", "abc123")
        run = get_run(store, run_id)
        assert run["filename"] == ""

    def test_save_run_with_summary_json(self, store):
        summary = {"total_requests": 100, "anomaly_count": 5}
        import json
        run_id = save_run(
            store, "alice", "upload", "abc123",
            filename="test.log",
            summary_json=json.dumps(summary),
        )
        result = get_run_summary(store, run_id)
        assert result is not None
        assert result["total_requests"] == 100
        assert result["anomaly_count"] == 5
        assert result["run_id"] == run_id
        assert result["filename"] == "test.log"

    def test_get_run_summary_no_summary(self, store):
        run_id = save_run(store, "alice", "sample", "abc123")
        assert get_run_summary(store, run_id) is None

    def test_get_run_summary_not_found(self, store):
        assert get_run_summary(store, 9999) is None

    def test_get_run_not_found(self, store):
        assert get_run(store, 9999) is None

    def test_list_runs_empty(self, store):
        assert list_runs(store) == []

    def test_list_runs_multiple(self, store):
        save_run(store, "alice", "sample", "h1")
        save_run(store, "bob", "upload", "h2")
        runs = list_runs(store)
        assert len(runs) == 2

    def test_list_runs_newest_first(self, store):
        id1 = save_run(store, "alice", "sample", "h1")
        id2 = save_run(store, "bob", "upload", "h2")
        runs = list_runs(store)
        assert runs[0]["id"] == id2
        assert runs[1]["id"] == id1

    def test_list_runs_limit(self, store):
        for i in range(10):
            save_run(store, "u", "sample", f"h{i}")
        runs = list_runs(store, limit=3)
        assert len(runs) == 3

    def test_list_runs_excludes_summary_json(self, store):
        """list_runs should not include the (potentially large) summary_json."""
        import json
        save_run(store, "alice", "upload", "h1", summary_json=json.dumps({"big": "data"}))
        runs = list_runs(store)
        assert "summary_json" not in runs[0]


class TestResultsCRUD:
    def test_save_and_get_results(self, store):
        run_id = save_run(store, "alice", "sample", "h1")
        records = [
            {
                "ip_address": "1.2.3.4",
                "hour_bucket": "2024-01-01T00:00:00+00:00",
                "features": {"requests_per_hour": 10},
                "anomaly_score": 0.8,
                "is_anomaly": True,
                "ensemble_score": 0.75,
                "model_scores": {"isolation_forest": 0.7},
                "ensemble_label": "anomaly",
                "explanations": {"reasons": []},
            }
        ]
        save_results(store, run_id, records)
        results = get_run_results(store, run_id)
        assert len(results) == 1
        assert results[0]["ip_address"] == "1.2.3.4"
        assert results[0]["is_anomaly"] == 1

    def test_get_results_empty_run(self, store):
        run_id = save_run(store, "alice", "sample", "h1")
        assert get_run_results(store, run_id) == []

    def test_results_have_db_id(self, store):
        run_id = save_run(store, "alice", "sample", "h1")
        save_results(store, run_id, [{"ip_address": "1.1.1.1", "hour_bucket": "2024-01-01T00:00:00"}])
        results = get_run_results(store, run_id)
        assert "id" in results[0]


class TestChainsCRUD:
    def test_save_and_get_chains(self, store):
        run_id = save_run(store, "alice", "sample", "h1")
        chains = [{"chain_id": 0, "ip_address": "1.2.3.4", "severity": "High"}]
        save_chains(store, run_id, chains)
        loaded = get_chains(store, run_id)
        assert len(loaded) == 1
        assert loaded[0]["ip_address"] == "1.2.3.4"
        assert "id" in loaded[0]

    def test_get_chains_empty(self, store):
        run_id = save_run(store, "alice", "sample", "h1")
        assert get_chains(store, run_id) == []

    def test_get_chain_by_id(self, store):
        run_id = save_run(store, "alice", "sample", "h1")
        save_chains(store, run_id, [{"chain_id": 0, "ip_address": "1.2.3.4"}])
        all_chains = get_chains(store, run_id)
        chain_db_id = all_chains[0]["id"]
        chain = get_chain(store, run_id, chain_db_id)
        assert chain is not None
        assert chain["ip_address"] == "1.2.3.4"

    def test_get_chain_not_found(self, store):
        run_id = save_run(store, "alice", "sample", "h1")
        assert get_chain(store, run_id, 9999) is None

    def test_get_chain_wrong_run(self, store):
        """A chain belonging to run A must not be accessible via run B."""
        run_a = save_run(store, "alice", "sample", "h1")
        run_b = save_run(store, "bob", "sample", "h2")
        save_chains(store, run_a, [{"chain_id": 0, "ip_address": "1.2.3.4"}])
        chains_a = get_chains(store, run_a)
        chain_id = chains_a[0]["id"]
        # Should not be found when queried under run_b
        assert get_chain(store, run_b, chain_id) is None
