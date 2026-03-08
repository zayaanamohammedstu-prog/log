"""
tests/test_ledger.py
--------------------
Unit tests for app/audit_ledger.py.
"""

from __future__ import annotations

import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.audit_ledger import (
    init_ledger,
    append_entry,
    get_all_entries,
    verify_chain,
)


@pytest.fixture
def ledger(tmp_path):
    """Initialised ledger directory."""
    init_ledger(str(tmp_path))
    return str(tmp_path)


class TestLedgerInit:
    def test_init_creates_table(self, tmp_path):
        init_ledger(str(tmp_path))
        db = os.path.join(str(tmp_path), "logguard.db")
        assert os.path.exists(db)
        conn = sqlite3.connect(db)
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()
        assert "ledger_entries" in tables

    def test_idempotent(self, tmp_path):
        """Calling init_ledger twice must not raise."""
        init_ledger(str(tmp_path))
        init_ledger(str(tmp_path))


class TestLedgerEmpty:
    def test_empty_chain_is_valid(self, ledger):
        result = verify_chain(ledger)
        assert result["valid"] is True
        assert result["entry_count"] == 0
        assert result["error"] is None

    def test_get_all_entries_empty(self, ledger):
        assert get_all_entries(ledger) == []


class TestAppendEntry:
    def test_append_single_entry(self, ledger):
        append_entry(ledger, "alice", "input_hash_1", "results_hash_1")
        entries = get_all_entries(ledger)
        assert len(entries) == 1

    def test_entry_fields(self, ledger):
        append_entry(ledger, "alice", "ih1", "rh1", config_hash="ch1")
        entry = get_all_entries(ledger)[0]
        assert entry["actor"] == "alice"
        assert entry["input_hash"] == "ih1"
        assert entry["results_hash"] == "rh1"
        assert entry["config_hash"] == "ch1"
        assert "timestamp" in entry
        assert "entry_hash" in entry
        assert "prev_hash" in entry

    def test_first_entry_prev_hash_is_genesis(self, ledger):
        append_entry(ledger, "alice", "ih1", "rh1")
        entry = get_all_entries(ledger)[0]
        assert entry["prev_hash"] == "0" * 64

    def test_second_entry_prev_hash_links(self, ledger):
        append_entry(ledger, "alice", "ih1", "rh1")
        append_entry(ledger, "bob", "ih2", "rh2")
        entries = get_all_entries(ledger)
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]

    def test_multiple_entries_ordered(self, ledger):
        for i in range(5):
            append_entry(ledger, f"user{i}", f"ih{i}", f"rh{i}")
        entries = get_all_entries(ledger)
        assert len(entries) == 5
        ids = [e["id"] for e in entries]
        assert ids == sorted(ids)


class TestVerifyChain:
    def test_valid_single_entry(self, ledger):
        append_entry(ledger, "alice", "h1", "r1")
        result = verify_chain(ledger)
        assert result["valid"] is True
        assert result["entry_count"] == 1

    def test_valid_multiple_entries(self, ledger):
        for i in range(5):
            append_entry(ledger, f"u{i}", f"h{i}", f"r{i}")
        result = verify_chain(ledger)
        assert result["valid"] is True
        assert result["entry_count"] == 5
        assert result["error"] is None

    def test_tampered_results_hash_invalidates_chain(self, ledger):
        append_entry(ledger, "alice", "h1", "r1")
        append_entry(ledger, "bob", "h2", "r2")
        db_path = os.path.join(ledger, "logguard.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            "UPDATE ledger_entries SET results_hash='tampered' WHERE id=1"
        )
        conn.commit()
        conn.close()
        result = verify_chain(ledger)
        assert result["valid"] is False
        assert result["error"] is not None

    def test_tampered_entry_hash_invalidates_chain(self, ledger):
        append_entry(ledger, "alice", "h1", "r1")
        db_path = os.path.join(ledger, "logguard.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            "UPDATE ledger_entries SET entry_hash='deadbeef' WHERE id=1"
        )
        conn.commit()
        conn.close()
        result = verify_chain(ledger)
        assert result["valid"] is False

    def test_tampered_prev_hash_invalidates_chain(self, ledger):
        append_entry(ledger, "alice", "h1", "r1")
        append_entry(ledger, "bob", "h2", "r2")
        db_path = os.path.join(ledger, "logguard.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            "UPDATE ledger_entries SET prev_hash='badhash' WHERE id=2"
        )
        conn.commit()
        conn.close()
        result = verify_chain(ledger)
        assert result["valid"] is False

    def test_default_config_hash_empty_string(self, ledger):
        append_entry(ledger, "alice", "h1", "r1")  # config_hash defaults to ""
        result = verify_chain(ledger)
        assert result["valid"] is True
