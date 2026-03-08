"""
tests/test_chains.py
--------------------
Unit tests for pipeline/attack_chain.py.
"""

from __future__ import annotations

import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.attack_chain import build_chains


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _df(*rows) -> pd.DataFrame:
    """Build a minimal anomalies DataFrame from (ip, hour_str, score) tuples."""
    return pd.DataFrame(
        {
            "ip_address": [r[0] for r in rows],
            "hour_bucket": pd.to_datetime([r[1] for r in rows]),
            "anomaly_score": [r[2] for r in rows],
            "ensemble_score": [r[2] for r in rows],
        }
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBuildChainsBasic:
    def test_empty_dataframe_returns_empty(self):
        assert build_chains(pd.DataFrame()) == []

    def test_returns_list(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.8))
        assert isinstance(build_chains(df), list)

    def test_single_row_produces_one_chain(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.8))
        chains = build_chains(df)
        assert len(chains) == 1

    def test_chain_has_required_fields(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.8))
        chain = build_chains(df)[0]
        required = {
            "chain_id", "ip_address", "start_time", "end_time",
            "anomaly_count", "max_score", "severity", "narrative",
            "anomaly_ids",
        }
        assert required.issubset(set(chain.keys()))


class TestBuildChainsGrouping:
    def test_adjacent_rows_same_ip_same_chain(self):
        """Rows 1 h apart (within default 2 h gap) → same chain."""
        df = _df(
            ("1.2.3.4", "2024-01-01 01:00", 0.8),
            ("1.2.3.4", "2024-01-01 02:00", 0.9),
        )
        chains = build_chains(df, time_gap_hours=2)
        assert len(chains) == 1
        assert chains[0]["anomaly_count"] == 2

    def test_distant_rows_same_ip_separate_chains(self):
        """Rows 8 h apart (beyond 2 h gap) → separate chains."""
        df = _df(
            ("1.2.3.4", "2024-01-01 01:00", 0.8),
            ("1.2.3.4", "2024-01-01 09:00", 0.7),
        )
        chains = build_chains(df, time_gap_hours=2)
        assert len(chains) == 2

    def test_different_ips_always_separate_chains(self):
        df = _df(
            ("1.2.3.4", "2024-01-01 01:00", 0.8),
            ("9.9.9.9", "2024-01-01 01:00", 0.7),
        )
        chains = build_chains(df)
        ips = {c["ip_address"] for c in chains}
        assert "1.2.3.4" in ips
        assert "9.9.9.9" in ips
        assert len(chains) == 2

    def test_three_rows_two_adjacent_one_separate(self):
        """01:00 and 02:00 same chain; 10:00 separate chain."""
        df = _df(
            ("1.2.3.4", "2024-01-01 01:00", 0.8),
            ("1.2.3.4", "2024-01-01 02:00", 0.9),
            ("1.2.3.4", "2024-01-01 10:00", 0.7),
        )
        chains = build_chains(df, time_gap_hours=2)
        assert len(chains) == 2
        counts = sorted(c["anomaly_count"] for c in chains)
        assert counts == [1, 2]

    def test_full_mixed_scenario(self):
        """IP A: 2 adjacent + 1 separate; IP B: 1. Total = 3 chains."""
        df = _df(
            ("A", "2024-01-01 01:00", 0.8),
            ("A", "2024-01-01 02:00", 0.9),
            ("A", "2024-01-01 10:00", 0.7),
            ("B", "2024-01-01 01:00", 0.6),
        )
        chains = build_chains(df, time_gap_hours=2)
        assert len(chains) == 3


class TestBuildChainsSeverity:
    def test_critical_severity(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.9))
        chains = build_chains(df)
        assert chains[0]["severity"] == "Critical"

    def test_high_severity(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.6))
        chains = build_chains(df)
        assert chains[0]["severity"] == "High"

    def test_medium_severity(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.3))
        chains = build_chains(df)
        assert chains[0]["severity"] == "Medium"


class TestBuildChainsMetrics:
    def test_max_score_correct(self):
        df = _df(
            ("1.2.3.4", "2024-01-01 01:00", 0.7),
            ("1.2.3.4", "2024-01-01 02:00", 0.9),
        )
        chains = build_chains(df, time_gap_hours=2)
        assert abs(chains[0]["max_score"] - 0.9) < 0.01

    def test_start_end_time_correct(self):
        df = _df(
            ("1.2.3.4", "2024-01-01 01:00", 0.8),
            ("1.2.3.4", "2024-01-01 03:00", 0.9),
        )
        chains = build_chains(df, time_gap_hours=4)
        c = chains[0]
        assert "2024-01-01T01:00" in c["start_time"]
        assert "2024-01-01T03:00" in c["end_time"]

    def test_anomaly_ids_are_list(self):
        df = _df(
            ("1.2.3.4", "2024-01-01 01:00", 0.8),
            ("1.2.3.4", "2024-01-01 02:00", 0.9),
        )
        chains = build_chains(df, time_gap_hours=2)
        assert isinstance(chains[0]["anomaly_ids"], list)
        assert len(chains[0]["anomaly_ids"]) == 2

    def test_narrative_contains_ip(self):
        df = _df(("192.168.1.1", "2024-01-01 01:00", 0.8))
        chains = build_chains(df)
        assert "192.168.1.1" in chains[0]["narrative"]
