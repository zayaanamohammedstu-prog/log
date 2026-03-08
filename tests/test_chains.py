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

from pipeline.attack_chain import build_chains, classify_attack_stage


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

    def test_chain_includes_stages_field(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.8))
        chain = build_chains(df)[0]
        assert "stages" in chain
        assert isinstance(chain["stages"], list)

    def test_chain_includes_tactic_field(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.8))
        chain = build_chains(df)[0]
        assert "tactic" in chain
        assert isinstance(chain["tactic"], str)

    def test_narrative_contains_tactic(self):
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.8))
        chain = build_chains(df)[0]
        assert "Tactic:" in chain["narrative"]


# ---------------------------------------------------------------------------
# classify_attack_stage
# ---------------------------------------------------------------------------

class TestClassifyAttackStage:
    def test_scanner_ua_maps_to_reconnaissance(self):
        assert classify_attack_stage(["SCANNER_UA"]) == "Reconnaissance"

    def test_high_error_rate_maps_to_scanning_exploitation(self):
        assert classify_attack_stage(["HIGH_ERROR_RATE"]) == "Scanning/Exploitation"

    def test_volume_spike_maps_to_volumetric_attack(self):
        assert classify_attack_stage(["VOLUME_SPIKE"]) == "Volumetric Attack"

    def test_bytes_spike_maps_to_data_exfiltration(self):
        assert classify_attack_stage(["BYTES_SPIKE"]) == "Data Exfiltration"

    def test_off_hours_maps_to_suspicious_activity(self):
        assert classify_attack_stage(["OFF_HOURS"]) == "Suspicious Activity"

    def test_off_hours_combined_maps_to_suspicious_activity(self):
        assert classify_attack_stage(["OFF_HOURS_COMBINED"]) == "Suspicious Activity"

    def test_empty_reasons_returns_unknown(self):
        assert classify_attack_stage([]) == "Unknown"

    def test_unknown_reason_code_returns_unknown(self):
        assert classify_attack_stage(["SOME_UNKNOWN_CODE"]) == "Unknown"

    def test_scanner_takes_priority_over_off_hours(self):
        """SCANNER_UA has higher priority than OFF_HOURS."""
        assert classify_attack_stage(["SCANNER_UA", "OFF_HOURS"]) == "Reconnaissance"

    def test_data_exfiltration_priority_over_suspicious_activity(self):
        assert classify_attack_stage(["BYTES_SPIKE", "OFF_HOURS"]) == "Data Exfiltration"

    def test_multiple_same_stage_returns_one_stage(self):
        result = classify_attack_stage(["OFF_HOURS", "OFF_HOURS_COMBINED"])
        assert result == "Suspicious Activity"


# ---------------------------------------------------------------------------
# Tactic classification via build_chains (with explanations_json)
# ---------------------------------------------------------------------------

def _df_with_exp(*rows) -> pd.DataFrame:
    """Build anomalies DataFrame including explanations_json.

    Each row is (ip, hour_str, score, reasons_list) where reasons_list is a
    list of reason-code strings like ["SCANNER_UA"].
    """
    import json as _json
    return pd.DataFrame(
        {
            "ip_address": [r[0] for r in rows],
            "hour_bucket": pd.to_datetime([r[1] for r in rows]),
            "anomaly_score": [r[2] for r in rows],
            "ensemble_score": [r[2] for r in rows],
            "explanations_json": [
                # reasons is stored as a list of [code, description] pairs;
                # we reuse the code string as a placeholder description here.
                _json.dumps({"reasons": [[c, c] for c in r[3]], "feature_deviations": []})
                for r in rows
            ],
        }
    )


class TestChainTacticClassification:
    def test_single_scanner_chain_tactic_reconnaissance(self):
        df = _df_with_exp(("1.2.3.4", "2024-01-01 01:00", 0.9, ["SCANNER_UA"]))
        chain = build_chains(df)[0]
        assert chain["tactic"] == "Reconnaissance"

    def test_single_exfil_chain_tactic_data_exfiltration(self):
        df = _df_with_exp(("1.2.3.4", "2024-01-01 01:00", 0.9, ["BYTES_SPIKE"]))
        chain = build_chains(df)[0]
        assert chain["tactic"] == "Data Exfiltration"

    def test_mixed_stages_yields_multi_stage_attack(self):
        df = _df_with_exp(
            ("1.2.3.4", "2024-01-01 01:00", 0.9, ["SCANNER_UA"]),
            ("1.2.3.4", "2024-01-01 02:00", 0.8, ["BYTES_SPIKE"]),
        )
        chain = build_chains(df, time_gap_hours=2)[0]
        assert chain["tactic"] == "Multi-Stage Attack"

    def test_no_explanations_tactic_unknown(self):
        """Chains built without explanations_json default to Unknown tactic."""
        df = _df(("1.2.3.4", "2024-01-01 01:00", 0.8))
        chain = build_chains(df)[0]
        assert chain["tactic"] == "Unknown"

    def test_stages_list_deduplicated(self):
        """Two anomalies with the same stage → only one unique stage in chain."""
        df = _df_with_exp(
            ("1.2.3.4", "2024-01-01 01:00", 0.9, ["SCANNER_UA"]),
            ("1.2.3.4", "2024-01-01 02:00", 0.8, ["SCANNER_UA"]),
        )
        chain = build_chains(df, time_gap_hours=2)[0]
        assert chain["stages"] == ["Reconnaissance"]
        assert chain["tactic"] == "Reconnaissance"
