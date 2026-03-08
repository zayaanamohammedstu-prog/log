"""
tests/test_explain.py
---------------------
Unit tests for model/explain.py.
"""

from __future__ import annotations

import json
import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from model.explain import explain_anomaly, explain_all, REASON_CODES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_baselines() -> dict:
    """Synthetic global baselines (24 hours, uniform stats)."""
    cols_flat = {}
    for col in ("requests_per_hour", "error_rate", "unique_endpoints",
                "avg_bytes_sent", "post_ratio"):
        cols_flat[f"{col}_mean"] = [5.0] * 24
        cols_flat[f"{col}_std"] = [2.0] * 24
        cols_flat[f"{col}_median"] = [4.0] * 24
    df = pd.DataFrame(cols_flat, index=range(24))
    df.index.name = "hour_of_day"
    return {"hourly": df}


def _normal_row() -> dict:
    return {
        "ip_address": "1.2.3.4",
        "has_scanner_ua": 0,
        "is_off_hours": 0,
        "error_rate": 0.05,
        "requests_per_hour": 5,
        "avg_bytes_sent": 512,
        "post_ratio": 0.1,
        "unique_endpoints": 3,
        "is_anomaly": False,
    }


# ---------------------------------------------------------------------------
# Tests for explain_anomaly
# ---------------------------------------------------------------------------

class TestExplainAnomaly:
    def test_returns_required_keys(self):
        row = _normal_row()
        result = explain_anomaly(row, _make_baselines(), {})
        assert "reasons" in result
        assert "feature_deviations" in result

    def test_scanner_ua_adds_reason(self):
        row = {**_normal_row(), "has_scanner_ua": 1}
        result = explain_anomaly(row, _make_baselines(), {})
        codes = [r[0] for r in result["reasons"]]
        assert "SCANNER_UA" in codes

    def test_high_error_rate_adds_reason(self):
        row = {**_normal_row(), "error_rate": 0.5}
        result = explain_anomaly(row, _make_baselines(), {})
        codes = [r[0] for r in result["reasons"]]
        assert "HIGH_ERROR_RATE" in codes

    def test_error_rate_below_threshold_no_reason(self):
        row = {**_normal_row(), "error_rate": 0.10}
        result = explain_anomaly(row, _make_baselines(), {})
        codes = [r[0] for r in result["reasons"]]
        assert "HIGH_ERROR_RATE" not in codes

    def test_off_hours_combined_when_high_volume(self):
        row = {**_normal_row(), "is_off_hours": 1, "requests_per_hour": 50}
        result = explain_anomaly(row, _make_baselines(), {})
        codes = [r[0] for r in result["reasons"]]
        assert "OFF_HOURS_COMBINED" in codes
        assert "OFF_HOURS" not in codes

    def test_off_hours_only_when_low_volume(self):
        row = {**_normal_row(), "is_off_hours": 1, "requests_per_hour": 3}
        result = explain_anomaly(row, _make_baselines(), {})
        codes = [r[0] for r in result["reasons"]]
        assert "OFF_HOURS" in codes
        assert "OFF_HOURS_COMBINED" not in codes

    def test_feature_deviations_contain_expected_fields(self):
        row = _normal_row()
        result = explain_anomaly(row, _make_baselines(), {})
        assert len(result["feature_deviations"]) > 0
        for dev in result["feature_deviations"]:
            assert "feature" in dev
            assert "value" in dev
            assert "z_score" in dev
            assert "percentile" in dev

    def test_accepts_pandas_series(self):
        row = pd.Series(_normal_row())
        result = explain_anomaly(row, _make_baselines(), {})
        assert "reasons" in result

    def test_volume_spike_detected(self):
        # z-score > 2 for requests_per_hour (mean=5, std=2, value=100)
        row = {**_normal_row(), "requests_per_hour": 100}
        result = explain_anomaly(row, _make_baselines(), {})
        codes = [r[0] for r in result["reasons"]]
        assert "VOLUME_SPIKE" in codes

    def test_empty_baselines_no_crash(self):
        row = _normal_row()
        result = explain_anomaly(row, {"hourly": pd.DataFrame()}, {})
        assert "reasons" in result

    def test_reason_descriptions_match_codes(self):
        row = {**_normal_row(), "has_scanner_ua": 1, "error_rate": 0.5}
        result = explain_anomaly(row, _make_baselines(), {})
        for code, description in result["reasons"]:
            assert code in REASON_CODES
            assert REASON_CODES[code] == description

    def test_ip_baselines_do_not_crash(self):
        """explain_anomaly must not raise when ip_baselines contains this IP."""
        row = {**_normal_row(), "ip_address": "known_ip", "requests_per_hour": 50}
        ip_baselines = {
            "known_ip": {
                "requests_per_hour_median": 5.0,
                "requests_per_hour_mean": 5.0,
                "error_rate_median": 0.02,
            }
        }
        result = explain_anomaly(row, _make_baselines(), ip_baselines)
        assert "reasons" in result
        assert "feature_deviations" in result

    def test_ip_baselines_and_global_both_provided(self):
        """Function should work correctly with both ip_baselines and global baselines."""
        row = {**_normal_row(), "ip_address": "10.0.0.1"}
        ip_baselines = {"10.0.0.1": {"requests_per_hour_median": 3.0}}
        result_with = explain_anomaly(row, _make_baselines(), ip_baselines)
        result_without = explain_anomaly(row, _make_baselines(), {})
        # Both should return valid dicts with the required structure
        assert isinstance(result_with["reasons"], list)
        assert isinstance(result_without["reasons"], list)


# ---------------------------------------------------------------------------
# Tests for explain_all
# ---------------------------------------------------------------------------

class TestExplainAll:
    def _make_df(self) -> pd.DataFrame:
        return pd.DataFrame(
            {
                "ip_address": ["1.2.3.4", "5.6.7.8"],
                "hour_bucket": ["2024-01-01T08:00:00", "2024-01-01T03:00:00"],
                "is_anomaly": [False, True],
                "has_scanner_ua": [0, 1],
                "is_off_hours": [0, 1],
                "error_rate": [0.05, 0.5],
                "requests_per_hour": [5, 100],
                "avg_bytes_sent": [512, 10000],
                "post_ratio": [0.1, 0.8],
                "unique_endpoints": [3, 50],
            }
        )

    def test_adds_explanations_json_column(self):
        df = self._make_df()
        result = explain_all(df, _make_baselines(), {})
        assert "explanations_json" in result.columns

    def test_returns_modified_copy(self):
        df = self._make_df()
        result = explain_all(df, _make_baselines(), {})
        assert "explanations_json" not in df.columns  # original unchanged

    def test_normal_row_has_empty_reasons(self):
        df = self._make_df()
        result = explain_all(df, _make_baselines(), {})
        exp = json.loads(result.iloc[0]["explanations_json"])
        assert exp["reasons"] == []

    def test_anomaly_row_has_reasons(self):
        df = self._make_df()
        result = explain_all(df, _make_baselines(), {})
        exp = json.loads(result.iloc[1]["explanations_json"])
        assert len(exp["reasons"]) > 0

    def test_explanations_json_is_valid_json(self):
        df = self._make_df()
        result = explain_all(df, _make_baselines(), {})
        for val in result["explanations_json"]:
            parsed = json.loads(val)
            assert "reasons" in parsed
            assert "feature_deviations" in parsed
