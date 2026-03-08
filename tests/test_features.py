"""
tests/test_features.py
-----------------------
Unit tests for pipeline.feature_engineering.
"""

import pytest
import pandas as pd
import numpy as np
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.feature_engineering import engineer_features, get_feature_matrix, _FEATURE_COLUMNS
from pipeline.log_parser import parse_log_lines
from pipeline.baselines import build_behavioral_profiles


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_df(lines):
    return parse_log_lines(lines)


# ── Sample log lines ─────────────────────────────────────────────────────────

NORMAL_LINES = [
    '10.0.0.1 - - [15/Jan/2024:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    '10.0.0.1 - - [15/Jan/2024:08:10:00 +0000] "GET /about.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    '10.0.0.2 - - [15/Jan/2024:08:05:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
]

ATTACK_LINES = [
    '192.168.99.1 - - [15/Jan/2024:03:00:00 +0000] "POST /login HTTP/1.1" 401 128 "-" "Nikto/2.1.6"',
    '192.168.99.1 - - [15/Jan/2024:03:01:00 +0000] "POST /login HTTP/1.1" 401 128 "-" "Nikto/2.1.6"',
    '192.168.99.1 - - [15/Jan/2024:03:02:00 +0000] "POST /login HTTP/1.1" 401 128 "-" "Nikto/2.1.6"',
]


# ── Tests ────────────────────────────────────────────────────────────────────

class TestEngineerFeatures:
    def test_returns_dataframe(self):
        df = _make_df(NORMAL_LINES)
        features = engineer_features(df)
        assert isinstance(features, pd.DataFrame)

    def test_expected_columns(self):
        df = _make_df(NORMAL_LINES)
        features = engineer_features(df)
        for col in _FEATURE_COLUMNS:
            assert col in features.columns, f"Missing column: {col}"
        assert "ip_address" in features.columns
        assert "hour_bucket" in features.columns

    def test_grouping_by_ip_and_hour(self):
        df = _make_df(NORMAL_LINES)
        features = engineer_features(df)
        # Two distinct IPs in the same hour → two rows
        assert len(features) == 2

    def test_requests_per_hour_counted(self):
        df = _make_df(NORMAL_LINES)
        features = engineer_features(df)
        ip1 = features[features["ip_address"] == "10.0.0.1"]
        assert ip1["requests_per_hour"].iloc[0] == 2

    def test_error_rate_computation(self):
        lines = [
            '10.0.0.5 - - [15/Jan/2024:09:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
            '10.0.0.5 - - [15/Jan/2024:09:10:00 +0000] "GET /b HTTP/1.1" 404 50 "-" "Mozilla/5.0"',
        ]
        df = _make_df(lines)
        features = engineer_features(df)
        row = features[features["ip_address"] == "10.0.0.5"].iloc[0]
        assert abs(row["error_rate"] - 0.5) < 1e-6

    def test_post_ratio(self):
        df = _make_df(ATTACK_LINES)
        features = engineer_features(df)
        row = features.iloc[0]
        assert row["post_ratio"] == 1.0  # all requests are POST

    def test_scanner_ua_detected(self):
        df = _make_df(ATTACK_LINES)
        features = engineer_features(df)
        assert features.iloc[0]["has_scanner_ua"] == 1

    def test_no_scanner_ua_normal(self):
        df = _make_df(NORMAL_LINES)
        features = engineer_features(df)
        assert features["has_scanner_ua"].sum() == 0

    def test_off_hours_flag(self):
        # ATTACK_LINES have timestamp at 03:00 UTC → is_off_hours should be 1
        df = _make_df(ATTACK_LINES)
        features = engineer_features(df)
        assert features.iloc[0]["is_off_hours"] == 1

    def test_empty_dataframe(self):
        features = engineer_features(pd.DataFrame())
        assert features.empty

    def test_no_nan_values(self):
        df = _make_df(NORMAL_LINES + ATTACK_LINES)
        features = engineer_features(df)
        assert not features[_FEATURE_COLUMNS].isnull().any().any()


class TestGetFeatureMatrix:
    def test_returns_numpy_array(self):
        df = _make_df(NORMAL_LINES)
        features = engineer_features(df)
        X = get_feature_matrix(features)
        assert isinstance(X, np.ndarray)

    def test_shape(self):
        df = _make_df(NORMAL_LINES)
        features = engineer_features(df)
        X = get_feature_matrix(features)
        assert X.shape == (len(features), len(_FEATURE_COLUMNS))

    def test_dtype_float(self):
        df = _make_df(NORMAL_LINES)
        features = engineer_features(df)
        X = get_feature_matrix(features)
        assert np.issubdtype(X.dtype, np.floating)


# ── Behavioral profiling tests ───────────────────────────────────────────────

class TestBuildBehavioralProfiles:
    """Tests for pipeline.baselines.build_behavioral_profiles."""

    def _features(self, lines):
        return engineer_features(_make_df(lines))

    def test_returns_dict(self):
        features = self._features(NORMAL_LINES)
        profiles = build_behavioral_profiles(features)
        assert isinstance(profiles, dict)

    def test_keys_are_ip_strings(self):
        features = self._features(NORMAL_LINES)
        profiles = build_behavioral_profiles(features)
        for key in profiles:
            assert isinstance(key, str)

    def test_one_profile_per_ip(self):
        features = self._features(NORMAL_LINES)
        profiles = build_behavioral_profiles(features)
        # NORMAL_LINES has two distinct IPs (10.0.0.1 and 10.0.0.2)
        assert len(profiles) == 2

    def test_profile_has_required_fields(self):
        features = self._features(NORMAL_LINES)
        profile = list(build_behavioral_profiles(features).values())[0]
        required = {
            "total_observations",
            "off_hours_ratio",
            "avg_requests_per_hour",
            "max_requests_per_hour",
            "avg_error_rate",
            "max_error_rate",
            "avg_bytes_sent",
            "avg_post_ratio",
            "has_scanner_activity",
            "category",
        }
        assert required.issubset(set(profile.keys()))

    def test_normal_ip_categorised_as_normal(self):
        features = self._features(NORMAL_LINES)
        profiles = build_behavioral_profiles(features)
        for profile in profiles.values():
            assert profile["category"] == "Normal"

    def test_scanner_ip_categorised_as_scanner(self):
        features = self._features(ATTACK_LINES)
        profiles = build_behavioral_profiles(features)
        assert profiles["192.168.99.1"]["category"] == "Scanner"

    def test_has_scanner_activity_true_for_attack_ip(self):
        features = self._features(ATTACK_LINES)
        profiles = build_behavioral_profiles(features)
        assert profiles["192.168.99.1"]["has_scanner_activity"] is True

    def test_has_scanner_activity_false_for_normal_ip(self):
        features = self._features(NORMAL_LINES)
        profiles = build_behavioral_profiles(features)
        for profile in profiles.values():
            assert profile["has_scanner_activity"] is False

    def test_empty_dataframe_returns_empty_dict(self):
        empty = engineer_features(pd.DataFrame())
        profiles = build_behavioral_profiles(empty)
        assert profiles == {}

    def test_baseline_embedded_when_provided(self):
        features = self._features(NORMAL_LINES)
        ip_baselines = {"10.0.0.1": {"requests_per_hour_median": 2.0}}
        profiles = build_behavioral_profiles(features, ip_baselines=ip_baselines)
        assert "baseline" in profiles["10.0.0.1"]
        assert profiles["10.0.0.1"]["baseline"]["requests_per_hour_median"] == 2.0

    def test_baseline_absent_when_not_provided(self):
        features = self._features(NORMAL_LINES)
        profiles = build_behavioral_profiles(features)
        for profile in profiles.values():
            assert "baseline" not in profile

    def test_total_observations_correct(self):
        features = self._features(NORMAL_LINES)
        profiles = build_behavioral_profiles(features)
        # 10.0.0.1 has 2 requests in the same hour → 1 observation row
        assert profiles["10.0.0.1"]["total_observations"] == 1
