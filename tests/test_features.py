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
