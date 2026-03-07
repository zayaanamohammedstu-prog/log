"""
tests/test_model.py
--------------------
Unit tests for model.anomaly_detector.
"""

import os
import sys
import tempfile

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from model.anomaly_detector import (
    build_pipeline,
    train,
    predict,
    save_model,
    load_model,
    run_full_analysis,
)
from pipeline.log_parser import parse_log_lines
from pipeline.feature_engineering import engineer_features


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_feature_df():
    """Create a minimal feature DataFrame from sample log lines."""
    lines = []
    # Normal traffic
    for i in range(20):
        h = 8 + (i % 8)
        lines.append(
            f'10.0.0.{i % 10 + 1} - - [15/Jan/2024:{h:02d}:{i * 2 % 60:02d}:00 +0000] '
            f'"GET /page HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        )
    # Obvious anomaly
    for i in range(30):
        lines.append(
            f'192.168.99.1 - - [15/Jan/2024:03:{i:02d}:00 +0000] '
            f'"POST /login HTTP/1.1" 401 50 "-" "Nikto/2.1.6"'
        )
    raw_df = parse_log_lines(lines)
    return engineer_features(raw_df)


# ── Tests ────────────────────────────────────────────────────────────────────

class TestBuildPipeline:
    def test_returns_pipeline(self):
        from sklearn.pipeline import Pipeline
        p = build_pipeline()
        assert isinstance(p, Pipeline)

    def test_custom_contamination(self):
        p = build_pipeline(contamination=0.1)
        assert p.named_steps["iforest"].contamination == 0.1


class TestTrainPredict:
    def setup_method(self):
        self.features = _make_feature_df()
        from pipeline.feature_engineering import get_feature_matrix
        self.X = get_feature_matrix(self.features)

    def test_train_returns_fitted_pipeline(self):
        pipeline = train(self.X)
        # A fitted Isolation Forest has estimators_
        assert hasattr(pipeline.named_steps["iforest"], "estimators_")

    def test_predict_labels_shape(self):
        pipeline = train(self.X)
        labels, scores = predict(pipeline, self.X)
        assert labels.shape == (len(self.X),)
        assert scores.shape == (len(self.X),)

    def test_predict_labels_values(self):
        pipeline = train(self.X)
        labels, _ = predict(pipeline, self.X)
        unique = set(labels.tolist())
        assert unique.issubset({1, -1})

    def test_scores_in_range(self):
        pipeline = train(self.X)
        _, scores = predict(pipeline, self.X)
        assert scores.min() >= 0.0 - 1e-9
        assert scores.max() <= 1.0 + 1e-9

    def test_anomaly_ip_gets_higher_score(self):
        """The brute-force IP should have a higher anomaly score than average."""
        pipeline = train(self.X)
        _, scores = predict(pipeline, self.X)
        # Identify the row index for 192.168.99.1
        attack_mask = self.features["ip_address"] == "192.168.99.1"
        if not attack_mask.any():
            pytest.skip("Attack IP not in feature set")
        attack_scores = scores[attack_mask.to_numpy()]
        normal_scores  = scores[~attack_mask.to_numpy()]
        assert attack_scores.mean() > normal_scores.mean()


class TestSaveLoadModel:
    def test_save_and_load(self):
        features = _make_feature_df()
        from pipeline.feature_engineering import get_feature_matrix
        X = get_feature_matrix(features)
        pipeline = train(X)

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            save_model(pipeline, tmp_path)
            loaded = load_model(tmp_path)

            labels_orig, scores_orig = predict(pipeline, X)
            labels_load, scores_load = predict(loaded,   X)

            np.testing.assert_array_equal(labels_orig, labels_load)
            np.testing.assert_allclose(scores_orig, scores_load, atol=1e-10)
        finally:
            os.unlink(tmp_path)


class TestRunFullAnalysis:
    def test_returns_annotated_df(self):
        features = _make_feature_df()
        result = run_full_analysis(features)
        assert "is_anomaly" in result.columns
        assert "anomaly_score" in result.columns

    def test_is_anomaly_is_bool(self):
        features = _make_feature_df()
        result = run_full_analysis(features)
        assert result["is_anomaly"].dtype == bool

    def test_anomaly_count_positive(self):
        features = _make_feature_df()
        result = run_full_analysis(features)
        assert result["is_anomaly"].sum() > 0

    def test_model_saved_and_reloaded(self):
        features = _make_feature_df()
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
            tmp_path = tmp.name
        os.unlink(tmp_path)   # delete so run_full_analysis trains fresh

        try:
            result1 = run_full_analysis(features, model_path=tmp_path)
            assert os.path.exists(tmp_path)
            result2 = run_full_analysis(features, model_path=tmp_path)
            pd.testing.assert_series_equal(
                result1["is_anomaly"].reset_index(drop=True),
                result2["is_anomaly"].reset_index(drop=True),
            )
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
