"""
tests/test_ensemble.py
----------------------
Unit tests for model/ensemble.py (4-model ensemble incl. Autoencoder).
"""

from __future__ import annotations

import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from model.ensemble import run_ensemble
from model.autoencoder import run_autoencoder


def _make_X(n: int = 100, n_features: int = 8, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.standard_normal((n, n_features))


def _make_X_with_outliers(
    n_normal: int = 95,
    n_outliers: int = 5,
    n_features: int = 4,
    seed: int = 0,
) -> np.ndarray:
    rng = np.random.default_rng(seed)
    X_normal = rng.standard_normal((n_normal, n_features))
    X_outliers = rng.standard_normal((n_outliers, n_features)) * 20
    return np.vstack([X_outliers, X_normal])


class TestRunEnsembleReturnShape:
    def test_returns_dict_with_expected_keys(self):
        X = _make_X()
        result = run_ensemble(X)
        assert set(result.keys()) == {
            "per_model_scores",
            "per_model_flags",
            "ensemble_score",
            "ensemble_label",
            "agreement_pct",
        }

    def test_per_model_keys(self):
        X = _make_X(50)
        result = run_ensemble(X)
        for key in ("per_model_scores", "per_model_flags"):
            assert set(result[key].keys()) == {
                "isolation_forest", "lof", "ocsvm", "autoencoder"
            }

    def test_all_lists_have_correct_length(self):
        n = 60
        X = _make_X(n)
        result = run_ensemble(X)
        assert len(result["ensemble_score"]) == n
        assert len(result["ensemble_label"]) == n
        for model in ("isolation_forest", "lof", "ocsvm", "autoencoder"):
            assert len(result["per_model_scores"][model]) == n
            assert len(result["per_model_flags"][model]) == n


class TestRunEnsembleValues:
    def test_ensemble_scores_in_unit_range(self):
        X = _make_X()
        result = run_ensemble(X)
        for s in result["ensemble_score"]:
            assert 0.0 <= s <= 1.0, f"score {s} out of range"

    def test_per_model_scores_in_unit_range(self):
        X = _make_X()
        result = run_ensemble(X)
        for model in ("isolation_forest", "lof", "ocsvm", "autoencoder"):
            for s in result["per_model_scores"][model]:
                assert 0.0 <= s <= 1.0

    def test_ensemble_labels_are_bool(self):
        X = _make_X()
        result = run_ensemble(X)
        for lbl in result["ensemble_label"]:
            assert isinstance(lbl, bool)

    def test_per_model_flags_are_bool(self):
        X = _make_X()
        result = run_ensemble(X)
        for model in ("isolation_forest", "lof", "ocsvm", "autoencoder"):
            for flag in result["per_model_flags"][model]:
                assert isinstance(flag, bool)

    def test_agreement_pct_in_unit_range(self):
        X = _make_X()
        result = run_ensemble(X)
        assert 0.0 <= result["agreement_pct"] <= 1.0


class TestRunEnsembleAnomalyDetection:
    def test_detects_obvious_outliers(self):
        X = _make_X_with_outliers(n_outliers=5, n_normal=95)
        result = run_ensemble(X, contamination=0.05)
        # The first 5 rows are extreme outliers – at least 3 should be flagged
        outlier_flags = result["ensemble_label"][:5]
        assert sum(outlier_flags) >= 3

    def test_contamination_affects_anomaly_count(self):
        X = _make_X(100)
        r_low = run_ensemble(X, contamination=0.01)
        r_high = run_ensemble(X, contamination=0.15)
        low_count = sum(r_low["ensemble_label"])
        high_count = sum(r_high["ensemble_label"])
        # Higher contamination should generally yield more anomalies
        assert high_count >= low_count

    def test_small_dataset(self):
        """Ensemble should handle datasets as small as 3 samples."""
        X = np.array([[1.0, 2.0], [3.0, 4.0], [100.0, 200.0]])
        result = run_ensemble(X, contamination=0.05)
        assert len(result["ensemble_score"]) == 3


# ============================================================
# Autoencoder-specific tests
# ============================================================

class TestAutoencoderReturnShape:
    def test_returns_two_arrays(self):
        X = _make_X(50)
        scores, flags = run_autoencoder(X)
        assert len(scores) == 50
        assert len(flags) == 50

    def test_scores_in_unit_range(self):
        X = _make_X(60)
        scores, _ = run_autoencoder(X)
        assert all(0.0 <= s <= 1.0 for s in scores)

    def test_flags_are_bool(self):
        X = _make_X(40)
        _, flags = run_autoencoder(X)
        for f in flags:
            assert isinstance(f, (bool, np.bool_))

    def test_flag_count_matches_contamination(self):
        """With contamination=0.10 on 100 samples, expect ~10 flags."""
        X = _make_X(100)
        _, flags = run_autoencoder(X, contamination=0.10)
        # Expect ~10% flagged; allow ±7 tolerance for threshold rounding
        flag_count = int(np.sum(flags))
        assert 3 <= flag_count <= 17

    def test_detects_obvious_outliers(self):
        X = _make_X_with_outliers(n_outliers=5, n_normal=95, n_features=4)
        scores, flags = run_autoencoder(X, contamination=0.05)
        # Extreme outliers should have higher scores than normal samples
        outlier_scores = scores[:5]
        normal_scores = scores[5:]
        assert outlier_scores.mean() > normal_scores.mean()

    def test_small_dataset(self):
        """Autoencoder should handle very small datasets (3 samples)."""
        X = np.array([[1.0, 2.0], [3.0, 4.0], [100.0, 200.0]])
        scores, flags = run_autoencoder(X, contamination=0.05)
        assert len(scores) == 3
        assert len(flags) == 3

