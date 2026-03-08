"""
model/ensemble.py
-----------------
Multi-model ensemble: IsolationForest + LOF + OneClassSVM.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# Minimum samples required to run the full ensemble
_MIN_SAMPLES = 3


def _normalize(scores: np.ndarray) -> np.ndarray:
    """Min-max normalise to [0, 1] where higher means *more anomalous*."""
    min_s, max_s = scores.min(), scores.max()
    if max_s == min_s:
        return np.zeros(len(scores), dtype=float)
    return (scores - min_s) / (max_s - min_s)


def run_ensemble(
    X: np.ndarray,
    contamination: float = 0.05,
    random_state: int = 42,
) -> dict:
    """
    Fit all three models on *X* and return an ensemble result dict:

    .. code-block:: python

        {
            "per_model_scores": {
                "isolation_forest": [...],
                "lof": [...],
                "ocsvm": [...],
            },
            "per_model_flags": {
                "isolation_forest": [...],  # list[bool]
                "lof": [...],
                "ocsvm": [...],
            },
            "ensemble_score": [...],   # average of normalised per-model scores
            "ensemble_label": [...],   # True if majority vote says anomaly
            "agreement_pct": float,    # fraction where all models agree
        }

    Parameters
    ----------
    X : np.ndarray
        Feature matrix (n_samples × n_features).
    contamination : float
        Expected fraction of anomalies (passed to each model).
    random_state : int
        Seed for reproducible results.
    """
    n = len(X)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── IsolationForest ──────────────────────────────────────────────────────
    iforest = IsolationForest(
        contamination=contamination,
        n_estimators=100,
        random_state=random_state,
    )
    iforest.fit(X_scaled)
    if_labels = iforest.predict(X_scaled)          # 1=normal, -1=anomaly
    if_raw = iforest.decision_function(X_scaled)   # higher = more normal
    if_scores = _normalize(-if_raw)                # invert → higher = anomaly
    if_flags: np.ndarray = if_labels == -1

    # ── LocalOutlierFactor (novelty=False, same-data) ────────────────────────
    # Cap n_neighbors at 20 to bound memory/runtime; require at least 1 so
    # the algorithm can run on any non-trivial dataset.
    n_neighbors = max(1, min(20, n - 1))
    lof = LocalOutlierFactor(
        n_neighbors=n_neighbors,
        contamination=contamination,
    )
    lof_labels = lof.fit_predict(X_scaled)          # 1=normal, -1=anomaly
    # negative_outlier_factor_: more negative → more anomalous; invert first
    lof_raw = -lof.negative_outlier_factor_         # now higher = more anomalous
    lof_scores = _normalize(lof_raw)
    lof_flags: np.ndarray = lof_labels == -1

    # ── OneClassSVM ──────────────────────────────────────────────────────────
    ocsvm = OneClassSVM(kernel="rbf", nu=contamination)
    ocsvm.fit(X_scaled)
    ocsvm_labels = ocsvm.predict(X_scaled)           # 1=normal, -1=anomaly
    ocsvm_raw = ocsvm.decision_function(X_scaled)    # higher = more normal
    ocsvm_scores = _normalize(-ocsvm_raw)            # invert → higher = anomaly
    ocsvm_flags: np.ndarray = ocsvm_labels == -1

    # ── Ensemble ─────────────────────────────────────────────────────────────
    ensemble_score: np.ndarray = (if_scores + lof_scores + ocsvm_scores) / 3.0

    # Majority vote: anomaly if ≥ 2 of 3 models flag as anomaly
    votes = if_flags.astype(int) + lof_flags.astype(int) + ocsvm_flags.astype(int)
    ensemble_label: np.ndarray = votes >= 2

    # Fraction of samples where all three models agree
    all_agree = (if_flags == lof_flags) & (lof_flags == ocsvm_flags)
    agreement_pct = float(all_agree.sum() / n) if n > 0 else 1.0

    return {
        "per_model_scores": {
            "isolation_forest": if_scores.tolist(),
            "lof": lof_scores.tolist(),
            "ocsvm": ocsvm_scores.tolist(),
        },
        "per_model_flags": {
            "isolation_forest": if_flags.tolist(),
            "lof": lof_flags.tolist(),
            "ocsvm": ocsvm_flags.tolist(),
        },
        "ensemble_score": ensemble_score.tolist(),
        "ensemble_label": ensemble_label.tolist(),
        "agreement_pct": agreement_pct,
    }
