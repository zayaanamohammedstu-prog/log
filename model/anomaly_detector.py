"""
anomaly_detector.py
-------------------
Trains and applies an Isolation Forest model to detect anomalous
IP / hour-bucket combinations in parsed server logs.

The trained model can be saved to / loaded from disk with
:func:`save_model` / :func:`load_model` so that the Flask app can
serve predictions without retraining on every request.
"""

from __future__ import annotations

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# Default model parameters
_DEFAULT_CONTAMINATION = 0.05   # expected fraction of anomalies (~5 %)
_DEFAULT_N_ESTIMATORS = 100
_DEFAULT_RANDOM_STATE = 42


def build_pipeline(
    contamination: float = _DEFAULT_CONTAMINATION,
    n_estimators: int = _DEFAULT_N_ESTIMATORS,
    random_state: int = _DEFAULT_RANDOM_STATE,
) -> Pipeline:
    """Return a fresh, untrained sklearn Pipeline (scaler + Isolation Forest)."""
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "iforest",
                IsolationForest(
                    contamination=contamination,
                    n_estimators=n_estimators,
                    random_state=random_state,
                ),
            ),
        ]
    )


def train(X: np.ndarray, **kwargs) -> Pipeline:
    """
    Fit and return a trained anomaly-detection Pipeline.

    Parameters
    ----------
    X : np.ndarray
        Feature matrix (n_samples × n_features).
    **kwargs
        Forwarded to :func:`build_pipeline`.

    Returns
    -------
    Pipeline
        Fitted scikit-learn pipeline.
    """
    pipeline = build_pipeline(**kwargs)
    pipeline.fit(X)
    return pipeline


def predict(pipeline: Pipeline, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Run predictions with a trained pipeline.

    Returns
    -------
    labels : np.ndarray
        Array of +1 (normal) or -1 (anomaly).
    scores : np.ndarray
        Anomaly scores in [0, 1] – higher means *more anomalous*.
    """
    labels = pipeline.predict(X)
    # decision_function returns negative values for anomalies;
    # invert and min-max normalise to [0, 1]
    raw_scores = pipeline.decision_function(X)
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s == min_s:
        scores = np.zeros_like(raw_scores, dtype=float)
    else:
        scores = 1.0 - (raw_scores - min_s) / (max_s - min_s)
    return labels, scores


def save_model(pipeline: Pipeline, path: str) -> None:
    """Persist a trained pipeline to *path* using joblib."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(pipeline, path)


def load_model(path: str) -> Pipeline:
    """Load a pipeline previously saved with :func:`save_model`."""
    return joblib.load(path)


def run_full_analysis(
    features_df: pd.DataFrame,
    model_path: str | None = None,
    **train_kwargs,
) -> pd.DataFrame:
    """
    End-to-end helper: train (or load) a model and annotate *features_df*
    with anomaly labels and scores.

    Parameters
    ----------
    features_df : pd.DataFrame
        Output of :func:`pipeline.feature_engineering.engineer_features`.
    model_path : str or None
        If given and the file exists, the saved model is loaded instead of
        retraining.  After training, the model is saved to this path.
    **train_kwargs
        Forwarded to :func:`train`.

    Returns
    -------
    pd.DataFrame
        Input DataFrame with two extra columns:
        ``is_anomaly`` (bool) and ``anomaly_score`` (float 0-1).
    """
    from pipeline.feature_engineering import get_feature_matrix

    X = get_feature_matrix(features_df)

    if model_path and os.path.exists(model_path):
        pipeline = load_model(model_path)
    else:
        pipeline = train(X, **train_kwargs)
        if model_path:
            save_model(pipeline, model_path)

    labels, scores = predict(pipeline, X)

    result = features_df.copy()
    result["is_anomaly"] = labels == -1
    result["anomaly_score"] = scores
    return result
