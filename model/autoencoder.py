"""
model/autoencoder.py
--------------------
Reconstruction-error autoencoder for anomaly detection.

Uses scikit-learn's MLPRegressor to build a *bottleneck* autoencoder:

    input (n_features)
        → encoder hidden layer (2× features)
        → bottleneck (max(2, n_features // 2))
        → decoder hidden layer (2× features)
        → reconstruction (n_features)

Samples with high mean-squared reconstruction error are flagged as
anomalies — the intuition being that the model learns to reconstruct
"normal" patterns well but struggles with anomalous ones.
"""

from __future__ import annotations

import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler


def _normalize(scores: np.ndarray) -> np.ndarray:
    """Min-max normalise to [0, 1]; all-equal → zeros."""
    lo, hi = scores.min(), scores.max()
    if hi == lo:
        return np.zeros(len(scores), dtype=float)
    return (scores - lo) / (hi - lo)


def run_autoencoder(
    X: np.ndarray,
    contamination: float = 0.05,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Fit a bottleneck autoencoder on *X* and return anomaly scores and flags.

    Parameters
    ----------
    X : np.ndarray
        Feature matrix (n_samples × n_features).
    contamination : float
        Expected fraction of anomalies; used to set the reconstruction-error
        flag threshold at the ``(1 - contamination)``-th percentile.
    random_state : int
        Seed for reproducible weight initialisation.

    Returns
    -------
    scores : np.ndarray, shape (n_samples,)
        Normalised anomaly scores in [0, 1].  Higher means more anomalous.
    flags : np.ndarray of bool, shape (n_samples,)
        True for samples whose reconstruction error exceeds the threshold.
    """
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    n_features = X_scaled.shape[1]
    bottleneck = max(2, n_features // 2)
    hidden = max(4, n_features * 2)

    ae = MLPRegressor(
        hidden_layer_sizes=(hidden, bottleneck, hidden),
        activation="relu",
        solver="adam",
        # 300 iterations is sufficient for convergence on the feature sizes
        # typical in LogGuard (8–11 features); increase if you observe high
        # reconstruction errors on larger/noisier feature sets.
        max_iter=300,
        random_state=random_state,
        early_stopping=False,
    )
    ae.fit(X_scaled, X_scaled)

    X_reconstructed = ae.predict(X_scaled)
    reconstruction_error = np.mean((X_scaled - X_reconstructed) ** 2, axis=1)

    scores = _normalize(reconstruction_error)

    # Flag samples whose error exceeds the (1 − contamination)-th percentile
    threshold = np.percentile(reconstruction_error, (1.0 - contamination) * 100.0)
    flags: np.ndarray = reconstruction_error > threshold

    return scores, flags
