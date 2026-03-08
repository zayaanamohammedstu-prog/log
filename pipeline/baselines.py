"""
pipeline/baselines.py
---------------------
Compute global and per-IP behavioral baselines.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

_FEATURE_COLS = [
    "requests_per_hour",
    "error_rate",
    "unique_endpoints",
    "avg_bytes_sent",
    "post_ratio",
]


def compute_global_baselines(features_df: pd.DataFrame) -> dict:
    """
    Compute global statistics per hour-of-day (0–23).

    Returns
    -------
    dict
        ``{"hourly": DataFrame}`` where the DataFrame is indexed by
        ``hour_of_day`` (0–23) and has columns
        ``<feature>_mean``, ``<feature>_std``, ``<feature>_median``.
    """
    df = features_df.copy()
    df["hour_of_day"] = pd.to_datetime(df["hour_bucket"]).dt.hour

    existing_cols = [c for c in _FEATURE_COLS if c in df.columns]
    if not existing_cols:
        return {"hourly": pd.DataFrame()}

    hourly = (
        df.groupby("hour_of_day")[existing_cols]
        .agg(["mean", "std", "median"])
        .fillna(0)
    )
    hourly.columns = ["_".join(c) for c in hourly.columns]

    return {"hourly": hourly}


def compute_ip_baselines(features_df: pd.DataFrame) -> dict:
    """
    Compute per-IP statistics (median, p95, mean, std for each feature).

    Returns
    -------
    dict
        Keyed by IP address; values are dicts of
        ``<feature>_median``, ``<feature>_p95``, ``<feature>_mean``,
        ``<feature>_std``.
    """
    result: dict[str, dict] = {}
    existing_cols = [c for c in _FEATURE_COLS if c in features_df.columns]

    for ip, group in features_df.groupby("ip_address"):
        stats: dict[str, float] = {}
        for col in existing_cols:
            vals = group[col].dropna()
            if len(vals) > 0:
                stats[f"{col}_median"] = float(vals.median())
                stats[f"{col}_p95"] = float(np.percentile(vals, 95))
                stats[f"{col}_mean"] = float(vals.mean())
                stats[f"{col}_std"] = float(vals.std()) if len(vals) > 1 else 0.0
        result[str(ip)] = stats

    return result


def add_baseline_features(
    features_df: pd.DataFrame,
    global_baselines: dict,
    ip_baselines: dict,
) -> pd.DataFrame:
    """
    Add baseline-adjusted columns to *features_df*:

    - ``requests_vs_expected`` – ratio of actual vs expected requests for
      that hour (IP baseline when available, else global hourly mean).
    - ``bytes_vs_expected`` – ratio of actual vs expected bytes for that hour.
    - ``error_rate_delta`` – error_rate minus expected error_rate for that hour.

    Returns
    -------
    pd.DataFrame
        New DataFrame with the three extra columns appended.
    """
    df = features_df.copy()
    df["_hour_of_day"] = pd.to_datetime(df["hour_bucket"]).dt.hour

    hourly: pd.DataFrame = global_baselines.get("hourly", pd.DataFrame())

    def _hourly_series(feature: str, stat: str = "mean", default: float = 1.0) -> pd.Series:
        """Map each row's hour to the hourly stat, using *default* for missing hours."""
        col = f"{feature}_{stat}"
        if hourly.empty or col not in hourly.columns:
            return pd.Series(default, index=df.index, dtype=float)
        return df["_hour_of_day"].map(
            lambda h: float(hourly.loc[h, col]) if h in hourly.index else default
        )

    def _ip_series(feature: str, stat: str = "median") -> pd.Series:
        """Map each row's IP to the per-IP stat (NaN when absent)."""
        key = f"{feature}_{stat}"
        return df["ip_address"].map(
            lambda ip: ip_baselines.get(str(ip), {}).get(key)
        ).astype(float)

    def _expected_positive(feature: str, default_global: float = 1.0) -> pd.Series:
        """IP baseline when positive and available, else global hourly mean."""
        ip_vals = _ip_series(feature)
        global_vals = _hourly_series(feature, default=default_global)
        use_ip = ip_vals.notna() & (ip_vals > 0)
        return ip_vals.where(use_ip, global_vals).clip(lower=1e-9)

    # requests_vs_expected (vectorised)
    exp_req = _expected_positive("requests_per_hour", default_global=1.0)
    df["requests_vs_expected"] = df["requests_per_hour"].astype(float) / exp_req

    # bytes_vs_expected (vectorised)
    exp_bytes = _expected_positive("avg_bytes_sent", default_global=1.0)
    df["bytes_vs_expected"] = df["avg_bytes_sent"].astype(float) / exp_bytes

    # error_rate_delta (vectorised) – zero is a valid IP baseline so only
    # fall back to global when the IP stat is completely absent (NaN)
    ip_err = _ip_series("error_rate")
    global_err = _hourly_series("error_rate", default=0.0)
    combined_err = ip_err.where(ip_err.notna(), global_err)
    df["error_rate_delta"] = df["error_rate"].astype(float) - combined_err

    df.drop(columns=["_hour_of_day"], inplace=True)
    return df
