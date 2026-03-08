"""
pipeline/baselines.py
---------------------
Compute global and per-IP behavioral baselines, and build per-IP
behavioral profiles for Phase 2 differentiation.
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

# Minimum clip value to prevent division-by-zero in ratio calculations
_MIN_EXPECTED_VALUE = 1e-9


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
        return ip_vals.where(use_ip, global_vals).clip(lower=_MIN_EXPECTED_VALUE)

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


# ---------------------------------------------------------------------------
# Behavioral profiling
# ---------------------------------------------------------------------------

# Thresholds used by _categorize_behavior.
# These values are calibrated for typical Apache / CLF server traffic:
#   - 50 req/hr is roughly 1 request per minute, distinguishing light
#     crawlers/scrapers from normal browser sessions.
#   - 30% error rate (0.30) signals brute-force or active scanning.
#   - 50% POST ratio (0.50) combined with a high error rate is a strong
#     indicator of credential-stuffing or login-brute-force attacks.
#   - 100 KB avg response is large enough to flag bulk data retrieval
#     while allowing normal media downloads to pass unnoticed.
#   - 50% off-hours ratio means the IP is active predominantly at night,
#     which is unusual for most legitimate services.
_HIGH_REQ_THRESHOLD = 50         # avg req/hr
_HIGH_ERROR_THRESHOLD = 0.30     # avg error rate
_HIGH_POST_THRESHOLD = 0.50      # avg POST ratio
_HIGH_BYTES_THRESHOLD = 100_000  # avg bytes per response
_OFF_HOURS_THRESHOLD = 0.50      # fraction of windows in off-hours


def _categorize_behavior(
    has_scanner: bool,
    avg_req: float,
    avg_err: float,
    avg_post: float,
    avg_bytes: float,
    off_hours_ratio: float,
) -> str:
    """
    Assign a behavioral category to an IP based on its aggregate features.

    Priority: Scanner > Credential Attack > Data Exfiltration >
              High Volume > Suspicious Timing > Normal
    """
    if has_scanner:
        return "Scanner"
    if avg_err > _HIGH_ERROR_THRESHOLD and avg_post > _HIGH_POST_THRESHOLD:
        return "Credential Attack"
    if avg_bytes > _HIGH_BYTES_THRESHOLD:
        return "Data Exfiltration"
    if avg_req > _HIGH_REQ_THRESHOLD:
        return "High Volume"
    if off_hours_ratio > _OFF_HOURS_THRESHOLD:
        return "Suspicious Timing"
    return "Normal"


def build_behavioral_profiles(
    features_df: pd.DataFrame,
    *,
    ip_baselines: dict | None = None,
) -> dict:
    """
    Build a behavioral profile for each IP address observed in *features_df*.

    Each profile summarises activity patterns, request volume, error
    behaviour, and assigns a behavioral-fingerprint category.

    Parameters
    ----------
    features_df : pd.DataFrame
        Feature-engineered DataFrame (output of ``engineer_features`` /
        ``add_baseline_features``).  Must contain at least ``ip_address``
        and ``hour_bucket`` columns.
    ip_baselines : dict, optional
        Per-IP baseline stats as returned by :func:`compute_ip_baselines`.
        When provided the stats are embedded in the profile under the
        ``"baseline"`` key.

    Returns
    -------
    dict
        Keyed by IP address string.  Each value is a dict with fields:

        - ``total_observations``     – number of IP/hour rows seen
        - ``off_hours_ratio``        – fraction of windows in off-hours
        - ``avg_requests_per_hour``  – mean request volume per window
        - ``max_requests_per_hour``  – peak request volume
        - ``avg_error_rate``         – mean error rate
        - ``max_error_rate``         – peak error rate
        - ``avg_bytes_sent``         – mean response bytes
        - ``avg_post_ratio``         – mean POST-request fraction
        - ``has_scanner_activity``   – True if scanner UA seen in any window
        - ``category``               – behavioral category string
        - ``baseline``               – per-IP baseline stats (if provided)
    """
    if ip_baselines is None:
        ip_baselines = {}

    profiles: dict[str, dict] = {}

    def _col_mean(grp: pd.DataFrame, col: str, default: float = 0.0) -> float:
        return float(grp[col].mean()) if col in grp.columns else default

    def _col_max(grp: pd.DataFrame, col: str, default: float = 0.0) -> float:
        return float(grp[col].max()) if col in grp.columns else default

    def _col_any(grp: pd.DataFrame, col: str) -> bool:
        return bool(grp[col].any()) if col in grp.columns else False

    for ip, group in features_df.groupby("ip_address"):
        ip_str = str(ip)

        avg_req = _col_mean(group, "requests_per_hour")
        max_req = _col_max(group, "requests_per_hour")
        avg_err = _col_mean(group, "error_rate")
        max_err = _col_max(group, "error_rate")
        avg_bytes = _col_mean(group, "avg_bytes_sent")
        avg_post = _col_mean(group, "post_ratio")
        off_hours_ratio = _col_mean(group, "is_off_hours")
        has_scanner = _col_any(group, "has_scanner_ua")

        category = _categorize_behavior(
            has_scanner=has_scanner,
            avg_req=avg_req,
            avg_err=avg_err,
            avg_post=avg_post,
            avg_bytes=avg_bytes,
            off_hours_ratio=off_hours_ratio,
        )

        profile: dict = {
            "total_observations": len(group),
            "off_hours_ratio": round(off_hours_ratio, 4),
            "avg_requests_per_hour": round(avg_req, 2),
            "max_requests_per_hour": round(max_req, 2),
            "avg_error_rate": round(avg_err, 4),
            "max_error_rate": round(max_err, 4),
            "avg_bytes_sent": round(avg_bytes, 2),
            "avg_post_ratio": round(avg_post, 4),
            "has_scanner_activity": has_scanner,
            "category": category,
        }

        if ip_str in ip_baselines:
            profile["baseline"] = ip_baselines[ip_str]

        profiles[ip_str] = profile

    return profiles
