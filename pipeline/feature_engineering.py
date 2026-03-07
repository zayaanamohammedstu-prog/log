"""
feature_engineering.py
-----------------------
Transforms a parsed log DataFrame (from log_parser) into a feature
matrix used by the anomaly-detection model.

Engineered features
-------------------
Per-IP aggregations (rolling 1-hour window keyed by the *end* of the window):
  - requests_per_hour       : total requests in the window
  - error_rate              : proportion of 4xx/5xx responses
  - unique_endpoints        : distinct endpoints visited
  - avg_bytes_sent          : mean response size
  - post_ratio              : fraction of POST requests
  - is_off_hours            : 1 if the window ends between 22:00–06:00 local hour
  - is_weekend              : 1 if Saturday or Sunday
  - has_scanner_ua          : 1 if any request in the window uses a known
                              scanner / bot user-agent string
"""

import re
import numpy as np
import pandas as pd

_SCANNER_UA_PATTERN = re.compile(
    r"(nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|"
    r"wfuzz|hydra|curl/|python-requests|scrapy|libwww-perl|"
    r"java/|wget/|go-http-client)",
    re.IGNORECASE,
)

_FEATURE_COLUMNS = [
    "requests_per_hour",
    "error_rate",
    "unique_endpoints",
    "avg_bytes_sent",
    "post_ratio",
    "is_off_hours",
    "is_weekend",
    "has_scanner_ua",
]


def _is_scanner(ua: str) -> bool:
    return bool(_SCANNER_UA_PATTERN.search(ua or ""))


def _is_off_hours(hour: int) -> int:
    return int(hour >= 22 or hour < 6)


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute per-IP, per-hour aggregated feature rows.

    Parameters
    ----------
    df : pd.DataFrame
        Output of :func:`pipeline.log_parser.parse_log_file`.

    Returns
    -------
    pd.DataFrame
        One row per (ip_address, hour_bucket).  Columns are the feature
        columns listed in ``_FEATURE_COLUMNS`` plus ``ip_address`` and
        ``hour_bucket`` as identifiers.
    """
    if df.empty:
        return pd.DataFrame(
            columns=["ip_address", "hour_bucket"] + _FEATURE_COLUMNS
        )

    work = df.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"], utc=True)
    work["hour_bucket"] = work["timestamp"].dt.floor("h")
    work["is_error"] = work["status_code"].between(400, 599).astype(int)
    work["is_post"] = (work["method"] == "POST").astype(int)
    work["scanner_flag"] = work["user_agent"].apply(_is_scanner).astype(int)
    work["hour_of_day"] = work["timestamp"].dt.hour
    work["dow"] = work["timestamp"].dt.dayofweek  # 0=Mon … 6=Sun

    groups = work.groupby(["ip_address", "hour_bucket"])

    features = groups.agg(
        requests_per_hour=("status_code", "count"),
        error_rate=("is_error", "mean"),
        unique_endpoints=("endpoint", "nunique"),
        avg_bytes_sent=("bytes_sent", "mean"),
        post_ratio=("is_post", "mean"),
        hour_of_day=("hour_of_day", "first"),
        dow=("dow", "first"),
        has_scanner_ua=("scanner_flag", "max"),
    ).reset_index()

    features["is_off_hours"] = features["hour_of_day"].apply(_is_off_hours)
    features["is_weekend"] = (features["dow"] >= 5).astype(int)
    features.drop(columns=["hour_of_day", "dow"], inplace=True)

    # Ensure correct column order
    id_cols = ["ip_address", "hour_bucket"]
    features = features[id_cols + _FEATURE_COLUMNS]
    return features


def get_feature_matrix(features: pd.DataFrame) -> np.ndarray:
    """
    Return a plain NumPy array of the feature columns, suitable for
    passing directly to a scikit-learn estimator.
    """
    return features[_FEATURE_COLUMNS].to_numpy(dtype=float)
