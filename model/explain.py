"""
model/explain.py
----------------
Statistical + rule-based explanations for anomalies.
"""

from __future__ import annotations

import json
import math

import pandas as pd

REASON_CODES: dict[str, str] = {
    "SCANNER_UA": "Known scanner/reconnaissance user-agent detected",
    "VOLUME_SPIKE": "Unusually high request volume",
    "OFF_HOURS": "Activity during off-hours (22:00–06:00)",
    "HIGH_ERROR_RATE": "Elevated error rate (>30%)",
    "BYTES_SPIKE": "Unusually high data transfer",
    "OFF_HOURS_COMBINED": "Off-hours activity combined with high volume",
}

_FEATURE_COLS = [
    "requests_per_hour",
    "error_rate",
    "unique_endpoints",
    "avg_bytes_sent",
    "post_ratio",
]


def _norm_cdf(z: float) -> float:
    """Approximate CDF of the standard normal distribution using math.erf."""
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def explain_anomaly(
    row: "dict | pd.Series",
    global_baselines: dict,
    ip_baselines: dict,
) -> dict:
    """
    Return a dict with:

    - ``reasons`` – list of ``(code, description)`` tuples explaining the
      anomaly.
    - ``feature_deviations`` – list of dicts, one per feature, containing
      ``{feature, value, global_mean, global_std, z_score, percentile}``.
    """
    if isinstance(row, pd.Series):
        row = row.to_dict()

    reasons: list[tuple[str, str]] = []

    # ── Rule-based checks ────────────────────────────────────────────────────
    if row.get("has_scanner_ua", 0):
        reasons.append(("SCANNER_UA", REASON_CODES["SCANNER_UA"]))

    if row.get("is_off_hours", 0) and float(row.get("requests_per_hour", 0)) > 10:
        reasons.append(("OFF_HOURS_COMBINED", REASON_CODES["OFF_HOURS_COMBINED"]))
    elif row.get("is_off_hours", 0):
        reasons.append(("OFF_HOURS", REASON_CODES["OFF_HOURS"]))

    if float(row.get("error_rate", 0)) > 0.30:
        reasons.append(("HIGH_ERROR_RATE", REASON_CODES["HIGH_ERROR_RATE"]))

    # ── Statistical deviations ───────────────────────────────────────────────
    hourly_df: pd.DataFrame = global_baselines.get("hourly", pd.DataFrame())

    # Build per-feature global stats from hourly averages
    global_stats: dict[str, dict[str, float]] = {}
    if not hourly_df.empty:
        for col in _FEATURE_COLS:
            mean_col = f"{col}_mean"
            std_col = f"{col}_std"
            if mean_col in hourly_df.columns:
                gm = float(hourly_df[mean_col].mean())
                gs = (
                    float(hourly_df[std_col].mean())
                    if std_col in hourly_df.columns
                    else 1.0
                )
                global_stats[col] = {"mean": gm, "std": max(gs, 1e-9)}

    feature_deviations: list[dict] = []
    for col in _FEATURE_COLS:
        raw_val = row.get(col)
        if raw_val is None:
            continue
        val = float(raw_val)
        gm = global_stats.get(col, {}).get("mean", 0.0)
        gs = global_stats.get(col, {}).get("std", 1.0)

        z_score = (val - gm) / gs if gs > 0 else 0.0
        percentile = round(_norm_cdf(z_score) * 100, 1)

        feature_deviations.append(
            {
                "feature": col,
                "value": val,
                "global_mean": gm,
                "global_std": gs,
                "z_score": round(z_score, 3),
                "percentile": percentile,
            }
        )

        # Volume spike
        if col == "requests_per_hour" and z_score > 2.0:
            if not any(r[0] == "VOLUME_SPIKE" for r in reasons):
                reasons.append(("VOLUME_SPIKE", REASON_CODES["VOLUME_SPIKE"]))

        # Bytes spike
        if col == "avg_bytes_sent" and z_score > 2.0:
            if not any(r[0] == "BYTES_SPIKE" for r in reasons):
                reasons.append(("BYTES_SPIKE", REASON_CODES["BYTES_SPIKE"]))

    return {"reasons": reasons, "feature_deviations": feature_deviations}


def explain_all(
    results_df: pd.DataFrame,
    global_baselines: dict,
    ip_baselines: dict,
) -> pd.DataFrame:
    """
    Add an ``explanations_json`` column to *results_df*.

    Non-anomalous rows get an empty explanation.
    Returns a modified copy.
    """
    df = results_df.copy()
    explanations: list[str] = []
    for _, row in df.iterrows():
        if row.get("is_anomaly", False):
            exp = explain_anomaly(row, global_baselines, ip_baselines)
        else:
            exp = {"reasons": [], "feature_deviations": []}
        explanations.append(json.dumps(exp))
    df["explanations_json"] = explanations
    return df
