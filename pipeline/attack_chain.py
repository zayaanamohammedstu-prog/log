"""
pipeline/attack_chain.py
------------------------
Group anomalies into chains by IP + time adjacency.
"""

from __future__ import annotations

import pandas as pd
from datetime import timedelta


def build_chains(
    anomalies_df: pd.DataFrame,
    time_gap_hours: float = 2,
) -> list[dict]:
    """
    Group anomalous rows into chains.  Two anomalies from the same IP
    within *time_gap_hours* of each other belong to the same chain.

    Parameters
    ----------
    anomalies_df : pd.DataFrame
        Rows where ``is_anomaly`` is True.  Must have columns
        ``ip_address``, ``hour_bucket``, and at least one of
        ``ensemble_score`` / ``anomaly_score``.
    time_gap_hours : float
        Maximum gap (hours) between consecutive anomalies that still
        belongs to the same chain.

    Returns
    -------
    list[dict]
        Each element is a chain dict with keys:
        ``chain_id``, ``ip_address``, ``start_time``, ``end_time``,
        ``anomaly_count``, ``max_score``, ``severity``, ``narrative``,
        ``anomaly_ids``.
    """
    if anomalies_df is None or anomalies_df.empty:
        return []

    df = anomalies_df.copy()
    # Preserve original row indices for anomaly_ids
    df = df.reset_index(drop=False).rename(columns={"index": "_orig_idx"})
    df["_ts"] = pd.to_datetime(df["hour_bucket"])
    df = df.sort_values(["ip_address", "_ts"])

    chains: list[dict] = []
    chain_id = 0
    gap = timedelta(hours=time_gap_hours)

    for ip, group in df.groupby("ip_address", sort=True):
        group = group.sort_values("_ts")
        current: list[pd.Series] = []
        prev_ts: pd.Timestamp | None = None

        for _, row in group.iterrows():
            ts: pd.Timestamp = row["_ts"]
            if prev_ts is None or (ts - prev_ts) <= gap:
                current.append(row)
            else:
                chains.append(_make_chain(chain_id, str(ip), current))
                chain_id += 1
                current = [row]
            prev_ts = ts

        if current:
            chains.append(_make_chain(chain_id, str(ip), current))
            chain_id += 1

    return chains


def _make_chain(chain_id: int, ip: str, rows: list[pd.Series]) -> dict:
    """Build a chain dict from a list of Series rows."""
    times = [r["_ts"] for r in rows]
    start: pd.Timestamp = min(times)
    end: pd.Timestamp = max(times)

    scores: list[float] = []
    for r in rows:
        score = r.get("ensemble_score") if r.get("ensemble_score") is not None else r.get("anomaly_score") or 0.0
        if hasattr(score, "item"):
            score = score.item()
        scores.append(float(score))

    max_score = max(scores) if scores else 0.0
    count = len(rows)
    duration_h = (end - start).total_seconds() / 3600.0

    if max_score >= 0.7:
        severity = "Critical"
    elif max_score >= 0.5:
        severity = "High"
    else:
        severity = "Medium"

    narrative = (
        f"IP {ip} showed {count} anomalous activity burst(s) between "
        f"{start.isoformat()} and {end.isoformat()} "
        f"(~{duration_h:.1f}h duration). "
        f"Maximum anomaly score: {max_score:.3f}. "
        f"Severity: {severity}."
    )

    anomaly_ids: list = []
    for r in rows:
        idx = r.get("_orig_idx")
        if idx is not None:
            if hasattr(idx, "item"):
                idx = idx.item()
            anomaly_ids.append(idx)

    return {
        "chain_id": chain_id,
        "ip_address": ip,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "anomaly_count": count,
        "max_score": round(max_score, 4),
        "severity": severity,
        "narrative": narrative,
        "anomaly_ids": anomaly_ids,
    }
