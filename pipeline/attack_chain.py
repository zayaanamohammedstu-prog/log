"""
pipeline/attack_chain.py
------------------------
Group anomalies into chains by IP + time adjacency.
Includes attack-stage classification and tactic labelling for
Phase 2 behavioral profiling.
"""

from __future__ import annotations

import json

import pandas as pd
from datetime import timedelta

# Severity thresholds based on maximum anomaly score in the chain
_CRITICAL_THRESHOLD = 0.7
_HIGH_THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# Attack-stage classification
# ---------------------------------------------------------------------------

# Maps XAI reason codes (from model/explain.py) to attack stage names.
_STAGE_MAP: dict[str, str] = {
    "SCANNER_UA": "Reconnaissance",
    "HIGH_ERROR_RATE": "Scanning/Exploitation",
    "VOLUME_SPIKE": "Volumetric Attack",
    "BYTES_SPIKE": "Data Exfiltration",
    "OFF_HOURS_COMBINED": "Suspicious Activity",
    "OFF_HOURS": "Suspicious Activity",
}

# Priority order used when multiple stages are found for one anomaly
_STAGE_PRIORITY: list[str] = [
    "Reconnaissance",
    "Data Exfiltration",
    "Scanning/Exploitation",
    "Volumetric Attack",
    "Suspicious Activity",
]


def classify_attack_stage(reasons: list[str]) -> str:
    """
    Classify a single anomaly into an attack stage based on its reason codes.

    Parameters
    ----------
    reasons : list[str]
        Reason code strings emitted by the XAI layer, e.g.
        ``["SCANNER_UA", "OFF_HOURS"]``.

    Returns
    -------
    str
        Attack stage name, such as ``"Reconnaissance"``,
        ``"Data Exfiltration"``, ``"Scanning/Exploitation"``,
        ``"Volumetric Attack"``, or ``"Suspicious Activity"``.
        Returns ``"Unknown"`` when no matching reason code is found.
    """
    found = {_STAGE_MAP[code] for code in reasons if code in _STAGE_MAP}
    for stage in _STAGE_PRIORITY:
        if stage in found:
            return stage
    return "Unknown"


def _classify_tactic(stages: list[str]) -> str:
    """
    Derive an overall tactic label from the unique stages observed in a chain.

    - Zero distinct (non-Unknown) stages → ``"Unknown"``
    - Exactly one distinct stage          → that stage name
    - Two or more distinct stages         → ``"Multi-Stage Attack"``
    """
    unique = list(dict.fromkeys(s for s in stages if s != "Unknown"))
    if len(unique) == 0:
        return "Unknown"
    if len(unique) == 1:
        return unique[0]
    return "Multi-Stage Attack"


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

    if max_score >= _CRITICAL_THRESHOLD:
        severity = "Critical"
    elif max_score >= _HIGH_THRESHOLD:
        severity = "High"
    else:
        severity = "Medium"

    # ── Attack-stage classification ──────────────────────────────────────────
    stages: list[str] = []
    for r in rows:
        exp_raw = r.get("explanations_json")
        if exp_raw is not None:
            try:
                if isinstance(exp_raw, str):
                    exp = json.loads(exp_raw)
                elif isinstance(exp_raw, dict):
                    exp = exp_raw
                else:
                    exp = {}
                # reasons is a list of [code, description] pairs
                reason_codes = [item[0] for item in exp.get("reasons", [])]
            except (json.JSONDecodeError, TypeError, ValueError, IndexError):
                reason_codes = []
        else:
            reason_codes = []
        stages.append(classify_attack_stage(reason_codes))

    # Deduplicate while preserving first-seen order
    unique_stages: list[str] = list(dict.fromkeys(stages))
    tactic = _classify_tactic(unique_stages)

    narrative = (
        f"IP {ip} showed {count} anomalous activity burst(s) between "
        f"{start.isoformat()} and {end.isoformat()} "
        f"(~{duration_h:.1f}h duration). "
        f"Maximum anomaly score: {max_score:.3f}. "
        f"Severity: {severity}. Tactic: {tactic}."
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
        "stages": unique_stages,
        "tactic": tactic,
        "narrative": narrative,
        "anomaly_ids": anomaly_ids,
    }
