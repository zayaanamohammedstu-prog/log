"""
scripts/retrain_model.py
------------------------
Retrain the Isolation Forest model using collected anomaly feedback.

Usage:
  python scripts/retrain_model.py retrain
  python scripts/retrain_model.py rollback --version model_20260509T120000Z.joblib
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from model.anomaly_detector import save_model, train

INSTANCE_DB = ROOT / "instance" / "logguard.db"
ACTIVE_MODEL_PATH = ROOT / "model" / "logguard_model.pkl"
VERSIONS_DIR = ROOT / "models" / "versions"
REGISTRY_PATH = VERSIONS_DIR / "registry.json"


def _load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        return {"active_version": None, "versions": []}
    with REGISTRY_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_registry(registry: dict) -> None:
    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)
    with REGISTRY_PATH.open("w", encoding="utf-8") as fh:
        json.dump(registry, fh, indent=2)


def _load_feedback_rows(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT ar.features_json, af.feedback
            FROM anomaly_feedback af
            JOIN analysis_results ar
              ON ar.run_id = af.run_id
             AND ar.ip_address = af.ip_address
             AND ar.hour_bucket = af.hour_bucket
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _build_training_arrays(rows: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    xs: list[list[float]] = []
    ys: list[int] = []
    for row in rows:
        features = json.loads(row["features_json"] or "{}")
        if not features:
            continue
        # Keep feature ordering stable for retraining consistency
        feat_names = sorted(features.keys())
        xs.append([float(features[k] or 0.0) for k in feat_names])
        ys.append(1 if row["feedback"] == "confirmed" else 0)
    if not xs:
        return np.empty((0, 0)), np.empty((0,), dtype=int)
    return np.asarray(xs, dtype=float), np.asarray(ys, dtype=int)


def _estimate_contamination(labels: np.ndarray) -> float:
    if labels.size == 0:
        return 0.05
    ratio = float((labels == 1).sum() / labels.size)
    return min(0.25, max(0.01, ratio))


def retrain(db_path: Path) -> int:
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        return 1

    rows = _load_feedback_rows(db_path)
    X, y = _build_training_arrays(rows)
    if X.shape[0] < 10:
        print("Not enough feedback data for retraining (need at least 10 labeled rows).")
        return 1

    contamination = _estimate_contamination(y)
    normal_mask = y == 0
    if normal_mask.sum() < 5:
        print("Need at least 5 false_positive labels to retrain a stable baseline.")
        return 1

    pipeline = train(X[normal_mask], contamination=contamination)

    # Simple feedback-fit metric for model registry visibility
    pred = pipeline.predict(X)  # +1 normal, -1 anomaly
    pred_anom = (pred == -1).astype(int)
    feedback_fit = float((pred_anom == y).sum() / max(1, y.size))

    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)
    version = f"model_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.joblib"
    version_path = VERSIONS_DIR / version
    save_model(pipeline, str(version_path))
    save_model(pipeline, str(ACTIVE_MODEL_PATH))

    registry = _load_registry()
    registry["active_version"] = version
    registry["versions"].append(
        {
            "version": version,
            "path": str(version_path),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "contamination": contamination,
            "feedback_rows": int(y.size),
            "feedback_fit": round(feedback_fit, 4),
        }
    )
    _save_registry(registry)

    print(f"Model retrained: {version}")
    print(f"Feedback rows: {y.size}, contamination={contamination:.4f}, fit={feedback_fit:.4f}")
    return 0


def rollback(version: str) -> int:
    registry = _load_registry()
    entry = next((v for v in registry.get("versions", []) if v.get("version") == version), None)
    if not entry:
        print(f"Version not found in registry: {version}")
        return 1

    source = Path(entry["path"])
    if not source.exists():
        print(f"Version file missing: {source}")
        return 1

    ACTIVE_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, ACTIVE_MODEL_PATH)
    registry["active_version"] = version
    _save_registry(registry)
    print(f"Rolled back active model to: {version}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="LogGuard model retraining + rollback.")
    parser.add_argument("command", choices=["retrain", "rollback"])
    parser.add_argument("--db-path", default=str(INSTANCE_DB), help="Path to logguard.db")
    parser.add_argument("--version", help="Model version filename to rollback to")
    args = parser.parse_args()

    if args.command == "retrain":
        return retrain(Path(args.db_path))
    if not args.version:
        print("--version is required for rollback")
        return 1
    return rollback(args.version)


if __name__ == "__main__":
    raise SystemExit(main())
