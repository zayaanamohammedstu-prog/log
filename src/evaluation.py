"""
src/evaluation.py
-----------------
End-to-end anomaly-detection evaluation using **Option A (attack injection)**.

Usage
-----
    python -m src.evaluation \\
        --input  data/processed/features.parquet \\
        --out    reports/ \\
        --metrics metrics.csv

What this script does
---------------------
1. Load processed feature data (parquet or CSV).
2. Perform Option A anomaly injection to create ground-truth ``y_true`` labels.
3. Train IsolationForest, LOF (novelty=True), and an MLP Autoencoder on the
   *clean* (non-injected) portion, then score the full dataset.
4. Apply percentile and F1-maximising thresholds to convert scores → labels.
5. Compute TP/FP/TN/FN, precision, recall, F1, FPR, ROC-AUC per model.
6. Export a summary to ``metrics.csv``.
7. Save plots (confusion matrices, ROC curves, score distributions) to ``out/``.
8. Measure and print system metrics: throughput, latency, CPU%, RSS memory.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import time
import warnings
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import psutil
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ── Constants ──────────────────────────────────────────────────────────────────
RANDOM_STATE = 42
INJECTION_FRACTION = 0.08      # fraction of rows to replace with anomalies
CONTAMINATION = INJECTION_FRACTION
FEATURE_COLUMNS = [
    "requests_per_hour",
    "error_rate",
    "unique_endpoints",
    "avg_bytes_sent",
    "post_ratio",
    "is_off_hours",
    "is_weekend",
    "has_scanner_ua",
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_features(path: str) -> pd.DataFrame:
    """Load feature data from parquet or CSV."""
    p = Path(path)
    if p.suffix in {".parquet", ".pq"}:
        return pd.read_parquet(p)
    return pd.read_csv(p)


def _ensure_feature_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Keep only recognised feature columns.  Missing numeric columns are filled
    with zero so the script is robust to datasets produced by different
    versions of the feature-engineering pipeline.
    """
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    return df[FEATURE_COLUMNS].copy()


def _inject_anomalies(
    X: np.ndarray,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Option A: replace a fraction of rows with synthetic anomaly patterns.

    Injection strategies (each applied to a random sub-subset):
    - DoS spike:       very high request rate, zero error rate
    - Brute-force:     high error rate, many POST requests, off-hours
    - Scanner:         has_scanner_ua=1, many unique endpoints, high error rate
    - Data-exfil:      large bytes_sent, normal-looking otherwise

    Returns
    -------
    X_mixed : np.ndarray
        Copy of *X* with injected rows.
    y_true : np.ndarray of int
        0 = normal, 1 = injected anomaly.
    """
    n = len(X)
    n_inject = max(1, int(n * INJECTION_FRACTION))
    idx = rng.choice(n, size=n_inject, replace=False)

    X_mixed = X.copy().astype(float)
    y_true = np.zeros(n, dtype=int)
    y_true[idx] = 1

    # Column indices (aligned with FEATURE_COLUMNS)
    col = {c: i for i, c in enumerate(FEATURE_COLUMNS)}

    # Split injected rows across 4 strategies
    splits = np.array_split(idx, 4)

    # DoS: extreme request rate, low errors
    dos_idx = splits[0]
    X_mixed[dos_idx, col["requests_per_hour"]] = (
        X[:, col["requests_per_hour"]].mean() * 10 + 500
    )
    X_mixed[dos_idx, col["error_rate"]] = 0.02

    # Brute-force: high error rate, high post_ratio, off-hours
    bf_idx = splits[1]
    X_mixed[bf_idx, col["error_rate"]] = 0.95
    X_mixed[bf_idx, col["post_ratio"]] = 0.90
    X_mixed[bf_idx, col["is_off_hours"]] = 1.0

    # Scanner: scanner UA, many endpoints, high errors
    sc_idx = splits[2]
    X_mixed[sc_idx, col["has_scanner_ua"]] = 1.0
    X_mixed[sc_idx, col["unique_endpoints"]] = (
        X[:, col["unique_endpoints"]].max() * 1.5 + 20
    )
    X_mixed[sc_idx, col["error_rate"]] = 0.60

    # Data-exfiltration: huge bytes_sent
    ex_idx = splits[3]
    X_mixed[ex_idx, col["avg_bytes_sent"]] = (
        X[:, col["avg_bytes_sent"]].mean() * 20 + 1_000_000
    )

    return X_mixed, y_true


def _minmax(scores: np.ndarray) -> np.ndarray:
    lo, hi = scores.min(), scores.max()
    if hi == lo:
        return np.zeros_like(scores, dtype=float)
    return (scores - lo) / (hi - lo)


# ── Model scoring ──────────────────────────────────────────────────────────────

def _score_iforest(
    X_train: np.ndarray,
    X_score: np.ndarray,
    scaler: StandardScaler,
) -> np.ndarray:
    """Fit IsolationForest on clean data, score full dataset."""
    clf = IsolationForest(
        contamination=CONTAMINATION,
        n_estimators=100,
        random_state=RANDOM_STATE,
    )
    clf.fit(scaler.transform(X_train))
    raw = clf.decision_function(scaler.transform(X_score))
    return _minmax(-raw)          # higher → more anomalous


def _score_lof(
    X_train: np.ndarray,
    X_score: np.ndarray,
    scaler: StandardScaler,
) -> np.ndarray:
    """Fit LOF (novelty=True) on clean data, score full dataset."""
    clf = LocalOutlierFactor(
        n_neighbors=min(20, len(X_train) - 1),
        novelty=True,
        contamination=CONTAMINATION,
    )
    clf.fit(scaler.transform(X_train))
    raw = clf.decision_function(scaler.transform(X_score))
    return _minmax(-raw)          # higher → more anomalous


def _score_autoencoder(
    X_train: np.ndarray,
    X_score: np.ndarray,
    scaler: StandardScaler,
) -> np.ndarray:
    """Fit MLP autoencoder on clean data, return reconstruction-error scores."""
    X_tr = scaler.transform(X_train)
    X_sc = scaler.transform(X_score)
    n_feat = X_tr.shape[1]
    bottleneck = max(2, n_feat // 2)
    hidden = max(4, n_feat * 2)

    ae = MLPRegressor(
        hidden_layer_sizes=(hidden, bottleneck, hidden),
        activation="relu",
        solver="adam",
        max_iter=300,
        random_state=RANDOM_STATE,
    )
    ae.fit(X_tr, X_tr)
    recon = ae.predict(X_sc)
    errors = np.mean((X_sc - recon) ** 2, axis=1)
    return _minmax(errors)


# ── Thresholding ───────────────────────────────────────────────────────────────

def _threshold_percentile(scores: np.ndarray, pct: float = 92.0) -> np.ndarray:
    """Flag top (100-pct)% as anomalies."""
    thr = np.percentile(scores, pct)
    return (scores >= thr).astype(int)


def _threshold_best_f1(
    scores: np.ndarray,
    y_true: np.ndarray,
    n_steps: int = 200,
) -> tuple[np.ndarray, float]:
    """
    Search for the threshold that maximises F1 on the given labels.
    Returns (y_pred, best_threshold).
    """
    best_thr, best_f1 = 0.5, 0.0
    for thr in np.linspace(0.0, 1.0, n_steps):
        y_pred = (scores >= thr).astype(int)
        if y_pred.sum() == 0:
            continue
        f = f1_score(y_true, y_pred, zero_division=0)
        if f > best_f1:
            best_f1 = f
            best_thr = thr
    return (scores >= best_thr).astype(int), best_thr


# ── Metric helpers ─────────────────────────────────────────────────────────────

def _compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores: np.ndarray,
    model_name: str,
    threshold_method: str,
) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    try:
        auc = roc_auc_score(y_true, scores)
    except ValueError:
        auc = float("nan")
    return {
        "model": model_name,
        "threshold_method": threshold_method,
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "roc_auc": round(auc, 4),
    }


# ── Plots ──────────────────────────────────────────────────────────────────────

def _plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    model_name: str,
    out_dir: Path,
) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Normal", "Anomaly"],
        yticklabels=["Normal", "Anomaly"],
        ax=ax,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title(f"Confusion Matrix — {model_name}")
    fig.tight_layout()
    fname = out_dir / f"cm_{model_name.lower().replace(' ', '_')}.png"
    fig.savefig(fname, dpi=120)
    plt.close(fig)


def _plot_roc(
    y_true: np.ndarray,
    scores_dict: dict[str, np.ndarray],
    out_dir: Path,
) -> None:
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot([0, 1], [0, 1], "k--", label="Random")
    for name, scores in scores_dict.items():
        try:
            fpr_arr, tpr_arr, _ = roc_curve(y_true, scores)
            auc = roc_auc_score(y_true, scores)
            ax.plot(fpr_arr, tpr_arr, label=f"{name} (AUC={auc:.3f})")
        except ValueError:
            pass
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — All Models")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out_dir / "roc_curves.png", dpi=120)
    plt.close(fig)


def _plot_score_distribution(
    y_true: np.ndarray,
    scores_dict: dict[str, np.ndarray],
    out_dir: Path,
) -> None:
    n_models = len(scores_dict)
    fig, axes = plt.subplots(1, n_models, figsize=(5 * n_models, 4))
    if n_models == 1:
        axes = [axes]
    for ax, (name, scores) in zip(axes, scores_dict.items()):
        ax.hist(scores[y_true == 0], bins=40, alpha=0.6, label="Normal", color="steelblue")
        ax.hist(scores[y_true == 1], bins=40, alpha=0.6, label="Anomaly", color="crimson")
        ax.set_title(f"Score Distribution — {name}")
        ax.set_xlabel("Anomaly Score")
        ax.set_ylabel("Count")
        ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "score_distributions.png", dpi=120)
    plt.close(fig)


# ── System metrics ─────────────────────────────────────────────────────────────

def _measure_system_metrics(
    fn,
    *args,
    **kwargs,
):
    """
    Run *fn* and record wall-clock time, throughput, CPU%, and RSS memory.

    Returns (result, sys_metrics_dict).
    """
    proc = psutil.Process()
    proc.cpu_percent(interval=None)  # warm-up; first call always returns 0.0
    mem_before = proc.memory_info().rss

    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    t1 = time.perf_counter()

    elapsed = t1 - t0
    cpu_pct = proc.cpu_percent(interval=None)
    mem_after = proc.memory_info().rss

    return result, {
        "elapsed_s": round(elapsed, 4),
        "cpu_pct": round(cpu_pct, 1),
        "rss_mb_before": round(mem_before / 1024 ** 2, 2),
        "rss_mb_after": round(mem_after / 1024 ** 2, 2),
    }


# ── Main entry point ───────────────────────────────────────────────────────────

def evaluate(
    input_path: str,
    out_dir: str,
    metrics_path: str,
) -> None:
    """
    Full evaluation pipeline.

    Parameters
    ----------
    input_path : str
        Path to processed feature data (parquet or CSV).
    out_dir : str
        Directory for output plots.
    metrics_path : str
        Path for the output ``metrics.csv``.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    Path(metrics_path).parent.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(RANDOM_STATE)

    # ── 1. Load data ──────────────────────────────────────────────────────────
    print(f"[1/7] Loading features from {input_path} …")
    df = _load_features(input_path)
    df = _ensure_feature_columns(df)
    X_raw = df.to_numpy(dtype=float)
    n_total = len(X_raw)
    print(f"      {n_total} rows loaded, {X_raw.shape[1]} features.")

    # ── 2. Inject anomalies (Option A) ────────────────────────────────────────
    print("[2/7] Injecting synthetic anomalies (Option A) …")
    X_mixed, y_true = _inject_anomalies(X_raw, rng)
    n_anomaly = int(y_true.sum())
    print(f"      {n_anomaly} anomalies injected ({n_anomaly/n_total*100:.1f}%).")

    # Clean subset = rows not injected (used for training)
    clean_mask = y_true == 0
    X_train = X_mixed[clean_mask]

    # ── 3. Fit shared scaler ──────────────────────────────────────────────────
    scaler = StandardScaler()
    scaler.fit(X_train)

    # ── 4. Score all three models (with latency tracking) ────────────────────
    print("[3/7] Scoring with IsolationForest …")
    (if_scores, if_sys) = _measure_system_metrics(
        _score_iforest, X_train, X_mixed, scaler
    )

    print("[4/7] Scoring with LOF (novelty=True) …")
    (lof_scores, lof_sys) = _measure_system_metrics(
        _score_lof, X_train, X_mixed, scaler
    )

    print("[5/7] Scoring with Autoencoder …")
    (ae_scores, ae_sys) = _measure_system_metrics(
        _score_autoencoder, X_train, X_mixed, scaler
    )

    scores_dict = {
        "IsolationForest": if_scores,
        "LOF": lof_scores,
        "Autoencoder": ae_scores,
    }
    sys_metrics = {
        "IsolationForest": if_sys,
        "LOF": lof_sys,
        "Autoencoder": ae_sys,
    }

    # ── 5. Compute metrics with two threshold methods ─────────────────────────
    print("[6/7] Computing evaluation metrics …")
    rows = []
    percentile_pct = 100.0 * (1 - CONTAMINATION)
    for model_name, scores in scores_dict.items():
        # Method A: percentile threshold
        y_pred_pct = _threshold_percentile(scores, pct=percentile_pct)
        rows.append(_compute_metrics(y_true, y_pred_pct, scores, model_name, "percentile"))

        # Method B: best-F1 threshold
        y_pred_f1, best_thr = _threshold_best_f1(scores, y_true)
        row = _compute_metrics(y_true, y_pred_f1, scores, model_name, f"best_f1(thr={best_thr:.3f})")
        rows.append(row)

        # Confusion matrix plot for best-F1 predictions
        _plot_confusion_matrix(y_true, y_pred_f1, model_name, out)

    # ── 6. Generate plots ─────────────────────────────────────────────────────
    _plot_roc(y_true, scores_dict, out)
    _plot_score_distribution(y_true, scores_dict, out)

    # ── 7. Export metrics.csv ─────────────────────────────────────────────────
    print(f"[7/7] Writing metrics to {metrics_path} …")
    fieldnames = [
        "model", "threshold_method", "TP", "FP", "TN", "FN",
        "precision", "recall", "f1", "fpr", "roc_auc",
    ]
    with open(metrics_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # ── Print summary ─────────────────────────────────────────────────────────
    print("\n── Evaluation Summary ──────────────────────────────────────────")
    for row in rows:
        print(
            f"  {row['model']:18s} [{row['threshold_method']:30s}] "
            f"P={row['precision']:.3f} R={row['recall']:.3f} "
            f"F1={row['f1']:.3f} FPR={row['fpr']:.3f} AUC={row['roc_auc']:.3f}"
        )

    print("\n── System Performance Metrics ──────────────────────────────────")
    for model_name, sm in sys_metrics.items():
        throughput = n_total / sm["elapsed_s"] if sm["elapsed_s"] > 0 else float("inf")
        print(
            f"  {model_name:18s}  latency={sm['elapsed_s']:.4f}s  "
            f"throughput={throughput:,.0f} rows/s  "
            f"CPU={sm['cpu_pct']:.1f}%  "
            f"RSS_delta={sm['rss_mb_after']-sm['rss_mb_before']:.1f} MB"
        )

    print(f"\nMetrics CSV : {metrics_path}")
    print(f"Plots saved : {out}/")


def _build_sample_features(data_dir: str) -> str:
    """
    Build a sample features parquet from the repo's sample_logs.txt if the
    target file does not already exist.  Returns the path to the parquet.
    """
    import importlib
    import pathlib

    out_path = Path(data_dir) / "processed" / "features.parquet"
    if out_path.exists():
        return str(out_path)

    # Try to locate sample_logs.txt relative to this file
    repo_root = Path(__file__).resolve().parent.parent
    log_file = repo_root / "data" / "sample_logs.txt"
    if not log_file.exists():
        raise FileNotFoundError(
            f"No feature file at {out_path} and no sample_logs.txt at {log_file}. "
            "Run notebook 01_parse_clean.ipynb first to produce the feature file."
        )

    sys.path.insert(0, str(repo_root))
    from pipeline.log_parser import parse_log_file
    from pipeline.feature_engineering import engineer_features

    print(f"[auto] Parsing {log_file} to build features …")
    raw_df = parse_log_file(str(log_file))
    feat_df = engineer_features(raw_df)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    feat_df.to_parquet(str(out_path), index=False)
    print(f"[auto] Saved features → {out_path}")
    return str(out_path)


# ── CLI ────────────────────────────────────────────────────────────────────────

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.evaluation",
        description="Evaluate anomaly-detection models using Option A injection.",
    )
    parser.add_argument(
        "--input",
        default="data/processed/features.parquet",
        help="Path to processed feature file (parquet or CSV). "
             "If missing, the script will auto-generate it from data/sample_logs.txt.",
    )
    parser.add_argument(
        "--out",
        default="reports/",
        help="Directory for output plots.",
    )
    parser.add_argument(
        "--metrics",
        default="metrics.csv",
        help="Path for the output metrics CSV.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    # Auto-generate features if the input file doesn't exist yet
    input_path = args.input
    if not Path(input_path).exists():
        repo_root = Path(__file__).resolve().parent.parent
        data_dir = str(repo_root / "data")
        input_path = _build_sample_features(data_dir)

    evaluate(input_path, args.out, args.metrics)


if __name__ == "__main__":
    main()
