"""
app.py
------
LogGuard Flask application.

Routes
------
GET  /              → Serve the dashboard (index.html)
GET  /api/status    → Health-check / summary statistics
POST /api/analyze   → Analyse a log file; returns anomaly results as JSON
GET  /api/results   → Return last analysis results (from in-memory cache)
"""

from __future__ import annotations

import io
import os
import sys
import json
import tempfile
import traceback

import pandas as pd
from flask import Flask, jsonify, render_template, request

# ---------------------------------------------------------------------------
# Make the project root importable regardless of working directory
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from pipeline.log_parser import parse_log_file, parse_log_lines
from pipeline.feature_engineering import engineer_features
from model.anomaly_detector import run_full_analysis

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")

# Path to saved model (relative to project root)
_MODEL_PATH = os.path.join(_ROOT, "model", "logguard_model.pkl")

# In-memory cache for the last analysis result
_last_results: dict = {}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _dataframe_to_records(df: pd.DataFrame) -> list[dict]:
    """Serialise a DataFrame to a JSON-safe list of records."""
    out = []
    for _, row in df.iterrows():
        rec = {}
        for col, val in row.items():
            if hasattr(val, "isoformat"):           # datetime / Timestamp
                rec[col] = val.isoformat()
            elif hasattr(val, "item"):              # numpy scalar
                rec[col] = val.item()
            elif isinstance(val, bool):
                rec[col] = val
            else:
                rec[col] = val
        out.append(rec)
    return out


def _analyse_df(raw_df: pd.DataFrame) -> dict:
    """Run the full pipeline on a parsed log DataFrame and return summary."""
    if raw_df.empty:
        return {"error": "No valid log entries found."}

    features_df = engineer_features(raw_df)
    if features_df.empty:
        return {"error": "Feature engineering produced no rows."}

    results_df = run_full_analysis(features_df, model_path=_MODEL_PATH)

    anomalies_df = results_df[results_df["is_anomaly"]].sort_values(
        "anomaly_score", ascending=False
    )
    normal_df = results_df[~results_df["is_anomaly"]]

    top_anomalies = _dataframe_to_records(anomalies_df.head(20))
    all_results = _dataframe_to_records(results_df)

    # Timeline: group all rows by hour_bucket, compute mean anomaly score
    timeline_df = (
        results_df.groupby("hour_bucket")["anomaly_score"]
        .mean()
        .reset_index()
        .rename(columns={"anomaly_score": "mean_risk_score"})
    )
    timeline = _dataframe_to_records(timeline_df)

    # Status code distribution from raw logs
    status_counts = (
        raw_df["status_code"]
        .value_counts()
        .sort_index()
        .to_dict()
    )
    status_counts = {str(k): int(v) for k, v in status_counts.items()}

    # Request method distribution
    method_counts = raw_df["method"].value_counts().to_dict()
    method_counts = {str(k): int(v) for k, v in method_counts.items()}

    summary = {
        "total_requests": int(len(raw_df)),
        "total_ip_hour_buckets": int(len(results_df)),
        "anomaly_count": int(len(anomalies_df)),
        "normal_count": int(len(normal_df)),
        "anomaly_rate": (
            round(len(anomalies_df) / len(results_df) * 100, 2)
            if len(results_df) > 0 else 0.0
        ),
        "top_anomalies": top_anomalies,
        "all_results": all_results,
        "timeline": timeline,
        "status_code_distribution": status_counts,
        "method_distribution": method_counts,
    }
    return summary


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    """Health check + info about last run."""
    return jsonify(
        {
            "status": "ok",
            "has_results": bool(_last_results),
            "model_trained": os.path.exists(_MODEL_PATH),
        }
    )


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyse an uploaded log file or a block of log text.

    Accepts:
    - multipart/form-data with field ``logfile`` (file upload)
    - application/json with field ``log_text`` (raw log string)
    - application/json with field ``use_sample`` (bool) to use bundled sample
    """
    global _last_results

    try:
        use_sample = False
        raw_df = None

        # --- file upload ---
        if "logfile" in request.files:
            f = request.files["logfile"]
            with tempfile.NamedTemporaryFile(
                suffix=".log", delete=False, mode="wb"
            ) as tmp:
                f.save(tmp)
                tmp_path = tmp.name
            try:
                raw_df = parse_log_file(tmp_path)
            finally:
                os.unlink(tmp_path)

        # --- JSON payload ---
        elif request.is_json:
            payload = request.get_json(force=True) or {}
            if payload.get("use_sample"):
                use_sample = True
            elif "log_text" in payload:
                lines = payload["log_text"].splitlines()
                raw_df = parse_log_lines(lines)
            else:
                use_sample = True

        # --- default: use bundled sample ---
        else:
            use_sample = True

        if use_sample:
            sample_path = os.path.join(_ROOT, "data", "sample_logs.txt")
            raw_df = parse_log_file(sample_path)

        result = _analyse_df(raw_df)
        if "error" not in result:
            _last_results = result

        return jsonify(result)

    except Exception:
        tb = traceback.format_exc()
        app.logger.error("Analysis error:\n%s", tb)
        return jsonify({"error": "Internal error during analysis.", "detail": tb}), 500


@app.route("/api/results")
def results():
    """Return the cached results from the last analysis."""
    if not _last_results:
        return jsonify({"error": "No analysis has been run yet."}), 404
    return jsonify(_last_results)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
