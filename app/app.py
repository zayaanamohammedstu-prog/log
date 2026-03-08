"""
app.py
------
LogGuard Flask application.

Routes
------
GET  /              → Serve the dashboard (index.html) – login required
GET  /login         → Login page
POST /login         → Authenticate and start session
GET  /logout        → End session
GET  /admin         → Admin page – admin role required
GET  /api/status    → Health-check / summary statistics – login required
POST /api/analyze   → Analyse a log file; returns anomaly results as JSON – login required
GET  /api/results   → Return last analysis results (from in-memory cache) – login required
"""

from __future__ import annotations

import io
import os
import sys
import json
import tempfile
import traceback

import pandas as pd
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

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

# Add the app directory to sys.path so that db and models are importable
# regardless of how the application is invoked (flask run, gunicorn, pytest…)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from db import (  # noqa: E402
    init_db,
    create_user,
    get_user_by_username,
    get_user_by_id,
    count_users,
    verify_password,
)
from models import User  # noqa: E402

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
    instance_relative_config=True,
)

# Secret key for Flask sessions – override with env var in production
app.secret_key = os.environ.get("LOGGUARD_SECRET_KEY", "dev-insecure-change-me")

# ---------------------------------------------------------------------------
# Flask-Login setup
# ---------------------------------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access the Audit Workbench."
login_manager.login_message_category = "warning"


@login_manager.user_loader
def _load_user(user_id: str) -> "User | None":
    row = get_user_by_id(app.instance_path, int(user_id))
    return User(row) if row else None


@login_manager.unauthorized_handler
def _unauthorized():
    """Return JSON 401 for API requests; redirect to /login for browser requests."""
    if request.path.startswith("/api/"):
        return jsonify({"error": "Authentication required."}), 401
    return redirect(url_for("login", next=request.path))


# ---------------------------------------------------------------------------
# DB bootstrap: create admin from env vars on first run
# ---------------------------------------------------------------------------
def _bootstrap_db() -> None:
    """Initialise the DB and create the first admin if no users exist."""
    init_db(app.instance_path)
    if count_users(app.instance_path) == 0:
        username = os.environ.get("LOGGUARD_ADMIN_USERNAME", "").strip()
        password = os.environ.get("LOGGUARD_ADMIN_PASSWORD", "").strip()
        if username and password:
            create_user(app.instance_path, username, password, role="admin")
            app.logger.info("Bootstrap: admin user '%s' created.", username)
        else:
            app.logger.warning(
                "No users exist. Set LOGGUARD_ADMIN_USERNAME and "
                "LOGGUARD_ADMIN_PASSWORD env vars to create the first admin."
            )


with app.app_context():
    _bootstrap_db()

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

    # Top 10 IPs by total request count
    top_ips = (
        raw_df.groupby("ip_address")
        .size()
        .reset_index(name="request_count")
        .sort_values("request_count", ascending=False)
        .head(10)
        .to_dict(orient="records")
    )
    top_ips = [{"ip_address": r["ip_address"], "request_count": int(r["request_count"])} for r in top_ips]

    # Hourly distribution (hour 0–23)
    hourly_dist_series = (
        pd.to_datetime(raw_df["timestamp"], utc=True)
        .dt.hour
        .value_counts()
        .sort_index()
    )
    hourly_distribution = {str(h): int(c) for h, c in hourly_dist_series.items()}

    # Risk classification for each IP/hour bucket
    def _classify_risk(score: float) -> str:
        if score >= 0.7:
            return "Critical"
        if score >= 0.5:
            return "High"
        if score >= 0.3:
            return "Medium"
        return "Low"

    results_df["risk_level"] = results_df["anomaly_score"].apply(_classify_risk)
    risk_distribution = results_df["risk_level"].value_counts().to_dict()
    risk_distribution = {k: int(v) for k, v in risk_distribution.items()}

    # Top anomalous IPs (max score per IP)
    if not anomalies_df.empty:
        top_anomalous_ips = (
            anomalies_df.groupby("ip_address")
            .agg(max_score=("anomaly_score", "max"), total_requests=("requests_per_hour", "sum"))
            .sort_values("max_score", ascending=False)
            .head(10)
            .reset_index()
        )
        top_anomalous_ips = [
            {
                "ip_address": r["ip_address"],
                "max_score": round(float(r["max_score"]), 4),
                "total_requests": int(r["total_requests"]),
            }
            for _, r in top_anomalous_ips.iterrows()
        ]
    else:
        top_anomalous_ips = []

    # Endpoint frequency (top 10 most visited endpoints)
    top_endpoints = (
        raw_df["endpoint"]
        .value_counts()
        .head(10)
        .to_dict()
    )
    top_endpoints = {str(k): int(v) for k, v in top_endpoints.items()}

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
        "top_ips": top_ips,
        "hourly_distribution": hourly_distribution,
        "risk_distribution": risk_distribution,
        "top_anomalous_ips": top_anomalous_ips,
        "top_endpoints": top_endpoints,
    }
    return summary


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    return render_template("index.html", user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_user_by_username(app.instance_path, username)
        if row and verify_password(row["password"], password):
            user = User(row)
            login_user(user)
            next_page = request.args.get("next") or url_for("index")
            # Prevent open-redirect: only follow relative paths
            if not next_page.startswith("/"):
                next_page = url_for("index")
            return redirect(next_page)
        error = "Invalid username or password."
    no_users = count_users(app.instance_path) == 0
    return render_template("login.html", error=error, no_users=no_users)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return render_template("admin.html", forbidden=True, user=current_user), 403
    user_count = count_users(app.instance_path)
    return render_template(
        "admin.html",
        forbidden=False,
        user=current_user,
        user_count=user_count,
    )


@app.route("/api/status")
@login_required
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
@login_required
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
@login_required
def results():
    """Return the cached results from the last analysis."""
    if not _last_results:
        return jsonify({"error": "No analysis has been run yet."}), 404
    return jsonify(_last_results)


@app.route("/api/export/<fmt>")
@login_required
def export_results(fmt: str):
    """Export the last analysis results as CSV or JSON.

    Parameters
    ----------
    fmt : str
        ``csv`` or ``json``.
    """
    if not _last_results:
        return jsonify({"error": "No analysis has been run yet."}), 404

    if fmt == "csv":
        rows = _last_results.get("all_results", [])
        if not rows:
            return jsonify({"error": "No row-level results to export."}), 404
        df = pd.DataFrame(rows)
        csv_data = df.to_csv(index=False)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=logguard_results.csv"
            },
        )

    if fmt == "json":
        return Response(
            json.dumps(_last_results, indent=2, default=str),
            mimetype="application/json",
            headers={
                "Content-Disposition": "attachment; filename=logguard_results.json"
            },
        )

    return jsonify({"error": "Unsupported format. Use 'csv' or 'json'."}), 400


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
