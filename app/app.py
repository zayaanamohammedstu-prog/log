"""
app.py
------
LogGuard Flask application.

Routes
------
GET  /              → Public landing page; authenticated users redirected by role
GET  /auditor       → Auditor workbench (index.html) – auditor role only
GET  /login         → Login page
POST /login         → Authenticate and redirect by role
GET  /logout        → End session
GET  /admin         → Admin page – admin role required
GET  /api/status    → Health-check / summary statistics – login required
POST /api/analyze   → Analyse a log file; returns anomaly results as JSON – login required
GET  /api/results   → Return last analysis results (from in-memory cache) – login required
GET  /api/runs                                → List all analysis runs
GET  /api/runs/<run_id>                       → Get run with results
GET  /api/runs/<run_id>/anomalies/<anomaly_id> → Single anomaly detail
GET  /api/runs/<run_id>/ips/<ip>/timeline     → IP activity timeline
GET  /api/runs/<run_id>/chains                → List attack chains
GET  /api/runs/<run_id>/chains/<chain_id>     → Single chain detail
GET  /api/runs/<run_id>/report                → HTML report
GET  /api/audit/verify                        → Verify ledger (admin)
GET  /api/audit/entries                       → List ledger entries (admin)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
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
from pipeline.feature_engineering import engineer_features, get_feature_matrix, _FEATURE_COLUMNS
from pipeline.baselines import (
    compute_global_baselines,
    compute_ip_baselines,
    add_baseline_features,
    build_behavioral_profiles,
)
from pipeline.attack_chain import build_chains
from model.anomaly_detector import run_full_analysis
from model.ensemble import run_ensemble
from model.explain import explain_all

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
    count_admins,
    promote_user_to_admin,
    verify_password,
    list_users,
    delete_user,
)
from models import User  # noqa: E402
from run_store import (  # noqa: E402
    init_run_store,
    save_run,
    save_results,
    get_run,
    list_runs,
    get_run_results,
    get_run_summary,
    save_chains,
    get_chains,
    get_chain,
)
from audit_ledger import (  # noqa: E402
    init_ledger,
    append_entry,
    get_all_entries,
    verify_chain,
)
from reporting import generate_html_report  # noqa: E402

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
    """Initialise the DB and create the first admin if no users exist.

    Admin recovery: if env vars are set and *no admin* exists (even when users
    are already present), the named account is created or promoted to admin.
    This lets operators recover from a locked-out state without resetting the DB.
    """
    init_db(app.instance_path)
    init_run_store(app.instance_path)
    init_ledger(app.instance_path)
    username = os.environ.get("LOGGUARD_ADMIN_USERNAME", "").strip()
    password = os.environ.get("LOGGUARD_ADMIN_PASSWORD", "").strip()
    if count_users(app.instance_path) == 0:
        if username and password:
            create_user(app.instance_path, username, password, role="admin")
            app.logger.info("Bootstrap: admin user '%s' created.", username)
        else:
            app.logger.warning(
                "No users exist. Set LOGGUARD_ADMIN_USERNAME and "
                "LOGGUARD_ADMIN_PASSWORD env vars to create the first admin."
            )
    elif username and password and count_admins(app.instance_path) == 0:
        # Users exist but there is no admin – promote or create the named account.
        existing = get_user_by_username(app.instance_path, username)
        if existing:
            if promote_user_to_admin(app.instance_path, username):
                app.logger.info(
                    "Bootstrap recovery: existing user '%s' promoted to admin.",
                    username,
                )
        else:
            create_user(app.instance_path, username, password, role="admin")
            app.logger.info(
                "Bootstrap recovery: admin user '%s' created (no admin existed).",
                username,
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

    # ── Baselines ────────────────────────────────────────────────────────────
    global_baselines = compute_global_baselines(features_df)
    ip_baselines = compute_ip_baselines(features_df)
    features_df = add_baseline_features(features_df, global_baselines, ip_baselines)

    # ── Ensemble anomaly detection ───────────────────────────────────────────
    X = get_feature_matrix(features_df)
    results_df = features_df.copy()
    try:
        ensemble_result = run_ensemble(X)
        results_df["is_anomaly"] = ensemble_result["ensemble_label"]
        results_df["anomaly_score"] = ensemble_result["ensemble_score"]
        results_df["ensemble_score"] = ensemble_result["ensemble_score"]
        results_df["ensemble_label"] = [
            "anomaly" if lbl else "normal"
            for lbl in ensemble_result["ensemble_label"]
        ]
        for model_name in ("isolation_forest", "lof", "ocsvm", "autoencoder"):
            results_df[f"score_{model_name}"] = (
                ensemble_result["per_model_scores"][model_name]
            )
        results_df["agreement_pct"] = ensemble_result["agreement_pct"]
    except Exception:
        app.logger.warning(
            "Ensemble failed, falling back to IsolationForest:\n%s",
            traceback.format_exc(),
        )
        fallback = run_full_analysis(features_df, model_path=_MODEL_PATH)
        results_df["is_anomaly"] = fallback["is_anomaly"]
        results_df["anomaly_score"] = fallback["anomaly_score"]
        results_df["ensemble_score"] = fallback["anomaly_score"]
        results_df["ensemble_label"] = [
            "anomaly" if a else "normal" for a in fallback["is_anomaly"]
        ]

    # ── Explanations ─────────────────────────────────────────────────────────
    results_df = explain_all(results_df, global_baselines, ip_baselines)

    # ── Derived splits ───────────────────────────────────────────────────────
    anomalies_df = results_df[results_df["is_anomaly"]].sort_values(
        "anomaly_score", ascending=False
    )
    normal_df = results_df[~results_df["is_anomaly"]]

    # ── Attack chains ────────────────────────────────────────────────────────
    chains = build_chains(anomalies_df)

    # ── Behavioral profiles ──────────────────────────────────────────────────
    behavioral_profiles = build_behavioral_profiles(features_df, ip_baselines=ip_baselines)

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
    top_ips = [
        {"ip_address": r["ip_address"], "request_count": int(r["request_count"])}
        for r in top_ips
    ]

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
            .agg(
                max_score=("anomaly_score", "max"),
                total_requests=("requests_per_hour", "sum"),
            )
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
        "chains": chains,
        "behavioral_profiles": behavioral_profiles,
    }
    return summary


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Self-service registration
# ---------------------------------------------------------------------------

def _signup_allowed() -> bool:
    """Return True when self-service registration is permitted.

    Registration is open when:
    - No users exist yet (first-time setup), OR
    - The LOGGUARD_ENABLE_PUBLIC_SIGNUP env var is set to a truthy value.
    """
    if os.environ.get("LOGGUARD_ENABLE_PUBLIC_SIGNUP", "").lower() in (
        "1", "true", "yes"
    ):
        return True
    return count_users(app.instance_path) == 0


@app.route("/register", methods=["GET", "POST"])
def register():
    """Self-service registration.  Only accessible when signup is allowed."""
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin"))
        return redirect(url_for("auditor"))

    if not _signup_allowed():
        return render_template(
            "register.html",
            error=None,
            signup_disabled=True,
        ), 403

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not username or not password:
            error = "Username and password are required."
        elif len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        elif get_user_by_username(app.instance_path, username):
            error = "That username is already taken."
        else:
            # First user becomes admin; subsequent users get auditor role.
            role = "admin" if count_users(app.instance_path) == 0 else "auditor"
            create_user(app.instance_path, username, password, role=role)
            return redirect(url_for("login"))

    return render_template("register.html", error=error, signup_disabled=False)


@app.route("/")
def main():
    """Public landing page. Authenticated users are redirected to their portal."""
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin"))
        return redirect(url_for("auditor"))
    return render_template("main.html", signup_allowed=_signup_allowed())


@app.route("/auditor")
@login_required
def auditor():
    """Auditor workbench portal. Accessible to auditor, admin, and administrator roles."""
    if not current_user.can_access_auditor_portal:
        return render_template(
            "admin.html", forbidden=True, forbidden_page="auditor", user=current_user
        ), 403
    return render_template("index.html", user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin"))
        return redirect(url_for("auditor"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_user_by_username(app.instance_path, username)
        if row and verify_password(row["password"], password):
            user = User(row)
            login_user(user)
            # Route by role; ignore next= to enforce separation of duties
            if user.is_admin:
                return redirect(url_for("admin"))
            return redirect(url_for("auditor"))
        error = "Invalid username or password."
    no_users = count_users(app.instance_path) == 0
    return render_template(
        "login.html",
        error=error,
        no_users=no_users,
        signup_allowed=_signup_allowed(),
    )


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return render_template(
            "admin.html", forbidden=True, forbidden_page="admin", user=current_user
        ), 403
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
        input_type = "sample"
        raw_bytes = b""
        filename = ""

        # --- file upload ---
        if "logfile" in request.files:
            f = request.files["logfile"]
            filename = f.filename or ""
            raw_bytes = f.read()
            input_type = "upload"
            with tempfile.NamedTemporaryFile(
                suffix=".log", delete=False, mode="wb"
            ) as tmp:
                tmp.write(raw_bytes)
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
                input_type = "log_text"
                raw_bytes = payload["log_text"].encode()
                lines = payload["log_text"].splitlines()
                raw_df = parse_log_lines(lines)
            else:
                use_sample = True

        # --- default: use bundled sample ---
        else:
            use_sample = True

        if use_sample:
            sample_path = os.path.join(_ROOT, "data", "sample_logs.txt")
            with open(sample_path, "rb") as fh:
                raw_bytes = fh.read()
            raw_df = parse_log_file(sample_path)
            filename = "sample_logs.txt"

        input_hash = hashlib.sha256(raw_bytes).hexdigest()

        result = _analyse_df(raw_df)
        if "error" not in result:
            # Build a compact summary (all_results omitted — large row-level data
            # is already persisted in analysis_results table).
            summary_for_storage = {
                k: v for k, v in result.items() if k != "all_results"
            }

            # ── Persist the run ───────────────────────────────────────────
            run_id = save_run(
                app.instance_path,
                username=current_user.username,
                input_type=input_type,
                input_hash=input_hash,
                filename=filename,
                summary_json=json.dumps(summary_for_storage, default=str),
            )

            # Build records for DB insertion using the canonical feature column list
            records_to_save = []
            for rec in result.get("all_results", []):
                model_scores = {
                    m: rec.get(f"score_{m}")
                    for m in ("isolation_forest", "lof", "ocsvm", "autoencoder")
                    if rec.get(f"score_{m}") is not None
                }
                records_to_save.append({
                    "ip_address": rec.get("ip_address"),
                    "hour_bucket": rec.get("hour_bucket"),
                    "features": {
                        col: rec.get(col)
                        for col in _FEATURE_COLUMNS  # from pipeline.feature_engineering
                        if col in rec
                    },
                    "anomaly_score": rec.get("anomaly_score"),
                    "is_anomaly": rec.get("is_anomaly"),
                    "ensemble_score": rec.get("ensemble_score"),
                    "model_scores": model_scores,
                    "ensemble_label": rec.get("ensemble_label"),
                    "explanations": (
                        json.loads(rec["explanations_json"])
                        if rec.get("explanations_json")
                        else {}
                    ),
                })
            save_results(app.instance_path, run_id, records_to_save)

            # Save attack chains
            chains = result.get("chains", [])
            if chains:
                save_chains(app.instance_path, run_id, chains)

            # Compute results_hash for the ledger
            results_summary = json.dumps(
                {
                    "run_id": run_id,
                    "anomaly_count": result.get("anomaly_count"),
                    "total_requests": result.get("total_requests"),
                },
                sort_keys=True,
            )
            results_hash = hashlib.sha256(results_summary.encode()).hexdigest()

            append_entry(
                app.instance_path,
                actor=current_user.username,
                input_hash=input_hash,
                results_hash=results_hash,
            )

            result["run_id"] = run_id
            result["filename"] = filename
            _last_results = result

        return jsonify(result)

    except Exception:
        tb = traceback.format_exc()
        app.logger.error("Analysis error:\n%s", tb)
        return jsonify({"error": "Internal error during analysis.", "detail": tb}), 500


# ---------------------------------------------------------------------------
# Run management endpoints
# ---------------------------------------------------------------------------

@app.route("/api/runs")
@login_required
def api_list_runs():
    """List all analysis runs, newest first."""
    runs = list_runs(app.instance_path)
    return jsonify({"runs": runs})


@app.route("/api/runs/<int:run_id>")
@login_required
def api_get_run(run_id: int):
    """Return run metadata and all result rows."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    results = get_run_results(app.instance_path, run_id)
    return jsonify({"run": run, "results": results})


@app.route("/api/runs/<int:run_id>/anomalies/<int:anomaly_id>")
@login_required
def api_get_anomaly(run_id: int, anomaly_id: int):
    """Return a single anomaly result row by its DB id."""
    results = get_run_results(app.instance_path, run_id)
    for r in results:
        if r.get("id") == anomaly_id:
            return jsonify(r)
    return jsonify({"error": "Anomaly not found."}), 404


@app.route("/api/runs/<int:run_id>/ips/<path:ip>/timeline")
@login_required
def api_ip_timeline(run_id: int, ip: str):
    """Return all result rows for a specific IP in a run, ordered by time."""
    results = get_run_results(app.instance_path, run_id)
    timeline = sorted(
        [r for r in results if r.get("ip_address") == ip],
        key=lambda r: r.get("hour_bucket") or "",
    )
    if not timeline:
        return jsonify({"error": "IP not found in this run."}), 404
    return jsonify({"ip_address": ip, "timeline": timeline})


@app.route("/api/runs/<int:run_id>/chains")
@login_required
def api_list_chains(run_id: int):
    """List all attack chains for a run."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    chains = get_chains(app.instance_path, run_id)
    return jsonify({"run_id": run_id, "chains": chains})


@app.route("/api/runs/<int:run_id>/chains/<int:chain_id>")
@login_required
def api_get_chain(run_id: int, chain_id: int):
    """Return a single chain by its DB id."""
    chain = get_chain(app.instance_path, run_id, chain_id)
    if chain is None:
        return jsonify({"error": "Chain not found."}), 404
    return jsonify(chain)


@app.route("/api/runs/<int:run_id>/summary")
@login_required
def api_run_summary(run_id: int):
    """Return the stored analysis summary for a run (for history reload)."""
    summary = get_run_summary(app.instance_path, run_id)
    if summary is None:
        # Run may exist but summary not stored (old run); fall back to metadata only
        run = get_run(app.instance_path, run_id)
        if run is None:
            return jsonify({"error": "Run not found."}), 404
        return jsonify({"error": "Summary not available for this run.", "run": run}), 404
    return jsonify(summary)


@app.route("/api/runs/<int:run_id>/report")
@login_required
def api_run_report(run_id: int):
    """Generate and return an HTML report for a run."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    results = get_run_results(app.instance_path, run_id)
    chains = get_chains(app.instance_path, run_id)
    html_report = generate_html_report(run, results, chains)
    return Response(
        html_report,
        mimetype="text/html",
        headers={
            "Content-Disposition": f'inline; filename="report_run_{run_id}.html"'
        },
    )


# ---------------------------------------------------------------------------
# Audit ledger endpoints (admin only)
# ---------------------------------------------------------------------------

@app.route("/api/audit/verify")
@login_required
def api_audit_verify():
    """Verify the integrity of the audit ledger. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    result = verify_chain(app.instance_path)
    return jsonify(result)


@app.route("/api/audit/entries")
@login_required
def api_audit_entries():
    """Return all audit ledger entries. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    entries = get_all_entries(app.instance_path)
    return jsonify({"entries": entries})


# ---------------------------------------------------------------------------
# Admin API endpoints (admin only)
# ---------------------------------------------------------------------------

@app.route("/api/admin/stats")
@login_required
def api_admin_stats():
    """Return system statistics for the admin panel."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    user_count = count_users(app.instance_path)
    runs = list_runs(app.instance_path, limit=1000)
    return jsonify({
        "user_count": user_count,
        "total_runs": len(runs),
        "version": "v2.0",
        "db_engine": "SQLite",
    })


@app.route("/api/admin/users", methods=["GET"])
@login_required
def api_admin_list_users():
    """List all registered users. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    users = list_users(app.instance_path)
    return jsonify({"users": users})


@app.route("/api/admin/users", methods=["POST"])
@login_required
def api_admin_create_user():
    """Create a new user. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    payload = request.get_json(force=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    role = (payload.get("role") or "auditor").strip()
    if not username or not password:
        return jsonify({"error": "username and password are required."}), 400
    if role not in ("admin", "auditor", "administrator"):
        return jsonify({"error": "role must be 'admin', 'administrator', or 'auditor'."}), 400
    existing = get_user_by_username(app.instance_path, username)
    if existing:
        return jsonify({"error": f"Username '{username}' already exists."}), 409
    new_id = create_user(app.instance_path, username, password, role=role)
    return jsonify({"id": new_id, "username": username, "role": role}), 201


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
def api_admin_delete_user(user_id: int):
    """Delete a user by id. Admin only. Cannot delete yourself."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    if user_id == current_user.id:
        return jsonify({"error": "You cannot delete your own account."}), 400
    deleted = delete_user(app.instance_path, user_id)
    if not deleted:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"deleted": True, "user_id": user_id})


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
