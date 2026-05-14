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
GET  /api/runs/<run_id>/report/pdf            → PDF report download
POST /api/runs/<run_id>/send/email            → Send PDF report via email
POST /api/runs/<run_id>/send/whatsapp         → Send PDF report via WhatsApp
GET  /api/audit/verify                        → Verify ledger (admin)
GET  /api/audit/entries                       → List ledger entries (admin)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import sys
import tempfile
import traceback
from datetime import datetime, timedelta, timezone
try:
    from app.mailer import send_report_email, send_verification_email, MailerError
    from app.reporting import generate_pdf_report  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - fallback for direct module execution
    from mailer import send_report_email, send_verification_email, MailerError
    from reporting import generate_pdf_report  # noqa: E402
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
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from werkzeug.utils import secure_filename

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
    list_pending_users,
    approve_user,
    reject_user,
    soft_delete_user,
    restore_user,
    list_deleted_users,
    update_user_role,
    count_super_admins,
    soft_delete_run,
    restore_run,
    list_deleted_runs,
    get_user_by_email,
    mark_email_verified,
    set_email_verification_token,
    get_user_by_verification_token,
    get_user_profile,
    update_user_profile,
    update_user_password,
    update_user_avatar,
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
    save_anomaly_feedback,
    get_feedback_counts,
)
from audit_ledger import (  # noqa: E402
    init_ledger,
    append_entry,
    get_all_entries,
    verify_chain,
)
from reporting import generate_html_report  # noqa: E402
from slack_alert import notify_critical_anomalies  # noqa: E402

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
# JWT, CORS, and SocketIO setup
# ---------------------------------------------------------------------------
app.config["JWT_SECRET_KEY"] = os.environ.get(
    "LOGGUARD_JWT_SECRET", app.secret_key + "-jwt"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)
jwt = JWTManager(app)
CORS(app, origins=os.environ.get("LOGGUARD_CORS_ORIGINS", "*").split(","))
socketio = SocketIO(
    app,
    cors_allowed_origins=os.environ.get("LOGGUARD_CORS_ORIGINS", "*"),
    async_mode="eventlet",
)

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

    # Super-admin bootstrap (takes precedence)
    sa_username = os.environ.get("LOGGUARD_SUPER_ADMIN_USERNAME", "").strip()
    sa_password = os.environ.get("LOGGUARD_SUPER_ADMIN_PASSWORD", "").strip()
    if sa_username and sa_password and count_super_admins(app.instance_path) == 0:
        existing = get_user_by_username(app.instance_path, sa_username)
        if not existing:
            create_user(
                app.instance_path, sa_username, sa_password,
                role="super_admin", status="active",
            )
            app.logger.info("Bootstrap: super_admin user '%s' created.", sa_username)

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


def _persist_analysis_result(
    result: dict,
    *,
    input_type: str,
    input_hash: str,
    filename: str,
) -> int:
    """Persist analysis outputs and emit audit + realtime notifications."""
    global _last_results

    init_run_store(app.instance_path)

    summary_for_storage = {k: v for k, v in result.items() if k != "all_results"}
    run_id = save_run(
        app.instance_path,
        username=current_user.username,
        input_type=input_type,
        input_hash=input_hash,
        filename=filename,
        summary_json=json.dumps(summary_for_storage, default=str),
    )

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
                for col in _FEATURE_COLUMNS
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

    chains = result.get("chains", [])
    if chains:
        save_chains(app.instance_path, run_id, chains)

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

    try:
        socketio.emit(
            "new_analysis",
            {
                "run_id": run_id,
                "username": current_user.username,
                "anomaly_count": result.get("anomaly_count"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            room="audit_room",
        )
    except Exception:
        pass

    try:
        critical = [
            r for r in result.get("top_anomalies", [])
            if float(r.get("anomaly_score") or 0.0) >= 0.7
        ]
        notify_critical_anomalies(run_id, critical)
    except Exception:
        app.logger.warning("Slack notification failed for run %s", run_id, exc_info=True)

    return run_id


def _flatten_run_results_for_export(results: list[dict]) -> list[dict]:
    """Convert persisted run rows to a tabular list for exports."""
    out: list[dict] = []
    for row in results:
        rec: dict = {
            "id": row.get("id"),
            "ip_address": row.get("ip_address"),
            "hour_bucket": row.get("hour_bucket"),
            "anomaly_score": row.get("anomaly_score"),
            "ensemble_score": row.get("ensemble_score"),
            "is_anomaly": row.get("is_anomaly"),
            "ensemble_label": row.get("ensemble_label"),
        }
        raw_features = row.get("features_json")
        if raw_features:
            try:
                features = json.loads(raw_features) if isinstance(raw_features, str) else raw_features
                if isinstance(features, dict):
                    rec.update(features)
            except Exception:
                pass
        out.append(rec)
    return out


def _build_report_attachment(run: dict, results: list[dict], chains: list[dict], fmt: str) -> tuple[str, str, bytes]:
    """Build a run report attachment as (filename, mime, bytes)."""
    fmt = (fmt or "pdf").strip().lower()
    run_id = run.get("id") or run.get("run_id") or "run"

    if fmt == "pdf":
        payload = generate_pdf_report(run, results, chains)
        return (f"logguard_report_run_{run_id}.pdf", "application/pdf", payload)

    if fmt == "html":
        html_report = generate_html_report(run, results, chains)
        return (
            f"logguard_report_run_{run_id}.html",
            "text/html; charset=utf-8",
            html_report.encode("utf-8"),
        )

    rows = _flatten_run_results_for_export(results)
    if fmt == "csv":
        df = pd.DataFrame(rows)
        csv_data = df.to_csv(index=False)
        return (
            f"logguard_results_run_{run_id}.csv",
            "text/csv; charset=utf-8",
            csv_data.encode("utf-8"),
        )
    if fmt == "json":
        payload = {
            "run": run,
            "results": rows,
            "chains": chains,
        }
        return (
            f"logguard_results_run_{run_id}.json",
            "application/json",
            json.dumps(payload, indent=2, default=str).encode("utf-8"),
        )

    raise ValueError("Unsupported format. Use one of: pdf, html, csv, json.")


def _emit_admin_notification(event_type: str, message: str, **payload: object) -> None:
    """Emit a realtime admin notification event to connected dashboard clients."""
    try:
        socketio.emit(
            "admin_notification",
            {
                "type": event_type,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **payload,
            },
            room="audit_room",
        )
    except Exception:
        pass


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


def _is_auditor_role() -> bool:
    """Return True when current user is a plain auditor account."""
    return (getattr(current_user, "role", "") or "").strip().lower() == "auditor"


def _run_access_denied(run: dict) -> bool:
    """Return True when the current user may not access the given run."""
    return _is_auditor_role() and run.get("username") != current_user.username


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
            signup_env_var="LOGGUARD_ENABLE_PUBLIC_SIGNUP=true",
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
    return render_template("main.html", signup_allowed=_signup_allowed(), now=datetime.utcnow())


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
            # Check user status before allowing login
            status = row.get("status", "active") or "active"
            if status == "email_verification_pending":
                error = "Please verify your email before admin approval."
            elif status == "pending":
                error = "Account pending approval."
            elif status == "suspended":
                error = "Account suspended."
            else:
                user = User(row)
                login_user(user)
                # Route by role; ignore next= to enforce separation of duties
                if user.is_admin:
                    return redirect(url_for("admin"))
                return redirect(url_for("auditor"))
        else:
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
            _persist_analysis_result(
                result,
                input_type=input_type,
                input_hash=input_hash,
                filename=filename,
            )

        return jsonify(result)

    except Exception:
        tb = traceback.format_exc()
        app.logger.error("Analysis error:\n%s", tb)
        return jsonify({"error": "Internal error during analysis.", "detail": tb}), 500


# ---------------------------------------------------------------------------
# Real-time ingestion + feedback endpoints
# ---------------------------------------------------------------------------

@app.route("/api/ingest", methods=["POST"])
@login_required
def api_ingest():
    """
    Ingest log lines in real-time via JSON.

    Accepted JSON payload keys:
    - ``log_line``: single log line string
    - ``log_lines`` / ``logs``: list of log line strings
    - ``log_text``: multiline log text
    """
    payload = request.get_json(silent=True) or {}
    lines: list[str] = []

    if isinstance(payload.get("log_line"), str):
        lines.append(payload["log_line"])
    if isinstance(payload.get("log_text"), str):
        lines.extend(payload["log_text"].splitlines())
    if isinstance(payload.get("log_lines"), list):
        lines.extend(str(v) for v in payload["log_lines"])
    if isinstance(payload.get("logs"), list):
        lines.extend(str(v) for v in payload["logs"])

    lines = [ln for ln in lines if ln and ln.strip()]
    if not lines:
        return jsonify({"error": "Provide log_line, log_lines/logs, or log_text."}), 400

    raw_df = parse_log_lines(lines)
    if raw_df.empty:
        return jsonify({"error": "No valid log entries found in payload."}), 400

    raw_text = "\n".join(lines).encode()
    input_hash = hashlib.sha256(raw_text).hexdigest()
    result = _analyse_df(raw_df)
    if "error" in result:
        return jsonify(result), 400

    _persist_analysis_result(
        result,
        input_type="ingest",
        input_hash=input_hash,
        filename="realtime_ingest",
    )
    result["received"] = len(lines)
    return jsonify(result), 201


@app.route("/api/feedback", methods=["POST"])
@login_required
def api_submit_feedback():
    """Create/update user feedback for an anomaly row candidate."""
    payload = request.get_json(silent=True) or {}
    run_id = payload.get("run_id")
    ip_address = (payload.get("ip_address") or "").strip()
    hour_bucket = (payload.get("hour_bucket") or "").strip()
    feedback = (payload.get("feedback") or "").strip().lower()

    if not isinstance(run_id, int):
        return jsonify({"error": "run_id (integer) is required."}), 400
    if not ip_address or not hour_bucket:
        return jsonify({"error": "ip_address and hour_bucket are required."}), 400
    if feedback not in ("confirmed", "false_positive"):
        return jsonify({"error": "feedback must be 'confirmed' or 'false_positive'."}), 400
    if get_run(app.instance_path, run_id) is None:
        return jsonify({"error": "Run not found."}), 404

    init_run_store(app.instance_path)
    save_anomaly_feedback(
        app.instance_path,
        run_id=run_id,
        ip_address=ip_address,
        hour_bucket=hour_bucket,
        username=current_user.username,
        feedback=feedback,
    )
    key = f"{ip_address}|{hour_bucket}"
    counts = get_feedback_counts(app.instance_path, run_id).get(
        key, {"confirmed": 0, "false_positive": 0}
    )
    return jsonify({"ok": True, "key": key, "counts": counts})


@app.route("/api/feedback/counts")
@login_required
def api_feedback_counts():
    """Return per-anomaly feedback counts for a run."""
    run_id_raw = request.args.get("run_id", "").strip()
    try:
        run_id = int(run_id_raw)
    except ValueError:
        return jsonify({"error": "run_id query parameter is required."}), 400
    init_run_store(app.instance_path)
    if get_run(app.instance_path, run_id) is None:
        return jsonify({"error": "Run not found."}), 404
    return jsonify({"run_id": run_id, "counts": get_feedback_counts(app.instance_path, run_id)})


# ---------------------------------------------------------------------------
# Run management endpoints
# ---------------------------------------------------------------------------

@app.route("/api/runs")
@login_required
def api_list_runs():
    """List analysis runs, newest first (auditors only see their own)."""
    runs = list_runs(app.instance_path)
    if _is_auditor_role():
        runs = [run for run in runs if run.get("username") == current_user.username]
    return jsonify({"runs": runs})


@app.route("/api/runs/<int:run_id>")
@login_required
def api_get_run(run_id: int):
    """Return run metadata and all result rows."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403
    results = get_run_results(app.instance_path, run_id)
    return jsonify({"run": run, "results": results})


@app.route("/api/runs/<int:run_id>/anomalies/<int:anomaly_id>")
@login_required
def api_get_anomaly(run_id: int, anomaly_id: int):
    """Return a single anomaly result row by its DB id."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403
    results = get_run_results(app.instance_path, run_id)
    for r in results:
        if r.get("id") == anomaly_id:
            return jsonify(r)
    return jsonify({"error": "Anomaly not found."}), 404


@app.route("/api/runs/<int:run_id>/ips/<path:ip>/timeline")
@login_required
def api_ip_timeline(run_id: int, ip: str):
    """Return all result rows for a specific IP in a run, ordered by time."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403
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
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403
    chains = get_chains(app.instance_path, run_id)
    return jsonify({"run_id": run_id, "chains": chains})


@app.route("/api/runs/<int:run_id>/chains/<int:chain_id>")
@login_required
def api_get_chain(run_id: int, chain_id: int):
    """Return a single chain by its DB id."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403
    chain = get_chain(app.instance_path, run_id, chain_id)
    if chain is None:
        return jsonify({"error": "Chain not found."}), 404
    return jsonify(chain)


@app.route("/api/runs/<int:run_id>/summary")
@login_required
def api_run_summary(run_id: int):
    """Return the stored analysis summary for a run (for history reload)."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403
    summary = get_run_summary(app.instance_path, run_id)
    if summary is None:
        # Run may exist but summary not stored (old run); fall back to metadata only
        return jsonify({"error": "Summary not available for this run.", "run": run}), 404
    return jsonify(summary)


@app.route("/api/runs/<int:run_id>/report")
@login_required
def api_run_report(run_id: int):
    """Generate and return an HTML report for a run."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403
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


@app.route("/api/runs/<int:run_id>/report/pdf")
@login_required
def api_run_report_pdf(run_id: int):
    """Generate and return a PDF report for a run."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403
    results = get_run_results(app.instance_path, run_id)
    chains = get_chains(app.instance_path, run_id)
    try:
        from reporting import generate_pdf_report  # noqa: E402
        pdf_bytes = generate_pdf_report(run, results, chains)
    except ImportError:
        return jsonify({"error": "PDF generation requires the 'fpdf2' package."}), 500
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="logguard_report_run_{run_id}.pdf"'
        },
    )


@app.route("/api/runs/<int:run_id>/send/email", methods=["POST"])
@login_required
def api_send_email(run_id: int):
    """Send a run report to an email address in a selected format."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403

    data = request.get_json(silent=True) or {}
    to_address = (data.get("to") or "").strip()
    report_format = (data.get("format") or "pdf").strip().lower()
    if not to_address:
        return jsonify({"error": "Recipient email address ('to') is required."}), 400

    results = get_run_results(app.instance_path, run_id)
    chains = get_chains(app.instance_path, run_id)
    try:
        filename, mime_type, attachment_bytes = _build_report_attachment(run, results, chains, report_format)
    except ImportError:
        return jsonify({"error": "PDF generation requires the 'fpdf2' package."}), 500
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        send_report_email(
            to_address,
            run_id,
            attachment_bytes,
            subject=f"LogGuard Report — Run #{run_id} ({report_format.upper()})",
            body=(
                f"Please find attached the LogGuard run #{run_id} report as {report_format.upper()}.\n\n"
                f"Generated by: {current_user.username}"
            ),
            attachment_filename=filename,
            attachment_mime_type=mime_type,
        )
    except MailerError as exc:
        app.logger.warning("Email send failed for run %s: %s", run_id, exc)
        # exc.args[0] is the controlled message we set in MailerError.__init__
        error_msg = exc.args[0] if exc.args else "Failed to send email."
        return jsonify({"error": error_msg}), 500

    _emit_admin_notification(
        "report_sent",
        f"Report run #{run_id} sent to {to_address} ({report_format.upper()}).",
        run_id=run_id,
        to=to_address,
        format=report_format,
        actor=current_user.username,
    )
    return jsonify({"ok": True, "message": f"Report ({report_format.upper()}) sent to {to_address}."})


@app.route("/api/runs/<int:run_id>/send/whatsapp", methods=["POST"])
@login_required
def api_send_whatsapp(run_id: int):
    """Send a PDF report to a WhatsApp number via the 360dialog WhatsApp API."""
    run = get_run(app.instance_path, run_id)
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    if _run_access_denied(run):
        return jsonify({"error": "Forbidden."}), 403

    data = request.get_json(silent=True) or {}
    to_number = (data.get("to") or "").strip()
    if not to_number:
        return jsonify({"error": "Recipient phone number ('to') is required."}), 400

    # Build a public URL for the 360dialog API to fetch the PDF
    public_base = os.environ.get("LOGGUARD_PUBLIC_URL", request.host_url.rstrip("/"))
    pdf_url = f"{public_base}/api/runs/{run_id}/report/pdf"

    try:
        from whatsapp_sender import send_report_whatsapp, WhatsAppSenderError  # noqa: E402
        send_report_whatsapp(to_number, run_id, pdf_url)
    except WhatsAppSenderError as exc:
        app.logger.warning("WhatsApp send failed for run %s: %s", run_id, exc)
        error_msg = exc.args[0] if exc.args else "Failed to send WhatsApp message."
        return jsonify({"error": error_msg}), 500

    return jsonify({"ok": True, "message": f"Report sent to {to_number} via WhatsApp."})


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
    """Soft-delete a user by id. Admin only. Cannot delete yourself."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    if user_id == current_user.id:
        return jsonify({"error": "You cannot delete your own account."}), 400
    deleted = soft_delete_user(app.instance_path, user_id, current_user.username)
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
        preferred = [
            ("IP", "ip_address"),
            ("Hour", "hour_bucket"),
            ("Score", "anomaly_score"),
            ("ReqHr", "requests_per_hour"),
            ("ErrRate", "error_rate"),
            ("Endpoints", "unique_endpoints"),
            ("PostRatio", "post_ratio"),
            ("OffHours", "is_off_hours"),
            ("ScannerUA", "has_scanner_ua"),
            ("Risk", "risk_level"),
        ]
        available = [(short, key) for short, key in preferred if key in df.columns]
        if available:
            df = df[[key for _, key in available]].rename(
                columns={key: short for short, key in available}
            )
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
# Viewer portal
# ---------------------------------------------------------------------------

@app.route("/viewer")
@login_required
def viewer():
    """Viewer dashboard – read-only access for all authenticated users."""
    return render_template("viewer.html", user=current_user)


# ---------------------------------------------------------------------------
# JWT API authentication endpoints
# ---------------------------------------------------------------------------

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """JWT login endpoint for API / React frontend."""
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password are required."}), 400
    row = get_user_by_username(app.instance_path, username)
    if not row or not verify_password(row["password"], password):
        return jsonify({"error": "Invalid username or password."}), 401
    status = row.get("status", "active") or "active"
    if status == "email_verification_pending":
        return jsonify({"error": "Please verify your email before admin approval."}), 403
    if status == "pending":
        return jsonify({"error": "Account pending approval."}), 403
    if status == "suspended":
        return jsonify({"error": "Account suspended."}), 403
    identity = str(row["id"])
    access_token = create_access_token(identity=identity)
    refresh_token = create_refresh_token(identity=identity)
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "status": status,
        },
    })


@app.route("/api/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def api_refresh():
    """Return a new access token using a valid refresh token."""
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify({"access_token": access_token})


@app.route("/api/auth/me", methods=["GET"])
@jwt_required()
def api_me():
    """Return current user info from JWT."""
    user_id = int(get_jwt_identity())
    row = get_user_by_id(app.instance_path, user_id)
    if not row:
        return jsonify({"error": "User not found."}), 404
    return jsonify({
        "id": row["id"],
        "username": row["username"],
        "display_name": row.get("display_name") or row["username"],
        "email": row.get("email") or "",
        "avatar_url": row.get("avatar_url") or "",
        "role": row["role"],
        "status": row.get("status", "active"),
    })


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    """Registration API endpoint – creates a pending user."""
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip()
    user_type = (data.get("user_type") or "auditor").strip().lower()
    if not username or not password:
        return jsonify({"error": "username and password are required."}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400
    if get_user_by_username(app.instance_path, username):
        return jsonify({"error": f"Username '{username}' already exists."}), 409
    if email and get_user_by_email(app.instance_path, email):
        return jsonify({"error": "An account with that email already exists."}), 409
    if count_users(app.instance_path) > 0 and not email:
        return jsonify({"error": "Email is required to register and verify your account."}), 400

    verification_token = secrets.token_urlsafe(32) if email else None
    if count_users(app.instance_path) == 0:
        role, status = "admin", "active"
        email_verified = 1 if email else 0
    else:
        role, status = "auditor", "email_verification_pending"
        email_verified = 0
    new_id = create_user(
        app.instance_path, username, password,
        role=role, status=status,
        email=email, user_type=user_type,
        email_verified=email_verified,
        verify_token=verification_token,
        display_name=username,
    )
    if verification_token and email:
        verify_url = url_for("verify_email", token=verification_token, _external=True)
        try:
            send_verification_email(email, verify_url)
        except MailerError as exc:
            app.logger.warning("Verification email send failed for user %s: %s", username, exc)
            return jsonify({"error": f"Could not send verification email: {exc}"}), 500
    message = (
        "Registration successful. Please verify your email to move to admin approval."
        if status == "email_verification_pending"
        else "Account created."
    )
    return jsonify({
        "id": new_id,
        "username": username,
        "role": role,
        "status": ("pending" if status == "email_verification_pending" else status),
        "message": message,
    }), 201


# ---------------------------------------------------------------------------
# Admin user approval / management API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/admin/users/pending", methods=["GET"])
@login_required
def api_admin_pending_users():
    """List users awaiting approval. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    users = list_pending_users(app.instance_path)
    return jsonify({"users": users})


@app.route("/api/admin/users/<int:user_id>/approve", methods=["POST"])
@login_required
def api_admin_approve_user(user_id: int):
    """Approve a pending user. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    ok = approve_user(app.instance_path, user_id, current_user.username)
    if not ok:
        return jsonify({"error": "User not found."}), 404
    _emit_admin_notification(
        "user_approved",
        f"User #{user_id} approved by {current_user.username}.",
        user_id=user_id,
        actor=current_user.username,
    )
    return jsonify({"approved": True, "user_id": user_id})


@app.route("/api/admin/users/<int:user_id>/reject", methods=["POST"])
@login_required
def api_admin_reject_user(user_id: int):
    """Reject/suspend a user. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    ok = reject_user(app.instance_path, user_id, current_user.username)
    if not ok:
        return jsonify({"error": "User not found."}), 404
    _emit_admin_notification(
        "user_rejected",
        f"User #{user_id} rejected by {current_user.username}.",
        user_id=user_id,
        actor=current_user.username,
    )
    return jsonify({"rejected": True, "user_id": user_id})


@app.route("/api/account/profile", methods=["GET"])
@login_required
def api_account_profile():
    """Return current account profile."""
    profile = get_user_profile(app.instance_path, current_user.id)
    if not profile:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"profile": profile})


@app.route("/api/account/profile", methods=["PATCH"])
@login_required
def api_account_update_profile():
    """Update current account profile fields."""
    data = request.get_json(force=True) or {}
    display_name = data.get("display_name")
    email = data.get("email")
    if email:
        existing = get_user_by_email(app.instance_path, email)
        if existing and existing.get("id") != current_user.id:
            return jsonify({"error": "An account with that email already exists."}), 409
    updated = update_user_profile(
        app.instance_path,
        current_user.id,
        display_name=display_name,
        email=email,
    )
    if not updated:
        return jsonify({"error": "No profile changes submitted."}), 400
    profile = get_user_profile(app.instance_path, current_user.id)
    return jsonify({"ok": True, "profile": profile})


@app.route("/api/account/password", methods=["POST"])
@login_required
def api_account_update_password():
    """Update current account password."""
    data = request.get_json(force=True) or {}
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters."}), 400
    row = get_user_by_id(app.instance_path, current_user.id)
    if not row or not verify_password(row["password"], current_password):
        return jsonify({"error": "Current password is incorrect."}), 400
    ok = update_user_password(app.instance_path, current_user.id, new_password)
    if not ok:
        return jsonify({"error": "Failed to update password."}), 500
    return jsonify({"ok": True, "message": "Password updated successfully."})


@app.route("/api/account/avatar", methods=["POST"])
@login_required
def api_account_upload_avatar():
    """Upload and assign a profile avatar for the current user."""
    if "avatar" not in request.files:
        return jsonify({"error": "avatar file is required."}), 400
    f = request.files["avatar"]
    if not f or not f.filename:
        return jsonify({"error": "No file uploaded."}), 400

    filename = secure_filename(f.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".webp"}:
        return jsonify({"error": "Unsupported image type. Use png, jpg, jpeg, or webp."}), 400

    f.seek(0, io.SEEK_END)
    size = f.tell()
    f.seek(0)
    if size > 2 * 1024 * 1024:
        return jsonify({"error": "Avatar file size must be <= 2MB."}), 400

    avatars_dir = os.path.join(app.static_folder, "uploads", "avatars")
    os.makedirs(avatars_dir, exist_ok=True)
    stored_name = f"user_{current_user.id}_{secrets.token_hex(8)}{ext}"
    abs_path = os.path.join(avatars_dir, stored_name)
    f.save(abs_path)

    avatar_url = f"/static/uploads/avatars/{stored_name}"
    ok = update_user_avatar(app.instance_path, current_user.id, avatar_url)
    if not ok:
        return jsonify({"error": "Failed to save avatar reference."}), 500
    profile = get_user_profile(app.instance_path, current_user.id)
    return jsonify({"ok": True, "avatar_url": avatar_url, "profile": profile})


@app.route("/api/admin/users/<int:user_id>/role", methods=["PATCH"])
@login_required
def api_admin_update_role(user_id: int):
    """Update a user's role. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    data = request.get_json(force=True) or {}
    new_role = (data.get("role") or "").strip()
    if not new_role:
        return jsonify({"error": "role is required."}), 400
    ok = update_user_role(app.instance_path, user_id, new_role)
    if not ok:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"updated": True, "user_id": user_id, "role": new_role})


# ---------------------------------------------------------------------------
# Soft-delete management routes
# ---------------------------------------------------------------------------

@app.route("/api/admin/users/deleted", methods=["GET"])
@login_required
def api_admin_deleted_users():
    """List soft-deleted users. Super-admin only."""
    if not current_user.is_super_admin:
        return jsonify({"error": "Super-admin access required."}), 403
    users = list_deleted_users(app.instance_path)
    return jsonify({"users": users})


@app.route("/api/admin/users/<int:user_id>/restore", methods=["POST"])
@login_required
def api_admin_restore_user(user_id: int):
    """Restore a soft-deleted user. Super-admin only."""
    if not current_user.is_super_admin:
        return jsonify({"error": "Super-admin access required."}), 403
    ok = restore_user(app.instance_path, user_id)
    if not ok:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"restored": True, "user_id": user_id})


@app.route("/api/admin/runs/deleted", methods=["GET"])
@login_required
def api_admin_deleted_runs():
    """List soft-deleted analysis runs. Super-admin only."""
    if not current_user.is_super_admin:
        return jsonify({"error": "Super-admin access required."}), 403
    runs = list_deleted_runs(app.instance_path)
    return jsonify({"runs": runs})


@app.route("/api/admin/runs/<int:run_id>/delete", methods=["POST"])
@login_required
def api_admin_soft_delete_run(run_id: int):
    """Soft-delete an analysis run. Admin only."""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required."}), 403
    ok = soft_delete_run(app.instance_path, run_id, current_user.username)
    if not ok:
        return jsonify({"error": "Run not found."}), 404
    return jsonify({"deleted": True, "run_id": run_id})


@app.route("/api/admin/runs/<int:run_id>/restore", methods=["POST"])
@login_required
def api_admin_restore_run(run_id: int):
    """Restore a soft-deleted analysis run. Super-admin only."""
    if not current_user.is_super_admin:
        return jsonify({"error": "Super-admin access required."}), 403
    ok = restore_run(app.instance_path, run_id)
    if not ok:
        return jsonify({"error": "Run not found."}), 404
    return jsonify({"restored": True, "run_id": run_id})


@app.route("/verify-email/<token>")
def verify_email(token: str):
    """Email verification endpoint."""
    user_row = get_user_by_verification_token(app.instance_path, token)
    if not user_row:
        return render_template("verify_email.html", success=False,
                               message="Invalid or expired verification link."), 400
    mark_email_verified(app.instance_path, user_row["id"])
    return render_template("verify_email.html", success=True,
                           message="Email verified! Your account is awaiting admin approval.")


@app.route("/super-admin")
@login_required
def super_admin():
    """Super-admin dashboard."""
    if not current_user.is_super_admin:
        return render_template(
            "admin.html", forbidden=True, forbidden_page="admin", user=current_user
        ), 403
    user_count = count_users(app.instance_path)
    return render_template(
        "super_admin.html",
        user=current_user,
        user_count=user_count,
    )


@app.route("/admin/auditors")
@login_required
def admin_auditors():
    """Redirect to admin page with auditors tab."""
    if not current_user.is_admin:
        return redirect(url_for("login"))
    return redirect(url_for("admin") + "?tab=auditors")


@app.route("/admin/companies")
@login_required
def admin_companies():
    """Redirect to admin page with companies tab."""
    if not current_user.is_admin:
        return redirect(url_for("login"))
    return redirect(url_for("admin") + "?tab=companies")


# ---------------------------------------------------------------------------
# Socket.IO events
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    """Handle a new Socket.IO connection."""
    emit("connected", {"message": "Connected to LogGuard audit stream."})


@socketio.on("join_audit_room")
def on_join_audit_room(data):
    """Join the shared audit room for real-time analysis notifications."""
    join_room("audit_room")
    emit("joined", {"room": "audit_room"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
