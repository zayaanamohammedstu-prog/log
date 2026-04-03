# LogGuard — Data-Driven IT Audit System for Anomaly Detection

LogGuard is a full-stack, Python-based prototype that uses **unsupervised machine
learning** (Isolation Forest) to analyse Apache / CLF server logs, detect
anomalous behaviour, and present a prioritised risk dashboard to IT auditors.

---

## Features

| Layer | Technology |
|---|---|
| Log parsing | Python + RegEx (Apache CLF / Combined Log Format) |
| Feature engineering | Pandas — per-IP/hour aggregations |
| Anomaly detection | Scikit-learn **Isolation Forest** (+ StandardScaler) |
| Backend API | **Flask** REST API |
| Authentication | **Flask-Login** + session-based auth, SQLite user store |
| Frontend | HTML / CSS / **Chart.js** — Audit Workbench shell |
| Tests | **pytest** (59 unit + integration tests) |

Detected anomaly patterns include:
- High-volume brute-force login attempts
- Off-hours activity from unusual IPs
- Known scanner / reconnaissance user-agents (Nikto, SQLMap, etc.)
- Bulk data exfiltration (unusually large response bytes)

---

## Project Structure

```
logguard/
├── app/
│   ├── app.py                 # Flask application & REST API
│   ├── db.py                  # SQLite data access layer (user CRUD)
│   ├── models.py              # Flask-Login User model
│   ├── templates/
│   │   ├── index.html         # Audit Workbench dashboard shell
│   │   ├── login.html         # Login page
│   │   └── admin.html         # Admin page
│   └── static/
│       ├── css/style.css
│       └── js/dashboard.js
├── pipeline/
│   ├── log_parser.py          # Apache CLF parser
│   └── feature_engineering.py # Feature extraction
├── model/
│   └── anomaly_detector.py    # Isolation Forest wrapper
├── data/
│   └── sample_logs.txt        # Synthetic demo log dataset (760 entries)
├── tests/
│   ├── test_parser.py
│   ├── test_features.py
│   ├── test_model.py
│   ├── test_app.py
│   └── test_auth.py           # Authentication & authorisation tests
└── requirements.txt
```

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/zayaanamohammedstu-prog/log.git
cd log
pip install -r requirements.txt
```

### 2. Set up the first admin account

**Option A — Self-service registration (easiest for local dev)**

When no users exist yet, the `/register` page is automatically enabled.
Simply start the server and open `http://localhost:5000/register` in your browser.
The first account you create will automatically receive the **admin** role.

You can also enable public signup at any time by setting:

```bash
export LOGGUARD_ENABLE_PUBLIC_SIGNUP=true
```

> **Windows (PowerShell):**
> ```powershell
> $env:LOGGUARD_ENABLE_PUBLIC_SIGNUP="true"
> ```

**Option B — Bootstrap via environment variables**

Set these **before** starting the server:

```bash
export LOGGUARD_ADMIN_USERNAME=admin
export LOGGUARD_ADMIN_PASSWORD=your-strong-password
export LOGGUARD_SECRET_KEY=your-random-secret-key   # required in production
```

> **Windows (PowerShell):**
> ```powershell
> $env:LOGGUARD_ADMIN_USERNAME="admin"
> $env:LOGGUARD_ADMIN_PASSWORD="your-strong-password"
> $env:LOGGUARD_SECRET_KEY="your-random-secret-key"
> ```

If these variables are not set when no users exist, the app starts but logs a
warning and the login page shows a setup notice — no user will be created.

**Admin recovery (locked out? no admin exists?)**

If you already have users in the database but no admin account (e.g., the
original admin was deleted), set `LOGGUARD_ADMIN_USERNAME` and
`LOGGUARD_ADMIN_PASSWORD` and restart the server.  LogGuard will
automatically **promote** an existing user with that name to admin, or
**create** a new admin account if the username doesn't exist yet. This is safe
and idempotent: it only runs when there is no existing admin.

### 3. Run the application

```bash
python -m flask --app app/app.py run
# Open http://localhost:5000 in your browser
```

You will be redirected to the login page. Sign in with the credentials you set
in step 2.

### 4. Analyse logs

- Click **"Analyse sample logs"** to run the bundled 760-entry demo dataset.
- Or click **"Choose File"** / drag-and-drop to upload your own Apache CLF log.

---

## Authentication

| Environment Variable | Description |
|---|---|
| `LOGGUARD_ADMIN_USERNAME` | Username for the bootstrap admin account |
| `LOGGUARD_ADMIN_PASSWORD` | Password for the bootstrap admin account (hashed with Werkzeug) |
| `LOGGUARD_SECRET_KEY` | Flask session secret key (use a long random string in production) |
| `LOGGUARD_ENABLE_PUBLIC_SIGNUP` | Set to `true` to allow anyone to self-register an account |

- The SQLite database (`logguard.db`) is stored in Flask's `instance/` folder and is excluded from version control.
- Passwords are never stored in plaintext — Werkzeug's `pbkdf2:sha256` is used.
- Roles: `admin`, `administrator`, `auditor`. Both `admin` and `administrator` have full admin privileges and can access both the Admin Portal and the Auditor Portal. The `/admin` page and user-management API endpoints are restricted to `admin`/`administrator` roles only.

---

## API Endpoints

All API endpoints require authentication. Unauthenticated requests receive a
JSON `401` response (not an HTML redirect).

### Core endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Audit Workbench dashboard (login required) |
| `GET/POST` | `/login` | Login page / authenticate |
| `GET/POST` | `/logout` | End session |
| `GET` | `/admin` | Admin panel (admin role required) |
| `GET` | `/api/status` | Health-check + model status |
| `POST` | `/api/analyze` | Analyse log data; returns JSON results + `run_id` |
| `GET` | `/api/results` | Return cached results from last analysis |
| `GET` | `/api/export/csv` | Export last results as CSV |
| `GET` | `/api/export/json` | Export last results as JSON |

**POST `/api/analyze`** accepts:
- `multipart/form-data` with field `logfile` (file upload)
- `application/json` with `{"log_text": "…"}` (raw log string)
- `application/json` with `{"use_sample": true}` (bundled demo data)

Response now includes `run_id`, `chains`, and per-row `explanations_json`.

### Analysis run persistence

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/runs` | List all analysis runs (newest first) |
| `GET` | `/api/runs/<run_id>` | Get run metadata + all result rows |
| `GET` | `/api/runs/<run_id>/anomalies/<anomaly_id>` | Single anomaly row detail |
| `GET` | `/api/runs/<run_id>/ips/<ip>/timeline` | All rows for a specific IP in a run |
| `GET` | `/api/runs/<run_id>/chains` | List attack chains for a run |
| `GET` | `/api/runs/<run_id>/chains/<chain_id>` | Single attack chain detail |
| `GET` | `/api/runs/<run_id>/report` | Download HTML audit report |
| `GET` | `/api/runs/<run_id>/report/pdf` | Download PDF audit report |
| `POST` | `/api/runs/<run_id>/send/email` | Send PDF report via email (JSON body: `{"to": "user@example.com"}`) |
| `POST` | `/api/runs/<run_id>/send/whatsapp` | Send PDF report via WhatsApp (JSON body: `{"to": "+447911123456"}`) |

### Audit ledger (admin only)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/audit/verify` | Verify tamper-evident ledger integrity |
| `GET` | `/api/audit/entries` | List all ledger entries |

---

## XAI & Advanced Features

### Multi-Model Ensemble (PR3)
Each analysis runs **three detectors** and produces a majority-vote result:
- **Isolation Forest** — tree-based anomaly scoring
- **LOF** (Local Outlier Factor) — density-based local anomaly detection
- **One-Class SVM** — boundary-based novelty detection

Per-model scores, per-model flags, ensemble score, and agreement percentage
are returned in each result row.

### Behavioral Baselines (PR2)
Global (per-hour-of-day) and per-IP baselines are computed from each dataset.
Three baseline-adjusted features are added to every row:
- `requests_vs_expected` — ratio of actual vs expected requests for that hour
- `bytes_vs_expected` — ratio of actual vs expected bytes for that hour
- `error_rate_delta` — deviation from expected error rate for that hour

### XAI Explanations (PR4)
Each anomalous row receives an `explanations_json` field containing:
- **Reason codes** — rule-based flags: `SCANNER_UA`, `VOLUME_SPIKE`, `OFF_HOURS`,
  `HIGH_ERROR_RATE`, `BYTES_SPIKE`, `OFF_HOURS_COMBINED`
- **Feature deviations** — z-score and percentile vs global mean for each feature

### Attack Chain Reconstruction (PR5)
Anomalies are grouped into **attack chains** by IP address and time adjacency
(configurable gap, default 2 hours). Each chain has a severity rating
(Critical/High/Medium) and a human-readable narrative.

### Interactive Drill-Down Dashboard (PR6)
Click any row in the Anomaly Explorer table to open a drill-down panel showing:
- Reason codes and feature deviations
- Per-model score bars
- Chain membership
- Raw feature values

### Automated HTML Report (PR7)
`GET /api/runs/<run_id>/report` returns an auditor-friendly HTML report with:
- Executive summary and statistics
- Top anomalies table with explanations
- Attack chains narrative
- Model settings appendix

### PDF Report & Sharing (PR-SHARE)
LogGuard can generate a structured PDF report and send it directly to colleagues via email or WhatsApp.

#### PDF download
`GET /api/runs/<run_id>/report/pdf` generates and downloads a PDF report.
The **"📥 Download PDF"** button in the *Export & Visualise* tab does this automatically.

#### Send via Email
`POST /api/runs/<run_id>/send/email` with body `{"to": "recipient@example.com"}` sends the PDF report as an email attachment via SMTP.

Set the following environment variables before starting the server:

```bash
export LOGGUARD_SMTP_HOST=smtp.gmail.com          # SMTP server hostname
export LOGGUARD_SMTP_PORT=587                     # SMTP port (default 587)
export LOGGUARD_SMTP_USER=you@gmail.com           # SMTP username / sender
export LOGGUARD_SMTP_PASSWORD=your-app-password   # SMTP password or App Password
export LOGGUARD_SMTP_FROM=you@gmail.com           # From address (defaults to SMTP_USER)
```

> **Gmail tip:** Use an [App Password](https://support.google.com/accounts/answer/185833) rather than your account password.

#### Send via WhatsApp (Meta WhatsApp Business Cloud API)
`POST /api/runs/<run_id>/send/whatsapp` with body `{"to": "+447911123456"}` sends the PDF report via the [Meta WhatsApp Business Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api).

Set the following environment variables before starting the server:

```bash
export WHATSAPP_PHONE_NUMBER_ID=your_phone_number_id   # Phone Number ID from Meta dashboard (WhatsApp > API Setup)
export WHATSAPP_ACCESS_TOKEN=your_access_token         # Permanent / long-lived access token from Meta dashboard
export LOGGUARD_PUBLIC_URL=https://yourapp.example.com # Public URL the Cloud API uses to fetch the PDF
```

> **Setup guide:**
> 1. Create a [Meta Developer](https://developers.facebook.com/) account and add the **WhatsApp** product to your app.
> 2. Under *WhatsApp > API Setup* copy your **Phone Number ID** and generate a **permanent access token**.
> 3. Register your recipient numbers in the Meta sandbox (for testing) or obtain a verified WhatsApp Business number for production.
> 4. The Meta API fetches the PDF directly from `LOGGUARD_PUBLIC_URL`, so the server must be publicly accessible.
>    For local development use a tunnelling tool such as [ngrok](https://ngrok.com/): `ngrok http 5000`.

**Optional:**

```bash
export WHATSAPP_API_VERSION=v19.0  # Graph API version (default: v19.0)
```

### Tamper-Evident Audit Ledger (PR8)
Every analysis run appends a SHA-256 hash-chain entry to the ledger.
Each entry records: `prev_hash`, `timestamp`, `actor`, `input_hash`,
`results_hash`, and `entry_hash`. Admins can verify integrity via
`GET /api/audit/verify`.

---

## Running Tests

```bash
pytest tests/ -v
```

All 138 tests should pass.

---

## Model Details

The anomaly detection pipeline:

1. **Parse** raw log lines with a RegEx pattern matching Apache CLF.
2. **Aggregate** per `(ip_address, hour_bucket)` into 8 features:
   - `requests_per_hour`, `error_rate`, `unique_endpoints`, `avg_bytes_sent`
   - `post_ratio`, `is_off_hours`, `is_weekend`, `has_scanner_ua`
3. **Scale** features with `StandardScaler`.
4. **Detect** anomalies with `IsolationForest(contamination=0.05)`.
5. **Score** each bucket with a normalised anomaly score in \[0, 1\].

The trained model is serialised to `model/logguard_model.pkl` after the first
run and reused on subsequent requests.

---

## Demo Results (sample dataset)

```
Total requests : 760
IP/hour buckets: 159
Anomalies      : 8  (5.03 %)

Top anomalies
  1. 45.33.32.156   score=1.000  (Nikto scanner, 80 req/hr)
  2. 192.168.99.1   score=0.973  (Brute-force login, off-hours, 150 req/hr)
  3. 172.16.0.55    score=0.960  (Data exfiltration, off-hours, 30 req/hr)
```