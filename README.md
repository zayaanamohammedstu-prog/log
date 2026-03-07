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

On the first run, LogGuard creates the admin user from environment variables.
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

- The SQLite database (`logguard.db`) is stored in Flask's `instance/` folder and is excluded from version control.
- Passwords are never stored in plaintext — Werkzeug's `pbkdf2:sha256` is used.
- Roles: `admin`, `auditor`, `viewer`. The `/admin` page is restricted to `admin` role only.

---

## API Endpoints

All API endpoints require authentication. Unauthenticated requests receive a
JSON `401` response (not an HTML redirect).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Audit Workbench dashboard (login required) |
| `GET` | `POST` `/login` | Login page / authenticate |
| `GET` | `POST` `/logout` | End session |
| `GET` | `/admin` | Admin panel (admin role required) |
| `GET` | `/api/status` | Health-check + model status |
| `POST` | `/api/analyze` | Analyse log data; returns JSON results |
| `GET` | `/api/results` | Return cached results from last analysis |

**POST `/api/analyze`** accepts:
- `multipart/form-data` with field `logfile` (file upload)
- `application/json` with `{"log_text": "…"}` (raw log string)
- `application/json` with `{"use_sample": true}` (bundled demo data)

---

## Running Tests

```bash
pytest tests/ -v
```

All 59 tests should pass.

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