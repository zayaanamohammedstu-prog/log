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
| Frontend | HTML / CSS / **Chart.js** dashboard |
| Tests | **pytest** (45 unit + integration tests) |

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
│   ├── templates/index.html   # Dashboard (HTML/CSS/JS)
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
│   └── test_app.py
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

### 2. Run the application

```bash
python -m flask --app app/app.py run
# Open http://localhost:5000 in your browser
```

### 3. Analyse logs

- Click **"Analyse sample logs"** to run the bundled 760-entry demo dataset.
- Or click **"Choose File"** / drag-and-drop to upload your own Apache CLF log.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard UI |
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

All 45 tests should pass.

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