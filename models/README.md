# models/

This directory stores trained model artefacts produced by the LogGuard training
notebooks.  The files here are **not committed** to git (they are generated at
runtime); this README explains what each file is, how it is produced, and how
to load it.

---

## Files

| File | Produced by | Description |
|------|-------------|-------------|
| `iforest_pipeline.joblib` | `notebooks/03_train_iforest_lof.ipynb` | Scikit-learn `Pipeline` containing a `StandardScaler` + `IsolationForest`. |
| `lof_pipeline.joblib` | `notebooks/03_train_iforest_lof.ipynb` | Scikit-learn `Pipeline` containing a `StandardScaler` + `LocalOutlierFactor` (novelty=True). |
| `scaler.joblib` | `notebooks/03_train_iforest_lof.ipynb` | Standalone `StandardScaler` fitted on the clean training split. Used as a shared preprocessing step. |
| `autoencoder_ae.joblib` | `notebooks/04_train_autoencoder.ipynb` | Fitted `MLPRegressor` autoencoder (bottleneck architecture). |
| `autoencoder_scaler.joblib` | `notebooks/04_train_autoencoder.ipynb` | `StandardScaler` fitted on the same training split as the autoencoder. |
| `thresholds.json` | `notebooks/05_evaluation.ipynb` | Best-F1 thresholds per model, stored as `{"IsolationForest": 0.42, "LOF": 0.38, "Autoencoder": 0.51}`. |

---

## How to reproduce

### Option 1 — Run all notebooks in order

```bash
pip install -r requirements.txt
jupyter notebook  # open and run 01 → 05 in the notebooks/ folder
```

### Option 2 — Run the evaluation script directly (auto-generates features)

```bash
pip install -r requirements.txt

# (optional) run full pipeline to produce data/processed/features.parquet first:
python - <<'EOF'
import sys; sys.path.insert(0, ".")
from pipeline.log_parser import parse_log_file
from pipeline.feature_engineering import engineer_features
import pathlib, pandas as pd

feat = engineer_features(parse_log_file("data/sample_logs.txt"))
pathlib.Path("data/processed").mkdir(parents=True, exist_ok=True)
feat.to_parquet("data/processed/features.parquet", index=False)
print("Features saved.")
EOF

# Then run the evaluation:
python -m src.evaluation \
    --input  data/processed/features.parquet \
    --out    reports/ \
    --metrics metrics.csv
```

The evaluation script trains its own instances of each model on-the-fly (it
does **not** require pre-saved model files).  Saved model artefacts from the
notebooks are intended for loading into the Flask API (see below).

---

## Loading models in the Flask API

### IsolationForest / LOF

```python
import joblib

pipeline = joblib.load("models/iforest_pipeline.joblib")
# pipeline is a sklearn Pipeline with steps 'scaler' and 'iforest'/'lof'

# Predict on new feature matrix X (numpy array, shape n_samples × 8)
labels = pipeline.predict(X)       # +1 = normal, -1 = anomaly
scores = pipeline.decision_function(X)  # higher = more normal
```

### Autoencoder

```python
import joblib, numpy as np

ae     = joblib.load("models/autoencoder_ae.joblib")
scaler = joblib.load("models/autoencoder_scaler.joblib")

X_scaled = scaler.transform(X)
recon    = ae.predict(X_scaled)
errors   = np.mean((X_scaled - recon) ** 2, axis=1)   # reconstruction error
```

### Thresholds

```python
import json

with open("models/thresholds.json") as f:
    thresholds = json.load(f)

# e.g.  thresholds["IsolationForest"]  → float decision boundary
```

---

## Feature columns (input schema)

All models expect the following **8 numerical features** in this exact order:

| # | Column | Description |
|---|--------|-------------|
| 0 | `requests_per_hour` | Total requests from this IP in the hour window |
| 1 | `error_rate` | Fraction of 4xx/5xx responses |
| 2 | `unique_endpoints` | Distinct endpoints accessed |
| 3 | `avg_bytes_sent` | Mean response size (bytes) |
| 4 | `post_ratio` | Fraction of POST requests |
| 5 | `is_off_hours` | 1 if hour ∈ [22:00–06:00), else 0 |
| 6 | `is_weekend` | 1 if Saturday or Sunday |
| 7 | `has_scanner_ua` | 1 if any scanner/bot user-agent was detected |

These are produced by `pipeline/feature_engineering.py → engineer_features()`.
