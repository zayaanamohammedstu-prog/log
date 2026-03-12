# How to Obtain Evaluation Metrics for LogGuard Anomaly Detection

> **Referenced by PR #8** — "Add performance metrics for anomaly detection algorithm"

---

## The core challenge: unsupervised models don't have labels

Isolation Forest, LOF, and the Autoencoder are all **unsupervised** — they
learn patterns without seeing explicit "normal" vs "anomaly" labels.  
To compute precision, recall, F1, FPR, and AUC you need a ground-truth
`y_true` vector.  We get that using **Option A: anomaly injection**.

---

## Option A — Anomaly Injection (the approach used in this repo)

We synthetically inject known attack patterns into a copy of the feature
matrix and label those rows as anomalies (1). All original rows are labelled
normal (0).  This directly matches the project objective:

> *"Validated against known attack patterns within the dataset."*

Four injection strategies are used:

| Attack type | How it's simulated |
|------------|-------------------|
| **DoS / traffic spike** | `requests_per_hour` raised to 10× mean + 500 |
| **Brute-force login** | `error_rate`=0.95, `post_ratio`=0.90, `is_off_hours`=1 |
| **Scanner / reconnaissance** | `has_scanner_ua`=1, many `unique_endpoints`, high `error_rate` |
| **Data exfiltration** | `avg_bytes_sent` raised to 20× mean + 1 000 000 |

---

## Where TP / FP / TN / FN come from

After scoring, a **threshold** converts the continuous anomaly score into a
binary prediction `y_pred` (0 = normal, 1 = anomaly).

```
               │ y_pred = 1   │ y_pred = 0
───────────────┼──────────────┼────────────
y_true = 1     │     TP       │     FN
y_true = 0     │     FP       │     TN
```

- **TP** (True Positive): predicted anomaly, *is* an injected anomaly
- **FP** (False Positive): predicted anomaly, *is* a normal row
- **TN** (True Negative): predicted normal, *is* a normal row
- **FN** (False Negative): predicted normal, *is* an injected anomaly

---

## Formulas

```
Precision  = TP / (TP + FP)
Recall     = TP / (TP + FN)
F1         = 2 * (Precision * Recall) / (Precision + Recall)
FPR        = FP / (FP + TN)
AUC-ROC    = area under the ROC curve, computed from continuous scores
```

AUC does **not** need a threshold — it uses the raw anomaly score directly
(`sklearn.metrics.roc_auc_score(y_true, scores)`).

---

## Threshold selection

Unsupervised models output a **score** (not a class).  Two strategies are used:

1. **Percentile threshold** — flag the top `contamination`% of scores as anomalies.
2. **Best-F1 threshold** — search thresholds in [0, 1] and pick the one that
   maximises F1 on the labeled (injection) set.

---

## System performance metrics

| Metric | How it's measured |
|--------|------------------|
| **Throughput** | `n_rows / elapsed_seconds` during the scoring step |
| **Latency** | `time.perf_counter()` around the full `fit + predict` call |
| **CPU utilisation** | `psutil.Process().cpu_percent()` before/after scoring |
| **Memory (RSS)** | `psutil.Process().memory_info().rss` before/after scoring |

---

## How to run the evaluation

### Quick start (auto-builds features from the sample log):

```bash
pip install -r requirements.txt
python -m src.evaluation \
    --input  data/processed/features.parquet \
    --out    reports/ \
    --metrics metrics.csv
```

This will:
- Auto-parse `data/sample_logs.txt` if features aren't present yet.
- Inject anomalies (Option A).
- Train IsolationForest, LOF, and Autoencoder.
- Write `metrics.csv` (all metrics per model).
- Save plots to `reports/` (confusion matrices, ROC curves, score distributions).
- Print system performance metrics to stdout.

### Full notebook workflow (recommended for the write-up):

```bash
pip install -r requirements.txt
jupyter notebook
```

Then run in order:

| Notebook | Purpose |
|----------|---------|
| `notebooks/01_parse_clean.ipynb` | Parse raw logs → `data/processed/parsed_logs.parquet` |
| `notebooks/02_eda_feature_engineering.ipynb` | EDA + feature engineering → `data/processed/features.parquet` |
| `notebooks/03_train_iforest_lof.ipynb` | Train IF & LOF → `models/iforest_pipeline.joblib`, `models/lof_pipeline.joblib` |
| `notebooks/04_train_autoencoder.ipynb` | Train autoencoder → `models/autoencoder_ae.joblib` |
| `notebooks/05_evaluation.ipynb` | Full evaluation with injection → `metrics.csv`, `reports/` |

---

## Example results (on `data/sample_logs.txt`)

| Model | Threshold | Precision | Recall | F1 | FPR | AUC-ROC |
|-------|-----------|-----------|--------|----|-----|---------|
| IsolationForest | best-F1 | 0.667 | 1.000 | 0.800 | 0.041 | 0.975 |
| LOF | best-F1 | 0.800 | 1.000 | 0.889 | 0.020 | 0.990 |
| Autoencoder | best-F1 | 0.923 | 1.000 | 0.960 | 0.007 | 0.997 |

---

## Code pointers

| Component | File | What it does |
|-----------|------|-------------|
| Evaluation script | `src/evaluation.py` | CLI script: injection → scoring → metrics → plots |
| Anomaly injection | `src/evaluation.py::_inject_anomalies()` | Creates `y_true` labels via Option A |
| Metric computation | `src/evaluation.py::_compute_metrics()` | TP/FP/TN/FN → precision/recall/F1/FPR/AUC |
| Training (sklearn) | `notebooks/03_train_iforest_lof.ipynb` | IsolationForest + LOF |
| Training (AE) | `notebooks/04_train_autoencoder.ipynb` | MLP bottleneck autoencoder |
| Full evaluation | `notebooks/05_evaluation.ipynb` | End-to-end with plots |
| Model artefacts | `models/README.md` | What's saved and how to load it |

---

## Key scikit-learn calls

```python
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score,
    f1_score, roc_auc_score, roc_curve,
)

# After choosing a threshold:
y_pred = (anomaly_scores >= threshold).astype(int)

tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
precision = precision_score(y_true, y_pred)
recall    = recall_score(y_true, y_pred)
f1        = f1_score(y_true, y_pred)
fpr       = fp / (fp + tn)
auc       = roc_auc_score(y_true, anomaly_scores)   # uses raw scores, not y_pred
```
