"""
app/reporting.py
----------------
Generates an HTML report for an analysis run.
"""

from __future__ import annotations

import html
import json


def generate_html_report(
    run: dict,
    results: list[dict],
    chains: list[dict],
) -> str:
    """
    Generate a self-contained HTML report string.

    Includes:
    - Executive summary (total buckets, anomaly count, rate)
    - Top anomalies table with explanation reasons
    - Attack chains narrative
    - Appendix with model settings

    Parameters
    ----------
    run : dict
        Run metadata from ``get_run``.
    results : list[dict]
        Per-row result records from ``get_run_results``.
    chains : list[dict]
        Attack chain records from ``get_chains``.

    Returns
    -------
    str
        HTML document as a string.
    """
    total = len(results)
    anomaly_count = sum(1 for r in results if r.get("is_anomaly"))
    normal_count = total - anomaly_count
    anomaly_rate = round(anomaly_count / total * 100, 2) if total > 0 else 0.0

    # Sort anomalies by score descending, take top 20
    anomalies = [r for r in results if r.get("is_anomaly")]
    anomalies_sorted = sorted(
        anomalies,
        key=lambda r: r.get("ensemble_score") or r.get("anomaly_score") or 0.0,
        reverse=True,
    )[:20]

    # ── Top anomalies table rows ─────────────────────────────────────────────
    anomaly_rows_html = ""
    for r in anomalies_sorted:
        ip = html.escape(str(r.get("ip_address", "")))
        hb = html.escape(str(r.get("hour_bucket", "")))
        score = r.get("ensemble_score") or r.get("anomaly_score") or 0.0
        if hasattr(score, "item"):
            score = float(score)

        reasons_text = "N/A"
        raw_exp = r.get("explanations_json") or r.get("explanations") or "{}"
        try:
            if isinstance(raw_exp, str):
                exp = json.loads(raw_exp)
            else:
                exp = raw_exp if isinstance(raw_exp, dict) else {}
            reasons_text = "; ".join(desc for _, desc in exp.get("reasons", [])) or "N/A"
        except Exception:
            pass

        anomaly_rows_html += (
            f"<tr>"
            f"<td>{ip}</td>"
            f"<td>{hb}</td>"
            f"<td>{score:.4f}</td>"
            f"<td>{html.escape(reasons_text)}</td>"
            f"</tr>\n"
        )

    # ── Attack chains list items ─────────────────────────────────────────────
    chains_html = ""
    for chain in chains:
        severity = html.escape(str(chain.get("severity", "")))
        narrative = html.escape(str(chain.get("narrative", "")))
        chains_html += f"<li><strong>[{severity}]</strong> {narrative}</li>\n"

    if not chains_html:
        chains_html = "<li>No attack chains detected.</li>\n"

    run_id = run.get("id", "N/A")
    ts = str(run.get("timestamp", "N/A"))
    username = html.escape(str(run.get("username", "N/A")))
    year = ts[:4] if ts and ts != "N/A" else "2024"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>LogGuard Analysis Report &ndash; Run #{run_id}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 2em; color: #333; background: #fff;
    }}
    h1 {{ color: #c0392b; margin-bottom: 0.2em; }}
    h2 {{
      color: #2c3e50; border-bottom: 2px solid #ecf0f1;
      padding-bottom: 4px; margin-top: 1.5em;
    }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #2c3e50; color: #fff; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
    .stats {{ display: flex; gap: 1em; flex-wrap: wrap; margin: 1em 0; }}
    .stat-box {{
      padding: 1em 1.5em; background: #ecf0f1; border-radius: 6px;
      min-width: 120px; text-align: center;
    }}
    .stat-box .label {{ font-size: 0.8em; color: #7f8c8d; text-transform: uppercase; }}
    .stat-box .value {{ font-size: 2em; font-weight: bold; color: #e74c3c; }}
    ul {{ list-style: disc; padding-left: 1.5em; }}
    .footer {{ margin-top: 2em; font-size: 0.8em; color: #aaa; border-top: 1px solid #eee; padding-top: 0.5em; }}
  </style>
</head>
<body>
  <h1>&#x1F6E1; LogGuard Anomaly Detection Report</h1>
  <p>
    <strong>Run ID:</strong> #{run_id} &nbsp;&mdash;&nbsp;
    <strong>Analyst:</strong> {username} &nbsp;&mdash;&nbsp;
    <strong>Timestamp:</strong> {html.escape(ts)}
  </p>

  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="stat-box">
      <div class="label">Total Buckets</div>
      <div class="value">{total}</div>
    </div>
    <div class="stat-box">
      <div class="label">Anomalies</div>
      <div class="value">{anomaly_count}</div>
    </div>
    <div class="stat-box">
      <div class="label">Normal</div>
      <div class="value">{normal_count}</div>
    </div>
    <div class="stat-box">
      <div class="label">Anomaly Rate</div>
      <div class="value">{anomaly_rate}%</div>
    </div>
  </div>

  <h2>Top Anomalies</h2>
  <table>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Hour Bucket</th>
        <th>Score</th>
        <th>Reasons</th>
      </tr>
    </thead>
    <tbody>
{anomaly_rows_html}    </tbody>
  </table>

  <h2>Attack Chains</h2>
  <ul>
{chains_html}  </ul>

  <h2>Appendix &ndash; Model Settings</h2>
  <p>
    <strong>Ensemble:</strong> IsolationForest + LocalOutlierFactor + OneClassSVM
    (majority vote, contamination=0.05).
  </p>
  <p>
    Per-model scores are normalised to [0,&nbsp;1]; the
    <code>ensemble_score</code> is the arithmetic mean across all three models.
    A row is flagged as anomalous when at least 2 of 3 models vote positive.
  </p>

  <div class="footer">
    Generated by LogGuard &copy; {year}
  </div>
</body>
</html>"""
