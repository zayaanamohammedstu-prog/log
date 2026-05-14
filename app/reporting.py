"""
app/reporting.py
----------------
Generates HTML and PDF reports for an analysis run.
"""

from __future__ import annotations

import html
import io
import json
import textwrap

# Keep report risk labels aligned with UI copy:
# Critical risk is classified at ensemble/anomaly score >= 0.85.
_CRITICAL_THRESHOLD = 0.85


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
    critical_count = sum(
        1
        for r in results
        if (r.get("ensemble_score") or r.get("anomaly_score") or 0.0) >= _CRITICAL_THRESHOLD
    )
    chain_count = len(chains)

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
  <title>LogGuard Analysis Report &ndash; Run {run_id}</title>
  <style>
    :root {{
      --bg: #f6f8fc;
      --text: #1f2937;
      --muted: #64748b;
      --brand: #1d4ed8;
      --danger: #dc2626;
      --surface: #ffffff;
      --line: #e5e7eb;
    }}
    body {{
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      color: var(--text);
      background: var(--bg);
      line-height: 1.45;
    }}
    .shell {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    .hero {{
      background: linear-gradient(135deg, #0f172a, #1e3a8a);
      color: #fff;
      padding: 24px;
      border-radius: 16px;
      box-shadow: 0 10px 30px rgba(15, 23, 42, 0.25);
      margin-bottom: 20px;
    }}
    .hero h1 {{ margin: 0 0 8px; font-size: 1.65rem; }}
    .hero p {{ margin: 0; color: rgba(255,255,255,0.9); }}
    h2 {{
      color: #0f172a;
      margin: 1.2rem 0 .6rem;
      font-size: 1.1rem;
      border-bottom: 1px solid var(--line);
      padding-bottom: 6px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin: 12px 0;
    }}
    .stat-box {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
      min-height: 92px;
    }}
    .stat-box .label {{ font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
    .stat-box .value {{ font-size: 1.55rem; font-weight: 700; color: var(--brand); margin-top: 2px; }}
    .risk-band {{
      display: flex; gap: 8px; margin-top: 8px; font-size: .82rem;
    }}
    .risk-pill {{
      padding: 4px 10px; border-radius: 999px; font-weight: 600;
    }}
    .pill-critical {{ color: #7f1d1d; background: #fee2e2; }}
    .pill-high {{ color: #78350f; background: #ffedd5; }}
    .pill-normal {{ color: #065f46; background: #d1fae5; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: .7em; background: #fff; border-radius: 10px; overflow: hidden; }}
    th, td {{ border: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; font-size: .9rem; }}
    th {{ background: #0f172a; color: #fff; font-weight: 600; }}
    tr:nth-child(even) {{ background: #f8fafc; }}
    ul {{ list-style: disc; padding-left: 1.2em; }}
    .card {{ background: #fff; border: 1px solid var(--line); border-radius: 12px; padding: 14px; }}
    .footer {{ margin-top: 1.25em; font-size: .78em; color: #94a3b8; border-top: 1px solid var(--line); padding-top: .5em; }}
  </style>
</head>
<body>
  <div class="shell">
  <div class="hero">
    <h1>&#x1F6E1; LogGuard Executive Audit Dashboard</h1>
    <p><strong>Run ID:</strong> {run_id} &nbsp;&middot;&nbsp; <strong>Analyst:</strong> {username} &nbsp;&middot;&nbsp; <strong>Timestamp:</strong> {html.escape(ts)}</p>
  </div>

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
    <div class="stat-box">
      <div class="label">Critical Risk</div>
      <div class="value">{critical_count}</div>
    </div>
    <div class="stat-box">
      <div class="label">Attack Chains</div>
      <div class="value">{chain_count}</div>
    </div>
  </div>
  <div class="risk-band">
    <span class="risk-pill pill-critical">Critical: score ≥ 0.85</span>
    <span class="risk-pill pill-high">High: score 0.70–0.84</span>
    <span class="risk-pill pill-normal">Normal: score &lt; 0.70</span>
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
  <div class="card">
  <ul>
{chains_html}  </ul>
  </div>

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
  </div>
</body>
</html>"""


def generate_pdf_report(
    run: dict,
    results: list[dict],
    chains: list[dict],
) -> bytes:
    """
    Generate a PDF report for an analysis run and return it as bytes.

    Uses fpdf2 to build a structured, printable PDF from the same data
    as the HTML report.

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
    bytes
        PDF document as raw bytes.
    """
    from fpdf import FPDF  # imported lazily so the app starts without fpdf2

    def _safe(text: str) -> str:
        """Strip characters outside latin-1 to avoid FPDF encoding errors."""
        return text.encode("latin-1", errors="replace").decode("latin-1")

    total = len(results)
    anomaly_count = sum(1 for r in results if r.get("is_anomaly"))
    normal_count = total - anomaly_count
    anomaly_rate = round(anomaly_count / total * 100, 2) if total > 0 else 0.0
    critical_count = sum(
        1
        for r in results
        if (r.get("ensemble_score") or r.get("anomaly_score") or 0.0) >= _CRITICAL_THRESHOLD
    )
    chain_count = len(chains)

    anomalies = [r for r in results if r.get("is_anomaly")]
    anomalies_sorted = sorted(
        anomalies,
        key=lambda r: r.get("ensemble_score") or r.get("anomaly_score") or 0.0,
        reverse=True,
    )[:20]

    run_id = run.get("id", "N/A")
    ts = _safe(str(run.get("timestamp", "N/A")))
    username = _safe(str(run.get("username", "N/A")))
    year = ts[:4] if ts and ts != "N/A" else "2024"

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Title ────────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(192, 57, 43)
    pdf.cell(0, 10, "LogGuard Anomaly Detection Report", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, _safe(f"Run {run_id}  |  Analyst: {username}  |  {ts}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # ── Executive summary ────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(220, 220, 220)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 180, pdf.get_y())
    pdf.ln(4)

    # Stat boxes (6 columns)
    col_w = 29
    stats = [
        ("RUN", str(run_id)),
        ("ANALYST", username),
        ("BUCKETS", str(total)),
        ("ANOM", str(anomaly_count)),
        ("CRIT", str(critical_count)),
        ("RATE", f"{anomaly_rate}%"),
    ]
    for label, value in stats:
        pdf.set_fill_color(236, 240, 241)
        pdf.rect(pdf.get_x(), pdf.get_y(), col_w - 2, 18, style="F")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(127, 140, 141)
        pdf.set_xy(pdf.get_x(), pdf.get_y() + 2)
        pdf.cell(col_w - 2, 5, _safe(label.upper()), align="C")
        pdf.set_xy(pdf.get_x() - (col_w - 2), pdf.get_y() + 5)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(231, 76, 60)
        pdf.cell(col_w - 2, 8, _safe(str(value)), align="C", new_x="RIGHT", new_y="TOP")
    pdf.ln(26)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(80, 80, 80)
    summary_line = (
        f"Timestamp: {ts} | Normal: {normal_count} | Attack chains: {chain_count}"
    )
    pdf.multi_cell(0, 6, _safe(summary_line))
    pdf.ln(2)

    # ── Top anomalies table ──────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 8, "Top Anomalies", new_x="LMARGIN", new_y="NEXT")
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 180, pdf.get_y())
    pdf.ln(4)

    # Table header
    headers = ["IP", "Hour", "Score", "Reason"]
    col_widths = [38, 34, 22, 86]
    pdf.set_fill_color(44, 62, 80)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    for w, h in zip(col_widths, headers):
        pdf.cell(w, 7, h, border=1, fill=True)
    pdf.ln()

    pdf.set_font("Helvetica", "", 7)
    fill = False
    # Keep the PDF compact and readable on small screens by showing top 12 only.
    for r in anomalies_sorted[:12]:
        ip = str(r.get("ip_address", ""))
        hb = str(r.get("hour_bucket", ""))
        score = r.get("ensemble_score") or r.get("anomaly_score") or 0.0
        if hasattr(score, "item"):
            score = float(score)
        score_str = f"{score:.4f}"

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

        # Wrap reasons text to fit column and sanitise for latin-1
        wrapped = _safe(textwrap.shorten(reasons_text, width=70, placeholder="..."))

        fill_color = (249, 249, 249) if fill else (255, 255, 255)
        pdf.set_fill_color(*fill_color)
        pdf.set_text_color(51, 51, 51)
        pdf.cell(col_widths[0], 6, _safe(ip), border=1, fill=True)
        pdf.cell(col_widths[1], 6, _safe(hb), border=1, fill=True)
        pdf.cell(col_widths[2], 6, score_str, border=1, fill=True)
        pdf.cell(col_widths[3], 6, wrapped, border=1, fill=True)
        pdf.ln()
        fill = not fill

    if not anomalies_sorted:
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 7, "No anomalies detected.", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # ── Attack chains ────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 8, "Attack Chains", new_x="LMARGIN", new_y="NEXT")
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 180, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(51, 51, 51)
    if chains:
        for chain in chains[:5]:
            severity = _safe(str(chain.get("severity", "")))
            narrative = _safe(str(chain.get("narrative", "")))
            line = f"[{severity}] {textwrap.shorten(narrative, width=100, placeholder='...')}"
            for chunk in textwrap.wrap(line, width=110) or [line]:
                pdf.cell(0, 6, chunk, new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, "No attack chains detected.", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(170, 170, 170)
    pdf.cell(0, 6, f"Generated by LogGuard (c) {year}", new_x="LMARGIN", new_y="NEXT")

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()
