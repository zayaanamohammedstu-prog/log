# LogGuard Roadmap & Contributor Guide

## Roles and flows
- **auditor**: `/auditor` → upload/analyze logs, review anomalies, export reports, view own upload history.
- **admin / administrator**: `/admin` + `/auditor` → manage users, approvals, ledger, all runs.
- **super_admin**: `/super-admin` + admin/auditor access → platform-wide account governance.
- **viewer**: `/viewer` → read-only dashboards and history.

## Core API endpoints
- Auth/session: `/login`, `/logout`, `/register`
- Analysis: `POST /api/analyze`, `GET /api/results`, `GET /api/status`
- Runs: `GET /api/runs`, `GET /api/runs/<id>`, `GET /api/runs/<id>/summary`
- Reports: `GET /api/runs/<id>/report`, `GET /api/runs/<id>/report/pdf`
- Feedback: `POST /api/feedback`, `GET /api/feedback/counts`
- Admin: `/api/admin/*`, `/api/audit/verify`, `/api/audit/entries`

## UI structure
- `app/templates/main.html`: public landing page (signup/login CTA, guide entry point).
- `app/templates/index.html`: auditor workbench (tabs, history, exports, guide tab).
- `app/templates/admin.html`: admin portal and user operations.
- `app/templates/super_admin.html`: super admin operations.
- `app/static/js/dashboard.js`: auditor dashboard behavior and history/export logic.
- `app/static/css/style.css`: shared workbench/viewer styles.

## Where to edit key features
- Registration and role routing: `app/app.py`, `app/templates/register.html`, `app/templates/login.html`
- Run privacy and access control: `app/app.py` (`/api/runs*` routes)
- Report generation: `app/reporting.py`
- Export shape: `app/app.py` (`/api/export/<fmt>`) + `app/static/js/dashboard.js`
- Navigation and UX links: `app/templates/*.html`

## Contributing
1. Create focused, minimal changes in the relevant module.
2. Add or update tests in `tests/` for behavior changes.
3. Run targeted checks before pushing (backend tests and affected UI verification).
4. Keep UI text concise and role-aware.
5. Update `README.md`/`ROADMAP.md` if flows or endpoints change.

## Audit workflow optimization roadmap (gap-only)

This section intentionally **ignores capabilities already present** in LogGuard (XAI explanations, alert delivery integrations, PDF/HTML reporting, RBAC roles, feedback capture, Docker support, and near-real-time `/api/ingest` endpoint).

### Scope note: real-time streaming
- **Out of scope for the current implementation cycle.**
- Keep ingestion extensible so Kafka/RabbitMQ/Redis Streams connectors can be added later without reworking core analysis routes.
- Preferred approach: add a transport adapter layer that normalizes stream events into the existing `api_ingest` payload shape.

### Prioritized backlog (missing/high-value)

#### P0 (must-have)
1. **Risk scoring framework (weighted)**
   - Combine model score with asset criticality, access timing, and privilege context.
   - Output consistent severity and priority ordering for triage.
2. **Case management workflow**
   - Auto-create investigation cases from critical anomalies.
   - Add status lifecycle (`open`, `investigating`, `resolved`, `false_positive`) and ownership.
3. **Historical trend analysis**
   - Add period-over-period anomaly trend views and recurring source/endpoint tracking.

#### P1 (should-have)
1. **Multi-log parser architecture**
   - Introduce pluggable parser interfaces for Nginx, IIS, syslog, firewall, and DB logs.
2. **Compliance mapping module**
   - Map anomaly classes to configurable control references (GDPR/SOX/PCI-DSS).
3. **Retraining governance improvements**
   - Extend existing retraining flow with drift thresholds and alerting on model degradation.

#### P2 (nice-to-have)
1. **Cloud deployment profiles**
   - Optional AWS/Azure/GCP reference stacks for scale-out and archival.
2. **On-prem lightweight packaging**
   - Harden single-node mode for constrained environments with minimal external dependencies.

### Suggested delivery sequence
1. Risk scoring foundations
2. Case management data model + APIs
3. Trend analytics views
4. Parser plugin abstraction
5. Compliance mapping and retraining governance enhancements
