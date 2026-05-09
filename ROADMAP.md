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
