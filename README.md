# Nuclei WebUI (Corporate Vulnerability Management)



A modern, high-signal Web UI for the Nuclei scanner on **Kali Linux** — designed for cybersecurity managers and cybersecurity teams who need actionable tooling visibility, fast triage, and operational governance.

## Why this project exists

Nuclei is powerful, but CLI-only workflows are hard to operationalize for non-terminal stakeholders.
This project wraps Nuclei in a manager-friendly interface with:

- Multi-page navigation (`Dashboard`, `Scans`, `Findings`, `Workflow`)
- Manual finding promotion (scan results are reviewed before entering triage)
- CVE/CVSS-focused detail views
- SLA and lifecycle visibility for governance and reporting

## Stack

- **Backend:** Python + Flask
- **Database:** SQLite3 + SQLAlchemy
- **Frontend:** Jinja templates + TailwindCSS + Vue 3 + Chart.js

## Core capabilities

- Secure login page
- Default credentials:
  - **User:** `Developer`
  - **Password:** configured via `.env` (`DEFAULT_ADMIN_PASSWORD`)
- Corporate dashboard with:
  - scan volume and SLA KPIs
  - open/overdue finding metrics
  - severity distribution chart
  - Nuclei runtime health/version
- Collapsible sidebar navigation (desktop + mobile)
- Theme toggle (light/dark)
- Nuclei scan orchestration:
  - target scans
  - optional template, severity, tags
  - advanced CLI arguments
- Manual promotion workflow:
  - scan outputs stay in review state
  - selected scan results are explicitly promoted to findings
- Findings intelligence views:
  - CVE IDs
  - CVSS score/metrics
  - template metadata
  - raw payload and references
- Workflow board:
  - `open`, `in_progress`, `accepted_risk`, `resolved`
- Exports:
  - CSV / JSON for reporting and governance
- Role model:
  - `admin`, `analyst`, `viewer`
- Tenant isolation support (`tenant_id`)

## Architecture and project structure

```text
.
├── .env
├── nuclei-webui.py
├── requirements.txt
├── backend/
│   ├── app.py
│   ├── routes/
│   │   ├── auth.py
│   │   ├── api.py
│   │   └── ui.py
│   ├── schemas/
│   │   └── models.py
│   ├── utils/
│   │   ├── extensions.py
│   │   └── nuclei_service.py
│   ├── templates/
│   │   ├── base.html
│   │   ├── app_shell.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── scans.html
│   │   ├── findings.html
│   │   └── workflow.html
│   └── static/
│       ├── css/app.css
│       └── js/
│           ├── app-shell.js
│           ├── dashboard.js
│           └── pages/
│               ├── dashboard-page.js
│               ├── scans-page.js
│               ├── findings-page.js
│               └── workflow-page.js
└── tests/
    └── test_webui.py
```

## Setup (Kali Linux + venv)

1. Activate virtual environment
2. Start the app with a single command

```bash
source .venv/bin/activate
python nuclei-webui.py
```

### What `python nuclei-webui.py` does now

- checks and auto-installs missing Python dependencies from `requirements.txt`
- initializes backend runtime and frontend asset checks
- prepares SQLite database path(s)
- starts the full application stack (backend API + frontend UI)
- runs schema compatibility checks and default admin bootstrap via the Flask app factory

Open:

- `http://127.0.0.1:5000`

## Configuration

Environment values in `.env`:

- `SECRET_KEY`
- `DATABASE_URL=sqlite:///nuclei_webui.db`
- `DEFAULT_ADMIN_USERNAME=Developer`
- `DEFAULT_ADMIN_PASSWORD=change-this-password`
- `DEFAULT_TENANT_ID=default`
- `NUCLEI_BINARY=nuclei`
- Optional: `NUCLEI_TEMPLATES=/path/to/nuclei-templates`

## API overview

- `GET /api/health` — Nuclei availability/version
- `GET /api/templates` — discovered templates
- `GET /api/scans` — recent scans
- `GET /api/scans/<id>` — scan detail + metadata
- `GET /api/scans/<id>/results` — parsed scan output for manual review
- `POST /api/scans` — start a new scan
- `POST /api/scans/<id>/promote-findings` — promote selected scan results
- `GET /api/dashboard/summary` — KPI summary
- `GET /api/me` — user/role/tenant
- `GET /api/findings` — finding list (optional filters)
- `GET /api/findings/<id>` — enriched finding details
- `PATCH /api/findings/<id>` — lifecycle/owner/SLA updates
- `GET /api/export/findings.csv` — CSV export
- `GET /api/export/findings.json` — JSON export

## Testing

```bash
source .venv/bin/activate
pytest -q
```

## Medium.com blog angle (suggested)

If you are writing **“How I created a WebUI for Nuclei in 2026”**, highlight:

1. Why manager-facing UX matters in offensive tooling ecosystems
2. Why manual finding promotion improves governance quality
3. How CVE/CVSS context reduces triage friction
4. Why lightweight Flask + SQLite can still deliver enterprise value
5. How to evolve from prototype to production (auth hardening, RBAC, observability, CI)

## Security notes

- Change default credentials before real usage
- Use HTTPS and a production WSGI server in non-dev environments
- Restrict network exposure and enforce least privilege for scanner execution
- Review and sanitize advanced scan arguments in controlled environments
