# Web Vulnerability Scanner

An automated, template-driven web application vulnerability scanner:
crawl → detect → score (CVSS) → capture evidence → PDF report.

**For authorized security testing only.** The scanner will refuse to
scan any domain without an active `AuthorizedTarget` record with a valid
date window (see `core/orchestrator.py::check_authorization`).

## Status: complete (10/10 build steps)

| # | Step | Status |
|---|------|--------|
| 1 | Project scaffold + deps | ✅ |
| 2 | Database layer (SQLAlchemy) | ✅ |
| 3 | CVSS scoring | ✅ |
| 4 | Template engine (YAML DSL) | ✅ |
| 5 | Crawler | ✅ |
| 6 | Scan orchestrator | ✅ |
| 7 | Screenshot evidence (Playwright) | ✅ (mock fallback verified; real Playwright path untested in this sandbox -- see note below) |
| 8 | PDF report generation | ✅ |
| 9 | CLI + REST API | ✅ |
| 10 | Docker packaging, scheduling, auth scanning, CI/CD | ✅ |

Detects: missing security headers, server version disclosure, exposed
`.git` directories, and reflected-XSS candidates (confirmed via a
browser-independent marker-reflection check). New checks = new YAML
files in `templates/`, no code changes required for passive/simple checks.

## Quick start (local dev)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m playwright install chromium   # needs network access to cdn.playwright.dev

# Authorize a target you own/have permission to test
python3 cli/scan.py authorize \
    --domain example.com \
    --authorized-by "Your Name" \
    --valid-until 2026-12-31

# Run a scan + generate a PDF report in one command
python3 cli/scan.py run --url https://example.com/ --depth 3
```

Or via the API:

```bash
uvicorn api.main:app --reload
# POST /targets/authorize, POST /scans, GET /scans/{id}, GET /scans/{id}/report
```

## Docker

```bash
docker compose up --build
```

Brings up: API (`:8000`), a Celery worker, Celery beat (for scheduled
scans), Postgres, and Redis. Swap `docker-compose.yml`'s Postgres creds
before any real deployment.

**Note on this sandbox build:** the environment I built this in has a
restricted network egress allowlist that blocks `cdn.playwright.dev`
(Chromium binary download) and arbitrary external hosts (I could only
reach localhost, so I built and scanned a local intentionally-vulnerable
test app instead of a public site). Everything was tested end-to-end
against that local target, including the full DB → crawl → detect →
score → screenshot → PDF pipeline and the CLI/API layers. The Docker
image's `RUN playwright install --with-deps chromium` step and any scan
against a real external target will need normal outbound network access,
which your deployment environment should have.

## Architecture

```
CLI / API  -->  Orchestrator  -->  Crawler (httpx / Playwright for JS+auth)
                    |                       |
                    v                       v
              Template Engine  <--  discovered assets
                    |
                    v
         Findings (CVSS-scored) + Screenshots
                    |
                    v
              PDF Report (Jinja2 + WeasyPrint)
```

Full schema, template DSL reference, and design rationale: see the
original design writeup (or `db/models.py` + `templates/*.yaml` directly
-- they're the living source of truth now).

## Extending detection

Add a new file to `templates/`, following the shape of the existing
ones. Supported matcher types today: `header-absence`,
`header-value-present`, `path-probe`, `reflected-marker`. Add new
matcher types in `core/template_engine.py::evaluate_template`.

## Authenticated scanning

`core/auth_login.py` drives a real Playwright login flow and hands the
resulting session cookies to `crawl(auth_cookies=...)`. For MFA/SSO
targets, see the notes at the bottom of that file.

## Scheduling

`workers/celery_app.py` has `run_scan_task` wired up; add entries to
`celery_app.conf.beat_schedule` (or, better, move to a DB-backed
schedule table so scans can be scheduled via the API instead of a
redeploy) and run `celery -A workers.celery_app beat`.

## CI/CD integration

See `.github/workflows/security-scan.yml` for a template that scans a
staging deploy and fails the build on new High/Critical findings,
uploading the PDF report as a build artifact.

## Known limitations / next steps beyond this build

- Report generator regenerates PDFs each call rather than caching immutable ones -- fine for demo, add caching/versioning for production.
- No RBAC/multi-tenant auth on the API yet -- add OAuth2/OIDC before exposing beyond localhost.
- The reflected-XSS check only tests parameters the crawler already discovered on a page (via its own query string) -- extend to also probe forms and known common parameter names.
- Active checks are intentionally non-destructive (marker-based, not real payloads); SQLi/SSRF/etc. templates would need similarly safe-by-default probes.
- Scale-out crawling still needs a distributed queue (Celery task per discovered URL) rather than one worker walking the whole site sequentially, for large targets.
