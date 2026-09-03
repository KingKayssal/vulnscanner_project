"""
Minimal REST API over the scanner core.

Run with:
    uvicorn api.main:app --host 0.0.0.0 --port 8000

Endpoints:
    POST /targets/authorize   Register/renew authorization for a domain
    POST /scans                Start a scan (synchronous for now; see note below)
    GET  /scans/{scan_id}      Scan status + finding counts
    GET  /scans/{scan_id}/findings   List findings
    GET  /scans/{scan_id}/report      Download the PDF report

NOTE: /scans runs synchronously for simplicity. In production, this should
enqueue a Celery task (see docker/worker.py stub in the packaging step) and
return 202 Accepted with a scan_id the client polls -- scans against real
targets can take minutes and shouldn't block an HTTP request/CI job.
"""
import datetime
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from db.session import init_db, get_session
from db.models import Organization, AuthorizedTarget, Scan, Finding
from core.orchestrator import run_scan, AuthorizationError
from reports.report_generator import generate_report

app = FastAPI(title="Web Vulnerability Scanner API", version="0.1")


@app.on_event("startup")
def _startup():
    init_db()


class AuthorizeRequest(BaseModel):
    domain: str
    authorized_by: str
    org: str = "Default Org"
    doc_url: str | None = None
    valid_until: str  # YYYY-MM-DD
    valid_from: str | None = None
    excluded_paths: list[str] = []


class ScanRequest(BaseModel):
    url: str
    depth: int = 2
    initiated_by: str = "api-client"
    generate_pdf: bool = True


@app.post("/targets/authorize")
def authorize_target(req: AuthorizeRequest):
    session = get_session()
    org = session.query(Organization).filter_by(name=req.org).first()
    if not org:
        org = Organization(name=req.org)
        session.add(org)
        session.flush()

    valid_until = datetime.date.fromisoformat(req.valid_until)
    valid_from = datetime.date.fromisoformat(req.valid_from) if req.valid_from else datetime.date.today()

    existing = session.query(AuthorizedTarget).filter_by(domain=req.domain).first()
    if existing:
        existing.authorized_by = req.authorized_by
        existing.authorization_doc_url = req.doc_url
        existing.valid_from = valid_from
        existing.valid_until = valid_until
        session.commit()
        return {"status": "updated", "target_id": existing.id}

    target = AuthorizedTarget(
        organization_id=org.id, domain=req.domain, authorized_by=req.authorized_by,
        authorization_doc_url=req.doc_url, valid_from=valid_from, valid_until=valid_until,
        excluded_paths=req.excluded_paths,
    )
    session.add(target)
    session.commit()
    return {"status": "created", "target_id": target.id}


@app.post("/scans")
def start_scan(req: ScanRequest):
    try:
        scan_id = run_scan(req.url, initiated_by=req.initiated_by, crawl_depth=req.depth)
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))

    if req.generate_pdf:
        generate_report(scan_id)

    return {"scan_id": scan_id}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    session = get_session()
    scan = session.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = session.query(Finding).filter_by(scan_id=scan_id).all()
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    return {
        "id": scan.id,
        "status": scan.status,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "finding_count": len(findings),
        "severity_counts": severity_counts,
    }


@app.get("/scans/{scan_id}/findings")
def list_findings(scan_id: str):
    session = get_session()
    findings = session.query(Finding).filter_by(scan_id=scan_id).all()
    return [
        {
            "id": f.id, "title": f.title, "severity": f.severity,
            "cvss_score": float(f.cvss_score) if f.cvss_score else None,
            "cvss_vector": f.cvss_vector, "status": f.status,
        }
        for f in findings
    ]


@app.get("/scans/{scan_id}/report")
def download_report(scan_id: str):
    path = generate_report(scan_id)  # idempotent-ish: regenerates latest
    return FileResponse(path, media_type="application/pdf", filename=f"report_{scan_id}.pdf")
