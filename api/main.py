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
import os
from urllib.parse import urlparse
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from db.session import init_db, get_session
from db.models import Organization, AuthorizedTarget, Scan, Finding
from core.orchestrator import run_scan, AuthorizationError
from core.target_security import normalize_domain

app = FastAPI(title="Web Vulnerability Scanner API", version="0.1")


def current_organization(
    api_key: str | None = Header(default=None, alias="X-API-Key"),
    organization: str | None = Header(default=None, alias="X-Organization"),
):
    configured_key = os.environ.get("SCANNER_API_KEY")
    if not configured_key or api_key != configured_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if not organization:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="X-Organization is required")

    session = get_session()
    try:
        org = session.query(Organization).filter_by(name=organization).first()
        if not org:
            raise HTTPException(status_code=404, detail="Not found")
        return org.id
    finally:
        session.close()


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
def authorize_target(req: AuthorizeRequest, organization_id: str = Depends(current_organization)):
    session = get_session()
    try:
        org = session.query(Organization).filter_by(id=organization_id).first()
        if req.org != org.name:
            raise HTTPException(status_code=404, detail="Not found")

        domain = normalize_domain(req.domain)
        valid_until = datetime.date.fromisoformat(req.valid_until)
        valid_from = datetime.date.fromisoformat(req.valid_from) if req.valid_from else datetime.date.today()

        existing = session.query(AuthorizedTarget).filter_by(domain=domain, organization_id=organization_id).first()
        if existing:
            existing.authorized_by = req.authorized_by
            existing.authorization_doc_url = req.doc_url
            existing.valid_from = valid_from
            existing.valid_until = valid_until
            existing.excluded_paths = req.excluded_paths
            session.commit()
            return {"status": "updated", "target_id": existing.id}

        target = AuthorizedTarget(
            organization_id=organization_id, domain=domain, authorized_by=req.authorized_by,
            authorization_doc_url=req.doc_url, valid_from=valid_from, valid_until=valid_until,
            excluded_paths=req.excluded_paths,
        )
        session.add(target)
        session.commit()
        return {"status": "created", "target_id": target.id}
    finally:
        session.close()


@app.post("/scans", status_code=status.HTTP_202_ACCEPTED)
def start_scan(req: ScanRequest, organization_id: str = Depends(current_organization)):
    session = get_session()
    try:
        target_domain = normalize_domain(urlparse(req.url).hostname or "")
        target = session.query(AuthorizedTarget).filter_by(domain=target_domain, organization_id=organization_id).first()
        if not target:
            raise HTTPException(status_code=404, detail="Not found")
        from workers.celery_app import run_scan_task
        task = run_scan_task.delay(req.url, req.initiated_by, req.depth, req.generate_pdf)
        return {"task_id": task.id}
    finally:
        session.close()


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str, organization_id: str = Depends(current_organization)):
    session = get_session()
    try:
        scan = session.query(Scan).filter_by(id=scan_id, organization_id=organization_id).first()
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
    finally:
        session.close()


@app.get("/scans/{scan_id}/findings")
def list_findings(scan_id: str, organization_id: str = Depends(current_organization)):
    session = get_session()
    try:
        scan = session.query(Scan).filter_by(id=scan_id, organization_id=organization_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = session.query(Finding).filter_by(scan_id=scan_id).all()
        return [
            {
                "id": f.id, "title": f.title, "severity": f.severity,
                "cvss_score": float(f.cvss_score) if f.cvss_score else None,
                "cvss_vector": f.cvss_vector, "status": f.status,
            }
            for f in findings
        ]
    finally:
        session.close()


@app.get("/scans/{scan_id}/report")
def download_report(scan_id: str, organization_id: str = Depends(current_organization)):
    session = get_session()
    scan = session.query(Scan).filter_by(id=scan_id, organization_id=organization_id).first()
    if not scan:
        session.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    session.close()
    from reports.report_generator import generate_report
    path = generate_report(scan_id)
    return FileResponse(path, media_type="application/pdf", filename=f"report_{scan_id}.pdf")
