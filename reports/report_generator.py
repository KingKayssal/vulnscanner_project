"""
Renders a completed scan into a professional PDF report.

    generate_report(scan_id) -> path to PDF on disk

Uses Jinja2 to fill reports/templates/report.html.jinja, then WeasyPrint
to convert that HTML to PDF. Screenshots are embedded as local file://
paths for now; in production, resolve S3/MinIO URLs (with signed access
or a fetch-and-embed step) instead.
"""
import os
import datetime as dt
from pathlib import Path
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from db.session import get_session
from db.models import Scan, Finding, Asset, AuthorizedTarget, Report

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
OUTPUT_DIR = Path(os.environ.get("SCANNER_REPORT_DIR", "./reports/output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _severity_counts(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _severity_pct(counts: dict) -> dict:
    total = sum(counts.values()) or 1
    return {k: round((v / total) * 100, 1) for k, v in counts.items()}


def _generate_report(scan_id: str, session) -> str:
    scan = session.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    target = session.query(AuthorizedTarget).filter_by(id=scan.target_id).first()
    findings = session.query(Finding).filter_by(scan_id=scan_id).all()
    assets = session.query(Asset).filter_by(scan_id=scan_id).all()

    assets_by_id = {asset.id: asset for asset in assets}
    finding_rows = []
    for f in findings:
        asset = assets_by_id.get(f.asset_id)
        screenshot_path = None
        if f.screenshot_url and os.path.exists(f.screenshot_url):
            screenshot_path = Path(f.screenshot_url).resolve().as_uri()
        finding_rows.append({
            "title": f.title,
            "severity": f.severity,
            "cvss_score": float(f.cvss_score) if f.cvss_score is not None else 0.0,
            "cvss_vector": f.cvss_vector,
            "cwe": "",
            "url": asset.url if asset else "",
            "description": f.description,
            "remediation": f.remediation,
            "evidence_request": f.evidence_request or "",
            "evidence_response": f.evidence_response or "",
            "screenshot_path": screenshot_path,
        })

    counts = _severity_counts(findings)
    pct = _severity_pct(counts)

    scan_ctx = {
        "id": scan.id,
        "target_domain": target.domain if target else urlparse(scan.config.get("seed_url", "")).hostname,
        "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M UTC") if scan.started_at else "N/A",
        "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else "N/A",
        "initiated_by": scan.initiated_by,
        "authorization_doc_url": target.authorization_doc_url if target else None,
        "pages_crawled": len(assets),
    }

    asset_rows = [
        {"url": a.url, "status": a.response_status, "discovered_via": a.discovered_via}
        for a in assets
    ]

    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.jinja")
    html_str = template.render(
        scan=scan_ctx,
        findings=finding_rows,
        assets=asset_rows,
        severity_counts=counts,
        severity_pct=pct,
        generated_at=dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
    )

    out_path = OUTPUT_DIR / f"report_{scan_id}.pdf"
    HTML(string=html_str, base_url=".").write_pdf(str(out_path))

    report_row = session.query(Report).filter_by(scan_id=scan_id).first()
    if report_row:
        report_row.file_url = str(out_path)
        report_row.summary = {"severity_counts": counts, "total_findings": len(findings)}
    else:
        session.add(Report(
            scan_id=scan_id,
            file_url=str(out_path),
            summary={"severity_counts": counts, "total_findings": len(findings)},
        ))
    session.commit()

    print(f"Report generated: {out_path}")
    return str(out_path)


def generate_report(scan_id: str) -> str:
    session = get_session()
    try:
        return _generate_report(scan_id, session)
    finally:
        session.close()


if __name__ == "__main__":
    import sys
    sid = sys.argv[1] if len(sys.argv) > 1 else None
    if not sid:
        # default: most recent scan
        session = get_session()
        latest = session.query(Scan).order_by(Scan.created_at.desc()).first()
        sid = latest.id
    generate_report(sid)
