from pathlib import Path

from db.models import Asset, Finding, Organization, Report, Scan, AuthorizedTarget
from db.session import Base, SessionLocal, engine
from reports import report_generator


def test_report_escapes_finding_data_and_reuses_report(monkeypatch, tmp_path):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    org = Organization(name="Report Org")
    session.add(org)
    session.flush()
    target = AuthorizedTarget(
        organization_id=org.id, domain="example.com", authorized_by="test",
        valid_from=__import__("datetime").date.today(), valid_until=__import__("datetime").date.today(),
    )
    session.add(target)
    session.flush()
    scan = Scan(
        organization_id=org.id, target_id=target.id, status="completed",
        initiated_by="test", config={"seed_url": "https://example.com"},
    )
    session.add(scan)
    session.flush()
    asset = Asset(scan_id=scan.id, url="https://example.com", response_status=200)
    session.add(asset)
    session.flush()
    session.add(Finding(
        scan_id=scan.id, asset_id=asset.id, template_id="xss", title="<script>alert(1)</script>",
        severity="high", cvss_score=8.0, cvss_vector="vector", description="<img src=x onerror=alert(1)>",
        remediation="fix", evidence_request="GET /", evidence_response="<script>alert(1)</script>",
    ))
    session.commit()
    scan_id = scan.id
    session.close()

    monkeypatch.setattr(report_generator, "OUTPUT_DIR", Path(tmp_path))
    first = report_generator.generate_report(scan_id)
    second = report_generator.generate_report(scan_id)
    assert first == second
    pdf = Path(first)
    assert pdf.exists()
    assert pdf.read_bytes().startswith(b"%PDF")
    assert pdf.stat().st_size > 1000

    check = SessionLocal()
    assert check.query(Report).filter_by(scan_id=scan_id).count() == 1
    check.close()