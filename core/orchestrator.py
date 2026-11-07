"""
Scan orchestrator: the workflow described in the design doc, wired up
end to end.

    1. Verify authorization
    2. Crawl
    3. Run templates against each discovered asset (passive + active)
    4. Confirm active/candidate findings with a second, targeted request
    5. Score confirmed findings with CVSS
    6. Persist everything
"""
import asyncio
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

import httpx

from core.crawler import crawl, CrawledPage
from core.template_engine import (
    load_templates, evaluate_template, HTTPResponseLike, generate_marker, LoadedTemplate
)
from core.cvss_calculator import score_vector
from core.screenshot import capture_evidence
from core.target_security import TargetBoundaryError, same_origin, validate_target_url, normalize_domain
from db.session import get_session
from db.models import Scan, Asset, Finding, AuthorizedTarget, utc_now

TEMPLATES_DIR = "templates"


class AuthorizationError(Exception):
    pass


def check_authorization(session, target_domain: str) -> AuthorizedTarget:
    target_domain = normalize_domain(target_domain)
    row = (
        session.query(AuthorizedTarget)
        .filter(AuthorizedTarget.domain == target_domain)
        .first()
    )
    if row is None:
        raise AuthorizationError(
            f"No authorization record found for domain '{target_domain}'. "
            "Refusing to scan. Add an AuthorizedTarget row first."
        )
    if not row.is_currently_authorized():
        raise AuthorizationError(
            f"Authorization for '{target_domain}' is not currently valid "
            f"(window: {row.valid_from} to {row.valid_until})."
        )
    return row


async def _probe_active_templates(
    base_url: str, page: CrawledPage, active_templates: list[LoadedTemplate]
) -> list[tuple[LoadedTemplate, HTTPResponseLike, str]]:
    """
    For templates that need their own probe request (path-probe,
    reflected-marker), issue those requests here.
    Returns list of (template, response, marker_used).
    """
    results = []
    expected_domain = validate_target_url(base_url)
    seed = urlparse(base_url)
    async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
        for tpl in active_templates:
            mtype = tpl.matcher["type"]

            if mtype == "path-probe":
                probe_url = f"{seed.scheme}://{seed.netloc}{tpl.matcher['path']}"
                try:
                    r = await client.get(probe_url)
                    if 300 <= r.status_code < 400 and r.headers.get("location"):
                        redirect_url = urljoin(probe_url, r.headers["location"])
                        if not same_origin(redirect_url, expected_domain, seed.scheme):
                            continue
                        validate_target_url(redirect_url, expected_domain)
                        r = await client.get(redirect_url)
                    validate_target_url(str(r.url), expected_domain)
                    resp = HTTPResponseLike(
                        url=probe_url, status_code=r.status_code,
                        headers=dict(r.headers), text=r.text,
                    )
                    results.append((tpl, resp, ""))
                except httpx.HTTPError:
                    continue

            elif mtype == "reflected-marker":
                parsed = urlparse(page.url)
                existing_params = parse_qs(parsed.query)
                if not existing_params:
                    # no query params on this page to test -- skip
                    continue
                marker = generate_marker(tpl.matcher.get("marker_prefix", "sc4n_"))
                # replace every existing param value with the marker so we
                # test each real, discovered parameter rather than guessing
                injected = {k: marker for k in existing_params}
                probe_url = urlunparse(parsed._replace(query=urlencode(injected)))
                try:
                    r = await client.get(probe_url)
                    if 300 <= r.status_code < 400 and r.headers.get("location"):
                        redirect_url = urljoin(probe_url, r.headers["location"])
                        if not same_origin(redirect_url, expected_domain, seed.scheme):
                            continue
                        validate_target_url(redirect_url, expected_domain)
                        r = await client.get(redirect_url)
                    validate_target_url(str(r.url), expected_domain)
                    resp = HTTPResponseLike(
                        url=probe_url, status_code=r.status_code,
                        headers=dict(r.headers), text=r.text,
                    )
                    results.append((tpl, resp, marker))
                except httpx.HTTPError:
                    continue
    return results


def run_scan(
    seed_url: str,
    initiated_by: str = "cli-user",
    crawl_depth: int = 2,
    templates_dir: str = TEMPLATES_DIR,
) -> str:
    """Synchronous entry point (wraps the async crawl/probe internally).
    Returns the scan_id."""
    session = get_session()
    scan = None
    try:
        try:
            domain = validate_target_url(seed_url)
        except TargetBoundaryError as exc:
            raise AuthorizationError(str(exc)) from exc

        target = check_authorization(session, domain)

        scan = Scan(
        organization_id=target.organization_id,
        target_id=target.id,
        status="crawling",
        crawl_depth=crawl_depth,
        started_at=utc_now(),
        initiated_by=initiated_by,
        config={"seed_url": seed_url},
    )
        session.add(scan)
        session.commit()

        templates = load_templates(templates_dir)
        passive_templates = [t for t in templates if t.matcher["type"] in ("header-absence", "header-value-present")]
        active_templates = [t for t in templates if t.matcher["type"] in ("path-probe", "reflected-marker")]

        crawl_result = asyncio.run(
            crawl(seed_url, max_depth=crawl_depth, excluded_paths=target.excluded_paths or [])
        )

        scan.status = "scanning"
        session.commit()

        finding_count = 0
        host_level_probed: set[str] = set()
        for page in crawl_result.pages:
            asset = Asset(
            scan_id=scan.id,
            url=page.url,
            method="GET",
            discovered_via="crawl",
            response_status=page.status_code,
            response_headers=page.headers,
        )
            session.add(asset)
            session.flush()

            resp_like = HTTPResponseLike(
            url=page.url, status_code=page.status_code,
            headers=page.headers, text=page.text,
        )

        # --- passive templates ---
            for tpl in passive_templates:
                result = evaluate_template(tpl, resp_like)
                if result.matched:
                    finding_count += _persist_finding(session, scan.id, asset.id, tpl, result.evidence, resp_like)

        # --- active templates (need their own probe request) ---
            host = urlparse(page.url).netloc
            per_page_active = list(active_templates)
            for tpl in list(per_page_active):
                if tpl.matcher["type"] == "path-probe":
                    key = f"{host}:{tpl.id}"
                    if key in host_level_probed:
                        per_page_active.remove(tpl)
                    else:
                        host_level_probed.add(key)

            active_results = asyncio.run(_probe_active_templates(seed_url, page, per_page_active))
            for tpl, probe_resp, marker in active_results:
                result = evaluate_template(tpl, probe_resp, marker=marker)
                if result.matched and result.confirmed:
                    finding_count += _persist_finding(session, scan.id, asset.id, tpl, result.evidence, probe_resp)

        scan.status = "completed"
        scan.completed_at = utc_now()
        session.commit()

        print(f"Scan {scan.id} complete: {len(crawl_result.pages)} pages, {finding_count} findings.")
        return scan.id
    except Exception as exc:
        session.rollback()
        if scan is not None:
            failed_scan = session.query(Scan).filter_by(id=scan.id).first()
            if failed_scan:
                failed_scan.status = "failed"
                failed_scan.completed_at = utc_now()
                failed_scan.config = {**(failed_scan.config or {}), "failure": str(exc)}
                session.commit()
        raise
    finally:
        session.close()


def _persist_finding(session, scan_id, asset_id, tpl, evidence, resp_like) -> int:
    cvss = score_vector(tpl.cvss_base_vector)
    finding = Finding(
        scan_id=scan_id,
        asset_id=asset_id,
        template_id=tpl.id,
        title=tpl.name,
        severity=cvss.severity.lower() if cvss.severity != "None" else "info",
        cvss_vector=cvss.vector,
        cvss_score=cvss.base_score,
        description=tpl.description,
        remediation=tpl.remediation,
        evidence_request=f"GET {resp_like.url}",
        evidence_response=evidence,
        confirmed=True,
        status="open",
    )
    session.add(finding)
    session.flush()  # get finding.id before screenshotting

    try:
        finding.screenshot_url = capture_evidence(resp_like.url, finding.id)
    except Exception as e:
        print(f"[finding {finding.id}] screenshot capture failed: {e}")

    session.commit()
    return 1


if __name__ == "__main__":
    import sys
    from db.session import init_db
    init_db()
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899/"
    run_scan(url)
