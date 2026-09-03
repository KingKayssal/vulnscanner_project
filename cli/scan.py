#!/usr/bin/env python3
"""
One-command CLI for the vulnerability scanner.

Usage:
    # Authorize a target (one-time, or renew when the window expires)
    python3 cli/scan.py authorize --domain example.com \\
        --authorized-by "Jane Doe, Security Lead" \\
        --doc-url "https://wiki.example.com/authz/2026-08" \\
        --valid-until 2026-12-31 \\
        --org "Acme Corp"

    # Run a full scan + generate a PDF report
    python3 cli/scan.py run --url https://example.com/ --depth 3

    # Just regenerate a report for an existing scan
    python3 cli/scan.py report --scan-id <uuid>

    # List recent scans
    python3 cli/scan.py list
"""
import argparse
import datetime
import sys
from urllib.parse import urlparse

from db.session import init_db, get_session
from db.models import Organization, AuthorizedTarget, Scan
from core.orchestrator import run_scan, AuthorizationError
from reports.report_generator import generate_report


def cmd_authorize(args):
    init_db()
    session = get_session()

    org = session.query(Organization).filter_by(name=args.org).first()
    if not org:
        org = Organization(name=args.org)
        session.add(org)
        session.flush()

    existing = session.query(AuthorizedTarget).filter_by(domain=args.domain).first()
    valid_until = datetime.date.fromisoformat(args.valid_until)
    valid_from = datetime.date.fromisoformat(args.valid_from) if args.valid_from else datetime.date.today()

    if existing:
        existing.authorized_by = args.authorized_by
        existing.authorization_doc_url = args.doc_url
        existing.valid_from = valid_from
        existing.valid_until = valid_until
        session.commit()
        print(f"Updated authorization for {args.domain} (valid {valid_from} -> {valid_until})")
    else:
        target = AuthorizedTarget(
            organization_id=org.id,
            domain=args.domain,
            authorized_by=args.authorized_by,
            authorization_doc_url=args.doc_url,
            valid_from=valid_from,
            valid_until=valid_until,
            excluded_paths=args.exclude or [],
        )
        session.add(target)
        session.commit()
        print(f"Authorized {args.domain} under org '{args.org}' (valid {valid_from} -> {valid_until})")


def cmd_run(args):
    init_db()
    try:
        scan_id = run_scan(args.url, initiated_by=args.by, crawl_depth=args.depth)
    except AuthorizationError as e:
        print(f"AUTHORIZATION ERROR: {e}", file=sys.stderr)
        print(f"Hint: run `python3 cli/scan.py authorize --domain {urlparse(args.url).hostname} ...` first.",
              file=sys.stderr)
        sys.exit(1)

    if args.no_report:
        return
    generate_report(scan_id)


def cmd_report(args):
    init_db()
    generate_report(args.scan_id)


def cmd_list(args):
    init_db()
    session = get_session()
    scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(args.limit).all()
    if not scans:
        print("No scans found.")
        return
    for s in scans:
        print(f"{s.id}  {s.status:10s}  started={s.started_at}  by={s.initiated_by}")


def main():
    parser = argparse.ArgumentParser(prog="scan.py", description="Web vulnerability scanner CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_auth = sub.add_parser("authorize", help="Register/renew authorization for a target domain")
    p_auth.add_argument("--domain", required=True)
    p_auth.add_argument("--authorized-by", required=True)
    p_auth.add_argument("--doc-url", default=None)
    p_auth.add_argument("--org", default="Default Org")
    p_auth.add_argument("--valid-from", default=None, help="YYYY-MM-DD, defaults to today")
    p_auth.add_argument("--valid-until", required=True, help="YYYY-MM-DD")
    p_auth.add_argument("--exclude", nargs="*", default=[], help="Path substrings to exclude from crawling")
    p_auth.set_defaults(func=cmd_authorize)

    p_run = sub.add_parser("run", help="Run a full scan and generate a report")
    p_run.add_argument("--url", required=True, help="Seed URL to start crawling from")
    p_run.add_argument("--depth", type=int, default=2)
    p_run.add_argument("--by", default="cli-user")
    p_run.add_argument("--no-report", action="store_true", help="Skip PDF generation")
    p_run.set_defaults(func=cmd_run)

    p_report = sub.add_parser("report", help="Generate a PDF report for an existing scan")
    p_report.add_argument("--scan-id", required=True)
    p_report.set_defaults(func=cmd_report)

    p_list = sub.add_parser("list", help="List recent scans")
    p_list.add_argument("--limit", type=int, default=10)
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
