"""
Celery app for background scan execution and recurring (scheduled) scans.

Run a worker:
    celery -A workers.celery_app worker --loglevel=info

Run the beat scheduler (for recurring scans):
    celery -A workers.celery_app beat --loglevel=info

Recurring scans are configured via the `recurring_scans` table-equivalent
(kept simple here as a Celery beat schedule; move to DB-backed
dynamic scheduling with celery-sqlalchemy-scheduler for a real multi-
tenant product so schedules can be added via the API instead of redeploys).
"""
import os
from celery import Celery
from celery.schedules import crontab

from core.orchestrator import run_scan, AuthorizationError
from reports.report_generator import generate_report

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")

celery_app = Celery("vulnscanner", broker=BROKER_URL, backend=BROKER_URL)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=60)
def run_scan_task(self, url: str, initiated_by: str = "scheduler", depth: int = 2, generate_pdf: bool = True):
    try:
        scan_id = run_scan(url, initiated_by=initiated_by, crawl_depth=depth)
    except AuthorizationError as e:
        # Do not retry auth failures -- retrying won't fix an expired/missing
        # authorization window; surface it for an operator to fix.
        return {"status": "authorization_error", "detail": str(e)}
    except Exception as exc:
        raise self.retry(exc=exc)

    if generate_pdf:
        generate_report(scan_id)
    return {"status": "completed", "scan_id": scan_id}


# Example recurring schedule: nightly scan of a target at 02:00 UTC.
# In production, load this list from the DB (a `scheduled_scans` table)
# instead of hardcoding it, so schedules can be managed via the API.
celery_app.conf.beat_schedule = {
    # "nightly-scan-example-com": {
    #     "task": "workers.celery_app.run_scan_task",
    #     "schedule": crontab(hour=2, minute=0),
    #     "args": ("https://example.com/", "scheduler", 3, True),
    # },
}
