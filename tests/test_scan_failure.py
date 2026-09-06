from unittest.mock import patch
from types import SimpleNamespace

import pytest

from core.orchestrator import run_scan


def test_crawl_failure_marks_scan_failed(tmp_path):
    scan_rows = []

    class FakeQuery:
        def filter_by(self, **kwargs):
            return self

        def first(self):
            return scan_rows[0] if scan_rows else None

    class FakeSession:
        def add(self, scan):
            scan.id = "scan-1"
            scan_rows.append(scan)

        def commit(self):
            return None

        def rollback(self):
            return None

        def query(self, model):
            return FakeQuery()

        def close(self):
            self.closed = True

    session = FakeSession()
    session.closed = False
    with patch("core.orchestrator.get_session") as get_session, patch(
        "core.orchestrator.check_authorization",
        return_value=SimpleNamespace(organization_id="org", id="target", excluded_paths=[]),
    ), patch("core.orchestrator.validate_target_url", return_value="example.com"), patch(
        "core.orchestrator.load_templates", return_value=[]
    ), patch("core.orchestrator.crawl", side_effect=RuntimeError("crawl failed")):
        get_session.return_value = session
        with pytest.raises(RuntimeError):
            run_scan("https://example.com")

        assert session.closed is True
        assert scan_rows[0].status == "failed"
        assert scan_rows[0].config["failure"] == "crawl failed"
