from unittest.mock import patch

import pytest

from core.orchestrator import run_scan


def test_crawl_failure_marks_scan_failed(tmp_path):
    with patch("core.orchestrator.get_session") as get_session, patch(
        "core.orchestrator.check_authorization", return_value=None
    ), patch("core.orchestrator.validate_target_url", return_value="example.com"), patch(
        "core.orchestrator.load_templates", return_value=[]
    ), patch("core.orchestrator.crawl", side_effect=RuntimeError("crawl failed")):
        with pytest.raises(RuntimeError):
            run_scan("https://example.com")

        session = get_session.return_value
        assert session.close.called
