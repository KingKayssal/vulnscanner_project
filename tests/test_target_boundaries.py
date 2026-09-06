import socket
import asyncio

import httpx
import pytest

from core.crawler import crawl
from core.target_security import TargetBoundaryError, normalize_domain, same_origin, validate_target_url
from db.models import AuthorizedTarget


def test_normalize_domain_handles_case_trailing_dot_and_idna():
    assert normalize_domain("ExAmPle.COM.") == "example.com"
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize("url", ["ftp://example.com", "http://localhost", "http://127.0.0.1"])
def test_validate_target_url_rejects_unsafe_targets(url):
    with pytest.raises(TargetBoundaryError):
        validate_target_url(url)


def test_validate_target_url_rejects_private_dns_result(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.5", 0))])
    with pytest.raises(TargetBoundaryError):
        validate_target_url("https://example.com")


def test_same_origin_rejects_domain_mismatch():
    assert not same_origin("https://evil.example/", "example.com", "https")


def test_same_origin_rejects_non_default_port():
    assert not same_origin("https://example.com:8443/", "example.com", "https")


def test_authorization_window_includes_today_and_excludes_expired(monkeypatch):
    from datetime import date, timedelta

    today = date.today()
    current = AuthorizedTarget(valid_from=today, valid_until=today)
    expired = AuthorizedTarget(valid_from=today - timedelta(days=2), valid_until=today - timedelta(days=1))
    assert current.is_currently_authorized() is True
    assert expired.is_currently_authorized() is False


async def _run_crawl(monkeypatch, handler):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 0))])
    transport = httpx.MockTransport(handler)
    original_client = httpx.AsyncClient

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    return await crawl("https://example.com/")


def test_crawl_does_not_follow_redirect_to_different_host(monkeypatch):
    requested = []

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})

    result = asyncio.run(_run_crawl(monkeypatch, handler))
    assert result.pages == []
    assert requested == ["https://example.com/"]


def test_crawl_does_not_follow_redirect_to_private_ip(monkeypatch):
    def handler(request):
        return httpx.Response(302, headers={"location": "https://10.0.0.4/admin"})

    result = asyncio.run(_run_crawl(monkeypatch, handler))
    assert result.pages == []


def test_crawl_respects_depth_exclusions_and_deduplicates(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 0))])
    pages = {
        "https://example.com/": '<html><a href="/one">one</a><a href="/one">dup</a><a href="/skip">skip</a></html>',
        "https://example.com/one": '<html><a href="/two">two</a></html>',
        "https://example.com/two": '<html>deep</html>',
    }
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, headers={"content-type": "text/html"}, text=pages[str(request.url)]
    ))
    original_client = httpx.AsyncClient

    def client_factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    result = asyncio.run(crawl("https://example.com/", max_depth=1, excluded_paths=["/skip"], delay_seconds=0))
    assert [page.url for page in result.pages] == ["https://example.com/", "https://example.com/one"]