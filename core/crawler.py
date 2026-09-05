"""
Lightweight async crawler using httpx.

For JS-heavy SPAs, swap/augment this with a Playwright-based crawler
(core/js_crawler.py can follow the same interface) -- kept separate so
the fast path doesn't need a browser for simple sites.
"""
import re
import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from core.target_security import TargetBoundaryError, same_origin, validate_target_url

import httpx

LINK_RE = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)


@dataclass
class CrawledPage:
    url: str
    status_code: int
    headers: dict
    text: str


@dataclass
class CrawlResult:
    pages: list[CrawledPage] = field(default_factory=list)


async def crawl(
    seed_url: str,
    max_depth: int = 2,
    max_pages: int = 50,
    delay_seconds: float = 0.05,
    excluded_paths: list[str] | None = None,
    auth_cookies: dict | None = None,
    auth_headers: dict | None = None,
) -> CrawlResult:
    """
    auth_cookies / auth_headers: pass a pre-established session (e.g. a
    cookie captured after an automated login flow, or a bearer token) to
    crawl authenticated areas of the app. For form-based logins, run a
    Playwright login flow first and hand off the resulting cookies here
    (see core/auth_login.py for the stub).
    """
    excluded_paths = excluded_paths or []
    seed_domain = validate_target_url(seed_url)
    seed_scheme = urlparse(seed_url).scheme
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(seed_url, 0)]
    result = CrawlResult()

    async with httpx.AsyncClient(
        follow_redirects=False, timeout=10.0,
        cookies=auth_cookies or {}, headers=auth_headers or {},
    ) as client:
        while queue and len(result.pages) < max_pages:
            url, depth = queue.pop(0)
            if url in seen or depth > max_depth:
                continue
            if any(ex in urlparse(url).path for ex in excluded_paths):
                continue
            seen.add(url)

            try:
                resp = await client.get(url)
            except (httpx.HTTPError, TargetBoundaryError):
                continue

            if 300 <= resp.status_code < 400 and resp.headers.get("location"):
                redirected = urljoin(url, resp.headers["location"])
                if not same_origin(redirected, seed_domain, seed_scheme):
                    continue
                try:
                    validate_target_url(redirected, seed_domain)
                except TargetBoundaryError:
                    continue
                queue.insert(0, (redirected, depth))
                continue

            page = CrawledPage(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text if "text" in resp.headers.get("content-type", "") else "",
            )
            result.pages.append(page)

            for href in LINK_RE.findall(page.text):
                absolute = urljoin(url, href)
                if same_origin(absolute, seed_domain, seed_scheme) and absolute not in seen:
                    queue.append((absolute, depth + 1))

            await asyncio.sleep(delay_seconds)  # politeness delay

    return result


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899/"
    r = asyncio.run(crawl(target, max_depth=2))
    for p in r.pages:
        print(p.status_code, p.url)
