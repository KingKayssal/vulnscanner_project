"""
Authenticated scanning support.

Most real targets require login before the interesting attack surface
is reachable. This module drives a real browser login (handles JS-based
forms, CSRF tokens, redirects) via Playwright, then extracts the
resulting session cookies so the rest of the scanner (httpx-based
crawler + template probes) can reuse that authenticated session without
needing a browser for every request.

Credentials should come from a secrets manager (Vault, AWS Secrets
Manager, etc.) at call time -- never hardcode or commit them. This
module just accepts them as parameters.

Usage:
    cookies = await login_and_get_session(
        login_url="https://app.example.com/login",
        username="scanner-bot@example.com",
        password=os.environ["SCAN_TARGET_PASSWORD"],
        username_selector="#email",
        password_selector="#password",
        submit_selector="button[type=submit]",
    )
    result = await crawl(seed_url, auth_cookies=cookies)
"""
from playwright.async_api import async_playwright


async def login_and_get_session(
    login_url: str,
    username: str,
    password: str,
    username_selector: str = "input[name=username]",
    password_selector: str = "input[name=password]",
    submit_selector: str = "button[type=submit]",
    success_url_contains: str | None = None,
) -> dict:
    """
    Drives a real login form and returns cookies as a dict suitable for
    httpx.AsyncClient(cookies=...).

    Raises RuntimeError if success_url_contains is set and the resulting
    URL doesn't match (a simple signal that login failed).
    """
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto(login_url, wait_until="networkidle")

        await page.fill(username_selector, username)
        await page.fill(password_selector, password)
        await page.click(submit_selector)
        await page.wait_for_load_state("networkidle")

        if success_url_contains and success_url_contains not in page.url:
            await browser.close()
            raise RuntimeError(
                f"Login flow did not reach expected post-login URL "
                f"(landed on {page.url}); check selectors/credentials."
            )

        cookies = await page.context.cookies()
        await browser.close()

    return {c["name"]: c["value"] for c in cookies}


# MFA / SSO note: for targets behind MFA or corporate SSO, either:
#   (a) provision a dedicated scanner service account with MFA excluded
#       via a conditional-access policy scoped to the scanner's IP, or
#   (b) pre-authenticate manually/via a scripted OTP step and hand the
#       resulting session cookie to `crawl(auth_cookies=...)` directly,
#       refreshing it on a schedule shorter than the session lifetime.
