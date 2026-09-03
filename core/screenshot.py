"""
Evidence screenshot capture.

Real implementation uses Playwright (headless Chromium) to render the
page and capture a full-page screenshot, optionally highlighting the
vulnerable element/parameter.

NOTE: requires `playwright install chromium` to have downloaded a browser
binary, which needs outbound access to cdn.playwright.dev. In network-
restricted CI/build sandboxes that domain may need to be allow-listed.
A `mock` mode is provided so the rest of the pipeline (storage path,
DB linkage, report embedding) can be built/tested without a browser.
"""
import os
import asyncio
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("SCANNER_EVIDENCE_DIR", "./evidence_output"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


async def _capture_with_playwright(url: str, finding_id: str, highlight_selector: str | None = None) -> str:
    out_path = EVIDENCE_DIR / f"{finding_id}.png"
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1280, "height": 800})
        await page.goto(url, wait_until="networkidle", timeout=15000)
        if highlight_selector:
            try:
                await page.eval_on_selector(
                    highlight_selector,
                    "el => el.style.outline = '3px solid red'"
                )
            except Exception:
                pass  # selector not found -- still capture the page
        await page.screenshot(path=str(out_path), full_page=True)
        await browser.close()
    return str(out_path)


def _capture_mock(url: str, finding_id: str, reason: str = "") -> str:
    """
    Fallback used when no browser binary is available (e.g. this sandbox).
    Writes a placeholder PNG plus a text sidecar noting why, so downstream
    code (DB linkage, report embedding) can be exercised end to end.
    """
    from PIL import Image, ImageDraw

    out_path = EVIDENCE_DIR / f"{finding_id}.png"
    img = Image.new("RGB", (800, 200), color=(240, 240, 240))
    draw = ImageDraw.Draw(img)
    draw.text((20, 20), f"Evidence placeholder for finding {finding_id}", fill=(20, 20, 20))
    draw.text((20, 50), f"URL: {url}"[:90], fill=(20, 20, 20))
    draw.text((20, 80), "(No browser binary available in this environment", fill=(150, 0, 0))
    draw.text((20, 100), " -- real deploys use Playwright/Chromium here.)", fill=(150, 0, 0))
    img.save(out_path)
    return str(out_path)


def capture_evidence(url: str, finding_id: str, highlight_selector: str | None = None) -> str:
    """Synchronous wrapper. Returns local path to the screenshot (upload to S3/MinIO in prod)."""
    if _PLAYWRIGHT_AVAILABLE:
        try:
            return asyncio.run(_capture_with_playwright(url, finding_id, highlight_selector))
        except Exception as e:
            print(f"[screenshot] Playwright capture failed ({e}), falling back to mock.")
    return _capture_mock(url, finding_id)


if __name__ == "__main__":
    path = capture_evidence("http://127.0.0.1:8899/", "test-finding-001")
    print("Saved:", path)
