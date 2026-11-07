# Automated Vulnerability Scanner — remaining work

**Priority:** 3 | **Status:** Code copied from `M:\vulnscanner_project` (with git history). 19/19 non-PDF tests pass on this PC; the PDF report test needs the MSYS2 Pango runtime (see below).

See [README.md](README.md) for the scanner's own documentation.

## Decisions

- [ ] Choose the next milestone
- [ ] Decide the CI strategy: Windows-native or Linux container

## Documentation

- [ ] Document how to move beyond the interim `SCANNER_API_KEY` + `X-Organization` authentication

## Housekeeping

- [x] Replace `datetime.utcnow()` — now `db.models.utc_now()` (naive UTC, same stored values)
- [x] Update the FastAPI lifespan handlers — `api/main.py` uses a `lifespan` context manager
- [ ] Script the dev environment setup

## Environment on this PC

- Dependencies are installed in the workspace venv: `..\.venv\Scripts\python.exe -m pytest -q`
- `tests/test_report_generator.py` fails to import WeasyPrint until MSYS2 is installed with
  `mingw-w64-x86_64-pango` and `$env:WEASYPRINT_DLL_DIRECTORIES = "C:\msys64\mingw64\bin"` is set.
- Not copied (regenerate locally): `.venv`, `.pytest_cache`, `__pycache__`.
