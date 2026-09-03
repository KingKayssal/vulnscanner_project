# Web Vulnerability Scanner -- container image
# Includes system libs needed by WeasyPrint (pango/cairo) and Playwright (Chromium deps).
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    # WeasyPrint (PDF rendering) system deps
    libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf2.0-0 \
    libffi-dev shared-mime-info fonts-liberation \
    # Playwright/Chromium runtime deps
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpangocairo-1.0-0 \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download the Chromium binary at build time so scans don't hit the
# network for it at runtime (needs outbound access to cdn.playwright.dev
# during `docker build`).
RUN python -m playwright install --with-deps chromium

COPY . .

RUN mkdir -p /app/evidence_output /app/reports/output

ENV SCANNER_DB_URL=sqlite:////app/data/scanner.db
ENV SCANNER_EVIDENCE_DIR=/app/evidence_output
ENV SCANNER_REPORT_DIR=/app/reports/output

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
