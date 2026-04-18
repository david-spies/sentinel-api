# ─────────────────────────────────────────────────────────────────────
#  Sentinel-API UI Server — Dockerfile
# ─────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/ui/

# Create reports mount point
RUN mkdir -p /reports

# Non-root
RUN useradd -r -u 1002 sentinel-ui && chown -R sentinel-ui:sentinel-ui /app
USER sentinel-ui

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

CMD ["uvicorn", "ui.main:app", "--host", "0.0.0.0", "--port", "3000", "--workers", "2"]
