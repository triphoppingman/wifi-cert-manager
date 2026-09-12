# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WCM_DATA_DIR=/data

WORKDIR /app

COPY requirements.txt pyproject.toml README.md ./
COPY wifi_cert_manager ./wifi_cert_manager

RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps . \
    && useradd --create-home --uid 1000 certmgr \
    && mkdir -p /data \
    && chown -R certmgr:certmgr /data /app

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["docker-entrypoint.sh"]
# Overridable at runtime, e.g. `docker run <image> certmgr status`
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "wifi_cert_manager.webapp.app:app"]
