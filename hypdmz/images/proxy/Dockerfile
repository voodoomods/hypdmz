# Pinned by digest (the multi-arch index of python:3.12-slim), so a rebuilt tag can't change what runs here.
# Update: `podman pull python:3.12-slim && podman image inspect python:3.12-slim --format '{{.RepoDigests}}'`
FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dedicated runtime UID. The pod's egress floor allows upstream traffic from this
# UID only — keep in sync with HYPDMZ_PROXY_UID in controller/apply-lockdown.sh.
ARG PROXY_UID=1001
RUN groupadd -r -g ${PROXY_UID} hypdmz-proxy \
    && useradd -r -u ${PROXY_UID} -g hypdmz-proxy -d /app -s /usr/sbin/nologin hypdmz-proxy

WORKDIR /app
COPY requirements.txt .
# Every package pinned to a version and the sha256 of its published files (pip-compile --generate-hashes);
# pip refuses anything that doesn't match. PYTHONDONTWRITEBYTECODE: the container's root filesystem is read-only.
ENV PYTHONDONTWRITEBYTECODE=1
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app/ ./app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /app/data/audit /app/config \
    && chown -R hypdmz-proxy:hypdmz-proxy /app/data

EXPOSE 8080 8002

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002", "--log-level", "warning"]
