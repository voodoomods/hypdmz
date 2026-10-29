FROM python:3.12-slim

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
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /app/data/audit /app/config \
    && chown -R hypdmz-proxy:hypdmz-proxy /app/data

EXPOSE 8080 8002

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002", "--log-level", "warning"]
