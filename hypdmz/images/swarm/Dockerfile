# The swarm container: hypswarm + hypgraph from PyPI, nothing else. Runs as the
# unprivileged `swarm` user (UID 1000), which the pod's egress floor keeps on
# loopback — every request the swarm makes goes to the proxy or nowhere.
FROM python:3.12-slim

ARG HYPSWARM_VERSION=0.1.0a11
ARG HYPGRAPH_VERSION=0.7.7

RUN apt-get update && apt-get install -y --no-install-recommends \
    gosu curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "hypswarm==${HYPSWARM_VERSION}" "hypgraph==${HYPGRAPH_VERSION}"

RUN groupadd -r swarm && useradd -r -g swarm -u 1000 -d /home/swarm -m swarm \
    && mkdir -p /records /work && chown swarm:swarm /records /work

COPY entrypoint.sh /entrypoint.sh
COPY probe_dns.py /usr/local/lib/hypdmz/probe_dns.py
# Code the swarm runs stays root-owned and not writable by it; the entrypoint re-checks.
RUN chmod 755 /entrypoint.sh \
    && chmod -R go-w /usr/local/lib/python3.12 /usr/local/bin /usr/local/lib/hypdmz /entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
