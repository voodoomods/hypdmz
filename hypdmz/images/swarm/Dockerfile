# The swarm container: hypswarm + hypgraph from PyPI, nothing else. Runs as the
# unprivileged `swarm` user (UID 1000), which the pod's egress floor keeps on
# loopback — every request the swarm makes goes to the proxy or nowhere.
# Pinned by digest (the multi-arch index of python:3.12-slim); see the proxy Dockerfile for how to update.
FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

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
