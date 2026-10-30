# Pinned by digest (the multi-arch index of alpine:3.19); see the proxy Dockerfile for how to update.
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1

RUN apk add --no-cache iptables ip6tables iproute2 bash curl socat

COPY entrypoint.sh      /controller/entrypoint.sh
COPY apply-lockdown.sh  /controller/apply-lockdown.sh
COPY inspect-network.sh /controller/inspect-network.sh

RUN chmod +x /controller/*.sh

CMD ["/controller/entrypoint.sh"]
