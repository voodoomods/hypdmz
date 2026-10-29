FROM alpine:3.19

RUN apk add --no-cache iptables ip6tables iproute2 bash curl socat

COPY entrypoint.sh      /controller/entrypoint.sh
COPY apply-lockdown.sh  /controller/apply-lockdown.sh
COPY inspect-network.sh /controller/inspect-network.sh

RUN chmod +x /controller/*.sh

CMD ["/controller/entrypoint.sh"]
