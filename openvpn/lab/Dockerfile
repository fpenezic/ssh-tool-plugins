FROM alpine:3.22
RUN apk add --no-cache openvpn easy-rsa openssl iptables bash iproute2 iproute2-tc python3
COPY setup.sh /setup.sh
COPY mgmt.py /mgmt.py
ENTRYPOINT ["/bin/bash","/setup.sh"]
