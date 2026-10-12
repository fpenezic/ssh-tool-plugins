#!/bin/bash
# OpenVPN lab server. MODE: none | tls-auth | tls-crypt. USERPASS=1 adds
# auth-user-pass-verify (test/test123; static challenge SCRV1 answer
# 123456). EXTRA: extra server lines. PENDING=crtext|webauth: logins held
# open by mgmt.py (pending auth). NETEM: tc netem on the link. Keys persist
# in /pki.
set -e
cd /pki
if [ ! -f pki/ca.crt ]; then
  cp -r /usr/share/easy-rsa/* .
  ./easyrsa --batch init-pki
  EASYRSA_REQ_CN=lab-ca ./easyrsa --batch build-ca nopass
  ./easyrsa --batch build-server-full server nopass
  ./easyrsa --batch build-client-full client nopass
  openvpn --genkey secret ta.key
fi
mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
cat > /etc/ovpn-auth.sh <<'A'
#!/bin/sh
u=$(sed -n 1p "$1"); p=$(sed -n 2p "$1")
[ "$u" = test ] || exit 1
case "$p" in
  SCRV1:*)
    pw=$(echo "$p" | cut -d: -f2 | base64 -d); resp=$(echo "$p" | cut -d: -f3 | base64 -d)
    [ "$pw" = test123 ] && [ "$resp" = 123456 ] && exit 0; exit 1 ;;
  CRV1::*)
    resp=$(echo "$p" | awk -F'::' '{print $3}')
    [ "$resp" = 123456 ] && exit 0; exit 1 ;;
  test123)
    if [ "$CRV1" = 1 ]; then
      # dynamic challenge: deferred refusal with a CRV1 question
      echo "CRV1:R,E:st4te:$(printf test | base64):Enter the code from your token" > "$auth_failed_reason_file"
      echo 0 > "$auth_control_file"
      exit 2
    fi
    exit 0 ;;
esac
exit 1
A
[ "$CRV1" = 1 ] && sed -i "2i CRV1=1" /etc/ovpn-auth.sh
chmod +x /etc/ovpn-auth.sh
extra=""
case "$MODE" in
  tls-auth) extra="tls-auth /pki/ta.key 0" ;;
  tls-crypt) extra="tls-crypt /pki/ta.key" ;;
esac
auth=""
[ "$USERPASS" = 1 ] && auth="auth-user-pass-verify /etc/ovpn-auth.sh via-file
script-security 2
username-as-common-name"
cat > /server.conf <<C
port 1194
proto ${PROTO:-udp}
dev tun
ca /pki/pki/ca.crt
cert /pki/pki/issued/server.crt
key /pki/pki/private/server.key
dh none
topology ${TOPO:-subnet}
server 10.88.0.0 255.255.255.0
push "route 172.31.88.0 255.255.255.0"
push "dhcp-option DNS 172.31.88.53"
push "dhcp-option DOMAIN lab.example.com"
data-ciphers ${CIPHERS:-AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305}
reneg-sec ${RENEG:-3600}
keepalive 10 60
verb 3
$extra
$auth
${EXTRA:-}
C
if [ -n "$PENDING" ]; then
  # Logins go through mgmt.py (pending auth); see the file.
  printf 'management 127.0.0.1 7505\nmanagement-client-auth\n' >> /server.conf
  python3 /mgmt.py &
fi
iptables -t nat -A POSTROUTING -s 10.88.0.0/24 -j MASQUERADE || true
# NETEM: e.g. "loss 5% delay 20ms 10ms reorder 10%" on the link to clients
[ -n "$NETEM" ] && tc qdisc add dev eth0 root netem $NETEM
exec openvpn --config /server.conf
