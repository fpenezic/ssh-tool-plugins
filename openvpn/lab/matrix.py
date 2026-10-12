#!/usr/bin/env python3
"""OpenVPN plugin regression matrix against a real OpenVPN 2.6 server.

Builds the plugin, a lab server image (Dockerfile + setup.sh here) and a
target web server, then runs each case: the plugin connects, fetches a
page (and files, checksummed) through its SOCKS proxy, optionally for a
while across renegotiations or a server restart.

    python3 lab/matrix.py              # every case (~15 minutes)
    python3 lab/matrix.py tls-crypt reneg-server

Needs Docker and curl. Everything listens on 127.0.0.1; the lab network
is 172.31.88.0/24 (server .2, target .10). Not run in CI.
"""
import os, re, shlex, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "_out")  # build output, configs, PKI (gitignored; "_" keeps go ./... out)
EXE = os.path.join(OUT, "ssh-tool-openvpn")
NET, SRV, TGT, IMG = "ovpnlab-net", "ovpnlab-srv", "ovpnlab-target", "ovpnlab"


def sh(cmd, check=True, **kw):
    return subprocess.run(cmd, shell=True, check=check, text=True, capture_output=True, **kw)


def setup():
    os.makedirs(os.path.join(OUT, "pki"), exist_ok=True)
    sh("cd %s/.. && CGO_ENABLED=0 go build -o %s ." % (shlex.quote(HERE), shlex.quote(EXE)))
    sh("docker build -q -t %s %s" % (IMG, shlex.quote(HERE)))
    sh("docker network create --subnet 172.31.88.0/24 %s" % NET, check=False)
    if TGT not in sh("docker ps --format '{{.Names}}'").stdout.split():
        sh("docker rm -f %s" % TGT, check=False)
        sh("docker run -d --name %s --network %s --ip 172.31.88.10 busybox:1.37 sh -c "
           "'echo hello-from-target > /index.html; head -c 31457280 /dev/urandom > /big; "
           "head -c 3000000 /big > /mid; httpd -f -p 80 -h /'" % (TGT, NET))
        time.sleep(1)
    # A compressible file, for the compression cases.
    sh("docker exec %s sh -c 'test -f /text || yes \"ssh-tool compresses this line well\" | head -c 3000000 > /text'" % TGT)
    sums = {}
    for f in ("big", "mid", "text"):
        sums[f] = sh("docker exec %s sha256sum /%s" % (TGT, f)).stdout.split()[0]
    # The first server start creates the PKI and the static key.
    run_server({})
    rd = lambda p: sh("docker exec %s cat %s" % (SRV, p)).stdout
    cert = sh("docker exec %s openssl x509 -in /pki/pki/issued/client.crt" % SRV).stdout
    blocks = ["<ca>\n%s</ca>" % rd("/pki/pki/ca.crt"), "<cert>\n%s</cert>" % cert,
              "<key>\n%s</key>" % rd("/pki/pki/private/client.key")]
    return blocks, rd("/pki/ta.key"), sums


def client(blocks, proto="udp", extra="", certs=True, port=None, **_):
    port = port or (11940 if proto == "udp" else 11941)
    out = "client\ndev tun\nnobind\nremote 127.0.0.1 %d %s\nremote-cert-tls server\n%s\n" % (port, proto, extra)
    for b in blocks:
        if not certs and (b.startswith("<cert>") or b.startswith("<key>")):
            continue
        out += b + "\n"
    return out


def run_server(env, proto="udp"):
    sh("docker rm -f %s" % SRV, check=False)
    port = "-p 127.0.0.1:11940:1194/udp" if proto == "udp" else "-p 127.0.0.1:11941:1194/tcp"
    envs = " ".join("-e %s=%s" % (k, shlex.quote(v)) for k, v in env.items())
    sh("docker run -d --name %s --cap-add NET_ADMIN --network %s --ip 172.31.88.2 %s -v %s:/pki %s %s"
       % (SRV, NET, port, shlex.quote(os.path.join(OUT, "pki")), envs, IMG))
    for _ in range(60):
        log = sh("docker logs %s 2>&1" % SRV, check=False).stdout
        if "Initialization Sequence Completed" in log:
            return
        if "Exiting" in log or "Options error" in log:
            raise SystemExit("server failed:\n" + log[-800:])
        time.sleep(0.5)
    raise SystemExit("server did not start")


def cases(ta):
    tlsauth = "<tls-auth>\n" + ta + "</tls-auth>\nkey-direction 1"
    tlscrypt = "<tls-crypt>\n" + ta + "</tls-crypt>"
    return {
        # name: (server env, client extra, seconds, user:pass, options)
        "plain-udp": ({}, "", 0, "", {}),
        "tls-auth": ({"MODE": "tls-auth"}, tlsauth, 0, "", {}),
        "tls-crypt": ({"MODE": "tls-crypt"}, tlscrypt, 0, "", {}),
        "tcp": ({"PROTO": "tcp"}, "", 0, "", {"proto": "tcp"}),
        "tcp-tls-crypt": ({"PROTO": "tcp", "MODE": "tls-crypt"}, tlscrypt, 0, "", {"proto": "tcp"}),
        "userpass": ({"USERPASS": "1"}, "auth-user-pass", 0, "test:test123", {}),
        "userpass-nocert": ({"USERPASS": "1", "EXTRA": "verify-client-cert none"}, "auth-user-pass", 0, "test:test123", {"certs": False}),
        "userpass-wrong": ({"USERPASS": "1"}, "auth-user-pass", 0, "test:wrong", {"expect": "auth-refused"}),
        "static-challenge": ({"USERPASS": "1"}, 'auth-user-pass\nstatic-challenge "Enter OTP" 1', 0, "test:test123", {}),
        "crv1": ({"USERPASS": "1", "CRV1": "1"}, "auth-user-pass", 0, "test:test123", {}),
        "pending-crtext": ({"PENDING": "crtext"}, "auth-user-pass", 0, "test:test123", {"expect": "crtext"}),
        "pending-webauth": ({"PENDING": "webauth"}, "auth-user-pass", 0, "test:test123", {"expect": "webauth"}),
        "x509-name": ({}, "verify-x509-name server name", 0, "", {}),
        "x509-name-wrong": ({}, "verify-x509-name other name", 0, "", {"expect": "x509-refused"}),
        "chacha": ({"CIPHERS": "CHACHA20-POLY1305"}, "", 0, "", {"big": True}),
        "aes128gcm": ({"CIPHERS": "AES-128-GCM"}, "", 0, "", {}),
        "cbc-sha256": ({"CIPHERS": "AES-256-CBC", "EXTRA": "auth SHA256"}, "auth SHA256", 0, "", {"big": True}),
        "cbc-sha1": ({"CIPHERS": "AES-128-CBC"}, "", 0, "", {}),
        "comp-lzo-no": ({"EXTRA": 'comp-lzo no\npush "comp-lzo no"'}, "comp-lzo no", 0, "", {}),
        "compress-stub": ({"EXTRA": 'compress stub\npush "compress stub"'}, "compress stub", 0, "", {}),
        "compress-stub-v2": ({"EXTRA": 'compress stub-v2\npush "compress stub-v2"'}, "compress stub-v2", 0, "", {}),
        "net30": ({"TOPO": "net30"}, "", 0, "", {}),
        "comp-lzo-yes": ({"EXTRA": 'allow-compression yes\ncomp-lzo yes\npush "comp-lzo yes"'}, "comp-lzo", 0, "", {"text": True}),
        "compress-lz4": ({"EXTRA": 'allow-compression yes\ncompress lz4\npush "compress lz4"'}, "compress lz4", 0, "", {"text": True}),
        "compress-lz4-v2": ({"EXTRA": 'allow-compression yes\ncompress lz4-v2\npush "compress lz4-v2"'}, "compress lz4-v2", 0, "", {"text": True}),
        "compress-lzo": ({"EXTRA": 'allow-compression yes\ncompress lzo\npush "compress lzo"'}, "compress lzo", 0, "", {"text": True}),
        "bulk-udp": ({}, "", 0, "", {"big": True}),
        "bulk-tcp": ({"PROTO": "tcp"}, "", 0, "", {"proto": "tcp", "big": True}),
        "failover": ({}, "", 0, "", {"first": "remote 127.0.0.1 11999 udp"}),
        "failover-blackhole": ({}, "", 0, "", {"first": "remote 192.0.2.1 1194 udp"}),
        "reneg-server": ({"RENEG": "20"}, "", 70, "", {}),
        "reneg-client": ({}, "reneg-sec 20", 70, "", {}),
        "reneg-wrap": ({"RENEG": "12"}, "", 120, "", {}),
        "reneg-tls-auth-userpass": ({"RENEG": "20", "MODE": "tls-auth", "USERPASS": "1"}, "auth-user-pass\n" + tlsauth, 50, "test:test123", {}),
        "auth-token": ({"RENEG": "20", "USERPASS": "1", "EXTRA": "auth-gen-token\nhand-window 10"}, "auth-user-pass", 70, "test:test123", {}),
        "restart-udp": ({"USERPASS": "1", "EXTRA": "auth-gen-token"}, "auth-user-pass", 110, "test:test123", {"restart": 20}),
        "restart-tcp": ({"PROTO": "tcp"}, "", 60, "", {"proto": "tcp", "restart": 20}),
        "lossy-reneg": ({"RENEG": "15", "MODE": "tls-crypt", "NETEM": "loss 3% delay 20ms 10ms"}, tlscrypt, 60, "", {"mid": True}),
    }


def main():
    blocks, ta, sums = setup()
    all_cases = cases(ta)
    names = sys.argv[1:] or list(all_cases)
    results = {}
    for name in names:
        env, extra, dur, user, opt = all_cases[name]
        proto = opt.get("proto", "udp")
        run_server(env, proto)
        conf = client(blocks, extra=extra, **opt)
        if opt.get("first"):
            conf = conf.replace("remote 127.0.0.1 11940 udp", opt["first"] + "\nremote 127.0.0.1 11940 udp")
        path = os.path.join(OUT, "case-%s.ovpn" % name)
        open(path, "w").write(conf)
        env2 = dict(os.environ)
        if opt.get("big"):
            env2["BIG"] = sums["big"]
        if opt.get("text"):
            env2["BIG"], env2["FILE"] = sums["text"], "text"
        if opt.get("mid"):
            env2["BIG"], env2["MID"] = sums["mid"], "1"
        if opt.get("restart"):
            env2["RESTART_AT"] = str(opt["restart"])
        print("=== %s" % name, flush=True)
        r = subprocess.run(["timeout", str(dur + 120), sys.executable, os.path.join(HERE, "run.py"), EXE, path, str(dur), user],
                           capture_output=True, text=True, env=env2)
        out = r.stdout + r.stderr
        ok = "RESULT PASS" in out
        if opt.get("expect") == "auth-refused":
            ok = "RESULT FAIL" in out and "authentication failed" in out and out.count("AUTH ") >= 2
        elif opt.get("expect") == "crtext":
            ok = ok and "AUTH Enter OTP" in out
        elif opt.get("expect") == "webauth":
            ok = ok and "OPEN_URL https://login.example.com/sso" in out
        elif opt.get("expect") == "x509-refused":
            ok = "RESULT FAIL" in out and "verify-x509-name" in out
        results[name] = "PASS" if ok else "FAIL"
        keep = [l for l in out.splitlines() if "peer info" not in l and ("ERR 20" not in l or re.search(r"reneg|fail|error|connected|challenge", l, re.I))]
        print("\n".join(keep[-14:]))
        if not ok:
            print(sh("docker logs --tail 15 %s 2>&1" % SRV, check=False).stdout)
        print("--- %s %s" % (name, results[name]), flush=True)
    sh("docker rm -f %s" % SRV, check=False)
    print("\nSUMMARY")
    for n, r in results.items():
        print("  %-26s %s" % (n, r))
    sys.exit(0 if all(r == "PASS" for r in results.values()) else 1)


if __name__ == "__main__":
    main()
