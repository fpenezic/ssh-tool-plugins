#!/usr/bin/env python3
# Management-interface auth for the PENDING lab cases: every client login
# is held open with client-pending-auth, then
#   PENDING=crtext  asks "Enter OTP" (CR_TEXT) and accepts 123456,
#   PENDING=webauth sends a WEB_AUTH URL and accepts after 3 seconds
#                   (standing in for the user finishing a browser login).
import base64, os, socket, threading, time

MODE = os.environ.get("PENDING", "crtext")


def main():
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", 7505))
            break
        except OSError:
            time.sleep(0.2)
    f = s.makefile("rw", newline="\n")
    lock = threading.Lock()

    def cmd(line):
        with lock:
            f.write(line + "\n")
            f.flush()

    cur = {}
    for line in f:
        line = line.strip()
        if line.startswith(">CLIENT:CONNECT,") or line.startswith(">CLIENT:REAUTH,"):
            _, rest = line.split(":", 1)
            parts = rest.split(",")
            cur = {"cid": parts[1], "kid": parts[2]}
        elif line == ">CLIENT:ENV,END" and cur:
            cid, kid = cur["cid"], cur["kid"]
            if MODE == "crtext":
                cmd("client-pending-auth %s %s \"CR_TEXT:E,R:Enter OTP\" 60" % (cid, kid))
            else:
                cmd("client-pending-auth %s %s WEB_AUTH::https://login.example.com/sso?state=lab 60" % (cid, kid))
                threading.Timer(3, lambda c=cid, k=kid: cmd("client-auth-nt %s %s" % (c, k))).start()
            cur = {}
        elif line.startswith(">CLIENT:CR_RESPONSE,"):
            _, rest = line.split(":", 1)
            parts = rest.split(",")
            answer = base64.b64decode(parts[3]).decode()
            if answer == "123456":
                cmd("client-auth-nt %s %s" % (parts[1], parts[2]))
            else:
                cmd('client-deny %s %s "wrong code"' % (parts[1], parts[2]))


main()
