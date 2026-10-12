import subprocess, json, sys, os, time, threading
# run.py EXE CONF [seconds] [user:pass] [target-url]: one plugin run for matrix.py.
# env: RESTART_AT=sec restarts the server, BIG=sha256 checks a download of
# FILE (big | mid | text; MID=1 also repeats it every 10 s).
EXE, CONF = sys.argv[1], sys.argv[2]
DUR = int(sys.argv[3]) if len(sys.argv) > 3 else 0
USER = sys.argv[4] if len(sys.argv) > 4 else ""
URL = sys.argv[5] if len(sys.argv) > 5 else "http://172.31.88.10/"
env = dict(os.environ, SSHTOOL_OVPN_CONFIG=open(CONF).read())
p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
t0 = time.time()
state = {"socks": None, "error": None, "auths": 0}
ready = threading.Event()
wlock = threading.Lock()

def send(obj):
    with wlock:
        p.stdin.write(json.dumps(obj) + "\n")
        p.stdin.flush()

def errs():
    for l in p.stderr:
        print("  ERR", l.rstrip(), flush=True)

def events():
    for line in p.stdout:
        ev = json.loads(line)
        e = ev["event"]
        if e == "auth":
            state["auths"] += 1
            print("  %5.1fs AUTH %s %s %s" % (time.time() - t0, ev.get("message"), ev.get("error"), [f["name"] for f in ev["fields"]]), flush=True)
            if state["auths"] > 3:
                send({"cmd": "cancel", "id": ev["id"]})
                continue
            u, _, pw = USER.partition(":")
            send({"cmd": "auth", "id": ev["id"], "values": {"username": u, "password": pw, "response": "123456"}})
        elif e == "open_url":
            print("  OPEN_URL %s" % ev["url"], flush=True)
        elif e == "info":
            i = ev["info"]
            print("  INFO", {k: i.get(k) for k in ("addresses", "routes", "cipher", "transport", "dns")}, flush=True)
        elif e == "ready":
            state["socks"] = ev["socks"]
            print("  READY %.1fs" % (time.time() - t0), flush=True)
            ready.set()
        elif e == "error":
            print("  ERROR", ev["error"], flush=True)
            state["error"] = ev["error"]
            ready.set()

threading.Thread(target=errs, daemon=True).start()
threading.Thread(target=events, daemon=True).start()

def curl():
    r = subprocess.run(["curl", "-s", "-m", "8", "--socks5-hostname", state["socks"], URL], capture_output=True, text=True)
    print("  %5.1fs CURL %r rc=%d" % (time.time() - t0, r.stdout.strip()[:40], r.returncode), flush=True)
    return r.returncode == 0

def big():
    want = os.environ.get("BIG")
    path = os.environ.get("FILE", "mid" if os.environ.get("MID") else "big")
    size = {"big": 30, "mid": 3, "text": 3}.get(path, 1)
    t = time.time()
    r = subprocess.run("curl -s -m 120 --socks5-hostname %s http://172.31.88.10/%s | sha256sum" % (state["socks"], path), shell=True, capture_output=True, text=True)
    got = r.stdout.split()[0] if r.stdout else ""
    dt = time.time() - t
    print("  BIG sha %s %.1fs %.2f MB/s" % ("OK" if got == want else "MISMATCH " + got[:12], dt, size / dt), flush=True)
    return got == want

ready.wait(timeout=80)
ok = False
if state["socks"] and not state["error"]:
    ok = curl()
    if os.environ.get("BIG"):
        ok = big() and ok
    end = time.time() + DUR
    rst = float(os.environ.get("RESTART_AT", "0"))
    last = ok
    while time.time() < end and not state["error"]:
        time.sleep(10)
        if rst and time.time() - t0 >= rst:
            print("  RESTARTING SERVER", flush=True)
            subprocess.run("docker restart -t 0 ovpnlab-srv >/dev/null", shell=True)
            rst = 0
        last = curl()
        if os.environ.get("MID"):
            last = big() and last
        if not os.environ.get("RESTART_AT"):
            ok = last and ok
    if os.environ.get("RESTART_AT"):
        ok = last
    if state["error"]:
        ok = False
try:
    p.stdin.close()
except Exception:
    pass
try:
    p.wait(timeout=10)
except Exception:
    p.kill()
print("RESULT", "PASS" if ok else "FAIL")
