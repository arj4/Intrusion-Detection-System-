#!/usr/bin/env python3
import hashlib, json, queue, re, threading, time, sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import psutil
import scapy.all as sc
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

ALERT_PATH = Path("alerts.log")
PROTECTED_FILES = ["/etc/passwd", "/etc/shadow", str(Path.home() / ".ssh/authorized_keys")]
AUTH_LOG = "/var/log/auth.log" if sys.platform != "darwin" else "/private/var/log/asl.log"
FAILED_RE = re.compile(r"(Failed password|authentication failure)", re.I)
REVERSE_SHELL_RE = re.compile(r"/dev/tcp|nc.+-e|bash\s+-i\b", re.I)
BRUTE_FORCE_CNT, BRUTE_FORCE_WIN = 10, 60
SCAN_CNT, SCAN_WIN = 50, 5
SCAN_FLAGS = {0x02: "SYN", 0x00: "NULL", 0x01: "FIN", 0x29: "XMAS"}
q = queue.Queue()

def alert(atype, ts, **kw): q.put(dict(type=atype, ts=ts, **kw))

def sha256(p): h = hashlib.sha256(); h.update(Path(p).read_bytes()); return h.hexdigest()

def authlog_watcher():
    pos, cache = 0, defaultdict(list)
    while True:
        try:
            with open(AUTH_LOG, "r", errors="ignore") as fh:
                fh.seek(pos)
                for line in fh:
                    pos = fh.tell()
                    if FAILED_RE.search(line):
                        ts = time.time()
                        ip = line.split()[-4] if ":" in line.split()[-4] else "UNK"
                        cache[ip] = [t for t in cache[ip] if ts - t < BRUTE_FORCE_WIN]
                        cache[ip].append(ts)
                        if len(cache[ip]) >= BRUTE_FORCE_CNT:
                            alert("Brute-Force", ts, src_ip=ip, attempts=len(cache[ip]))
                            cache[ip].clear()
        except FileNotFoundError:
            pass
        time.sleep(1)

class IntegrityHandler(FileSystemEventHandler):
    def __init__(self, bl): self.bl = bl
    def on_modified(self, ev):
        if ev.is_directory or ev.src_path not in self.bl: return
        new = sha256(ev.src_path)
        if new != self.bl[ev.src_path]:
            alert("File Tamper", time.time(), path=ev.src_path)
            self.bl[ev.src_path] = new

def integrity_monitor():
    bl = {p: sha256(p) for p in PROTECTED_FILES if Path(p).exists()}
    ob = Observer(); hd = IntegrityHandler(bl)
    [ob.schedule(hd, path=p, recursive=False) for p in bl]
    ob.start(); ob.join()

def safe_listen_ports() -> set[int]:
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        # any failure → just skip this cycle
        return set()
    return {c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN}


def port_monitor():
    baseline = safe_listen_ports()
    while True:
        now = safe_listen_ports()
        for p in now - baseline:
            alert("New Port", time.time(), port=p)
            baseline.add(p)
        time.sleep(4)



def proc_monitor():
    seen = set()
    while True:
        for p in psutil.process_iter(attrs=["pid", "cmdline"]):
            if p.pid in seen:
                continue
            cmd = " ".join(p.info.get("cmdline") or [])   # <- safe join
            if REVERSE_SHELL_RE.search(cmd):
                alert("Reverse Shell",
                      time.time(),
                      pid=p.pid,
                      cmd=cmd[:120])
            seen.add(p.pid)
        time.sleep(3)


def scan_monitor():
    cache = defaultdict(list)
    def pkt(pkt):
        if not pkt.haslayer(sc.IP) or not pkt.haslayer(sc.TCP): return
        flags = int(pkt[sc.TCP].flags)
        if flags not in SCAN_FLAGS: return
        ts, src = time.time(), pkt[sc.IP].src
        cache[src] = [t for t in cache[src] if ts - t < SCAN_WIN]
        cache[src].append(ts)
        if len(cache[src]) >= SCAN_CNT:
            alert("Port Scan", ts, src_ip=src, technique=SCAN_FLAGS[flags], packets=len(cache[src]))
            cache[src].clear()
    sc.sniff(prn=pkt, filter="tcp", store=False)

def writer():
    with ALERT_PATH.open("a", buffering=1) as fh:
        while True:
            rec = q.get()
            rec["iso_time"] = datetime.fromtimestamp(rec["ts"]).isoformat(sep=" ", timespec="seconds")
            fh.write(json.dumps(rec) + "\n")
            print("[ALERT]", rec)

if __name__ == "__main__":
    ths = [
        threading.Thread(target=authlog_watcher, daemon=True),
        threading.Thread(target=integrity_monitor, daemon=True),
        threading.Thread(target=port_monitor, daemon=True),
        threading.Thread(target=proc_monitor, daemon=True),
        threading.Thread(target=scan_monitor, daemon=True),
        threading.Thread(target=writer, daemon=True),
    ]
    [t.start() for t in ths]
    print("Host IDS running:", ALERT_PATH.resolve())
    while True: time.sleep(60)
