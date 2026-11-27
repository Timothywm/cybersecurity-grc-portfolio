#!/usr/bin/env python3
"""Separate periodic check-ins from bulk uploads on a suspect TLS destination and report interval statistics.
  python3 tools/beacon_stats.py lab/raw/incident-01.pcap 127.10.2.10 127.66.6.6 8443
"""
import statistics as st, subprocess, sys
from collections import defaultdict

def streams(rows):
    d = defaultdict(lambda: [1e18, 0])
    for r in rows:
        s, t, ln = r.split("\t"); d[s][0] = min(d[s][0], float(t)); d[s][1] += int(ln)
    return sorted((v[0], v[1]) for v in d.values())

def stats(starts):
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    if len(gaps) < 2: return None
    m = st.mean(gaps); sd = st.stdev(gaps)
    return dict(n=len(starts), mean=m, sd=sd, cv=sd / m, lo=min(gaps), hi=max(gaps))

def main():
    pcap, src, dst, port = sys.argv[1:5]; thr = int(sys.argv[5]) if len(sys.argv) > 5 else 20000
    f = f"ip.src=={src} && ip.dst=={dst} && tcp.dstport=={port}"
    out = subprocess.run(["tshark", "-r", pcap, "-Y", f, "-T", "fields", "-e", "tcp.stream", "-e", "frame.time_relative", "-e", "frame.len"],
                         capture_output=True, text=True, check=True).stdout
    ss = streams([l for l in out.splitlines() if l.strip()])
    small = [t for t, b in ss if b < thr]; big = [t for t, b in ss if b >= thr]
    for name, grp in (("check-ins (<%d B upstream)" % thr, small), ("bulk uploads (>=%d B upstream)" % thr, big)):
        s = stats(grp)
        print(f"{name}: " + (f"n={s['n']} mean={s['mean']:.1f}s sd={s['sd']:.1f}s CV={s['cv']*100:.0f}% min={s['lo']:.1f}s max={s['hi']:.1f}s" if s else f"n={len(grp)}"))

if __name__ == "__main__":
    main()
