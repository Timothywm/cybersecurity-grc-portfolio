#!/usr/bin/env python3
"""Correlate Snort alert_fast output with the attack timeline -> evidence/results.md (+ results.json).
Pure stdlib. Usage: analyze_alerts.py --alerts alert_fast.txt --timeline attack-timeline.csv --rules rules/local.rules
"""
import argparse, csv, json, re, sys, datetime as dt
from collections import Counter, defaultdict

ALERT = re.compile(
    r'^(?:(?P<yr>\d{2,4})/)?(?P<mo>\d\d)/(?P<dy>\d\d)-(?P<h>\d\d):(?P<mi>\d\d):(?P<s>\d\d)\.(?P<us>\d+)\s+'
    r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"?(?P<msg>.*?)"?\s+\[\*\*\]'
    r'.*?\{(?P<proto>[\w-]+)\}\s+(?P<src>\S+?)(?::(?P<sp>\d+))?\s+->\s+(?P<dst>\S+?)(?::(?P<dp>\d+))?\s*$')
TELEMETRY = {1000008}   # informational sids are not counted as detections/false positives

def parse_alerts(path, year, skew):
    out = []
    for line in open(path, errors="replace"):
        m = ALERT.match(line.strip())
        if not m: continue
        yr = int(m["yr"]) if m["yr"] else year
        yr = yr + 2000 if yr < 100 else yr
        t = dt.datetime(yr, int(m["mo"]), int(m["dy"]), int(m["h"]), int(m["mi"]), int(m["s"]), int(m["us"][:6].ljust(6, "0")))
        out.append(dict(ts=t.timestamp() + skew, sid=int(m["sid"]), rev=int(m["rev"]), msg=m["msg"],
                        proto=m["proto"], src=m["src"], dst=m["dst"], dp=m["dp"]))
    return out

def rule_names(path):
    names = {}
    for line in open(path):
        m = re.search(r'msg:"([^"]+)".*sid:(\d+)', line)
        if m and not line.lstrip().startswith("#"): names[int(m[2])] = m[1]
    return names

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", required=True); ap.add_argument("--timeline", required=True)
    ap.add_argument("--rules", required=True); ap.add_argument("--out", default="results.md")
    ap.add_argument("--tolerance", type=float, default=5.0, help="seconds around each scenario window")
    ap.add_argument("--skew", type=float, default=0.0, help="add to alert time if attacker/sensor clocks differ")
    ap.add_argument("--year", type=int, default=dt.datetime.now().year)
    a = ap.parse_args()

    alerts = parse_alerts(a.alerts, a.year, a.skew); names = rule_names(a.rules)
    rows = list(csv.DictReader(open(a.timeline)))
    res, attributed = [], set()
    for r in rows:
        s, e = float(r["start_epoch"]) - a.tolerance, float(r["end_epoch"]) + a.tolerance
        hit = [i for i, al in enumerate(alerts) if s <= al["ts"] <= e]
        attributed.update(hit)
        fired = sorted({alerts[i]["sid"] for i in hit})
        exp = sorted({int(x) for x in re.split(r"[;,]", r["expected_sids"]) if x.strip()})
        det = [x for x in fired if x not in TELEMETRY]
        t = r["type"]
        if t == "TP":
            verdict = "DETECTED" if exp and set(exp) <= set(fired) else ("PARTIAL" if set(exp) & set(fired) else "MISSED")
        elif t == "FP":
            verdict = "CLEAN (no alert)" if not det else "FALSE POSITIVE"
        elif t == "FN":
            verdict = "DETECTED (evasion failed)" if set(exp) & set(fired) else "MISSED (evasion succeeded)"
        elif t == "BLINDSPOT":
            payload_sids = {1000003, 1000006, 1000007}
            verdict = "BLIND SPOT CONFIRMED" if (set(fired) & TELEMETRY) and not (set(fired) & payload_sids) else \
                      ("ATTACK STILL DETECTED" if set(fired) & payload_sids else "NO TELEMETRY (check TLS proxy/ssl inspector)")
        else:
            verdict = "n/a"
        res.append(dict(scenario=r["scenario"], type=t, description=r["description"], expected=exp, fired=fired,
                        alerts=len(hit), verdict=verdict))

    per_sid = Counter(al["sid"] for al in alerts)
    srcs = Counter(al["src"].split(":")[0] if al["proto"] != "ICMP" else al["src"] for al in alerts)
    tp = [x for x in res if x["type"] == "TP"]; fp = [x for x in res if x["type"] == "FP"]
    fn = [x for x in res if x["type"] == "FN"]
    tp_det = sum(1 for x in tp if x["verdict"] == "DETECTED"); fp_cnt = sum(1 for x in fp if x["verdict"] == "FALSE POSITIVE")
    fn_miss = sum(1 for x in fn if x["verdict"].startswith("MISSED"))
    unattr = [alerts[i] for i in range(len(alerts)) if i not in attributed and alerts[i]["sid"] not in TELEMETRY]

    L = ["# Test Results (auto-generated)", "",
         f"_Generated {dt.datetime.now():%Y-%m-%d %H:%M} from `{a.alerts.split('/')[-1]}` ({len(alerts)} alerts) and `{a.timeline.split('/')[-1]}` ({len(rows)} scenarios)._", "",
         "## Summary", "", "| Metric | Value |", "|---|---|",
         f"| True-positive scenarios detected | **{tp_det}/{len(tp)}** |",
         f"| Benign scenarios that raised a false positive | **{fp_cnt}/{len(fp)}** |",
         f"| Evasion scenarios that went undetected (false negatives) | **{fn_miss}/{len(fn)}** |",
         f"| Alerts not attributable to any scenario | {len(unattr)} |", "",
         "## Scenario results", "", "| ID | Type | Description | Expected SIDs | Fired SIDs | Alerts | Verdict |", "|---|---|---|---|---|---|---|"]
    for x in res:
        L.append(f"| {x['scenario']} | {x['type']} | {x['description']} | {', '.join(map(str, x['expected'])) or '-'} | {', '.join(map(str, x['fired'])) or '-'} | {x['alerts']} | **{x['verdict']}** |")
    L += ["", "## Alerts per rule", "", "| SID | Rule | Alerts |", "|---|---|---|"]
    for sid in sorted(set(per_sid) | set(names)):
        L.append(f"| {sid} | {names.get(sid, '?')} | {per_sid.get(sid, 0)} |")
    L += ["", "## Top alert sources", "", "| Source | Alerts |", "|---|---|"] + [f"| {k} | {v} |" for k, v in srcs.most_common(5)]
    if unattr:
        L += ["", "## Unattributed alerts (investigate - possible noise or clock skew)", "", "| Time | SID | Source -> Dest |", "|---|---|---|"]
        L += [f"| {dt.datetime.fromtimestamp(u['ts']):%H:%M:%S} | {u['sid']} | {u['src']} -> {u['dst']} |" for u in unattr[:20]]
    open(a.out, "w").write("\n".join(L) + "\n")
    json.dump(dict(tp_detected=tp_det, tp_total=len(tp), fp=fp_cnt, fp_total=len(fp), fn_missed=fn_miss, fn_total=len(fn), scenarios=res),
              open(a.out.rsplit(".", 1)[0] + ".json", "w"), indent=2)
    print(f"TP {tp_det}/{len(tp)} | FP {fp_cnt}/{len(fp)} | FN {fn_miss}/{len(fn)} | wrote {a.out}")

if __name__ == "__main__":
    main()
