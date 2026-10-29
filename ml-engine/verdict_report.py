#!/usr/bin/env python3
"""
verdict_report.py — one line per verdict, with the fields that explain WHY a
verdict was ATTACK or NORMAL. Run it after (or during) a test case.

  python3 verdict_report.py                 # everything currently in the stream
  python3 verdict_report.py --last 40       # only the last 40 verdicts
  python3 verdict_report.py --since 10:29:40 --until 10:30:20   # local time window
  python3 verdict_report.py --follow        # keep printing new verdicts

Columns
  time    local time the verdict was published
  verdict ATTACK / NORMAL
  final   final score (what the mitigation service thresholds on)
  net/pkt Line-1 anomaly score of the network / packet modality
  esc     1 = Line 1 escalated this case to Line 2
  l2      1 = Line 2 classifiers were run
  l2net/l2pkt  Line-2 attack probability (>= 0.5 => ATTACK)
  pktdata 1 = a packet flow was fused in (0 = network-only fallback)
  src_ip  source of the fused packet flow (empty when no packet data)
  reason  Line-1 fusion reason
"""
import argparse, json, time
from datetime import datetime
import redis

def hhmmss(s):
    h, m, sec = (s.split(":") + ["0", "0"])[:3]
    now = datetime.now()
    return now.replace(hour=int(h), minute=int(m), second=int(sec), microsecond=0).timestamp()

def f(x, w=5):
    if x in (None, "", "None"):
        return "-".rjust(w)
    try:
        return f"{float(x):.3f}".rjust(w)
    except ValueError:
        return str(x).rjust(w)

def short_reason(r):
    r = r or ""
    r = r.replace("escalated: ", "ESC: ").replace("network above its own boundary", "net>bnd")
    r = r.replace("packet above its own boundary", "pkt>bnd").replace("combined weighted score above combined boundary", "comb>bnd")
    r = r.replace("below all escalation boundaries", "no-escalation")
    r = r.replace("packet score unavailable in window -- network-only fallback", "net-only fallback")
    return r[:44]

def row(mid, d):
    try:
        det = json.loads(d.get("details", "{}"))
    except Exception:
        det = {}
    ts = float(d.get("timestamp", 0) or 0)
    return ts, (
        f"{datetime.fromtimestamp(ts).strftime('%H:%M:%S')}  {d.get('verdict','?'):<6}  "
        f"{f(d.get('final_score'))}  {f(d.get('line1_network_score'))} {f(d.get('line1_packet_score'))}  "
        f"{d.get('line1_escalated','?'):>3} {d.get('line2_invoked','?'):>2}  "
        f"{f(det.get('line2_network_prob'))} {f(det.get('line2_packet_prob'))}  "
        f"{d.get('packet_data_available','?'):>7}  {(d.get('src_ip') or '-'):<13} {short_reason(det.get('fusion_reason'))}"
    )

HEADER = ("time      verdict  final    net   pkt  esc l2  l2net l2pkt  pktdata src_ip        reason\n"
          + "-" * 118)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost"); ap.add_argument("--port", type=int, default=6379)
    ap.add_argument("--last", type=int); ap.add_argument("--since"); ap.add_argument("--until")
    ap.add_argument("--follow", action="store_true")
    a = ap.parse_args()
    r = redis.Redis(host=a.host, port=a.port, decode_responses=True)
    since = hhmmss(a.since) if a.since else None
    until = hhmmss(a.until) if a.until else None

    items = r.xrange("verdicts", "-", "+")
    if a.last:
        items = items[-a.last:]
    print(HEADER)
    n_att = 0
    for mid, d in items:
        ts, line = row(mid, d)
        if (since and ts < since) or (until and ts > until):
            continue
        n_att += d.get("verdict") == "ATTACK"
        print(line)
    print(f"\n{len(items)} verdict(s) read, {n_att} ATTACK in the printed window.")
    if a.follow:
        last = items[-1][0] if items else "$"
        while True:
            for _s, msgs in r.xread({"verdicts": last}, block=5000) or []:
                for mid, d in msgs:
                    last = mid; print(row(mid, d)[1])

if __name__ == "__main__":
    main()
