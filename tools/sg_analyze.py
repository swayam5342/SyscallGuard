#!/usr/bin/env python3
"""Summarise a SyscallGuard event log (written by `sgd -l events.jsonl`).

Computes admission wait-time percentiles, rejection rate per syscall class, budget
utilisation, borrowing (count, volume, repayment ratio) and Jain's fairness
index over per-job service normalised by priority weight.

Uses only the standard library; --plot additionally needs matplotlib
(sudo apt install python3-matplotlib).

    python3 tools/sg_analyze.py events.jsonl
    python3 tools/sg_analyze.py events.jsonl --jobs 2,3 --json
    python3 tools/sg_analyze.py events.jsonl --plot waits.png
"""

import argparse
import json
import math
import sys
from collections import defaultdict

FINAL_DECISIONS = ("ALLOW", "REJECT", "DROP")


def percentile(values, p):
    """Nearest-rank percentile of an already sorted list (0 if empty)."""
    if not values:
        return 0.0
    rank = max(1, math.ceil(p / 100.0 * len(values)))
    return values[rank - 1]


def jain(xs):
    """Jain's fairness index (sum x)^2 / (n * sum x^2).

    1 means every job got the same normalised service; 1/n means one job got
    all of it. None if there is nothing to compare.
    """
    xs = list(xs)
    if not xs:
        return None
    squares = sum(x * x for x in xs)
    if squares == 0:
        return 1.0
    return sum(xs) ** 2 / (len(xs) * squares)


def read_events(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"warning: {path}:{lineno}: skipping malformed line", file=sys.stderr)
    return events


def analyze(events, job_filter=None):
    """Turn raw events into a summary dict (see main() for the printed form)."""
    jobs = {}
    waits = defaultdict(list)                    # job -> admission waits (ms) of allowed calls
    by_class = defaultdict(lambda: [0, 0])       # class -> [final decisions, rejections]
    loans = {}
    sgd = {}

    def wanted(job):
        return job_filter is None or job in job_filter

    for ev in events:
        kind = ev.get("ev")
        job = ev.get("job")
        if kind in ("sgd_start", "sgd_stop"):
            sgd[kind] = ev
        elif kind == "job_start" and wanted(job):
            jobs[job] = {"name": ev["name"], "start_us": ev["t_us"], "end": None}
        elif kind == "job_end" and wanted(job):
            jobs.setdefault(job, {"name": ev["name"], "start_us": None})["end"] = ev
        elif kind == "call" and wanted(job):
            dec = ev["dec"]
            if dec == "ALLOW":
                waits[job].append(ev["wait_us"] / 1000.0)
            if dec in FINAL_DECISIONS:
                counts = by_class[ev.get("cls", "?")]
                counts[0] += 1
                counts[1] += dec == "REJECT"
        elif kind == "loan_open":
            loans[ev["loan"]] = {"from": ev["from"], "to": ev["to"], "amount": ev["amount"],
                                 "repaid": 0.0, "status": "open"}
        elif kind in ("loan_repaid", "loan_written_off"):
            loan = loans.setdefault(ev["loan"], {"from": ev["from"], "to": ev["to"], "amount": ev["amount"]})
            loan["repaid"] = ev["repaid"]
            loan["status"] = "repaid" if kind == "loan_repaid" else "written_off"
            loan["age_s"] = ev["age_us"] / 1e6

    rows = []
    for job_id in sorted(jobs):
        job = jobs[job_id]
        end = job["end"]
        if end is None:
            continue    # still running when the log was cut
        duration = (end["t_us"] - job["start_us"]) / 1e6 if job["start_us"] is not None else None
        w = sorted(waits[job_id])
        calls = end["calls"]
        entitled = end.get("entitled") or 0
        rows.append({
            "job": job_id,
            "name": job["name"],
            "prio": end["prio"],
            "duration_s": duration,
            "calls": calls,
            "allowed": end["allowed"],
            "waited": end["waited"],
            "rejected": end["rejected"],
            "dropped": end["dropped"],
            "waited_pct": 100.0 * end["waited"] / calls if calls else 0.0,
            "rejected_pct": 100.0 * end["rejected"] / calls if calls else 0.0,
            "wait_p50_ms": percentile(w, 50),
            "wait_p95_ms": percentile(w, 95),
            "wait_p99_ms": percentile(w, 99),
            "wait_max_ms": w[-1] if w else 0.0,
            "charged": end["charged"],
            "entitled": entitled,
            "utilisation": end["charged"] / entitled if entitled else None,
            "borrowed": end.get("borrowed", 0.0),
            "lent": end.get("lent", 0.0),
            # charged units per second per priority weight: equal for every job
            # when service is exactly proportional to priority
            "service_per_weight": end["charged"] / duration / end["prio"] if duration else None,
        })

    all_waits = sorted(x for job_id in jobs for x in waits[job_id])
    closed = [l for l in loans.values() if l["status"] != "open"]
    volume = sum(l["amount"] for l in loans.values())
    closed_volume = sum(l["amount"] for l in closed)
    repaid = [l for l in loans.values() if l["status"] == "repaid"]
    stop = sgd.get("sgd_stop")
    fair_inputs = [r["service_per_weight"] for r in rows if r["service_per_weight"] is not None]

    return {
        "config": sgd.get("sgd_start"),
        "jobs": rows,
        "overall": {
            "jobs": len(rows),
            "calls": sum(r["calls"] for r in rows),
            "rejected": sum(r["rejected"] for r in rows),
            "wait_p50_ms": percentile(all_waits, 50),
            "wait_p95_ms": percentile(all_waits, 95),
            "wait_p99_ms": percentile(all_waits, 99),
            "wait_max_ms": all_waits[-1] if all_waits else 0.0,
            "global_utilisation": (stop["charged"] / stop["global_entitled"]
                                   if stop and stop.get("global_entitled") else None),
            "jain_fairness": jain(fair_inputs),
        },
        "classes": {cls: {"decided": n, "rejected": r, "rejection_rate": r / n if n else 0.0}
                    for cls, (n, r) in sorted(by_class.items())},
        "loans": {
            "opened": len(loans),
            "repaid": len(repaid),
            "written_off": sum(1 for l in loans.values() if l["status"] == "written_off"),
            "open": sum(1 for l in loans.values() if l["status"] == "open"),
            "volume": volume,
            "repayment_ratio": (sum(l["repaid"] for l in closed) / closed_volume) if closed_volume else None,
            "mean_repay_s": (sum(l["age_s"] for l in repaid) / len(repaid)) if repaid else None,
        },
    }


def fmt(value, spec=".2f", none="-"):
    return none if value is None else format(value, spec)


def print_summary(s, out=sys.stdout):
    o = s["overall"]
    print(f"SyscallGuard run: {o['jobs']} jobs, {o['calls']} costed calls, {o['rejected']} rejected", file=out)
    cfg = s["config"]
    if cfg:
        print(f"config: global {cfg['global_rate']} units/s, burst {cfg['burst_ms']} ms, "
              f"T_max {cfg['tmax_ms']} ms, borrowing {'on' if cfg['borrowing'] else 'off'}", file=out)
    print(file=out)
    print(f"{'JOB':>4} {'NAME':<14} {'PRIO':>4} {'DUR_S':>7} {'CALLS':>8} {'WAIT%':>6} {'REJ%':>6} "
          f"{'P50_MS':>7} {'P95_MS':>7} {'P99_MS':>7} {'MAX_MS':>8} {'UTIL':>5} {'BORROW':>8} {'LENT':>8}",
          file=out)
    for r in s["jobs"]:
        print(f"{r['job']:>4} {r['name'][:14]:<14} {r['prio']:>4} {fmt(r['duration_s'], '.2f'):>7} "
              f"{r['calls']:>8} {r['waited_pct']:>6.1f} {r['rejected_pct']:>6.1f} "
              f"{r['wait_p50_ms']:>7.2f} {r['wait_p95_ms']:>7.2f} {r['wait_p99_ms']:>7.2f} "
              f"{r['wait_max_ms']:>8.2f} {fmt(r['utilisation']):>5} {r['borrowed']:>8.1f} {r['lent']:>8.1f}",
              file=out)
    print(file=out)
    print(f"Admission wait (all jobs): p50 {o['wait_p50_ms']:.2f} ms, p95 {o['wait_p95_ms']:.2f} ms, "
          f"p99 {o['wait_p99_ms']:.2f} ms, max {o['wait_max_ms']:.2f} ms", file=out)
    print("Rejection rate by class:", file=out)
    for cls, c in s["classes"].items():
        print(f"  {cls:<12} {100 * c['rejection_rate']:6.2f}%  ({c['rejected']} / {c['decided']})", file=out)
    l = s["loans"]
    print(f"Loans: {l['opened']} opened, {l['repaid']} repaid, {l['written_off']} written off, {l['open']} open; "
          f"volume {l['volume']:.2f} units; repayment ratio {fmt(l['repayment_ratio'])}; "
          f"mean time to repay {fmt(l['mean_repay_s'])} s", file=out)
    print(f"Global budget utilisation: {fmt(o['global_utilisation'], '.3f')}", file=out)
    print(f"Jain's fairness index (charged/s per priority weight, {len(s['jobs'])} jobs): "
          f"{fmt(o['jain_fairness'], '.3f')}", file=out)


def plot_waits(events, path, job_filter=None):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        sys.exit("--plot needs matplotlib (sudo apt install python3-matplotlib)")
    names, waits = {}, defaultdict(list)
    for ev in events:
        if job_filter is not None and ev.get("job") not in job_filter:
            continue
        if ev.get("ev") == "job_start":
            names[ev["job"]] = ev["name"]
        elif ev.get("ev") == "call" and ev["dec"] == "ALLOW":
            waits[ev["job"]].append(ev["wait_us"] / 1000.0)
    fig, ax = plt.subplots(figsize=(7, 4))
    for job, w in sorted(waits.items()):
        w.sort()
        ax.step(w, [(i + 1) / len(w) for i in range(len(w))], where="post",
                label=f"{job} {names.get(job, '')}")
    ax.set_xlabel("admission wait (ms)")
    ax.set_ylabel("fraction of admitted calls")
    ax.set_title("Admission wait CDF per job")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    print(f"wrote {path}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("log", help="JSON-lines event log from sgd -l")
    ap.add_argument("--jobs", help="comma-separated job ids to include (e.g. jobs that ran together)")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    ap.add_argument("--plot", metavar="PNG", help="also save an admission-wait CDF plot")
    args = ap.parse_args(argv)

    job_filter = {int(x) for x in args.jobs.split(",")} if args.jobs else None
    events = read_events(args.log)
    summary = analyze(events, job_filter)
    if args.json:
        json.dump(summary, sys.stdout, indent=2)
        print()
    else:
        print_summary(summary)
    if args.plot:
        plot_waits(events, args.plot, job_filter)


if __name__ == "__main__":
    main()
