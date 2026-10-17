#!/usr/bin/env python3
"""Wake-up latency diagnostics for sgd.

wakeup  The victim alone, natively and under sgd with synchronous wake-up on
        (default), off (-W) and with spinning (-S 200): what an occasional
        costed call costs and where the time goes.
fanin   The victim next to 16 fork workers under the uniform limiter and full
        SyscallGuard, each with synchronous wake-up on and off.

Every configuration gets --reps untraced runs (latency, run-queue wait, sgd
CPU and CPU migrations) and one run traced with tools/sg_wakeup_trace.py.
Tracing needs root; without it only the untraced runs are done.

    make all eval-bins
    sudo python3 eval/diagnose.py --label baremetal
    # -> eval/results/baremetal/diagnose.md and diagnose.json
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import run_eval as ev  # noqa: E402
from sg_wakeup_trace import SEGMENTS, Tracer  # noqa: E402

WAKEUP_CONFIGS = ["none", "sg-full", "sg-full-nosync", "sg-full-spin"]
FANIN_CONFIGS = ["uniform", "uniform-nosync", "sg-full", "sg-full-nosync"]

CONFIG_NOTES = {
    "none": "no sgd (native)",
    "sg-full": "sgd defaults (synchronous wake-up on)",
    "sg-full-nosync": "sgd -W (synchronous wake-up off)",
    "sg-full-spin": "sgd -S 200 (spinning; turns synchronous wake-up off)",
    "uniform": "uniform-cost limiter, synchronous wake-up on",
    "uniform-nosync": "uniform-cost limiter, -W",
}

SEGMENT_NOTES = {
    "total": "syscall entry to return, as the victim sees it",
    "seccomp": "inside seccomp: the whole round trip through sgd",
    "to_sgd": "entry until sgd has received the notification",
    "to_wakeup": "entry until sgd is woken",
    "filter": "seccomp filter, until the notification code starts",
    "notify": "notification code until the kernel starts waking sgd",
    "cpu_wake": "waking sgd: wake issued until sgd's CPU has taken it (remote/idle CPU cost)",
    "sgd_sched": "sgd woken until it runs",
    "sgd_to_recv": "sgd running until it asks for the notification (epoll return, loop)",
    "recv": "the NOTIF_RECV ioctl",
    "decide": "sgd's budget decision",
    "back": "sgd's reply until the victim continues in the kernel",
    "kernel": "the real syscall",
    "sgd_wake": "any sgd wake-up: woken until running",
    "victim_wake": "any victim wake-up: woken until running",
}


def trace_hook(env):
    return Tracer(governed=env.sgd is not None)


def run_configs(ctx, exp, configs, aggressors, victim_only, reps, traced):
    results = {}
    for config in configs:
        runs = []
        for rep in range(reps):
            runs.append(ev.contention_run(ctx, config, exp, aggressors, rep, victim_only=victim_only))
            print(f"  {exp} {config} run {rep + 1}/{reps}", flush=True)
        trace = None
        if traced:
            trace = ev.contention_run(ctx, config, exp, aggressors, reps, victim_only=victim_only, hook=trace_hook)
            print(f"  {exp} {config} traced run", flush=True)
        results[config] = {"runs": runs, "traced": trace}
    return results


def stat(values):
    return ev.stat([v for v in values if v is not None and v >= 0])


def runs_table(block, with_forks):
    head = "| config | victim p50 (µs) | victim p99 (µs) | victim run-queue wait (ms) |"
    sep = "|---|---|---|---|"
    if with_forks:
        head += " forks/s |"
        sep += "---|"
    head += " sgd CPU (s) | sgd CPU migrations |"
    sep += "---|---|"
    lines = [head, sep]
    for config, r in block.items():
        runs = r["runs"]
        rq = [x.get("victim", {}).get("rq_wait_us") for x in runs]
        row = (f"| {config} | {ev.show(stat(ev.get(runs, 'victim', 'p50_us')))} "
               f"| {ev.show(stat(ev.get(runs, 'victim', 'p99_us')))} "
               f"| {ev.show(stat([v / 1000 if v is not None and v >= 0 else None for v in rq]), 1)} |")
        if with_forks:
            row += f" {ev.show(stat(ev.get(runs, 'forker', 'forks_per_s')))} |"
        mig = [x.get("_sgd", {}).get("sched", {}).get("se.nr_migrations") for x in runs]
        row += (f" {ev.show(stat(ev.get(runs, '_sgd', 'cpu_s')), 2)} | {ev.show(stat(mig))} |")
        lines.append(row)
    return lines


def trace_table(block):
    configs = [c for c, r in block.items() if r["traced"] and r["traced"].get("_trace")]
    if not configs:
        return ["(no traced runs: tracing needs root and bpftrace)"]
    lines = ["Per costed call (openat/write) of the victim, p50 / p99 in µs, from the traced run:", "",
             "| stage | " + " | ".join(configs) + " | meaning |",
             "|---|" + "---|" * len(configs) + "---|"]
    for seg in SEGMENTS:
        cells, any_value = [], False
        for c in configs:
            s = block[c]["traced"]["_trace"]["segments"].get(seg)
            if s:
                any_value = True
                cells.append(f"{s['p50_us']:.1f} / {s['p99_us']:.1f}")
            else:
                cells.append("–")
        if any_value:
            lines.append(f"| {seg} | " + " | ".join(cells) + f" | {SEGMENT_NOTES.get(seg, '')} |")
    lines += ["", "Wake-ups on the waking CPU vs another CPU (counts):", "",
              "| config | sgd same CPU | sgd other CPU | victim same CPU | victim other CPU |",
              "|---|---|---|---|---|"]
    for c in configs:
        w = block[c]["traced"]["_trace"].get("where", {})
        lines.append(f"| {c} | {w.get('sgd_same_cpu', 0)} | {w.get('sgd_other_cpu', 0)} "
                     f"| {w.get('victim_same_cpu', 0)} | {w.get('victim_other_cpu', 0)} |")
    errors = [f"{c}: {block[c]['traced']['_trace']['error']}" for c in configs
              if block[c]["traced"]["_trace"].get("error")]
    if errors:
        lines += ["", "Tracer errors: " + "; ".join(errors)]
    return lines


def summarise(meta, results):
    lines = [f"# SyscallGuard wake-up diagnostics: {meta['label']}", "",
             f"Host `{meta['host']}`, kernel `{meta['kernel']}`, {meta['cpus']} CPUs, {meta['date']}. "
             f"{meta['reps']} untraced runs per configuration (mean ± sd) plus one traced run; victim "
             f"probe every {meta['interval_ms']} ms for {meta['duration'] - 1} s; costs `{meta['costs']}`.", ""]
    if meta.get("note"):
        lines += [meta["note"], ""]
    lines += ["Configurations: " + "; ".join(f"`{c}` = {CONFIG_NOTES[c]}" for c in CONFIG_NOTES), ""]
    if "wakeup" in results:
        lines += ["## Victim alone: wake-up cost of an occasional costed call", ""]
        lines += runs_table(results["wakeup"], with_forks=False) + [""]
        lines += trace_table(results["wakeup"]) + [""]
    if "fanin" in results:
        lines += ["## Victim next to 16 fork workers: synchronous wake-up on/off", ""]
        lines += runs_table(results["fanin"], with_forks=True) + [""]
        lines += trace_table(results["fanin"]) + [""]
    failed = ev.failed_jobs({k: {c: r["runs"] for c, r in v.items()} for k, v in results.items()})
    lines += ["## Failed runs", ""]
    lines += [f"- {f}" for f in failed] if failed else ["None: every job in every run exited with status 0."]
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--label", default=f"{platform.node()}-{platform.release()}")
    ap.add_argument("--only", help="wakeup, fanin or both (default)")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--interval-ms", type=int, default=10)
    ap.add_argument("--rate", type=int, default=200_000)
    ap.add_argument("--costs", help="calibrated cost file (default: the one in costs/ for this kernel; 'seed' = none)")
    ap.add_argument("--no-trace", action="store_true", help="skip the traced runs")
    args = ap.parse_args(argv)

    for name in ("sgd", "sg-launch", "victim", "fork_pressure"):
        if not os.path.exists(ev.bin_path(name)):
            sys.exit(f"missing build/{name}: run `make all eval-bins` first")
    only = {x.strip().lower() for x in args.only.split(",")} if args.only else {"wakeup", "fanin"}
    root = os.geteuid() == 0
    traced = root and not args.no_trace and shutil.which("bpftrace") is not None
    costs, cost_args = ev.find_costs(args.costs)
    work = tempfile.mkdtemp(prefix="sg-diag-", dir="/tmp")
    ctx = {"work": work, "reps": args.reps, "duration": args.duration, "rate": args.rate,
           "interval_ms": args.interval_ms, "cost_args": cost_args, "uniform_costs": ev.uniform_cost_file(work),
           "notes": {}}
    meta = {"label": args.label, "host": platform.node(), "kernel": platform.release(), "cpus": os.cpu_count(),
            "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "reps": args.reps, "duration": args.duration, "interval_ms": args.interval_ms,
            "costs": os.path.relpath(costs, ROOT) if costs != "seed" else "seed"}
    if not traced:
        meta["note"] = ("Tracing was skipped (" + ("--no-trace" if args.no_trace else
                        "needs root and bpftrace") + "): only the untraced tables are filled.")

    results = {}
    try:
        if "wakeup" in only:
            print("victim alone", flush=True)
            results["wakeup"] = run_configs(ctx, "wakeup", WAKEUP_CONFIGS, ev.e4_aggressors, True, args.reps, traced)
        if "fanin" in only:
            print("victim next to fork pressure", flush=True)
            results["fanin"] = run_configs(ctx, "fanin", FANIN_CONFIGS, ev.e4_aggressors, False, args.reps, traced)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    outdir = os.path.join(ROOT, "eval", "results", args.label)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "diagnose.json"), "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=1)
    summary = summarise(meta, results)
    with open(os.path.join(outdir, "diagnose.md"), "w") as f:
        f.write(summary)
    if root:
        owner = os.stat(ROOT)
        for p in (outdir, os.path.join(outdir, "diagnose.json"), os.path.join(outdir, "diagnose.md")):
            try:
                os.chown(p, owner.st_uid, owner.st_gid)
            except OSError:
                pass
    print(summary)
    print(f"\nwrote {os.path.relpath(outdir, ROOT)}/diagnose.md and diagnose.json")


if __name__ == "__main__":
    main()
