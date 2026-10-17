#!/usr/bin/env python3
"""SyscallGuard evaluation harness.

Runs every experiment under every configuration, repeats each run, and
writes eval/results/<label>/results.json plus summary.md (and PNG charts if
matplotlib is installed).

Experiments
  E1  per-call overhead: native vs filtered fast path vs round trip to sgd
  E2  build overhead: make -j4 natively vs under an unthrottled sgd
  E3  noisy neighbour: a priority-8 victim probe next to a metadata storm,
      an fsync flood and a cheap-I/O job (all priority 2)
  E4  bounded fork pressure: victim next to 16 fork+wait workers
  E5  borrowing: a fixed dd burst next to an idle neighbour
  E6  throttled make -j4 under each fork policy (reject, brief, wait)

Configurations
  none         no control
  cgroup       aggressors in a cgroup v2 group (cpu.max, io.max, pids.max); needs root
  uniform      sgd, every call costs 1, no borrowing (the uniform-cost ablation)
  sg-noborrow  sgd with calibrated costs and priorities, borrowing off
  sg-full      sgd with calibrated costs, priorities and borrowing
  sg-full-reject / -brief / -wait   sg-full with every job launched with that fork policy

    make all eval-bins
    python3 eval/run_eval.py                       # as a normal user: no cgroup baseline
    sudo python3 eval/run_eval.py --label vm       # everything
    python3 eval/run_eval.py --only E1,E3 --reps 1 --duration 5
"""

import argparse
import contextlib
import datetime
import json
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
CGROUP_ROOT = "/sys/fs/cgroup"

# Aggressor limits for the cgroup baseline.
CGROUP_CPU_MAX = "100000 100000"   # one CPU
CGROUP_PIDS_MAX = "32"
CGROUP_WIOPS = 200

UNTHROTTLED_RATE = 1_000_000_000   # sgd budget that never binds (overhead runs)

SGD_EXTRA = []   # --sgd-extra

SUMMARY_RE = re.compile(
    r"job (\d+) \((.*?)\) ended after ([\d.]+)s: calls=(\d+) allowed=(\d+) waited=(\d+) rejected=(\d+) "
    r"dropped=(\d+) charged=(\d+) max_wait_ms=([\d.]+) loans=(\d+) borrowed=(\d+) lent=(\d+)")


def bin_path(name):
    return os.path.join(BUILD, name)


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                return None
    return None


def run_staged(stages, workdir, timeout, background=()):
    """Start (delay_s, name, argv) jobs on schedule and wait for them.

    Jobs named in background are terminated once all the others have
    finished. Returns {name: result dict}: the job's last JSON line plus
    rc and wall_s.
    """
    t0 = time.monotonic()
    procs, files, started, ended = {}, {}, {}, {}
    for delay, name, argv in sorted(stages, key=lambda s: s[0]):
        pause = t0 + delay - time.monotonic()
        if pause > 0:
            time.sleep(pause)
        files[name] = (open(os.path.join(workdir, f"{name}.out"), "w+"),
                       open(os.path.join(workdir, f"{name}.stderr"), "w+"))
        started[name] = time.monotonic()
        procs[name] = subprocess.Popen([str(a) for a in argv], stdout=files[name][0], stderr=files[name][1])

    deadline = time.monotonic() + timeout
    foreground = [n for n in procs if n not in background]
    while any(n not in ended for n in foreground):
        for n in foreground:
            if n not in ended and procs[n].poll() is not None:
                ended[n] = time.monotonic()
        if time.monotonic() > deadline:
            for n in foreground:
                if n not in ended:
                    procs[n].kill()
            break
        time.sleep(0.01)
    for n in background:
        procs[n].terminate()
    results = {}
    for n, p in procs.items():
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        out_f, err_f = files[n]
        out_f.seek(0)
        err_f.seek(0)
        res = last_json(out_f.read()) or {}
        err = err_f.read().strip()
        out_f.close()
        err_f.close()
        res["rc"] = p.returncode
        res["wall_s"] = ended.get(n, time.monotonic()) - started[n]
        if p.returncode not in (0, None) and n not in background and err:
            res["stderr"] = err[-300:]
        results[n] = res
    return results


class Sgd:
    """An sgd instance for one run; reads its CPU time and job summaries."""

    def __init__(self, workdir, name, args):
        self.sock = os.path.join(workdir, f"{name}.sock")
        self.err_path = os.path.join(workdir, f"{name}.sgd.err")
        self.args = [str(a) for a in args] + SGD_EXTRA
        self.cpu_s = None
        self.sched = {}
        self.jobs = {}

    def __enter__(self):
        self.err = open(self.err_path, "w")
        self.proc = subprocess.Popen([bin_path("sgd"), "-s", self.sock, *self.args], stderr=self.err)
        for _ in range(500):
            if os.path.exists(self.sock):
                return self
            if self.proc.poll() is not None:
                break
            time.sleep(0.01)
        raise RuntimeError(f"sgd did not start: {open(self.err_path).read()}")

    def launch(self, prio, name, argv, rate=None, fork_policy=None):
        extra = ["-r", str(rate)] if rate else []
        if fork_policy:
            extra += ["-f", fork_policy]
        return [bin_path("sg-launch"), "-s", self.sock, "-p", str(prio), "-n", name, *extra, "--", *argv]

    def _cpu(self):
        with open(f"/proc/{self.proc.pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")

    def _sched(self):
        """CPU migrations and context switches of sgd (needs CONFIG_SCHED_DEBUG for migrations)."""
        out = {}
        with contextlib.suppress(OSError):
            with open(f"/proc/{self.proc.pid}/sched") as f:
                for line in f:
                    key, _, value = line.partition(":")
                    key = key.strip()
                    if key in ("se.nr_migrations", "nr_switches", "nr_voluntary_switches"):
                        out[key] = int(float(value))
        return out

    def __exit__(self, *exc):
        time.sleep(0.1)   # let the last job summaries arrive
        if self.proc.poll() is None:
            self.cpu_s = self._cpu()
            self.sched = self._sched()
            self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.err.close()
        with open(self.err_path) as f:
            for m in SUMMARY_RE.finditer(f.read()):
                self.jobs[m.group(2)] = {
                    "duration_s": float(m.group(3)), "calls": int(m.group(4)), "allowed": int(m.group(5)),
                    "waited": int(m.group(6)), "rejected": int(m.group(7)), "charged": int(m.group(9)),
                    "max_wait_ms": float(m.group(10)), "loans": int(m.group(11)),
                    "borrowed": int(m.group(12)), "lent": int(m.group(13)),
                }
        return False


def disk_device(path):
    """MAJ:MIN of the whole disk holding path (io.max rejects partitions), or None."""
    st = os.stat(path)
    sysdir = f"/sys/dev/block/{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    if not os.path.exists(sysdir):
        return None
    if os.path.exists(os.path.join(sysdir, "partition")):
        with open(os.path.join(os.path.dirname(os.path.realpath(sysdir)), "dev")) as f:
            return f.read().strip()
    return f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"


@contextlib.contextmanager
def cgroup(workdir, notes):
    path = os.path.join(CGROUP_ROOT, f"sg-eval-{os.getpid()}")
    os.mkdir(path)
    try:
        limits = {"cpu.max": CGROUP_CPU_MAX, "pids.max": CGROUP_PIDS_MAX}
        dev = disk_device(workdir)
        if dev:
            limits["io.max"] = f"{dev} wiops={CGROUP_WIOPS}"
        for key, value in limits.items():
            try:
                with open(os.path.join(path, key), "w") as f:
                    f.write(value)
                notes.setdefault("cgroup_limits", {})[key] = value
            except OSError as e:
                notes.setdefault("cgroup_errors", {})[key] = str(e)
        yield path
    finally:
        try:
            with open(os.path.join(path, "cgroup.procs")) as f:
                leftover = f.read().split()
            for pid in leftover:
                with open(os.path.join(CGROUP_ROOT, "cgroup.procs"), "w") as f:
                    f.write(pid)
        except OSError:
            pass
        for _ in range(50):
            try:
                os.rmdir(path)
                break
            except OSError:
                time.sleep(0.1)


class Env:
    """How one configuration wraps a job: wrap(prio, name, argv, aggressor)."""

    def __init__(self, wrap, sgd=None):
        self.wrap = wrap
        self.sgd = sgd


@contextlib.contextmanager
def environment(config, ctx, workdir, run_name, rate):
    """Suffixes: -nosync (sgd -W), -spin (sgd -S 200), then -brief/-wait/-reject (fork policy)."""
    fork, extra = None, []
    for suffix, opts in (("-nosync", ["-W"]), ("-spin", ["-S", "200"])):
        if config.endswith(suffix):
            config, extra = config[:-len(suffix)], opts
    for policy in ("brief", "wait", "reject"):
        if config.endswith("-" + policy):
            config, fork = config[:-len(policy) - 1], policy
    if config == "none":
        yield Env(lambda prio, name, argv, aggressor=False: argv)
    elif config == "cgroup":
        with cgroup(workdir, ctx["notes"]) as cg:
            def wrap(prio, name, argv, aggressor=False):
                if not aggressor:
                    return argv
                return ["sh", "-c", f'echo $$ > {cg}/cgroup.procs && exec "$@"', "sh", *argv]
            yield Env(wrap)
    else:
        args = ["-r", rate]
        if config == "uniform":
            args += ["-B", "-c", ctx["uniform_costs"]]
        elif config == "sg-noborrow":
            args += ["-B", *ctx["cost_args"]]
        elif config == "sg-full":
            args += ctx["cost_args"]
        else:
            raise ValueError(config)
        with Sgd(workdir, run_name, args + extra) as sgd:
            yield Env(lambda prio, name, argv, aggressor=False: sgd.launch(prio, name, argv, fork_policy=fork), sgd)


def fresh_dir(path):
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    return path


def e1_overhead(ctx):
    runs = {"native": [], "sgd": []}
    for _ in range(ctx["reps"]):
        argv = [bin_path("bench_syscall"), 2_000_000, 100_000]
        runs["native"].append(run_staged([(0, "bench", argv)], ctx["work"], 120)["bench"])
        with Sgd(ctx["work"], "e1", ["-r", UNTHROTTLED_RATE, *ctx["cost_args"]]) as sgd:
            res = run_staged([(0, "bench", sgd.launch(5, "bench", argv))], ctx["work"], 300)["bench"]
        res["sgd_cpu_s"] = sgd.cpu_s
        runs["sgd"].append(res)
    return runs


def build_tree(ctx):
    src = os.path.join(ctx["work"], "buildsrc")
    if not os.path.exists(src):
        os.makedirs(src)
        shutil.copytree(os.path.join(ROOT, "src"), os.path.join(src, "src"))
        shutil.copy(os.path.join(ROOT, "Makefile"), src)
    return ["make", "-s", "-C", src, "-B", "-j4", "all"]


def e2_build(ctx):
    make = build_tree(ctx)
    runs = {"native": [], "sgd": []}
    for _ in range(ctx["reps"]):
        runs["native"].append(run_staged([(0, "build", make)], ctx["work"], 600)["build"])
        with Sgd(ctx["work"], "e2", ["-r", UNTHROTTLED_RATE, *ctx["cost_args"]]) as sgd:
            res = run_staged([(0, "build", sgd.launch(5, "build", make))], ctx["work"], 600)["build"]
        res["sgd_cpu_s"] = sgd.cpu_s
        res["sgd_job"] = sgd.jobs.get("build")
        runs["sgd"].append(res)
    return runs


def contention_run(ctx, config, exp, aggressors, rep, victim_only=False, hook=None):
    """One run of a victim (priority 8) next to priority-2 aggressors.

    hook(env), if given, is a context manager entered after sgd starts and
    before any job starts (used to attach a tracer); its .result is stored
    under "_trace".
    """
    d = ctx["duration"]
    base = fresh_dir(os.path.join(ctx["work"], f"{exp}-{config}-{rep}"))
    shared = fresh_dir(os.path.join(base, "shared"))
    with environment(config, ctx, base, f"{exp}-{config}-{rep}", ctx["rate"]) as env:
        stages = []
        if not victim_only:
            for name, argv in aggressors(base, shared, d):
                stages.append((0, name, env.wrap(2, name, argv, aggressor=True)))
        victim = [bin_path("victim"), os.path.join(shared, "victim.dat"), d - 1, ctx["interval_ms"], "nosync"]
        stages.append((0.5, "victim", env.wrap(8, "victim", victim)))
        with (hook(env) if hook else contextlib.nullcontext()) as traced:
            res = run_staged(stages, base, d + 60)
    if env.sgd:
        res["_sgd"] = {"cpu_s": env.sgd.cpu_s, "jobs": env.sgd.jobs, "sched": env.sgd.sched}
    if hook:
        res["_trace"] = traced.result
    shutil.rmtree(base, ignore_errors=True)
    return res


def e3_aggressors(base, shared, d):
    flood = fresh_dir(os.path.join(base, "flood"))
    return [
        ("storm", [bin_path("meta_storm"), shared, d, 16]),
        ("flood", [bin_path("fsync_flood"), flood, d, 4, 4096]),
        ("cheap", [bin_path("cheap_io"), d]),
    ]


def e4_aggressors(base, shared, d):
    return [("forker", [bin_path("fork_pressure"), d, 16])]


def contention_experiment(ctx, exp, aggressors, configs, alone):
    runs = {}
    for config in (["none-alone", "sg-alone"] if alone else []) + configs:
        runs[config] = []
        for rep in range(ctx["reps"]):
            real = {"none-alone": "none", "sg-alone": "sg-full"}.get(config, config)
            runs[config].append(contention_run(ctx, real, exp, aggressors, rep, victim_only=config.endswith("-alone")))
            print(f"  {exp} {config} rep {rep + 1}/{ctx['reps']}", flush=True)
    return runs


E5_RATE = 20_000        # two priority-5 jobs, so the burst's share is 10,000 units/s
E5_RECORDS = 10_000     # 64 B read (1) + write (3) = 4 units each, ~40,000 units


def e5_borrowing(ctx):
    """A fixed amount of throttled work (no forks) next to an idle neighbour.

    With share r = 10,000 units/s and capacity C = r * H, it takes about
    (W - C) / r = 3 s. Borrowing lends at most beta * C at a time and is
    repaid from later refills, so it can save at most beta * H = 0.5 s.
    """
    burst = ["dd", "if=/dev/zero", "of=/dev/null", "bs=64", f"count={E5_RECORDS}", "status=none"]
    runs = {"rate": E5_RATE, "records": E5_RECORDS}
    for config in ("sg-noborrow", "sg-full"):
        runs[config] = []
        for rep in range(ctx["reps"]):
            base = fresh_dir(os.path.join(ctx["work"], f"e5-{config}-{rep}"))
            with environment(config, ctx, base, f"e5-{config}-{rep}", E5_RATE) as env:
                res = run_staged([
                    (0, "neighbour", env.wrap(5, "neighbour", ["sleep", "600"])),
                    (1.5, "burst", env.wrap(5, "burst", burst)),   # neighbour is idle by now
                ], base, 120, background={"neighbour"})
            res["_sgd"] = {"cpu_s": env.sgd.cpu_s, "jobs": env.sgd.jobs}
            runs[config].append(res)
            shutil.rmtree(base, ignore_errors=True)
            print(f"  E5 {config} rep {rep + 1}/{ctx['reps']}", flush=True)
    return runs


E6_CONFIGS = ("sg-full-reject", "sg-full-brief", "sg-full-wait")


def e6_throttled_build(ctx, demand):
    """make -j4 throttled to a quarter of its measured demand, under each fork policy."""
    make = build_tree(ctx)
    rate = max(1000, int(demand / 4))
    runs = {"rate": rate}
    for config in E6_CONFIGS:
        runs[config] = []
        for rep in range(ctx["reps"]):
            base = fresh_dir(os.path.join(ctx["work"], f"e6-{config}-{rep}"))
            with environment(config, ctx, base, f"e6-{config}-{rep}", rate) as env:
                res = run_staged([(0, "build", env.wrap(5, "build", make))], base, 600)
            res["_sgd"] = {"cpu_s": env.sgd.cpu_s, "jobs": env.sgd.jobs}
            runs[config].append(res)
            shutil.rmtree(base, ignore_errors=True)
            print(f"  E6 {config} rep {rep + 1}/{ctx['reps']}", flush=True)
    return runs


def stat(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    return statistics.mean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def show(s, digits=0):
    if s is None:
        return "–"
    mean, sd = s
    return f"{mean:,.{digits}f} ± {sd:,.{digits}f}" if sd else f"{mean:,.{digits}f}"


def get(runs, *path):
    out = []
    for r in runs:
        v = r
        for key in path:
            v = v.get(key) if isinstance(v, dict) else None
        out.append(v)
    return out


def summarise(results, meta):
    lines = [f"# SyscallGuard evaluation: {meta['label']}", ""]
    lines.append(f"Host `{meta['host']}`, kernel `{meta['kernel']}`, {meta['cpus']} CPUs, {meta['date']}. "
                 f"{meta['reps']} repetitions per cell (mean ± standard deviation), runs of {meta['duration']} s, "
                 f"global budget R_g = {meta['rate']:,} units/s, costs: `{meta['costs']}`, "
                 f"extra sgd options: `{meta.get('sgd_extra') or 'none (defaults)'}`.")
    if meta.get("cgroup_limits"):
        lims = ", ".join(f"`{k}={v}`" for k, v in meta["cgroup_limits"].items())
        lines.append(f"cgroup baseline limits on the aggressors: {lims}.")
    if meta.get("cgroup_errors"):
        lines.append(f"cgroup limits that could not be set: {meta['cgroup_errors']}.")
    if meta.get("skipped"):
        lines.append(f"Skipped: {'; '.join(meta['skipped'])}.")
    if meta.get("merged"):
        lines.append(f"Merged results: {meta['merged']}.")
    lines.append("")

    if "E1" in results:
        r = results["E1"]
        lines += ["## E1 Per-call overhead", "",
                  "| path | ns per call |", "|---|---|",
                  f"| getppid, native | {show(stat(get(r['native'], 'getppid_ns')), 1)} |",
                  f"| getppid under sgd (in-kernel filter only, fast path) | {show(stat(get(r['sgd'], 'getppid_ns')), 1)} |",
                  f"| read 1 B, native | {show(stat(get(r['native'], 'read_ns')), 1)} |",
                  f"| read 1 B under sgd (round trip to the supervisor) | {show(stat(get(r['sgd'], 'read_ns')), 1)} |",
                  ""]
    if "E2" in results:
        r = results["E2"]
        native, sg = stat(get(r["native"], "wall_s")), stat(get(r["sgd"], "wall_s"))
        slow = f"{100 * (sg[0] / native[0] - 1):+.1f}%" if native and sg else "–"
        calls = stat([j["calls"] / j["duration_s"] if j else None for j in get(r["sgd"], "sgd_job")])
        lines += ["## E2 Build overhead (make -j4, unthrottled)", "",
                  "| config | build time (s) | slowdown | costed calls/s | sgd CPU (s) |", "|---|---|---|---|---|",
                  f"| none | {show(native, 2)} | | | |",
                  f"| sgd | {show(sg, 2)} | {slow} | {show(calls)} | {show(stat(get(r['sgd'], 'sgd_cpu_s')), 2)} |", ""]
    if "E3" in results:
        lines += ["## E3 Noisy neighbour", "",
                  "Victim (priority 8): open + 64 B write + close in the shared directory every "
                  f"{meta['interval_ms']} ms. Aggressors (priority 2): metadata storm (16 workers creating and "
                  "unlinking files in the same directory), fsync flood (4 workers), cheap I/O (64 B read + write). "
                  "Aggressor kernel CPU is the system time of all aggressor processes.", "",
                  "| config | victim p50 (µs) | victim p95 (µs) | victim p99 (µs) | storm ops/s | fsync ops/s | "
                  "cheap ops/s | aggressor kernel CPU (s) | sgd CPU (s) | rejected calls |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for config, runs in results["E3"].items():
            ksys = [sum(r.get(a, {}).get("sys_s", 0) for a in ("storm", "flood", "cheap"))
                    if "storm" in r else None for r in runs]
            rej = [sum(j["rejected"] for j in r["_sgd"]["jobs"].values()) if "_sgd" in r else None for r in runs]
            lines.append(
                f"| {config} | {show(stat(get(runs, 'victim', 'p50_us')))} | {show(stat(get(runs, 'victim', 'p95_us')))} "
                f"| {show(stat(get(runs, 'victim', 'p99_us')))} | {show(stat(get(runs, 'storm', 'ops_per_s')))} "
                f"| {show(stat(get(runs, 'flood', 'ops_per_s')))} | {show(stat(get(runs, 'cheap', 'ops_per_s')))} "
                f"| {show(stat(ksys), 2)} | {show(stat(get(runs, '_sgd', 'cpu_s')), 2)} | {show(stat(rej))} |")
        lines.append("")
    if "E4" in results:
        lines += ["## E4 Bounded fork pressure", "",
                  "16 workers fork a child that exits at once and reap it, in a loop (at most 33 processes).", "",
                  "| config | victim p99 (µs) | forks/s | fork EAGAIN | forker kernel CPU (s) | sgd CPU (s) |",
                  "|---|---|---|---|---|---|"]
        for config, runs in results["E4"].items():
            lines.append(
                f"| {config} | {show(stat(get(runs, 'victim', 'p99_us')))} | {show(stat(get(runs, 'forker', 'forks_per_s')))} "
                f"| {show(stat(get(runs, 'forker', 'eagain')))} | {show(stat(get(runs, 'forker', 'sys_s')), 2)} "
                f"| {show(stat(get(runs, '_sgd', 'cpu_s')), 2)} |")
        lines.append("")
    if "E5" in results:
        r = results["E5"]
        lines += ["## E5 Borrowing", "",
                  f"A fixed burst of work (dd, {r['records']:,} records of 64 B, about {4 * r['records']:,} units) at "
                  f"priority 5 next to an idle priority-5 neighbour, R_g = {r['rate']:,} units/s, so the burst's "
                  "share is half of that. Theory: about 3.0 s without borrowing; borrowing can save at most "
                  "beta * H = 0.5 s.", "",
                  "| config | completed | time (s) | waited calls | loans | borrowed units |",
                  "|---|---|---|---|---|---|"]
        for config in ("sg-noborrow", "sg-full"):
            runs = r[config]
            ok = [x for x in runs if x.get("burst", {}).get("rc") == 0]
            jobs = [x["_sgd"]["jobs"].get("burst", {}) for x in ok]
            lines.append(f"| {config} | {len(ok)}/{len(runs)} | {show(stat(get(ok, 'burst', 'wall_s')), 2)} "
                         f"| {show(stat(get(jobs, 'waited')))} | {show(stat(get(jobs, 'loans')))} "
                         f"| {show(stat(get(jobs, 'borrowed')))} |")
        lines.append("")

    if "E6" in results:
        r = results["E6"]
        lines += ["## E6 Throttled build under each fork policy", "",
                  f"`make -j4` alone under R_g = {r['rate']:,} units/s (a quarter of its measured demand). "
                  "reject = EAGAIN at once; brief = wait up to the bound (sgd -F, default 500 ms), then "
                  "EAGAIN (the default); wait = wait up to T_max.", "",
                  "| fork policy | builds completed | build time (s) | waited calls | rejected calls |",
                  "|---|---|---|---|---|"]
        for config in E6_CONFIGS:
            runs = r.get(config, [])
            ok = [x for x in runs if x.get("build", {}).get("rc") == 0]
            jobs = [x["_sgd"]["jobs"].get("build", {}) for x in runs]
            lines.append(f"| {config.rsplit('-', 1)[1]} | {len(ok)}/{len(runs)} | {show(stat(get(ok, 'build', 'wall_s')), 2)} "
                         f"| {show(stat(get(jobs, 'waited')))} | {show(stat(get(jobs, 'rejected')))} |")
        lines.append("")

    failed = failed_jobs(results)
    lines += ["## Failed runs", ""]
    if failed:
        lines += ["Jobs that exited with a non-zero status (excluded where a table says so; failed builds under "
                  "the reject policy in E6 are the effect E6 measures):", ""]
        lines += [f"- {f}" for f in failed]
    else:
        lines.append("None: every job in every run exited with status 0.")
    lines.append("")
    return "\n".join(lines)


def failed_jobs(results):
    """'E5/sg-full/run 1/burst: exit 2 (...)' for every job that did not exit 0."""
    out = []
    for exp, v in results.items():
        for config, runs in v.items():
            if not isinstance(runs, list):
                continue
            for i, run in enumerate(runs):
                for job, res in run.items():
                    if job.startswith("_") or job == "neighbour" or not isinstance(res, dict):
                        continue
                    if res.get("rc") not in (0, None):
                        why = res.get("stderr", "").strip().splitlines()
                        out.append(f"{exp}/{config}/run {i + 1}/{job}: exit {res['rc']}"
                                   + (f" ({why[0][:80]})" if why else ""))
    return out


def plot(results, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return []
    made = []
    if "E3" in results:
        configs = list(results["E3"])
        fig, ax = plt.subplots(figsize=(8, 4))
        for i, pct in enumerate(("p50_us", "p95_us", "p99_us")):
            vals = [stat(get(results["E3"][c], "victim", pct)) for c in configs]
            ax.bar([x + i * 0.27 for x in range(len(configs))], [v[0] if v else 0 for v in vals], 0.27,
                   yerr=[v[1] if v else 0 for v in vals], label=pct.replace("_us", ""))
        ax.set_xticks([x + 0.27 for x in range(len(configs))], configs, rotation=20)
        ax.set_yscale("log")
        ax.set_ylabel("victim latency (µs)")
        ax.set_title("E3 noisy neighbour: victim latency")
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, "e3_victim_latency.png"), dpi=150)
        made.append("e3_victim_latency.png")
    return made


def find_costs(arg):
    if arg == "seed":
        return "seed", []
    if arg:
        return arg, ["-c", arg]
    for name in sorted(os.listdir(os.path.join(ROOT, "costs"))) if os.path.isdir(os.path.join(ROOT, "costs")) else []:
        path = os.path.join(ROOT, "costs", name)
        with open(path) as f:
            head = f.read(400)
        if f"kernel {platform.release()}," in head:
            return path, ["-c", path]
    sys.exit("no calibration file for this kernel in costs/: run `make calibrate`, or pass --costs FILE "
             "(or --costs seed)")


def uniform_cost_file(workdir):
    out = subprocess.run([bin_path("sgd"), "-L"], check=True, capture_output=True, text=True).stdout
    path = os.path.join(workdir, "uniform.conf")
    with open(path, "w") as f:
        f.write("# uniform-cost limiter: every costed call costs 1\n")
        for line in out.splitlines()[1:]:
            f.write(f"{line.split()[1]} 1\n")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--label", default=f"{platform.node()}-{platform.release()}", help="results directory name")
    ap.add_argument("--only", help="comma-separated experiments, e.g. E1,E3")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--duration", type=int, default=10, help="seconds per contention run (default 10)")
    ap.add_argument("--rate", type=int, default=200_000, help="global budget R_g for E3/E4 (default 200000)")
    ap.add_argument("--interval-ms", type=int, default=10, help="victim probe interval (default 10)")
    ap.add_argument("--costs", help="calibrated cost file (default: the one in costs/ for this kernel; 'seed' = none)")
    ap.add_argument("--workdir", default="/tmp", help="scratch directory on a local disk (default /tmp)")
    ap.add_argument("--sgd-extra", default="",
                    help='extra sgd options for every run, e.g. "-R 0 -W -k 0" to reproduce v1 behaviour')
    ap.add_argument("--merge", action="store_true",
                    help="keep the other experiments already in this label's results.json")
    args = ap.parse_args(argv)
    SGD_EXTRA.extend(args.sgd_extra.split())

    for name in ("sgd", "sg-launch", "victim", "meta_storm", "fsync_flood", "cheap_io", "fork_pressure",
                 "bench_syscall"):
        if not os.path.exists(bin_path(name)):
            sys.exit(f"missing build/{name}: run `make all eval-bins` first")

    only = ({x.strip().upper() for x in args.only.split(",")} if args.only
            else {"E1", "E2", "E3", "E4", "E5", "E6"})
    root = os.geteuid() == 0
    costs, cost_args = find_costs(args.costs)
    work = tempfile.mkdtemp(prefix="sg-eval-", dir=args.workdir)
    notes = {}
    ctx = {"work": work, "reps": args.reps, "duration": args.duration, "rate": args.rate,
           "interval_ms": args.interval_ms, "cost_args": cost_args, "uniform_costs": uniform_cost_file(work),
           "notes": notes}
    meta = {"label": args.label, "host": platform.node(), "kernel": platform.release(), "cpus": os.cpu_count(),
            "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "reps": args.reps, "duration": args.duration, "rate": args.rate, "interval_ms": args.interval_ms,
            "costs": os.path.relpath(costs, ROOT) if costs != "seed" else "seed", "skipped": [],
            "sgd_extra": args.sgd_extra}
    configs = ["none", "uniform", "sg-noborrow", "sg-full"]
    if root:
        configs.insert(1, "cgroup")
    else:
        meta["skipped"].append("cgroup baseline (needs root)")

    results = {}
    try:
        if "E1" in only:
            print("E1 per-call overhead", flush=True)
            results["E1"] = e1_overhead(ctx)
        if "E2" in only or "E6" in only:   # E6 is sized from the build's measured demand
            print("E2 build overhead", flush=True)
            results["E2"] = e2_build(ctx)
        if "E3" in only:
            print("E3 noisy neighbour", flush=True)
            results["E3"] = contention_experiment(ctx, "e3", e3_aggressors, configs, alone=True)
        if "E4" in only:
            print("E4 bounded fork pressure", flush=True)
            results["E4"] = contention_experiment(
                ctx, "e4", e4_aggressors, [c for c in configs if c != "sg-noborrow"] + ["sg-full-reject"],
                alone=False)
        if "E5" in only:
            print("E5 borrowing", flush=True)
            results["E5"] = e5_borrowing(ctx)
        if "E6" in only:
            print("E6 throttled build", flush=True)
            jobs = [j for j in get(results["E2"]["sgd"], "sgd_job") if j]
            results["E6"] = e6_throttled_build(ctx, statistics.mean(j["charged"] / j["duration_s"] for j in jobs))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    meta.update(notes)
    outdir = os.path.join(ROOT, "eval", "results", args.label)
    os.makedirs(outdir, exist_ok=True)
    previous = os.path.join(outdir, "results.json")
    if args.merge and os.path.exists(previous):
        with open(previous) as f:
            old = json.load(f)
        merged = dict(old["results"])
        merged.update(results)
        results = {k: merged[k] for k in ("E1", "E2", "E3", "E4", "E5", "E6") if k in merged}
        meta["merged"] = f"{', '.join(sorted(only))} re-run on {meta['date']}; others from {old['meta']['date']}"
        for key in ("cgroup_limits", "cgroup_errors"):
            if key in old["meta"] and key not in meta:
                meta[key] = old["meta"][key]
    with open(os.path.join(outdir, "results.json"), "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=1)
    summary = summarise(results, meta)
    charts = plot(results, outdir)
    if charts:
        summary += "\n" + "\n".join(f"![{c}]({c})" for c in charts) + "\n"
    with open(os.path.join(outdir, "summary.md"), "w") as f:
        f.write(summary)
    if root:
        owner = os.stat(ROOT)
        for dirpath, _, files in os.walk(outdir):
            for p in [dirpath, *(os.path.join(dirpath, x) for x in files)]:
                with contextlib.suppress(OSError):
                    os.chown(p, owner.st_uid, owner.st_gid)
    print(summary)
    print(f"\nwrote {os.path.relpath(outdir, ROOT)}/summary.md and results.json")


if __name__ == "__main__":
    main()
