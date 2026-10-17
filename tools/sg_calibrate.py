#!/usr/bin/env python3
"""sg_calibrate: measure syscall latency with eBPF and write a cost table for sgd.

Attaches bpftrace to the raw_syscalls:sys_enter/sys_exit tracepoints, records
a latency histogram per syscall while a workload runs, and converts the
median latency of every costed syscall into cost units (1 unit = 1 us,
minimum 1). Thread creation (clone with CLONE_THREAD, and clone3) is
measured separately as "clone_thread".

Needs root for bpftrace. Enforcement with the resulting file does not.

    sudo python3 tools/sg_calibrate.py -o costs/host.conf               # built-in workload
    sudo python3 tools/sg_calibrate.py -o costs/host.conf -- make -j4   # your own workload
    sudo python3 tools/sg_calibrate.py -o costs/host.conf -d 10         # trace 10 s of host activity
    ./build/sgd -c costs/host.conf ...

Latency is wall time from syscall entry to exit, so a call that blocks
(e.g. a read on an empty pipe) includes its sleep. The median and a
workload that does not block keep this small.
"""

import argparse
import datetime
import os
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import time

CLONE_THREAD = 0x10000
CLONE3_NR = 435             # same on x86-64 and aarch64
THREAD_ID = 1_000_000       # pseudo syscall id for thread creation
MIN_SAMPLES = 20

BPF_PROGRAM = r"""
tracepoint:raw_syscalls:sys_enter
{
    $id = args->id;
    if ($id == %(clone_nr)d && (args->args[0] & %(clone_thread)d)) {
        $id = %(thread_id)d;
    }
    if ($id == %(clone3_nr)d) {
        $id = %(thread_id)d;
    }
    @start[tid] = nsecs;
    @id[tid] = $id;
}

tracepoint:raw_syscalls:sys_exit
/@start[tid]/
{
    $ns = nsecs - @start[tid];
    /* 100 ns buckets below 10 us, 10 us buckets below 1 ms, 1 ms above */
    $b = $ns / 1000000 * 1000000;
    if ($ns < 1000000) {
        $b = $ns / 10000 * 10000;
    }
    if ($ns < 10000) {
        $b = $ns / 100 * 100;
    }
    @lat[@id[tid], $b] = count();
    delete(@start[tid]);
    delete(@id[tid]);
}

END
{
    clear(@start);
    clear(@id);
}
"""


def bucket_width(start_ns):
    if start_ns < 10_000:
        return 100
    if start_ns < 1_000_000:
        return 10_000
    return 1_000_000


def parse_bpftrace(text):
    """'@lat[257, 1200]: 34' lines -> {syscall id: [(bucket start ns, count), ...]}."""
    hist = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("@lat["):
            continue
        try:
            key, count = line[len("@lat["):].split("]:")
            sid, start = (int(x) for x in key.split(","))
            hist.setdefault(sid, []).append((start, int(count)))
        except ValueError:
            continue
    for buckets in hist.values():
        buckets.sort()
    return hist


def percentile_ns(buckets, p):
    """p-th percentile of a sorted bucketed histogram, interpolated inside its bucket."""
    total = sum(c for _, c in buckets)
    if total == 0:
        return None
    target = total * p / 100.0
    seen = 0
    for start, count in buckets:
        if seen + count >= target:
            return start + bucket_width(start) * (target - seen) / count
        seen += count
    return float(buckets[-1][0])


def median_ns(buckets):
    """Median of a bucketed histogram, interpolated linearly inside the median bucket."""
    return percentile_ns(buckets, 50)


def cost_units(median):
    """Median ns -> whole microseconds, rounding halves up (not to even), minimum 1."""
    return max(1, int(median / 1000.0 + 0.5))


def read_table(sgd):
    """Costed syscalls from `sgd -L`: [(nr, name, seed)], including clone_thread."""
    out = subprocess.run([sgd, "-L"], check=True, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines()[1:]:
        nr, name, _cls, seed, _cost = line.split()
        rows.append((int(nr), name, int(seed)))
    return rows


def builtin_workload(seconds):
    """A mix that exercises every cost class without blocking."""
    import mmap
    import threading

    deadline = time.monotonic() + seconds
    rounds = 0
    with tempfile.TemporaryDirectory(prefix="sg-calib-") as d:
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(64)
        addr = srv.getsockname()
        while time.monotonic() < deadline:
            path = os.path.join(d, f"f{rounds % 8}")
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            os.write(fd, b"x" * 4096)
            if rounds % 16 == 0:
                os.fsync(fd)
                os.fdatasync(fd)
            os.close(fd)
            fd = os.open(path, os.O_RDONLY)
            os.read(fd, 4096)
            os.pread(fd, 512, 0)
            os.close(fd)
            os.rename(path, path + ".r")
            os.unlink(path + ".r")
            os.mkdir(path + ".d")
            os.rmdir(path + ".d")
            m = mmap.mmap(-1, 1 << 20)
            m.close()
            c = socket.socket()
            c.connect(addr)
            s, _ = srv.accept()
            c.sendall(b"ping")
            s.recv(16)
            s.close()
            c.close()
            if rounds % 32 == 0:
                subprocess.run(["/bin/true"], check=False)
                t = threading.Thread(target=lambda: None)
                t.start()
                t.join()
                pid = os.fork()
                if pid == 0:
                    os._exit(0)
                os.waitpid(pid, 0)
            rounds += 1
        srv.close()
    return f"built-in mix, {rounds} rounds in {seconds:g} s"


def trace(program, workload):
    env = dict(os.environ, BPFTRACE_MAX_MAP_KEYS="200000")
    with tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False) as f:
        f.write(program)
        prog_path = f.name
    try:
        proc = subprocess.Popen(["bpftrace", prog_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env)
        first = proc.stdout.readline()          # "Attaching N probes..."
        if not first.startswith("Attaching"):
            proc.kill()
            _, err = proc.communicate()
            sys.exit(f"bpftrace failed to start: {first.strip()} {err.strip()}")
        try:
            desc = workload()
        finally:
            proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=120)
    finally:
        os.unlink(prog_path)
    if proc.returncode not in (0, -signal.SIGINT):
        sys.exit(f"bpftrace exited with {proc.returncode}: {err.strip()}")
    return out, desc


def build_rows(table, hist):
    """[(name, cost or None, median ns or None, samples, seed)] in table order."""
    rows = []
    for nr, name, seed in table:
        sid = THREAD_ID if name == "clone_thread" else nr
        buckets = hist.get(sid, [])
        samples = sum(c for _, c in buckets)
        med = median_ns(buckets) if samples >= MIN_SAMPLES else None
        rows.append((name, cost_units(med) if med is not None else None, med, samples, seed))
    return rows


def write_cost_file(path, rows, desc):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with open(path, "w", encoding="utf-8") as f:
        f.write("# SyscallGuard cost table, generated by tools/sg_calibrate.py\n")
        f.write(f"# host {platform.node()}, kernel {platform.release()}, {platform.machine()}, {now}\n")
        f.write(f"# workload: {desc}\n")
        f.write("# 1 unit = 1 us of median syscall latency (minimum 1); syscalls with fewer than\n")
        f.write(f"# {MIN_SAMPLES} samples are left out and keep their seed cost.\n")
        f.write(f"# {'name':<14} {'cost':>6} {'median_ns':>10} {'samples':>9} {'seed':>5}\n")
        for name, cost, med, samples, seed in rows:
            if cost is not None:
                f.write(f"{name:<16} {cost:>6} {med:>10.0f} {samples:>9} {seed:>5}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--output", required=True, help="cost file to write")
    ap.add_argument("-d", "--duration", type=float, default=5.0,
                    help="seconds to run the built-in workload, or to trace if --idle (default 5)")
    ap.add_argument("--idle", action="store_true", help="no workload: trace whatever runs on the host")
    ap.add_argument("--sgd", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "sgd"),
                    help="sgd binary, used to read the costed syscall table")
    ap.add_argument("command", nargs="*", help="workload command (after --) instead of the built-in mix")
    args = ap.parse_args(argv)

    if os.geteuid() != 0:
        sys.exit("sg_calibrate needs root for bpftrace: run it with sudo")

    table = read_table(args.sgd)
    clone_nr = next(nr for nr, name, _ in table if name == "clone")
    program = BPF_PROGRAM % {"clone_nr": clone_nr, "clone_thread": CLONE_THREAD,
                             "clone3_nr": CLONE3_NR, "thread_id": THREAD_ID}

    if args.command:
        def workload():
            rc = subprocess.run(args.command, check=False).returncode
            return f"{' '.join(args.command)} (exit {rc})"
    elif args.idle:
        def workload():
            time.sleep(args.duration)
            return f"host activity for {args.duration:g} s"
    else:
        def workload():
            return builtin_workload(args.duration)

    out, desc = trace(program, workload)
    rows = build_rows(table, parse_bpftrace(out))
    write_cost_file(args.output, rows, desc)

    print(f"workload: {desc}")
    print(f"{'NAME':<14} {'SEED':>5} {'COST':>6} {'MEDIAN_US':>10} {'SAMPLES':>9}")
    for name, cost, med, samples, seed in rows:
        print(f"{name:<14} {seed:>5} {cost if cost is not None else '-':>6} "
              f"{med / 1000 if med is not None else 0:>10.2f} {samples:>9}")
    print(f"wrote {args.output} ({sum(1 for r in rows if r[1] is not None)} calibrated syscalls)")


if __name__ == "__main__":
    main()
