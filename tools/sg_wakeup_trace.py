#!/usr/bin/env python3
"""sg_wakeup_trace: where does a costed call's time go?

Traces the costed calls (openat, write) of a process named "victim" and
splits each into stages, using bpftrace:

    total        syscall entry ... the call returns (what the victim sees)
    seccomp      syscall entry ... seccomp lets the call continue
                 (for a governed call: the whole round trip through sgd)
    to_sgd       syscall entry ... sgd's NOTIF_RECV returns this notification,
                 split into:
      to_wakeup    syscall entry ... sgd is woken (sched_wakeup), split into
        filter       syscall entry ... the kernel's user-notification code starts
                     (only if seccomp_do_user_notification can be kprobed)
        notify       ... the kernel starts waking sgd (sched_waking, on the
                     notifying CPU)
        cpu_wake     sched_waking ... sched_wakeup: when sgd is woken on another
                     CPU, sched_wakeup is recorded only once that CPU has taken
                     the wake-up interrupt (and left idle), so this is the cost
                     of waking a remote, possibly idle, CPU
      sgd_sched    sgd woken ... sgd on a CPU (sched_switch)
      sgd_to_recv  sgd on a CPU ... sgd calls NOTIF_RECV (epoll returns, loop)
      recv         NOTIF_RECV call ... it returns
                 (the first three only when sgd was asleep when the call came)
    decide       sgd received it ... sgd calls NOTIF_SEND for it (the decision)
    back         sgd calls NOTIF_SEND ... the victim continues in the kernel
                 (mostly the victim waking up)
    kernel       the real syscall (raw_syscalls sys_enter ... sys_exit)
    sgd_wake     sgd woken ... sgd running (scheduling delay)
    victim_wake  victim woken ... victim running (scheduling delay)

Seccomp runs before the raw_syscalls:sys_enter tracepoint, so a governed
call's start is taken at kprobe:__secure_computing; for a native victim
(no seccomp) total equals kernel.

sgd and the victim are identified by process name ("sgd", "victim"), not
pid: under WSL2 or in a container the pids a process sees are not the ones
the tracepoints report. A notification is attributed to the victim when its
syscall is openat or write (read from sgd's own NOTIF_RECV buffer), and its
reply by notification id (from the NOTIF_SEND buffer), so no other governed
job may make openat/write calls while tracing (the fork-pressure job of
eval/diagnose.py only forks). Counts of the victim being woken on the
waker's CPU (what synchronous wake-up does) are reported as
where[same_cpu|other_cpu]. Needs root. Used by eval/diagnose.py; can also
trace a running sgd by hand:

    sudo python3 tools/sg_wakeup_trace.py --governed --seconds 10
"""

import argparse
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sg_calibrate import bucket_width, percentile_ns  # noqa: E402

SEGMENTS = ("total", "seccomp", "to_sgd", "to_wakeup", "filter", "notify", "cpu_wake", "sgd_sched",
            "sgd_to_recv", "recv", "decide", "back", "kernel", "sgd_wake", "victim_wake")


def notification_probe():
    """The kprobe name of seccomp_do_user_notification on this kernel (often .isra.N), or None."""
    try:
        out = subprocess.run(["bpftrace", "-l", "kprobe:seccomp_do_user_notification*"],
                             capture_output=True, text=True, timeout=60).stdout.split()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out[0] if out else None

# Syscall numbers the tracer needs, per architecture.
ARCH_NR = {
    "x86_64": {"openat": 257, "write": 1, "ioctl": 16},
    "aarch64": {"openat": 56, "write": 64, "ioctl": 29},
}


def ioc_wr(type_char, nr, size):
    """_IOWR(type, nr, size) as in <asm-generic/ioctl.h> (x86-64 and aarch64)."""
    return (3 << 30) | (size << 16) | (ord(type_char) << 8) | nr


# struct seccomp_notif is 80 bytes, struct seccomp_notif_resp 24 (<linux/seccomp.h>).
NOTIF_RECV = ioc_wr("!", 0, 80)
NOTIF_SEND = ioc_wr("!", 1, 24)


def bucket(name, expr):
    """bpftrace statements adding expr (ns) to the histogram and sum of segment name.

    Keys use the segment's index, not its name: (string, int) tuple keys of
    different string lengths fail the BPF verifier (misaligned stack access).
    """
    seg = SEGMENTS.index(name)
    return f"""
    $d = {expr};
    $b = $d / 1000000 * 1000000;
    if ($d < 1000000) {{ $b = $d / 10000 * 10000; }}
    if ($d < 10000) {{ $b = $d / 100 * 100; }}
    @seg[{seg}, $b] = count();
    @sum[{seg}] = sum($d);"""


def program(governed, arch=None, notif_probe=None):
    """The bpftrace program; governed=False traces a victim that runs without sgd.

    notif_probe: kprobe name of seccomp_do_user_notification (see
    notification_probe()), to split to_wakeup into filter and notify.
    """
    nr = ARCH_NR[arch or platform.machine()]
    calls = f"(args->id == {nr['openat']} || args->id == {nr['write']})"
    reset = """
    @vtid = (uint64)tid;
    @t0 = nsecs;
    @pending = 1;
    @t_ntf = (uint64)0;
    @t_wkg = (uint64)0;
    @t_wk = (uint64)0;
    @t_run = (uint64)0;
    @t_rin = (uint64)0;
    @t_recv = (uint64)0;
    @t_send = (uint64)0;"""
    if governed:
        # Every syscall of a seccomp-filtered task passes here before sys_enter.
        start = f"""
kprobe:__secure_computing
/comm == "victim"/
{{{reset}
}}

tracepoint:raw_syscalls:sys_enter
/comm == "victim" && @pending && {calls}/
{{
    @t_in = nsecs;
    @counted = 1;
}}
"""
        if notif_probe:
            start += f"""
{notif_probe}
/comm == "victim" && @pending && @t_ntf == 0/
{{
    @t_ntf = nsecs;
}}
"""
    else:
        start = f"""
tracepoint:raw_syscalls:sys_enter
/comm == "victim" && {calls}/
{{{reset}
    @t_in = @t0;
    @counted = 1;
}}
"""
    filter_block = ""
    if governed and notif_probe:
        filter_block = f"""
    if (@t_ntf) {{{bucket("filter", "@t_ntf - @t0")}
        if (@t_wkg > @t_ntf) {{{bucket("notify", "@t_wkg - @t_ntf")}
        }}
    }}"""
    text = start + f"""
tracepoint:raw_syscalls:sys_exit
/comm == "victim" && @counted && {calls}/
{{
    $now = nsecs;{bucket("total", "$now - @t0")}{bucket("kernel", "$now - @t_in")}
    if (@t_in > @t0) {{{bucket("seccomp", "@t_in - @t0")}
    }}
    if (@t_recv) {{{bucket("to_sgd", "@t_recv - @t0")}
        if (@t_send) {{{bucket("decide", "@t_send - @t_recv")}{bucket("back", "@t_in - @t_send")}
        }}
        if (@t_rin) {{{bucket("recv", "@t_recv - @t_rin")}
        }}
    }}
{filter_block}
    if (@t_wkg && @t_wk >= @t_wkg) {{{bucket("cpu_wake", "@t_wk - @t_wkg")}
    }}
    if (@t_wk) {{{bucket("to_wakeup", "@t_wk - @t0")}
        if (@t_run) {{{bucket("sgd_sched", "@t_run - @t_wk")}
            if (@t_rin > @t_run) {{{bucket("sgd_to_recv", "@t_rin - @t_run")}
            }}
        }}
    }}
    @pending = 0;
    @counted = 0;
}}

tracepoint:sched:sched_waking
{{
    /* Recorded on the waking CPU, before any wake-up interrupt. */
    $pid = (uint64)args->pid;
    if ((@sgdpid && $pid == @sgdpid) || (@vtid && $pid == @vtid)) {{
        @wkcpu[$pid] = cpu;
        if ($pid == @sgdpid && @pending && @t_wkg == 0) {{ @t_wkg = nsecs; }}
    }}
}}

tracepoint:sched:sched_wakeup
{{
    /* Read the tracepoint fields once: re-reading them after a branch fails the verifier. */
    $pid = (uint64)args->pid;
    $tcpu = (uint64)args->target_cpu;
    if ((@sgdpid && $pid == @sgdpid) || (@vtid && $pid == @vtid)) {{
        @wk[$pid] = nsecs;
        if ($pid == @sgdpid && @pending && @t_wk == 0) {{ @t_wk = nsecs; }}
        $same = $tcpu == @wkcpu[$pid];
        if ($pid == @vtid) {{
            if ($same) {{ @where["victim_same_cpu"] = count(); }}
            else {{ @where["victim_other_cpu"] = count(); }}
        }} else {{
            if ($same) {{ @where["sgd_same_cpu"] = count(); }}
            else {{ @where["sgd_other_cpu"] = count(); }}
        }}
    }}
}}

tracepoint:sched:sched_switch
{{
    $next = (uint64)args->next_pid;
    $woken = @wk[$next];
    if ($woken) {{
        if ($next == @sgdpid) {{{bucket("sgd_wake", "nsecs - $woken")}
            if (@pending && @t_wk && @t_run == 0) {{ @t_run = nsecs; }}
        }} else {{{bucket("victim_wake", "nsecs - $woken")}
        }}
        delete(@wk[$next]);
    }}
}}
"""
    if governed:
        text += f"""
tracepoint:raw_syscalls:sys_enter
/comm == "sgd"/
{{
    /* sgd's pid as the scheduler tracepoints see it (it differs inside WSL2 or a container) */
    @sgdpid = (uint64)pid;
}}

tracepoint:raw_syscalls:sys_enter
/comm == "sgd" && args->id == {nr['ioctl']} && (args->args[1] == {NOTIF_RECV} || args->args[1] == {NOTIF_SEND})/
{{
    $p = (uint64)args->args[2];
    @arg[tid] = $p;
    @cmd[tid] = args->args[1];
    if (args->args[1] == {NOTIF_RECV} && @pending && @t_rin == 0) {{ @t_rin = nsecs; }}
    if (args->args[1] == {NOTIF_SEND} && @pending && @t_recv && @t_send == 0) {{
        if (*(uint64 *)uptr($p) == @vid) {{ @t_send = nsecs; }}
    }}
}}

tracepoint:raw_syscalls:sys_exit
/comm == "sgd" && args->id == {nr['ioctl']} && @cmd[tid] == {NOTIF_RECV}/
{{
    if (args->ret == 0 && @pending && @t_recv == 0) {{
        $req = @arg[tid];
        /* struct seccomp_notif: id @0, pid @8, flags @12, data.nr @16 */
        $nr = *(int32 *)uptr($req + 16);
        if ($nr == {nr['openat']} || $nr == {nr['write']}) {{
            @t_recv = nsecs;
            @vid = *(uint64 *)uptr($req);
        }}
    }}
    delete(@cmd[tid]);
    delete(@arg[tid]);
}}
"""
    sgd_maps = " clear(@vid); clear(@arg); clear(@cmd);" if governed else ""
    if not governed:   # the sched probes read @sgdpid; define it so the program compiles
        text = "BEGIN { @sgdpid = (uint64)0; }\n" + text
    text += f"""
END
{{
    clear(@vtid); clear(@t0); clear(@t_in); clear(@pending); clear(@counted); clear(@t_recv);
    clear(@t_send); clear(@t_ntf); clear(@t_wkg); clear(@t_wk); clear(@t_run); clear(@t_rin); clear(@wk);
    clear(@wkcpu); clear(@sgdpid);{sgd_maps}
}}
"""
    return text


SEG_RE = re.compile(r"^@seg\[(\d+), (\d+)\]: (\d+)$")
SUM_RE = re.compile(r"^@sum\[(\d+)\]: (\d+)$")
WHERE_RE = re.compile(r"^@where\[(\w+)\]: (\d+)$")


def parse(text):
    """bpftrace output -> {"segments": {name: {count, mean_us, p50_us, p90_us, p99_us}}, "where": {...}}."""
    hist, sums, where = {}, {}, {}
    for line in text.splitlines():
        line = line.strip()
        m = SEG_RE.match(line)
        if m and int(m.group(1)) < len(SEGMENTS):
            hist.setdefault(SEGMENTS[int(m.group(1))], []).append((int(m.group(2)), int(m.group(3))))
            continue
        m = SUM_RE.match(line)
        if m and int(m.group(1)) < len(SEGMENTS):
            sums[SEGMENTS[int(m.group(1))]] = int(m.group(2))
            continue
        m = WHERE_RE.match(line)
        if m:
            where[m.group(1)] = int(m.group(2))
    segments = {}
    for name in SEGMENTS:
        buckets = sorted(hist.get(name, []))
        n = sum(c for _, c in buckets)
        if n == 0:
            continue
        segments[name] = {
            "count": n,
            "mean_us": sums.get(name, 0) / n / 1000.0,
            "p50_us": percentile_ns(buckets, 50) / 1000.0,
            "p90_us": percentile_ns(buckets, 90) / 1000.0,
            "p99_us": percentile_ns(buckets, 99) / 1000.0,
        }
    return {"segments": segments, "where": where}


class Tracer:
    """Context manager: attach bpftrace on enter, detach and parse on exit (.result)."""

    def __init__(self, governed):
        self.governed = governed
        self.result = None

    def __enter__(self):
        probe = notification_probe() if self.governed else None
        with tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False) as f:
            f.write(program(self.governed, notif_probe=probe))
            self.path = f.name
        env = dict(os.environ, BPFTRACE_MAX_MAP_KEYS="200000")
        self.proc = subprocess.Popen(["bpftrace", self.path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, env=env)
        first = self.proc.stdout.readline()
        if not first.startswith("Attaching"):
            self.proc.kill()
            _, err = self.proc.communicate()
            os.unlink(self.path)
            raise RuntimeError(f"bpftrace failed: {first.strip()} {err.strip()}")
        return self

    def __exit__(self, *exc):
        self.proc.send_signal(signal.SIGINT)
        out, err = self.proc.communicate(timeout=60)
        os.unlink(self.path)
        self.result = parse(out)
        if not self.result["segments"] and err.strip():
            self.result["error"] = err.strip()[-300:]
        return False


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--governed", action="store_true", help="the victim runs under sgd (omit for a native victim)")
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--print-program", action="store_true", help="print the bpftrace program and exit")
    args = ap.parse_args(argv)
    if args.print_program:
        print(program(args.governed, notif_probe=notification_probe() if args.governed else None))
        return
    if os.geteuid() != 0:
        sys.exit("sg_wakeup_trace needs root for bpftrace: run it with sudo")
    with Tracer(args.governed) as t:
        time.sleep(args.seconds)
    print(f"{'segment':<12} {'count':>7} {'mean':>9} {'p50':>9} {'p90':>9} {'p99':>9}   (µs)")
    for name, s in t.result["segments"].items():
        print(f"{name:<12} {s['count']:>7} {s['mean_us']:>9.1f} {s['p50_us']:>9.1f} {s['p90_us']:>9.1f} "
              f"{s['p99_us']:>9.1f}")
    print("victim woken on the waker's CPU:", t.result["where"])


if __name__ == "__main__":
    main()
