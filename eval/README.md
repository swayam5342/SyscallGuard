# SyscallGuard evaluation

`run_eval.py` runs the experiments below and writes
`eval/results/<label>/summary.md` (tables) and `results.json` (every run's raw
numbers). With `python3-matplotlib` installed it also draws charts.

## Experiments

| | Workload | Question |
|---|---|---|
| E1 | `bench_syscall`: getppid (never costed) and 1-byte reads (costed) | What does one call cost natively, on the in-kernel fast path, and with a round trip to sgd? |
| E2 | `make -j4` of this project, unthrottled | How much does governance slow a real build? |
| E3 | `victim` (priority 8) next to `meta_storm` + `fsync_flood` + `cheap_io` (priority 2) | Does SyscallGuard protect a latency-sensitive job from a noisy neighbour, and what does cost weighting add over a uniform limiter? |
| E4 | `victim` next to `fork_pressure` (16 workers, bounded) | Is process creation contained, and at what cost? |
| E5 | a fixed `dd` burst (10,000 x 64 B) next to an idle job | How much does borrowing help a bursty job? |
| E6 | `make -j4` throttled to a quarter of its demand, under each fork policy | Does a throttled build complete? |

| Configuration | Meaning |
|---|---|
| `none` | no control |
| `cgroup` | aggressors in a cgroup v2 group with `cpu.max` (1 CPU), `io.max` (200 write IOPS), `pids.max` (32); only when run as root |
| `uniform` | sgd with every call costing 1 and no borrowing |
| `sg-noborrow` | sgd with calibrated costs and priorities, borrowing off |
| `sg-full` | full SyscallGuard (default fork policy `brief`) |
| `sg-full-reject`, `-brief`, `-wait` | full SyscallGuard with every job launched with that fork policy |
| `*-alone` | the victim alone, natively and under sgd (its baseline) |

Every workload is bounded: `fork_pressure` keeps at most 33 processes alive,
`meta_storm` reuses 64 file names per worker, `fsync_flood` overwrites a
1 MiB region per worker, and all of them stop after `--duration` seconds.

## Running it

Use a Linux machine or VM (4+ CPUs is better, because the aggressors need
to saturate the CPUs for E3 to show interference).

```sh
sudo apt install build-essential bpftrace python3-matplotlib
make && make test                  # everything should PASS
make calibrate                     # writes costs/$(uname -r).conf (root, ~10 s)
make eval-bins
sudo python3 eval/run_eval.py --label myhost     # ~15 minutes; root enables the cgroup baseline
```

Useful options: `--only E3,E4`, `--reps 5`, `--duration 20`, `--rate 100000`
(global budget R_g for E3/E4), `--costs FILE` (or `--costs seed`),
`--merge` (re-run some experiments into an existing label), and
`--sgd-extra "..."` (extra sgd options for every run, e.g. `-R 0 -W -k 0` to
switch off paced rejection, synchronous wake-up and chunked loans).

Check the "Failed runs" section at the end of each summary: apart from E6
under `reject`, every job should exit with status 0. Keep the machine
otherwise idle while it runs: everything is timing-sensitive.

## Wake-up diagnostics

`diagnose.py` measures what an occasional costed call costs and where the
time goes:

- **wakeup**: the victim alone, natively and under sgd with synchronous
  wake-up on, off (`-W`) and with spinning (`-S 200`);
- **fanin**: the victim next to 16 fork workers under the uniform limiter and
  full SyscallGuard, each with synchronous wake-up on and off.

Each configuration gets 3 untraced runs plus one run traced with
[tools/sg_wakeup_trace.py](../tools/sg_wakeup_trace.py), which splits every
costed call into stages (seccomp filter, waking sgd's CPU, sgd running,
decision, waking the victim, the real syscall). It takes about 7 minutes:

```sh
make && make eval-bins
sudo python3 eval/diagnose.py --label myhost
```

The results are in `eval/results/myhost/diagnose.md` and `diagnose.json`.
Close other programs first: CPU idle states are part of what is measured.

## Reading the results

- **E3** is the main result. Compare victim p95/p99 under `none` with the
  `*-alone` rows (how much the neighbour hurts) and with the governed rows
  (how much is recovered). Then compare `uniform` with `sg-noborrow`: same
  budget, same priorities, only the cost weighting differs, so the
  differences in fsync ops/s and aggressor kernel CPU are what cost
  weighting buys.
- **E1/E2** are the price: the round-trip time per costed call and the build
  slowdown.
- **E4**: the fork rate should be held at the job's budget whichever fork
  policy is used; with `reject`, the EAGAIN count shows how often the
  workers retried.
- **E5**: the burst should take about 3.0 s without borrowing, and borrowing
  can shorten it by at most 0.5 s.
- **E6**: builds under `reject` may fail; under `brief` and `wait` all should
  complete.
