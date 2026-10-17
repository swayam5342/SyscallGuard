# SyscallGuard evaluation: wsl2-6.6-v3

Host `Swayamp`, kernel `6.6.114.1-microsoft-standard-WSL2`, 10 CPUs, 2026-10-16 21:37 UTC. 3 repetitions per cell (mean ± standard deviation), runs of 10 s, global budget R_g = 200,000 units/s, costs: `costs/wsl2-6.6.conf`, extra sgd options: `none (defaults)`.
cgroup baseline limits on the aggressors: `cpu.max=100000 100000`, `pids.max=32`, `io.max=8:80 wiops=200`.

## E1 Per-call overhead

| path | ns per call |
|---|---|
| getppid, native | 72.0 ± 4.6 |
| getppid under sgd (in-kernel filter only, fast path) | 78.3 ± 4.5 |
| read 1 B, native | 97.3 ± 1.0 |
| read 1 B under sgd (round trip to the supervisor) | 15,849.2 ± 1,577.1 |

## E2 Build overhead (make -j4, unthrottled)

| config | build time (s) | slowdown | costed calls/s | sgd CPU (s) |
|---|---|---|---|---|
| none | 0.65 ± 0.10 | | | |
| sgd | 0.64 ± 0.07 | -2.5% | 18,792 ± 1,958 | 0.04 ± 0.01 |

## E3 Noisy neighbour

Victim (priority 8): open + 64 B write + close in the shared directory every 10 ms. Aggressors (priority 2): metadata storm (16 workers creating and unlinking files in the same directory), fsync flood (4 workers), cheap I/O (64 B read + write). Aggressor kernel CPU is the system time of all aggressor processes.

| config | victim p50 (µs) | victim p95 (µs) | victim p99 (µs) | storm ops/s | fsync ops/s | cheap ops/s | aggressor kernel CPU (s) | sgd CPU (s) | rejected calls |
|---|---|---|---|---|---|---|---|---|---|
| none-alone | 60 | 107 ± 33 | 164 ± 38 | – | – | – | – | – | – |
| sg-alone | 296 ± 16 | 477 ± 33 | 580 ± 48 | – | – | – | – | 0.10 ± 0.01 | 0 |
| none | 33 | 8,303 ± 36 | 12,050 ± 61 | 135,025 ± 1,104 | 405 ± 12 | 4,052,055 ± 150,128 | 73.16 ± 0.23 | – | – |
| cgroup | 67 ± 2 | 185,362 ± 3,507 | 195,877 ± 1,842 | 5,047 ± 227 | 88 ± 6 | 338,797 ± 15,336 | 9.25 ± 0.12 | – | – |
| uniform | 69 ± 1 | 151 ± 31 | 249 ± 118 | 12,843 ± 122 | 2,935 ± 1,003 | 16,363 ± 66 | 8.52 ± 0.42 | 2.46 ± 0.16 | 0 |
| sg-noborrow | 121 ± 23 | 222 ± 35 | 383 ± 213 | 3,521 ± 6 | 26 | 9,263 ± 52 | 4.91 ± 0.05 | 1.53 ± 0.02 | 0 |
| sg-full | 115 ± 11 | 198 ± 19 | 259 ± 23 | 3,518 ± 1 | 26 | 9,725 ± 10 | 4.96 ± 0.09 | 1.57 ± 0.02 | 0 |

## E4 Bounded fork pressure

16 workers fork a child that exits at once and reap it, in a loop (at most 33 processes).

| config | victim p99 (µs) | forks/s | fork EAGAIN | forker kernel CPU (s) | sgd CPU (s) |
|---|---|---|---|---|---|
| none | 109 ± 15 | 76,132 ± 692 | 0 | 44.91 ± 0.33 | – |
| cgroup | 116 ± 10 | 3,310 ± 342 | 9,587 ± 1,176 | 5.88 ± 0.14 | – |
| uniform | 1,566 ± 73 | 35,080 ± 257 | 0 | 29.82 ± 0.07 | 1.40 ± 0.02 |
| sg-full | 594 ± 142 | 452 ± 0 | 0 | 1.11 ± 0.05 | 0.19 ± 0.01 |
| sg-full-reject | 561 ± 28 | 450 ± 1 | 8,040 ± 32 | 1.23 ± 0.08 | 0.26 ± 0.01 |

## E5 Borrowing

A fixed burst of work (dd, 10,000 records of 64 B, about 40,000 units) at priority 5 next to an idle priority-5 neighbour, R_g = 20,000 units/s, so the burst's share is half of that. Theory: about 3.0 s without borrowing; borrowing can save at most beta * H = 0.5 s.

| config | completed | time (s) | waited calls | loans | borrowed units |
|---|---|---|---|---|---|
| sg-noborrow | 3/3 | 3.08 ± 0.01 | 297 | 0 | 0 |
| sg-full | 3/3 | 2.58 ± 0.00 | 241 ± 2 | 641 ± 31 | 17,339 ± 13 |

## E6 Throttled build under each fork policy

`make -j4` alone under R_g = 19,214 units/s (a quarter of its measured demand). reject = EAGAIN at once; brief = wait up to the bound (sgd -F, default 500 ms), then EAGAIN (the default); wait = wait up to T_max.

| fork policy | builds completed | build time (s) | waited calls | rejected calls |
|---|---|---|---|---|
| reject | 1/3 | 1.74 | 18 ± 16 | 3 ± 1 |
| brief | 3/3 | 1.97 ± 0.63 | 338 ± 39 | 0 |
| wait | 3/3 | 1.53 ± 0.00 | 381 ± 32 | 0 |

## Failed runs

Jobs that exited with a non-zero status (excluded where a table says so; failed builds under the reject policy in E6 are the effect E6 measures):

- E6/sg-full-reject/run 2/build: exit 2 (make: cc: Resource temporarily unavailable)
- E6/sg-full-reject/run 3/build: exit 2 (make: cc: Resource temporarily unavailable)
