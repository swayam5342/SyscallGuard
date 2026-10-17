# SyscallGuard evaluation: wsl2-6.6-v1

Host `Swayamp`, kernel `6.6.114.1-microsoft-standard-WSL2`, 10 CPUs, 2026-10-16 21:19 UTC. 3 repetitions per cell (mean ± standard deviation), runs of 10 s, global budget R_g = 200,000 units/s, costs: `costs/wsl2-6.6.conf`, extra sgd options: `-R 0 -W -k 0`.
cgroup baseline limits on the aggressors: `cpu.max=100000 100000`, `pids.max=32`, `io.max=8:80 wiops=200`.
Merged results: E5 re-run on 2026-10-16 21:19 UTC; others from 2026-10-16 20:59 UTC.

## E1 Per-call overhead

| path | ns per call |
|---|---|
| getppid, native | 69.2 ± 1.2 |
| getppid under sgd (in-kernel filter only, fast path) | 76.0 ± 0.3 |
| read 1 B, native | 101.5 ± 3.6 |
| read 1 B under sgd (round trip to the supervisor) | 27,564.1 ± 445.1 |

## E2 Build overhead (make -j4, unthrottled)

| config | build time (s) | slowdown | costed calls/s | sgd CPU (s) |
|---|---|---|---|---|
| none | 0.48 ± 0.03 | | | |
| sgd | 0.54 ± 0.11 | +12.0% | 22,380 ± 4,066 | 0.13 ± 0.01 |

## E3 Noisy neighbour

Victim (priority 8): open + 64 B write + close in the shared directory every 10 ms. Aggressors (priority 2): metadata storm (16 workers creating and unlinking files in the same directory), fsync flood (4 workers), cheap I/O (64 B read + write). Aggressor kernel CPU is the system time of all aggressor processes.

| config | victim p50 (µs) | victim p95 (µs) | victim p99 (µs) | storm ops/s | fsync ops/s | cheap ops/s | aggressor kernel CPU (s) | sgd CPU (s) | rejected calls |
|---|---|---|---|---|---|---|---|---|---|
| none-alone | 63 ± 1 | 89 | 127 ± 9 | – | – | – | – | – | – |
| sg-alone | 408 ± 54 | 669 ± 61 | 810 ± 35 | – | – | – | – | 0.15 ± 0.02 | 0 |
| none | 33 ± 1 | 8,367 ± 120 | 12,037 ± 82 | 134,703 ± 979 | 412 ± 3 | 4,104,901 ± 72,346 | 72.82 ± 0.42 | – | – |
| cgroup | 66 ± 5 | 185,609 ± 1,327 | 196,097 ± 4,318 | 5,630 ± 507 | 92 ± 8 | 358,442 ± 27,798 | 9.22 ± 0.02 | – | – |
| uniform | 78 ± 2 | 166 ± 46 | 349 ± 88 | 11,718 ± 25 | 2,898 ± 691 | 15,782 ± 81 | 10.50 ± 0.48 | 7.37 ± 0.18 | 0 |
| sg-noborrow | 108 ± 19 | 195 ± 7 | 355 ± 150 | 3,528 ± 17 | 26 | 8,845 ± 36 | 4.93 ± 0.11 | 3.53 ± 0.05 | 0 |
| sg-full | 98 ± 6 | 202 ± 58 | 331 ± 151 | 3,517 ± 6 | 26 ± 0 | 9,739 ± 17 | 4.67 ± 0.04 | 3.71 ± 0.07 | 0 |

## E4 Bounded fork pressure

16 workers fork a child that exits at once and reap it, in a loop (at most 33 processes).

| config | victim p99 (µs) | forks/s | fork EAGAIN | forker kernel CPU (s) | sgd CPU (s) |
|---|---|---|---|---|---|
| none | 601 ± 395 | 75,819 ± 769 | 0 | 45.06 ± 0.25 | – |
| cgroup | 141 ± 47 | 3,334 ± 114 | 10,062 ± 471 | 5.67 ± 0.12 | – |
| uniform | 722 ± 183 | 44,604 ± 98 | 224,316 ± 39,305 | 39.87 ± 0.24 | 5.10 ± 0.22 |
| sg-full | 180 ± 32 | 452 ± 1 | 990,462 ± 869 | 16.93 ± 0.09 | 9.88 ± 0.01 |

## E5 Borrowing

A fixed burst of work (dd, 10,000 records of 64 B, about 40,000 units) at priority 5 next to an idle priority-5 neighbour, R_g = 20,000 units/s, so the burst's share is half of that. Theory: about 3.0 s without borrowing; borrowing can save at most beta * H = 0.5 s.

| config | completed | time (s) | waited calls | loans | borrowed units |
|---|---|---|---|---|---|
| sg-noborrow | 3/3 | 3.09 ± 0.02 | 273 ± 17 | 0 | 0 |
| sg-full | 3/3 | 2.58 ± 0.01 | 221 ± 8 | 10,345 ± 198 | 17,027 ± 38 |

## Failed runs

None: every job in every run exited with status 0.
