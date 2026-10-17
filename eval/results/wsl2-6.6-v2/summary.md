# SyscallGuard evaluation: wsl2-6.6-v2

Host `Swayamp`, kernel `6.6.114.1-microsoft-standard-WSL2`, 10 CPUs, 2026-10-16 21:19 UTC. 3 repetitions per cell (mean ± standard deviation), runs of 10 s, global budget R_g = 200,000 units/s, costs: `costs/wsl2-6.6.conf`, extra sgd options: `none (defaults)`.
cgroup baseline limits on the aggressors: `cpu.max=100000 100000`, `pids.max=32`, `io.max=8:80 wiops=200`.
Merged results: E5 re-run on 2026-10-16 21:19 UTC; others from 2026-10-16 21:05 UTC.

## E1 Per-call overhead

| path | ns per call |
|---|---|
| getppid, native | 69.6 ± 2.9 |
| getppid under sgd (in-kernel filter only, fast path) | 76.9 ± 1.3 |
| read 1 B, native | 101.4 ± 1.3 |
| read 1 B under sgd (round trip to the supervisor) | 16,735.9 ± 151.2 |

## E2 Build overhead (make -j4, unthrottled)

| config | build time (s) | slowdown | costed calls/s | sgd CPU (s) |
|---|---|---|---|---|
| none | 0.55 ± 0.06 | | | |
| sgd | 0.59 ± 0.11 | +7.1% | 20,641 ± 4,153 | 0.04 |

## E3 Noisy neighbour

Victim (priority 8): open + 64 B write + close in the shared directory every 10 ms. Aggressors (priority 2): metadata storm (16 workers creating and unlinking files in the same directory), fsync flood (4 workers), cheap I/O (64 B read + write). Aggressor kernel CPU is the system time of all aggressor processes.

| config | victim p50 (µs) | victim p95 (µs) | victim p99 (µs) | storm ops/s | fsync ops/s | cheap ops/s | aggressor kernel CPU (s) | sgd CPU (s) | rejected calls |
|---|---|---|---|---|---|---|---|---|---|
| none-alone | 42 ± 4 | 79 ± 5 | 126 ± 39 | – | – | – | – | – | – |
| sg-alone | 308 ± 22 | 567 ± 76 | 735 ± 99 | – | – | – | – | 0.10 ± 0.01 | 0 |
| none | 34 ± 2 | 8,299 ± 138 | 11,998 ± 279 | 133,516 ± 1,388 | 410 ± 15 | 4,046,591 ± 61,665 | 72.80 ± 0.61 | – | – |
| cgroup | 66 ± 6 | 181,099 ± 8,960 | 194,111 ± 3,355 | 5,512 ± 291 | 97 ± 7 | 365,858 ± 34,603 | 9.18 ± 0.07 | – | – |
| uniform | 71 ± 6 | 116 ± 19 | 171 ± 24 | 12,721 ± 77 | 3,200 ± 750 | 16,306 ± 68 | 8.91 ± 0.46 | 2.54 ± 0.15 | 0 |
| sg-noborrow | 129 ± 21 | 298 ± 115 | 611 ± 565 | 3,517 ± 5 | 26 ± 0 | 9,323 ± 48 | 4.91 ± 0.13 | 1.56 ± 0.02 | 0 |
| sg-full | 122 ± 27 | 232 ± 37 | 358 ± 15 | 3,520 ± 13 | 26 ± 0 | 9,731 ± 16 | 4.83 ± 0.10 | 1.54 ± 0.03 | 0 |

## E4 Bounded fork pressure

16 workers fork a child that exits at once and reap it, in a loop (at most 33 processes).

| config | victim p99 (µs) | forks/s | fork EAGAIN | forker kernel CPU (s) | sgd CPU (s) |
|---|---|---|---|---|---|
| none | 284 ± 295 | 75,915 ± 713 | 0 | 45.20 ± 0.62 | – |
| cgroup | 170 ± 61 | 3,363 ± 155 | 9,670 ± 708 | 5.73 ± 0.18 | – |
| uniform | 1,680 ± 91 | 34,779 ± 364 | 0 | 30.05 ± 0.09 | 1.40 ± 0.01 |
| sg-full | 580 ± 61 | 451 ± 1 | 8,063 ± 15 | 1.34 ± 0.12 | 0.27 ± 0.01 |

## E5 Borrowing

A fixed burst of work (dd, 10,000 records of 64 B, about 40,000 units) at priority 5 next to an idle priority-5 neighbour, R_g = 20,000 units/s, so the burst's share is half of that. Theory: about 3.0 s without borrowing; borrowing can save at most beta * H = 0.5 s.

| config | completed | time (s) | waited calls | loans | borrowed units |
|---|---|---|---|---|---|
| sg-noborrow | 3/3 | 3.09 ± 0.01 | 297 ± 2 | 0 | 0 |
| sg-full | 3/3 | 2.58 ± 0.00 | 241 ± 2 | 603 ± 15 | 17,312 ± 30 |

## Failed runs

None: every job in every run exited with status 0.
