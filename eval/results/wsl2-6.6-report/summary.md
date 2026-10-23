# SyscallGuard evaluation: wsl2-6.6-report

Host `Swayamp`, kernel `6.6.114.1-microsoft-standard-WSL2`, 10 CPUs, 2026-10-23 16:49 UTC. 3 repetitions per cell (mean ± standard deviation), runs of 10 s, global budget R_g = 200,000 units/s, costs: `costs/wsl2-6.6.conf`, extra sgd options: `none (defaults)`.
cgroup baseline limits on the aggressors: `cpu.max=100000 100000`, `pids.max=32`, `io.max=8:80 wiops=200`.

## E1 Per-call overhead

| path | ns per call |
|---|---|
| getppid, native | 78.9 ± 0.8 |
| getppid under sgd (in-kernel filter only, fast path) | 82.6 ± 3.7 |
| read 1 B, native | 102.3 ± 1.6 |
| read 1 B under sgd (round trip to the supervisor) | 17,731.7 ± 281.2 |

## E2 Build overhead (make -j4, unthrottled)

| config | build time (s) | slowdown | costed calls/s | sgd CPU (s) |
|---|---|---|---|---|
| none | 1.16 ± 0.25 | | | |
| sgd | 1.08 ± 0.04 | -6.9% | 11,098 ± 375 | 0.04 ± 0.01 |

## E3 Noisy neighbour

Victim (priority 8): open + 64 B write + close in the shared directory every 10 ms. Aggressors (priority 2): metadata storm (16 workers creating and unlinking files in the same directory), fsync flood (4 workers), cheap I/O (64 B read + write). Aggressor kernel CPU is the system time of all aggressor processes.

| config | victim p50 (µs) | victim p95 (µs) | victim p99 (µs) | storm ops/s | fsync ops/s | cheap ops/s | aggressor kernel CPU (s) | sgd CPU (s) | rejected calls |
|---|---|---|---|---|---|---|---|---|---|
| none-alone | 62 ± 1 | 92 ± 1 | 122 ± 2 | – | – | – | – | – | – |
| sg-alone | 322 ± 3 | 530 ± 20 | 623 ± 38 | – | – | – | – | 0.10 ± 0.01 | 0 |
| none | 48 ± 2 | 7,829 ± 355 | 10,621 ± 353 | 76,546 ± 1,373 | 458 ± 23 | 4,187,303 ± 107,633 | 65.94 ± 1.18 | – | – |
| cgroup | 83 ± 6 | 127,655 ± 43,328 | 189,818 ± 870 | 2,936 ± 199 | 88 ± 7 | 288,320 ± 15,239 | 9.27 ± 0.01 | – | – |
| uniform | 77 ± 2 | 204 ± 101 | 423 ± 216 | 12,322 ± 199 | 2,737 ± 740 | 16,263 ± 186 | 10.71 ± 0.10 | 2.56 ± 0.06 | 0 |
| sg-noborrow | 116 ± 4 | 399 ± 180 | 1,014 ± 1,018 | 3,510 ± 9 | 26 ± 0 | 9,037 ± 86 | 5.90 ± 0.20 | 1.60 ± 0.06 | 0 |
| sg-full | 139 ± 14 | 269 ± 22 | 355 ± 39 | 3,517 ± 2 | 26 ± 0 | 9,731 ± 12 | 5.62 ± 0.21 | 1.58 ± 0.03 | 0 |

## E4 Bounded fork pressure

16 workers fork a child that exits at once and reap it, in a loop (at most 33 processes).

| config | victim p99 (µs) | forks/s | fork EAGAIN | forker kernel CPU (s) | sgd CPU (s) |
|---|---|---|---|---|---|
| none | 167 ± 47 | 71,125 ± 3,104 | 0 | 42.84 ± 0.26 | – |
| cgroup | 159 ± 27 | 3,326 ± 159 | 8,355 ± 437 | 5.71 ± 0.07 | – |
| uniform | 1,693 ± 91 | 32,107 ± 730 | 0 | 28.48 ± 0.62 | 1.34 ± 0.03 |
| sg-full | 495 ± 74 | 451 ± 1 | 0 | 0.97 ± 0.06 | 0.17 ± 0.01 |
| sg-full-reject | 523 ± 65 | 451 ± 0 | 8,010 ± 41 | 1.18 ± 0.01 | 0.22 ± 0.02 |

## E5 Borrowing

A fixed burst of work (dd, 10,000 records of 64 B, about 40,000 units) at priority 5 next to an idle priority-5 neighbour, R_g = 20,000 units/s, so the burst's share is half of that. Theory: about 3.0 s without borrowing; borrowing can save at most beta * H = 0.5 s.

| config | completed | time (s) | waited calls | loans | borrowed units |
|---|---|---|---|---|---|
| sg-noborrow | 3/3 | 3.08 ± 0.01 | 295 ± 1 | 0 | 0 |
| sg-full | 3/3 | 2.58 ± 0.00 | 242 | 624 ± 8 | 17,322 ± 4 |

## E6 Throttled build under each fork policy

`make -j4` alone under R_g = 11,351 units/s (a quarter of its measured demand). reject = EAGAIN at once; brief = wait up to the bound (sgd -F, default 500 ms), then EAGAIN (the default); wait = wait up to T_max.

| fork policy | builds completed | build time (s) | waited calls | rejected calls |
|---|---|---|---|---|
| reject | 0/3 | – | 124 ± 2 | 3 |
| brief | 3/3 | 3.57 ± 0.49 | 974 ± 60 | 0 |
| wait | 3/3 | 3.27 ± 0.00 | 971 ± 51 | 0 |

## Failed runs

Jobs that exited with a non-zero status (excluded where a table says so; failed builds under the reject policy in E6 are the effect E6 measures):

- E6/sg-full-reject/run 1/build: exit 2 (make: cc: Resource temporarily unavailable)
- E6/sg-full-reject/run 2/build: exit 2 (make: cc: Resource temporarily unavailable)
- E6/sg-full-reject/run 3/build: exit 2 (make: cc: Resource temporarily unavailable)
