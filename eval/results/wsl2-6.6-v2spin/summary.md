# SyscallGuard evaluation: wsl2-6.6-v2spin

Host `Swayamp`, kernel `6.6.114.1-microsoft-standard-WSL2`, 10 CPUs, 2026-10-16 21:11 UTC. 3 repetitions per cell (mean ± standard deviation), runs of 10 s, global budget R_g = 200,000 units/s, costs: `costs/wsl2-6.6.conf`, extra sgd options: `-S 200`.
cgroup baseline limits on the aggressors: `cpu.max=100000 100000`, `pids.max=32`, `io.max=8:80 wiops=200`.

## E1 Per-call overhead

| path | ns per call |
|---|---|
| getppid, native | 70.6 ± 0.6 |
| getppid under sgd (in-kernel filter only, fast path) | 76.8 ± 1.6 |
| read 1 B, native | 100.0 ± 1.5 |
| read 1 B under sgd (round trip to the supervisor) | 3,577.7 ± 81.5 |

## E3 Noisy neighbour

Victim (priority 8): open + 64 B write + close in the shared directory every 10 ms. Aggressors (priority 2): metadata storm (16 workers creating and unlinking files in the same directory), fsync flood (4 workers), cheap I/O (64 B read + write). Aggressor kernel CPU is the system time of all aggressor processes.

| config | victim p50 (µs) | victim p95 (µs) | victim p99 (µs) | storm ops/s | fsync ops/s | cheap ops/s | aggressor kernel CPU (s) | sgd CPU (s) | rejected calls |
|---|---|---|---|---|---|---|---|---|---|
| none-alone | 59 ± 2 | 86 ± 4 | 139 ± 6 | – | – | – | – | – | – |
| sg-alone | 300 ± 19 | 702 ± 10 | 880 ± 39 | – | – | – | – | 0.37 ± 0.01 | 0 |
| none | 35 ± 1 | 8,338 ± 150 | 12,056 ± 37 | 133,480 ± 494 | 455 ± 22 | 4,054,401 ± 18,965 | 72.35 ± 0.58 | – | – |
| cgroup | 67 ± 1 | 183,456 ± 2,674 | 194,016 ± 1,714 | 5,175 ± 652 | 99 ± 13 | 332,864 ± 59,028 | 9.22 ± 0.06 | – | – |
| uniform | 76 ± 16 | 198 ± 64 | 459 ± 196 | 11,711 ± 65 | 3,108 ± 448 | 15,854 ± 31 | 9.79 ± 0.40 | 9.14 ± 0.34 | 0 |
| sg-noborrow | 214 ± 193 | 423 ± 372 | 730 ± 671 | 3,519 ± 2 | 26 ± 0 | 9,155 ± 129 | 4.16 ± 0.14 | 5.36 ± 0.16 | 0 |
| sg-full | 127 ± 8 | 318 ± 169 | 501 ± 334 | 3,519 ± 1 | 26 ± 0 | 9,741 ± 5 | 4.05 ± 0.17 | 5.35 ± 0.05 | 0 |

## E4 Bounded fork pressure

16 workers fork a child that exits at once and reap it, in a loop (at most 33 processes).

| config | victim p99 (µs) | forks/s | fork EAGAIN | forker kernel CPU (s) | sgd CPU (s) |
|---|---|---|---|---|---|
| none | 125 ± 14 | 76,914 ± 156 | 0 | 44.99 ± 0.29 | – |
| cgroup | 172 ± 31 | 3,421 ± 226 | 9,396 ± 564 | 5.81 ± 0.05 | – |
| uniform | 4,646 ± 435 | 45,503 ± 64 | 3,325 ± 22 | 35.25 ± 0.06 | 9.58 ± 0.03 |
| sg-full | 952 ± 329 | 451 ± 1 | 8,007 ± 6 | 1.64 ± 0.07 | 1.12 ± 0.16 |

## Failed runs

None: every job in every run exited with status 0.
