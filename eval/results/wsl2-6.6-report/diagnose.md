# SyscallGuard wake-up diagnostics: wsl2-6.6-report

Host `Swayamp`, kernel `6.6.114.1-microsoft-standard-WSL2`, 10 CPUs, 2026-10-23 16:58 UTC. 3 untraced runs per configuration (mean ± sd) plus one traced run; victim probe every 10 ms for 9 s; costs `costs/wsl2-6.6.conf`.

Configurations: `none` = no sgd (native); `sg-full` = sgd defaults (synchronous wake-up on); `sg-full-nosync` = sgd -W (synchronous wake-up off); `sg-full-spin` = sgd -S 200 (spinning; turns synchronous wake-up off); `uniform` = uniform-cost limiter, synchronous wake-up on; `uniform-nosync` = uniform-cost limiter, -W

## Victim alone: wake-up cost of an occasional costed call

| config | victim p50 (µs) | victim p99 (µs) | victim run-queue wait (ms) | sgd CPU (s) | sgd CPU migrations |
|---|---|---|---|---|---|
| none | 56 ± 2 | 124 ± 34 | 6.5 ± 4.5 | – | – |
| sg-full | 277 ± 2 | 512 ± 10 | 7.5 ± 0.5 | 0.08 ± 0.01 | 1,806 ± 5 |
| sg-full-nosync | 390 ± 8 | 710 ± 55 | 5.8 ± 5.8 | 0.12 ± 0.01 | 41 ± 9 |
| sg-full-spin | 278 ± 7 | 751 ± 19 | 4.5 ± 2.7 | 0.33 ± 0.01 | 32 ± 20 |

Per costed call (openat/write) of the victim, p50 / p99 in µs, from the traced run:

| stage | none | sg-full | sg-full-nosync | sg-full-spin | meaning |
|---|---|---|---|---|---|
| total | 31.1 / 114.2 | 161.4 / 344.8 | 228.2 / 476.5 | 219.3 / 479.9 | syscall entry to return, as the victim sees it |
| seccomp | – | 133.3 / 289.9 | 197.6 / 433.2 | 189.2 / 433.3 | inside seccomp: the whole round trip through sgd |
| to_sgd | – | 114.1 / 258.8 | 113.4 / 289.9 | 101.1 / 249.9 | entry until sgd has received the notification |
| to_wakeup | – | 81.8 / 198.8 | 80.9 / 215.9 | 95.7 / 207.5 | entry until sgd is woken |
| filter | – | 3.9 / 19.2 | 4.8 / 31.9 | 5.4 / 20.0 | seccomp filter, until the notification code starts |
| notify | – | 2.0 / 6.6 | 3.2 / 7.7 | 4.2 / 9.6 | notification code until the kernel starts waking sgd |
| cpu_wake | – | 73.5 / 187.1 | 71.0 / 194.9 | 82.7 / 185.7 | waking sgd: wake issued until sgd's CPU has taken it (remote/idle CPU cost) |
| sgd_sched | – | 8.9 / 54.9 | 10.3 / 58.3 | 10.9 / 35.0 | sgd woken until it runs |
| sgd_to_recv | – | 14.5 / 37.2 | 13.7 / 99.9 | 15.5 / 48.0 | sgd running until it asks for the notification (epoll return, loop) |
| recv | – | 5.4 / 10.6 | 5.0 / 17.6 | 4.5 / 15.0 | the NOTIF_RECV ioctl |
| decide | – | 4.9 / 13.3 | 4.9 / 34.8 | 4.5 / 16.4 | sgd's budget decision |
| back | – | 13.8 / 30.0 | 72.4 / 232.8 | 77.4 / 218.0 | sgd's reply until the victim continues in the kernel |
| kernel | 31.1 / 114.2 | 26.5 / 67.0 | 27.8 / 107.9 | 28.7 / 64.9 | the real syscall |
| sgd_wake | – | 10.4 / 93.4 | 11.7 / 60.7 | 12.6 / 45.9 | any sgd wake-up: woken until running |
| victim_wake | 14.7 / 106.2 | 7.0 / 28.7 | 7.6 / 83.7 | 8.0 / 60.7 | any victim wake-up: woken until running |

Wake-ups on the waking CPU vs another CPU (counts):

| config | sgd same CPU | sgd other CPU | victim same CPU | victim other CPU |
|---|---|---|---|---|
| none | 0 | 0 | 888 | 15 |
| sg-full | 886 | 1878 | 2701 | 23 |
| sg-full-nosync | 890 | 1869 | 873 | 1851 |
| sg-full-spin | 930 | 1215 | 868 | 1856 |

## Victim next to 16 fork workers: synchronous wake-up on/off

| config | victim p50 (µs) | victim p99 (µs) | victim run-queue wait (ms) | forks/s | sgd CPU (s) | sgd CPU migrations |
|---|---|---|---|---|---|---|
| uniform | 358 ± 24 | 1,709 ± 76 | 294.4 ± 16.6 | 33,097 ± 68 | 1.31 ± 0.03 | 69,383 ± 558 |
| uniform-nosync | 176 ± 8 | 615 ± 113 | 103.0 ± 22.9 | 44,444 ± 96 | 3.84 ± 0.03 | 4,245 ± 278 |
| sg-full | 226 ± 24 | 466 ± 6 | 6.7 ± 0.5 | 452 ± 0 | 0.15 ± 0.01 | 2,533 ± 55 |
| sg-full-nosync | 372 ± 11 | 703 ± 25 | 8.5 ± 7.6 | 453 ± 0 | 0.28 ± 0.02 | 517 ± 22 |

Per costed call (openat/write) of the victim, p50 / p99 in µs, from the traced run:

| stage | uniform | uniform-nosync | sg-full | sg-full-nosync | meaning |
|---|---|---|---|---|---|
| total | 216.9 / 1904.7 | 95.8 / 544.9 | 187.7 / 808.7 | 183.6 / 382.4 | syscall entry to return, as the victim sees it |
| seccomp | 197.8 / 1899.0 | 75.2 / 523.9 | 159.2 / 778.7 | 157.3 / 349.9 | inside seccomp: the whole round trip through sgd |
| to_sgd | 39.0 / 439.9 | 30.0 / 434.8 | 111.3 / 267.1 | 86.0 / 213.0 | entry until sgd has received the notification |
| to_wakeup | 43.6 / 532.2 | 34.0 / 343.2 | 74.0 / 202.3 | 64.4 / 173.7 | entry until sgd is woken |
| filter | 3.2 / 7.2 | 3.5 / 8.9 | 5.0 / 32.4 | 4.0 / 17.4 | seccomp filter, until the notification code starts |
| notify | 57.0 / 518.7 | 37.5 / 357.0 | 3.0 / 258.8 | 2.6 / 6.2 | notification code until the kernel starts waking sgd |
| cpu_wake | 16.6 / 63.9 | 2.6 / 50.4 | 69.2 / 193.2 | 56.4 / 161.2 | waking sgd: wake issued until sgd's CPU has taken it (remote/idle CPU cost) |
| sgd_sched | 2.5 / 253.9 | 4.2 / 274.7 | 8.2 / 93.4 | 5.4 / 25.0 | sgd woken until it runs |
| sgd_to_recv | 6.5 / 30.3 | 4.5 / 19.3 | 18.9 / 96.3 | 10.5 / 29.5 | sgd running until it asks for the notification (epoll return, loop) |
| recv | 4.7 / 68.3 | 8.7 / 79.9 | 4.7 / 13.3 | 3.5 / 7.9 | the NOTIF_RECV ioctl |
| decide | 1.9 / 4.2 | 1.9 / 6.2 | 4.8 / 12.7 | 4.1 / 9.5 | sgd's budget decision |
| back | 110.4 / 1796.8 | 27.0 / 292.4 | 23.4 / 644.9 | 60.9 / 174.2 | sgd's reply until the victim continues in the kernel |
| kernel | 16.1 / 48.4 | 17.1 / 81.9 | 25.7 / 86.5 | 24.1 / 50.0 | the real syscall |
| sgd_wake | 2.1 / 379.1 | 7.6 / 227.7 | 6.0 / 82.1 | 6.5 / 57.9 | any sgd wake-up: woken until running |
| victim_wake | 61.7 / 1672.6 | 7.5 / 504.8 | 13.2 / 582.5 | 5.1 / 19.8 | any victim wake-up: woken until running |

Wake-ups on the waking CPU vs another CPU (counts):

| config | sgd same CPU | sgd other CPU | victim same CPU | victim other CPU |
|---|---|---|---|---|
| uniform | 597 | 73796 | 2195 | 526 |
| uniform-nosync | 9767 | 54971 | 1476 | 1227 |
| sg-full | 206 | 3636 | 2690 | 34 |
| sg-full-nosync | 877 | 3455 | 884 | 1840 |

## Failed runs

None: every job in every run exited with status 0.
