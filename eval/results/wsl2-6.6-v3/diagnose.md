# SyscallGuard wake-up diagnostics: wsl2-6.6-v3

Host `Swayamp`, kernel `6.6.114.1-microsoft-standard-WSL2`, 10 CPUs, 2026-10-17 11:08 UTC. 3 untraced runs per configuration (mean ± sd) plus one traced run; victim probe every 10 ms for 9 s; costs `costs/wsl2-6.6.conf`.

Configurations: `none` = no sgd (native); `sg-full` = sgd defaults (synchronous wake-up on); `sg-full-nosync` = sgd -W (synchronous wake-up off); `sg-full-spin` = sgd -S 200 (spinning; turns synchronous wake-up off); `uniform` = uniform-cost limiter, synchronous wake-up on; `uniform-nosync` = uniform-cost limiter, -W

## Victim alone: wake-up cost of an occasional costed call

| config | victim p50 (µs) | victim p99 (µs) | victim run-queue wait (ms) | sgd CPU (s) | sgd CPU migrations |
|---|---|---|---|---|---|
| none | 64 ± 11 | 161 ± 67 | 0.5 ± 0.6 | – | – |
| sg-full | 294 ± 21 | 589 ± 49 | 10.0 ± 0.7 | 0.10 ± 0.01 | 1,810 ± 13 |
| sg-full-nosync | 416 ± 5 | 749 ± 31 | 1.9 ± 3.2 | 0.15 | 3 ± 3 |
| sg-full-spin | 278 ± 12 | 817 ± 25 | 1.8 ± 2.7 | 0.36 ± 0.01 | 10 ± 2 |

Per costed call (openat/write) of the victim, p50 / p99 in µs, from the traced run:

| stage | none | sg-full | sg-full-nosync | sg-full-spin | meaning |
|---|---|---|---|---|---|
| total | 31.4 / 115.6 | 176.5 / 452.4 | 222.8 / 499.8 | 238.8 / 536.5 | syscall entry to return, as the victim sees it |
| seccomp | – | 146.2 / 413.2 | 191.8 / 454.8 | 207.2 / 494.8 | inside seccomp: the whole round trip through sgd |
| to_sgd | – | 122.4 / 339.9 | 108.3 / 279.8 | 113.2 / 285.6 | entry until sgd has received the notification |
| to_wakeup | – | 86.9 / 219.5 | 78.7 / 209.9 | 96.9 / 228.8 | entry until sgd is woken |
| filter | – | 4.4 / 19.6 | 6.1 / 19.8 | 6.5 / 20.0 | seccomp filter, until the notification code starts |
| notify | – | 2.0 / 6.6 | 3.1 / 6.1 | 4.0 / 8.7 | notification code until the kernel starts waking sgd |
| cpu_wake | – | 78.3 / 199.9 | 68.3 / 196.6 | 83.6 / 207.3 | waking sgd: wake issued until sgd's CPU has taken it (remote/idle CPU cost) |
| sgd_sched | – | 11.5 / 91.2 | 9.6 / 31.9 | 13.7 / 48.8 | sgd woken until it runs |
| sgd_to_recv | – | 15.3 / 87.4 | 12.3 / 49.9 | 16.1 / 58.8 | sgd running until it asks for the notification (epoll return, loop) |
| recv | – | 5.7 / 39.9 | 5.2 / 9.9 | 5.3 / 17.6 | the NOTIF_RECV ioctl |
| decide | – | 5.1 / 36.6 | 5.2 / 9.9 | 5.4 / 13.2 | sgd's budget decision |
| back | – | 15.9 / 92.4 | 74.2 / 229.8 | 80.7 / 279.8 | sgd's reply until the victim continues in the kernel |
| kernel | 31.4 / 115.6 | 26.9 / 123.7 | 28.7 / 82.4 | 29.0 / 99.8 | the real syscall |
| sgd_wake | – | 12.7 / 83.2 | 12.4 / 35.6 | 14.8 / 47.1 | any sgd wake-up: woken until running |
| victim_wake | 17.4 / 115.0 | 7.9 / 48.0 | 7.1 / 26.6 | 8.5 / 33.5 | any victim wake-up: woken until running |

Wake-ups on the waking CPU vs another CPU (counts):

| config | sgd same CPU | sgd other CPU | victim same CPU | victim other CPU |
|---|---|---|---|---|
| none | 0 | 0 | 898 | 5 |
| sg-full | 910 | 1866 | 2716 | 8 |
| sg-full-nosync | 936 | 1834 | 895 | 1829 |
| sg-full-spin | 942 | 1246 | 898 | 1826 |

## Victim next to 16 fork workers: synchronous wake-up on/off

| config | victim p50 (µs) | victim p99 (µs) | victim run-queue wait (ms) | forks/s | sgd CPU (s) | sgd CPU migrations |
|---|---|---|---|---|---|---|
| uniform | 326 ± 17 | 1,566 ± 91 | 288.1 ± 17.4 | 35,378 ± 479 | 1.40 ± 0.01 | 75,503 ± 914 |
| uniform-nosync | 163 ± 3 | 553 ± 21 | 88.7 ± 4.0 | 44,648 ± 199 | 3.95 ± 0.05 | 5,436 ± 471 |
| sg-full | 206 ± 12 | 464 ± 12 | 7.9 ± 0.6 | 452 ± 0 | 0.16 ± 0.01 | 2,509 ± 21 |
| sg-full-nosync | 191 ± 17 | 540 ± 55 | 0.0 ± 0.0 | 452 ± 0 | 0.21 ± 0.02 | 512 ± 84 |

Per costed call (openat/write) of the victim, p50 / p99 in µs, from the traced run:

| stage | uniform | uniform-nosync | sg-full | sg-full-nosync | meaning |
|---|---|---|---|---|---|
| total | 198.3 / 1774.4 | 89.5 / 519.8 | 130.0 / 288.5 | 121.2 / 319.9 | syscall entry to return, as the victim sees it |
| seccomp | 180.5 / 1765.6 | 71.9 / 469.5 | 105.0 / 254.2 | 99.8 / 287.4 | inside seccomp: the whole round trip through sgd |
| to_sgd | 38.2 / 429.5 | 28.2 / 369.5 | 86.7 / 223.3 | 62.6 / 175.6 | entry until sgd has received the notification |
| to_wakeup | 37.7 / 475.8 | 24.6 / 276.7 | 64.9 / 182.8 | 43.6 / 139.3 | entry until sgd is woken |
| filter | 3.0 / 6.9 | 3.1 / 7.8 | 3.9 / 18.5 | 4.0 / 18.7 | seccomp filter, until the notification code starts |
| notify | 46.5 / 459.2 | 23.1 / 283.9 | 1.6 / 4.9 | 2.2 / 6.3 | notification code until the kernel starts waking sgd |
| cpu_wake | 15.8 / 49.9 | 2.0 / 47.8 | 58.3 / 167.4 | 36.0 / 130.0 | waking sgd: wake issued until sgd's CPU has taken it (remote/idle CPU cost) |
| sgd_sched | 2.2 / 274.1 | 3.3 / 298.9 | 5.5 / 19.8 | 4.7 / 19.4 | sgd woken until it runs |
| sgd_to_recv | 6.0 / 20.1 | 3.9 / 23.8 | 12.2 / 30.8 | 9.8 / 32.4 | sgd running until it asks for the notification (epoll return, loop) |
| recv | 4.0 / 86.5 | 7.7 / 67.1 | 3.7 / 8.0 | 3.3 / 9.2 | the NOTIF_RECV ioctl |
| decide | 1.9 / 3.7 | 1.8 / 11.1 | 4.6 / 9.4 | 3.3 / 7.6 | sgd's budget decision |
| back | 95.9 / 953.9 | 24.3 / 279.5 | 13.4 / 33.0 | 33.8 / 142.4 | sgd's reply until the victim continues in the kernel |
| kernel | 15.4 / 37.1 | 16.0 / 89.8 | 23.8 / 47.8 | 19.3 / 46.5 | the real syscall |
| sgd_wake | 1.8 / 336.2 | 7.2 / 219.5 | 6.6 / 38.3 | 4.8 / 59.0 | any sgd wake-up: woken until running |
| victim_wake | 57.8 / 939.2 | 5.0 / 429.5 | 6.5 / 19.8 | 3.1 / 18.2 | any victim wake-up: woken until running |

Wake-ups on the waking CPU vs another CPU (counts):

| config | sgd same CPU | sgd other CPU | victim same CPU | victim other CPU |
|---|---|---|---|---|
| uniform | 1377 | 82891 | 2224 | 499 |
| uniform-nosync | 9930 | 57598 | 1443 | 1267 |
| sg-full | 941 | 3839 | 2718 | 6 |
| sg-full-nosync | 894 | 3405 | 899 | 1825 |

## Failed runs

None: every job in every run exited with status 0.
