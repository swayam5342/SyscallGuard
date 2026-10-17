#!/bin/sh
# Integration tests: real programs run under sg-launch, decisions checked
# through exit codes, timing and sgd's per-job summaries.
set -u
cd "$(dirname "$0")/.." || exit 1
B=./build
SOCK=/tmp/sg-test-$$.sock
ERR=/tmp/sg-test-$$.err
LOG=/tmp/sg-test-$$.jsonl
ORDER=/tmp/sg-test-$$.order
SGD=
fail=0

check() {
    if [ "$1" -eq 0 ]; then echo "PASS  $2"; else echo "FAIL  $2"; fail=1; fi
}
now_ms() { echo $(($(date +%s%N) / 1000000)); }
cleanup() {
    rc=$?   # dash would otherwise exit with the status of the trap's last command
    [ -n "$SGD" ] && kill "$SGD" 2>/dev/null
    rm -f "$SOCK" "$ERR" "$LOG" "$ORDER"
    exit $rc
}
trap cleanup EXIT

start_sgd() {
    $B/sgd -s "$SOCK" "$@" 2>"$ERR" &
    SGD=$!
    i=0
    while [ ! -S "$SOCK" ]; do
        i=$((i + 1))
        if [ $i -gt 100 ]; then echo "sgd failed to start:"; cat "$ERR"; exit 1; fi
        sleep 0.02
    done
}
stop_sgd() {
    kill "$SGD" 2>/dev/null
    wait "$SGD" 2>/dev/null
    SGD=
}
L() { $B/sg-launch -s "$SOCK" "$@"; }
# Wait until sgd has reported $1 finished jobs.
wait_jobs() {
    i=0
    while [ "$(grep -c ' ended ' "$ERR")" -lt "$1" ]; do
        i=$((i + 1))
        [ $i -gt 150 ] && return 1
        sleep 0.02
    done
}
# Value of a counter in the most recent job summary.
field() { grep ' ended ' "$ERR" | tail -1 | sed -n "s/.* $1=\([0-9.]*\).*/\1/p"; }

echo "-- basics (default budget)"
start_sgd -l "$LOG"
[ "$(L cat /etc/hostname)" = "$(cat /etc/hostname)" ]
check $? "command output is unchanged"
L sh -c 'exit 7'
[ $? -eq 7 ]
check $? "exit status is passed through"
L /nonexistent/binary 2>/dev/null
[ $? -eq 127 ]
check $? "missing command returns 127"
L $B/threadn >/dev/null
check $? "pthread_create works (clone3 falls back to clone)"
wait_jobs 4
check $? "sgd reports a summary for every job"
[ "$(grep ' ended ' "$ERR" | grep -vc 'rejected=0')" -eq 0 ]
check $? "nothing is rejected under the default budget"
stop_sgd
[ ! -e "$SOCK" ]
check $? "sgd removes its socket on shutdown"
grep -q '"ev":"call".*"sys":"openat".*"dec":"ALLOW"' "$LOG" && grep -q '"ev":"pcb"' "$LOG"
check $? "JSON-lines log records decisions and per-process stats"

$B/sg-launch -s /tmp/sg-missing-$$.sock true 2>/dev/null
[ $? -eq 125 ]
check $? "sg-launch fails cleanly when sgd is not running"

echo "-- process creation over budget, fork policy reject"
start_sgd -r 2000 -R 0
t0=$(now_ms)
out=$(L -f reject $B/forkn 200)
t1=$(now_ms)
echo "$out" | grep -q 'ok=[1-9]'
check $? "forks within budget succeed ($out)"
echo "$out" | grep -q 'eagain=[1-9]'
check $? "forks beyond budget fail with EAGAIN at once"
wait_jobs 1 && [ "$(field rejected)" -gt 0 ]
check $? "sgd counted the rejections"
stop_sgd
fast=$((t1 - t0))

start_sgd -r 2000
t0=$(now_ms)
out=$(L --fork-policy reject $B/forkn 200)
t1=$(now_ms)
eagain=$(echo "$out" | sed -n 's/.*eagain=\([0-9]*\).*/\1/p')
[ "$eagain" -gt 0 ] && [ $((t1 - t0)) -ge $((eagain * 9)) ]
check $? "paced rejections: $eagain EAGAINs took $((t1 - t0)) ms (>= 10 ms each; $fast ms with -R 0)"
stop_sgd

echo "-- process creation over budget, fork policies brief (default) and wait"
start_sgd -r 2000
out=$(L $B/forkn 100)
echo "$out" | grep -q '^ok=100 eagain=0 '
check $? "default (brief): forks over budget wait for refill and all succeed ($out)"
stop_sgd
start_sgd -r 100 -F 50
t0=$(now_ms)
out=$(L $B/forkn 10)
t1=$(now_ms)
eagain=$(echo "$out" | sed -n 's/.*eagain=\([0-9]*\).*/\1/p')
[ "$eagain" -gt 0 ] && [ $((t1 - t0)) -ge $((eagain * 45)) ]
check $? "brief: forks not fundable within -F 50 ms fail after waiting ($out, $((t1 - t0)) ms)"
stop_sgd
start_sgd -r 100 -F 50
out=$(L -f wait $B/forkn 5)
echo "$out" | grep -q '^ok=5 eagain=0 '
check $? "wait: the same forks wait as long as needed and succeed ($out)"
stop_sgd
$B/sg-launch -s "$SOCK" -f sometimes true 2>/dev/null
[ $? -eq 125 ]
check $? "an unknown fork policy is a usage error"

echo "-- data I/O over budget WAITS"
start_sgd -r 4000
t0=$(now_ms)
L dd if=/dev/zero of=/dev/null bs=1 count=6000 status=none
rc=$?
t1=$(now_ms)
[ $rc -eq 0 ]
check $? "throttled dd still succeeds"
[ $((t1 - t0)) -ge 1500 ]
check $? "dd is slowed to the budget (~12000 units at 4000/s took $((t1 - t0)) ms)"
wait_jobs 1 && [ "$(field waited)" -gt 0 ] && [ "$(field rejected)" -eq 0 ]
check $? "calls waited instead of failing"
stop_sgd

echo "-- priority shares"
start_sgd -r 4000 -H 100
: >"$ORDER"
(L -p 2 -n low dd if=/dev/zero of=/dev/null bs=1 count=2000 status=none; echo low >>"$ORDER") &
p1=$!
(L -p 8 -n high dd if=/dev/zero of=/dev/null bs=1 count=2000 status=none; echo high >>"$ORDER") &
p2=$!
wait $p1 $p2
[ "$(head -1 "$ORDER")" = high ]
check $? "priority-8 job finishes before priority-2 job"
stop_sgd

echo "-- calls that cannot fit"
start_sgd -r 10
L true 2>/dev/null
[ $? -eq 126 ]
check $? "execve (40) larger than the whole burst (10) is rejected at once"
stop_sgd

# Large global budget, but a fixed job rate whose burst (30) is below execve's
# cost (40) yet within the borrow cap (45): the call waits and never fits.
start_sgd -r 100000 -T 300
t0=$(now_ms)
L -r 30 true 2>/dev/null
rc=$?
t1=$(now_ms)
[ $rc -eq 126 ] && [ $((t1 - t0)) -ge 300 ]
check $? "a call still waiting after T_max is rejected ($((t1 - t0)) ms)"
stop_sgd

# A borrower at a fixed 1000 units/s holds at most 1000 and may owe 500.
# bigmmap 1200 costs 1202, so it can only succeed with a loan.
echo "-- borrowing"
start_sgd -r 100000 -T 500 -l "$LOG"
L -r 1000 -n alone $B/bigmmap 1200 >/dev/null
[ $? -eq 1 ]
check $? "a call larger than the job's burst fails when nobody can lend"
L -r 2000 -p 2 -n lender sleep 2 &
lp=$!
sleep 0.3
L -r 1000 -p 8 -n borrower $B/bigmmap 1200 1 >/dev/null
check $? "the same call succeeds by borrowing from a lower-priority job"
wait $lp
wait_jobs 3
stop_sgd
grep -q '"ev":"loan_open".*"from":2,"to":3' "$LOG"
check $? "the loan is recorded in the ledger (lender -> borrower)"
grep -q '"ev":"loan_repaid".*"from":2,"to":3' "$LOG"
check $? "the loan is repaid from the borrower's later refills"
[ "$(grep '(lender) ended' "$ERR" | sed -n 's/.* lent=\([0-9]*\).*/\1/p')" -gt 0 ]
check $? "the lender's summary shows what it lent"
python3 tools/sg_analyze.py "$LOG" | grep -q '^Loans: 1 opened, 1 repaid, 0 written off.*repayment ratio 1.00'
check $? "sg_analyze reports the loan and its repayment"

echo "-- lending rules"
start_sgd -r 100000 -T 500 -I 1000
L -r 2000 -p 9 -n important sleep 3 &
lp=$!
sleep 0.3
L -r 1000 -p 2 $B/bigmmap 1200 >/dev/null
[ $? -eq 1 ]
check $? "an active higher-priority job does not lend to a lower one"
sleep 1.2
L -r 1000 -p 2 $B/bigmmap 1200 >/dev/null
check $? "once idle for the idle window, it lends to anyone (idle tax)"
wait $lp
stop_sgd

start_sgd -r 100000 -T 500 -B
L -r 2000 -p 2 -n lender sleep 1 &
lp=$!
sleep 0.3
L -r 1000 -p 8 $B/bigmmap 1200 >/dev/null
[ $? -eq 1 ]
check $? "with borrowing disabled (-B) the call fails"
wait $lp
stop_sgd

echo "-- calibrated costs"
COSTS=/tmp/sg-test-$$.conf
printf '# test costs\nexecve 500\n' >"$COSTS"
$B/sgd -L -c "$COSTS" | grep -q '^59 *execve *exec *40 *500$'
check $? "sgd -L shows the calibrated cost next to the seed"
start_sgd -r 100
L true
check $? "with seed costs, execve (40) fits a 100-unit burst"
stop_sgd
start_sgd -r 100 -c "$COSTS"
L true 2>/dev/null
[ $? -eq 126 ]
check $? "with execve calibrated to 500 it can never fit and is rejected"
stop_sgd
printf 'execve 0\n' >"$COSTS"
$B/sgd -s "$SOCK" -c "$COSTS" 2>/dev/null
[ $? -eq 2 ]
check $? "sgd refuses an invalid cost file"
if ls costs/*.conf >/dev/null 2>&1; then
    for f in costs/*.conf; do
        $B/sgd -L -c "$f" >/dev/null || { echo "bad cost file $f"; false; }
    done
    check $? "the committed calibration files load"
fi
rm -f "$COSTS"

echo "-- sgctl and /metrics"
PORT=$((20000 + $$ % 20000))
C() { $B/sgctl -s "$SOCK" "$@"; }
start_sgd -m "$PORT" -l "$LOG"
L -p 3 -n sleeper -f wait sleep 2 &
lp=$!
sleep 0.3
C status | grep -q '^1 *sleeper *3 *share.* wait$'
check $? "sgctl status lists the running job and its fork policy"
C set-prio 1 9 >/dev/null && C status | grep -q '^1 *sleeper *9 '
check $? "sgctl set-prio changes the priority at run time"
C set-rate 1 777 >/dev/null && C status | grep -q 'fixed *777 '
check $? "sgctl set-rate switches the job to a fixed rate"
C set-prio 42 5 2>/dev/null
[ $? -eq 1 ]
check $? "sgctl reports an unknown job as an error"
C loans | grep -q 'no outstanding loans'
check $? "sgctl loans lists outstanding loans"
C metrics | grep -q '^sg_job_rate_units{job="1",name="sleeper"} 777$'
check $? "sgctl metrics prints Prometheus text"
curl -s "http://127.0.0.1:$PORT/metrics" | grep -q '^sg_admission_wait_seconds_count [1-9]'
check $? "HTTP /metrics serves the same metrics"
wait $lp
stop_sgd
python3 tools/sg_analyze.py "$LOG" | grep -q "^Jain's fairness index"
check $? "sg_analyze summarises the event log"

exit $fail
