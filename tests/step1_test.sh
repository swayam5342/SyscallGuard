#!/bin/sh
# Step 1 checks: openat is intercepted, the command still works, and the
# exit status is passed through.
set -u
BIN=./build/step1_hello
fail=0

check() {
    if [ "$1" -eq 0 ]; then echo "PASS  $2"; else echo "FAIL  $2"; fail=1; fi
}

out=$($BIN cat /etc/hostname 2>&1)
code=$?
echo "$out" | grep -q 'openat("/etc/hostname"'
check $? "openat of /etc/hostname is intercepted"
[ "$code" -eq 0 ]
check $? "cat exits 0 under the filter"
[ "$(cat /etc/hostname)" = "$($BIN cat /etc/hostname 2>/dev/null)" ]
check $? "command output is unchanged"

$BIN sh -c 'exit 7' 2>/dev/null
[ $? -eq 7 ]
check $? "exit status is passed through"

$BIN /nonexistent/binary 2>/dev/null
[ $? -eq 127 ]
check $? "missing command returns 127"

out=$($BIN sh -c 'cat /etc/hostname & cat /etc/hostname; wait' 2>&1)
[ "$(echo "$out" | grep -c 'openat("/etc/hostname"')" -eq 2 ]
check $? "child processes inherit the filter"

exit $fail
