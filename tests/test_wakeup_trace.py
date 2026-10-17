"""Unit tests for tools/sg_wakeup_trace.py (program generation and parsing; no root needed)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import sg_wakeup_trace as wt  # noqa: E402


class IoctlTest(unittest.TestCase):
    def test_seccomp_ioctl_numbers(self):
        # SECCOMP_IOCTL_NOTIF_RECV / _SEND from <linux/seccomp.h> on x86-64 and aarch64
        self.assertEqual(wt.NOTIF_RECV, 0xC0502100)
        self.assertEqual(wt.NOTIF_SEND, 0xC0182101)


class ProgramTest(unittest.TestCase):
    def test_governed_x86(self):
        p = wt.program(True, arch="x86_64", notif_probe="kprobe:seccomp_do_user_notification.isra.0")
        self.assertIn("kprobe:__secure_computing", p)            # seccomp runs before sys_enter
        self.assertIn("kprobe:seccomp_do_user_notification.isra.0", p)
        self.assertIn("args->id == 257 || args->id == 1", p)       # openat, write
        self.assertIn(f"args->args[1] == {wt.NOTIF_RECV}", p)
        self.assertIn('comm == "sgd"', p)                          # by name, not pid (namespaces)
        self.assertNotIn('@seg["', p)                              # string tuple keys fail the verifier
        self.assertIn("sched:sched_waking", p)

    def test_native_aarch64(self):
        p = wt.program(False, arch="aarch64")
        self.assertIn("args->id == 56 || args->id == 64", p)
        self.assertNotIn("__secure_computing", p)
        self.assertNotIn("NOTIF", p)
        self.assertIn("BEGIN { @sgdpid = (uint64)0; }", p)         # sched probes read @sgdpid

    def test_without_notification_probe(self):
        p = wt.program(True, arch="x86_64", notif_probe=None)
        self.assertNotIn("seccomp_do_user_notification", p)
        self.assertNotIn(f"@seg[{wt.SEGMENTS.index('filter')}, $b]", p)

    def test_segment_ids_are_stable(self):
        p = wt.program(True, arch="x86_64", notif_probe="kprobe:x")
        for name in ("total", "cpu_wake", "decide", "victim_wake"):
            self.assertIn(f"@seg[{wt.SEGMENTS.index(name)}, $b]", p)


OUTPUT = """Attaching 11 probes...


@seg[0, 100000]: 10
@seg[0, 120000]: 10
@seg[6, 30000]: 20
@seg[99, 100]: 5
@sum[0]: 2200000
@sum[6]: 700000
@where[sgd_other_cpu]: 18
@where[victim_same_cpu]: 20
@pending: 0
"""


class ParseTest(unittest.TestCase):
    def test_parse(self):
        r = wt.parse(OUTPUT)
        total = r["segments"]["total"]
        self.assertEqual(total["count"], 20)
        self.assertAlmostEqual(total["mean_us"], 110.0)
        self.assertAlmostEqual(total["p50_us"], 110.0)               # end of the 100-110 µs bucket
        cpu_wake = r["segments"][wt.SEGMENTS[6]]
        self.assertEqual(cpu_wake["count"], 20)
        self.assertAlmostEqual(cpu_wake["mean_us"], 35.0)
        self.assertNotIn("decide", r["segments"])
        self.assertEqual(r["where"], {"sgd_other_cpu": 18, "victim_same_cpu": 20})
        self.assertEqual(len(r["segments"]), 2)                       # id 99 is ignored


if __name__ == "__main__":
    unittest.main()
