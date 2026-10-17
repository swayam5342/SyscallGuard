"""Unit tests for tools/sg_calibrate.py (parsing and statistics; no root needed)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import sg_calibrate as sc  # noqa: E402

BPFTRACE_OUTPUT = """Attaching 3 probes...


@lat[0, 300]: 60
@lat[0, 400]: 40
@lat[59, 110000]: 30
@lat[1000000, 44000]: 25
@lat[56, 160000]: 3
garbage line
"""


class ParseTest(unittest.TestCase):
    def test_parse(self):
        hist = sc.parse_bpftrace(BPFTRACE_OUTPUT)
        self.assertEqual(hist[0], [(300, 60), (400, 40)])
        self.assertEqual(hist[59], [(110000, 30)])
        self.assertEqual(hist[sc.THREAD_ID], [(44000, 25)])
        self.assertNotIn("garbage", str(hist))

    def test_bucket_widths(self):
        self.assertEqual(sc.bucket_width(9900), 100)
        self.assertEqual(sc.bucket_width(10000), 10000)
        self.assertEqual(sc.bucket_width(990000), 10000)
        self.assertEqual(sc.bucket_width(1000000), 1000000)


class MedianTest(unittest.TestCase):
    def test_interpolates_inside_the_median_bucket(self):
        # 4 samples, median position 2: one in [0,100), three in [500,600)
        self.assertAlmostEqual(sc.median_ns([(0, 1), (500, 3)]), 500 + 100 * (2 - 1) / 3)

    def test_single_bucket(self):
        self.assertAlmostEqual(sc.median_ns([(110000, 30)]), 110000 + 10000 * 0.5)

    def test_empty(self):
        self.assertIsNone(sc.median_ns([]))

    def test_cost_units(self):
        self.assertEqual(sc.cost_units(300), 1)       # minimum 1
        self.assertEqual(sc.cost_units(1499), 1)
        self.assertEqual(sc.cost_units(1500), 2)      # halves round up
        self.assertEqual(sc.cost_units(2500), 3)      # not to even
        self.assertEqual(sc.cost_units(115000), 115)


class RowsTest(unittest.TestCase):
    TABLE = [(0, "read", 1), (59, "execve", 40), (56, "clone", 30), (56, "clone_thread", 10)]

    def test_rows(self):
        rows = {r[0]: r for r in sc.build_rows(self.TABLE, sc.parse_bpftrace(BPFTRACE_OUTPUT))}
        self.assertEqual(rows["read"][1], 1)
        self.assertEqual(rows["read"][3], 100)
        self.assertEqual(rows["execve"][1], 115)
        self.assertEqual(rows["clone_thread"][1], 49)          # 44 us bucket + half of 10 us
        self.assertIsNone(rows["clone"][1])                    # 3 samples < MIN_SAMPLES

    def test_cost_file_round_trip(self):
        rows = sc.build_rows(self.TABLE, sc.parse_bpftrace(BPFTRACE_OUTPUT))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "costs.conf")
            sc.write_cost_file(path, rows, "test")
            entries = {}
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].split()
                    if line:
                        entries[line[0]] = int(line[1])
        self.assertEqual(entries, {"read": 1, "execve": 115, "clone_thread": 49})


if __name__ == "__main__":
    unittest.main()
