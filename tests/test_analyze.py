"""Unit tests for tools/sg_analyze.py on a small synthetic event log."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import sg_analyze as sa  # noqa: E402


def call(job, dec, cls="data_io", wait_us=0):
    return {"ev": "call", "job": job, "dec": dec, "cls": cls, "wait_us": wait_us}


def job_end(job, name, prio, t_us, calls, charged, entitled, **kw):
    ev = {"ev": "job_end", "job": job, "name": name, "prio": prio, "t_us": t_us, "calls": calls,
          "allowed": kw.get("allowed", calls), "waited": kw.get("waited", 0),
          "rejected": kw.get("rejected", 0), "dropped": 0, "charged": charged, "entitled": entitled,
          "borrowed": kw.get("borrowed", 0.0), "lent": kw.get("lent", 0.0)}
    return ev


EVENTS = [
    {"ev": "sgd_start", "global_rate": 1000, "burst_ms": 1000, "tmax_ms": 2000, "aging_ms": 500,
     "borrowing": 1, "global_entitled": 1000.0, "charged": 0.0},
    {"ev": "job_start", "job": 1, "name": "low", "prio": 2, "t_us": 0},
    {"ev": "job_start", "job": 2, "name": "high", "prio": 8, "t_us": 0},
    call(1, "ALLOW"), call(1, "ALLOW"), call(1, "ALLOW"),
    call(1, "WAIT"), call(1, "ALLOW", wait_us=4000),
    call(1, "REJECT", cls="process"),
    call(2, "ALLOW"), call(2, "ALLOW"),
    {"ev": "loan_open", "loan": 1, "from": 1, "to": 2, "amount": 100.0, "repaid": 0.0, "age_us": 0},
    {"ev": "loan_repaid", "loan": 1, "from": 1, "to": 2, "amount": 100.0, "repaid": 100.0, "age_us": 500000},
    job_end(1, "low", 2, 1000000, calls=5, charged=100.0, entitled=200.0, allowed=4, waited=1, rejected=1,
            lent=100.0),
    job_end(2, "high", 8, 1000000, calls=2, charged=400.0, entitled=800.0, borrowed=100.0),
    {"ev": "sgd_stop", "global_rate": 1000, "burst_ms": 1000, "tmax_ms": 2000, "aging_ms": 500,
     "borrowing": 1, "global_entitled": 1000.0, "charged": 500.0},
]


class PercentileTest(unittest.TestCase):
    def test_nearest_rank(self):
        values = list(range(1, 101))
        self.assertEqual(sa.percentile(values, 50), 50)
        self.assertEqual(sa.percentile(values, 95), 95)
        self.assertEqual(sa.percentile(values, 99), 99)
        self.assertEqual(sa.percentile(values, 100), 100)

    def test_edges(self):
        self.assertEqual(sa.percentile([], 50), 0.0)
        self.assertEqual(sa.percentile([7], 99), 7)


class JainTest(unittest.TestCase):
    def test_equal_shares_are_fair(self):
        self.assertAlmostEqual(sa.jain([3, 3, 3, 3]), 1.0)

    def test_one_job_takes_all(self):
        self.assertAlmostEqual(sa.jain([1, 0, 0, 0]), 0.25)

    def test_two_jobs(self):
        self.assertAlmostEqual(sa.jain([2, 1]), 0.9)

    def test_empty(self):
        self.assertIsNone(sa.jain([]))


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        self.s = sa.analyze(EVENTS)

    def test_per_job(self):
        low, high = self.s["jobs"]
        self.assertEqual((low["job"], high["job"]), (1, 2))
        self.assertAlmostEqual(low["utilisation"], 0.5)
        self.assertAlmostEqual(low["rejected_pct"], 20.0)
        self.assertAlmostEqual(low["wait_p99_ms"], 4.0)
        self.assertAlmostEqual(low["wait_p50_ms"], 0.0)

    def test_classes(self):
        self.assertAlmostEqual(self.s["classes"]["process"]["rejection_rate"], 1.0)
        self.assertAlmostEqual(self.s["classes"]["data_io"]["rejection_rate"], 0.0)
        self.assertEqual(self.s["classes"]["data_io"]["decided"], 6)   # WAIT is not a final decision

    def test_loans(self):
        loans = self.s["loans"]
        self.assertEqual((loans["opened"], loans["repaid"], loans["written_off"]), (1, 1, 0))
        self.assertAlmostEqual(loans["repayment_ratio"], 1.0)
        self.assertAlmostEqual(loans["mean_repay_s"], 0.5)

    def test_fairness_is_one_when_service_matches_weights(self):
        # low: 100 units/s / prio 2 = 50; high: 400 / 8 = 50
        self.assertAlmostEqual(self.s["overall"]["jain_fairness"], 1.0)
        self.assertAlmostEqual(self.s["overall"]["global_utilisation"], 0.5)

    def test_job_filter(self):
        s = sa.analyze(EVENTS, job_filter={2})
        self.assertEqual([r["job"] for r in s["jobs"]], [2])
        self.assertEqual(s["overall"]["calls"], 2)


if __name__ == "__main__":
    unittest.main()
