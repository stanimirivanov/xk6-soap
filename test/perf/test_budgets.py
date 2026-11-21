import json
import unittest

from run import HERE, check_budget_schema, compare, retention_growth, summarize


class BudgetTest(unittest.TestCase):
    def test_missing_and_nonfinite_measurements_fail(self):
        for observations in ({}, {"parse_p95_ms": float("nan")}):
            with self.subTest(observations=observations):
                self.assertTrue(compare(observations, {"parse_p95_ms": {"max": 5.0}}))

    def test_boundaries_are_inclusive_and_drops_fail(self):
        limits = {"throughput": {"min": 90}, "drops": {"max": 0}}
        self.assertEqual(compare({"throughput": 90, "drops": 0}, limits), [])
        self.assertEqual(len(compare({"throughput": 89, "drops": 1}, limits)), 2)

    def test_retention_growth_requires_repeated_increases(self):
        self.assertEqual(retention_growth([100, 112, 108, 119]), 0)
        self.assertEqual(retention_growth([100, 112, 118, 124]), 24)
        self.assertEqual(retention_growth([200, 100, 112, 118, 124]), 24)

    def test_invalid_budget_cannot_silently_disable_a_metric(self):
        for bounds in ({}, {"upper": 9}, {"max": float("inf")}, {"max": True}):
            with self.subTest(bounds=bounds):
                self.assertTrue(compare({"heap": 10}, {"heap": bounds}))

    def test_missing_group_cannot_disable_the_gate(self):
        with self.assertRaises(ValueError):
            check_budget_schema({})

    def test_committed_baseline_matches_workload_and_passes_budgets(self):
        baseline = json.loads((HERE / "baseline.json").read_text())
        for name in ("runner", "workload"):
            with self.subTest(manifest=name):
                self.assertEqual(baseline[name], json.loads((HERE / f"{name}.json").read_text()))
        check_budget_schema(baseline["budgets"])
        summary = summarize(baseline)
        self.assertEqual(summary, baseline["summary"])
        for section, cases in baseline["budgets"].items():
            for case, limits in cases.items():
                with self.subTest(section=section, case=case):
                    self.assertEqual(compare(summary[section][case], limits), [])
