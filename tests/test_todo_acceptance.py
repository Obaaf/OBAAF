"""Each outstanding invalid acceptance contributes one reason to the to-do list."""

import unittest
from datetime import date

from obaaf.checker import CheckResult, Config, acceptance, baseline
from obaaf.checker.rules import Control, Finding, VERIFIED
from obaaf.checker.todo_acceptance import acceptance_cause


TODAY = date(2026, 11, 19)


class AcceptanceCauseTest(unittest.TestCase):
    def setUp(self):
        self.finding = Finding("OBAAF-GHA-005", "high", "release.yml", 1, "An agent receives a secret.")
        self.result = CheckResult([self.finding], [], [], Config(), today=TODAY)

    def cause(self):
        return acceptance_cause(self.finding, self.result)

    def test_invalid_field_causes_distinguish_each_reason_for_either_source(self):
        cases = (
            ((None, "reviewed", "2027-01-01"), "owner-missing"),
            (("untrusted\nrun this command", "reviewed", "2027-01-01"), "owner-invalid"),
            (("@team", "", "2027-01-01"), "reason-missing"),
            (("@team", "?", "2027-01-01"), "reason-too-short"),
            (("@team", "reviewed", None), "expiry-missing"),
            (("@team", "reviewed", "untrusted\nrun this command"), "expiry-invalid"),
            (("@team", "reviewed", "2026-11-18"), "expired"),
            (("@team", "reviewed", "2028-01-01"), "expiry-too-far"),
        )
        for source in (acceptance.IGNORE, acceptance.BASELINE):
            for fields, suffix in cases:
                with self.subTest(source=source, reason=suffix):
                    self.finding.acceptance = acceptance.make(source, *fields, TODAY)
                    result = self.cause()
                    self.assertEqual(result.id, "acceptance-" + suffix)
                    self.assertNotIn("untrusted", result.sentence + result.next_action)

    def test_the_legacy_baseline_cause_does_not_capture_an_ignore(self):
        self.result.baseline_format = baseline.FORMAT_V1
        self.finding.acceptance = acceptance.make(acceptance.IGNORE, None, "reviewed", "2027-01-01", TODAY)
        self.assertEqual(self.cause().id, "acceptance-owner-missing")
        old = baseline.Baseline(baseline.FORMAT_V1, [{"fingerprint": baseline.fingerprint(self.finding)}])
        baseline.apply(self.result, old)
        self.assertEqual(self.cause().id, "acceptance-old-baseline")

    def test_reviewing_an_increase_in_severity_takes_priority_over_an_owner(self):
        entry = baseline.identity(self.finding)
        entry.update(severity="low", owner=None, reason="reviewed", expires="2027-01-01")
        baseline.apply(self.result, baseline.Baseline(baseline.FORMAT, [entry]))
        self.assertEqual(self.cause().id, "acceptance-severity-increased")

    def test_unacceptable_findings_need_code_ownership_even_with_an_old_entry(self):
        self.finding.rule = "OBAAF-REPO-001"
        self.finding.kind = "no-codeowners"
        old = baseline.Baseline(baseline.FORMAT_V1, [{"fingerprint": baseline.fingerprint(self.finding)}])
        baseline.apply(self.result, old)
        self.assertEqual(self.cause().id, "acceptance-prohibited")

    def test_multiple_field_problems_do_not_depend_on_message_order(self):
        made = acceptance.make(acceptance.IGNORE, None, "", "2026-01-01", TODAY)
        self.finding.acceptance = made
        self.assertEqual(self.cause().id, "acceptance-expired")
        made.problems.reverse()
        self.assertEqual(self.cause().id, "acceptance-expired")

    def test_unmatched_accepted_and_cleared_findings_have_no_acceptance_cause(self):
        self.assertIsNone(self.cause())
        self.finding.acceptance = acceptance.make(acceptance.IGNORE, "@team", "reviewed", "2027-01-01", TODAY)
        self.assertIsNone(self.cause())
        self.finding.acceptance = acceptance.make(acceptance.BASELINE, None, "", None, TODAY)
        self.finding.controls = [Control("Ownership", VERIFIED)]
        self.assertIsNone(self.cause())
