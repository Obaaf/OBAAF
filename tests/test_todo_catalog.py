"""A finding has exactly one rule/kind cause, including kinds with no specific entry."""

import copy
import unittest
from unittest.mock import patch

from helpers import run_cli
from obaaf.catalog import load
from obaaf.causes import CauseCatalog


JENKINS = "OBAAF-JEN-001"
INSTALL = "OBAAF-GHA-025"
LANE = "OBAAF-CFG-001"


def entry(cause_id, **selectors):
    return {
        "id": cause_id,
        "sentence": "A Jenkins step needs review.",
        "fix_kind": "by-hand",
        "next": "Review the affected step.",
        **selectors,
    }


class CauseSelectorsTest(unittest.TestCase):
    def test_empty_kind_can_have_its_own_cause_in_either_entry_order(self):
        other = entry("other", rules=[JENKINS], except_kinds={JENKINS: [""]})
        plain = entry("plain", kinds={JENKINS: [""]})
        for rows in ([other, plain], [plain, other]):
            with self.subTest(first=rows[0]["id"]):
                causes = CauseCatalog({"causes": rows}, {JENKINS})
                self.assertEqual(causes.problems, [])
                self.assertEqual(causes.for_finding(JENKINS, "").id, "plain")
                remainder = causes.for_finding(JENKINS, "future-kind")
                self.assertEqual(remainder.id, "other")
                self.assertEqual(remainder.sentence, other["sentence"])
                self.assertEqual(remainder.fix_kind, "by-hand")
                self.assertEqual(remainder.next_action, other["next"])

    def test_gaps_and_overlaps_make_the_catalogue_inconsistent(self):
        whole = entry("all", rules=[JENKINS])
        remainder = entry("rest", rules=[JENKINS], except_kinds={JENKINS: [""]})
        exact = entry("plain", kinds={JENKINS: [""]})
        other_exact = entry("another", kinds={JENKINS: [""]})
        cases = {
            "no remainder": [exact],
            "two remainders": [whole, entry("also-all", rules=[JENKINS])],
            "excluded kind has no owner": [remainder],
            "exact overlaps remainder": [whole, exact],
            "exact overlaps exact": [remainder, exact, other_exact],
            "unknown rule": [whole, entry("unknown", rules=["OBAAF-JEN-999"])],
            "duplicate cause id": [remainder, entry("rest", kinds={JENKINS: [""]})],
        }
        for name, rows in cases.items():
            with self.subTest(name=name):
                self.assertTrue(CauseCatalog({"causes": rows}, {JENKINS}).problems)

    def test_malformed_data_reports_problems(self):
        whole = entry("all", rules=[JENKINS])
        for data in (
            None, {}, {"causes": "all"}, {"causes": [None]},
            {"causes": [{**whole, "fix_kind": []}]},
            {"causes": [{**whole, "rules": JENKINS}]},
            {"causes": [{**whole, "exept_kinds": {JENKINS: ["plain"]}}]},
            {"causes": [{**whole, "except_kinds": {JENKINS: "plain"}}]},
        ):
            with self.subTest(data=data):
                problems = CauseCatalog(data, {JENKINS}).problems
                self.assertTrue(problems)
                self.assertTrue(all(isinstance(problem, str) for problem in problems))

    def test_catalog_command_fails_on_a_gap(self):
        catalog = copy.copy(load())
        catalog.causes = CauseCatalog({"causes": []}, catalog.rules)
        with patch("obaaf.catalog.load", return_value=catalog):
            code, out, err = run_cli("catalog")
        self.assertEqual(code, 1)
        self.assertIn(catalog.causes.problems[0], out + err)


class ShippedCauseCatalogTest(unittest.TestCase):
    def test_every_shipped_rule_has_a_remainder_and_jenkins_is_manual(self):
        catalog = load()
        self.assertEqual(catalog.causes.problems, [])
        for rule in catalog.rules:
            with self.subTest(rule=rule):
                cause = catalog.causes.for_finding(rule, "future-kind")
                self.assertTrue(cause.id)
                self.assertTrue(cause.sentence)
                self.assertTrue(cause.next_action)
                if rule.startswith("OBAAF-JEN-"):
                    self.assertEqual(catalog.causes.for_finding(rule, "").fix_kind, "by-hand")

    def test_installs_and_ineffective_lane_declarations_get_relevant_next_actions(self):
        causes = load().causes
        package = causes.for_finding(INSTALL, "agent-cli")
        download = causes.for_finding(INSTALL, "piped-download")
        unread = causes.for_finding(INSTALL, "too-long")
        self.assertEqual(package.id, download.id)
        self.assertEqual(package.fix_kind, "tightening")
        self.assertNotEqual(unread.id, package.id)
        self.assertEqual(unread.fix_kind, "by-hand")
        typo = causes.for_finding(LANE, "entry-not-a-lane")
        missing_job = causes.for_finding(LANE, "entry-no-job")
        self.assertEqual(typo.fix_kind, "paperwork")
        self.assertEqual(missing_job.fix_kind, "by-hand")
        self.assertNotEqual(typo.id, missing_job.id)
