"""An upgrade hint counts stale entries without carrying over their decisions."""

from copy import deepcopy
import unittest

from obaaf.checker.acceptance import Acceptance, BASELINE
from obaaf.checker.rules import CANNOT_TELL, VERIFIED, Control, Finding
from obaaf.checker.todo_upgrade import previous_acceptances


RULE = "OBAAF-GHA-005"
PATH = ".github/workflows/agent.yml"


def finding(line=1, **fields):
    values = dict(rule=RULE, path=PATH, job="agent", severity="high", kind="secrets",
                  line=line, message="Agent job receives a secret.", facts={"secrets": ["MODEL_KEY"]})
    values.update(fields)
    return Finding(**values)


def stale(**fields):
    entry = dict(rule=RULE, path=PATH, job="agent", kind="secrets", facts={"previous": "identity"})
    entry.update(fields)
    return entry


class PreviousAcceptancesTest(unittest.TestCase):
    def test_pairs_only_within_rule_path_and_job_and_does_not_mutate_inputs(self):
        current = finding()
        findings = [current, finding(rule="OBAAF-GHA-003"), finding(job="second"), finding(path="other.yml")]
        entries = [stale()]
        originals = deepcopy((entries, findings))
        self.assertEqual(previous_acceptances(entries, findings), {id(current): 1})
        self.assertEqual((entries, findings), originals)

    def test_cached_identity_may_have_changed_and_a_job_may_be_absent(self):
        earlier = stale(kind="older-case")
        del earlier["job"]
        current = finding(job=None)
        self.assertEqual(previous_acceptances([earlier], [current]), {id(current): 1})

    def test_invalid_accepted_and_fixed_findings_never_receive_a_hint(self):
        invalid = Acceptance(BASELINE, problems=["it names no owner"])
        unknown = finding(controls=[Control("environment", CANNOT_TELL)])
        candidates = [finding(baselined=True), finding(suppressed="ignored"),
                      finding(controls=[Control("environment", VERIFIED)]), finding(acceptance=invalid),
                      finding(message="Example. (An ignore entry for this finding expired on 2026-11-17.)"),
                      unknown]
        self.assertEqual(previous_acceptances([stale()], candidates), {id(unknown): 1})

    def test_conflicting_candidate_kinds_get_no_hint_even_when_counts_match(self):
        candidates = [finding(), finding(kind="environment")]
        entries = [stale(), stale()]
        self.assertEqual(previous_acceptances(entries, candidates), {})
        self.assertEqual(previous_acceptances(reversed(entries), reversed(candidates)), {})

    def test_two_equal_entries_count_twice_and_repeated_objects_count_once(self):
        first, second, third = finding(1), finding(2), finding(3)
        old = stale()
        entries = [old, dict(old), old]
        candidates = [third, second, first, first]
        expected = {id(first): 1, id(second): 1}
        self.assertEqual(previous_acceptances(entries, candidates), expected)
        self.assertEqual(previous_acceptances(reversed(entries), reversed(candidates)), expected)
        self.assertEqual(previous_acceptances(entries, [first, first]), {id(first): 1})

    def test_source_location_ties_are_independent_of_input_order(self):
        one, two = finding(), finding()
        forward = previous_acceptances([stale()], [one, two])
        self.assertEqual(len(forward), 1)
        self.assertEqual(forward, previous_acceptances([stale()], [two, one]))
