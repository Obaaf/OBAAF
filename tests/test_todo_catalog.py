"""A finding has exactly one rule/kind cause, including kinds with no specific entry."""

import ast
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from helpers import run_cli
from obaaf.catalog import load
from obaaf.causes import CauseCatalog


SRC = Path(__file__).resolve().parent.parent / "src" / "obaaf"
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


# The literal kinds each rule's `add` calls give a finding that have no cause of their own, each read
# against its rule's remaining-kinds cause. A new literal kind fails the test below until its author
# assigns it a cause in causes.yaml or, having read that rule's remaining-kinds cause, adds it here.
# (The review of #253 found OBAAF-GHA-026's command-line kinds from #255 under the cause written for
# an action's inputs.) "" is a finding given no kind. Kinds built at run time are not seen here.
REMAINDER_READ = {
    "OBAAF-GHA-001": {"privileged", "privileged-environment"},
    "OBAAF-GHA-002": {"checkout", "checkout-unresolved", "fetch", "fetch-unresolved"},
    "OBAAF-GHA-003": {"inherited", "undeclared", "write"},
    "OBAAF-GHA-004": {""},
    "OBAAF-GHA-005": {"secrets"},
    "OBAAF-GHA-006": {"called-restores", "needed-job-restores"},
    "OBAAF-GHA-007": {""},
    "OBAAF-GHA-008": {"action", "container", "image", "image-expression", "image-unreadable", "reusable-workflow"},
    "OBAAF-GHA-009": {""},
    "OBAAF-GHA-010": {"", "indirect", "through-matrix"},
    "OBAAF-GHA-011": {""},
    "OBAAF-GHA-012": {"fetch", "fetch-unresolved", "head", "merge-commit", "unresolved"},
    "OBAAF-GHA-014": {"", "capability"},
    "OBAAF-GHA-015": {"", "capability-call", "environment"},
    "OBAAF-GHA-016": {"unchecked"},
    "OBAAF-GHA-017": {""},
    "OBAAF-GHA-018": {"action", "command", "secrets"},
    "OBAAF-GHA-019": {""},
    "OBAAF-GHA-021": {"no-proposal", "no-record", "unchecked"},
    "OBAAF-GHA-022": {""},
    "OBAAF-GHA-023": {""},
    "OBAAF-GHA-024": {"caller", "environment-expression", "environment-not-a-name", "environment-unsure",
                      "no-environment", "other-environment"},
    "OBAAF-GHA-025": {"agent-cli", "piped-download"},
    "OBAAF-GHA-026": {"option", "setting"},
    **{f"OBAAF-JEN-{n:03d}": {""} for n in range(1, 16)},
    "OBAAF-REPO-001": {"gate-no-owner", "no-owner"},
    "OBAAF-REPO-002": {"no-owner"},
}


def _is_add(func):
    """`self.add(...)` or `add(...)`, the calls that report a finding (not `self.applicable.add`)."""
    if isinstance(func, ast.Name):
        return func.id == "add"
    return (isinstance(func, ast.Attribute) and func.attr == "add"
            and isinstance(func.value, ast.Name) and func.value.id == "self")


def _literals(node):
    """The strings an expression is when it is a literal, or a choice between two literals."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        body, orelse = _literals(node.body), _literals(node.orelse)
        return body | orelse if body and orelse else set()
    return set()


def _trees():
    return [ast.parse(path.read_text(encoding="utf-8")) for path in sorted(SRC.rglob("*.py"))]


def literal_kinds(rules):
    """Each (rule, kind) an `add` call in the package writes out, for the rules in `rules`."""
    found = set()
    for tree in _trees():
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _is_add(node.func) and node.args
                    and isinstance(node.args[0], ast.Constant) and node.args[0].value in rules):
                continue
            kind = next((k.value for k in node.keywords if k.arg == "kind"), ast.Constant(""))
            found.update((node.args[0].value, value) for value in _literals(kind))
    return found


def _own_nodes(function):
    """The nodes of a function's body, without those of the functions defined inside it."""
    todo = list(ast.iter_child_nodes(function))
    while todo:
        node = todo.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            todo.extend(ast.iter_child_nodes(node))


# Rules whose kinds are written outside the function that reports them, and only there.
KINDS_WRITTEN_IN = {"OBAAF-INS-001": "_examine_instruction_file"}


def kind_words(rules):
    """For each rule, the string literals of the functions that report it: its kinds can only be
    one of them, or one followed by another that begins with "-" ("no-cache-mode" + "-self-hosted")."""
    from obaaf.checker import _IDLE_TEMPLATES

    words = {"OBAAF-CFG-001": set(_IDLE_TEMPLATES)}
    functions = [node for tree in _trees() for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for function in functions:
        own = list(_own_nodes(function))
        literals = {n.value for n in own if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for node in own:
            if (isinstance(node, ast.Call) and _is_add(node.func) and node.args
                    and isinstance(node.args[0], ast.Constant) and node.args[0].value in rules
                    and node.args[0].value not in KINDS_WRITTEN_IN):
                words.setdefault(node.args[0].value, set()).update(literals)
    for rule, name in KINDS_WRITTEN_IN.items():
        for function in functions:
            if function.name == name:
                words.setdefault(rule, set()).update(
                    n.value for n in _own_nodes(function) if isinstance(n, ast.Constant) and isinstance(n.value, str))
    return words


class LiteralKindsTest(unittest.TestCase):
    def test_every_literal_kind_has_its_own_cause_or_was_read_against_the_remainder(self):
        causes = load().causes
        found = literal_kinds(set(load().rules))
        self.assertGreater(len(found), 60)
        unread = sorted(pair for pair in found
                        if pair not in causes._exact and pair[1] not in REMAINDER_READ.get(pair[0], set()))
        self.assertEqual(unread, [], "assign these a cause in causes.yaml, or read the rule's remaining-kinds "
                                     "cause and add them to REMAINDER_READ")
        listed = {(rule, kind) for rule, kinds in REMAINDER_READ.items() for kind in kinds}
        self.assertEqual(sorted(listed - found), [], "REMAINDER_READ names kinds the checker no longer writes")
        self.assertEqual(sorted(listed & set(causes._exact)), [], "REMAINDER_READ names kinds with a cause")

    def test_agent_cli_kinds_have_their_own_causes(self):
        causes = load().causes
        action = causes.for_finding("OBAAF-GHA-026", "setting")
        self.assertIs(causes.for_finding("OBAAF-GHA-026", "option"), action)
        option = causes.for_finding("OBAAF-GHA-026", "command-option")
        unread = causes.for_finding("OBAAF-GHA-026", "command-computed")
        self.assertEqual(len({action.id, option.id, unread.id,
                              causes.for_finding("OBAAF-GHA-026", "computed").id}), 4)
        self.assertIn("CLI", option.sentence)
        self.assertIn("cannot read", unread.sentence)

    def test_every_kind_the_catalogue_names_is_written_where_its_rule_is_reported(self):
        # A misspelt kind on both sides of an exception would pass the consistency check, and the
        # real kind would get the remainder's advice. A kind is a literal of a function that reports
        # its rule, or two of them joined, the second beginning with "-" (see kind_words).
        causes = load().causes
        words = kind_words(set(load().rules))

        def written(rule, kind):
            own = words.get(rule, set())
            return kind in own or any(kind == a + b for a in own for b in own if b.startswith("-"))

        self.assertEqual(sorted(pair for pair in causes._exact if not written(*pair)), [])
        for rule, typo in (("OBAAF-CFG-001", "entry-no-jobs"), ("OBAAF-INS-001", "not-utf-8"),
                           ("OBAAF-INS-001", "not-loaded"), ("OBAAF-GHA-006", "no-cache-mode-selfhosted"),
                           ("OBAAF-GHA-006", "no-cache-mode-agent"), ("OBAAF-GHA-026", "comand-option"),
                           ("OBAAF-GHA-001", "pull-request-agent")):
            with self.subTest(rule=rule, typo=typo):
                self.assertFalse(written(rule, typo))
        for rule, real in (("OBAAF-GHA-006", "no-cache-mode-self-hosted"), ("OBAAF-GHA-007", "unreadable"),
                           ("OBAAF-INS-001", "not-utf8"), ("OBAAF-CFG-001", "entry-no-stage")):
            with self.subTest(rule=rule, real=real):
                self.assertTrue(written(rule, real))

    def test_fix_kinds_follow_the_adoption_design(self):
        # docs/adoption-experience-design.md: the first version has two tightening fixes, OBAAF-GHA-011's
        # and OBAAF-GHA-025's; confinement is how the agent runs; Jenkins findings are by hand.
        causes = load().causes
        pairs = [(rule, cause) for rule, cause in causes._remaining.items()]
        pairs += [(rule, cause) for (rule, _kind), cause in causes._exact.items()]
        by_kind = {}
        for rule, cause in pairs:
            by_kind.setdefault(cause.fix_kind, set()).add(rule)
        self.assertLessEqual(by_kind.get("tightening", set()), {"OBAAF-GHA-011", "OBAAF-GHA-025"})
        self.assertLessEqual(by_kind.get("confinement", set()), {"OBAAF-GHA-005", "OBAAF-GHA-020"})
        self.assertLessEqual(by_kind.get("paperwork", set()), {"OBAAF-CFG-001"})


class CauseFieldChecksTest(unittest.TestCase):
    def problems(self, **changes):
        rows = [{**entry("all", rules=[JENKINS]), **changes}, entry("lanes", rules=[LANE])]
        return CauseCatalog({"causes": rows}, {JENKINS, LANE}).problems

    def test_the_shipped_shape_has_no_problem(self):
        self.assertEqual(self.problems(), [])

    def test_each_field_check_reports_on_its_own(self):
        cases = {
            "fix kind not in the design": ({"fix_kind": "automatic"}, "invalid fix_kind"),
            "id not lower-case words": ({"id": "All_Causes"}, "invalid id"),
            "id with a trailing hyphen": ({"id": "all-"}, "invalid id"),
            "selector repeated": ({"except_kinds": {JENKINS: ["a", "a"]}}, "repeated except_kinds"),
            "exception for a rule not selected": ({"except_kinds": {LANE: ["x"]}}, "unknown rule"),
            "empty sentence": ({"sentence": "  "}, "nonempty"),
        }
        for name, (changes, expected) in cases.items():
            with self.subTest(name=name):
                problems = self.problems(**changes)
                self.assertTrue(any(expected in p for p in problems), problems)
