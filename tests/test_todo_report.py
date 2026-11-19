"""The to-do list accounts for every outstanding finding exactly once."""

from datetime import date
import json
import shlex
import unittest

from obaaf.cli import build_parser
from obaaf.checker.todo_acceptance import migration_command
from obaaf.checker import CheckResult, Config, acceptance, baseline, report
from obaaf.checker.rules import Control, Finding, VERIFIED


class TodoReportTest(unittest.TestCase):
    def test_count_each_outstanding_finding_once_without_changing_the_gate(self):
        rule = "OBAAF-GHA-025"
        path = "build.yml"
        eligible = Finding(rule, "high", path, 1, "Install.", kind="agent-cli", pin_candidate="claude")
        manual = Finding(rule, "medium", path, 2, "Download.", kind="piped-download")
        ownerless = Finding(rule, "high", path, 3, "No owner.")
        ownerless.acceptance = acceptance.make(acceptance.IGNORE, None, "reviewed", "2027-01-01",
                                               date(2026, 11, 19))
        accepted = Finding(rule, "high", path, 4, "Accepted.", baselined=True)
        cleared = Finding(rule, "high", path, 5, "Cleared.", controls=[Control("Example", VERIFIED)])
        previous = Finding("OBAAF-GHA-005", "high", "another.yml", 2, "Secrets.", job="agent")
        result = CheckResult([eligible, manual, ownerless, accepted, cleared, previous], [], [], Config(),
                             today=date(2026, 11, 19))
        result.baseline_stale = [{"rule": previous.rule, "path": previous.path, "job": previous.job}]
        before = [f.state for f in result.findings]
        data = json.loads(report.to_json(result))
        after = [f.state for f in result.findings]
        self.assertEqual(before, after)
        groups = {g["id"]: g for g in data["todo"]}
        self.assertEqual(sum(g["count"] for g in data["todo"]), 4)
        self.assertEqual(groups["acceptance-owner-missing"]["count"], 1)
        self.assertEqual(groups["agent-secrets"]["previousMatches"], 1)
        install = groups["agent-tool-version"]
        self.assertEqual((install["count"], install["pinCandidates"], install["byHand"]), (2, 1, 1))
        self.assertEqual(install["bySeverity"], {"high": 1, "medium": 1, "low": 0, "info": 0})

    def test_migration_with_the_original_check_inputs_precedes_manual_work(self):
        first = Finding("OBAAF-GHA-025", "low", "wf", 2, "Old entry.")
        other = Finding("OBAAF-JEN-001", "high", "Jenkinsfile", 3, "Fix by hand.")
        result = CheckResult([other, first], [], [], Config(), checked="folder with spaces",
                             options=["--config=ops/config.yml", "--platform=github"])
        first.acceptance = acceptance.Acceptance(acceptance.BASELINE, problems=[baseline.V1_PROBLEM])
        result.baseline_path = "ops/team's baseline.json"
        result.baseline_format = baseline.FORMAT_V1
        groups = json.loads(report.to_json(result))["todo"]
        self.assertEqual(groups[0]["id"], "acceptance-old-baseline")
        self.assertEqual(shlex.split(groups[0]["command"]), [
            "obaaf", "baseline", "migrate", result.baseline_path, result.checked,
            "--owner", "OWNER", "--reason", "REASON", "--expires", "YYYY-MM-DD", *result.options])

    def test_migration_command_parses_relative_paths_starting_with_a_dash(self):
        result = CheckResult([], [], [], Config(), checked="-source", baseline_path="-old.json")
        args = build_parser().parse_args(shlex.split(migration_command(result))[1:])
        self.assertEqual((args.file, args.path), ("./-old.json", "./-source"))


class TodoOrderAndFieldsTest(unittest.TestCase):
    """What each entry says and the order of entries (D-092), from the review of #258."""

    def todo(self, findings, **result_fields):
        result = CheckResult(findings, [], [], Config(), today=date(2026, 11, 19))
        for name, value in result_fields.items():
            setattr(result, name, value)
        return json.loads(report.to_json(result))["todo"]

    def test_ordering_is_migration_then_highest_severity_then_count_then_id(self):
        old = Finding("OBAAF-GHA-011", "low", "wf", 1, "Old entry.")
        old.acceptance = acceptance.Acceptance(acceptance.BASELINE, problems=[baseline.V1_PROBLEM])
        lows = [Finding("OBAAF-GHA-009", "low", "wf", n, "Implicit.") for n in range(2, 5)]
        medium = Finding("OBAAF-GHA-023", "medium", "wf", 5, "Placeholder.")
        highs = [Finding("OBAAF-GHA-019", "high", "wf", 6, "Unsafe."),
                 *(Finding("OBAAF-GHA-010", "high", "wf", n, "Script.") for n in (7, 8))]
        other_high = Finding("OBAAF-GHA-002", "high", "wf", 9, "Checkout.")
        groups = self.todo([*lows, medium, *highs, other_high, old],
                           baseline_format=baseline.FORMAT_V1, baseline_path="b.json")
        self.assertEqual([g["id"] for g in groups], [
            "acceptance-old-baseline",       # the one action the CLI can take now
            "untrusted-script-text",         # high, 2 findings
            "privileged-checkout",           # high, 1, and before unsafe-checkout-option by id
            "unsafe-checkout-option",        # high, 1
            "template-placeholder",          # medium
            "implicit-token-permissions",    # low, 3: count never outranks severity
        ])
        self.assertEqual([g["count"] for g in groups], [1, 2, 1, 1, 1, 3])

    def test_fields_of_a_rule_entry_and_an_acceptance_entry(self):
        ownerless = Finding("OBAAF-GHA-011", "high", "wf", 1, "Kept.")
        ownerless.acceptance = acceptance.make(acceptance.IGNORE, None, "reviewed", "2027-01-01",
                                               date(2026, 11, 19))
        plain = Finding("OBAAF-GHA-009", "low", "wf", 2, "Implicit.")
        by_id = {g["id"]: g for g in self.todo([ownerless, plain])}
        rule, accept = by_id["implicit-token-permissions"], by_id["acceptance-owner-missing"]
        self.assertEqual((rule["kind"], accept["kind"]), ("rule", "acceptance"))
        for group in (rule, accept):
            with self.subTest(group=group["id"]):
                self.assertIsNone(group["command"])           # a manual step has no command
                self.assertNotEqual(group["nextAction"], group["sentence"])
                self.assertNotIn("previousMatches", group)
                self.assertNotIn("pinCandidates", group)
                self.assertEqual(group["count"], sum(group["bySeverity"].values()))

    def test_a_hint_goes_only_to_the_group_whose_finding_shares_the_location(self):
        secrets = Finding("OBAAF-GHA-005", "high", "a.yml", 1, "Secrets.", job="agent", kind="secrets")
        other = Finding("OBAAF-GHA-009", "low", "a.yml", 2, "Implicit.", job="agent")
        groups = self.todo([secrets, other], baseline_stale=[
            {"rule": "OBAAF-GHA-005", "path": "a.yml", "job": "agent"}])
        by_id = {g["id"]: g for g in groups}
        self.assertEqual(by_id["agent-secrets"]["previousMatches"], 1)
        self.assertNotIn("previousMatches", by_id["implicit-token-permissions"])

    def test_the_report_is_written_whatever_the_list_cannot_read(self):
        odd = Finding("OBAAF-GHA-009", "critical", "wf", 1, "Odd severity.")
        old = Finding("OBAAF-GHA-011", "low", "wf", 2, "Old entry.")
        old.acceptance = acceptance.Acceptance(acceptance.BASELINE, problems=[baseline.V1_PROBLEM])
        stale = [{"path": "wf"}, {"rule": "OBAAF-GHA-009", "path": "wf", "job": ["j"]}, "not an entry"]
        groups = self.todo([odd, old], baseline_stale=stale, baseline_format=baseline.FORMAT_V1, options=None)
        self.assertEqual(sum(g["count"] for g in groups), 2)

    def test_an_inconsistent_catalogue_leaves_the_list_empty_and_says_why(self):
        from obaaf.catalog import load
        from obaaf.causes import CauseCatalog
        import copy
        catalog = copy.copy(load())
        catalog.causes = CauseCatalog({"causes": []}, catalog.rules)
        result = CheckResult([Finding("OBAAF-GHA-009", "low", "wf", 1, "Implicit.")], [], [], Config())
        data = json.loads(report.to_json(result, catalog))
        self.assertEqual(data["todo"], [])
        self.assertTrue(any("cause catalogue is inconsistent" in note for note in data["notes"]))

    def test_acceptance_causes_do_not_share_an_id_with_the_catalogue(self):
        import ast
        from pathlib import Path
        from obaaf.catalog import load
        from obaaf.checker import todo_acceptance
        tree = ast.parse(Path(todo_acceptance.__file__).read_text(encoding="utf-8"))
        ids = {node.args[0].value for node in ast.walk(tree)
               if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Cause"
               and node.args and isinstance(node.args[0], ast.Constant)}
        self.assertGreaterEqual(len(ids), 11)
        causes = load().causes
        shipped = {c.id for c in [*causes._remaining.values(), *causes._exact.values()]}
        self.assertEqual(ids & shipped, set())
