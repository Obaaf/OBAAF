"""The to-do list accounts for every outstanding finding exactly once."""

from datetime import date
import json
import shlex
import unittest

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
