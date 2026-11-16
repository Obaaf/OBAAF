"""Slice 3.2b: each finding says in one line why it matters.

Every rule in the catalogue has a `why`, one sentence of at most `WHY_MAX` characters; the text
report prints it under each finding's message (and leaves it out with the fix under `--no-fixes`),
the JSON report carries it beside the fix, SARIF puts it first in each rule's help, and the
generated rule page has it under each rule.
"""

import copy
import json
import re
import unittest
from datetime import date, timedelta

from helpers import RISKY, ROOT, TempDir, run_cli

from obaaf.catalog import WHY_MAX, Catalog, load

PWN = RISKY / "pwn-request.yml"


def _rules_with(why_by_rule: dict) -> Catalog:
    """The catalogue with some rules' `why` replaced (None deletes it)."""
    c = load()
    data = {name: copy.deepcopy(getattr(c, attr)) for name, attr in (
        ("profile", "profile"), ("assessment", "assessment"), ("controls", "controls"),
        ("compromises", "compromises"), ("frameworks", "frameworks"), ("rules_data", "rules_data"),
        ("detection", "detection"))}
    for rule in data["rules_data"]["rules"]:
        if rule["id"] in why_by_rule:
            if why_by_rule[rule["id"]] is None:
                rule.pop("why", None)
            else:
                rule["why"] = why_by_rule[rule["id"]]
    return Catalog(**data)


class CatalogueTest(unittest.TestCase):
    def test_every_rule_has_a_why_of_one_short_sentence(self):
        c = load()
        self.assertEqual(c.problems(), [])
        for rule_id, rule in c.rules.items():
            why = " ".join(str(rule.get("why", "")).split())
            with self.subTest(rule=rule_id):
                self.assertTrue(why)
                self.assertLessEqual(len(why), WHY_MAX)
                self.assertTrue(why.endswith("."))
                self.assertNotIn(". ", why)

    def test_a_missing_or_long_why_is_a_problem_of_the_catalogue(self):
        self.assertIn("OBAAF-GHA-008: missing why", _rules_with({"OBAAF-GHA-008": None}).problems())
        self.assertIn("OBAAF-GHA-008: missing why", _rules_with({"OBAAF-GHA-008": "  "}).problems())
        for bad, problem in (("x" * WHY_MAX + ".", f"why must be at most {WHY_MAX} characters, not {WHY_MAX + 1}"),
                             ("No full stop", "why must end with a full stop"),
                             ("Two sentences. Here.", "why must be one sentence"),
                             ("Danger! Anyone can read it.", "why must be one sentence"),
                             ("Is it? Yes.", "why must be one sentence"),
                             ("One.Two.", "why must be one sentence")):
            with self.subTest(why=bad[:20]):
                self.assertIn(f"OBAAF-GHA-008: {problem}", _rules_with({"OBAAF-GHA-008": bad}).problems())
        for good in ("Pinned to v7.0.1 it cannot move.", "A word, e.g. this one, is fine."):
            with self.subTest(why=good):
                self.assertFalse([p for p in _rules_with({"OBAAF-GHA-008": good}).problems()
                                  if p.startswith("OBAAF-GHA-008:")])


class ReportTest(unittest.TestCase):
    def test_the_text_report_says_why_under_each_finding(self):
        code, out, _ = run_cli("check", PWN, "--fail-on", "never")
        self.assertEqual(code, 0)
        c = load()
        rules = re.findall(r"^\s+\d+\s+[A-Z]+\s+(OBAAF-[A-Z]+-\d+)\s", out, re.M)
        self.assertTrue(rules)
        whys = re.findall(r"^        Why: (.*)$", out, re.M)
        self.assertEqual(len(whys), len(rules))
        for rule_id, why in zip(rules, whys):
            self.assertEqual(why, " ".join(c.rules[rule_id]["why"].split()))
        # Directly under the message, which is directly under the finding's first line, and before the
        # requirement and the fix.
        lines = out.splitlines()
        first = next(i for i, line in enumerate(lines) if line.startswith("        Why: "))
        self.assertRegex(lines[first - 2], r"^\s+\d+\s+[A-Z]+\s+OBAAF-[A-Z]+-\d+\s")
        self.assertTrue(lines[first - 1].startswith("        ") and lines[first - 1][8:9] != " ")
        self.assertFalse(lines[first - 1].startswith(("        Why: ", "        Fix: ", "        Requirement: ")))
        after = lines[first + 1:]
        self.assertLess(next(i for i, l in enumerate(after) if l.startswith("        Requirement: ")),
                        next(i for i, l in enumerate(after) if l.startswith("        Fix: ")))

    def test_no_fixes_leaves_out_the_why_with_the_fix(self):
        code, out, _ = run_cli("check", PWN, "--fail-on", "never", "--no-fixes")
        self.assertEqual(code, 0)
        self.assertNotIn("        Why: ", out)
        self.assertNotIn("        Fix: ", out)
        self.assertIn("OBAAF-GHA-002", out)

    def test_json_and_sarif_carry_it(self):
        c = load()
        out = run_cli("check", PWN, "--fail-on", "never", "--format", "json")[1]
        findings = json.loads(out)["findings"]
        self.assertTrue(findings)
        for f in findings:
            self.assertEqual(f["why"], " ".join(c.rules[f["rule"]]["why"].split()))
        sarif = json.loads(run_cli("check", PWN, "--fail-on", "never", "--format", "sarif")[1])
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            why = " ".join(c.rules[rule["id"]]["why"].split())
            self.assertTrue(rule["help"]["text"].startswith(f"Why it matters: {why} Fix: "))
            self.assertTrue(rule["help"]["markdown"].startswith(f"**Why it matters:** {why}\n\n**Fix:** "))

    def test_the_rule_page_has_it_for_every_rule(self):
        page = (ROOT / "spec" / "checker-rules.md").read_text(encoding="utf-8")
        c = load()
        for rule_id, rule in c.rules.items():
            with self.subTest(rule=rule_id):
                section = page.split(f"## {rule_id}\n", 1)[1].split("\n## ", 1)[0]
                self.assertIn(f"**Why it matters.** {' '.join(rule['why'].split())}", section)


PR_SECRET = """\
name: x
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$T"
        env:
          T: ${{ secrets.TOKEN }}
"""
# Every file the check looks at owned, but not the baseline.
OWNED_BUT_THE_BASELINE = "".join(f"{p} @octocat\n" for p in (
    "/.github/workflows/", "/.github/CODEOWNERS", "/.github/obaaf.yml", "/.github/obaaf.yaml", "/obaaf.yml",
    "/.github/egress-firewall.yaml", "/CODEOWNERS", "/docs/CODEOWNERS"))
ACCEPT = ("--owner", "@octocat", "--reason", "Tracked in issue 12", "--expires",
          (date.today() + timedelta(days=60)).isoformat())


class WriteBaselineStatusTest(unittest.TestCase):
    """`--write-baseline` ends as `obaaf check --baseline` with the file it wrote and the same `--fail-on`."""

    def statuses(self, codeowners: str | None, fail_on: str) -> tuple[int, int, str]:
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "x.yml").write_text(PR_SECRET, encoding="utf-8")
            if codeowners is not None:
                (tmp / ".github" / "CODEOWNERS").write_text(codeowners, encoding="utf-8")
            baseline = tmp / ".github" / "obaaf-baseline.json"
            code, _, err = run_cli("check", tmp, "--write-baseline", baseline, "--fail-on", fail_on, *ACCEPT)
            gate = run_cli("check", tmp, "--baseline", baseline, "--fail-on", fail_on)[0]
        return code, gate, err

    def test_it_agrees_with_the_gate_whatever_the_threshold(self):
        # No CODEOWNERS file: OBAAF-REPO-001 (medium, authority) is a finding no entry can accept.
        # Every file owned but the baseline: the gate's OBAAF-REPO-001 names the baseline (the review's B1).
        for codeowners in (None, OWNED_BUT_THE_BASELINE):
            for fail_on in ("medium", "low", "high", "never", "authority", "authority:medium", "hygiene",
                            "hygiene:low"):
                with self.subTest(codeowners=codeowners is not None, fail_on=fail_on):
                    code, gate, err = self.statuses(codeowners, fail_on)
                    self.assertEqual(code, gate, err)
                    self.assertIn("not written: medium OBAAF-REPO-001", err)
                    self.assertIn("error:" if code else "warning:", err)

    def test_a_baseline_the_check_owns_leaves_nothing_out(self):
        owned = OWNED_BUT_THE_BASELINE + "/.github/obaaf-baseline.json @octocat\n"
        code, gate, err = self.statuses(owned, "low")
        self.assertEqual((code, gate), (0, 0), err)
        self.assertNotIn("not written", err)


if __name__ == "__main__":
    unittest.main()
