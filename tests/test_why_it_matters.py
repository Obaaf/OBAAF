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

from helpers import RISKY, ROOT, run_cli

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
        for bad in ("x" * WHY_MAX + ".", "No full stop", "Two sentences. Here."):
            with self.subTest(why=bad[:20]):
                problems = _rules_with({"OBAAF-GHA-008": bad}).problems()
                self.assertTrue([p for p in problems if p.startswith("OBAAF-GHA-008: why must be one sentence")],
                                problems)


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
        # Under the message, before the requirement and the fix.
        lines = out.splitlines()
        first = next(i for i, line in enumerate(lines) if line.startswith("        Why: "))
        self.assertTrue(lines[first - 1].startswith("        ") and not lines[first - 1].startswith("        Why"))
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


if __name__ == "__main__":
    unittest.main()
