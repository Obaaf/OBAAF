"""Slice 3.2c (from #202): each rule of the settings audit says in one line why its findings matter.

Every rule of `obaaf audit`, OBAAF-SET-001 to 015, has a `why`: one sentence of at most `WHY_MAX`
characters, held to the same form as the `why` of the rules of `obaaf check` (slice 3.2b). The text report
prints it as `Why:` under each rule's findings, before its fix, and `--no-fixes` leaves both out; the JSON
report carries it, and the fix, on each rule's entry; the guide lists every sentence.
"""

import json
import re
import unittest
from dataclasses import fields

from helpers import ROOT
from test_settings_audit import recording
from test_settings_rules import ADMIN, INCIDENT_REPO, assess, audit_command, of

from obaaf.audit import report, rules
from obaaf.catalog import WHY_MAX, _SENTENCE_END

# A rule's line is indented by four spaces. The list of what was not read has its own `Why:` lines, about why
# a setting was not read, indented by six (the review of slice 3.2c): they are not this slice's.
RULE_WHY = re.compile(r"^    Why: ", re.M)


def _form_problems(why: str) -> list[str]:
    """What the catalogue would say of this `why`, by the same tests (slice 3.2b's `Catalog.problems`)."""
    why = " ".join(why.split())
    out = []
    if not why:
        out.append("missing")
    if len(why) > WHY_MAX:
        out.append(f"longer than {WHY_MAX} characters ({len(why)})")
    if why and not why.endswith("."):
        out.append("no full stop at the end")
    if why and _SENTENCE_END.search(why[:-1]):
        out.append("more than one sentence")
    return out


class SentenceTest(unittest.TestCase):
    def test_every_rule_has_a_why_of_one_short_sentence(self):
        self.assertEqual(len(rules.RULES), 15)
        for rule in rules.RULES:
            with self.subTest(rule=rule.id):
                self.assertEqual(_form_problems(rule.why), [])
                # As for the catalogue's sentences: no ". " anywhere, which a second sentence that begins in
                # lower case would need.
                self.assertNotIn(". ", rule.why)
                # Written on one line of the report: no line break or tab inside it, no space around it.
                self.assertEqual(rule.why, " ".join(rule.why.split()))

    def test_the_form_check_refuses_what_the_catalogue_refuses(self):
        for bad in ("", "x" * WHY_MAX + ".", "No full stop", "Two sentences. Here.", "Is it? Yes.", "One.Two.",
                    "Two sentences. `GITHUB_TOKEN` leaks.", "Two. 3 more."):
            with self.subTest(why=bad[:20]):
                self.assertTrue(_form_problems(bad))
        self.assertEqual(_form_problems("A word, e.g. this one, is fine."), [])

    def test_a_rule_cannot_be_defined_without_one(self):
        why = next(f for f in fields(rules.Rule) if f.name == "why")
        self.assertTrue(why.kw_only)
        with self.assertRaises(TypeError):
            rules.Rule("OBAAF-SET-999", "title", "low", (), "compares", "description", "fix")  # no why

    def test_no_two_rules_share_a_sentence(self):
        whys = [rule.why for rule in rules.RULES]
        self.assertEqual(len(set(whys)), len(whys))


class ReportTest(unittest.TestCase):
    def test_the_text_report_says_why_before_each_rules_fix(self):
        code, out, _ = audit_command(ADMIN, INCIDENT_REPO, token=True)
        self.assertEqual(code, 1)
        found = assess(ADMIN)
        with_findings = [rule for rule in rules.RULES if of(found, rule.id, "finding")]
        self.assertGreaterEqual(len(with_findings), 5)
        lines = out.splitlines()
        whys = [line for line in lines if RULE_WHY.match(line)]
        self.assertEqual(len(whys), len(with_findings))
        for rule in with_findings:
            with self.subTest(rule=rule.id):
                at = lines.index(f"    Why: {rule.why}")
                # The fix follows at once, and the rule's heading is the nearest one above.
                self.assertEqual(lines[at + 1], f"    Fix: {rule.fix}")
                heading = next(line for line in reversed(lines[:at]) if re.match(r"^  OBAAF-SET-\d{3}  ", line))
                self.assertTrue(heading.startswith(f"  {rule.id}  "), heading)

    def test_a_rule_with_only_cannot_tell_gets_no_why(self):
        found = assess(ADMIN)
        only_unknown = [rule for rule in rules.RULES
                        if of(found, rule.id, "cannot-tell") and not of(found, rule.id, "finding")]
        self.assertTrue(only_unknown)
        out = "\n".join(report.findings_lines(found))
        for rule in only_unknown:
            self.assertNotIn(rule.why, out, rule.id)

    def test_no_fixes_leaves_out_the_why_with_the_fix(self):
        _, out, _ = audit_command(ADMIN, INCIDENT_REPO, "--no-fixes", token=True)
        self.assertIsNone(RULE_WHY.search(out))
        self.assertNotIn("    Fix: ", out)

    def test_the_lines_about_settings_not_read_are_left_alone(self):
        # A workflow's token cannot read every setting, so the report lists some as not read, each with a
        # `Why:` line of its own; --no-fixes keeps those and drops the rules' lines.
        entries = recording("workflow-token")
        _, out, _ = audit_command(entries, INCIDENT_REPO, token=True)
        _, short, _ = audit_command(entries, INCIDENT_REPO, "--no-fixes", token=True)
        unread = re.findall(r"^      Why: .*$", out, re.M)
        self.assertTrue(unread)
        self.assertEqual(re.findall(r"^      Why: .*$", short, re.M), unread)
        self.assertTrue(RULE_WHY.search(out))
        self.assertIsNone(RULE_WHY.search(short))

    def test_the_json_report_carries_each_rules_why_and_fix(self):
        code, out, _ = audit_command(ADMIN, INCIDENT_REPO, "--format", "json", token=True)
        self.assertEqual(code, 1)
        document = json.loads(out)
        self.assertEqual([entry["id"] for entry in document["rules"]], [rule.id for rule in rules.RULES])
        for entry, rule in zip(document["rules"], rules.RULES):
            with self.subTest(rule=rule.id):
                self.assertEqual(entry["why"], rule.why)
                self.assertEqual(entry["fix"], rule.fix)

    def test_the_result_file_still_counts_an_audit_report_that_has_them(self):
        # `python -m obaaf.result --audit` reads the report's rules by key and writes counts only (slice
        # 3.8): the new keys must neither break it nor reach the file.
        from obaaf.result import summarize_audit
        _, out, _ = audit_command(ADMIN, INCIDENT_REPO, "--format", "json", token=True)
        counted = summarize_audit(json.loads(out), frozenset(rule.id for rule in rules.RULES))
        self.assertEqual(sum(row["findings"] for row in counted["rules"]), 8)
        text = json.dumps(counted)
        for rule in rules.RULES:
            self.assertNotIn(rule.why, text)
            self.assertNotIn(rule.fix, text)


class GuideTest(unittest.TestCase):
    def test_the_guide_lists_every_rules_why_and_nothing_else(self):
        guide = (ROOT / "docs" / "settings-audit.md").read_text(encoding="utf-8")
        section = guide.split("### Why each finding matters\n", 1)[1].split("\n### ", 1)[0]
        listed = [line for line in section.splitlines() if line.startswith("- `OBAAF-SET-")]
        self.assertEqual(listed, [f"- `{rule.id}`: {rule.why}" for rule in rules.RULES])

    def test_the_guides_example_prints_the_rules_own_sentences(self):
        guide = (ROOT / "docs" / "settings-audit.md").read_text(encoding="utf-8")
        sentences = {rule.why for rule in rules.RULES}
        shown = re.findall(r"^    Why: (.*)$", guide, re.M)
        self.assertTrue(shown)
        for sentence in shown:
            self.assertIn(sentence, sentences)


if __name__ == "__main__":
    unittest.main()
