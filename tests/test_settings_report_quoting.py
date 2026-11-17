"""Flagship slice 2b.8 (issue #125): names in the settings report's "What was read" cannot pass for other text.

A required check, a reviewer, a secret, an event or a workflow path is a name from outside: from GitHub, or
from a snapshot file, which can hold anything. In a list each is now printed in double quotes, which it
cannot close early, and a single value (a ruleset's enforcement, a branch, a setting's word) is printed as it
is only when it is one plain word.
"""

import copy
import unittest

from test_settings_audit import R, TOKEN, entry_for, recording, replace, take

from obaaf.audit import report

# The example in #125: a check name that, printed bare, reads as the end of one rule and a second rule of a
# type the audit does not know.
SPOOF = 'a), "evil" (a type this audit does not know), update, (b'


def _ruleset_checks(entries, names):
    for path in (f"{R}/rulesets/1?includes_parents=true", f"{R}/rules/branches/main?per_page=100"):
        try:
            body = entry_for(entries, path)["body"]
        except (StopIteration, KeyError, AssertionError):
            continue
        for rule in body["rules"] if isinstance(body, dict) else body:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"] = [{"context": n} for n in names]
    return entries


class ListedNamesTest(unittest.TestCase):
    def test_a_required_check_named_to_imitate_a_rule_is_printed_inside_its_quotes(self):
        text = report._rule_text({"type": "required_status_checks", "parameters": {
            "required_status_checks": [{"context": SPOOF}, {"context": "test"}]}})
        self.assertEqual(text, 'required_status_checks ("a), \\"evil\\" (a type this audit does not know), update, '
                               '(b", "test")')
        # Before the slice it printed `required_status_checks (a), "evil" (a type this audit does not know), ...`.
        self.assertNotIn('(a), "evil"', text)

    def test_classic_protection_checks_are_quoted_and_the_level_stays_outside(self):
        line = report._check_names({"contexts": ["test (3.13)", SPOOF], "checks": None})
        self.assertEqual(line, 'required checks: "a), \\"evil\\" (a type this audit does not know), update, (b", '
                               '"test (3.13)"')

    def test_every_list_of_names_quotes_each_one(self):
        self.assertEqual(report._list(["one", "two, three", 'four"']), '"one", "two, three", "four\\""')
        self.assertEqual(report._list([f"n{i}" for i in range(10)], 2), '"n0", "n1" and 8 more')

    def test_an_environment_names_its_patterns_and_reviewers_in_quotes(self):
        env = {"name": "prod", "deployment_branches": "selected", "wait_timer": 0,
               "branch_policies": [{"name": "main; no required reviewers", "type": "branch"},
                                   {"name": "v*", "type": "tag"}, {"name": "x", "type": None},
                                   {"name": "y", "type": "branch, tag"}],
               "reviewers": [{"type": "User", "name": "a, b"}], "prevent_self_review": True,
               "other_protection_rules": ["custom; reviewers: nobody"], "can_admins_bypass": False}
        self.assertEqual(report._environment_text(env),
                         '"prod": may deploy: branch "main; no required reviewers", tag "v*", pattern "x", '
                         '"branch, tag" "y"; reviewers: "a, b" (self-review prevented); other rules: '
                         '"custom; reviewers: nobody"; administrators may bypass these rules: no')


class SingleValuesTest(unittest.TestCase):
    def test_a_plain_word_is_printed_as_it_is_and_anything_else_is_quoted(self):
        for word in ("active", "main", "release/1.0", "v1.2.3", "Expectrail/Expectrail", "first_time_contributors",
                     "a+b", "user@example"):
            self.assertEqual(report._token(word), word)
        for value in ("active, evaluate", "main)", "two words", 'say "x"', "", "-flag", "é", "x" * 61):
            with self.subTest(value=value):
                self.assertEqual(report._token(value)[0], '"', value)

    def test_a_snapshot_cannot_fake_a_rulesets_enforcement_or_source(self):
        snap, _ = take(recording("admin-token"), token=TOKEN)
        snap = copy.deepcopy(snap)
        ruleset = snap["settings"]["rulesets"]["value"][0]
        ruleset.update(enforcement="active), x (", source="x y")
        line = next(l for l in report.to_text(snap).splitlines() if l.strip().startswith(f'"{ruleset["name"]}" ('))
        self.assertIn('("active), x (", ', line)
        self.assertIn('"x y"', line)

    def test_a_snapshot_cannot_fake_the_repositorys_line(self):
        snap, _ = take(recording("admin-token"), token=TOKEN)
        snap = copy.deepcopy(snap)
        snap["settings"]["repository"]["value"]["default_branch"] = "main, archived"
        text = report.to_text(snap)
        self.assertIn('default branch "main, archived",', text)

    def test_the_words_github_gives_read_as_before(self):
        # Only the names change: GitHub's words for a setting print as they did.
        entries = replace(recording("admin-token"), f"{R}/branches/main/protection", status=200, body={
            "enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False},
            "required_status_checks": {"contexts": ["ci"], "strict": True}})
        text = report.to_text(take(entries, token=TOKEN)[0])
        self.assertIn("the workflow token defaults to read; workflows may not approve pull requests", text)
        self.assertIn("approval is required for: first_time_contributors", text)
        self.assertIn('ruleset 42 "main protection": OrganizationAdmin (always), RepositoryRole 5 (pull_request)', text)
        self.assertIn('"main": no review required; required checks: "ci"; administrators are held to it', text)


if __name__ == "__main__":
    unittest.main()
