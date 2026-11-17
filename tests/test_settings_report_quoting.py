"""Flagship slice 2b.8 (issue #125): names in the settings report's "What was read" cannot pass for other text.

A required check, a reviewer, a secret, an event or a workflow path is a name from outside: from GitHub, or
from a snapshot file, which can hold anything. In a list each is now printed in double quotes, which it
cannot close early, and a single value (a ruleset's enforcement, a branch, a setting's word) is printed as it
is only when it is one plain word.
"""

import copy
import unittest

from test_settings_audit import R, TOKEN, recording, replace, take

from obaaf.audit import github

from obaaf.audit import report
from obaaf.audit import snapshot as snapshot_mod

# The example in #125: a check name that, printed bare, reads as the end of one rule and a second rule of a
# type the audit does not know.
SPOOF = 'a), "evil" (a type this audit does not know), update, (b'


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


# A value that would pass for structure if printed bare: a comma, a bracket and a space.
BAD = "x, y (z"
SHOWN = '"x, y (z"'


def _snapshot() -> dict:
    """The administrator's recording, with every field the report prints from outside set to BAD (each is a
    value the snapshot's schema allows)."""
    snap, _ = take(recording("admin-token"), token=TOKEN)
    snap = copy.deepcopy(snap)
    s = snap["settings"]
    repo = s["repository"]["value"]
    repo.update(visibility=BAD, default_branch=BAD, owner=BAD)
    ruleset = s["rulesets"]["value"][0]
    ruleset.update(enforcement=BAD, target=BAD, source_type=BAD, source=BAD)
    ruleset["rules"].append({"type": "required_status_checks",
                             "parameters": {"required_status_checks": [{"context": BAD}]}})
    actor = s["ruleset_bypass_actors"]["value"][0]["actors"][0]
    actor.update(actor_type=BAD, bypass_mode=BAD)
    for rules_in_force in s["branch_rules"]["value"].values():
        rules_in_force.append({"type": "required_status_checks", "ruleset_id": 42, "ruleset_source_type": "Repository",
                               "ruleset_source": "example-studio/game",
                               "parameters": {"required_status_checks": [{"context": BAD}]}})
    env = s["environments"]["value"][0]
    env.update(deployment_branches="selected", branch_policies=[{"name": BAD, "type": BAD}],
               reviewers=[{"type": "User", "name": BAD, "id": 1}], other_protection_rules=[BAD])
    s["environment_secrets"]["value"] = {env["name"]: [BAD]}
    s["repository_secrets"]["value"] = [BAD]
    s["actions_permissions"]["value"].update(allowed_actions=BAD)
    s["actions_permissions"]["value"].pop("selected_actions", None)   # only "selected" has the list
    s["workflow_permissions"]["value"].update(default_workflow_permissions=BAD)
    s["fork_pull_requests"]["value"].update(approval_policy=BAD)
    policy = s["actions_policies"]["value"][0]
    policy.update(enforcement=BAD)
    policy["rules"] = [{"type": "restrict_action_events", "parameters": {"allowed_events": [BAD]}},
                       {"type": BAD, "parameters": {}}]
    policy["conditions"] = {"workflow_path": {"include": [BAD], "exclude": []}}
    for branch in s["branches"]["value"].values():
        branch["public_protection"] = {"enabled": True, "required_status_checks": {
            "strict": True, "enforcement_level": BAD, "contexts": [BAD], "checks": []}}
    snap["requested_as"] = BAD
    snap["api"] = BAD
    return snap


class EveryFieldTest(unittest.TestCase):
    """Each place the slice changed prints the bad value quoted (the review of slice 2b.8 found that reverting
    most of them one at a time left every test passing)."""

    def setUp(self):
        self.snap = _snapshot()
        self.assertEqual(snapshot_mod.problems(self.snap), [])
        # Without the origin line the header prints where the settings were read from.
        self.text = report.to_text(self.snap)
        self.lines = self.text.splitlines()

    def line(self, start: str) -> str:
        return next(l for l in self.lines if l.strip().startswith(start))

    def test_every_field_prints_quoted(self):
        cases = {
            "repository: visibility, default branch, owner": (
                f"{SHOWN} repository, default branch {SHOWN}, owned by the organisation {SHOWN}", 1),
            "ruleset: enforcement, target, source type, source": (
                f"({SHOWN}, {SHOWN}, from {SHOWN} {SHOWN}):", 1),
            "ruleset's required checks": (f"required_status_checks ({SHOWN})", 2),
            "pattern: type and name": (f"may deploy: {SHOWN} {SHOWN};", 1),
            "reviewers": (f"reviewers: {SHOWN};", 1),
            "other protection rules": (f"other rules: {SHOWN};", 1),
            "allowed actions": (f"allowed actions: {SHOWN};", 1),
            "default token permission": (f"the workflow token defaults to {SHOWN};", 1),
            "fork approval policy": (f"approval is required for: {SHOWN}", 1),
            "policy: enforcement": (f"({SHOWN}, from ", 1),
            "policy: paths": (f"for {SHOWN}:", 1),
            "policy: events": (f"only these events may start a workflow: {SHOWN}", 1),
            "policy: a rule of a type it does not know": (f"; {SHOWN}", 1),
            "the public view: checks and enforcement level": (
                f"required checks: {SHOWN} (enforcement: {SHOWN})", 1),
            "header: asked for as": (f"Asked for as {SHOWN};", 1),
            "header: where it was read from": (f"from {SHOWN}, with a token.", 1),
        }
        for what, (text, count) in cases.items():
            with self.subTest(what=what):
                self.assertGreaterEqual(self.text.count(text), count, text)
        # Nothing prints the value bare, anywhere.
        bare = [l for l in self.lines if BAD in l.replace(SHOWN, "")]
        self.assertEqual(bare, [])

    def test_the_bypass_actor_and_the_secrets_print_quoted(self):
        self.assertIn(f"{SHOWN} ({SHOWN})", self.line("ruleset 42 "))
        env = self.snap["settings"]["environments"]["value"][0]["name"]
        self.assertIn(f"{github.quoted(env)}: {SHOWN}", self.text)
        secrets = self.lines[self.lines.index("  Names of the repository's secrets") + 1]
        self.assertEqual(secrets.strip(), SHOWN)

    def test_patterns_and_bypass_actors_are_named_up_to_eight_as_before(self):
        snap = copy.deepcopy(self.snap)
        env = snap["settings"]["environments"]["value"][0]
        env["branch_policies"] = [{"name": f"p{i}", "type": "branch"} for i in range(10)]
        snap["settings"]["ruleset_bypass_actors"]["value"][0]["actors"] = [
            {"actor_type": "Team", "actor_id": i + 1, "bypass_mode": "always"} for i in range(10)]
        text = report.to_text(snap)
        self.assertIn('branch "p7" and 2 more;', text)
        self.assertIn("Team 8 (always) and 2 more", text)

    def test_a_quote_without_a_space_is_not_a_plain_word(self):
        self.assertEqual(report._token('x"y'), '"x\\"y"')


class LooksLikeAQuoteTest(unittest.TestCase):
    def test_issue_125s_example_with_a_look_alike_quote_stays_inside(self):
        # From the review of slice 2b.8: U+02F6 is a modifier letter that prints as a double quote.
        for mark in ("\u02f6", "\u02f5", "\u1cd3", "\u2e42", "\u275d", "\u275e", "\u2760", "\U0001f676", "\uff02"):
            with self.subTest(mark=hex(ord(mark))):
                shown = github.quoted(f"a){mark}, {mark}evil{mark} (b")
                self.assertEqual(shown, '"a)?, ?evil? (b"')

    def test_a_look_alike_backslash_cannot_make_the_closing_quote_look_escaped(self):
        for mark in ("\uff3c", "\ufe68", "\u29f5", "\u29f9", "\u2216", "\u2572", "\u27cd"):
            with self.subTest(mark=hex(ord(mark))):
                self.assertEqual(github.quoted(f"lint{mark}"), '"lint?"')

    def test_every_compatibility_form_of_a_quote_or_backslash_is_replaced(self):
        import unicodedata
        found = [chr(c) for c in range(0x80, 0x30000) if chr(c) not in '"\\'
                 and any(x in '"\\' for x in unicodedata.normalize("NFKC", chr(c)))]
        self.assertTrue(found)
        for ch in found:
            self.assertEqual(github.quoted(ch), '"?"', hex(ord(ch)))

    def test_names_with_ordinary_marks_are_left_alone(self):
        self.assertEqual(github.quoted("Sean\u2019s env, l'autre, caf\u00e9"), '"Sean\u2019s env, l\'autre, caf\u00e9"')


if __name__ == "__main__":
    unittest.main()
