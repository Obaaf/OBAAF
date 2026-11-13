"""Parameters of a ruleset's pull_request rule beyond the count (flagship slice 2b.5).

GitHub's answer for the first adopter's ruleset carries `require_extra_approval_for_unattributed_changes: true`
beside `required_approving_review_count: 0`. Before this slice the two rules about approvals, OBAAF-SET-005
(required approvals cannot be given) and OBAAF-SET-013 (a workflow can give a required approval), read the
count and the code-owner flag only, and passed over every other parameter in silence: "not read" looked like
"nothing wrong".

Now every parameter GitHub's REST reference lists for the rule (read on 2026-11-13) is placed in the code as
read by the rules or as about neither how many approvals are needed nor who can give them, and a parameter
in neither, or one in a form the rules do not read, makes both rules "cannot tell" for its branch, naming it.
What GitHub's pages establish about each parameter is in docs/settings-audit.md.
"""

import copy
import unittest

from test_settings_audit import R, recording, replace
from test_settings_rules import (ADMIN, BRANCH_RULES, COLLABORATORS, assess_files, job, of, status, with_body,
                                 workflow)

from obaaf.audit import rules

CI = {"ci.yml": workflow("  pull_request:\n", job("test"))}
WORKFLOW_SETTINGS = f"{R}/actions/permissions/workflow"
PROTECTION = f"{R}/branches/main/protection"
EXTRA = "require_extra_approval_for_unattributed_changes"


def people(entries, count: int) -> list[dict]:
    """The recording with ``count`` collaborators who can push and nobody else."""
    return with_body(entries, COLLABORATORS, lambda body: body.__setitem__(slice(None), [
        {"login": f"user{n}", "id": n, "permissions": {"pull": True, "triage": True, "push": True,
                                                      "maintain": False, "admin": False}}
        for n in range(count)]))


def pull_request(entries, **parameters) -> list[dict]:
    """The recording with the branch's pull_request rule's parameters updated (None removes one)."""
    def change(body):
        rule = next(r for r in body if r["type"] == "pull_request")["parameters"]
        for name, value in parameters.items():
            if value is None:
                rule.pop(name, None)
            else:
                rule[name] = value
    return with_body(entries, BRANCH_RULES, change)


def second_ruleset(entries, **parameters) -> list[dict]:
    """The recording with a second ruleset's pull_request rule in force on the branch."""
    def change(body):
        body.append({"type": "pull_request", "ruleset_source_type": "Repository",
                     "ruleset_source": "example-studio/game", "ruleset_id": 99, "parameters": parameters})
    return with_body(entries, BRANCH_RULES, change)


def approving(entries) -> list[dict]:
    """The recording with workflows allowed to approve pull requests."""
    return with_body(entries, WORKFLOW_SETTINGS, lambda body: body.update(can_approve_pull_request_reviews=True))


def results(found: dict, rule: str) -> list[tuple]:
    return [(r["state"], r["subject"]) for r in of(found, rule)]


class GitHubsOwnAnswersTest(unittest.TestCase):
    """The two answers GitHub gave about the first adopter, with no token (2026-11-12 and 2026-11-13)."""

    def adopter(self, name: str) -> dict:
        return assess_files(recording(name), CI, token=None, repository="Expectrail/Expectrail")

    def test_every_parameter_github_sent_is_placed(self):
        for name in ("live-expectrail-no-token", "live-expectrail-2026-11-13"):
            body = next(e for e in recording(name) if e["path"].endswith("/rules/branches/main?per_page=100"))["body"]
            parameters = next(r for r in body if r["type"] == "pull_request")["parameters"]
            self.assertEqual(len(parameters), 9, name)
            self.assertEqual(set(parameters) - rules.APPROVAL_PARAMETERS - rules.OTHER_PULL_REQUEST_PARAMETERS,
                             set(), name)

    def test_the_extra_approval_on_a_count_of_zero_does_nothing_and_the_rule_says_it_read_it(self):
        for name in ("live-expectrail-no-token", "live-expectrail-2026-11-13"):
            found = self.adopter(name)
            self.assertEqual(status(found, "OBAAF-SET-005"), "not-applicable", name)
            note = next(r["note"] for r in found["rules"] if r["id"] == "OBAAF-SET-005")
            self.assertEqual(note, 'no audited branch requires an approval (require_extra_approval_for_unattributed'
                                   '_changes is on a rule counting 0 on "main", where it adds none)')
            # Whether workflows may approve is not shown without a token, so the other rule cannot tell, and
            # for that reason only.
            unknown, = of(found, "OBAAF-SET-013")
            self.assertEqual((unknown["state"], unknown["unread"]), ("cannot-tell", ["workflow_permissions"]))


    def test_beside_a_parameter_the_rules_do_not_know_it_is_cannot_tell_not_does_not_apply(self):
        entries = with_body(recording("live-expectrail-2026-11-13"), BRANCH_RULES.replace(
            "example-studio/game", "Expectrail/Expectrail"), lambda body: next(
                r for r in body if r["type"] == "pull_request")["parameters"].update(require_human_approval=True))
        found = assess_files(entries, CI, token=None, repository="Expectrail/Expectrail")
        result, = of(found, "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn('"require_human_approval" = true', result["message"])


class TheParameterListTest(unittest.TestCase):
    def test_the_lists_are_the_nine_of_githubs_reference_and_do_not_overlap(self):
        self.assertEqual(rules.APPROVAL_PARAMETERS & rules.OTHER_PULL_REQUEST_PARAMETERS, frozenset())
        self.assertEqual(rules.APPROVAL_PARAMETERS | rules.OTHER_PULL_REQUEST_PARAMETERS, frozenset((
            "allowed_merge_methods", "dismiss_stale_reviews_on_push", "dismissal_restriction",
            "require_code_owner_review", EXTRA, "require_last_push_approval",
            "required_approving_review_count", "required_review_thread_resolution", "required_reviewers")))


class AParameterTheRulesDoNotKnowTest(unittest.TestCase):
    def test_with_no_approval_by_count_both_rules_cannot_tell_and_name_it(self):
        entries = approving(pull_request(ADMIN, required_approving_review_count=0, require_human_approval=True))
        found = assess_files(entries, CI)
        for rule in ("OBAAF-SET-005", "OBAAF-SET-013"):
            result, = of(found, rule)
            self.assertEqual((result["state"], result["subject"]), ("cannot-tell", 'branch "main"'), rule)
            self.assertIn('"require_human_approval" = true (ruleset 42), a parameter this audit does not know',
                          result["message"], rule)
        # Without it, both have nothing to say.
        plain = assess_files(approving(pull_request(ADMIN, required_approving_review_count=0)), CI)
        self.assertEqual(status(plain, "OBAAF-SET-005"), "not-applicable")
        self.assertEqual(status(plain, "OBAAF-SET-013"), "no-finding")

    def test_whatever_its_value_false_null_and_empty_included(self):
        for value in (False, None, [], {}, 0, ""):
            parameters = {"required_approving_review_count": 0, "future_review_rule": value}
            entries = with_body(ADMIN, BRANCH_RULES, lambda body, p=parameters: next(
                r for r in body if r["type"] == "pull_request").__setitem__("parameters", p))
            result, = of(assess_files(entries, CI), "OBAAF-SET-005")
            self.assertEqual(result["state"], "cannot-tell", value)
            self.assertIn('"future_review_rule" = ', result["message"])

    def test_with_approvals_the_accounts_can_give_it_is_cannot_tell_not_no_finding(self):
        entries = people(pull_request(ADMIN, require_human_approval=True), 3)
        result, = of(assess_files(entries, CI), "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("requires 1 approval, which 3 accounts can give each other", result["message"])
        self.assertEqual(status(assess_files(people(ADMIN, 3), CI), "OBAAF-SET-005"), "no-finding")

    def test_a_finding_by_count_stays_a_finding_and_names_it(self):
        finding, = of(assess_files(pull_request(ADMIN, require_human_approval=True), CI), "OBAAF-SET-005")
        self.assertEqual(finding["state"], "finding")  # one account, one approval: as before
        self.assertIn('Its rules also ask for what this audit cannot weigh: "require_human_approval"',
                      finding["message"])
        workflow_finding, = of(assess_files(approving(pull_request(ADMIN, require_human_approval=True)), CI),
                               "OBAAF-SET-013")
        self.assertEqual(workflow_finding["state"], "finding")
        self.assertIn('"require_human_approval" = true', workflow_finding["message"])

    def test_a_cannot_tell_given_for_another_reason_still_names_it(self):
        refused_protection = replace(pull_request(ADMIN, required_approving_review_count=0, future=True),
                                     PROTECTION, status=403, body={"message": "Resource not accessible"})
        result, = of(assess_files(refused_protection, CI), "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn('"future" = true (ruleset 42)', result["message"])
        no_people = replace(pull_request(ADMIN, future=True), COLLABORATORS, status=403,
                            body={"message": "Resource not accessible"})
        result, = of(assess_files(no_people, CI), "OBAAF-SET-005")
        self.assertEqual((result["state"], result["unread"]), ("cannot-tell", ["collaborators"]))
        self.assertIn('"future" = true (ruleset 42)', result["message"])
        found = assess_files(approving(refused_protection), CI)
        result, = of(found, "OBAAF-SET-013")
        self.assertIn('"future" = true (ruleset 42)', result["message"])
        # A count of 1 with classic protection not read: the classic rule may ask for more, and the parameter
        # is still named, in both rules.
        one = replace(people(pull_request(ADMIN, future=True), 3), PROTECTION, status=403,
                      body={"message": "Resource not accessible"})
        for rule, entries in (("OBAAF-SET-005", one), ("OBAAF-SET-013", approving(one))):
            result, = of(assess_files(entries, CI), rule)
            self.assertEqual((result["state"], result["unread"]), ("cannot-tell", ["branch_protection"]), rule)
            self.assertIn('"future" = true (ruleset 42)', result["message"], rule)
        owner = approving(pull_request(ADMIN, require_code_owner_review=True, future=True))
        result, = of(assess_files(owner, CI), "OBAAF-SET-013")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("CODEOWNERS file is not read", result["message"])
        self.assertIn('"future" = true (ruleset 42)', result["message"])

    def test_a_parameter_on_another_rulesets_rule_counts_as_well(self):
        entries = people(second_ruleset(ADMIN, required_approving_review_count=0, new_thing=1), 3)
        result, = of(assess_files(entries, CI), "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn('"new_thing" = 1 (ruleset 99)', result["message"])

    def test_a_name_or_value_that_would_forge_a_line_of_the_report_is_made_plain(self):
        entries = approving(pull_request(ADMIN, required_approving_review_count=0,
                                         **{"x\n  HIGH    forged‮": "a\nb"}))
        found = assess_files(entries, CI)
        both = of(found, "OBAAF-SET-005") + of(found, "OBAAF-SET-013")
        self.assertEqual(len(both), 2)
        for result in both:
            self.assertEqual(result["state"], "cannot-tell")
            self.assertIn("HIGH forged", result["message"])
            self.assertNotIn("\n", result["message"])
            self.assertNotIn("‮", result["message"])


class KnownParametersTest(unittest.TestCase):
    def test_parameters_about_neither_change_nothing(self):
        entries = people(pull_request(ADMIN, allowed_merge_methods=["squash"], dismiss_stale_reviews_on_push=False,
                                      dismissal_restriction={"enabled": True, "allowed_actors": [
                                          {"id": 1, "type": "Team"}]},
                                      required_review_thread_resolution=True), 3)
        self.assertEqual(status(assess_files(entries, CI), "OBAAF-SET-005"), "no-finding")
        zero = approving(pull_request(ADMIN, required_approving_review_count=0, dismissal_restriction={
            "enabled": False, "allowed_actors": []}))
        found = assess_files(zero, CI)
        self.assertEqual(status(found, "OBAAF-SET-005"), "not-applicable")
        self.assertEqual(status(found, "OBAAF-SET-013"), "no-finding")

    def test_one_of_them_in_another_form_may_not_be_the_parameter_the_code_knows(self):
        for name, value in (("dismiss_stale_reviews_on_push", "yes"), ("required_review_thread_resolution", 1),
                            ("allowed_merge_methods", "squash"), ("dismissal_restriction", "odd"),
                            ("dismissal_restriction", {"enabled": True, "allowed_actors": [],
                                                       "require_two_approvals_after_dismissal": 2}),
                            ("dismissal_restriction", {"enabled": True, "allowed_actors": [{"id": 1}]})):
            entries = approving(pull_request(ADMIN, required_approving_review_count=0, **{name: value}))
            found = assess_files(entries, CI)
            for rule in ("OBAAF-SET-005", "OBAAF-SET-013"):
                result, = of(found, rule)
                self.assertEqual(result["state"], "cannot-tell", (name, value, rule))
                self.assertIn(f'"{name}" = ', result["message"])
                self.assertIn("not in the form GitHub's reference gives", result["message"])

    def test_a_flag_that_is_not_true_or_false_is_cannot_tell(self):
        for name in ("require_code_owner_review", "require_last_push_approval", EXTRA):
            entries = approving(pull_request(ADMIN, required_approving_review_count=0, **{name: "true"}))
            found = assess_files(entries, CI)
            for rule in ("OBAAF-SET-005", "OBAAF-SET-013"):
                result, = of(found, rule)
                self.assertEqual(result["state"], "cannot-tell", (name, rule))
                self.assertIn(f'"{name}" = "true" (ruleset 42), not true or false', result["message"])

    def test_last_push_approval_with_no_approval_by_count_is_cannot_tell(self):
        entries = approving(pull_request(ADMIN, required_approving_review_count=0, require_last_push_approval=True))
        found = assess_files(entries, CI)
        for rule in ("OBAAF-SET-005", "OBAAF-SET-013"):
            result, = of(found, rule)
            self.assertEqual(result["state"], "cannot-tell", rule)
            self.assertIn("require_last_push_approval is set (ruleset 42) where no approval is required",
                          result["message"])

    def test_last_push_approval_with_approvals_changes_no_answer(self):
        # The author can push last; their pull request needs an approval from someone else anyway.
        with_it = pull_request(ADMIN, require_last_push_approval=True)
        self.assertEqual(results(assess_files(people(with_it, 2), CI), "OBAAF-SET-005"), [])
        self.assertEqual(status(assess_files(people(with_it, 2), CI), "OBAAF-SET-005"), "no-finding")
        self.assertEqual(len(of(assess_files(with_it, CI), "OBAAF-SET-005", "finding")), 1)
        self.assertEqual(len(of(assess_files(approving(with_it), CI), "OBAAF-SET-013", "finding")), 1)

    def test_last_push_approval_on_a_classic_rule_with_no_approval_by_count(self):
        classic = {"url": "x", "enforce_admins": {"enabled": True}, "required_pull_request_reviews": {
            "required_approving_review_count": 0, "require_last_push_approval": True}}
        entries = replace(with_body(ADMIN, BRANCH_RULES, lambda body: body.clear()), PROTECTION, status=200,
                          body=classic)
        result, = of(assess_files(entries, CI), "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("require_last_push_approval is set (the classic protection rule)", result["message"])
        classic["required_pull_request_reviews"]["require_last_push_approval"] = False
        entries = replace(with_body(ADMIN, BRANCH_RULES, lambda body: body.clear()), PROTECTION, status=200,
                          body=classic)
        self.assertEqual(status(assess_files(entries, CI), "OBAAF-SET-005"), "not-applicable")

    def test_a_code_owners_review_with_no_approval_by_count(self):
        # The page: "Require an approving review in pull requests that modify files that have a designated code
        # owner". Who the code owners are is the CODEOWNERS file, not read: the approvals rule cannot tell
        # whether anyone but the author can give it. A workflow is no code owner, so the other rule has nothing
        # a workflow could give.
        entries = approving(pull_request(ADMIN, required_approving_review_count=0, require_code_owner_review=True))
        found = assess_files(entries, CI)
        result, = of(found, "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("CODEOWNERS file", result["message"])
        self.assertEqual(status(found, "OBAAF-SET-013"), "no-finding")

    def test_a_code_owners_review_with_approvals_the_accounts_can_give(self):
        entries = people(pull_request(ADMIN, require_code_owner_review=True), 3)
        result, = of(assess_files(entries, CI), "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("requires 1 approval, which 3 accounts can give each other", result["message"])
        self.assertIn("require_code_owner_review", result["message"])


class TheExtraApprovalTest(unittest.TestCase):
    """`require_extra_approval_for_unattributed_changes`: "When Copilot opens a pull request without a human
    collaborator, require one more approving review if a non-zero approval count is required" (GitHub's REST
    reference); "This setting has no effect if the ruleset requires zero approvals" (Available rules for
    rulesets). Both read on 2026-11-13."""

    def test_on_a_count_of_zero_it_does_nothing(self):
        entries = approving(pull_request(ADMIN, required_approving_review_count=0, **{EXTRA: True}))
        found = assess_files(entries, CI)
        self.assertEqual(status(found, "OBAAF-SET-005"), "not-applicable")
        self.assertEqual(status(found, "OBAAF-SET-013"), "no-finding")

    def test_with_one_approval_and_two_accounts_the_copilot_pull_request_needs_two_and_gets_them(self):
        found = assess_files(people(pull_request(ADMIN, **{EXTRA: True}), 2), CI)
        self.assertEqual(status(found, "OBAAF-SET-005"), "no-finding")
        note = next(r["note"] for r in found["rules"] if r["id"] == "OBAAF-SET-005")
        self.assertIn('on "main" a pull request Copilot opens without a person needs one more, which they can give, '
                      'none being its author', note)
        self.assertLessEqual(len(note), 300)  # the report prints notes up to 300 characters

    def test_a_finding_by_count_says_the_copilot_pull_request_cannot_get_its_approvals_either(self):
        finding, = of(assess_files(pull_request(ADMIN, **{EXTRA: True}), CI), "OBAAF-SET-005")
        self.assertIn("A pull request Copilot opens without a person needs 2", finding["message"])
        self.assertNotIn("cannot weigh", finding["message"])

    def test_on_a_rule_of_zero_beside_another_rule_that_asks_for_approvals_it_adds_none(self):
        # "This setting has no effect if the ruleset requires zero approvals": its own ruleset.
        entries = people(second_ruleset(ADMIN, required_approving_review_count=0, **{EXTRA: True}), 2)
        found = assess_files(entries, CI)
        self.assertEqual(status(found, "OBAAF-SET-005"), "no-finding")
        note = next(r["note"] for r in found["rules"] if r["id"] == "OBAAF-SET-005")
        self.assertIn('require_extra_approval_for_unattributed_changes is on a rule counting 0 on "main", where '
                      'it adds none', note)
        self.assertNotIn("Copilot opens", note)

    def test_it_adds_one_to_its_own_rules_count_and_the_branch_needs_the_most_any_rule_asks(self):
        # Two rulesets with the flag, counting 2 and 1: a pull request Copilot opens without a person needs 3.
        entries = second_ruleset(pull_request(ADMIN, required_approving_review_count=2, **{EXTRA: True}),
                                 required_approving_review_count=1, **{EXTRA: True})
        finding, = of(assess_files(entries, CI), "OBAAF-SET-005")
        self.assertIn("A pull request Copilot opens without a person needs 3", finding["message"])
        # A rule of 1 with the flag beside a rule of 3: such a pull request needs 3, not 2, which is the count.
        entries = people(second_ruleset(ADMIN, required_approving_review_count=3), 4)
        entries = pull_request(entries, **{EXTRA: True})
        found = assess_files(entries, CI)
        self.assertEqual(status(found, "OBAAF-SET-005"), "no-finding")
        self.assertNotIn("Copilot", next(r["note"] for r in found["rules"] if r["id"] == "OBAAF-SET-005"))

    def test_false_or_absent_changes_nothing(self):
        for value in (False, None):
            found = assess_files(people(pull_request(ADMIN, **{EXTRA: value}), 2), CI)
            self.assertEqual(status(found, "OBAAF-SET-005"), "no-finding", value)
            note = next(r["note"] for r in found["rules"] if r["id"] == "OBAAF-SET-005")
            self.assertNotIn("Copilot", note)


class RequiredReviewersTest(unittest.TestCase):
    TEAM = {"reviewer": {"id": 31, "type": "Team"}, "file_patterns": ["src/**", "*.yml"], "minimum_approvals": 1}

    def test_none_or_a_team_whose_approval_is_optional_changes_nothing(self):
        optional = dict(self.TEAM, minimum_approvals=0)
        for value in ([], [optional]):
            entries = approving(pull_request(ADMIN, required_approving_review_count=0, required_reviewers=value))
            found = assess_files(entries, CI)
            self.assertEqual(status(found, "OBAAF-SET-005"), "not-applicable", value)
            self.assertEqual(status(found, "OBAAF-SET-013"), "no-finding", value)

    def test_a_team_that_must_approve_is_cannot_tell_naming_it(self):
        entries = approving(pull_request(ADMIN, required_approving_review_count=0, required_reviewers=[self.TEAM]))
        found = assess_files(entries, CI)
        for rule in ("OBAAF-SET-005", "OBAAF-SET-013"):
            result, = of(found, rule)
            self.assertEqual(result["state"], "cannot-tell", rule)
            self.assertIn('required_reviewers asks team 31 for 1 approval on changes to files matching "src/**", '
                          '"*.yml" (ruleset 42), and who is in the team is not read', result["message"])

    def test_one_not_in_the_form_of_githubs_reference_is_cannot_tell(self):
        for value in ("team", [{"reviewer": {"id": "31"}, "file_patterns": ["*"], "minimum_approvals": 1}],
                      [dict(self.TEAM, minimum_approvals=-1)], [dict(self.TEAM, file_patterns="*")], [None],
                      # The reference gives the reviewer an id and the type "Team", and an entry nothing more: a
                      # field it does not list could add a requirement, even where the minimum is 0.
                      [dict(self.TEAM, reviewer={"id": 31})], [dict(self.TEAM, reviewer={"id": 31, "type": "User"})],
                      [dict(self.TEAM, minimum_approvals=0, approvals_required_from_outside_team=2)],
                      [dict(self.TEAM, reviewer={"id": 31, "type": "Team", "also": 1})]):
            entries = pull_request(ADMIN, required_approving_review_count=0, required_reviewers=value)
            result, = of(assess_files(entries, CI), "OBAAF-SET-005")
            self.assertEqual(result["state"], "cannot-tell", value)
            self.assertIn("not in the form GitHub's reference gives", result["message"])


class NothingElseMovesTest(unittest.TestCase):
    def test_the_other_rules_answer_as_they_did(self):
        before = assess_files(copy.deepcopy(ADMIN), CI)
        after = assess_files(pull_request(ADMIN, require_human_approval=True, required_reviewers=[
            RequiredReviewersTest.TEAM]), CI)
        for rule in rules.RULES:
            if rule.id in ("OBAAF-SET-005", "OBAAF-SET-013"):
                continue
            self.assertEqual(of(before, rule.id), of(after, rule.id), rule.id)


if __name__ == "__main__":
    unittest.main()
