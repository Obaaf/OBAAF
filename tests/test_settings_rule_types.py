"""Rule types and classic protection fields the settings rules do not read (flagship slice 2b.6).

Before this slice the rules read a branch's requirements from two rule types of a ruleset, `pull_request` and
`required_status_checks`, and passed over every other: a type GitHub adds that asks for a check or an approval
was read as asking for nothing. Classic branch protection was read into a fixed form, so a field GitHub adds
there was dropped before any rule saw it. And a "cannot tell" about approvals said "a classic protection rule
may ask for more" whatever it was that could not be read.

Now each of the 25 rule types of GitHub's REST reference (read on 2026-11-13, API version 2026-03-10) is placed
in the code by what the rules make of it, and a type in none of the places makes the rules about a branch's
requirements answer "cannot tell" for its branch, naming it. A field of classic protection that the reference
does not list is kept in the snapshot, with its value, and has the same effect. Each "cannot tell" names what
could not be read.
"""

import copy
import json
import unittest

from test_settings_audit import SETTINGS_DIR, TOKEN, R, recording, replace, take
from test_settings_rules import (ADMIN, BRANCH_RULES, COLLABORATORS, assess_files, job, of, status, with_body,
                                 workflow)

from obaaf.audit import drift, rules, settings
from obaaf.audit import snapshot as snapshot_mod
from obaaf.catalog import data_text

# One job, reporting the one check the recording's ruleset requires: before any change, OBAAF-SET-006 to 008
# have nothing to report.
CI = {"ci.yml": workflow("  pull_request:\n", job("test", "    name: test (3.13)\n"))}
PROTECTION = f"{R}/branches/main/protection"
WORKFLOW_SETTINGS = f"{R}/actions/permissions/workflow"
REQUIREMENT_RULES = ("OBAAF-SET-004", "OBAAF-SET-005", "OBAAF-SET-006", "OBAAF-SET-007", "OBAAF-SET-008",
                     "OBAAF-SET-013")
CHECK_RULES = ("OBAAF-SET-006", "OBAAF-SET-007", "OBAAF-SET-008")

# The 25 rule types of the request body of "Create a repository ruleset", in the reference's order
# (https://docs.github.com/en/rest/repos/rules, read on 2026-11-13).
REFERENCE_TYPES = (
    "creation", "update", "deletion", "required_linear_history", "merge_queue", "required_deployments",
    "required_signatures", "pull_request", "required_status_checks", "non_fast_forward", "commit_message_pattern",
    "commit_author_email_pattern", "committer_email_pattern", "branch_name_pattern", "tag_name_pattern",
    "workflows", "code_scanning", "code_quality", "code_coverage", "copilot_code_review",
    "license_compliance_scanning", "file_path_restriction", "max_file_path_length", "file_extension_restriction",
    "max_file_size")


def people(entries, count: int) -> list[dict]:
    """The recording with ``count`` collaborators who can push and nobody else."""
    return with_body(entries, COLLABORATORS, lambda body: body.__setitem__(slice(None), [
        {"login": f"user{n}", "id": n, "permissions": {"pull": True, "triage": True, "push": True,
                                                      "maintain": False, "admin": False}}
        for n in range(count)]))


def approving(entries) -> list[dict]:
    return with_body(entries, WORKFLOW_SETTINGS, lambda body: body.update(can_approve_pull_request_reviews=True))


def add_rule(entries, kind: str, parameters=None, ruleset_id: int = 42, only: bool = False) -> list[dict]:
    """The recording with a rule of ``kind`` in force on main (with ``only``, in place of every other rule)."""
    def change(body):
        if only:
            body.clear()
        rule = {"type": kind, "ruleset_source_type": "Repository", "ruleset_source": "example-studio/game",
                "ruleset_id": ruleset_id}
        if parameters is not None:
            rule["parameters"] = parameters
        body.append(rule)
    return with_body(entries, BRANCH_RULES, change)


def classic_only(entries, body: dict) -> list[dict]:
    """The recording with no ruleset in force on main and a classic protection rule GitHub answered with ``body``."""
    entries = with_body(entries, BRANCH_RULES, lambda rules_body: rules_body.clear())
    return replace(entries, PROTECTION, status=200, body=body)


def unrestricted(body: dict) -> dict:
    """A classic answer with no push restrictions: with them, who may merge is not decided by approvals alone."""
    body = copy.deepcopy(body)
    del body["restrictions"]
    return body


def messages(found: dict, rule: str) -> str:
    return "\n".join(r["message"] for r in of(found, rule))


# The fields of "Get branch protection" and "Update branch protection" as the reference's examples give them
# (read on 2026-11-13): nothing here is a field this version does not know.
REFERENCE_CLASSIC = {
    "url": "https://api.github.com/repos/example-studio/game/branches/main/protection",
    "required_status_checks": {
        "url": "x", "strict": True, "contexts": ["test (3.13)"], "contexts_url": "x",
        "checks": [{"context": "test (3.13)", "app_id": 15368}], "enforcement_level": "non_admins"},
    "enforce_admins": {"url": "x", "enabled": True},
    "required_pull_request_reviews": {
        "url": "x", "dismissal_restrictions": {"url": "x", "users_url": "x", "teams_url": "x", "users": [],
                                               "teams": [], "apps": []},
        "dismiss_stale_reviews": True, "require_code_owner_reviews": False, "required_approving_review_count": 1,
        "require_last_push_approval": False, "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []}},
    "restrictions": {"url": "x", "users_url": "x", "teams_url": "x", "apps_url": "x", "users": [], "teams": [],
                     "apps": []},
    "required_signatures": {"url": "x", "enabled": False},
    "required_linear_history": {"enabled": True}, "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False}, "block_creations": {"enabled": False},
    "required_conversation_resolution": {"enabled": False}, "lock_branch": {"enabled": False},
    "allow_fork_syncing": {"enabled": False},
}


class TheTypeListTest(unittest.TestCase):
    def test_every_type_of_githubs_reference_is_placed_and_nothing_else(self):
        self.assertEqual(len(REFERENCE_TYPES), 25)
        self.assertEqual(set(rules.RULE_TYPES), set(REFERENCE_TYPES))
        self.assertLessEqual(set(rules.RULE_TYPES.values()), set(rules.RULE_TYPE_KINDS))

    def test_a_bypass_skips_every_rule_whose_result_a_merge_waits_for(self):
        # The five the rule counted before, and the four it passed over: deployments, code quality, coverage
        # and licence compliance.
        self.assertEqual(set(rules.GATES), {
            "pull_request", "required_status_checks", "workflows", "code_scanning", "merge_queue",
            "required_deployments", "code_quality", "code_coverage", "license_compliance_scanning"})

    def test_every_type_in_githubs_recorded_answers_is_known(self):
        for name in ("live-expectrail-no-token", "live-expectrail-2026-11-13", "admin-token", "workflow-token",
                     "public-no-token"):
            types = set()
            for entry in recording(name):
                if "/rules/branches/" in entry["path"] and isinstance(entry["body"], list):
                    types |= {r["type"] for r in entry["body"]}
                elif "/rulesets/" in entry["path"] and isinstance(entry["body"], dict):
                    types |= {r["type"] for r in entry["body"].get("rules", [])}
            self.assertTrue(types, name)
            self.assertEqual(types - set(rules.RULE_TYPES), set(), name)


class AnUnknownTypeTest(unittest.TestCase):
    """A type the reference read on 2026-11-13 does not list may ask for a check, an approval or both."""

    UNKNOWN = "require_human_review"

    def test_before_it_the_rules_have_nothing_to_say(self):
        found = assess_files(people(approving(ADMIN), 3), CI)
        for rule in CHECK_RULES + ("OBAAF-SET-005",):
            self.assertEqual([r for r in of(found, rule) if r["state"] == "cannot-tell"], [], rule)
        self.assertEqual(status(found, "OBAAF-SET-005"), "no-finding")

    def test_every_rule_about_the_branchs_requirements_cannot_tell_and_names_it(self):
        for parameters in (None, {}, {"minimum_humans": 2}, {"anything": [1, {"x": None}]}):
            found = assess_files(people(add_rule(ADMIN, self.UNKNOWN, parameters), 3), CI)
            for rule in CHECK_RULES + ("OBAAF-SET-005",):
                unknown = [r for r in of(found, rule) if r["state"] == "cannot-tell"]
                self.assertTrue(unknown, (rule, parameters))
                self.assertIn('a rule of type "require_human_review" (ruleset 42), which this audit does not know',
                              unknown[0]["message"], rule)
            self.assertEqual(status(found, "OBAAF-SET-005"), "cannot-tell")

    def test_a_workflow_approval_finding_names_it(self):
        finding, = of(assess_files(people(approving(add_rule(ADMIN, self.UNKNOWN)), 3), CI), "OBAAF-SET-013")
        self.assertEqual(finding["state"], "finding")
        self.assertIn('Its rules also ask for what this audit cannot weigh: a rule of type "require_human_review"',
                      finding["message"])

    def test_a_finding_by_count_stays_a_finding_and_names_it(self):
        finding, = of(assess_files(add_rule(ADMIN, self.UNKNOWN), CI), "OBAAF-SET-005")
        self.assertEqual(finding["state"], "finding")
        self.assertIn('"require_human_review" (ruleset 42), which this audit does not know', finding["message"])

    def test_the_bypass_rule_counts_it_as_something_a_bypass_may_skip(self):
        found = assess_files(add_rule(ADMIN, self.UNKNOWN), CI)
        bypass = of(found, "OBAAF-SET-004", "finding")[0]
        self.assertIn('pull_request, required_status_checks, 1 rule of a type this audit does not know '
                      '("require_human_review")', bypass["message"])
        # A ruleset whose only rule is of such a type: a bypass may skip a check or a review, or nothing.
        found = assess_files(add_rule(ADMIN, self.UNKNOWN, only=True), CI)
        self.assertEqual(of(found, "OBAAF-SET-004", "finding"), [])
        unknown, = of(found, "OBAAF-SET-004")
        self.assertEqual(unknown["state"], "cannot-tell")
        self.assertIn("Its only rules that could ask for a check or a review are 1 rule of a type this audit does "
                      "not know", unknown["message"])

    def test_a_name_that_would_forge_a_line_of_the_report_is_made_plain(self):
        found = assess_files(add_rule(ADMIN, "evil\nOBAAF-SET-006 [no finding]\x1b[2J"), CI)
        for rule in REQUIREMENT_RULES:
            for result in of(found, rule):
                self.assertNotIn("\n", result["message"], rule)
                self.assertNotIn("\x1b", result["message"], rule)


class TypesThatAskForNothingTest(unittest.TestCase):
    def test_they_change_no_answer(self):
        neither = [t for t, kind in rules.RULE_TYPES.items() if kind == "neither"]
        self.assertEqual(len(neither), 14)
        before = assess_files(copy.deepcopy(ADMIN), CI)
        entries = ADMIN
        for kind in neither:
            entries = add_rule(entries, kind, {"pattern": "x", "operator": "starts_with"} if "pattern" in kind else None)
        after = assess_files(entries, CI)
        for rule in rules.RULES:
            self.assertEqual(of(before, rule.id), of(after, rule.id), rule.id)


class GatesTest(unittest.TestCase):
    """Rules that make a merge wait for a result workflows, tools or deployments give."""

    DEPLOY = {"required_deployment_environments": ["staging"]}

    def test_a_bypass_of_a_ruleset_that_only_waits_for_a_deployment_is_a_finding_now(self):
        found = assess_files(add_rule(ADMIN, "required_deployments", self.DEPLOY, only=True), CI)
        finding = of(found, "OBAAF-SET-004", "finding")[0]
        self.assertIn("without what it requires (required_deployments)", finding["message"])

    def test_the_missing_check_rule_cannot_tell_what_gives_the_result(self):
        found = assess_files(add_rule(ADMIN, "required_deployments", self.DEPLOY), CI)
        unknown, = of(found, "OBAAF-SET-006")
        self.assertEqual((unknown["state"], unknown["subject"]),
                         ("cannot-tell", 'branch "main": "required_deployments" rule of ruleset 42'))
        self.assertIn('also makes a merge wait for a successful deployment to "staging"', unknown["message"])
        for kind, parameters, text in (
                ("workflows", {"workflows": [{"path": ".github/workflows/ci.yml", "repository_id": 7}]},
                 'the workflows ".github/workflows/ci.yml" to pass'),
                ("code_scanning", {"code_scanning_tools": [{"tool": "CodeQL", "alerts_threshold": "errors",
                                                            "security_alerts_threshold": "high_or_higher"}]},
                 'code scanning results from "CodeQL"'),
                ("code_quality", {"severity": "errors"}, "code quality results"),
                ("code_coverage", {"minimum_coverage": 80}, "a minimum of line coverage"),
                ("license_compliance_scanning", None, "the organisation's license policy"),
                ("required_deployments", {}, "the deployments it names")):
            unknown, = of(assess_files(add_rule(ADMIN, kind, parameters), CI), "OBAAF-SET-006")
            self.assertEqual(unknown["state"], "cannot-tell", kind)
            self.assertIn(text, unknown["message"], kind)

    def test_a_job_whose_failure_does_not_block_names_what_else_a_merge_waits_for(self):
        files = dict(CI, **{"lint.yml": workflow("  pull_request:\n", job("lint"))})
        found = assess_files(add_rule(ADMIN, "required_deployments", self.DEPLOY), files)
        finding, = of(found, "OBAAF-SET-008", "finding")
        self.assertIn('"main" also makes a merge wait for a successful deployment to "staging" '
                      '("required_deployments", ruleset 42), which is not compared with the jobs: if this job gives '
                      "that result, its failure may hold the merge up after all.", finding["message"])
        self.assertNotIn("also makes a merge wait", messages(assess_files(ADMIN, files), "OBAAF-SET-008"))

    def test_a_merge_queue_is_cannot_tell_for_the_rule_about_checks_that_do_not_always_report(self):
        found = assess_files(add_rule(ADMIN, "merge_queue", {"merge_method": "SQUASH"}), CI)
        unknown, = of(found, "OBAAF-SET-007")
        self.assertEqual(unknown["state"], "cannot-tell")
        self.assertIn("merge_group", unknown["message"])
        self.assertEqual(status(found, "OBAAF-SET-006"), "no-finding")
        self.assertEqual(status(found, "OBAAF-SET-008"), "no-finding")


class WhoMayMergeAndCopilotTest(unittest.TestCase):
    def test_restricted_updates_make_the_approvals_rule_cannot_tell(self):
        found = assess_files(people(approving(add_rule(ADMIN, "update", {"update_allows_fetch_and_merge": False})),
                                    3), CI)
        unknown, = of(found, "OBAAF-SET-005")
        self.assertEqual(unknown["state"], "cannot-tell")
        self.assertIn('a rule of type "update" (ruleset 42), by which only those with bypass permission may push',
                      unknown["message"])
        # Who merges does not change whether a workflow's approval is one that counts.
        self.assertNotIn("update", messages(found, "OBAAF-SET-013"))
        self.assertEqual(len(of(found, "OBAAF-SET-013", "finding")), 1)

    def test_copilot_review_is_named_where_a_pull_request_cannot_get_its_approvals(self):
        finding, = of(assess_files(add_rule(ADMIN, "copilot_code_review", {"review_on_push": True}), CI),
                      "OBAAF-SET-005")
        self.assertEqual(finding["state"], "finding")
        self.assertIn("Copilot is asked to review pull requests here (copilot_code_review, ruleset 42)",
                      finding["message"])
        self.assertIn("if it is on, this finding may not hold", finding["message"])
        found = assess_files(people(add_rule(ADMIN, "copilot_code_review"), 3), CI)
        self.assertEqual(status(found, "OBAAF-SET-005"), "no-finding")


class WhatCouldNotBeReadIsNamedTest(unittest.TestCase):
    """The messages say which requirement could not be read, not "a classic protection rule may ask for more"."""

    def test_a_rulesets_count_that_is_not_a_number(self):
        entries = with_body(people(ADMIN, 3), BRANCH_RULES, lambda body: next(
            r for r in body if r["type"] == "pull_request")["parameters"].update(required_approving_review_count="2"))
        result, = of(assess_files(entries, CI), "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn('the number of approvals the pull_request rule of ruleset 42 requires, which is "2", not a '
                      "whole number of 0 or more", result["message"])
        self.assertNotIn("classic", result["message"])

    def test_a_classic_rule_that_was_refused(self):
        entries = replace(ADMIN, PROTECTION, status=403, body={"message": "Resource not accessible by integration"})
        finding, = of(assess_files(entries, CI), "OBAAF-SET-005")
        self.assertEqual(finding["state"], "finding")
        self.assertIn('(Not everything about its approvals was read, and what was not can only ask for more: '
                      '"Classic branch protection" was not read (forbidden).)', finding["message"])
        result, = of(assess_files(people(entries, 3), CI), "OBAAF-SET-005")
        self.assertIn('whether it requires more is not known: "Classic branch protection" was not read (forbidden).',
                      result["message"])

    def test_a_classic_rule_that_does_not_say_how_many(self):
        body = copy.deepcopy(REFERENCE_CLASSIC)
        del body["required_pull_request_reviews"]["required_approving_review_count"]
        result, = of(assess_files(people(classic_only(ADMIN, body), 3), CI), "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("the number of approvals the classic protection rule requires, which GitHub's answer did not "
                      "give", result["message"])

    def test_required_checks_in_a_form_the_reference_does_not_give(self):
        entries = with_body(ADMIN, BRANCH_RULES, lambda body: next(
            r for r in body if r["type"] == "required_status_checks")["parameters"].update(
                required_status_checks="test (3.13)"))
        for rule in CHECK_RULES:
            unknown = of(assess_files(entries, CI), rule, "cannot-tell")
            self.assertIn("the checks of the required_status_checks rule of ruleset 42, which are not in the form "
                          "GitHub's reference gives", unknown[0]["message"], rule)


class ClassicFieldsTest(unittest.TestCase):
    def test_every_field_of_the_references_examples_is_known(self):
        snap, _ = take(classic_only(ADMIN, REFERENCE_CLASSIC), token=TOKEN)
        value = snap["settings"]["branch_protection"]["value"]["main"]
        self.assertEqual(snap["settings"]["branch_protection"]["status"], "read")
        self.assertNotIn("other_fields", value)
        found = assess_files(people(classic_only(ADMIN, REFERENCE_CLASSIC), 3), CI)
        for rule in REQUIREMENT_RULES:
            self.assertNotIn("does not know", messages(found, rule), rule)

    def test_a_field_the_reference_does_not_list_is_kept_with_its_value(self):
        body = copy.deepcopy(REFERENCE_CLASSIC)
        body["require_human_review"] = {"enabled": True}
        body["required_pull_request_reviews"]["required_reviewing_teams"] = [{"slug": "core", "minimum": 2}]
        body["required_pull_request_reviews"]["bypass_pull_request_allowances"]["roles"] = ["maintain"]
        body["lock_branch"]["until"] = "2027-01-01"
        snap, _ = take(classic_only(ADMIN, body), token=TOKEN)
        value = snap["settings"]["branch_protection"]["value"]["main"]
        self.assertEqual(value["other_fields"], {
            "branch_protection": {"require_human_review": {"enabled": True}},
            "lock_branch": {"until": "2027-01-01"},
            "required_pull_request_reviews": {"required_reviewing_teams": [{"minimum": 2, "slug": "core"}]},
            "required_pull_request_reviews.bypass_pull_request_allowances": {"roles": ["maintain"]}})
        self.assertEqual(snapshot_mod.problems(snap), [])
        # Written out and read back like any snapshot.
        self.assertEqual(json.loads(snapshot_mod.dumps(snap))["settings"]["branch_protection"],
                         snap["settings"]["branch_protection"])

    def test_the_schema_names_the_same_places_as_the_reader(self):
        schema = json.loads(data_text("schemas/settings-snapshot.schema.json"))
        exists = schema["$defs"]["classic_protection"]["oneOf"][1]
        places = exists["properties"]["other_fields"]["propertyNames"]["enum"]
        self.assertEqual(set(places), set(settings.CLASSIC_PLACES))
        self.assertEqual(set(settings.CLASSIC_PLACES) - {settings.CLASSIC_CHECKS},
                         {k or settings.CLASSIC_TOP for k in settings.CLASSIC_FIELDS})
        self.assertNotIn("other_fields", exists["required"])

    def test_a_field_about_reviews_makes_the_approval_rules_cannot_tell(self):
        body = copy.deepcopy(REFERENCE_CLASSIC)
        body["required_pull_request_reviews"]["require_two_people"] = True
        found = assess_files(people(approving(classic_only(ADMIN, body)), 3), CI)
        result, = of(found, "OBAAF-SET-005")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn('"required_pull_request_reviews.require_two_people" = true (the classic protection rule), a '
                      "field this audit does not know", result["message"])
        self.assertIn("require_two_people", messages(found, "OBAAF-SET-013"))
        for rule in CHECK_RULES:
            self.assertNotIn("require_two_people", messages(found, rule), rule)

    def test_a_field_about_checks_makes_the_check_rules_cannot_tell(self):
        body = unrestricted(REFERENCE_CLASSIC)
        body["required_status_checks"]["required_deployments"] = ["staging"]
        found = assess_files(people(classic_only(ADMIN, body), 3), CI)
        for rule in CHECK_RULES:
            unknown = of(found, rule, "cannot-tell")
            self.assertTrue(unknown, rule)
            self.assertIn('"required_status_checks.required_deployments" = ["staging"]', unknown[0]["message"], rule)
        self.assertEqual(status(found, "OBAAF-SET-005"), "no-finding")

    def test_a_field_anywhere_else_makes_both_cannot_tell_and_the_bypass_rule_too(self):
        body = copy.deepcopy(REFERENCE_CLASSIC)
        body["admins_may_skip"] = True
        found = assess_files(people(classic_only(ADMIN, body), 3), CI)
        for rule in CHECK_RULES + ("OBAAF-SET-005",):
            self.assertIn('"admins_may_skip" = true', messages(found, rule), rule)
        unknown, = of(found, "OBAAF-SET-004", "cannot-tell")
        self.assertEqual(unknown["subject"], 'branch "main": classic protection: fields this audit does not know')


    def test_a_field_of_a_required_check_is_kept_and_the_check_rules_cannot_tell(self):
        # The reference gives an entry of `checks` a context and an app id, and nothing else.
        body = unrestricted(REFERENCE_CLASSIC)
        body["required_status_checks"]["checks"][0]["enforcement"] = "evaluate_only"
        snap, _ = take(classic_only(ADMIN, body), token=TOKEN)
        value = snap["settings"]["branch_protection"]["value"]["main"]
        self.assertEqual(value["other_fields"], {"required_status_checks.checks": {"enforcement": [
            {"app_id": 15368, "context": "test (3.13)", "value": "evaluate_only"}]}})
        files = dict(CI, **{"lint.yml": workflow("  pull_request:\n", job("lint"))})
        found = assess_files(people(classic_only(ADMIN, body), 3), files)
        for rule in CHECK_RULES:
            unknown = of(found, rule, "cannot-tell")
            self.assertTrue(unknown, rule)
            self.assertIn('"required_status_checks.checks.enforcement" = [{"app_id": 15368, "context": "test (3.13)", '
                          '"value": "evaluate_only"}]', unknown[0]["message"])
        self.assertEqual(status(found, "OBAAF-SET-005"), "no-finding")

    def test_a_known_object_in_another_form_is_kept_not_read_as_not_known(self):
        # Read as GitHub's reference gives it, `lock_branch` is an object with `enabled`. `true` there used to
        # become null, and a rule passed over it.
        for change, place, name, value in (
                (lambda b: b.__setitem__("lock_branch", True), "branch_protection", "lock_branch", True),
                (lambda b: b["required_pull_request_reviews"].__setitem__("dismissal_restrictions", ["x"]),
                 "required_pull_request_reviews", "dismissal_restrictions", ["x"]),
                (lambda b: b["allow_fork_syncing"].__setitem__("enabled", "yes"), "allow_fork_syncing", "enabled",
                 "yes"),
                # null is "not known" in a snapshot: an `enabled` GitHub sent as null is not read as not locked.
                (lambda b: b["lock_branch"].__setitem__("enabled", None), "lock_branch", "enabled", None),
                # A flag with no `enabled` at all, which the reader would also record as not known.
                (lambda b: b.__setitem__("lock_branch", {}), "branch_protection", "lock_branch", {})):
            body = unrestricted(REFERENCE_CLASSIC)
            change(body)
            snap, _ = take(classic_only(ADMIN, body), token=TOKEN)
            value_read = snap["settings"]["branch_protection"]["value"]["main"]
            self.assertEqual(value_read["other_fields"], {place: {name: value}}, name)
            found = assess_files(people(classic_only(ADMIN, body), 3), CI)
            self.assertEqual(status(found, "OBAAF-SET-005"), "cannot-tell", name)


class ClassicWhoMayPushTest(unittest.TestCase):
    """Push restrictions and a locked branch decide who may merge, as a ruleset's `update` rule does."""

    def test_push_restrictions_make_the_approvals_rule_cannot_tell(self):
        found = assess_files(people(approving(classic_only(ADMIN, REFERENCE_CLASSIC)), 3), CI)
        unknown, = of(found, "OBAAF-SET-005")
        self.assertEqual(unknown["state"], "cannot-tell")
        self.assertIn("the classic protection rule's restrictions on who may push to the branch (restrictions)",
                      unknown["message"])
        self.assertEqual(status(assess_files(people(classic_only(ADMIN, unrestricted(REFERENCE_CLASSIC)), 3), CI),
                                "OBAAF-SET-005"), "no-finding")
        self.assertEqual(len(of(found, "OBAAF-SET-013", "finding")), 1)

    def test_a_locked_branch_makes_it_cannot_tell(self):
        body = unrestricted(REFERENCE_CLASSIC)
        body["lock_branch"]["enabled"] = True
        unknown, = of(assess_files(people(classic_only(ADMIN, body), 3), CI), "OBAAF-SET-005")
        self.assertEqual(unknown["state"], "cannot-tell")
        self.assertIn('lock_branch, by which, in GitHub\'s reference, "users will not be able to push to the branch"',
                      unknown["message"])


class RequiredChecksInAnotherFormTest(unittest.TestCase):
    """The parameters of a ruleset's `required_status_checks` rule, as the reference gives them."""

    def change(self, fn) -> list[dict]:
        return with_body(ADMIN, BRANCH_RULES, lambda body: fn(next(
            r for r in body if r["type"] == "required_status_checks")["parameters"]))

    def test_the_recorded_answers_have_nothing_else(self):
        for name in ("live-expectrail-2026-11-13", "admin-token"):
            for entry in recording(name):
                if "/rules/branches/" in entry["path"]:
                    for rule in entry["body"]:
                        if rule["type"] == "required_status_checks":
                            self.assertLessEqual(set(rule["parameters"]), set(rules.CHECKS_PARAMETERS), name)
                            for check in rule["parameters"]["required_status_checks"]:
                                self.assertLessEqual(set(check), set(rules.CHECK_FIELDS), name)

    def test_a_parameter_or_a_field_it_does_not_know_may_add_a_check(self):
        for fn, text in (
                (lambda p: p.__setitem__("required_check_suites", ["deploy"]), '"required_check_suites" = ["deploy"]'),
                (lambda p: p.__setitem__("strict_required_status_checks_policy", "yes"),
                 '"strict_required_status_checks_policy" = "yes"'),
                (lambda p: p["required_status_checks"][0].__setitem__("enforcement", "evaluate"), '"enforcement"'),
                (lambda p: p["required_status_checks"][0].__setitem__("integration_id", "15368"),
                 '"integration_id": "15368"')):
            found = assess_files(self.change(fn), CI)
            for rule in CHECK_RULES:
                unknown = of(found, rule, "cannot-tell")
                self.assertTrue(unknown, (rule, text))
                self.assertIn(text, unknown[0]["message"], rule)
                self.assertIn("not in the form GitHub's reference gives", unknown[0]["message"], rule)

    def test_without_them_nothing_changes(self):
        found = assess_files(self.change(lambda p: p.pop("do_not_enforce_on_create")), CI)
        for rule in CHECK_RULES:
            self.assertEqual(of(found, rule, "cannot-tell"), [], rule)


class EveryCannotTellSaysWhyTest(unittest.TestCase):
    def test_a_snapshot_file_that_leaves_out_an_audited_branch(self):
        from test_settings_rules import tree
        from obaaf.audit import rules as audit_rules, workflows
        from test_settings_audit import TempDir
        snap, _ = take(people(approving(ADMIN), 3), token=TOKEN)
        snap["settings"]["branch_rules"]["value"] = {}
        self.assertEqual(snapshot_mod.problems(snap), [])
        with TempDir() as tmp:
            found = audit_rules.evaluate(snap, workflows.read(tree(tmp, CI)))
        for rule in ("OBAAF-SET-005", "OBAAF-SET-006", "OBAAF-SET-013"):
            for result in of(found, rule, "cannot-tell"):
                self.assertIn("the rules in force on it, which the snapshot does not hold", result["message"], rule)
                self.assertFalse(result["message"].endswith("What was not read."), rule)


class TheReportTest(unittest.TestCase):
    def test_a_type_it_does_not_know_is_printed_quoted_and_says_so(self):
        from test_settings_audit import full_report
        snap, _ = take(add_rule(ADMIN, "required_status_checks (deploy)"), token=TOKEN)
        text = full_report(snap)
        self.assertIn('"required_status_checks (deploy)" (a type this audit does not know)', text)


class ABranchTheSnapshotLeavesOutTest(unittest.TestCase):
    def test_the_bypass_rule_cannot_tell_and_says_why(self):
        from test_settings_rules import tree
        from obaaf.audit import rules as audit_rules, workflows
        from test_settings_audit import TempDir
        snap, _ = take(ADMIN, token=TOKEN)
        snap["settings"]["branch_rules"]["value"] = {}
        with TempDir() as tmp:
            found = audit_rules.evaluate(snap, workflows.read(tree(tmp, CI)))
        unknown, = of(found, "OBAAF-SET-004", "cannot-tell")
        self.assertEqual(unknown["message"], "Which rulesets are in force on it is not known: the rules in force on "
                                             "it, which the snapshot does not hold.")


class DriftTest(unittest.TestCase):
    """The snapshot changed: a classic protection rule may now carry ``other_fields``. A snapshot taken before,
    which has none, is still compared with one taken now."""

    BEFORE = SETTINGS_DIR / "classic-before-2b6" / "snapshot.json"

    def snapshots(self, body):
        # Written by the code before this slice (the fixture's README says how), and read as a committed file.
        expected = snapshot_mod.load(self.BEFORE)
        live, _ = take(classic_only(ADMIN, body), token=TOKEN)
        return expected, live

    def test_an_earlier_snapshot_matches_one_taken_now_of_the_same_settings(self):
        expected, live = self.snapshots(REFERENCE_CLASSIC)
        self.assertEqual(expected["settings"]["branch_protection"], live["settings"]["branch_protection"])
        result = drift.compare(expected, live)
        self.assertFalse(drift.failed(result))
        self.assertEqual(result["outcomes"]["branch_protection"], "matches")

    def test_a_field_that_moves_from_one_required_check_to_another_is_drift(self):
        def body(on: str) -> dict:
            body = unrestricted(REFERENCE_CLASSIC)
            body["required_status_checks"]["checks"] = [{"context": "a", "app_id": 15368},
                                                        {"context": "b", "app_id": 15368}]
            next(c for c in body["required_status_checks"]["checks"] if c["context"] == on)["enforcement"] = "evaluate"
            return body
        expected, _ = take(classic_only(ADMIN, body("a")), token=TOKEN)
        live, _ = take(classic_only(ADMIN, body("b")), token=TOKEN)
        self.assertTrue(drift.failed(drift.compare(expected, live)))

    def test_a_field_the_earlier_reader_dropped_shows_as_added(self):
        body = copy.deepcopy(REFERENCE_CLASSIC)
        body["require_human_review"] = {"enabled": True}
        expected, live = self.snapshots(body)
        result = drift.compare(expected, live)
        self.assertTrue(drift.failed(result))
        text = json.dumps(result)
        self.assertIn("other_fields", text)
        self.assertIn("require_human_review", text)


if __name__ == "__main__":
    unittest.main()
