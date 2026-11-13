"""The settings rules (flagship slice 2b.2): what `obaaf audit` makes of the settings it read.

Each rule compares a setting with something the workflow files use. The settings come from the recordings
under tests/fixtures/settings/ (see test_settings_audit.py for which were written by hand and which are
GitHub's own answers); the workflow files come from tests/fixtures/settings/incident-repo/, a repository
shaped after the first adopter's incidents, or are written by a test into a temporary directory.

Three things are tested for every rule: that it reports the problem when the settings show it, that it
reports nothing when they show there is none, and that it answers "cannot tell", never "no finding", when
a setting it needs was not read.
"""

import copy
import json
import random
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from helpers import ROOT, TempDir, run_cli
from test_settings_audit import (R, REPO, SETTINGS_DIR, TOKEN, clean_env, entry_for, recording, replace, take)

from obaaf import audit
from obaaf.audit import cli as audit_cli, github, report, rules, snapshot as snapshot_mod, workflows

INCIDENT_REPO = SETTINGS_DIR / "incident-repo"
PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
ENVIRONMENTS = f"{R}/environments?per_page=100"
RULESET_42 = f"{R}/rulesets/42?includes_parents=true"
BRANCH_RULES = f"{R}/rules/branches/main?per_page=100"
POLICY_7 = f"{R}/actions/policies/7"
POLICIES = f"{R}/actions/policies?has_parents=true&per_page=100"
COLLABORATORS = f"{R}/collaborators?affiliation=all&per_page=100"


def workflow(on: str, jobs: str, permissions: str = "permissions:\n  contents: read\n") -> str:
    return f"name: W\non:\n{on}{permissions}jobs:\n{jobs}"


def job(name: str, body: str = "", steps: str | None = None) -> str:
    steps = steps if steps is not None else "      - run: echo hello\n"
    return f"  {name}:\n    runs-on: ubuntu-latest\n{body}    steps:\n{steps}"


def tree(tmp: Path, files: dict, config: str | None = None) -> Path:
    """A repository in a temporary directory: workflow files by name, and the checker's configuration."""
    target = tmp / "repo" / ".github" / "workflows"
    target.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (target / name).write_text(text, encoding="utf-8")
    if config is not None:
        (tmp / "repo" / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")
    return tmp / "repo"


def assess(entries, root: Path = INCIDENT_REPO, token: str | None = TOKEN, repository: str = REPO) -> dict:
    snap, _ = take(entries, token=token, repository=repository)
    return rules.evaluate(snap, workflows.read(root))


def assess_files(entries, files: dict, config: str | None = None, token: str | None = TOKEN,
                 repository: str = REPO) -> dict:
    with TempDir() as tmp:
        return assess(entries, tree(tmp, files, config), token=token, repository=repository)


def of(assessment: dict, rule: str, state: str | None = None) -> list[dict]:
    return [r for r in assessment["results"] if r["rule"] == rule and state in (None, r["state"])]


def status(assessment: dict, rule: str) -> str:
    return next(r["status"] for r in assessment["rules"] if r["id"] == rule)


def with_body(entries, path: str, change) -> list[dict]:
    """A copy of a recording in which one answer's body has been changed in place by ``change``."""
    out = copy.deepcopy(entries)
    change(entry_for(out, path)["body"])
    return out


def refused(entries, *paths: str) -> list[dict]:
    out = copy.deepcopy(entries)
    for path in paths:
        entry_for(out, path).update(status=403, body={"message": "Resource not accessible by integration"})
    return out


def environments(entries, **changes) -> list[dict]:
    """The recording with the environment `main-only` changed."""
    def change(body):
        env = next(e for e in body["environments"] if e["name"] == "main-only")
        env.update(changes)
    return with_body(entries, ENVIRONMENTS, change)


ADMIN = recording("admin-token")
REVIEWERS = [{"id": 1, "node_id": "x", "type": "required_reviewers", "prevent_self_review": True,
              "reviewers": [{"type": "User", "reviewer": {"login": "octocat", "id": 1}}]}]
ONLY_MAIN = {"protected_branches": False, "custom_branch_policies": True}


def main_only_policies(*patterns) -> dict:
    return {"path": f"{R}/environments/main-only/deployment-branch-policies?per_page=100", "status": 200,
            "headers": {}, "body": {"total_count": len(patterns), "branch_policies": [
                {"id": n, "name": name, "type": kind} for n, (name, kind) in enumerate(patterns, 1)]}}


def limited(entries, *patterns, **changes) -> list[dict]:
    """`main-only` limited to the given (pattern, type) pairs."""
    return environments(entries, deployment_branch_policy=ONLY_MAIN, **changes) + [main_only_policies(*patterns)]


class TheSixIncidentsTest(unittest.TestCase):
    """The settings behind the first adopter's incidents, each caught by a rule from a recorded answer."""

    @classmethod
    def setUpClass(cls):
        cls.found = assess(ADMIN)

    def one(self, rule: str) -> dict:
        found = of(self.found, rule, "finding")
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_1_an_environment_with_no_branch_restriction(self):
        finding = self.one("OBAAF-SET-001")
        self.assertEqual((finding["severity"], finding["subject"]), ("high", 'environment "main-only"'))
        self.assertIn("Any branch or tag may use", finding["message"])
        self.assertIn(".github/workflows/agent.yml#agent", finding["message"])
        self.assertIn("no required reviewers", finding["message"])

    def test_1_and_the_key_it_was_meant_to_hold_is_also_a_repository_secret(self):
        finding = self.one("OBAAF-SET-003")
        self.assertEqual((finding["severity"], finding["subject"]), ("high", 'secret "MODEL_API_KEY"'))
        self.assertIn('"*_API_KEY"', finding["message"])

    def test_2_a_bypass_that_covers_the_only_account_that_can_push(self):
        finding = self.one("OBAAF-SET-004")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("organisation administrators may always bypass", finding["message"])
        self.assertIn("holds nobody who can author a change", finding["message"])
        self.assertIn("1 account can push: 1 admin, 0 maintain, 0 write.", finding["evidence"])

    def test_3_required_approvals_that_the_one_account_cannot_give(self):
        finding = self.one("OBAAF-SET-005")
        self.assertEqual((finding["severity"], finding["subject"]), ("medium", 'branch "main"'))
        self.assertIn("requires 1 approval, and 1 account has the write access", finding["message"])
        self.assertIn("at most 0 approvals", finding["message"])

    def test_4_a_required_checks_list_that_names_one_job_of_those_that_run(self):
        subjects = sorted(r["subject"] for r in of(self.found, "OBAAF-SET-008", "finding"))
        self.assertEqual(subjects, ['branch "main": job .github/workflows/ci.yml#lint',
                                    'branch "main": job .github/workflows/scan.yml#scan'])
        self.assertEqual(status(self.found, "OBAAF-SET-006"), "no-finding")  # "test (3.13)" is the matrix job's

    def test_5_an_actions_policy_that_blocks_a_trigger_the_workflow_uses(self):
        finding = self.one("OBAAF-SET-009")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn(".github/workflows/scan.yml is started by workflow_run", finding["message"])
        self.assertIn("allows only pull_request_target, workflow_dispatch", finding["message"])
        self.assertIn("fails at startup with no job", finding["message"])

    def test_6_a_reusable_workflow_that_cannot_see_its_callers_environment_secret(self):
        finding = self.one("OBAAF-SET-011")
        self.assertEqual(finding["subject"], "job .github/workflows/release.yml#publish")
        self.assertIn('stored only in the environment "release"', finding["message"])

    def test_the_summary_counts_them_and_nothing_failed(self):
        # The one "cannot tell": whether this public repository has self-hosted runners, which a fork's pull
        # request could name in its own copy of a workflow (OBAAF-SET-014).
        self.assertEqual(self.found["summary"], {"findings": 8, "high": 3, "medium": 5, "low": 0, "cannot_tell": 1,
                                                 "rules_cannot_tell": 1, "rules_failed": 0})
        self.assertTrue(rules.fails(self.found, "high"))

    def test_with_no_token_the_rules_that_need_more_say_cannot_tell(self):
        found = assess(recording("public-no-token"), token=None)
        for rule in ("OBAAF-SET-003", "OBAAF-SET-004", "OBAAF-SET-005", "OBAAF-SET-009", "OBAAF-SET-010",
                     "OBAAF-SET-011", "OBAAF-SET-015"):
            self.assertEqual(status(found, rule), "cannot-tell", rule)
            self.assertFalse(of(found, rule, "finding"), rule)
        # What anyone may read still gives its findings: the open environment and the checks.
        self.assertEqual(of(found, "OBAAF-SET-001", "finding")[0]["severity"], "high")
        self.assertEqual(len(of(found, "OBAAF-SET-008", "finding")), 2)
        target = of(found, "OBAAF-SET-010")[0]
        self.assertIn("2026-12-02", target["message"])
        self.assertEqual(target["unread"], ["actions_policies"])

    def test_with_a_workflow_token_a_refusal_is_cannot_tell_too(self):
        found = assess(recording("workflow-token"))
        for rule in ("OBAAF-SET-003", "OBAAF-SET-004", "OBAAF-SET-009", "OBAAF-SET-011"):
            self.assertEqual(status(found, rule), "cannot-tell", rule)
        # The workflow's token can count collaborators: three, who can give each other the ruleset's one
        # approval. The classic rule GitHub shows on the branch was refused and may ask for more.
        result, = of(found, "OBAAF-SET-005")
        self.assertEqual((result["state"], result["unread"]), ("cannot-tell", ["branch_protection"]))
        self.assertIn("a classic protection rule may ask for more", result["message"])

    def test_a_setting_that_was_not_read_never_turns_a_finding_into_no_finding(self):
        snap, _ = take(ADMIN, token=TOKEN)
        usage = workflows.read(INCIDENT_REPO)
        before = rules.evaluate(snap, usage)
        for rule in rules.RULES:
            if status(before, rule.id) != "findings":
                continue
            for key in rule.reads:
                hidden = copy.deepcopy(snap)
                hidden["settings"][key] = {"status": "unread", "reason_code": "forbidden", "reason": "refused",
                                           "needs": audit.BY_KEY[key].needs}
                after = rules.evaluate(hidden, usage)
                self.assertIn(status(after, rule.id), ("findings", "cannot-tell"), (rule.id, key))


class RecordedFromGitHubRulesTest(unittest.TestCase):
    """The rules on what GitHub itself answered a caller with no token (the two "live-" recordings)."""

    CHECKS = ("test", "obaaf-audit", "capture-smoke", "web-capture", "seeded-bugs", "agents-gate1",
              "agents-harness-verify", "feedback-offline", "agents-sandbox", "agents-bench-compare",
              "private-export-scan")

    def adopter(self, names, extra: dict | None = None) -> dict:
        ci = workflow("  pull_request:\n  push:\n", "".join(job(n) for n in names))
        return assess_files(recording("live-expectrail-no-token"), {"ci.yml": ci, **(extra or {})}, token=None,
                            repository="Expectrail/Expectrail")

    def test_every_required_check_reported_and_every_job_required_is_no_finding(self):
        found = self.adopter(self.CHECKS)
        for rule in ("OBAAF-SET-006", "OBAAF-SET-007", "OBAAF-SET-008"):
            self.assertEqual(status(found, rule), "no-finding", rule)

    def test_a_job_that_runs_on_pull_requests_and_is_not_among_the_eleven(self):
        found = self.adopter(self.CHECKS + ("package",))
        finding, = of(found, "OBAAF-SET-008", "finding")
        self.assertEqual(finding["subject"], 'branch "main": job .github/workflows/ci.yml#package')
        self.assertIn("11 checks are required there", finding["message"])

    def test_a_required_check_that_no_job_reports_any_more(self):
        found = self.adopter(self.CHECKS[:-1])
        finding, = of(found, "OBAAF-SET-006", "finding")
        self.assertEqual(finding["subject"], 'branch "main": required check "private-export-scan"')
        self.assertIn("from GitHub Actions", finding["message"])

    def test_the_bypass_list_github_withheld_is_cannot_tell(self):
        found = self.adopter(self.CHECKS)
        result, = of(found, "OBAAF-SET-004")
        self.assertEqual((result["state"], result["unread"]), ("cannot-tell", ["ruleset_bypass_actors"]))
        self.assertIn('ruleset 26914817 "Protect main"', result["subject"])

    def test_zero_required_approvals_is_nothing_for_the_approvals_rule_to_compare(self):
        self.assertEqual(status(self.adopter(self.CHECKS), "OBAAF-SET-005"), "not-applicable")

    def test_an_environment_any_branch_may_use_with_a_reviewer_who_may_approve_their_own_run(self):
        unity = workflow("  pull_request:\n", job("build", "    environment: unity\n"))
        found = self.adopter(self.CHECKS, {"unity.yml": unity})
        finding, = of(found, "OBAAF-SET-001", "finding")
        self.assertEqual((finding["severity"], finding["subject"]), ("medium", 'environment "unity"'))
        self.assertIn("a reviewer may approve their own run", finding["message"])

    def test_this_repositorys_own_required_checks_are_read_from_the_public_view(self):
        ci = workflow("  pull_request:\n", job("actionlint") + job("extra"))
        found = assess_files(recording("live-obaaf-no-token"), {"ci.yml": ci}, token=None, repository="Obaaf/OBAAF")
        finding, = of(found, "OBAAF-SET-008", "finding")
        self.assertIn("ci.yml#extra", finding["subject"])
        self.assertIn("taken from what GitHub shows anyone; the rule itself was not read", finding["message"])
        # How many approvals a classic rule asks for is not shown to anyone, so that is not known.
        self.assertEqual(status(found, "OBAAF-SET-005"), "cannot-tell")


class EnvironmentRulesTest(unittest.TestCase):
    AGENT = {"agent.yml": workflow("  workflow_dispatch:\n", job(
        "agent", "    environment: main-only\n",
        "      - run: ./agent\n        env:\n          KEY: ${{ secrets.MODEL_API_KEY }}\n"))}

    def test_limited_to_the_default_branch_is_no_finding(self):
        found = assess_files(limited(ADMIN, ("main", "branch")), self.AGENT)
        self.assertEqual(status(found, "OBAAF-SET-001"), "no-finding")

    def test_a_pattern_of_stars_is_as_open_as_no_limit(self):
        for pattern in ("*", "**", "*/*"):
            finding, = of(assess_files(limited(ADMIN, (pattern, "branch")), self.AGENT), "OBAAF-SET-001")
            self.assertEqual(finding["severity"], "high", pattern)
            self.assertIn("lets nearly every branch through", finding["message"])

    def test_a_wildcard_or_a_tag_pattern_with_no_reviewer_is_medium_and_with_one_is_not_reported(self):
        for pattern in (("release/*", "branch"), ("v*", "tag"), ("v1.0.0", "tag")):
            finding, = of(assess_files(limited(ADMIN, pattern), self.AGENT), "OBAAF-SET-001")
            self.assertEqual(finding["severity"], "medium", pattern)
            self.assertIn("Anyone with write access can push", finding["message"])
            guarded = assess_files(limited(ADMIN, pattern, protection_rules=REVIEWERS), self.AGENT)
            self.assertEqual(status(guarded, "OBAAF-SET-001"), "no-finding", pattern)

    def test_any_branch_behind_reviewers_is_medium(self):
        finding, = of(assess_files(environments(ADMIN, protection_rules=REVIEWERS), self.AGENT), "OBAAF-SET-001")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("self-review is prevented", finding["message"])

    def test_protected_branches_only_is_cannot_tell(self):
        entries = environments(ADMIN, deployment_branch_policy={"protected_branches": True,
                                                                "custom_branch_policies": False})
        result, = of(assess_files(entries, self.AGENT), "OBAAF-SET-001")
        self.assertEqual(result["state"], "cannot-tell")

    def test_patterns_that_were_not_read_are_cannot_tell(self):
        entries = limited(ADMIN, ("main", "branch"))
        entry_for(entries, f"{R}/environments/main-only/deployment-branch-policies?per_page=100").update(
            status=403, body={"message": "Resource not accessible by integration"})
        result, = of(assess_files(entries, self.AGENT), "OBAAF-SET-001")
        self.assertEqual((result["state"], result["unread"]), ("cannot-tell", ["environments"]))

    def test_an_environment_a_job_names_that_does_not_exist(self):
        ghost = {"x.yml": workflow("  workflow_dispatch:\n", job("deploy", "    environment: Staging\n"))}
        finding, = of(assess_files(ADMIN, ghost), "OBAAF-SET-001")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("is not among the repository's environments", finding["message"])

    def test_environment_names_compare_without_regard_to_case_and_a_computed_name_is_not_guessed(self):
        files = {"x.yml": workflow("  workflow_dispatch:\n", job("a", "    environment: MAIN-ONLY\n") + job(
            "b", "    environment: ${{ inputs.target }}\n") + job("c", "    environment:\n      name: main-only\n"))}
        found = assess_files(ADMIN, files)
        finding, = of(found, "OBAAF-SET-001", "finding")
        self.assertIn("2 jobs name it", finding["message"])
        unknown, = of(found, "OBAAF-SET-001", "cannot-tell")
        self.assertEqual(unknown["subject"], "job .github/workflows/x.yml#b")
        self.assertIn("names its environment with an expression", unknown["message"])

    def test_no_environment_named_does_not_apply(self):
        found = assess_files(ADMIN, {"x.yml": workflow("  push:\n", job("a"))})
        self.assertEqual(status(found, "OBAAF-SET-001"), "not-applicable")

    def test_environments_not_read_is_cannot_tell(self):
        result, = of(assess_files(refused(ADMIN, ENVIRONMENTS), self.AGENT), "OBAAF-SET-001")
        self.assertEqual((result["state"], result["unread"]), ("cannot-tell", ["environments"]))

    # -- OBAAF-SET-002
    def target(self, event: str = "pull_request_target") -> dict:
        return {"t.yml": workflow(f"  {event}:\n", job(
            "triage", "    environment: main-only\n",
            "      - run: ./triage\n        env:\n          KEY: ${{ secrets.MODEL_API_KEY }}\n"))}

    def test_a_branch_limit_does_not_stop_an_event_that_runs_on_the_default_branch(self):
        for event in ("pull_request_target", "issue_comment", "issues", "workflow_run"):
            found = assess_files(limited(ADMIN, ("main", "branch")), self.target(event))
            finding, = of(found, "OBAAF-SET-002")
            self.assertEqual((finding["state"], finding["severity"]), ("finding", "high"), event)
            self.assertIn("admits the default branch", finding["message"])
            self.assertIn("so the limit does not stop them", finding["message"])
            self.assertEqual(status(found, "OBAAF-SET-001"), "no-finding")

    def test_required_reviewers_clear_it_and_a_push_never_raises_it(self):
        guarded = assess_files(limited(ADMIN, ("main", "branch"), protection_rules=REVIEWERS), self.target())
        self.assertEqual(status(guarded, "OBAAF-SET-002"), "no-finding")
        self.assertEqual(status(assess_files(ADMIN, self.target("push")), "OBAAF-SET-002"), "not-applicable")

    def test_an_environment_with_no_secret_and_a_job_that_reads_none_is_not_reported(self):
        files = {"t.yml": workflow("  issues:\n", job("label", "    environment: main-only\n"))}
        empty = with_body(ADMIN, f"{R}/environments/main-only/secrets?per_page=100",
                          lambda body: body.update(total_count=0, secrets=[]))
        self.assertEqual(status(assess_files(empty, files), "OBAAF-SET-002"), "no-finding")
        self.assertEqual(len(of(assess_files(ADMIN, files), "OBAAF-SET-002", "finding")), 1)
        unknown = assess_files(recording("public-no-token"), files, token=None)
        self.assertEqual(status(unknown, "OBAAF-SET-002"), "cannot-tell")


class SecretRulesTest(unittest.TestCase):
    READS = workflow("  push:\n", job("build", "", "      - run: ./b\n        env:\n          K: ${{ secrets.model_api_key }}\n"))

    def test_without_a_configuration_a_secret_in_both_places_that_a_job_reads_is_medium(self):
        finding, = of(assess_files(ADMIN, {"b.yml": self.READS}), "OBAAF-SET-003", "finding")
        self.assertEqual((finding["severity"], finding["subject"]), ("medium", 'secret "MODEL_API_KEY"'))
        self.assertIn('stored in the environment "main-only" and also as a repository secret', finding["message"])

    def test_a_copy_nobody_reads_and_nobody_protects_is_not_reported(self):
        other = workflow("  push:\n", job("build", "", "      - run: ./b\n        env:\n          K: ${{ secrets.OTHER }}\n"))
        self.assertEqual(status(assess_files(ADMIN, {"b.yml": other}), "OBAAF-SET-003"), "no-finding")

    def test_an_organisation_secret_that_matches_a_protected_pattern(self):
        entries = with_body(ADMIN, f"{R}/actions/organization-secrets?per_page=100",
                            lambda body: body.update(total_count=1, secrets=[{"name": "OPENAI_API_KEY"}]))
        found = assess_files(entries, {"b.yml": self.READS}, config='protected_secrets:\n  "*_API_KEY": main-only\n')
        subjects = sorted(r["subject"] for r in of(found, "OBAAF-SET-003", "finding"))
        self.assertEqual(subjects, ['secret "MODEL_API_KEY"', 'secret "OPENAI_API_KEY"'])
        self.assertIn("an organisation secret", of(found, "OBAAF-SET-003")[1]["message"])

    def test_the_environment_the_configuration_names_does_not_exist(self):
        found = assess_files(ADMIN, {"b.yml": self.READS}, config="protected_secrets:\n  HELDOUT_TOKEN: vault\n")
        finding, = [r for r in of(found, "OBAAF-SET-003", "finding") if r["subject"] == 'environment "vault"']
        self.assertEqual(finding["severity"], "high")

    def test_an_entry_that_protects_nothing_stored_in_its_environment_is_low(self):
        found = assess_files(ADMIN, {"b.yml": self.READS}, config="protected_secrets:\n  DEPLOY_TOKEN: main-only\n")
        finding, = [r for r in of(found, "OBAAF-SET-003", "finding") if r["severity"] == "low"]
        self.assertIn("protects nothing that is there", finding["message"])

    def test_where_the_secrets_are_stored_was_not_read(self):
        found = assess_files(refused(ADMIN, f"{R}/actions/secrets?per_page=100"), {"b.yml": self.READS},
                             config="protected_secrets: [MODEL_API_KEY]\n")
        result, = of(found, "OBAAF-SET-003", "cannot-tell")
        self.assertEqual(result["unread"], ["repository_secrets"])
        self.assertEqual(status(found, "OBAAF-SET-003"), "cannot-tell")

    # -- OBAAF-SET-011
    def caller(self, secrets: str, uses: str = "./.github/workflows/publish.yml") -> str:
        return workflow("  push:\n", f"  publish:\n    uses: {uses}\n    secrets: {secrets}\n")

    def callee(self, environment: str = "") -> str:
        return workflow("  workflow_call:\n", job("upload", environment, "      - run: ./u\n        env:\n"
                                                  "          T: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n"))

    def test_inherit_and_a_called_job_without_the_environment(self):
        found = assess_files(ADMIN, {"r.yml": self.caller("inherit"), "publish.yml": self.callee()})
        finding, = of(found, "OBAAF-SET-011", "finding")
        self.assertIn('whose job "upload" reads secrets.PACKAGE_INDEX_TOKEN', finding["message"])

    def test_the_called_job_declares_the_environment_itself(self):
        found = assess_files(ADMIN, {"r.yml": self.caller("inherit"),
                                     "publish.yml": self.callee("    environment: release\n")})
        self.assertEqual(status(found, "OBAAF-SET-011"), "no-finding")

    def test_a_workflow_in_another_repository_is_cannot_tell(self):
        found = assess_files(ADMIN, {"r.yml": self.caller("inherit", "octo-org/shared/.github/workflows/p.yml@" + "a" * 40)})
        result, = of(found, "OBAAF-SET-011")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("PACKAGE_INDEX_TOKEN", result["message"])

    def test_a_secret_stored_for_every_job_is_passed_whole(self):
        found = assess_files(ADMIN, {"r.yml": self.caller("\n      key: ${{ secrets.MODEL_API_KEY }}"),
                                     "publish.yml": self.callee()})
        self.assertEqual(status(found, "OBAAF-SET-011"), "no-finding")

    def test_secret_names_not_read_is_cannot_tell_and_no_caller_does_not_apply(self):
        found = assess_files(recording("public-no-token"), {"r.yml": self.caller("inherit")}, token=None)
        self.assertEqual(status(found, "OBAAF-SET-011"), "cannot-tell")
        self.assertEqual(status(assess_files(ADMIN, {"b.yml": self.READS}), "OBAAF-SET-011"), "not-applicable")


class BranchRulesTest(unittest.TestCase):
    CI = {"ci.yml": workflow("  pull_request:\n", job("test", "    strategy:\n      matrix:\n        python: ['3.13']\n"))}

    def bypass(self, *actors) -> list[dict]:
        entries = with_body(ADMIN, RULESET_42, lambda body: body.update(
            bypass_actors=[{"actor_id": i, "actor_type": t, "bypass_mode": m} for t, i, m in actors],
            current_user_can_bypass="never"))
        return entries

    def people(self, entries, *roles) -> list[dict]:
        """One collaborator for each role given (admin, maintain, push, triage, pull)."""
        order = ("pull", "triage", "push", "maintain", "admin")
        return with_body(entries, COLLABORATORS, lambda body: body.__setitem__(slice(None), [
            {"login": f"user{n}", "id": n, "permissions": {r: order.index(r) <= order.index(role) for r in order}}
            for n, role in enumerate(roles)]))

    def test_a_bypass_only_when_merging_a_pull_request_is_low(self):
        finding, = of(assess_files(self.bypass(("RepositoryRole", 5, "pull_request")), self.CI), "OBAAF-SET-004")
        self.assertEqual(finding["severity"], "low")
        self.assertIn("the repository role admin may bypass it when merging a pull request", finding["message"])

    def test_roles_that_cover_everyone_who_can_push_are_high_and_fewer_are_medium(self):
        entries = self.people(self.bypass(("RepositoryRole", 5, "always"), ("RepositoryRole", 4, "always")),
                              "admin", "push", "push", "pull")
        finding, = of(assess_files(entries, self.CI), "OBAAF-SET-004")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("Every account that can push holds one of those roles", finding["message"])
        entries = self.people(self.bypass(("RepositoryRole", 5, "always")), "admin", "push")
        finding, = of(assess_files(entries, self.CI), "OBAAF-SET-004")
        self.assertEqual(finding["severity"], "medium")
        self.assertNotIn("holds nobody", finding["message"])

    def test_a_mode_this_version_does_not_know_is_read_as_the_wider_one(self):
        finding, = of(assess_files(self.bypass(("Team", 9, "exempt")), self.CI), "OBAAF-SET-004")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("Team 9 (mode: exempt) may always bypass", finding["message"])

    def test_classic_protection_that_does_not_hold_administrators(self):
        classic = {"url": "x", "enforce_admins": {"enabled": False},
                   "required_pull_request_reviews": {"required_approving_review_count": 1}}
        entries = replace(with_body(ADMIN, BRANCH_RULES, lambda body: body.clear()),
                          f"{R}/branches/main/protection", status=200, body=classic)
        found = assess_files(entries, self.CI)
        finding, = of(found, "OBAAF-SET-004", "finding")
        self.assertEqual((finding["severity"], finding["subject"]), ("high", 'branch "main": classic protection'))
        self.assertIn("All 1 account that can push are administrators", finding["message"])
        # GitHub's answer did not say who may bypass the required reviews: that is not "nobody".
        unknown, = of(found, "OBAAF-SET-004", "cannot-tell")
        self.assertIn("did not say who may bypass them", unknown["message"])
        self.assertEqual(len(of(found, "OBAAF-SET-005", "finding")), 1)  # the classic rule's one approval

    def test_no_rules_in_force_does_not_apply(self):
        entries = with_body(ADMIN, BRANCH_RULES, lambda body: body.clear())
        self.assertEqual(status(assess_files(entries, self.CI), "OBAAF-SET-004"), "not-applicable")

    # -- OBAAF-SET-005
    def test_two_who_can_approve_and_one_approval_is_no_finding_and_two_approvals_is_a_finding(self):
        two = self.people(ADMIN, "admin", "push", "triage")
        self.assertEqual(status(assess_files(two, self.CI), "OBAAF-SET-005"), "no-finding")

        def more(body):
            next(r for r in body if r["type"] == "pull_request")["parameters"]["required_approving_review_count"] = 2
        finding, = of(assess_files(with_body(two, BRANCH_RULES, more), self.CI), "OBAAF-SET-005")
        self.assertIn("requires 2 approvals, and 2 accounts have the write access", finding["message"])
        self.assertIn("at most 1 approval", finding["message"])

    def test_a_pull_request_rule_without_its_parameters_is_cannot_tell_not_zero(self):
        def strip(body):
            next(r for r in body if r["type"] == "pull_request").pop("parameters")
        found = assess_files(with_body(ADMIN, BRANCH_RULES, strip), self.CI)
        self.assertEqual(status(found, "OBAAF-SET-005"), "cannot-tell")

    def test_collaborators_not_read_is_cannot_tell(self):
        result, = of(assess_files(refused(ADMIN, COLLABORATORS), self.CI), "OBAAF-SET-005")
        self.assertEqual((result["state"], result["unread"]), ("cannot-tell", ["collaborators"]))


class RequiredCheckRulesTest(unittest.TestCase):
    def require(self, *checks) -> list[dict]:
        """The recording with these (context, integration id) pairs as the required checks."""
        def change(body):
            rule = next(r for r in body if r["type"] == "required_status_checks")
            rule["parameters"]["required_status_checks"] = [
                {"context": c, **({"integration_id": i} if i is not None else {})} for c, i in checks]
        return with_body(ADMIN, BRANCH_RULES, change)

    def test_a_required_check_nobody_reports(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("build"))}
        found = assess_files(self.require(("build", 15368), ("biuld", 15368)), files)
        finding, = of(found, "OBAAF-SET-006")
        self.assertEqual((finding["state"], finding["subject"]),
                         ("finding", 'branch "main": required check "biuld"'))

    def test_a_check_that_need_not_come_from_actions_is_cannot_tell(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("build"))}
        for app in (None, 99):
            result, = of(assess_files(self.require(("license/cla", app)), files), "OBAAF-SET-006")
            self.assertEqual(result["state"], "cannot-tell", app)

    def test_a_computed_job_name_or_a_file_that_does_not_parse_is_cannot_tell(self):
        named = workflow("  pull_request:\n", "  build:\n    name: build ${{ matrix.os }}\n    runs-on: x\n    steps:\n      - run: a\n")
        for files in ({"ci.yml": named}, {"ci.yml": workflow("  pull_request:\n", job("other")), "bad.yml": "on: [push\n"}):
            found = assess_files(self.require(("build", 15368)), files)
            self.assertEqual({r["state"] for r in of(found, "OBAAF-SET-006")}, {"cannot-tell"})
            self.assertIn("whether anything reports it is not known", of(found, "OBAAF-SET-006")[0]["message"])

    def test_names_a_job_reports(self):
        files = {"ci.yml": workflow("  pull_request:\n", (
            "  a:\n    name: Unit tests\n    runs-on: x\n    steps:\n      - run: a\n"
            + job("m", "    strategy:\n      matrix:\n        os: [linux, mac]\n")
            + "  c:\n    uses: ./.github/workflows/r.yml\n")),
            "r.yml": workflow("  workflow_call:\n", job("inner"))}
        found = assess_files(self.require(("Unit tests", 15368), ("m (linux)", 15368), ("m (mac)", 15368),
                                          ("c / inner", 15368)), files)
        self.assertEqual(status(found, "OBAAF-SET-006"), "no-finding")
        self.assertEqual(status(found, "OBAAF-SET-008"), "no-finding")
        # One of a matrix's checks required is not enough: the other can fail and the pull request merges
        # (the first adopter required one check of eleven).
        found = assess_files(self.require(("Unit tests", 15368), ("m (linux)", 15368), ("c / inner", 15368)), files)
        self.assertEqual(status(found, "OBAAF-SET-006"), "no-finding")
        finding, = of(found, "OBAAF-SET-008", "finding")
        self.assertIn("reports 2 checks, of which 1 is not", finding["message"])
        self.assertIn("m (mac)", finding["message"])
        found = assess_files(self.require(("a", 15368), ("m", 15368), ("c", 15368)), files)
        self.assertEqual(len(of(found, "OBAAF-SET-006", "finding")), 3)
        self.assertEqual(len(of(found, "OBAAF-SET-008", "finding")), 3)

    def test_a_required_check_behind_a_paths_filter(self):
        filtered = workflow("  pull_request:\n    paths:\n      - 'src/**'\n", job("build"))
        finding, = of(assess_files(self.require(("build", 15368)), {"ci.yml": filtered}), "OBAAF-SET-007")
        self.assertIn("runs only when certain paths change", finding["message"])
        ignore = workflow("  pull_request:\n    paths-ignore:\n      - 'docs/**'\n", job("build"))
        self.assertEqual(len(of(assess_files(self.require(("build", 15368)), {"ci.yml": ignore}), "OBAAF-SET-007")), 1)

    def test_a_second_workflow_that_always_reports_the_check_clears_it(self):
        filtered = workflow("  pull_request:\n    paths: ['src/**']\n", job("build"))
        for other in (workflow("  pull_request:\n", job("build")), workflow("  push:\n", job("build"))):
            found = assess_files(self.require(("build", 15368)), {"ci.yml": filtered, "all.yml": other})
            self.assertEqual(status(found, "OBAAF-SET-007"), "no-finding")
        tags = workflow("  push:\n    tags: ['v*']\n", job("build"))
        found = assess_files(self.require(("build", 15368)), {"ci.yml": filtered, "tags.yml": tags})
        self.assertEqual(len(of(found, "OBAAF-SET-007", "finding")), 1)

    def test_a_job_behind_a_paths_filter_is_not_asked_to_be_required(self):
        filtered = workflow("  pull_request:\n    paths: ['src/**']\n", job("live"))
        found = assess_files(self.require(("build", 15368)), {"ci.yml": workflow("  pull_request:\n", job("build")),
                                                            "live.yml": filtered})
        self.assertEqual(status(found, "OBAAF-SET-008"), "no-finding")

    def test_an_advisory_job_says_so_in_the_workflow(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("build") + job("flaky", "    continue-on-error: true\n")
                                    + job("maybe", "    continue-on-error: ${{ matrix.experimental }}\n"))}
        subjects = [r["subject"] for r in of(assess_files(self.require(("build", 15368)), files), "OBAAF-SET-008")]
        self.assertEqual(subjects, ['branch "main": job .github/workflows/ci.yml#maybe'])

    def test_branch_filters_and_jobs_that_pull_requests_do_not_reach(self):
        files = {
            "other.yml": workflow("  pull_request:\n    branches: [release]\n", job("only-release")),
            "main.yml": workflow("  pull_request:\n    branches: [main]\n", job("on-main")),
            "pattern.yml": workflow("  pull_request:\n    branches: ['rel*']\n", job("pattern")),
            "ignore.yml": workflow("  pull_request:\n    branches-ignore: [main]\n", job("ignored")),
            "mixed.yml": workflow("  pull_request:\n  push:\n", job("deploy", "    if: github.event_name == 'push'\n")),
        }
        subjects = [r["subject"] for r in of(assess_files(self.require(("x", None)), files), "OBAAF-SET-008", "finding")]
        self.assertEqual(subjects, ['branch "main": job .github/workflows/main.yml#on-main'])

    def test_no_required_check_at_all(self):
        entries = with_body(ADMIN, BRANCH_RULES, lambda body: body.clear())
        finding, = of(assess_files(entries, {"ci.yml": workflow("  pull_request:\n", job("build"))}), "OBAAF-SET-008")
        self.assertEqual(finding["subject"], 'branch "main": no required check')
        self.assertIn('No check is required on "main", and 1 job runs on every pull request into it', finding["message"])

    def test_a_list_of_required_checks_that_is_not_whole_is_cannot_tell(self):
        def strip(body):
            next(r for r in body if r["type"] == "required_status_checks").pop("parameters")
        found = assess_files(with_body(ADMIN, BRANCH_RULES, strip), {"ci.yml": workflow("  pull_request:\n", job("build"))})
        for rule in ("OBAAF-SET-006", "OBAAF-SET-007", "OBAAF-SET-008"):
            self.assertEqual(status(found, rule), "cannot-tell", rule)
        self.assertFalse(of(found, "OBAAF-SET-008", "finding"))


class ActionsSettingsRulesTest(unittest.TestCase):
    SCAN = {"scan.yml": workflow("  pull_request_target:\n  workflow_run:\n    workflows: [CI]\n", job("scan"))}

    def policy(self, **changes) -> list[dict]:
        return with_body(ADMIN, POLICY_7, lambda body: body.update(changes))

    def test_evaluate_mode_is_low_and_a_disabled_policy_blocks_nothing(self):
        finding, = of(assess_files(self.policy(enforcement="evaluate"), self.SCAN), "OBAAF-SET-009")
        self.assertEqual(finding["severity"], "low")
        self.assertIn("evaluate mode", finding["message"])
        self.assertEqual(status(assess_files(self.policy(enforcement="disabled"), self.SCAN), "OBAAF-SET-009"),
                         "no-finding")

    def test_a_policy_for_another_file_or_one_that_allows_every_event_used(self):
        other = self.policy(conditions={"workflow_path": {"include": [".github/workflows/other.yml"], "exclude": []}})
        self.assertEqual(status(assess_files(other, self.SCAN), "OBAAF-SET-009"), "no-finding")
        allowed = self.policy(rules=[{"type": "restrict_action_events", "parameters": {
            "allowed_events": ["pull_request_target", "workflow_run"]}}])
        self.assertEqual(status(assess_files(allowed, self.SCAN), "OBAAF-SET-009"), "no-finding")

    def test_all_workflows_and_an_exclusion(self):
        everything = {"workflow_path": {"include": ["~ALL"], "exclude": []}}
        self.assertEqual(len(of(assess_files(self.policy(conditions=everything), self.SCAN), "OBAAF-SET-009", "finding")), 1)
        everything["workflow_path"]["exclude"] = [".github/workflows/scan.yml"]
        self.assertEqual(status(assess_files(self.policy(conditions=everything), self.SCAN), "OBAAF-SET-009"), "no-finding")

    def test_a_policy_in_a_form_the_rule_does_not_understand_is_cannot_tell(self):
        for changes in ({"conditions": None}, {"conditions": {"ref_name": {"include": ["main"]}}},
                        {"conditions": {"workflow_path": {"include": "scan.yml"}}}, {"enforcement": "strict"},
                        {"rules": [{"type": "restrict_action_events", "parameters": {"allowed_events": "push"}}]}):
            found = assess_files(self.policy(**changes), self.SCAN)
            self.assertEqual([r["state"] for r in of(found, "OBAAF-SET-009")], ["cannot-tell"], changes)
            self.assertEqual(status(found, "OBAAF-SET-010"), "cannot-tell", changes)

    def test_a_rule_about_who_may_start_a_workflow_is_not_this_rules_subject(self):
        actors = self.policy(rules=[{"type": "restrict_actors", "parameters": {"allowed_actors": [{"id": 1}]}}])
        self.assertEqual(status(assess_files(actors, self.SCAN), "OBAAF-SET-009"), "no-finding")

    # -- OBAAF-SET-010
    def test_no_policy_that_allows_pull_request_target_in_a_public_repository(self):
        empty = with_body(ADMIN, POLICIES, lambda body: body.update(total_count=0, policies=[]))
        finding, = of(assess_files(empty, self.SCAN), "OBAAF-SET-010")
        self.assertEqual((finding["state"], finding["severity"]), ("finding", "medium"))
        self.assertIn("from 2026-12-02 a default policy blocks the event", finding["message"])
        self.assertEqual(status(assess_files(ADMIN, self.SCAN), "OBAAF-SET-010"), "no-finding")

    def test_a_policy_that_applies_and_does_not_allow_it_is_the_other_rules_finding(self):
        narrow = self.policy(rules=[{"type": "restrict_action_events", "parameters": {"allowed_events": ["push"]}}])
        found = assess_files(narrow, self.SCAN)
        self.assertFalse(of(found, "OBAAF-SET-010"))
        self.assertIn("pull_request_target", of(found, "OBAAF-SET-009", "finding")[0]["message"])

    def test_a_private_repository_and_a_repository_without_the_trigger(self):
        private = with_body(ADMIN, R, lambda body: body.update(private=True, visibility="private"))
        private.append({"path": f"{R}/actions/permissions/fork-pr-workflows-private-repos", "status": 200,
                        "headers": {}, "body": {"run_workflows_from_fork_pull_requests": False,
                                                "send_write_tokens_to_workflows": False,
                                                "send_secrets_and_variables": False,
                                                "require_approval_for_fork_pr_workflows": True}})
        self.assertEqual(status(assess_files(private, self.SCAN), "OBAAF-SET-010"), "not-applicable")
        plain_ci = {"ci.yml": workflow("  pull_request:\n", job("build"))}
        self.assertEqual(status(assess_files(ADMIN, plain_ci), "OBAAF-SET-010"), "not-applicable")

    # -- OBAAF-SET-012 and 013
    BARE = {"ci.yml": workflow("  pull_request:\n", job("build") + job("lint"), permissions="")}
    WRITER = {"ci.yml": workflow("  pull_request:\n", job("review", "    permissions:\n      pull-requests: write\n"))}

    def token_default(self, default: str, approve: bool) -> list[dict]:
        return with_body(ADMIN, f"{R}/actions/permissions/workflow", lambda body: body.update(
            default_workflow_permissions=default, can_approve_pull_request_reviews=approve))

    def test_jobs_with_no_permissions_block_and_a_default_of_write(self):
        finding, = of(assess_files(self.token_default("write", False), self.BARE), "OBAAF-SET-012")
        self.assertIn("2 jobs in .github/workflows/ci.yml declare no permissions (build, lint)", finding["message"])
        self.assertEqual(status(assess_files(ADMIN, self.BARE), "OBAAF-SET-012"), "no-finding")
        self.assertEqual(status(assess_files(self.token_default("write", False), self.WRITER), "OBAAF-SET-012"),
                         "not-applicable")
        unknown = assess_files(recording("public-no-token"), self.BARE, token=None)
        self.assertEqual(status(unknown, "OBAAF-SET-012"), "cannot-tell")

    def test_workflows_that_may_approve_and_a_job_that_can_write_to_pull_requests(self):
        finding, = of(assess_files(self.token_default("read", True), self.WRITER), "OBAAF-SET-013")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn('"main" requires 1 approval', finding["message"])
        self.assertEqual(status(assess_files(ADMIN, self.WRITER), "OBAAF-SET-013"), "no-finding")
        # With a default of write, a job with no permissions block holds such a token as well.
        self.assertEqual(len(of(assess_files(self.token_default("write", True), self.BARE), "OBAAF-SET-013")), 1)
        # With a default of read too: a workflow on any branch can ask for the token, whatever the files here say.
        self.assertEqual(len(of(assess_files(self.token_default("read", True), self.BARE), "OBAAF-SET-013")), 1)
        unknown = assess_files(recording("public-no-token"), self.WRITER, token=None)
        self.assertEqual(status(unknown, "OBAAF-SET-013"), "cannot-tell")

    # -- OBAAF-SET-014
    HOSTED = {"ci.yml": workflow("  pull_request:\n", "  build:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make\n")}

    def test_a_pull_request_job_on_a_self_hosted_runner_in_a_public_repository(self):
        finding, = of(assess_files(ADMIN, self.HOSTED), "OBAAF-SET-014")
        self.assertEqual(finding["severity"], "high")
        self.assertIn('required only for "first_time_contributors"', finding["message"])
        everyone = with_body(ADMIN, f"{R}/actions/permissions/fork-pr-contributor-approval",
                             lambda body: body.update(approval_policy="all_external_contributors"))
        self.assertEqual(status(assess_files(everyone, self.HOSTED), "OBAAF-SET-014"), "no-finding")
        # No job here names a self-hosted runner, but a fork's pull request runs its own copy of the workflow
        # and can name one; whether the repository has any is not read.
        self.assertEqual(status(assess_files(ADMIN, {"ci.yml": workflow("  pull_request:\n", job("b"))}),
                                "OBAAF-SET-014"), "cannot-tell")
        self.assertEqual(status(assess_files(ADMIN, {"ci.yml": workflow("  push:\n", job("b"))}),
                                "OBAAF-SET-014"), "cannot-tell")
        unknown = assess_files(recording("public-no-token"), self.HOSTED, token=None)
        self.assertEqual(status(unknown, "OBAAF-SET-014"), "cannot-tell")

    # -- OBAAF-SET-015
    def pinning(self, required) -> list[dict]:
        return with_body(ADMIN, f"{R}/actions/permissions", lambda body: body.update(sha_pinning_required=required))

    def test_pinning_required_and_an_action_that_is_not_pinned(self):
        loose = {"ci.yml": workflow("  push:\n", job("build", "", "      - uses: actions/checkout@v7\n      - uses: ./local\n"))}
        finding, = of(assess_files(self.pinning(True), loose), "OBAAF-SET-015")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn('"actions/checkout@v7"', finding["message"])
        self.assertNotIn("./local", finding["message"])
        self.assertEqual(status(assess_files(self.pinning(False), loose), "OBAAF-SET-015"), "no-finding")

    def test_everything_pinned_and_nothing_requires_it_is_low(self):
        pinned = {"ci.yml": workflow("  push:\n", job("build", "", f"      - uses: {PIN}\n"))}
        finding, = of(assess_files(self.pinning(False), pinned), "OBAAF-SET-015")
        self.assertEqual(finding["severity"], "low")
        self.assertEqual(status(assess_files(self.pinning(True), pinned), "OBAAF-SET-015"), "no-finding")

        def drop(body):
            body.pop("sha_pinning_required")
        self.assertEqual(status(assess_files(with_body(ADMIN, f"{R}/actions/permissions", drop), pinned),
                                "OBAAF-SET-015"), "cannot-tell")


class NeverAPassTest(unittest.TestCase):
    """What the rules do when they cannot know: say so."""

    def test_the_rule_list_is_whole_and_in_order(self):
        self.assertEqual([r.id for r in rules.RULES], [f"OBAAF-SET-{n:03d}" for n in range(1, len(rules.RULES) + 1)])
        self.assertEqual(set(rules.RULE_FUNCTIONS), set(rules.RULE_BY_ID))
        for rule in rules.RULES:
            self.assertIn(rule.severity, rules.SEVERITIES)
            self.assertTrue(set(rule.reads) <= set(audit.BY_KEY), rule.id)

    def test_without_the_workflow_files_every_rule_is_cannot_tell(self):
        snap, _ = take(ADMIN, token=TOKEN)
        found = rules.evaluate(snap, workflows.not_read("no directory was given"))
        reads_files = {r.id for r in rules.RULES if r.files}
        self.assertEqual(len(reads_files), 12)
        self.assertEqual({r["status"] for r in found["rules"] if r["id"] in reads_files}, {"cannot-tell"})
        self.assertIn("no directory was given", of(found, "OBAAF-SET-001")[0]["message"])
        # The bypass, the approvals and whether workflows may approve are settings and nothing else, so
        # those three rules still answer (the recording does not let workflows approve).
        self.assertEqual([r["rule"] for r in found["results"] if r["state"] == "finding"],
                         ["OBAAF-SET-004", "OBAAF-SET-005"])

    def test_a_repository_that_was_not_read_is_cannot_tell_for_every_rule(self):
        snap, _ = take(replace(ADMIN, R, status=404, body={"message": "Not Found"}), token=TOKEN)
        found = rules.evaluate(snap, workflows.read(INCIDENT_REPO))
        self.assertEqual({r["status"] for r in found["rules"]}, {"cannot-tell"})

    def test_a_workflow_file_that_does_not_parse_makes_every_quiet_rule_cannot_tell(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("build")), "broken.yml": "on: [push\njobs: {"}
        found = assess_files(ADMIN, files)
        reads_files = {r.id for r in rules.RULES if r.files}
        self.assertNotIn("no-finding", {r["status"] for r in found["rules"] if r["id"] in reads_files})
        self.assertNotIn("not-applicable", {r["status"] for r in found["rules"] if r["id"] in reads_files})
        self.assertIn("broken.yml", of(found, "OBAAF-SET-010")[0]["message"])

    def test_a_rule_that_fails_is_cannot_tell_and_the_command_exits_1(self):
        def boom(run):
            raise KeyError("no such field")
        with mock.patch.dict(rules.RULE_FUNCTIONS, {"OBAAF-SET-001": boom}):
            found = assess(ADMIN)
            self.assertEqual(found["summary"]["rules_failed"], 1)
            result, = of(found, "OBAAF-SET-001")
            self.assertEqual(result["state"], "cannot-tell")
            self.assertIn("bug in obaaf", result["message"])
            code, out, err = audit_command(ADMIN, INCIDENT_REPO, "--fail-on", "never", token=True)
        self.assertEqual(code, 1)
        self.assertIn("1 rule(s) failed while running", err)

    def test_no_finding_is_above_its_rules_highest_severity(self):
        for entries, token in ((ADMIN, TOKEN), (recording("public-no-token"), None)):
            for result in assess(entries, token=token)["results"]:
                if result["state"] == "finding":
                    top = rules.RULE_BY_ID[result["rule"]].severity
                    self.assertLessEqual(rules.SEVERITIES.index(top), rules.SEVERITIES.index(result["severity"]))

    def test_parameters_and_conditions_of_any_shape_never_stop_a_rule(self):
        """A rule's parameters and a policy's conditions are kept as GitHub sent them, so the rules must take
        whatever is there. 3,000 snapshots with those parts replaced by other JSON: no rule fails."""
        snap, _ = take(ADMIN, token=TOKEN)
        usage = workflows.read(INCIDENT_REPO)
        rng = random.Random(20261113)
        junk = [None, True, 0, -1, 2 ** 40, 1.5, "", "main", [], {}, [None], ["a", 1], {"include": 3},
                {"required_status_checks": [{"context": 5}]}, {"required_status_checks": "x"},
                {"required_approving_review_count": "2"}, {"required_approving_review_count": True},
                {"allowed_events": [1]}, {"allowed_events": None}, {"workflow_path": []},
                {"workflow_path": {"include": [1]}}, {"workflow_path": {"include": ["~ALL"], "exclude": None}}]

        def spots(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ("parameters", "conditions"):
                        yield value, key
                    yield from spots(item)
            elif isinstance(value, list):
                for item in value:
                    yield from spots(item)

        for _ in range(3000):
            mutated = copy.deepcopy(snap)
            places = list(spots(mutated["settings"]))
            for holder, key in rng.sample(places, rng.randint(1, 3)):
                holder[key] = copy.deepcopy(rng.choice(junk))
            if snapshot_mod.problems(mutated):
                continue  # not a snapshot the command would load
            found = rules.evaluate(mutated, usage)
            self.assertEqual(found["summary"]["rules_failed"], 0, json.dumps(mutated["settings"]["branch_rules"]))

    def test_names_from_settings_and_workflows_cannot_forge_a_line_of_the_report(self):
        def rename(body):
            body["environments"][0]["name"] = 'x"\n  HIGH    forged\u202e'
        entries = with_body(ADMIN, ENVIRONMENTS, rename)
        entry_for(entries, f"{R}/environments/main-only/secrets?per_page=100")["path"] = (
            f"{R}/environments/x%22%0A%20%20HIGH%20%20%20%20forged%E2%80%AE/secrets?per_page=100")
        files = {"a.yml": workflow("  push:\n", job("j", '    environment: "x\\"\\n  HIGH    forged\\u202E"\n'))}
        with TempDir() as tmp:
            snap, _ = take(entries, token=TOKEN)
            usage = workflows.read(tree(tmp, files))
            text = report.to_text(snap, assessment=rules.evaluate(snap, usage), usage=usage)
        self.assertIn("OBAAF-SET-001", text)
        self.assertNotIn("\u202e", text)
        self.assertFalse([line for line in text.splitlines() if line.startswith("  HIGH    forged")])


class FirstReviewTest(unittest.TestCase):
    """Faults an independent review found in the first version of the rules, each by running it. Most were
    a "no finding" or a "does not apply" where the rule had not looked; each is pinned here."""

    READS_KEY = "      - run: ./a\n        env:\n          K: ${{ secrets.MODEL_API_KEY }}\n"

    def states(self, found, rule):
        return sorted({r["state"] for r in of(found, rule)})

    # -- environments
    def test_an_environment_named_by_an_expression_is_cannot_tell_for_both_environment_rules(self):
        for spelling in ("${{ 'main-only' }}", "\n      name: ${{ inputs.e }}", "${{ matrix.e }}"):
            files = {"t.yml": workflow("  pull_request_target:\n", job("j", f"    environment: {spelling}\n",
                                                                       self.READS_KEY))}
            found = assess_files(ADMIN, files)
            for rule in ("OBAAF-SET-001", "OBAAF-SET-002"):
                self.assertEqual(status(found, rule), "cannot-tell", (rule, spelling))
                self.assertEqual(of(found, rule)[0]["subject"], "job .github/workflows/t.yml#j")

    def test_a_job_moved_into_a_reusable_workflow_is_still_reached_by_its_callers_events(self):
        caller = workflow("  pull_request_target:\n  pull_request:\n", "  c:\n    uses: ./.github/workflows/b.yml\n")
        called = workflow("  workflow_call:\n", "  inner:\n    runs-on: self-hosted\n    environment: main-only\n"
                                                "    steps:\n" + self.READS_KEY)
        found = assess_files(limited(ADMIN, ("main", "branch")), {"a.yml": caller, "b.yml": called})
        finding, = of(found, "OBAAF-SET-002", "finding")
        self.assertEqual(finding["subject"], "job .github/workflows/b.yml#inner")
        self.assertIn("pull_request_target", finding["message"])
        self.assertEqual(len(of(found, "OBAAF-SET-014", "finding")), 1)

    def test_a_called_workflow_that_was_not_read_is_cannot_tell(self):
        caller = workflow("  pull_request_target:\n  pull_request:\n",
                          "  c:\n    uses: octo-org/shared/.github/workflows/b.yml@" + "a" * 40 + "\n")
        found = assess_files(ADMIN, {"a.yml": caller})
        self.assertEqual(status(found, "OBAAF-SET-002"), "cannot-tell")
        self.assertEqual(status(found, "OBAAF-SET-014"), "cannot-tell")

    def test_an_environment_limited_to_other_branches_shuts_default_branch_events_out(self):
        target = {"t.yml": workflow("  issue_comment:\n", job("j", "    environment: main-only\n", self.READS_KEY))}
        self.assertEqual(status(assess_files(limited(ADMIN, ("release", "branch")), target), "OBAAF-SET-002"),
                         "no-finding")
        finding, = of(assess_files(limited(ADMIN, ("rel*", "branch")), target), "OBAAF-SET-002")
        self.assertIn("was not read or rests on a pattern", finding["message"])

    def test_pull_request_target_runs_as_the_default_branch_whatever_the_base(self):
        # GitHub's changelog of 2025-11-07: from 2025-12-08, for pull_request_target "environment rules
        # evaluate against the default branch", whatever the pull request's base. A review on 2026-11-13
        # first said the base branch; the third pass read the changelog.
        target = {"t.yml": workflow("  pull_request_target:\n    branches: [release]\n",
                                    job("j", "    environment: main-only\n", self.READS_KEY))}
        self.assertEqual(status(assess_files(limited(ADMIN, ("release", "branch")), target), "OBAAF-SET-002"),
                         "no-finding")
        finding, = of(assess_files(limited(ADMIN, ("main", "branch")), target), "OBAAF-SET-002")
        self.assertIn("admits the default branch", finding["message"])

    def test_an_environment_that_holds_no_secret_is_low_and_says_what_it_does_not_know(self):
        empty = with_body(ADMIN, f"{R}/environments/main-only/secrets?per_page=100",
                          lambda body: body.update(total_count=0, secrets=[]))
        files = {"x.yml": workflow("  push:\n", job("deploy", "    environment: main-only\n"))}
        finding, = of(assess_files(empty, files), "OBAAF-SET-001")
        self.assertEqual(finding["severity"], "low")
        self.assertIn("It holds no secret", finding["message"])
        self.assertNotIn("read whatever secrets", finding["message"])

    def test_an_environment_limited_to_a_branch_that_was_not_audited_is_cannot_tell(self):
        files = {"x.yml": workflow("  push:\n", job("deploy", "    environment: main-only\n"))}
        result, = of(assess_files(limited(ADMIN, ("dev", "branch")), files), "OBAAF-SET-001")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("--branch", result["message"])
        both = assess_files(limited(ADMIN, ("dev", "branch"), ("main", "branch"), protection_rules=REVIEWERS), files)
        self.assertEqual(status(both, "OBAAF-SET-001"), "no-finding")

    # -- secrets
    def test_a_job_that_can_read_every_secret_reads_the_one_stored_twice(self):
        for body in ("      - run: ./a\n        env:\n          K: ${{ toJSON(secrets) }}\n",
                     "      - run: ./a\n        env:\n          K: ${{ secrets[format('{0}_KEY', 'MODEL_API')] }}\n"):
            found = assess_files(ADMIN, {"x.yml": workflow("  push:\n", job("j", "", body))})
            self.assertEqual([r["subject"] for r in of(found, "OBAAF-SET-003", "finding")], ['secret "MODEL_API_KEY"'])
        inherit = workflow("  push:\n", "  c:\n    uses: octo-org/s/.github/workflows/w.yml@v1\n    secrets: inherit\n")
        self.assertEqual(len(of(assess_files(ADMIN, {"x.yml": inherit}), "OBAAF-SET-003", "finding")), 1)

    def test_a_configuration_that_cannot_be_read_is_cannot_tell_not_protects_nothing(self):
        files = {"x.yml": workflow("  push:\n", job("j"))}
        for config in ("protected_secrets:\n  '*_API_KEY': main-only\nlane: {}\n", "ignore: 5\n", "ignore: true\n"):
            found = assess_files(ADMIN, files, config=config)
            self.assertEqual(found["summary"]["rules_failed"], 0, config)
            for rule in ("OBAAF-SET-001", "OBAAF-SET-003"):
                self.assertEqual(self.states(found, rule), ["cannot-tell"], (rule, config))
                self.assertIn("The configuration could not be read", of(found, rule)[0]["message"])
        with TempDir() as tmp:
            code, out, err = audit_command(ADMIN, tree(tmp, files, config="ignore: 5\n"), "--fail-on", "never",
                                           token=True)
        self.assertEqual(code, 0)
        self.assertIn("The checker's configuration could not be read", out)
        self.assertNotIn("failed unexpectedly", err)

    def test_an_environment_the_configuration_names_when_the_environments_were_not_all_read(self):
        files = {"x.yml": workflow("  push:\n", job("j"))}
        config = "protected_secrets:\n  DEPLOY_KEY: production\n"
        partly = refused(ADMIN, f"{R}/environments/release/deployment-branch-policies?per_page=100")
        for entries in (partly, refused(ADMIN, ENVIRONMENTS)):
            results = [r for r in of(assess_files(entries, files, config=config), "OBAAF-SET-003")
                       if r["subject"] == 'environment "production"']
            self.assertEqual([(r["state"], r["unread"]) for r in results], [("cannot-tell", ["environments"])])
        self.assertEqual(len([r for r in of(assess_files(ADMIN, files, config=config), "OBAAF-SET-003", "finding")
                              if r["subject"] == 'environment "production"']), 1)

    # -- reusable workflows
    def test_ways_of_passing_an_environment_only_secret(self):
        callee = workflow("  workflow_call:\n", job("u", "", "      - run: ./u\n        env:\n          T: ${{ secrets.t }}\n"))
        computed = workflow("  push:\n", "  c:\n    uses: ./.github/workflows/p.yml\n    secrets:\n"
                                         "      t: ${{ secrets[format('{0}', 'PACKAGE_INDEX_TOKEN')] }}\n")
        found = assess_files(ADMIN, {"r.yml": computed, "p.yml": callee})
        self.assertEqual(self.states(found, "OBAAF-SET-011"), ["cannot-tell"])
        as_input = workflow("  push:\n", "  c:\n    uses: ./.github/workflows/p.yml\n    with:\n"
                                         "      token: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n")
        finding, = of(assess_files(ADMIN, {"r.yml": as_input, "p.yml": callee}), "OBAAF-SET-011")
        self.assertEqual(finding["state"], "finding")
        every = workflow("  workflow_call:\n", job("u", "", "      - run: ./u\n        env:\n          T: ${{ toJSON(secrets) }}\n"))
        inherit = workflow("  push:\n", "  c:\n    uses: ./.github/workflows/p.yml\n    secrets: inherit\n")
        self.assertEqual(self.states(assess_files(ADMIN, {"r.yml": inherit, "p.yml": every}), "OBAAF-SET-011"),
                         ["cannot-tell"])

    def test_a_called_job_whose_environment_is_an_input_is_cannot_tell_not_a_finding(self):
        caller = workflow("  push:\n", "  c:\n    uses: ./.github/workflows/p.yml\n    with:\n      environment: release\n"
                                        "    secrets: inherit\n")
        callee = workflow("  workflow_call:\n", job("u", "    environment: ${{ inputs.environment }}\n",
                                                   "      - run: ./u\n        env:\n          T: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n"))
        found = assess_files(ADMIN, {"r.yml": caller, "p.yml": callee})
        self.assertEqual(self.states(found, "OBAAF-SET-011"), ["cannot-tell"])

    def test_a_secret_passed_by_name_is_empty_whatever_the_called_job_declares(self):
        caller = workflow("  push:\n", "  c:\n    uses: ./.github/workflows/p.yml\n    secrets:\n"
                                        "      PACKAGE_INDEX_TOKEN: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n")
        callee = workflow("  workflow_call:\n", job("u", "    environment: release\n",
                                                   "      - run: ./u\n        env:\n          T: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n"))
        finding, = of(assess_files(ADMIN, {"r.yml": caller, "p.yml": callee}), "OBAAF-SET-011")
        self.assertIn("whatever the called workflow declares", finding["message"])
        self.assertIn("stop passing it from the caller", rules.RULE_BY_ID["OBAAF-SET-011"].fix)

    # -- bypass
    def test_what_github_says_of_the_tokens_own_account_does_not_stand_for_the_list(self):
        def hide(body):
            body.pop("bypass_actors")
            body["current_user_can_bypass"] = "pull_requests_only"
        found = assess_files(with_body(ADMIN, RULESET_42, hide), BranchRulesTest.CI)
        self.assertEqual([r["severity"] for r in of(found, "OBAAF-SET-004", "finding")], ["low"])
        unknown, = of(found, "OBAAF-SET-004", "cannot-tell")
        self.assertEqual(unknown["unread"], ["ruleset_bypass_actors"])

    def test_who_may_skip_a_classic_rules_reviews(self):
        classic = {"url": "x", "enforce_admins": {"enabled": True}, "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "bypass_pull_request_allowances": {"users": [{"login": "dev1"}], "teams": [], "apps": []}}}
        entries = replace(with_body(ADMIN, BRANCH_RULES, lambda body: body.clear()),
                          f"{R}/branches/main/protection", status=200, body=classic)
        finding, = of(assess_files(entries, BranchRulesTest.CI), "OBAAF-SET-004")
        self.assertEqual((finding["state"], finding["severity"]), ("finding", "medium"))
        self.assertIn("lets 1 user, team or app bypass that", finding["message"])

    def test_a_ruleset_that_asks_for_no_check_and_no_review_is_not_this_rules_subject(self):
        def only_history(body):
            body[:] = [r for r in body if r["type"] in ("deletion", "non_fast_forward")]
        found = assess_files(with_body(ADMIN, BRANCH_RULES, only_history), BranchRulesTest.CI)
        self.assertEqual(status(found, "OBAAF-SET-004"), "not-applicable")

    def test_a_bypass_with_the_collaborators_unread_says_what_it_could_not_count(self):
        found = assess_files(refused(ADMIN, COLLABORATORS), BranchRulesTest.CI)
        self.assertEqual([r["severity"] for r in of(found, "OBAAF-SET-004", "finding")], ["medium"])
        unknown, = of(found, "OBAAF-SET-004", "cannot-tell")
        self.assertEqual(unknown["unread"], ["collaborators"])

    def test_the_ruleset_is_named_as_it_is_written(self):
        entries = with_body(ADMIN, RULESET_42, lambda body: body.update(name="Protect MAIN (Prod)"))
        entry_for(entries, f"{R}/rulesets?includes_parents=true&per_page=100")["body"][0]["name"] = "Protect MAIN (Prod)"
        finding, = of(assess_files(entries, BranchRulesTest.CI), "OBAAF-SET-004")
        self.assertIn('The ruleset 42 "Protect MAIN (Prod)" is in force', finding["message"])

    # -- required checks
    def require(self, *checks):
        return RequiredCheckRulesTest.require(None, *checks)

    def test_a_required_check_whose_job_never_runs_for_a_pull_request_into_the_branch(self):
        for on, expected in (("  schedule:\n    - cron: '0 0 * * *'\n", "finding"),
                             ("  pull_request:\n    branches: [develop]\n", "finding"),
                             ("  pull_request:\n    branches-ignore: [main]\n", "finding"),
                             ("  merge_group:\n", "finding"),
                             ("  pull_request:\n    types: [labeled]\n", "finding"),
                             ("  pull_request:\n    branches: ['release/**']\n", "cannot-tell"),
                             ("  workflow_dispatch:\n", "cannot-tell"),
                             ("  pull_request:\n    types: [opened, synchronize, reopened]\n", None)):
            found = assess_files(self.require(("test", 15368)), {"w.yml": workflow(on, job("test"))})
            self.assertEqual(self.states(found, "OBAAF-SET-007"), [expected] if expected else [], on)
            self.assertEqual(status(found, "OBAAF-SET-006"), "no-finding", on)

    def test_a_token_that_may_write_checks_makes_a_missing_check_cannot_tell(self):
        writer = workflow("  pull_request:\n", job("other"), permissions="permissions:\n  statuses: write\n")
        found = assess_files(self.require(("build", 15368)), {"w.yml": writer})
        result, = of(found, "OBAAF-SET-006")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("may write checks or statuses", result["message"])
        bare = workflow("  pull_request:\n", job("other"), permissions="")
        self.assertEqual(self.states(assess_files(self.require(("build", 15368)), {"w.yml": bare}), "OBAAF-SET-006"),
                         ["finding"])  # the recording's default for the token is read
        unknown = assess_files(refused(self.require(("build", 15368)), f"{R}/actions/permissions/workflow"),
                               {"w.yml": bare})
        self.assertEqual(self.states(unknown, "OBAAF-SET-006"), ["cannot-tell"])

    def test_matrix_values_are_compared_when_the_matrix_is_written_out(self):
        other = workflow("  pull_request:\n", job("test", "    strategy:\n      matrix:\n        python: ['3.11', '3.12']\n"))
        found = assess_files(ADMIN, {"ci.yml": other})  # the recording requires "test (3.13)"
        self.assertEqual(self.states(found, "OBAAF-SET-006"), ["finding"])
        two = workflow("  pull_request:\n", job("t", "    strategy:\n      matrix:\n        os: [linux, mac]\n        py: [3, 4]\n"))
        found = assess_files(self.require(("t (linux, 3)", 15368), ("t (mac, 4)", 15368), ("t (3, mac)", 15368)), {"ci.yml": two})
        self.assertEqual([r["subject"] for r in of(found, "OBAAF-SET-006", "finding")],
                         ['branch "main": required check "t (3, mac)"'])
        for body in ("    strategy:\n      matrix:\n        python: ${{ fromJSON(inputs.v) }}\n",
                     "    strategy:\n      matrix:\n        python: ['3.13']\n        include:\n          - python: '3.14'\n",
                     "    strategy:\n      matrix:\n        python: [3.13]\n"):
            found = assess_files(ADMIN, {"ci.yml": workflow("  pull_request:\n", job("test", body))})
            self.assertEqual(self.states(found, "OBAAF-SET-006"), ["cannot-tell"], body)

    def test_the_checks_of_a_called_workflow_are_the_called_jobs(self):
        files = {"ci.yml": workflow("  pull_request:\n", "  build:\n    uses: ./.github/workflows/lib.yml\n"),
                 "lib.yml": workflow("  workflow_call:\n", job("lint"))}
        found = assess_files(self.require(("build / test", 15368)), files)
        self.assertEqual(self.states(found, "OBAAF-SET-006"), ["finding"])
        self.assertEqual(status(assess_files(self.require(("build / lint", 15368)), files), "OBAAF-SET-006"), "no-finding")
        # A job in a workflow that is only called does not report under its own name.
        self.assertEqual(self.states(assess_files(self.require(("lint", 15368)), files), "OBAAF-SET-006"), ["finding"])

    def test_a_matrix_of_calls_reports_name_values_and_called_job(self):
        files = {"ci.yml": workflow("  pull_request:\n", "  build:\n    strategy:\n      matrix:\n        os: [linux, mac]\n"
                                                         "    uses: ./.github/workflows/lib.yml\n"),
                 "lib.yml": workflow("  workflow_call:\n", job("test"))}
        found = assess_files(self.require(("build (linux) / test", 15368), ("build (mac) / test", 15368)), files)
        for rule in ("OBAAF-SET-006", "OBAAF-SET-008"):
            self.assertEqual(status(found, rule), "no-finding", rule)

    def test_a_job_that_runs_only_for_some_pull_request_activity_is_not_asked_to_be_required(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("build")),
                 "cleanup.yml": workflow("  pull_request:\n    types: [closed]\n", job("cleanup")),
                 "label.yml": workflow("  pull_request_target:\n    types: [labeled]\n", job("label"))}
        self.assertEqual(status(assess_files(self.require(("build", 15368)), files), "OBAAF-SET-008"), "no-finding")

    def test_a_requirement_tied_to_another_app_is_cannot_tell_even_when_a_job_has_the_name(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("build"))}
        result, = of(assess_files(self.require(("build", 999)), files), "OBAAF-SET-006")
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("the app with id 999, which is not GitHub Actions", result["message"])

    # -- Actions settings
    def test_a_policy_rule_in_a_form_the_rule_does_not_know_is_cannot_tell_for_both_policy_rules(self):
        for parameters in (None, {"events": ["pull_request_target", "workflow_run"]}, {"allowed_actors": "all"}):
            entries = with_body(ADMIN, POLICY_7, lambda body: body.update(
                rules=[{"type": "restrict_action_events", **({"parameters": parameters} if parameters else {})}]))
            found = assess_files(entries, ActionsSettingsRulesTest.SCAN)
            for rule in ("OBAAF-SET-009", "OBAAF-SET-010"):
                self.assertEqual(self.states(found, rule), ["cannot-tell"], (rule, parameters))

    def test_a_default_for_the_token_that_is_a_word_the_rule_does_not_know(self):
        entries = with_body(ADMIN, f"{R}/actions/permissions/workflow",
                            lambda body: body.update(default_workflow_permissions="permissive"))
        self.assertEqual(status(assess_files(entries, ActionsSettingsRulesTest.BARE), "OBAAF-SET-012"), "cannot-tell")

    def test_a_workflows_approval_and_what_clears_it(self):
        approve = ActionsSettingsRulesTest.token_default(None, "read", True)
        writer = ActionsSettingsRulesTest.WRITER

        def owners(body):
            next(r for r in body if r["type"] == "pull_request")["parameters"]["require_code_owner_review"] = True
        # One approval that must be a code owner's: cleared where every file has an owner, which is the
        # CODEOWNERS file, not read.
        self.assertEqual(status(assess_files(with_body(approve, BRANCH_RULES, owners), writer), "OBAAF-SET-013"),
                         "cannot-tell")

        def owners_and_two(body):
            rule = next(r for r in body if r["type"] == "pull_request")["parameters"]
            rule.update(require_code_owner_review=True, required_approving_review_count=2)
        # Two approvals and a code owner's: the workflow's approval is one of the two.
        finding, = of(assess_files(with_body(approve, BRANCH_RULES, owners_and_two), writer), "OBAAF-SET-013")
        self.assertIn("still counts towards the number", finding["message"])

        def none(body):
            next(r for r in body if r["type"] == "pull_request")["parameters"]["required_approving_review_count"] = 0
        self.assertEqual(status(assess_files(with_body(approve, BRANCH_RULES, none), writer), "OBAAF-SET-013"),
                         "no-finding")
        unknown = assess_files(refused(approve, BRANCH_RULES), writer)
        self.assertEqual(self.states(unknown, "OBAAF-SET-013"), ["cannot-tell"])

    def test_a_runner_the_audit_cannot_classify_is_cannot_tell(self):
        for runs_on in ("${{ matrix.r }}\n    strategy:\n      matrix:\n        r: [gpu-box]", "${{ vars.RUNNER }}",
                        "[gpu-box]"):
            files = {"ci.yml": workflow("  pull_request:\n", f"  b:\n    runs-on: {runs_on}\n    steps:\n      - run: make\n")}
            self.assertEqual(self.states(assess_files(ADMIN, files), "OBAAF-SET-014"), ["cannot-tell"], runs_on)
        literal = workflow("  pull_request:\n", "  b:\n    runs-on: ${{ matrix.r }}\n    strategy:\n      matrix:\n"
                                                "        r: [self-hosted]\n    steps:\n      - run: make\n")
        self.assertEqual(self.states(assess_files(ADMIN, {"ci.yml": literal}), "OBAAF-SET-014"), ["finding"])
        hosted = workflow("  pull_request:\n", job("b"))
        self.assertEqual(status(assess_files(ADMIN, {"ci.yml": hosted}), "OBAAF-SET-014"), "cannot-tell")

    def test_a_private_repository_that_sends_fork_pull_requests_secrets(self):
        private = with_body(ADMIN, R, lambda body: body.update(private=True, visibility="private"))
        private.append({"path": f"{R}/actions/permissions/fork-pr-workflows-private-repos", "status": 200,
                        "headers": {}, "body": {"run_workflows_from_fork_pull_requests": True,
                                                "send_write_tokens_to_workflows": False,
                                                "send_secrets_and_variables": True,
                                                "require_approval_for_fork_pr_workflows": False}})
        caller = workflow("  pull_request:\n", "  c:\n    uses: ./.github/workflows/p.yml\n    secrets: inherit\n")
        callee = workflow("  workflow_call:\n", job("u", "", "      - run: ./u\n        env:\n          T: ${{ secrets.K }}\n"))
        finding, = of(assess_files(private, {"ci.yml": caller, "p.yml": callee}), "OBAAF-SET-014")
        self.assertEqual((finding["state"], finding["severity"]), ("finding", "high"))
        # A job that reads no secret does not clear it: a fork's pull request runs its own copy of the workflow.
        quiet = workflow("  pull_request:\n", job("b"))
        self.assertEqual(status(assess_files(private, {"ci.yml": quiet}), "OBAAF-SET-014"), "findings")
        self.assertEqual(status(assess_files(private, {"ci.yml": workflow("  push:\n", job("b"))}), "OBAAF-SET-014"),
                         "findings")
        closed = with_body(private, f"{R}/actions/permissions/fork-pr-workflows-private-repos",
                           lambda body: body.update(send_secrets_and_variables=False))
        self.assertEqual(status(assess_files(closed, {"ci.yml": quiet}), "OBAAF-SET-014"), "no-finding")

    def test_pinning_is_about_jobs_that_use_an_action(self):
        entries = ActionsSettingsRulesTest.pinning(None, False)
        only_run = {"ci.yml": workflow("  push:\n", job("b"))}
        self.assertEqual(status(assess_files(entries, only_run), "OBAAF-SET-015"), "not-applicable")

    # -- whose files, and what a name can do
    def test_a_directory_inside_a_clone_is_not_the_clone(self):
        with TempDir() as tmp:
            root = tree(tmp, {"ci.yml": workflow("  push:\n", job("a"))})
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "remote", "add", "origin", "https://github.com/example-studio/game"],
                           check=True)
            nested = tree(root / "examples", {"t.yml": workflow("  push:\n", job("t"))})
            self.assertIsNone(audit_cli.usage_for(str(root), REPO).get("note"))
            self.assertIn("is not the top level of a clone", audit_cli.usage_for(str(nested), REPO)["note"])
            with mock.patch.dict("os.environ", {"GIT_DIR": str(root / ".git")}):
                self.assertIn("is not the top level", audit_cli.usage_for(str(tmp), REPO).get("note", "is not the top level"))
                self.assertEqual(audit_cli._origin(str(nested)), None)
            snap, _ = take(ADMIN, token=TOKEN)
            snapshot_mod.write(snap, tmp / "s.json")
            done = subprocess.run([__import__("sys").executable, "-m", "obaaf", "audit", "--from-snapshot",
                                   str(tmp / "s.json"), "--fail-on", "never"], cwd=nested, capture_output=True,
                                  text=True, timeout=60, check=False,
                                  env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")})
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("The workflow files were not read: the current directory is not the top level of a clone",
                          done.stdout)

    def test_a_remote_on_github_com_says_nothing_about_another_server(self):
        usage = audit_cli.usage_for(None, "Obaaf/OBAAF", github_com=False)
        self.assertFalse(usage["read"])
        self.assertIn("a server other than github.com", usage["reason"])

    def test_characters_that_print_as_blanks_cannot_push_text_to_the_start_of_a_line(self):
        for blank in "\u2800\u3164\u115f\u1160\uffa0":
            self.assertEqual(github.plain("x" + blank * 40 + "OBAAF-SET-001  no finding"), "x" + "?" * 40
                             + "OBAAF-SET-001 no finding")
        step = f'      - uses: "x@1{chr(0x2800) * 60}  OBAAF-SET-001  no finding: 1 environment"\n'
        with TempDir() as tmp:
            snap, _ = take(ActionsSettingsRulesTest.pinning(None, True), token=TOKEN)
            usage = workflows.read(tree(tmp, {"ci.yml": workflow("  push:\n", job("b", "", step))}))
            text = report.to_text(snap, assessment=rules.evaluate(snap, usage), usage=usage)
        self.assertNotIn("\u2800", text)
        self.assertIn("OBAAF-SET-015", text)

    def test_the_report_counts_the_files_that_could_not_be_read_and_every_file_rule_says_so(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("build", "    environment: main-only\n")),
                 "broken.yml": "on: [push\njobs: {"}
        with TempDir() as tmp:
            snap, _ = take(refused(ADMIN, ENVIRONMENTS), token=TOKEN)
            usage = workflows.read(tree(tmp, files))
            found = rules.evaluate(snap, usage)
            text = report.to_text(snap, assessment=found, usage=usage)
        self.assertIn("Compared with 1 workflow file in the directory", text)
        self.assertIn("(1 more could not be read)", text)
        for rule in rules.RULES:
            mentions = [r for r in of(found, rule.id) if "broken.yml" in r["message"]]
            self.assertEqual(len(mentions), 1 if rule.files else 0, rule.id)


def audit_command(entries, directory, *args, token: bool = False, repository: str = REPO):
    """Run `obaaf audit DIRECTORY --repo REPOSITORY` in-process against a recording."""
    transport = audit.ReplayTransport(copy.deepcopy(entries))
    env = {"GH_TOKEN": TOKEN} if token else {}
    with clean_env(**env), mock.patch.object(github, "UrllibTransport", return_value=transport):
        return run_cli("audit", *([directory] if directory else []), "--repo", repository, *args)


class CommandTest(unittest.TestCase):
    def test_findings_decide_the_exit_code_at_the_severity_asked_for(self):
        code, out, err = audit_command(ADMIN, INCIDENT_REPO, token=True)
        self.assertEqual(code, 1)
        self.assertIn("8 finding(s): 3 high, 5 medium, 0 low (--fail-on medium)", err)
        self.assertIn("FINDINGS: 8 (3 high, 5 medium, 0 low). CANNOT TELL: 1, from 1 of 15 rules.", out)
        self.assertLess(out.index("FINDINGS: 8"), out.index("WHAT WAS READ"))
        self.assertEqual(audit_command(ADMIN, INCIDENT_REPO, "--fail-on", "never", token=True)[0], 0)
        self.assertEqual(audit_command(ADMIN, INCIDENT_REPO, "--fail-on", "high", token=True)[0], 1)
        # GitHub's own answers for the first adopter, and one job that is not among its required checks.
        names = RecordedFromGitHubRulesTest.CHECKS + ("package",)
        with TempDir() as tmp:
            root = tree(tmp, {"ci.yml": workflow("  pull_request:\n", "".join(job(n) for n in names))})
            run = lambda *args: audit_command(recording("live-expectrail-no-token"), root, *args,  # noqa: E731
                                              repository="Expectrail/Expectrail")
            code, out, _ = run()
            self.assertEqual(code, 1)
            self.assertIn("FINDINGS: 1 (0 high, 1 medium, 0 low)", out)
            self.assertEqual(run("--fail-on", "high")[0], 0)  # a medium finding is below it
            self.assertEqual(run("--fail-on", "low")[0], 1)

    def test_fails_at_each_severity(self):
        low = {"results": [{"state": "finding", "severity": "low"}, {"state": "cannot-tell", "severity": None}]}
        self.assertEqual([rules.fails(low, level) for level in ("high", "medium", "low", "never")],
                         [False, False, True, False])
        self.assertFalse(rules.fails({"results": [{"state": "cannot-tell", "severity": None}]}, "low"))

    def test_cannot_tell_fails_only_when_asked_and_is_said_first(self):
        code, out, err = audit_command(recording("public-no-token"), INCIDENT_REPO, "--fail-on", "never")
        self.assertEqual(code, 0)
        self.assertIn('"Cannot tell" is never a pass', out)
        self.assertIn("CANNOT TELL: 10, from 9 of 15 rules.", out)
        self.assertIn("CANNOT TELL: 10. A setting or a file the rule needs was not read", out)
        code, _, err = audit_command(recording("public-no-token"), INCIDENT_REPO, "--fail-on", "never",
                                     "--fail-on-cannot-tell")
        self.assertEqual(code, 1)
        self.assertIn("could not tell in 10 case(s)", err)

    def test_every_rule_has_a_line_and_fixes_can_be_left_out(self):
        _, out, _ = audit_command(ADMIN, INCIDENT_REPO, token=True)
        for rule in rules.RULES:
            self.assertEqual(sum(1 for line in out.splitlines() if line.startswith(f"  {rule.id}  ")),
                             2 if of(assess(ADMIN), rule.id) else 1, rule.id)
        self.assertIn("    Fix: ", out)
        self.assertNotIn("    Fix: ", audit_command(ADMIN, INCIDENT_REPO, "--no-fixes", token=True)[1])

    def test_json_holds_the_results_the_rules_and_the_snapshot(self):
        code, out, _ = audit_command(ADMIN, INCIDENT_REPO, "--format", "json", token=True)
        document = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(document["format"], "obaaf-settings-audit/v0.1")
        self.assertEqual(document["summary"]["findings"], 8)
        self.assertEqual(len(document["rules"]), len(rules.RULES))
        self.assertEqual({r["state"] for r in document["results"]}, {"finding", "cannot-tell"})
        self.assertEqual(snapshot_mod.problems(document["snapshot"]), [])
        self.assertEqual(document["workflows"]["read"], True)
        self.assertEqual(len(document["workflows"]["files"]), 5)
        self.assertNotIn(TOKEN, out)

    def test_settings_are_not_compared_with_the_workflows_of_whichever_clone_one_is_in(self):
        # This test runs in a clone of OBAAF, and the recording is of another repository.
        code, out, _ = audit_command(ADMIN, None, "--fail-on", "never", token=True)
        self.assertEqual(code, 0)
        self.assertIn("The workflow files were not read:", out)
        self.assertIn("name the directory that holds them", out)
        # The three rules that read settings only still answer; the twelve that compare cannot.
        self.assertIn("FINDINGS: 2 (1 high, 1 medium, 0 low). CANNOT TELL: 12, from 12 of 15 rules", out)
        self.assertIn("OBAAF-SET-004, OBAAF-SET-005 and OBAAF-SET-013 read settings only", out)
        self.assertEqual(audit_command(ADMIN, None, token=True)[0], 1)

    def test_a_directory_that_is_named_is_compared_and_the_report_says_whose_it_looks_like(self):
        with TempDir() as tmp:
            root = tree(tmp, {"ci.yml": workflow("  pull_request:\n", job("build"))})
            _, out, _ = audit_command(ADMIN, root, "--fail-on", "never", token=True)
            self.assertIn("is not the top level of a clone of this repository on github.com; its files are "
                          "compared because the directory was named", out)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "remote", "add", "origin", "https://github.com/Example-Studio/Game.git"],
                           check=True)
            _, out, _ = audit_command(ADMIN, root, "--fail-on", "never", token=True)
            self.assertNotIn("origin remote", out)
            usage = audit_cli.usage_for(str(root), "other/repo")
            self.assertIn("names Example-Studio/Game, not other/repo", usage["note"])
            self.assertTrue(audit_cli.usage_for(str(root), "new/name", also="example-studio/game").get("note") is None)

    def test_a_snapshot_can_be_compared_later_with_no_network(self):
        with TempDir() as tmp:
            snap, _ = take(ADMIN, token=TOKEN)
            snapshot_mod.write(snap, tmp / "s.json")
            with clean_env():
                code, out, _ = run_cli("audit", INCIDENT_REPO, "--from-snapshot", tmp / "s.json", "--fail-on", "high")
        self.assertEqual(code, 1)
        self.assertIn("FINDINGS: 8", out)
        self.assertIn("Nothing was asked of GitHub now.", out)

    def test_a_directory_with_no_workflows_says_so(self):
        with TempDir() as tmp:
            _, out, _ = audit_command(ADMIN, tmp, token=True)
        self.assertIn("there is no .github/workflows directory there", out)


class WorkflowUsageTest(unittest.TestCase):
    def test_what_is_read_from_the_incident_repository(self):
        usage = workflows.read(INCIDENT_REPO)
        self.assertEqual([f["path"] for f in usage["files"]], [f".github/workflows/{n}.yml" for n in (
            "agent", "ci", "publish", "release", "scan")])
        self.assertEqual(usage["config"], {"path": ".github/obaaf.yml", "protected_secrets": {
            "*_API_KEY": "main-only", "HELDOUT_TOKEN": "main-only"}})
        jobs = {f"{f['path'].rsplit('/', 1)[1]}#{j['id']}": j for f in usage["files"] for j in f["jobs"]}
        self.assertEqual(jobs["agent.yml#agent"]["environment"], {"name": "main-only"})
        self.assertEqual(jobs["agent.yml#agent"]["secrets"], ["MODEL_API_KEY"])
        self.assertEqual(jobs["ci.yml#test"]["check"], {"kind": "matrix", "name": "test", "matrix": True,
                                                        "names": ["test (3.13)"]})
        self.assertEqual(jobs["release.yml#publish"]["check"]["names"], ["publish / upload"])
        self.assertEqual(jobs["publish.yml#upload"]["called_from"], ["push"])
        self.assertEqual(jobs["release.yml#publish"]["passes"], {"inherit": False, "names": ["PACKAGE_INDEX_TOKEN"],
                                                                 "all": False})
        self.assertEqual(jobs["scan.yml#scan"]["triggers"], ["pull_request_target", "workflow_run"])

    def test_a_configuration_that_cannot_be_read_is_said_and_protects_nothing_silently(self):
        with TempDir() as tmp:
            usage = workflows.read(tree(tmp, {"ci.yml": workflow("  push:\n", job("a"))}, config="protected-secrets: [X]\n"))
        self.assertIsNone(usage["config"])
        self.assertIn("unknown setting", usage["config_error"])

    def test_a_file_that_is_too_large_or_not_text_is_recorded_as_not_read(self):
        with TempDir() as tmp:
            root = tree(tmp, {"ci.yml": workflow("  push:\n", job("a")), "big.yml": "#" * (workflows.MAX_WORKFLOW_BYTES + 1)})
            (root / ".github" / "workflows" / "bin.yml").write_bytes(b"\xff\xfe\x00")
            errors = {f["path"]: f["error"] for f in workflows.read(root)["files"]}
        self.assertIsNone(errors[".github/workflows/ci.yml"])
        self.assertIn("larger than 2 MB", errors[".github/workflows/big.yml"])
        self.assertIn("not UTF-8", errors[".github/workflows/bin.yml"])


class DocumentedTest(unittest.TestCase):
    def test_the_guide_lists_every_rule_with_its_title_and_severity(self):
        guide = (ROOT / "docs" / "settings-audit.md").read_text(encoding="utf-8")
        for rule in rules.RULES:
            self.assertIn(f"| `{rule.id}` | {rule.title} | {rule.severity} |", guide, rule.id)

    def test_the_guides_table_row_is_the_rules_own_definition(self):
        guide = (ROOT / "docs" / "settings-audit.md").read_text(encoding="utf-8")
        for rule in rules.RULES:
            reads = ", ".join(f"`{key}`" for key in rule.reads)
            self.assertIn(f"| `{rule.id}` | {rule.title} | {rule.severity} | {reads} | {rule.compares} |", guide,
                          rule.id)


class SecondReviewTest(unittest.TestCase):
    """What the second review (2026-11-13, run redshank) found: each case gave "no finding" or "does not
    apply" where the truth was a finding or "cannot tell"."""

    def require(self, *checks):
        return RequiredCheckRulesTest.require(self, *checks)

    def test_a_branch_filter_that_names_the_branch_beside_a_pattern(self):
        for branches in ("[main, 'releases/**']", "[main, 'mai+n']"):
            files = {"ci.yml": workflow(f"  pull_request:\n    branches: {branches}\n", job("lint"))}
            finding, = of(assess_files(self.require(("test (3.13)", 15368)), files), "OBAAF-SET-008", "finding")
            self.assertIn("ci.yml#lint", finding["subject"], branches)

    def test_a_branch_filter_decided_by_a_pattern_is_cannot_tell(self):
        for trigger in ("    branches: ['**']\n", "    branches-ignore: ['dependabot/**']\n",
                        "    branches: ['mai+n']\n", "    branches: [main, '!main']\n"):
            files = {"ci.yml": workflow("  pull_request:\n" + trigger, job("lint"))}
            found = assess_files(self.require(("test (3.13)", 15368)), files)
            self.assertEqual(status(found, "OBAAF-SET-008"), "cannot-tell", trigger)

    def test_a_branch_named_plainly_in_branches_ignore_shuts_it_out(self):
        files = {"ci.yml": workflow("  pull_request:\n    branches-ignore: [main, 'wip/**']\n", job("lint"))}
        found = assess_files(self.require(("test (3.13)", 15368)), files)
        self.assertEqual(status(found, "OBAAF-SET-008"), "not-applicable")

    def test_one_of_a_called_workflows_checks_required_is_not_enough(self):
        files = {"ci.yml": workflow("  pull_request:\n", "  test:\n    uses: ./.github/workflows/r.yml\n"),
                 "r.yml": workflow("  workflow_call:\n", job("unit") + job("lint"))}
        found = assess_files(self.require(("test / unit", 15368)), files)
        finding, = of(found, "OBAAF-SET-008", "finding")
        self.assertIn("reports 2 checks, of which 1 is not", finding["message"])
        self.assertIn("test / lint", finding["message"])
        found = assess_files(self.require(("test / unit", 15368), ("test / lint", 15368)), files)
        self.assertEqual(status(found, "OBAAF-SET-008"), "no-finding")

    def test_a_long_chain_of_reusable_workflows_still_carries_the_event(self):
        depth = 8
        files = {"a.yml": workflow("  pull_request_target:\n", "  c:\n    uses: ./.github/workflows/w7.yml\n")}
        for n in range(depth - 1, 0, -1):  # named so that each callee sorts before its caller
            files[f"w{n}.yml"] = workflow("  workflow_call:\n", f"  c:\n    uses: ./.github/workflows/w{n - 1}.yml\n")
        files["w0.yml"] = workflow("  workflow_call:\n", job("inner", "    environment: main-only\n",
                                                               FirstReviewTest.READS_KEY))
        finding, = of(assess_files(ADMIN, files), "OBAAF-SET-002", "finding")
        self.assertEqual(finding["subject"], "job .github/workflows/w0.yml#inner")

    def test_a_cycle_of_reusable_workflows_ends_and_leaves_the_names_unknown(self):
        files = {"a.yml": workflow("  pull_request:\n  workflow_call:\n", "  c:\n    uses: ./.github/workflows/b.yml\n"),
                 "b.yml": workflow("  workflow_call:\n", "  c:\n    uses: ./.github/workflows/a.yml\n")}
        found = assess_files(self.require(("c / c", 15368)), files)
        self.assertEqual(status(found, "OBAAF-SET-008"), "cannot-tell")

    def test_a_job_that_is_not_a_mapping_makes_github_refuse_the_file(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("test") + "  broken: oops\n")}
        found = assess_files(self.require(("test", 15368)), files)
        for rule in ("OBAAF-SET-006", "OBAAF-SET-007", "OBAAF-SET-008"):
            self.assertEqual(status(found, rule), "cannot-tell", rule)

    # -- the third pass
    def test_other_files_github_refuses(self):
        for name, text in (
                ("both branch filters", workflow("  pull_request:\n    branches: [main]\n    branches-ignore: [wip]\n",
                                                 job("test"))),
                ("both path filters", workflow("  pull_request:\n    paths: [src]\n    paths-ignore: [docs]\n",
                                               job("test"))),
                ("no runs-on", workflow("  pull_request:\n", "  test:\n    steps:\n      - run: make\n")),
                ("runs_on misspelt", workflow("  pull_request:\n", "  test:\n    runs_on: ubuntu-latest\n"
                                                                    "    steps:\n      - run: make\n"))):
            found = assess_files(self.require(("test", 15368)), {"ci.yml": text})
            for rule in ("OBAAF-SET-006", "OBAAF-SET-007", "OBAAF-SET-008"):
                self.assertEqual(status(found, rule), "cannot-tell", (name, rule))
        usage = workflows._file(".github/workflows/ci.yml", workflow("  pull_request:\n", "  test:\n    steps: []\n"))
        self.assertIn("'test' has neither runs-on nor uses, and GitHub refuses such a file", usage["error"])

    def test_a_negated_entry_in_branches_ignore_is_left_to_the_patterns(self):
        files = {"ci.yml": workflow("  pull_request:\n    branches-ignore: [main, '!main']\n", job("lint"))}
        found = assess_files(self.require(("test (3.13)", 15368)), files)
        self.assertEqual(status(found, "OBAAF-SET-008"), "cannot-tell")

    def test_a_requirement_tied_to_another_app_is_not_met_by_the_actions_job(self):
        files = {"ci.yml": workflow("  pull_request:\n", job("test"))}
        finding, = of(assess_files(self.require(("test", 99)), files), "OBAAF-SET-008", "finding")
        self.assertIn("ci.yml#test", finding["subject"])
        self.assertEqual(status(assess_files(self.require(("test", 15368)), files), "OBAAF-SET-008"), "no-finding")
        self.assertEqual(status(assess_files(self.require(("test", None)), files), "OBAAF-SET-008"), "no-finding")
        matrix = {"ci.yml": workflow("  pull_request:\n", job("t", "    strategy:\n      matrix:\n        v: [a, b]\n"))}
        found = assess_files(self.require(("t (a)", 99), ("t (b)", 99)), matrix)
        self.assertEqual(len(of(found, "OBAAF-SET-008", "finding")), 1)

    def test_any_self_hosted_job_shows_the_repository_has_a_runner_a_fork_can_name(self):
        files = {"ci.yml": workflow("  push:\n", "  build:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make\n")}
        finding, = of(assess_files(ADMIN, files), "OBAAF-SET-014", "finding")
        self.assertIn("so the repository has one", finding["message"])


if __name__ == "__main__":
    unittest.main()
