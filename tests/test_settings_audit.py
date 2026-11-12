"""The settings audit's reader (flagship slice 2b.1): what it asks GitHub for, how it records the answers,
and above all how it records what it could not read.

Three of the recordings under tests/fixtures/settings/ (public-no-token, workflow-token, admin-token) were
written by hand from the example responses in GitHub's REST reference (read 2026-11-12). They were not
recorded from a live repository. The two whose names begin with "live-" are GitHub's own answers to a run
with no token, as the workflow .github/workflows/settings-audit-live.yml printed them (RecordedFromGitHubTest
says which run). That workflow runs the same reader against GitHub itself whenever the reader changes.
"""

import copy
import http.server
import importlib.util
import json
import os
import ssl
import subprocess
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from helpers import FIXTURES, ROOT, TempDir, run_cli

from obaaf import audit
from obaaf.audit import cli as audit_cli, github, report, settings as settings_mod, snapshot as snapshot_mod

SETTINGS_DIR = FIXTURES / "settings"
REPO = "example-studio/game"
R = f"/repos/{REPO}"
NOW = datetime(2026, 11, 12, 1, 0, tzinfo=timezone.utc)
TOKEN = "ghx_NotARealTokenUsedOnlyInTests0123456789"
LIST = "?includes_parents=true&per_page=100"
PUBLIC_PATHS = [
    R,
    f"{R}/rulesets{LIST}",
    f"{R}/rulesets/42?includes_parents=true",
    f"{R}/rulesets/73?includes_parents=true",
    f"{R}/rules/branches/main?per_page=100",
    f"{R}/branches/main",
    f"{R}/environments?per_page=100",
    f"{R}/environments/release/deployment-branch-policies?per_page=100",
]
NEEDS_A_TOKEN = ["branch_protection", "environment_secrets", "repository_secrets", "organization_secrets",
                 "actions_permissions", "workflow_permissions", "fork_pull_requests", "actions_policies",
                 "collaborators"]


def recording(name: str) -> list[dict]:
    return json.loads((SETTINGS_DIR / name / "responses.json").read_text(encoding="utf-8"))["responses"]


def ok(path: str, body, headers=None) -> dict:
    return {"path": path, "status": 200, "headers": dict(headers or {}), "body": body}


def entry_for(entries: list[dict], path: str) -> dict:
    hits = [e for e in entries if e["path"] == path]
    assert len(hits) == 1, f"{path} is in the recording {len(hits)} times"
    return hits[0]


def replace(entries: list[dict], path: str, **changes) -> list[dict]:
    """A copy of a recording with the answer for one path changed."""
    out = copy.deepcopy(entries)
    entry_for(out, path).update(changes)
    return out


def take(entries: list[dict], token: str | None = None, repository: str = REPO, branches=()):
    transport = audit.ReplayTransport(copy.deepcopy(entries))
    client = audit.Client(transport=transport, token=token)
    snap = audit.take(client, repository, tuple(branches), now=NOW)
    assert snapshot_mod.problems(snap) == [], snapshot_mod.problems(snap)  # whatever happens, a valid snapshot
    return snap, transport


def statuses(snap: dict) -> dict[str, str]:
    return {key: entry["status"] for key, entry in snap["settings"].items()}


class clean_env:
    """The process environment without anything the audit reads from it, plus what a test sets."""

    def __init__(self, **values):
        self.values = values

    def __enter__(self):
        self._patch = mock.patch.dict(os.environ, self.values)
        self._patch.start()
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPOSITORY"):
            if name not in self.values:
                os.environ.pop(name, None)

    def __exit__(self, *exc):
        self._patch.stop()


def cli(entries: list[dict], *args: str, env: dict | None = None):
    """Run `obaaf audit` in-process against a recording. Returns (code, out, err, transport)."""
    transport = audit.ReplayTransport(copy.deepcopy(entries))
    with clean_env(**(env or {})), mock.patch.object(github, "UrllibTransport", return_value=transport):
        code, out, err = run_cli("audit", *args)
    return code, out, err, transport


class ReadWithoutATokenTest(unittest.TestCase):
    def setUp(self):
        self.snap, self.transport = take(recording("public-no-token"))

    def test_it_asks_only_for_what_github_shows_anyone_and_sends_no_credential(self):
        self.assertEqual([path for path, _ in self.transport.seen], PUBLIC_PATHS)
        self.assertEqual(self.transport.missing, [])
        for _, headers in self.transport.seen:
            self.assertNotIn("Authorization", headers)
            self.assertEqual(headers["X-GitHub-Api-Version"], github.API_VERSION)
            self.assertTrue(headers["User-Agent"].startswith("obaaf/"))

    def test_every_setting_is_in_the_snapshot_read_or_named_as_unread(self):
        got = statuses(self.snap)
        self.assertEqual(list(got), [s.key for s in audit.SETTINGS])
        for key in ("repository", "rulesets", "branch_rules", "branches", "environments"):
            self.assertEqual(got[key], "read", key)
        for key in NEEDS_A_TOKEN:
            entry = self.snap["settings"][key]
            self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "no_token"), key)
            self.assertEqual(entry["needs"], audit.BY_KEY[key].needs)

    def test_a_bypass_list_github_left_out_is_unread_not_empty(self):
        entry = self.snap["settings"]["ruleset_bypass_actors"]
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "withheld"))
        self.assertNotIn("value", entry)

    def test_what_was_read_is_recorded_without_the_noise(self):
        s = self.snap["settings"]
        self.assertEqual(s["repository"]["value"], {
            "full_name": REPO, "visibility": "public", "default_branch": "main", "owner": "example-studio",
            "owner_type": "Organization", "fork": False, "archived": False})
        first, second = s["rulesets"]["value"]
        self.assertEqual((first["id"], first["enforcement"], first["target"]), (42, "active", "branch"))
        self.assertEqual([r["type"] for r in first["rules"]],
                         ["deletion", "non_fast_forward", "pull_request", "required_status_checks"])
        self.assertEqual(first["rules"][2]["parameters"]["required_approving_review_count"], 1)
        self.assertEqual((second["source_type"], second["enforcement"]), ("Organization", "evaluate"))
        self.assertNotIn("node_id", json.dumps(self.snap))
        self.assertNotIn("avatar_url", json.dumps(self.snap))
        main_only, release = s["environments"]["value"]
        # Any branch may deploy: the first of the adopter's incidents.
        self.assertEqual(main_only, {"name": "main-only", "deployment_branches": "any", "wait_timer": 0,
                                     "reviewers": [], "prevent_self_review": None, "other_protection_rules": []})
        self.assertEqual(release, {
            "name": "release", "deployment_branches": "selected",
            "branch_policies": [{"name": "main", "type": "branch"}, {"name": "release/*", "type": None}],
            "wait_timer": 30, "prevent_self_review": False, "other_protection_rules": [],
            "reviewers": [{"type": "Team", "name": "justice-league", "id": 1},
                          {"type": "User", "name": "octocat", "id": 1}]})
        self.assertEqual(s["branches"]["value"]["main"], {"protected": True, "public_protection": {
            "enabled": True, "required_status_checks": {
                "strict": None, "enforcement_level": "non_admins", "contexts": ["test (3.13)"],
                "checks": [{"context": "test (3.13)", "app_id": 15368}]}}})
        self.assertEqual(self.snap["viewer"], {"authenticated": False})
        self.assertEqual(self.snap["requests"], [{"path": p, "status": 200} for p in PUBLIC_PATHS])

    def test_the_report_names_every_unread_setting_before_anything_it_read(self):
        text = report.to_text(self.snap)
        self.assertLess(text.index("NOT READ: 10 of 15"), text.index("READ: 5 of 15"))
        for key in NEEDS_A_TOKEN + ["ruleset_bypass_actors"]:
            self.assertIn(audit.BY_KEY[key].title, text)
        self.assertIn("It does not judge them yet", text)
        self.assertIn('"main-only": any branch or tag may deploy', text)
        self.assertIn("8 requests sent, all GET", text)


class RecordedFromGitHubTest(unittest.TestCase):
    """GitHub's own answers, not hand-written ones: what api.github.com sent a caller with no token on
    2026-11-12, as this repository's live workflow printed it. Both repositories are public, and so is
    everything in the answers.

    - live-obaaf-no-token: this repository at 06:32 UTC,
      https://github.com/Obaaf/OBAAF/actions/runs/43168837657
    - live-expectrail-no-token: the first adopter's at 01:33 UTC,
      https://github.com/Obaaf/OBAAF/actions/runs/43135263367

    Only what anyone may read is covered. No answer to an administrator's token has been recorded yet."""

    def take(self, name: str, repository: str):
        entries = recording(name)
        snap, transport = take(entries, repository=repository)
        self.assertEqual(transport.missing, [])
        # The reader asks today for exactly what it asked for on the day, in the same order.
        self.assertEqual([path for path, _ in transport.seen], [e["path"] for e in entries])
        return snap, report.to_text(snap)

    def test_this_repository_as_anyone_sees_it(self):
        snap, text = self.take("live-obaaf-no-token", "Obaaf/OBAAF")
        s = snap["settings"]
        self.assertEqual({k: v for k, v in statuses(snap).items() if v != "unread"}, {
            "repository": "read", "rulesets": "read", "ruleset_bypass_actors": "not_applicable",
            "branch_rules": "read", "branches": "read", "environments": "read"})
        self.assertEqual({s[k]["reason_code"] for k in NEEDS_A_TOKEN}, {"no_token"})
        self.assertEqual(s["repository"]["value"], {
            "full_name": "Obaaf/OBAAF", "visibility": "public", "default_branch": "main", "owner": "Obaaf",
            "owner_type": "Organization", "fork": False, "archived": False})
        self.assertEqual(s["rulesets"]["value"], [])
        self.assertEqual(s["branch_rules"]["value"], {"main": []})
        # Classic branch protection's required checks are shown to anyone.
        main = s["branches"]["value"]["main"]
        self.assertTrue(main["protected"])
        self.assertEqual(len(main["public_protection"]["required_status_checks"]["contexts"]), 8)
        pages, pypi = s["environments"]["value"]
        self.assertEqual(pages, {
            "name": "github-pages", "deployment_branches": "selected", "wait_timer": 0, "reviewers": [],
            "prevent_self_review": None, "other_protection_rules": [], "can_admins_bypass": True,
            "branch_policies": [{"name": "main", "type": "branch"}]})
        self.assertEqual([r["name"] for r in pypi.pop("reviewers")], ["FehintolaObafemi", "Ofonna-N", "seanudeke"])
        self.assertEqual(pypi, {
            "name": "pypi", "deployment_branches": "selected", "wait_timer": 0, "prevent_self_review": True,
            "other_protection_rules": [], "can_admins_bypass": False,
            "branch_policies": [{"name": "v*", "type": "tag"}]})
        # A pattern is said to be for tags or for branches: "v*" means different things as each.
        self.assertIn('"pypi": may deploy: tag v*; reviewers: FehintolaObafemi, Ofonna-N, seanudeke '
                      "(self-review prevented); administrators may bypass these rules: no\n", text)
        # Nothing for an administrator to bypass, so nothing is said about it.
        self.assertIn('"github-pages": may deploy: branch main; no required reviewers\n', text)

    def test_a_repository_protected_by_a_ruleset_as_anyone_sees_it(self):
        snap, text = self.take("live-expectrail-no-token", "Expectrail/Expectrail")
        s = snap["settings"]
        (ruleset,) = s["rulesets"]["value"]
        self.assertEqual((ruleset["id"], ruleset["name"], ruleset["enforcement"], ruleset["target"]),
                         (26914817, "Protect main", "active", "branch"))
        self.assertEqual([r["type"] for r in ruleset["rules"]],
                         ["deletion", "non_fast_forward", "pull_request", "required_status_checks"])
        self.assertEqual(ruleset["rules"][2]["parameters"]["required_approving_review_count"], 0)
        # GitHub sent a caller with no token no bypass_actors field at all, not an empty list.
        bypass = s["ruleset_bypass_actors"]
        self.assertEqual((bypass["status"], bypass["reason_code"]), ("unread", "withheld"))
        self.assertNotIn("can_bypass_rulesets", snap["viewer"])
        self.assertEqual([r["ruleset_id"] for r in s["branch_rules"]["value"]["main"]], [26914817] * 4)
        # The branch has no classic protection, and GitHub still calls it protected.
        self.assertEqual(s["branches"]["value"]["main"], {"protected": True, "public_protection": {
            "enabled": False, "required_status_checks": {"strict": None, "enforcement_level": "off",
                                                         "contexts": [], "checks": []}}})
        self.assertIn("main: GitHub calls it protected; no required checks shown in this view", text)
        self.assertIn('"unity": any branch or tag may deploy; reviewers: seanudeke (self-review allowed); '
                      "administrators may bypass these rules: yes\n", text)
        self.assertIn('"main-only": may deploy: branch main; no required reviewers\n', text)

    def test_every_required_check_of_a_rule_is_named_in_the_report(self):
        # The first report from this recording cut the rule off after three names and part of a fourth.
        _, text = self.take("live-expectrail-no-token", "Expectrail/Expectrail")
        checks = ("required_status_checks (test, obaaf-audit, capture-smoke, web-capture, seeded-bugs, "
                  "agents-gate1, agents-harness-verify, feedback-offline, agents-sandbox, agents-bench-compare, "
                  "private-export-scan)")
        rules = f"deletion, non_fast_forward, pull_request (0 approvals), {checks}"
        self.assertIn(f'"Protect main" (active, branch, from Repository Expectrail/Expectrail): {rules}\n', text)
        self.assertIn(f"      main: {rules}\n", text)

    def test_more_checks_than_fit_on_a_line_are_counted_not_dropped_without_a_word(self):
        entries = recording("live-expectrail-no-token")
        for path in ("/repos/Expectrail/Expectrail/rulesets/26914817?includes_parents=true",
                     "/repos/Expectrail/Expectrail/rules/branches/main?per_page=100"):
            body = entry_for(entries, path)["body"]
            rule = next(r for r in (body["rules"] if isinstance(body, dict) else body)
                        if r["type"] == "required_status_checks")
            rule["parameters"]["required_status_checks"] = [{"context": f"check-{n:02}"} for n in range(35)]
        text = report.to_text(take(entries, repository="Expectrail/Expectrail")[0])
        self.assertEqual(text.count("check-29 and 5 more)"), 2)
        self.assertNotIn("check-30", text)


class ReadWithAnAdministratorsTokenTest(unittest.TestCase):
    def setUp(self):
        self.snap, self.transport = take(recording("admin-token"), token=TOKEN)

    def test_every_request_carries_the_token_and_nothing_else_is_asked(self):
        self.assertEqual(self.transport.missing, [])
        self.assertEqual(len(self.transport.seen), 20)
        for _, headers in self.transport.seen:
            self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")

    def test_the_token_is_in_neither_the_snapshot_nor_the_report(self):
        self.assertNotIn(TOKEN, json.dumps(self.snap))
        self.assertNotIn(TOKEN, report.to_text(self.snap))

    def test_what_an_administrator_can_see(self):
        got = statuses(self.snap)
        self.assertEqual({k for k, v in got.items() if v != "read"}, {"ruleset_bypass_actors"})
        s = self.snap["settings"]
        self.assertEqual(s["branch_protection"]["value"], {"main": {"exists": False}})
        self.assertEqual(s["environment_secrets"]["value"],
                         {"main-only": ["HELDOUT_TOKEN", "MODEL_API_KEY"], "release": ["PACKAGE_INDEX_TOKEN"]})
        # The same key as a repository secret reaches every job on every branch.
        self.assertEqual(s["repository_secrets"]["value"], ["MODEL_API_KEY"])
        self.assertEqual(s["organization_secrets"]["value"], [])
        self.assertEqual(s["actions_permissions"]["value"], {
            "enabled": True, "allowed_actions": "selected", "sha_pinning_required": True,
            "selected_actions": {"github_owned_allowed": True, "verified_allowed": False,
                                 "patterns_allowed": ["docker/*", "monalisa/octocat@*"]}})
        self.assertEqual(s["workflow_permissions"]["value"],
                         {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False})
        # A public repository: the private-repository part does not apply and is left out.
        self.assertEqual(s["fork_pull_requests"]["value"], {"approval_policy": "first_time_contributors"})
        policy, = s["actions_policies"]["value"]
        self.assertEqual(policy["rules"], [{"type": "restrict_action_events", "parameters": {
            "allowed_events": ["pull_request_target", "workflow_dispatch"]}}])
        self.assertEqual(policy["conditions"], {"workflow_path": {"exclude": [], "include": [".github/workflows/scan.yml"]}})
        # Counts only: the collaborator list is not kept.
        self.assertEqual(s["collaborators"]["value"], {"total": 1, "by_role": {
            "admin": 1, "maintain": 0, "write": 0, "triage": 0, "read": 0}})
        self.assertNotIn("shared-account", json.dumps(self.snap))
        self.assertEqual(self.snap["viewer"]["can_bypass_rulesets"],
                         [{"ruleset_id": 42, "can_bypass": "always"}, {"ruleset_id": 73, "can_bypass": "never"}])
        self.assertTrue(self.snap["viewer"]["repository_permissions"]["admin"])

    def test_a_bypass_list_with_entries_is_recorded_and_an_empty_one_is_not_taken_for_nobody(self):
        entry = self.snap["settings"]["ruleset_bypass_actors"]
        self.assertEqual(entry["status"], "partial")
        self.assertEqual(entry["value"], [{"ruleset_id": 42, "actors": [
            {"actor_type": "OrganizationAdmin", "actor_id": None, "bypass_mode": "always"},
            {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "pull_request"}]}])
        problem, = entry["problems"]
        self.assertEqual((problem["key"], problem["reason_code"]), ("73", "withheld"))
        text = report.to_text(self.snap)
        self.assertIn('ruleset 42 "main protection": OrganizationAdmin (always), RepositoryRole 5 (pull_request)', text)
        self.assertIn('NOT READ: ruleset 73 "organisation baseline"', text)
        self.assertIn("for .github/workflows/scan.yml: only these events may start a workflow: "
                      "pull_request_target, workflow_dispatch", text)


class BypassListTest(unittest.TestCase):
    """Nothing in an answer shows whether the caller would have been given the real bypass list, so an
    empty list is never recorded as "nobody may bypass", whoever asks."""

    def bypass(self, base, repo_list, org_list, token):
        entries = recording(base)
        for ruleset, value in ((42, repo_list), (73, org_list)):
            body = entry_for(entries, f"{R}/rulesets/{ruleset}?includes_parents=true")["body"]
            body.pop("bypass_actors", None)
            if value != "absent":
                body["bypass_actors"] = value
        return take(entries, token=token)[0]["settings"]

    def test_an_empty_list_is_not_nobody_even_from_an_administrator(self):
        for base, token in (("admin-token", TOKEN), ("workflow-token", TOKEN), ("public-no-token", None)):
            entry = self.bypass(base, [], [], token)["ruleset_bypass_actors"]
            self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "withheld"), base)
            self.assertNotIn("value", entry)

    def test_null_and_absent_are_left_out(self):
        for value in (None, "absent"):
            entry = self.bypass("admin-token", value, value, TOKEN)["ruleset_bypass_actors"]
            self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "withheld"))

    def test_a_list_that_is_not_a_list_makes_the_rulesets_unread(self):
        s = self.bypass("admin-token", "nobody", "absent", TOKEN)
        self.assertEqual(s["rulesets"]["reason_code"], "unexpected")
        self.assertEqual(s["ruleset_bypass_actors"]["reason_code"], "depends")

    def test_with_no_ruleset_there_is_nothing_to_bypass(self):
        entries = replace(recording("public-no-token"), f"{R}/rulesets{LIST}", body=[])
        entries = replace(entries, f"{R}/rules/branches/main?per_page=100", body=[])
        snap, transport = take(entries)
        self.assertEqual(snap["settings"]["rulesets"], {"status": "read", "value": []})
        self.assertEqual(snap["settings"]["ruleset_bypass_actors"]["status"], "not_applicable")
        self.assertNotIn(f"{R}/rulesets/42?includes_parents=true", [p for p, _ in transport.seen])

    def test_a_rule_in_force_from_a_ruleset_the_list_did_not_name_means_the_list_was_not_whole(self):
        entries = replace(recording("public-no-token"), f"{R}/rulesets{LIST}", body=[])
        s = take(entries)[0]["settings"]
        self.assertEqual(s["rulesets"]["status"], "partial")
        self.assertEqual([(p["key"], p["reason_code"]) for p in s["rulesets"]["problems"]], [("42", "unexpected")])
        self.assertEqual((s["ruleset_bypass_actors"]["status"], s["ruleset_bypass_actors"]["reason_code"]),
                         ("unread", "unexpected"))

    def test_a_list_that_names_a_ruleset_twice_or_answers_for_another_is_unread(self):
        listing = entry_for(recording("public-no-token"), f"{R}/rulesets{LIST}")["body"]
        twice = replace(recording("public-no-token"), f"{R}/rulesets{LIST}", body=listing + [listing[0]])
        self.assertEqual(take(twice)[0]["settings"]["rulesets"]["reason_code"], "unexpected")
        other = recording("public-no-token")
        entry_for(other, f"{R}/rulesets/42?includes_parents=true")["body"]["id"] = 73
        self.assertEqual(take(other)[0]["settings"]["rulesets"]["reason_code"], "unexpected")


class RefusedByGitHubTest(unittest.TestCase):
    def setUp(self):
        self.snap, self.transport = take(recording("workflow-token"), token=TOKEN)

    def test_a_refusal_is_unread_with_the_message_and_what_would_be_accepted(self):
        # The status, message and header values are those GitHub sent this repository's workflow token on
        # 2026-11-12 (the live workflow's first run); the recording itself is hand-written.
        self.assertEqual(self.transport.missing, [])
        s = self.snap["settings"]
        for key in ("branch_protection", "environment_secrets", "repository_secrets", "organization_secrets",
                    "actions_permissions", "workflow_permissions", "fork_pull_requests", "actions_policies"):
            self.assertEqual((s[key]["status"], s[key]["reason_code"]), ("unread", "forbidden"), key)
            self.assertIn("Resource not accessible by integration", s[key]["reason"])
        self.assertEqual(s["actions_permissions"]["accepted_permissions"], "administration=read")
        self.assertEqual(s["branch_protection"]["accepted_permissions"], "administration=read")
        self.assertEqual(s["environment_secrets"]["accepted_permissions"], "environments=read")
        self.assertEqual(s["actions_policies"]["accepted_permissions"], "administration=write")
        self.assertEqual(s["collaborators"]["value"]["by_role"]["admin"], 3)

    def test_a_404_on_branch_protection_is_no_protection_only_with_the_exact_message(self):
        path = f"{R}/branches/main/protection"
        for message, expected in (("Branch not protected", "read"), ("Not Found", "unread"),
                                  ("Branch not protected.", "unread"), ("branch not protected", "unread")):
            entries = replace(recording("admin-token"), path, body={"message": message})
            entry = take(entries, token=TOKEN)[0]["settings"]["branch_protection"]
            self.assertEqual(entry["status"], expected, message)
        entries = replace(recording("admin-token"), path, status=403, body={"message": "Branch not protected"})
        self.assertEqual(take(entries, token=TOKEN)[0]["settings"]["branch_protection"]["status"], "unread")

    def classic(self, body):
        entries = replace(recording("admin-token"), f"{R}/branches/main/protection", status=200, body=body)
        snap, _ = take(entries, token=TOKEN)
        return snap["settings"]["branch_protection"], report.to_text(snap)

    def test_classic_branch_protection_is_recorded_when_there_is_one(self):
        entry, text = self.classic({
            "url": "https://api.github.com/repos/example-studio/game/branches/main/protection",
            "required_status_checks": {"contexts": ["ci"], "strict": True, "enforcement_level": "non_admins"},
            "enforce_admins": {"url": "x", "enabled": False},
            "required_pull_request_reviews": {
                "required_approving_review_count": 2, "dismiss_stale_reviews": True,
                "require_code_owner_reviews": True, "require_last_push_approval": False,
                "bypass_pull_request_allowances": {"users": [{"login": "octocat", "id": 1}], "teams": [],
                                                   "apps": [{"slug": "octoapp", "id": 1}]}},
            "allow_force_pushes": {"enabled": False}, "lock_branch": {"enabled": False}})
        value = entry["value"]["main"]
        self.assertEqual(value["required_pull_request_reviews"], {
            "required": True, "required_approving_review_count": 2, "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True, "require_last_push_approval": False,
            "bypass_allowances": {"users": ["octocat"], "teams": [], "apps": ["octoapp"]}})
        self.assertEqual(value["required_status_checks"], {
            "required": True, "strict": True, "enforcement_level": "non_admins", "contexts": ["ci"], "checks": None})
        self.assertEqual(value["restrictions"], {"restricted": False})
        self.assertIs(value["enforce_admins"], False)
        self.assertIsNone(value["required_signatures"])  # not in the answer, so not known
        self.assertIn("main: 2 approvals required; required checks: ci; administrators are not held to it", text)

    def test_sections_github_leaves_out_are_recorded_as_not_required_and_unknowns_as_null(self):
        entry, text = self.classic({"enforce_admins": {"enabled": True},
                                    "required_pull_request_reviews": {"dismiss_stale_reviews": False}})
        value = entry["value"]["main"]
        self.assertEqual(value["required_status_checks"], {"required": False})
        self.assertIsNone(value["required_pull_request_reviews"]["required_approving_review_count"])
        self.assertIsNone(value["required_pull_request_reviews"]["bypass_allowances"])  # not "nobody"
        self.assertIn("main: review required (the number of approvals was not given); no required checks; "
                      "administrators are held to it", text)

    def test_an_object_that_is_not_recognisably_a_protection_is_unread(self):
        for body in ({}, {"restrictions": {}}, {"enforce_admins": True}, {"enforce_admins": {"enabled": "yes"}},
                     {"enforce_admins": {"enabled": True}, "required_status_checks": {}},
                     {"enforce_admins": {"enabled": True}, "restrictions": {"users": "all"}}, []):
            entry, _ = self.classic(body)
            self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "unexpected"), body)

    def test_a_rejected_token_reads_nothing_and_says_so(self):
        entries = [{"path": R, "status": 401, "headers": {}, "body": {"message": "Bad credentials"}}]
        snap, transport = take(entries, token=TOKEN)
        self.assertEqual(len(transport.seen), 1)
        self.assertEqual(snap["settings"]["repository"]["reason_code"], "unauthorized")
        self.assertEqual({e["reason_code"] for k, e in snap["settings"].items() if k != "repository"}, {"depends"})

    def test_a_repository_that_cannot_be_seen_reads_nothing(self):
        entries = [{"path": R, "status": 404, "headers": {}, "body": {"message": "Not Found"}}]
        snap, _ = take(entries)
        self.assertEqual(snap["settings"]["repository"]["reason_code"], "not_found")
        self.assertEqual(set(statuses(snap).values()), {"unread"})


class RateLimitTest(unittest.TestCase):
    LIMITED = {"status": 403, "headers": {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1794448800"},
               "body": {"message": "API rate limit exceeded for 203.0.113.7."}}

    def test_at_the_first_request_nothing_is_read_and_nothing_more_is_asked(self):
        snap, transport = take([{"path": R, **self.LIMITED}])
        self.assertEqual(len(transport.seen), 1)
        entry = snap["settings"]["repository"]
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "rate_limited"))
        self.assertIn("60 requests an hour", entry["reason"])
        self.assertIn("resets at", entry["reason"])

    def test_midway_everything_after_it_is_unread_and_no_further_request_is_sent(self):
        entries = replace(recording("admin-token"), f"{R}/branches/main", **self.LIMITED)
        snap, transport = take(entries, token=TOKEN)
        paths = [p for p, _ in transport.seen]
        self.assertEqual(paths[-1], f"{R}/branches/main")
        self.assertEqual(len(paths), 6)
        got = statuses(snap)
        self.assertEqual([k for k, v in got.items() if v == "read"], ["repository", "rulesets", "branch_rules"])
        for key in ("branches", "branch_protection", "environments", "repository_secrets", "actions_policies"):
            self.assertEqual(snap["settings"][key]["reason_code"], "rate_limited", key)
        self.assertEqual(snap["settings"]["environment_secrets"]["reason_code"], "depends")

    def test_each_sign_of_a_rate_limit_is_enough_on_its_own(self):
        for status, headers, message in ((403, {"x-ratelimit-remaining": "0"}, "Forbidden"),
                                         (403, {"retry-after": "60"}, "slow down"),
                                         (403, {}, "You have exceeded a secondary rate limit."),
                                         (429, {}, "Too many"), (429, {"retry-after": "²"}, "x")):
            snap, transport = take([{"path": R, "status": status, "headers": headers, "body": {"message": message}}])
            self.assertEqual(snap["settings"]["repository"]["reason_code"], "rate_limited", (status, headers))
            self.assertEqual(len(transport.seen), 1)

    def test_a_plain_refusal_is_not_taken_for_a_rate_limit(self):
        snap, _ = take([{"path": R, "status": 403, "headers": {"x-ratelimit-remaining": "57"},
                         "body": {"message": "Resource not accessible by integration"}}])
        self.assertEqual(snap["settings"]["repository"]["reason_code"], "forbidden")


class ShapeTest(unittest.TestCase):
    """An answer that is not what GitHub documents is unread, never guessed at and never a crash."""

    def unread(self, entries, key, token=None):
        entry = take(entries, token=token)[0]["settings"][key]
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "unexpected"), entry)
        return entry

    def environments(self, change):
        entries = recording("public-no-token")
        change(entry_for(entries, f"{R}/environments?per_page=100")["body"]["environments"])
        return entries

    def test_a_field_whose_absence_could_pass_for_none_must_be_there(self):
        cases = {
            "no branch policy field": lambda envs: envs[0].pop("deployment_branch_policy"),
            "no protection rules": lambda envs: envs[1].pop("protection_rules"),
            "no reviewers in a reviewers rule": lambda envs: envs[1]["protection_rules"][1].pop("reviewers"),
            "neither kind of branch policy": lambda envs: envs[1].update(
                deployment_branch_policy={"protected_branches": False, "custom_branch_policies": False}),
            "both kinds of branch policy": lambda envs: envs[1].update(
                deployment_branch_policy={"protected_branches": True, "custom_branch_policies": True}),
            "the same environment twice": lambda envs: envs.append(copy.deepcopy(envs[0])),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.unread(self.environments(change), "environments")
        entries = recording("public-no-token")
        del entry_for(entries, f"{R}/rulesets/42?includes_parents=true")["body"]["rules"]
        self.unread(entries, "rulesets")
        entries = recording("public-no-token")
        del entry_for(entries, f"{R}/branches/main")["body"]["protection"]["required_status_checks"]["contexts"]
        self.unread(entries, "branches")
        for body in ({}, {"github_owned_allowed": True, "verified_allowed": True},
                     {"github_owned_allowed": True, "verified_allowed": True, "patterns_allowed": [1]}):
            entries = replace(recording("admin-token"), f"{R}/actions/permissions/selected-actions", body=body)
            self.unread(entries, "actions_permissions", token=TOKEN)

    def test_wrong_types_are_unread(self):
        for key, path, body in [
            ("rulesets", f"{R}/rulesets{LIST}", {"message": "hello"}),
            ("rulesets", f"{R}/rulesets{LIST}", [{"id": "42"}]),
            ("rulesets", f"{R}/rulesets{LIST}", [{"id": True}]),
            ("rulesets", f"{R}/rulesets{LIST}", [{"id": 2 ** 70}]),
            ("rulesets", f"{R}/rulesets{LIST}", None),
            ("branch_rules", f"{R}/rules/branches/main?per_page=100", [{"type": 7}]),
            ("branches", f"{R}/branches/main", {"name": "main", "protected": "yes"}),
            ("environments", f"{R}/environments?per_page=100", {"total_count": 1, "environments": "none"}),
            ("environments", f"{R}/environments?per_page=100", {"total_count": 1, "environments": [{"name": 3}]}),
            ("environments", f"{R}/environments?per_page=100", {"environments": []}),
            ("environments", f"{R}/environments?per_page=100", {"total_count": True, "environments": []}),
            ("environments", f"{R}/environments?per_page=100", {"total_count": "0", "environments": []}),
        ]:
            with self.subTest(path=path, body=body):
                self.unread(replace(recording("public-no-token"), path, body=body), key)
        for key, path, body in [
            ("collaborators", f"{R}/collaborators?affiliation=all&per_page=100", [{"login": "x"}]),
            ("collaborators", f"{R}/collaborators?affiliation=all&per_page=100", [{"login": "x", "permissions": {}}]),
            ("repository_secrets", f"{R}/actions/secrets?per_page=100", {"total_count": 1, "secrets": [{}]}),
            ("actions_permissions", f"{R}/actions/permissions", {"enabled": "true"}),
            ("workflow_permissions", f"{R}/actions/permissions/workflow", {"default_workflow_permissions": "read"}),
            ("fork_pull_requests", f"{R}/actions/permissions/fork-pr-contributor-approval", {}),
            ("actions_policies", f"{R}/actions/policies?has_parents=true&per_page=100",
             {"total_count": 1, "policies": [{"id": 0}]}),
        ]:
            with self.subTest(path=path, body=body):
                self.unread(replace(recording("admin-token"), path, body=body), key, token=TOKEN)

    def test_one_part_of_the_wrong_shape_does_not_hide_the_rest(self):
        entries = replace(recording("public-no-token"), f"{R}/rulesets/42?includes_parents=true", body=[])
        s = take(entries)[0]["settings"]
        self.assertEqual(s["rulesets"]["reason_code"], "unexpected")
        self.assertEqual(s["environments"]["status"], "read")
        entries = replace(recording("public-no-token"),
                          f"{R}/environments/release/deployment-branch-policies?per_page=100", body=[])
        entry = take(entries)[0]["settings"]["environments"]
        self.assertEqual(entry["status"], "partial")
        self.assertEqual((entry["problems"][0]["key"], entry["problems"][0]["reason_code"]), ("release", "unexpected"))

    def test_a_repository_answer_that_cannot_be_used_reads_nothing(self):
        for change in (lambda b: b.update(full_name="example-studio/game/../../../orgs/evil"),
                       lambda b: b.update(full_name="example-studio/game\n"), lambda b: b.pop("owner"),
                       lambda b: b.update(default_branch="\ud800"), lambda b: b.update(private="no")):
            entries = recording("public-no-token")
            change(entries[0]["body"])
            snap, transport = take(entries)
            self.assertEqual(snap["settings"]["repository"]["reason_code"], "unexpected")
            self.assertEqual(len(transport.seen), 1)
            self.assertEqual({e["reason_code"] for k, e in snap["settings"].items() if k != "repository"}, {"depends"})

    def test_text_that_is_not_valid_unicode_is_unread_not_a_crash(self):
        entries = recording("public-no-token")
        entry_for(entries, f"{R}/environments?per_page=100")["body"]["environments"][0]["name"] = "prod\ud800"
        self.unread(entries, "environments")
        entries = recording("public-no-token")
        entry_for(entries, f"{R}/rulesets/42?includes_parents=true")["body"]["name"] = "main \ud83d"
        snap, _ = take(entries)
        self.assertEqual(snap["settings"]["rulesets"]["reason_code"], "unexpected")
        report.to_text(snap).encode("utf-8")

    def test_numbers_that_are_not_json_are_refused(self):
        raw = b'[{"id": 42, "name": "x", "weight": NaN}]'
        answer = audit.Client(transport=type("T", (), {"get": lambda self, u, h: github.Raw(200, {}, raw)})()).get(R)
        self.assertEqual(answer.code, "unexpected")
        with self.assertRaises(settings_mod.Shape):
            settings_mod._json_safe({"a": float("inf")}, "x")

    def test_an_answer_that_is_empty_not_json_too_deep_or_too_large_is_unread(self):
        for body in ("<html>proxy login</html>", "", "[" * 100000):
            entries = replace(recording("public-no-token"), f"{R}/branches/main", body=body)
            self.unread(entries, "branches")

        class Huge:
            def get(self, url, headers):
                return github.Raw(200, {}, b"[" + b" " * (github.MAX_BODY_BYTES + 1))
        answer = audit.Client(transport=Huge()).get(R)
        self.assertEqual(answer.code, "unexpected")
        self.assertIn("5 MB", answer.why)

    def test_an_unforeseen_error_in_one_reader_is_unread_for_that_setting(self):
        entries = recording("public-no-token")
        with mock.patch.object(settings_mod, "_environment", side_effect=KeyError("boom")):
            s = take(entries)[0]["settings"]
        self.assertEqual((s["environments"]["status"], s["environments"]["reason_code"]), ("unread", "unexpected"))
        self.assertEqual(s["branches"]["status"], "read")

    def test_an_unknown_rule_type_is_kept_as_it_came(self):
        entries = recording("public-no-token")
        rules = entry_for(entries, f"{R}/rulesets/42?includes_parents=true")["body"]["rules"]
        rules.append({"type": "a_rule_from_next_year", "parameters": {"level": {"deep": [1, 2]}}})
        snap, _ = take(entries)
        self.assertEqual(snap["settings"]["rulesets"]["status"], "read")
        self.assertIn({"type": "a_rule_from_next_year", "parameters": {"level": {"deep": [1, 2]}}},
                      snap["settings"]["rulesets"]["value"][0]["rules"])

    def test_an_unknown_environment_rule_is_named_not_dropped(self):
        entries = self.environments(lambda envs: envs[0]["protection_rules"].append({"id": 9, "type": "something_new"}))
        snap, _ = take(entries)
        self.assertEqual(snap["settings"]["environments"]["value"][0]["other_protection_rules"], ["something_new"])


class PaginationTest(unittest.TestCase):
    """Pages are asked for by number; a list is whole only when a short page with no next link ends it."""

    PATH = f"{R}/collaborators?affiliation=all&per_page=100"

    def people(self, n):
        return [{"login": f"u{i}", "permissions": {"pull": True}} for i in range(n)]

    def collaborators(self, pages):
        entries = [e for e in recording("admin-token") if e["path"] != self.PATH]
        for number, page in enumerate(pages, 1):
            entries.append({"path": self.PATH + (f"&page={number}" if number > 1 else ""), "status": 200,
                            "headers": {}, "body": page, **(page if isinstance(page, dict) and "status" in page else {})})
        snap, transport = take(entries, token=TOKEN)
        return snap["settings"]["collaborators"], [p for p, _ in transport.seen if "collaborators" in p]

    def test_a_full_page_is_followed_by_the_next_whatever_the_headers_say(self):
        entry, asked = self.collaborators([self.people(100), self.people(50)])
        self.assertEqual(entry["value"]["total"], 150)
        self.assertEqual(len(asked), 2)
        entry, asked = self.collaborators([self.people(100), []])
        self.assertEqual(entry["value"]["total"], 100)

    def test_any_spelling_of_a_next_link_asks_for_the_next_page(self):
        for link in ('<https://api.github.com/x?page=2>; rel="next"', "<https://api.github.com/x?page=2>; rel=next",
                     '<https://api.github.com/x?page=2>; rel="next last"', '<https://api.github.com/x>; REL="Next"',
                     '<https://api.github.com/x>; title="t"; rel="next"',
                     '<https://api.github.com/a>; rel="prev", <https://api.github.com/b,c>; rel="next"',
                     '<https://evil.example/steal>; rel="next"'):
            entries = [e for e in recording("admin-token") if e["path"] != self.PATH]
            entries.append(ok(self.PATH, self.people(3), {"link": link}))
            entries.append(ok(self.PATH + "&page=2", self.people(2)))
            snap, transport = take(entries, token=TOKEN)
            self.assertEqual(snap["settings"]["collaborators"]["value"]["total"], 5, link)
            # The address in the header is never fetched; the next page is asked for by number.
            self.assertEqual(transport.missing, [], link)
            self.assertFalse([p for p, _ in transport.seen if "evil" in p or p.endswith("/x?page=2")])
        self.assertFalse(github._names_next_page('<https://api.github.com/x>; rel="prev"'))
        self.assertFalse(github._names_next_page(""))

    def test_a_later_page_that_fails_makes_the_whole_list_unread(self):
        entries = [e for e in recording("admin-token") if e["path"] != self.PATH]
        entries.append(ok(self.PATH, self.people(100)))
        entries.append({"path": self.PATH + "&page=2", "status": 502, "headers": {}, "body": "bad gateway"})
        entry = take(entries, token=TOKEN)[0]["settings"]["collaborators"]
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "server_error"))

    def test_a_list_longer_than_the_cap_or_one_that_never_ends_is_unread(self):
        entries = [e for e in recording("admin-token") if e["path"] != self.PATH]
        entries.append(ok(self.PATH, self.people(100)))
        entries += [ok(f"{self.PATH}&page={n}", self.people(100)) for n in range(2, github.MAX_PAGES + 2)]
        snap, transport = take(entries, token=TOKEN)
        entry = snap["settings"]["collaborators"]
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "unexpected"))
        self.assertEqual(len([p for p, _ in transport.seen if "collaborators" in p]), github.MAX_PAGES)
        entries = [e for e in recording("admin-token") if e["path"] != self.PATH]
        entries.append(ok(self.PATH, [], {"link": '<https://api.github.com/x>; rel="next"'}))
        entry = take(entries, token=TOKEN)[0]["settings"]["collaborators"]
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "unexpected"))

    def test_a_wrapped_list_must_say_how_many_and_agree(self):
        path = f"{R}/actions/secrets?per_page=100"
        first = ok(path, {"total_count": 3, "secrets": [{"name": "B"}, {"name": "A"}]},
                   {"link": f'<https://api.github.com{path}&page=2>; rel="next"'})
        second = ok(path + "&page=2", {"total_count": 3, "secrets": [{"name": "C"}]})
        entries = [e for e in recording("admin-token") if e["path"] != path]
        snap, transport = take(entries + [first, second], token=TOKEN)
        self.assertEqual(snap["settings"]["repository_secrets"]["value"], ["A", "B", "C"])
        self.assertEqual(transport.missing, [])
        for count, reason in ((4, "4 entries and returned 3"), (2, "2 entries and returned 3")):
            wrong = copy.deepcopy([first, second])
            wrong[0]["body"]["total_count"] = wrong[1]["body"]["total_count"] = count
            entry = take(entries + wrong, token=TOKEN)[0]["settings"]["repository_secrets"]
            self.assertEqual(entry["reason_code"], "unexpected")
            self.assertIn(reason, entry["reason"])
        changed = copy.deepcopy([first, second])
        changed[1]["body"]["total_count"] = 9
        entry = take(entries + changed, token=TOKEN)[0]["settings"]["repository_secrets"]
        self.assertIn("changed between pages", entry["reason"])


class PartsTest(unittest.TestCase):
    def test_one_ruleset_that_cannot_be_read_makes_the_setting_partial(self):
        entries = replace(recording("public-no-token"), f"{R}/rulesets/73?includes_parents=true", status=500,
                          body={"message": "Server Error"})
        snap, _ = take(entries)
        entry = snap["settings"]["rulesets"]
        self.assertEqual(entry["status"], "partial")
        self.assertEqual([r["id"] for r in entry["value"]], [42])
        self.assertEqual((entry["problems"][0]["key"], entry["problems"][0]["reason_code"]), ("73", "server_error"))
        self.assertIn("NOT READ: ruleset 73", report.to_text(snap))

    def test_branch_patterns_that_cannot_be_read_make_environments_partial(self):
        entries = replace(recording("public-no-token"),
                          f"{R}/environments/release/deployment-branch-policies?per_page=100", status=404,
                          body={"message": "Not Found"})
        snap, _ = take(entries)
        entry = snap["settings"]["environments"]
        self.assertEqual(entry["status"], "partial")
        self.assertIsNone(entry["value"][1]["branch_policies"])
        self.assertIn("the patterns were not read", report.to_text(snap))

    def test_selected_actions_that_cannot_be_read_make_the_permissions_partial(self):
        entries = replace(recording("admin-token"), f"{R}/actions/permissions/selected-actions", status=403,
                          body={"message": "no"})
        snap, _ = take(entries, token=TOKEN)
        entry = snap["settings"]["actions_permissions"]
        self.assertEqual(entry["status"], "partial")
        self.assertIsNone(entry["value"]["selected_actions"])
        self.assertEqual(entry["problems"][0]["key"], "selected_actions")
        self.assertIn("selected (the list was not read)", report.to_text(snap))

    def test_what_does_not_apply_is_left_out_of_a_value(self):
        entries = replace(recording("admin-token"), f"{R}/actions/permissions",
                          body={"enabled": True, "allowed_actions": "all"})
        value = take(entries, token=TOKEN)[0]["settings"]["actions_permissions"]["value"]
        self.assertEqual(value, {"enabled": True, "allowed_actions": "all", "sha_pinning_required": None})

    def test_a_private_repository_owned_by_a_user(self):
        entries = recording("admin-token")
        entries[0]["body"].update(private=True, visibility="private")
        entries[0]["body"]["owner"]["type"] = "User"
        entries.append(ok(f"{R}/actions/permissions/fork-pr-workflows-private-repos", {
            "run_workflows_from_fork_pull_requests": True, "send_write_tokens_to_workflows": False,
            "send_secrets_and_variables": True, "require_approval_for_fork_pr_workflows": True}))
        snap, transport = take(entries, token=TOKEN)
        self.assertEqual(snap["settings"]["organization_secrets"]["status"], "not_applicable")
        self.assertNotIn(f"{R}/actions/organization-secrets?per_page=100", [p for p, _ in transport.seen])
        self.assertTrue(snap["settings"]["fork_pull_requests"]["value"]["private_repository"]
                        ["send_secrets_and_variables"])
        self.assertIn("secrets: yes", report.to_text(snap))

    def test_only_a_user_owner_rules_out_organisation_secrets(self):
        for owner_type in ("Enterprise", "organization", ""):
            entries = recording("admin-token")
            entries[0]["body"]["owner"]["type"] = owner_type
            snap, _ = take(entries, token=TOKEN)
            self.assertEqual(snap["settings"]["organization_secrets"]["status"], "read", owner_type)

    def test_more_branches_can_be_audited_in_a_fixed_order_with_their_names_encoded(self):
        entries = recording("public-no-token")
        branch = entry_for(entries, f"{R}/branches/main")
        for name in ("release%2F1.0", "a%20b%3F", "%2E%2E"):
            entries.append({**copy.deepcopy(branch), "path": f"{R}/branches/{name}"})
            entries.append(ok(f"{R}/rules/branches/{name}?per_page=100", []))
        snap, transport = take(entries, branches=("release/1.0", "main"))
        self.assertEqual(transport.missing, [])
        self.assertEqual(snap["branches"], ["main", "release/1.0"])
        self.assertEqual(take(entries, branches=("main", "release/1.0"))[0]["settings"], snap["settings"])
        self.assertEqual(snap["settings"]["branch_rules"]["value"]["release/1.0"], [])
        self.assertIn("release/1.0: no active rule", report.to_text(snap))
        for bad in ("rel*", "a b", "", "-x", "a?b", "a\nb", "a‮b"):
            with self.assertRaises(ValueError):
                audit.take(audit.Client(transport=audit.ReplayTransport([])), REPO, (bad,))
        self.assertEqual(settings_mod._segment(".."), "%2E%2E")
        self.assertEqual(settings_mod._segment("."), "%2E")
        self.assertEqual(settings_mod._segment("a/b?c#d e"), "a%2Fb%3Fc%23d%20e")

    def test_an_environment_called_dot_dot_addresses_only_itself(self):
        entries = recording("admin-token")
        entry_for(entries, f"{R}/environments?per_page=100")["body"]["environments"][0]["name"] = ".."
        entries.append(ok(f"{R}/environments/%2E%2E/secrets?per_page=100", {"total_count": 0, "secrets": []}))
        snap, transport = take(entries, token=TOKEN)
        self.assertNotIn(f"{R}/environments/../secrets?per_page=100", [p for p, _ in transport.seen])
        self.assertEqual(snap["settings"]["environment_secrets"]["value"][".."], [])


class RedirectTest(unittest.TestCase):
    def test_a_moved_repository_is_followed_on_the_same_host_and_its_new_name_is_used(self):
        entries = recording("public-no-token")
        moved = {"path": "/repos/old-owner/game", "status": 301,
                 "headers": {"location": "https://api.github.com/repositories/1296269"}, "body": {"message": "Moved"}}
        entries[0]["path"] = "/repositories/1296269"
        snap, transport = take([moved] + entries, repository="old-owner/game")
        self.assertEqual(transport.missing, [])
        self.assertEqual((snap["repository"], snap["requested_as"]), (REPO, "old-owner/game"))
        self.assertEqual([p for p, _ in transport.seen][:3],
                         ["/repos/old-owner/game", "/repositories/1296269", f"{R}/rulesets{LIST}"])
        self.assertIn("Asked for as old-owner/game", report.to_text(snap))

    def test_a_redirect_anywhere_else_is_not_followed(self):
        for location in ("https://evil.example/repos/x/y", "//evil.example/x", "http://api.github.com/x",
                         "https://api.github.com:8443/x", "https://api.github.com:x/", "https://api.github.com@evil.example/",
                         "https://[::1/x", "https://api.github.com.evil.example/x"):
            away = {"path": R, "status": 302, "headers": {"location": location}, "body": None}
            snap, transport = take([away], token=TOKEN)
            self.assertEqual([p for p, _ in transport.seen], [R], location)
            self.assertEqual(snap["settings"]["repository"]["reason_code"], "unexpected", location)

    def test_redirects_do_not_go_round_for_ever(self):
        loop = {"path": R, "status": 307, "headers": {"location": f"https://api.github.com{R}"}, "body": None}
        snap, transport = take([loop])
        self.assertEqual(len(transport.seen), github.MAX_REDIRECTS + 1)
        self.assertEqual(snap["settings"]["repository"]["reason_code"], "unexpected")
        snap, transport = take([{"path": R, "status": 303, "headers": {"location": "/x"}, "body": None}])
        self.assertEqual(len(transport.seen), 1)


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the test output quiet
        pass

    def _answer(self):
        type(self).seen.append((self.command, self.path, dict(self.headers.items())))
        if self.path == "/away":
            self._send(302, b"", [("Location", f"http://localhost:{self.server.server_port}/elsewhere")])
        elif self.path == "/moved":
            self._send(301, b"", [("Location", "/here")])
        elif self.path == "/two-links":
            self._send(200, b"[1]", [("Link", '<http://x/a>; rel="prev"'), ("Link", '<http://x/b>; rel="next"')])
        elif self.path == "/broken":
            self.send_response(403)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b'5\r\n{"mes\r\nZZ\r\n')
            self.close_connection = True
        else:
            self._send(200, json.dumps({"path": self.path}).encode(), [("Content-Type", "application/json")])

    def _send(self, status, body, headers):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _answer


class RealTransportTest(unittest.TestCase):
    """The real HTTP client against a server on this machine: what actually goes over the wire."""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.api = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Handler.seen.clear()

    def test_it_sends_get_with_no_body_and_the_token_only_when_it_has_one(self):
        with_token = audit.Client(api=self.api, token=TOKEN)
        self.assertEqual(with_token.get("/here").data, {"path": "/here"})
        without = audit.Client(api=self.api)
        self.assertTrue(without.get("/here").ok)
        (m1, _, h1), (m2, _, h2) = _Handler.seen
        h1, h2 = ({k.lower(): v for k, v in h.items()} for h in (h1, h2))
        self.assertEqual((m1, m2), ("GET", "GET"))
        self.assertEqual(h1["authorization"], f"Bearer {TOKEN}")
        self.assertNotIn("authorization", h2)
        self.assertEqual(h1["x-github-api-version"], "2026-03-10")
        self.assertEqual(h1["accept"], "application/vnd.github+json")
        self.assertRegex(h1["user-agent"], r"^obaaf/\S+ ")
        self.assertNotIn("content-length", h1)

    def test_a_redirect_to_another_host_is_refused_and_the_token_does_not_travel(self):
        answer = audit.Client(api=self.api, token=TOKEN).get("/away")
        self.assertEqual(answer.code, "unexpected")
        self.assertEqual([path for _, path, _ in _Handler.seen], ["/away"])

    def test_a_redirect_on_the_same_host_is_followed(self):
        answer = audit.Client(api=self.api, token=TOKEN).get("/moved")
        self.assertEqual(answer.data, {"path": "/here"})
        self.assertEqual([path for _, path, _ in _Handler.seen], ["/moved", "/here"])

    def test_a_header_sent_on_two_lines_counts_in_full(self):
        answer = audit.Client(api=self.api).get("/two-links")
        self.assertTrue(answer.more)

    def test_an_answer_that_breaks_off_or_never_comes_is_a_network_problem_not_a_crash(self):
        answer = audit.Client(api=self.api, token=TOKEN).get("/broken")
        self.assertEqual(answer.code, "network")
        closed = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        port = closed.server_port
        closed.server_close()
        answer = audit.Client(api=f"http://127.0.0.1:{port}", token=TOKEN).get("/here")
        self.assertEqual(answer.code, "network")
        self.assertNotIn(TOKEN, answer.why)

    def test_an_error_that_quotes_a_header_names_only_its_kind(self):
        # A token with a line break makes urllib refuse the header; its message would quote the value.
        raw = github.UrllibTransport().get(self.api + "/here", {"Authorization": f"Bearer {TOKEN}\r\nX: 1"})
        self.assertEqual(raw.status, 0)
        self.assertNotIn(TOKEN, raw.error)
        self.assertEqual(_Handler.seen, [])

    def test_certificates_are_verified_and_there_is_no_way_to_ask_otherwise(self):
        transport = github.UrllibTransport()
        self.assertEqual(transport.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(transport.context.check_hostname)
        for opener in (transport._opener, transport._local):
            https = [h for h in opener.handlers if type(h).__name__ == "HTTPSHandler"]
            self.assertEqual(len(https), 1)
            self.assertIs(https[0]._context, transport.context)
            self.assertFalse([h for h in opener.handlers if type(h).__name__ in ("FileHandler", "FTPHandler")])
        self.assertFalse([h for h in transport._opener.handlers if type(h).__name__ == "HTTPHandler"])
        for module in (github, settings_mod, audit_cli, report, snapshot_mod):
            text = Path(module.__file__).read_text(encoding="utf-8")
            for unsafe in ("_create_unverified_context", "CERT_NONE", "check_hostname = False", "verify=False"):
                self.assertFalse(unsafe in text, f"{unsafe} in {module.__name__}")

    def test_the_client_has_no_way_to_send_anything_but_get(self):
        client_source = Path(github.__file__).read_text(encoding="utf-8")
        # One place builds a request, and it names the verb and passes no body.
        self.assertEqual(client_source.count("urllib.request.Request("), 1)
        self.assertIn('urllib.request.Request(url, headers=headers, method="GET")', client_source)
        for module in (github, settings_mod, audit_cli, report, snapshot_mod):
            text = Path(module.__file__).read_text(encoding="utf-8")
            for verb in ('"POST"', '"PUT"', '"PATCH"', '"DELETE"', "urlopen("):
                self.assertFalse(verb in text, f"{verb} in {module.__name__}")
            if module is not github:
                self.assertFalse("urllib.request" in text, f"urllib.request in {module.__name__}")
        self.assertEqual([name for name in dir(audit.Client) if not name.startswith("_")],
                         ["authenticated", "get", "get_all", "recording_text"])

    def test_only_plain_https_addresses_are_accepted_except_on_this_machine(self):
        self.assertEqual(github.check_api_url("https://github.example.com/api/v3/"), "https://github.example.com/api/v3")
        for bad in ("http://github.example.com/api/v3", "ftp://x", "file:///etc/passwd", "https://user:pw@host/",
                    "https://@host", "https://host/?a=b", "https://host/?", "https://host/#", " https://host",
                    "https://host:x/", "https://host:0", "http://[::1", "http://localhost.evil.example",
                    "http://127.0.0.1.evil.example", "", "github.example.com", "https://host\\@evil"):
            with self.assertRaises(audit.ApiUrlError, msg=bad):
                github.check_api_url(bad)


class TokenNeverComesBackOutTest(unittest.TestCase):
    """If a server ever echoed the token, it is cut out before anything else sees the answer."""

    def run_cli_with(self, entries):
        with TempDir() as tmp:
            code, out, err, _ = cli(entries, "--repo", REPO, "--snapshot-out", tmp / "s.json", "--record", tmp / "rec",
                                    env={"GH_TOKEN": TOKEN})
            written = (tmp / "s.json").read_text() + (tmp / "rec" / "responses.json").read_text()
        return code, out + err + written

    def test_in_an_error_message(self):
        code, everything = self.run_cli_with(
            [{"path": R, "status": 401, "headers": {}, "body": {"message": f"Bad credentials: {TOKEN}"}}])
        self.assertEqual(code, 1)
        self.assertNotIn(TOKEN, everything)
        self.assertIn("Bad credentials: [token]", everything)

    def test_in_a_name_a_key_a_header_or_a_body_that_is_not_json(self):
        entries = recording("admin-token")
        entry_for(entries, f"{R}/rulesets/42?includes_parents=true")["body"]["name"] = f"main {TOKEN}"
        entry_for(entries, f"{R}/rulesets/42?includes_parents=true")["body"]["conditions"] = {TOKEN: {"x": [TOKEN]}}
        denied = entry_for(entries, f"{R}/actions/permissions")
        denied.update(status=403, headers={"x-accepted-github-permissions": f"administration=read {TOKEN}"},
                      body={"message": "no"})
        entry_for(entries, f"{R}/actions/permissions/workflow").update(body=f"<html>{TOKEN}</html>")
        code, everything = self.run_cli_with(entries)
        self.assertEqual(code, 0)
        self.assertNotIn(TOKEN, everything)
        self.assertGreaterEqual(everything.count("[token]"), 5)

    def test_in_an_answer_nested_too_deeply_to_examine(self):
        # Deep enough to be past any examination, shallow enough for the JSON parser to accept it.
        deep = "[" * 300 + json.dumps({"echo": TOKEN}) + "]" * 300
        for token in (TOKEN, None):
            client = audit.Client(transport=audit.ReplayTransport([ok(R, deep)]), token=token)
            answer = client.get(R)
            self.assertEqual((answer.code, answer.data), ("unexpected", None))
            if token:
                self.assertNotIn(TOKEN, client.recording_text())
        entries = replace(recording("admin-token"), f"{R}/actions/permissions/workflow", body=deep)
        code, everything = self.run_cli_with(entries)
        self.assertEqual(code, 0)
        self.assertNotIn(TOKEN, everything)

    def test_across_the_place_where_a_long_answer_that_is_not_json_is_cut(self):
        for before in (github.RECORDED_TEXT_CHARS - 10, github.RECORDED_TEXT_CHARS - 1, 5):
            body = "<" * before + TOKEN + ">" * 50
            client = audit.Client(transport=audit.ReplayTransport([ok(R, body)]), token=TOKEN)
            client.get(R)
            kept = client.recorded[0]["body"]
            self.assertLessEqual(len(kept), github.RECORDED_TEXT_CHARS)
            for length in range(4, len(TOKEN) + 1):
                self.assertNotIn(TOKEN[:length], kept, (before, length))

    def test_in_a_transport_error(self):
        class Breaks:
            def get(self, url, headers):
                return github.Raw(0, error=f"Invalid header value b'Bearer {TOKEN}'")
        client = audit.Client(transport=Breaks(), token=TOKEN)
        answer = client.get(R)
        self.assertNotIn(TOKEN, answer.why + client.recording_text())
        self.assertIn("[token]", answer.why)


class SnapshotFileTest(unittest.TestCase):
    def setUp(self):
        self.snap, _ = take(recording("admin-token"), token=TOKEN)

    def test_it_round_trips_and_is_plain_ascii(self):
        with TempDir() as tmp:
            snapshot_mod.write(self.snap, tmp / "deep" / "settings.json")
            text = (tmp / "deep" / "settings.json").read_text(encoding="utf-8")
            self.assertEqual(snapshot_mod.load(tmp / "deep" / "settings.json"), self.snap)
        self.assertTrue(text.isascii())
        self.assertTrue(text.endswith("}\n"))

    def test_the_settings_part_is_the_same_for_the_same_settings(self):
        # Another time, another order of the same answers and of --branch: the settings part does not change.
        entries = recording("admin-token")
        entry_for(entries, f"{R}/rulesets{LIST}")["body"].reverse()
        entry_for(entries, f"{R}/environments?per_page=100")["body"]["environments"].reverse()
        other = audit.take(audit.Client(transport=audit.ReplayTransport(entries), token=TOKEN), REPO,
                           now=datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(json.dumps(other["settings"]), json.dumps(self.snap["settings"]))
        self.assertNotEqual(other["taken_at"], self.snap["taken_at"])

    def refused(self, data, expect=""):
        with TempDir() as tmp:
            (tmp / "s.json").write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
            with self.assertRaises(audit.SnapshotError) as caught:
                snapshot_mod.load(tmp / "s.json")
        self.assertIn(expect, str(caught.exception))
        return str(caught.exception)

    def test_a_file_that_is_not_a_snapshot_of_this_version_is_refused(self):
        def broken(change):
            data = copy.deepcopy(self.snap)
            change(data)
            return data
        cases = {
            "another format": lambda d: d.update(format="obaaf-settings-snapshot/v9"),
            "a missing setting": lambda d: d["settings"].pop("actions_policies"),
            "an unknown setting": lambda d: d["settings"].update(extra={"status": "read", "value": 1}),
            "an unknown status": lambda d: d["settings"]["rulesets"].update(status="fine"),
            "unread with no reason": lambda d: d["settings"].update(rulesets={"status": "unread"}),
            "an unknown reason code": lambda d: d["settings"].update(
                rulesets={"status": "unread", "reason_code": "meh", "reason": "x", "needs": "y"}),
            "read with no value": lambda d: d["settings"].update(rulesets={"status": "read"}),
            "partial with no problems": lambda d: d["settings"].update(
                rulesets={"status": "partial", "value": [], "problems": [], "needs": "y"}),
            "a problem with no key": lambda d: d["settings"]["ruleset_bypass_actors"]["problems"][0].pop("key"),
            "an unknown top-level key": lambda d: d.update(note="trust me"),
            "a list": lambda d: d.clear(),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.refused(broken(change))
        self.refused("{not json")
        self.refused("[" * 100000)
        self.refused(json.dumps(self.snap).replace('"taken_at"', '"x": NaN, "taken_at"'))
        with self.assertRaises(audit.SnapshotError):
            snapshot_mod.load("/nonexistent/snapshot.json")

    def test_the_value_of_every_setting_is_checked_not_only_the_outline(self):
        for key in self.snap["settings"]:
            for value in (None, 1, "x", [1], {"surprise": True}):
                data = copy.deepcopy(self.snap)
                if data["settings"][key]["status"] == "partial":
                    data["settings"][key] = {"status": "read", "value": value}
                else:
                    data["settings"][key]["value"] = value
                with self.subTest(key=key, value=value):
                    self.refused(data, "does not match the snapshot format")
        cases = {
            "an environment open to all with patterns": lambda s: s["environments"]["value"][0].update(branch_policies=[]),
            "selected branches with no patterns field": lambda s: s["environments"]["value"][1].pop("branch_policies"),
            "a null bypass list": lambda s: s["ruleset_bypass_actors"]["value"][0].update(actors=None),
            "an empty bypass list": lambda s: s["ruleset_bypass_actors"]["value"][0].update(actors=[]),
            "a role that does not exist": lambda s: s["collaborators"]["value"]["by_role"].update({"owner\n": 1}),
            "a count that is text": lambda s: s["collaborators"]["value"].update(total="1\nREAD: 15 of 15"),
            "a negative wait": lambda s: s["environments"]["value"][1].update(wait_timer=-1),
            "protection that exists with nothing in it": lambda s: s["branch_protection"]["value"].update(
                main={"exists": True}),
        }
        for name, change in cases.items():
            data = copy.deepcopy(self.snap)
            change(data["settings"])
            with self.subTest(name):
                self.refused(data, "does not match the snapshot format")

    def test_a_key_given_twice_is_refused(self):
        text = json.dumps(self.snap)
        text = text.replace('"rulesets": {"status": "read"',
                            '"rulesets": {"status": "unread", "reason_code": "forbidden", "reason": "x", "needs": "y"}, '
                            '"rulesets": {"status": "read"', 1)
        self.assertIn("given twice", self.refused(text))

    def test_a_file_too_large_or_too_deep_is_refused_without_being_read_whole(self):
        with TempDir() as tmp, mock.patch.object(snapshot_mod, "MAX_SNAPSHOT_BYTES", 1000):
            (tmp / "big.json").write_text(json.dumps(self.snap), encoding="utf-8")
            with self.assertRaises(audit.SnapshotError) as caught:
                snapshot_mod.load(tmp / "big.json")
            self.assertIn("larger than", str(caught.exception))
        if os.path.exists("/dev/zero"):
            with mock.patch.object(snapshot_mod, "MAX_SNAPSHOT_BYTES", 1000), self.assertRaises(audit.SnapshotError):
                snapshot_mod.load("/dev/zero")
        deep = copy.deepcopy(self.snap)
        nested = {}
        for _ in range(60):
            nested = {"a": nested}
        deep["settings"]["rulesets"]["value"][0]["conditions"] = nested
        self.assertIn("nested more than", self.refused(deep))

    def test_an_error_about_a_file_cannot_write_to_the_terminal(self):
        data = copy.deepcopy(self.snap)
        data["settings"]["zz\x1b[2J\nerror: all good"] = {"status": "read", "value": 1}
        message = self.refused(data)
        self.assertNotIn("\x1b", message)
        self.assertNotIn("\n", message)
        data = copy.deepcopy(self.snap)
        data["settings"]["collaborators"]["value"]["by_role"] = {"x\x1b]0;PWNED\x07\nREAD: 15 of 15": 1}
        message = self.refused(data)
        self.assertNotIn("\x1b", message)
        self.assertNotIn("PWNED", message)
        message = self.refused({"format": "v\x1b[2J\nok"})
        self.assertNotIn("\x1b", message)


class TerminalTest(unittest.TestCase):
    """Names come from whoever can create a ruleset, an environment or a branch."""

    NASTY = 'prod\x1b[2J‮gnp.exe​؜\U000e0041\nREAD: all is "fine"\x7f\x9b'
    SHOWN = '"prod?[2J?gnp.exe????READ: all is \\"fine\\"??"'

    def test_plain_and_quoted(self):
        self.assertEqual(github.quoted(self.NASTY, 200), self.SHOWN)
        self.assertEqual(github.plain("a\ud800bc d\re"), "a?b?c?d?e")
        self.assertEqual(github.plain("x" * 300, 10), "x" * 9 + "…")
        self.assertEqual(github.plain(None), "None")

    def test_every_name_in_the_report_is_made_safe(self):
        entries = recording("admin-token")
        bodies = {e["path"]: e["body"] for e in entries}
        bodies[f"{R}/environments?per_page=100"]["environments"][0]["name"] = self.NASTY
        bodies[f"{R}/rulesets/42?includes_parents=true"]["name"] = self.NASTY
        bodies[f"{R}/rulesets/42?includes_parents=true"]["bypass_actors"][0]["actor_type"] = self.NASTY
        bodies[f"{R}/rulesets/73?includes_parents=true"]["name"] = self.NASTY
        bodies[f"{R}/rulesets/73?includes_parents=true"]["rules"].extend([
            {"type": self.NASTY},
            {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": self.NASTY}]}}])
        bodies[f"{R}/actions/policies/7"]["name"] = self.NASTY
        bodies[f"{R}/actions/policies/7"]["rules"][0]["parameters"]["allowed_events"] = [self.NASTY]
        bodies[f"{R}/actions/secrets?per_page=100"]["secrets"][0]["name"] = self.NASTY
        bodies[f"{R}/actions/permissions/workflow"]["default_workflow_permissions"] = self.NASTY
        bodies[f"{R}/actions/permissions/fork-pr-contributor-approval"]["approval_policy"] = self.NASTY
        entry_for(entries, f"{R}/collaborators?affiliation=all&per_page=100").update(
            status=403, body={"message": self.NASTY}, headers={"x-accepted-github-permissions": self.NASTY})
        encoded = "prod%1B%5B2J%E2%80%AEgnp.exe%E2%80%8B%D8%9C%F3%A0%81%81%0AREAD%3A%20all%20is%20%22fine%22%7F%C2%9B"
        entries.append(ok(f"{R}/environments/{encoded}/secrets?per_page=100", {"total_count": 0, "secrets": []}))
        snap, transport = take(entries, token=TOKEN)
        self.assertEqual(transport.missing, [])
        text = report.to_text(snap)
        for bad in ("\x1b", "‮", "​", "؜", "\U000e0041", "\x7f", "\x9b", "\r"):
            self.assertNotIn(bad, text, repr(bad))
        self.assertNotIn("\nREAD: all is", text)
        self.assertGreaterEqual(text.count("READ: all is"), 11)
        self.assertEqual(len([line for line in text.splitlines() if line.startswith("READ:")]), 1)
        self.assertIn(self.SHOWN[:40], text)
        self.assertTrue(snapshot_mod.dumps(snap).isascii())

    def test_a_name_cannot_close_its_quotes_to_imitate_the_rest_of_its_line(self):
        entries = recording("public-no-token")
        envs = entry_for(entries, f"{R}/environments?per_page=100")["body"]["environments"]
        envs[0]["name"] = 'prod": only protected branches may deploy; reviewers: sec ('
        text = report.to_text(take(entries)[0])
        self.assertIn('"prod\\": only protected branches may deploy; reviewers: sec (": any branch or tag may deploy', text)

    def test_messages_to_standard_error_are_made_safe_too(self):
        code, out, err, _ = cli([], "--repo", "o/r\x1b[2J")
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", err)
        code, out, err, _ = cli([], "--token-env", "X\x1b[2J", "--repo", REPO)
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", err)
        with TempDir() as tmp:
            (tmp / "s.json").write_text(json.dumps({"format": "x\x1b[2J"}), encoding="utf-8")
            code, out, err, _ = cli([], "--from-snapshot", tmp / "s.json")
            self.assertEqual(code, 2)
            self.assertNotIn("\x1b", err)


class CommandLineTest(unittest.TestCase):
    def test_it_is_listed_and_documented(self):
        code, out, _ = run_cli("--help")
        self.assertIn("audit", out)
        code, out, _ = run_cli("audit", "--help")
        self.assertEqual(code, 0)
        for flag in ("--repo", "--from-snapshot", "--snapshot-out", "--no-token", "--token-env", "--fail-on-unread"):
            self.assertIn(flag, out)
        self.assertNotIn("--token ", out)

    def test_without_a_token_it_reports_and_exits_zero(self):
        code, out, err, transport = cli(recording("public-no-token"), "--repo", REPO)
        self.assertEqual((code, transport.missing), (0, []))
        self.assertIn("NOT READ: 10 of 15", out)
        self.assertNotIn("Using the token", err)

    def test_fail_on_unread(self):
        code, _, err, _ = cli(recording("public-no-token"), "--repo", REPO, "--fail-on-unread")
        self.assertEqual(code, 1)
        self.assertIn("10 setting(s) were not read in full", err)
        self.assertIn("ruleset_bypass_actors", err)
        code, _, err, _ = cli(recording("admin-token"), "--repo", REPO, "--fail-on-unread", env={"GH_TOKEN": TOKEN})
        self.assertEqual(code, 1)  # one ruleset's bypass list was not established
        self.assertIn("1 setting(s)", err)

    def test_reading_nothing_is_a_failure_not_a_pass(self):
        entries = [{"path": R, "status": 404, "headers": {}, "body": {"message": "Not Found"}}]
        code, out, err, _ = cli(entries, "--repo", REPO)
        self.assertEqual(code, 1)
        self.assertIn("Nothing was audited", err)
        self.assertIn("NOT READ: 15 of 15", out)

    def test_the_token_comes_from_the_environment_and_is_never_printed(self):
        with TempDir() as tmp:
            code, out, err, transport = cli(
                recording("admin-token"), "--repo", REPO, "--snapshot-out", tmp / "s.json", "--record", tmp / "rec",
                env={"GH_TOKEN": TOKEN, "GITHUB_TOKEN": "other-token"})
            self.assertEqual((code, transport.missing), (0, []))
            self.assertEqual(transport.seen[0][1]["Authorization"], f"Bearer {TOKEN}")
            self.assertIn("Using the token in the environment variable GH_TOKEN", err)
            written = (tmp / "s.json").read_text() + (tmp / "rec" / "responses.json").read_text()
            for text in (out, err, written):
                self.assertNotIn(TOKEN, text)
            self.assertNotIn("Authorization", written)
            # A recording made by the tool replays to the same snapshot.
            again = audit.ReplayTransport.load(tmp / "rec")
            replayed = audit.take(audit.Client(transport=again, token=TOKEN), REPO, now=NOW)
            first = json.loads((tmp / "s.json").read_text())
            self.assertEqual(replayed["settings"], first["settings"])
            self.assertEqual(again.missing, [])

    def test_no_token_overrides_the_environment(self):
        code, _, err, transport = cli(recording("public-no-token"), "--repo", REPO, "--no-token",
                                      env={"GH_TOKEN": TOKEN})
        self.assertEqual(code, 0)
        self.assertFalse([h for _, h in transport.seen if "Authorization" in h])

    def test_token_env(self):
        code, _, _, transport = cli(recording("admin-token"), "--repo", REPO, "--token-env", "AUDIT_TOKEN",
                                    env={"AUDIT_TOKEN": TOKEN, "GH_TOKEN": "wrong-token"})
        self.assertEqual(transport.seen[0][1]["Authorization"], f"Bearer {TOKEN}")
        code, _, err, transport = cli(recording("admin-token"), "--repo", REPO, "--token-env", "AUDIT_TOKEN")
        self.assertEqual((code, transport.seen), (2, []))
        self.assertIn("not set", err)
        for bad in ("two words\r\nX-Injected: 1", 'quote"inside', "back\\slash", "x1", "café-token-value"):
            code, _, err, transport = cli(recording("admin-token"), "--repo", REPO, env={"GH_TOKEN": bad})
            self.assertEqual((code, transport.seen), (2, []), bad)
            self.assertNotIn(bad, err)

    def test_a_token_in_the_environment_is_not_sent_to_another_api_address(self):
        entries = recording("public-no-token")
        transport = audit.ReplayTransport(entries, api="https://github.example.com/api/v3")
        with clean_env(GH_TOKEN=TOKEN), mock.patch.object(github, "UrllibTransport", return_value=transport):
            code, _, err = run_cli("audit", "--repo", REPO, "--api-url", "https://github.example.com/api/v3")
        self.assertEqual(code, 0)
        self.assertEqual(len(transport.seen), 8)
        self.assertFalse([h for _, h in transport.seen if "Authorization" in h])
        code, _, err = run_cli("audit", "--repo", REPO, "--api-url", "http://github.example.com/api/v3")
        self.assertEqual(code, 2)
        self.assertIn("https", err)

    def test_json_output_and_output_to_a_file(self):
        with TempDir() as tmp:
            code, out, _, _ = cli(recording("public-no-token"), "--repo", REPO, "--format", "json",
                                  "--snapshot-out", tmp / "s.json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out), json.loads((tmp / "s.json").read_text()))
            self.assertEqual(json.loads(out)["format"], audit.FORMAT)
            code, out, _, _ = cli(recording("public-no-token"), "--repo", REPO, "-o", tmp / "sub" / "report.txt")
            self.assertEqual((code, out), (0, ""))
            self.assertIn("NOT READ: 10 of 15", (tmp / "sub" / "report.txt").read_text())

    def test_output_that_cannot_be_written_is_a_failure_with_a_message(self):
        with TempDir() as tmp:
            for args in (("-o", tmp), ("--snapshot-out", tmp), ("--record", tmp / "s.json" / "x")):
                (tmp / "s.json").write_text("{}")
                code, out, err, _ = cli(recording("public-no-token"), "--repo", REPO, *args)
                self.assertEqual(code, 1, args)
                self.assertIn("error:", err)
                self.assertNotIn("Traceback", err)

    def test_a_bug_is_a_failure_with_a_message_never_a_pass(self):
        with mock.patch.object(report, "to_text", side_effect=RuntimeError("boom")):
            code, out, err, _ = cli(recording("public-no-token"), "--repo", REPO)
        self.assertEqual(code, 1)
        self.assertIn("failed unexpectedly (RuntimeError)", err)
        self.assertIn("nothing was established", err)

    def test_offline_from_a_snapshot_no_request_is_sent(self):
        with TempDir() as tmp:
            _, live_out, _, _ = cli(recording("admin-token"), "--repo", REPO, "--snapshot-out", tmp / "s.json",
                                    env={"GH_TOKEN": TOKEN})
            code, out, err, transport = cli([], "--from-snapshot", tmp / "s.json", env={"GH_TOKEN": TOKEN})
            self.assertEqual((code, transport.seen), (0, []))
            self.assertIn("Nothing was asked of GitHub now", out)
            self.assertEqual(out.splitlines()[2:], live_out.splitlines()[2:])
            code, _, err, _ = cli([], "--from-snapshot", tmp / "s.json", "--fail-on-unread")
            self.assertEqual(code, 1)
            code, _, err, _ = cli([], "--from-snapshot", tmp / "s.json", "--repo", "someone/else")
            self.assertEqual(code, 2)
            self.assertIn("is a snapshot of example-studio/game", err)
            for extra in (("--no-token",), ("--token-env", "X"), ("--record", tmp / "r"), ("--branch", "dev"),
                          ("--api-url", "https://x.example"), ("--snapshot-out", tmp / "t.json")):
                code, _, err, transport = cli([], "--from-snapshot", tmp / "s.json", *extra)
                self.assertEqual((code, transport.seen), (2, []), extra)
            code, _, err, _ = cli([], "--from-snapshot", tmp / "missing.json")
            self.assertEqual(code, 2)

    def test_usage_errors(self):
        for args in (("--repo", "not-a-repo"), ("--repo", "a/b/c"), ("--repo", "../x"), ("--repo", "o/.."),
                     ("--repo", REPO + "\n"), ("--repo", "o/r?x=1"), ("--repo", "o/r#frag"),
                     ("--repo", REPO, "--branch", "rel*")):
            code, _, err, transport = cli(recording("public-no-token"), *args)
            self.assertEqual((code, transport.seen), (2, []), args)

    def test_the_repository_is_found_from_the_clone_or_the_environment(self):
        with TempDir() as tmp:
            subprocess.run(["git", "init", "-q", str(tmp)], check=True)
            for url in ("https://github.com/example-studio/game.git", "git@github.com:example-studio/game.git",
                        "ssh://git@github.com/example-studio/game"):
                subprocess.run(["git", "-C", str(tmp), "config", "remote.origin.url", url], check=True)
                code, _, err, transport = cli(recording("public-no-token"), tmp)
                self.assertEqual((code, transport.missing), (0, []), url)
                self.assertIn("from the origin remote", err)
            subprocess.run(["git", "-C", str(tmp), "config", "remote.origin.url",
                            "https://gitlab.com/example-studio/game.git"], check=True)
            code, _, err, _ = cli(recording("public-no-token"), tmp)
            self.assertEqual(code, 2)
            self.assertIn("--repo OWNER/REPO", err)
            code, _, err, _ = cli(recording("public-no-token"), tmp, env={"GITHUB_REPOSITORY": REPO})
            self.assertEqual(code, 0)
            self.assertIn("$GITHUB_REPOSITORY", err)


def _load_check_script():
    spec = importlib.util.spec_from_file_location("check_live_audit", ROOT / "scripts" / "check_live_audit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LiveCheckScriptTest(unittest.TestCase):
    """scripts/check_live_audit.py decides whether the live workflow passes, so it is tested like the rest."""

    @classmethod
    def setUpClass(cls):
        cls.script = _load_check_script()

    def check(self, entries, *args, token=None, code=0, report_text=None, mangle=None):
        snap, _ = take(entries, token=token)
        printed = report.to_text(snap) if report_text is None else report_text
        if mangle:
            mangle(snap)
        with TempDir() as tmp, mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            (tmp / "s.json").write_text(json.dumps(snap), encoding="utf-8")
            (tmp / "r.txt").write_text(printed, encoding="utf-8")
            return self.script.main([str(tmp / "s.json"), "--report", str(tmp / "r.txt"), "--exit-code", str(code),
                                     *args])

    READ = ("--read", "repository", "rulesets", "branch_rules", "branches", "environments")

    def test_a_good_run_passes(self):
        self.assertEqual(self.check(recording("public-no-token"), *self.READ), 0)
        self.assertEqual(self.check(recording("workflow-token"), *self.READ, token=TOKEN), 0)

    def test_a_setting_that_had_to_be_read_and_was_not_fails(self):
        entries = replace(recording("public-no-token"), f"{R}/branches/main", status=404, body={"message": "Not Found"})
        self.assertEqual(self.check(entries, *self.READ), 1)

    def test_an_answer_of_an_unexpected_shape_fails_even_where_nothing_was_required(self):
        entries = replace(recording("workflow-token"), f"{R}/collaborators?affiliation=all&per_page=100", body={})
        self.assertEqual(self.check(entries, *self.READ, token=TOKEN), 1)
        # ...and a rate limit later in the same run does not excuse it.
        entries = replace(recording("workflow-token"), f"{R}/branches/main", body={"protected": "yes"})
        entries = replace(entries, f"{R}/environments?per_page=100", status=429, body={"message": "x"})
        self.assertEqual(self.check(entries, "--rate-limit-ok", token=TOKEN), 1)

    def test_a_rate_limit_passes_only_when_allowed(self):
        limited = [{"path": R, "status": 429, "headers": {}, "body": {"message": "slow"}}]
        self.assertEqual(self.check(limited, *self.READ, code=1), 1)
        self.assertEqual(self.check(limited, *self.READ, "--rate-limit-ok", code=1), 0)

    def test_another_repository_that_cannot_be_read_passes_only_when_allowed(self):
        gone = [{"path": R, "status": 404, "headers": {}, "body": {"message": "Not Found"}}]
        self.assertEqual(self.check(gone, code=1), 1)
        self.assertEqual(self.check(gone, "--unreadable-ok", code=1), 0)

    def test_a_run_whose_exit_code_or_report_does_not_fit_its_snapshot_fails(self):
        entries = recording("public-no-token")
        self.assertEqual(self.check(entries, *self.READ, code=1), 1)   # read everything, yet exited 1
        self.assertEqual(self.check(entries, *self.READ, code=2), 1)
        self.assertEqual(self.check(entries, *self.READ, report_text=""), 1)   # the report never got written
        self.assertEqual(self.check(entries, *self.READ, report_text="Traceback (most recent call last):\n"), 1)
        gone = [{"path": R, "status": 404, "headers": {}, "body": {"message": "Not Found"}}]
        self.assertEqual(self.check(gone, "--unreadable-ok", code=0), 1)   # read nothing, yet exited 0

    def test_a_snapshot_that_is_not_valid_fails(self):
        self.assertEqual(self.check(recording("public-no-token"), *self.READ,
                                    mangle=lambda s: s["settings"].pop("rulesets")), 1)
        self.assertEqual(self.script.main(["/nonexistent.json", "--report", "/nonexistent.txt", "--exit-code", "0"]), 1)
        with mock.patch("sys.stderr"):
            self.assertEqual(self.script.main(["x", "--report", "y", "--exit-code", "0", "--read", "nonsense"]), 2)


class LiveWorkflowTest(unittest.TestCase):
    def test_the_workflow_cannot_pass_over_a_failed_command(self):
        text = (ROOT / ".github" / "workflows" / "settings-audit-live.yml").read_text(encoding="utf-8")
        self.assertNotIn("| tee", text)   # a pipe would report tee's status, not the audit's
        self.assertNotIn("continue-on-error", text)
        self.assertEqual(text.count("scripts/check_live_audit.py"), text.count("obaaf audit --repo") + 1)
        self.assertIn("contents: read", text)
        self.assertNotIn("write", text.split("jobs:")[0].split("permissions:")[1])


class DocumentedSettingsTest(unittest.TestCase):
    def test_every_setting_the_audit_reads_is_described_in_the_guide(self):
        guide = (ROOT / "docs" / "settings-audit.md").read_text(encoding="utf-8")
        for setting in audit.SETTINGS:
            self.assertIn(f"`{setting.key}`", guide, setting.key)
            for path in setting.paths:
                self.assertIn(path, guide, path)
        for code in audit.REASONS:
            self.assertIn(f"`{code}`", guide, code)

    def test_the_schema_names_every_setting_and_reason_the_reader_uses(self):
        from obaaf.catalog import data_text
        schema = json.loads(data_text("schemas/settings-snapshot.schema.json"))
        self.assertEqual(schema["$defs"]["reason_code"]["enum"], list(audit.REASONS))
        self.assertEqual(schema["properties"]["settings"]["required"], [s.key for s in audit.SETTINGS])
        self.assertEqual(list(schema["properties"]["settings"]["properties"]), [s.key for s in audit.SETTINGS])


if __name__ == "__main__":
    unittest.main()
