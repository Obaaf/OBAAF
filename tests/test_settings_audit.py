"""The settings audit's reader (flagship slice 2b.1): what it asks GitHub for, how it records the answers,
and above all how it records what it could not read.

The recordings under tests/fixtures/settings/ were written by hand from the example responses in GitHub's
REST reference (read 2026-11-12). They were not recorded from a live repository; the workflow
.github/workflows/settings-audit-live.yml runs the same reader against GitHub itself.
"""

import copy
import http.server
import json
import os
import subprocess
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

from helpers import FIXTURES, TempDir, run_cli

from obaaf import audit
from obaaf.audit import github, report, settings as settings_mod, snapshot as snapshot_mod

SETTINGS_DIR = FIXTURES / "settings"
REPO = "example-studio/game"
R = f"/repos/{REPO}"
NOW = datetime(2026, 11, 12, 1, 0, tzinfo=timezone.utc)
TOKEN = "ghx_NotARealTokenUsedOnlyInTests0123456789"
PUBLIC_PATHS = [
    R,
    f"{R}/rulesets?includes_parents=true&per_page=100",
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


def replace(entries: list[dict], path: str, **changes) -> list[dict]:
    """A copy of a recording with the answer for one path changed."""
    out = copy.deepcopy(entries)
    hits = [e for e in out if e["path"] == path]
    assert len(hits) == 1, f"{path} is in the recording {len(hits)} times"
    hits[0].update(changes)
    return out


def take(entries: list[dict], token: str | None = None, repository: str = REPO, branches=()):
    transport = audit.ReplayTransport(copy.deepcopy(entries))
    client = audit.Client(transport=transport, token=token)
    snap = audit.take(client, repository, tuple(branches), now=NOW)
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
        self.assertEqual(snapshot_mod.problems(self.snap), [])

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
        # null means any branch may deploy: the first of the adopter's incidents.
        self.assertIsNone(main_only["deployment_branch_policy"])
        self.assertIsNone(main_only["required_reviewers"])
        self.assertEqual(release["deployment_branch_policy"],
                         {"protected_branches": False, "custom_branch_policies": True})
        self.assertEqual(release["branch_policies"], [{"name": "main", "type": "branch"},
                                                      {"name": "release/*", "type": None}])
        self.assertEqual(release["wait_timer"], 30)
        self.assertEqual(release["required_reviewers"], {"prevent_self_review": False, "reviewers": [
            {"type": "Team", "name": "justice-league", "id": 1}, {"type": "User", "name": "octocat", "id": 1}]})
        self.assertEqual(s["branches"]["value"]["main"]["protected"], True)
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
        self.assertEqual(s["branch_protection"]["value"], {"main": None})
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
        self.assertEqual(s["fork_pull_requests"]["value"],
                         {"approval_policy": "first_time_contributors", "private_repository": None})
        policy, = s["actions_policies"]["value"]
        self.assertEqual(policy["rules"], [{"type": "restrict_action_events", "parameters": {
            "allowed_events": ["pull_request_target", "workflow_dispatch"]}}])
        self.assertEqual(policy["conditions"], {"workflow_path": {"exclude": [], "include": [".github/workflows/scan.yml"]}})
        # Counts only: no login is kept.
        self.assertEqual(s["collaborators"]["value"], {"total": 1, "by_role": {
            "admin": 1, "maintain": 0, "write": 0, "triage": 0, "read": 0}})
        self.assertNotIn("shared-account", json.dumps(self.snap))
        self.assertEqual(self.snap["viewer"]["can_bypass_rulesets"], {"42": "always", "73": "never"})
        self.assertTrue(self.snap["viewer"]["repository_permissions"]["admin"])

    def test_a_bypass_list_is_recorded_and_an_empty_one_from_the_organisation_is_not_believed(self):
        entry = self.snap["settings"]["ruleset_bypass_actors"]
        self.assertEqual(entry["status"], "partial")
        self.assertEqual(entry["value"], {"42": [
            {"actor_type": "OrganizationAdmin", "actor_id": None, "bypass_mode": "always"},
            {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "pull_request"}]})
        problem, = entry["problems"]
        self.assertEqual(problem["reason_code"], "withheld")
        self.assertIn("73", problem["what"])
        text = report.to_text(self.snap)
        self.assertIn('ruleset 42 "main protection": OrganizationAdmin (always), RepositoryRole 5 (pull_request)', text)
        self.assertIn("NOT READ: ruleset 73", text)
        self.assertIn("for .github/workflows/scan.yml: only these events may start a workflow: "
                      "pull_request_target, workflow_dispatch", text)


class EmptyBypassListTest(unittest.TestCase):
    """An empty bypass list means "nobody" only when the caller would have been shown a full one."""

    def bypass(self, entries, token):
        return take(entries, token=token)[0]["settings"]["ruleset_bypass_actors"]

    def with_lists(self, base, repo_list, org_list):
        entries = recording(base)
        r42 = next(e for e in entries if e["path"].startswith(f"{R}/rulesets/42"))
        r73 = next(e for e in entries if e["path"].startswith(f"{R}/rulesets/73"))
        for entry, value in ((r42, repo_list), (r73, org_list)):
            entry["body"].pop("bypass_actors", None)
            if value != "absent":
                entry["body"]["bypass_actors"] = value
        return entries

    def test_from_an_administrator_for_the_repositorys_own_ruleset_it_is_read(self):
        entry = self.bypass(self.with_lists("admin-token", [], "absent"), TOKEN)
        self.assertEqual(entry["status"], "partial")
        self.assertEqual(entry["value"], {"42": []})

    def test_from_a_caller_who_is_not_an_administrator_it_is_not(self):
        entry = self.bypass(self.with_lists("workflow-token", [], []), TOKEN)
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "withheld"))

    def test_without_a_token_it_is_not(self):
        entry = self.bypass(self.with_lists("public-no-token", [], []), None)
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "withheld"))

    def test_null_is_treated_as_left_out(self):
        entry = self.bypass(self.with_lists("admin-token", None, None), TOKEN)
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "withheld"))

    def test_a_list_that_is_not_a_list_makes_the_rulesets_unread(self):
        snap, _ = take(self.with_lists("admin-token", "nobody", "absent"), token=TOKEN)
        self.assertEqual(snap["settings"]["rulesets"]["reason_code"], "unexpected")
        self.assertEqual(snap["settings"]["ruleset_bypass_actors"]["reason_code"], "depends")

    def test_with_no_ruleset_there_is_nothing_to_bypass(self):
        entries = replace(recording("public-no-token"), f"{R}/rulesets?includes_parents=true&per_page=100", body=[])
        snap, transport = take(entries)
        self.assertEqual(snap["settings"]["rulesets"], {"status": "read", "value": []})
        self.assertEqual(snap["settings"]["ruleset_bypass_actors"]["status"], "not_applicable")
        self.assertNotIn(f"{R}/rulesets/42?includes_parents=true", [p for p, _ in transport.seen])


class RefusedByGitHubTest(unittest.TestCase):
    def setUp(self):
        self.snap, self.transport = take(recording("workflow-token"), token=TOKEN)

    def test_a_refusal_is_unread_with_githubs_own_words_and_what_it_would_accept(self):
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
        self.assertEqual((s["collaborators"]["status"], s["collaborators"]["reason_code"]), ("unread", "not_found"))
        self.assertEqual(snapshot_mod.problems(self.snap), [])

    def test_a_404_on_branch_protection_is_no_protection_only_with_githubs_message_for_it(self):
        path = f"{R}/branches/main/protection"
        for message, expected in (("Branch not protected", "read"), ("Not Found", "unread"),
                                  ("Branch not protected.", "unread")):
            entries = replace(recording("admin-token"), path, body={"message": message})
            entry = take(entries, token=TOKEN)[0]["settings"]["branch_protection"]
            self.assertEqual(entry["status"], expected, message)

    def test_classic_branch_protection_is_recorded_when_there_is_one(self):
        body = {"url": "https://api.github.com/repos/example-studio/game/branches/main/protection",
                "required_status_checks": {"contexts": ["ci"], "checks": [{"context": "ci", "app_id": None}],
                                           "strict": True, "enforcement_level": "non_admins"},
                "enforce_admins": {"url": "x", "enabled": False},
                "required_pull_request_reviews": {
                    "required_approving_review_count": 2, "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True, "require_last_push_approval": False,
                    "bypass_pull_request_allowances": {"users": [{"login": "octocat", "id": 1}], "teams": [],
                                                       "apps": [{"slug": "octoapp", "id": 1}]}},
                "restrictions": None, "allow_force_pushes": {"enabled": False}, "lock_branch": {"enabled": False}}
        entries = replace(recording("admin-token"), f"{R}/branches/main/protection", status=200, body=body)
        value = take(entries, token=TOKEN)[0]["settings"]["branch_protection"]["value"]["main"]
        self.assertEqual(value["required_pull_request_reviews"]["required_approving_review_count"], 2)
        self.assertEqual(value["required_pull_request_reviews"]["bypass_allowances"],
                         {"users": ["octocat"], "teams": [], "apps": ["octoapp"]})
        self.assertEqual(value["required_status_checks"]["contexts"], ["ci"])
        self.assertIs(value["enforce_admins"], False)
        self.assertIsNone(value["required_signatures"])  # not in the answer, so not known

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

    def test_a_secondary_limit_is_recognised_by_retry_after_or_by_the_message(self):
        for headers, message in (({"retry-after": "60"}, "slow down"),
                                 ({}, "You have exceeded a secondary rate limit.")):
            snap, _ = take([{"path": R, "status": 429, "headers": headers, "body": {"message": message}}])
            self.assertEqual(snap["settings"]["repository"]["reason_code"], "rate_limited")


class ShapeTest(unittest.TestCase):
    """An answer that is not what GitHub documents is unread, never guessed at and never a crash."""

    def unread(self, entries, key, token=None):
        entry = take(entries, token=token)[0]["settings"][key]
        self.assertEqual((entry["status"], entry["reason_code"]), ("unread", "unexpected"), entry)
        return entry

    def test_an_environment_with_no_branch_policy_field_is_not_taken_for_any_branch(self):
        entries = recording("public-no-token")
        env = next(e for e in entries if e["path"] == f"{R}/environments?per_page=100")
        del env["body"]["environments"][0]["deployment_branch_policy"]
        self.assertIn("deployment_branch_policy", self.unread(entries, "environments")["reason"])

    def test_a_ruleset_with_no_rules_list_is_not_taken_for_an_empty_ruleset(self):
        entries = recording("public-no-token")
        del next(e for e in entries if e["path"].startswith(f"{R}/rulesets/42"))["body"]["rules"]
        self.unread(entries, "rulesets")

    def test_wrong_types_anywhere_are_unread(self):
        cases = [
            ("rulesets", f"{R}/rulesets?includes_parents=true&per_page=100", {"message": "hello"}),
            ("rulesets", f"{R}/rulesets?includes_parents=true&per_page=100", [{"id": "42"}]),
            ("rulesets", f"{R}/rulesets?includes_parents=true&per_page=100", [{"id": True}]),
            ("rulesets", f"{R}/rulesets/42?includes_parents=true", []),
            ("branch_rules", f"{R}/rules/branches/main?per_page=100", [{"type": 7}]),
            ("branches", f"{R}/branches/main", {"name": "main", "protected": "yes"}),
            ("environments", f"{R}/environments?per_page=100", {"total_count": 1, "environments": "none"}),
            ("environments", f"{R}/environments?per_page=100", {"total_count": 1, "environments": [{"name": 3}]}),
            ("environments", f"{R}/environments/release/deployment-branch-policies?per_page=100", []),
        ]
        for key, path, body in cases:
            with self.subTest(path=path, body=body):
                entries = replace(recording("public-no-token"), path, body=body)
                snap, _ = take(entries)
                self.assertIn(snap["settings"][key]["status"], ("unread", "partial"))
                self.assertEqual(snapshot_mod.problems(snap), [])
        for key, path, body in [
            ("collaborators", f"{R}/collaborators?affiliation=all&per_page=100", [{"login": "x"}]),
            ("collaborators", f"{R}/collaborators?affiliation=all&per_page=100", [{"login": "x", "permissions": {}}]),
            ("repository_secrets", f"{R}/actions/secrets?per_page=100", {"total_count": 1, "secrets": [{}]}),
            ("actions_permissions", f"{R}/actions/permissions", {"enabled": "true"}),
            ("workflow_permissions", f"{R}/actions/permissions/workflow", {"default_workflow_permissions": "read"}),
            ("fork_pull_requests", f"{R}/actions/permissions/fork-pr-contributor-approval", {}),
            ("actions_policies", f"{R}/actions/policies?has_parents=true&per_page=100", {"policies": [{"id": 0}]}),
        ]:
            with self.subTest(path=path, body=body):
                self.unread(replace(recording("admin-token"), path, body=body), key, token=TOKEN)

    def test_a_repository_name_that_is_not_owner_repo_is_refused_before_it_is_used_in_a_path(self):
        entries = recording("public-no-token")
        entries[0]["body"]["full_name"] = "example-studio/game/../../../orgs/evil"
        snap, transport = take(entries)
        self.assertEqual(snap["settings"]["repository"]["reason_code"], "unexpected")
        self.assertEqual(len(transport.seen), 1)

    def test_a_count_that_disagrees_with_the_list_is_unread(self):
        entries = recording("public-no-token")
        next(e for e in entries if e["path"] == f"{R}/environments?per_page=100")["body"]["total_count"] = 3
        self.assertIn("3 entries and returned 2", self.unread(entries, "environments")["reason"])

    def test_an_answer_that_is_not_json_or_is_too_large_is_unread(self):
        entries = replace(recording("public-no-token"), f"{R}/branches/main", body="<html>proxy login</html>")
        self.unread(entries, "branches")

        class Huge:
            def get(self, url, headers):
                return github.Raw(200, {}, b"[" + b" " * (github.MAX_BODY_BYTES + 1))
        answer = audit.Client(transport=Huge()).get(R)
        self.assertEqual(answer.code, "unexpected")
        self.assertIn("5 MB", answer.why)

    def test_an_unknown_rule_type_is_kept_as_it_came(self):
        entries = recording("public-no-token")
        rules = next(e for e in entries if e["path"].startswith(f"{R}/rulesets/42"))["body"]["rules"]
        rules.append({"type": "a_rule_from_next_year", "parameters": {"level": {"deep": [1, 2]}}})
        snap, _ = take(entries)
        self.assertEqual(snap["settings"]["rulesets"]["status"], "read")
        self.assertIn({"type": "a_rule_from_next_year", "parameters": {"level": {"deep": [1, 2]}}},
                      snap["settings"]["rulesets"]["value"][0]["rules"])

    def test_an_unknown_environment_rule_is_named_not_dropped(self):
        entries = recording("public-no-token")
        env = next(e for e in entries if e["path"] == f"{R}/environments?per_page=100")
        env["body"]["environments"][0]["protection_rules"].append({"id": 9, "type": "something_new"})
        snap, _ = take(entries)
        self.assertEqual(snap["settings"]["environments"]["value"][0]["other_protection_rules"], ["something_new"])


class PartsTest(unittest.TestCase):
    def test_one_ruleset_that_cannot_be_read_makes_the_setting_partial(self):
        entries = replace(recording("public-no-token"), f"{R}/rulesets/73?includes_parents=true", status=500,
                          body={"message": "Server Error"})
        entry = take(entries)[0]["settings"]["rulesets"]
        self.assertEqual(entry["status"], "partial")
        self.assertEqual([r["id"] for r in entry["value"]], [42])
        self.assertEqual(entry["problems"][0]["reason_code"], "server_error")
        self.assertIn("NOT READ: ruleset 73", report.to_text(take(entries)[0]))

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
        entry = take(entries, token=TOKEN)[0]["settings"]["actions_permissions"]
        self.assertEqual(entry["status"], "partial")
        self.assertIsNone(entry["value"]["selected_actions"])

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

    def test_more_branches_can_be_audited_and_their_names_are_encoded(self):
        entries = recording("public-no-token")
        branch = next(e for e in entries if e["path"] == f"{R}/branches/main")
        entries.append({**copy.deepcopy(branch), "path": f"{R}/branches/release%2F1.0"})
        entries.append(ok(f"{R}/rules/branches/release%2F1.0?per_page=100", []))
        snap, transport = take(entries, branches=("release/1.0", "main"))
        self.assertEqual(transport.missing, [])
        self.assertEqual(snap["branches"], ["main", "release/1.0"])
        self.assertEqual(snap["settings"]["branch_rules"]["value"]["release/1.0"], [])
        self.assertIn("release/1.0: no active rule", report.to_text(snap))
        for bad in ("rel*", "a b", "", "-x", "a?b"):
            with self.assertRaises(ValueError):
                audit.take(audit.Client(transport=audit.ReplayTransport([])), REPO, (bad,))

    def test_lists_are_read_to_their_last_page(self):
        first = ok(f"{R}/actions/secrets?per_page=100", {"total_count": 3, "secrets": [{"name": "B"}, {"name": "A"}]},
                   {"link": f'<https://api.github.com{R}/actions/secrets?per_page=100&page=2>; rel="next", '
                            f'<https://api.github.com{R}/actions/secrets?per_page=100&page=2>; rel="last"'})
        second = ok(f"{R}/actions/secrets?per_page=100&page=2", {"total_count": 3, "secrets": [{"name": "C"}]})
        entries = [e for e in recording("admin-token") if e["path"] != f"{R}/actions/secrets?per_page=100"]
        snap, transport = take(entries + [first, second], token=TOKEN)
        self.assertEqual(snap["settings"]["repository_secrets"]["value"], ["A", "B", "C"])
        self.assertEqual(transport.missing, [])

    def test_a_next_page_on_another_host_is_not_fetched(self):
        first = ok(f"{R}/actions/secrets?per_page=100", {"total_count": 3, "secrets": [{"name": "A"}]},
                   {"link": '<https://evil.example/steal?page=2>; rel="next"'})
        entries = [e for e in recording("admin-token") if e["path"] != f"{R}/actions/secrets?per_page=100"]
        snap, transport = take(entries + [first], token=TOKEN)
        self.assertEqual(snap["settings"]["repository_secrets"]["reason_code"], "unexpected")
        self.assertFalse([p for p, _ in transport.seen if "evil.example" in p])


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
                         ["/repos/old-owner/game", "/repositories/1296269",
                          f"{R}/rulesets?includes_parents=true&per_page=100"])
        self.assertIn("Asked for as old-owner/game", report.to_text(snap))
        self.assertEqual(snapshot_mod.problems(snap), [])

    def test_a_redirect_to_another_host_is_not_followed(self):
        away = {"path": R, "status": 302, "headers": {"location": "https://evil.example/repos/x/y"}, "body": None}
        snap, transport = take([away], token=TOKEN)
        self.assertEqual([p for p, _ in transport.seen], [R])
        entry = snap["settings"]["repository"]
        self.assertEqual(entry["reason_code"], "unexpected")
        self.assertIn("evil.example", entry["reason"])

    def test_redirects_do_not_go_round_for_ever(self):
        loop = {"path": R, "status": 307, "headers": {"location": f"https://api.github.com{R}"}, "body": None}
        snap, transport = take([loop])
        self.assertEqual(len(transport.seen), github.MAX_REDIRECTS + 1)
        self.assertEqual(snap["settings"]["repository"]["reason_code"], "unexpected")


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *args):  # keep the test output quiet
        pass

    def _answer(self):
        type(self).seen.append((self.command, self.path, dict(self.headers.items())))
        if self.path == "/away":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/elsewhere")
            self.end_headers()
        elif self.path == "/moved":
            self.send_response(301)
            self.send_header("Location", "/here")
            self.end_headers()
        else:
            body = json.dumps({"path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
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

    def test_it_sends_get_with_the_token_only_when_it_has_one(self):
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
        self.assertNotIn("content-length", h1)  # no body is ever sent

    def test_a_redirect_to_another_host_is_refused_and_the_token_does_not_travel(self):
        answer = audit.Client(api=self.api, token=TOKEN).get("/away")
        self.assertEqual(answer.code, "unexpected")
        self.assertEqual([path for _, path, _ in _Handler.seen], ["/away"])

    def test_a_redirect_on_the_same_host_is_followed(self):
        answer = audit.Client(api=self.api, token=TOKEN).get("/moved")
        self.assertEqual(answer.data, {"path": "/here"})
        self.assertEqual([path for _, path, _ in _Handler.seen], ["/moved", "/here"])

    def test_nothing_answering_is_a_network_problem_not_a_crash(self):
        closed = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        port = closed.server_port
        closed.server_close()
        answer = audit.Client(api=f"http://127.0.0.1:{port}", token=TOKEN).get("/here")
        self.assertEqual(answer.code, "network")
        self.assertNotIn(TOKEN, answer.why)

    def test_the_client_has_no_way_to_send_anything_but_get(self):
        from pathlib import Path

        from obaaf.audit import cli as audit_cli
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

    def test_only_https_addresses_are_accepted_except_on_this_machine(self):
        self.assertEqual(github.check_api_url("https://github.example.com/api/v3/"), "https://github.example.com/api/v3")
        for bad in ("http://github.example.com/api/v3", "ftp://x", "file:///etc/passwd", "https://user:pw@host/",
                    "https://host/?a=b", "", "github.example.com"):
            with self.assertRaises(audit.ApiUrlError, msg=bad):
                github.check_api_url(bad)

    def test_an_error_that_could_quote_a_header_names_only_its_kind(self):
        class Breaks:
            def get(self, url, headers):
                return github.Raw(0, error=f"Invalid header value b'Bearer {TOKEN}'")
        client = audit.Client(transport=Breaks(), token=TOKEN)
        answer = client.get(R)
        self.assertNotIn(TOKEN, answer.why)
        self.assertNotIn(TOKEN, client.recording_text())


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
            "an unknown top-level key": lambda d: d.update(note="trust me"),
            "a list": lambda d: d.clear(),
        }
        for name, change in cases.items():
            with self.subTest(name), TempDir() as tmp:
                (tmp / "s.json").write_text(json.dumps(broken(change)), encoding="utf-8")
                with self.assertRaises(audit.SnapshotError):
                    snapshot_mod.load(tmp / "s.json")
        with TempDir() as tmp:
            (tmp / "s.json").write_text("{not json", encoding="utf-8")
            with self.assertRaises(audit.SnapshotError):
                snapshot_mod.load(tmp / "s.json")
            with self.assertRaises(audit.SnapshotError):
                snapshot_mod.load(tmp / "absent.json")
            (tmp / "deep.json").write_text("[" * 100000, encoding="utf-8")
            with self.assertRaises(audit.SnapshotError):
                snapshot_mod.load(tmp / "deep.json")

    def test_names_from_github_cannot_write_to_the_terminal(self):
        entries = recording("public-no-token")
        env = next(e for e in entries if e["path"] == f"{R}/environments?per_page=100")
        env["body"]["environments"][0]["name"] = "prod\x1b[2J‮gnp.exe\nREAD: everything is fine"
        entries.append(ok(f"{R}/environments/prod%1B%5B2J%E2%80%AEgnp.exe%0AREAD%3A%20everything%20is%20fine/"
                          "deployment-branch-policies?per_page=100", {"branch_policies": []}))
        snap, _ = take(entries)
        text = report.to_text(snap)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("‮", text)
        self.assertNotIn("\nREAD: everything is fine", text)
        self.assertIn('"prod?[2J?gnp.exe?READ: everything is fine"', text)
        self.assertTrue(snapshot_mod.dumps(snap).isascii())

    def test_a_snapshot_edited_by_hand_cannot_crash_the_report(self):
        data = copy.deepcopy(self.snap)
        data["settings"]["environments"]["value"] = [{"name": "x"}]
        data["settings"]["rulesets"]["value"] = "not a list"
        text = report.to_text(data)
        self.assertEqual(text.count("recorded, but not in a form this version can describe"), 2)


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
                env={"GH_TOKEN": TOKEN, "GITHUB_TOKEN": "other"})
            self.assertEqual((code, transport.missing), (0, []))
            self.assertEqual(transport.seen[0][1]["Authorization"], f"Bearer {TOKEN}")
            self.assertIn("Using the token in $GH_TOKEN", err)
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
                                    env={"AUDIT_TOKEN": TOKEN, "GH_TOKEN": "wrong"})
        self.assertEqual(transport.seen[0][1]["Authorization"], f"Bearer {TOKEN}")
        code, _, err, transport = cli(recording("admin-token"), "--repo", REPO, "--token-env", "AUDIT_TOKEN")
        self.assertEqual((code, transport.seen), (2, []))
        self.assertIn("not set", err)
        code, _, err, transport = cli(recording("admin-token"), "--repo", REPO,
                                      env={"GH_TOKEN": "two words\r\nX-Injected: 1"})
        self.assertEqual((code, transport.seen), (2, []))
        self.assertNotIn("two words", err)

    def test_a_token_in_the_environment_is_not_sent_to_another_api_address(self):
        entries = recording("public-no-token")
        transport = audit.ReplayTransport(entries, api="https://github.example.com/api/v3")
        with clean_env(GH_TOKEN=TOKEN), mock.patch.object(github, "UrllibTransport", return_value=transport):
            code, _, err = run_cli("audit", "--repo", REPO, "--api-url", "https://github.example.com/api/v3")
        self.assertEqual(code, 0)
        self.assertFalse([h for _, h in transport.seen if "Authorization" in h])
        code, _, err = run_cli("audit", "--repo", REPO, "--api-url", "http://github.example.com/api/v3")
        self.assertEqual(code, 2)
        self.assertIn("https", err)

    def test_json_output_is_the_snapshot(self):
        with TempDir() as tmp:
            code, out, _, _ = cli(recording("public-no-token"), "--repo", REPO, "--format", "json",
                                  "--snapshot-out", tmp / "s.json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out), json.loads((tmp / "s.json").read_text()))
            self.assertEqual(json.loads(out)["format"], audit.FORMAT)

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


class DocumentedSettingsTest(unittest.TestCase):
    def test_every_setting_the_audit_reads_is_described_in_the_guide(self):
        from helpers import ROOT
        guide = (ROOT / "docs" / "settings-audit.md").read_text(encoding="utf-8")
        for setting in audit.SETTINGS:
            self.assertIn(f"`{setting.key}`", guide, setting.key)
            for path in setting.paths:
                self.assertIn(path, guide, path)
        for code in audit.REASONS:
            self.assertIn(f"`{code}`", guide, code)

    def test_the_reason_codes_in_the_schema_are_the_ones_the_reader_uses(self):
        from obaaf.catalog import data_text
        schema = json.loads(data_text("schemas/settings-snapshot.schema.json"))
        self.assertEqual(schema["$defs"]["reason_code"]["enum"], list(audit.REASONS))


if __name__ == "__main__":
    unittest.main()
