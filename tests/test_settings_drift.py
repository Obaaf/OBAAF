"""Drift (flagship slice 2b.3): a committed snapshot of the settings compared with the settings as they are.

The snapshots here are built by the real reader from the recordings in tests/fixtures/settings/, then
changed the way a setting would change on GitHub. Two of those recordings are GitHub's own answers (the
names beginning with "live-"); the others were written by hand from GitHub's REST reference.
"""

import copy
import json
import os
import re
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from helpers import FIXTURES, ROOT, TEMPLATES, TEST_SHA, TempDir, run_cli

from obaaf import audit
from obaaf.audit import drift, github, settings as settings_mod, snapshot as snapshot_mod
from obaaf import checker

SETTINGS_DIR = FIXTURES / "settings"
REPO = "example-studio/game"
TOKEN = "ghx_NotARealTokenUsedOnlyInTests0123456789"
NOW = datetime(2026, 11, 12, 1, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 11, 13, 5, 41, tzinfo=timezone.utc)


def recording(name: str) -> list[dict]:
    return json.loads((SETTINGS_DIR / name / "responses.json").read_text(encoding="utf-8"))["responses"]


def take(name: str = "admin-token", token: str | None = TOKEN, repository: str = REPO, branches=(), now=NOW,
         entries: list[dict] | None = None) -> dict:
    transport = audit.ReplayTransport(copy.deepcopy(entries if entries is not None else recording(name)))
    snap = audit.take(audit.Client(transport=transport, token=token), repository, tuple(branches), now=now)
    assert snapshot_mod.problems(snap) == [], snapshot_mod.problems(snap)
    return snap


def expectrail() -> dict:
    return take("live-expectrail-no-token", token=None, repository="Expectrail/Expectrail")


def env(snap: dict, name: str) -> dict:
    return next(e for e in snap["settings"]["environments"]["value"] if e["name"] == name)


def rule(ruleset: dict, kind: str) -> dict:
    return next(r for r in ruleset["rules"] if r["type"] == kind)


def changed(result: dict) -> list[tuple]:
    """(setting, part, path, kind) for every change, to assert on without depending on the wording."""
    return [(d["setting"], d["item"], c["path"], c["change"]) for d in result["differences"] for c in d["changes"]]


def write(snap: dict, path: Path) -> Path:
    snapshot_mod.write(snap, path)
    return path


def workflow_findings(repository: Path) -> list[tuple]:
    """What obaaf check reports about the workflows, leaving out the repository rules (CODEOWNERS)."""
    return [(f.rule, f.message) for f in checker.check(repository).findings if not f.rule.startswith("OBAAF-REPO-")]


class clean_env:
    def __enter__(self):
        self._patch = mock.patch.dict(os.environ, {})
        self._patch.start()
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPOSITORY"):
            os.environ.pop(name, None)

    def __exit__(self, *exc):
        self._patch.stop()


class SameSettingsTest(unittest.TestCase):
    def test_a_snapshot_matches_itself_and_a_later_reading_of_the_same_settings(self):
        for name, token, repository in (("admin-token", TOKEN, REPO), ("workflow-token", TOKEN, REPO),
                                        ("public-no-token", None, REPO),
                                        ("live-expectrail-no-token", None, "Expectrail/Expectrail"),
                                        ("live-obaaf-no-token", None, "Obaaf/OBAAF")):
            with self.subTest(name):
                first = take(name, token=token, repository=repository)
                later = take(name, token=token, repository=repository, now=LATER)
                result = drift.compare(first, later)
                self.assertEqual(result["differences"], [])
                self.assertEqual(result["not_compared"], [])
                self.assertFalse(drift.failed(result))
                self.assertGreater(result["summary"]["compared"], 0)

    def test_the_order_of_any_list_changes_nothing(self):
        """GitHub's order is kept inside a rule's parameters and a ruleset's conditions; it means nothing."""
        expected = expectrail()
        live = copy.deepcopy(expected)
        for ruleset in live["settings"]["rulesets"]["value"]:
            ruleset["rules"].reverse()
            for r in ruleset["rules"]:
                for value in (r["parameters"] or {}).values():
                    if isinstance(value, list):
                        value.reverse()
            ruleset["conditions"]["ref_name"]["include"].reverse()
        for found in live["settings"]["branch_rules"]["value"].values():
            found.reverse()
            for r in found:
                checks = (r["parameters"] or {}).get("required_status_checks")
                if checks:
                    checks.insert(0, checks.pop())
        live["settings"]["environments"]["value"].reverse()
        self.assertFalse(drift.failed(drift.compare(expected, live)))

    def test_the_snapshot_written_to_a_file_and_read_back_matches(self):
        snap = take()
        with TempDir() as tmp:
            again = snapshot_mod.load(write(snap, tmp / "s.json"))
        self.assertFalse(drift.failed(drift.compare(snap, again)))

    def test_every_setting_has_a_shape(self):
        self.assertEqual(set(drift.SHAPES), {s.key for s in settings_mod.SETTINGS})


class EachKindOfChangeTest(unittest.TestCase):
    """The incidents the first adopter had, and the settings the audit reads, changed one at a time."""

    def setUp(self):
        self.expected = take()
        self.live = copy.deepcopy(self.expected)

    def result(self):
        return drift.compare(self.expected, self.live)

    def test_an_environment_opened_to_every_branch(self):
        release = env(self.live, "release")
        release["deployment_branches"] = "any"
        del release["branch_policies"]
        found = changed(self.result())
        self.assertIn(("environments", "release", "deployment_branches", "changed"), found)
        self.assertIn(("environments", "release", "branch_policies", "removed"), found)
        self.assertEqual(len(self.result()["differences"]), 1)  # one environment, one finding

    def test_a_reviewer_removed_and_self_review_allowed(self):
        release = env(self.live, "release")
        release["reviewers"] = [r for r in release["reviewers"] if r["name"] != "octocat"]
        release["prevent_self_review"] = None
        found = changed(self.result())
        self.assertIn(("environments", "release", "reviewers[octocat]", "removed"), found)
        self.assertIn(("environments", "release", "prevent_self_review", "changed"), found)

    def test_a_bypass_actor_added_to_a_ruleset(self):
        self.live["settings"]["ruleset_bypass_actors"]["value"][0]["actors"].append(
            {"actor_type": "Integration", "actor_id": 99, "bypass_mode": "always"})
        self.assertEqual(changed(self.result()), [("ruleset_bypass_actors", "42", "actors[Integration, 99]", "added")])

    def test_required_approvals_lowered_and_a_required_check_dropped(self):
        ruleset = self.live["settings"]["rulesets"]["value"][0]
        rule(ruleset, "pull_request")["parameters"]["required_approving_review_count"] = 0
        rule(ruleset, "required_status_checks")["parameters"]["required_status_checks"] = []
        found = changed(self.result())
        self.assertIn(("rulesets", "42", "rules[pull_request].parameters.required_approving_review_count",
                       "changed"), found)
        self.assertIn(("rulesets", "42", 'rules[required_status_checks].parameters.required_status_checks["test (3.13)"]',
                       "removed"), found)

    def test_a_ruleset_switched_to_evaluate_or_removed(self):
        self.live["settings"]["rulesets"]["value"][0]["enforcement"] = "evaluate"
        self.assertEqual(changed(self.result()), [("rulesets", "42", "enforcement", "changed")])
        self.live["settings"]["rulesets"]["value"].pop(0)
        self.assertIn(("rulesets", "42", "", "removed"), changed(self.result()))

    def test_a_new_secret_a_new_environment_and_a_new_policy(self):
        self.live["settings"]["repository_secrets"]["value"].append("DEPLOY_KEY")
        self.live["settings"]["environments"]["value"].append(
            {"name": "staging", "deployment_branches": "any", "wait_timer": 0, "reviewers": [],
             "prevent_self_review": None, "other_protection_rules": [], "can_admins_bypass": None})
        policy = copy.deepcopy(self.live["settings"]["actions_policies"]["value"][0])
        policy["id"], policy["name"] = 8, "another"
        self.live["settings"]["actions_policies"]["value"].append(policy)
        found = changed(self.result())
        self.assertIn(("repository_secrets", "DEPLOY_KEY", "", "added"), found)
        self.assertIn(("environments", "staging", "", "added"), found)
        self.assertIn(("actions_policies", "8", "", "added"), found)

    def test_an_actions_policy_that_stops_allowing_an_event(self):
        allowed = rule(self.live["settings"]["actions_policies"]["value"][0], "restrict_action_events")
        allowed["parameters"]["allowed_events"] = ["workflow_dispatch"]
        self.assertEqual(changed(self.result()), [
            ("actions_policies", "7", "rules[restrict_action_events].parameters.allowed_events", "removed")])

    def test_token_permissions_pinning_and_fork_approval(self):
        value = self.live["settings"]
        value["workflow_permissions"]["value"]["default_workflow_permissions"] = "write"
        value["actions_permissions"]["value"]["sha_pinning_required"] = False
        value["fork_pull_requests"]["value"]["approval_policy"] = "first_time_contributors_new_to_github"
        found = changed(self.result())
        self.assertIn(("workflow_permissions", "default_workflow_permissions", "", "changed"), found)
        self.assertIn(("actions_permissions", "sha_pinning_required", "", "changed"), found)
        self.assertIn(("fork_pull_requests", "approval_policy", "", "changed"), found)

    def test_one_more_administrator(self):
        counts = self.live["settings"]["collaborators"]["value"]
        counts["total"] += 1
        counts["by_role"]["admin"] += 1
        self.assertEqual({(s, i) for s, i, _, _ in changed(self.result())},
                         {("collaborators", "total"), ("collaborators", "by_role")})

    def test_true_is_not_1_and_1_is_not_1_point_0(self):
        """Python says True == 1 and 1 == 1.0. A snapshot file can hold any of them."""
        value = self.live["settings"]["workflow_permissions"]["value"]
        value["can_approve_pull_request_reviews"] = 0
        self.assertTrue(drift.failed(self.result()))
        value["can_approve_pull_request_reviews"] = False
        env(self.live, "release")["wait_timer"] = 30.0
        self.assertEqual(changed(self.result()), [("environments", "release", "wait_timer", "changed")])

    def test_a_value_set_and_a_value_unknown_are_different(self):
        env(self.live, "release")["prevent_self_review"] = None
        self.assertTrue(drift.failed(self.result()))

    def test_duplicates_in_a_list_count(self):
        live = self.live["settings"]["actions_permissions"]["value"]["selected_actions"]["patterns_allowed"]
        live.append(live[0])
        self.assertEqual(changed(self.result()), [
            ("actions_permissions", "selected_actions", "patterns_allowed", "added")])

    def test_a_setting_that_starts_to_apply_is_a_difference(self):
        user_owned = copy.deepcopy(self.expected)
        user_owned["settings"]["organization_secrets"] = {"status": "not_applicable", "reason": "a user's"}
        found = changed(drift.compare(user_owned, self.live))
        self.assertIn(("organization_secrets", None, "", "status"), found)


class WhatCannotBeComparedTest(unittest.TestCase):
    def test_a_setting_the_expected_snapshot_holds_and_this_run_could_not_read_fails(self):
        expected = take()  # an administrator's token
        live = take("public-no-token", token=None)  # no token now
        result = drift.compare(expected, live)
        not_compared = {e["setting"] for e in result["not_compared"]}
        self.assertIn("environment_secrets", not_compared)
        self.assertIn("collaborators", not_compared)
        self.assertTrue(drift.failed(result))
        self.assertIn("different access", drift.to_text(result))

    def test_a_setting_the_expected_snapshot_did_not_read_is_not_covered_and_does_not_fail(self):
        expected = take("public-no-token", token=None)
        live = take("public-no-token", token=None, now=LATER)
        result = drift.compare(expected, live)
        self.assertFalse(drift.failed(result))
        self.assertIn("collaborators", {e["setting"] for e in result["not_covered"]})
        self.assertIn("NOT COVERED", drift.to_text(result))

    def test_a_part_this_run_could_not_read_is_not_compared_and_the_rest_is(self):
        expected = take()
        entries = recording("admin-token")
        for entry in entries:
            if entry["path"].endswith("/environments/release/deployment-branch-policies?per_page=100"):
                entry.update(status=500, body={"message": "Server Error"})
        live = take(entries=entries)
        self.assertEqual(live["settings"]["environments"]["status"], "partial")
        env(live, "main-only")["deployment_branches"] = "selected"  # and a real change elsewhere
        result = drift.compare(expected, live)
        self.assertEqual([(e["setting"], e["item"]) for e in result["not_compared"]], [("environments", "release")])
        self.assertEqual(changed(result), [("environments", "main-only", "deployment_branches", "changed")])
        self.assertTrue(drift.failed(result))

    def test_a_part_the_expected_snapshot_did_not_read_is_not_covered(self):
        expected = take()  # ruleset 73's bypass list was not read: GitHub sent an empty one
        self.assertEqual(expected["settings"]["ruleset_bypass_actors"]["status"], "partial")
        result = drift.compare(expected, copy.deepcopy(expected))
        self.assertEqual([(e["setting"], e["item"]) for e in result["not_covered"]], [("ruleset_bypass_actors", "73")])
        self.assertFalse(drift.failed(result))

    def test_every_bypass_actor_removed_is_not_compared_rather_than_no_drift(self):
        """GitHub's empty bypass list is never believed, so a ruleset whose last bypass actor went is a part
        this run could not read, not a ruleset nobody may bypass."""
        expected = take()
        entries = recording("admin-token")
        for entry in entries:
            if entry["path"].endswith("/rulesets/42?includes_parents=true"):
                entry["body"]["bypass_actors"] = []
        live = take(entries=entries)
        # Both lists are empty now, so neither is believed and the whole setting is unread.
        self.assertEqual(live["settings"]["ruleset_bypass_actors"]["status"], "unread")
        result = drift.compare(expected, live)
        self.assertIn(("ruleset_bypass_actors", None), [(e["setting"], e["item"]) for e in result["not_compared"]])
        self.assertTrue(drift.failed(result))

    def test_nothing_compared_is_not_a_pass(self):
        expected = take("public-no-token", token=None)
        for key, entry in expected["settings"].items():
            expected["settings"][key] = {"status": "unread", "reason_code": "network", "reason": "x", "needs": "y"}
        result = drift.compare(expected, take("public-no-token", token=None))
        self.assertEqual(result["summary"]["compared"], 0)
        self.assertTrue(drift.failed(result))
        self.assertIn("NOTHING COMPARED", drift.to_text(result))


class HolesInTheExpectedSnapshotTest(unittest.TestCase):
    """A part the committed snapshot did not read, by GitHub's doing or by an edit, must not hide a change
    that this run can see (found by the first review of the slice)."""

    def test_a_first_bypass_actor_added_where_the_expected_list_was_empty(self):
        expected = take()  # ruleset 73's bypass list came back empty, which is never believed
        entries = recording("admin-token")
        for entry in entries:
            if entry["path"].endswith("/rulesets/73?includes_parents=true"):
                entry["body"]["bypass_actors"] = [{"actor_type": "Integration", "actor_id": 99, "bypass_mode": "always"}]
        result = drift.compare(expected, take(entries=entries))
        self.assertIn(("ruleset_bypass_actors", "73"), [(e["setting"], e["item"]) for e in result["not_compared"]])
        self.assertTrue(drift.failed(result))

    def test_an_environment_the_expected_snapshot_read_only_in_part(self):
        entries = recording("admin-token")
        for entry in entries:
            if entry["path"].endswith("/environments/release/deployment-branch-policies?per_page=100"):
                entry.update(status=500, body={"message": "Server Error"})
        expected = take(entries=entries)  # a passing error while the snapshot was taken
        live = take()
        release = env(live, "release")
        release["deployment_branches"], release["reviewers"], release["wait_timer"] = "any", [], 0
        del release["branch_policies"]
        result = drift.compare(expected, live)
        self.assertIn(("environments", "release"), [(e["setting"], e["item"]) for e in result["not_compared"]])
        self.assertTrue(drift.failed(result))

    def test_a_problem_written_into_the_file_by_hand_hides_nothing(self):
        expected = take()
        live = copy.deepcopy(expected)
        live["settings"]["workflow_permissions"]["value"]["default_workflow_permissions"] = "write"
        forged = copy.deepcopy(expected)
        forged["settings"]["workflow_permissions"] = {
            "status": "partial", "value": forged["settings"]["workflow_permissions"]["value"],
            "problems": [{"key": "default_workflow_permissions", "what": "x", "reason_code": "network", "reason": "x"}],
            "needs": "x"}
        forged["settings"]["environments"] = {
            "status": "partial", "value": forged["settings"]["environments"]["value"],
            "problems": [{"key": "staging", "what": "x", "reason_code": "network", "reason": "x"}], "needs": "x"}
        live["settings"]["environments"]["value"].append(
            {"name": "staging", "deployment_branches": "any", "wait_timer": 0, "reviewers": [],
             "prevent_self_review": None, "other_protection_rules": [], "can_admins_bypass": None})
        self.assertEqual(snapshot_mod.problems(forged), [])
        result = drift.compare(forged, live)
        not_compared = [(e["setting"], e["item"]) for e in result["not_compared"]]
        self.assertIn(("workflow_permissions", "default_workflow_permissions"), not_compared)
        self.assertIn(("environments", "staging"), not_compared)
        self.assertTrue(drift.failed(result))

    def test_a_whole_setting_marked_as_not_read_in_the_file_hides_nothing(self):
        expected = take()
        live = copy.deepcopy(expected)
        env(live, "release")["reviewers"] = []
        expected["settings"]["environments"] = {"status": "unread", "reason_code": "network", "reason": "x",
                                                "needs": "x"}
        result = drift.compare(expected, live)
        self.assertIn(("environments", None), [(e["setting"], e["item"]) for e in result["not_compared"]])
        self.assertTrue(drift.failed(result))

    def test_a_token_that_reads_more_than_the_expected_snapshot_did_fails_until_it_is_taken_again(self):
        result = drift.compare(take("public-no-token", token=None), take())
        self.assertIn("collaborators", {e["setting"] for e in result["not_compared"]})
        self.assertIn("Take the expected snapshot again", drift.to_text(result))
        self.assertTrue(drift.failed(result))

    def test_numbers_that_python_takes_for_one_another_are_two_elements(self):
        expected = take()
        actors = expected["settings"]["ruleset_bypass_actors"]["value"][0]["actors"]
        actors.insert(0, {"actor_type": "RepositoryRole", "actor_id": 5.0, "bypass_mode": "always"})
        result = drift.compare(expected, take())
        self.assertEqual([c for _, _, _, c in changed(result)], ["removed"])
        self.assertTrue(drift.failed(result))

    def test_a_branch_only_one_side_audited_is_not_compared_not_new(self):
        live = take(branches=("release",), entries=recording("admin-token") + [
            {"path": f"/repos/{REPO}/rules/branches/release?per_page=100", "status": 200, "headers": {}, "body": []},
            {"path": f"/repos/{REPO}/branches/release", "status": 200, "headers": {},
             "body": {"name": "release", "protected": False}},
            {"path": f"/repos/{REPO}/branches/release/protection", "status": 404, "headers": {},
             "body": {"message": "Branch not protected"}}])
        result = drift.compare(take(), live)
        self.assertEqual(result["differences"], [])
        self.assertEqual({(e["setting"], e["item"]) for e in result["not_compared"]},
                         {("branch_rules", "release"), ("branches", "release"), ("branch_protection", "release")})
        self.assertIn("Branches: main in the expected snapshot; main, release now.", drift.to_text(result))



class CommittedFileTest(unittest.TestCase):
    """The expected snapshot is a committed file anyone can change in a pull request."""

    def run_files(self, expected: dict, live: dict, *extra: str):
        with TempDir() as tmp:
            write(expected, tmp / "expected.json")
            write(live, tmp / "live.json")
            return run_cli("audit", "--from-snapshot", tmp / "live.json", "--expected", tmp / "expected.json", *extra)

    def test_exit_codes(self):
        snap = take()
        code, out, err = self.run_files(snap, snap)
        self.assertEqual(code, 0, err)
        self.assertIn("NO DRIFT in the 15 setting(s) compared", out)
        self.assertIn("Settings audit of example-studio/game", out)  # the audit's own report follows
        changed_snap = copy.deepcopy(snap)
        env(changed_snap, "release")["wait_timer"] = 0
        code, out, err = self.run_files(snap, changed_snap)
        self.assertEqual(code, 1)
        self.assertIn("DRIFT: 1 part(s) of 1 setting(s)", out)
        self.assertIn("wait_timer: was 30, now 0", out)
        self.assertIn("1 difference(s)", err)

    def test_json_output(self):
        snap = take()
        changed_snap = copy.deepcopy(snap)
        changed_snap["settings"]["repository_secrets"]["value"] = []
        code, out, _ = self.run_files(snap, changed_snap, "--format", "json")
        self.assertEqual(code, 1)
        document = json.loads(out)
        self.assertEqual(document["format"], "obaaf-settings-drift/v0.1")
        self.assertEqual(document["rule"], "OBAAF-DRIFT-001")
        self.assertEqual(document["summary"]["findings"], 1)
        self.assertEqual(document["differences"][0]["changes"][0], {"path": "", "change": "removed", "expected": True})
        self.assertEqual(document["snapshot"]["settings"], changed_snap["settings"])

    def test_another_repository_or_another_server_is_refused(self):
        snap = take()
        other = take("live-expectrail-no-token", token=None, repository="Expectrail/Expectrail")
        code, _, err = self.run_files(snap, other)
        self.assertEqual(code, 2)
        self.assertIn("is of example-studio/game, not of Expectrail/Expectrail", err)
        elsewhere = copy.deepcopy(snap)
        elsewhere["api"] = "https://github.example.com/api/v3"
        code, _, err = self.run_files(elsewhere, snap)
        self.assertEqual(code, 2)
        self.assertIn("was read from", err)

    def test_a_renamed_repository_is_still_the_same_repository(self):
        snap = take()
        renamed = copy.deepcopy(snap)
        renamed["repository"], renamed["requested_as"] = "example-studio/game-2", "example-studio/game"
        renamed["settings"]["repository"]["value"]["full_name"] = "example-studio/game-2"
        code, out, _ = self.run_files(snap, renamed)
        self.assertEqual(code, 1)  # it is compared, and the new name is a difference
        self.assertIn("full_name: was", out)

    def test_two_parts_with_one_name_are_refused_not_merged(self):
        """The schema does not say names are unique; a file with two environments of one name would hide
        one of them behind the other."""
        snap = take()
        doubled = copy.deepcopy(snap)
        doubled["settings"]["environments"]["value"].append(copy.deepcopy(env(doubled, "release")))
        code, _, err = self.run_files(doubled, snap)
        self.assertEqual(code, 2)
        self.assertIn("two entries have the name \"release\"", err)
        doubled = copy.deepcopy(snap)
        doubled["settings"]["repository_secrets"]["value"] = ["A", "A"]
        code, _, err = self.run_files(doubled, snap)
        self.assertEqual(code, 2)
        self.assertIn("a name is listed twice", err)

    def test_a_file_that_is_not_a_snapshot_is_refused(self):
        with TempDir() as tmp:
            (tmp / "bad.json").write_text('{"format": "something else"}', encoding="utf-8")
            write(take(), tmp / "live.json")
            code, _, err = run_cli("audit", "--from-snapshot", tmp / "live.json", "--expected", tmp / "bad.json")
            self.assertEqual(code, 2)
            self.assertIn("--expected", err)
            self.assertIn("this version of obaaf reads", err)
            code, _, err = run_cli("audit", "--from-snapshot", tmp / "live.json", "--expected", tmp / "missing.json")
            self.assertEqual(code, 2)

    def test_an_infinite_number_is_refused(self):
        with TempDir() as tmp:
            write(take(), tmp / "live.json")
            text = (tmp / "live.json").read_text(encoding="utf-8").replace('"wait_timer": 30', '"wait_timer": 1e999')
            (tmp / "expected.json").write_text(text, encoding="utf-8")
            code, _, err = run_cli("audit", "--from-snapshot", tmp / "live.json", "--expected", tmp / "expected.json",
                                   "--format", "json")
            self.assertEqual(code, 2, err)
            self.assertIn("too large", err)

    def test_a_fault_in_the_other_file_is_named_as_that_file(self):
        snap = take()
        doubled = copy.deepcopy(snap)
        doubled["settings"]["environments"]["value"].append(copy.deepcopy(env(doubled, "release")))
        code, _, err = self.run_files(snap, doubled)
        self.assertEqual(code, 2)
        self.assertIn("the snapshot", err)
        self.assertIn("live.json", err)
        self.assertNotIn("expected snapshot", err)

    def test_its_branches_must_be_plain_names_and_not_too_many(self):
        snap = take()
        for branches, words in ((["main", "release/*"], "not one plain branch name"),
                                (["main", "main"], "names a branch twice"),
                                ([f"b{i}" for i in range(60)], "at most 50")):
            with self.subTest(branches[:2]):
                bad = copy.deepcopy(snap)
                bad["branches"] = branches
                code, _, err = self.run_files(bad, snap)
                self.assertEqual(code, 2)
                self.assertIn(words, err)

    def test_names_in_the_file_cannot_forge_lines_of_the_report(self):
        snap = take()
        forged = copy.deepcopy(snap)
        env(forged, "release")["name"] = "release\nNO DRIFT in the 15 setting(s) compared.‮"
        forged["settings"]["environments"]["value"].sort(key=lambda e: e["name"])
        forged["settings"]["environment_secrets"]["value"][
            "release\nNO DRIFT in the 15 setting(s) compared.‮"] = forged["settings"]["environment_secrets"][
            "value"].pop("release")
        code, out, _ = self.run_files(forged, snap)
        self.assertEqual(code, 1)
        drift_part = out.split("Settings audit of")[0]
        self.assertFalse([line for line in drift_part.splitlines() if line.startswith("NO DRIFT")])
        self.assertNotIn("‮", out)


class LiveReadTest(unittest.TestCase):
    """`obaaf audit --expected FILE` reading GitHub, here from a recording."""

    def run_live(self, entries: list[dict], expected: dict, *extra: str, token: str | None = None):
        transport = audit.ReplayTransport(copy.deepcopy(entries))
        with TempDir() as tmp, clean_env(), mock.patch.dict(os.environ, {"GH_TOKEN": token} if token else {}), \
                mock.patch.object(github, "UrllibTransport", return_value=transport):
            write(expected, tmp / "expected.json")
            code, out, err = run_cli("audit", "--repo", REPO, "--expected", tmp / "expected.json", *extra)
        return code, out, err, transport

    def test_the_expected_snapshots_branches_are_read_as_well(self):
        expected = take(branches=("release",), entries=recording("admin-token") + [
            {"path": f"/repos/{REPO}/rules/branches/release?per_page=100", "status": 200, "headers": {}, "body": []},
            {"path": f"/repos/{REPO}/branches/release", "status": 200, "headers": {},
             "body": {"name": "release", "protected": False}},
            {"path": f"/repos/{REPO}/branches/release/protection", "status": 404, "headers": {},
             "body": {"message": "Branch not protected"}}])
        self.assertEqual(expected["branches"], ["main", "release"])
        code, out, err, transport = self.run_live(recording("admin-token"), expected, token=TOKEN)
        self.assertIn(f"/repos/{REPO}/branches/release", transport.missing)  # it asked
        self.assertEqual(code, 1)
        self.assertIn("NOT COMPARED", out)  # and could not read it from this recording, so it fails

    def test_a_file_of_another_repository_stops_the_command_before_any_request(self):
        expected = take("live-expectrail-no-token", token=None, repository="Expectrail/Expectrail")
        code, _, err, transport = self.run_live(recording("admin-token"), expected, token=TOKEN)
        self.assertEqual(code, 2)
        self.assertEqual(transport.seen, [])
        self.assertIn("is of Expectrail/Expectrail", err)

    def test_a_live_read_that_matches(self):
        expected = take()
        code, out, err, _ = self.run_live(recording("admin-token"), expected, token=TOKEN)
        self.assertEqual(code, 0, err + out)
        self.assertIn("NO DRIFT", out)

    def test_with_snapshot_out_the_live_snapshot_is_kept(self):
        expected = take()
        transport = audit.ReplayTransport(copy.deepcopy(recording("admin-token")))
        with TempDir() as tmp, clean_env(), mock.patch.dict(os.environ, {"GH_TOKEN": TOKEN}), \
                mock.patch.object(github, "UrllibTransport", return_value=transport):
            write(expected, tmp / "expected.json")
            code, _, err = run_cli("audit", "--repo", REPO, "--expected", tmp / "expected.json",
                                   "--snapshot-out", tmp / "live.json")
            self.assertEqual(code, 0, err)
            self.assertEqual(snapshot_mod.load(tmp / "live.json")["settings"], expected["settings"])

    def test_the_repository_not_read_at_all_fails(self):
        expected = take()
        entries = [{"path": f"/repos/{REPO}", "status": 404, "headers": {}, "body": {"message": "Not Found"}}]
        code, out, err, _ = self.run_live(entries, expected, token=TOKEN)
        self.assertEqual(code, 1)
        self.assertIn("Nothing was audited", err)


class TemplateTest(unittest.TestCase):
    TEMPLATE = TEMPLATES / "optional" / "obaaf-settings-drift.yml"

    def test_the_template_runs_on_a_schedule_with_read_only_access_and_has_no_findings(self):
        text = self.TEMPLATE.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^  schedule:\n    - cron: ")
        self.assertIn("--expected", text)
        self.assertRegex(text, r"(?m)^permissions:\n  contents: read$")
        with TempDir() as tmp:
            wf = tmp / ".github" / "workflows"
            wf.mkdir(parents=True)
            installed = text.replace("OBAAF_OWNER/obaaf", "example-studio/obaaf").replace("0" * 40, TEST_SHA)
            (wf / "obaaf-settings-drift.yml").write_text(installed, encoding="utf-8")
            self.assertEqual(workflow_findings(tmp), [])

    def test_the_uninstalled_template_is_flagged_so_it_cannot_run_by_accident(self):
        with TempDir() as tmp:
            wf = tmp / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "obaaf-settings-drift.yml").write_text(self.TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
            self.assertIn("OBAAF-GHA-023", {f.rule for f in checker.check(tmp).findings})

    def test_this_repositorys_own_drift_workflow_has_no_findings(self):
        path = ROOT / ".github" / "workflows" / "settings-drift.yml"
        with TempDir() as tmp:
            wf = tmp / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            self.assertEqual(workflow_findings(tmp), [])


class GuideExampleTest(unittest.TestCase):
    """The example in docs/settings-audit.md is what the command prints for the changes it describes."""

    def test_the_guides_example_is_the_commands_output(self):
        expected = expectrail()
        now = copy.deepcopy(expected)
        main_only = env(now, "main-only")
        main_only["deployment_branches"] = "any"
        del main_only["branch_policies"]
        ruleset = now["settings"]["rulesets"]["value"][0]
        rule(ruleset, "pull_request")["parameters"]["required_approving_review_count"] = 1
        checks = rule(ruleset, "required_status_checks")["parameters"]["required_status_checks"]
        checks[:] = [c for c in checks if c["context"] != "test"]
        guide = (ROOT / "docs" / "settings-audit.md").read_text(encoding="utf-8")
        block = guide.split("## Drift\n", 1)[1].split("```text\n", 1)[1].split("```", 1)[0]
        with TempDir() as tmp:
            write(expected, tmp / "expected.json")
            write(now, tmp / "now.json")
            here = os.getcwd()
            os.chdir(tmp)
            try:
                code, out, _ = run_cli("audit", "--from-snapshot", "now.json", "--expected", "expected.json")
            finally:
                os.chdir(here)
        self.assertEqual(code, 1)
        printed = out.split("\nSettings audit of ", 1)[0].splitlines()
        shown = block.rstrip("\n").splitlines()
        cut = shown.index("  ...")  # the guide shortens the list of what is not covered
        self.assertEqual(shown[:cut], printed[:cut])
        self.assertEqual(shown[cut + 1:], printed[-len(shown) + cut + 1:])


class WordingTest(unittest.TestCase):
    def test_paths_name_list_elements_by_what_they_are(self):
        self.assertEqual(drift.path_text(["rules", ("pull_request",), "parameters", "x"]),
                         "rules[pull_request].parameters.x")
        self.assertEqual(drift.path_text(["a b", ("x y", 3)]), '"a b"["x y", 3]')
        self.assertEqual(drift.path_text(["a\nb"]), '"a\\nb"')

    def test_every_line_of_the_report_is_printable(self):
        expected = take()
        live = copy.deepcopy(expected)
        env(live, "release")["reviewers"][0]["name"] = "evil\x1b[2Jteam"
        text = drift.to_text(drift.compare(expected, live))
        self.assertIsNone(re.search(r"[\x00-\x09\x0b-\x1f\x7f]", text))


if __name__ == "__main__":
    unittest.main()
