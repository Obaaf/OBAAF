"""The settings audit on the first adopter, 2026-11-13 (flagship slice 2b.4).

tests/fixtures/settings/live-expectrail-2026-11-13/ holds GitHub's answers to a caller with no token about
Expectrail/Expectrail and the snapshot the audit made of them, both as the live workflow printed them
(.github/workflows/settings-audit-live.yml, run 43399109471, 2026-11-13 09:10 UTC). docs/expectrail-settings-
audit.md is the record of that run. These tests hold the record to the data: the snapshot is what the answers
give, and what the page says the settings were is what the snapshot says. The findings that depend on the
adopter's workflow files are not repeated here: those files are another project's and are not copied into
this one. The page says how to make that part of the report again from the snapshot and a clone.
"""

import json
import unittest
from datetime import datetime, timezone

from helpers import ROOT
from test_settings_audit import SETTINGS_DIR

from obaaf import audit
from obaaf.audit import cli as audit_cli, report, rules, snapshot as snapshot_mod, workflows

FIXTURE = SETTINGS_DIR / "live-expectrail-2026-11-13"
PAGE = ROOT / "docs" / "expectrail-settings-audit.md"
TAKEN = datetime(2026, 11, 13, 9, 10, 57, tzinfo=timezone.utc)
ADOPTER = "Expectrail/Expectrail"


def committed() -> dict:
    return snapshot_mod.load(str(FIXTURE / "snapshot.json"))


def replayed() -> dict:
    client = audit.Client(transport=audit.ReplayTransport.load(FIXTURE), token=None)
    return audit.take(client, ADOPTER, (), now=TAKEN)


def without_files(snap: dict) -> dict:
    return rules.evaluate(snap, workflows.not_read("not part of this test"))


def results(assessment: dict, rule: str) -> list[dict]:
    return [r for r in assessment["results"] if r["rule"] == rule]


def status(assessment: dict, rule: str) -> str:
    return next(r["status"] for r in assessment["rules"] if r["id"] == rule)


class TheRecordIsGitHubsAnswersTest(unittest.TestCase):
    def test_the_snapshot_is_valid_and_of_the_adopter_read_with_no_token(self):
        snap = committed()
        self.assertEqual(snapshot_mod.problems(snap), [])
        self.assertEqual(snap["repository"], ADOPTER)
        self.assertEqual(snap["taken_at"], "2026-11-13T09:10:57Z")
        self.assertFalse(snap["viewer"]["authenticated"])

    def test_the_snapshot_is_what_the_recorded_answers_give(self):
        # The page's reproduction starts from the snapshot; this ties the snapshot to GitHub's own answers.
        snap, again = committed(), replayed()
        self.assertEqual(again["settings"], snap["settings"])
        self.assertEqual(again["branches"], snap["branches"])
        self.assertEqual(again["requests"], snap["requests"])

    def test_the_recording_holds_eight_get_answers_and_nothing_a_token_could_be_in(self):
        data = json.loads((FIXTURE / "responses.json").read_text(encoding="utf-8"))
        self.assertEqual(data["format"], "obaaf-api-recording/v0.1")
        self.assertEqual(len(data["responses"]), 8)
        headers = {name.lower() for entry in data["responses"] for name in entry["headers"]}
        self.assertFalse(headers & {"authorization", "cookie", "set-cookie"})


class WhatThePageSaysTest(unittest.TestCase):
    def setUp(self):
        self.page = PAGE.read_text(encoding="utf-8")
        self.snap = committed()

    def test_the_read_block_is_the_reports_own_to_the_character(self):
        usage = workflows.not_read("not part of this test")
        text = report.to_text(self.snap, assessment=rules.evaluate(self.snap, usage), usage=usage)
        block = text.split("READ: 5 of 15\n")[1].split("\n\n")[0]
        quoted = self.page.split("```text\nREAD: 5 of 15\n")[1].split("```")[0]
        self.assertEqual(quoted.rstrip("\n"), block.rstrip("\n"))

    def test_the_unread_settings_are_the_ten_the_page_names(self):
        unread = report.unread_keys(self.snap)
        self.assertEqual(sorted(unread), sorted([
            "ruleset_bypass_actors", "branch_protection", "environment_secrets", "repository_secrets",
            "organization_secrets", "actions_permissions", "workflow_permissions", "fork_pull_requests",
            "actions_policies", "collaborators"]))
        settings = self.snap["settings"]
        self.assertEqual(settings["ruleset_bypass_actors"]["reason_code"], "withheld")
        self.assertEqual({settings[k]["reason_code"] for k in unread if k != "ruleset_bypass_actors"}, {"no_token"})
        self.assertIn("Not read (10 of 15)", self.page)
        self.assertIn("**10 of the 15 settings were not read**", self.page)

    def test_the_rules_that_read_settings_only_answer_as_the_page_says(self):
        assessment = without_files(self.snap)
        self.assertEqual(status(assessment, "OBAAF-SET-004"), "cannot-tell")
        self.assertEqual([r["subject"] for r in results(assessment, "OBAAF-SET-004")],
                         ['branch "main": ruleset 26914817 "Protect main"'])
        self.assertEqual(status(assessment, "OBAAF-SET-005"), "not-applicable")
        self.assertEqual(status(assessment, "OBAAF-SET-013"), "cannot-tell")
        self.assertIn('ruleset "Protect main"', self.page)
        self.assertIn('"Protect main" now requires 0 approvals', self.page)

    def test_the_environment_unity_is_as_the_page_describes_it(self):
        environments = {e["name"]: e for e in self.snap["settings"]["environments"]["value"]}
        self.assertEqual(sorted(environments), ["github-pages", "main-only", "unity"])
        unity = environments["unity"]
        self.assertEqual([(r["type"], r["name"]) for r in unity["reviewers"]], [("User", "seanudeke")])
        self.assertIs(unity["prevent_self_review"], False)
        self.assertIs(unity["can_admins_bypass"], True)
        self.assertEqual(unity["deployment_branches"], "any")
        for name in ("github-pages", "main-only"):
            self.assertEqual(environments[name]["reviewers"], [], name)
        self.assertIn("one required reviewer (`seanudeke`), self-review allowed, and administrators allowed to "
                      "bypass", self.page)

    def test_twelve_checks_are_required_and_package_is_the_one_added_since_the_first_reading(self):
        def required(snap):
            return [c["context"] for rule in snap["settings"]["branch_rules"]["value"]["main"]
                    if rule["type"] == "required_status_checks"
                    for c in rule["parameters"]["required_status_checks"]]

        now = required(self.snap)
        self.assertEqual(len(now), 12)
        self.assertIn("12 checks are required", self.page)
        client = audit.Client(transport=audit.ReplayTransport.load(SETTINGS_DIR / "live-expectrail-no-token"),
                              token=None)
        before = required(audit.take(client, ADOPTER, (), now=TAKEN))
        self.assertEqual(sorted(set(now) - set(before)), ["package"])
        self.assertEqual(sorted(set(before) - set(now)), [])

    def test_the_commit_and_the_run_are_named(self):
        self.assertIn("36a7a8aeb9b041ae70d481310bafe1d7a89d9fb5", self.page)
        self.assertIn("actions/runs/43399109471", self.page)
        self.assertIn("tests/fixtures/settings/live-expectrail-2026-11-13/snapshot.json", self.page)

    def test_the_reproduction_command_parses(self):
        line = next(l.strip() for l in self.page.splitlines() if l.strip().startswith("obaaf audit expectrail"))
        import argparse

        parser = argparse.ArgumentParser()
        audit_cli.add_parser(parser.add_subparsers())
        args = parser.parse_args(line.split()[1:])
        self.assertEqual(args.path, "expectrail")
        self.assertTrue((ROOT / args.from_snapshot).is_file())


if __name__ == "__main__":
    unittest.main()
