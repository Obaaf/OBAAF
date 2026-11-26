"""Custom deployment protection rules beside OBAAF-SET-001, 002 and 003 (flagship slice 2b.9b, issue #212 item 2).

A custom deployment protection rule is a GitHub App that must approve a job naming an environment before the
job runs. GitHub lists an environment's rules at GET /repos/{owner}/{repo}/environments/{environment_name}/
deployment_protection_rules (REST reference "Deployment protection rules", API version 2026-03-10, read on
2026-11-26): {"total_count", "custom_deployment_protection_rules": [{"id", "node_id", "enabled", "app": {"id",
"node_id", "slug", "integration_url"}}]}. The answers here are written by hand in that shape; none is GitHub's.

What the rules make of such a rule: a gate whose decisions the audit cannot read. Beside a finding that required
reviewers leave standing (an environment any branch may use) it makes the finding medium and is named; a finding
reviewers would have suppressed becomes "cannot tell"; OBAAF-SET-002 and OBAAF-SET-003's open copy become
"cannot tell". Where the rules were not read (an earlier snapshot, a failed answer) each rule keeps its finding
and says that it may overstate.
"""

import copy
import unittest

from helpers import TempDir
from test_settings_audit import R, REPO, TOKEN, entry_for, ok, recording, take
from test_settings_bypasses import assess, changed, environment, extra_branch, job, of, wf, with_environments

from obaaf.audit import drift, report, rules, settings as settings_mod, snapshot as snapshot_mod, workflows

ADMIN = recording("admin-token")
CUSTOM = settings_mod.CUSTOM_RULES
MAIN_ONLY_RULES = f"{R}/environments/main-only/deployment_protection_rules?per_page=100"
RELEASE_RULES = f"{R}/environments/release/deployment_protection_rules?per_page=100"
GATE = 'a custom deployment protection rule run by the app "a-custom-app"'
AGENT = {"a.yml": wf("  push:\n", job("agent", "    environment: production\n",
                                       "      - run: ./a\n        env:\n          K: ${{ secrets.DEPLOY_KEY }}\n"))}
OUTSIDERS = {"t.yml": wf("  pull_request_target:\n", job("triage", "    environment: production\n",
                                                          "      - run: ./t\n        env:\n"
                                                          "          K: ${{ secrets.DEPLOY_KEY }}\n"))}


def rules_answer(*apps, enabled=True, count=None) -> dict:
    """GitHub's answer, in the reference's shape, listing a rule for each app slug."""
    items = [{"id": n, "node_id": "DPR_x", "enabled": enabled,
              "app": {"id": 100 + n, "node_id": "A_x", "slug": app,
                      "integration_url": f"https://api.github.com/apps/{app}"}} for n, app in enumerate(apps, 1)]
    return {"total_count": len(items) if count is None else count, "custom_deployment_protection_rules": items}


def answered_with(entries, path, body=None, status=200) -> list[dict]:
    out = copy.deepcopy(entries)
    entry_for(out, path).update(status=status, body=body)
    return out


def production(mode=None, reviewers=False, policies=(), custom=(), other_types=(), secrets=("DEPLOY_KEY",)):
    """The recording with one environment, "production", holding the secrets named."""
    env = environment("production", mode, reviewers)
    env["protection_rules"].extend({"id": 9, "node_id": "x", "type": kind} for kind in other_types)
    return with_environments(ADMIN, [env], policies={"production": list(policies)} if mode else None,
                             secrets={"production": list(secrets)}, custom={"production": list(custom)})


def evaluate(snap: dict, files: dict, config: str | None = None) -> dict:
    """The rules on a snapshot given as it is (an earlier version's, or one changed by a test)."""
    with TempDir() as tmp:
        root = tmp / "repo"
        (root / ".github" / "workflows").mkdir(parents=True)
        for name, text in files.items():
            (root / ".github" / "workflows" / name).write_text(text, encoding="utf-8")
        if config is not None:
            (root / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")
        return rules.evaluate(snap, workflows.read(root))


def before_the_slice(snap: dict) -> dict:
    """The snapshot as a version before slice 2b.9b would have written it: no custom rules field."""
    out = copy.deepcopy(snap)
    for env in out["settings"]["environments"]["value"]:
        env.pop(CUSTOM, None)
    return out


def result(found: dict, rule_id: str) -> dict:
    results = of(found, rule_id)
    assert len(results) == 1, results
    return results[0]


class ReaderTest(unittest.TestCase):
    def test_each_rule_is_recorded_by_its_app_and_whether_it_is_enabled(self):
        entries = answered_with(ADMIN, MAIN_ONLY_RULES, rules_answer("zeta-gate", "a-custom-app"))
        snap, transport = take(entries, token=TOKEN)
        self.assertEqual(transport.missing, [])
        main_only = next(e for e in snap["settings"]["environments"]["value"] if e["name"] == "main-only")
        self.assertEqual(main_only[CUSTOM], [{"app": "a-custom-app", "app_id": 102, "enabled": True},
                                             {"app": "zeta-gate", "app_id": 101, "enabled": True}])
        self.assertEqual(snap["settings"]["environments"]["status"], "read")
        self.assertEqual(snapshot_mod.problems(snap), [])
        self.assertNotIn("integration_url", snapshot_mod.dumps(snap))
        self.assertNotIn("DPR_x", snapshot_mod.dumps(snap))

    def test_none_is_an_empty_list_and_every_environment_is_asked(self):
        snap, transport = take(ADMIN, token=TOKEN)
        asked = [p for p, _ in transport.seen if p.endswith("/deployment_protection_rules?per_page=100")]
        self.assertEqual(asked, [MAIN_ONLY_RULES, RELEASE_RULES])
        self.assertEqual([e[CUSTOM] for e in snap["settings"]["environments"]["value"]], [[], []])
        # Without a token too: GitHub's reference says anyone may read it for a public repository.
        snap, transport = take(recording("public-no-token"))
        self.assertEqual([e[CUSTOM] for e in snap["settings"]["environments"]["value"]], [[], []])
        self.assertFalse([h for _, h in transport.seen if "Authorization" in h])

    def test_a_refused_answer_is_not_read_for_that_environment_and_the_rest_is_kept(self):
        for status, code in ((403, "forbidden"), (404, "not_found"), (500, "server_error"), (429, "rate_limited")):
            entries = answered_with(ADMIN, RELEASE_RULES, {"message": "no"}, status=status)
            snap, _ = take(entries, token=TOKEN)
            envs = snap["settings"]["environments"]
            self.assertEqual(envs["status"], "partial", status)
            problem, = envs["problems"]
            self.assertEqual((problem["key"], problem["reason_code"]), ("release", code), status)
            self.assertEqual(problem["what"], 'the custom deployment protection rules of environment "release"')
            main_only, release = envs["value"]
            self.assertIsNone(release[CUSTOM])
            self.assertEqual(main_only[CUSTOM], [])
            # Its branch patterns were read all the same.
            self.assertEqual(release["branch_policies"], [{"name": "main", "type": "branch"},
                                                          {"name": "release/*", "type": None}])

    def test_an_answer_of_another_shape_is_not_read_never_none(self):
        bad = {
            "no list": {"total_count": 0},
            "a count that disagrees": rules_answer("a-custom-app", count=2),
            "no count": {"custom_deployment_protection_rules": []},
            "no enabled": {"total_count": 1, "custom_deployment_protection_rules": [
                {"id": 1, "app": {"id": 2, "slug": "a"}}]},
            "enabled as text": rules_answer("a-custom-app", enabled="true"),
            "enabled as null": rules_answer("a-custom-app", enabled=None),
            "no app": {"total_count": 1, "custom_deployment_protection_rules": [{"id": 1, "enabled": True}]},
            "no slug": {"total_count": 1, "custom_deployment_protection_rules": [
                {"id": 1, "enabled": True, "app": {"id": 2}}]},
            "a slug that is not text": {"total_count": 1, "custom_deployment_protection_rules": [
                {"id": 1, "enabled": True, "app": {"id": 2, "slug": 5}}]},
            "an app id that is not a number": {"total_count": 1, "custom_deployment_protection_rules": [
                {"id": 1, "enabled": True, "app": {"id": "2", "slug": "a"}}]},
            "an item that is not an object": {"total_count": 1, "custom_deployment_protection_rules": ["a"]},
            "a list": [],
        }
        for label, body in bad.items():
            snap, _ = take(answered_with(ADMIN, MAIN_ONLY_RULES, body), token=TOKEN)
            envs = snap["settings"]["environments"]
            main_only, release = envs["value"]
            self.assertIsNone(main_only[CUSTOM], label)
            self.assertEqual(release[CUSTOM], [], label)
            self.assertEqual([(p["key"], p["reason_code"]) for p in envs["problems"]], [("main-only", "unexpected")],
                             label)
            self.assertEqual(snapshot_mod.problems(snap), [], label)

    def test_a_rule_marked_not_enabled_is_kept_as_it_came(self):
        snap, _ = take(answered_with(ADMIN, MAIN_ONLY_RULES, rules_answer("a-custom-app", enabled=False)), token=TOKEN)
        self.assertEqual(snap["settings"]["environments"]["value"][0][CUSTOM],
                         [{"app": "a-custom-app", "app_id": 101, "enabled": False}])

    def test_the_environment_name_is_one_encoded_path_segment(self):
        env = environment("a/../b c")
        entries = with_environments(ADMIN, [env])
        snap, transport = take(entries, token=TOKEN)
        self.assertIn(f"{R}/environments/a%2F..%2Fb%20c/deployment_protection_rules?per_page=100",
                      [p for p, _ in transport.seen])

    def test_the_schema_holds_the_field_to_its_shape(self):
        snap, _ = take(answered_with(ADMIN, MAIN_ONLY_RULES, rules_answer("a-custom-app")), token=TOKEN)
        for label, value in (("an app that is not text", [{"app": 5, "app_id": 1, "enabled": True}]),
                             ("enabled missing", [{"app": "a", "app_id": 1}]),
                             ("a field more", [{"app": "a", "app_id": 1, "enabled": True, "url": "x"}]),
                             ("not a list", "a")):
            changed_snap = copy.deepcopy(snap)
            changed_snap["settings"]["environments"]["value"][0][CUSTOM] = value
            self.assertNotEqual(snapshot_mod.problems(changed_snap), [], label)
        # An earlier snapshot, which has no such field, is still a snapshot.
        self.assertEqual(snapshot_mod.problems(before_the_slice(snap)), [])


class EnvironmentAnyBranchMayUseTest(unittest.TestCase):
    """OBAAF-SET-001 beside a custom rule: the finding stands, at medium, and names the app."""

    def test_a_custom_rule_makes_the_any_branch_finding_medium_and_is_named(self):
        finding = result(assess(production(custom=["a-custom-app"]), AGENT), "OBAAF-SET-001")
        self.assertEqual((finding["state"], finding["severity"]), ("finding", "medium"))
        self.assertIn("Any branch or tag may use the environment", finding["message"])
        self.assertIn(f"It has no required reviewers. Its protection is {GATE}, whose decisions the audit does "
                      "not read.", finding["message"])

    def test_with_reviewers_both_are_named(self):
        finding = result(assess(production(reviewers=True, custom=["a-custom-app"]), AGENT), "OBAAF-SET-001")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn(f"Its protection is its required reviewers, and {GATE}, whose decisions", finding["message"])

    def test_without_one_it_is_high_as_before_and_says_nothing_of_custom_rules(self):
        finding = result(assess(production(), AGENT), "OBAAF-SET-001")
        self.assertEqual(finding["severity"], "high")
        self.assertTrue(finding["message"].endswith("It has no required reviewers."), finding["message"])

    def test_a_rule_marked_not_enabled_counts_for_nothing(self):
        entries = with_environments(ADMIN, [environment("production")], secrets={"production": ["DEPLOY_KEY"]})
        path = f"{R}/environments/production/deployment_protection_rules?per_page=100"
        entries = answered_with(entries, path, rules_answer("a-custom-app", enabled=False))
        self.assertEqual(result(assess(entries, AGENT), "OBAAF-SET-001")["severity"], "high")

    def test_an_environment_that_holds_no_secret_stays_low(self):
        finding = result(assess(production(custom=["a-custom-app"], secrets=()), AGENT), "OBAAF-SET-001")
        self.assertEqual(finding["severity"], "low")

    def test_a_wide_pattern_is_weighed_the_same(self):
        found = assess(production("custom", policies=[("*", "branch")], custom=["a-custom-app"]), AGENT)
        finding = result(found, "OBAAF-SET-001")
        self.assertEqual((finding["state"], finding["severity"]), ("finding", "medium"))
        self.assertIn("lets nearly every branch through", finding["message"])
        self.assertIn(GATE, finding["message"])

    def test_a_protection_rule_of_a_type_this_version_does_not_know_is_weighed_the_same(self):
        finding = result(assess(production(other_types=["something_new"]), AGENT), "OBAAF-SET-001")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn('a protection rule of the type "something_new", which this version does not know',
                      finding["message"])


class NarrowerLimitTest(unittest.TestCase):
    """OBAAF-SET-001's findings that required reviewers suppress are "cannot tell" beside a custom rule."""

    def test_a_tag_pattern_beside_a_custom_rule_is_cannot_tell(self):
        plain = assess(production("custom", policies=[("v*", "tag")]), AGENT)
        self.assertEqual(result(plain, "OBAAF-SET-001")["state"], "finding")
        gated = result(assess(production("custom", policies=[("v*", "tag")], custom=["a-custom-app"]), AGENT),
                       "OBAAF-SET-001")
        self.assertEqual(gated["state"], "cannot-tell")
        self.assertIn('may be used from tag pattern "v*"', gated["message"])
        self.assertIn(f"Its protection is {GATE}, whose decisions the audit does not read, so whether a job there "
                      "gets the environment without anyone's approval is not known.", gated["message"])

    def test_a_branch_anyone_can_push_to_beside_a_custom_rule_is_cannot_tell(self):
        # "dev" is audited and has no rule: anyone with write access can push there.
        plain = assess(extra_branch(production("custom", policies=[("dev", "branch")]), "dev"), AGENT, branches=("dev",))
        self.assertEqual(result(plain, "OBAAF-SET-001")["state"], "finding")
        gated = result(assess(extra_branch(production("custom", policies=[("dev", "branch")], custom=["a-custom-app"]),
                                           "dev"), AGENT, branches=("dev",)), "OBAAF-SET-001")
        self.assertEqual(gated["state"], "cannot-tell")
        self.assertIn("names the environment. Its protection is", gated["message"])

    def test_reviewers_still_suppress_it_with_or_without_a_custom_rule(self):
        for custom in ((), ["a-custom-app"]):
            found = assess(production("custom", reviewers=True, policies=[("v*", "tag")], custom=custom), AGENT)
            self.assertEqual(of(found, "OBAAF-SET-001"), [], custom)

    def test_an_unknown_protection_rule_type_is_weighed_the_same(self):
        gated = result(assess(production("custom", policies=[("v*", "tag")], other_types=["something_new"]), AGENT),
                       "OBAAF-SET-001")
        self.assertEqual(gated["state"], "cannot-tell")


class OutsidersTest(unittest.TestCase):
    """OBAAF-SET-002: an environment with a custom rule does not ask nobody."""

    def test_a_custom_rule_makes_it_cannot_tell(self):
        plain = result(assess(production(), OUTSIDERS), "OBAAF-SET-002")
        self.assertEqual((plain["state"], plain["severity"]), ("finding", "high"))
        gated = result(assess(production(custom=["a-custom-app"]), OUTSIDERS), "OBAAF-SET-002")
        self.assertEqual(gated["state"], "cannot-tell")
        self.assertIn(f"The environment has no required reviewers, but its protection is {GATE}, whose decisions "
                      "the audit does not read", gated["message"])

    def test_reviewers_still_clear_it(self):
        self.assertEqual(of(assess(production(reviewers=True, custom=["a-custom-app"]), OUTSIDERS), "OBAAF-SET-002"),
                         [])


class OpenCopyTest(unittest.TestCase):
    """OBAAF-SET-003: a copy of a protected secret in an environment behind a custom rule is "cannot tell"."""

    CONFIG = "protected_secrets:\n  DEPLOY_KEY: production\n"
    FILES = {"d.yml": wf("  push:\n", job("deploy", "    environment: production\n"))}

    def entries(self, custom):
        entries = with_environments(ADMIN, [environment("production", "custom"), environment("staging"),
                                            environment("qa")],
                                    policies={"production": [("main", "branch")]},
                                    secrets={"production": ["DEPLOY_KEY"], "staging": ["DEPLOY_KEY"],
                                             "qa": ["DEPLOY_KEY"]},
                                    custom=custom)
        return changed(entries, f"{R}/actions/secrets?per_page=100", lambda body: body.update(total_count=0, secrets=[]))

    def secret(self, custom):
        found = assess(self.entries(custom), self.FILES, config=self.CONFIG)
        return [r for r in of(found, "OBAAF-SET-003") if r["subject"] == 'secret "DEPLOY_KEY"']

    def test_both_copies_behind_custom_rules_is_cannot_tell(self):
        res, = self.secret({"staging": ["a-custom-app"], "qa": ["b-gate"]})
        self.assertEqual(res["state"], "cannot-tell")
        self.assertIn('also stored in the environment "qa", "staging"', res["message"])
        self.assertIn('run by the app "b-gate"', res["message"])
        self.assertIn('run by the app "a-custom-app"', res["message"])

    def test_one_open_copy_is_still_a_finding_and_names_only_it(self):
        res, = self.secret({"staging": ["a-custom-app"]})
        self.assertEqual((res["state"], res["severity"]), ("finding", "high"))
        self.assertIn('also stored in the environment "qa", which any branch', res["message"])
        self.assertNotIn("staging", res["message"])

    def test_without_custom_rules_both_copies_are_the_finding(self):
        res, = self.secret({})
        self.assertEqual((res["state"], res["severity"]), ("finding", "high"))
        self.assertIn('"qa", "staging"', res["message"])


class NotReadTest(unittest.TestCase):
    """Where the custom rules were not read, each rule keeps the finding it gives without one, and says so."""

    def test_a_snapshot_taken_before_the_slice_keeps_todays_findings_with_a_clause(self):
        snap, _ = take(production(), token=TOKEN)
        now = evaluate(snap, AGENT)
        earlier = evaluate(before_the_slice(snap), AGENT)
        finding, before = result(now, "OBAAF-SET-001"), result(earlier, "OBAAF-SET-001")
        self.assertEqual((before["state"], before["severity"]), ("finding", "high"))
        self.assertEqual(before["message"], finding["message"] + (
            " Whether a custom deployment protection rule also stands in the way is not known (its custom deployment "
            "protection rules were not read: the snapshot was taken by a version of obaaf that did not read them); "
            "with one, this finding may overstate what is open."))
        outsiders = result(evaluate(before_the_slice(snap), OUTSIDERS), "OBAAF-SET-002")
        self.assertEqual((outsiders["state"], outsiders["severity"]), ("finding", "high"))
        self.assertIn("this finding may overstate what is open", outsiders["message"])

    def test_an_answer_that_failed_keeps_the_finding_with_a_clause(self):
        path = f"{R}/environments/production/deployment_protection_rules?per_page=100"
        entries = answered_with(production(), path, {"message": "Not Found"}, status=404)
        for files, rule_id in ((AGENT, "OBAAF-SET-001"), (OUTSIDERS, "OBAAF-SET-002")):
            finding = result(assess(entries, files), rule_id)
            self.assertEqual((finding["state"], finding["severity"]), ("finding", "high"), rule_id)
            self.assertIn("(its custom deployment protection rules could not be read)", finding["message"])
        for policies in ([("v*", "tag")], [("dev", "branch")]):
            entries = answered_with(production("custom", policies=policies), path, {"message": "no"}, status=403)
            finding = result(assess(extra_branch(entries, "dev"), AGENT, branches=("dev",)), "OBAAF-SET-001")
            self.assertEqual((finding["state"], finding["severity"]), ("finding", "medium"), policies)
            self.assertIn("could not be read", finding["message"])

    def test_an_open_copy_in_an_earlier_snapshot_keeps_its_finding_with_a_clause(self):
        entries = OpenCopyTest().entries({})
        snap, _ = take(entries, token=TOKEN)
        res = [r for r in of(evaluate(before_the_slice(snap), OpenCopyTest.FILES, OpenCopyTest.CONFIG),
                              "OBAAF-SET-003") if r["subject"] == 'secret "DEPLOY_KEY"']
        self.assertEqual([(r["state"], r["severity"]) for r in res], [("finding", "high")])
        self.assertIn("this finding may overstate what is open", res[0]["message"])


class ReportTest(unittest.TestCase):
    def line(self, snap: dict, name: str) -> str:
        text = report.to_text(snap)
        return next(line.strip() for line in text.splitlines() if line.strip().startswith(f'"{name}": '))

    def test_the_environment_line_names_each_app_and_what_was_not_read(self):
        entries = answered_with(ADMIN, MAIN_ONLY_RULES, rules_answer("a-custom-app", "b-gate"))
        entries = answered_with(entries, RELEASE_RULES, {"message": "no"}, status=403)
        snap, _ = take(entries, token=TOKEN)
        self.assertEqual(self.line(snap, "main-only"),
                         '"main-only": any branch or tag may deploy; no required reviewers; custom deployment '
                         'protection rules: app "a-custom-app", app "b-gate"; administrators may bypass these '
                         'rules: not given')
        self.assertIn("; custom deployment protection rules: not read; administrators", self.line(snap, "release"))
        self.assertIn("; custom deployment protection rules: not read (this snapshot predates them)",
                      self.line(before_the_slice(snap), "main-only"))

    def test_a_rule_not_enabled_is_said_so_and_none_says_nothing(self):
        snap, _ = take(answered_with(ADMIN, MAIN_ONLY_RULES, rules_answer("a-custom-app", enabled=False)),
                       token=TOKEN)
        self.assertIn('custom deployment protection rules: app "a-custom-app" (not enabled)', self.line(snap, "main-only"))
        self.assertNotIn("custom deployment", self.line(snap, "release"))


class DriftTest(unittest.TestCase):
    def snapshots(self, live_entries=ADMIN, expected_entries=ADMIN):
        return take(expected_entries, token=TOKEN)[0], take(live_entries, token=TOKEN)[0]

    def test_a_custom_rule_added_or_removed_is_drift(self):
        expected, live = self.snapshots(answered_with(ADMIN, MAIN_ONLY_RULES, rules_answer("a-custom-app")))
        found = drift.compare(expected, live)
        self.assertEqual([(d["setting"], d["item"], c["path"], c["change"]) for d in found["differences"]
                          for c in d["changes"]], [("environments", "main-only", CUSTOM, "added")])
        back = drift.compare(live, expected)
        self.assertEqual([c["change"] for d in back["differences"] for c in d["changes"]], ["removed"])
        self.assertTrue(drift.failed(found) and drift.failed(back))

    def test_the_same_rules_match(self):
        entries = answered_with(ADMIN, MAIN_ONLY_RULES, rules_answer("a-custom-app"))
        self.assertFalse(drift.failed(drift.compare(*self.snapshots(entries, entries))))

    def test_an_expected_snapshot_taken_before_the_slice_is_not_compared_for_its_environments(self):
        expected, live = self.snapshots()
        found = drift.compare(before_the_slice(expected), live)
        self.assertTrue(drift.failed(found))
        self.assertEqual(found["differences"], [])
        self.assertEqual(sorted((e["item"], e["reason_code"]) for e in found["not_compared"]),
                         [("main-only", "not_recorded"), ("release", "not_recorded")])
        self.assertEqual(found["outcomes"]["environments"], "in part")
        text = drift.to_text(found)
        self.assertIn("did not read custom deployment protection rules", text)
        self.assertIn("Take the expected snapshot again", text)
        # The other settings are compared as before.
        self.assertEqual({k for k, v in found["outcomes"].items() if v == "matches"},
                         {k for k, v in drift.compare(expected, live)["outcomes"].items() if v == "matches"}
                         - {"environments"})

    def test_a_part_one_side_did_not_read_is_never_a_change(self):
        # Both read the environment "release" in part: the expected snapshot's custom rules failed, and this
        # run's branch patterns. Neither missing part is a change; a real change in the rest still is.
        expected_entries = answered_with(ADMIN, RELEASE_RULES, {"message": "no"}, status=403)
        live_entries = answered_with(ADMIN, f"{R}/environments/release/deployment-branch-policies?per_page=100",
                                     {"message": "no"}, status=403)
        expected, live = self.snapshots(live_entries, expected_entries)
        found = drift.compare(expected, live)
        self.assertEqual(found["differences"], [])
        self.assertIn("release", [e["item"] for e in found["not_covered"]])
        live_env = next(e for e in live["settings"]["environments"]["value"] if e["name"] == "release")
        live_env["wait_timer"] = 5
        found = drift.compare(expected, live)
        self.assertEqual([(d["item"], c["path"]) for d in found["differences"] for c in d["changes"]],
                         [("release", "wait_timer")])

    def test_rules_not_read_now_are_not_compared(self):
        expected, live = self.snapshots(answered_with(ADMIN, MAIN_ONLY_RULES, {"message": "no"}, status=500))
        found = drift.compare(expected, live)
        self.assertEqual([(e["item"], e["reason_code"]) for e in found["not_compared"]], [("main-only", "server_error")])
        self.assertTrue(drift.failed(found))


if __name__ == "__main__":
    unittest.main()
