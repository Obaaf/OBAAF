"""Flagship slice 2d.4b1: a called local reusable workflow is read with what its callers give it.

Before this slice, a workflow that another workflow of the same repository calls (`uses:
./.github/workflows/x.yml`) was read with its own trigger only, `workflow_call`. Its jobs got none of
the events that start the calling job, so a `pull_request_target` workflow that called a local
workflow which checks out the pull request's head got no OBAAF-GHA-002, and one that ran it on a
self-hosted runner got no OBAAF-GHA-013 (docs/bypass-attempts.md, slices 2d.2c and 2d.2d). And the
finding on a called agent job named only the parameter it reads (`secrets.MODEL_KEY`), never the
secret the caller maps onto it, so changing the mapping raised nothing (slice 2d.2b).

Now the checker reads every workflow file first, finds the jobs that call a workflow of the
repository, and gives each called workflow's jobs the events that can start each calling job, as
well as `workflow_call` (another repository may call it too). OBAAF-GHA-001 and OBAAF-GHA-005 name,
as a fact of the finding, what each caller passes for the secrets the called job reads.
"""

import os
import time
import unittest

from helpers import TempDir

from obaaf import checker
from obaaf.checker import baseline as baseline_mod

SHA = "1111111111111111111111111111111111111111"
HEAD_CHECKOUT = (f"      - uses: actions/checkout@{SHA}\n        with:\n"
                 "          ref: ${{ github.event.pull_request.head.sha }}\n          persist-credentials: false\n")


def build(tmp, files):
    root = tmp / "repo"
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def check(tmp, files, **kwargs):
    return checker.check(build(tmp, files), **kwargs)


def caller(on, uses="./.github/workflows/called.yml", extra="", job="call"):
    return f"on: {on}\npermissions: {{}}\njobs:\n  {job}:\n{extra}    uses: {uses}\n"


def called(steps=HEAD_CHECKOUT, runner="ubuntu-latest", on="workflow_call", job="work", extra=""):
    return (f"on: {on}\npermissions:\n  contents: read\njobs:\n  {job}:\n    runs-on: {runner}\n{extra}"
            f"    steps:\n{steps}")


def rules_on(result, path, job=None):
    return sorted({f.rule for f in result.findings
                   if f.path == path and (job is None or f.job == job)})


CALLED = ".github/workflows/called.yml"


class ACalledJobGetsItsCallersEventsTest(unittest.TestCase):

    def test_pull_request_target_reaches_a_checkout_of_the_head_in_the_called_workflow(self):
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": caller("pull_request_target"),
                                 CALLED: called()})
            (found,) = [f for f in result.findings if f.rule == "OBAAF-GHA-002"]
            self.assertEqual(found.path, CALLED)
            self.assertEqual(found.severity, "high")
            self.assertIn("pull_request_target", found.facts["triggers"])

    def test_without_the_caller_the_called_workflow_is_read_as_before(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLED: called()})
            self.assertNotIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_a_self_hosted_runner_reached_from_a_pull_request(self):
        # Attempt 027 of slice 2d.2d.
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": caller("pull_request"),
                                 CALLED: called(steps="      - run: make\n", runner="self-hosted")})
            self.assertIn("OBAAF-GHA-013", rules_on(result, CALLED, "work"))

    def test_a_self_hosted_runner_called_only_from_push_is_not_reported_for_pull_requests(self):
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": caller("push"),
                                 CALLED: called(steps="      - run: make\n", runner="self-hosted")})
            self.assertNotIn("OBAAF-GHA-013", rules_on(result, CALLED, "work"))

    def test_the_calling_jobs_if_narrows_the_events(self):
        with TempDir() as tmp:
            text = caller("[push, pull_request_target]", extra="    if: github.event_name == 'push'\n")
            result = check(tmp, {".github/workflows/caller.yml": text, CALLED: called()})
            self.assertNotIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_the_jobs_the_caller_needs_narrow_the_events(self):
        with TempDir() as tmp:
            text = ("on: [push, pull_request_target]\npermissions: {}\njobs:\n"
                    "  gate:\n    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n"
                    "    steps:\n      - run: true\n"
                    "  call:\n    needs: gate\n    uses: ./.github/workflows/called.yml\n")
            result = check(tmp, {".github/workflows/caller.yml": text, CALLED: called()})
            self.assertNotIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_the_called_jobs_own_if_narrows_the_callers_events(self):
        with TempDir() as tmp:
            text = called(extra="    if: github.event_name == 'push'\n")
            result = check(tmp, {".github/workflows/caller.yml": caller("[push, pull_request_target]"),
                                 CALLED: text})
            self.assertNotIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_two_callers_give_both_their_events(self):
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/a.yml": caller("push"),
                                 ".github/workflows/b.yml": caller("issue_comment"),
                                 CALLED: called()})
            (found,) = [f for f in result.findings if f.rule == "OBAAF-GHA-002"]
            self.assertIn("issue_comment", found.facts["triggers"])

    def test_a_chain_of_calls_carries_the_first_callers_events(self):
        with TempDir() as tmp:
            middle = ("on: workflow_call\npermissions: {}\njobs:\n  again:\n"
                      "    uses: ./.github/workflows/called.yml\n")
            result = check(tmp, {".github/workflows/a.yml": caller("pull_request_target",
                                                                     uses="./.github/workflows/middle.yml"),
                                 ".github/workflows/middle.yml": middle, CALLED: called()})
            self.assertIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_a_cycle_of_calls_ends_and_gives_every_file_the_events(self):
        # GitHub refuses a cycle; the checker must still end, and read the widest way.
        with TempDir() as tmp:
            one = ("on: [workflow_call, pull_request_target]\npermissions: {}\njobs:\n"
                   "  call:\n    uses: ./.github/workflows/two.yml\n")
            two = ("on: workflow_call\npermissions: {}\njobs:\n  back:\n    uses: ./.github/workflows/one.yml\n"
                   "  work:\n    runs-on: ubuntu-latest\n    steps:\n" + HEAD_CHECKOUT)
            result = check(tmp, {".github/workflows/one.yml": one, ".github/workflows/two.yml": two})
            self.assertIn("OBAAF-GHA-002", rules_on(result, ".github/workflows/two.yml"))

    def test_the_forms_of_a_local_call(self):
        forms = ["./.github/workflows/called.yml", "$/.github/workflows/called.yml",
                 "./.github/workflows/called.yml@main", " ./.github/workflows/called.yml ",
                 "./.github/workflows/../workflows/called.yml", ".\\.github\\workflows\\called.yml"]
        for uses in forms:
            with self.subTest(uses=uses), TempDir() as tmp:
                result = check(tmp, {".github/workflows/caller.yml": caller("pull_request_target",
                                                                              uses=repr(uses)),
                                     CALLED: called()})
                self.assertIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_a_call_that_leaves_the_repository_or_is_computed_gives_nothing(self):
        for uses in ["./../other/.github/workflows/called.yml", "./${{ inputs.file }}"]:
            with self.subTest(uses=uses), TempDir() as tmp:
                result = check(tmp, {".github/workflows/caller.yml": caller("pull_request_target",
                                                                              uses=repr(uses)),
                                     CALLED: called()})
                self.assertNotIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_a_ref_the_caller_passes_as_an_input_is_cannot_tell(self):
        # The caller's `with:` is not put in (left to slice 2d.4b3); an input in a checkout of a job an
        # outsider's event can start is "cannot tell" at medium, never nothing.
        steps = HEAD_CHECKOUT.replace("github.event.pull_request.head.sha", "inputs.ref")
        text = caller("pull_request_target") + "    with:\n      ref: ${{ github.event.pull_request.head.sha }}\n"
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": text, CALLED: called(steps=steps)})
        (found,) = [f for f in result.findings if f.rule == "OBAAF-GHA-002"]
        self.assertEqual((found.path, found.severity, found.kind), (CALLED, "medium", "checkout-unresolved"))

    def test_an_at_reading_outside_the_repository_does_not_drop_the_one_inside(self):
        # From the review: the path as written leads outside, the path before the `@` does not.
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": caller(
                "pull_request_target", uses="./.github/workflows/called.yml@../../../../../x"), CALLED: called()})
            self.assertIn("OBAAF-GHA-002", rules_on(result, CALLED))

    @unittest.skipIf(os.name == "nt", "links need privileges on Windows")
    def test_a_link_is_matched_by_its_own_name_only(self):
        # From the review: a link to the called file was given the events too, and every finding twice.
        with TempDir() as tmp:
            root = build(tmp, {".github/workflows/caller.yml": caller("pull_request_target"), CALLED: called()})
            os.symlink("called.yml", root / ".github/workflows/link.yml")
            result = checker.check(root)
            self.assertEqual([f.path for f in result.findings if f.rule == "OBAAF-GHA-002"], [CALLED])
            self.assertEqual(len([n for n in result.notes if "is called by" in n]), 1)

    def test_a_long_chain_with_an_event_at_each_level_is_quick(self):
        # From the review: each pass moved the events one file, and every pass worked every call out again.
        files = {}
        count = 300
        for level in range(count):
            name = f".github/workflows/w{count - level:05d}.yml"
            event = "".join(chr(97 + int(d)) for d in f"{level:04d}")
            if level == count - 1:
                files[name] = called(on=f"[workflow_call, ev_{event}]", steps="      - run: echo\n")
            else:
                files[name] = (f"on: [workflow_call, ev_{event}]\npermissions: {{}}\njobs:\n  call:\n"
                               f"    uses: ./.github/workflows/w{count - level - 1:05d}.yml\n")
        with TempDir() as tmp:
            start = time.monotonic()
            result = check(tmp, files)
            spent = time.monotonic() - start
        last = [n for n in result.notes if n.startswith(".github/workflows/w00001.yml")]
        self.assertEqual(len(last), 1)
        self.assertTrue(last[0].endswith(checker.wf_mod.OTHER_EVENT))
        self.assertLess(spent, 30)

    def test_a_long_chain_behind_a_cycle_is_quick(self):
        # From the second review: a chain behind a self-call was worked out again for each event (30 s for
        # 1,200 files before the fix, about 1.5 s after).
        count = 1200
        files = {".github/workflows/a00000.yml": (
            "on: [workflow_call, pull_request_target]\npermissions: {}\njobs:\n"
            "  self:\n    uses: ./.github/workflows/a00000.yml\n  next:\n    uses: ./.github/workflows/w00001.yml\n")}
        for level in range(1, count):
            event = "".join(chr(97 + int(d)) for d in f"{level:04d}")
            name = f".github/workflows/w{level:05d}.yml"
            if level == count - 1:
                files[name] = called(on=f"[workflow_call, ev_{event}]")
            else:
                files[name] = (f"on: [workflow_call, ev_{event}]\npermissions: {{}}\njobs:\n  call:\n"
                               f"    uses: ./.github/workflows/w{level + 1:05d}.yml\n")
        with TempDir() as tmp:
            start = time.monotonic()
            result = check(tmp, files)
            spent = time.monotonic() - start
        self.assertIn("OBAAF-GHA-002", rules_on(result, f".github/workflows/w{count - 1:05d}.yml"))
        self.assertLess(spent, 15)

    def test_an_event_github_does_not_document_is_passed_on_as_one(self):
        # From the third review: each file of a chain inventing its own event made every file hold every
        # name. A caller's undocumented events reach the called jobs as one stand-in, which no rule names.
        files = {".github/workflows/a.yml": caller("[ev_one, ev_two, pull_request_target]"), CALLED: called()}
        with TempDir() as tmp:
            result = check(tmp, files)
        (found,) = [f for f in result.findings if f.rule == "OBAAF-GHA-002"]
        self.assertEqual(found.facts["triggers"], ["pull_request_target"])
        (note,) = [n for n in result.notes if "is called by" in n]
        self.assertIn(checker.wf_mod.OTHER_EVENT, note)
        self.assertNotIn("ev_one", note)

    def test_every_file_of_a_cycle_gets_every_event_that_reaches_it(self):
        # From the second review: an `if:` on a call inside the cycle kept an event from a file of it.
        one = ("on: [workflow_call, push, pull_request_target]\npermissions: {}\njobs:\n"
               "  call:\n    if: github.event_name == 'push'\n    uses: ./.github/workflows/two.yml\n")
        two = ("on: workflow_call\npermissions: {}\njobs:\n  back:\n    uses: ./.github/workflows/one.yml\n"
               "  work:\n    runs-on: ubuntu-latest\n    steps:\n" + HEAD_CHECKOUT)
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/one.yml": one, ".github/workflows/two.yml": two})
        self.assertIn("OBAAF-GHA-002", rules_on(result, ".github/workflows/two.yml"))

    def test_every_event_a_rule_names_is_passed_on_as_itself(self):
        # From the fourth review: `commit_comment`, which OBAAF-GHA-010 names, was folded into the stand-in.
        from obaaf.checker import rules as rules_mod
        from obaaf.checker import workflow as wf_mod
        sets = [value for module in (wf_mod, rules_mod) for value in vars(module).values()
                if isinstance(value, (set, frozenset)) and value and all(isinstance(v, str) for v in value)]
        sets += [value for value in vars(rules_mod.WorkflowRules).values()
                 if isinstance(value, (set, frozenset)) and value and all(isinstance(v, str) for v in value)]
        named = set().union(*[s for s in sets if s & {"push", "pull_request", "workflow_run", "issue_comment",
                                                         "merge_group", "pull_request_target"}])
        self.assertTrue(named)
        self.assertEqual(sorted(named - wf_mod.GITHUB_EVENTS), [])

    def test_a_workflow_that_cannot_be_called_gets_no_events(self):
        # GitHub refuses to call a workflow without `on: workflow_call`, so its jobs never run from the call.
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": caller("pull_request_target"),
                                 CALLED: called(on="push")})
            self.assertNotIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_a_file_checked_on_its_own_knows_no_callers(self):
        with TempDir() as tmp:
            root = build(tmp, {".github/workflows/caller.yml": caller("pull_request_target"), CALLED: called()})
            result = checker.check(root, files=[root / CALLED])
            self.assertNotIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_both_files_checked_together_know_the_call(self):
        with TempDir() as tmp:
            root = build(tmp, {".github/workflows/caller.yml": caller("pull_request_target"), CALLED: called()})
            result = checker.check(root, files=[root / ".github/workflows/caller.yml", root / CALLED])
            self.assertIn("OBAAF-GHA-002", rules_on(result, CALLED))

    def test_lanes_follow_the_callers_events(self):
        # `--lanes` reads the files the way `check` does: a called job that applies the output of the run
        # that started its caller (`workflow_run`) is an effect job.
        steps = (f"      - uses: actions/download-artifact@{SHA}\n        with:\n"
                 "          run-id: ${{ github.event.workflow_run.id }}\n      - run: ./apply.sh\n")
        text = called(steps=steps).replace("contents: read", "contents: write")
        with TempDir() as tmp:
            root = build(tmp, {".github/workflows/caller.yml": caller("workflow_run"), CALLED: text})
            rows = checker.lanes(root, notes=[], errors=[], seen=[])
            by_job = {(path, job): lane for path, job, lane, _ in rows}
            self.assertEqual(by_job[(CALLED, "work")], "effect")
        with TempDir() as tmp:
            root = build(tmp, {CALLED: text})
            rows = checker.lanes(root, notes=[], errors=[], seen=[])
            self.assertEqual({job: lane for _, job, lane, _ in rows}["work"], "trusted")


AGENT_STEPS = (f"      - uses: actions/checkout@{SHA}\n        with:\n          persist-credentials: false\n"
               "      - run: claude -p 'review'\n        env:\n          ANTHROPIC_API_KEY: ${{ secrets.MODEL_KEY }}\n")


def agent_called(on="workflow_call"):
    return called(steps=AGENT_STEPS, on=on)


def mapping_caller(value, on="workflow_dispatch", job="call"):
    return (f"on: {on}\npermissions: {{}}\njobs:\n  {job}:\n    uses: ./.github/workflows/called.yml\n"
            f"    secrets:\n      MODEL_KEY: {value}\n")


class WhatTheCallerPassesIsPartOfTheFindingTest(unittest.TestCase):

    def gha005(self, files):
        with TempDir() as tmp:
            result = check(tmp, files)
        (found,) = [f for f in result.findings if f.rule == "OBAAF-GHA-005"]
        return found

    def test_the_mapped_secret_is_named(self):
        found = self.gha005({".github/workflows/caller.yml": mapping_caller("${{ secrets.PROD_DEPLOY_KEY }}"),
                             CALLED: agent_called()})
        self.assertIn("PROD_DEPLOY_KEY", found.message)
        self.assertIn(".github/workflows/caller.yml", found.message)
        self.assertTrue(any("PROD_DEPLOY_KEY" in entry for entry in found.facts["passed"]))

    def test_changing_the_mapping_changes_the_finding(self):
        # The way past OBAAF-GHA-005 that slice 2d.2b recorded: an acceptance of the finding must not
        # cover a caller that maps another secret onto the parameter.
        one = self.gha005({".github/workflows/caller.yml": mapping_caller("${{ secrets.ANTHROPIC_API_KEY }}"),
                           CALLED: agent_called()})
        two = self.gha005({".github/workflows/caller.yml": mapping_caller("${{ secrets.PROD_DEPLOY_KEY }}"),
                           CALLED: agent_called()})
        self.assertNotEqual(baseline_mod.key(one), baseline_mod.key(two))

    def test_adding_a_caller_changes_the_finding(self):
        one = self.gha005({".github/workflows/a.yml": mapping_caller("${{ secrets.ANTHROPIC_API_KEY }}"),
                           CALLED: agent_called()})
        two = self.gha005({".github/workflows/a.yml": mapping_caller("${{ secrets.ANTHROPIC_API_KEY }}"),
                           ".github/workflows/b.yml": mapping_caller("${{ secrets.PROD_DEPLOY_KEY }}"),
                           CALLED: agent_called()})
        self.assertNotEqual(baseline_mod.key(one), baseline_mod.key(two))
        self.assertIn("PROD_DEPLOY_KEY", two.message)

    def test_the_parameter_is_matched_in_any_case(self):
        text = mapping_caller("${{ secrets.PROD_DEPLOY_KEY }}").replace("MODEL_KEY:", "model_key:")
        found = self.gha005({".github/workflows/caller.yml": text, CALLED: agent_called()})
        self.assertIn("PROD_DEPLOY_KEY", found.message)

    def test_a_parameter_the_job_does_not_read_is_left_out(self):
        text = mapping_caller("${{ secrets.ANTHROPIC_API_KEY }}") + "      OTHER: ${{ secrets.PROD_DEPLOY_KEY }}\n"
        found = self.gha005({".github/workflows/caller.yml": text, CALLED: agent_called()})
        self.assertNotIn("PROD_DEPLOY_KEY", found.message)
        self.assertIn("ANTHROPIC_API_KEY", found.message)

    def test_a_job_that_reads_every_secret_names_every_parameter_passed(self):
        steps = AGENT_STEPS.replace("${{ secrets.MODEL_KEY }}", "${{ toJSON(secrets) }}")
        text = mapping_caller("${{ secrets.ANTHROPIC_API_KEY }}") + "      OTHER: ${{ secrets.PROD_DEPLOY_KEY }}\n"
        found = self.gha005({".github/workflows/caller.yml": text, CALLED: called(steps=steps)})
        self.assertIn("PROD_DEPLOY_KEY", found.message)

    def test_secrets_inherit(self):
        text = "on: workflow_dispatch\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n"
        found = self.gha005({".github/workflows/caller.yml": text, CALLED: agent_called()})
        self.assertIn("secrets: inherit", found.message)
        self.assertTrue(found.facts["passed"])

    def test_a_token_passed_as_a_secret_is_named(self):
        found = self.gha005({".github/workflows/caller.yml": mapping_caller("${{ secrets.GITHUB_TOKEN }}"),
                             CALLED: agent_called()})
        self.assertIn("GITHUB_TOKEN", found.message)

    def test_a_value_that_names_no_secret_is_shown_as_written(self):
        found = self.gha005({".github/workflows/caller.yml": mapping_caller("${{ github.token }}"),
                             CALLED: agent_called()})
        self.assertIn("github.token", found.message)

    def test_a_caller_that_passes_nothing_for_it_adds_nothing(self):
        text = "on: workflow_dispatch\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n"
        found = self.gha005({".github/workflows/caller.yml": text, CALLED: agent_called()})
        self.assertNotIn("passed", found.facts)

    def test_without_callers_the_finding_is_what_it_was(self):
        found = self.gha005({CALLED: agent_called()})
        self.assertNotIn("passed", found.facts)
        self.assertEqual(found.message, "Agent job 'work' receives MODEL_KEY.")

    def test_a_chain_of_callers_is_followed_to_the_first(self):
        # A maps a secret onto MODEL_KEY for B, and B passes its MODEL_KEY on to the agent's workflow:
        # changing A's mapping must change the finding on the agent's job.
        middle = ("on:\n  workflow_call:\n    secrets:\n      MODEL_KEY:\n        required: true\n"
                  "permissions: {}\njobs:\n  again:\n    uses: ./.github/workflows/called.yml\n"
                  "    secrets:\n      MODEL_KEY: ${{ secrets.MODEL_KEY }}\n")
        first = mapping_caller("${{ secrets.ANTHROPIC_API_KEY }}").replace("called.yml", "middle.yml")
        one = self.gha005({".github/workflows/a.yml": first, ".github/workflows/middle.yml": middle,
                           CALLED: agent_called()})
        two = self.gha005({".github/workflows/a.yml": first.replace("ANTHROPIC_API_KEY", "PROD_DEPLOY_KEY"),
                           ".github/workflows/middle.yml": middle, CALLED: agent_called()})
        self.assertIn("ANTHROPIC_API_KEY", one.message)
        self.assertIn("PROD_DEPLOY_KEY", two.message)
        self.assertNotEqual(baseline_mod.key(one), baseline_mod.key(two))

    def test_a_chain_through_secrets_inherit_is_followed(self):
        middle = ("on: workflow_call\npermissions: {}\njobs:\n  again:\n    uses: ./.github/workflows/called.yml\n"
                  "    secrets: inherit\n")
        first = mapping_caller("${{ secrets.PROD_DEPLOY_KEY }}").replace("called.yml", "middle.yml")
        found = self.gha005({".github/workflows/a.yml": first, ".github/workflows/middle.yml": middle,
                             CALLED: agent_called()})
        self.assertIn("PROD_DEPLOY_KEY", found.message)
        self.assertIn("secrets: inherit", found.message)

    def test_a_cycle_of_mappings_ends(self):
        one = ("on: [workflow_call, workflow_dispatch]\npermissions: {}\njobs:\n  call:\n"
               "    uses: ./.github/workflows/called.yml\n    secrets:\n      MODEL_KEY: ${{ secrets.MODEL_KEY }}\n")
        text = agent_called() + ("  back:\n    uses: ./.github/workflows/one.yml\n"
                                 "    secrets:\n      MODEL_KEY: ${{ secrets.MODEL_KEY }}\n")
        found = self.gha005({".github/workflows/one.yml": one, CALLED: text})
        self.assertIn(".github/workflows/one.yml", found.message)

    def test_a_key_that_is_not_text_is_taken_for_every_name(self):
        # From the review: `null:` was read as NONE, so changing what it maps kept an acceptance.
        for key in ["null", "NULL", "true", "12"]:
            with self.subTest(key=key):
                one = self.gha005({".github/workflows/caller.yml": mapping_caller(
                    "${{ secrets.ANTHROPIC }}").replace("MODEL_KEY:", f"{key}:"), CALLED: agent_called()})
                two = self.gha005({".github/workflows/caller.yml": mapping_caller(
                    "${{ secrets.PROD }}").replace("MODEL_KEY:", f"{key}:"), CALLED: agent_called()})
                self.assertIn("PROD", two.message)
                self.assertNotEqual(baseline_mod.key(one), baseline_mod.key(two))

    def test_a_key_with_space_round_it_is_read_without_it(self):
        text = mapping_caller("${{ secrets.PROD_DEPLOY_KEY }}").replace("MODEL_KEY:", "' MODEL_KEY ':")
        found = self.gha005({".github/workflows/caller.yml": text, CALLED: agent_called()})
        self.assertIn("PROD_DEPLOY_KEY", found.message)

    def test_what_callers_pass_is_bounded(self):
        # From the review: one entry per caller and key, for every called job, made a 290 KB repository
        # print 249 MB. Past five entries the finding names three and a digest of all of them.
        keys = "".join(f"      K{i}: ${{{{ secrets.S{i} }}}}\n" for i in range(400))
        text = ("on: workflow_dispatch\npermissions: {}\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n"
                "    secrets:\n" + keys)
        steps = AGENT_STEPS.replace("${{ secrets.MODEL_KEY }}", "${{ toJSON(secrets) }}")
        jobs = "".join(f"  j{i}:\n    runs-on: ubuntu-latest\n    steps:\n{steps}" for i in range(50))
        many = "on: workflow_call\npermissions:\n  contents: read\njobs:\n" + jobs
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": text, CALLED: many})
        found = [f for f in result.findings if f.rule == "OBAAF-GHA-005"]
        self.assertEqual(len(found), 50)
        self.assertLess(max(len(f.message) for f in found), 1200)
        self.assertEqual(len(found[0].facts["passed"]), 4)
        self.assertIn("400 entries", found[0].facts["passed"][-1])
        changed = text.replace("secrets.S399 ", "secrets.OTHER ")
        with TempDir() as tmp:
            again = check(tmp, {".github/workflows/caller.yml": changed, CALLED: many})
        other = [f for f in again.findings if f.rule == "OBAAF-GHA-005"]
        self.assertNotEqual(baseline_mod.key(found[0]), baseline_mod.key(other[0]))

    def test_one_long_entry_is_bounded_too(self):
        # From the second review: one value naming 2,000 secrets made each entry 14 KB, for every job.
        value = "".join(f"${{{{ secrets.A{i} }}}}" for i in range(2000))
        text = mapping_caller(f'"{value}"')
        jobs = "".join(f"  j{i}:\n    runs-on: ubuntu-latest\n    steps:\n{AGENT_STEPS}" for i in range(20))
        many = "on: workflow_call\npermissions:\n  contents: read\njobs:\n" + jobs
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": text, CALLED: many})
        found = [f for f in result.findings if f.rule == "OBAAF-GHA-005"]
        self.assertEqual(len(found), 20)
        self.assertLess(max(len(f.message) for f in found), 1500)
        self.assertLess(max(sum(len(e) for e in f.facts["passed"]) for f in found), 1500)
        with TempDir() as tmp:
            again = check(tmp, {".github/workflows/caller.yml": text.replace("A1999", "B1999"), CALLED: many})
        other = [f for f in again.findings if f.rule == "OBAAF-GHA-005"]
        self.assertNotEqual(baseline_mod.key(found[0]), baseline_mod.key(other[0]))

    def test_gha018_every_secret_names_what_is_passed(self):
        steps = "      - run: make sign\n        env:\n          K: ${{ toJSON(secrets) }}\n"
        text = mapping_caller("${{ secrets.PROD_RELEASE }}").replace("MODEL_KEY:", "SIGN:")
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": text, CALLED: called(steps=steps)})
        found = [f for f in result.findings if f.rule == "OBAAF-GHA-018" and f.path == CALLED]
        self.assertEqual([f.kind for f in found], ["any-secret"])
        self.assertIn("PROD_RELEASE", found[0].message)

    def test_gha018_names_what_is_passed(self):
        steps = "      - run: make sign\n        env:\n          K: ${{ secrets.SIGNING_KEY }}\n"
        text = mapping_caller("${{ secrets.RELEASE_GPG }}").replace("MODEL_KEY:", "SIGNING_KEY:")
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": text, CALLED: called(steps=steps)})
        found = [f for f in result.findings if f.rule == "OBAAF-GHA-018" and f.kind == "secrets" and f.path == CALLED]
        self.assertEqual(len(found), 1)
        self.assertIn("RELEASE_GPG", found[0].message)

    def test_gha001_names_what_is_passed_too(self):
        with TempDir() as tmp:
            result = check(tmp, {".github/workflows/caller.yml": mapping_caller("${{ secrets.PROD_DEPLOY_KEY }}",
                                                                                 on="pull_request_target"),
                                 CALLED: called(steps="      - run: make\n        env:\n"
                                                      "          K: ${{ secrets.MODEL_KEY }}\n")})
        found = [f for f in result.findings if f.rule == "OBAAF-GHA-001" and f.path == CALLED]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")
        self.assertIn("PROD_DEPLOY_KEY", found[0].message)


if __name__ == "__main__":
    unittest.main()
