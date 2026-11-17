"""The settings audit's gaps found by the fourth review of slice 2d.2g (issue #182), fixed in flagship slice 2b.7.

1. A call written as `uses: ./` alone was not compared, and `$/` calls were taken for another repository's.
2. A job id outside GitHub's form gave "no finding" for a file GitHub refuses, and let a job id forge a problem
   that the audit lets through.
3. An empty list of selected actions (`allowed_actions: selected`) was read as letting every action run.
4. The loop that spreads "may not run" to the callers of a workflow cost the square of a chain's length.

Each test fails on the commit before the fix, except those marked as holding before and after.
"""

import copy
import time
import unittest

from test_settings_audit import R, TOKEN, take
from test_settings_bypasses import (ACTIONS_PERMISSIONS, ADMIN, MATRIX_313, PIN, PR, WORKFLOW_PERMISSIONS, answer,
                                    answered, assess, environment, job, of, requiring, wf, with_environments)

from obaaf.audit import rules, workflows

SELECTED = f"{R}/actions/permissions/selected-actions"
SHA = "a" * 40
W = ".github/workflows/"


def selected(patterns=(), github_owned=False, verified=False, entries=ADMIN):
    """The repository allows only selected actions, with this list (pinning not required)."""
    out = answer(entries, ACTIONS_PERMISSIONS, {"enabled": True, "allowed_actions": "selected",
                                                "selected_actions_url": "https://api.github.com/x"})
    return answer(out, SELECTED, {"github_owned_allowed": github_owned, "verified_allowed": verified,
                                  "patterns_allowed": list(patterns)})


def steps(*uses):
    return "".join(f"      - uses: {u}\n" for u in uses) + "      - run: echo\n"


class CallsThatWereNotComparedTest(unittest.TestCase):
    """Item 1: `uses: ./` alone, and calls written with `$/`."""

    def test_a_call_to_dot_slash_alone_is_a_call_to_a_file_that_was_not_read(self):
        files = {"ci.yml": wf(PR, job("lint") + "  ci:\n    uses: ./\n")}
        found = assess(requiring("lint"), files)
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")
        stopped, maybe, _, _ = self._stops(files)
        self.assertIn('"./"', maybe[W + "ci.yml"])
        self.assertIn("not among the workflow files that were read", maybe[W + "ci.yml"])

    def test_a_dollar_slash_call_to_a_missing_workflow(self):
        files = {"ci.yml": wf(PR, job("lint") + "  ci:\n    uses: $/.github/workflows/missing.yml\n")}
        self.assertEqual(answered(assess(requiring("lint"), files), "OBAAF-SET-006"), "cannot-tell")

    def test_a_dollar_slash_call_to_a_workflow_that_was_read_is_never_counted_as_running(self):
        files = {"ci.yml": wf(PR, "  ci:\n    uses: $/.github/workflows/r.yml\n"),
                 "r.yml": wf("  workflow_call:\n", job("test"))}
        found = assess(requiring("ci / test"), files)
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")
        _, maybe, _, _ = self._stops(files)
        self.assertIn("written with $/", maybe[W + "ci.yml"])
        # The called job learns its caller's events, as for `./` (the widest reading for the rules about
        # which events reach a job).
        usage = self._usage(files)
        called = next(f for f in usage["files"] if f["path"] == W + "r.yml")["jobs"][0]
        self.assertEqual(called["called_from"], ["pull_request"])

    def test_dot_slash_calls_read_as_before(self):
        # Holds before and after: a `./` call to a workflow that was read is compared and counted.
        files = {"ci.yml": wf(PR, "  ci:\n    uses: ./.github/workflows/r.yml\n"),
                 "r.yml": wf("  workflow_call:\n", job("test"))}
        self.assertEqual(answered(assess(requiring("ci / test"), files), "OBAAF-SET-006"), "no-finding")

    def test_a_dollar_slash_call_is_not_another_repositorys_under_local_only(self):
        entries = answer(ADMIN, ACTIONS_PERMISSIONS, {"enabled": True, "allowed_actions": "local_only"})
        files = {"ci.yml": wf(PR, job("lint") + "  ci:\n    uses: $/.github/workflows/r.yml\n"),
                 "r.yml": wf("  workflow_call:\n", job("test"))}
        _, maybe, _, _ = self._stops(files, entries)
        self.assertNotIn("local_only", maybe[W + "ci.yml"])
        self.assertIn("written with $/", maybe[W + "ci.yml"])

    def test_a_dollar_slash_caller_never_covers_a_called_workflows_token(self):
        # OBAAF-SET-012: a workflow only other workflows start gets its callers' token. A `./` caller that
        # declares its permissions covers it; a `$/` caller beside it that declares none uncovers it.
        called = wf("  workflow_call:\n", job("test"), permissions="")
        declared = "    permissions:\n      contents: read\n"
        covered = {"a.yml": wf(PR, "  ci:\n" + declared + "    uses: ./.github/workflows/r.yml\n"), "r.yml": called}
        mixed = dict(covered, **{"b.yml": wf(PR, "  ci:\n    uses: $/.github/workflows/r.yml\n", permissions="")})
        only_dollar = {"a.yml": wf(PR, "  ci:\n" + declared + "    uses: $/.github/workflows/r.yml\n"), "r.yml": called}
        writes = answer(ADMIN, WORKFLOW_PERMISSIONS, {"default_workflow_permissions": "write",
                                                      "can_approve_pull_request_reviews": False})
        self.assertEqual(of(assess(writes, covered), "OBAAF-SET-012", subject="r.yml"), [])
        self.assertEqual(answered(assess(writes, mixed), "OBAAF-SET-012", "r.yml"), "finding medium")
        # Holds before and after: a `$/` caller alone never covered it.
        self.assertEqual(answered(assess(writes, only_dollar), "OBAAF-SET-012", "r.yml"), "finding medium")

    def test_a_workflow_called_with_dollar_slash_is_read_for_the_events_that_reach_it(self):
        # OBAAF-SET-002: before, the caller was "cannot tell" (the call was taken for another repository's) and
        # the called job was never reached by pull_request_target; it is now, as with `./`.
        entries = with_environments(ADMIN, [environment("prod")], secrets={"prod": ["DEPLOY_TOKEN"]})
        called = wf("  workflow_call:\n", job("deploy", "    environment: prod\n",
                                               steps="      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n"))
        for prefix in ("./", "$/"):
            files = {"ci.yml": wf("  pull_request_target:\n", f"  ci:\n    uses: {prefix}.github/workflows/d.yml\n"),
                     "d.yml": called}
            found = assess(entries, files)
            self.assertEqual(answered(found, "OBAAF-SET-002", "d.yml#deploy"), "finding high", prefix)
            self.assertEqual(of(found, "OBAAF-SET-002", "cannot-tell", "ci.yml"), [], prefix)

    def test_a_dollar_slash_call_that_passes_every_secret_is_read(self):
        # OBAAF-SET-011: before, "cannot tell" (the called workflow was taken for another repository's).
        entries = with_environments(ADMIN, [environment("prod")], secrets={"prod": ["DEPLOY_TOKEN"]})
        called = wf("  workflow_call:\n", job("deploy", steps="      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n"))
        for prefix in ("./", "$/"):
            files = {"ci.yml": wf("  push:\n", f"  ci:\n    uses: {prefix}.github/workflows/d.yml\n"
                                              "    secrets: inherit\n"), "d.yml": called}
            self.assertEqual(answered(assess(entries, files), "OBAAF-SET-011", "ci.yml#ci"), "finding medium", prefix)

    def _usage(self, files):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".github" / "workflows"
            target.mkdir(parents=True)
            for name, text in files.items():
                (target / name).write_text(text, encoding="utf-8")
            return workflows.read(tmp)

    def _stops(self, files, entries=ADMIN):
        snap, _ = take(entries, token=TOKEN)
        run = rules._Run(rules.RULES[0], snap, self._usage(files))
        return rules._stops(run)


class JobIdsTest(unittest.TestCase):
    """Item 2: job ids outside GitHub's form."""

    CI = wf(PR, job("test", MATRIX_313))

    def ci_with(self, job_id: str, body: str = "    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n") -> str:
        return self.CI + f"  {job_id}:\n{body}"

    def test_an_id_github_refuses_makes_the_file_one_it_refuses(self):
        for job_id in ('"bad id"', "1abc", "-x", '"a.b"', '"a:b"', '"x\'y"', '"tab\\there"'):
            usage = CallsThatWereNotComparedTest()._usage({"ci.yml": self.ci_with(job_id)})
            file, = usage["files"]
            self.assertIn("is not in GitHub's form for one", file["error"] or "", job_id)
            self.assertIn("GitHub refuses such a file", file["error"], job_id)
            self.assertEqual(file["jobs"], [], job_id)
            found = assess(requiring("test (3.13)"), {"ci.yml": self.ci_with(job_id)})
            self.assertNotEqual(answered(found, "OBAAF-SET-006"), "no-finding", job_id)

    def test_ids_in_githubs_form_read_as_before(self):
        # Holds before and after.
        for job_id in ("_x", "a-b_c", "A1", "lint"):
            usage = CallsThatWereNotComparedTest()._usage({"ci.yml": self.ci_with(job_id)})
            self.assertIsNone(usage["files"][0]["error"], job_id)
            self.assertEqual(usage["files"][0]["doubt"], [], job_id)
            self.assertEqual(answered(assess(requiring("test (3.13)"), {"ci.yml": self.ci_with(job_id)}),
                                      "OBAAF-SET-006"), "no-finding", job_id)

    def test_an_id_with_a_character_outside_ascii_or_100_long_is_a_doubt(self):
        for job_id, words in (("café", "outside ASCII"), ("x" * 100, "100 or more")):
            usage = CallsThatWereNotComparedTest()._usage({"ci.yml": self.ci_with(job_id)})
            file, = usage["files"]
            self.assertIsNone(file["error"])
            self.assertTrue(any(words in d for d in file["doubt"]), (job_id, file["doubt"]))
            found = assess(requiring("test (3.13)"), {"ci.yml": self.ci_with(job_id)})
            self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell", job_id)
        usage = CallsThatWereNotComparedTest()._usage({"ci.yml": self.ci_with("x" * 99)})
        self.assertEqual(usage["files"][0]["doubt"], [])

    def test_a_job_id_cannot_forge_a_problem_the_audit_lets_through(self):
        # The checker quotes the id in its problems; an id that ends like the harmless problem about an input's
        # name made the problem that follows it (here: `uses` that is not text) read as harmless.
        forged = '"a'"'"', step 1 has an input name with a letter outside ASCII (z"'
        text = self.ci_with(forged, "    uses: [1]\n")
        found = assess(requiring("test (3.13)"), {"ci.yml": text})
        self.assertNotEqual(answered(found, "OBAAF-SET-006"), "no-finding")
        file, = CallsThatWereNotComparedTest()._usage({"ci.yml": text})["files"]
        self.assertIn("GitHub refuses such a file", file["error"] or "")


class SelectedActionsTest(unittest.TestCase):
    """Item 3: `allowed_actions: selected`. Only GitHub's own actions (where allowed) and an entry that is the
    reference itself are matched; anything else is a file GitHub may refuse."""

    def check(self, entries, *uses, calls: str = "") -> str:
        files = {"ci.yml": wf(PR, job("test", MATRIX_313, steps=steps(*uses)) + calls)}
        return answered(assess(entries, files), "OBAAF-SET-006")

    def test_an_empty_list_allows_no_other_repositorys_action(self):
        self.assertEqual(self.check(selected(), PIN), "cannot-tell")
        self.assertEqual(self.check(selected(), f"someone/tool@{SHA}"), "cannot-tell")

    def test_githubs_own_where_allowed(self):
        self.assertEqual(self.check(selected(github_owned=True), PIN), "no-finding")
        self.assertEqual(self.check(selected(github_owned=True), f"github/codeql-action/init@{SHA}"), "no-finding")
        for odd in (f"Actions/checkout@{SHA}", f"actions/../someone/x@{SHA}", f"actions/checkout/../../x@{SHA}",
                    "actions/checkout", f"someone/actions@{SHA}"):
            self.assertEqual(self.check(selected(github_owned=True), odd), "cannot-tell", odd)

    def test_an_entry_that_is_the_reference_itself(self):
        self.assertEqual(self.check(selected([f"someone/tool@{SHA}"]), f"someone/tool@{SHA}"), "no-finding")
        for pattern in ("someone/*", "someone/tool@*", "someone/tool", f"Someone/tool@{SHA}"):
            self.assertEqual(self.check(selected([pattern]), f"someone/tool@{SHA}"), "cannot-tell", pattern)
        # The review of 2b.7: a reference that repeats a wildcard or odd entry is not matched by it either.
        for odd in ("someone/*", "someone/tool@*", "'someone/tool@v1 '", "someone/tool@v1..x", "./x@v1"):
            self.assertEqual(self.check(selected([odd.strip("'")]), odd), "cannot-tell", odd)

    def test_an_entry_that_may_block_means_nothing_is_matched(self):
        entries = selected([f"someone/tool@{SHA}", "!evil/*"], github_owned=True)
        self.assertEqual(self.check(entries, PIN), "cannot-tell")
        self.assertEqual(self.check(entries, f"someone/tool@{SHA}"), "cannot-tell")
        entries = selected([f"someone/tool@{SHA}", "x/y@v1, !someone/*"])
        self.assertEqual(self.check(entries, f"someone/tool@{SHA}"), "cannot-tell")

    def test_verified_creators_are_not_matched(self):
        self.assertEqual(self.check(selected(verified=True), f"someone/tool@{SHA}"), "cannot-tell")

    def test_a_reusable_workflow_of_another_repository(self):
        call = f"  scan:\n    uses: actions/tools/.github/workflows/scan.yml@{SHA}\n"
        self.assertEqual(self.check(selected(github_owned=True), PIN, calls=call), "cannot-tell")
        self.assertEqual(self.check(selected([f"actions/tools/.github/workflows/scan.yml@{SHA}"], github_owned=True),
                                    PIN, calls=call), "no-finding")

    def test_a_list_that_was_not_read(self):
        entries = answer(selected(), SELECTED, {"message": "Must have admin rights"}, status=403)
        files = {"ci.yml": wf(PR, job("test", MATRIX_313, steps=steps(PIN)))}
        found = assess(entries, files)
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")
        snap, _ = take(entries, token=TOKEN)
        usage = CallsThatWereNotComparedTest()._usage(files)
        _, maybe, _, _ = rules._stops(rules._Run(rules.RULES[0], snap, usage))
        self.assertIn("the list was not read", maybe[W + "ci.yml"])

    def test_a_local_action_or_an_image_is_not_read(self):
        # The review of 2b.7: a local composite action's own steps are not read, and may use an action the
        # setting blocks; whether the setting covers a container image is not read either.
        local_only = answer(ADMIN, ACTIONS_PERMISSIONS, {"enabled": True, "allowed_actions": "local_only"})
        for entries in (selected(github_owned=True), local_only):
            for uses in ("./.github/actions/build", "$/.github/actions/build", "docker://alpine:3.20"):
                self.assertEqual(self.check(entries, uses), "cannot-tell", uses)
        every = answer(ADMIN, ACTIONS_PERMISSIONS, {"enabled": True, "allowed_actions": "all"})
        self.assertEqual(self.check(every, "./.github/actions/build", "docker://alpine:3.20"), "no-finding")

    def test_a_file_that_may_not_run_keeps_its_paths_finding(self):
        # The review of 2b.7: the paths filter keeps the check from reporting whether or not the file runs, so
        # OBAAF-SET-007's finding stands; whether an unrequired check exists at all does not (OBAAF-SET-008).
        tool = f"someone/tool@{SHA}"
        entries = requiring("lint", entries=selected(["someone/*"]))
        paths = {"ci.yml": wf("  pull_request:\n    paths: ['src/**']\n", job("lint", steps=steps(tool)))}
        self.assertEqual(answered(assess(entries, paths), "OBAAF-SET-007"), "finding medium")
        self.assertEqual(answered(assess(entries, paths), "OBAAF-SET-006"), "cannot-tell")
        free = {"ci.yml": wf(PR, job("lint") + job("test", steps=steps(tool)))}
        self.assertEqual(answered(assess(entries, free), "OBAAF-SET-008", "ci.yml#test"), "cannot-tell")

    def test_the_hand_written_recording_reads_as_before(self):
        # Holds before and after: the admin-token recording allows GitHub's own actions, and the tests built on
        # it use actions/checkout pinned to a commit.
        self.assertEqual(self.check(ADMIN, PIN), "no-finding")


class ChainOfCallsTest(unittest.TestCase):
    """Item 4: a chain of calls costs its length."""

    def test_a_long_chain_of_calls(self):
        snap, _ = take(ADMIN, token=TOKEN)
        n = 4000
        files = [{"path": f"w{k}.yml", "error": None, "problems": [], "doubt": [], "triggers": {},
                  "jobs": [{"id": "c", "calls": f"./w{k + 1}.yml", "remote_actions": [], "unpinned": [],
                            "unread_actions": [], "actions": 0}]} for k in range(n)]
        usage = {"files": files, "actions_lock": False}
        run = rules._Run(rules.RULES[0], snap, usage)
        start = time.monotonic()
        stopped, maybe, _, _ = rules._stops(run)
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertEqual(len(maybe), n)
        self.assertIn(f"it calls w{n}.yml, which GitHub may not run: it is not among", maybe[f"w{n - 1}.yml"])
        # Three nested calls below a file are allowed; a fourth is a doubt of its own (the review of 2b.7).
        self.assertEqual(maybe[f"w{n - 4}.yml"], f"it calls w{n - 3}.yml, which GitHub may not run")
        self.assertIn("it starts a chain of 4 nested calls", maybe[f"w{n - 5}.yml"])
        self.assertIn(f"it starts a chain of {n - 1} nested calls", maybe["w0.yml"])

    def test_the_reason_is_the_first_bad_call_in_the_order_the_jobs_are_written(self):
        # Holds before and after: the new loop keeps the old loop's reasons.
        files = {"ci.yml": wf(PR, "  a:\n    uses: ./.github/workflows/fine.yml\n"
                                  "  b:\n    uses: ./.github/workflows/gone.yml\n"
                                  "  c:\n    uses: ./.github/workflows/refused.yml\n"),
                 "fine.yml": wf("  workflow_call:\n", job("t")),
                 "refused.yml": wf("  workflow_call:\n", job("t", steps="      - uses: actions/checkout@v4\n"))}
        _, maybe, _, _ = CallsThatWereNotComparedTest()._stops(files)
        self.assertIn("gone.yml", maybe[W + "ci.yml"])
        self.assertNotIn("refused.yml", maybe[W + "ci.yml"])

    def test_a_cycle_of_calls(self):
        # The review of 2b.7: a file in a cycle of calls, or that calls itself, counted as running.
        files = {"a.yml": wf(PR + "  workflow_call:\n", job("lint") + "  x:\n    uses: ./.github/workflows/b.yml\n"),
                 "b.yml": wf("  workflow_call:\n", "  y:\n    uses: ./.github/workflows/a.yml\n")}
        _, maybe, _, _ = CallsThatWereNotComparedTest()._stops(files)
        self.assertIn("in a cycle of calls with .github/workflows/b.yml", maybe[W + "a.yml"])
        self.assertIn("in a cycle of calls with .github/workflows/a.yml", maybe[W + "b.yml"])
        self.assertEqual(answered(assess(requiring("lint"), files), "OBAAF-SET-006"), "cannot-tell")
        itself = {"ci.yml": wf(PR + "  workflow_call:\n", job("lint") + "  again:\n    uses: ./.github/workflows/ci.yml\n")}
        _, maybe, _, _ = CallsThatWereNotComparedTest()._stops(itself)
        self.assertEqual(maybe[W + "ci.yml"], "it calls itself, a cycle GitHub cannot expand")
        self.assertEqual(answered(assess(requiring("lint"), itself), "OBAAF-SET-006"), "cannot-tell")

    def test_how_deep_calls_nest(self):
        def chain(length):
            files = {"ci.yml": wf(PR, job("lint") + "  c:\n    uses: ./.github/workflows/r1.yml\n")}
            for k in range(1, length):
                files[f"r{k}.yml"] = wf("  workflow_call:\n", f"  c:\n    uses: ./.github/workflows/r{k + 1}.yml\n")
            files[f"r{length}.yml"] = wf("  workflow_call:\n", job("t"))
            return files
        self.assertEqual(answered(assess(requiring("lint"), chain(3)), "OBAAF-SET-006"), "no-finding")
        self.assertEqual(answered(assess(requiring("lint"), chain(4)), "OBAAF-SET-006"), "cannot-tell")


if __name__ == "__main__":
    unittest.main()
