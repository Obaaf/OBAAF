"""Flagship slice 2d.4b3b: what a called local workflow does, counted for the job that calls it.

Since slice 2d.4b1 a workflow that a job of the same repository calls (`uses:
./.github/workflows/x.yml`) is read with the events that can start the calling job, and since 2d.4b3a
with what the caller hands its inputs. What the called workflow's jobs do was still not counted for the
caller, though they run as jobs of the caller's run, with its token, its secrets and no more cache access
than it has:

- a job that calls a workflow which publishes was not a release job (attempts 026 of 2d.2d and 103 of
  2d.2e in docs/bypass-attempts.md);
- a release job that calls a workflow whose steps restore a cache got only the low "does not set
  cache-mode: none" (attempt 034 of 2d.2e);
- a called release job whose every caller sets `cache-mode: none` was reported as if it could restore
  (attempt 035 of 2d.2e, a false positive the checker could not see past).

Two points from 2d.4b1's reviews are decided here too: a call written `owner/repo/<path>@ref` is not
read as a call of this repository's file, and a note says so; and a called job's own
`if: github.event_name == '<event>'` adds that event for a caller in another repository.
"""

import time
import unittest

from helpers import TempDir

from obaaf import checker
from obaaf.checker import rules as rules_mod

SHA = "1111111111111111111111111111111111111111"
CALLED = ".github/workflows/called.yml"
CALLER = ".github/workflows/caller.yml"
CONFIG = ".github/obaaf.yml"


def build(tmp, files):
    root = tmp / "repo"
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def check(tmp, files, **kwargs):
    return checker.check(build(tmp, files), **kwargs)


def lanes(tmp, files):
    return {(path, job): (lane, reason) for path, job, lane, reason in checker.lanes(build(tmp, files))}


def caller(on="push", job="release", extra="", uses="./.github/workflows/called.yml", secrets=""):
    return (f"on: {on}\npermissions: {{}}\njobs:\n  {job}:\n    permissions:\n      contents: read\n{extra}"
            f"    uses: {uses}\n{secrets}")


def called(steps, extra_job="", on="workflow_call", job="publish", more=""):
    return (f"on: {on}\npermissions: {{}}\njobs:\n  {job}:\n    runs-on: ubuntu-latest\n    permissions:\n"
            f"      contents: read\n{extra_job}    steps:\n{steps}{more}")


PUBLISH = "      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
RESTORE = (f"      - uses: actions/cache@{SHA}\n        with:\n          path: ~/.npm\n"
           "          key: npm-${{ hashFiles('package-lock.json') }}\n")
BUILD = "      - run: npm ci && npm run build\n"


def found(result, rule, path=None, job=None):
    return [f for f in result.findings if f.rule == rule and (path is None or f.path == path)
            and (job is None or f.job == job)]


class ACallThatPublishesMakesAReleaseJobTest(unittest.TestCase):
    """Attempts 026 (2d.2d) and 103 (2d.2e)."""

    def test_attempt_026_the_calling_job_is_a_release_job(self):
        # A pull_request_target workflow calls a local workflow with secrets: inherit, whose job publishes
        # in environment production.
        files = {CALLER: caller(on="pull_request_target", secrets="    secrets: inherit\n"),
                 CALLED: called(PUBLISH, extra_job="    environment: production\n")}
        with TempDir() as tmp:
            shown = lanes(tmp, files)
        with TempDir() as tmp:
            result = check(tmp, files)
        lane, reason = shown[(CALLER, "release")]
        self.assertEqual(lane, "release")
        self.assertEqual(reason, "calls .github/workflows/called.yml, whose job 'publish' uploads or publishes "
                                 "artifacts")
        # The called job carries the release rules with the caller's events (slice 2d.4b1); the calling job
        # has no steps and cannot name an environment, so they are not given to it again.
        (release,) = found(result, "OBAAF-GHA-015", CALLED)
        self.assertIn("pull_request_target", release.facts["triggers"])
        self.assertEqual(found(result, "OBAAF-GHA-015", CALLER), [])
        self.assertEqual(found(result, "OBAAF-GHA-014", CALLER), [])
        # A job that can read every secret and releases is a release job's signing-key finding: high.
        (signing,) = found(result, "OBAAF-GHA-018", CALLER)
        self.assertEqual(signing.severity, "high")

    def test_attempt_103_the_called_publish_is_held_to_the_release_rules_and_the_caller_is_a_release_job(self):
        files = {CALLER: caller(secrets="    secrets:\n      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"),
                 CALLED: called(PUBLISH)}
        with TempDir() as tmp:
            result = check(tmp, files)
        with TempDir() as tmp:
            shown = lanes(tmp, files)
        self.assertEqual(len(found(result, "OBAAF-GHA-014", CALLED)), 1)
        self.assertEqual(len(found(result, "OBAAF-GHA-016", CALLED)), 1)
        self.assertEqual(shown[(CALLER, "release")][0], "release")
        # Nothing about environments for a job that cannot have one.
        self.assertEqual(found(result, "OBAAF-GHA-014", CALLER), [])

    def test_what_the_calling_job_holds_is_read_as_before(self):
        # OBAAF-GHA-015 `capability` (a job untrusted input can start that holds what publishing needs) is
        # what the calling job got before; reading the call must not drop it.
        files = {CALLER: caller(on="pull_request_target",
                                secrets="    secrets:\n      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"),
                 CALLED: called(PUBLISH)}
        with TempDir() as tmp:
            result = check(tmp, files)
        (capability,) = found(result, "OBAAF-GHA-015", CALLER)
        self.assertEqual(capability.kind, "capability")

    def test_a_call_that_does_not_publish_leaves_the_caller_where_it_was(self):
        files = {CALLER: caller(), CALLED: called(BUILD)}
        with TempDir() as tmp:
            shown = lanes(tmp, files)
        self.assertEqual(shown[(CALLER, "release")][0], "trusted")

    def test_a_publish_in_a_local_action_of_the_called_job_counts(self):
        action = ("runs:\n  using: composite\n  steps:\n    - run: npm publish\n      shell: bash\n")
        files = {CALLER: caller(),
                 CALLED: called("      - uses: ./.github/actions/ship\n"),
                 ".github/actions/ship/action.yml": action}
        with TempDir() as tmp:
            shown = lanes(tmp, files)
        lane, reason = shown[(CALLER, "release")]
        self.assertEqual(lane, "release")
        self.assertIn("job 'publish'", reason)

    def test_a_chain_of_calls_carries_the_release_to_the_first_caller(self):
        middle = ".github/workflows/middle.yml"
        files = {CALLER: caller(uses="./.github/workflows/middle.yml"),
                 middle: "on: workflow_call\njobs:\n  hop:\n    uses: ./.github/workflows/called.yml\n",
                 CALLED: called(PUBLISH)}
        with TempDir() as tmp:
            shown = lanes(tmp, files)
        lane, reason = shown[(CALLER, "release")]
        self.assertEqual(lane, "release")
        self.assertEqual(reason, "calls .github/workflows/middle.yml, where, in .github/workflows/called.yml, job "
                                 "'publish' uploads or publishes artifacts")
        self.assertEqual(shown[(middle, "hop")][0], "release")

    def test_a_declared_lane_is_kept(self):
        files = {CALLER: caller(), CALLED: called(PUBLISH),
                 CONFIG: "lanes:\n  .github/workflows/caller.yml#release: release\n"}
        with TempDir() as tmp:
            shown = lanes(tmp, files)
        self.assertEqual(shown[(CALLER, "release")], ("release", "set in the checker configuration"))

    def test_a_cycle_is_read_without_end_and_the_wider_way(self):
        # GitHub refuses a cycle of calls; each calling job in it is given everything any file of it does.
        other = ".github/workflows/other.yml"
        files = {CALLER: "on: workflow_call\njobs:\n  release:\n    uses: ./.github/workflows/other.yml\n"
                         "  ship:\n    runs-on: ubuntu-latest\n    steps:\n" + PUBLISH,
                 other: "on: workflow_call\njobs:\n  back:\n    uses: ./.github/workflows/caller.yml\n"}
        with TempDir() as tmp:
            shown = lanes(tmp, files)
        self.assertEqual(shown[(CALLER, "release")][0], "release")
        self.assertEqual(shown[(other, "back")][0], "release")


class ACalledCacheRestoreCountsForTheCallerTest(unittest.TestCase):
    """Attempt 034 (2d.2e): a release job that calls a workflow whose steps restore a cache."""

    def declared(self, steps=RESTORE + BUILD, caller_extra="", called_extra=""):
        return {CALLER: caller(extra=caller_extra), CALLED: called(steps, extra_job=called_extra, job="build"),
                CONFIG: "lanes:\n  .github/workflows/caller.yml#release: release\n"}

    def test_attempt_034_a_declared_release_job_gets_the_restore_at_high(self):
        with TempDir() as tmp:
            result = check(tmp, self.declared())
        (finding,) = found(result, "OBAAF-GHA-006", CALLER)
        self.assertEqual((finding.severity, finding.kind), ("high", "called-restores"))
        self.assertEqual(finding.facts["steps"], ["job 'build' of .github/workflows/called.yml, actions/cache"])
        self.assertEqual(finding.facts["workflows"], [CALLED])
        self.assertEqual(finding.facts["mode"], "")
        self.assertIn("cache-mode: none here", finding.message)

    def test_cache_mode_none_on_the_caller_clears_it(self):
        with TempDir() as tmp:
            result = check(tmp, self.declared(caller_extra="    cache-mode: none\n"))
        self.assertEqual(found(result, "OBAAF-GHA-006", CALLER), [])

    def test_cache_mode_none_on_the_called_job_clears_it(self):
        with TempDir() as tmp:
            result = check(tmp, self.declared(called_extra="    cache-mode: none\n"))
        self.assertEqual([f.kind for f in found(result, "OBAAF-GHA-006", CALLER)], ["no-cache-mode"])

    def test_no_restore_leaves_the_declared_job_its_low_finding(self):
        with TempDir() as tmp:
            result = check(tmp, self.declared(steps=BUILD))
        self.assertEqual([(f.severity, f.kind) for f in found(result, "OBAAF-GHA-006", CALLER)],
                         [("low", "no-cache-mode")])

    def test_a_release_by_the_call_with_a_restoring_build_job(self):
        # The called workflow builds in one job, which restores a cache, and publishes in another.
        steps = RESTORE + BUILD
        more = "  publish:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n" + PUBLISH
        files = {CALLER: caller(), CALLED: called(steps, job="build", more=more)}
        with TempDir() as tmp:
            result = check(tmp, files)
        (finding,) = found(result, "OBAAF-GHA-006", CALLER)
        self.assertEqual((finding.severity, finding.kind), ("high", "called-restores"))
        self.assertEqual(finding.facts["steps"], ["job 'build' of .github/workflows/called.yml, actions/cache"])

    def test_a_release_by_the_call_with_no_restore_gets_nothing_on_the_caller(self):
        files = {CALLER: caller(), CALLED: called(PUBLISH)}
        with TempDir() as tmp:
            result = check(tmp, files)
        self.assertEqual(found(result, "OBAAF-GHA-006", CALLER), [])
        # The called release job keeps its own.
        self.assertEqual([f.kind for f in found(result, "OBAAF-GHA-006", CALLED)], ["no-cache-mode"])

    def test_a_calling_job_between_that_forbids_stops_what_is_beyond_it(self):
        middle = ".github/workflows/middle.yml"
        files = {CALLER: caller(uses="./.github/workflows/middle.yml"),
                 middle: "on: workflow_call\njobs:\n  hop:\n    cache-mode: none\n"
                         "    uses: ./.github/workflows/called.yml\n",
                 CALLED: called(RESTORE + PUBLISH)}
        with TempDir() as tmp:
            result = check(tmp, files)
        self.assertEqual(found(result, "OBAAF-GHA-006", CALLER), [])
        self.assertEqual(found(result, "OBAAF-GHA-006", middle), [])

    def test_many_restoring_steps_are_one_bounded_fact_that_changes_with_any_of_them(self):
        def files(changed):
            steps = "".join(
                f"      - name: restore {n if n != 60 or not changed else 'sixty'}\n        uses: actions/cache@{SHA}\n"
                f"        with:\n          path: p{n}\n          key: k{n}\n" for n in range(100))
            return self.declared(steps=steps)
        with TempDir() as tmp:
            first = found(check(tmp, files(False)), "OBAAF-GHA-006", CALLER)[0]
        with TempDir() as tmp:
            second = found(check(tmp, files(True)), "OBAAF-GHA-006", CALLER)[0]
        self.assertLessEqual(len(first.facts["steps"]), 4)
        self.assertIn("(100 entries)", first.facts["steps"][-1])
        self.assertLess(len(first.message), 2000)
        self.assertNotEqual(first.facts, second.facts)


class CallersCacheModeTest(unittest.TestCase):
    """Attempt 035 (2d.2e): a called release job whose caller sets cache-mode: none."""

    def files(self, caller_extra="    cache-mode: none\n", on="workflow_call", second=None):
        out = {CALLER: caller(extra=caller_extra), CALLED: called(RESTORE + PUBLISH, on=on)}
        if second is not None:
            out[".github/workflows/second.yml"] = caller(extra=second)
        return out

    def test_attempt_035_every_caller_forbids_so_it_cannot_be_told(self):
        with TempDir() as tmp:
            result = check(tmp, self.files())
        (finding,) = found(result, "OBAAF-GHA-006", CALLED)
        self.assertEqual(finding.kind, "restores")
        self.assertEqual(finding.state, "cannot-tell")
        (control,) = finding.controls
        self.assertEqual((control.id, control.verdict), ("callers-cache-mode", "cannot tell"))
        self.assertIn("a caller in another repository is not seen", control.detail)
        # It still fails the check: only a fixed or accepted finding does not.
        self.assertIn(finding, result.gating("medium", checker.load()))

    def test_write_only_forbids_too(self):
        with TempDir() as tmp:
            result = check(tmp, self.files(caller_extra="    cache-mode: write-only\n"))
        (finding,) = found(result, "OBAAF-GHA-006", CALLED)
        self.assertEqual(finding.state, "cannot-tell")

    def test_a_caller_that_does_not_forbid_leaves_it_new(self):
        with TempDir() as tmp:
            result = check(tmp, self.files(second=""))
        (finding,) = found(result, "OBAAF-GHA-006", CALLED)
        self.assertEqual((finding.state, finding.controls), ("new", []))

    def test_a_workflow_that_can_also_be_started_on_its_own_is_new(self):
        with TempDir() as tmp:
            result = check(tmp, self.files(on="\n  workflow_call:\n  push:\n"))
        (finding,) = found(result, "OBAAF-GHA-006", CALLED)
        self.assertEqual((finding.state, finding.controls), ("new", []))

    def test_no_caller_is_as_before(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLED: called(RESTORE + PUBLISH)})
        (finding,) = found(result, "OBAAF-GHA-006", CALLED)
        self.assertEqual((finding.state, finding.controls), ("new", []))

    def test_a_caller_that_is_called_only_by_forbidding_jobs_forbids(self):
        middle = ".github/workflows/middle.yml"
        files = {CALLER: caller(extra="    cache-mode: none\n", uses="./.github/workflows/middle.yml"),
                 middle: "on: workflow_call\njobs:\n  hop:\n    uses: ./.github/workflows/called.yml\n",
                 CALLED: called(RESTORE + PUBLISH)}
        with TempDir() as tmp:
            result = check(tmp, files)
        (finding,) = found(result, "OBAAF-GHA-006", CALLED)
        self.assertEqual(finding.state, "cannot-tell")

    def test_a_cycle_does_not_forbid(self):
        files = {CALLED: called(RESTORE + PUBLISH, more="  again:\n    uses: ./.github/workflows/called.yml\n")}
        with TempDir() as tmp:
            result = check(tmp, files)
        (finding,) = found(result, "OBAAF-GHA-006", CALLED, job="publish")
        self.assertEqual(finding.state, "new")

    def test_the_low_finding_gets_the_same_control(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(extra="    cache-mode: none\n"), CALLED: called(PUBLISH)})
        (finding,) = found(result, "OBAAF-GHA-006", CALLED)
        self.assertEqual((finding.kind, finding.state), ("no-cache-mode", "cannot-tell"))


class ACallByARepositorysNameTest(unittest.TestCase):

    def test_a_call_by_owner_and_repo_is_not_matched_and_a_note_says_so(self):
        files = {CALLER: caller(on="pull_request_target",
                                uses=f"someone/repo/.github/workflows/called.yml@{SHA}"),
                 CALLED: called(PUBLISH)}
        with TempDir() as tmp:
            result = check(tmp, files)
        with TempDir() as tmp:
            shown = lanes(tmp, files)
        self.assertEqual(shown[(CALLER, "release")][0], "trusted")
        # The called file is read on its own: no caller's events.
        self.assertEqual(found(result, "OBAAF-GHA-015", CALLED), [])
        (note,) = [n for n in result.notes if "names a path this repository has a workflow at" in n]
        self.assertIn(f"someone/repo/.github/workflows/called.yml@{SHA}", note)
        self.assertIn("nothing is read at that ref", note)

    def test_no_note_without_such_a_file(self):
        files = {CALLER: caller(uses=f"someone/repo/.github/workflows/elsewhere.yml@{SHA}"), CALLED: called(PUBLISH)}
        with TempDir() as tmp:
            result = check(tmp, files)
        self.assertEqual([n for n in result.notes if "names a path this repository has" in n], [])


class AnOutsideCallersEventTest(unittest.TestCase):
    """A called job's own `if: github.event_name == '<event>'`: `workflow_call` stands for a caller in
    another repository, which can raise that event."""

    HEAD_CHECKOUT = (f"      - uses: actions/checkout@{SHA}\n        with:\n"
                     "          ref: ${{ github.event.pull_request.head.sha }}\n"
                     "          persist-credentials: false\n"
                     "      - run: make\n        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n")

    def test_an_event_the_if_names_is_one_the_job_can_run_on(self):
        body = called(self.HEAD_CHECKOUT, extra_job="    if: github.event_name == 'pull_request_target'\n",
                      job="work")
        with TempDir() as tmp:
            result = check(tmp, {CALLED: body})
        self.assertTrue(found(result, "OBAAF-GHA-002", CALLED))
        (secret,) = found(result, "OBAAF-GHA-001", CALLED)
        self.assertIn("pull_request_target", secret.facts["triggers"])

    def test_a_test_with_not_equal_adds_nothing(self):
        body = called(self.HEAD_CHECKOUT, extra_job="    if: github.event_name != 'pull_request_target'\n",
                      job="work")
        with TempDir() as tmp:
            result = check(tmp, {CALLED: body})
        self.assertEqual(found(result, "OBAAF-GHA-001", CALLED), [])

    def test_a_workflow_no_one_can_call_is_as_before(self):
        body = called(self.HEAD_CHECKOUT, extra_job="    if: github.event_name == 'pull_request_target'\n",
                      job="work", on="push")
        with TempDir() as tmp:
            result = check(tmp, {CALLED: body})
        self.assertEqual(found(result, "OBAAF-GHA-001", CALLED), [])
        self.assertEqual(found(result, "OBAAF-GHA-002", CALLED), [])


class ReportedInTheSameOrderTest(unittest.TestCase):
    """Every file is classified before any is checked (slice 2d.4b3b); what classifying a file reports is
    reported with that file, where it was before."""

    def test_errors_keep_the_order_of_the_files(self):
        files = {".github/workflows/a.yml": "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n"
                                           "      - uses: ./.github/actions/broken\n",
                 ".github/actions/broken/action.yml": "runs: [\n",
                 ".github/workflows/b.yml": "on: [\n",
                 ".github/workflows/c.yml": "on: push\njobs:\n  y:\n    runs-on: ubuntu-latest\n    steps:\n"
                                           "      - uses: ./.github/actions/broken\n"}
        with TempDir() as tmp:
            result = check(tmp, files)
        order = [e.split(":", 1)[0] for e in result.errors]
        self.assertEqual(order, sorted(order))
        self.assertTrue(any(e.startswith(".github/workflows/a.yml") for e in result.errors))
        self.assertTrue(any(e.startswith(".github/workflows/b.yml") for e in result.errors))
        self.assertTrue(any(e.startswith(".github/workflows/c.yml") for e in result.errors))


class CostTest(unittest.TestCase):

    def test_a_long_chain_of_calls_each_restoring_is_linear(self):
        files = {CONFIG: "lanes:\n  .github/workflows/w0.yml#call: release\n"}
        n = 300
        for i in range(n):
            nxt = f"    uses: ./.github/workflows/w{i + 1}.yml\n" if i + 1 < n else ""
            job = ("  call:\n" + nxt) if nxt else ""
            files[f".github/workflows/w{i}.yml"] = (
                f"on: {'push' if i == 0 else 'workflow_call'}\njobs:\n{job}  build:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n{RESTORE}")
        with TempDir() as tmp:
            start = time.monotonic()
            result = check(tmp, files)
            took = time.monotonic() - start
        (finding,) = found(result, "OBAAF-GHA-006", ".github/workflows/w0.yml", job="call")
        self.assertIn(f"({n - 1} entries)", finding.facts["steps"][-1])
        self.assertLess(took, 60)

    def test_the_summaries_are_bounded(self):
        summary = rules_mod.CallSummary()
        for n in range(1000):
            summary = summary + rules_mod.CallSummary.of([f"entry {n}"])
        self.assertEqual(len(summary.kept), rules_mod.CALL_EFFECTS_KEPT)
        self.assertEqual(summary.count, 1000)


if __name__ == "__main__":
    unittest.main()
