"""Flagship slice 2d.4b2: the steps of a local composite action are read as the job's own steps.

Before this slice only the agent lane looked inside `uses: ./.github/actions/x` (slice 2d.4a). Every
other rule saw one step with a local path, so a job could hide a checkout of a pull request's head, a
cache, a publish, an unpinned action or a script that expands an outsider's text behind a local action
(attempts 015, 111 and A185 in docs/bypass-attempts.md, and the checkout of the head SHA through a local
action recorded by slice 2d.2c). Now the rules are run again with each such step followed by the
action's steps, the using step's inputs put in as expressions, and what that adds is kept.

The main test is a property: a job that runs some steps through a local action gets every finding the
same steps written in the job get (by rule, case and severity), and nothing more than what the first
pass already gives the step that uses the action.
"""

import json
import unittest
from collections import Counter

from helpers import TempDir

from obaaf import checker
from obaaf.checker import LOCAL_STEPS

SHA = "1111111111111111111111111111111111111111"
ACTION = ".github/actions/x"
CODEOWNERS = "* @example/maintainers\n"


def build(tmp, workflow_text, files=None):
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows" / "wf.yml").write_text(workflow_text, encoding="utf-8")
    (root / ".github" / "CODEOWNERS").write_text(CODEOWNERS, encoding="utf-8")
    for rel, body in (files or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def check(workflow_text, files=None, config=None):
    with TempDir() as tmp:
        root = build(tmp, workflow_text, files)
        conf = checker.Config.from_data(config, "obaaf.yml") if config else None
        return checker.check(root, config=conf)


def indent(text, by):
    return "".join(" " * by + line if line.strip() else line for line in text.splitlines(True))


def composite(steps, inputs=()):
    head = "name: x\n"
    if inputs:
        head += "inputs:\n" + "".join(f"  {name}:\n    default: ''\n" for name in inputs)
    return head + "runs:\n  using: composite\n  steps:\n" + indent(steps, 4)


def job(steps, on="workflow_dispatch", extra="", permissions="{contents: read}"):
    return (f"on: {on}\npermissions: {permissions}\njobs:\n  a:\n    runs-on: ubuntu-latest\n{extra}"
            f"    steps:\n" + indent(steps, 6))


def using(given=None, extra=""):
    text = f"- uses: ./{ACTION}\n"
    if given:
        text += "  with:\n" + "".join(f"    {k}: {json.dumps(v)}\n" for k, v in given.items())
    return text + extra


def shape(findings, job_id="a"):
    return Counter((f.rule, f.kind, f.severity) for f in findings
                   if f.job == job_id and not f.rule.startswith("OBAAF-REPO"))


# Each case: (what it is, the trigger, the job's extra keys, the action's steps written with inputs, the
# inputs the using step gives, the same steps written in the job with those inputs put in by hand).
CASES = [
    ("a checkout of the pull request's head (2d.2c's recorded way past)", "pull_request_target", "",
     "- uses: actions/checkout@" + SHA + "\n  with:\n    ref: ${{ inputs.ref }}\n    persist-credentials: false\n"
     "- run: make\n  shell: bash\n",
     {"ref": "${{ github.event.pull_request.head.sha }}"},
     "- uses: actions/checkout@" + SHA + "\n  with:\n    ref: ${{ github.event.pull_request.head.sha }}\n"
     "    persist-credentials: false\n- run: make\n  shell: bash\n"),
    ("the head behind `||` with another context", "pull_request_target", "",
     "- uses: actions/checkout@" + SHA + "\n  with:\n    ref: ${{ inputs.ref || github.event.pull_request.head.ref }}\n"
     "    persist-credentials: false\n",
     {"ref": ""},
     "- uses: actions/checkout@" + SHA + "\n  with:\n    ref: ${{ '' || github.event.pull_request.head.ref }}\n"
     "    persist-credentials: false\n"),
    ("a checkout that keeps the token", "pull_request_target", "",
     "- uses: actions/checkout@" + SHA + "\n",
     {},
     "- uses: actions/checkout@" + SHA + "\n"),
    ("an outsider's text expanded in a script through an input", "issues", "",
     "- run: echo \"${{ inputs.title }}\"\n  shell: bash\n",
     {"title": "${{ github.event.issue.title }}"},
     "- run: echo \"${{ github.event.issue.title }}\"\n  shell: bash\n"),
    ("an outsider's text inside a longer input", "issues", "",
     "- run: echo ${{ inputs.title }}\n  shell: bash\n",
     {"title": "issue: ${{ github.event.issue.title }} (open)"},
     "- run: \"echo ${{ format('issue: {0} (open)', github.event.issue.title) }}\"\n  shell: bash\n"),
    ("an action not pinned to a SHA (A185, attempt 015)", "push", "",
     "- uses: actions/setup-node@v4\n",
     {},
     "- uses: actions/setup-node@v4\n"),
    ("an image not pinned", "push", "",
     "- uses: docker://alpine:3\n",
     {},
     "- uses: docker://alpine:3\n"),
    ("a cache restored in a release job (attempt 015)", "push", "    cache-mode: read\n",
     "- uses: actions/cache@" + SHA + "\n  with:\n    path: x\n    key: k\n",
     {},
     "- uses: actions/cache@" + SHA + "\n  with:\n    path: x\n    key: k\n",
     "- run: npm publish\n  shell: bash\n"),
    ("a publish (attempt 111)", "push", "",
     "- run: npm publish\n  shell: bash\n",
     {},
     "- run: npm publish\n  shell: bash\n"),
    ("a publish whose command is an input", "push", "",
     "- run: ${{ inputs.command }}\n  shell: bash\n",
     {"command": "twine upload dist/*"},
     "- run: twine upload dist/*\n  shell: bash\n"),
    ("a release step behind a cache, in a job that publishes", "push", "",
     "- uses: actions/cache@" + SHA + "\n  with:\n    path: x\n    key: k\n- run: npm publish\n  shell: bash\n",
     {},
     "- uses: actions/cache@" + SHA + "\n  with:\n    path: x\n    key: k\n- run: npm publish\n  shell: bash\n"),
    ("a checkout of a pull request's merge commit on pull_request_target", "pull_request_target", "",
     "- uses: actions/checkout@" + SHA + "\n  with:\n    ref: refs/pull/${{ inputs.number }}/merge\n"
     "    persist-credentials: false\n",
     {"number": "${{ github.event.pull_request.number }}"},
     "- uses: actions/checkout@" + SHA + "\n  with:\n    ref: refs/pull/${{ github.event.pull_request.number }}/merge\n"
     "    persist-credentials: false\n"),
    ("a fetch of the head in a script", "pull_request_target", "",
     "- run: git fetch origin ${{ inputs.sha }} && git checkout FETCH_HEAD\n  shell: bash\n",
     {"sha": "${{ github.event.pull_request.head.sha }}"},
     "- run: git fetch origin ${{ github.event.pull_request.head.sha }} && git checkout FETCH_HEAD\n  shell: bash\n"),
    ("unsafe checkout allowed through an input", "pull_request_target", "",
     "- uses: actions/checkout@" + SHA + "\n  with:\n    ref: ${{ inputs.ref }}\n    persist-credentials: false\n"
     "    allow-unsafe-pr-checkout: ${{ inputs.unsafe }}\n",
     {"ref": "${{ github.event.pull_request.head.sha }}", "unsafe": "true"},
     "- uses: actions/checkout@" + SHA + "\n  with:\n    ref: ${{ github.event.pull_request.head.sha }}\n"
     "    persist-credentials: false\n    allow-unsafe-pr-checkout: true\n"),
]


class ReadAsTheJobsOwnStepsTest(unittest.TestCase):
    """A job that runs steps through a local action gets what the same steps written in it get."""

    def test_every_case_gets_what_the_steps_written_in_the_job_get(self):
        """Where the first pass already gives the using step a stronger finding of a rule (it takes a local
        action to restore a cache whatever it holds, decision D-062, which is high where a release job
        that sets no cache-mode is low), that finding stands for the weaker one."""
        order = {"high": 0, "medium": 1, "low": 2}
        for what, on, extra, steps, given, inline, *after in CASES:
            after = after[0] if after else ""
            with self.subTest(what):
                names = sorted(given) or ["unused"]
                through = check(job(using(given) + after, on=on, extra=extra),
                                {f"{ACTION}/action.yml": composite(steps, names)})
                written = check(job(inline + after, on=on, extra=extra))
                self.assertEqual(through.errors, [], what)
                self.assertEqual(written.errors, [], what)
                self.assertTrue(shape(written.findings), f"{what}: the written steps give no finding to compare")
                got, want = shape(through.findings), shape(written.findings)
                missing = Counter({(rule, kind, severity): n for (rule, kind, severity), n in (want - got).items()
                                   if not any(f.rule == rule and f.step == f"./{ACTION}"
                                              and order[f.severity] <= order[severity] for f in through.findings)})
                self.assertEqual(missing, Counter(), f"{what}: missed through the local action")
                extra_found = [f for f in through.findings if f.job == "a" and not f.rule.startswith("OBAAF-REPO")
                               and f.step != f"./{ACTION}"]
                self.assertEqual(Counter((f.rule, f.kind, f.severity) for f in extra_found) - want, Counter(),
                                 f"{what}: more than the written steps give, beyond the using step's own")

    def test_before_this_slice_the_cases_were_not_seen(self):
        """The first pass alone, which is what the checker did before, misses each case that is not about
        the using step itself; this keeps the property from passing on a checker that reads nothing."""
        from obaaf.checker import rules as rules_mod
        original = rules_mod.WorkflowRules.through_local_actions
        rules_mod.WorkflowRules.through_local_actions = lambda self: None
        try:
            missed = []
            for what, on, extra, steps, given, inline, *after in CASES:
                after = after[0] if after else ""
                names = sorted(given) or ["unused"]
                through = check(job(using(given) + after, on=on, extra=extra),
                                {f"{ACTION}/action.yml": composite(steps, names)})
                written = check(job(inline + after, on=on, extra=extra))
                if shape(written.findings) - shape(through.findings):
                    missed.append(what)
            # The one exception: the first pass already takes a local action to restore a cache (D-062).
            seen_before = sorted({c[0] for c in CASES} - set(missed))
            self.assertEqual(seen_before, ["a cache restored in a release job (attempt 015)"])
        finally:
            rules_mod.WorkflowRules.through_local_actions = original

    def test_the_finding_names_the_action_and_its_step_and_the_workflow_line(self):
        steps = "- name: Get the head\n  uses: actions/checkout@v4\n  with:\n    ref: ${{ inputs.ref }}\n"
        result = check(job("- run: echo first\n  shell: bash\n" + using({"ref": "${{ github.event.pull_request.head.sha }}"}),
                           on="pull_request_target"),
                       {f"{ACTION}/action.yml": composite(steps, ["ref"])})
        (found,) = [f for f in result.findings if f.rule == "OBAAF-GHA-002"]
        self.assertEqual(found.step, f"./{ACTION}: Get the head")
        self.assertEqual(found.line, 9)          # the line of `- uses: ./.github/actions/x` in the workflow
        self.assertEqual(found.path, ".github/workflows/wf.yml")
        unnamed = check(job(using({"ref": "${{ github.event.pull_request.head.sha }}"},
                                  extra="  name: Check out\n"), on="pull_request_target"),
                        {f"{ACTION}/action.yml": composite("- run: echo one\n  shell: bash\n"
                                                            "- uses: actions/checkout@v4\n  with:\n    ref: ${{ inputs.ref }}\n",
                                                            ["ref"])})
        self.assertIn(f"Check out > ./{ACTION}: actions/checkout@v4",
                      {f.step for f in unnamed.findings if f.rule == "OBAAF-GHA-002"})

    def test_a_local_action_inside_a_local_action(self):
        inner = composite("- uses: actions/checkout@" + SHA + "\n  with:\n    ref: ${{ inputs.ref }}\n"
                          "    persist-credentials: false\n", ["ref"])
        outer = composite("- uses: ./.github/actions/y\n  with:\n    ref: ${{ inputs.sha }}\n", ["sha"])
        result = check(job(using({"sha": "${{ github.event.pull_request.head.sha }}"}), on="pull_request_target"),
                       {f"{ACTION}/action.yml": outer, ".github/actions/y/action.yml": inner})
        steps = {f.step for f in result.findings if f.rule == "OBAAF-GHA-002"}
        self.assertEqual(steps, {f"./{ACTION}: ./.github/actions/y: actions/checkout@{SHA}"})

    def test_the_workflows_own_inputs_are_not_the_actions(self):
        """`inputs.ref` the using step passes is the workflow's input; the action's `inputs.ref` is what it
        is given. Each is put in once, so the workflow's stays the workflow's."""
        action_text = composite("- uses: actions/checkout@" + SHA + "\n  with:\n    ref: ${{ inputs.ref }}\n"
                                "    persist-credentials: false\n", ["ref"])
        text = ("on:\n  workflow_dispatch:\n    inputs:\n      ref: {type: string}\npermissions: {contents: read}\n"
                "jobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      REF: ${{ inputs.ref }}\n    steps:\n"
                f"      - uses: ./{ACTION}\n        with:\n          ref: main\n")
        result = check(text, {f"{ACTION}/action.yml": action_text})
        self.assertEqual([f.rule for f in result.findings if f.job == "a" and f.rule == "OBAAF-GHA-002"], [])


class ReadingOnlyAddsTest(unittest.TestCase):
    """What the first pass found stays as it was: reading through never clears a finding."""

    def test_a_check_inside_the_action_does_not_clear_an_upload_after_it(self):
        text = job(using() + "- run: npm publish\n  shell: bash\n", on="push")
        verify = composite("- run: obaaf verify release dist\n  shell: bash\n")
        nothing = composite("- run: echo hi\n  shell: bash\n")
        with_check = shape(check(text, {f"{ACTION}/action.yml": verify}).findings)
        without = shape(check(text, {f"{ACTION}/action.yml": nothing}).findings)
        self.assertIn("OBAAF-GHA-016", {rule for rule, _, _ in with_check})
        self.assertEqual(with_check, without)

    def test_a_step_that_writes_github_path_inside_the_action_is_seen_by_the_check_after_it(self):
        """The check after the action can no longer be vouched for when the action changes the `PATH`:
        what `obaaf` is in the check is then whatever the action put first."""
        text = job(using() + "- run: obaaf verify release dist\n  shell: bash\n"
                   "- run: npm publish\n  shell: bash\n", on="push")
        path = composite("- run: echo /tmp/bin >> \"$GITHUB_PATH\"\n  shell: bash\n")
        plain = composite("- run: echo hi\n  shell: bash\n")
        kinds = {f.kind for f in check(text, {f"{ACTION}/action.yml": path}).findings if f.rule == "OBAAF-GHA-016"}
        self.assertEqual(kinds, {"cannot-tell"})
        self.assertEqual([f for f in check(text, {f"{ACTION}/action.yml": plain}).findings
                          if f.rule == "OBAAF-GHA-016"], [])

    def test_first_pass_findings_are_unchanged(self):
        """A finding on a job's own step keeps its name and identity, and its step keeps its number."""
        from obaaf.checker import baseline
        text = job("- uses: actions/checkout@v4\n" + using() + "- run: echo ${{ github.event.issue.title }}\n",
                   on="issues")
        plain = composite("- run: echo hi\n  shell: bash\n")
        risky = composite("- uses: actions/setup-node@v4\n")
        a = check(text, {f"{ACTION}/action.yml": plain})
        b = check(text, {f"{ACTION}/action.yml": risky})
        keys_a = {baseline.key(f) for f in a.findings}
        keys_b = {baseline.key(f) for f in b.findings}
        self.assertLessEqual(keys_a, keys_b)
        self.assertIn("step 3", {f.step for f in b.findings if f.rule == "OBAAF-GHA-010"})
        self.assertEqual({f.step for f in b.findings} - {f.step for f in a.findings},
                         {f"./{ACTION}: actions/setup-node@v4"})

    def test_a_control_inside_the_action_clears_nothing(self):
        """An egress monitor or OBAAF's egress action inside a local action is not taken for the job's."""
        mon = composite("- uses: step-security/harden-runner@" + SHA + "\n  with:\n    egress-policy: block\n"
                        "    allowed-endpoints: api.anthropic.com:443\n")
        text = ("on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    steps:\n" + indent(using() + "- run: claude -p hi\n  shell: bash\n", 6))
        plain = check(text, {f"{ACTION}/action.yml": composite("- run: echo hi\n  shell: bash\n")})
        monitored = check(text, {f"{ACTION}/action.yml": mon})
        self.assertEqual([(f.rule, f.kind, f.state) for f in plain.findings if f.rule == "OBAAF-GHA-020"],
                         [(f.rule, f.kind, f.state) for f in monitored.findings if f.rule == "OBAAF-GHA-020"])


class ConditionsTest(unittest.TestCase):
    def test_the_using_steps_if_is_the_actions_steps_condition(self):
        """OBAAF-GHA-002 names the condition a step runs under; a step of the action runs under the using
        step's `if:` and its own, both, as the same steps written in the job with both would."""
        given = {"ref": "${{ github.event.pull_request.head.sha }}"}
        on = "[push, pull_request_target]"
        for own in ("", "  if: inputs.ref != ''\n"):
            with self.subTest(own=own):
                steps = ("- uses: actions/checkout@" + SHA + "\n" + own + "  with:\n    ref: ${{ inputs.ref }}\n"
                         "    persist-credentials: false\n")
                narrowed = check(job(using(given, extra="  if: github.event_name == 'push'\n"), on=on),
                                 {f"{ACTION}/action.yml": composite(steps, ["ref"])})
                both = "github.event_name == 'push'" if not own else \
                    "${{ (github.event_name == 'push') && ((github.event.pull_request.head.sha)!='') }}"
                written = check(job("- uses: actions/checkout@" + SHA + f"\n  if: {json.dumps(both)}\n  with:\n"
                                    "    ref: ${{ github.event.pull_request.head.sha }}\n"
                                    "    persist-credentials: false\n", on=on))
                (a,) = [f for f in narrowed.findings if f.rule == "OBAAF-GHA-002"]
                (b,) = [f for f in written.findings if f.rule == "OBAAF-GHA-002"]
                self.assertEqual(a.facts["condition"], b.facts["condition"])

    def test_the_actions_own_if_reads_its_inputs(self):
        steps = ("- if: inputs.pr == 'yes'\n  uses: actions/checkout@" + SHA + "\n  with:\n"
                 "    ref: ${{ github.event.pull_request.head.sha }}\n    persist-credentials: false\n")
        on = "pull_request_target"
        never = check(job(using({"pr": "no"}), on=on), {f"{ACTION}/action.yml": composite(steps, ["pr"])})
        given = check(job(using({"pr": "yes"}), on=on), {f"{ACTION}/action.yml": composite(steps, ["pr"])})
        # The checker does not evaluate a comparison of texts: both are read the wider way.
        self.assertEqual(len([f for f in never.findings if f.rule == "OBAAF-GHA-002"]), 1)
        self.assertEqual(len([f for f in given.findings if f.rule == "OBAAF-GHA-002"]), 1)

    def test_continue_on_error_of_the_using_step_reaches_a_check_inside(self):
        text = job(using(extra="  continue-on-error: true\n"), on="push")
        both = composite("- run: obaaf verify release dist\n  shell: bash\n- run: npm publish\n  shell: bash\n")
        found = check(text, {f"{ACTION}/action.yml": both})
        self.assertIn("OBAAF-GHA-016", {f.rule for f in found.findings})
        plain = check(job(using(), on="push"), {f"{ACTION}/action.yml": both})
        self.assertNotIn("OBAAF-GHA-016", {f.rule for f in plain.findings})


class WhatCannotBeReadTest(unittest.TestCase):
    def test_inputs_read_in_a_way_not_worked_out_are_in_the_note(self):
        steps = "- run: echo '${{ toJSON(inputs) }}'\n  shell: bash\n"
        result = check(job(using({"a": "b"})), {f"{ACTION}/action.yml": composite(steps, ["a"])})
        (note,) = [n for n in result.notes if n.startswith("Local actions were not read through")]
        self.assertIn("reads the action's inputs in a way the checker does not work out", note)
        self.assertIn("not seen by the other rules", note)

    def test_more_steps_than_one_check_reads_is_an_error(self):
        many = composite("".join(f"- run: echo {n}\n  shell: bash\n" for n in range(LOCAL_STEPS + 1)))
        result = check(job(using()), {f"{ACTION}/action.yml": many})
        self.assertTrue(any("more than 1000 steps" in e for e in result.errors), result.errors)

    def test_text_that_grows_through_nested_actions_is_bounded(self):
        """Each level doubles the text it is given; ten levels of a long input stop at the budget, an
        error, and do not take minutes or memory."""
        import time
        files = {}
        for level in range(10):
            nxt = f"./.github/actions/l{level + 1}" if level < 9 else None
            body = ("- uses: " + nxt + "\n  with:\n    v: ${{ inputs.v }}${{ inputs.v }}\n") if nxt else \
                "- run: echo ${{ inputs.v }}\n  shell: bash\n"
            files[f".github/actions/l{level}/action.yml"] = composite(body, ["v"])
        files[f"{ACTION}/action.yml"] = composite("- uses: ./.github/actions/l0\n  with:\n    v: ${{ inputs.v }}\n", ["v"])
        start = time.monotonic()
        result = check(job(using({"v": "x" * 150_000})), files)
        self.assertLess(time.monotonic() - start, 30)
        self.assertTrue(result.errors or result.notes)

    def test_an_unreadable_action_file_is_one_error(self):
        result = check(job(using()), {f"{ACTION}/action.yml": "runs: [\n"})
        self.assertEqual(len([e for e in result.errors if "./.github/actions/x" in e]), 1, result.errors)

    def test_a_file_checked_on_its_own_reads_no_action(self):
        with TempDir() as tmp:
            root = build(tmp, job(using(), on="push"),
                         {f"{ACTION}/action.yml": composite("- uses: actions/setup-node@v4\n")})
            result = checker.check(root / ".github" / "workflows" / "wf.yml")
        self.assertNotIn("OBAAF-GHA-008", {f.rule for f in result.findings})

    def test_a_cycle_ends(self):
        loop = composite("- uses: ./.github/actions/x\n")
        result = check(job(using()), {f"{ACTION}/action.yml": loop})
        self.assertTrue(any("comes back to itself" in n for n in result.notes), result.notes)


if __name__ == "__main__":
    unittest.main()
