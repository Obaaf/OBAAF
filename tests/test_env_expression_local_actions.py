"""Flagship slice 2d.19f (#382): OBAAF-GHA-026 reads the options that `${{ }}` expressions reading `env` give in a
local composite action's steps.

Slice 2d.19c (D-143) taught OBAAF-GHA-026 to work out `${{ env.X }}` in a workflow's own step where the checker knows
the one text GitHub puts in. In a local composite action's step it still read the line as written, so
`claude ${{ env.FLAGS }} -p x` there, with `FLAGS: --dangerously-skip-permissions` in the job's `env`, was its medium
"cannot tell" where GitHub runs the warned option. The action's inputs are worked out by its caller, in the caller's
context, before the action starts; the second pass (2d.4b2) puts them in as expressions, which the action step would
work out with its own `env`. Now the rule reads such a step's command lines with the inputs worked out as the caller
works them out (`Step.given_texts`), and the expressions the action wrote with the action step's `env`: the
workflow's, the job's, the using step's and its own, the nearest winning. CI's job `composite-env-premise` shows that
order on a GitHub-hosted runner. What the checker cannot work out so stays "cannot tell".
"""

import time
import unittest

from helpers import TempDir
from test_local_composite_actions import check

SKIP = "--dangerously-skip-permissions"
HIGH = [("high", "command-option")]
CANNOT_TELL = [("medium", "command-computed")]
ACTION = ".github/actions/run-claude/action.yml"


def composite(*steps, inputs=""):
    """An action file: `inputs` is the text under `inputs:` (indented four spaces), each step a list item."""
    head = "name: run claude\n" + (f"inputs:\n{inputs}" if inputs else "")
    return head + "runs:\n  using: composite\n  steps:\n" + "".join(steps)


def bash_step(run, env=""):
    return ("    - shell: bash\n" + (f"      env: {env}\n" if env else "")
            + "      run: " + run + "\n")


def caller(using="      - uses: ./.github/actions/run-claude\n", top_env="", job_env="", runs_on="ubuntu-24.04",
           before="", jobs=("a",)):
    """A workflow whose jobs each hold a model key and run `before` and `using` (the step that uses the action)."""
    text = "on: workflow_dispatch\n" + (f"env: {top_env}\n" if top_env else "") + "jobs:\n"
    for job in jobs:
        text += (f"  {job}:\n    runs-on: {runs_on}\n    permissions: {{contents: read}}\n    env:\n"
                 "      ANTHROPIC_API_KEY: ${{ secrets.K }}\n"
                 + "".join(f"      {pair.strip()}\n" for pair in job_env.strip("{}").split(",") if pair.strip())
                 + "    steps:\n" + before + (using if isinstance(using, str) else using[job]))
    return text


def uses(with_="", env="", path="./.github/actions/run-claude"):
    return (f"      - uses: {path}\n" + (f"        env: {env}\n" if env else "")
            + (f"        with: {with_}\n" if with_ else ""))


def gha026(action_text, workflow_text, files=None, job=None):
    """(severity, kind) of each OBAAF-GHA-026 finding (on `job` where given), and the check's errors."""
    with TempDir() as tmp:
        result = check(tmp, workflow_text, files={ACTION: action_text, **(files or {})})
    found = sorted((f.severity, f.kind) for f in result.findings
                   if f.rule == "OBAAF-GHA-026" and (job is None or f.job == job))
    return found, list(result.errors)


class TheActionsOwnExpressionsTest(unittest.TestCase):
    """An expression the action writes is worked out with the action step's `env`."""

    def test_written_out_in_the_action_is_high(self):
        # The oracle: the option written in the action's step.
        self.assertEqual(gha026(composite(bash_step(f"claude {SKIP} -p hi")), caller()), (HIGH, []))

    def test_from_each_scope(self):
        for name, workflow_text, own in (
                ("workflow", caller(top_env=f"{{FLAGS: {SKIP}}}"), ""),
                ("job", caller(job_env=f"FLAGS: {SKIP}"), ""),
                ("using step", caller(uses(env=f"{{FLAGS: {SKIP}}}")), ""),
                ("action step", caller(), f"{{FLAGS: {SKIP}}}")):
            with self.subTest(scope=name):
                self.assertEqual(gha026(composite(bash_step("claude ${{ env.FLAGS }} -p hi", env=own)),
                                        workflow_text), (HIGH, []))

    def test_the_nearest_scope_wins(self):
        harmless = "{FLAGS: --model sonnet}"
        for name, workflow_text, own in (
                ("action step over job", caller(job_env=f"FLAGS: {SKIP}"), harmless),
                ("using step over job", caller(uses(env=harmless), job_env=f"FLAGS: {SKIP}"), ""),
                ("action step over using step", caller(uses(env=f"{{FLAGS: {SKIP}}}")), harmless)):
            with self.subTest(order=name):
                self.assertEqual(gha026(composite(bash_step("claude ${{ env.FLAGS }} -p hi", env=own)),
                                        workflow_text), ([], []))
        # And the other way round.
        self.assertEqual(gha026(composite(bash_step("claude ${{ env.FLAGS }} -p hi", env=f"{{FLAGS: {SKIP}}}")),
                                caller(uses(env=harmless))), (HIGH, []))

    def test_an_earlier_action_steps_env_is_not_a_later_ones(self):
        action_text = composite(bash_step("echo one", env=f"{{FLAGS: {SKIP}}}"),
                                bash_step("claude ${{ env.FLAGS }} -p hi"))
        self.assertEqual(gha026(action_text, caller(job_env="FLAGS: --model sonnet")), ([], []))

    def test_a_name_set_nowhere_is_cannot_tell(self):
        self.assertEqual(gha026(composite(bash_step("claude ${{ env.FLAGS }} -p hi")), caller()),
                         (CANNOT_TELL, []))

    def test_windows_folds_the_name(self):
        step = "    - shell: pwsh\n      run: claude ${{ env.flags }} -p hi\n"
        self.assertEqual(gha026(composite(step), caller(job_env=f"FLAGS: {SKIP}", runs_on="windows-latest")),
                         (HIGH, []))


class TheCallersInputsTest(unittest.TestCase):
    """The caller's `with:` is worked out in the caller's context, before the action starts."""

    def test_a_literal_input(self):
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi")),
                                caller(uses(with_=f"{{flags: {SKIP}}}"))), (HIGH, []))

    def test_an_input_the_caller_reads_from_env(self):
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi")),
                                caller(uses(with_="{flags: '${{ env.X }}'}"), job_env=f"X: {SKIP}")), (HIGH, []))

    def test_the_callers_env_not_the_action_steps(self):
        # The base read this as written ("cannot tell"); worked out with the action step's `env` it would be quiet.
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi", env="{X: --model sonnet}")),
                                caller(uses(with_="{flags: '${{ env.X }}'}"), job_env=f"X: {SKIP}")), (HIGH, []))
        # And the other way round: GitHub hands the action the caller's harmless value.
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi", env=f"{{X: {SKIP}}}")),
                                caller(uses(with_="{flags: '${{ env.X }}'}"), job_env="X: --model sonnet")),
                         ([], []))

    def test_the_using_steps_own_env(self):
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi")),
                                caller(uses(with_="{flags: '${{ env.X }}'}", env=f"{{X: {SKIP}}}"),
                                       job_env="X: --model sonnet")), (HIGH, []))

    def test_an_input_and_an_env_expression_in_one(self):
        # `inputs.flags` is empty, so `||` gives the action step's `env.X`.
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags || env.X }} -p hi",
                                                    env=f"{{X: {SKIP}}}")),
                                caller(uses(with_="{flags: ''}"))), (HIGH, []))

    def test_each_job_its_own_value(self):
        using = {"a": uses(with_=f"{{flags: {SKIP}}}"), "b": uses(with_="{flags: --model sonnet}")}
        action_text = composite(bash_step("claude ${{ inputs.flags }} -p hi"))
        self.assertEqual(gha026(action_text, caller(using, jobs=("a", "b")), job="a"), (HIGH, []))
        self.assertEqual(gha026(action_text, caller(using, jobs=("a", "b")), job="b"), ([], []))

    def test_an_input_put_into_the_action_steps_env(self):
        action_text = composite(bash_step("claude ${{ env.FLAGS }} -p hi", env="{FLAGS: '${{ inputs.flags }}'}"))
        self.assertEqual(gha026(action_text, caller(uses(with_=f"{{flags: {SKIP}}}"))), (HIGH, []))


class WhatStaysCannotTellTest(unittest.TestCase):
    """What the checker does not work out in the caller's or the action's context is read as written."""

    def test_another_context_in_the_callers_value(self):
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi")),
                                caller(uses(with_="{flags: '${{ vars.FLAGS }}'}"))), (CANNOT_TELL, []))
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi")),
                                caller(uses(with_="{flags: '${{ env.X }} ${{ github.sha }}'}"),
                                       job_env=f"X: {SKIP}")), (CANNOT_TELL, []))

    def test_a_default_that_reads_env(self):
        # Whether the runner gives a default the `env` context is not established (F-425).
        inputs = "  flags:\n    default: ${{ env.X }}\n"
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi"), inputs=inputs),
                                caller(job_env="X: --model sonnet")), (CANNOT_TELL, []))

    def test_a_literal_default(self):
        inputs = f"  flags:\n    default: '{SKIP}'\n"
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi"), inputs=inputs), caller()),
                         (HIGH, []))

    def test_with_written_as_one_expression(self):
        found, _errors = gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi")),
                                caller(uses(with_="${{ fromJSON(vars.W) }}")))
        self.assertEqual(found, CANNOT_TELL)

    def test_an_input_the_caller_does_not_work_out_beside_env(self):
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags || env.X }} -p hi",
                                                    env="{X: --model sonnet}")),
                                caller(uses(with_="{flags: '${{ vars.F }}'}"))), (CANNOT_TELL, []))

    def test_an_env_written_as_one_expression(self):
        for name, workflow_text, own in (
                ("action step", caller(job_env=f"FLAGS: {SKIP}"), "${{ fromJSON(vars.E) }}"),
                ("using step", caller(uses(env="${{ fromJSON(vars.E) }}"), job_env=f"FLAGS: {SKIP}"), "")):
            with self.subTest(scope=name):
                found, _errors = gha026(composite(bash_step("claude ${{ env.FLAGS }} -p hi", env=own)),
                                        workflow_text)
                self.assertEqual(found, CANNOT_TELL)

    def test_an_earlier_step_that_may_write_env(self):
        writer = "echo FLAGS=x >> \"$GITHUB_ENV\""
        # In the action, before the step.
        action_text = composite(bash_step(writer), bash_step("claude ${{ env.FLAGS }} -p hi"))
        self.assertEqual(gha026(action_text, caller(job_env="FLAGS: --model sonnet")), (CANNOT_TELL, []))
        # In the job, before the step that uses the action, for a value the caller works out from `env`.
        before = f"      - run: {writer}\n"
        self.assertEqual(gha026(composite(bash_step("claude ${{ inputs.flags }} -p hi")),
                                caller(uses(with_="{flags: '${{ env.X }}'}"), job_env="X: --model sonnet",
                                       before=before)), (CANNOT_TELL, []))

    def test_a_further_local_action(self):
        # Its inputs are given by the first action's step, in that step's context: not worked out (a stated limit).
        inner = composite(bash_step("claude ${{ env.FLAGS }} -p hi"))
        outer = composite("    - uses: ./.github/actions/inner\n")
        found, errors = gha026(outer, caller(job_env=f"FLAGS: {SKIP}"),
                               files={".github/actions/inner/action.yml": inner})
        self.assertEqual((found, errors), (CANNOT_TELL, []))

    def test_an_expression_that_does_not_name_its_name(self):
        self.assertEqual(gha026(composite(bash_step("claude ${{ toJSON(env.FLAGS) }} -p hi")),
                                caller(job_env=f"FLAGS: {SKIP}")), (CANNOT_TELL, []))


class TheCostTest(unittest.TestCase):
    """Working out the callers' values once for each step that uses the action costs little."""

    def test_many_jobs_using_one_action(self):
        using = {f"j{n}": uses(with_="{flags: '${{ env.X }}'}") for n in range(150)}
        action_text = composite(*(bash_step("claude ${{ inputs.flags }} -p hi " + str(n)) for n in range(5)))
        started = time.monotonic()
        found, errors = gha026(action_text, caller(using, job_env="X: --model sonnet", jobs=tuple(using)))
        self.assertEqual((found, errors), ([], []))
        self.assertLess(time.monotonic() - started, 60)


if __name__ == "__main__":
    unittest.main()
