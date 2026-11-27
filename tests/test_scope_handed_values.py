"""Flagship slice 2d.22 (#399): a value handed to a local action, under an `env` written as one expression.

Slice 2d.19e (D-145) made a local composite action's steps fail closed as D-144 makes a workflow's own step fail
closed: under a scope written as one expression (`env: ${{ fromJSON(vars.E) }}`), a name no nearer mapping sets may
be any text, and where an expression that may give it stands where a command's program goes, or where an agent's
name would be read as its command line, the step is an error of its file. A value handed in through the caller's
`with:` is read as giving the scope's value whole, wherever in the value the scope's part stands. So an input run
as the command line (`run: ${{ inputs.run }}`) given `npm test -- --shard=${{ env.SHARD }}` was an error, where the
same line in a workflow's own step is none: D-145's known false error.

D-150: that reading stays, apart from two changes for an expression that is one plain reference to an input whose
value, as the caller wrote it, holds what the scope may give:

- **Cleared.** In a bash or sh step's `run`, a value that is one text of plain characters (`_PLAIN_TEXT`) whose
  every expression is one plain reference to `env`, each scope's part inside a word after a character other than a
  space or `/` (`--shard=${{ env.SHARD }}`), is read as its text, with the scope's part as a plain word. Whatever
  one word the scope gives there, no program and no command a program runs from its arguments is named by it.
- **Added.** A newline before a scope's part, in any text the caller's value can make, is a program's place, as a
  shell reads it, also where the value is put after `echo` (one of D-145's stated ways past).

Everything else is read as before. The first review of this slice showed why the wider reading first built here
(the line made read as D-144 reads a workflow's own step) was quieter than the base: D-144's program reader does not
know every program that runs its arguments (`xvfb-run`, `find -exec`, `trap`), a line a `^` or a backtick continues,
separators written inside the caller's expressions, or a comment's backslash.
"""

import json
import time
import unittest

from test_env_scope_local_actions import JOB, files, lane, result, scope_errors, step, wf

INPUT = "  run: {required: true}\n"


def handed(command, action_run="${{ inputs.run }}", shell="bash", **scopes):
    """The scope errors of a job under the job's `env` written as one expression whose step hands COMMAND to a local
    action that runs ACTION_RUN in a step with SHELL."""
    scopes.setdefault("job", JOB)
    return scope_errors(wf(with_="{run: " + json.dumps(command) + "}", **scopes),
                        files(step(action_run, shell=shell), inputs=INPUT))


class TheKnownFalseErrorIsClearedTest(unittest.TestCase):
    """D-145's known false error is gone where the scope's part stands inside a word of a plain value."""

    def test_inside_a_word_of_a_plain_value(self):
        for command in ("npm test -- --shard=${{ env.SHARD }}", "./build.sh --out=${{ env.OUT }}/bin",
                        "deploy --region=${{ env.REGION }}-${{ env.STAGE }}", "npm test -- --shard=${{ env['SHARD'] }}",
                        "pytest --k=a${{ env.K }} tests/", "make V=${{ env.V }}", "x@${{ env.H }}:1"):
            with self.subTest(command=command):
                self.assertEqual(handed(command), [])

    def test_the_input_written_otherwise_and_sh(self):
        for action_run in ("${{ inputs['run'] }}", "${{ INPUTS.RUN }}", "${{ inputs.run }} --more",
                           "timeout 60 ${{ inputs.run }}"):
            with self.subTest(action_run=action_run):
                self.assertEqual(handed("npm test --shard=${{ env.S }}", action_run=action_run), [])
        self.assertEqual(handed("npm test --shard=${{ env.S }}", shell="sh"), [])

    def test_a_name_the_caller_settles_is_put_in(self):
        self.assertEqual(handed("npm ${{ env.CMD }} --shard=${{ env.S }}", step="{CMD: test}"), [])
        self.assertEqual(len(handed("npm ${{ env.CMD }} --shard=${{ env.S }}", step="{CMD: 'test; x'}")), 1)

    def test_an_assignment_before_another_expression(self):
        """A cleared value is read as its own text, not as one word, so an assignment it writes leaves the program's
        place to what follows."""
        self.assertEqual(len(handed("X=${{ env.S }}", action_run="${{ inputs.run }} ${{ env.T }} --v")), 1)
        self.assertEqual(handed("X=${{ env.S }}", action_run="${{ inputs.run }} make --v"), [])

    def test_where_the_caller_settles_the_name_there_was_no_error_and_is_none(self):
        self.assertEqual(handed("${{ env.AGENT }} -p x", step="{AGENT: echo}"), [])
        self.assertEqual(lane(wf(job=JOB, step="{AGENT: claude}", with_="{run: '${{ env.AGENT }} -p x'}"),
                              files(step("${{ inputs.run }}"), inputs=INPUT)), "agent")


class WhatStaysAnErrorTest(unittest.TestCase):
    """Anything that is not cleared is read as D-145 reads it: the whole value from the scope, so an input run as
    the command line stays an error. Each case here gave no error with the wider reading first built (the first
    review of this slice), and bash runs the scope's value as a program in each where the value says so."""

    def assertError(self, command, **kwargs):
        self.assertEqual(len(handed(command, **kwargs)), 1, command)

    def test_the_scopes_part_as_a_word_of_its_own(self):
        for command in ("make ${{ env.TARGET }}", "${{ env.AGENT }} -p x", "npx ${{ env.AGENT }}",
                        "xvfb-run -a ${{ env.A }} --message hi", "timeout 5 ${{ env.A }} --message hi",
                        "exec -a x ${{ env.A }} --message hi", "${{ env.DIR }}/bin/tool --v",
                        "./bin/${{ env.T }} --v", "/usr/bin/${{ env.T }}", "x ${{ env.S }}"):
            with self.subTest(command=command):
                self.assertError(command)

    def test_characters_the_shell_reads_as_more_than_words(self):
        for command in ("find . -exec ${{ env.A }} --message hi \\;", "trap '${{ env.A }} --message hi' EXIT",
                        "A=\"x y\" ${{ env.A }} --message hi", "echo \"x=${{ env.A }} --message hi\" | bash",
                        "make ^\n${{ env.A }} --message hi", "make `\n${{ env.A }} --message hi`",
                        "make \\\r\n${{ env.A }} --message hi", "# note \\\n${{ env.A }} --message hi",
                        "echo x \\\\\n${{ env.A }} --message hi", "x=${{ env.A }}\tz", "x={${{ env.A }},y}",
                        "x=${{ env.A }};y", "x=a&${{ env.A }}", "x=$(${{ env.A }})", "x=*${{ env.A }}",
                        "x=~${{ env.A }}", "x='${{ env.A }}'"):
            with self.subTest(command=command):
                self.assertError(command)

    def test_separators_written_inside_the_callers_expressions(self):
        for command in ("${{ format('make; {0} -p hi', env.A) }}", "${{ format('make; {0} --message x', env.A) }}",
                        "${{ format('make && {0} -p x', env.A) }}", "${{ 'x;' }} ${{ env.A }} --message hi",
                        "${{ 'x;' }} ${{ env.A }} ${{ '-p' }} hi", "${{ github.head_ref || 'x;' }} ${{ env.A }} --message hi",
                        "${{ fromJSON('\"x;\"') }} ${{ env.A }} --message hi", "x=${{ format('{0}', env.A) }}",
                        "x=${{ env.A || 'y' }}", "x=${{ toJSON(env.A) }}", "x=${{ matrix.sep }}${{ env.A }}"):
            with self.subTest(command=command):
                self.assertError(command)

    def test_other_shells_and_other_command_lines(self):
        for shell in ("pwsh", "cmd", "python", "Bash"):
            with self.subTest(shell=shell):
                self.assertError("npm test --shard=${{ env.S }}", shell=shell)
        for body in ("    - uses: actions/github-script@1111111111111111111111111111111111111111\n"
                     "      with:\n        script: |\n          exec('${{ inputs.run }}')\n",
                     "    - uses: Obaaf/OBAAF/actions/egress@1111111111111111111111111111111111111111\n"
                     "      with:\n        allow: api.anthropic.com\n        run: ${{ inputs.run }}\n"):
            given = {".github/actions/run-agent/action.yml":
                     "name: x\ninputs:\n" + INPUT + "runs:\n  using: composite\n  steps:\n" + body}
            with self.subTest(body=body.split("@")[0]):
                self.assertEqual(len(scope_errors(wf(job=JOB, with_="{run: 'npm test --shard=${{ env.S }}'}"),
                                                  given)), 1)

    def test_an_actions_own_expression_that_is_not_one_plain_reference(self):
        for action_run in ("${{ format('{0}', inputs.run) }}", "${{ inputs.run || 'x' }}",
                           "${{ inputs.z == '' && inputs.run || inputs.run }}"):
            with self.subTest(action_run=action_run):
                self.assertError("npm test -- --shard=${{ env.SHARD }}", action_run=action_run)

    def test_a_value_handed_on_through_a_further_local_action(self):
        inner = ("name: i\ninputs:\n  run: {required: true}\nruns:\n  using: composite\n  steps:\n"
                 "    - run: ${{ inputs.run }}\n      shell: bash\n")
        outer = ("name: x\ninputs:\n  run: {required: true}\nruns:\n  using: composite\n  steps:\n"
                 "    - uses: ./.github/actions/inner\n      with:\n        run: ${{ inputs.run }}\n")
        given = {".github/actions/run-agent/action.yml": outer, ".github/actions/inner/action.yml": inner}
        self.assertEqual(len(scope_errors(wf(job=JOB, with_="{run: 'npm test -- --shard=${{ env.SHARD }}'}"),
                                          given)), 1)

    def test_past_what_the_reader_makes(self):
        self.assertError("npm test --shard=${{ env.S }} " + "a" * 200_001)
        deep = "${{ " + "(env.Z == 'q' || " * 10 + "env.S" + ")" * 10 + " }}"
        self.assertError("npm test --shard=" + deep)

    def test_the_fifth_reviews_ways_past_of_2d19e_hold(self):
        forged = files(step("# ${{ inputs.d }}{{ '\n${{ env.AGENT }} -p x\n# ' }}"), inputs="  d: {default: $}\n")
        self.assertEqual(len(scope_errors(wf(job=JOB), forged)), 1)
        paired = ("${{ env.Q1 == 'a' && format('echo {0};', env.X) || format('echo {0}', env.X) }} "
                  "${{ env.Q2 == 'a' && format('x {0}', env.Y) || env.Y }} --yes")
        self.assertEqual(len(scope_errors(wf(job=JOB), files(step(paired)))), 1)


class ANewlineBeforeTheScopesPartTest(unittest.TestCase):
    """A newline before the scope's part in a handed value starts a command there, wherever the value is put."""

    def test_put_after_echo(self):
        for command in ("make\n${{ env.AGENT }} -p x", "make\n${{ env.T }} --v", "make ^\n${{ env.A }} --message hi",
                        "make \\\r\n${{ env.A }} --message hi", "echo a\n\n  ${{ env.T }}",
                        "${{ env.Z == 'a' && 'make' || 'make\n' }}${{ env.T }} --yes"):
            with self.subTest(command=command):
                (error,) = handed(command, action_run="echo ${{ inputs.run }}")
                self.assertIn("where a command's program goes", error)

    def test_a_newline_after_it_is_no_error_in_an_arguments_place(self):
        for command in ("echo ${{ env.T }}\nmake", "${{ github.head_ref || env.REF }}", "${{ 'y' || env.X }}"):
            with self.subTest(command=command):
                self.assertEqual(handed(command, action_run="echo ${{ inputs.run }}"), [])

    def test_the_inputs_default(self):
        given = files(step("echo ${{ inputs.run }}"), inputs="  run: {default: \"make\\n${{ env.T }} --v\"}\n")
        self.assertEqual(len(scope_errors(wf(job=JOB), given)), 1)


class TheCostTest(unittest.TestCase):

    def test_a_long_action_and_a_value_of_many_readings(self):
        """The first review's worst case: a long step and a handed value of 16 readings, 12 times the base with the
        wider reading. Each line is read once now."""
        lines = "\n".join(f"e ${{{{env.X}}}} {n}" for n in range(8000))
        given = files(step(lines + "\necho ${{ inputs.run }}"), inputs=INPUT)
        value = "${{ env.Q0 == 'a' && 'p0' || 'q0' }} ${{ env.Q1 == 'a' && 'p1' || 'q1' }} --s=${{ env.S }}"
        started = time.monotonic()
        self.assertEqual(scope_errors(wf(job=JOB, with_="{run: " + json.dumps(value) + "}"), given), [])
        self.assertLess(time.monotonic() - started, 20)


if __name__ == "__main__":
    unittest.main()
