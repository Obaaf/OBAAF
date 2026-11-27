"""Flagship slice 2d.22 (#399): a value handed to a local action, under an `env` written as one expression.

Slice 2d.19e (D-145) made a local composite action's steps fail closed as D-144 makes a workflow's own step fail
closed: under a scope written as one expression (`env: ${{ fromJSON(vars.E) }}`), a name no nearer mapping sets may
be any text, and where an expression that may give it stands where a command's program goes, or where an agent's
name would be read as its command line, the step is an error of its file. A value handed in through the caller's
`with:` was read as giving the scope's value whole, wherever in the value the scope's text stood. So an input run
as the command line (`run: ${{ inputs.run }}`) given `npm test -- --shard=${{ env.SHARD }}` was an error, where the
same line in a workflow's own step is none: D-145's known false error.

Now an action's expression that is one plain reference to an input the caller hands in is read as the text the
caller's value makes, with each of the caller's expressions read as D-144 reads them in a workflow's own step: one
that may give what the scope sets as one word from the scope, any other that reads `env` as its first value, any
other as a plain word. `workflow._scope_at_program` reads the line made so, as it reads a workflow's own step. That
also reads a newline, a single `&` and a process substitution before the scope's text in such a value, which the
separator rule did not count (D-145's stated ways past).

Anything else is read as before: an action's own expression that is not one plain reference to an input, a value
handed on through a further local action, a value the reader cannot work out, and a line past the text this reading
may make.
"""

import json
import time
import unittest

from test_env_scope_local_actions import JOB, files, lane, result, scope_errors, step, wf

INPUT = "  run: {required: true}\n"


def handed(command, action_run="${{ inputs.run }}", **scopes):
    """The errors of a job under the job's `env` written as one expression whose step hands COMMAND to a local
    action that runs ACTION_RUN."""
    scopes.setdefault("job", JOB)
    return scope_errors(wf(with_="{run: " + json.dumps(command) + "}", **scopes),
                        files(step(action_run), inputs=INPUT))


class TheKnownFalseErrorTest(unittest.TestCase):
    """D-145's known false error is gone: the line is read as a workflow's own step reads it."""

    def test_a_value_from_the_scope_in_an_arguments_place(self):
        for command in ("npm test -- --shard=${{ env.SHARD }}", "make ${{ env.TARGET }}",
                        "pytest -k ${{ env.K }} tests/", "./build.sh --out=${{ env.OUT }}/bin",
                        "echo ${{ env.A }} ${{ env.B }}", "git checkout ${{ github.head_ref || env.REF }}",
                        "deploy --to ${{ format('{0}-{1}', env.REGION, env.STAGE) }}",
                        "${{ env.DIR }}/bin/tool --v"):
            with self.subTest(command=command):
                self.assertEqual(handed(command), [])

    def test_the_same_as_a_workflows_own_step(self):
        """Each command gives an error in a workflow's own step under the same scope exactly where it gives one
        handed to `run: ${{ inputs.run }}`."""
        own = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    permissions: {contents: read}\n"
               f"    env: {JOB}\n    steps:\n      - run: |\n          COMMAND\n")
        for command in ("npm test -- --shard=${{ env.SHARD }}", "${{ env.AGENT }} -p x", "npx ${{ env.AGENT }}",
                        "make; ${{ env.AGENT }} --yes", "make\n${{ env.AGENT }} --yes", "x & ${{ env.AGENT }} --yes",
                        "x <(${{ env.AGENT }} --yes)", "${{ env.DIR }}/bin/tool --v", "sudo ${{ env.TOOL }} --v",
                        "echo ${{ env.A }} -p x", "https://x.test/?a=1&b=${{ env.B }}",
                        "x ${{ env.A || 'safe' }}", "${{ env.A || 'safe' }} --v"):
            with self.subTest(command=command):
                lines = command.split("\n")
                text = own.replace("COMMAND", "\n          ".join(lines))
                expected = bool([e for e in result(text, {}).errors if "may set" in e])
                self.assertEqual(bool(handed(command)), expected)

    def test_where_the_scopes_text_stands_where_a_program_goes(self):
        for command, where in (("${{ env.AGENT }} -p x", "agent"), ("npx ${{ env.AGENT }}", "program"),
                               ("cd x && ${{ env.TOOL }} --v", "program"), ("${{ env.P }}claude", "program"),
                               ("x=1 ${{ env.TOOL }}", "program"), ("echo ok; ${{ env.T }}", "program")):
            with self.subTest(command=command):
                (error,) = handed(command)
                self.assertIn("where an agent's name would be read" if where == "agent"
                              else "where a command's program goes", error)

    def test_where_the_caller_settles_the_name_there_is_no_error(self):
        self.assertEqual(handed("${{ env.AGENT }} -p x", step="{AGENT: echo}"), [])
        self.assertEqual(lane(wf(job=JOB, step="{AGENT: claude}", with_="{run: '${{ env.AGENT }} -p x'}"),
                              files(step("${{ inputs.run }}"), inputs=INPUT)), "agent")


class TheStatedWaysPastTest(unittest.TestCase):
    """D-145's stated ways past, for a value handed in and put in an argument's place, are errors now."""

    def test_a_newline_a_single_ampersand_and_a_process_substitution(self):
        for command in ("make\n${{ env.AGENT }} -p x", "make & ${{ env.AGENT }} -p x", "make &${{ env.T }}",
                        "x <(${{ env.AGENT }} -p x)", "x >(${{ env.T }} --v)", "make\n${{ env.T }} --v"):
            with self.subTest(command=command):
                self.assertEqual(len(handed(command, action_run="echo ${{ inputs.run }}")), 1)

    def test_what_the_separator_rule_counted_still_counts(self):
        for command in ("make; ${{ env.AGENT }} -p review", "make && ${{ env.AGENT }} -p review",
                        "x $(${{ env.AGENT }} -p review)", "make | ${{ env.AGENT }}", "x `${{ env.T }}`",
                        "echo ${{ env.A }}; ${{ env.B }} -p review"):
            with self.subTest(command=command):
                self.assertEqual(len(handed(command, action_run="echo ${{ inputs.run }}")), 1)

    def test_an_argument_in_an_arguments_place_is_none(self):
        for command in ("make ${{ env.TARGET }}", "https://x.test/?a=1&b=${{ env.B }}", "{\"a\": \"${{ env.A }}\"}",
                        "${{ github.head_ref || env.REF }}", "${{ 'y' || env.X }}"):
            with self.subTest(command=command):
                self.assertEqual(handed(command, action_run="echo ${{ inputs.run }}"), [])


class EveryReadingTest(unittest.TestCase):
    """Every text the caller's expressions may give is read with every other, so a separator one may give before
    another's part from the scope counts, as the separator rule read every reading."""

    def test_a_separator_another_expression_may_give(self):
        for command in ("${{ env.Q == 'a' && 'x;' || 'y' }} ${{ env.T }} --yes",
                        "${{ env.S || 'x;' }} ${{ env.T }} --yes",
                        "${{ format('{0}', env.Q == 'a' && 'x &&' || 'y') }} ${{ env.T }} --yes",
                        "${{ env.Z == 'a' && 'make' || 'make\n' }}${{ env.T }} --yes"):
            with self.subTest(command=command):
                self.assertEqual(len(handed(command, action_run="echo ${{ inputs.run }}")), 1)

    def test_two_handed_inputs_on_one_line(self):
        inputs = "  a: {required: true}\n  b: {required: true}\n"
        given = files(step("echo ${{ inputs.a }} ${{ inputs.b }} --yes"), inputs=inputs)
        for a, b, errors in (("x ${{ env.S || 'y;' }}", "${{ env.T }}", 1),
                             ("x ${{ env.S }}", "${{ env.T }}", 0),
                             ("x;", "${{ env.T }}", 1),
                             ("x ${{ env.S }};", "z", 0)):
            with self.subTest(a=a, b=b):
                with_ = "{a: " + json.dumps(a) + ", b: " + json.dumps(b) + "}"
                self.assertEqual(len(scope_errors(wf(job=JOB, with_=with_), given)), errors)

    def test_past_sixteen_readings_it_is_read_as_before(self):
        many = " ".join(f"${{{{ env.Q{n} == 'a' && 'p{n}' || 'q{n}' }}}}" for n in range(5))
        # 32 readings of the caller's value: read as giving the scope's value whole, the known false error.
        self.assertEqual(len(handed("npm test " + many + " --shard=${{ env.S }}")), 1)
        few = " ".join(f"${{{{ env.Q{n} == 'a' && 'p{n}' || 'q{n}' }}}}" for n in range(1))
        self.assertEqual(handed("npm test " + few + " --shard=${{ env.S }}"), [])


class WhatIsReadAsBeforeTest(unittest.TestCase):
    """Where the value cannot be read as the caller wrote it, the expression is read as giving the scope's value
    whole, as before (the known false error stays there, and nothing is quieter)."""

    def test_an_actions_own_expression_that_is_not_one_plain_reference(self):
        for action_run in ("${{ format('{0}', inputs.run) }}", "${{ inputs.run || 'x' }}",
                           "${{ inputs.z == '' && inputs.run || inputs.run }}"):
            with self.subTest(action_run=action_run):
                self.assertEqual(len(handed("npm test -- --shard=${{ env.SHARD }}", action_run=action_run)), 1)

    def test_a_value_handed_on_through_a_further_local_action(self):
        inner = ("name: i\ninputs:\n  run: {required: true}\nruns:\n  using: composite\n  steps:\n"
                 "    - run: ${{ inputs.run }}\n      shell: bash\n")
        outer = ("name: x\ninputs:\n  run: {required: true}\nruns:\n  using: composite\n  steps:\n"
                 "    - uses: ./.github/actions/inner\n      with:\n        run: ${{ inputs.run }}\n")
        given = {".github/actions/run-agent/action.yml": outer, ".github/actions/inner/action.yml": inner}
        self.assertEqual(len(scope_errors(wf(job=JOB, with_="{run: 'npm test -- --shard=${{ env.SHARD }}'}"),
                                          given)), 1)

    def test_the_fifth_reviews_ways_past_hold(self):
        forged = files(step("# ${{ inputs.d }}{{ '\n${{ env.AGENT }} -p x\n# ' }}"), inputs="  d: {default: $}\n")
        self.assertEqual(len(scope_errors(wf(job=JOB), forged)), 1)
        paired = ("${{ env.Q1 == 'a' && format('echo {0};', env.X) || format('echo {0}', env.X) }} "
                  "${{ env.Q2 == 'a' && format('x {0}', env.Y) || env.Y }} --yes")
        self.assertEqual(len(scope_errors(wf(job=JOB), files(step(paired)))), 1)

    def test_a_value_that_would_open_an_expression_with_the_actions_own_text(self):
        """A handed value ending in `$` beside the action's own `{{ ... }}`: the line is read as the runner gives it,
        and the action's own expression after it still counts."""
        given = files(step("${{ inputs.run }}{{ x }}\n${{ env.AGENT }} -p x"), inputs=INPUT)
        self.assertEqual(len(scope_errors(wf(job=JOB, with_="{run: 'echo ${{ env.S }} $'}"), given)), 1)
        given = files(step("echo ${{ inputs.run }}{{ ' ${{ env.AGENT }} -p x ' }}"), inputs=INPUT)
        self.assertEqual(len(scope_errors(wf(job=JOB, with_="{run: 'a ${{ env.S }} $'}"), given)), 1)

    def test_a_caller_expression_nested_more_deeply_than_the_reader_follows(self):
        deep = "${{ " + "(env.Z == 'q' || " * 10 + "env.S" + ")" * 10 + " }}"
        self.assertEqual(len(handed("npm test --shard=" + deep)), 1)


class TheActionsOwnTextTest(unittest.TestCase):
    """The text a handed value makes beside the action's own expressions hides none of them."""

    def test_an_actions_own_expression_after_a_handed_value(self):
        for action_run in ("${{ inputs.run }} ${{ env.AGENT }} -p x", "${{ inputs.run }}; ${{ env.T }} --v",
                           "${{ inputs.run }}\n${{ env.T }} --v", "${{ inputs.run }} && ${{ env.T }}"):
            for command in ("npm test --shard=${{ env.S }}", "echo #${{ env.S }}", "echo '${{ env.S }}"):
                with self.subTest(action_run=action_run, command=command):
                    self.assertEqual(len(handed(command, action_run=action_run)), 1)

    def test_a_github_script_script_and_the_egress_actions_command(self):
        for body, bad in (("    - uses: actions/github-script@1111111111111111111111111111111111111111\n"
                           "      with:\n        script: |\n          exec('${{ inputs.run }}')\n", None),
                          ("    - uses: Obaaf/OBAAF/actions/egress@1111111111111111111111111111111111111111\n"
                           "      with:\n        allow: api.anthropic.com\n        run: ${{ inputs.run }}\n", None)):
            given = {".github/actions/run-agent/action.yml":
                     "name: x\ninputs:\n" + INPUT + "runs:\n  using: composite\n  steps:\n" + body}
            with self.subTest(body=body.split("@")[0]):
                self.assertEqual(len(scope_errors(wf(job=JOB, with_="{run: '${{ env.AGENT }} -p x'}"), given)), 1)
                self.assertEqual(scope_errors(wf(job=JOB, with_="{run: 'npm test --shard=${{ env.S }}'}"),
                                              given), [])

    def test_the_inputs_default(self):
        given = files(step("${{ inputs.run }}"), inputs="  run: {default: 'npm test --shard=${{ env.S }}'}\n")
        self.assertEqual(scope_errors(wf(job=JOB), given), [])
        given = files(step("${{ inputs.run }}"), inputs="  run: {default: '${{ env.T }} --v'}\n")
        self.assertEqual(len(scope_errors(wf(job=JOB), given)), 1)


class TheCostTest(unittest.TestCase):

    def test_a_large_value_read_in_many_lines(self):
        big = "npm test " + " ".join(f"--x{n}=${{{{ env.S{n} }}}}" for n in range(3000))
        run = "\n".join(f"echo {n} ${{{{ inputs.run }}}}" for n in range(300))
        given = files(step(run), inputs=INPUT)
        started = time.monotonic()
        self.assertEqual(scope_errors(wf(job=JOB, with_="{run: '" + big + "'}"), given), [])
        self.assertLess(time.monotonic() - started, 20)


if __name__ == "__main__":
    unittest.main()
