"""Flagship slice 2d.19c (#382): OBAAF-GHA-026 reads the options that `${{ }}` expressions reading `env` give.

GitHub works out a `${{ }}` expression in a step's `run`, a github-script script and an action's input before the
shell or the script starts. Slice 2d.19b taught the lanes to work out the ones that read `env`; OBAAF-GHA-026 still
read them as written, so `claude ${{ env.FLAGS }} -p review` with `FLAGS: --dangerously-skip-permissions` was its
medium "cannot tell" (`command-computed`) where the same option written out is high, and a harmless value was
"cannot tell" too. Now the rule reads the worked-out text where the checker knows every value the expressions can
read (`Rules._env_expressions_worked`), and as written otherwise.
"""

import time
import unittest

from helpers import TempDir
from test_egress_recognised import RELEASED, action, run_check, workflow
from test_env_expressions import flow
from test_local_composite_actions import check

SKIP = "--dangerously-skip-permissions"


def gha026(text):
    """(severity, kind) of each OBAAF-GHA-026 finding on job `a`."""
    with TempDir() as tmp:
        result = check(tmp, text)
    return sorted((f.severity, f.kind) for f in result.findings if f.rule == "OBAAF-GHA-026")


def errors(text):
    with TempDir() as tmp:
        return list(check(tmp, text).errors)


HIGH = [("high", "command-option")]
CANNOT_TELL = [("medium", "command-computed")]


class TheOptionIsReadTest(unittest.TestCase):
    """A warned option an expression gives is the high finding it is written out."""

    def test_written_out_is_high(self):
        # The oracle: the same option written in the script.
        self.assertEqual(gha026(flow(f"claude {SKIP} -p review")), HIGH)

    def test_from_each_scope(self):
        for where in ("top_env", "job_env", "step_env"):
            with self.subTest(where=where):
                self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review", **{where: f"{{FLAGS: {SKIP}}}"})),
                                 HIGH)

    def test_the_agent_and_the_option_both_from_env(self):
        self.assertEqual(gha026(flow("${{ env.AGENT }} ${{ env.FLAGS }} -p review",
                                     job_env=f"{{AGENT: claude, FLAGS: {SKIP}}}")), HIGH)

    def test_bracket_and_upper_case_context(self):
        for ref in ("env['FLAGS']", "ENV.FLAGS", "Env['FLAGS']"):
            with self.subTest(ref=ref):
                self.assertEqual(gha026(flow(f"claude ${{{{ {ref} }}}} -p review", job_env=f"{{FLAGS: {SKIP}}}")),
                                 HIGH)

    def test_an_option_in_pieces_across_two_expressions(self):
        self.assertEqual(gha026(flow("claude ${{ env.A }}${{ env.B }} -p review",
                                     job_env="{A: --dangerously-skip, B: -permissions}")), HIGH)

    def test_a_value_that_holds_shell_syntax_is_read_as_the_shell_reads_it(self):
        # GitHub pastes the value into the script, so its quotes are the script's (`$FLAGS` would not be).
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review",
                                     job_env=f"{{FLAGS: \"'{SKIP}'\"}}")), HIGH)

    def test_pwsh_on_windows_folds_the_name(self):
        # #387: a hosted Windows runner compares `env` names without regard to case.
        self.assertEqual(gha026(flow("claude ${{ env.flags }} -p review", job_env=f"{{FLAGS: {SKIP}}}",
                                     runs_on="windows-latest", shell="pwsh")), HIGH)

    def test_cmd_takes_a_caret_out_of_the_value_too(self):
        # GitHub puts the value in first; cmd then takes `^` out of the whole line, the value included.
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review",
                                     job_env="{FLAGS: --dangerously-skip-^permissions}",
                                     runs_on="windows-latest", shell="cmd")), HIGH)

    def test_github_script(self):
        step = ("      - uses: actions/github-script@" + "a" * 40 + "\n        with:\n"
                "          script: await exec.exec('claude', ['${{ env.FLAGS }}', '-p', 'x'])\n"
                "        env:\n          ANTHROPIC_API_KEY: ${{ secrets.K }}\n")
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    permissions: {contents: read}\n"
                f"    env: {{FLAGS: {SKIP}}}\n    steps:\n" + step)
        self.assertEqual(gha026(text), HIGH)

    def test_the_egress_actions_command(self):
        text = workflow(action(run="claude ${{ env.FLAGS }} -p review", ref=RELEASED),
                        job_extra=f"    env: {{FLAGS: {SKIP}}}")
        result = run_check(text)
        found = sorted((f.severity, f.kind) for f in result.findings if f.rule == "OBAAF-GHA-026")
        self.assertEqual(found, HIGH)

    def test_one_reading_where_the_runner_is_not_known(self):
        # A runner that may be Windows, with the name set once: both comparisons give the same text.
        self.assertEqual(gha026(flow("claude ${{ env.flags }} -p review", job_env=f"{{flags: {SKIP}}}",
                                     runs_on="[self-hosted]")), HIGH)


class AHarmlessValueIsQuietTest(unittest.TestCase):
    """Where the checker knows every value and none warns, there is nothing to tell."""

    def test_a_harmless_value(self):
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: --model sonnet}")), [])

    def test_the_steps_value_wins(self):
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review", job_env=f"{{FLAGS: {SKIP}}}",
                                     step_env="FLAGS: --model sonnet")), [])

    def test_the_steps_value_wins_on_windows_in_another_case(self):
        # #387: on Windows the step's `flags` replaces the job's `FLAGS`.
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review", job_env=f"{{FLAGS: {SKIP}}}",
                                     step_env="flags: --model sonnet", runs_on="windows-latest", shell="pwsh")), [])

    def test_on_linux_another_case_is_another_name(self):
        # Exact on a hosted Linux runner: `flags` is not `FLAGS`, so the job's value is the one.
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review", job_env=f"{{FLAGS: {SKIP}}}",
                                     step_env="flags: --model sonnet")), HIGH)


class WhatTheCheckerDoesNotKnowIsCannotTellTest(unittest.TestCase):
    """Each case where a value may be other than the files say stays "cannot tell", as before the slice."""

    def test_a_name_no_env_sets(self):
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review")), CANNOT_TELL)

    def test_a_name_set_only_in_another_case_on_linux(self):
        # GitHub gives nothing; the checker does not take a name it cannot find for empty.
        self.assertEqual(gha026(flow("claude ${{ env.flags }} -p review", job_env="{FLAGS: --model x}")),
                         CANNOT_TELL)

    def test_an_earlier_step_writes_github_env(self):
        text = flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: --model x}").replace(
            "    steps:\n", f"    steps:\n      - run: echo 'FLAGS={SKIP}' >> \"$GITHUB_ENV\"\n", 1)
        self.assertEqual(gha026(text), CANNOT_TELL)

    def test_an_env_written_as_one_expression(self):
        for where in ("top_env", "job_env"):
            with self.subTest(where=where):
                self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review",
                                             **{where: "${{ fromJSON(vars.E) }}"})), CANNOT_TELL)

    def test_a_reference_not_pinned_to_one_name(self):
        for ref in ("env[matrix.k]", "toJSON(env)", "join(env.*, ' ')"):
            with self.subTest(ref=ref):
                text = flow(f"claude ${{{{ {ref} }}}} -p review", job_env="{FLAGS: --model x}",
                            extra="    strategy: {matrix: {k: [FLAGS]}}\n")
                self.assertEqual(gha026(text), CANNOT_TELL)

    def test_another_context_beside_an_empty_value(self):
        # `env.F` is empty, so `||` gives the input, which the checker does not know.
        self.assertEqual(gha026(flow("claude ${{ env.F || github.event.inputs.f }} -p review",
                                     job_env="{F: ''}")), CANNOT_TELL)

    def test_an_expression_of_another_context_on_the_same_line(self):
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} ${{ inputs.more }} -p review",
                                     job_env="{FLAGS: --model x}")), CANNOT_TELL)

    def test_a_value_that_is_not_text(self):
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: [a, b]}")),
                         CANNOT_TELL)


class WhatTheReviewFoundTest(unittest.TestCase):
    """The review of 2d.19c (#382): each way past it found, base medium and quiet with the first version."""

    def test_another_context_beside_a_known_value(self):
        # `env_expr` leaves out a value it does not know beside one it knows, and reads one inside `format` and
        # `join` as empty: GitHub runs what `inputs.flags` holds.
        for expression in ("inputs.flags || env.SAFE", "format('{0} {1}', env.SAFE, inputs.extra)",
                           "join(matrix.f, env.SAFE)", "matrix.f || env.EMPTY", "env.SAFE && github.event.x",
                           "vars.F || env.SAFE"):
            with self.subTest(expression=expression):
                self.assertEqual(gha026(flow(f"claude ${{{{ {expression} }}}} -p review",
                                             job_env="{SAFE: --model sonnet, EMPTY: ''}")), CANNOT_TELL)

    def test_several_readings_of_a_line(self):
        # The second reading would be inside the first's heredoc; GitHub runs one of them, which may warn.
        run = ("claude ${{ startsWith(env.MODE, 'safe') && '--model sonnet' || '" + SKIP + "' }} -p \"$(cat <<'P'\n"
               "Review.\nP\n)\"")
        self.assertEqual(gha026(flow(run, job_env="{MODE: full}")), CANNOT_TELL)
        # Two letter cases on a runner that may be Windows: two readings.
        self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: --model x}",
                                     step_env=f"flags: {SKIP}", runs_on="[self-hosted]")), CANNOT_TELL)

    def test_a_value_that_holds_an_expression(self):
        # GitHub works the value's own expression out before it puts the value in.
        for value in ('"--model sonnet # ${{ vars.EXTRA }}"', "\"'${{ vars.F }}'\"", '"${{ matrix.f }}"'):
            with self.subTest(value=value):
                self.assertEqual(gha026(flow("claude ${{ env.FLAGS }} -p review", job_env=f"{{FLAGS: {value}}}")),
                                 CANNOT_TELL)

    def test_writers_the_older_pattern_misses(self):
        for writer in ("echo 'FLAGS=x' >> \"${{ github.env }}\"", "echo '::set-env name=FLAGS::x'"):
            with self.subTest(writer=writer):
                text = flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: --model x}").replace(
                    "    steps:\n", f"    steps:\n      - run: |\n          {writer}\n", 1)
                self.assertEqual(gha026(text), CANNOT_TELL)
        script = ("      - uses: actions/github-script@" + "a" * 40 + "\n        with:\n"
                  "          script: c['export' + 'Variable']('FLAGS', 'x')\n")
        text = flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: --model x}").replace(
            "    steps:\n", "    steps:\n" + script, 1)
        self.assertEqual(gha026(text), CANNOT_TELL)
        text = flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: --model x, ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'}")
        self.assertEqual(gha026(text), CANNOT_TELL)

    def test_a_local_actions_step_is_read_as_written(self):
        # The caller works its `with` out in its own context; the action's step reads its own `env`.
        action = ("runs:\n  using: composite\n  steps:\n    - shell: bash\n      env: {X: --model sonnet}\n"
                  "      run: claude ${{ inputs.flags }} -p hi\n")
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    permissions: {contents: read}\n"
                f"    env:\n      X: {SKIP}\n      ANTHROPIC_API_KEY: ${{{{ secrets.K }}}}\n    steps:\n"
                "      - uses: ./.github/actions/run-claude\n        with: {flags: '${{ env.X }}'}\n")
        with TempDir() as tmp:
            result = check(tmp, text, files={".github/actions/run-claude/action.yml": action})
        self.assertEqual(list(result.errors), [])
        found = sorted((f.severity, f.kind) for f in result.findings if f.rule == "OBAAF-GHA-026")
        self.assertEqual(found, CANNOT_TELL)

    def test_many_values_under_odd_names_do_not_raise(self):
        job_env = "{" + ", ".join(f"{n}: v{n}" for n in range(4200)) + ", X: --model sonnet}"
        with TempDir() as tmp:
            result = check(tmp, flow("claude ${{ env.X }} -p hi", job_env=job_env))
        self.assertIsNotNone(result)


class TheSecondReviewTest(unittest.TestCase):
    """The second review of 2d.19c: each way past and cost it found."""

    def test_fromjson_and_tojson_are_read_as_written(self):
        # Python's JSON reader refuses what the runner's reads (single quotes, comments, trailing commas), and
        # took the refused text for empty.
        for expression, value in (("fromJSON(env.J)", f"\"'{SKIP}'\""),
                                  ("fromJSON(env.J).flags", f"\"{{flags: '{SKIP}'}}\""),
                                  ("fromJSON(env.J)[0]", f"'[\"{SKIP}\",]'"),
                                  ("fromJSON(env.J)", f"'\"{SKIP}\" // default'"),
                                  ("toJSON(env.J)", "--model sonnet"),
                                  ("contains(env.J, 'x') && '--model sonnet' || '--model haiku'", "x")):
            with self.subTest(expression=expression):
                self.assertEqual(gha026(flow(f"claude ${{{{ {expression} }}}} -p hi", job_env=f"{{J: {value}}}")),
                                 CANNOT_TELL)

    def test_more_writers(self):
        for writer in ('for f in "$RUNNER_TEMP"/_runner_file_command*/set_env_*; do echo "FLAGS=x" >> "$f"; done',
                       "echo '${{ toJSON(github) }}' | jq -r .env",
                       "node -e \"require('@actions/core')['export' + 'Variable']('FLAGS', 'x')\""):
            with self.subTest(writer=writer):
                text = flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: --model x}").replace(
                    "    steps:\n", f"    steps:\n      - run: |\n          {writer}\n", 1)
                self.assertEqual(gha026(text), CANNOT_TELL)

    def test_an_alias_bomb_before_the_step_is_read_once(self):
        lines = ["x0: &x0 [" + ", ".join(["aaaaaaaaaa"] * 5) + "]"]
        for n in range(1, 25):
            lines.append(f"x{n}: &x{n} [*x{n - 1}, *x{n - 1}]")
        bomb = "".join(f"          {line}\n" for line in lines)
        text = flow("claude ${{ env.FLAGS }} -p review", job_env="{FLAGS: --model x}").replace(
            "    steps:\n", "    steps:\n      - uses: some/action@" + "a" * 40 + "\n        with:\n" + bomb, 1)
        started = time.monotonic()
        self.assertEqual(gha026(text), [])
        self.assertLess(time.monotonic() - started, 10)


class NothingElseChangesTest(unittest.TestCase):

    def test_no_new_error(self):
        for text in (flow("claude ${{ env.FLAGS }} -p review", job_env=f"{{FLAGS: {SKIP}}}"),
                     flow("claude ${{ env.FLAGS }} -p review"),
                     flow("make ${{ env.T }}", job_env="{T: test}")):
            with self.subTest(text=text):
                self.assertEqual(errors(text), [])

    def test_a_step_that_names_no_agent(self):
        self.assertEqual(gha026(flow("make ${{ env.T }}", job_env=f"{{T: {SKIP}}}")), [])


if __name__ == "__main__":
    unittest.main()
