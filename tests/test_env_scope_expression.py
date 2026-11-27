"""Flagship slice 2d.19d (#382): a scope's `env` written as one expression, in the lanes.

GitHub works out a `${{ }}` expression in a step's `run` with the `env` context: the workflow's, the job's and the
step's own `env`, the nearest winning. A scope may be written as one expression (`env: ${{ fromJSON(vars.E) }}`,
`env: ${{ matrix.env }}`), whose names and values the file does not show. Before this slice the lanes (D-142) read a
name such a scope may set as a value of another context, which made no reading, so `run: ${{ env.AGENT }} -p x`
under `env: ${{ fromJSON(vars.E) }}` put the job in no agent lane, with no error and no finding (F-418). Now such a
scope may give any name any text: an expression whose text may be what it gives (a name no mapping nearer the step
sets, under the runner's comparison of names, or the whole `env`) still makes no reading, but where it stands where
a command's program goes the step is an error of its file, as D-142's other refusals are. Elsewhere in a line
(`echo ${{ env.VERSION }}`, `mkdir -p ${{ env.CCACHE_DIR }}`) it is read as before, so the ordinary idiom
`env: ${{ matrix.env }}` gives no new error there; where the value is the program (`${{ env.CC }} --version`) it is
an error, since the checker does not read the matrix through it.
"""

import time
import unittest

from helpers import TempDir
from test_env_expressions import UNREAD, lane, problems
from test_local_composite_actions import KEY, check

from obaaf.checker import env_expr

SCOPE = "written as one expression the checker does not read, may set"
PLACE = "where a command's program goes"


def wf(run, top="", job="", step="", runs_on="ubuntu-24.04", matrix="", shell="bash", key=True):
    """A workflow of one job `a`. `top`, `job` and `step` are the `env` of each scope, written as YAML (a flow
    mapping or one expression); `matrix` is the job's matrix as YAML lines under `matrix:`."""
    body = "".join(f"          {line}\n" for line in run.split("\n"))
    text = "on: workflow_dispatch\n" + (f"env: {top}\n" if top else "")
    text += f"jobs:\n  a:\n    runs-on: {runs_on}\n    permissions: {{contents: read}}\n"
    if matrix:
        text += "    strategy:\n      matrix:\n" + "".join(f"        {line}\n" for line in matrix.split("\n"))
    if job:
        text += f"    env: {job}\n"
    text += f"    steps:\n      - shell: {shell}\n        run: |\n{body}"
    if step:
        text += f"        env: {step}\n"
    if key:
        text += f"      - run: echo done\n        env:\n          ANTHROPIC_API_KEY: {KEY}\n"
    return text


def scope_errors(text):
    return [p for p in problems(text) if SCOPE in p]


JOB = "${{ fromJSON(vars.E) }}"


class TheCaseOfF418Test(unittest.TestCase):
    """The case F-418 left: no agent lane, no error and no finding on the base."""

    def test_the_issue_case_is_an_error_of_the_file(self):
        (error,) = problems(wf("${{ env.AGENT }} -p review", job=JOB))
        self.assertIn(UNREAD, error)
        self.assertIn("('${{ env.AGENT }}'), where an agent's name would be read as its command line, reads from "
                      f"`env` what the job's `env`, {SCOPE}", error)
        self.assertIn("so the checker cannot tell whether an agent runs in it", error)

    def test_each_scope_is_named_and_the_nearest_one(self):
        for where, scopes in (("the workflow's", {"top": JOB}), ("the job's", {"job": JOB}),
                              ("the step's own", {"step": JOB}), ("the job's", {"top": JOB, "job": JOB})):
            with self.subTest(where=where, scopes=scopes):
                (error,) = scope_errors(wf("${{ env.AGENT }} -p x", **scopes))
                self.assertIn(f"what {where} `env`, {SCOPE}", error)

    def test_a_scope_from_the_matrix_or_written_any_other_way(self):
        for scope in ("${{ matrix.env }}", "${{ vars.E }}", "'${{ fromJSON(needs.a.outputs.e) }}'", "some text",
                      "'${{ inputs.e }}'", "[a, b]", "3"):
            with self.subTest(scope=scope):
                text = wf("${{ env.AGENT }} -p x", job=scope, matrix="env:\n  - {AGENT: claude}")
                self.assertEqual(len(scope_errors(text)), 1, problems(text))

    def test_the_egress_actions_command_and_a_github_script_script(self):
        egress = (f"on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    env: {JOB}\n"
                  "    steps:\n      - uses: Obaaf/OBAAF/actions/egress@1111111111111111111111111111111111111111\n"
                  "        with:\n          allow: api.anthropic.com\n          run: ${{ env.AGENT }} -p x\n")
        script = (f"on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    env: {JOB}\n"
                  "    steps:\n      - uses: actions/github-script@1111111111111111111111111111111111111111\n"
                  "        with:\n          script: |\n            exec.exec('${{ env.AGENT }} -p x')\n")
        for text in (egress, script):
            with self.subTest(text=text[-60:]):
                self.assertEqual(len(scope_errors(text)), 1)


class WhereACommandsProgramGoesTest(unittest.TestCase):
    """The places the lanes read as a command's program; and the rest of a line, read as before."""

    def test_program_places(self):
        for run in ("${{ env.AGENT }} -p x", "echo hi; ${{ env.AGENT }} -p x", "true && ${{ env.AGENT }}",
                    "a | ${{ env.AGENT }}", "x=$(${{ env.AGENT }} -p y)", "sudo -u r ${{ env.AGENT }} -p x",
                    "npx ${{ env.AGENT }}", "env A=1 ${{ env.AGENT }}", "timeout 5m ${{ env.AGENT }}",
                    "bash -c \"${{ env.AGENT }} -p x\"", "\"${{ env.AGENT }}\" -p x", "eval ${{ env.AGENT }}",
                    "A=1 ${{ env.AGENT }}", "/usr/bin/${{ env.AGENT }} -p x", "${{ env.PREFIX }}claude -p x",
                    "${{ matrix.x }}${{ env.AGENT }} -p x", "if true; then\n  ${{ env.AGENT }} -p x\nfi",
                    "run \\\n  && ${{ env.AGENT }}", "(${{ env.AGENT }})", "{ ${{ env.AGENT }}; }",
                    "${{ format('{0} -p', env.AGENT) }} x", "${{ env.AGENT || 'echo' }} -p x",
                    "${{ toJSON(env) }}", "${{ join(env.*, ' ') }}", "${{ env[matrix.k] }} -p x"):
            with self.subTest(run=run):
                self.assertEqual(len(scope_errors(wf(run, job=JOB))), 1, problems(wf(run, job=JOB)))

    def test_where_the_agents_pattern_would_see_its_name(self):
        # From the second review: places the lanes see a name written out in, through the catalog's own pattern for
        # the agent's command line (`claude ... -p`), wherever the line holds it.
        for run in ("if true; then ${{ env.AGENT }} -p x; fi", "for i in 1; do ${{ env.AGENT }} -p x; done",
                    "if ${{ env.AGENT }} -p x; then :; fi", "while ${{ env.AGENT }} -p x; do break; done",
                    "! ${{ env.AGENT }} -p x", "${{ '' }} ${{ env.AGENT }} -p x",
                    "${{ github.event.inputs.sudo }} ${{ env.AGENT }} -p x", "xvfb-run ${{ env.AGENT }} -p x",
                    "strace -f ${{ env.AGENT }} -p x", "flock /tmp/l ${{ env.AGENT }} -p x",
                    "find . -exec ${{ env.AGENT }} -p x {} \\;", "su runner -c \"${{ env.AGENT }} -p x\"",
                    "uv run ${{ env.AGENT }} -p x", "poetry run ${{ env.AGENT }} -p x", "watch -n1 ${{ env.AGENT }} -p x",
                    "systemd-run --user --wait ${{ env.AGENT }} -p x", "exec -a name ${{ env.AGENT }} -p x",
                    "docker exec c ${{ env.AGENT }} -p x", "bash --noprofile --norc -eo pipefail -c \"${{ env.AGENT }} -p x\"",
                    "pwsh -c \"${{ env.AGENT }} -p x\"", "cmd /c ${{ env.AGENT }} -p x", ">log ${{ env.AGENT }} -p x",
                    "2>/dev/null ${{ env.AGENT }} -p x", "${{ env.AGENT }} exec 'fix it'", "${{ env.AGENT }} run 'fix it'",
                    "echo ${{ env.AGENT }} -p x"):
            with self.subTest(run=run):
                self.assertEqual(len(scope_errors(wf(run, job=JOB))), 1, problems(wf(run, job=JOB)))
                # The control: the name written out puts the job in the agent lane.
                program = "codex" if " exec '" in run else "opencode" if " run '" in run else "claude"
                self.assertEqual(lane(wf(run.replace("${{ env.AGENT }}", program))), "agent")

    def test_another_expression_before_it_is_read_as_its_value(self):
        # From the second and third reviews: a known value of another expression on the line is put in.
        for step in ("{PRE: ''}", "{PRE: sudo}"):
            with self.subTest(step=step):
                text = wf("${{ env.PRE }} ${{ env.AGENT }} -p x", job=JOB, step=step)
                (error,) = scope_errors(text)
                self.assertIn("${{ env.AGENT }}", error)
        text = wf("xvfb-run ${{ env.AGENT }} ${{ env.F }} x", job=JOB, step="{F: -p}")
        self.assertEqual(len(scope_errors(text)), 1)
        self.assertEqual(lane(wf("xvfb-run claude ${{ env.F }} x", step="{F: -p}")), "agent")

    def test_the_message_says_which_place(self):
        (program,) = scope_errors(wf("${{ env.AGENT }} --task x", job=JOB))
        self.assertIn(PLACE, program)
        (pattern,) = scope_errors(wf("xvfb-run ${{ env.AGENT }} -p x", job=JOB))
        self.assertIn("where an agent's name would be read as its command line", pattern)

    def test_continued_by_a_backtick_or_a_caret(self):
        # From the third review: PowerShell's and cmd's continuations, which the lanes join for a name written out.
        self.assertEqual(len(scope_errors(wf("Start-Process -FilePath ${{ env.AGENT }} `\n  -ArgumentList '-p x'",
                                             job=JOB, shell="pwsh", runs_on="windows-latest"))), 1)
        self.assertEqual(len(scope_errors(wf("xvfb-run ${{ env.AGENT }} ^\n  -p x", job=JOB, shell="cmd",
                                             runs_on="windows-latest"))), 1)

    def test_every_strict_pattern_has_the_shape_the_search_rests_on(self):
        # The third review: one try per piece holds because every such pattern is the name, an optional quote, a
        # space, anything, then its keyword; a pattern of another shape would be left out without this test.
        import re
        from obaaf.checker import workflow as wf_mod
        for tool in wf_mod.load_catalog().detection.get("agent_tools", []):
            for program in tool.get("programs") or []:
                for pattern in tool.get("commands") or []:
                    if pattern.startswith("@") or re.search(pattern, f"{program} zzz", re.M):
                        continue
                    with self.subTest(pattern=pattern):
                        self.assertEqual(pattern.count(program), 1)
                        self.assertTrue(pattern.startswith(wf_mod._SCOPE_PATTERN_HEAD + program
                                                           + wf_mod._SCOPE_PATTERN_MIDDLE), pattern)

    def test_stated_limits(self):
        # A keyword after an option's value from such a scope is an error, as an agent's name there would be read as
        # its command line; a package's name is not tried; a value holding a whole command elsewhere is not seen.
        for run in ("psql -h ${{ env.PGHOST }} -p 5432", "npm --prefix ${{ env.APP_DIR }} run build",
                    "docker compose -f ${{ env.COMPOSE_FILE }} run --rm app"):
            with self.subTest(run=run):
                self.assertEqual(len(scope_errors(wf(run, job=JOB))), 1)
        for run in ("deno run -A npm:${{ env.PKG }} -p x", "echo ${{ env.CMD }}"):
            with self.subTest(run=run):
                self.assertEqual(problems(wf(run, job=JOB)), [])

    def test_powershell_and_cmd(self):
        for run, shell in (("& ${{ env.AGENT }} -p x", "pwsh"), ("iex \"${{ env.AGENT }} -p x\"", "pwsh"),
                           ("Start-Process ${{ env.AGENT }}", "pwsh"), ("call ${{ env.AGENT }} -p x", "cmd")):
            with self.subTest(run=run):
                self.assertEqual(len(scope_errors(wf(run, job=JOB, shell=shell, runs_on="windows-latest"))), 1)

    def test_the_rest_of_a_line_is_read_as_before(self):
        # The ordinary uses of a value from such a scope: no new error (what the base gave: nothing).
        for run in ("echo ${{ env.VERSION }}", "mkdir -p ${{ env.CCACHE_DIR }}",
                    "cp a ${{ env.CCACHE_DIR }}/ccache.conf", "${{ env.DIR }}/bin/tool --x",
                    "call ${{ env.MX_PATH }}\\mx.cmd -p substratevm", "echo '${{ toJSON(env) }}'",
                    "make ${{ env.DEBUG && 'V=1' || '' }}", "du -sh ${{ env.BASEDIR }}/target_ws",
                    "./build.sh ${{ env.NAME }} ${{ env.VERSION }}",
                    # From the second review: an argument on a line a backslash continues.
                    "docker build \\\n  ${{ env.ARGS }} \\\n  -t img .",
                    "cmake -S . \\\n  -DCMAKE_C_COMPILER=${{ env.CC }} \\\n  -B build"):
            with self.subTest(run=run):
                self.assertEqual(problems(wf(run, job=JOB)), [])
                self.assertEqual(problems(wf(run, job="${{ matrix.env }}",
                                             matrix="env:\n  - {VERSION: '1'}\n  - {VERSION: '2'}")), [])

    def test_the_existing_reading_through_another_context_stands(self):
        # A default that names an agent still makes its reading, as on the base, and the program place is an error.
        text = wf("${{ env.AGENT || 'claude' }} -p x", job=JOB)
        self.assertEqual(len(scope_errors(text)), 1)
        self.assertEqual(lane(text), "agent")

    def test_a_value_only_tested_is_read(self):
        for expression in ("env.X == 'a' && 'claude' || 'echo'", "contains(env.X, 'y') && 'claude' || 'echo'",
                           "!env.X && 'claude' || 'echo'", "env.X && 'claude' || 'echo'",
                           "format('{0}', env.X) == 'a' && 'claude' || 'echo'"):
            with self.subTest(expression=expression):
                text = wf("${{ " + expression + " }} -p x", job=JOB)
                self.assertEqual(problems(text), [])
                self.assertEqual(lane(text), "agent")

    def test_expressions_that_do_not_read_env_and_steps_that_read_none(self):
        for run in ("echo ${{ github.sha }}", "make test", "${{ matrix.cmd }} -p x", "echo $AGENT"):
            with self.subTest(run=run):
                self.assertEqual(problems(wf(run, job=JOB)), [])

    def test_a_name_variable_is_not_put_in_as_before(self):
        # D-139's `$NAME` put-in reads only mappings (its stated limit): unchanged, no lane and no error.
        text = wf("$AGENT -p x", job=JOB)
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "trusted")


class ANearerMappingSettlesTheNameTest(unittest.TestCase):
    """A mapping nearer the step that sets the name gives its value, as GitHub gives it: no error."""

    def test_the_steps_own_value_over_a_jobs_expression(self):
        text = wf("${{ env.AGENT }} -p x", job=JOB, step="{AGENT: claude}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "agent")

    def test_the_jobs_value_over_the_workflows_expression(self):
        text = wf("${{ env.AGENT }} -p x", top=JOB, job="{AGENT: claude}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "agent")

    def test_an_outer_mapping_does_not_settle_it(self):
        self.assertEqual(len(scope_errors(wf("${{ env.AGENT }} -p x", top="{AGENT: echo}", job=JOB))), 1)

    def test_letter_case_follows_the_runner(self):
        # Exact on Linux: `agent` does not set `AGENT`, so the job's expression may.
        self.assertEqual(len(scope_errors(wf("${{ env.AGENT }} -p x", job=JOB, step="{agent: claude}"))), 1)
        # Folded on Windows: it does.
        self.assertEqual(scope_errors(wf("${{ env.AGENT }} -p x", job=JOB, step="{agent: claude}",
                                         runs_on="windows-latest")), [])
        # Both readings where the runner is not known: the exact one is not settled.
        self.assertEqual(len(scope_errors(wf("${{ env.AGENT }} -p x", job=JOB, step="{agent: claude}",
                                             runs_on="${{ inputs.os }}"))), 1)

    def test_a_name_outside_ascii_on_windows_is_not_settled(self):
        # .NET's mapping outside ASCII is not copied, so the job's expression may hold a name it folds to.
        text = wf("${{ env['ÄGENT'] }} -p x", job=JOB, step="{ÄGENT: claude}", runs_on="windows-latest")
        self.assertEqual(len(scope_errors(text)), 1)

    def test_a_nearer_value_that_is_not_text_does_not_settle_it(self):
        self.assertEqual(len(scope_errors(wf("${{ env.AGENT }} -p x", job=JOB, step="{AGENT: [claude]}"))), 1)

    def test_a_key_yaml_reads_otherwise_settles_nothing(self):
        # From the review: GitHub names `0o7` `7`, so `env['0o7']` comes from the job's scope.
        self.assertEqual(len(scope_errors(wf("${{ env['0o7'] }} -p x", job=JOB, step="{0o7: echo}"))), 1)


class TheRuleIsUnchangedTest(unittest.TestCase):
    """OBAAF-GHA-026 (D-143) still reads an option beside a scope written as one expression as "cannot tell"."""

    def finding(self, text):
        with TempDir() as tmp:
            result = check(tmp, text)
        return [f for f in result.findings if f.rule == "OBAAF-GHA-026"]

    def test_through_the_matrix_and_beside_a_settled_name(self):
        for text in (wf("claude ${{ env.FLAGS }} -p x", job="${{ matrix.env }}",
                        matrix="env:\n  - {FLAGS: --dangerously-skip-permissions}"),
                     wf("claude ${{ env.FLAGS }} -p x", job=JOB, step="{FLAGS: --dangerously-skip-permissions}")):
            with self.subTest(text=text[-120:]):
                (found,) = self.finding(text)
                self.assertEqual(found.severity, "medium")
                self.assertIn("cannot read", found.message)

    def test_written_out_it_is_high(self):
        (found,) = self.finding(wf("claude --dangerously-skip-permissions -p x"))
        self.assertEqual(found.severity, "high")


class CostTest(unittest.TestCase):
    """Each line holding such an expression is read once more, for where its program goes."""

    def test_many_references_on_one_line_and_many_lines(self):
        one_line = "echo " + " ".join(f"${{{{ env.A{n} }}}}" for n in range(20000))
        lines = "\n".join(f"echo ${{{{ env.A{n} }}}} ${{{{ env.B }}}}" for n in range(20000))
        for run in (one_line, lines):
            text = wf(run, job=JOB)
            start = time.monotonic()
            self.assertEqual(problems(text), [])
            self.assertLess(time.monotonic() - start, 30)

    def test_many_steps(self):
        steps = "".join(f"      - run: echo ${{{{ env.AGENT }}}} {n}\n" for n in range(2000))
        text = (f"on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    env: {JOB}\n    steps:\n"
                + steps)
        start = time.monotonic()
        self.assertEqual(problems(text), [])
        self.assertLess(time.monotonic() - start, 30)


class ReaderTest(unittest.TestCase):
    """The values the reader gives for such scopes, and the plan's `scoped`."""

    def values(self, body, scopes, case="exact"):
        env = env_expr.Env(scopes, case)
        out = []
        for value in env_expr._Reader(env_expr.expr_mod.tokens(body), env).read():
            out.extend(env_expr.text_of(value, env))
        return out

    def test_from_scope(self):
        unread = [JOB, None, None]
        self.assertIn(env_expr.FROM_SCOPE, self.values("env.A", unread))
        self.assertEqual(self.values("env.A", [JOB, {"A": "x"}, None]), ["x"])
        self.assertEqual(sorted(self.values("env.A == 'x'", unread)), ["false", "true"])
        self.assertEqual(set(self.values("env.A && 'y'", unread)), {"", "0", "false", "y"})
        for body in ("format('{0}', env.A)", "join(env.A, ',')", "toJSON(env.A)", "fromJSON(env.A).x", "env",
                     "toJSON(env)", "join(env.*, ',')", "env[matrix.k]", "(env).A", "env.A || 'd'"):
            with self.subTest(body=body):
                self.assertIn(env_expr.FROM_SCOPE, self.values(body, unread))

    def test_the_plan_names_the_expressions(self):
        text = "echo ${{ env.A }} ${{ github.sha }}\n${{ env.B }} -p"
        made = env_expr.plan(text, env_expr.Env([JOB, None, None], "exact"))
        self.assertEqual([text[s:e] for s, e in made.scoped], ["${{ env.A }}", "${{ env.B }}"])
        # Only the name's being unset (an empty text) is a reading; what the scope may give makes none.
        self.assertEqual([texts for _u0, _u1, here in made.units for _s, _e, texts in here], [[""], [""]])

    def test_the_fast_path_is_as_before(self):
        env = env_expr.Env([{"A": "x"}, {"B": "y"}, None], "exact")
        self.assertFalse(env.unread)
        self.assertEqual(env.lookup("A"), ["x"])
        self.assertEqual(env.every(), ["x", "y", None])
        self.assertIsNone(env.where)
        self.assertEqual(env_expr.plan("${{ env.A }}", env).scoped, ())


if __name__ == "__main__":
    unittest.main()
