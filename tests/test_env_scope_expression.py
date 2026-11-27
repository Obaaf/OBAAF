"""Flagship slice 2d.19d (#382): a scope's `env` written as one expression, in the lanes.

GitHub works out a `${{ }}` expression in a step's `run` with the `env` context: the workflow's, the job's and the
step's own `env`, the nearest winning. A scope may be written as one expression (`env: ${{ fromJSON(vars.E) }}`,
`env: ${{ matrix.env }}`), whose names and values the file does not show. Before this slice the lanes (D-142) read a
name such a scope may set as a value of another context, which made no reading, so `run: ${{ env.AGENT }} -p x`
under `env: ${{ fromJSON(vars.E) }}` put the job in no agent lane, with no error and no finding (F-418). Now:

- `env: ${{ matrix.KEY }}` in a job or a step, where the job's matrix lists every value of KEY as a mapping of
  names to texts, is read as each of those mappings (and as none, where a combination may have no value for KEY);
- any other such scope may give any name any text: an expression whose text may be what it gives (a name no
  mapping nearer the step sets, under the runner's comparison of names, or the whole `env`) makes the step an error
  of its file, as D-142's other refusals do; an expression that only compares such a value is read as before.
"""

import time
import unittest

from helpers import TempDir
from test_env_expressions import UNREAD, flow, lane, problems
from test_local_composite_actions import KEY, check

from obaaf.checker import env_expr

SCOPE = "written as one expression the checker does not read, may set"


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


class TheCaseOfF418Test(unittest.TestCase):
    """The case F-418 left: no agent lane, no error and no finding on the base."""

    def test_the_issue_case_is_an_error_of_the_file(self):
        text = wf("${{ env.AGENT }} -p review", job="${{ fromJSON(vars.E) }}")
        (error,) = problems(text)
        self.assertIn(UNREAD, error)
        self.assertIn("('${{ env.AGENT }}') reads from `env` what the job's `env`, " + SCOPE, error)
        self.assertIn("so the checker cannot tell whether an agent runs in it", error)

    def test_each_scope_is_named(self):
        for where, scopes in (("the workflow's", {"top": "${{ fromJSON(vars.E) }}"}),
                              ("the job's", {"job": "${{ fromJSON(vars.E) }}"}),
                              ("the step's own", {"step": "${{ fromJSON(vars.E) }}"})):
            with self.subTest(where=where):
                (error,) = scope_errors(wf("${{ env.AGENT }} -p x", **scopes))
                self.assertIn(f"what {where} `env`, {SCOPE}", error)

    def test_two_such_scopes_are_both_named(self):
        (error,) = scope_errors(wf("${{ env.AGENT }} -p x", top="${{ fromJSON(vars.T) }}",
                                   job="${{ fromJSON(vars.E) }}"))
        self.assertIn("what the workflow's and the job's `env`, " + SCOPE, error)

    def test_the_egress_actions_command_and_a_github_script_script(self):
        egress = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    env: ${{ fromJSON(vars.E) }}\n"
                  "    steps:\n      - uses: Obaaf/OBAAF/actions/egress@1111111111111111111111111111111111111111\n"
                  "        with:\n          allow: api.anthropic.com\n          run: ${{ env.AGENT }} -p x\n")
        script = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    env: ${{ fromJSON(vars.E) }}\n"
                  "    steps:\n      - uses: actions/github-script@1111111111111111111111111111111111111111\n"
                  "        with:\n          script: |\n            exec.exec('${{ env.AGENT }} -p x')\n")
        for text in (egress, script):
            with self.subTest(text=text[-60:]):
                self.assertEqual(len(scope_errors(text)), 1)

    def test_a_scope_written_any_other_way_that_is_not_a_mapping(self):
        for scope in ("${{ vars.E }}", "'${{ fromJSON(needs.a.outputs.e) }}'", "some text", "'${{ inputs.e }}'"):
            with self.subTest(scope=scope):
                self.assertEqual(len(scope_errors(wf("${{ env.AGENT }} -p x", job=scope))), 1)


class ANearerMappingSettlesTheNameTest(unittest.TestCase):
    """A mapping nearer the step that sets the name gives its value, as GitHub gives it: no error."""

    def test_the_steps_own_value_over_a_jobs_expression(self):
        text = wf("${{ env.AGENT }} -p x", job="${{ fromJSON(vars.E) }}", step="{AGENT: claude}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "agent")

    def test_the_jobs_value_over_the_workflows_expression(self):
        text = wf("${{ env.AGENT }} -p x", top="${{ fromJSON(vars.E) }}", job="{AGENT: claude}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "agent")

    def test_an_outer_mapping_does_not_settle_it(self):
        text = wf("${{ env.AGENT }} -p x", top="{AGENT: echo}", job="${{ fromJSON(vars.E) }}")
        self.assertEqual(len(scope_errors(text)), 1)

    def test_letter_case_follows_the_runner(self):
        # Exact on Linux: `agent` does not set `AGENT`, so the job's expression may.
        linux = wf("${{ env.AGENT }} -p x", job="${{ fromJSON(vars.E) }}", step="{agent: claude}")
        self.assertEqual(len(scope_errors(linux)), 1)
        # Folded on Windows: it does.
        windows = wf("${{ env.AGENT }} -p x", job="${{ fromJSON(vars.E) }}", step="{agent: claude}",
                     runs_on="windows-latest")
        self.assertEqual(scope_errors(windows), [])
        # Both readings where the runner is not known: the exact one is not settled.
        unknown = wf("${{ env.AGENT }} -p x", job="${{ fromJSON(vars.E) }}", step="{agent: claude}",
                     runs_on="${{ inputs.os }}")
        self.assertEqual(len(scope_errors(unknown)), 1)

    def test_a_name_outside_ascii_on_windows_is_not_settled(self):
        # .NET's mapping outside ASCII is not copied, so the job's expression may hold a name it folds to.
        text = wf("${{ env['ÄGENT'] }} -p x", job="${{ fromJSON(vars.E) }}", step="{ÄGENT: claude}",
                  runs_on="windows-latest")
        self.assertEqual(len(scope_errors(text)), 1)

    def test_a_nearer_value_that_is_not_text_does_not_settle_it(self):
        text = wf("${{ env.AGENT }} -p x", job="${{ fromJSON(vars.E) }}", step="{AGENT: [claude]}")
        self.assertEqual(len(scope_errors(text)), 1)


class WhatTheScopeMayGiveTest(unittest.TestCase):
    """Every form that may put such a value in the text is an error; one that only tests it is read."""

    def test_forms_that_put_it_in(self):
        for expression in ("env.AGENT", "env['AGENT']", "ENV.AGENT", "env.AGENT || 'echo'", "env.X && env.AGENT",
                           "format('{0}', env.AGENT)", "format(env.T, 'x')", "join(env.AGENT, ' ')",
                           "join(fromJSON('[1,2]'), env.SEP)", "toJSON(env.AGENT)", "fromJSON(env.AGENT)",
                           "fromJSON(env.AGENT).x", "fromJSON(env.AGENT)[0]", "fromJSON(env.AGENT).*",
                           "toJSON(env)", "env", "join(env.*, ' ')", "env.*[0]", "env[matrix.k]", "(env).AGENT",
                           "env[env.K]", "format('{0}', env)", "toJSON(fromJSON(env.AGENT))"):
            with self.subTest(expression=expression):
                text = wf("${{ " + expression + " }} -p x", job="${{ fromJSON(vars.E) }}")
                self.assertEqual(len(scope_errors(text)), 1, problems(text))

    def test_the_issue_cases_with_a_default_that_names_an_agent(self):
        # On the base the default made a reading (`claude -p x`) and the job was an agent job; the scope may give
        # AGENT any text, so the line is not known now.
        text = wf("${{ env.AGENT || 'claude' }} -p x", job="${{ fromJSON(vars.E) }}")
        self.assertEqual(len(scope_errors(text)), 1)

    def test_forms_that_only_test_it_are_read(self):
        for expression in ("env.X == 'a' && 'claude' || 'echo'", "contains(env.X, 'y') && 'claude' || 'echo'",
                           "startsWith(env.X, 'y') && 'claude' || 'echo'", "!env.X && 'claude' || 'echo'",
                           "format('{0}', env.X) == 'a' && 'claude' || 'echo'"):
            with self.subTest(expression=expression):
                text = wf("${{ " + expression + " }} -p x", job="${{ fromJSON(vars.E) }}")
                self.assertEqual(problems(text), [])
                self.assertEqual(lane(text), "agent")

    def test_expressions_that_do_not_read_env_and_steps_that_read_none(self):
        for run in ("echo ${{ github.sha }}", "make test", "${{ matrix.cmd }} -p x", "echo $AGENT"):
            with self.subTest(run=run):
                self.assertEqual(problems(wf(run, job="${{ fromJSON(vars.E) }}")), [])

    def test_a_name_variable_is_not_put_in_as_before(self):
        # D-139's `$NAME` put-in reads only mappings (its stated limit): unchanged, no lane and no error.
        text = wf("$AGENT -p x", job="${{ fromJSON(vars.E) }}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "trusted")


class AMatrixScopeIsReadTest(unittest.TestCase):
    """`env: ${{ matrix.KEY }}` with the matrix written out: each mapping it lists, with no new error."""

    MATRIX = "env:\n  - {AGENT: claude, D: one}\n  - {AGENT: echo, D: two}"

    def test_an_agent_in_one_of_the_mappings(self):
        text = wf("${{ env.AGENT }} -p x", job="${{ matrix.env }}", matrix=self.MATRIX)
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "agent")

    def test_no_agent_in_any(self):
        text = wf("${{ env.AGENT }} -p x", job="${{ matrix.env }}",
                  matrix="env:\n  - {AGENT: echo}\n  - {AGENT: make}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "trusted")

    def test_the_ordinary_idiom_gives_no_error(self):
        # The shape of industrial_ci workflows: `env: ${{ matrix.env }}` and `mkdir -p ${{ env.CCACHE_DIR }}`.
        run = "mkdir -p ${{ env.CCACHE_DIR }}\ncp .github/ccache.conf ${{ env.CCACHE_DIR }}/ccache.conf"
        text = wf(run, job="${{ matrix.env }}",
                  matrix="env:\n  - {IMAGE: rolling-ci, CCACHE_DIR: /home/c}\n  - {IMAGE: humble-ci}")
        self.assertEqual(problems(text), [])

    def test_include_entries_and_a_step_scope(self):
        text = wf("${{ env.AGENT }} -p x", step="${{ matrix.e }}",
                  matrix="os: [a, b]\ninclude:\n  - {os: a, e: {AGENT: claude}}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "agent")

    def test_a_combination_with_none_falls_through_to_the_outer_scopes(self):
        # `include` entries without `e` may make a combination of their own, with no `e`: the job's value stands.
        text = wf("${{ env.AGENT }} -p x", job="{AGENT: claude}", step="${{ matrix.e }}",
                  matrix="include:\n  - {e: {AGENT: echo}}\n  - {other: 1}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "agent")
        # Every combination has one: the job's value is never seen.
        listed = wf("${{ env.AGENT }} -p x", job="{AGENT: claude}", step="${{ matrix.e }}",
                    matrix="e:\n  - {AGENT: echo}")
        self.assertEqual(lane(listed), "trusted")

    def test_a_matrix_the_checker_does_not_read_is_a_scope_it_does_not_read(self):
        for matrix in ("env: ${{ fromJSON(needs.a.outputs.m) }}", "env:\n  - {AGENT: '${{ vars.A }}'}",
                       "env:\n  - claude", "env:\n  - {AGENT: {deep: claude}}", "Env:\n  - {AGENT: claude}",
                       "env:\n  - {AGENT: claude}\nENV: [x]", "include: ${{ fromJSON(vars.I) }}",
                       "env:\n  - {'${{ vars.N }}': claude}"):
            with self.subTest(matrix=matrix):
                text = wf("${{ env.AGENT }} -p x", job="${{ matrix.env }}", matrix=matrix)
                self.assertEqual(len(scope_errors(text)), 1, problems(text))

    def test_a_merge_key_in_the_file(self):
        text = wf("${{ env.AGENT }} -p x", job="${{ matrix.env }}",
                  matrix="env:\n  - &e {AGENT: claude}\n  - {<<: *e, B: x}")
        self.assertEqual(len(scope_errors(text)), 1)

    def test_other_spellings_of_the_matrix_reference_are_not_read_through(self):
        for scope in ("${{ matrix.ENV }}", "${{ matrix['env'] }}", "${{ matrix.env || fromJSON('{}') }}"):
            with self.subTest(scope=scope):
                text = wf("${{ env.AGENT }} -p x", job=scope, matrix="env:\n  - {AGENT: claude}")
                self.assertEqual(len(scope_errors(text)), 1, problems(text))

    def test_the_workflows_env_has_no_matrix(self):
        text = wf("${{ env.AGENT }} -p x", top="${{ matrix.env }}", matrix="env:\n  - {AGENT: claude}")
        self.assertEqual(len(scope_errors(text)), 1)

    def test_too_many_combinations(self):
        mappings = "\n".join(f"  - {{AGENT: a{n}}}" for n in range(env_expr.ALTERNATIVES + 1))
        text = wf("${{ env.AGENT }} -p x", job="${{ matrix.env }}", matrix="env:\n" + mappings)
        self.assertEqual(len(scope_errors(text)), 1)
        # A job's and a step's together past the bound: both are read as scopes the checker does not read.
        half = "\n".join(f"  - {{AGENT: a{n}}}" for n in range(17))
        text = wf("${{ env.AGENT }} -p x", job="${{ matrix.env }}", step="${{ matrix.e }}",
                  matrix="env:\n" + half + "\ne:\n" + half.replace("AGENT", "B"))
        self.assertEqual(len(scope_errors(text)), 1)

    def test_the_whole_env_through_the_matrix(self):
        text = wf("echo '${{ toJSON(env) }}'\n${{ join(env.*, ' ') }} -p x", job="${{ matrix.env }}",
                  matrix="env:\n  - {A: claude}\n  - {A: echo}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "agent")


class TheRuleIsUnchangedTest(unittest.TestCase):
    """OBAAF-GHA-026 (D-143) still reads an option through a scope written as one expression as "cannot tell"."""

    def finding(self, text):
        with TempDir() as tmp:
            result = check(tmp, text)
        return [f for f in result.findings if f.rule == "OBAAF-GHA-026"]

    def test_through_the_matrix(self):
        text = wf("claude ${{ env.FLAGS }} -p x", job="${{ matrix.env }}",
                  matrix="env:\n  - {FLAGS: --dangerously-skip-permissions}")
        (found,) = self.finding(text)
        self.assertEqual(found.severity, "medium")
        self.assertIn("cannot read", found.message)

    def test_written_out_it_is_high(self):
        (found,) = self.finding(wf("claude --dangerously-skip-permissions -p x"))
        self.assertEqual(found.severity, "high")


class CostTest(unittest.TestCase):
    """The matrix's mappings are read once for the job, and a lookup goes through each world."""

    def test_many_references_over_many_combinations(self):
        mappings = "\n".join(f"  - {{A{n}: v{n}, AGENT: echo}}" for n in range(env_expr.ALTERNATIVES))
        run = "\n".join("echo " + " ".join(f"${{{{ env.A{n} }}}}" for n in range(k, k + 5)) for k in range(0, 200, 5))
        text = wf(run, job="${{ matrix.env }}", matrix="env:\n" + mappings)
        start = time.monotonic()
        self.assertEqual(problems(text), [])
        self.assertLess(time.monotonic() - start, 20)

    def test_many_steps_share_one_reading_of_the_matrix(self):
        mappings = "\n".join(f"  - {{AGENT: v{n}}}" for n in range(64))
        steps = "".join(f"      - run: echo ${{{{ env.AGENT }}}} {n}\n" for n in range(400))
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    strategy:\n      matrix:\n"
                "        env:\n" + "".join(f"        {line}\n" for line in mappings.split("\n"))
                + "    env: ${{ matrix.env }}\n    steps:\n" + steps)
        start = time.monotonic()
        self.assertEqual(problems(text), [])
        self.assertLess(time.monotonic() - start, 20)


class ReaderTest(unittest.TestCase):
    """The values the reader gives for such scopes."""

    def values(self, body, scopes, case="exact"):
        env = env_expr.Env(scopes, case)
        out = []
        for value in env_expr._Reader(env_expr.expr_mod.tokens(body), env).read():
            out.extend(env_expr.text_of(value, env))
        return out

    def test_from_scope(self):
        unread = ["${{ fromJSON(vars.E) }}", None, None]
        self.assertIn(env_expr.FROM_SCOPE, self.values("env.A", unread))
        self.assertEqual(self.values("env.A", [unread[0], {"A": "x"}, None]), ["x"])
        self.assertEqual(sorted(self.values("env.A == 'x'", unread)), ["false", "true"])

    def test_alternatives(self):
        alts = env_expr.Alternatives(({"A": "x"}, {"A": "y"}, {}))
        self.assertEqual(sorted(self.values("env.A", [{"A": "outer"}, alts, None])), ["outer", "x", "y"])
        self.assertEqual(sorted(self.values("env.A", [None, alts, {"A": "z"}])), ["z"])

    def test_the_fast_path_is_as_before(self):
        env = env_expr.Env([{"A": "x"}, {"B": "y"}, None], "exact")
        self.assertEqual(len(env.worlds), 1)
        self.assertEqual(env.lookup("A"), ["x"])
        self.assertEqual(env.every(), ["x", "y", None])
        self.assertIsNone(env.where)


if __name__ == "__main__":
    unittest.main()
