"""Flagship slice 2d.19 (#382): `${{ }}` expressions that read `env` in a workflow's own step.

GitHub works out a `${{ }}` expression in a step's `run` before the shell starts, with the `env` context (the
workflow's, the job's and the step's own `env`, the nearest winning). Before this slice the lanes read such an
expression as written, so `run: ${{ env.AGENT }} -p review` with `AGENT: claude` in the job's `env` put the job in
no agent lane and no agent rule applied. Now each expression that reads `env` is worked out (`env_expr.put_in`):
each on its own, line by line; only `env` at the head of a reference counts; a reference not pinned to one name
gives every value or makes the step an error of its file; letter case follows the runner as #387 measured it.
"""

import json
import re
import unittest
from unittest import mock

from helpers import TempDir
from test_local_composite_actions import KEY, check, lane_of

from obaaf.checker import env_expr
from obaaf.checker import workflow as wf

UNREAD = "its command lines hold an expression that reads `env` which the checker does not work out"


def flow(run, top_env="", job_env="", step_env="", runs_on="ubuntu-24.04", shell="bash", extra=""):
    """A workflow of one job `a` holding a model key in its step's `env`. The `env` arguments are flow
    mappings (`{a: cla}`) or empty; `run` is written as a YAML block scalar."""
    env = f"          ANTHROPIC_API_KEY: {KEY}\n"
    if step_env:
        env += "".join(f"          {pair.strip()}\n" for pair in step_env.strip("{}").split(","))
    body = "".join(f"          {line}\n" for line in run.split("\n"))
    return ("on: workflow_dispatch\n" + (f"env: {top_env}\n" if top_env else "")
            + f"jobs:\n  a:\n    runs-on: {runs_on}\n    permissions: {{contents: read}}\n"
            + (f"    env: {job_env}\n" if job_env else "") + extra + "    steps:\n"
            + f"      - shell: {shell}\n        run: |\n{body}        env:\n{env}")


def lane(text):
    with TempDir() as tmp:
        rows, _notes = lane_of(tmp, text)
    return rows["a"][0]


def problems(text):
    with TempDir() as tmp:
        result = check(tmp, text)
    return list(result.errors)


class TheFormsOfTheEntryTest(unittest.TestCase):
    """Each form the entry names puts the job in the agent lane."""

    def test_the_issue_case(self):
        self.assertEqual(lane(flow("${{ env.AGENT }} -p review", job_env="{AGENT: claude}")), "agent")

    def test_the_base_read_it_as_written(self):
        # The same step with the expression's value written out is an agent step, so the reading is the same.
        self.assertEqual(lane(flow("claude -p review")), "agent")

    def test_values_from_each_scope(self):
        for scopes in ({"top_env": "{AGENT: claude}"}, {"job_env": "{AGENT: claude}"},
                       {"step_env": "{AGENT: claude}"}):
            with self.subTest(scopes=scopes):
                self.assertEqual(lane(flow("${{ env.AGENT }} -p review", **scopes)), "agent")

    def test_the_nearest_scope_wins(self):
        self.assertEqual(lane(flow("${{ env.AGENT }} -p x", job_env="{AGENT: claude}", step_env="{AGENT: echo}")),
                         "trusted")
        self.assertEqual(lane(flow("${{ env.AGENT }} -p x", top_env="{AGENT: echo}", job_env="{AGENT: claude}")),
                         "agent")

    def test_pieces_in_two_expressions(self):
        self.assertEqual(lane(flow("${{ ENV.a }}${{ env['b'] }} -p review", job_env="{a: cla, b: ude}")), "agent")

    def test_format(self):
        self.assertEqual(lane(flow("${{ format('{0}{1}', env.a, env.b) }} -p x", job_env="{a: cla, b: ude}")),
                         "agent")

    def test_format_with_no_env_anywhere(self):
        self.assertEqual(lane(flow("${{ format('{0}{1}', env.X || 'cla', 'ude') }} -p x")), "agent")

    def test_or(self):
        self.assertEqual(lane(flow("${{ env.x || env.a }} -p x", job_env="{a: claude}")), "agent")
        self.assertEqual(lane(flow("${{ env.x || env.a }} -p x", job_env="{x: echo, a: claude}")), "trusted")

    def test_and_or_with_a_condition_the_checker_does_not_know(self):
        text = flow("${{ github.event_name == 'push' && env.A || env.B }} -p x", job_env="{A: echo, B: claude}")
        self.assertEqual(lane(text), "agent")

    def test_a_group(self):
        self.assertEqual(lane(flow("${{ (env).AGENT }} -p x", job_env="{AGENT: claude}")), "agent")
        self.assertEqual(lane(flow("${{ (env)['AGENT'] }} -p x", job_env="{AGENT: claude}")), "agent")

    def test_to_json_and_join_of_one_value(self):
        self.assertEqual(lane(flow("${{ toJSON(env.AGENT) }} -p x", job_env="{AGENT: claude}")), "agent")
        self.assertEqual(lane(flow("${{ join(env.AGENT, '') }} -p x", job_env="{AGENT: claude}")), "agent")

    def test_from_json(self):
        text = flow("${{ fromJSON(env.CONF).tool }} -p x", job_env="{CONF: '{\"tool\": \"claude\"}'}")
        self.assertEqual(lane(text), "agent")

    def test_an_index_worked_out(self):
        self.assertEqual(lane(flow("${{ env[env.KEY] }} -p x", job_env="{KEY: AGENT, AGENT: claude}")), "agent")
        self.assertEqual(lane(flow("${{ env[format('{0}', 'AGENT')] }} -p x", job_env="{AGENT: claude}")), "agent")

    def test_an_index_the_checker_does_not_know_gives_every_value(self):
        self.assertEqual(lane(flow("${{ env[matrix.key] }} -p x", job_env="{OTHER: x, AGENT: claude}")), "agent")
        self.assertEqual(lane(flow("${{ env[env.KEY] }} -p x", job_env="{AGENT: claude}")), "trusted")

    def test_the_env_object_made_into_text_gives_every_value(self):
        self.assertEqual(lane(flow("${{ env }} -p x", job_env="{AGENT: claude}")), "agent")
        self.assertEqual(lane(flow("${{ toJSON(env) }} -p x", job_env="{AGENT: claude}")), "agent")
        self.assertEqual(lane(flow("${{ format('{0} -p x', env.*) }}", job_env="{AGENT: claude}")), "agent")

    def test_join_over_the_whole_env_gives_the_values_joined_and_each(self):
        # `echo "${{ join(env.*, ' ') }}"` is in an older test of OBAAF-GHA-010 as an ordinary form: no error.
        # (With '' the step's model key, whose value the checker does not know, would follow `ude`.)
        text = flow("${{ join(env.*, '') }} -p x", job_env="{a: cla, b: ude}").replace(
            f"          ANTHROPIC_API_KEY: {KEY}\n", "          NOTHING: ''\n")
        self.assertEqual(lane(text), "agent")
        self.assertEqual(lane(flow("${{ join(env.*, ' ') }} -p x", job_env="{a: x, b: claude}")), "agent")
        self.assertEqual(problems(flow("echo \"${{ join(env.*, ' ') }}\"", job_env="{a: x}")), [])

    def test_the_value_is_then_read_by_the_shell(self):
        # An expression's value that holds `$NAME` is put in first, then the shell's variables (2d.18).
        self.assertEqual(lane(flow("${{ env.CMD }} -p x", job_env="{CMD: $AGENT, AGENT: claude}")), "agent")
        self.assertEqual(lane(flow("${{ env.WRAP }} $PKG -p x",
                                   job_env="{WRAP: npx, PKG: '@anthropic-ai/claude-code'}")), "agent")

    def test_a_value_over_several_lines_and_a_continued_line(self):
        self.assertEqual(lane(flow("echo start\n${{ env.AGENT }} \\\n  -p x", job_env="{AGENT: claude}")), "agent")
        self.assertEqual(lane(flow("${{ env.SCRIPT }}", job_env="{SCRIPT: \"echo a\\nclaude -p x\"}")), "agent")

    def test_the_egress_actions_command(self):
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    env: {AGENT: claude}\n"
                "    steps:\n      - uses: Obaaf/OBAAF/actions/egress@0123456789abcdef0123456789abcdef01234567\n"
                "        with:\n          allow: api.anthropic.com\n          run: ${{ env.AGENT }} -p x\n")
        self.assertEqual(lane(text), "agent")

    def test_a_github_script_script(self):
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    env: {AGENT: claude}\n"
                "    steps:\n      - uses: actions/github-script@0123456789abcdef0123456789abcdef01234567\n"
                "        with:\n          script: |\n            await exec.exec(\"bash\", [\"-c\", \"${{ env.AGENT }} -p x\"])\n"
                f"        env:\n          ANTHROPIC_API_KEY: {KEY}\n")
        literal = text.replace("${{ env.AGENT }}", "claude")
        self.assertEqual(lane(text), lane(literal))

    def test_the_agent_rules_follow(self):
        with TempDir() as tmp:
            result = check(tmp, flow("${{ env.AGENT }} -p review", job_env="{AGENT: claude}"))
        rules = {f.rule for f in result.findings if f.job == "a"}
        self.assertIn("OBAAF-GHA-005", rules)
        self.assertIn("OBAAF-GHA-020", rules)


class LetterCaseTest(unittest.TestCase):
    """#387 and the lead's decision on F-405: exact on a known GitHub-hosted Linux or macOS runner, folded on a known
    GitHub-hosted Windows runner (the step's value over the job's), both readings elsewhere."""

    def test_linux_and_macos_are_exact(self):
        for runner in ("ubuntu-24.04", "ubuntu-latest", "macos-latest", "macos-15"):
            with self.subTest(runner=runner):
                self.assertEqual(lane(flow("${{ env.agent }} -p x", job_env="{AGENT: claude}", runs_on=runner)),
                                 "trusted")
                self.assertEqual(lane(flow("${{ env['agent'] }} -p x", job_env="{AGENT: claude}", runs_on=runner)),
                                 "trusted")

    def test_windows_folds(self):
        for form in ("${{ env.agent }}", "${{ env['agent'] }}", "${{ ENV.Agent }}"):
            with self.subTest(form=form):
                self.assertEqual(lane(flow(f"{form} -p x", job_env="{AGENT: claude}", runs_on="windows-latest")),
                                 "agent")

    def test_windows_the_steps_value_wins_under_the_jobs_spelling(self):
        text = flow("${{ env.AGENT }} -p x", job_env="{AGENT: echo}", step_env="{agent: claude}",
                    runs_on="windows-2025")
        self.assertEqual(lane(text), "agent")
        linux = flow("${{ env.AGENT }} -p x", job_env="{AGENT: echo}", step_env="{agent: claude}")
        self.assertEqual(lane(linux), "trusted")

    def test_a_runner_the_checker_cannot_place_keeps_both(self):
        for runner in ("self-hosted", "[self-hosted, linux]", "my-runner", "${{ inputs.os }}", "ubuntu-gpu"):
            with self.subTest(runner=runner):
                self.assertEqual(lane(flow("${{ env.agent }} -p x", job_env="{AGENT: claude}", runs_on=runner)),
                                 "agent")

    def test_a_matrix_of_linux_and_windows_keeps_both(self):
        extra = "    strategy:\n      matrix:\n        os: [ubuntu-24.04, windows-latest]\n"
        text = flow("${{ env.agent }} -p x", job_env="{AGENT: claude}", runs_on="${{ matrix.os }}", extra=extra)
        self.assertEqual(lane(text), "agent")
        extra = "    strategy:\n      matrix:\n        os: [ubuntu-24.04, macos-latest]\n"
        text = flow("${{ env.agent }} -p x", job_env="{AGENT: claude}", runs_on="${{ matrix.os }}", extra=extra)
        self.assertEqual(lane(text), "trusted")

    def test_env_case(self):
        class Job:
            def __init__(self, sets, hosted=False):
                self._sets, self.self_hosted = sets, hosted

            def runner_label_sets(self):
                return self._sets
        self.assertEqual(env_expr.env_case(None), "both")
        self.assertEqual(env_expr.env_case(Job([["ubuntu-24.04"]])), "exact")
        self.assertEqual(env_expr.env_case(Job([["Windows-Latest"]])), "folded")
        self.assertEqual(env_expr.env_case(Job([["ubuntu-24.04"], ["windows-latest"]])), "both")
        self.assertEqual(env_expr.env_case(Job([["ubuntu-24.04", "gpu"]])), "both")
        self.assertEqual(env_expr.env_case(Job(None)), "both")
        self.assertEqual(env_expr.env_case(Job([["ubuntu-24.04"]], hosted=True)), "both")


class OnlyEnvAtTheHeadTest(unittest.TestCase):
    """`matrix.env`, `inputs.env`, `steps.env.outputs` and the text 'env' are not the `env` context."""

    def test_other_contexts_are_left_as_written(self):
        for form in ("${{ matrix.env }}", "${{ inputs.env }}", "${{ steps.env.outputs.x }}", "${{ 'env' }}",
                     "${{ github.env }}"):
            with self.subTest(form=form):
                text = flow(f"echo {form}", job_env="{AGENT: claude}")
                self.assertEqual(lane(text), "trusted")
                self.assertEqual(problems(text), [])

    def test_head_reads_env(self):
        tokens = env_expr.expr_mod.tokens
        self.assertTrue(env_expr.head_reads_env(tokens("env.X")))
        self.assertTrue(env_expr.head_reads_env(tokens("x[env.K]")))
        self.assertTrue(env_expr.head_reads_env(tokens("toJSON(ENV)")))
        self.assertFalse(env_expr.head_reads_env(tokens("matrix.env")))
        self.assertFalse(env_expr.head_reads_env(tokens("'env'")))
        self.assertFalse(env_expr.head_reads_env(tokens("inputs.env || steps.env.outputs.x")))


class FailsClosedTest(unittest.TestCase):
    """What the checker does not work out is an error of the file, never read as empty."""

    def assert_unread(self, text, why):
        found = problems(text)
        self.assertTrue(any(UNREAD in p and why in p for p in found), found)

    def test_a_function_the_checker_does_not_know(self):
        self.assert_unread(flow("${{ case(env.A, 'x') }} -p x", job_env="{A: claude}"),
                           "function the checker does not know")

    def test_from_json_of_the_whole_env(self):
        self.assert_unread(flow("${{ fromJSON(env) }}"), "fromJSON")

    def test_a_form_the_checker_does_not_read(self):
        self.assert_unread(flow("${{ env.A env.B }}", job_env="{A: claude}"), "form the checker does not read")
        self.assert_unread(flow("${{ (env.A }}", job_env="{A: claude}"), "bracket")

    def test_too_deep(self):
        # The expression reader of the other rules already makes this an error of the file; either way the check
        # fails.
        found = problems(flow("${{ " + "(" * 80 + "env.A" + ")" * 80 + " }}", job_env="{A: claude}"))
        self.assertTrue(any("nested too deeply" in p for p in found), found)
        self.assertRaises(env_expr.Unread, env_expr.put_in, "${{ " + "!" * 80 + "env.A }}",
                          env_expr.Env([{"A": "claude"}], "exact"))

    def test_too_many_readings_of_one_line(self):
        many = " ".join("${{ env[matrix.k%d] }}" % n for n in range(3))
        self.assert_unread(flow(f"echo {many}", job_env="{" + ", ".join(f"V{n}: v{n}" for n in range(20)) + "}"),
                           "readings of one line")

    def test_too_much_copied(self):
        env = "{" + ", ".join(f"V{n}: v{n}" for n in range(3000)) + "}"
        lines = "\n".join("echo " + "x" * 200 + " ${{ env[matrix.k] }}" for _ in range(5))
        self.assert_unread(flow(lines, job_env=env), "characters")


class NoNewErrorOnOrdinaryExpressionsTest(unittest.TestCase):
    """The first review of 2d.18 found ordinary `||` expressions made errors when readings were multiplied across a
    step. Each expression is read on its own here."""

    def test_five_defaults(self):
        run = "echo " + " ".join("${{ env.X%d || 'd' }}" % n for n in range(5))
        text = flow(run, job_env="{X1: a}")
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "trusted")

    def test_ternaries_on_many_lines(self):
        run = "\n".join("echo ${{ github.event_name == 'push' && env.A || env.B }}" for _ in range(40))
        self.assertEqual(problems(flow(run, job_env="{A: x, B: y}")), [])

    def test_eight_ternaries_on_one_line(self):
        run = "tool " + " ".join("--a%d ${{ github.event_name == 'push' && env.A || env.B }}" % n for n in range(8))
        self.assertEqual(problems(flow(run, job_env="{A: x, B: y}")), [])

    def test_to_json_of_a_large_env(self):
        env = "{" + ", ".join(f"V{n}: value{n}" for n in range(1000)) + "}"
        text = flow('echo "${{ toJSON(env) }}"', job_env=env)
        self.assertEqual(problems(text), [])
        self.assertEqual(lane(text), "trusted")

    def test_comparisons_and_functions(self):
        run = ("echo ${{ env.X == 'a' }} ${{ contains(env.X, 'b') }} ${{ !env.Y }} ${{ hashFiles('x') }}\n"
               "echo ${{ success() && env.X }} ${{ env.X != 'a' && 'yes' || 'no' }} ${{ format('{{0}}', env.X) }}")
        self.assertEqual(problems(flow(run, job_env="{X: a}")), [])

    def test_this_repository_and_expectrail_shapes(self):
        run = "echo ${{ env.HELDOUT_TOKEN_SET == 'true' && format('{0}/heldout-set', github.workspace) || '' }}"
        self.assertEqual(problems(flow(run, job_env="{HELDOUT_TOKEN_SET: 'true'}")), [])


class ReaderTest(unittest.TestCase):
    """The values the reader gives, on the cases the entry names."""

    def values(self, body, scopes, case="exact"):
        env = env_expr.Env(scopes, case)
        out = []
        for value in env_expr._Reader(env_expr.expr_mod.tokens(body), env).read():
            out.extend(env_expr.text_of(value, env))
        return out

    def test_pinned(self):
        self.assertEqual(self.values("env.A", [{"A": "x"}]), ["x"])
        self.assertEqual(self.values("env.B", [{"A": "x"}]), [""])
        self.assertEqual(self.values("env.A || 'd'", [{"A": ""}]), ["d"])
        self.assertEqual(self.values("env.A && 'y'", [{"A": "x"}]), ["y"])
        self.assertEqual(self.values("toJSON(env.A)", [{"A": 'a"b'}]), ['"a\\"b"'])
        self.assertEqual(self.values("format('{0}-{1}', env.A, 2)", [{"A": "x"}]), ["x-2"])

    def test_unknown_contexts_keep_the_written_text(self):
        self.assertEqual(self.values("matrix.a || env.A", [{"A": "x"}]), [env_expr.UNKNOWN, "x"])
        self.assertEqual(self.values("format('{0}{1}', env.A, matrix.b)", [{"A": "cla"}]), [env_expr.UNKNOWN, "cla"])

    def test_case_modes(self):
        scopes = [{"AGENT": "echo"}, {"agent": "claude"}]
        self.assertEqual(self.values("env.AGENT", scopes, "exact"), ["echo"])
        self.assertEqual(self.values("env.AGENT", scopes, "folded"), ["claude"])
        self.assertEqual(sorted(self.values("env.agent", [{"AGENT": "claude"}], "both")), ["", "claude"])

    def test_a_scope_written_as_one_expression(self):
        self.assertIn(env_expr.UNKNOWN, self.values("env.A", ["${{ fromJSON(inputs.e) }}", {"B": "x"}]))

    def test_numbers_and_booleans_in_env(self):
        self.assertEqual(self.values("env.N", [{"N": 3}]), ["3"])
        self.assertEqual(self.values("env.B", [{"B": True}]), ["true"])


class CostTest(unittest.TestCase):
    """The review of 2d.18's first head: 20,000 references over 5,000 `env` entries took 16.9 s against 3.4 s, and
    three aliased steps about 627 s against 9.6 s. The `env` is folded once per reading and a reading is made once
    for steps YAML makes of one mapping; these count what is made, not seconds (F-384)."""

    def test_many_references_build_the_env_once(self):
        env = "{" + ", ".join(f"E{n}: v{n}" for n in range(5000)) + "}"
        run = "echo " + " ".join("${{ env.E%d }}" % (n % 5000) for n in range(20000))
        built = []
        real = env_expr.Env.__init__

        def counting(self, scopes, case):
            built.append(case)
            real(self, scopes, case)
        with mock.patch.object(env_expr.Env, "__init__", counting):
            found = problems(flow(run, job_env=env))
        self.assertEqual(found, [])
        self.assertLessEqual(len(built), 2)

    def test_aliased_steps_are_read_once(self):
        run = "\n".join("echo ${{ env.E%d || env.F }} ${{ env[matrix.k] }}" % n for n in range(50))
        body = "".join(f"          {line}\n" for line in run.split("\n"))
        env = "{" + ", ".join(f"E{n}: v{n}" for n in range(200)) + "}"
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n"
                f"    env: {env}\n    steps:\n      - &s\n        run: |\n{body}      - *s\n      - *s\n")
        calls = []
        real = env_expr.plan

        def counting(text_, env_):
            calls.append(1)
            return real(text_, env_)
        with mock.patch.object(env_expr, "plan", counting):
            problems(text)
        self.assertEqual(len(calls), 1)

    def test_the_values_put_in_are_on_the_workflows_ledger(self):
        value = "v" * 100_000
        steps = "".join(f"      - run: echo ${{{{ env.BIG }}}}\n" for _ in range(60))
        text = (f"on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    env:\n      BIG: {value}\n"
                f"    steps:\n{steps}")
        found = problems(text)
        self.assertTrue(any(wf.ENV_PUT_IN_WORKFLOW_UNREAD in p for p in found), found[:2])
        # Steps before the bound are read; the first is not an error.
        self.assertFalse(any("step 'step 1'" in p for p in found))



class FromTheReviewTest(unittest.TestCase):
    """The first review of slice 2d.19 (on `0fcffb3`): each case failed there."""

    def test_nine_defaults_in_one_continued_command_are_no_error(self):
        sets = " \\\n".join("  --set k%d=${{ inputs.k%d || env.K }}" % (n, n) for n in range(9))
        self.assertEqual(problems(flow("helm upgrade app ./chart \\\n" + sets, job_env="{K: v}")), [])
        args = " ".join("--build-arg K%d=${{ matrix.k || env.K }}" % n for n in range(9))
        self.assertEqual(problems(flow(f"docker build {args} .", job_env="{K: v}")), [])
        sets = " ".join("--k%d ${{ github.event.inputs.k != '' && github.event.inputs.k || env.K }}" % n
                        for n in range(9))
        self.assertEqual(problems(flow(f"tool {sets}", job_env="{K: v}")), [])

    def test_a_default_still_finds_the_agent(self):
        self.assertEqual(lane(flow("${{ inputs.tool || env.AGENT }} -p x", job_env="{AGENT: claude}")), "agent")

    def test_an_index_of_many_unknown_keys_builds_every_value_once(self):
        calls = []
        real = env_expr.Env.every

        def counting(self):
            calls.append(1)
            return real(self)
        env = "{" + ", ".join(f"J{n}: '{{\"a\": {n}}}'" for n in range(300)) + "}"
        with mock.patch.object(env_expr.Env, "every", counting):
            problems(flow("echo ${{ env[fromJSON(env[matrix.k])] }}", job_env=env))
        self.assertLessEqual(len(calls), 3)

    def test_from_json_parses_each_text_once(self):
        big = json.dumps({f"k{n}": f"v{n}" for n in range(2000)})
        run = "\n".join("echo ${{ fromJSON(env.BIG).k%d }}" % n for n in range(300))
        calls = []
        real = env_expr.json.loads

        def counting(text):
            calls.append(len(text))
            return real(text)
        with mock.patch.object(env_expr.json, "loads", counting):
            found = problems(flow(run, job_env="{BIG: '" + big.replace("'", "''") + "'}"))
        self.assertEqual(found, [])
        self.assertEqual(len(calls), 1)

    def test_from_json_has_a_bound(self):
        env = env_expr.Env([{f"B{n}": f"[{n}," + "1," * 100_000 + "1]" for n in range(30)}], "exact")
        body = " || ".join(f"fromJSON(env.B{n})[0]" for n in range(30))
        self.assertRaises(env_expr.Unread, env_expr.put_in, "${{ " + body + " }}", env)

    def test_copies_are_counted_for_the_workflow_before_they_are_made(self):
        env = "{" + ", ".join(f"V{n}: value{n}" for n in range(1000)) + "}"
        steps = "".join(f"      - run: echo {n} ${{{{ env }}}} {'x' * 400}\n" for n in range(40))
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-24.04\n"
                f"    env: {env}\n    steps:\n{steps}")
        made = []
        real = env_expr.build

        def counting(text_, plan_):
            out = real(text_, plan_)
            made.append(len(out))
            return out
        with mock.patch.object(env_expr, "build", counting):
            found = problems(text)
        self.assertTrue(any(wf.ENV_EXPRESSIONS_WORKFLOW_UNREAD in p for p in found), found[:1])
        self.assertLessEqual(sum(made), wf.ENV_PUT_IN_WORKFLOW + max(made))

    def test_letter_case_outside_ascii(self):
        # GitHub compares texts letter by letter without regard to case (.NET's ordinal comparison): `ß` is not
        # `SS`, and the Kelvin sign is not `k`. Outside ASCII the comparison may go either way here.
        for value, other in (("ß", "SS"), ("\u212a", "k")):
            with self.subTest(value=value):
                run = "${{ env.M == '%s' && 'echo' || env.AGENT }} -p x" % other
                self.assertEqual(lane(flow(run, job_env="{AGENT: claude, M: '%s'}" % value)), "agent")
                run = "${{ env.M != '%s' && env.AGENT || 'echo' }} -p x" % other
                self.assertEqual(lane(flow(run, job_env="{AGENT: claude, M: '%s'}" % value)), "agent")
        text = flow("${{ env.SS }} -p x", job_env="{SS: claude}", step_env="{ß: echo}", runs_on="windows-latest")
        self.assertEqual(lane(text), "agent")
        self.assertEqual(env_expr.fold("straße"), "STRAßE")

    def test_names_yaml_reads_as_other_than_text(self):
        for key, form in (("1", "env['1']"), ("true", "env.true"), ("null", "env['']"), ("1.5", "env['1.5']"),
                          ("0o7", "env['7']")):
            with self.subTest(key=key):
                self.assertEqual(lane(flow("${{ %s }} -p x" % form, job_env="{%s: claude}" % key)), "agent")

    def test_a_number_index_is_taken_whole(self):
        self.assertEqual(lane(flow("${{ fromJSON(env.L)[1.9] }} -p x", job_env="{L: '[\"echo\",\"claude\"]'}")),
                         "agent")

    def test_a_template_the_checker_does_not_know(self):
        self.assertEqual(lane(flow("${{ format(inputs.fmt, env.AGENT) }} -p x", job_env="{AGENT: claude}")), "agent")

    def test_a_negative_number(self):
        self.assertEqual(problems(flow("echo ${{ env.RETRIES || -1 }}")), [])


if __name__ == "__main__":
    unittest.main()
