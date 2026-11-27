"""Flagship slice 2d.19e (#382): an `env` written as one expression, for a local composite action's steps.

GitHub works out a `${{ }}` expression in a step of a composite action with the `env` context its caller runs with
(the workflow's, the job's and the using step's own `env`) under the action step's own. Any of them may be written
as one expression (`env: ${{ fromJSON(vars.E) }}`), whose names and values the file does not show. Slice 2d.19d made
such a scope fail closed in a workflow's own step (D-144). In a local action's step, read by 2d.4a's reader, it did
not (F-421): the reader dropped such a scope and read a name it did not have as empty, so `run: ${{ env.AGENT }} -p x`
in the action, under the job's `env: ${{ fromJSON(vars.E) }}`, put the job in no agent lane, with no error and no
finding. Now a name no mapping nearer the step sets may be any text there too, and where an expression that may give
it stands where an agent's name would be read as its command line or where a command's program goes, the step is an
error of its file, as D-144 draws the line. Elsewhere in a line it is read as empty, as before.

The same reader also read `env` too narrowly where no scope is written so: a read not pinned to one name
(`toJSON(env)`, `env[inputs.k]`) was empty, and a name gave only the last value of the names that fold to it.
"""

import unittest

from helpers import TempDir
from test_local_composite_actions import ACTION_DIR, KEY, build, composite

from obaaf import checker

SCOPE = "written as one expression the checker does not read, may set"
UNREAD = "its command lines hold an expression that reads `env` which the checker does not work out"
USES = f"./{ACTION_DIR}"
JOB = "${{ fromJSON(vars.E) }}"


def wf(top="", job="", step="", uses=USES, with_="", key=True):
    """A workflow of one job `a` whose step uses the local action; `top`, `job` and `step` are the `env` of the
    workflow, the job and the using step, written as YAML (a flow mapping or one expression)."""
    text = "on: workflow_dispatch\n" + (f"env: {top}\n" if top else "")
    text += "jobs:\n  a:\n    runs-on: ubuntu-24.04\n    permissions: {contents: read}\n"
    if job:
        text += f"    env: {job}\n"
    text += f"    steps:\n      - uses: {uses}\n"
    if with_:
        text += f"        with: {with_}\n"
    if step:
        text += f"        env: {step}\n"
    if key:
        text += f"      - run: echo done\n        env:\n          ANTHROPIC_API_KEY: {KEY}\n"
    return text


def step(run, env="", shell="bash"):
    """A step of a composite action running `run` (a block scalar), with its own `env` written as YAML."""
    body = "".join(f"        {line}\n" for line in run.split("\n"))
    out = f"    - shell: {shell}\n      run: |\n{body}"
    if env:
        out += f"      env: {env}\n"
    return out


def files(*steps, inputs=""):
    head = f"name: x\ninputs:\n{inputs}" if inputs else "name: x\n"
    return {f"{ACTION_DIR}/action.yml": head + "runs:\n  using: composite\n  steps:\n" + "".join(steps)}


def result(text, given):
    with TempDir() as tmp:
        return checker.check(build(tmp, text, given))


def lanes(text, given):
    with TempDir() as tmp:
        rows = checker.lanes(build(tmp, text, given), notes=[], errors=[], seen=[])
    return {job: (lane, reason) for _, job, lane, reason in rows}.get("a")


def lane(text, given):
    return lanes(text, given)[0]


# The reason 2d.4a's reader (the first pass) gives; the second pass (2d.4b2) says "in a local action it uses".
FIRST_PASS = f"runs an agent CLI in step 'step 1' of the local action {USES}"


def scope_errors(text, given):
    return [e for e in result(text, given).errors if SCOPE in e]


class TheCaseOfF421Test(unittest.TestCase):
    """The case F-421 left: no agent lane, no error and no finding on the base (`ccbe0b8`)."""

    def test_the_case_is_an_error_of_the_file(self):
        (error,) = result(wf(job=JOB), files(step("${{ env.AGENT }} -p review"))).errors
        self.assertIn(f"job 'a' uses the local action {USES}, and in step 1 of the local action {USES} {UNREAD} "
                      "(one ('${{ env.AGENT }}'), where an agent's name would be read as its command line, reads "
                      f"from `env` what the job's `env`, {SCOPE})", error)
        self.assertIn("so the checker cannot tell whether an agent runs in it", error)

    def test_each_scope_is_named_and_the_nearest_one(self):
        own = files(step("${{ env.AGENT }} -p x", env=JOB))
        plain = files(step("${{ env.AGENT }} -p x"))
        for where, scopes, given in (
                ("the workflow's `env`", {"top": JOB}, plain),
                ("the job's `env`", {"job": JOB}, plain),
                (f"the `env` of the step that uses {USES}", {"step": JOB}, plain),
                ("the job's `env`", {"top": JOB, "job": JOB}, plain),
                (f"the `env` of step 1 of the local action {USES}", {}, own),
                (f"the `env` of step 1 of the local action {USES}", {"job": JOB, "step": "{AGENT: claude}"}, own)):
            with self.subTest(where=where, scopes=scopes):
                (error,) = scope_errors(wf(**scopes), given)
                self.assertIn(f"what {where}, {SCOPE}", error)

    def test_through_a_further_local_action(self):
        inner = {".github/actions/inner/action.yml": composite("    - run: ${{ env.AGENT }} -p x\n      shell: bash\n")}
        for outer_env, where in (("", "the job's `env`"),
                                 (f"\n      env: {JOB}", f"the `env` of step 1 of the local action {USES}")):
            with self.subTest(where=where):
                given = {f"{ACTION_DIR}/action.yml": composite(f"    - uses: ./.github/actions/inner{outer_env}\n"),
                         **inner}
                (error,) = scope_errors(wf(job=JOB if not outer_env else ""), given)
                self.assertIn("in step 1 of the local action ./.github/actions/inner", error)
                self.assertIn(f"what {where}, {SCOPE}", error)

    def test_the_egress_actions_command_and_a_github_script_script(self):
        for body in ("    - uses: Obaaf/OBAAF/actions/egress@1111111111111111111111111111111111111111\n"
                     "      with:\n        allow: api.anthropic.com\n        run: ${{ env.AGENT }} -p x\n",
                     "    - uses: actions/github-script@1111111111111111111111111111111111111111\n"
                     "      with:\n        script: |\n          exec('${{ env.AGENT }} -p x')\n"):
            with self.subTest(body=body.split("@")[0]):
                errors = scope_errors(wf(job=JOB), {f"{ACTION_DIR}/action.yml": composite(body)})
                self.assertEqual(len(errors), 1, errors)

    def test_where_the_patterns_and_the_programs_are(self):
        for run in ("if true; then ${{ env.A }} -p y; fi", "xvfb-run ${{ env.A }} -p y", "npx ${{ env.A }}",
                    "sudo ${{ env.A }}", "make && ${{ env.A }}", "${{ env.DIR }}/bin/${{ env.A }} run",
                    "${{ format('{0}', env.A) }} -p x", "${{ env.X || env.A }} -p x",
                    "${{ fromJSON(toJSON(env)).A }} -p x", "${{ env[inputs.k] }} -p x"):
            with self.subTest(run=run):
                self.assertEqual(len(scope_errors(wf(job=JOB), files(step(run)))), 1)

    def test_a_cut_past_sixteen_values_keeps_what_the_scope_may_give(self):
        chain = " || ".join(f"'w{n}'" for n in range(20))
        run = f"${{{{ {chain} || env.AGENT }}}} -p x"
        self.assertEqual(len(scope_errors(wf(job=JOB), files(step(run)))), 1)
        run = f"${{{{ format('{{0}}{{1}}', {chain}, env.AGENT) }}}} -p x"
        self.assertEqual(len(scope_errors(wf(job=JOB), files(step(run)))), 1)

    def test_an_input_is_read_as_before_beside_it(self):
        given = files(step("${{ inputs.tool }} -p x"), inputs="  tool: {default: claude}\n")
        text = wf(job=JOB)
        self.assertEqual(result(text, given).errors, [])
        self.assertEqual(lane(text, given), "agent")


class WhatANearerMappingSetsTest(unittest.TestCase):
    """A name a mapping nearer the step than the scope written as one expression sets is read as before."""

    def test_the_using_steps_or_the_action_steps_own_value(self):
        for scopes, own, expected in (({"job": JOB, "step": "{AGENT: claude}"}, "", "agent"),
                                      ({"job": JOB, "step": "{AGENT: echo}"}, "", "trusted"),
                                      ({"job": JOB}, "{AGENT: claude}", "agent"),
                                      ({"job": JOB}, "{AGENT: echo}", "trusted"),
                                      ({"top": JOB, "job": "{AGENT: claude}"}, "", "agent")):
            with self.subTest(scopes=scopes, own=own):
                text, given = wf(**scopes), files(step("${{ env.AGENT }} -p x", env=own))
                self.assertEqual(result(text, given).errors, [])
                self.assertEqual(lane(text, given), expected)

    def test_what_settles_nothing(self):
        """A value farther than the scope, a name in another letter case, a value that is not text, and a key YAML
        1.2 may read as another scalar settle nothing (as `env_expr.Env` reads a workflow's own step)."""
        for scopes, run in (({"top": "{AGENT: echo}", "job": JOB}, "${{ env.AGENT }} -p x"),
                            ({"job": JOB, "step": "{agent: echo}"}, "${{ env.AGENT }} -p x"),
                            ({"job": JOB, "step": "{AGENT: [echo]}"}, "${{ env.AGENT }} -p x"),
                            ({"job": JOB, "step": "{'0o7': echo}"}, "${{ env['0o7'] }} -p x")):
            with self.subTest(scopes=scopes):
                self.assertEqual(len(scope_errors(wf(**scopes), files(step(run)))), 1)

    def test_an_own_value_from_an_input(self):
        given = files(step("${{ env.T }} -p x", env="{T: '${{ inputs.tool }}'}"), inputs="  tool: {default: claude}\n")
        self.assertEqual(lane(wf(job=JOB), given), "agent")


class ElsewhereInALineTest(unittest.TestCase):
    """Elsewhere in a line such a value is read as empty, as before: no new error on ordinary lines."""

    def test_ordinary_lines(self):
        for run in ("echo ${{ env.VERSION }}", "mkdir -p ${{ env.CCACHE_DIR }}", "make CC=${{ env.CC }}",
                    "echo \"${{ toJSON(env) }}\" > env.json", "test -n \"${{ env.TOKEN }}\""):
            with self.subTest(run=run):
                text, given = wf(job=JOB), files(step(run))
                self.assertEqual(result(text, given).errors, [])
                self.assertEqual(lane(text, given), "trusted")

    def test_no_scope_written_so_gives_no_error(self):
        for run in ("${{ env.AGENT }} -p x", "${{ env.CC }} --version"):
            with self.subTest(run=run):
                self.assertEqual(result(wf(job="{CC: gcc}"), files(step(run))).errors, [])


class WithoutAScopeWrittenSoTest(unittest.TestCase):
    """2d.4a's reader read `env` more narrowly than GitHub where no scope is written as one expression. On the base
    the second pass (2d.4b2, whose steps env_expr reads) put the job in the agent lane for all of these but
    `env[inputs.k]`, which neither pass read; now the first pass reads each, and its reason is the one given."""

    def test_a_read_not_pinned_to_one_name_gives_every_value(self):
        for run in ("${{ fromJSON(toJSON(env)).AGENT }} -p x", "${{ env[inputs.k] }} -p x",
                    "${{ toJSON(env.AGENT) }} -p x"):
            with self.subTest(run=run):
                self.assertEqual(lanes(wf(job="{AGENT: claude}"), files(step(run))), ("agent", FIRST_PASS))

    def test_a_name_gives_its_own_value_as_well_as_the_last_that_folds_to_it(self):
        """Before, `env.AGENT` gave `echo`, the last value of a name that folds to it; a Linux runner gives
        `claude`."""
        text, given = wf(job="{AGENT: claude}", step="{agent: echo}"), files(step("${{ env.AGENT }} -p x"))
        self.assertEqual(lanes(text, given), ("agent", FIRST_PASS))
        # And `env.agent` gives `echo` on any runner: not an agent.
        self.assertEqual(lane(text, files(step("${{ env.agent }} -p x"))), "trusted")


if __name__ == "__main__":
    unittest.main()
