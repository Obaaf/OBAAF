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

Where no scope of the chain is written as one expression, the reader reads `env` as before.
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
    """Where no scope is written as one expression the reader reads `env` as before. A first version gave every value
    for a read not pinned to one name, and a name's own value beside the last that folds to it; the review found that
    this multiplied whole texts past what the reader reads (an agent script lost, with OBAAF-GHA-005 and 020), new
    notes on ordinary workflows, a false agent lane through `hashFiles(env.AGENT)` and a cost 23 times the base's."""

    def test_ordinary_reads_of_env_are_as_on_the_base(self):
        many = "{" + ", ".join(f"V{n}: a{n}" for n in range(20)) + "}"
        for job, run, expected in ((many, "echo '${{ toJSON(env) }}' > env.json", "trusted"),
                                   (many, "echo ${{ env[inputs.k] }}", "trusted"),
                                   ("{AGENT: claude}", "${{ hashFiles(env.AGENT) }} -p x", "trusted"),
                                   ("{AGENT: claude}", "${{ env.AGENT }} -p x", "agent")):
            with self.subTest(run=run):
                text, given = wf(job=job), files(step(run))
                with TempDir() as tmp:
                    notes: list = []
                    rows = checker.lanes(build(tmp, text, given), notes=notes, errors=[], seen=[])
                self.assertEqual({j: l for _, j, l, _r in rows}.get("a"), expected)
                self.assertEqual(notes, [])

    def test_a_long_script_beside_toJSON_env_keeps_its_input(self):
        """The review's case: 16 entries in the job's `env` and `toJSON(env)` in a 15 KB `run` that also names the
        agent's script through an input."""
        lines = [f"echo 'step {n}: doing the usual build bookkeeping here {n:04d}'" for n in range(260)]
        run = "\n".join([*lines, "bash ./scripts/${{ inputs.script }}", "echo '${{ toJSON(env) }}' > env.json"])
        given = {**files(step(run), inputs="  script: {default: agent.sh}\n"),
                 "scripts/agent.sh": "#!/bin/bash\nclaude -p 'review'\n"}
        job = "{" + ", ".join(f"V{n}: a{n}" for n in range(16)) + "}"
        self.assertEqual(lane(wf(job=job), given), "agent")


class TheReviewersFindingsTest(unittest.TestCase):
    """What the first review of 2d.19e found under a scope written as one expression (2026-11-27)."""

    def test_a_with_value_that_reads_env_handed_to_a_further_action(self):
        inner = {".github/actions/inner/action.yml":
                 "name: i\ninputs:\n  tool: {default: echo}\nruns:\n  using: composite\n  steps:\n"
                 "    - run: ${{ inputs.tool }} -p x\n      shell: bash\n"}
        for handed, own in (("${{ env.AGENT }}", ""), ("${{ format('{0}', env.AGENT) }}", ""),
                            ("${{ env.AGENT }}", f"\n      env: {JOB}")):
            with self.subTest(handed=handed, own=own):
                given = {f"{ACTION_DIR}/action.yml": composite(
                    f"    - uses: ./.github/actions/inner\n      with:\n        tool: {handed}{own}\n"), **inner}
                (error,) = scope_errors(wf(job=JOB), given)
                self.assertIn("in step 1 of the local action ./.github/actions/inner", error)

    def test_a_workflows_with_value_that_reads_env(self):
        command = files(step("${{ inputs.command }}"), inputs="  command: {required: true}\n")
        tool = files(step("${{ inputs.tool }} -p x"), inputs="  tool: {default: echo}\n")
        for scopes, with_, given in (({"job": JOB}, "{command: '${{ env.AGENT }} -p review'}", command),
                                     ({"job": JOB}, "{tool: '${{ env.AGENT }}'}", tool),
                                     ({"step": JOB}, "{tool: '${{ env.AGENT }}'}", tool)):
            with self.subTest(scopes=scopes, with_=with_):
                self.assertEqual(len(scope_errors(wf(with_=with_, **scopes), given)), 1)
        # Without a scope the value is read from the job's `env`, as before.
        self.assertEqual(lane(wf(job="{AGENT: claude}", with_="{command: '${{ env.AGENT }} -p review'}"), command),
                         "agent")

    def test_an_inputs_default_that_reads_env(self):
        given = files(step("${{ inputs.tool }} -p x"), inputs="  tool: {default: '${{ env.AGENT }}'}\n")
        self.assertEqual(len(scope_errors(wf(job=JOB), given)), 1)

    def test_format_combines_what_the_scope_may_give_first(self):
        literals = " || ".join(["'-p'"] + [f"'b{n}'" for n in range(2, 17)])
        run = f"${{{{ format('{{0}} {{1}}', env.Z == 'x' || env.AGENT, {literals}) }}}} review"
        self.assertEqual(len(scope_errors(wf(job=JOB), files(step(run)))), 1)

    def test_nested_more_deeply_than_the_reader_follows(self):
        run = "${{ " + "(env.Z == 'q' || " * 10 + "env.AGENT" + ")" * 10 + " }} -p x"
        self.assertEqual(len(scope_errors(wf(job=JOB), files(step(run)))), 1)
        # Not reading `env`, it is named as not read, as before.
        run = "${{ " + "(inputs.z == 'q' || " * 10 + "inputs.a" + ")" * 10 + " }} -p x"
        self.assertEqual(scope_errors(wf(job=JOB), files(step(run))), [])

    def test_the_runners_comparison_of_names(self):
        """On a known Windows runner a name in another letter case settles it; a name outside ASCII never does
        there, as `env_expr.Env` reads a workflow's own step."""
        def text(runs_on, step_env):
            return wf(job=JOB, step=step_env).replace("runs-on: ubuntu-24.04", f"runs-on: {runs_on}")
        for runs_on, step_env, run, errors in (("windows-latest", "{Agent: echo}", "${{ env.AGENT }} -p x", 0),
                                               ("ubuntu-24.04", "{Agent: echo}", "${{ env.AGENT }} -p x", 1),
                                               ("windows-latest", "{ÄGENT: echo}", "${{ env['ÄGENT'] }} -p x", 1),
                                               ("ubuntu-24.04", "{ÄGENT: echo}", "${{ env['ÄGENT'] }} -p x", 0)):
            with self.subTest(runs_on=runs_on, step_env=step_env):
                self.assertEqual(len(scope_errors(text(runs_on, step_env), files(step(run)))), errors)

    def test_hashFiles_gives_a_hash(self):
        run = "docker run --name ${{ hashFiles(env.F) }} -p 8080:80 img"
        self.assertEqual(scope_errors(wf(job=JOB), files(step(run))), [])


class TheReviewersSecondPassTest(unittest.TestCase):
    """What the second review of 2d.19e found (2026-11-27)."""

    INNER = (".github/actions/inner/action.yml", "name: i\ninputs:\n  tool: {default: echo}\nruns:\n  using: composite\n"
             "  steps:\n    - run: ${{ inputs.tool }} -p x\n      shell: bash\n")

    def test_a_value_handed_in_is_worked_out_with_the_env_it_was_written_under(self):
        """The workflow's `with:` (or an input's default) that reads `env`, handed on to a further action by a step
        whose own `env` settles the name: GitHub works it out in the workflow's step, where the scope may set it."""
        handing = ("    - uses: ./.github/actions/inner\n      env: {AGENT: echo}\n      with:\n"
                   "        tool: ${{ inputs.tool }}\n")
        for inputs, with_ in (("  tool: {default: echo}\n", "{tool: '${{ env.AGENT }}'}"),
                              ("  tool: {default: '${{ env.AGENT }}'}\n", "")):
            with self.subTest(inputs=inputs):
                given = {f"{ACTION_DIR}/action.yml": f"name: x\ninputs:\n{inputs}runs:\n  using: composite\n  steps:\n"
                         + handing, self.INNER[0]: self.INNER[1]}
                (error,) = scope_errors(wf(job=JOB, with_=with_), given)
                self.assertIn("in step 1 of the local action ./.github/actions/inner", error)

    def test_a_value_handed_in_through_the_next_steps_env(self):
        inner = ("name: i\ninputs:\n  tool: {default: echo}\nruns:\n  using: composite\n  steps:\n"
                 "    - shell: bash\n      env: {T: '${{ inputs.tool }}'}\n      run: ${{ env.T }} -p x\n")
        given = {f"{ACTION_DIR}/action.yml": composite("    - uses: ./.github/actions/inner\n      with:\n"
                                                       "        tool: ${{ env.AGENT }}\n"),
                 ".github/actions/inner/action.yml": inner}
        self.assertEqual(len(scope_errors(wf(job=JOB), given)), 1)
        # Without the scope, the job's value is read through, as before.
        self.assertEqual(lane(wf(job="{AGENT: claude}"), given), "agent")

    def test_a_text_left_as_written_past_what_the_reader_reads_is_a_note_as_before(self):
        """Sixteen readings of a long `run` pass what the reader reads, so the text is left as written and named in
        the note; the step's own `env` settles `PY`, so the caller's `env` is not the one to read it with."""
        lines = [f"echo 'line {n}: some ordinary build output goes here for the record'" for n in range(250)]
        run = "\n".join([*lines, "echo ${{ inputs.b0 || 'd0' }} ${{ inputs.b1 || 'd1' }} ${{ inputs.b2 || 'd2' }} "
                          "${{ inputs.b3 || 'd3' }}", "${{ env.PY }} -m build"])
        inputs = "".join(f"  b{n}: {{default: ''}}\n" for n in range(4))
        text = wf(job="${{ matrix.env }}").replace("    env: ${{ matrix.env }}\n",
                                                   "    strategy: {matrix: {env: [{A: '1'}]}}\n"
                                                   "    env: ${{ matrix.env }}\n")
        with TempDir() as tmp:
            notes: list = []
            errors: list = []
            checker.lanes(build(tmp, text, files(step(run, env="{PY: python3}"), inputs=inputs)), notes=notes,
                          errors=errors, seen=[])
        self.assertEqual(errors, [])
        self.assertTrue(any("longer than the checker reads" in note for note in notes), notes)

    def test_without_a_scope_jobs_on_both_kinds_of_runner_share_a_reading(self):
        """With the runner's kind in every key, an action used by Linux and Windows jobs was read once for each
        kind; it is kept by kind only where it was read under a scope."""
        from obaaf import checker as checker_mod
        calls = []
        real = checker_mod._charge

        def counting(cache, units):
            calls.append(units)
            return real(cache, units)

        jobs = "".join(f"  {kind}{n}:\n    runs-on: {runs_on}\n    steps:\n      - uses: {USES}\n        with: {{k: v{n}}}\n"
                       for n in range(2) for kind, runs_on in (("l", "ubuntu-24.04"), ("w", "windows-2022")))
        text = "on: workflow_dispatch\njobs:\n" + jobs
        given = files(step("echo ${{ inputs.k }}"), inputs="  k: {default: a}\n")
        checker_mod._charge = counting
        try:
            with TempDir() as tmp:
                checker.lanes(build(tmp, text, given), notes=[], errors=[], seen=[])
        finally:
            checker_mod._charge = real
        readings = [units for units in calls if units > 0]
        # One reading for each input value, as on the base, whatever the runners.
        self.assertEqual(len(readings), 2, calls)


class TheReviewersThirdPassTest(unittest.TestCase):
    """What the third review of 2d.19e found (2026-11-27): a value handed in was told apart by its text, and the
    `env` handed on lost what the scope may give. An input is now worked out where it is given."""

    def test_the_action_writing_the_same_expression_hides_nothing(self):
        run = step("${{ inputs.tool }} -p x\necho ${{ env.AGENT }}", env="{AGENT: echo}")
        for inputs, with_ in (("  tool: {default: echo}\n", "{tool: '${{ env.AGENT }}'}"),
                              ("  tool: {default: '${{ env.AGENT }}'}\n", "")):
            with self.subTest(inputs=inputs):
                self.assertEqual(len(scope_errors(wf(job=JOB, with_=with_), files(run, inputs=inputs))), 1)

    def test_handed_on_beside_the_same_expression(self):
        inner = ("name: i\ninputs:\n  tool: {default: echo}\nruns:\n  using: composite\n  steps:\n"
                 "    - run: ${{ inputs.tool }} -p x\n      shell: bash\n")
        outer = ("name: x\ninputs:\n  tool: {default: echo}\nruns:\n  using: composite\n  steps:\n"
                 "    - uses: ./.github/actions/inner\n      env: {AGENT: echo}\n      with:\n"
                 "        tool: '${{ inputs.tool }} ${{ env.AGENT }}'\n")
        given = {f"{ACTION_DIR}/action.yml": outer, ".github/actions/inner/action.yml": inner}
        self.assertEqual(len(scope_errors(wf(job=JOB, with_="{tool: '${{ env.AGENT }}'}"), given)), 1)

    def test_handed_on_through_env(self):
        reader = composite("    - run: ${{ env.T }} -p x\n      shell: bash\n")
        outer = ("name: x\ninputs:\n  tool: {default: echo}\nruns:\n  using: composite\n  steps:\n"
                 "    - uses: ./.github/actions/inner\n      env: {AGENT: echo, T: '${{ inputs.tool }}'}\n")
        given = {f"{ACTION_DIR}/action.yml": outer, ".github/actions/inner/action.yml": reader}
        self.assertEqual(len(scope_errors(wf(job=JOB, with_="{tool: '${{ env.AGENT }}'}"), given)), 1)
        # Three levels: the scope's value handed in `with:`, then on through the next step's `env`.
        middle = ("name: m\ninputs:\n  tool: {default: echo}\nruns:\n  using: composite\n  steps:\n"
                  "    - uses: ./.github/actions/third\n      env: {T: '${{ inputs.tool }}'}\n")
        given = {f"{ACTION_DIR}/action.yml": composite("    - uses: ./.github/actions/inner\n      with:\n"
                                                       "        tool: ${{ env.AGENT }}\n"),
                 ".github/actions/inner/action.yml": middle, ".github/actions/third/action.yml": reader}
        self.assertEqual(len(scope_errors(wf(job=JOB), given)), 1)
        self.assertEqual(lane(wf(job="{AGENT: claude}"), given), "agent")

    def test_a_long_text_does_not_hide_a_handed_value(self):
        lines = [f"echo 'line {n}: some ordinary build output goes here for the record'" for n in range(250)]
        run = "\n".join([*lines, "echo ${{ inputs.b0 || 'd0' }} ${{ inputs.b1 || 'd1' }} ${{ inputs.b2 || 'd2' }} "
                          "${{ inputs.b3 || 'd3' }}", "${{ inputs.tool }} -p x"])
        inputs = "".join(f"  b{n}: {{default: ''}}\n" for n in range(4)) + "  tool: {default: echo}\n"
        given = files(step(run), inputs=inputs)
        self.assertEqual(len(scope_errors(wf(job=JOB, with_="{tool: '${{ env.AGENT }}'}"), given)), 1)

    def test_a_handed_value_nested_more_deeply_than_the_reader_follows(self):
        run = "${{ " + "(inputs.z == 'q' || " * 10 + "inputs.tool" + ")" * 10 + " }} -p x"
        given = files(step(run), inputs="  tool: {default: echo}\n  z: {default: ''}\n")
        self.assertEqual(len(scope_errors(wf(job=JOB, with_="{tool: '${{ env.AGENT }}'}"), given)), 1)
        self.assertEqual(scope_errors(wf(job=JOB, with_="{tool: claude}"), given), [])


class TheReviewersFourthPassTest(unittest.TestCase):
    """What the fourth review of 2d.19e found (2026-11-27)."""

    def test_a_value_from_the_scope_in_an_argument_of_a_handed_command_is_a_known_false_error(self):
        """An input run as the command line that holds a value from the scope in an argument's place is read as
        giving that value whole, so it is an error of the file where the input stands where a command's program goes
        (D-145's known false errors). A version that read where in the value it stands was got past by the fifth
        review twice (a value that opens an expression with the action's own text, and readings of two expressions
        paired only by their order), so it was taken back. Where the caller's `env` settles the name, or the input
        stands elsewhere, there is no error."""
        given = files(step("${{ inputs.run }}"), inputs="  run: {required: true}\n")
        for command in ("npm test -- --shard=${{ env.SHARD }}", "${{ env.AGENT }} -p x", "npx ${{ env.AGENT }}"):
            with self.subTest(command=command):
                self.assertEqual(len(scope_errors(wf(job=JOB, with_="{run: '" + command + "'}"), given)), 1)
        self.assertEqual(scope_errors(wf(job=JOB, step="{SHARD: '1'}",
                                         with_="{run: 'npm test -- --shard=${{ env.SHARD }}'}"), given), [])
        echo = files(step("echo ${{ inputs.run }}"), inputs="  run: {required: true}\n")
        self.assertEqual(scope_errors(wf(job=JOB, with_="{run: 'npm test -- --shard=${{ env.SHARD }}'}"), echo), [])

    def test_the_fifth_reviews_ways_past_a_reading_of_where_a_value_stands(self):
        forged = files(step("# ${{ inputs.d }}{{ '\n${{ env.AGENT }} -p x\n# ' }}"), inputs="  d: {default: $}\n")
        self.assertEqual(len(scope_errors(wf(job=JOB), forged)), 1)
        paired = ("${{ env.Q1 == 'a' && format('echo {0};', env.X) || format('echo {0}', env.X) }} "
                  "${{ env.Q2 == 'a' && format('x {0}', env.Y) || env.Y }} --yes")
        self.assertEqual(len(scope_errors(wf(job=JOB), files(step(paired)))), 1)

    def test_inputs_no_step_reads_are_not_worked_out(self):
        import time
        big = " ".join(f"${{{{ env.X{n} || 'a' || 'b' || 'c' }}}}" for n in range(400))
        handed = "{" + ", ".join(f"i{n}: *big" for n in range(40)) + "}"
        text = 'x-big: &big "' + big + '"\n' + wf(job=JOB, with_=handed)
        started = time.monotonic()
        self.assertEqual(result(text, files(step("echo hi"))).errors, [])
        # About 1 s here; forty times the value's work took about 45 s at 1,300 expressions.
        self.assertLess(time.monotonic() - started, 20)


class TheReviewersSixthPassTest(unittest.TestCase):
    """What the sixth check of 2d.19e found (2026-11-27): a handed command line put in an argument's place."""

    def test_a_value_from_the_scope_after_a_separator_in_a_handed_value(self):
        echo = files(step("echo ${{ inputs.cmd }}"), inputs="  cmd: {default: x}\n")
        for command in ("make; ${{ env.AGENT }} -p review", "make && ${{ env.AGENT }} -p review",
                        "x $(${{ env.AGENT }} -p review)", "make | ${{ env.AGENT }}"):
            with self.subTest(command=command):
                (error,) = scope_errors(wf(job=JOB, with_="{cmd: '" + command + "'}"), echo)
                self.assertIn("where a command's program goes", error)
        default = files(step("echo ${{ inputs.cmd }}"), inputs="  cmd: {default: 'make; ${{ env.AGENT }} -p x'}\n")
        self.assertEqual(len(scope_errors(wf(job=JOB), default)), 1)
        self.assertEqual(scope_errors(wf(job=JOB, with_="{cmd: 'make ${{ env.TARGET }}'}"), echo), [])


if __name__ == "__main__":
    unittest.main()
