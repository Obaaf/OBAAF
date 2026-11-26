"""Flagship slice 2d.18 (#377): an agent named through the `env` a step runs with.

A step runs with its own `env` over its job's over its workflow's. Before this slice:

- the lanes (`Step.agent_text`, through `Step.env_put_in`) put only the step's own `env` into its command lines,
  so `run: $CLAUDE -p review` with `CLAUDE` set in the workflow's or the job's `env` put the job in no agent
  lane, and a job that held a model key got no OBAAF-GHA-005, 020 or any other agent rule;
- OBAAF-GHA-026 put the `env` values of the step, the job and the workflow into a script only where the
  script also had an `=` (a guard written for names a script sets itself, `a=cla; b=ude; $a$b`), so
  `$a$b --dangerously-skip-permissions` with `a: cla` and `b: ude` in any `env` got no finding;
- in a local composite action read for an agent (slice 2d.4a), only the using step's own `env` was put in.

Now the lanes put in the `env` the step runs with, nearest scope first; OBAAF-GHA-026 puts the plain `env`
values into any script with a `$`; and a local action read for an agent is given the `env` the step that uses
it runs with. What the step's own `env` sets outranks the job's, and the job's the workflow's, as GitHub's.
"""

import re
import time
import unittest
from unittest import mock

from helpers import TempDir
from test_egress_recognised import run_check
from test_local_composite_actions import ACTION_DIR, KEY, check, composite, lane_of

from obaaf import checker as checker_mod
from obaaf.checker import workflow as wf
from obaaf.checker.workflow import ENV_PUT_IN_UNREAD, Step
from obaaf.catalog import load as load_catalog

AGENTS = [re.compile(p, re.M) for p in load_catalog().detection["agent_commands"]]
UNREAD_ERROR = f"{ENV_PUT_IN_UNREAD}, so the checker cannot tell whether an agent runs in it"


def flow(run, top_env="", job_env="", step_env="", extra_steps="", uses=None):
    """A workflow of one job `a` holding a model key in its step's `env`. `top_env`, `job_env` and `step_env` are
    `env:` mappings written in flow style (`{a: cla}`), or empty."""
    step = f"      - uses: {uses}\n" if uses else f"      - run: {run}\n        shell: bash\n"
    env = f"          ANTHROPIC_API_KEY: {KEY}\n"
    if step_env:
        env += "".join(f"          {pair.strip()}\n" for pair in step_env.strip("{}").split(","))
    return ("on: workflow_dispatch\n" + (f"env: {top_env}\n" if top_env else "")
            + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: {contents: read}\n"
            + (f"    env: {job_env}\n" if job_env else "") + "    steps:\n" + extra_steps + step
            + "        env:\n" + env)


def rules_of(result, job="a"):
    return sorted({f.rule for f in result.findings if f.job == job and f.rule.startswith("OBAAF-GHA")})


class TheLanesTest(unittest.TestCase):
    """The job's and the workflow's `env` are put in for the lanes, under the step's own."""

    def lane(self, text, files=None):
        with TempDir() as tmp:
            rows, _notes = lane_of(tmp, text, files)
        return rows["a"][0]

    def test_the_issue_case_puts_the_job_in_the_agent_lane(self):
        self.assertEqual(self.lane(flow("$a$b --dangerously-skip-permissions -p review", job_env="{a: cla, b: ude}")),
                         "agent")

    def test_an_agent_named_in_the_workflows_env(self):
        text = flow('$CLAUDE -p "review"', top_env="{CLAUDE: npx @anthropic-ai/claude-code@1.0.0}")
        self.assertEqual(self.lane(text), "agent")

    def test_an_agent_named_in_the_jobs_env_in_braces(self):
        self.assertEqual(self.lane(flow("${AGENT} -p review", job_env="{AGENT: claude}")), "agent")

    def test_pieces_from_every_scope(self):
        text = flow("$a$b$c -p review", top_env="{a: cl}", job_env="{b: au}", step_env="{c: de}")
        self.assertEqual(self.lane(text), "agent")

    def test_the_steps_own_env_outranks_the_jobs(self):
        text = flow("$AGENT -p review", job_env="{AGENT: claude}", step_env="{AGENT: echo}")
        self.assertEqual(self.lane(text), "trusted")

    def test_the_jobs_env_outranks_the_workflows(self):
        text = flow("$AGENT -p review", top_env="{AGENT: claude}", job_env="{AGENT: echo}")
        self.assertEqual(self.lane(text), "trusted")
        text = flow("$AGENT -p review", top_env="{AGENT: echo}", job_env="{AGENT: claude}")
        self.assertEqual(self.lane(text), "agent")

    def test_a_name_no_scope_sets_is_left_as_written(self):
        self.assertEqual(self.lane(flow("$a$b -p review", job_env="{x: cla, y: ude}")), "trusted")

    def test_an_env_written_as_one_expression_adds_nothing_and_raises_nothing(self):
        text = flow("$a$b -p review", job_env="${{ fromJSON(vars.E) }}")
        self.assertEqual(self.lane(text), "trusted")

    def test_a_parallel_group_step(self):
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: {contents: read}\n"
                "    env: {a: cla, b: ude}\n    steps:\n      - parallel:\n          - run: $a$b -p review\n"
                "            shell: bash\n          - run: make test\n")
        self.assertEqual(self.lane(text), "agent")

    def test_every_agent_rule_applies(self):
        with TempDir() as tmp:
            result = check(tmp, flow("$a$b -p review", job_env="{a: cla, b: ude}"))
        self.assertIn("OBAAF-GHA-005", rules_of(result))
        self.assertIn("OBAAF-GHA-020", rules_of(result))

    def test_a_local_action_is_given_the_jobs_and_workflows_env(self):
        files = {f"{ACTION_DIR}/action.yml": composite("    - run: $a$b -p 'fix the bug'\n      shell: bash\n")}
        for top, job in (("", "{a: cla, b: ude}"), ("{a: cla, b: ude}", ""), ("{a: cla}", "{b: ude}")):
            with self.subTest(top=top, job=job):
                self.assertEqual(self.lane(flow("", top_env=top, job_env=job, uses=f"./{ACTION_DIR}"), files), "agent")

    def test_a_nested_local_action_is_given_the_jobs_env_too(self):
        inner = ".github/actions/inner"
        files = {f"{ACTION_DIR}/action.yml": composite(f"    - uses: ./{inner}\n"),
                 f"{inner}/action.yml": composite("    - run: $a$b -p 'fix the bug'\n      shell: bash\n")}
        self.assertEqual(self.lane(flow("", job_env="{a: cla, b: ude}", uses=f"./{ACTION_DIR}"), files), "agent")

    def test_jobs_whose_other_values_differ_share_one_reading_of_a_local_action(self):
        """A local action is read once for each set of values it is given (2d.4a). It is given only the job's and
        the workflow's names its files hold as words, so 100 jobs that differ in a value it does not name cost one
        reading, as before this slice; a value it names costs a reading for each job (stated in D-139)."""
        # 90 steps of 400 characters, used by 110 jobs: read again for each job, the readings cost more than the
        # check's units for local actions (an error, checked by giving the action every name).
        steps = "".join(f"    - run: ./scripts/part.sh {n} --retries 3 --cache ~/.cache/part-{n} "
                        + "--mirror https://mirror.example.com/toolchain " * 8 + "\n      shell: bash\n" for n in range(90))
        files = {f"{ACTION_DIR}/action.yml": composite(steps)}
        jobs = "".join(f"  j{n}:\n    runs-on: ubuntu-latest\n    permissions: {{contents: read}}\n"
                       f"    env: {{OTHER: value-{n}}}\n    steps:\n      - uses: ./{ACTION_DIR}\n" for n in range(110))
        with TempDir() as tmp:
            result = check(tmp, "on: workflow_dispatch\njobs:\n" + jobs, files)
        self.assertEqual(result.errors, [])
        with mock.patch.object(checker_mod, "_env_words", lambda raws: None), TempDir() as tmp:
            result = check(tmp, "on: workflow_dispatch\njobs:\n" + jobs, files)
        self.assertTrue(any("units" in error for error in result.errors), result.errors)

    def test_a_local_action_is_given_the_names_its_caller_hands_it(self):
        """From the second review: a script path handed in through `with:` (`$TOOLS/review.sh`) names a job's value
        the action's files never hold as a word."""
        files = {f"{ACTION_DIR}/action.yml": composite("    - run: bash ${{ inputs.script }}\n      shell: bash\n"),
                 "ci/review.sh": "#!/bin/bash\nclaude --dangerously-skip-permissions -p review\n"}
        text = flow("", job_env="{TOOLS: ./ci}", uses=f"./{ACTION_DIR}").replace(
            "        env:\n", "        with: {script: $TOOLS/review.sh}\n        env:\n", 1)
        self.assertEqual(self.lane(text, files), "agent")

    def test_a_local_action_names_a_value_in_any_letter_case_and_with_a_hyphen(self):
        """From the second review: the reader folds an `env` name's case and keeps `-` in `env['MY-TOOL']`."""
        for job_env, run in (("{CLAUDE: claude}", "${{ env.claude }}"), ("{MY-TOOL: claude}", "${{ env['MY-TOOL'] }}")):
            with self.subTest(run=run):
                files = {f"{ACTION_DIR}/action.yml": composite(f"    - run: {run} -p review\n      shell: bash\n")}
                self.assertEqual(self.lane(flow("", job_env=job_env, uses=f"./{ACTION_DIR}"), files), "agent")

    def test_readings_an_inputs_default_makes_do_not_pass_a_steps_bound(self):
        """From the second review: four `${{ inputs.x || 'default' }}` make 16 readings of the step, each holding
        `$PROMPT` once; with a 13 KB prompt in the job's `env` that passed D-137's bound for one reading, an error.
        The bound is as many times as wide as the readings."""
        run = ("./summarize --model ${{ inputs.model || 'small' }} --lang ${{ inputs.lang || 'en' }} "
               "--fmt ${{ inputs.fmt || 'md' }} --out ${{ inputs.out || 'out.md' }} --prompt \"$PROMPT\"")
        action = ("name: sum\ninputs:\n  model: {description: m}\n  lang: {description: l}\n  fmt: {description: f}\n"
                  "  out: {description: o}\nruns:\n  using: composite\n  steps:\n"
                  f"    - shell: bash\n      run: {run}\n")
        prompt = "Review the change and report problems. " * 340
        for scope in ("job_env", "step_env"):
            with self.subTest(scope=scope), TempDir() as tmp:
                text = flow("", uses=f"./{ACTION_DIR}", **{scope: "{PROMPT: '" + prompt + "'}"})
                result = check(tmp, text, {f"{ACTION_DIR}/action.yml": action})
                self.assertEqual(result.errors, [])

    def test_in_a_local_action_the_using_steps_env_outranks_the_jobs(self):
        files = {f"{ACTION_DIR}/action.yml": composite("    - run: $AGENT -p 'fix the bug'\n      shell: bash\n")}
        text = flow("", job_env="{AGENT: claude}", step_env="{AGENT: echo}", uses=f"./{ACTION_DIR}")
        self.assertEqual(self.lane(text, files), "trusted")

    def test_a_step_read_on_its_own_inherits_nothing(self):
        step = Step(index=0, raw={"run": "$a$b -p x"}, line=1)
        self.assertEqual(step.env_put_in(), "$a$b -p x")
        self.assertNotIn("claude", step.agent_text(AGENTS))


class TheStepsEnvTest(unittest.TestCase):
    """`Step.run_env`: what the step runs with, as the workflow writes it."""

    def steps(self, text):
        return wf.parse(".github/workflows/w.yml", text).jobs["a"].steps

    def test_nearest_first_text_only(self):
        (step,) = self.steps(flow("echo", top_env="{A: 1, B: w, C: w}", job_env="{B: j, C: j}", step_env="{C: s}"))
        env = step.run_env
        self.assertEqual((env["B"], env["C"]), ("j", "s"))
        self.assertEqual(env["ANTHROPIC_API_KEY"], KEY)
        self.assertNotIn("A", env)      # a number is not text: as before, it is not put in


class TheOptionsTest(unittest.TestCase):
    """OBAAF-GHA-026 reads a name made from `env` values in a script with no `=`."""

    def findings(self, text):
        result = run_check(text, config={})
        return [f for f in result.findings if f.rule == "OBAAF-GHA-026"]

    def test_the_issue_case(self):
        (finding,) = self.findings(flow("$a$b --dangerously-skip-permissions -p review", job_env="{a: cla, b: ude}"))
        self.assertEqual(finding.severity, "high")

    def test_from_the_workflows_and_the_steps_env(self):
        for scope in ("top_env", "step_env"):
            with self.subTest(scope=scope):
                text = flow("$a$b --dangerously-skip-permissions -p review", **{scope: "{a: cla, b: ude}"})
                (finding,) = self.findings(text)
                self.assertEqual(finding.severity, "high")

    def test_braces(self):
        (finding,) = self.findings(flow("${a}${b} --dangerously-skip-permissions -p x", job_env="{a: cla, b: ude}"))
        self.assertEqual(finding.severity, "high")

    def test_no_tool_no_finding(self):
        self.assertEqual(self.findings(flow("$a$b --dangerously-skip-permissions", job_env="{a: ec, b: ho}")), [])


class TheBoundTest(unittest.TestCase):
    """A job's or a workflow's value is put in under D-137's and D-138's bounds, as a step's own is."""

    def test_a_jobs_value_put_in_past_a_steps_bound_is_an_error_of_the_file(self):
        long = "ab " * 20_000
        run = "echo " + " ".join(["$P"] * 20)
        with TempDir() as tmp:
            result = check(tmp, flow(run, job_env="{P: '" + long + "'}"))
        self.assertTrue(any(UNREAD_ERROR in error for error in result.errors), result.errors)

    def test_a_workflow_value_used_once_in_many_steps_costs_little(self):
        value = "ab " * 3_000
        steps = "".join(f"      - run: echo $P step{n}\n        shell: bash\n" for n in range(300))
        text = ("on: workflow_dispatch\nenv: {P: '" + value + "'}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    permissions: {contents: read}\n    steps:\n" + steps)
        with TempDir() as tmp:
            started = time.process_time()
            result = check(tmp, text)
            spent = time.process_time() - started
        self.assertEqual(result.errors, [])
        self.assertLess(spent, 30)


if __name__ == "__main__":
    unittest.main()
