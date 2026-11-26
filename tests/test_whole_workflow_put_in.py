"""Flagship slice 2d.17 (#376): what putting variables in makes is bounded for a whole workflow.

Slice 2d.16 bounds one step's reading: each value may be put in eight times, and the times past the eighth may
add up to 100,000 characters. It did not bound the total across steps. A value given once and reached by many
steps (one YAML value aliased into many steps' `env`, which `Step.agent_text` reads; the job's or the
workflow's `env`, which OBAAF-GHA-026 reads) was put in again in each step, up to eight times each: 100 KB of
YAML read as 80,000,000 characters, 13 to 20 s, and 42 s for a workflow-level value in 20 steps.

Now the same rule holds for the whole workflow, for each reader apart (`PutIns`): each value, counted by its
text, may be put in eight times in the workflow whatever its length, and the times past that may add up to
`ENV_PUT_IN_WORKFLOW` characters. Each reading is counted once (`PutInLedger.settle`), and `Step.env_put_in`
keeps what it made on the workflow's ledger, so a step read again (about six times in a check) is not made or
read again. Past the bound the reading fails closed: an error of the file for the lanes, "cannot tell" for
OBAAF-GHA-026.
"""

import json
import random
import re
import time
import unittest
from dataclasses import replace

from helpers import TempDir, run_cli
from test_egress_recognised import CANNOT_TELL, CHECKOUT, detail, egress, keyed, run_check, secret_control, verdict, workflow
from test_local_composite_actions import ACTION_DIR, check, composite, job_using, lane_of

from obaaf.checker import agent_flags
from obaaf.checker import workflow as wf
from obaaf.checker.workflow import (ENV_PUT_IN_EXTRA, ENV_PUT_IN_TIMES, ENV_PUT_IN_UNREAD, ENV_PUT_IN_WORKFLOW,
                                    ENV_PUT_IN_WORKFLOW_UNREAD, PutInBudget, PutInLedger, PutIns, Step)
from obaaf.catalog import load as load_catalog

AGENTS = [re.compile(p, re.M) for p in load_catalog().detection["agent_commands"]]
WORKFLOW_ERROR = f"{ENV_PUT_IN_WORKFLOW_UNREAD}, so the checker cannot tell whether an agent runs in it"
# A value as long as this, with spaces in it, is read as many words, which is what costs (2d.16's numbers).
LONG = "ab " * 33_333


def head(env=""):
    return ("on: workflow_dispatch\n" + env + "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    permissions: {contents: read}\n    steps:\n")


def aliased(steps, times, before="echo", value=LONG, apart=True):
    """`steps` steps whose `env` gives one value through a YAML alias, each putting it in `times` times; each
    step's script differs from the others' when `apart`."""
    text = head()
    for n in range(steps):
        anchor = f"&p {value}" if n == 0 else "*p"
        tail = f" step{n}" if apart else ""
        text += (f"      - run: {before} " + " ".join(["$P"] * times) + f"{tail}\n        shell: bash\n"
                 f"        env:\n          P: {anchor}\n")
    return text


def workflow_level(steps, times, before="claude -p x", value=LONG, after=""):
    """`steps` steps that each put the workflow's `W` in `times` times."""
    text = head(f"env:\n  W: {value}\n")
    for n in range(steps):
        text += (f"      - run: {before} " + " ".join(['"$W"' if after else "$W"] * times) + f" {after}{n}\n"
                 "        shell: bash\n")
    return text


def timed(tmp, text, files=None):
    started = time.monotonic()
    result = check(tmp, text, files)
    return result, time.monotonic() - started


def put_in_errors(result):
    return [e for e in result.errors if "put into the command lines" in e]


class TheLedgerTest(unittest.TestCase):
    """`PutInLedger.settle`: the workflow's rule is a step's rule, with each reading counted once."""

    def test_eight_times_free_then_the_room(self):
        ledger, value = PutInLedger(), "x" * 1000
        self.assertTrue(ledger.settle("a", {value: ENV_PUT_IN_TIMES}))
        self.assertEqual(ledger.room, ENV_PUT_IN_WORKFLOW)
        fits = ENV_PUT_IN_WORKFLOW // 1000
        self.assertTrue(all(ledger.settle(("b", n), {value: 1}) for n in range(fits)))
        self.assertEqual(ledger.room, 0)
        self.assertFalse(ledger.settle("c", {value: 1}))

    def test_a_reading_is_counted_once(self):
        ledger, value = PutInLedger(), "x" * 1000
        for _ in range(100):
            self.assertTrue(ledger.settle("same", {value: ENV_PUT_IN_TIMES + 10}))
        self.assertEqual(ledger.room, ENV_PUT_IN_WORKFLOW - 10 * 1000)

    def test_a_refused_reading_takes_nothing(self):
        ledger, small, big = PutInLedger(), "s" * 10, "b" * (ENV_PUT_IN_WORKFLOW + 1)
        self.assertFalse(ledger.settle("big", {big: ENV_PUT_IN_TIMES + 1}))
        self.assertEqual(ledger.room, ENV_PUT_IN_WORKFLOW)
        self.assertFalse(ledger.settle("big", {}))          # its answer stays the same
        self.assertTrue(ledger.settle("small", {small: 100}))

    def test_equal_values_are_one_value(self):
        """A value is counted by its text: equal values written apart, or a script's own `P=...` read again in
        another step (a new string each time), are one value."""
        ledger = PutInLedger()
        one, other = "x" * 999 + "y", "".join(["x" * 999, "y"])
        self.assertIsNot(one, other)
        self.assertTrue(ledger.settle(1, {one: ENV_PUT_IN_TIMES}))
        self.assertTrue(ledger.settle(2, {other: 1}))
        self.assertEqual(ledger.room, ENV_PUT_IN_WORKFLOW - 1000)

    def test_the_ledgers_are_apart_and_number_the_steps(self):
        put_ins = PutIns()
        self.assertIsNot(put_ins.lanes, put_ins.options)
        self.assertIsNot(put_ins.options, put_ins.names)
        self.assertEqual([put_ins.number() for _ in range(3)], [1, 2, 3])


class TheLanesAcrossStepsTest(unittest.TestCase):
    """`Step.env_put_in` (the lanes, the agent rules and the egress controls) across a workflow's steps."""

    def test_one_value_aliased_into_many_steps_is_bounded(self):
        """The case measured by 2d.16's reviewer, with each step's script its own: 100 steps that each put one
        100 KB value in eight times took 19 s on `2454e7c` here, with no error."""
        with TempDir() as tmp:
            result, took = timed(tmp, aliased(100, 8))
        self.assertLess(took, 8)
        errors = put_in_errors(result)
        self.assertEqual(errors[0], f".github/workflows/wf.yml: job 'a', step 'step 4': {WORKFLOW_ERROR}")
        self.assertEqual(len(errors), 97)        # 8 free, then 2,000,000 characters: three more steps of 800,000
        self.assertTrue(all(ENV_PUT_IN_WORKFLOW_UNREAD in e for e in errors))

    def test_the_command_fails(self):
        with TempDir() as tmp:
            root = tmp / "repo"
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "wf.yml").write_text(aliased(30, 8), encoding="utf-8")
            code, out, err = run_cli("check", root)
        self.assertEqual(code, 1, out + err)
        self.assertIn("in the workflow, and those times come to more than 2,000,000 characters", out + err)

    def test_the_same_step_aliased_is_read_once_and_is_no_error(self):
        """100 steps with the same script and the same value are one reading: nothing is made again, so
        nothing passes the bound, and the check is quick (19.7 s on `2454e7c`)."""
        with TempDir() as tmp:
            result, took = timed(tmp, aliased(100, 8, apart=False))
        self.assertLess(took, 8)
        self.assertEqual(put_in_errors(result), [])

    def test_a_value_used_once_in_a_few_dozen_steps_is_read(self):
        """A 40 KB value aliased into 48 steps' `env`, each using it once: 40 times past the eighth, 1,600,000
        characters, within the bound."""
        with TempDir() as tmp:
            result, _took = timed(tmp, aliased(48, 1, value="q " * 20_000))
        self.assertEqual(put_in_errors(result), [])

    def test_an_agent_named_through_a_variable_is_found_in_every_step_within_the_bound(self):
        text = head()
        for n in range(40):
            text += f"      - run: $A -p x{n}\n        env:\n          A: claude\n"
        with TempDir() as tmp:
            lanes, _notes = lane_of(tmp, text)
            result = check(tmp, text)
        self.assertEqual(lanes["a"][0], "agent")
        self.assertEqual(result.errors, [])

    def test_an_agent_hidden_past_the_bound_is_an_error(self):
        """The agent is named through a variable in a step after the workflow's bound is spent: the step is an
        error, as past a step's own bound, so the agent cannot go unseen."""
        text = aliased(4, 8) + "      - run: $A -p x $P $P $P $P $P\n        env:\n          A: claude\n          P: *p\n"
        with TempDir() as tmp:
            result = check(tmp, text)
        self.assertIn(f".github/workflows/wf.yml: job 'a', step 'step 5': {WORKFLOW_ERROR}", result.errors)

    def test_a_step_read_again_is_not_made_again(self):
        """`agent_text` reads an agent job's steps about six times in a check: the text is made, counted and
        searched for an agent once (`command_segments` is where 2d.16's reviewer's 13 s went)."""
        w = wf.parse("wf.yml", aliased(1, 8, before="$A -p"))
        (step,) = w.jobs["a"].steps
        step.raw["env"]["A"] = "claude"
        calls = []
        original = wf.command_segments

        def counting(text):
            calls.append(len(text))
            return original(text)

        wf.command_segments = counting
        try:
            texts = {step.agent_text(AGENTS) for _ in range(6)}
        finally:
            wf.command_segments = original
        self.assertEqual(len(texts), 1)
        made = [n for n in calls if n > 8 * len(LONG)]
        self.assertEqual(len(made), 1, calls)
        self.assertEqual(len(w.put_ins.lanes.settled), 1)

    def test_a_value_changed_after_reading_is_a_new_text(self):
        """D-084 puts a caller's values into a called workflow and, past its bound, puts them back as written:
        the ledger keys a text by the values' ids, so a step whose value changed is read with the new one."""
        w = wf.parse("wf.yml", head() + "      - run: $A -p x\n        env:\n          A: echo\n")
        (step,) = w.jobs["a"].steps
        self.assertEqual(step.env_put_in(), "echo -p x")
        step.raw["env"]["A"] = "".join(["cla", "ude"])
        self.assertEqual(step.env_put_in(), "claude -p x")
        self.assertIn("claude -p x", step.agent_text(AGENTS))

    def test_a_copy_of_a_step_shares_its_workflow_s_ledger(self):
        """The second pass through local actions reads copies of the steps (`dataclasses.replace`): they keep
        the ledger and the number, so they are not counted again."""
        w = wf.parse("wf.yml", aliased(3, 8))
        before = w.put_ins.lanes.room
        for step in w.jobs["a"].steps:
            step.env_put_in()
        spent = w.put_ins.lanes.room
        self.assertLess(spent, before)
        for step in w.jobs["a"].steps:
            copy = replace(step, index=step.index + 10)
            self.assertIs(copy.put_ins, w.put_ins)
            self.assertEqual(copy.seq, step.seq)
            copy.env_put_in()
        self.assertEqual(w.put_ins.lanes.room, spent)

    def test_a_step_read_on_its_own_has_only_its_own_bound(self):
        """A `Step` made outside a workflow (in a test, or by another tool) keeps 2d.16's reading."""
        long = "a" * (3 * ENV_PUT_IN_EXTRA)
        s = Step(index=0, raw={"run": " ".join(["$P"] * ENV_PUT_IN_TIMES), "env": {"P": long}}, line=1)
        self.assertIsNone(s.put_ins)
        self.assertIsNotNone(s.env_put_in())
        self.assertIsNone(s.env_put_in_why)

    def test_the_step_s_own_bound_says_so(self):
        w = wf.parse("wf.yml", head() + "      - run: echo " + "$P " * 200 + "\n        env:\n          P: "
                     + "a" * 1000 + "\n")
        (step,) = w.jobs["a"].steps
        self.assertEqual(step.env_put_in_why, ENV_PUT_IN_UNREAD)

    def test_each_workflow_has_its_own_ledger(self):
        """The bound is for one workflow: two files that each spend most of it are both read."""
        text = aliased(3, 8)
        with TempDir() as tmp:
            result = check(tmp, text, {".github/workflows/other.yml": text})
        self.assertEqual(put_in_errors(result), [])


class ALocalActionAcrossStepsTest(unittest.TestCase):
    """The steps of local actions: read for an agent (2d.4a) on one ledger for the check, and as the job's own
    steps (2d.4b2) on the workflow's."""

    def action(self, steps, times=8):
        body = "name: x\nruns:\n  using: composite\n  steps:\n"
        for n in range(steps):
            anchor = f"&p {LONG}" if n == 0 else "*p"
            body += (f"    - run: echo " + " ".join(["$P"] * times) + f" step{n}\n      shell: bash\n"
                     f"      env:\n        P: {anchor}\n")
        return body

    def test_an_action_whose_steps_pass_the_bound_is_an_error(self):
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": self.action(60)})
            took = time.monotonic() - started
        self.assertLess(took, 8)
        self.assertEqual(put_in_errors(result),
                         [f".github/workflows/wf.yml: job 'a' uses the local action ./{ACTION_DIR}, and in its step 4 "
                          f"{WORKFLOW_ERROR}"])

    def test_an_action_within_the_bound_is_no_error(self):
        with TempDir() as tmp:
            result = check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": self.action(3)})
        self.assertEqual(put_in_errors(result), [])

    def test_the_action_s_agent_is_found_within_the_bound(self):
        body = composite("    - run: $A -p x\n      shell: bash\n      env:\n        A: claude\n")
        with TempDir() as tmp:
            lanes, _notes = lane_of(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": body})
        self.assertEqual(lanes["a"][0], "agent")


class TheEgressControlAcrossStepsTest(unittest.TestCase):
    """A step before the agent that the workflow's bound left unread leaves both egress controls at "cannot
    tell", and says which bound."""

    def test_past_the_workflow_s_bound_both_are_cannot_tell(self):
        before = ""
        for n in range(5):
            anchor = f"&p {LONG}" if n == 0 else "*p"
            before += "      - run: echo " + "$P " * 8 + f"step{n}\n        env: {{P: {anchor}}}\n"
        result = run_check(workflow(CHECKOUT + "\n" + before + keyed()))
        f, key = egress(result), secret_control(result)
        self.assertEqual(verdict(f), CANNOT_TELL, detail(f))
        self.assertIn(ENV_PUT_IN_WORKFLOW_UNREAD, detail(f))
        self.assertEqual(key.verdict, CANNOT_TELL, key.detail)
        self.assertIn(ENV_PUT_IN_WORKFLOW_UNREAD, key.detail)


class OBAAFGHA026AcrossStepsTest(unittest.TestCase):
    """OBAAF-GHA-026's put-ins (`agent_flags._substitute` and `put_in_cheaply`) across a workflow's steps."""

    def gha026(self, result):
        return [f for f in result.findings if f.rule == "OBAAF-GHA-026"]

    def test_a_workflow_level_value_in_many_steps_is_bounded(self):
        """The issue's case: 20 steps that each put a 100 KB workflow-level `W` in eight times took 42 s on
        #375's head (21.6 s on `2454e7c` here). The first steps are read; the rest are "cannot tell"."""
        with TempDir() as tmp:
            result, took = timed(tmp, workflow_level(20, 8))
        self.assertLess(took, 12)
        found = self.gha026(result)
        self.assertEqual({f.kind for f in found}, {"command-computed"})
        unread = [f for f in found if any(agent_flags.PUT_IN_UNREAD in w for w in f.facts["words"])]
        self.assertEqual(len(unread), 17)
        self.assertEqual(result.errors, [])          # the lanes do not read the workflow's `env`

    def test_a_long_workflow_level_prompt_used_once_by_a_few_dozen_steps_is_read(self):
        """The first case #376 says must pass: a 40 KB prompt, used once by each of 48 steps, with a warned
        option after it, which is found in every step."""
        text = workflow_level(48, 1, before="claude -p", value="q " * 20_000, after="--dangerously-skip-permissions --model m")
        with TempDir() as tmp:
            result, took = timed(tmp, text)
        self.assertLess(took, 8)
        kinds = [f.kind for f in self.gha026(result)]
        self.assertEqual(kinds, ["command-option"] * 48)
        self.assertEqual(result.errors, [])

    def test_the_second_pass_through_local_actions_counts_nothing_again(self):
        """Where a job uses a local action, every rule reads the workflow again on a copy: its steps keep their
        numbers, so the prompt above, read twice, is counted once and still read in every step."""
        text = workflow_level(48, 1, before="claude -p", value="q " * 20_000, after="--dangerously-skip-permissions --model m")
        text += f"      - uses: ./{ACTION_DIR}\n"
        body = composite("    - run: echo hello\n      shell: bash\n")
        with TempDir() as tmp:
            result = check(tmp, text, {f"{ACTION_DIR}/action.yml": body})
        kinds = [f.kind for f in self.gha026(result)]
        self.assertEqual(kinds, ["command-option"] * 48)

    def test_a_name_made_past_the_bound_is_cannot_tell(self):
        """`put_in_cheaply` past the workflow's bound: whether the values make the tool's name is decided without
        the text, so a step that makes `claude` from `a=cla; b=ude` is still read as naming it."""
        text = head(f"env:\n  W: {LONG}\n")
        for n in range(20):
            text += ("      - run: a=cla; b=ude; $a$b -p x " + " ".join(["$W"] * 8) + f" step{n}\n"
                     "        shell: bash\n")
        with TempDir() as tmp:
            result, took = timed(tmp, text)
        self.assertLess(took, 12)
        unread = {f.step for f in self.gha026(result)
                  if f.kind == "command-computed" and any(agent_flags.PUT_IN_UNREAD in w for w in f.facts["words"])}
        self.assertEqual(unread, {f"step {n}" for n in range(4, 21)})

    def test_the_twenty_callers_case_is_read(self):
        """The second case #376 says must pass (from #375's tests): 20 callers each hand a 2.9 KB prompt that a
        called workflow uses three times; its warned option is found and nothing is an error."""
        called = ("on:\n  workflow_call:\n    inputs:\n      prompt: {type: string}\njobs:\n  c:\n"
                  "    runs-on: ubuntu-latest\n    permissions: {contents: read}\n    steps:\n      - run: |\n"
                  "          echo \"$PROMPT\" > prompt.txt\n          echo \"$PROMPT\" >> \"$GITHUB_STEP_SUMMARY\"\n"
                  "          claude -p \"$PROMPT\" --dangerously-skip-permissions\n"
                  "        env: {PROMPT: '${{ inputs.prompt }}'}\n")
        jobs = "".join(f"  j{n}:\n    permissions: {{contents: read}}\n    uses: ./.github/workflows/called.yml\n"
                       f"    with: {{prompt: {'p' * 2900}{n}}}\n" for n in range(20))
        with TempDir() as tmp:
            result = check(tmp, "on: push\njobs:\n" + jobs, {".github/workflows/called.yml": called})
        self.assertEqual(put_in_errors(result), [])
        self.assertIn("command-option", [f.kind for f in self.gha026(result) if f.job == "c"])

    def test_substitute_settles_on_the_ledger(self):
        ledger = PutInLedger()
        value = "a" * 1000
        fits = ENV_PUT_IN_TIMES + ENV_PUT_IN_WORKFLOW // 1000
        budget = PutInBudget(ledger, 1)
        self.assertIsNotNone(agent_flags._substitute("$P " * 8, {"P": value}, budget))
        # The same reading again (another tool's, or the second pass) adds nothing.
        self.assertIsNotNone(agent_flags._substitute("$P " * 8, {"P": value}, PutInBudget(ledger, 1)))
        self.assertEqual(ledger.room, ENV_PUT_IN_WORKFLOW)
        # Other steps' readings of the same value spend the room, eight at a time within each step's own bound.
        spent = 8
        place = 2
        while spent + 8 <= fits:
            self.assertIsNotNone(agent_flags._substitute("$P " * 8, {"P": value}, PutInBudget(ledger, place)))
            spent, place = spent + 8, place + 1
        self.assertIsNone(agent_flags._substitute("$P " * 8, {"P": value}, PutInBudget(ledger, place)))
        self.assertIsNone(agent_flags.put_in_cheaply("$P " * 8, [{"P": value}], ledger, place))

    def test_put_in_cheaply_settles_on_its_own_ledger(self):
        put_ins = PutIns()
        value = "a" * 1000
        for place in range(1, 1 + (ENV_PUT_IN_WORKFLOW // 1000) // 8 + 1):
            agent_flags.put_in_cheaply("x=1; $P " * 8, [{"P": value}], put_ins.names, place)
        self.assertIsNone(agent_flags.put_in_cheaply("x=1; $P " * 8, [{"P": value}], put_ins.names, 10_000))
        self.assertEqual(put_ins.options.room, ENV_PUT_IN_WORKFLOW)


class SameAsBeforeTest(unittest.TestCase):
    """Within the bound, a step of a workflow reads as a step on its own: on 1,000 generated workflows, every
    step's `env_put_in` and `agent_text` is the same with the workflow's ledger as without it, and so is
    OBAAF-GHA-026's `_substitute`."""

    WORDS = ["$A", "${A}", "$B", "$C", "-p", "x", '"$A"', "'$A'", "sudo", "npx", "echo", ";", "&&", "|", "bash -c",
             "cl$B", "$Aude", "$A$B"]
    VALUES = ["claude", "cla", "ude", "claude -p x", "-p", "--dangerously-skip-permissions", "codex exec", "",
              "prose about claude", "x" * 300, "y " * 2000]

    def test_the_same_reading(self):
        rng = random.Random(2017)
        for n in range(1000):
            shared = {name: rng.choice(self.VALUES) for name in ("A", "B", "C")}
            text = head()
            for k in range(rng.randint(1, 6)):
                run = " ".join(rng.choice(self.WORDS) for _ in range(rng.randint(1, 10)))
                env = "".join(f"          {name}: '{shared[name]}'\n" for name in shared if rng.random() < 0.7)
                text += f"      - run: {json.dumps(run)}\n" + (f"        env:\n{env}" if env else "")
            w = wf.parse("wf.yml", text)
            for step in (s for job in w.jobs.values() for s in job.steps):
                alone = replace(step, put_ins=None)
                with self.subTest(n=n, run=step.run):
                    self.assertEqual(step.env_put_in(), alone.env_put_in())
                    self.assertEqual(step.agent_text(AGENTS), alone.agent_text(AGENTS))
                    variables = {k: v for k, v in step.env.items() if isinstance(v, str)}
                    self.assertEqual(agent_flags._substitute(step.run, variables, PutInBudget(w.put_ins.options, step.seq)),
                                     agent_flags._substitute(step.run, variables))


if __name__ == "__main__":
    unittest.main()
