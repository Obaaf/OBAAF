"""Flagship slice 2d.16 (#372): a step's env values put into its command lines are read only up to a bound.

`Step.agent_text` reads a step's command lines with the step's `env` values put in (`run: $AGENT -p x` with
`env: {AGENT: claude}` runs claude). Nothing bounded that text: a `run` of 2,000 `$P` with a 2,000-character
`P` (6 KB of YAML) was read as 4,000,000 characters, six times in one check, and the text grew with the
square of the file. OBAAF-GHA-026's reading (`agent_flags._substitute` and `put_in_cheaply`) made the same
text, with the job's and the workflow's `env` and the script's own assignments too: 48 KB of YAML was read
as 256,000,000 characters.

Now each text is made only while the values put in, counted each time one is put in, come to no more than
every value counted once and `ENV_PUT_IN_EXTRA` characters more, so a value put in once is always read,
whatever its length. Past the bound:

- a workflow's step is an error of its file, which fails the check: the checker cannot tell whether an
  agent runs in it;
- a local action's step is named as not read, in the words `_expand_variables` uses for the same;
- the egress control (OBAAF-GHA-020) and `key-out-of-reach` (OBAAF-GHA-005) are "cannot tell" for such a
  step before or beside the agent;
- OBAAF-GHA-026 is "cannot tell" where the step names the tool, or where the tool's name may be made by the
  values the checker could not put in.

Within the bound nothing changes: `SameAsBeforeTest` compares `agent_text` with the reading it replaces.
"""

import random
import re
import time
import unittest

from helpers import TempDir, run_cli
from test_egress_recognised import (CANNOT_TELL, CHECKOUT, VERIFIED, detail, egress, keyed, run_check, secret_control,
                                    verdict, workflow)
from test_local_composite_actions import ACTION_DIR, check, composite, job_using, lane_of

from obaaf.checker import agent_flags
from obaaf.checker import workflow as wf
from obaaf.checker.workflow import (ENV_PUT_IN_EXTRA, ENV_PUT_IN_UNREAD, Step, _first_word_forms, _readings,
                                    command_segments, matches_any)
from obaaf.catalog import load as load_catalog

AGENTS = [re.compile(p, re.M) for p in load_catalog().detection["agent_commands"]]
UNREAD_ERROR = f"{ENV_PUT_IN_UNREAD}, so the checker cannot tell whether an agent runs in it"
# The step as the error names it: `job 'a', step 'step 1': ...`.


def step(run, env=None, **raw):
    given = {"run": run, **raw}
    if env is not None:
        given["env"] = env
    return Step(index=0, raw=given, line=1)


def repeated(n, length=1000, before="echo"):
    """A `run` that puts a `length`-character `P` in `n` times, and its env."""
    return before + " " + " ".join(["$P"] * n), {"P": "a" * length}


def job(run, env_lines, permissions="contents: read", job_env=""):
    return ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions:\n"
            f"      {permissions}\n{job_env}    steps:\n      - run: {run}\n        shell: bash\n"
            + (f"        env:\n{env_lines}" if env_lines else ""))


def env_lines(env):
    return "".join(f"          {name}: {value}\n" for name, value in env.items())


class TheBoundTest(unittest.TestCase):
    """`Step.env_put_in`: what is put in, and where it stops."""

    def test_a_value_put_in_once_is_read_whatever_its_length(self):
        long = "a" * (3 * ENV_PUT_IN_EXTRA)
        s = step('$A -p "$P" --dangerously-skip-permissions', {"A": "claude", "P": long})
        self.assertEqual(s.env_put_in(), f'claude -p "{long}" --dangerously-skip-permissions')
        self.assertFalse(s.env_put_in_unread)

    def test_a_name_the_env_does_not_give_is_left_as_written(self):
        self.assertEqual(step("$X ${A} $A_B", {"A": "claude"}).env_put_in(), "$X claude $A_B")
        self.assertEqual(step("$X ${Y}", {"A": "claude"}).env_put_in(), "$X ${Y}")
        self.assertEqual(step("claude -p x", {"A": "b"}).env_put_in(), "claude -p x")
        self.assertEqual(step("$A -p x").env_put_in(), "$A -p x")

    def test_the_bound_is_every_value_once_and_the_extra(self):
        # A value of 1,000 characters may be put in 1 + ENV_PUT_IN_EXTRA / 1,000 times, and not once more.
        times = 1 + ENV_PUT_IN_EXTRA // 1000
        run, env = repeated(times)
        self.assertEqual(len(step(run, env).env_put_in()), len("echo") + times * 1001)
        run, env = repeated(times + 1)
        self.assertIsNone(step(run, env).env_put_in())
        self.assertTrue(step(run, env).env_put_in_unread)
        # Every value counts once, whether or not it is put in.
        run, env = repeated(times + 1)
        env["UNUSED"] = "b" * 1000
        self.assertIsNotNone(step(run, env).env_put_in())

    def test_a_value_that_is_not_text_is_not_put_in(self):
        self.assertEqual(step("$A -p x", {"A": 1, 2: "claude"}).env_put_in(), "$A -p x")

    def test_what_is_read_is_every_command_line_agent_text_reads(self):
        """The script, a github-script script and the command OBAAF's egress action runs, as before."""
        script = Step(index=0, raw={"uses": "actions/github-script@v7", "with": {"script": "$A -p x"},
                                    "env": {"A": "claude"}}, line=1)
        self.assertIn("claude -p x", script.env_put_in())
        egress = Step(index=0, raw={"uses": wf.EGRESS_ACTION + "@" + "c" * 40, "with": {"run": "$A -p x"},
                                    "env": {"A": "claude"}}, line=1)
        self.assertIn("claude -p x", egress.env_put_in())

    def test_agent_text_finds_an_agent_named_through_a_variable_within_the_bound(self):
        for run in ("$A -p x", "${A} -p x", "sudo $A -p x", "$A --print x", "echo hi; $A -p x"):
            with self.subTest(run=run):
                self.assertTrue(matches_any(AGENTS, step(run, {"A": "claude"}).agent_text(AGENTS)))
        # And its options: the text the agent rules read holds them.
        text = step("$A -p x $F", {"A": "claude", "F": "--dangerously-skip-permissions"}).agent_text(AGENTS)
        self.assertIn("claude -p x --dangerously-skip-permissions", text)

    def test_agent_text_does_not_read_past_the_bound(self):
        run, env = repeated(1 + ENV_PUT_IN_EXTRA // 1000 + 1, before="$A -p x")
        env["A"] = "claude"
        s = step(run, env)
        self.assertTrue(s.env_put_in_unread)
        self.assertNotIn("claude", s.agent_text(AGENTS))
        self.assertLess(len(s.agent_text(AGENTS)), 10 * len(run))

    def test_making_the_text_past_the_bound_costs_no_more_than_the_bound(self):
        """16,000 `$P` of 16,000 characters would be 256,000,000 characters: the reading stops at the bound."""
        run, env = repeated(16000, 16000)
        s = step(run, env)
        started = time.monotonic()
        for _ in range(20):
            self.assertTrue(s.env_put_in_unread)
            s.agent_text(AGENTS)
        self.assertLess(time.monotonic() - started, 3)


class AWorkflowStepPastTheBoundTest(unittest.TestCase):
    """A workflow's step past the bound fails the check, and the check stays quick."""

    def check(self, text):
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, text)
            return result, time.monotonic() - started

    def test_it_is_an_error_of_its_file(self):
        run, env = repeated(200, before="$A -p x")
        env["A"] = "claude"
        result, _ = self.check(job(run, env_lines(env)))
        self.assertEqual([e for e in result.errors if "put into the command lines" in e],
                         [f".github/workflows/wf.yml: job 'a', step 'step 1': {UNREAD_ERROR}"])

    def test_the_command_fails(self):
        run, env = repeated(200)
        with TempDir() as tmp:
            root = tmp / "repo"
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "wf.yml").write_text(job(run, env_lines(env)), encoding="utf-8")
            code, out, err = run_cli("check", root)
        self.assertEqual(code, 1, out + err)
        self.assertIn("cannot tell whether an agent runs in it", out + err)

    def test_a_step_in_a_parallel_group_too(self):
        run, env = repeated(200)
        text = ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: {contents: read}\n"
                "    steps:\n      - parallel:\n          - run: make\n          - run: " + run + "\n"
                "            env: {P: " + env["P"] + "}\n")
        result, _ = self.check(text)
        self.assertIn(f".github/workflows/wf.yml: job 'a', step 'step 2': {UNREAD_ERROR}", result.errors)

    def test_a_value_a_caller_hands_is_counted(self):
        """A called workflow's `inputs` are put in after the file is read (slice 2d.4b3a), so the bound is
        checked after they are: a short `${{ inputs.p }}` that a caller fills with 1,000 characters."""
        called = ("on:\n  workflow_call:\n    inputs:\n      p: {type: string}\njobs:\n  c:\n    runs-on: ubuntu-latest\n"
                  "    permissions: {contents: read}\n    steps:\n      - run: echo " + "$P " * 200 + "\n"
                  "        env: {P: '${{ inputs.p }}'}\n")
        caller = ("on: push\njobs:\n  a:\n    permissions: {contents: read}\n    uses: ./.github/workflows/called.yml\n"
                  "    with: {p: " + "a" * 1000 + "}\n")
        with TempDir() as tmp:
            result = check(tmp, caller, {".github/workflows/called.yml": called})
        self.assertIn(f".github/workflows/called.yml: job 'c', step 'step 1': {UNREAD_ERROR}", result.errors)
        with TempDir() as tmp:
            alone = check(tmp, caller.replace("a" * 1000, "a"), {".github/workflows/called.yml": called})
        self.assertEqual([e for e in alone.errors if "put into the command lines" in e], [])

    def test_within_the_bound_the_agent_is_found_and_nothing_is_reported(self):
        result, _ = self.check(job("$A -p x", env_lines({"A": "claude"})))
        self.assertEqual(result.errors, [])
        with TempDir() as tmp:
            lanes, _notes = lane_of(tmp, job("$A -p x", env_lines({"A": "claude"})))
        self.assertEqual(lanes["a"][0], "agent")

    def test_a_long_prompt_and_an_option_after_it_are_read(self):
        """The case F-373 names: truncating each value would lose the option after the prompt."""
        text = job('$A -p "$P" --dangerously-skip-permissions', env_lines({"A": "claude", "P": "a" * 150_000}))
        result, _ = self.check(text)
        self.assertEqual(result.errors, [])
        options = [f for f in result.findings if f.rule == "OBAAF-GHA-026"]
        self.assertEqual([(f.kind, f.severity) for f in options], [("command-option", "high")])
        with TempDir() as tmp:
            lanes, _notes = lane_of(tmp, text)
        self.assertEqual(lanes["a"][0], "agent")

    def test_a_command_line_held_in_one_value_is_still_read(self):
        """`CMD: 'claude -p "<3,000 characters>" --dangerously-skip-permissions'` and `run: $CMD`: one value,
        put in once, so read whole; its quotes make it a value OBAAF-GHA-026 cannot read, so "cannot tell"."""
        value = "'claude -p \"" + "a" * 3000 + "\" --dangerously-skip-permissions'"
        text = job("$CMD", env_lines({"CMD": value}))
        result, _ = self.check(text)
        self.assertEqual(result.errors, [])
        with TempDir() as tmp:
            lanes, _notes = lane_of(tmp, text)
        self.assertEqual(lanes["a"][0], "agent")
        self.assertTrue(any(f.rule == "OBAAF-GHA-026" for f in result.findings))

    def test_the_check_is_quick_past_the_bound(self):
        """Before, the first of these took 6 s at 4,000 by 4,000 and grew with the square of the file."""
        for before in ("echo", "$A -p x", "claude -p"):
            run, env = repeated(16000, 16000, before=before)
            env["A"] = "claude"
            result, took = self.check(job(run, env_lines(env)))
            with self.subTest(before=before):
                self.assertLess(took, 3)
                self.assertIn(f".github/workflows/wf.yml: job 'a', step 'step 1': {UNREAD_ERROR}", result.errors)

    def test_obaaf_gha_026_is_cannot_tell_where_the_step_names_the_tool(self):
        run, env = repeated(16000, 16000, before="claude -p")
        result, _ = self.check(job(run, env_lines(env)))
        (option,) = [f for f in result.findings if f.rule == "OBAAF-GHA-026"]
        self.assertEqual(option.kind, "command-computed")
        self.assertTrue(any(agent_flags.PUT_IN_UNREAD in w for w in option.facts["words"]), option.facts)


class AStepOfALocalActionTest(unittest.TestCase):
    """In a local action, a step past the bound is named as not read, as `_expand_variables` names it."""

    def test_it_is_named_and_is_not_an_error(self):
        # 150 `$P` of 1,000 characters: under `_expand_variables`' 200,000, past `env_put_in`'s 101,000.
        run, env = repeated(150, before="$A -p x")
        body = composite(f"    - run: {run}\n      shell: bash\n      env:\n        A: claude\n        P: {env['P']}\n")
        with TempDir() as tmp:
            result = check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": body})
        self.assertEqual([e for e in result.errors if "put into" in e], [])
        self.assertTrue(any("step 1: its environment, put into a script, makes a text longer than the checker reads"
                            in n for n in result.notes), result.notes)

    def test_within_the_bound_the_agent_is_found(self):
        body = composite("    - run: $A -p x\n      shell: bash\n      env:\n        A: claude\n")
        with TempDir() as tmp:
            lanes, notes = lane_of(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": body})
        self.assertEqual(lanes["a"][0], "agent")


class TheEgressControlTest(unittest.TestCase):
    """A step before the agent that the checker could not read put in leaves both egress controls at
    "cannot tell", and says why. (Any `run` step in the job already leaves them at "cannot tell", for the
    artifact uploads it may make, decision D-133; the reason here holds whatever becomes of that one.)"""

    def steps(self, times):
        run, env = repeated(times)
        before = f"      - run: {run}\n        env: {{P: {env['P']}}}\n"
        return CHECKOUT + "\n" + before + keyed()

    def test_past_the_bound_both_are_cannot_tell(self):
        result = run_check(workflow(self.steps(200)))
        f, key = egress(result), secret_control(result)
        self.assertEqual(verdict(f), CANNOT_TELL, detail(f))
        self.assertIn(ENV_PUT_IN_UNREAD, detail(f))
        self.assertIn("outside the confined command", detail(f))
        self.assertEqual(key.verdict, CANNOT_TELL, key.detail)
        self.assertIn(ENV_PUT_IN_UNREAD, key.detail)
        self.assertTrue(any(UNREAD_ERROR in e for e in result.errors), result.errors)

    def test_within_the_bound_neither_gives_that_reason(self):
        result = run_check(workflow(self.steps(2)))
        self.assertNotIn(ENV_PUT_IN_UNREAD, detail(egress(result)))
        self.assertNotIn(ENV_PUT_IN_UNREAD, secret_control(result).detail)
        self.assertEqual(result.errors, [])

    def test_without_the_step_both_are_verified(self):
        result = run_check(workflow(CHECKOUT + "\n" + keyed()))
        self.assertEqual(verdict(egress(result)), VERIFIED, detail(egress(result)))
        self.assertEqual(secret_control(result).verdict, VERIFIED, secret_control(result).detail)


class OBAAFGHA026ReadingTest(unittest.TestCase):
    """OBAAF-GHA-026's own put-in (`agent_flags`) stops at the same bound."""

    def test_substitute_stops_at_the_bound(self):
        times = 1 + ENV_PUT_IN_EXTRA // 1000
        values = {"P": "a" * 1000}
        self.assertEqual(len(agent_flags._substitute("x " + "$P " * times, values)), 2 + times * 1001)
        self.assertIsNone(agent_flags._substitute("x " + "$P " * (times + 1), values))
        # Inside single quotes nothing is put in, so nothing is counted.
        self.assertIsNotNone(agent_flags._substitute("x '" + "$P " * (times + 1) + "'", values))
        commands, problem = agent_flags._lex("claude " + "$P " * (times + 1), values)
        self.assertEqual(problem, agent_flags.PUT_IN_UNREAD)
        self.assertTrue(commands)

    def test_put_in_cheaply_stops_at_the_bound(self):
        times = 1 + ENV_PUT_IN_EXTRA // 1000
        scopes = [{"P": "a" * 1000}, {}, {}]
        self.assertIsNotNone(agent_flags.put_in_cheaply("x=1 " + "$P " * times, scopes))
        self.assertIsNone(agent_flags.put_in_cheaply("x=1 " + "$P " * (times + 1), scopes))

    def test_a_name_made_from_values_past_the_bound_is_cannot_tell(self):
        """`a=cla; b=ude; $a$b ...` was read as claude through the cheap put-in; past the bound the checker
        cannot tell, so it says so rather than reading nothing."""
        def text(times):
            run = "a=cla; b=ude; $a$b --dangerously-skip-permissions; echo " + "$P " * times
            return job(run, "", job_env="    env:\n      P: " + "a" * 1000 + "\n")

        with TempDir() as tmp:
            within = check(tmp, text(2))
        with TempDir() as tmp:
            past = check(tmp, text(200))
        self.assertEqual([f.kind for f in within.findings if f.rule == "OBAAF-GHA-026"], ["command-option"])
        self.assertEqual([f.kind for f in past.findings if f.rule == "OBAAF-GHA-026"], ["command-computed"])
        self.assertIn("claude", [f for f in past.findings if f.rule == "OBAAF-GHA-026"][0].message)

    def test_values_past_the_bound_that_make_no_name_give_nothing(self):
        """Only a tool whose name the values may make is read: `x=1; echo $P ...` names none."""
        for job_env in ("", "    env:\n      P: " + "a" * 1000 + "\n"):
            run = "x=1; echo " + "$P " * 200
            text = job(run, "" if job_env else env_lines({"P": "a" * 1000}), job_env=job_env)
            with TempDir() as tmp:
                result = check(tmp, text)
            with self.subTest(job_env=bool(job_env)):
                self.assertEqual([f for f in result.findings if f.rule == "OBAAF-GHA-026"], [])

    def test_names_when_put_in_is_the_reading_it_stands_for(self):
        """On 3,000 generated scripts within the bound, `names_when_put_in` answers as `appears` does on the
        text `put_in_cheaply` makes, except where bash's `$'...'` could be made, where it answers yes."""
        rng = random.Random(2161)
        words = ["$a", "${b}", "$c", "cla", "ude", "CL", "aUDE", "'", '"', "\\", "$'", "x=1", "a=cla", "b=ude",
                 "c=\"de\"", "c='$'", "echo", ";", "claude", "@anthropic-ai/claude-code", "-p", "q" * 70, ""]
        env_values = ["cla", "ude", "Claude", "x" * 80, "c" * 61 + "la", "ude" + "u" * 70, "1", "a b", ""]
        programs, packages = ["claude"], ["@anthropic-ai/claude-code"]
        for n in range(3000):
            text = "".join(rng.choice(words) + rng.choice(["", " "]) for _ in range(rng.randint(1, 14)))
            scopes = [{name: rng.choice(env_values) for name in "abc" if rng.random() < 0.5}, {}, {}]
            put = agent_flags.put_in_cheaply(text, scopes)
            self.assertIsNotNone(put)
            got = agent_flags.names_when_put_in(text, scopes, programs, packages)
            values = agent_flags._cheap_values(text, scopes)
            used = [values[m.group(1)] for m in agent_flags._CHEAP_NAME_RE.finditer(text) if m.group(1) in values]
            wide = "$'" in text or any(ch in v for v in used for ch in "$'\\")
            with self.subTest(n=n, text=text, scopes=scopes):
                if wide:
                    self.assertTrue(got)
                else:
                    self.assertEqual(got, agent_flags.appears(put, programs, packages))


def _old_agent_text(s: Step, commands) -> str:
    """`Step.agent_text` as it was before flagship slice 2d.16, for the comparison below."""
    own = s._command_text()
    found: list[str] = []
    lines: list = []
    if s.uses and s.uses.strip().lower().startswith("docker://"):
        entry, args = s.with_.get("entrypoint"), s.with_.get("args")
        lines.append(" ".join(v for v in (entry, args) if isinstance(v, str)))
    elif s.uses and not s.confines:
        for name, given in s.with_.items():
            if isinstance(given, str) and not (name == "script" and s.uses_action("actions/github-script")):
                lines.append(given)
    shell = s.raw.get("shell")
    if isinstance(shell, str):
        lines.append(shell)
    lines.extend(v for v in s.env.values() if isinstance(v, str))
    for value in lines:
        for variant in _readings(value):
            if any(matches_any(commands, candidate, anchored=True) for segment in command_segments(variant)
                   for candidate in wf._first_word_forms(segment)):
                found.append(variant)
                break
    env = {k: v for k, v in s.env.items() if isinstance(k, str) and isinstance(v, str)}
    if env and own and "$" in own:
        put = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: env.get(m.group(1), m.group(0)), own)
        if put != own:
            for variant in _readings(put):
                if any(matches_any(commands, candidate, anchored=True) for segment in command_segments(variant)
                       for candidate in _first_word_forms(segment)):
                    found.append(variant)
                    break
    text = "\n".join(p for p in [own, *found] if p)
    return "\n".join(dict.fromkeys(v for v in _readings(text) if v))


class SameAsBeforeTest(unittest.TestCase):
    """Within the bound, `agent_text` gives what it gave before, on 2,000 generated steps."""

    WORDS = ["$A", "${A}", "$B", "${B}", "$C", "$A_B", "$1", "-p", "x", '"$A"', "'$A'", "sudo", "npx", "echo", ";",
             "&&", "|", "\\\n", "bash -c", "$(", ")", "--print", "#", "cl$B", "$Aude"]
    VALUES = ["claude", "cla", "ude", "sudo claude", "claude -p x", "-p", "--dangerously-skip-permissions",
              "codex exec", "@anthropic-ai/claude-code", "prose about claude", "", "a; claude -p y", "x" * 300]

    def test_the_same_text(self):
        rng = random.Random(2016)
        kinds = ["run", "script", "egress", "docker", "other"]
        for n in range(2000):
            run = " ".join(rng.choice(self.WORDS) for _ in range(rng.randint(1, 12)))
            env = {name: rng.choice(self.VALUES) for name in ("A", "B", "C") if rng.random() < 0.6}
            kind = rng.choice(kinds)
            if kind == "run":
                raw = {"run": run}
            elif kind == "script":
                raw = {"uses": "actions/github-script@v7", "with": {"script": run}}
            elif kind == "egress":
                raw = {"uses": wf.EGRESS_ACTION + "@" + "c" * 40, "with": {"run": run, "allow": "x.example"}}
            elif kind == "docker":
                raw = {"uses": "docker://alpine", "with": {"entrypoint": rng.choice(self.VALUES), "args": run}}
            else:
                raw = {"uses": "some/action@v1", "with": {"command": run}}
            if env:
                raw["env"] = env
            s = Step(index=0, raw=raw, line=1)
            with self.subTest(n=n, raw=raw):
                self.assertFalse(s.env_put_in_unread)
                self.assertEqual(s.agent_text(AGENTS), _old_agent_text(s, AGENTS))


if __name__ == "__main__":
    unittest.main()
