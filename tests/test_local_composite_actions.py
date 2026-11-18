"""Flagship slice 2d.4a: an agent inside a local composite action.

Before this slice, a job whose agent ran inside an action of its own repository (`uses:
./.github/actions/run-agent`, or `$/...`) was in no lane for agents, so a job with `contents: write`
and `id-token: write` got neither OBAAF-GHA-003 nor 004, and one holding a model key got no
OBAAF-GHA-005 and no OBAAF-GHA-020 (docs/bypass-attempts.md, slice 2d.2b). Now the checker reads the
action's `action.yml` or `action.yaml`: a composite action's steps are read as a job's steps are for
an agent, through further local actions and the repository scripts they run. A local action the
checker cannot read through is named in a note, never passed over in silence.
"""

import unittest

from helpers import TempDir
from test_egress_recognised import CHECKOUT, action, run_check, workflow

from obaaf import checker
from obaaf.checker.rules import NOT_MET

SHA = "1111111111111111111111111111111111111111"
KEY = "${{ secrets.ANTHROPIC_API_KEY }}"
AGENT_RULES = ["OBAAF-GHA-003", "OBAAF-GHA-004", "OBAAF-GHA-005", "OBAAF-GHA-020"]
CLI = "    - run: claude -p 'fix the bug'\n      shell: bash\n"
AGENT_ACTION = f"    - uses: anthropics/claude-code-action@{SHA}\n"
PLAIN = "    - run: make test\n      shell: bash\n"


def build(tmp, workflow_text, files=None, name="wf.yml"):
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows" / name).write_text(workflow_text, encoding="utf-8")
    for rel, body in (files or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def check(tmp, workflow_text, files=None):
    return checker.check(build(tmp, workflow_text, files))


def agent_rules(result, job="a"):
    return sorted({f.rule for f in result.findings if f.job == job and f.rule in AGENT_RULES})


def job_using(uses, env=True, extra_steps=""):
    env_text = f"    env:\n      ANTHROPIC_API_KEY: {KEY}\n" if env else ""
    return ("on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      contents: write\n      id-token: write\n"
            f"{env_text}    steps:\n"
            f"      - uses: actions/checkout@{SHA}\n        with:\n          persist-credentials: false\n"
            f"      - uses: {uses}\n{extra_steps}")


def composite(*steps, name="x"):
    return f"name: {name}\nruns:\n  using: composite\n  steps:\n" + "".join(steps)


def lane_of(tmp, workflow_text, files=None):
    notes: list = []
    rows = checker.lanes(build(tmp, workflow_text, files), notes=notes, errors=[], seen=[])
    return {job: (lane, reason) for _, job, lane, reason in rows}, notes


ACTION_DIR = ".github/actions/run-agent"


class AnAgentInALocalActionMakesAnAgentJobTest(unittest.TestCase):
    """The way past OBAAF-GHA-003, 004 and 005 that slice 2d.2b recorded, and its neighbours."""

    def test_an_agent_cli_in_a_composite_step_gets_every_agent_rule(self):
        with TempDir() as tmp:
            result = check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": composite(CLI)})
            self.assertEqual(agent_rules(result), AGENT_RULES)
            (write,) = [f for f in result.findings if f.rule == "OBAAF-GHA-003"]
            self.assertIn(f"of the local action ./{ACTION_DIR}", write.message)
            self.assertEqual(result.notes, [])

    def test_the_forms_an_agent_takes_inside_the_action(self):
        cases = {
            "an agent action": composite(AGENT_ACTION),
            "a CLI behind a wrapper": composite("    - run: sudo -u runner npx @anthropic-ai/claude-code -p x\n"
                                                "      shell: bash\n"),
            "a CLI given to another action": composite(f"    - uses: some/runner@{SHA}\n      with:\n"
                                                       "        command: codex exec 'fix it'\n"),
            "the step's shell": composite("    - run: fix the bug\n      shell: claude -p {0}\n"),
            "after a plain step": composite(PLAIN, CLI),
            "action.yaml": None,
        }
        for label, body in cases.items():
            with self.subTest(label), TempDir() as tmp:
                files = ({f"{ACTION_DIR}/action.yaml": composite(CLI)} if body is None
                         else {f"{ACTION_DIR}/action.yml": body})
                self.assertEqual(agent_rules(check(tmp, job_using(f"./{ACTION_DIR}"), files)), AGENT_RULES)

    def test_the_ways_to_name_the_action(self):
        for uses in (f"./{ACTION_DIR}", f"./{ACTION_DIR}/", f"$/{ACTION_DIR}", f"./.github/./actions/run-agent",
                     f"./.github/actions/other/../run-agent"):
            with self.subTest(uses=uses), TempDir() as tmp:
                result = check(tmp, job_using(uses), {f"{ACTION_DIR}/action.yml": composite(CLI)})
                self.assertEqual(agent_rules(result), AGENT_RULES)

    def test_an_action_at_the_repository_root(self):
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, job_using("./"), {"action.yml": composite(CLI)})), AGENT_RULES)

    def test_through_another_local_action(self):
        inner = ".github/actions/inner"
        files = {f"{ACTION_DIR}/action.yml": composite(PLAIN, f"    - uses: ./{inner}\n"),
                 f"{inner}/action.yml": composite(AGENT_ACTION)}
        with TempDir() as tmp:
            result = check(tmp, job_using(f"./{ACTION_DIR}"), files)
            self.assertEqual(agent_rules(result), AGENT_RULES)
            (write,) = [f for f in result.findings if f.rule == "OBAAF-GHA-003"]
            self.assertIn(f"in the local action ./{inner}", write.message)

    def test_through_a_script_the_action_runs(self):
        script = "#!/bin/sh\nclaude -p 'fix it'\n"
        for run, path in (("${{ github.action_path }}/agent.sh", f"{ACTION_DIR}/agent.sh"),
                          ("bash ${{github.action_path}}/agent.sh", f"{ACTION_DIR}/agent.sh"),
                          ("$GITHUB_ACTION_PATH/agent.sh", f"{ACTION_DIR}/agent.sh"),
                          ("./scripts/agent.sh", "scripts/agent.sh")):
            with self.subTest(run=run), TempDir() as tmp:
                files = {f"{ACTION_DIR}/action.yml": composite(f"    - run: {run}\n      shell: bash\n"), path: script}
                self.assertEqual(agent_rules(check(tmp, job_using(f"./{ACTION_DIR}"), files)), AGENT_RULES)

    def test_both_metadata_files_are_read(self):
        """Which of action.yml and action.yaml GitHub takes when both are there is not established, so
        an agent in either counts."""
        for agent_in in ("action.yml", "action.yaml"):
            other = "action.yaml" if agent_in == "action.yml" else "action.yml"
            with self.subTest(agent_in=agent_in), TempDir() as tmp:
                files = {f"{ACTION_DIR}/{agent_in}": composite(CLI), f"{ACTION_DIR}/{other}": composite(PLAIN)}
                self.assertEqual(agent_rules(check(tmp, job_using(f"./{ACTION_DIR}"), files)), AGENT_RULES)

    def test_inputs_are_put_in(self):
        """`run: ${{ inputs.tool }} -p x`: the tool from the step's `with:`, or the action's default."""
        uses_tool = composite("    - run: ${{ inputs.tool }} -p \"$PROMPT\"\n      shell: bash\n")
        with_default = ("name: x\ninputs:\n  tool:\n    default: claude\n" + uses_tool.split("\n", 1)[1])
        given = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        with:\n          TOOL: claude\n"
        bracket = composite("    - run: ${{inputs['tool']}} -p x\n      shell: bash\n")
        via_env = composite("    - run: $T -p x\n      shell: bash\n      env:\n        T: ${{ inputs.tool }}\n")
        for label, text, body in (("given", given, uses_tool), ("default", job_using(f"./{ACTION_DIR}"), with_default),
                                  ("bracket", given, bracket), ("through env", given, via_env)):
            with self.subTest(label), TempDir() as tmp:
                result = check(tmp, text, {f"{ACTION_DIR}/action.yml": body})
                self.assertEqual(agent_rules(result), AGENT_RULES)

    def test_inputs_are_put_in_through_another_local_action(self):
        inner = ".github/actions/inner"
        files = {f"{ACTION_DIR}/action.yml": composite(f"    - uses: ./{inner}\n      with:\n        tool: codex\n"),
                 f"{inner}/action.yml": composite("    - run: ${{ inputs.tool }} exec 'fix it'\n      shell: bash\n")}
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, job_using(f"./{ACTION_DIR}"), files)), AGENT_RULES)

    def test_a_declaration_cannot_take_the_job_out_of_the_agent_lane(self):
        text = job_using(f"./{ACTION_DIR}").replace("    env:\n", "    env:\n      OBAAF_LANE: trusted\n")
        with TempDir() as tmp:
            result = check(tmp, text, {f"{ACTION_DIR}/action.yml": composite(CLI)})
            self.assertEqual(agent_rules(result), AGENT_RULES)

    def test_lanes_says_the_same(self):
        with TempDir() as tmp:
            lanes, notes = lane_of(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": composite(CLI)})
            self.assertEqual(lanes["a"][0], "agent")
            self.assertIn(f"local action ./{ACTION_DIR}", lanes["a"][1])
            self.assertEqual(notes, [])


class NoAgentNoChangeTest(unittest.TestCase):
    """A local action with no agent in it changes nothing, as on the first adopter's five."""

    def test_a_composite_action_without_an_agent(self):
        body = composite(f"    - uses: actions/cache/restore@{SHA}\n      with:\n        path: x\n        key: k\n",
                         "    - run: sudo apt-get install -y libfoo\n      shell: bash\n",
                         "    - run: echo 'runs claude later' > notes.txt\n      shell: bash\n")
        with TempDir() as tmp:
            result = check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": body})
            self.assertEqual(agent_rules(result), [])
            self.assertEqual(result.notes[1:], [])
            self.assertFalse(any("Local actions" in note for note in result.notes))

    def test_an_input_the_job_gives_is_still_read(self):
        """`with: {cmd: claude -p x}` to a local action was found before this slice, by the step's inputs."""
        body = composite("    - run: ${{ inputs.cmd }}\n      shell: bash\n")
        text = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        with:\n          cmd: claude -p 'fix'\n"
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, text, {f"{ACTION_DIR}/action.yml": body})), AGENT_RULES)


class WhatIsNotReadIsNamedTest(unittest.TestCase):
    """A local action the checker cannot read through is in a note, which names the file, the job, the
    action as written and why. It is not a finding: whether such an action runs an agent is not known."""

    def note_for(self, files, uses=f"./{ACTION_DIR}"):
        with TempDir() as tmp:
            result = check(tmp, job_using(uses), files)
            self.assertEqual(agent_rules(result), [])
            notes = [n for n in result.notes if n.startswith("Local actions were not read through")]
            self.assertEqual(len(notes), 1, result.notes)
            self.assertIn(".github/workflows/wf.yml job 'a'", notes[0])
            self.assertIn("OBAAF_LANE: agent", notes[0])
            return notes[0]

    def test_each_reason(self):
        cases = {
            "missing": ({}, "no action.yml or action.yaml"),
            "JavaScript": ({f"{ACTION_DIR}/action.yml": "runs:\n  using: node24\n  main: index.js\n"},
                           "a JavaScript action"),
            "Docker": ({f"{ACTION_DIR}/action.yml": "runs:\n  using: docker\n  image: Dockerfile\n"},
                       "a Docker action"),
            "no runs": ({f"{ACTION_DIR}/action.yml": "name: x\n"}, "`runs.using`"),
            "using not text": ({f"{ACTION_DIR}/action.yml": "runs:\n  using: [composite]\n  steps: []\n"},
                               "`runs.using`"),
            "steps not a list": ({f"{ACTION_DIR}/action.yml": "runs:\n  using: composite\n  steps: x\n"},
                                 "not a list"),
            "a step not a mapping": ({f"{ACTION_DIR}/action.yml": "runs:\n  using: composite\n  steps: [x]\n"},
                                     "step 1 is not a mapping"),
            "an input nested too deeply to work out": (
                {f"{ACTION_DIR}/action.yml": composite("    - run: ${{ " + "(" * 65 + "inputs.tool" + ")" * 65
                                                       + " }} -p x\n      shell: bash\n")}, "nested more deeply"),
        }
        for label, (files, why) in cases.items():
            with self.subTest(label):
                self.assertIn(why, self.note_for(files))

    def test_an_action_file_the_checker_cannot_read_is_an_error(self):
        """As a workflow file the checker cannot read is: the action's author writes it as freely."""
        cases = {
            "not YAML": ("runs: [\n", "cannot parse YAML"),
            "duplicate keys": ("runs:\n  using: composite\n  using: node24\n", "cannot parse YAML"),
            "a list": ("- runs\n", "not an action"),
            "a tag": ("runs: !!binary aGk=\n", "does not read"),
            "a disputed break": ("name: a\u2028b\nruns:\n  using: composite\n  steps: []\n", "line break"),
            "too large": (composite(PLAIN) + "#" * 1_000_001 + "\n", "larger than the checker reads"),
        }
        for label, (body, why) in cases.items():
            with self.subTest(label), TempDir() as tmp:
                result = check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": body})
                self.assertEqual(len(result.errors), 1, result.errors)
                self.assertIn(why, result.errors[0])
                self.assertIn("cannot tell whether an agent runs in it", result.errors[0])
                self.assertIn(f"job 'a' uses the local action ./{ACTION_DIR}", result.errors[0])

    def test_paths_outside_the_repository(self):
        for uses, why in (("./../elsewhere", "leads outside the repository"),
                          ("./.github/../../elsewhere", "leads outside the repository"),
                          ("./${{ inputs.where }}", "holds an expression")):
            with self.subTest(uses=uses):
                self.assertIn(why, self.note_for({}, uses=uses))

    def test_a_link_out_of_the_repository(self):
        with TempDir() as tmp:
            outside = tmp / "outside"
            outside.mkdir()
            (outside / "action.yml").write_text(composite(CLI), encoding="utf-8")
            root = build(tmp, job_using(f"./{ACTION_DIR}"))
            (root / ACTION_DIR).parent.mkdir(parents=True, exist_ok=True)
            (root / ACTION_DIR).symlink_to(outside, target_is_directory=True)
            result = checker.check(root)
            self.assertEqual(agent_rules(result), [])
            self.assertTrue(any("leads outside the repository" in n for n in result.notes), result.notes)

    def test_an_unread_action_inside_a_read_one(self):
        files = {f"{ACTION_DIR}/action.yml": composite(PLAIN, "    - uses: ./.github/actions/js\n"),
                 ".github/actions/js/action.yml": "runs:\n  using: node24\n  main: index.js\n"}
        note = self.note_for(files)
        self.assertIn("./.github/actions/js", note)
        self.assertIn("JavaScript", note)

    def test_a_cycle_ends_and_is_named(self):
        files = {f"{ACTION_DIR}/action.yml": composite(PLAIN, "    - uses: ./.github/actions/b\n"),
                 ".github/actions/b/action.yml": composite(PLAIN, f"    - uses: ./{ACTION_DIR}\n")}
        self.assertIn("comes back to itself", self.note_for(files))

    def test_a_chain_too_deep_ends_and_is_named(self):
        files = {f".github/actions/a{n}/action.yml": composite(PLAIN, f"    - uses: ./.github/actions/a{n + 1}\n")
                 for n in range(12)}
        files[".github/actions/a12/action.yml"] = composite(CLI)
        self.assertIn("more than 10 local actions", self.note_for(files, uses="./.github/actions/a0"))

    def test_an_agent_found_beside_an_unread_action_still_counts(self):
        files = {f"{ACTION_DIR}/action.yml": composite("    - uses: ./.github/actions/missing\n", CLI)}
        with TempDir() as tmp:
            result = check(tmp, job_using(f"./{ACTION_DIR}"), files)
            self.assertEqual(agent_rules(result), AGENT_RULES)
            self.assertTrue(any("./.github/actions/missing" in n for n in result.notes), result.notes)

    def test_a_file_checked_on_its_own(self):
        with TempDir() as tmp:
            root = build(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": composite(CLI)})
            result = checker.check(root / ".github" / "workflows" / "wf.yml")
            self.assertEqual(agent_rules(result), [])
            self.assertTrue(any("checked on its own" in n for n in result.notes), result.notes)

    def test_the_note_lists_five_and_counts_the_rest(self):
        steps = "".join(f"      - uses: ./.github/actions/m{n}\n" for n in range(7))
        with TempDir() as tmp:
            result = check(tmp, job_using(f"./{ACTION_DIR}", extra_steps=steps))
            (note,) = [n for n in result.notes if n.startswith("Local actions")]
            self.assertIn("in 8 place(s)", note)
            self.assertIn("and 3 more", note)

    def test_lanes_names_them_too(self):
        with TempDir() as tmp:
            lanes, notes = lane_of(tmp, job_using(f"./{ACTION_DIR}"))
            self.assertNotEqual(lanes["a"][0], "agent")
            self.assertTrue(any(n.startswith("Local actions") for n in notes), notes)


class ManyUsesCostOneReadingTest(unittest.TestCase):

    def test_an_action_used_many_times_through_others_is_read_once(self):
        """Ten levels, each using the next twenty times, would be 20**10 readings without the cache."""
        files = {f".github/actions/a{n}/action.yml": composite(*[f"    - uses: ./.github/actions/a{n + 1}\n"] * 20)
                 for n in range(9)}
        files[".github/actions/a9/action.yml"] = composite(CLI)
        with TempDir() as tmp:
            result = check(tmp, job_using("./.github/actions/a0"), files)
            self.assertEqual(agent_rules(result), AGENT_RULES)


    def test_many_uses_with_different_inputs_stop_at_a_bound(self):
        """Ten levels, each using the next twenty times and passing on its own input changed, would be 20**10
        readings: the check stops at its bound and names what it did not read."""
        files = {f".github/actions/a{n}/action.yml": composite(
            *[f"    - uses: ./.github/actions/a{n + 1}\n      with:\n        n: '${{{{ inputs.n }}}}{k}'\n"
              for k in range(20)])
            for n in range(9)}
        files[".github/actions/a9/action.yml"] = composite(PLAIN)
        with TempDir() as tmp:
            result = check(tmp, job_using("./.github/actions/a0"), files)
            self.assertEqual(len(result.errors), 1, result.errors)
            self.assertIn("units the check spends on them", result.errors[0])


class TheReviewersWaysPastTest(unittest.TestCase):
    """The ways past the first version of this slice that its reviewer found (2026-11-18), one test
    for each class."""

    def two_workflows(self, tmp, files, first, second):
        root = build(tmp, first, files, name="a.yml")
        (root / ".github" / "workflows" / "b.yml").write_text(second, encoding="utf-8")
        return checker.check(root)

    def test_a_reading_cut_short_elsewhere_is_not_kept(self):
        """A reading cut short by a cycle or by the depth in one workflow was kept and given to a job of
        another workflow, where neither applied."""
        cycle = {".github/actions/X/action.yml": composite(CLI, "    - uses: ./.github/actions/Y\n      if: false\n"),
                 ".github/actions/Y/action.yml": composite("    - uses: ./.github/actions/X\n")}
        chain = {f".github/actions/a{n}/action.yml": composite(PLAIN, f"    - uses: ./.github/actions/a{n + 1}\n")
                 for n in range(10)}
        chain[".github/actions/a10/action.yml"] = composite(CLI)
        for label, files, deep, shallow in (("cycle", cycle, "./.github/actions/X", "./.github/actions/Y"),
                                            ("depth", chain, "./.github/actions/a0", "./.github/actions/a9")):
            with self.subTest(label), TempDir() as tmp:
                second = job_using(shallow).replace("  a:", "  second:")
                result = self.two_workflows(tmp, files, job_using(deep), second)
                self.assertEqual(agent_rules(result, job="second"), AGENT_RULES)

    def test_an_at_sign_and_a_backslash_in_the_path(self):
        """Whether GitHub takes what follows `@` as part of the path, or a backslash as a separator, is
        not established: each reading is read, and an agent in any counts."""
        cases = {
            "x@main is a folder": ("./.github/actions/x@main", {".github/actions/x/action.yml": composite(PLAIN),
                                                               ".github/actions/x@main/action.yml": composite(CLI)}),
            "x@v1/../y": ("./.github/actions/x@v1/../y", {".github/actions/x/action.yml": composite(PLAIN),
                                                          ".github/actions/x@v1/README": "x\n",
                                                          ".github/actions/y/action.yml": composite(CLI)}),
            "x@ only": ("./.github/actions/x@", {".github/actions/x/action.yml": composite(CLI)}),
            ".\\ on Windows": (".\\.github\\actions\\x", {".github/actions/x/action.yml": composite(CLI)}),
            "space around": (" ./.github/actions/x ", {".github/actions/x/action.yml": composite(CLI)}),
        }
        for label, (uses, files) in cases.items():
            with self.subTest(label), TempDir() as tmp:
                text = job_using(f"'{uses}'")
                self.assertEqual(agent_rules(check(tmp, text, files)), AGENT_RULES)

    def test_the_action_path_in_other_spellings(self):
        script = {f"{ACTION_DIR}/agent.sh": "#!/bin/sh\nclaude -p 'fix it'\n"}
        for step in ("    - run: ${{ GITHUB.ACTION_PATH }}/agent.sh\n      shell: bash\n",
                     "    - run: ${{ github['action_path'] }}/agent.sh\n      shell: bash\n",
                     "    - run: \"${GITHUB_ACTION_PATH:-.}/agent.sh\"\n      shell: bash\n",
                     "    - run: ${{ format('{0}/agent.sh', github.action_path) }}\n      shell: bash\n",
                     "    - run: bash \"$P/agent.sh\"\n      shell: bash\n      env:\n        P: ${{ github.action_path }}\n",
                     "    - run: cd \"$GITHUB_ACTION_PATH\" && ./agent.sh\n      shell: bash\n",
                     "    - run: ./agent.sh\n      shell: bash\n      working-directory: ${{ github.action_path }}\n"):
            with self.subTest(step=step.strip()[:50]), TempDir() as tmp:
                files = {f"{ACTION_DIR}/action.yml": composite(step), **script}
                self.assertEqual(agent_rules(check(tmp, job_using(f"./{ACTION_DIR}"), files)), AGENT_RULES)

    def test_the_using_steps_env_reaches_the_actions_steps(self):
        text = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        env:\n          AGENT: claude\n"
        files = {f"{ACTION_DIR}/action.yml": composite("    - run: $AGENT -p x\n      shell: bash\n")}
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, text, files)), AGENT_RULES)

    def test_inputs_inside_larger_expressions(self):
        given = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        with:\n          tool: claude\n"
        for run in ("${{ (inputs.tool) }} -p x", "${{ format('{0} -p x', inputs.tool) }}",
                    "${{ inputs.other || inputs.tool }} -p x", "${{ ((inputs.tool)) }} -p x",
                    "${{ format('{0} {1}', inputs.tool, '-p x') }}"):
            with self.subTest(run=run), TempDir() as tmp:
                files = {f"{ACTION_DIR}/action.yml": composite(f"    - run: \"{run}\"\n      shell: bash\n")}
                self.assertEqual(agent_rules(check(tmp, given, files)), AGENT_RULES)

    def test_an_alias_named_a_million_times_is_quick(self):
        import time
        levels = ["l0: &l0 [claude -p x]"]
        for n in range(1, 7):
            levels.append(f"l{n}: &l{n} [" + ", ".join([f"*l{n - 1}"] * 10) + "]")
        body = ("name: x\nx-anchors:\n" + "".join(f"  {line}\n" for line in levels) +
                "runs:\n  using: composite\n  steps:\n    - uses: some/action@" + SHA + "\n      with:\n"
                "        big: *l6\n")
        with TempDir() as tmp:
            started = time.monotonic()
            check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": body})
            self.assertLess(time.monotonic() - started, 10)

    def test_a_long_input_put_in_many_times_is_not_read_whole(self):
        import time
        body = ("name: x\ninputs:\n  big:\n    default: '" + "a" * 100_000 + "'\nruns:\n  using: composite\n"
                "  steps:\n    - run: \"" + "${{ inputs.big }} " * 100 + "\"\n      shell: bash\n")
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": body})
            self.assertLess(time.monotonic() - started, 5)
            self.assertTrue(any("longer than the checker reads" in n for n in result.notes), result.notes)


class TheReviewersSecondPassTest(unittest.TestCase):
    """What the second review pass of this slice found (2026-11-18)."""

    def timed(self, files, text=None, limit=3):
        import time
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, text or job_using(f"./{ACTION_DIR}"), files)
            self.assertLess(time.monotonic() - started, limit)
            return result

    def test_an_environment_put_into_a_script_is_capped(self):
        body = composite("    - run: echo " + "$P " * 2000 + "\n      shell: bash\n      env:\n        P: " + "a" * 2000 + "\n")
        result = self.timed({f"{ACTION_DIR}/action.yml": body})
        self.assertTrue(any("longer than the checker reads" in n for n in result.notes), result.notes)

    def test_deep_parentheses_are_quick(self):
        body = composite("    - run: ${{ " + "(" * 6000 + "inputs.a" + ")" * 6000 + " }} -p x\n      shell: bash\n")
        result = self.timed({f"{ACTION_DIR}/action.yml": body})
        self.assertTrue(any("nested more deeply" in n for n in result.notes), result.notes)

    def test_a_large_repository_with_a_different_input_in_each_job_passes(self):
        jobs = "".join(f"  j{n}:\n    runs-on: ubuntu-latest\n    permissions: {{contents: read}}\n    steps:\n"
                       f"      - uses: ./.github/actions/setup\n        with: {{key: job-{n}}}\n" for n in range(400))
        files = {".github/actions/setup/action.yml": composite(
                     "    - uses: ./.github/actions/cache\n      with: {key: '${{ inputs.key }}'}\n",
                     "    - uses: ./.github/actions/tools\n      with: {key: '${{ inputs.key }}'}\n"),
                 ".github/actions/cache/action.yml": composite(PLAIN),
                 ".github/actions/tools/action.yml": composite(PLAIN)}
        result = self.timed(files, text="on: push\njobs:\n" + jobs, limit=20)
        self.assertEqual([e for e in result.errors if "readings" in e], [])

    def test_common_expressions_give_no_note(self):
        for expression in ("${{ inputs.token || github.token }}", "${{ inputs.verbose == 'true' && '--debug' || '' }}",
                           "${{ fromJSON(inputs.matrix).os }}", "${{ github.event.inputs.ref }}",
                           "${{ contains(inputs.tags, 'x') }}", "${{ inputs.ref != '' && inputs.ref || github.ref }}"):
            with self.subTest(expression=expression):
                body = composite(f"    - run: echo \"{expression}\"\n      shell: bash\n")
                result = self.timed({f"{ACTION_DIR}/action.yml": body})
                self.assertEqual([n for n in result.notes if n.startswith("Local actions")], [])

    def test_an_input_inside_a_function_is_read_the_widest_way(self):
        given = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        with:\n          cmd: claude -p x\n"
        body = composite("    - run: ${{ fromJSON(inputs.cmd) }}\n      shell: bash\n")
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, given, {f"{ACTION_DIR}/action.yml": body})), AGENT_RULES)

    def test_a_line_break_in_the_path_is_escaped_in_the_error(self):
        folder = ".github/actions/x\nFORGED: everything passed"
        text = job_using('"./.github/actions/x\\nFORGED: everything passed"')
        with TempDir() as tmp:
            result = check(tmp, text, {f"{folder}/action.yml": "runs: [\n"})
            self.assertEqual(len(result.errors), 1, result.errors)
            self.assertNotIn("\n", result.errors[0])

    def test_a_cycle_under_a_fan_out_does_not_exhaust_the_readings(self):
        files = {f".github/actions/a{n}/action.yml": composite(*[f"    - uses: ./.github/actions/a{n + 1}\n"] * 4)
                 for n in range(5)}
        files[".github/actions/a5/action.yml"] = composite(PLAIN, "    - uses: ./.github/actions/a0\n      if: false\n")
        result = self.timed(files, text=job_using("./.github/actions/a0"))
        # Slice 2d.4b2 reads the same actions as steps of the job: four uses at each of five levels are
        # 2,388 steps that would run, past the 1,000 it reads for one job, which is an error of its own.
        # The readings this test is about (2d.4a's budget) are not exhausted.
        self.assertEqual([e for e in result.errors if "would give more than 1000 steps" not in e], [])
        self.assertEqual(len(result.errors), 1, result.errors)

    def test_the_actions_folder_is_searched_only_when_the_step_goes_there(self):
        files = {f"{ACTION_DIR}/action.yml": composite("    - run: ./build.sh\n      shell: bash\n"),
                 f"{ACTION_DIR}/build.sh": "#!/bin/sh\nclaude -p 'fix it'\n",
                 "build.sh": "#!/bin/sh\nmake\n"}
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, job_using(f"./{ACTION_DIR}"), files)), [])

    def test_an_expression_in_a_nested_uses_is_a_note(self):
        files = {f"{ACTION_DIR}/action.yml": composite("    - uses: ./${{ inputs.dir }}\n"),
                 "action.yml": composite(CLI)}
        with TempDir() as tmp:
            result = check(tmp, job_using(f"./{ACTION_DIR}"), files)
            self.assertEqual(agent_rules(result), [])
            self.assertTrue(any("holds an expression" in n for n in result.notes), result.notes)


class TheReviewersThirdPassTest(unittest.TestCase):
    """What the third review pass of this slice found (2026-11-18)."""

    def caught(self, run, with_="", env="", extra_files=None):
        text = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n"
        if with_:
            text += "        with:\n" + "".join(f"          {line}\n" for line in with_.split("\n"))
        if env:
            text += "        env:\n" + "".join(f"          {line}\n" for line in env.split("\n"))
        files = {f"{ACTION_DIR}/action.yml": composite(f"    - run: {run}\n      shell: bash\n"), **(extra_files or {})}
        with TempDir() as tmp:
            return agent_rules(check(tmp, text, files))

    def test_a_comparison_inside_a_function_keeps_the_inputs(self):
        for run in ("${{ fromJSON(inputs.mode == 'ai' && inputs.tool || '\"make\"') }} -p fix",
                    "${{ fromJSON(!inputs.quiet && inputs.tool || '\"make\"') }} -p fix"):
            with self.subTest(run=run):
                self.assertEqual(self.caught(json_quoted(run), with_="mode: ai\ntool: '\"claude\"'"), AGENT_RULES)

    def test_inputs_as_a_whole(self):
        self.assertEqual(self.caught(json_quoted("${{ fromJSON(toJSON(inputs)).tool }} -p fix"), with_="tool: claude"),
                         AGENT_RULES)

    def test_the_env_context_is_put_in(self):
        self.assertEqual(self.caught(json_quoted("${{ inputs.tool || env.AGENT }} -p fix"), env="AGENT: claude"),
                         AGENT_RULES)

    def test_cd_with_options_a_modifier_or_a_subfolder(self):
        script = {f"{ACTION_DIR}/agent.sh": "#!/bin/sh\nclaude -p 'fix it'\n",
                  f"{ACTION_DIR}/bin/agent.sh": "#!/bin/sh\nclaude -p 'fix it'\n"}
        for run in ('cd -- "$GITHUB_ACTION_PATH" && ./agent.sh', 'cd -P "$GITHUB_ACTION_PATH" && ./agent.sh',
                    'cd "${GITHUB_ACTION_PATH%/}" && ./agent.sh', 'cd "$GITHUB_ACTION_PATH/bin" && ./agent.sh'):
            with self.subTest(run=run):
                self.assertEqual(self.caught(json_quoted(run), extra_files=script), AGENT_RULES)

    def test_the_bound_counts_steps(self):
        import time
        steps = 40
        files = {f".github/actions/a{n}/action.yml": composite(
            *[f"    - uses: ./.github/actions/a{n + 1}\n      with:\n        n: '${{{{ inputs.n }}}}{k}'\n"
              for k in range(steps)]) for n in range(5)}
        files[".github/actions/a5/action.yml"] = composite(*[PLAIN] * steps)
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, job_using("./.github/actions/a0"), files)
            self.assertLess(time.monotonic() - started, 5)
            self.assertTrue(any("units the check spends on them" in e for e in result.errors), result.errors)


class TheReviewersFourthPassTest(unittest.TestCase):
    """What the fourth review pass of this slice found (2026-11-18)."""

    def test_an_env_value_set_from_an_input_is_put_in(self):
        body = composite("    - run: ${{ env.T }} -p fix\n      shell: bash\n      env:\n        T: ${{ inputs.tool }}\n")
        text = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        with:\n          tool: claude\n"
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, text, {f"{ACTION_DIR}/action.yml": body})), AGENT_RULES)

    def test_values_left_out_past_the_limit_are_named(self):
        chain = " && ".join(f"'a{n}'" for n in range(16)) + " && inputs.tool"
        body = composite(f"    - run: ${{{{ {chain} }}}} -p fix\n      shell: bash\n")
        text = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        with:\n          tool: claude\n"
        with TempDir() as tmp:
            result = check(tmp, text, {f"{ACTION_DIR}/action.yml": body})
            self.assertTrue(agent_rules(result) == AGENT_RULES
                            or any("more than 16 texts" in n for n in result.notes), result.notes)

    def test_a_big_step_read_many_times_is_bounded_by_its_size(self):
        """8,000 readings of a 10 KB step: before the size counted, about 40 s and no error; now the
        bound is reached after a few hundred (slice 2d.4a-timing made it a test of the bound)."""
        import time
        files = {f".github/actions/a{n}/action.yml": composite(
            *[f"    - uses: ./.github/actions/a{n + 1}\n      with:\n        n: '${{{{ inputs.n }}}}{k}'\n"
              for k in range(20)]) for n in range(3)}
        files[".github/actions/a3/action.yml"] = composite(
            "    - run: echo ${{ inputs.n }} " + "x" * 10_000 + "\n      shell: bash\n")
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, job_using("./.github/actions/a0"), files)
            # About 2.5 s locally; the limit leaves room for a slow CI runner.
            self.assertLess(time.monotonic() - started, 12)
            self.assertTrue(any("units the check spends on them" in e for e in result.errors), result.errors)


class TheReviewersFifthPassTest(unittest.TestCase):
    """What the fifth review pass of this slice found (2026-11-18)."""

    def test_format_combines_the_values_of_its_arguments(self):
        body = composite("    - run: ${{ format('{0} {1}', inputs.tool || 'claude', inputs.flag || '-p') }} fix\n"
                         "      shell: bash\n")
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, job_using(f"./{ACTION_DIR}"), {f"{ACTION_DIR}/action.yml": body})),
                             AGENT_RULES)

    def test_text_a_caller_hands_on_is_paid_for(self):
        import time
        parent = ("name: p\ninputs:\n  big:\n    default: '" + "b" * 20_000 + "'\nruns:\n  using: composite\n  steps:\n"
                  + "".join(f"    - uses: ./.github/actions/c\n      with:\n        big: ${{{{ inputs.big }}}}\n"
                            f"        n: '{i}'\n" for i in range(300)))
        files = {".github/actions/p/action.yml": parent,
                 ".github/actions/c/action.yml": composite("    - run: echo ${{ inputs.big }} ${{ inputs.n }}\n"
                                                           "      shell: bash\n")}
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, job_using("./.github/actions/p"), files)
            # About 1.5 s locally; before the text was charged, about 3 s and no error. The error is the
            # main check (slice 2d.4a-timing), and the limit leaves room for a slow CI runner.
            self.assertLess(time.monotonic() - started, 12)
            self.assertTrue(any("units the check spends on them" in e for e in result.errors), result.errors)

    def test_an_alias_shared_by_env_and_run_is_read_for_each(self):
        body = ("runs:\n  using: composite\n  steps:\n    - env:\n        T: ${{ inputs.tool }}\n"
                "        R: &r \"${{ env.T }} -p fix\"\n      run: *r\n      shell: bash\n")
        text = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        with:\n          tool: claude\n"
        with TempDir() as tmp:
            self.assertEqual(agent_rules(check(tmp, text, {f"{ACTION_DIR}/action.yml": body})), AGENT_RULES)


class TheReviewersSixthPassTest(unittest.TestCase):
    """What the sixth review pass of this slice found (2026-11-18)."""

    def test_combinations_format_did_not_make_are_named(self):
        second = " || ".join(f"'w{n}'" for n in range(16))
        body = composite(f"    - run: ${{{{ format('{{0}} -p fix', false || 0 || 0.0 || inputs.tool, {second}) }}}}\n"
                         "      shell: bash\n")
        text = job_using(f"./{ACTION_DIR}").rstrip("\n") + "\n        with:\n          tool: claude\n"
        with TempDir() as tmp:
            result = check(tmp, text, {f"{ACTION_DIR}/action.yml": body})
            self.assertTrue(agent_rules(result) == AGENT_RULES
                            or any("more than 16 texts" in n for n in result.notes), result.notes)

    def test_a_large_repository_with_realistic_actions_passes(self):
        def padded(steps, name):
            body = "".join(f"    - name: {name} step {n}\n      run: echo \"$KEY\" {'x' * 600}\n      shell: bash\n"
                           f"      env:\n        KEY: ${{{{ inputs.key }}}}\n" for n in range(steps))
            return f"name: {name}\ninputs:\n  key:\n    default: ''\nruns:\n  using: composite\n  steps:\n" + body
        setup = padded(10, "setup") + "".join(
            f"    - uses: ./.github/actions/{inner}\n      with:\n        key: ${{{{ inputs.key }}}}\n"
            for inner in ("cache", "tools"))
        files = {".github/actions/setup/action.yml": setup,
                 ".github/actions/cache/action.yml": padded(4, "cache"),
                 ".github/actions/tools/action.yml": padded(4, "tools")}
        jobs = "".join(f"  j{n}:\n    runs-on: ubuntu-latest\n    permissions: {{contents: read}}\n    steps:\n"
                       f"      - uses: ./.github/actions/setup\n        with: {{key: pkg-{n}}}\n" for n in range(400))
        import time
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, "on: push\njobs:\n" + jobs, files)
            self.assertLess(time.monotonic() - started, 30)
            self.assertEqual([e for e in result.errors if "units" in e], [])


class TheReviewersSeventhPassTest(unittest.TestCase):
    """Many cheap uses of a local action cannot buy a long reading for a heavy one (2026-11-18)."""

    def test_cheap_uses_buy_nothing_for_another_step(self):
        import time
        files = {".github/actions/t/action.yml": composite(PLAIN)}
        # A fan-out sized so that it fits the shared bound plus what 500 cheap uses would add if their
        # units were pooled, and not the shared bound alone: with the allowance pooled (as before the fix)
        # it ends with no error; with each use's units its own, it stops at the bound (found by the review
        # of slice 2d.4a-timing, which tried both).
        files.update({f".github/actions/f{n}/action.yml": composite(
            *[f"    - uses: ./.github/actions/f{n + 1}\n      with:\n        n: '${{{{ inputs.n }}}}{k}'\n"
              for k in range(20 if n < 2 else 2)]) for n in range(3)})
        files[".github/actions/f3/action.yml"] = composite(
            *["    - run: echo '${{ inputs.n }}'\n      shell: bash\n"] * 20)
        cheap = "".join("      - uses: ./.github/actions/t\n" for _ in range(500))
        text = ("on: workflow_dispatch\njobs:\n  buy:\n    runs-on: ubuntu-latest\n    permissions: {}\n"
                f"    steps:\n{cheap}  heavy:\n    runs-on: ubuntu-latest\n    permissions: {{}}\n    steps:\n"
                "      - uses: ./.github/actions/f0\n")
        with TempDir() as tmp:
            started = time.monotonic()
            result = check(tmp, text, files)
            # About 1.2 s locally; the error is the main check, and the limit leaves room for a slow CI
            # runner (slice 2d.4a-timing: the first version of this case took 5.0 s on CI once).
            self.assertLess(time.monotonic() - started, 8)
            self.assertTrue(any("units the check spends on them" in e for e in result.errors), result.errors)


def json_quoted(text):
    import json
    return json.dumps(text)


class TheEgressControlSeesTheAgentOutsideTest(unittest.TestCase):
    """An agent in a local action beside OBAAF's egress action runs outside the confined command, and
    the control says where."""

    def test_it_is_not_met_and_names_the_action(self):
        steps = CHECKOUT + "\n" + action(run="make test") + f"\n      - uses: ./{ACTION_DIR}"
        result = run_check(workflow(steps), files={f"{ACTION_DIR}/action.yml": composite(CLI)}, config={"lanes": {}})
        (f,) = [f for f in result.findings if f.rule == "OBAAF-GHA-020"]
        (control,) = f.controls
        self.assertEqual(control.verdict, NOT_MET)
        self.assertIn(f"of the local action ./{ACTION_DIR}", control.detail)
        self.assertIn("outside the confined command", control.detail)


if __name__ == "__main__":
    unittest.main()
