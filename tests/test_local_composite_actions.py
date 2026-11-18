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
            "not YAML": ({f"{ACTION_DIR}/action.yml": "runs: [\n"}, "not YAML"),
            "duplicate keys": ({f"{ACTION_DIR}/action.yml": "runs:\n  using: composite\n  using: node24\n"},
                               "not YAML"),
            "a list": ({f"{ACTION_DIR}/action.yml": "- runs\n"}, "not a mapping"),
            "a tag": ({f"{ACTION_DIR}/action.yml": "runs: !!binary aGk=\n"}, "does not read"),
            "a disputed break": ({f"{ACTION_DIR}/action.yml": "name: a\u2028b\nruns:\n  using: composite\n"
                                  "  steps: []\n"}, "line break"),
            "too large": ({f"{ACTION_DIR}/action.yml": composite(PLAIN) + "#" * 1_000_001 + "\n"}, "larger"),
        }
        for label, (files, why) in cases.items():
            with self.subTest(label):
                self.assertIn(why, self.note_for(files))

    def test_paths_outside_the_repository(self):
        for uses in ("./../elsewhere", "./.github/../../elsewhere", "./${{ inputs.where }}"):
            with self.subTest(uses=uses):
                self.assertIn("leads outside the repository or holds an expression", self.note_for({}, uses=uses))

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
            self.assertTrue(any("reads no more" in n for n in result.notes), result.notes)


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
