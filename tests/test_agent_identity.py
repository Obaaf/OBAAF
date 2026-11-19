"""Flagship slice 2d.11 (#236): which actions and called workflows are an agent's.

Before this slice an agent action was matched as the first characters of a step's `uses:` value with a
`/` after them, and of a called workflow's `uses:` with nothing after them. Two false positives followed,
both of them on a repository's first run:

- `anthropics/claude-code-action/agent-approval-check`, an action in a folder of Claude Code's action
  repository that checks a pull request's approvals and runs no agent, made its job an agent job, with
  OBAAF-GHA-003, 004, 005, 012, 020 and 025 and the fact `agents: [claude-code]`;
- a job that calls a workflow of a repository whose name only begins like an agent action's
  (`anthropics/claude-code-action-docs/.github/workflows/docs.yml`, the lead session's case in #236) was
  an agent job too.

Now a called workflow is read as a step's action is (its `owner/repo` and folders, a `/` after the prefix),
and the catalogue lists, under each entry's `not_agents`, the actions in a folder under its actions that
run no agent, each with the action's own words and where they were read. Every other path under an agent
action is still the agent (the wider reading). The workflows here are written for these tests; the
approval check's inputs are its own (`action.yml` at f431ada).
"""

import copy
import json
import dataclasses
import datetime
import unittest
from unittest import mock

from helpers import TempDir
from test_agent_tools_data import AGENT_RULES, agents_of, check, is_agent_job, job_with

from obaaf import agent_tools, catalog, checker
from obaaf.checker import Config
from obaaf.checker import workflow as wf_mod

APPROVAL_SHA = "f431adaf77e0fecf918431e75a2b5b45b85af002"
APPROVAL = f"anthropics/claude-code-action/agent-approval-check@{APPROVAL_SHA}"
APPROVAL_STEP = (f"      - uses: {APPROVAL}\n        with:\n          required_approvals: \"2\"\n"
                 "          agent_logins: claude[bot],claude-code[bot]\n")


def agent_findings(result):
    return [(f.rule, f.job) for f in result.findings if f.rule in AGENT_RULES]


def calling(uses, extra=""):
    """One job that calls the workflow `uses`."""
    return f"on: workflow_dispatch\njobs:\n  a:\n    uses: {uses}\n{extra}"


def lane_of(text, config=None, files=None):
    with TempDir() as tmp:
        root = tmp / "repo"
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "wf.yml").write_text(text, encoding="utf-8")
        for rel, body in (files or {}).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return {(job, lane, reason) for _f, job, lane, reason in checker.lanes(root, config=config or Config())}


class SubActionTest(unittest.TestCase):
    """An action in a folder under an agent action's that the catalogue lists as running no agent."""

    def test_the_approval_check_is_not_an_agent(self):
        for uses in (APPROVAL, "anthropics/claude-code-action/agent-approval-check@v1",
                     "Anthropics/Claude-Code-Action/agent-approval-check@v1",
                     "anthropics/claude-code-action/./agent-approval-check@v1"):
            with self.subTest(uses):
                result = check(job_with(f"      - uses: {uses}\n"))
                self.assertFalse(is_agent_job(result))
                self.assertEqual(agent_findings(result), [])

    def test_its_job_is_not_put_in_the_agent_lane(self):
        text = ("on: pull_request_review\npermissions: {contents: read}\njobs:\n  approval:\n    runs-on: ubuntu-latest\n"
                "    permissions: {statuses: write, pull-requests: write}\n    steps:\n" + APPROVAL_STEP)
        self.assertEqual(lane_of(text), {("approval", "trusted", "default")})

    def test_other_spellings_of_its_folder_are_still_the_agent(self):
        # Only the folder as the catalogue writes it is taken out: another case (which a Linux runner does
        # not find), a folder under it, a folder whose name begins like it, and `..` back to the agent.
        for uses in ("anthropics/claude-code-action/Agent-Approval-Check@v1",
                     "anthropics/claude-code-action/agent-approval-check/inner@v1",
                     "anthropics/claude-code-action/agent-approval-check-v2@v1",
                     "anthropics/claude-code-action/agent-approval-check/../base-action@v1",
                     "anthropics/claude-code-action/agent-approval-check/@v1"):
            with self.subTest(uses):
                result = check(job_with(f"      - uses: {uses}\n"))
                self.assertTrue(is_agent_job(result))
                self.assertEqual(agents_of(result), [["claude-code"]])

    def test_documented_agent_actions_still_are(self):
        for uses in ("anthropics/claude-code-action@v1", "anthropics/claude-code-action/base-action@v1",
                     "anthropics/claude-code-base-action@v0", "ANTHROPICS/claude-code-action@v1"):
            with self.subTest(uses):
                result = check(job_with(f"      - uses: {uses}\n"))
                self.assertTrue(is_agent_job(result))
                self.assertEqual(agents_of(result), [["claude-code"]])

    def test_an_agent_beside_it_keeps_the_job_an_agent_job(self):
        result = check(job_with(APPROVAL_STEP + "      - run: codex exec \"review\"\n"))
        self.assertTrue(is_agent_job(result))
        self.assertEqual(agents_of(result), [["codex"]])

    def test_it_is_given_no_setting_of_the_agent_action(self):
        # OBAAF-GHA-026 reads Claude Code's action's settings on that action; the approval check has other
        # inputs, so a value of the same name there is not that setting.
        def workflow(uses):
            return ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                    f"    steps:\n      - uses: {uses}\n        with:\n          allowed_non_write_users: \"*\"\n"
                    "          claude_args: --dangerously-skip-permissions\n")
        self.assertEqual([f for f in check(workflow(APPROVAL)).findings if f.rule == "OBAAF-GHA-026"], [])
        self.assertTrue([f for f in check(workflow("anthropics/claude-code-action@v1")).findings
                         if f.rule == "OBAAF-GHA-026"])
        whole = ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                 f"    steps:\n      - uses: {APPROVAL}\n        with: ${{{{ fromJSON(vars.INPUTS) }}}}\n")
        self.assertEqual([f for f in check(whole).findings if f.rule == "OBAAF-GHA-026"], [])

    def test_inside_a_local_composite_action(self):
        def composite(uses):
            return {".github/actions/gate/action.yml":
                    f"runs:\n  using: composite\n  steps:\n    - uses: {uses}\n"}
        steps = (f"      - uses: actions/checkout@{'0' * 40}\n        with: {{persist-credentials: false}}\n"
                 "      - uses: ./.github/actions/gate\n")
        self.assertFalse(is_agent_job(check(job_with(steps), files=composite(APPROVAL))))
        found = check(job_with(steps), files=composite("anthropics/claude-code-action/base-action@v1"))
        self.assertTrue(is_agent_job(found))
        self.assertIn(["claude-code"], agents_of(found))

    def test_a_repository_that_names_it_as_its_own_agent_is_believed(self):
        # The catalogue's list narrows only the catalogue's actions; `agents.actions` is the repository's own
        # word, and a prefix there names every path under it.
        for prefix in ("anthropics/claude-code-action/agent-approval-check", "anthropics"):
            with self.subTest(prefix):
                result = check(job_with(f"      - uses: {APPROVAL}\n"), config=Config(agents={"actions": [prefix]}))
                self.assertTrue(is_agent_job(result))
                self.assertEqual(agents_of(result), [[f"agents.actions: {prefix}"]])

    def test_before_the_egress_action_it_is_not_an_agent_outside_it(self):
        from test_egress_recognised import (CHECKOUT, NOT_MET, VERIFIED, action, egress, run_check, verdict,
                                            workflow)
        before = CHECKOUT + "\n" + APPROVAL_STEP.rstrip("\n") + "\n" + action()
        self.assertEqual(verdict(egress(run_check(workflow(before)))), VERIFIED)
        outside = CHECKOUT + "\n      - uses: anthropics/claude-code-action/base-action@v1\n" + action()
        self.assertEqual(verdict(egress(run_check(workflow(outside)))), NOT_MET)


class CalledWorkflowTest(unittest.TestCase):
    """A called workflow is under an agent action when its `owner/repo` and folders are, as a step's
    action is, and not when its repository's name only begins like the action's."""

    def actions(self):
        return [(entry["id"], action) for entry in agent_tools.tools(catalog.load().detection)
                for action in entry["actions"]]

    def test_the_lead_sessions_case(self):
        text = calling("anthropics/claude-code-action-docs/.github/workflows/docs.yml@v1")
        self.assertEqual(lane_of(text), {("a", "trusted", "default")})
        self.assertEqual(agent_findings(check(text)), [])

    def test_no_repository_named_like_an_agent_action_is_one(self):
        for tool, action in self.actions():
            owner, repo = action.split("/")[:2]
            for uses in (f"{owner}/{repo}-docs/.github/workflows/x.yml@v1", f"{action}-docs/x.yml@v1",
                         f"{owner}/{repo}x/.github/workflows/x.yml@v1"):
                with self.subTest(tool=tool, uses=uses):
                    self.assertEqual(agent_findings(check(calling(uses, "    secrets: inherit\n"))), [])
            with self.subTest(tool=tool, step=f"{action}-docs"):
                self.assertFalse(is_agent_job(check(job_with(f"      - uses: {action}-docs@v1\n"))))

    def test_a_workflow_in_an_agent_actions_repository_still_is(self):
        # Where the action is a whole repository: a workflow can only be at `owner/repo/.github/workflows/`.
        whole = [(tool, action) for tool, action in self.actions() if action.count("/") == 1]
        self.assertGreater(len(whole), 20)
        for tool, action in whole:
            for uses in (f"{action}/.github/workflows/review.yml@v1", f"{action.upper()}/.github/workflows/x.yml@v1",
                         f"{action}/.github/workflows/x.yml@{'a' * 40}"):
                with self.subTest(tool=tool, uses=uses):
                    found = [f for f in check(calling(uses, "    secrets: inherit\n")).findings if f.rule in AGENT_RULES]
                    self.assertTrue(found)
                    self.assertTrue(all(f.facts["agents"] == [tool] for f in found), found)

    def test_a_workflow_beside_an_action_in_a_folder_is_not_that_action(self):
        # Continue's, Kilo Code's and OpenHands' actions are folders of a larger repository; that
        # repository's own workflows are not under the action (found by the review of slice 2d.11, which
        # showed the guide said otherwise).
        folders = [(tool, action) for tool, action in self.actions() if action.count("/") > 1]
        self.assertEqual(len(folders), 7)
        for tool, action in folders:
            owner, repo = action.split("/")[:2]
            with self.subTest(tool=tool, action=action):
                self.assertEqual(agent_findings(check(calling(f"{owner}/{repo}/.github/workflows/x.yml@v1"))), [])

    def test_spaces_around_the_call_are_read_through(self):
        text = calling('" anthropics/claude-code-action/.github/workflows/x.yml@v1 "', "    secrets: inherit\n")
        self.assertTrue(agent_findings(check(text)))

    def test_dot_dot_does_not_climb_out_of_the_repository(self):
        text = calling("anthropics/claude-code-action-docs/../claude-code-action/.github/workflows/x.yml@v1")
        self.assertEqual(agent_findings(check(text)), [])

    def test_a_configured_action_is_read_without_its_ref_and_a_slash_at_its_end(self):
        # Found by the review of slice 2d.11: a call was compared with the entry as written before, so an
        # entry with an `@ref` or a `/` at its end named the call; it still does, as a prefix.
        call = calling("my-org/agent/.github/workflows/x.yml@v1", "    secrets: inherit\n")
        for entry in ("my-org/agent/.github/workflows/x.yml@v1", "my-org/agent/.github/workflows/x.yml@",
                      "my-org/agent/", "my-org/", " my-org/agent ", "My-Org/Agent@main"):
            with self.subTest(entry=entry):
                found = [f for f in check(call, config=Config(agents={"actions": [entry]})).findings
                         if f.rule in AGENT_RULES]
                self.assertTrue(found)
                self.assertTrue(all(f.facts["agents"] == [f"agents.actions: {entry.strip()}"] for f in found))
        step = job_with("      - uses: my-org/agent/run@v2\n")
        self.assertTrue(is_agent_job(check(step, config=Config(agents={"actions": ["my-org/agent/@v1"]}))))

    def test_a_configured_action_that_names_nothing_is_refused(self):
        for agents in ({"actions": "my-org/agent"}, {"actions": ["@v1"]}, {"actions": [""]}, {"actions": ["/"]},
                       {"actions": [3]}, {"actions": ["./.github/actions/run-agent"]}, {"actions": ["$/x"]},
                       {"actions": ["docker://ghcr.io/x/agent"]}, {"actions": ["my-org\\agent"]},
                       {"commands": "run-agent"}, {"commands": [" "]}, {"commands": ["("]}):
            with self.subTest(agents=agents), self.assertRaises(checker.ConfigError):
                Config.from_data({"agents": agents}, "obaaf.yml")
        Config.from_data({"agents": {"actions": ["my-org"], "commands": ["run-agent"]}}, "obaaf.yml")

    def test_a_configured_action_is_read_the_same_way(self):
        config = Config(agents={"actions": ["example/agent"]})
        self.assertEqual(agent_findings(check(calling("example/agent-docs/.github/workflows/x.yml@v1"),
                                              config=config)), [])
        found = [f for f in check(calling("example/agent/.github/workflows/x.yml@v1", "    secrets: inherit\n"),
                                  config=config).findings if f.rule in AGENT_RULES]
        self.assertTrue(found)
        self.assertTrue(all(f.facts["agents"] == ["agents.actions: example/agent"] for f in found))

    def test_a_local_call_is_not_an_agent_actions(self):
        actions = wf_mod.AgentActions({"agent_actions": ["anthropics/claude-code-action"]}, ["."])
        self.assertFalse(actions.calls("./.github/workflows/x.yml"))
        self.assertFalse(actions.calls(None))
        self.assertFalse(actions.calls("   "))


class OutOfTheRepositoryTest(unittest.TestCase):
    """Found by the review of slice 2d.11: the runner puts the whole repository of each action a job uses in
    one folder beside the workspace, so after the approval check a step can reach Claude Code's own action
    by a path that leaves its repository. Such a path is taken for an agent action, in any job."""

    ESCAPES = [
        f"./../../_actions/anthropics/claude-code-action/{APPROVAL_SHA}",
        f"./.github/../../../_actions/anthropics/claude-code-action/{APPROVAL_SHA}",
        f".\\..\\..\\_actions\\anthropics\\claude-code-action\\{APPROVAL_SHA}",
        f"$/../x",
        f"actions/checkout/../../../anthropics/claude-code-action/{APPROVAL_SHA}@v4",
        "actions/checkout/..@v4",
        "actions/../x/y@v1",
        "actions/checkout/x\\..\\..\\y@v4",
    ]
    STAYS = ["./.github/actions/a/../b", "actions/cache/save/../restore@v4", "actions/checkout@v4",
             "./.github/actions/x", "docker://alpine:3", "actions/cache/./save@v4"]

    def test_a_path_out_of_its_repository_is_an_agent(self):
        for uses in self.ESCAPES:
            with self.subTest(uses=uses):
                self.assertTrue(wf_mod.leaves_repository(uses))
                # As a YAML double-quoted string, so each backslash is one backslash.
                result = check(job_with(APPROVAL_STEP + f"      - uses: {json.dumps(uses)}\n"))
                self.assertTrue(is_agent_job(result))
                self.assertTrue(is_agent_job(check(job_with(f"      - uses: {json.dumps(uses)}\n"))))

    def test_a_path_that_stays_is_not(self):
        for uses in self.STAYS:
            with self.subTest(uses=uses):
                self.assertFalse(wf_mod.leaves_repository(uses))
        self.assertFalse(wf_mod.leaves_repository(None))
        self.assertFalse(is_agent_job(check(job_with(APPROVAL_STEP + "      - uses: actions/checkout@v4\n"))))

    def test_it_says_why_and_names_no_tool(self):
        with TempDir() as tmp:
            root = tmp / "repo"
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "wf.yml").write_text(
                job_with(APPROVAL_STEP + f"      - uses: {self.ESCAPES[0]}\n"), encoding="utf-8")
            ((_f, _job, lane, reason),) = checker.lanes(root, config=Config())
        self.assertEqual(lane, "agent")
        self.assertIn("a path out of its repository", reason)
        result = check(job_with(f"      - uses: {self.ESCAPES[4]}\n"))
        self.assertEqual(agents_of(result), [None])

    def test_a_link_out_of_the_repository_is_one_too(self):
        # Found by the second review of slice 2d.11: a link committed in the repository that leads out of it
        # reaches the same folder as `./..`.
        for target in ("../../../../_actions/anthropics/claude-code-action/" + APPROVAL_SHA,
                       "/home/runner/work/_actions/anthropics/claude-code-action/" + APPROVAL_SHA):
            with self.subTest(target=target), TempDir() as tmp:
                root = tmp / "repo"
                (root / ".github" / "workflows").mkdir(parents=True)
                (root / ".github" / "workflows" / "wf.yml").write_text(
                    job_with(APPROVAL_STEP + "      - uses: ./.github/actions/gate\n"), encoding="utf-8")
                (root / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
                (root / ".github" / "actions").mkdir()
                (root / ".github" / "actions" / "gate").symlink_to(target, target_is_directory=True)
                result = checker.check(root)
                self.assertTrue(is_agent_job(result))
                self.assertFalse([n for n in result.notes if n.startswith("Local actions were not read through")])
                ((_f, _job, lane, reason),) = checker.lanes(root)
                self.assertEqual(lane, "agent")
                self.assertIn("leads outside the repository", reason)

    def test_inside_a_local_composite_action_and_before_the_egress_action(self):
        files = {".github/actions/gate/action.yml":
                 f"runs:\n  using: composite\n  steps:\n    - uses: {self.ESCAPES[4]}\n"}
        steps = (f"      - uses: actions/checkout@{'0' * 40}\n        with: {{persist-credentials: false}}\n"
                 "      - uses: ./.github/actions/gate\n")
        self.assertTrue(is_agent_job(check(job_with(steps), files=files)))
        from test_egress_recognised import CHECKOUT, NOT_MET, action, egress, run_check, verdict, workflow
        before = CHECKOUT + "\n" + APPROVAL_STEP + f"      - uses: {self.ESCAPES[0]}\n" + action()
        self.assertEqual(verdict(egress(run_check(workflow(before)))), NOT_MET)


class NotAgentsDataTest(unittest.TestCase):
    """The catalogue's `not_agents`: what an item must say, and what the checker refuses."""

    def entry(self, **changes):
        out = {"id": "tool", "name": "Tool", "read": datetime.date(2026, 11, 19),
               "sources": ["https://example.com/docs"], "actions": {"example/tool-action": {}},
               "commands": [], "packages": {}, "install_urls": [], "settings": [],
               "no_warnings": "Read the README at a commit; it warns about nothing.",
               "not_agents": [self.item()]}
        out.update(changes)
        return out

    def item(self, **changes):
        out = {"action": "example/tool-action/check", "read": datetime.date(2026, 11, 19),
               "says": "Checks approvals.", "checked": "Its one step runs its own script, which calls only GitHub.",
               "source": "https://github.com/example/tool-action/blob/" + "a" * 40 + "/check/action.yml#L1-L3"}
        out.update(changes)
        return out

    def faults(self, *entries):
        return agent_tools.problems({"agent_tools": list(entries)})

    def test_a_good_item_passes(self):
        self.assertEqual(self.faults(self.entry()), [])

    def test_each_fault_is_named(self):
        other = self.entry(id="other", actions={"example/tool-action/check/deeper": {}}, not_agents=[])
        cases = {
            "not_agents must be a list": (self.entry(not_agents={}),),
            "not a mapping": (self.entry(not_agents=["example/tool-action/check"]),),
            "missing checked": (self.entry(not_agents=[{k: v for k, v in self.item().items() if k != "checked"}]),),
            "unknown key": (self.entry(not_agents=[self.item(colour="blue")]),),
            "must be owner/repo/path": (self.entry(not_agents=[self.item(action="example/tool-action")]),),
            "without a . or .. part": (self.entry(not_agents=[self.item(action="example/tool-action/./check")]),),
            "without a . or .. part ": (self.entry(not_agents=[self.item(action="example/tool-action/x/../check")]),),
            "in the action's folder": (self.entry(not_agents=[self.item(
                source="https://github.com/example/tool-action/blob/" + "a" * 40 + "/action.yml#L1")]),),
            "not in a folder under one of the entry's actions": (
                self.entry(not_agents=[self.item(action="example/other/check")]),),
            "folder under one of the entry's actions ": (
                self.entry(not_agents=[self.item(action="example/tool-action-docs/check")]),),
            "cannot also run no agent": (self.entry(), self.entry(
                id="other", actions={"example/tool-action/check": {}}, not_agents=[])),
            "is also under an action of other": (
                self.entry(not_agents=[self.item(action="example/tool-action/check/deeper/x")]), other),
            "is listed twice": (self.entry(not_agents=[self.item(), self.item(action="Example/Tool-Action/check")]),),
            "read must be a date": (self.entry(not_agents=[self.item(read="2026-11-19")]),),
            "says must be": (self.entry(not_agents=[self.item(says=" ")]),),
            "checked must be": (self.entry(not_agents=[self.item(checked=None)]),),
            "source must be a file at a commit": (self.entry(not_agents=[self.item(source="https://example.com")]),),
            "the action's own repository": (self.entry(not_agents=[self.item(
                source="https://github.com/someone/else/blob/" + "a" * 40 + "/action.yml#L1")]),),
        }
        for words, entries in cases.items():
            with self.subTest(words):
                got = self.faults(*entries)
                self.assertTrue(any(words.strip() in p for p in got), got)

    def test_the_list_is_built_from_the_entries_and_not_written_by_hand(self):
        data = {"agent_tools": [self.entry()]}
        self.assertEqual(agent_tools.expand(data)["agent_not_actions"], ["example/tool-action/check"])
        self.assertTrue(any("agent_not_actions is built from agent_tools" in p
                            for p in agent_tools.problems({**data, "agent_not_actions": ["x/y/z"]})))

    def test_the_shipped_list(self):
        detection = catalog.load().detection
        self.assertEqual(detection["agent_not_actions"], ["anthropics/claude-code-action/agent-approval-check"])
        (item,) = next(e for e in agent_tools.tools(detection) if e["id"] == "claude-code")["not_agents"]
        self.assertIn(APPROVAL_SHA, item["source"])
        self.assertIn("agent-approval-check/action.yml#L1-L6", item["source"])

    def test_a_listed_path_is_taken_out_of_every_entry_and_rule(self):
        # The list is read wherever an agent action is matched: the lanes, the egress control's steps,
        # local actions, the agents named in the facts and OBAAF-GHA-026. A catalogue that lists the root
        # action's folder `base-action` as running no agent takes it out everywhere.
        cat = checker.load()
        detection = copy.deepcopy(cat.detection)
        detection["agent_not_actions"] = detection["agent_not_actions"] + ["anthropics/claude-code-action/base-action"]
        changed = dataclasses.replace(cat, detection=detection)
        with TempDir() as tmp:
            root = tmp / "repo"
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "wf.yml").write_text(
                job_with("      - uses: anthropics/claude-code-action/base-action@v1\n"
                         "        with: {claude_args: --dangerously-skip-permissions}\n"), encoding="utf-8")
            (root / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
            before = checker.check(root)
            # The lanes are found with the shipped catalogue (`workflow.classify` loads it), so it is the
            # changed one for this check.
            with mock.patch.object(wf_mod, "load_catalog", lambda: changed):
                after = checker.check(root, catalog=changed)
        self.assertTrue(is_agent_job(before))
        self.assertFalse(is_agent_job(after))
        self.assertEqual([f for f in after.findings if f.rule in AGENT_RULES + ("OBAAF-GHA-026",)], [])

    def test_the_guide_names_it(self):
        from pathlib import Path
        guide = (Path(__file__).resolve().parents[1] / "docs" / "checker-configuration.md").read_text(encoding="utf-8")
        self.assertIn("anthropics/claude-code-action/agent-approval-check", guide)
        self.assertIn("not_agents", guide)


if __name__ == "__main__":
    unittest.main()
