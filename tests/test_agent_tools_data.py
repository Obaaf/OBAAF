"""Flagship slice 2d.5b: agent tools as data, and the agent's name in the agent rules' facts.

Before this slice `detection.yaml` held five flat lists (agent actions, command patterns, packages, the
packages 2c.8 reads as installs, install scripts), with no word of which tool each line was for, and the
agent rules' facts said why a job was an agent job only as the text of OBAAF-GHA-003's `why`. Now each
tool is one entry, read from its own repository or documentation and dated, the lists are built from the
entries, and every agent rule's finding has a fact `agents` that names the tools the job runs.

The workflows here are written for these tests from the tools' own documentation (each entry's
`sources`); none is copied from another project.
"""

import datetime
import re
import unittest

from helpers import TempDir

from obaaf import agent_tools, catalog, checker
from obaaf.checker import Config

CODEOWNERS = "* @example/maintainers\n"
AGENT_RULES = ("OBAAF-GHA-003", "OBAAF-GHA-004", "OBAAF-GHA-005", "OBAAF-GHA-012", "OBAAF-GHA-020",
               "OBAAF-GHA-025")

# The flat lists as they were in detection.yaml at the merge of slice 2d.5a (#234, cf03ca4). Each must
# still be built from the entries, so that no agent the checker found before is lost. The one install
# script pattern that was widened, OpenCode's, is checked by what it matches.
BEFORE_ACTIONS = [
    "anthropics/claude-code-action", "anthropics/claude-code-base-action", "google-github-actions/run-gemini-cli",
    "openai/codex-action", "actions/ai-inference", "qodo-ai/pr-agent", "Codium-ai/pr-agent",
    "coderabbitai/ai-pr-reviewer", "All-Hands-AI/OpenHands", "sst/opencode", "cline/cline",
]
BEFORE_COMMANDS = [
    '(^|[\\s;&|(/"\'`])claude["\'`]?\\s+([^\\n;&|]*\\s)?(-p|--print)\\b',
    "@anthropic-ai/claude-code",
    '(^|[\\s;&|(/"\'`])gemini["\'`]?\\s+([^\\n;&|]*\\s)?(-p|--prompt)\\b',
    "@google/gemini-cli",
    '(^|[\\s;&|(/"\'`])codex["\'`]?\\s+([^\\n;&|]*\\s)?exec\\b',
    "@openai/codex",
    "(^|[\\s;&|(])aider\\s",
    '(^|[\\s;&|(/"\'`])opencode["\'`]?\\s+([^\\n;&|]*\\s)?run\\b',
    '(^|[\\s;&|(/"\'`])copilot["\'`]?\\s+([^\\n;&|]*\\s)?(-p|--prompt)\\b',
    "(^|[\\s;&|(])cline\\s",
]
BEFORE_PACKAGES = ["@anthropic-ai/claude-code", "@google/gemini-cli", "@openai/codex", "@github/copilot",
                   "opencode-ai", "aider-chat", "aider-install", "@qodo/command"]
BEFORE_INSTALLS = {"@anthropic-ai/claude-code": "claude", "@openai/codex": "codex", "@google/gemini-cli": "gemini"}
BEFORE_URLS = ["claude\\.ai/install\\.(sh|ps1|cmd)\\b", "aider\\.chat/install\\.(sh|ps1)\\b"]

# The 20 signature files ci-agent-audit had at its commit 4a88ee6 (2026-11-07), by their ids, and the
# entry here that covers each tool (docs/landscape.md, part 3; positioning point 2).
CI_AGENT_AUDIT_4A88EE6 = {
    "aider-ci": "aider", "amp": "amp", "auggie": "auggie", "claude-code-action": "claude-code",
    "claude-code-security-review": "claude-code-security-review", "coderabbit": "coderabbit",
    "codex-action": "codex", "continue-ci": "continue", "github-ai-inference": "github-models",
    "google-jules": "jules", "goose-ci": "goose", "kilo-code": "kilo", "kiro-cli": "kiro",
    "opencode": "opencode", "openhands-resolver": "openhands", "pr-agent": "pr-agent", "qwen-code": "qwen-code",
    "run-gemini-cli": "gemini-cli", "swe-agent-ci": "swe-agent", "warp-oz": "warp",
}


def raw_detection():
    from importlib import resources

    from obaaf import yamlutil
    text = resources.files("obaaf.data").joinpath("detection.yaml").read_text(encoding="utf-8")
    return yamlutil.load(text)


def check(workflow_text, files=None, config=None):
    with TempDir() as tmp:
        root = tmp / "repo"
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "wf.yml").write_text(workflow_text, encoding="utf-8")
        (root / ".github" / "CODEOWNERS").write_text(CODEOWNERS, encoding="utf-8")
        for rel, body in (files or {}).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return checker.check(root, config=config)


def job_with(steps, env=""):
    """One job, started by hand, with a key so that OBAAF-GHA-005 has something to report."""
    return ("on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            + env + "    env:\n      KEY: ${{ secrets.MODEL_API_KEY }}\n    steps:\n" + steps)


def agents_of(result, rule="OBAAF-GHA-005"):
    found = [f for f in result.findings if f.rule == rule]
    return [f.facts.get("agents") for f in found]


def is_agent_job(result, job="a"):
    """OBAAF-GHA-020 is reported for every agent job, cleared or not, and for no other."""
    return any(f.rule == "OBAAF-GHA-020" and f.job == job for f in result.findings)


class EntriesTest(unittest.TestCase):
    def test_the_entries_have_no_fault(self):
        self.assertEqual(agent_tools.problems(raw_detection()), [])
        self.assertEqual([p for p in catalog.load().problems() if "agent tool" in p or "agent_tools" in p], [])

    def test_every_entry_says_where_and_when_it_was_read(self):
        for entry in agent_tools.tools(raw_detection()):
            with self.subTest(entry["id"]):
                self.assertIsInstance(entry["read"], datetime.date)
                # The one entry with no source says why in a comment of the file; every other has one.
                if entry["id"] != "coderabbit":
                    self.assertTrue(entry["sources"])

    def test_the_lists_are_built_from_the_entries_and_lose_nothing(self):
        detection = catalog.load().detection
        for name, before in (("agent_actions", BEFORE_ACTIONS), ("agent_commands", BEFORE_COMMANDS),
                             ("agent_packages", BEFORE_PACKAGES), ("agent_install_urls", BEFORE_URLS)):
            with self.subTest(name):
                self.assertEqual([x for x in before if x not in detection[name]], [])
        self.assertEqual({k: v for k, v in detection["agent_installs"].items() if k in BEFORE_INSTALLS}, BEFORE_INSTALLS)
        urls = [re.compile(u, re.I) for u in detection["agent_install_urls"]]
        for line in ("curl -fsSL https://opencode.ai/install | bash", "curl -fsSL https://opencode.ai/v2/install | bash"):
            self.assertTrue(any(rx.search(line) for rx in urls), line)

    def test_no_list_is_written_by_hand(self):
        raw = raw_detection()
        for name in agent_tools.DERIVED:
            self.assertNotIn(name, raw)

    def test_every_tool_ci_agent_audit_recognised_has_an_entry(self):
        ids = {entry["id"] for entry in agent_tools.tools(raw_detection())}
        self.assertEqual(sorted(set(CI_AGENT_AUDIT_4A88EE6.values()) - ids), [])

    def test_the_guide_lists_every_entry(self):
        from pathlib import Path
        guide = (Path(__file__).resolve().parents[1] / "docs" / "checker-configuration.md").read_text(encoding="utf-8")
        section = guide.split("### The agent tools the checker knows", 1)[1].split("\n## ", 1)[0]
        listed = re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.M)
        self.assertEqual(sorted(listed), sorted(entry["id"] for entry in agent_tools.tools(raw_detection())))

    def test_a_file_without_entries_is_left_as_it_is(self):
        data = {"agent_actions": ["x/y"]}
        self.assertIs(agent_tools.expand(data), data)


class ProblemsTest(unittest.TestCase):
    def entry(self, **changes):
        out = {"id": "tool", "name": "Tool", "read": datetime.date(2026, 11, 18),
               "sources": ["https://example.com/docs"], "actions": {"example/tool-action": {"prompt_inputs": ["prompt"]}},
               "commands": [], "programs": [], "prompt_flags": [], "packages": {}, "installs": {},
               "install_urls": [], "settings": []}
        out.update(changes)
        return out

    def faults(self, *entries, **extra):
        return agent_tools.problems({"agent_tools": list(entries), **extra})

    def test_a_good_entry_passes(self):
        self.assertEqual(self.faults(self.entry()), [])

    def test_each_fault_is_named(self):
        cases = {
            "unknown key": self.entry(colour="blue"),
            "missing sources": {k: v for k, v in self.entry().items() if k != "sources"},
            "id must be": self.entry(id="Tool Name"),
            "read must be a date": self.entry(read="2026-11-18"),
            "https addresses": self.entry(sources=["http://example.com"]),
            "is not owner/repo": self.entry(actions={"docker://image": {}}),
            "expected {prompt_inputs": self.entry(actions={"example/x": {"prompt": "y"}}),
            "does not compile": self.entry(commands=["(unclosed"]),
            "must map npm or pypi": self.entry(packages={"cargo": ["x"]}),
            "which its packages do not list": self.entry(installs={"x": "x"}, programs=["x"]),
            "which its programs do not list": self.entry(packages={"npm": ["x"]}, installs={"x": "y"}),
            "nothing finds it": self.entry(actions={}, commands=[]),
            "settings must be a list": self.entry(settings={}),
        }
        for words, entry in cases.items():
            with self.subTest(words):
                self.assertTrue(any(words in p for p in self.faults(entry)), self.faults(entry))

    def test_two_entries_cannot_claim_the_same_thing(self):
        first = self.entry()
        second = self.entry(id="other", actions={"Example/Tool-Action": {}})
        self.assertTrue(any("also tool's" in p for p in self.faults(first, second)))
        self.assertTrue(any("is also" in p for p in self.faults(first, self.entry())))

    def test_a_flat_list_beside_the_entries_is_refused(self):
        self.assertTrue(any("built from agent_tools" in p
                            for p in self.faults(self.entry(), agent_commands=["x"])))
        self.assertEqual(agent_tools.problems({}), ["detection: agent_tools must be a non-empty list"])


class NewToolsTest(unittest.TestCase):
    """The tools this slice adds are found, in the forms their own documentation gives, and look-alikes
    are not."""

    FOUND = {
        "google-gemini/gemini-cli-action@v1": "gemini-cli",
        "The-PR-Agent/pr-agent@main": "pr-agent",
        "OpenHands/extensions/plugins/pr-review@main": "openhands",
        "anomalyco/opencode/github@latest": "opencode",
        "qodo-ai/command@v1": "qodo",
        "anthropics/claude-code-security-review@main": "claude-code-security-review",
        "augmentcode/augment-action@v1": "auggie",
        "augmentcode/augment-agent@v0": "auggie",
        "continuedev/continue/actions/general-review@main": "continue",
        "google-labs-code/jules-action@v1": "jules",
        "Kilo-Org/kilocode/github@main": "kilo",
        "QwenLM/qwen-code-action@v1": "qwen-code",
        "warpdotdev/oz-agent-action@v1": "warp",
        "warpdotdev/warp-agent-action@v1": "warp",
    }
    COMMANDS = {
        "auggie --print \"review the change\"": "auggie",
        "npx -y @augmentcode/auggie --print hi": "auggie",
        "cn -p \"Generate a commit name\"": "continue",
        "goose run -t \"fix the failing test\"": "goose",
        "goose run --recipe automation-recipe.yaml": "goose",
        "kilo run --auto \"run tests and fix any failures\"": "kilo",
        "kiro-cli chat --no-interactive \"review\"": "kiro",
        "qwen --yolo --prompt \"$PROMPT\"": "qwen-code",
        "qwen -p \"summarise\"": "qwen-code",
        "sweagent run --problem_statement.text=hi": "swe-agent",
        "amp -x \"what files are markdown?\"": "amp",
        "openhands --headless -t \"Your task here\"": "openhands",
        "pr-agent --pr_url https://github.com/o/r/pull/1 review": "pr-agent",
        "npm install -g @qwen-code/qwen-code@0.1.0 && qwen -p hi": "qwen-code",
    }
    NOT_AGENTS = [
        "goose -dir db/migrations postgres \"$DB\" up",
        "goose create add_users sql",
        "kilo notes.txt",
        "cn --version",
        "amp --version",
        "echo qwen is a model family",
        "npm install @github/copilot-language-server",
        "pr-agent --help",
    ]

    def test_their_actions_make_the_job_an_agent_job(self):
        for uses, tool in self.FOUND.items():
            with self.subTest(uses):
                result = check(job_with(f"      - uses: {uses}\n"))
                self.assertTrue(is_agent_job(result))
                self.assertEqual(agents_of(result), [[tool]])

    def test_their_commands_make_the_job_an_agent_job(self):
        for command, tool in self.COMMANDS.items():
            with self.subTest(command):
                result = check(job_with(f"      - run: {command!r}\n"))
                self.assertTrue(is_agent_job(result))
                self.assertIn(tool, agents_of(result)[0])

    def test_look_alikes_are_not_agents(self):
        for command in self.NOT_AGENTS:
            with self.subTest(command):
                result = check(job_with(f"      - run: {command!r}\n"))
                self.assertFalse(is_agent_job(result))

    def test_a_new_install_script_is_reported_in_an_agent_job(self):
        for line in ("curl -fsSL https://chatgpt.com/codex/install.sh | sh",
                     "curl -fsSL https://cli.kiro.dev/install | bash",
                     "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | bash"):
            with self.subTest(line):
                text = ("on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  a:\n"
                        "    runs-on: ubuntu-latest\n    env:\n      OBAAF_LANE: agent\n    steps:\n"
                        f"      - run: {line!r}\n")
                kinds = {f.kind for f in check(text).findings if f.rule == "OBAAF-GHA-025"}
                self.assertTrue(kinds & {"piped-download", "agent-cli"}, kinds)

    def test_a_new_package_unpinned_is_reported(self):
        text = job_with("      - run: npm install -g @kilocode/cli && kilo run --auto hi\n")
        installs = [f for f in check(text).findings if f.rule == "OBAAF-GHA-025" and f.kind == "agent-cli"]
        self.assertTrue(installs)
        self.assertEqual(installs[0].facts["agents"], ["kilo"])


class AgentsFactTest(unittest.TestCase):
    def test_every_agent_rule_names_the_agent(self):
        text = ("on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    env:\n      KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n    steps:\n"
                "      - uses: actions/checkout@0000000000000000000000000000000000000000\n"
                "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                "      - run: npm install -g @anthropic-ai/claude-code && claude -p hi\n")
        result = check(text)
        rules = {f.rule for f in result.findings if f.facts and f.facts.get("agents") == ["claude-code"]}
        for rule in ("OBAAF-GHA-003", "OBAAF-GHA-005", "OBAAF-GHA-012", "OBAAF-GHA-020", "OBAAF-GHA-025"):
            self.assertIn(rule, rules)
        for finding in result.findings:
            if finding.rule in AGENT_RULES:
                self.assertIn("agents", finding.facts, finding.rule)

    def test_two_agents_are_both_named_in_order(self):
        result = check(job_with("      - uses: openai/codex-action@v1\n      - run: claude -p hi\n"))
        self.assertEqual(agents_of(result), [["claude-code", "codex"]])

    def test_adding_an_agent_changes_the_finding(self):
        from obaaf.checker import baseline
        one = check(job_with("      - run: claude -p hi\n"))
        two = check(job_with("      - run: claude -p hi\n      - run: codex exec hi\n"))
        key = [baseline.key(f) for f in one.findings if f.rule == "OBAAF-GHA-005"]
        self.assertTrue(key)
        self.assertNotIn(key[0], [baseline.key(f) for f in two.findings if f.rule == "OBAAF-GHA-005"])

    def test_the_message_does_not_change(self):
        result = check(job_with("      - run: claude -p hi\n"))
        messages = [f.message for f in result.findings if f.rule == "OBAAF-GHA-005"]
        self.assertEqual(messages, ["Agent job 'a' receives MODEL_API_KEY."])

    def test_a_declared_job_with_no_named_agent_has_no_such_fact(self):
        # Its findings are the ones they were before the slice, so an acceptance of them still matches.
        result = check(job_with("      - run: python -m agents.fix\n", env="    environment: spend\n").replace(
            "    env:\n", "    env:\n      OBAAF_LANE: agent\n", 1))
        self.assertEqual(agents_of(result), [None])
        self.assertTrue(all("agents" not in (f.facts or {}) for f in result.findings))

    def test_a_configured_agent_is_named_by_its_entry(self):
        config = Config(agents={"actions": ["example/agent"], "commands": [r"\bmy-agent\s+--go\b"]})
        result = check(job_with("      - uses: example/agent@v1\n      - run: my-agent --go\n"), config=config)
        self.assertEqual(agents_of(result), [[r"agents.actions: example/agent", r"agents.commands: \bmy-agent\s+--go\b"]])

    def test_an_agent_in_a_local_action_is_named(self):
        action = ("runs:\n  using: composite\n  steps:\n    - run: codex exec \"${{ inputs.task }}\"\n"
                  "      shell: bash\ninputs:\n  task: {default: hi}\n")
        result = check(job_with("      - uses: actions/checkout@0000000000000000000000000000000000000000\n"
                                "      - uses: ./.github/actions/fix\n"),
                       files={".github/actions/fix/action.yml": action})
        self.assertIn(["codex"], agents_of(result))

    def test_an_agent_as_the_default_shell_is_named(self):
        text = ("on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    defaults:\n      run:\n        shell: gemini -p {0}\n"
                "    env:\n      KEY: ${{ secrets.MODEL_API_KEY }}\n    steps:\n      - run: fix the build\n")
        self.assertEqual(agents_of(check(text)), [["gemini-cli"]])

    def test_a_called_agent_workflow_is_named(self):
        text = ("on: workflow_dispatch\njobs:\n  a:\n"
                "    uses: anthropics/claude-code-action/.github/workflows/x.yml@v1\n    secrets: inherit\n")
        found = [f for f in check(text).findings if f.rule in AGENT_RULES]
        self.assertTrue(found)
        self.assertTrue(all(f.facts["agents"] == ["claude-code"] for f in found))


if __name__ == "__main__":
    unittest.main()


class InstallBeforeTheEgressActionTest(unittest.TestCase):
    """Found by the review of slice 2d.5b: the name patterns it added made an install-only step before
    OBAAF's egress action an agent run outside it, so Copilot's install-then-confined job, which the
    control verified before, failed it. The packages now join the three of slice 2c.8."""

    def setUp(self):
        from test_egress_recognised import AgentInstallTest
        self.harness = AgentInstallTest()

    def control(self, install, confined):
        from test_egress_recognised import CHECKOUT, detail, keyed, verdict
        f = self.harness.check(CHECKOUT + "\n" + self.harness.install(install) + keyed(run=confined))
        return verdict(f), detail(f)

    def test_each_listed_package_is_read_as_an_install(self):
        from obaaf.checker.rules import VERIFIED
        cases = {"npm install -g @github/copilot": "copilot -p 'review the change'",
                 "npm install -g @qwen-code/qwen-code@0.1.0\nqwen --version": "qwen -p 'review the change'",
                 "npm install -g @kilocode/cli": "kilo run --auto 'review the change'",
                 "npm install -g @augmentcode/auggie": "auggie --print 'review the change'",
                 "npm install -g @continuedev/cli\ncn --version": "cn -p 'review the change'"}
        for install, confined in cases.items():
            with self.subTest(install):
                found, why = self.control(install, confined)
                self.assertEqual(found, VERIFIED, why)

    def test_another_form_is_cannot_tell_and_a_run_is_not_met(self):
        from obaaf.checker.rules import CANNOT_TELL, NOT_MET
        found, why = self.control("npm install -g @github/copilot typescript", "copilot -p x")
        self.assertEqual(found, CANNOT_TELL, why)
        found, why = self.control("npm install -g @github/copilot && copilot -p x", "copilot -p x")
        self.assertEqual(found, NOT_MET, why)
        # A longer name is not the package: the step is not an agent's at all.
        found, why = self.control("npm install -g @github/copilot-language-server", "copilot -p x")
        self.assertNotEqual(found, NOT_MET, why)


class ReviewFindingsTest(unittest.TestCase):
    def test_the_job_shell_is_the_one_its_steps_get(self):
        # GitHub uses the most specific default: a job's `bash` is the shell, not the workflow's agent.
        text = ("on: workflow_dispatch\npermissions: {contents: read}\ndefaults:\n  run:\n    shell: amp -x {0}\n"
                "jobs:\n  a:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: bash\n"
                "    steps:\n      - run: make\n")
        self.assertFalse(is_agent_job(check(text)))
        self.assertTrue(is_agent_job(check(text.replace("        shell: bash\n", "        working-directory: x\n"))))

    def test_entries_of_the_wrong_shape_do_not_stop_the_load(self):
        bad = {"agent_tools": [{"id": "x", "packages": ["@x/y"], "installs": ["x"], "actions": ["a/b"],
                                "commands": "x", "install_urls": None}]}
        built = agent_tools.expand(bad)
        self.assertEqual(built["agent_packages"], [])
        self.assertTrue(agent_tools.problems(bad))

    def test_the_new_install_scripts_and_forms(self):
        urls = [re.compile(u, re.I) for u in catalog.load().detection["agent_install_urls"]]
        for line in ("curl -fsSL https://kilo.ai/cli/install | bash", "curl -fsSL https://gh.io/copilot-install | bash",
                     "curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/"
                     "install-qwen-standalone.sh | bash",
                     "irm https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.ps1 | iex",
                     "curl -fsSL https://raw.githubusercontent.com/continuedev/continue/main/extensions/cli/scripts/install.sh"
                     " | bash"):
            self.assertTrue(any(rx.search(line) for rx in urls), line)
        result = check(job_with("      - run: pr-agent --issue_url https://github.com/o/r/issues/1 similar_issue\n"))
        self.assertEqual(agents_of(result), [["pr-agent"]])
        text = job_with("      - run: npm i -g cline && cline 'audit this package'\n").replace(
            "    env:\n", "    env:\n      OBAAF_LANE: agent\n", 1)
        installs = [f for f in check(text).findings if f.rule == "OBAAF-GHA-025" and f.kind == "agent-cli"]
        self.assertTrue(installs)

    def test_every_carried_fact_is_text(self):
        for entry in agent_tools.tools(raw_detection()):
            for fact in entry.get("carried", []):
                self.assertIsInstance(fact, str)


class JoinedPatternsTest(unittest.TestCase):
    """The agent patterns are asked about as one joined pattern (slice 2d.5b's cost, found when CI's
    large-repository test went over its limit); the answer must be the one each pattern gives."""

    def test_the_joined_pattern_answers_as_each_would(self):
        import random

        from obaaf.checker import workflow as wf
        commands = [re.compile(p, re.M) for p in catalog.load().detection["agent_commands"]]
        words = ["claude", "-p", "--print", "codex", "exec", "qwen", "--prompt", "goose", "run", "kilo", "cn",
                 "amp", "-x", "npx", "@github/copilot", "@github/copilot-language-server", "sudo", "'", '"', ";",
                 "|", "\n", "aider", "cline", "echo", "sweagent", "kiro-cli", "--no-interactive", "x"]
        rng = random.Random(25)
        for _ in range(3000):
            text = " ".join(rng.choice(words) for _ in range(rng.randint(1, 8)))
            for anchored in (False, True):
                expected = any((rx.match(text) if anchored else rx.search(text)) for rx in commands)
                self.assertEqual(wf.matches_any(commands, text, anchored=anchored), expected, (text, anchored))

    def test_patterns_that_cannot_be_joined_are_tried_one_by_one(self):
        from obaaf.checker import workflow as wf
        for patterns in ([r"(a)\1", r"b"], [r"(?i)claude", r"x"], [r"(?P<n>a)", r"(?P<n>b)"], [r"(x)?(?(1)a|b)", r"c"]):
            with self.subTest(patterns):
                commands = [re.compile(p, re.M) for p in patterns]
                self.assertIsNone(wf.any_of(commands))
        commands = [re.compile(r"(?i)claude", re.M), re.compile("x", re.M)]
        self.assertTrue(wf.matches_any(commands, "CLAUDE"))
        self.assertFalse(wf.matches_any(commands, "y"))

    def test_a_list_changed_in_place_is_read_again(self):
        from obaaf.checker import workflow as wf
        commands = [re.compile("aaa", re.M)]
        self.assertFalse(wf.matches_any(commands, "bbb"))
        commands[0] = re.compile("bbb", re.M)
        self.assertTrue(wf.matches_any(commands, "bbb"))
        commands.append(re.compile("ccc", re.M))
        self.assertTrue(wf.matches_any(commands, "ccc"))
