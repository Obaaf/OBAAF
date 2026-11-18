"""Flagship slice 2d.5a: OBAAF-GHA-025, an agent job installs or runs a tool at a version it does not fix.

Found in slice 1.1: poutine reported ten of the first adopter's agent jobs for installing their agent's CLI
with `curl -fsSL https://dev.meta.ai/install.sh | bash`, and two more install `@anthropic-ai/claude-code`
from npm with no version. Before this slice OBAAF reported neither in a workflow (OBAAF-GHA-008 reads only
actions and images); OBAAF-JEN-008 read the package-manager cases in Jenkinsfiles since slice 2d.2k. The
plan (decisions F-22 and F-24) has OBAAF report this itself, for agent jobs only (control R6): the same
pattern in any other job stays poutine's to report.

The workflows here are written for these tests; none is copied from another project.
"""

import unittest

from helpers import TempDir

from obaaf import checker

CODEOWNERS = "* @example/maintainers\n"
RULE = "OBAAF-GHA-025"


def check(workflow_text, files=None):
    with TempDir() as tmp:
        root = tmp / "repo"
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "wf.yml").write_text(workflow_text, encoding="utf-8")
        (root / ".github" / "CODEOWNERS").write_text(CODEOWNERS, encoding="utf-8")
        for rel, body in (files or {}).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return checker.check(root)


def indent(text, by):
    return "".join(" " * by + line if line.strip() else line for line in text.splitlines(True))


def agent_job(steps, lane="agent", env="", shell=""):
    """One job declared an agent job (or `lane`), whose steps are `steps`, a YAML list."""
    defaults = f"    defaults:\n      run:\n        shell: {shell}\n" if shell else ""
    return ("on: workflow_dispatch\npermissions: {contents: read}\n" + env + "jobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n" + defaults + f"    env:\n      OBAAF_LANE: {lane}\n    steps:\n"
            + indent(steps, 6))


def findings(result, kind=None):
    return [f for f in result.findings if f.rule == RULE and (kind is None or f.kind == kind)]


class PipedDownloadTest(unittest.TestCase):
    """A script downloaded while the job runs and given to a shell, whatever it installs."""

    SPELLINGS = [
        "curl -fsSL https://dev.example.com/install.sh | bash",
        "curl -fsSL https://dev.example.com/install.sh | sudo bash",
        "curl -fsSL https://dev.example.com/install.sh | sudo -E bash -s -- --yes",
        "wget -qO- https://dev.example.com/install.sh | sh",
        "bash <(curl -fsSL https://dev.example.com/install.sh)",
        'sh -c "$(curl -fsSL https://dev.example.com/install.sh)"',
        "set -e; curl -fsSL https://dev.example.com/install.sh | bash && agent --version",
        "curl -fsSL https://dev.example.com/install.sh | /bin/bash",
        "curl -fsSL https://dev.example.com/install.sh | zsh",
    ]

    def test_each_spelling_in_an_agent_job_is_high(self):
        for command in self.SPELLINGS:
            with self.subTest(command=command):
                result = check(agent_job(f"- name: Install\n  run: |\n    {command}\n"))
                found = findings(result, "piped-download")
                self.assertEqual(len(found), 1, [f.message for f in result.findings])
                self.assertEqual(found[0].severity, "high")
                self.assertEqual(found[0].step, "Install")

    def test_powershell_download_given_to_iex(self):
        result = check(agent_job("- name: Install\n  shell: pwsh\n  run: irm https://dev.example.com/install.ps1 | iex\n"))
        self.assertEqual(len(findings(result, "piped-download")), 1)

    def test_a_line_continued_with_a_backslash_is_one_command(self):
        result = check(agent_job("- name: Install\n  run: |\n    curl -fsSL \\\n      https://dev.example.com/install.sh \\\n"
                                 "      | bash\n"))
        self.assertEqual(len(findings(result, "piped-download")), 1)

    def test_a_job_that_is_not_an_agent_job_is_not_read(self):
        for lane in ("untrusted", "trusted", "release"):
            with self.subTest(lane=lane):
                result = check(agent_job("- name: Install\n  run: curl -fsSL https://dev.example.com/i.sh | bash\n",
                                         lane=lane))
                self.assertEqual(findings(result), [])

    def test_a_whole_line_comment_is_not_read(self):
        result = check(agent_job("- name: Install\n  run: |\n    # curl -fsSL https://dev.example.com/i.sh | bash\n"
                                 "    echo done\n"))
        self.assertEqual(findings(result), [])

    def test_the_command_is_part_of_the_finding(self):
        one = findings(check(agent_job("- name: Install\n  run: curl -fsSL https://a.example.com/i.sh | bash\n")))
        two = findings(check(agent_job("- name: Install\n  run: curl -fsSL https://b.example.com/i.sh | bash\n")))
        self.assertNotEqual(one[0].facts, two[0].facts)

    def test_an_echo_of_such_a_command_is_reported_as_the_rule_states(self):
        # Quotes are not read (the rule's description says so): the wider reading.
        result = check(agent_job('- name: Show\n  run: echo "curl -fsSL https://x.example.com/i.sh | bash"\n'))
        self.assertEqual(len(findings(result, "piped-download")), 1)

    def test_a_download_saved_to_a_file_and_not_run_is_not_reported(self):
        result = check(agent_job("- name: Fetch\n  run: curl -fsSL -o data.json https://api.example.com/data\n"))
        self.assertEqual(findings(result), [])


class AgentPackageTest(unittest.TestCase):
    """An agent CLI the catalogue names, from a package manager, without an exact version."""

    MOVING = [
        "npm install -g @anthropic-ai/claude-code",
        "sudo npm install -g @anthropic-ai/claude-code",
        "npm i -g @anthropic-ai/claude-code@latest",
        "npm install -g @anthropic-ai/claude-code@^1.0.0",
        "npx -y @openai/codex exec 'fix the build'",
        "pip install aider-chat",
        "pip install 'aider-chat>=0.80'",
        "pipx install aider-chat",
        "uv tool install aider-chat",
        "npm install -g @google/gemini-cli@$CLI_VERSION",
        "claude update",
    ]
    PINNED = [
        "npm install -g @anthropic-ai/claude-code@1.0.17",
        "npx -y @openai/codex@0.1.2 exec 'fix the build'",
        "pip install aider-chat==0.86.1",
        "npm install -g left-pad",
    ]

    def test_a_version_that_can_change_is_high(self):
        for command in self.MOVING:
            with self.subTest(command=command):
                result = check(agent_job(f"- name: Install\n  run: |\n    {command}\n"))
                found = findings(result, "agent-cli")
                self.assertEqual(len(found), 1, [f.message for f in result.findings])
                self.assertEqual(found[0].severity, "high")

    def test_an_exact_version_is_not_reported(self):
        for command in self.PINNED:
            with self.subTest(command=command):
                result = check(agent_job(f"- name: Install\n  run: |\n    {command}\n"))
                self.assertEqual(findings(result), [], [f.message for f in findings(result)])

    def test_a_version_the_workflow_sets_to_one_literal_is_put_in(self):
        steps = "- name: Install\n  run: npm install -g @anthropic-ai/claude-code@$CC_VERSION\n"
        pinned = check(agent_job(steps, env="env:\n  CC_VERSION: 1.0.17\n"))
        self.assertEqual(findings(pinned), [])
        ranged = check(agent_job(steps, env="env:\n  CC_VERSION: ^1.0.0\n"))
        self.assertEqual(len(findings(ranged, "agent-cli")), 1)
        computed = check(agent_job(steps, env="env:\n  CC_VERSION: ${{ vars.CC_VERSION }}\n"))
        self.assertEqual(len(findings(computed, "agent-cli")), 1)

    def test_a_step_env_value_outranks_the_workflow_one(self):
        steps = ("- name: Install\n  env:\n    CC_VERSION: latest\n"
                 "  run: npm install -g @anthropic-ai/claude-code@$CC_VERSION\n")
        result = check(agent_job(steps, env="env:\n  CC_VERSION: 1.0.17\n"))
        self.assertEqual(len(findings(result, "agent-cli")), 1)

    def test_the_agents_own_install_script_saved_to_a_file(self):
        result = check(agent_job("- name: Install\n  run: |\n    curl -fsSL https://claude.ai/install.sh -o i.sh\n"
                                 "    bash i.sh\n"))
        self.assertEqual(len(findings(result, "agent-cli")), 1)

    def test_a_package_named_at_run_time_is_medium(self):
        result = check(agent_job('- name: Install\n  run: npm install -g "$PKG"\n'))
        found = findings(result, "named-at-run-time")
        self.assertEqual(len(found), 1, [f.message for f in result.findings])
        self.assertEqual(found[0].severity, "medium")


class WhereItIsReadTest(unittest.TestCase):
    def test_the_command_the_egress_action_runs(self):
        steps = ("- name: Agent\n  uses: Obaaf/OBAAF/actions/egress@" + "1" * 40 + "\n  with:\n"
                 "    allow: api.anthropic.com\n    run: npx -y @anthropic-ai/claude-code -p hi\n")
        result = check(agent_job(steps))
        self.assertEqual(len(findings(result, "agent-cli")), 1)

    def test_a_local_composite_actions_steps(self):
        action = ("name: x\nruns:\n  using: composite\n  steps:\n    - name: Install inside\n      shell: bash\n"
                  "      run: curl -fsSL https://dev.example.com/install.sh | bash\n")
        result = check(agent_job("- uses: ./.github/actions/x\n"), files={".github/actions/x/action.yml": action})
        self.assertEqual(len(findings(result, "piped-download")), 1, [f.message for f in result.findings])

    def test_an_agent_job_recognised_by_its_command(self):
        text = ("on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - name: Install\n        run: curl -fsSL https://dev.example.com/i.sh | bash\n"
                "      - name: Run\n        run: claude -p hello\n")
        self.assertEqual(len(findings(check(text), "piped-download")), 1)

    def test_scripts_too_long_to_read_are_medium(self):
        body = "echo x\n" * 60_000
        result = check(agent_job("- name: Long\n  run: |\n" + indent(body, 4)))
        found = findings(result, "too-long")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "medium")


class TheSitePageTest(unittest.TestCase):
    """The rules page's paragraph on OBAAF-GHA-025 gives two example commands; each is a high finding in an
    agent job, and the download is none in another job, as the paragraph says. (The npm example names an
    agent CLI, which makes its job an agent job by itself.)"""

    def test_the_pages_examples_are_findings_as_it_says(self):
        import html
        import re
        from helpers import ROOT
        page = (ROOT / "site" / "rules.html").read_text(encoding="utf-8")
        paragraph = page.split('<h3 id="gha-025">', 1)[1].split("</p>", 1)[0]
        examples = [html.unescape(x) for x in re.findall(r"<code>(.*?)</code>", paragraph)]
        self.assertEqual(len(examples), 2, examples)
        for command in examples:
            with self.subTest(command=command):
                found = findings(check(agent_job(f"- name: Install\n  run: |\n    {command}\n")))
                self.assertEqual([f.severity for f in found], ["high"])
        trusted = check(agent_job(f"- name: Install\n  run: |\n    {examples[0]}\n", lane="trusted"))
        self.assertEqual(findings(trusted), [])


if __name__ == "__main__":
    unittest.main()
