"""Pin guidance uses literal source evidence, independent of finding identity."""
import unittest
from dataclasses import replace

from obaaf.checker.baseline import identity
from test_agent_tool_installs import agent_job, check, findings


class PinCandidateTest(unittest.TestCase):
    def test_direct_npm_install(self):
        finding, = findings(check(agent_job("- run: npm install -g @anthropic-ai/claude-code\n")))
        self.assertEqual(finding.pin_candidate, "@anthropic-ai/claude-code")
        manual = replace(finding, pin_candidate=None)
        self.assertEqual(manual, finding)
        self.assertEqual(identity(manual), identity(finding))
        self.assertNotIn("pin_candidate", finding.facts)

    def test_install_then_query_on_its_own_line(self):
        # Both adopter steps use the sudo spelling and the same separate version query.
        for prefix in ("sudo ", ""):
            with self.subTest(prefix=prefix):
                body = f"- run: |\n    {prefix}npm install -g @anthropic-ai/claude-code\n    claude --version\n"
                finding, = findings(check(agent_job(body)))
                self.assertEqual(finding.pin_candidate, "@anthropic-ai/claude-code")

    def test_indirect_and_multicommand_steps_are_manual(self):
        pkg = "@anthropic-ai/claude-code"
        command = f"npm install -g {pkg}"
        for body in (
            f"- run: npx {pkg}\n",
            f"- run: {command} && claude --version\n",
            f"- run: sudo {command}\n",
            f"- run: |\n    sudo {command}\n    codex --version\n",
            f"- run: |\n    sudo {command}\n    claude --version > version.txt\n",
            f"- run: |\n    sudo {command}\n    claude --version\n    echo done\n",
            f"- run: |\n    sudo -E {command}\n    claude --version\n",
            f"- run: |\n    sudo {command}\n    alias claude=other\n    claude --version\n",
            f"- run: {command} @openai/codex\n",
            f"- run: {command}@latest\n",
            f"- run: {command}\n  shell: python\n",
            f"- run: |\n    NAME={pkg}\n    npm install -g \"$NAME\"\n",
            "- run: curl -fsSL https://example.test/install.sh | bash\n",
            f"- uses: docker://example\n  with:\n    entrypoint: npm\n    args: install -g {pkg}\n",
        ):
            with self.subTest(body=body):
                found = findings(check(agent_job(body)))
                self.assertTrue(found)
                self.assertTrue(all(f.pin_candidate is None for f in found))

    def test_workflow_checked_with_caller_inputs_is_manual(self):
        caller = ("on: workflow_dispatch\njobs:\n  call:\n    uses: ./.github/workflows/tool.yml\n"
                  "    with: {package: '@openai/codex'}\n")
        callee = ("on:\n  workflow_call:\n    inputs:\n      package: {type: string}\n"
                  "jobs:\n  a:\n    runs-on: ubuntu-latest\n    env: {OBAAF_LANE: agent}\n"
                  "    steps:\n      - run: npm install -g @openai/codex\n        name: ${{ inputs.package }}\n")
        found = findings(check(caller, {".github/workflows/tool.yml": callee}))
        self.assertTrue(found)
        self.assertTrue(all(f.pin_candidate is None for f in found))

    def test_composite_install_is_manual(self):
        action = "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: npm install -g @openai/codex\n"
        result = check(agent_job("- uses: ./.github/actions/tool\n"),
                       {".github/actions/tool/action.yml": action})
        finding, = findings(result)
        self.assertIsNone(finding.pin_candidate)
