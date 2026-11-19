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

    def test_an_install_reached_through_a_yaml_alias_is_manual(self):
        # One edit under the anchor changes every step that reaches it (review of #258).
        jobs = {
            "a": "      - run: &install npm install -g @anthropic-ai/claude-code\n",
            "b": "      - run: *install\n",
            "c": "      - &step {run: npm install -g @openai/codex}\n",
            "d": "      - *step\n",
            "e": "      - <<: *step\n        name: Merged\n",
            "f": "      - run: npm install -g @openai/codex\n",
        }
        workflow = "on: push\njobs:\n" + "".join(
            f"  {name}:\n    runs-on: ubuntu-latest\n    env: {{OBAAF_LANE: agent}}\n    steps:\n{step}"
            for name, step in jobs.items())
        found = sorted(findings(check(workflow)), key=lambda f: f.job)
        self.assertEqual([f.job for f in found], list(jobs))
        self.assertEqual([f.pin_candidate for f in found], [None] * 5 + ["@openai/codex"])

    def test_a_windows_runner_without_a_shell_is_manual(self):
        # GitHub's default shell on Windows is PowerShell, as OBAAF-GHA-025 itself reads it.
        for runs_on, shell, expected in (("windows-latest", "", None),
                                         ("windows-latest", "        shell: bash\n", "@openai/codex"),
                                         ("ubuntu-latest", "", "@openai/codex")):
            workflow = (f"on: push\njobs:\n  a:\n    runs-on: {runs_on}\n    env: {{OBAAF_LANE: agent}}\n"
                        f"    steps:\n      - run: npm install -g @openai/codex\n{shell}")
            with self.subTest(runs_on=runs_on, shell=shell):
                finding, = findings(check(workflow))
                self.assertEqual(finding.pin_candidate, expected)

    def test_an_aliased_list_of_steps_is_manual(self):
        workflow = ("on: push\njobs:\n"
                    "  a:\n    runs-on: ubuntu-latest\n    env: {OBAAF_LANE: agent}\n"
                    "    steps: &l\n      - run: npm install -g @anthropic-ai/claude-code\n"
                    "  b:\n    runs-on: ubuntu-latest\n    env: {OBAAF_LANE: agent}\n    steps: *l\n")
        found = findings(check(workflow))
        self.assertEqual(sorted(f.job for f in found), ["a", "b"])
        self.assertTrue(all(f.pin_candidate is None for f in found))


class SharedValueLoaderTest(unittest.TestCase):
    def test_a_recursive_alias_is_refused_at_once(self):
        # Marking stops at a node already marked; without that, this document would never finish
        # composing. Run in a child process so a hang fails the test instead of the suite.
        import os
        from pathlib import Path
        import subprocess
        import sys
        src = Path(__file__).resolve().parent.parent / "src"
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(src), os.environ.get("PYTHONPATH")]))}
        code = ("from obaaf import yamlutil\n"
                "try:\n    yamlutil.load('a: &a [*a]\\nb: *a\\n')\n"
                "except Exception as exc:\n    print(type(exc).__name__)\n")
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(done.stdout.strip(), "ConstructorError", done.stderr)

    def test_shared_keys_name_only_values_reached_from_more_than_one_place(self):
        from obaaf import yamlutil
        data = yamlutil.load("a: {run: &r x, other: y}\nb: {run: *r}\nc: {run: x}\n")
        self.assertEqual((data["a"].shared_keys, data["b"].shared_keys, data["c"].shared_keys),
                         ({"run"}, {"run"}, set()))
        self.assertEqual(data["a"]["run"], "x")
