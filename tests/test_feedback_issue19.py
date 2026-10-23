"""Pilot feedback (issue #19): the checker should warn when an agent is likely
run but left in the trusted lane, let a repo declare indirect agent entry points,
and separate authority findings from hygiene findings so the latter do not bury
the former.
"""

import json
import unittest

from helpers import RISKY, ROOT, TempDir, run_cli

from obaaf import checker
from obaaf.catalog import load
from obaaf.checker import report

SHA = "1" * 40


def _write_repo(tmp, workflow, config=None, instruction="AGENTS.md"):
    (tmp / ".github" / "workflows").mkdir(parents=True)
    if instruction:
        (tmp / instruction).write_text("# Agent instructions\nBe helpful.\n", encoding="utf-8")
    (tmp / ".github" / "workflows" / "ci.yml").write_text(workflow, encoding="utf-8")
    if config is not None:
        (tmp / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")


WRAPPER_JOB = ("on: issue_comment\npermissions: {}\njobs:\n  triage:\n    runs-on: ubuntu-latest\n"
               "    permissions: {contents: write}\n    steps:\n      - run: bash scripts/run-agent.sh\n")


class LaneNotesTest(unittest.TestCase):
    def test_instruction_files_without_an_agent_lane_emit_a_note(self):
        with TempDir() as tmp:
            _write_repo(tmp, WRAPPER_JOB)
            notes = checker.check(tmp).notes
            self.assertTrue(any("no workflow job was classified into the agent lane" in n for n in notes), notes)
            self.assertTrue(any("agents.commands" in n for n in notes), notes)

    def test_agents_commands_config_catches_a_wrapper_script(self):
        with TempDir() as tmp:
            _write_repo(tmp, WRAPPER_JOB, config="agents:\n  commands:\n    - 'run-agent\\.sh'\n")
            result = checker.check(tmp)
            # The wrapper job is now in the agent lane...
            self.assertTrue(any(lane == "agent" for _, _, lane, _ in checker.lanes(tmp)))
            # ...so the agent-authority rule for a write token fires...
            self.assertIn("OBAAF-GHA-003", {f.rule for f in result.findings})
            # ...and the "no agent lane" note is gone.
            self.assertFalse(any("no workflow job was classified into the agent lane" in n for n in result.notes),
                             result.notes)

    def test_no_note_when_an_agent_lane_is_present(self):
        wf = ("on: issue_comment\npermissions: {}\njobs:\n  triage:\n    runs-on: ubuntu-latest\n"
              "    permissions: {contents: read}\n    steps:\n"
              f"      - uses: anthropics/claude-code-action@{SHA}\n")
        with TempDir() as tmp:
            _write_repo(tmp, wf)
            self.assertEqual(checker.check(tmp).notes, [])

    def test_a_trusted_job_named_like_an_agent_is_flagged(self):
        wf = ("on: push\npermissions: {}\njobs:\n  ai-review:\n    runs-on: ubuntu-latest\n"
              "    permissions: {contents: read}\n    steps:\n      - run: ./review.sh\n")
        with TempDir() as tmp:
            _write_repo(tmp, wf, instruction=None)
            notes = checker.check(tmp).notes
            self.assertTrue(any("suggests agent work but stayed in the trusted lane" in n for n in notes), notes)


class CategoryTest(unittest.TestCase):
    def test_every_rule_declares_a_valid_category(self):
        for rid, rule in load().rules.items():
            with self.subTest(rule=rid):
                self.assertIn(rule.get("category"), ("authority", "hygiene"))

    def test_pinning_is_hygiene_and_agent_write_is_authority(self):
        rules = load().rules
        self.assertEqual(rules["OBAAF-GHA-008"]["category"], "hygiene")
        self.assertEqual(rules["OBAAF-GHA-020"]["category"], "hygiene")
        self.assertEqual(rules["OBAAF-GHA-003"]["category"], "authority")

    def test_text_summary_splits_authority_from_hygiene(self):
        out = report.to_text(checker.check(RISKY / "pwn-request.yml"))
        self.assertIn("Authority findings:", out)
        self.assertIn("Hygiene findings:", out)

    def test_json_findings_carry_a_category(self):
        data = json.loads(report.to_json(checker.check(RISKY / "nx-title-injection.yml")))
        self.assertTrue(data["findings"])
        self.assertTrue(all(f["category"] in ("authority", "hygiene") for f in data["findings"]))
        self.assertIn("notes", data)

    def test_sarif_rules_carry_a_category(self):
        sarif = json.loads(report.to_sarif(checker.check(RISKY / "nx-title-injection.yml")))
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            self.assertIn(rule["properties"]["obaaf-category"], ("authority", "hygiene"))


class ConfigurationGuideTest(unittest.TestCase):
    def test_configuration_guide_exists_and_is_linked(self):
        self.assertTrue((ROOT / "docs" / "checker-configuration.md").is_file())
        self.assertIn("docs/checker-configuration.md", (ROOT / "spec" / "checker-rules.md").read_text())


class FailOnCategoryTest(unittest.TestCase):
    # GHA-001 (authority, high), GHA-008 (hygiene, medium), GHA-011 (authority, medium).
    WF = ("on: issue_comment\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
          "    permissions: {contents: read}\n    steps:\n      - uses: actions/checkout@v4\n"
          "      - run: ./deploy.sh\n        env: {TOKEN: '${{ secrets.DEPLOY }}'}\n")

    def _exit(self, tmp, spec):
        path = tmp / "wf.yml"
        path.write_text(self.WF, encoding="utf-8")
        return run_cli("check", path, "--fail-on", spec)[0]

    def test_authority_gate_ignores_the_pinning_noise(self):
        with TempDir() as tmp:
            self.assertEqual(self._exit(tmp, "authority:high"), 1)   # the real problem fails the gate
            self.assertEqual(self._exit(tmp, "hygiene:high"), 0)     # pinning noise alone does not

    def test_category_bare_and_never_forms(self):
        with TempDir() as tmp:
            self.assertEqual(self._exit(tmp, "hygiene:medium"), 1)
            self.assertEqual(self._exit(tmp, "authority"), 1)
            self.assertEqual(self._exit(tmp, "never"), 0)

    def test_plain_severity_is_unchanged(self):
        with TempDir() as tmp:
            self.assertEqual(self._exit(tmp, "high"), 1)

    def test_invalid_fail_on_is_a_usage_error(self):
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(self.WF, encoding="utf-8")
            code, _, err = run_cli("check", path, "--fail-on", "bogus")
            self.assertEqual(code, 2)
            self.assertIn("fail-on", err)


if __name__ == "__main__":
    unittest.main()
