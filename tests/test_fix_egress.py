"""Exercise the offline draft through the CLI with a catalogue-local release."""
import dataclasses
import unittest
from unittest.mock import patch

from helpers import TempDir, run_cli
from obaaf.catalog import load

SHA = "c" * 40
STEP = """      - name: Review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.MODEL }}
          REVIEW_KEY: ${{ secrets.OTHER }}
        run: claude -p review
"""
WORKFLOW = """on: workflow_dispatch
permissions: {}
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
"""


class EgressDraftTests(unittest.TestCase):
    def draft(self, root):
        cat = load()
        cat = dataclasses.replace(cat, detection={**cat.detection, "egress_action_releases": [SHA]})
        with patch("obaaf.fix_egress.load", return_value=cat):
            return run_cli("fix", "egress", "--job", "review", root)

    def workflow(self, root, step=STEP):
        directory = root / ".github/workflows"
        directory.mkdir(parents=True)
        path = directory / "review.yml"
        path.write_text(WORKFLOW + step)
        return path

    def test_unlisted_stops_before_reading_path(self):
        code, out, _ = run_cli("fix", "egress", "--job", "review", "absent")
        self.assertEqual(code, 0)
        self.assertIn("No released commit", out)

    def test_key_placement_and_real_checker_verdicts(self):
        with TempDir() as root:
            path = self.workflow(root)
            original = path.read_bytes()
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertEqual(path.read_bytes(), original)
            for item in (SHA, "model-keys: ANTHROPIC_API_KEY", "env: REVIEW_KEY", "api.anthropic.com",
                         "OBAAF-GHA-005:", "not met", "verified", "denied", "subdomains", "If you adopt", ".invalid", "secrets.OTHER is passed"):
                self.assertIn(item, out)

    def test_install_then_agent_wraps_only_the_agent(self):
        with TempDir() as root:
            self.workflow(root, "      - run: npm install -g @anthropic-ai/claude-code@2.0.0\n" + STEP)
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertIn("- run: npm install -g @anthropic-ai/claude-code@2.0.0", out)
            self.assertIn("run: claude -p review", out)

    def test_later_step_needs_split(self):
        with TempDir() as root:
            self.workflow(root, STEP + "      - run: echo completed\n")
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertIn("Split later", out)
            self.assertIn("cannot tell", out)
            self.assertIn("echo completed", out)

    def test_ambiguous_and_non_run_steps(self):
        with TempDir() as root:
            path = self.workflow(root, STEP * 2)
            self.assertIn("exactly one", self.draft(root)[2])
            path.with_name("second.yml").write_bytes(path.read_bytes())
            self.assertIn("2 workflows", self.draft(root)[2])
        with TempDir() as root:
            self.workflow(root, "      - uses: anthropics/claude-code-action@v1\n")
            self.assertIn("ordinary run step", self.draft(root)[2])

    def test_all_unmet_conditions_are_shown_even_when_checker_summary_is_short(self):
        with TempDir() as root:
            path = self.workflow(root, STEP + "".join(
                f"      - name: follow-{n}\n        run: echo done\n" for n in range(5)))
            path.write_text(path.read_text().replace("ubuntu-24.04", "ubuntu-latest")
                            .replace("permissions: {}", "permissions: {id-token: write, models: read}"))
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            details = out.split("Conditions still requiring work on the egress action:")[1].split("\nreview:")[0]
            for reason in ("OIDC", "GitHub Models", "ubuntu-latest", "follow-0", "follow-4"):
                self.assertIn(reason, details)

    def test_other_provider_without_model_key(self):
        with TempDir() as root:
            self.workflow(root, STEP.replace("ANTHROPIC_API_KEY", "OTHER_PROVIDER_KEY"))
            code, out, err = self.draft(root)
            self.assertEqual(code, 0, err)
            self.assertIn("env: OTHER_PROVIDER_KEY REVIEW_KEY", out)
            self.assertIn("OBAAF-GHA-020: fixed", out)
            self.assertIn("secrets.MODEL is passed to the command", out)

    def test_no_apply(self):
        self.assertEqual(run_cli("fix", "egress", "--job", "review", "--apply")[0], 2)
