import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from obaaf import cli
from obaaf.checker import Config
from obaaf.init import WORKFLOW


class InitTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.config = self.root / ".github/obaaf.yml"
        self.workflow = self.root / WORKFLOW

    def invoke(self, *options):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = cli.main(["init", str(self.root), *options])
        return status, stdout.getvalue() + stderr.getvalue()

    def test_preview_apply_repeat(self):
        status, text = self.invoke()
        self.assertEqual(status, 0, text)
        self.assertIn("GitHub Agentic Workflows", text)
        self.assertIn("+++ .github/obaaf.yml", text)
        self.assertIn("+++ " + WORKFLOW, text)
        self.assertEqual(list(self.root.iterdir()), [])
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        self.assertEqual(Config.load(self.root).lanes, {})
        workflow = yaml.safe_load(self.workflow.read_bytes())
        steps = workflow["jobs"]["check"]["steps"]
        self.assertIn("--fail-on never", steps[-1]["run"])
        for step in steps:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(self.invoke("--apply")[1].count("Already matches"), 2)

    def test_jobs_secrets_and_ambiguous_environments(self):
        dest = self.workflow.with_name("jobs.yml")
        dest.parent.mkdir(parents=True)
        dest.write_text("""on: push
jobs:
  ai:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: openai/codex-action@v1
        env:
          OPENAI_API_KEY: ${{ secrets.PRIVATE_MODEL }}
          DEPLOY: ${{ secrets.DEPLOY_TOKEN }}
  custom:
    runs-on: ubuntu-latest
    env:
      KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      DEPLOY: ${{ secrets.deploy_token }}
    steps: []
""")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        config = Config.load(self.root)
        self.assertEqual(config.protected_secrets, {"PRIVATE_MODEL": "production"})
        self.assertEqual(config.lanes, {".github/workflows/jobs.yml#ai": "agent",
                                        ".github/workflows/jobs.yml#custom": "agent"})
        self.assertIn("Review DEPLOY_TOKEN", text)
        self.assertIn("Review ANTHROPIC_API_KEY", text)
        self.assertIn("codex", text.lower())

    def test_conflicts_in_either_file_stop_both_writes(self):
        for target, other in [(self.workflow, self.config), (self.config, self.workflow)]:
            with self.subTest(target=target):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("custom\n")
                status, text = self.invoke("--apply")
                self.assertEqual(status, 1, text)
                self.assertIn("-custom", text)
                self.assertEqual(target.read_text(), "custom\n")
                self.assertFalse(other.exists())
                target.unlink()

    def test_alternate_config_and_linked_parent(self):
        alt = self.root / "obaaf.yml"
        alt.write_text("{}")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 1, text)
        self.assertIn("--- obaaf.yml", text)
        self.assertIn("-{}", text)
        self.assertFalse(self.workflow.exists())
        self.assertFalse(self.config.exists())
        alt.write_text("lanes: {}\nprotected_secrets: {}\n")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 1, text)
        self.assertIn("The contents match", text)
        self.assertFalse(self.workflow.exists())
        self.assertFalse(self.config.exists())
        alt.unlink()
        with tempfile.TemporaryDirectory() as external:
            (self.root / ".github").symlink_to(external, target_is_directory=True)
            self.assertNotEqual(self.invoke("--apply")[0], 0)
            self.assertEqual(list(Path(external).iterdir()), [])

    def test_second_write_failure_rolls_back_first(self):
        link = os.link

        def write(source, dest):
            if dest == self.workflow:
                raise OSError("test write failure")
            link(source, dest)

        with patch("obaaf.init.os.link", side_effect=write):
            self.assertNotEqual(self.invoke("--apply")[0], 0)
        self.assertFalse(self.config.exists())
        self.assertFalse(self.workflow.exists())

    def test_dynamic_environment_reusable_secret_and_short_name_require_review(self):
        dest = self.workflow.with_name("called.yml")
        dest.parent.mkdir(parents=True)
        dest.write_text("""on: workflow_call
jobs:
  first:
    environment: production
    env:
      TOKEN: ${{ secrets.SERVICE_TOKEN }}
    steps: []
  second:
    environment: ${{ inputs.target }}
    env:
      KEY: ${{ secrets.ID }}
    steps: []
""")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        self.assertIn("Review SERVICE_TOKEN", text)
        self.assertIn("Review ID", text)
        self.assertEqual(Config.load(self.root).protected_secrets, {})

    def test_no_final_newline_is_a_visible_conflict(self):
        self.assertEqual(self.invoke("--apply")[0], 0)
        self.config.write_bytes(self.config.read_bytes().rstrip(b"\n"))
        self.workflow.unlink()
        status, text = self.invoke("--apply")
        self.assertEqual(status, 1, text)
        self.assertIn("No newline at end of file", text)
        self.assertFalse(self.workflow.exists())

    def test_unreadable_workflow_blocks_apply(self):
        path = self.workflow.with_name("invalid.yml")
        path.parent.mkdir(parents=True)
        path.write_text("jobs: [")
        status, text = self.invoke("--apply")
        self.assertNotEqual(status, 0)
        self.assertIn("invalid.yml", text)
        self.assertFalse(self.config.exists())
        self.assertFalse(self.workflow.exists())

    def test_local_composite_and_workflow_level_renamed_provider_key(self):
        path = self.workflow.with_name("local.yml")
        path.parent.mkdir(parents=True)
        action = self.root / ".github/actions/assistant/action.yml"
        action.parent.mkdir(parents=True)
        action.write_text("""name: assistant
runs:
  using: composite
  steps:
    - uses: openai/codex-action@v1
""")
        path.write_text("""on: push
jobs:
  named:
    steps:
      - uses: ./.github/actions/assistant
  ordinary:
    steps: []
""")
        path.with_name("provider.yml").write_text("""on: push
env:
  INTERNAL_MODEL_CREDENTIAL: ${{ secrets.AZURE_OPENAI_API_KEY }}
jobs:
  custom:
    steps: []
""")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        self.assertIn("local.yml#named: codex", text)
        self.assertIn("provider.yml#custom: references AZURE_OPENAI_API_KEY", text)
        self.assertEqual(set(Config.load(self.root).lanes), {
            ".github/workflows/local.yml#named", ".github/workflows/provider.yml#custom"})
        self.assertIn("Review AZURE_OPENAI_API_KEY", text)

    def test_unnamed_access_in_other_environment_keeps_named_secret_for_review(self):
        path = self.workflow.with_name("two.yml")
        path.parent.mkdir(parents=True)
        path.write_text("""on: push
jobs:
  named:
    environment: production
    env:
      VALUE: ${{ secrets.SERVICE_TOKEN }}
    steps: []
  selected:
    environment: staging
    env:
      VALUE: ${{ secrets[inputs.secret_name] }}
    steps: []
""")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        self.assertIn("Review SERVICE_TOKEN", text)
        self.assertIn("review access to unnamed", text)
        self.assertEqual(Config.load(self.root).protected_secrets, {})


    def test_matching_first_destination_is_preserved_when_creating_the_other(self):
        self.assertEqual(self.invoke("--apply")[0], 0)
        original = self.config.stat()
        self.workflow.unlink()
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        self.assertIn("Already matches: .github/obaaf.yml", text)
        self.assertIn("Wrote " + WORKFLOW, text)
        self.assertEqual(original.st_ino, self.config.stat().st_ino)
        self.assertEqual(original.st_mtime_ns, self.config.stat().st_mtime_ns)
