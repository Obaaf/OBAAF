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
        self.assertEqual(config.lanes, {".github/workflows/jobs.yml#custom": "agent"})
        self.assertIn("Review DEPLOY_TOKEN", text)
        self.assertIn("Review ANTHROPIC_API_KEY", text)
        self.assertIn("codex", text.lower())

    def test_script_agent_with_a_provider_key_keeps_its_inferred_lane(self):
        workflow = self.workflow.with_name("script.yml")
        workflow.parent.mkdir(parents=True)
        (self.root / "review.sh").write_text("codex exec 'review'\n")
        workflow.write_text("""on: push
jobs:
  review:
    env:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    steps:
      - run: bash review.sh
""")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        self.assertEqual(Config.load(self.root).lanes, {})
        self.assertIn("script.yml#review:", text)
        self.assertIn("references OPENAI_API_KEY", text)
        self.assertNotIn("To create an agent workflow", text)

    def lanes_after_check(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = cli.main(["check", str(self.root), "--lanes"])
        self.assertEqual(status, 0, stdout.getvalue() + stderr.getvalue())
        return dict(line.split(": ", 1) for line in stdout.getvalue().splitlines() if ": " in line)

    def test_a_lane_is_omitted_only_where_the_checkout_finds_the_agent(self):
        """Review of #362: a job whose agent the checker finds only in a script Git does not track
        (untracked, ignored or in a submodule) would get no lane from init and none in CI, whose
        checkout does not hold the script. Init declares it, and says why."""
        from helpers import git, init_repo
        init_repo(self.root)
        workflow = self.workflow.with_name("script.yml")
        workflow.parent.mkdir(parents=True)
        workflow.write_text("""on: push
jobs:
  review:
    env:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    steps:
      - run: bash review.sh
  direct:
    steps:
      - run: claude -p review
""")
        (self.root / "review.sh").write_text("codex exec 'review'\n")
        git(self.root, "add", workflow.relative_to(self.root).as_posix())
        status, text = self.invoke()
        self.assertEqual(status, 0, text)
        self.assertIn('+  .github/workflows/script.yml#review: agent', text)
        self.assertNotIn("script.yml#direct: agent", text)
        self.assertIn("Git tracks outside submodules", text)
        self.assertIn("script.yml#review", text.split("Git tracks outside submodules")[1])
        (self.root / ".gitignore").write_text("review.sh\n")
        self.assertIn('+  .github/workflows/script.yml#review: agent', self.invoke()[1])
        (self.root / ".gitignore").unlink()
        git(self.root, "add", "review.sh")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        self.assertEqual(Config.load(self.root).lanes, {})
        self.assertNotIn("Git tracks outside submodules", text)
        lanes = self.lanes_after_check()
        for job in ("review", "direct"):
            self.assertTrue(lanes[f".github/workflows/script.yml#{job}"].startswith("agent ("), lanes)

    def test_every_job_init_names_is_an_agent_job_when_checked(self):
        """Review of #362: the property the change rests on. Each job init lists as an agent job is
        in the agent lane when the checker runs with what init wrote, declared or not."""
        from helpers import git, init_repo
        init_repo(self.root)
        folder = self.workflow.parent
        folder.mkdir(parents=True)
        action = self.root / ".github/actions/assistant/action.yml"
        action.parent.mkdir(parents=True)
        action.write_text("name: assistant\nruns:\n  using: composite\n  steps:\n    - uses: openai/codex-action@v1\n")
        (self.root / "review.sh").write_text("claude -p review\n")
        (folder / "a.yml").write_text("""on: pull_request
jobs:
  action:
    steps:
      - uses: anthropics/claude-code-action@v1
  composite:
    steps:
      - uses: ./.github/actions/assistant
  script:
    steps:
      - run: bash review.sh
  key:
    steps:
      - run: python probe.py
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
  call:
    uses: ./.github/workflows/b.yml
""")
        (folder / "b.yml").write_text("on: workflow_call\njobs:\n  inner:\n    steps:\n      - run: npx @openai/codex exec x\n")
        git(self.root, "add", "-A")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        named = [line.split(":")[0] for line in text.splitlines() if line.startswith(".github/workflows/")]
        self.assertEqual(sorted(named), sorted(f".github/workflows/{key}" for key in (
            "a.yml#action", "a.yml#composite", "a.yml#script", "a.yml#key", "b.yml#inner")), text)
        self.assertEqual(Config.load(self.root).lanes, {".github/workflows/a.yml#key": "agent"})
        lanes = self.lanes_after_check()
        for key in named:
            self.assertTrue(lanes[key].startswith("agent ("), (key, lanes))

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
        self.assertEqual(Config.load(self.root).lanes, {".github/workflows/provider.yml#custom": "agent"})
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


class InitReviewTests(unittest.TestCase):
    """From the review of #273 (run goosander)."""

    setUp = InitTests.setUp
    invoke = InitTests.invoke

    def write_workflow(self, name, text):
        path = self.workflow.with_name(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_a_workflow_that_is_not_utf8_is_named(self):
        self.workflow.parent.mkdir(parents=True)
        self.workflow.with_name("latin.yml").write_bytes(b"on: push\njobs:\n  j:\n    steps:\n      - run: echo \xff\n")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 2, text)
        self.assertIn(".github/workflows/latin.yml is not UTF-8 text", text)
        self.assertFalse(self.config.exists())

    def test_an_environment_on_a_calling_job_is_not_proposed(self):
        self.write_workflow("called.yml", "on: workflow_call\njobs:\n  x:\n    steps: []\n")
        self.write_workflow("caller.yml", """on: push
jobs:
  mapped:
    environment: production
    uses: ./.github/workflows/called.yml
    secrets:
      TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  inherited:
    environment: production
    uses: ./.github/workflows/called.yml
    secrets: inherit
  plain:
    environment: production
    env:
      VALUE: ${{ secrets.SERVICE_TOKEN }}
    steps: []
""")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        self.assertIn("Review DEPLOY_TOKEN: no single literal environment", text)
        self.assertIn("Review SERVICE_TOKEN: no single literal environment", text)
        self.assertEqual(Config.load(self.root).protected_secrets, {})

    def test_a_name_github_refuses_or_a_short_name_says_why(self):
        self.write_workflow("names.yml", """on: push
jobs:
  j:
    environment: production
    env:
      A: ${{ secrets.AB }}
      B: ${{ secrets.GITHUB_PAT }}
      C: ${{ secrets._X_Y }}
      D: ${{ secrets.SERVICE_TOKEN }}
    steps: []
""")
        status, text = self.invoke("--apply")
        self.assertEqual(status, 0, text)
        for name in ("AB", "GITHUB_PAT", "_X_Y"):
            self.assertIn(f"Review {name}: init proposes rules only for secret names GitHub accepts", text)
        self.assertEqual(Config.load(self.root).protected_secrets, {"SERVICE_TOKEN": "production"})

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_written_files_get_the_mode_of_other_new_files(self):
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)
        self.assertEqual(self.invoke("--apply")[0], 0)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.workflow.stat().st_mode & 0o777, 0o644)

    def test_the_diff_breaks_lines_only_at_newlines(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text("lanes: {}\u2028\rprotected_secrets: {}\n")
        status, text = self.invoke()
        self.assertEqual(status, 1, text)
        self.assertNotIn("No newline at end of file", text)
        self.assertEqual(sum(line.startswith("-lanes") for line in text.splitlines()), 1)

    def test_a_folder_inside_a_git_repository_is_named(self):
        (self.root / ".git").mkdir()
        inner = self.root / "src"
        inner.mkdir()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["init", str(inner)]), 0)
        self.assertIn(f"is inside the Git repository at {self.root.resolve()}", stdout.getvalue())
        self.assertNotIn("is inside the Git repository", self.invoke()[1])
