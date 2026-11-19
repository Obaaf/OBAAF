"""Replay reported tightening commands with the selected offline settings evidence."""
import os
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from helpers import run_cli
from obaaf import checker, fix
from obaaf.audit import snapshot
from test_settings_audit import recording, take


class FixSettingsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.addCleanup(os.chdir, Path.cwd())
        os.chdir(self.root)
        self.path = Path(".github/workflows/ci.yml")
        self.path.parent.mkdir(parents=True)
        self.path.write_text("""on: workflow_dispatch
permissions: {contents: read}
jobs:
  assistant:
    runs-on: ubuntu-latest
    environment: release
    env:
      API_KEY: ${{ secrets.PACKAGE_INDEX_TOKEN }}
    steps:
      - uses: actions/checkout@v4
      - run: npm install -g @openai/codex
      - run: codex exec review
""")
        Path(".github/CODEOWNERS").write_text("/.github/ @example/build\n")
        self.config = Path(".github/obaaf.yml")
        self.config.write_text("protected_secrets: {PACKAGE_INDEX_TOKEN: release}\n")
        self.settings = Path("-team settings.json")
        self.option = f"--settings={self.settings}"
        self.data, _ = take(recording("admin-token"), token="dummy")
        self.data["taken_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.data["settings"]["environments"]["value"][1]["branch_policies"] = [{"type": "branch", "name": "main"}]
        snapshot.write(self.data, self.settings)
        for args in (["init", "-q"], ["remote", "add", "origin", "https://github.com/example-studio/game.git"],
                     ["add", "."], ["-c", "user.name=Example", "-c", "user.email=test@example.org",
                                    "commit", "-qm", "Fixture"]):
            subprocess.run(["git", *args], check=True)

    def test_report_commands_replay_same_control_and_ownership_through_apply(self):
        code, out, err = run_cli("check", ".", "--format=json", "--platform=github", "--fail-on=never", self.option)
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        groups = {g["id"]: g for g in report["todo"]}
        original = checker.check
        observed = []

        def check(*args, **kwargs):
            result = original(*args, **kwargs)
            control = next(f for f in result.findings if f.rule == "OBAAF-GHA-005").controls[1]
            self.assertEqual(control.verdict, "verified")
            self.assertTrue(any(f.rule == "OBAAF-REPO-001" and str(self.settings) in f.message for f in result.findings))
            self.assertEqual(kwargs["settings"].source, args[0] / self.settings)
            observed.append(args[0])
            return result

        with patch.object(checker, "check", side_effect=check):
            for cause in ("agent-tool-version", "checkout-credentials"):
                args = shlex.split(groups[cause]["command"])
                self.assertIn(self.option, args)
                args = [w.replace("=VERSION", "=1.2.3") for w in args[1:]]
                for flags in [(), ("--apply",)]:
                    observed.clear()
                    code, out, err = run_cli(*args, *flags)
                    self.assertEqual(code, 0, err)
                    self.assertIn("PACKAGE_INDEX_TOKEN: verified", err)
                    self.assertIn("--- a/", out)
                    self.assertIn(self.root, observed)
                    self.assertGreaterEqual(len(set(observed)), 4 if flags else 3)
                subprocess.run(["git", "-c", "user.name=Example", "-c", "user.email=test@example.org",
                                "commit", "-qam", "Apply fixture change"], check=True)

    def test_partial_scan_and_unusable_settings(self):
        args = ("fix", str(self.path), "--config", str(self.config), "--tighten", "checkout-credentials")
        code, _, err = run_cli(*args, self.option)
        self.assertEqual(code, 0, err)
        self.assertIn("does not check snapshot code ownership", err)
        old = self.path.read_bytes()
        for name in ("missing.json", str(self.root.parent / "outside.json"), str(self.settings)):
            if name == str(self.settings):
                self.settings.write_text("{}")
            code, _, err = run_cli(*args, f"--settings={name}", "--apply")
            self.assertEqual(code, 2, err)
            self.assertEqual(self.path.read_bytes(), old)
        for args in [("fix", "--gate", "medium"), ("fix", "egress", "--job", "assistant")]:
            self.assertEqual(run_cli(*args, self.option)[0], 2)

    def test_changed_snapshot_refused_before_write(self):
        display = fix._render
        before = self.path.read_bytes()

        def changed(*args):
            display(*args)
            self.data["settings"]["repository_secrets"]["value"].append("ANOTHER_NAME")
            snapshot.write(self.data, self.settings)

        with patch.object(fix, "_render", side_effect=changed):
            code, _, err = run_cli("fix", ".", "--tighten", "checkout-credentials", self.option, "--apply")
        self.assertEqual(code, 2, err)
        self.assertIn("settings evidence changed", err)
        self.assertEqual(self.path.read_bytes(), before)
