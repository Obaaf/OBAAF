"""Replay reported tightening commands with the selected offline settings evidence."""
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from helpers import run_cli
from obaaf import checker, fix
from obaaf.catalog import load
from obaaf.audit import snapshot
from obaaf.checker import baseline
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

    def test_child_targets_replay_report_and_named_commands_from_parent(self):
        findings = checker.check(self.root).findings
        expires = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
        with tempfile.TemporaryDirectory() as parent:
            self.addCleanup(os.chdir, self.root)
            os.chdir(parent)
            for name in ("egress", "=ls"):
                child = Path(name)
                shutil.copytree(self.root, child)
                settings = f"--settings={child / self.settings}"
                threshold = "--fail-on=never"
                policy = child / "baseline.json"
                policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": []}))
                code, out, err = run_cli("check", name, "--format=json", settings, threshold,
                                         "--platform=github", f"--baseline={policy}")
                self.assertEqual(code, 0, err)
                groups = {g["id"]: g for g in json.loads(out)["todo"]}
                workflow = child / self.path
                original = workflow.read_bytes()
                for cause, rule, step, change in (
                    ("checkout-credentials", "OBAAF-GHA-011", 1, "persist-credentials: false"),
                    ("agent-tool-version", "OBAAF-GHA-025", 2, "@openai/codex@1.2.3"),
                ):
                    with self.subTest(name=name, cause=cause):
                        def replay(command):
                            args = shlex.split(command)
                            self.assertEqual(args[:3], ["obaaf", "fix", "./" + name])
                            for option in (settings, threshold, "--platform=github", f"--baseline={policy}"):
                                self.assertIn(option, args)
                            self.assertNotIn("--apply", args)
                            result = run_cli(*args[1:])
                            self.assertEqual(workflow.read_bytes(), original)
                            return result

                        command = groups[cause]["command"].replace("=VERSION", "=1.2.3")
                        code, out, err = replay(command)
                        self.assertEqual(code, 0, err)
                        self.assertIn(change, out)
                        self.assertIn("PACKAGE_INDEX_TOKEN: verified", err)

                        finding = next(f for f in findings if f.rule == rule)
                        entry = baseline.entry_for(finding, "@example/build", "previous review", expires)
                        policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": [entry]}))
                        candidate = f"{self.path}#assistant/step-{step}"
                        code, out, err = replay(command + " " + shlex.quote("--candidate=" + candidate))
                        self.assertEqual(code, 1, err or out)
                        marker = "After resolving it, preview the same request again with: "
                        retry, = [line.split(marker, 1)[1] for line in out.splitlines() if marker in line]
                        self.assertIn("--candidate=" + candidate, shlex.split(retry))
                        policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": []}))
                        code, out, err = replay(retry)
                        self.assertEqual(code, 0, err)
                        self.assertIn(change, out)
                        self.assertIn("PACKAGE_INDEX_TOKEN: verified", err)
            os.chdir(self.root)

    def test_explicit_egress_job_still_previews_confinement(self):
        before = self.path.read_bytes()
        catalog = load()
        catalog = replace(catalog, detection={**catalog.detection, "egress_action_releases": ["c" * 40]})
        with patch("obaaf.fix_egress.load", return_value=catalog):
            code, out, err = run_cli("fix", "egress", "--job", "assistant", ".")
        self.assertEqual(code, 0, err)
        self.assertIn("Checked on a private copy", out)
        self.assertIn("job 'assistant'", out)
        self.assertEqual(self.path.read_bytes(), before)

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

    def test_withheld_checkout_and_pin_omit_retry_for_multiline_settings_path(self):
        settings = Path("team\nsettings.json")
        self.settings.rename(settings)
        findings = checker.check(self.root).findings
        for rule, step, selection in [("OBAAF-GHA-011", 1, ["--tighten", "checkout-credentials"]),
                                      ("OBAAF-GHA-025", 2, ["--pin", "@openai/codex=1.2.3"])]:
            with self.subTest(rule=rule):
                finding = next(f for f in findings if f.rule == rule)
                expires = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
                policy = Path("baseline.json")
                policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": [
                    baseline.entry_for(finding, "@example/build", "previous review", expires)]}))
                candidate = f"{self.path}#assistant/step-{step}"
                code, out, err = run_cli("fix", ".", *selection, "--baseline", policy, f"--settings={settings}",
                                         "--candidate", candidate)
                self.assertEqual(code, 1, err or out)
                self.assertIn("Review the reported findings", out)
                self.assertIn("named retry cannot be printed on one line", out)
                self.assertNotIn("obaaf fix", out)
                self.assertNotIn("--- a/", out)

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
