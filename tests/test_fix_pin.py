"""Offline package pinning through check, preview and explicit apply."""

from datetime import date, timedelta
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import unittest

from helpers import TempDir, run_cli
from obaaf import checker
from obaaf.checker import baseline
from test_agent_tool_installs import agent_job


class PinTest(unittest.TestCase):
    def setUp(self):
        tmp = TempDir()
        self.root = tmp.__enter__()
        self.addCleanup(tmp.__exit__)
        self.rel = Path(".github/workflows/install.yml")
        self.path = self.root / self.rel
        self.path.parent.mkdir(parents=True)
        self.package = "@anthropic-ai/claude-code"
        self.pin = self.package + "=1.2.3-beta.1+build.2"
        self.install = "npm install -g " + self.package
        self.write(f"- name: first\n  run: {self.install}\n")
        self.name = f"{self.rel}#a/step-1"

    def write(self, steps):
        self.path.write_text(agent_job(steps))

    def fix(self, *args):
        return run_cli("fix", self.root, *args)

    def test_explicit_pin_previews_only_the_requested_token_and_package(self):
        self.write(f"- name: first\n  run: {self.install} # keep\n"
                   f"- run: |\n    sudo {self.install}\n    claude --version\n"
                   "- run: npm install -g @openai/codex\n")
        source = self.path.read_bytes()
        self.assertNotIn("--- a/", self.fix()[1])
        code, out, err = self.fix("--pin", self.pin)
        self.assertEqual(code, 0, err or out)
        self.assertIn(self.name, out)
        self.assertIn("/step-2", out)
        self.assertIn("select its package @openai/codex", out)
        self.assertIn(self.package + "@1.2.3-beta.1+build.2 # keep", out)
        self.assertIn("sudo " + self.install + "@1.2.3-beta.1+build.2", out)
        self.assertNotIn("+          claude --version", out)
        self.assertEqual(self.path.read_bytes(), source)

    @unittest.skipUnless(os.name == "posix" and shutil.which("git"), "apply requires POSIX and Git")
    def test_named_apply_writes_exact_version_and_leaves_other_occurrences(self):
        self.write(f"- run: |\n    sudo {self.install}\n    claude --version\n- run: {self.install}\n")
        old = self.path.read_bytes().replace(b"\n", b"\r\n")
        self.path.write_bytes(old)
        for args in (["init", "-q"], ["add", "."], ["-c", "user.name=Test", "-c", "user.email=test@example.org",
                                                      "commit", "-qm", "fixture"]):
            subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)
        code, out, err = self.fix("--pin", self.pin, "--candidate", self.name, "--apply")
        self.assertEqual(code, 0, err or out)
        expected = old.replace(self.install.encode(), self.install.encode() + b"@1.2.3-beta.1+build.2", 1)
        self.assertEqual(self.path.read_bytes(), expected)
        self.assertEqual(len([f for f in checker.check(self.root).findings if f.rule == "OBAAF-GHA-025"]), 1)

    def test_missing_inexact_and_invalid_versions_make_no_edit(self):
        old = self.path.read_bytes()
        for value in ("", self.package, self.package + "=", "=1.2.3", "x=latest", "x=^1.2.3", "x=1.2",
                      "x=01.2.3", "x=1.2.3-01", "x=1.2.3+a..b", "x=1.2.3+", "x=١.٢.٣",
                      "x=1.2.3\n", "x=9007199254740992.0.0", "x=1.2.3 other", "x=1.2.3;other"):
            with self.subTest(value=value):
                code, out, _ = self.fix("--pin", value, "--apply")
                self.assertEqual(code, 2)
                self.assertNotIn("--- a/", out)
                self.assertEqual(self.path.read_bytes(), old)
        for options in (["--owner", "@person"], ["--tighten", "checkout-credentials"]):
            self.assertEqual(self.fix("--pin", self.pin, *options)[0], 2)

    def test_manual_and_unrelated_packages_remain_unchanged(self):
        self.write(f"- run: npx {self.package}\n- run: {self.install}@latest\n"
                   "- run: npm install -g @openai/codex\n")
        old = self.path.read_bytes()
        code, out, err = self.fix("--pin", self.pin, "--apply")
        self.assertEqual(code, 1, err)
        self.assertIn("review this install by hand", out)
        self.assertIn("select its package @openai/codex", out)
        self.assertIn("No eligible direct install", out)
        self.assertNotIn("--- a/", out)
        self.assertEqual(self.path.read_bytes(), old)

    def test_single_group_counts_candidates_and_manual_and_preserves_exact_scope(self):
        self.write(f"- run: {self.install}\n- run: npx {self.package}\n"
                   "- run: npm install -g @openai/codex\n")
        config = self.root / "team config.yml"
        config.write_text("{}")
        policy = self.root / "team's baseline.json"
        policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": []}))
        opts = ["--config", config, "--baseline", policy, "--platform", "github", "--fail-on", "never"]
        code, out, err = run_cli("check", self.path, "--format", "json", *opts)
        self.assertEqual(code, 0, err)
        group, = [g for g in json.loads(out)["todo"] if g["id"] == "agent-tool-version"]
        self.assertEqual((group["count"], group["pinCandidates"], group["byHand"]), (3, 2, 1))
        self.assertIn(self.package, group["nextAction"])
        self.assertIn("@openai/codex", group["nextAction"])
        args = shlex.split(group["command"])
        self.assertEqual(args, ["obaaf", "fix", str(self.path), "--pin", "PACKAGE=VERSION", f"--config={config}",
                                "--platform=github", f"--baseline={policy}", "--fail-on=never"])
        args[args.index("PACKAGE=VERSION")] = self.pin
        code, out, err = run_cli(*args[1:])
        self.assertEqual(code, 0, err)
        self.assertIn("At --fail-on never", out)

    def test_accepted_target_stays_withheld_and_named_retry_preserves_package_and_version(self):
        f = next(f for f in checker.check(self.root).findings if f.rule == "OBAAF-GHA-025")
        expiry = (date.today() + timedelta(days=30)).isoformat()
        policy = self.root / "baseline.json"
        policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": [
            baseline.entry_for(f, "@team", "previous review", expiry)]}))
        original = policy.read_bytes()
        code, out, err = self.fix("--pin", self.pin, "--candidate", self.name, "--baseline", policy, "--apply")
        self.assertEqual(code, 1, err or out)
        self.assertIn("1 unmatched", out)
        line = next(l for l in out.splitlines() if "Retry this step alone with " in l)
        command = shlex.split(line.split("Retry this step alone with ", 1)[1])
        self.assertIn(self.pin, command)
        self.assertIn("--candidate=" + self.name, command)
        self.assertIn("--baseline=" + str(policy), command)
        self.assertNotIn("--- a/", out)
        self.assertEqual(policy.read_bytes(), original)

    def test_all_manual_group_has_no_pin_command(self):
        self.write(f"- run: npx {self.package}\n")
        code, out, err = run_cli("check", self.root, "--format", "json", "--fail-on", "never")
        self.assertEqual(code, 0, err)
        group, = [g for g in json.loads(out)["todo"] if g["id"] == "agent-tool-version"]
        self.assertEqual((group["pinCandidates"], group["byHand"], group["command"]), (0, 1, None))

    def test_both_fixable_causes_precede_higher_severity_manual_work(self):
        from obaaf.catalog import load
        from obaaf.checker.rules import Finding
        from obaaf.checker.todo import todo

        findings = [
            Finding("OBAAF-JEN-001", "high", "Jenkinsfile", 1, "Review by hand."),
            Finding("OBAAF-GHA-025", "low", "ci.yml", 2, "Install.", pin_candidate=self.package),
            Finding("OBAAF-GHA-011", "low", "ci.yml", 3, "Checkout."),
        ]
        groups = todo(checker.CheckResult(findings, [], [], checker.Config()), load())
        self.assertEqual({g["id"] for g in groups[:2]}, {"agent-tool-version", "checkout-credentials"})
        self.assertIsNone(groups[2]["command"])

    def test_repeated_request_with_no_install_finding_is_a_noop(self):
        pinned = f"- run: {self.install}@1.2.3\n"
        self.write(pinned)
        old = self.path.read_bytes()
        code, out, err = self.fix("--pin", self.package + "=1.2.3", "--apply")
        self.assertEqual(code, 0, err)
        self.assertIn("Nothing to apply", out)
        self.assertNotIn("--- a/", out)
        self.assertEqual(self.path.read_bytes(), old)

    def test_repeated_option_cannot_silently_drop_a_package(self):
        code, out, err = self.fix("--pin", self.pin, "--pin", "@openai/codex=1.2.3", "--apply")
        self.assertEqual(code, 2)
        self.assertIn("one --pin", err)
        self.assertNotIn("--- a/", out)

    def test_folded_quoted_and_unshared_anchored_package_tokens_are_proven(self):
        for scalar in (f">-\n    npm install -g\n    {self.package}\n",
                       f'"npm install -g\n    {self.package}"\n',
                       f"&install >- # {self.install}\n    npm install -g\n    {self.package}\n"):
            with self.subTest(scalar=scalar):
                self.write(f"- run: {scalar}")
                finding, = [f for f in checker.check(self.root).findings if f.rule == "OBAAF-GHA-025"]
                self.assertEqual(finding.pin_candidate, self.package)
                code, out, err = self.fix("--pin", self.pin)
                self.assertEqual(code, 0, err or out)
                self.assertIn(self.package + "@1.2.3-beta.1+build.2", out)
                self.assertIn("Checked on a copy:", out)

    def test_repeat_for_one_package_keeps_other_eligible_and_manual_findings_visible(self):
        self.write(f"- run: {self.install}@1.2.3\n- run: npm install -g @openai/codex\n"
                   "- run: npx @openai/codex\n")
        old = self.path.read_bytes()
        for selector in ([], ["--candidate", self.name]):
            with self.subTest(selector=selector):
                code, out, err = self.fix("--pin", self.package + "=1.2.3", "--apply", *selector)
                self.assertEqual(code, 0, err or out)
                self.assertIn("Observed " + self.package + "@1.2.3", out)
                self.assertNotIn("--- a/", out)
                if not selector:
                    self.assertIn("select its package @openai/codex", out)
                    self.assertIn("review this install by hand", out)
                self.assertEqual(self.path.read_bytes(), old)

    def test_repeat_does_not_hide_a_manual_install_of_the_same_package(self):
        self.write(f"- run: {self.install}@1.2.3\n- run: npx {self.package}\n")
        code, out, err = self.fix("--pin", self.package + "=1.2.3", "--apply")
        self.assertEqual(code, 1, err or out)
        self.assertIn("review this install by hand", out)
        self.assertNotIn("Nothing to apply", out)

    def test_a_different_version_absent_package_or_unsupported_shell_is_not_satisfied(self):
        for steps in (f"- run: {self.install}@2.0.0\n", "- run: echo hello\n",
                      f"- run: {self.install}@1.2.3\n  shell: python\n",
                      f"- run: {self.install}@1.2.3\n- run: {self.install}@2.0.0\n"):
            with self.subTest(steps=steps):
                self.write(steps)
                code, out, err = self.fix("--pin", self.package + "=1.2.3", "--apply")
                self.assertEqual(code, 1, err or out)
                self.assertNotIn("Nothing to apply", out)
                self.assertNotIn("--- a/", out)
