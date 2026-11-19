"""The summary changes how the checker reports, while preserving its verdict."""

from datetime import date, timedelta
import shlex
import unittest

from helpers import ROOT, RISKY, TempDir, run_cli
from obaaf import __version__


class SummaryCliTest(unittest.TestCase):
    def test_summary_is_the_same_list_and_keeps_the_threshold(self):
        target = RISKY / "pwn-request.yml"
        for threshold, expected in (("high", 1), ("never", 0)):
            with self.subTest(threshold=threshold):
                args = ("check", target, "--platform", "github", "--fail-on", threshold)
                code, full, err = run_cli(*args)
                short_code, short, short_err = run_cli(*args, "--summary")
                self.assertEqual((code, short_code, short_err), (expected, expected, err))
                self.assertTrue(short.startswith("What to do next:"))
                self.assertTrue(full.endswith(short + f"Checked by obaaf {__version__}.\n"))
                command, = [line for line in short.splitlines() if "--write-baseline=" in line]
                words = shlex.split(command)
                self.assertEqual(words[:4], ["obaaf", "check", str(target), "--platform=github"])
                self.assertEqual(words[words.index("--fail-on") + 1], threshold)

    def test_settings_scope_replays_for_ownership_and_lane_suggestions(self):
        with TempDir() as root:
            folder = root / ".github"
            (folder / "workflows").mkdir(parents=True)
            (folder / "workflows/build.yml").write_text(
                "on: push\njobs: {build: {runs-on: ubuntu-latest, steps: [{run: echo ok}]}}\n")
            (folder / "CODEOWNERS").write_text("/.github/ @example/build\n")
            config = folder / "checker config.yml"
            config.write_text("lanes: {'.github/workflows/build.yml#missing': agent}\n")
            settings = root / "team's settings; review.json"
            settings.write_bytes((ROOT / ".github/obaaf-settings.json").read_bytes())
            args = ("check", root, "--config", config, "--settings", settings, "--platform", "github",
                    "--fail-on", "never")
            for display in ((), ("--summary",)):
                code, text, err = run_cli(*args, *display)
                self.assertEqual(code, 0, err)
                line, = [line for line in text.splitlines() if "--write-baseline=" in line]
                suggested = shlex.split(line)
                self.assertNotIn("obaaf check . --lanes", text)
                lane = next(line for line in text.splitlines() if line.startswith("   Compare the configured path"))
                start = lane.index("obaaf check ")
                lane_words = shlex.split(lane[start:lane.index("--lanes", start) + len("--lanes")])
                for words in (suggested, lane_words):
                    self.assertIn(f"--settings={settings}", words)
                    self.assertIn(f"--config={config}", words)
                    self.assertIn("--platform=github", words)
                    self.assertEqual(words[words.index("--fail-on") + 1], "never")
                self.assertEqual(run_cli(*lane_words[1:])[0], 0)
            # Fill in only the acceptance decisions and destination in the printed command.
            replacements = {"--write-baseline=NEW_BASELINE_FILE": f"--write-baseline={folder / 'accepted.json'}",
                            "OWNER": "@example/build", "REASON": "Reviewed during local adoption",
                            "YYYY-MM-DD": (date.today() + timedelta(days=7)).isoformat()}
            code, replay, err = run_cli(*(replacements.get(word, word) for word in suggested[1:]))
            self.assertEqual(code, 0, err)
            self.assertIn("OBAAF-REPO-001", replay)
            self.assertIn(settings.name, replay)
            self.assertTrue((folder / "accepted.json").is_file())

    def test_summary_keeps_scan_errors_visible(self):
        with TempDir() as root:
            path = root / ".github/workflows/bad.yml"
            path.parent.mkdir(parents=True)
            path.write_text("jobs: [", encoding="utf-8")
            code, text, err = run_cli("check", root, "--summary", "--fail-on", "never")
            self.assertNotEqual(code, 0)
            self.assertIn("bad.yml", text + err)
            self.assertNotIn("--write-baseline=", text)

    def test_output_file_and_conflicting_modes(self):
        target = RISKY / "pwn-request.yml"
        with TempDir() as root:
            output = root / "result.txt"
            code, out, err = run_cli("check", target, "--summary", "--fail-on", "never", "-o", output)
            self.assertEqual((code, out, err), (0, "", ""))
            self.assertIn("What to do next:", output.read_text(encoding="utf-8"))
            baseline = root / "baseline.json"
            for args in (("--format", "json"), ("--format", "sarif"), ("--lanes",),
                         ("--write-baseline", str(baseline))):
                with self.subTest(args=args):
                    code, _, err = run_cli("check", target, "--summary", *args)
                    self.assertEqual(code, 2)
                    self.assertIn("--summary", err)
            self.assertFalse(baseline.exists())

    def test_summary_keeps_incomplete_jenkins_coverage_visible(self):
        with TempDir() as root:
            path = root / "Jenkinsfile"
            path.write_text("node { parallel generateBranches(['a']) }", encoding="utf-8")
            full_code, full, _ = run_cli("check", path)
            code, summary, err = run_cli("check", path, "--summary")
            self.assertEqual(full_code, 0, full)
            self.assertEqual(code, full_code, err)
            self.assertIn("15 unknown", full)
            self.assertIn("15 unknown rule results across 1 Jenkinsfile", summary)
