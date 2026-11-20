"""The summary changes how the checker reports, while preserving its verdict."""

from datetime import date, timedelta
import os
import shlex
import unittest

from helpers import RISKY, TempDir, run_cli
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
                # The summary opens as the full report does, with the accepted risk (D-043), and its list
                # is the full report's list, word for word.
                self.assertTrue(short.startswith("Accepted risk: none."), short)
                self.assertTrue(full.startswith(short.splitlines()[0]))
                todo = short[short.index("What to do next:"):]
                self.assertTrue(full.endswith(todo + f"Checked by obaaf {__version__}.\n"))
                command, = [line for line in short.splitlines() if "--write-baseline=" in line]
                words = shlex.split(command)
                self.assertEqual(words[:4], ["obaaf", "check", str(target), "--platform=github"])
                self.assertEqual(words[words.index("--fail-on") + 1], threshold)

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

    def test_summary_shows_accepted_risk_expiry_and_an_old_baseline(self):
        import json
        from datetime import date, timedelta

        target = RISKY / "pwn-request.yml"
        with TempDir() as root:
            baseline = root / "b.json"
            soon = (date.today() + timedelta(days=2)).isoformat()
            code, _, err = run_cli("check", target, "--platform", "github", "--write-baseline", baseline,
                                   "--owner", "@someone", "--reason", "accepted for this test", "--expires", soon,
                                   "--fail-on", "never")
            self.assertEqual(0, code, err)
            args = ("check", target, "--platform", "github", "--baseline", baseline, "--fail-on", "high")
            full_code, full, _ = run_cli(*args)
            code, short, _ = run_cli(*args, "--summary")
            self.assertEqual(full_code, code)
            self.assertIn("Accepted risk: 5 finding(s) are accepted", short)
            self.assertIn("Expiring soon: 5 acceptance(s)", short)
            code, quiet, _ = run_cli(*args, "--summary", "--expiry-warning", "0")
            self.assertNotIn("Expiring soon", quiet)
        # An old-format baseline accepts nothing, and the summary says so (the fixture of the lifecycle tests).
        from test_finding_lifecycle import fixture_repo

        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            args = ("check", repo, "--baseline", old, "--fail-on", "low", "--no-fixes")
            full_code, full, _ = run_cli(*args)
            code, short, _ = run_cli(*args, "--summary")
            self.assertEqual((1, 1), (full_code, code))
            self.assertIn("The baseline is in the old format (obaaf-baseline/v0.1)", short)

    def test_printable_migration_hint_replays_in_both_views(self):
        from test_finding_lifecycle import fixture_repo

        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            name = "-old team baseline.json"
            baseline = tmp / name
            old.rename(baseline)
            previous = os.getcwd()
            try:
                os.chdir(tmp)
                for display in ((), ("--summary",)):
                    status, report, err = run_cli("check", repo, "--baseline=" + name, "--platform", "github",
                                                  "--fail-on", "low", *display)
                    self.assertEqual(status, 1, err)
                    commands = {line.strip() for line in report.splitlines()
                                if line.strip().startswith("obaaf baseline migrate ")}
                    self.assertEqual(len(commands), 1)
                    words = shlex.split(commands.pop())
                    self.assertEqual(words[3:5], ["./" + name, str(repo)])
                    self.assertIn("--platform=github", words)
                decisions = {"OWNER": "@studio/build", "REASON": "Reviewed legacy findings",
                             "YYYY-MM-DD": (date.today() + timedelta(days=30)).isoformat()}
                status, out, err = run_cli(*(decisions.get(w, w) for w in words[1:]))
                self.assertEqual(status, 0, out + err)
                self.assertIn("obaaf-baseline/v0.2", baseline.read_text())
            finally:
                os.chdir(previous)

    def test_unprintable_migration_arguments_get_manual_guidance_in_both_views(self):
        from test_finding_lifecycle import fixture_repo

        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            # With no matching acceptance there is no migration group in the to-do
            # list; the lifecycle notice still has to explain what the user can do.
            empty = tmp / "old\nempty.json"
            empty.write_text('{"format":"obaaf-baseline/v0.1","findings":[]}')
            config = tmp / "team\tpolicy.yml"
            config.write_text("{}")
            for options in (["--baseline", empty], ["--baseline", old, "--config", config]):
                for display in ((), ("--summary",)):
                    status, report, err = run_cli("check", repo, *options, "--fail-on", "low", *display)
                    self.assertEqual(status, 1, err)
                    self.assertIn("Run obaaf baseline migrate yourself with the baseline's original path", report)
                    self.assertNotIn("The full report gives the command", report)
                    self.assertFalse(any(line.strip().startswith("obaaf baseline migrate ")
                                         for line in report.splitlines()))

    def test_the_lanes_command_stands_on_its_own_line_and_runs(self):
        with TempDir() as root:
            path = root / ".github" / "workflows" / "w.yml"
            path.parent.mkdir(parents=True)
            path.write_text("on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n"
                            "      OBAAF_LANE: agnet\n    steps:\n      - run: echo hi\n", encoding="utf-8")
            code, short, err = run_cli("check", root, "--summary", "--fail-on", "low")
            self.assertIn("the command below", short, short + err)
            command, = [line.strip() for line in short.splitlines() if line.strip().startswith("obaaf check")
                        and line.strip().endswith("--lanes")]
            words = shlex.split(command)
            self.assertEqual(["obaaf", "check", str(root)], words[:3])
            lanes_code, lanes, lanes_err = run_cli(*words[1:])
            self.assertEqual(0, lanes_code, lanes_err)
            self.assertIn("w.yml#a", lanes)

    def test_guards_in_the_list(self):
        from datetime import date, timedelta

        with TempDir() as root:
            path = root / ".github/workflows/bad.yml"
            path.parent.mkdir(parents=True)
            path.write_text("jobs: [", encoding="utf-8")
            good = root / ".github/workflows/ok.yml"
            good.write_text("on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                            "      - uses: actions/checkout@v4\n", encoding="utf-8")
            full_code, full, _ = run_cli("check", root, "--fail-on", "never")
            code, short, _ = run_cli("check", root, "--summary", "--fail-on", "never")
            self.assertEqual(full_code, code)
            self.assertNotEqual(0, code)
            self.assertIn("The scan is incomplete", short)
            self.assertNotIn("Optional bulk acceptance", short)
            # A baseline with an entry that matches nothing: review it before writing a new one.
            baseline = root / "b.json"
            path.unlink()
            run_cli("check", root, "--write-baseline", baseline, "--owner", "@someone", "--reason",
                    "accepted for this test", "--expires", (date.today() + timedelta(days=30)).isoformat(),
                    "--fail-on", "never")
            good.write_text(good.read_text(encoding="utf-8").replace("@v4", "@" + "1" * 40), encoding="utf-8")
            code, short, _ = run_cli("check", root, "--summary", "--baseline", baseline, "--fail-on", "never")
            self.assertIn("Stale baseline entries:", short)
            self.assertIn("Review stale entries before deciding whether to replace the baseline.", short)

    def test_the_other_guards_and_the_baseline_in_the_lanes_command(self):
        import json
        from datetime import date, timedelta

        from test_finding_lifecycle import fixture_repo

        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            # The migrate command for a baseline whose path cannot be printed on one line is left out.
            odd = tmp / "bl\nnl.json"
            odd.write_text(old.read_text(encoding="utf-8"), encoding="utf-8")
            code, short, _ = run_cli("check", repo, "--baseline", odd, "--fail-on", "low", "--summary")
            self.assertEqual(1, code)
            self.assertIn("Use the original check paths and options; they cannot be printed", short)
            self.assertNotIn("bl\\nnl.json", short)
            # With a scan error, the list does not suggest migrating the baseline.
            bad = repo / ".github" / "workflows" / "zz-bad.yml"
            bad.parent.mkdir(parents=True, exist_ok=True)
            bad.write_text("jobs: [", encoding="utf-8")
            code, short, _ = run_cli("check", repo, "--baseline", old, "--fail-on", "low", "--summary")
            self.assertIn("Resolve the scan errors before migrating the baseline.", short)
            self.assertNotIn("obaaf baseline migrate", short)
        with TempDir() as root:
            path = root / ".github" / "workflows" / "w.yml"
            path.parent.mkdir(parents=True)
            path.write_text("on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n"
                            "      OBAAF_LANE: agnet\n    steps:\n      - run: echo hi\n", encoding="utf-8")
            baseline = root / "base line.json"
            soon = (date.today() + timedelta(days=30)).isoformat()
            run_cli("check", root, "--write-baseline", baseline, "--owner", "@someone", "--reason",
                    "accepted for this test", "--expires", soon, "--fail-on", "never")
            data = json.loads(baseline.read_text(encoding="utf-8"))
            lane = [e for e in data["findings"] if e["rule"] == "OBAAF-CFG-001"]
            self.assertEqual(1, len(lane), data)
            # An expired entry: the list asks for a review instead of offering to write the baseline.
            lane[0]["expires"] = (date.today() - timedelta(days=1)).isoformat()
            baseline.write_text(json.dumps(data), encoding="utf-8")
            code, short, _ = run_cli("check", root, "--baseline", baseline, "--fail-on", "low", "--summary")
            self.assertIn("Review invalid baseline acceptances before deciding whether to write the baseline.", short)
            self.assertNotIn("--write-baseline=", short)
            # Without that entry the lane finding is outstanding, and the lanes command keeps the baseline.
            data["findings"] = [e for e in data["findings"] if e["rule"] != "OBAAF-CFG-001"]
            baseline.write_text(json.dumps(data), encoding="utf-8")
            code, short, _ = run_cli("check", root, "--baseline", baseline, "--fail-on", "low", "--summary")
            command, = [line.strip() for line in short.splitlines() if line.strip().endswith("--lanes")]
            self.assertIn(f"--baseline={baseline}", shlex.split(command))
