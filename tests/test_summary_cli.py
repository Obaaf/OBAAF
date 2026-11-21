"""The summary changes how the checker reports, while preserving its verdict."""

from datetime import date, timedelta
import json
import os
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
                lane, = [line for line in text.splitlines()
                         if line.strip().startswith("obaaf check ") and line.endswith("--lanes")]
                lane_words = shlex.split(lane)
                for words in (suggested, lane_words):
                    self.assertIn(f"--settings={settings}", words)
                    self.assertIn(f"--config={config}", words)
                    self.assertIn("--platform=github", words)
                    self.assertEqual(words[words.index("--fail-on") + 1], "never")
                self.assertEqual(run_cli(*lane_words[1:])[0], 0)
            code, output, err = run_cli(*args, "--format", "json")
            self.assertEqual(code, 0, err)
            group = next(g for g in json.loads(output)["todo"] if "configured path and target" in g["nextAction"])
            self.assertIsNone(group["command"])
            self.assertEqual(shlex.split(group["nextAction"].split("obaaf check ", 1)[1]), lane_words[2:])
            # Fill in only the acceptance decisions and destination in the printed command.
            replacements = {"--write-baseline=NEW_BASELINE_FILE": f"--write-baseline={folder / 'accepted.json'}",
                            "OWNER": "@example/build", "REASON": "Reviewed during local adoption",
                            "YYYY-MM-DD": (date.today() + timedelta(days=7)).isoformat()}
            code, replay, err = run_cli(*(replacements.get(word, word) for word in suggested[1:]))
            self.assertEqual(code, 0, err)
            self.assertIn("OBAAF-REPO-001", replay)
            self.assertIn(settings.name, replay)
            self.assertTrue((folder / "accepted.json").is_file())

    def test_check_suggestions_keep_a_literal_equals_target(self):
        with TempDir() as parent:
            root = parent / "=ls"
            workflow = root / ".github/workflows/build.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("on: push\njobs: {build: {runs-on: ubuntu-latest, steps: [{run: echo ok}]}}\n")
            config = root / "team config.yml"
            config.write_text("lanes: {'.github/workflows/build.yml#missing': agent}\n")
            previous = os.getcwd()
            try:
                os.chdir(parent)
                code, summary, err = run_cli("check", "=ls", "--config", config, "--fail-on", "never", "--summary")
                self.assertEqual(code, 0, summary + err)
                commands = [shlex.split(line) for line in summary.splitlines()
                            if line.strip().startswith("obaaf check ")]
                lane, = [args for args in commands if "--lanes" in args]
                write, = [args for args in commands if "--write-baseline=NEW_BASELINE_FILE" in args]
                for args in (lane, write):
                    self.assertEqual(args[:3], ["obaaf", "check", "./=ls"])
                code, lanes, err = run_cli(*lane[1:])
                self.assertEqual(code, 0, err)
                self.assertIn("build.yml#build", lanes)
                destination = parent / "accepted.json"
                replacements = {"--write-baseline=NEW_BASELINE_FILE": f"--write-baseline={destination}",
                                "OWNER": "@example/build", "REASON": "Reviewed during local adoption",
                                "YYYY-MM-DD": (date.today() + timedelta(days=7)).isoformat()}
                code, output, err = run_cli(*(replacements.get(word, word) for word in write[1:]))
                self.assertEqual(code, 0, output + err)
                findings = json.loads(destination.read_text(encoding="utf-8"))["findings"]
                self.assertIn("OBAAF-CFG-001", [entry["rule"] for entry in findings])
            finally:
                os.chdir(previous)

    def test_lane_advice_replays_from_finding_and_json_without_settings(self):
        with TempDir() as root:
            workflow = root / ".github/workflows/build.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("on: push\njobs: {build: {runs-on: ubuntu-latest, steps: [{run: echo ok}]}}\n")
            baseline = root / "team baseline.json"
            baseline.write_text(json.dumps({"format": "obaaf-baseline/v0.2", "findings": []}))
            for name in ("team config.yml", "team\nconfig.yml"):
                with self.subTest(name=name):
                    config = root / name
                    config.write_text("lanes: {'.github/workflows/build.yml#missing': agent}\n")
                    args = ("check", root, "--config", config, "--platform", "github",
                            "--baseline", baseline, "--fail-on", "never")
                    code, text, err = run_cli(*args)
                    self.assertEqual(code, 0, err)
                    code, output, err = run_cli(*args, "--format", "json")
                    self.assertEqual(code, 0, err)
                    data = json.loads(output)
                    fix = next(line for line in text.splitlines() if "Fix: Correct the declaration" in line)
                    finding = next(f for f in data["findings"] if f["rule"] == "OBAAF-CFG-001")
                    group = next(g for g in data["todo"] if "configured path and target" in g["nextAction"])
                    self.assertIsNone(group["command"])
                    for remedy in (fix, finding["fix"]):
                        self.assertIn("Correct the declaration or delete it", remedy)
                    for advice in (fix, finding["fix"], group["nextAction"]):
                        if "\n" in name:
                            # The command is named, never printed with the path it cannot show.
                            self.assertIn("original path and options with obaaf check --lanes", advice)
                            self.assertNotIn("obaaf check /", advice)
                            self.assertNotIn("config.yml", advice)
                        else:
                            self.assertEqual(advice.count("obaaf check"), 1)
                            command = shlex.split(advice[advice.index("obaaf check"):])
                            self.assertEqual(command, ["obaaf", "check", str(root), f"--config={config}",
                                                       "--platform=github", f"--baseline={baseline}",
                                                       "--fail-on", "never", "--lanes"])
                            code, lanes, err = run_cli(*command[1:])
                            self.assertEqual(code, 0, err)
                            self.assertIn("build.yml#build", lanes)

    def test_a_check_of_one_file_gives_the_repository_form_of_a_lanes_key(self):
        """Review of #311: the lane command of a one-file check lists `build.yml#build`, a key the repository's
        check does not match, so the fix gives the key's form by example, not by that command."""
        with TempDir() as root:
            workflow = root / ".github/workflows/build.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("on: push\njobs: {build: {runs-on: ubuntu-latest, steps: [{run: echo ok}]}}\n")
            config = root / "c.yml"
            config.write_text("lanes: {'.github/workflows/build.yml#build': probe}\n")
            code, text, err = run_cli("check", workflow, "--config", config, "--fail-on", "never")
            self.assertEqual(code, 0, err)
            fix, = [line for line in text.splitlines() if "Fix: Correct the declaration" in line]
            self.assertIn("(`.github/workflows/ci.yml#build`)", fix)
            self.assertEqual(fix.count("obaaf check"), 1)
            command = shlex.split(fix[fix.index("Lane check: ") + len("Lane check: "):])
            self.assertEqual(command[:3], ["obaaf", "check", str(workflow)])
            code, lanes, err = run_cli(*command[1:])
            self.assertEqual(code, 0, err)
            self.assertIn("build.yml#build", lanes)

    def test_a_leading_equals_sign_gets_dot_slash_in_fix_and_migration_commands(self):
        """Review of #311: zsh expands a word that begins with `=`, and only the check commands guarded it."""
        from types import SimpleNamespace
        from obaaf.checker.todo import tightening_command
        from obaaf.checker.todo_acceptance import scoped_migration_command
        result = SimpleNamespace(checked="=ls", options=("--config==c.yml",), baseline_path="=b.json",
                                 fail_on="low")
        words = shlex.split(tightening_command(result, ["--pin", "tool=VERSION"]))
        self.assertEqual(words[:3], ["obaaf", "fix", "./=ls"])
        self.assertIn("--baseline==b.json", words)
        words = shlex.split(scoped_migration_command("=b.json", "=ls", ()))
        self.assertEqual(words[3:5], ["./=b.json", "./=ls"])
        for plain in ("ls", "-x"):
            with self.subTest(plain=plain):
                result.checked = plain
                target = shlex.split(tightening_command(result, ["--pin", "t=V"]))[2]
                self.assertEqual(target, plain if plain == "ls" else "./-x")

    def test_an_unprintable_scope_loses_only_the_command_in_a_fix(self):
        """Review of #299: with a selected snapshot whose path cannot be printed on one line, the rule's
        whole Fix text was replaced by the fallback sentence; only its command may be."""
        with TempDir() as root:
            folder = root / ".github"
            (folder / "workflows").mkdir(parents=True)
            (folder / "workflows/build.yml").write_text(
                "on: push\njobs: {build: {runs-on: ubuntu-latest, steps: [{run: echo ok}]}}\n")
            config = folder / "obaaf.yml"
            config.write_text("lanes: {'.github/workflows/build.yml#missing': agent}\n")
            settings = root / "line\nbreak.json"
            settings.write_bytes((ROOT / ".github/obaaf-settings.json").read_bytes())
            code, text, err = run_cli("check", root, "--settings", settings, "--platform", "github",
                                      "--fail-on", "never")
            self.assertEqual(code, 0, err)
            fix, = [line for line in text.splitlines() if line.strip().startswith("Fix: Correct the declaration")]
            self.assertIn("Correct the declaration or delete it", fix)
            self.assertIn("original path and options with obaaf check --lanes", fix)
            self.assertNotIn("--settings", fix)
            self.assertNotIn("line\nbreak", fix)

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
                    # Review of #319: the action list says which baseline the hint means, also when the
                    # migration step is a prerequisite of a checkout or pin preview rather than its own row.
                    actions = report.split("What to do next:", 1)[1]
                    if options[1] == empty:
                        self.assertIn(r"Original baseline (escaped, for display only): " + str(tmp) + r"/old\nempty.json",
                                      actions)
                    else:
                        self.assertIn("Original baseline: " + shlex.quote(str(old)), actions)
                        self.assertNotIn("for display only", actions)

    def test_manual_migration_in_the_action_list_names_the_original_baseline(self):
        from test_finding_lifecycle import fixture_repo

        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            odd = tmp / "team\tbaseline.json"
            old.rename(odd)
            for display in ((), ("--summary",)):
                status, report, err = run_cli("check", repo, "--baseline", odd, "--fail-on", "low", *display)
                self.assertEqual(status, 1, err)
                actions = report.split("What to do next:", 1)[1]
                self.assertIn("Run obaaf baseline migrate yourself", actions)
                self.assertIn("baseline's original path", actions)
                self.assertIn(r"team\tbaseline.json", actions)
                self.assertNotIn(str(odd), actions)
                self.assertNotIn("obaaf baseline migrate '", actions)

    def test_incomplete_scan_defers_migration_in_both_views_even_without_a_matching_entry(self):
        from test_finding_lifecycle import fixture_repo

        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            (repo / ".github/workflows/broken.yml").write_text("jobs: [")
            odd = tmp / "team\tbaseline.json"
            odd.write_bytes(old.read_bytes())
            empty = tmp / "empty.json"
            empty.write_text('{"format":"obaaf-baseline/v0.1","findings":[]}')
            for baseline in (old, odd, empty):
                for display in ((), ("--summary",)):
                    status, report, err = run_cli("check", repo, "--baseline", baseline, "--fail-on", "never", *display)
                    self.assertEqual(status, 1, err)
                    self.assertIn("Resolve the scan errors before migrating the baseline.", report)
                    for prompt in ("obaaf baseline migrate", "Convert it once", "The full report gives the command"):
                        self.assertNotIn(prompt, report)

    def test_incomplete_migration_preserves_scoped_lane_advice_in_both_action_lists(self):
        from test_finding_lifecycle import fixture_repo

        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            workflows = repo / ".github/workflows"
            (workflows / "broken.yml").write_text("jobs: [", encoding="utf-8")
            (workflows / "lane.yml").write_text(
                "on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n"
                "      OBAAF_LANE: agnet\n    steps:\n      - run: echo hi\n", encoding="utf-8")
            args = ("check", repo, "--baseline", old, "--platform", "github", "--fail-on", "never")
            for display in ((), ("--summary",)):
                status, report, err = run_cli(*args, *display)
                self.assertEqual(status, 1, err)
                actions = report.split("What to do next:", 1)[1]
                self.assertIn("Resolve the scan errors before migrating the baseline.", actions)
                self.assertNotIn("obaaf baseline migrate", actions)
                lane, = [line.strip() for line in actions.splitlines()
                         if line.strip().startswith("obaaf check ") and line.endswith("--lanes")]
                words = shlex.split(lane)
                self.assertEqual(words[:3], ["obaaf", "check", str(repo)])
                self.assertIn(f"--baseline={old}", words)
                self.assertIn("--platform=github", words)
                self.assertEqual(words[words.index("--fail-on") + 1], "never")

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
