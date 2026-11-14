"""docs/ci-integration.md: what it promises a CI job, and that its examples are what it says."""
import contextlib
import io
import json
from pathlib import Path
import re
import os
import shlex
import shutil
import subprocess
import unittest

import yaml

from helpers import ROOT, TempDir, cli, run_cli
from obaaf.checker import CONFIG_LOCATIONS, parse_fail_on

PAGE = ROOT / "docs/ci-integration.md"
TEMPLATE = ROOT / "templates/github-actions/workflows/obaaf-pipeline-check.yml"
PLACEHOLDER = ("OBAAF_OWNER/obaaf/actions/setup-obaaf@0000000000000000000000000000000000000000"
               " # pin to an OBAAF release")
PINNED = re.compile(r"Obaaf/OBAAF/actions/setup-obaaf@[0-9a-f]{40} # [^\n]+")


def blocks(language: str) -> list:
    return re.findall(rf"```{language}\n(.*?)```", PAGE.read_text(encoding="utf-8"), re.S)


class CiReportContractTest(unittest.TestCase):
    def test_failing_gate_writes_equivalent_located_findings_in_both_formats(self):
        workflow = ROOT / "tests/fixtures/workflows/risky/agent-lane-misspelled.yml"
        with TempDir() as directory:
            reports = {}
            for fmt in ("json", "sarif"):
                path = Path(directory) / ("report." + fmt)
                status, _, err = run_cli("check", str(workflow), "--fail-on", "medium",
                                         "--format", fmt, "--output", str(path))
                self.assertEqual(status, 1, err)
                reports[fmt] = json.loads(path.read_text(encoding="utf-8"))

        findings = sorted((f["rule"], f["path"], f["line"]) for f in reports["json"]["findings"])
        self.assertIn(("OBAAF-CFG-001", workflow.name, 14), findings)
        self.assertIn(("OBAAF-GHA-001", workflow.name, 10), findings)
        results = []
        for result in reports["sarif"]["runs"][0]["results"]:
            location = result["locations"][0]["physicalLocation"]
            results.append((result["ruleId"], location["artifactLocation"]["uri"],
                            location["region"]["startLine"]))
        self.assertEqual(sorted(results), findings)

    def test_a_file_that_cannot_be_read_ends_with_one_and_is_an_error_in_sarif(self):
        with TempDir() as directory:
            workflow = directory / "bad.yml"
            workflow.write_text("on: [push\njobs: {\n", encoding="utf-8")
            report = directory / "report.sarif"
            status, _, err = run_cli("check", str(workflow), "--fail-on", "never",
                                     "--format", "sarif", "--output", str(report))
            self.assertEqual(status, 1, err)
            run = json.loads(report.read_text(encoding="utf-8"))["runs"][0]
        self.assertEqual(run["results"], [])
        invocation = run["invocations"][0]
        self.assertIs(invocation["executionSuccessful"], False)
        errors = [n for n in invocation["toolExecutionNotifications"] if n["level"] == "error"]
        self.assertEqual([n["descriptor"]["id"] for n in errors], ["not-read"])

    def test_nothing_to_check_and_a_misplaced_format_end_with_two(self):
        with TempDir() as directory:
            status, _, err = run_cli("check", str(directory))
            self.assertEqual(status, 2, err)
            self.assertIn("nothing was checked", err)
            (directory / "ci.yml").write_text("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                                              "    steps:\n      - run: echo hi\n", encoding="utf-8")
            status, out, err = run_cli("check", str(directory / "ci.yml"), "--format", "json", "--fail-on", "never")
            self.assertEqual(status, 0, out + err)
            status, _, err = run_cli("--format", "json", "check", str(directory / "ci.yml"), "--fail-on", "never")
            self.assertEqual(status, 2, err)


class ThePageTest(unittest.TestCase):
    def test_the_workflow_on_the_page_is_the_template_with_its_pin_filled_in(self):
        workflows = [b for b in blocks("yaml") if "jobs:" in b]
        self.assertEqual(len(workflows), 1)
        shown = workflows[0]
        pins = PINNED.findall(shown)
        self.assertEqual(len(pins), 1, pins)
        template = TEMPLATE.read_text(encoding="utf-8")
        self.assertIn(PLACEHOLDER, template)
        self.assertEqual(shown, template.replace(PLACEHOLDER, pins[0]))

    def test_the_pin_is_the_same_everywhere_on_the_page(self):
        text = PAGE.read_text(encoding="utf-8")
        shas = set(re.findall(r"(?:setup-obaaf@|OBAAF\.git@)([0-9a-f]{40})", text))
        self.assertEqual(len(shas), 1, shas)
        self.assertIn(f"`{shas.pop()}`", text)

    def test_the_workflow_on_the_page_has_no_findings(self):
        workflow = next(b for b in blocks("yaml") if "jobs:" in b)
        with TempDir() as directory:
            (directory / ".github/workflows").mkdir(parents=True)
            (directory / ".github/workflows/obaaf-pipeline-check.yml").write_text(workflow, encoding="utf-8")
            (directory / ".github/CODEOWNERS").write_text("* @example/build\n", encoding="utf-8")
            status, out, err = run_cli("check", str(directory), "--fail-on", "low")
        self.assertEqual(status, 0, out + err)

    def test_the_hook_checks_the_whole_repository(self):
        hooks = [b for b in blocks("yaml") if "repos:" in b]
        self.assertEqual(len(hooks), 1)
        hook = yaml.safe_load(hooks[0])["repos"][0]["hooks"][0]
        self.assertEqual(hook["entry"].split()[:3], ["obaaf", "check", "."])
        self.assertIs(hook["pass_filenames"], False)
        self.assertIs(hook["always_run"], True)

    def commands(self) -> list:
        """Every obaaf command the page tells a reader to run, wherever it is written."""
        page = PAGE.read_text(encoding="utf-8")
        found = [line.strip() for block in blocks("bash") for line in block.splitlines()
                 if line.strip().startswith("obaaf ")]
        workflow = next(b for b in blocks("yaml") if "jobs:" in b)
        found += [line.strip().replace(' "${config[@]}"', "") for line in workflow.splitlines()
                  if line.strip().startswith("obaaf ")]
        hook = next(b for b in blocks("yaml") if "repos:" in b)
        found.append(yaml.safe_load(hook)["repos"][0]["hooks"][0]["entry"])
        # Inline commands in the prose, less the ones the page gives as output or as a mistake.
        found += [c for c in re.findall(r"`(obaaf [^`]*)`", page)
                  if c not in ("obaaf 0.4.0.dev0", "obaaf --format json")]
        return found

    def test_every_obaaf_command_on_the_page_is_one_the_command_line_accepts(self):
        parser = cli.build_parser()
        commands = self.commands()
        self.assertGreaterEqual(len(commands), 9, commands)
        for command in commands:
            with self.subTest(command=command):
                words = shlex.split(command)
                try:
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        parser.parse_args(words[1:])
                except SystemExit as exc:      # --version and --help exit 0 on purpose
                    if not (exc.code == 0 and words[1:] in (["--version"], ["--help"])):
                        self.fail(f"`{command}` is not a command the tool accepts ({exc.code})")
                for i, word in enumerate(words):   # argparse does not check these values; the checker does
                    if word == "--fail-on":
                        parse_fail_on(words[i + 1])

    def test_the_failing_example_on_the_page_fails_as_it_says(self):
        page = PAGE.read_text(encoding="utf-8")
        examples = [c for c in self.commands() if "tests/fixtures/" in c]
        self.assertEqual(len(examples), 1, examples)
        words = shlex.split(examples[0])
        path = next(w for w in words if w.startswith("tests/fixtures/"))
        words[words.index(path)] = str(ROOT / path)
        status, out, err = run_cli(*words[1:])
        self.assertEqual(status, 1, err)
        found = {(f["rule"], f["line"]) for f in json.loads(out)["findings"]}
        self.assertEqual(found, {("OBAAF-GHA-001", 10), ("OBAAF-CFG-001", 14)})
        self.assertIn("Status 1. Both formats report `OBAAF-GHA-001` at line 10 and `OBAAF-CFG-001` at line 14", page)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class TheTemplateStepTest(unittest.TestCase):
    """The template's check step, run with bash and a stand-in for obaaf that keeps what it is given."""

    def run_step(self, event: str, base: dict, workspace: dict | None = None, links: dict | None = None,
                 status: int = 0) -> tuple[list, str | None, bool]:
        workflow = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))
        script = next(s["run"] for s in workflow["jobs"]["check"]["steps"] if "obaaf check" in s.get("run", ""))
        with TempDir() as directory:
            work, temp, bin_ = directory / "work", directory / "temp", directory / "bin"
            for folder in (work, temp, bin_):
                folder.mkdir()
            for name, text in {**{f".obaaf-base/{k}": v for k, v in base.items()}, **(workspace or {})}.items():
                (work / name).parent.mkdir(parents=True, exist_ok=True)
                (work / name).write_text(text, encoding="utf-8")
            for name, target in (links or {}).items():
                (work / ".obaaf-base" / name).parent.mkdir(parents=True, exist_ok=True)
                (work / ".obaaf-base" / name).symlink_to(target)
            log = directory / "calls"
            stub = bin_ / "obaaf"
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$OBAAF_CALLS"\n'
                            'for a; do if [ "$prev" = --config ]; then cat "$a" > "$OBAAF_CALLS.config"; fi; prev="$a"; done\n',
                            encoding="utf-8")
            stub.chmod(0o755)
            env = {**os.environ, "PATH": f"{bin_}{os.pathsep}{os.environ['PATH']}", "RUNNER_TEMP": str(temp),
                   "GITHUB_EVENT_NAME": event, "OBAAF_CALLS": str(log)}
            done = subprocess.run(["bash", "-c", script], cwd=work, env=env, capture_output=True, text=True)
            self.assertEqual(done.returncode, status, done.stdout + done.stderr)
            calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            config = Path(f"{log}.config")
            return calls, config.read_text(encoding="utf-8") if config.exists() else None, (work / ".obaaf-base").exists()

    def test_a_pull_request_reads_the_target_branch_configuration_under_each_name_the_checker_reads(self):
        for name in CONFIG_LOCATIONS:
            with self.subTest(name=name):
                calls, config, left = self.run_step("pull_request", {name: f"# from {name}\n"})
                self.assertEqual(len(calls), 2, calls)
                self.assertTrue(all("--config" in c for c in calls), calls)
                self.assertIn("--format sarif --output obaaf.sarif --fail-on never", calls[0])
                self.assertTrue(calls[1].endswith("--fail-on medium"), calls)
                self.assertEqual(config, f"# from {name}\n")
                self.assertFalse(left)

    def test_the_first_name_wins_as_in_the_checker(self):
        base = {name: f"# from {name}\n" for name in CONFIG_LOCATIONS}
        _, config, _ = self.run_step("pull_request", base)
        self.assertEqual(config, f"# from {CONFIG_LOCATIONS[0]}\n")

    def test_a_pull_request_with_no_configuration_on_the_target_branch_gets_none(self):
        _, config, _ = self.run_step("pull_request", {})
        self.assertEqual(config, "{}\n")

    def test_a_link_on_the_target_branch_fails_the_step(self):
        base = {"conf/obaaf.yml": "# the real one\n", ".github/obaaf.yaml": "# a looser one\n"}
        calls, config, _ = self.run_step("pull_request", base, links={".github/obaaf.yml": "../conf/obaaf.yml"},
                                         status=1)
        self.assertEqual(calls, [])
        self.assertIsNone(config)

    def test_a_push_reads_its_own_configuration_even_with_a_directory_of_that_name(self):
        calls, config, _ = self.run_step("push", {".github/obaaf.yml": "# planted\n"})
        self.assertEqual(len(calls), 2, calls)
        self.assertTrue(calls[1].endswith("--fail-on medium"), calls)
        self.assertFalse(any("--config" in c for c in calls), calls)
        self.assertIsNone(config)

    def test_a_directory_the_pull_request_brings_is_removed_before_the_target_branch_is_checked_out(self):
        steps = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))["jobs"]["check"]["steps"]
        removal = next(i for i, s in enumerate(steps) if s.get("run", "").strip() == "rm -rf .obaaf-base")
        checkout = next(i for i, s in enumerate(steps) if s.get("with", {}).get("path") == ".obaaf-base")
        self.assertLess(removal, checkout)
        self.assertEqual(steps[removal]["if"], steps[checkout]["if"])
        on = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))[True]   # YAML 1.1 reads `on:` as true
        self.assertIn("edited", on["pull_request"]["types"])
        patterns = steps[checkout]["with"]["sparse-checkout"].split()
        self.assertEqual(patterns, ["/" + name for name in CONFIG_LOCATIONS])

if __name__ == "__main__":
    unittest.main()
