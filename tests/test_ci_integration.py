"""docs/ci-integration.md: what it promises a CI job, and that its examples are what it says."""
import contextlib
import io
import json
from pathlib import Path
import re
import shlex
import unittest

import yaml

from helpers import ROOT, TempDir, cli, run_cli

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
        status, _, _ = run_cli("--format", "json")
        self.assertEqual(status, 2)


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

    def test_every_obaaf_command_on_the_page_is_one_the_command_line_accepts(self):
        parser = cli.build_parser()
        commands = [line.strip() for block in blocks("bash") for line in block.splitlines()
                    if line.strip().startswith("obaaf ")]
        commands.append(next(b for b in blocks("yaml") if "repos:" in b).split("entry: ", 1)[1].splitlines()[0])
        self.assertGreaterEqual(len(commands), 5, commands)
        for command in commands:
            with self.subTest(command=command):
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        parser.parse_args(shlex.split(command)[1:])
                except SystemExit as exc:      # --version and --help exit 0 on purpose
                    if exc.code == 0 and command.split()[1:] in (["--version"], ["--help"]):
                        continue
                    self.fail(f"`{command}` is not a command the tool accepts ({exc.code})")


if __name__ == "__main__":
    unittest.main()
