"""The work order contains trusted instructions and bounded, inert repository metadata."""

import contextlib
import dataclasses
import unittest
from unittest.mock import patch

from helpers import TempDir, run_cli
from obaaf.catalog import load
from obaaf.fix_copy import private_copy

PIN = "80db1e68769165c9ecf24e553254fa35d6e168d5"
WORKFLOW = """on: workflow_dispatch
permissions: {}
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - name: Step name from a repository
        env:
          OPENAI_API_KEY: ${{ secrets.MODEL }}
          OTHER_PROVIDER_KEY: ${{ secrets.OTHER }}
        run: claude -p "repository command text"
"""


def draft(*args):
    return run_cli("fix", "egress", "--job", "review", *args)


def brief(*args):
    return draft("--brief", *args)


class WorkOrderTests(unittest.TestCase):
    def test_release_hold_precedes_any_copy(self):
        cat = load()
        empty = dataclasses.replace(cat, detection={**cat.detection, "egress_action_releases": []})
        with patch("obaaf.fix_egress.load", return_value=empty), patch("obaaf.fix_egress.private_copy", side_effect=AssertionError):
            code, out, err = brief("absent")
            self.assertEqual((code, err), (0, ""))
            self.assertIn("No released commit", out)
            self.assertNotIn("# Egress confinement work order", out)

    def test_named_harness_uses_catalogued_release(self):
        with TempDir() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            path = workflows / "review.yml"
            original = WORKFLOW.replace('claude -p "repository command text"', "python review.py")
            path.write_text(original)
            code, out, err = brief("--step", "Step name from a repository", root)
            self.assertEqual((code, err), (0, ""))
            self.assertIn(PIN, out)
            self.assertIn("Step number = 1", out)
            self.assertNotIn("python review.py", out)
            self.assertEqual(path.read_text(), original)

    def test_trusted_instructions_and_real_verdicts(self):
        with TempDir() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            path = workflows / "review.yml"
            path.write_text(WORKFLOW)
            code, out, err = brief(root)
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(path.read_text(), WORKFLOW)
            for word in ("branch you trust", 'Job ID = "review"', "Step number = 1", PIN,
                         'Proxy variable names = "OPENAI_API_KEY"', 'Command variable names = "OTHER_PROVIDER_KEY"',
                         "OBAAF-GHA-005 — new", "OBAAF-GHA-020 — fixed", "— not met", "— verified",
                         "obaaf check . --platform auto --fail-on medium", "Do not add or widen",
                         "only after the checker", "subdomains", "own proxy", "private-copy draft"):
                self.assertIn(word, out)
            for untrusted in ("Step name from", "repository command text", "claude -p"):
                self.assertNotIn(untrusted, out)

    def test_selected_step_and_multiline_warning_preserve_source_bytes(self):
        workflow = WORKFLOW.replace("    steps:\n", "    steps:\n      - run: echo ready\n").replace(
            "          OTHER_PROVIDER_KEY:", "          PROMPT: |\n            private first line\n"
            "            private second line\n          OTHER_PROVIDER_KEY:")
        with TempDir() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            path = workflows / "review.yml"
            original = workflow.replace("\n", "\r\n").encode("utf-8")
            path.write_bytes(original)
            code, out, err = brief(root)
            self.assertEqual((code, err), (0, ""))
            data = out.split("## Repository data\n\n")[1].split("\n\n## Change")[0]
            self.assertIn("    Step number = 2", data.splitlines())
            self.assertIn('    Variable names with a line break or NUL in the value = "PROMPT"', data.splitlines())
            for value in ("private first line", "private second line", "repository command text"):
                self.assertNotIn(value, out)
            self.assertEqual(path.read_bytes(), original)

            code, ordinary, err = draft(root)
            self.assertEqual((code, err), (0, ""))
            warning = next(line for line in ordinary.splitlines() if "line break or NUL" in line)
            self.assertTrue(warning.endswith(": PROMPT"), warning)
            self.assertIn("Draft only.", ordinary)
            self.assertIn("run: claude -p", ordinary)
            self.assertEqual(path.read_bytes(), original)

    def test_cleanup_failure_reports_only_the_refusal(self):
        @contextlib.contextmanager
        def failing_cleanup(root):
            with private_copy(root) as copy:
                yield copy
            raise OSError("example cleanup detail")

        with TempDir() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            path = workflows / "review.yml"
            path.write_text(WORKFLOW)
            original = path.read_bytes()
            with patch("obaaf.fix_egress.private_copy", failing_cleanup):
                code, out, err = brief(root)
            self.assertEqual((code, out), (2, ""))
            self.assertEqual(len(err.splitlines()), 1)
            self.assertIn("trusted branch", err)
            self.assertNotIn("example cleanup detail", err)
            self.assertEqual(path.read_bytes(), original)

    def test_brief_rejects_apply_at_parse_time(self):
        code, out, err = brief("absent", "--apply")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("unrecognized arguments: --apply", err)

    def test_checker_reasons_identify_the_job_specific_manual_work(self):
        with TempDir() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            path = workflows / "review.yml"
            path.write_text(WORKFLOW)
            code, ordinary, err = brief(root)
            self.assertEqual((code, err), (0, ""))
            changed = WORKFLOW.replace("ubuntu-24.04", "ubuntu-latest").replace(
                "permissions: {}", "permissions: {id-token: write, models: read}")
            path.write_text(changed + '      - name: "later `sample` [label](sample)"\n        run: echo done\n')
            code, out, err = brief(root)
            self.assertEqual((code, err), (0, ""))
            data, instructions = out.split("## Change the selected job")
            reasons = [line for line in data.splitlines() if line.startswith("    Checker reason (")]
            reason_text = "\n".join(reasons)
            for expected in ("ubuntu-latest", "id-token: write", "models permission", "can run after",
                             "later `sample` [label](sample)", "no environment", "not listed in protected_secrets"):
                self.assertIn(expected, reason_text)
            self.assertNotIn("later `sample`", instructions)
            self.assertNotIn("ubuntu-latest", ordinary)
            self.assertNotIn("can run after", ordinary)

    def test_many_later_steps_each_retain_the_reason(self):
        with TempDir() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            names = [f"Save review summary for component {i:02}" for i in range(1, 36)]
            path = workflows / "review.yml"
            path.write_text(WORKFLOW + "".join(f"      - name: {name}\n        run: echo done\n" for name in names))
            code, out, err = brief(root)
            self.assertEqual((code, err), (0, ""))
            reasons = [line for line in out.splitlines() if "Checker reason (Egress action condition)" in line]
            self.assertGreaterEqual(len(reasons), 10)
            for name, line in zip(names, reasons):
                self.assertIn(name, line)
                self.assertIn("can run after it or beside it", line)
            self.assertIn("Additional checker reasons omitted =", out)

    def test_names_stay_in_bounded_literal_block_and_out_of_proof_command(self):
        with TempDir() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            path = workflows / ('sample "name" `~~~/'.replace("/", "") + "\n# sample" + "x" * 130 + ".yml")
            path.write_text(WORKFLOW)
            config = root / "example [link](sample).yml"
            config.write_text("{}\n")
            baseline = root / "sample-baseline.json"
            baseline.write_text('{"format":"obaaf-baseline/v0.2","findings":[]}')
            code, out, err = brief(path, "--config", config, "--baseline", baseline,
                                   "--platform", "github", "--fail-on", "authority:high")
            self.assertEqual((code, err), (0, ""))
            data = out.split("## Repository data\n\n")[1].split("\n\n## Change")[0]
            self.assertTrue(all(line.startswith("    ") for line in data.splitlines()))
            self.assertIn('sample \\"name\\"', data)
            self.assertIn("?# sample", data)
            self.assertIn("…", data)
            self.assertNotIn("x" * 120, data)
            instructions = out.split("## Change the selected job")[1]
            self.assertNotIn("sample", instructions)
            self.assertIn('obaaf check "./${OBAAF_CHECK_PATH:?}" --config "./${OBAAF_CONFIG_PATH:?}" '
                          '--baseline "./${OBAAF_BASELINE_PATH:?}" --platform github --fail-on authority:high', instructions)

    def test_refusal_excludes_free_text_diagnostic(self):
        with TempDir() as root:
            code, out, err = brief(root / "example-repository-text")
            self.assertEqual((code, out), (2, ""))
            self.assertIn("trusted branch", err)
            self.assertNotIn("example-repository-text", err)
