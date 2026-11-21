import contextlib
from importlib.resources import files
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

from obaaf import cli
from obaaf.init import WORKFLOW

SCANNERS = ("zizmor", "actionlint", "poutine")


class CompanionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.workflow = self.root / WORKFLOW

    def invoke(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = cli.main(["init", str(self.root), *args])
        return code, output.getvalue()

    def scanner_steps(self):
        workflow = yaml.safe_load(self.workflow.read_bytes())
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        return [s for s in workflow["jobs"]["check"]["steps"] if s["name"].endswith(" findings")
                and s["name"] != "Report findings"]

    def test_default_off_and_later_selection_conflicts(self):
        code, text = self.invoke("--apply")
        self.assertEqual(code, 0, text)
        self.assertIn("--with-scanner zizmor", text)
        self.assertEqual(self.workflow.read_bytes(), files("obaaf.data").joinpath("init-workflow.yaml").read_bytes())
        before = self.workflow.read_bytes()
        code, text = self.invoke("--with-scanner", "zizmor", "--apply")
        self.assertEqual(code, 1, text)
        self.assertIn("Conflict: " + WORKFLOW, text)
        self.assertEqual(self.workflow.read_bytes(), before)

    def test_each_choice_is_independent(self):
        for name in SCANNERS:
            with self.subTest(name=name):
                code, text = self.invoke("--with-scanner", name)
                self.assertEqual(code, 0, text)
                self.assertFalse(self.workflow.exists())
                for other in SCANNERS:
                    self.assertEqual(f"Report {other} findings" in text, other == name)

    def test_all_steps_have_pins_read_only_input_and_no_network(self):
        args = ["--with-scanner", "actionlint", "--with-scanner", "poutine", "--with-scanner", "zizmor"]
        code, text = self.invoke("--apply", *args)
        self.assertEqual(code, 0, text)
        before = self.workflow.read_bytes()
        checks = self.scanner_steps()
        self.assertEqual([step["name"] for step in checks], [f"Report {s} findings" for s in SCANNERS])
        for step in checks:
            script = step["run"]
            self.assertRegex(script, r"@sha256:[a-f0-9]{64}\s")
            self.assertIn("--network none --read-only", script)
            self.assertIn("dst=/source,readonly", script)
            self.assertNotIn("GH_TOKEN", script)
        code, text = self.invoke("--apply", "--with-scanner", "poutine", *args)
        self.assertEqual(code, 0, text)
        self.assertEqual(self.workflow.read_bytes(), before)

    @unittest.skipUnless(shutil.which("bash") and Path("/proc/sys/kernel/random/uuid").is_file(),
                         "generated steps run on the Linux runner")
    def test_finding_exit_is_nonblocking_and_tool_errors_surface(self):
        code, text = self.invoke("--apply", *(arg for name in SCANNERS for arg in ("--with-scanner", name)))
        self.assertEqual(code, 0, text)
        docker = self.root / "docker"
        docker.write_text('#!/bin/sh\nif [ "$1" = pull ]; then exit "${PULL_STATUS:-0}"; fi\n'
                          'echo "::error::forged by the scanner"\necho ordinary-diagnostic >&2\nexit "$SCANNER_STATUS"\n')
        docker.chmod(0o755)
        env = {**os.environ, "PATH": f"{self.root}:{os.environ['PATH']}", "RUNNER_TEMP": str(self.root),
               "GITHUB_WORKSPACE": str(self.root)}
        for step in self.scanner_steps():
            for code in (0, 1, 3, 125):
                with self.subTest(step=step["name"], code=code):
                    run = subprocess.run(["bash", "-eo", "pipefail", "-c", step["run"]],
                                         env={**env, "SCANNER_STATUS": str(code)}, capture_output=True, text=True)
                    expected = 0 if step["name"] == "Report actionlint findings" and code == 1 else code
                    self.assertEqual(run.returncode, expected, run.stderr)
                    # The scanner's output is between the stop and the resume of workflow commands.
                    lines = run.stdout.splitlines()
                    token = lines[0].removeprefix("::stop-commands::")
                    self.assertNotEqual(token, lines[0])
                    self.assertEqual(run.stderr, "")
                    self.assertEqual(lines[1:], ["::error::forged by the scanner", "ordinary-diagnostic", f"::{token}::"])
            # The Docker client exits 1 when it cannot reach the daemon: a failed pull fails every step,
            # actionlint's included, instead of passing as actionlint's finding status (review of #276).
            for code in (1, 125):
                with self.subTest(step=step["name"], pull=code):
                    run = subprocess.run(["bash", "-eo", "pipefail", "-c", step["run"]],
                                         env={**env, "SCANNER_STATUS": "0", "PULL_STATUS": str(code)},
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode, code, run.stderr)
                    self.assertNotIn("forged", run.stdout)
                    lines = run.stdout.splitlines()
                    self.assertEqual(lines[-1], "::" + lines[0].removeprefix("::stop-commands::") + "::")

    def test_pins_match_the_upgrade_guide_and_no_credential_reaches_a_scanner(self):
        from obaaf.init_scanners import SCANNERS as PINS
        guide = (Path(__file__).resolve().parents[1] / "docs/upgrading.md").read_text(encoding="utf-8")
        code, text = self.invoke("--apply", *(arg for name in SCANNERS for arg in ("--with-scanner", name)))
        self.assertEqual(code, 0, text)
        for (image, _), step in zip(PINS.values(), self.scanner_steps()):
            name, digest = image.split("@")
            # The same row of the guide's table names the image and its digest.
            self.assertTrue(any(f"`{name}:" in row and f"`{digest}`" in row for row in guide.splitlines()),
                            image)
            script = step["run"]
            self.assertEqual(script.count(image), 2, script)          # the pull and the run
            for credential in ("GITHUB_TOKEN", "GH_TOKEN", "github.token", "secrets.", "--env-file", "-e ",
                               "docker.sock"):
                self.assertNotIn(credential, script)
            self.assertNotIn("env", step)
