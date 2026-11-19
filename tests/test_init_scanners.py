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
        docker.write_text('#!/bin/sh\nexit "$SCANNER_STATUS"\n')
        docker.chmod(0o755)
        env = {**os.environ, "PATH": f"{self.root}:{os.environ['PATH']}", "RUNNER_TEMP": str(self.root),
               "GITHUB_WORKSPACE": str(self.root)}
        for step in self.scanner_steps():
            for code in (0, 1, 3, 125):
                with self.subTest(step=step["name"], code=code):
                    run = subprocess.run(["bash", "-eo", "pipefail", "-c", step["run"]],
                                         env={**env, "SCANNER_STATUS": str(code)}, capture_output=True)
                    expected = 0 if step["name"] == "Report actionlint findings" and code == 1 else code
                    self.assertEqual(run.returncode, expected, run.stderr)
