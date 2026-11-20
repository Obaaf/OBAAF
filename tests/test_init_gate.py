import contextlib
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from obaaf import cli
from obaaf.init import WORKFLOW
from obaaf.init_scanners import steps


def command(*args):
    out = StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        status = cli.main(list(map(str, args)))
    return status, out.getvalue()


def commit(root):
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=test@example.com",
                    "commit", "--allow-empty", "-qm", "fixture"], check=True)


class GateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "source"
        self.root.mkdir()
        self.workflow = self.root / WORKFLOW

    def install(self, *extra):
        code, text = command("init", self.root, "--apply", *extra)
        self.assertEqual(code, 0, text)
        return text

    def gate(self, *extra):
        return command("fix", self.root, "--gate", "medium", *extra)

    def test_init_ends_with_action_list_for_requested_path(self):
        status, preview = command("init", self.root)
        self.assertEqual(status, 0, preview)
        self.assertIn("Proposed setup on a temporary copy:", preview)
        self.assertEqual(list(self.root.iterdir()), [])
        applied = self.install()
        self.assertIn("Current repository:", applied)
        self.assertEqual(preview.split("What to do next:")[-1], applied.split("What to do next:")[-1])
        self.assertIn("What to do next: 1 finding", preview)
        self.assertTrue(applied.rstrip().endswith(f"obaaf fix -- {self.root}"))

    def test_copy_refusal_labels_the_actual_repository_and_writes_nothing(self):
        from obaaf.fix_copy import PrivateCopyError
        with patch("obaaf.fix_copy.private_copy", side_effect=PrivateCopyError("unavailable on this platform")):
            code, text = command("init", self.root)
        self.assertEqual(code, 0, text)
        self.assertIn("Could not simulate the proposed setup", text)
        self.assertIn("Current repository before applying either file", text)
        self.assertNotIn("Proposed setup on a temporary copy:", text)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_apply_reports_successful_install_if_followup_check_is_unavailable(self):
        with patch("obaaf.checker.check", side_effect=OSError("summary unavailable")):
            code, text = command("init", self.root, "--apply")
        self.assertEqual(code, 0, text)
        self.assertTrue(self.workflow.is_file())
        self.assertIn("Setup files installed. The follow-up summary was unavailable", text)
        self.assertIn("obaaf check --summary", text)

    def test_gate_is_separate_and_changes_only_one_command(self):
        self.install("--with-scanner", "poutine")
        original = self.workflow.read_bytes()
        self.assertNotIn("gate preview", command("fix", self.root)[1].lower())
        status, out = self.gate()
        self.assertEqual(status, 0, out)
        self.assertIn("1 finding currently counts", out)
        self.assertIn("zero baseline acceptances", out)
        self.assertEqual(self.workflow.read_bytes(), original)
        code, text = self.gate("--apply")
        self.assertNotEqual(code, 0, text)  # untracked
        self.assertEqual(self.workflow.read_bytes(), original)
        commit(self.root)
        status, refusal = self.gate("--fail-on", "medium", "--apply")
        self.assertEqual(status, 2, refusal)
        self.assertIn("omit acceptance metadata and --fail-on", refusal)
        self.assertEqual(self.workflow.read_bytes(), original)
        status, text = self.gate("--apply")
        self.assertEqual(status, 0, text)
        after = self.workflow.read_text()
        self.assertEqual(after, original.decode().replace('obaaf check source "${config[@]}" --fail-on never',
                                                           'gate_check .github/obaaf-baseline.json --fail-on medium'))
        self.assertFalse((self.root / ".github/obaaf-baseline.json").exists())
        self.assertIn("already gates", self.gate()[1])
        self.assertNotEqual(self.gate("--owner", "@demo")[0], 0)

    def check_crlf_gate(self, *extra):
        self.install(*extra)
        (self.root / ".gitattributes").write_text(f"{WORKFLOW} text eol=crlf\n")
        commit(self.root)
        self.workflow.unlink()
        subprocess.run(["git", "-C", str(self.root), "checkout", "--", str(WORKFLOW)], check=True)
        before = self.workflow.read_bytes()
        self.assertIn(b"\r\n", before)
        self.assertNotIn(b"\n", before.replace(b"\r\n", b""))
        status, preview = self.gate()
        self.assertEqual(status, 0, preview)
        self.assertIn("Gate preview at --fail-on medium", preview)
        self.assertEqual(self.workflow.read_bytes(), before)
        status, applied = self.gate("--apply")
        self.assertEqual(status, 0, applied)
        expected = before.replace(b'obaaf check source "${config[@]}" --fail-on never\r\n',
                                  b"gate_check .github/obaaf-baseline.json --fail-on medium\r\n")
        self.assertNotEqual(expected, before)
        self.assertEqual(self.workflow.read_bytes(), expected)

    def test_crlf_gate(self):
        self.check_crlf_gate()

    def test_crlf_gate_with_scanner(self):
        self.check_crlf_gate("--with-scanner", "poutine")

    def test_mixed_endings_and_custom_crlf_workflow_get_manual_guidance(self):
        self.install()
        generated = self.workflow.read_bytes().replace(b"\r\n", b"\n")
        crlf = generated.replace(b"\n", b"\r\n")
        for before in (crlf.replace(b"\r\n", b"\n", 1), crlf + b"# team change\r\n"):
            with self.subTest(before=before[:80]):
                self.workflow.write_bytes(before)
                commit(self.root)
                code, text = self.gate("--apply")
                self.assertEqual(code, 0, text)
                self.assertIn("by hand", text)
                self.assertEqual(self.workflow.read_bytes(), before)

    def test_unsupported_gate_preview_gives_manual_guidance_and_apply_refuses(self):
        self.install()
        commit(self.root)
        before = self.workflow.read_bytes()
        with patch("obaaf.fix_apply.XATTR_FUNCTIONS", ("no_such_function",)):
            status, preview = self.gate()
            self.assertEqual(status, 0, preview)
            self.assertIn("Make the displayed changes by hand", preview)
            self.assertNotIn("Run again with --apply", preview)
            self.assertEqual(self.workflow.read_bytes(), before)
            status, refusal = self.gate("--apply")
            self.assertEqual(status, 2, refusal)
            self.assertIn("supported only on Linux", refusal)
            self.assertEqual(self.workflow.read_bytes(), before)

    def test_repeat_gate_validates_its_explicit_baseline(self):
        self.install()
        path = self.root / "accepted.json"
        path.write_text('{"format":"obaaf-baseline/v0.2","findings":[]}')
        commit(self.root)
        self.assertEqual(self.gate("--baseline", path, "--apply")[0], 0)
        gated = self.workflow.read_bytes()
        self.assertIn("already gates", self.gate("--baseline", path)[1])
        path.unlink()
        code, text = self.gate("--baseline", path)
        self.assertEqual(code, 2, text)
        self.assertIn("explicitly selected baseline must exist", text)
        path.write_text("invalid")
        code, text = self.gate("--baseline", path, "--apply")
        self.assertEqual(code, 2, text)
        self.assertIn("cannot be read", text)
        self.assertEqual(self.workflow.read_bytes(), gated)

    def test_custom_ci_gets_manual_guidance_and_remains_unchanged(self):
        self.install()
        self.workflow.write_bytes(self.workflow.read_bytes() + b"# team change\n")
        before = self.workflow.read_bytes()
        code, text = self.gate("--apply")
        self.assertEqual(code, 0, text)
        self.assertIn("by hand", text)
        self.assertIn("--fail-on medium", text)
        self.assertEqual(self.workflow.read_bytes(), before)

    def test_earlier_generated_workflow_with_companions_is_recognized(self):
        self.install()
        old = Path(__file__).parent / "fixtures/init/report-only-3.3.yaml"
        tail = steps(["zizmor", "actionlint"])
        self.workflow.write_bytes(old.read_bytes() + tail)
        commit(self.root)
        code, text = self.gate("--apply")
        self.assertEqual(code, 0, text)
        self.assertIn("Applied the displayed gate change", text)
        self.assertTrue(self.workflow.read_bytes().endswith(tail))

    @unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and Git")
    def test_actual_ci_script_reads_only_the_target_policy_on_pr(self):
        self.install()
        baseline = self.root / ".github/obaaf-baseline.json"
        baseline.write_text(json.dumps({"format": "obaaf-baseline/v0.2", "findings": []}))
        commit(self.root)
        self.assertEqual(self.gate("--apply")[0], 0)
        text = self.workflow.read_text()
        script = yaml.safe_load(text)["jobs"]["check"]["steps"][3]["run"]
        work = self.root.parent
        temp = work / "temp"
        temp.mkdir()
        stub = work / "obaaf"
        stub.write_text("""#!/bin/bash
set -eu
echo "$*"
while (( $# )); do
  case "$1" in
    --config) cat "$2"; shift ;;
    --baseline) cat "$2"; shift ;;
  esac
  shift
done
""")
        stub.chmod(0o755)
        policy = work / "policy"
        folder = policy / ".github"
        folder.mkdir(parents=True)
        (folder / "obaaf.yml").write_text("# target config\n")
        config = self.root / ".github/obaaf.yml"
        config.write_text("# PR config\n")
        commit(policy)

        def execute(event):
            return subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=work, text=True,
                                  capture_output=True, env={**os.environ, "GITHUB_EVENT_NAME": event,
                                  "RUNNER_TEMP": str(temp), "PATH": str(work) + os.pathsep + os.environ["PATH"]})

        baseline.write_text("PR BASELINE\n")
        missing = execute("pull_request")
        self.assertEqual(missing.returncode, 0, missing.stderr)
        self.assertIn("# target config", missing.stdout)
        self.assertNotIn("--baseline", missing.stdout)
        self.assertNotIn("PR BASELINE", missing.stdout)
        pushed = execute("push")
        self.assertEqual(pushed.returncode, 0, pushed.stderr)
        self.assertIn("PR BASELINE", pushed.stdout)
        (folder / baseline.name).write_text("TARGET BASELINE\n")
        commit(policy)
        target = execute("pull_request")
        self.assertEqual(target.returncode, 0, target.stderr)
        self.assertIn("TARGET BASELINE", target.stdout)
        self.assertNotIn("PR BASELINE", target.stdout)
        # A PR that removes the directory containing a custom baseline still uses the target's file.
        custom = Path("adoption/policy/team-baseline.json")
        (self.root / custom).parent.mkdir(parents=True)
        (self.root / custom).write_text('{"format":"obaaf-baseline/v0.2","findings":[]}')
        self.workflow.write_text(text.replace("gate_check .github/obaaf-baseline.json --fail-on medium",
                                              'obaaf check source "${config[@]}" --fail-on never'))
        commit(self.root)
        code, out = self.gate("--apply", "--baseline", self.root / custom)
        self.assertEqual(code, 0, out)
        script = yaml.safe_load(self.workflow.read_text())["jobs"]["check"]["steps"][3]["run"]
        (policy / custom).parent.mkdir(parents=True)
        (policy / custom).write_text("CUSTOM TARGET BASELINE\n")
        commit(policy)
        shutil.rmtree(self.root / "adoption")
        nested = execute("pull_request")
        self.assertEqual(nested.returncode, 0, nested.stderr)
        self.assertIn("CUSTOM TARGET BASELINE", nested.stdout)

        shutil.rmtree(policy / ".git")
        self.assertNotEqual(execute("pull_request").returncode, 0)
