import contextlib
from datetime import date, timedelta
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import sys
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

    def test_gate_and_tool_pin_cannot_be_applied_together(self):
        self.install()
        commit(self.root)
        original = self.workflow.read_bytes()
        pin = ("--pin", "@openai/codex=1.2.3")
        gate = ("--gate", "medium")
        for options in ((*gate, *pin), (*pin, *gate)):
            with self.subTest(options=options):
                code, text = command("fix", self.root, *options, "--apply")
                self.assertEqual(code, 2, text)
                self.assertIn("--gate is a separate operation", text)
                self.assertEqual(self.workflow.read_bytes(), original)

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

    def execute_ci(self, event):
        work = self.root.parent
        temp = work / "temp"
        temp.mkdir(exist_ok=True)
        path = os.pathsep.join((str(work), str(Path(sys.executable).parent), os.environ["PATH"]))
        script = yaml.safe_load(self.workflow.read_text())["jobs"]["check"]["steps"][3]["run"]
        return subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=work, text=True,
                              capture_output=True, env={**os.environ, "GITHUB_EVENT_NAME": event,
                              "RUNNER_TEMP": str(temp), "PATH": path})

    @unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and Git")
    def test_actual_ci_script_limits_pr_acceptances_to_both_commits(self):
        self.install()
        work = self.root.parent
        policy = work / "policy"
        (policy / ".github").mkdir(parents=True)
        (policy / ".github/obaaf.yml").write_text("# target config\n")
        commit(policy)
        relative = Path("adoption/policy/team-baseline.json")
        baseline = self.root / relative
        baseline.parent.mkdir(parents=True)
        shared = {"rule": "OBAAF-GHA-011", "severity": "medium", "path": "workflow.yml",
                  "owner": "@demo", "reason": "pending review", "expires": str(date.today() + timedelta(days=30))}
        second = dict(shared, path="other.yml")
        changed = dict(shared, severity="high")
        added = dict(shared, path="new.yml")

        def write(path, entries):
            path.write_text(json.dumps({"format": "obaaf-baseline/v0.2", "findings": entries}))

        source_entries = [added, second, shared, shared, changed]
        write(baseline, [])
        commit(self.root)
        status, output = self.gate("--apply", "--baseline", baseline)
        self.assertEqual(status, 0, output)
        write(baseline, source_entries)
        commit(self.root)
        stub = work / "obaaf"
        stub.write_text("""#!/bin/bash
set -eu
while (( $# )); do
  case "$1" in
    --config) cat "$2"; shift ;;
    --baseline) cp -- "$2" observed.json; shift ;;
  esac
  shift
done
""")
        stub.chmod(0o755)
        observed = work / "observed.json"

        def run(event):
            observed.unlink(missing_ok=True)
            result = self.execute_ci(event)
            self.assertEqual(result.returncode, 0, result.stderr)
            if event == "pull_request":
                self.assertIn("# target config", result.stdout)
            return json.loads(observed.read_text())["findings"] if observed.exists() else []

        self.assertEqual(run("pull_request"), [])
        self.assertEqual(run("push"), source_entries)
        target = policy / relative
        target.parent.mkdir(parents=True)
        write(target, [shared, dict(changed, owner="@other"), second])
        commit(policy)
        # The working copies disagree with both commits.
        write(target, [added])
        write(baseline, [added])
        self.assertEqual(run("pull_request"), [shared, second])
        shutil.rmtree(self.root / "adoption")
        commit(self.root)
        self.assertEqual(run("pull_request"), [])
        shutil.rmtree(policy / ".git")
        self.assertNotEqual(self.execute_ci("pull_request").returncode, 0)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and Git")
    def test_real_pr_gate_allows_a_fix_and_rejects_an_unfixed_finding(self):
        self.install()
        (self.root / ".github/CODEOWNERS").write_text("* @reviewers\n")
        example = self.root / ".github/workflows/build.yml"
        example.write_text("""name: build
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
        baseline = self.root / ".github/obaaf-baseline.json"
        code, report = command("check", self.root, "--write-baseline", baseline, "--owner", "@demo",
                               "--reason", "Scheduled for remediation", "--expires",
                               date.today() + timedelta(days=30), "--fail-on", "never")
        self.assertEqual(code, 0, report)
        document = json.loads(baseline.read_text())
        rel = example.relative_to(self.root).as_posix()
        removed = [entry for entry in document["findings"]
                   if entry["path"] == rel and entry["rule"] == "OBAAF-GHA-011"]
        self.assertEqual(len(removed), 1, report)
        commit(self.root)
        code, report = self.gate("--apply")
        self.assertEqual(code, 0, report)
        commit(self.root)
        work = self.root.parent
        subprocess.run(["git", "clone", "-q", str(self.root), str(work / "policy")], check=True)
        checker = work / "obaaf"
        checker.write_text(f"#!{sys.executable}\nfrom obaaf.cli import main\nraise SystemExit(main())\n")
        checker.chmod(0o755)

        def check(event, expected):
            result = self.execute_ci(event)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

        check("pull_request", 0)
        document["findings"] = [entry for entry in document["findings"] if entry not in removed]
        baseline.write_text(json.dumps(document))
        commit(self.root)
        check("pull_request", 1)
        example.write_text(example.read_text() + "        with:\n          persist-credentials: false\n")
        commit(self.root)
        check("pull_request", 0)
        check("push", 0)
