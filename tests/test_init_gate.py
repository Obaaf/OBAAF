import contextlib
from contextlib import nullcontext
from datetime import date, timedelta
from importlib.resources import files
from itertools import combinations
from io import StringIO
import json
import os
from pathlib import Path
import shlex
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


# The SHA-256 of each gate-capable template as it landed, and (in tests/fixtures/init) its bytes. They are
# kept here, not beside the packaged copies in obaaf.fix_gate, so that a packaged copy edited on its own, or
# with its digest, fails a test. A copy, its fixture and its digest edited together cannot be told apart.
FIRST_GATE_DIGEST = "ad3c9f980acc1003b31695d3f7fdbee488ec4ecf10fbe12ac7a8621ddbaa67cb"  # 27b15c9, #293
SETTINGS_GATE_DIGEST = "46cfc1864e30b4b386f0799e98e698809f6727aaac8de6404e5311c014d2b70a"  # review-gpt #367


def previous_steps(names):
    """The scanner steps as init wrote them before #340: without `exec 2>&1`."""
    return steps(names).replace(b"          exec 2>&1\n", b"")


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
        # Resolved, so that a temporary folder reached through a link (macOS's /var) does not count as
        # one of the linked paths init replaces in its follow-up commands.
        self.root = Path(tmp.name).resolve() / "source"
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

    def test_followup_keeps_a_printable_relative_path(self):
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.root)
        directory = Path("-team repo")
        directory.mkdir()
        status, output = command("init", "--", directory)
        self.assertEqual(status, 0, output)
        last = output.splitlines()[-1].removeprefix("Preview available fixes with ")
        self.assertEqual(shlex.split(last), ["obaaf", "fix", "--", str(directory)])

    def test_followup_preserves_a_relative_equals_path(self):
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.root)
        Path("=ls").mkdir()
        fix = "Preview available fixes with obaaf fix -- ./=ls"
        check = "To check the current repository, run obaaf check --summary -- ./=ls"
        for options in ((), ("--apply",)):
            code, output = command("init", *options, "--", "=ls")
            self.assertEqual(code, 0, output)
            self.assertEqual(output.splitlines()[-1], fix)
        with patch("obaaf.checker.check", side_effect=OSError("summary unavailable")):
            code, output = command("init", "--", "=ls")
        self.assertEqual(code, 0, output)
        self.assertEqual(output.splitlines()[-2:], [check, fix])
        for advice, prefix in ((output.splitlines()[-2], "To check the current repository, run "),
                               (output.splitlines()[-1], "Preview available fixes with ")):
            words = shlex.split(advice.removeprefix(prefix))
            expected, _ = command(*words[1:-1], self.root / "=ls")
            actual, replay = command(*words[1:])
            self.assertEqual(actual, expected, replay)
            if words[1] == "check":
                self.assertIn("What to do next:", replay)

    @unittest.skipIf(os.name == "nt", "symbolic links need extra rights on Windows")
    def test_followup_through_a_link_names_the_folder_init_worked_on(self):
        # review-gpt #305: fix does not resolve links as init and check do, so `obaaf fix -- LINKED`
        # refused the repository, and `obaaf fix -- link/..` read another folder.
        real = self.root / "private" / "tmp" / "repo"
        real.mkdir(parents=True)
        (self.root / "tmp").symlink_to(Path("private") / "tmp")
        (self.root / ".github" / "workflows").mkdir(parents=True)
        (self.root / ".github" / "workflows" / "top.yml").write_text(
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo top\n")
        (self.root / "l").symlink_to(Path("private") / "tmp" / "repo" / "inner")
        (real / "inner").mkdir()
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.root)
        for given, folder in ((self.root / "tmp" / "repo", real), (Path("l") / "..", real)):
            with self.subTest(given=str(given)):
                for options in ((), ("--apply",)):
                    code, output = command("init", *options, "--", given)
                    self.assertEqual(code, 0, output)
                    last = output.splitlines()[-1].removeprefix("Preview available fixes with ")
                    self.assertEqual(shlex.split(last), ["obaaf", "fix", "--", str(folder)])
                with patch("obaaf.checker.check", side_effect=OSError("summary unavailable")):
                    code, output = command("init", "--", given)
                self.assertEqual(code, 0, output)
                check = output.splitlines()[-2].removeprefix("To check the current repository, run ")
                self.assertEqual(shlex.split(check), ["obaaf", "check", "--summary", "--", str(folder)])
                words = shlex.split(last)
                expected, _ = command(*words[1:-1], folder)
                actual, replay = command(*words[1:])
                self.assertEqual(actual, expected, replay)
                self.assertNotIn("top.yml", replay)

    @unittest.skipIf(os.name == "nt", "a Windows directory name cannot contain a newline")
    def test_followup_for_a_multiline_directory_uses_the_current_directory(self):
        directory = self.root / "team\nrepo"
        directory.mkdir()
        advice = "From inside the selected repository, run "
        for args in ((), ("--apply",)):
            status, output = command("init", directory, *args)
            self.assertEqual(status, 0, output)
            self.assertEqual(output.splitlines()[-1], advice + "obaaf fix")
        with patch("obaaf.checker.check", side_effect=OSError("summary unavailable")):
            status, output = command("init", directory)
        self.assertEqual(status, 0, output)
        self.assertEqual(output.splitlines()[-2:], [advice + "obaaf check --summary", advice + "obaaf fix"])

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

    def check_crlf_gate(self, *extra, previous_scanners=False):
        self.install(*extra)
        if previous_scanners:
            workflow = self.workflow.read_bytes()
            previous = workflow.replace(b"          exec 2>&1\n", b"")
            self.assertNotEqual(workflow, previous)
            self.workflow.write_bytes(previous)
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

    def test_crlf_gate_preserves_previous_scanner_steps(self):
        self.check_crlf_gate("--with-scanner", "poutine", "--with-scanner", "zizmor",
                             previous_scanners=True)

    def test_the_first_gate_template_as_it_landed_is_recognised(self):
        # review-gpt #306: the other tests build the historical template from the current one, so a
        # digest taken from an edited template would pass them while every workflow installed from the
        # real first gate-capable template fell to manual guidance. This one uses the landed bytes.
        from hashlib import sha256

        from obaaf.fix_gate import FIRST_GATE, ORIGINAL_SETUP, REPORT
        from obaaf.init_scanners import SCANNERS

        first = (Path(__file__).parent / "fixtures/init/gate-template-27b15c9.yaml").read_bytes()
        self.assertEqual(sha256(first).hexdigest(), FIRST_GATE_DIGEST)
        self.assertEqual(FIRST_GATE.read_bytes(), first)
        self.assertIn(ORIGINAL_SETUP, first)
        future = self.root.parent / "release"
        future.mkdir()
        next_setup = b"uses: Obaaf/OBAAF/actions/setup-obaaf@" + b"e" * 40
        (future / "init-workflow.yaml").write_bytes(first.replace(ORIGINAL_SETUP, next_setup))
        gated = first.replace(REPORT, b"gate_check .github/obaaf-baseline.json --fail-on medium\n")
        self.assertNotEqual(gated, first)
        self.install()
        for label, template in (("current template", None), ("rotated template", future)):
            for count in range(len(SCANNERS) + 1):
                for names in combinations(SCANNERS, count):
                    with self.subTest(template=label, scanners=names):
                        tail = steps(names)
                        self.workflow.write_bytes(first + tail)
                        commit(self.root)
                        with patch("obaaf.fix_gate.files", return_value=template) if template else nullcontext():
                            code, text = self.gate("--apply")
                        self.assertEqual(code, 0, text)
                        self.assertIn("Applied the displayed gate change", text)
                        self.assertEqual(self.workflow.read_bytes(), gated + tail)

    def test_every_landed_template_is_packaged_as_it_landed(self):
        from hashlib import sha256

        from obaaf.fix_gate import LANDED, SETTINGS_GATE

        self.assertEqual([sha256(landed.read_bytes()).hexdigest() for landed, _ in LANDED],
                         [FIRST_GATE_DIGEST, SETTINGS_GATE_DIGEST])
        fixtures = Path(__file__).parent / "fixtures/init"
        self.assertEqual([landed.read_bytes() for landed, _ in LANDED],
                         [(fixtures / name).read_bytes() for name in
                          ("gate-template-27b15c9.yaml", "gate-template-settings-8caddd6.yaml")])
        for landed, pin in LANDED:
            self.assertEqual(landed.read_bytes().count(pin), 1)
        # Until the template changes again, the settings template is the one init writes.
        self.assertEqual(SETTINGS_GATE.read_bytes(),
                         files("obaaf.data").joinpath("init-workflow.yaml").read_bytes(),
                         "init-workflow.yaml changed: keep init-gate-settings-8caddd6.yaml, its fixture and its "
                         "digest as they landed, and add the changed template to obaaf.fix_gate.LANDED as a new file")

    def test_landed_templates_are_recognised_after_the_template_changes(self):
        # review-gpt #367: a later edit of the template must not leave workflows installed from an earlier
        # one to manual guidance, at the pin they were installed with or after the documented pin-only
        # update to the current template's commit (docs/upgrading.md).
        from obaaf.fix_gate import LANDED, REPORT
        from obaaf.init_scanners import SCANNERS

        future = self.root.parent / "release"
        future.mkdir()
        next_setup = b"uses: Obaaf/OBAAF/actions/setup-obaaf@" + b"f" * 40
        current = files("obaaf.data").joinpath("init-workflow.yaml").read_bytes()
        source = b"uses: " + yaml.safe_load(current)["jobs"]["check"]["steps"][0]["uses"].encode()
        later = current.replace(source, next_setup).replace(b"permissions:\n", b"# A later edit.\npermissions:\n", 1)
        self.assertNotEqual(later, current.replace(source, next_setup))
        (future / "init-workflow.yaml").write_bytes(later)
        self.install()
        for landed, pin in LANDED:
            body = landed.read_bytes()
            for label, setup in (("landed pin", pin), ("current pin", next_setup)):
                installed = body.replace(pin, setup)
                for before, after in ((installed, b"medium"), (installed.replace(REPORT, b"gate_check .github/obaaf-baseline.json --fail-on high\n"), b"medium")):
                    for names in ((), tuple(SCANNERS)):
                        with self.subTest(template=landed.name, pin=label, gated=before != installed, scanners=names):
                            tail = steps(names)
                            self.workflow.write_bytes(before + tail)
                            commit(self.root)
                            with patch("obaaf.fix_gate.files", return_value=future):
                                code, text = self.gate("--apply")
                            self.assertEqual(code, 0, text)
                            self.assertIn("Applied the displayed gate change", text)
                            gated = installed.replace(REPORT, b"gate_check .github/obaaf-baseline.json --fail-on " + after + b"\n")
                            self.assertEqual(self.workflow.read_bytes(), gated + tail)
                            self.assertIn(setup, self.workflow.read_bytes())

    def test_first_gate_workflow_after_the_documented_pin_update(self):
        # review-gpt #367: docs/upgrading.md tells a team to move a gate-capable workflow's pin to the commit
        # in the current init template and keep the rest. The first template's body at that pin is still
        # recognised now that the current template's body differs from it.
        from obaaf.fix_gate import ORIGINAL_SETUP, REPORT

        first = (Path(__file__).parent / "fixtures/init/gate-template-27b15c9.yaml").read_bytes()
        current = files("obaaf.data").joinpath("init-workflow.yaml").read_bytes()
        source = b"uses: " + yaml.safe_load(current)["jobs"]["check"]["steps"][0]["uses"].encode()
        self.assertNotEqual(first.replace(ORIGINAL_SETUP, source), current)
        moved = first.replace(ORIGINAL_SETUP, source).replace(
            REPORT, b"gate_check .github/obaaf-baseline.json --fail-on medium\n") + steps(["zizmor"])
        self.install()
        self.workflow.write_bytes(moved)
        commit(self.root)
        code, text = command("fix", self.root, "--gate", "high", "--apply")
        self.assertEqual(code, 0, text)
        self.assertIn("Applied the displayed gate change", text)
        self.assertEqual(self.workflow.read_bytes(), moved.replace(b"--fail-on medium", b"--fail-on high"))

    def test_gate_preview_says_its_count_does_not_read_the_snapshot(self):
        # review-gpt #367: the preview cannot take --settings (D-112), while a run of the generated
        # workflow with OBAAF_USE_SETTINGS reads .github/obaaf-settings.json, and its count can differ.
        self.install()
        commit(self.root)
        note = "This count does not use .github/obaaf-settings.json."
        status, preview = self.gate()
        self.assertEqual(status, 0, preview)
        self.assertNotIn(note, preview)
        (self.root / ".github/obaaf-settings.json").write_text("{}\n")
        commit(self.root)
        status, preview = self.gate()
        self.assertEqual(status, 0, preview)
        self.assertIn(note, preview)
        # The first template does not read the variable, so the note would mislead there.
        first = (Path(__file__).parent / "fixtures/init/gate-template-27b15c9.yaml").read_bytes()
        self.workflow.write_bytes(first)
        commit(self.root)
        status, preview = self.gate()
        self.assertEqual(status, 0, preview)
        self.assertIn("Gate preview at --fail-on medium", preview)
        self.assertNotIn(note, preview)

    def test_crlf_threshold_change_after_a_pin_rotation_keeps_pin_and_endings(self):
        # review-gpt #306, as the queue asks: #306's historical-template search and #293's CRLF
        # handling together. A gate written with the original checker, in CRLF, changes threshold
        # under a newer template without taking the newer pin or losing its line endings.
        from obaaf.fix_gate import SETTINGS_SETUP

        self.install()
        current = files("obaaf.data").joinpath("init-workflow.yaml").read_bytes()
        source = yaml.safe_load(current)["jobs"]["check"]["steps"][0]["uses"].encode()
        historical = current.replace(b"uses: " + source, SETTINGS_SETUP)
        future = self.root.parent / "release"
        future.mkdir()
        next_setup = b"uses: Obaaf/OBAAF/actions/setup-obaaf@" + b"d" * 40
        (future / "init-workflow.yaml").write_bytes(historical.replace(SETTINGS_SETUP, next_setup))
        tail = steps(["zizmor"])
        high = historical.replace(b'obaaf check source "${config[@]}" --fail-on never',
                                  b"gate_check .github/obaaf-baseline.json --fail-on high") + tail
        self.workflow.write_bytes(high.replace(b"\n", b"\r\n"))
        commit(self.root)
        with patch("obaaf.fix_gate.files", return_value=future):
            code, text = self.gate("--apply")
        self.assertEqual(code, 0, text)
        self.assertIn("Applied the displayed gate change", text)
        written = self.workflow.read_bytes()
        self.assertEqual(written, high.replace(b"--fail-on high", b"--fail-on medium").replace(b"\n", b"\r\n"))
        self.assertIn(SETTINGS_SETUP, written)
        self.assertNotIn(next_setup, written)

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

    def test_scanner_steps_in_mixed_or_edited_form_get_manual_guidance(self):
        # review-gpt #345: only a complete current or complete pre-#340 suffix is recognised.
        self.install("--with-scanner", "zizmor", "--with-scanner", "actionlint")
        current = self.workflow.read_bytes()
        names = ["zizmor", "actionlint"]
        body = current.removesuffix(steps(names))
        self.assertNotEqual(body, current)
        mixed = body + steps(names).replace(b"          exec 2>&1\n", b"", 1)
        edited = body + previous_steps(names).replace(b"status=0\n", b"status=0 \n", 1)
        for label, before in (("mixed", mixed), ("edited", edited)):
            with self.subTest(label):
                self.assertNotIn(before, (current, body + previous_steps(names)))
                self.workflow.write_bytes(before)
                commit(self.root)
                code, text = self.gate("--apply")
                self.assertEqual(code, 0, text)
                self.assertIn("by hand", text)
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

    def test_gate_changes_after_a_setup_pin_rotation(self):
        from obaaf.fix_gate import SETTINGS_SETUP
        from obaaf.init_scanners import SCANNERS

        self.install()
        current = files("obaaf.data").joinpath("init-workflow.yaml").read_bytes()
        source = yaml.safe_load(current)["jobs"]["check"]["steps"][0]["uses"].encode()
        historical = current.replace(b"uses: " + source, SETTINGS_SETUP)
        future = self.root.parent / "release"
        future.mkdir()
        next_setup = b"uses: Obaaf/OBAAF/actions/setup-obaaf@" + b"c" * 40
        (future / "init-workflow.yaml").write_bytes(historical.replace(SETTINGS_SETUP, next_setup))
        legacy = (Path(__file__).parent / "fixtures/init/report-only-3.3.yaml").read_bytes()
        path = self.root / "policy files" / "accepted.json"
        path.parent.mkdir()
        path.write_text('{"format":"obaaf-baseline/v0.2","findings":[]}')
        old_gate = historical.replace(b"/.github/obaaf-baseline.json\n", b"/policy files/accepted.json\n").replace(
            b'obaaf check source "${config[@]}" --fail-on never', b"gate_check 'policy files/accepted.json' --fail-on high")
        expected = old_gate.replace(b"--fail-on high", b"--fail-on medium")
        with patch("obaaf.fix_gate.files", return_value=future):
            for count in range(len(SCANNERS) + 1):
                for names in combinations(SCANNERS, count):
                    # review-gpt #345: scanner steps written before #340 are kept as they are.
                    for form, tail in (("current steps", steps(names)), ("pre-#340 steps", previous_steps(names))):
                        for label, report in (("current report", historical), ("legacy report", legacy),
                                              ("previous gate", old_gate)):
                            with self.subTest(scanners=names, steps=form, workflow=label):
                                self.workflow.write_bytes(report + tail)
                                commit(self.root)
                                code, text = self.gate("--baseline", path, "--apply")
                                self.assertEqual(code, 0, text)
                                self.assertIn("Applied the displayed gate change", text)
                                if label == "legacy report":
                                    first = (Path(__file__).parent / "fixtures/init/gate-template-27b15c9.yaml").read_bytes()
                                    first = first.replace(b"/.github/obaaf-baseline.json\n", b"/policy files/accepted.json\n")
                                    expected_body = first.replace(b'obaaf check source "${config[@]}" --fail-on never',
                                                                  b"gate_check 'policy files/accepted.json' --fail-on medium")
                                else:
                                    expected_body = expected
                                self.assertEqual(self.workflow.read_bytes(), expected_body + tail)
                                self.assertIn("already gates", self.gate("--baseline", path)[1])
            self.workflow.write_bytes(historical.replace(SETTINGS_SETUP, next_setup))
            commit(self.root)
            code, text = self.gate("--baseline", path, "--apply")
            self.assertEqual(code, 0, text)
            self.assertEqual(self.workflow.read_bytes(), expected.replace(SETTINGS_SETUP, next_setup))

            custom = historical.replace(SETTINGS_SETUP, b"uses: team/custom-checker@v1")
            self.workflow.write_bytes(custom)
            code, text = self.gate("--baseline", path, "--apply")
            self.assertEqual(code, 0, text)
            self.assertIn("by hand", text)
            self.assertEqual(self.workflow.read_bytes(), custom)

    def execute_ci(self, event, *, settings=False):
        work = self.root.parent
        temp = work / "temp"
        temp.mkdir(exist_ok=True)
        installed = os.environ.get("OBAAF_TEST_PINNED_CHECKER")
        python_dir = Path(installed or sys.executable).parent
        path = os.pathsep.join((str(work), str(python_dir), os.environ["PATH"]))
        env = {**os.environ, "GITHUB_EVENT_NAME": event, "RUNNER_TEMP": str(temp),
               "PATH": path, "USE_SETTINGS": "true" if settings else ""}
        if installed:
            env.pop("PYTHONPATH", None)
        script = yaml.safe_load(self.workflow.read_text())["jobs"]["check"]["steps"][3]["run"]
        return subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=work, text=True,
                              capture_output=True, env=env)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and Git")
    def test_generated_ci_reads_opted_in_settings_from_the_event_commit(self):
        from test_settings_audit import recording, take

        self.install()
        work = self.root.parent
        policy = work / "policy"
        folder = self.root / ".github"
        (folder / "CODEOWNERS").write_text("* @example/build\n")
        snapshot = folder / "obaaf-settings.json"
        observed, _ = take(recording("admin-token"), token="dummy")
        snapshot.write_text(json.dumps(observed))
        target = snapshot.read_bytes()
        commit(self.root)
        subprocess.run(["git", "clone", "-q", str(self.root), str(policy)], check=True)
        subprocess.run(["git", "-C", str(self.root), "remote", "add", "origin",
                        "https://github.com/example-studio/game.git"], check=True)
        # The hosted acceptance run supplies the executable installed by the generated setup action.
        checker = work / "obaaf"
        if installed := os.environ.get("OBAAF_TEST_PINNED_CHECKER"):
            checker.symlink_to(Path(installed).resolve(strict=True))
        else:
            checker.write_text(f"#!{sys.executable}\nfrom obaaf.cli import main\nraise SystemExit(main())\n")
            checker.chmod(0o755)
        generated = yaml.safe_load(self.workflow.read_bytes())["jobs"]["check"]["steps"]
        self.assertEqual(generated[3]["env"]["USE_SETTINGS"], "${{ vars.OBAAF_USE_SETTINGS }}")
        self.assertEqual(generated[2]["with"]["ref"], "${{ github.event.pull_request.base.sha }}")
        self.assertIn("/.github/obaaf-settings.json", generated[2]["with"]["sparse-checkout"].splitlines())

        for gated in (False, True):
            if gated:
                status, out = self.gate("--apply")
                self.assertEqual(status, 0, out)
                commit(self.root)
            # An invalid source snapshot proves which bytes the installed checker parses.
            snapshot.write_text("{}")
            commit(self.root)
            off = self.execute_ci("push")
            self.assertIn(off.returncode, (0, 1) if gated else (0,), off.stdout + off.stderr)
            self.assertNotIn("error: --settings", off.stderr)
            self.assertNotIn("Settings snapshot for", off.stderr)
            pr = self.execute_ci("pull_request", settings=True)
            self.assertIn(pr.returncode, (0, 1) if gated else (0,), pr.stdout + pr.stderr)
            self.assertIn("What to do next", pr.stdout)
            self.assertNotIn("error: --settings", pr.stderr)
            # Each obaaf check the step runs (the report, or once gated the gate alone) read the target's.
            self.assertEqual(pr.stderr.count(f"Settings snapshot for {observed['repository']}, taken "), 1,
                             pr.stderr)
            self.assertEqual(snapshot.read_bytes(), target)
            push = self.execute_ci("push", settings=True)
            self.assertEqual(push.returncode, 2, push.stdout + push.stderr)
            self.assertIn("error: --settings", push.stderr)
            snapshot.write_bytes(target)
            commit(self.root)

        (policy / ".github/obaaf-settings.json").unlink()
        commit(policy)
        missing = self.execute_ci("pull_request", settings=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("must be a regular file committed in the target commit", missing.stderr)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and Git")
    def test_generated_ci_refuses_a_github_folder_it_cannot_read_as_one(self):
        # review-gpt #367: neither guard had a test. The target's .github is read from Git, so a link or a
        # submodule there fails every pull request run, with or without the settings opt-in; the checked-out
        # .github must be a directory when the snapshot is written into it.
        self.install()
        work = self.root.parent
        policy = work / "policy"
        policy.mkdir()
        (policy / "elsewhere").mkdir()
        (policy / "elsewhere/obaaf.yml").write_text("{}\n")
        (policy / ".github").symlink_to("elsewhere")
        commit(policy)
        commit(self.root)
        stub = work / "obaaf"
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
        for settings in (False, True):
            with self.subTest(settings=settings):
                result = self.execute_ci("pull_request", settings=settings)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("On the target commit, .github must be a directory", result.stderr)
        shutil.rmtree(policy)
        subprocess.run(["git", "clone", "-q", str(self.root), str(policy)], check=True)
        (policy / ".github/obaaf-settings.json").write_text("{}\n")
        commit(policy)
        shutil.move(self.root / ".github", work / "moved")
        (self.root / ".github").symlink_to(work / "moved")
        result = self.execute_ci("pull_request", settings=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("the checked-out .github must be a directory, not a link", result.stderr)
        self.assertFalse((work / "moved/obaaf-settings.json").exists())

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
