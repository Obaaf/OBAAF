"""The paperwork preview exposes only verified edits and never writes them."""

from datetime import date, timedelta
import unittest

from helpers import TempDir, run_cli


class FixCliTest(unittest.TestCase):
    def setUp(self):
        tmp = TempDir()
        self.root = tmp.__enter__()
        self.addCleanup(tmp.__exit__)
        self.workflow = self.root / ".github/workflows/build.yml"
        self.workflow.parent.mkdir(parents=True)
        self.workflow.write_text("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                                 "    steps:\n      - uses: actions/checkout@v4\n")
        self.config = self.root / ".github/obaaf.yml"

    def test_each_acceptance_precedes_the_diff_and_remains_unwritten(self):
        expiry = (date.today() + timedelta(days=28)).isoformat()
        source = ("ignore:\n  - rule: OBAAF-GHA-008\n    path: .github/workflows/build.yml\n"
                  f"    reason: reviewed for adoption\n    until: {expiry}\n")
        self.config.write_text(source)
        code, out, err = run_cli("fix", self.root, "--owner", "@team")
        self.assertEqual(code, 0, err)
        self.assertIn("You are accepting risk (1 finding)", out)
        self.assertIn(f"@team until {expiry}: reviewed for adoption", out)
        self.assertLess(out.index("OBAAF-GHA-008"), out.index("--- a/"))
        self.assertIn("Checked on a copy:", out)
        self.assertEqual(self.config.read_text(), source)
        self.assertFalse((self.root / ".github/CODEOWNERS").exists())

    def test_explicit_metadata_and_named_check_inputs(self):
        code, _, err = run_cli("fix", self.root, "--reason", "reviewed for adoption")
        self.assertEqual(code, 2)
        self.assertIn("--owner", err)
        code, _, err = run_cli("fix", self.root, "--baseline", self.root.parent / "outside.json")
        self.assertEqual(code, 2)
        self.assertIn("inside the repository", err)

    def test_manual_owner_guidance_makes_no_files(self):
        code, out, err = run_cli("fix", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("Review CODEOWNERS by hand", out)
        self.assertIn("/.github/workflows/*.yml OWNER", out)
        self.assertNotIn("--- a/", out)
        self.assertFalse(self.config.exists())

    def test_custom_gate_file_has_exact_manual_owner_guidance(self):
        from obaaf.checker import baseline
        import json

        policy = self.root / "policy.json"
        policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": []}))
        code, out, err = run_cli("fix", self.root, "--baseline", policy)
        self.assertEqual(code, 0, err)
        self.assertIn("/policy.json OWNER", out)
        self.assertFalse((self.root / ".github/CODEOWNERS").exists())

    def test_unprovable_lane_change_leaves_separate_owner_preview_intact(self):
        from obaaf import checker
        from obaaf.checker import baseline
        import json

        expiry = (date.today() + timedelta(days=28)).isoformat()
        self.config.write_text(
            "lanes:\n  .github/workflows/build.yml#build: trused\n"
            "ignore:\n  - rule: OBAAF-GHA-008\n    path: .github/workflows/build.yml\n"
            f"    reason: previously reviewed\n    until: {expiry}\n")
        lane = next(f for f in checker.check(self.root).findings if f.kind == "entry-not-a-lane")
        policy = self.root / "accepted.json"
        policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": [
            baseline.entry_for(lane, "@prior", "separate review", expiry)]}))
        source = self.config.read_bytes()
        code, out, err = run_cli("fix", self.root, "--baseline", policy, "--owner", "@team")
        self.assertEqual(code, 0, err)
        self.assertIn("Could not be made automatically:", out)
        self.assertIn("You are accepting risk (1 finding)", out)
        self.assertIn("0 stale entries", out)
        self.assertNotIn("+  .github/workflows/build.yml#build: trusted", out)
        self.assertEqual(self.config.read_bytes(), source)

    def test_diff_preserves_crlf_and_marks_missing_final_newline(self):
        self.config.write_bytes(b"lanes:\r\n  .github/workflows/build.yml#build: trused")
        code, out, err = run_cli("fix", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn(" lanes:\r\n", out)
        self.assertIn(r"\ No newline at end of file", out)
        self.assertTrue(self.config.read_bytes().endswith(b"trused"))


class FixCliReviewTest(unittest.TestCase):
    """From the review of #278 (run goosander); each failed on 2538c5f."""

    def setUp(self):
        FixCliTest.setUp(self)
        self.expiry = (date.today() + timedelta(days=28)).isoformat()

    def test_an_ignore_entry_with_a_key_that_is_not_text_is_no_traceback(self):
        for key in ("1", "true", "~"):
            with self.subTest(key=key):
                self.config.write_text("ignore:\n  - rule: OBAAF-GHA-008\n    path: .github/workflows/build.yml\n"
                                       f"    reason: reviewed pin\n    until: {self.expiry}\n    {key}: note\n")
                code, out, err = run_cli("fix", self.root, "--owner", "@team")
                self.assertEqual(code, 0, err)
                self.assertNotIn("Traceback", err)
                self.assertIn("You are accepting risk", out)

    def test_an_ignore_setting_that_is_not_a_list_is_an_error(self):
        for value in ("5", "true"):
            with self.subTest(value=value):
                self.config.write_text(f"ignore: {value}\n")
                for command in ("fix", "check"):
                    code, _, err = run_cli(command, self.root)
                    self.assertEqual(code, 2, err)
                    self.assertIn("ignore must be a list of entries", err)

    def test_a_linked_configuration_name_is_escaped_in_the_diff(self):
        import os
        target = self.root / "conf\x1b[31mRED\x07.yml"
        target.write_text("ignore:\n  - rule: OBAAF-GHA-008\n    path: absent.yml\n"
                          f"    reason: reviewed pin\n    until: {self.expiry}\n")
        os.symlink(os.path.relpath(target, self.config.parent), self.config)
        code, out, err = run_cli("fix", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("Remove unmatched ignore entry 1", out)
        self.assertIn("--- a/", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_a_partial_check_withholds_a_lane_correction(self):
        self.config.write_text("lanes:\n  .github/workflows/build.yml#build: trused\n")
        code, out, err = run_cli("fix", self.workflow, "--config", self.config)
        self.assertEqual(code, 0, err)
        self.assertIn("a partial check cannot establish what the correction changes", out)
        self.assertNotIn("--- a/", out)
        code, out, err = run_cli("fix", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("Correct lane", out)
        self.assertIn("+  .github/workflows/build.yml#build: trusted", out)

    def test_a_comment_beside_the_last_flow_entries_is_not_moved(self):
        source = ("ignore: [\n"
                  "  {rule: OBAAF-GHA-008, owner: '@prior', path: .github/workflows/build.yml, reason: reviewed, "
                  f"until: '{self.expiry}'}}, # reviewed by security\n"
                  f"  {{rule: OBAAF-GHA-008, path: absent.yml, reason: reviewed, until: '{self.expiry}'}} # file is gone\n"
                  "]\n")
        self.config.write_text(source)
        code, out, err = run_cli("fix", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("a comment beside the last entries of a flow-style list would move", out)
        self.assertNotIn("--- a/", out)
        self.assertEqual(self.config.read_text(), source)
