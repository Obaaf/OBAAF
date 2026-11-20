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

    def test_invalid_preview_inputs_name_the_repository_files(self):
        for flag, path, data in (("--baseline", self.root / "team baseline.json", b"["),
                                 ("--config", self.config, b"[one]")):
            with self.subTest(flag=flag):
                path.write_bytes(data)
                code, out, err = run_cli("fix", self.root, flag, path)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("./" + path.relative_to(self.root).as_posix(), err)
                self.assertNotIn("obaaf-proof-", err)
                self.assertEqual(path.read_bytes(), data)
                path.unlink()

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
