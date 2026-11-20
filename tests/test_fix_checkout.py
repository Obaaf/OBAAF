"""Explicit checkout tightening through the normal preview and apply commands."""

from datetime import date, timedelta
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import unittest

from helpers import TempDir, run_cli
from obaaf import checker, yamlutil
from obaaf.checker import baseline


class CheckoutTighteningTest(unittest.TestCase):
    def setUp(self):
        temp = TempDir()
        self.root = temp.__enter__()
        self.addCleanup(temp.__exit__)
        self.rel = Path(".github/workflows/ci.yml")
        self.path = self.root / self.rel
        self.path.parent.mkdir(parents=True)
        self.name = f"{self.rel}#test/step-1"
        self.options = ["--tighten", "checkout-credentials"]
        self.header = ("name: Check\non: pull_request\npermissions: {contents: read}\njobs:\n  test:\n"
                       "    runs-on: ubuntu-latest\n    steps:\n")
        self.write("      - uses: actions/checkout@v4 # keep\n")

    def write(self, steps):
        self.path.write_text(self.header + steps)

    def run_fix(self, *args):
        return run_cli("fix", self.root, *args)

    def accepted(self, finding):
        expiry = (date.today() + timedelta(days=30)).isoformat()
        path = self.root / "baseline.json"
        path.write_text(json.dumps({"format": baseline.FORMAT, "findings": [
            baseline.entry_for(finding, "@review", "previous review", expiry)]}))
        return path

    def test_default_excludes_tightening_explicit_kind_previews_one_input(self):
        self.assertNotIn("--- a/", self.run_fix()[1])
        old = self.path.read_bytes()
        code, out, err = self.run_fix(*self.options)
        self.assertEqual(code, 0, err)
        self.assertIn(self.name, out)
        self.assertIn("+        with: {persist-credentials: false}", out)
        self.assertIn("0 newly counting findings", out)
        self.assertEqual(self.path.read_bytes(), old)
        self.assertNotIn(".github/obaaf.yml", out.split("--- a/")[-1])

    @unittest.skipUnless(os.name == "posix" and shutil.which("git"), "apply uses POSIX and Git")
    def test_works_by_name_and_applies_only_that_checkout_with_the_original_key_case(self):
        self.write("      - uses: actions/checkout@v4\n        with:\n          PERSIST-CREDENTIALS: true # stay\n"
                   "          fetch-depth: 1\n      - {name: second, uses: actions/checkout@v4}\n")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "-c", "user.email=test@example.org", "-c", "user.name=Test",
                        "commit", "-qm", "fixture"], cwd=self.root, check=True)
        code, out, err = self.run_fix(*self.options, "--candidate", self.name, "--apply")
        self.assertEqual(code, 0, err or out)
        self.assertIn("PERSIST-CREDENTIALS: false # stay", self.path.read_text())
        steps = yamlutil.load_file(self.path)["jobs"]["test"]["steps"]
        self.assertEqual(steps[0]["with"], {"PERSIST-CREDENTIALS": False, "fetch-depth": 1})
        self.assertNotIn("with", steps[1])

    def test_multiple_candidates_and_scoped_file_check(self):
        self.write("      - uses: actions/checkout@v4\n        with: {fetch-depth: 1}\n"
                   "      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 2\n")
        code, out, err = run_cli("fix", self.path, *self.options)
        self.assertEqual(code, 0, err)
        self.assertIn("/step-2", out)
        self.assertIn("fetch-depth: 1, persist-credentials: false", out)
        self.assertIn("+          persist-credentials: false", out)

    def test_a_withheld_named_request_names_the_finding_and_offers_no_identical_retry(self):
        # Review of #287: the edit also clears OBAAF-GHA-023 (the input is an expression), so the proof
        # withholds it. The refusal must say which finding, and not suggest the request that just failed.
        self.write("      - uses: actions/checkout@v4\n        with:\n"
                   "          persist-credentials: ${{ inputs.OBAAF_OWNER }}\n")
        found = {f.rule for f in checker.check(self.root).findings}
        self.assertIn("OBAAF-GHA-011", found)
        code, out, err = self.run_fix(*self.options, "--candidate", self.name)
        self.assertEqual(code, 1, err or out)
        refusal = next(line for line in out.splitlines() if "finding changes differ" in line)
        self.assertRegex(refusal, r"OBAAF-GHA-\d{3} in \.github/workflows/ci\.yml test")
        self.assertNotIn("Retry this step alone", out)
        self.assertIn("After resolving it, preview the same request again with: obaaf fix", refusal)
        code, out, err = self.run_fix(*self.options)
        self.assertIn("Retry this step alone with", out)

    def test_every_proof_refusal_names_findings_in_the_rows_it_compares(self):
        # The gate and evidence refusals have no fixture that reaches them here; check the naming they share
        # on the rows the proof compares, including the evidence rows' reduction to findings.
        from collections import Counter
        from obaaf import fix_proof
        findings = checker.check(self.root).findings
        rows = fix_proof._rows(findings)
        text = fix_proof._named(rows)
        self.assertIn("× OBAAF-GHA-011 in .github/workflows/ci.yml test", text)
        evidence = fix_proof._changed_occurrences(fix_proof._evidence(findings))
        self.assertEqual(fix_proof._named(evidence), text)
        many = Counter({(key, severity, f"state{i}"): 1 for i, ((key, severity, _), _) in
                        enumerate(list(rows.items()) * 7)})
        self.assertTrue(fix_proof._named(many).endswith(f" and {len(many) - 3} more"))
        # One finding whose control evidence changed is in both differences and is named once.
        row = next(r for r in rows if '"OBAAF-GHA-011"' in r[0])
        before = Counter({(row, None, ("c", "n", "cannot tell", "")): 1})
        after = Counter({(row, None, ("c", "n", "verified", "")): 1})
        changed = (fix_proof._changed_occurrences(before - after) | fix_proof._changed_occurrences(after - before))
        self.assertTrue(fix_proof._named(changed).startswith("1 × OBAAF-GHA-011"))

    def test_a_workflow_that_is_not_utf8_is_named_and_does_not_block_another_file(self):
        # Review of #287: one Latin-1 workflow made every request exit 2 with a bare decode error.
        other = self.root / ".github/workflows/b.yml"
        other.write_text(self.header + "      - uses: actions/checkout@v4\n")
        self.path.write_bytes((self.header + "      - name: caf\xe9\n        uses: actions/checkout@v4\n")
                              .encode("latin-1"))
        self.assertTrue(any(f.rule == "OBAAF-GHA-011" and f.path.endswith("ci.yml")
                            for f in checker.check(self.root).findings))
        code, out, err = self.run_fix(*self.options, "--candidate", ".github/workflows/b.yml#test/step-1")
        self.assertEqual(code, 0, err or out)
        self.assertIn("+        with: {persist-credentials: false}", out)
        code, out, err = self.run_fix(*self.options, "--candidate", self.name)
        self.assertEqual(code, 1, err or out)
        self.assertIn(f"{self.rel}: review its checkouts by hand; the file is not UTF-8 text", out)
        code, out, err = self.run_fix(*self.options, "--candidate", f"{self.rel}#nojob/step-9")
        self.assertEqual(code, 2, err or out)
        code, out, err = self.run_fix(*self.options)
        self.assertEqual(code, 0, err or out)
        self.assertIn(f"{self.rel}: review its checkouts by hand", out)
        self.assertIn("b.yml#test/step-1", out)

    def test_named_request_explains_stale_target_then_succeeds_after_review(self):
        found = next(f for f in checker.check(self.root).findings if f.rule == "OBAAF-GHA-011")
        path = self.accepted(found)
        opts = [*self.options, "--baseline", path]
        old, old_base = self.path.read_bytes(), path.read_bytes()
        code, out, err = self.run_fix(*opts)
        self.assertEqual(code, 0, err)
        self.assertIn("1 unmatched", out)
        self.assertIn(self.name, out)
        self.assertNotIn("--- a/", out)
        code, out, err = self.run_fix(*opts, "--candidate", self.name, "--apply")
        self.assertEqual(code, 1, err)
        self.assertIn("Named checkout withheld", out)
        self.assertIn("baseline OBAAF-GHA-011", out)
        self.assertEqual((self.path.read_bytes(), path.read_bytes()), (old, old_base))
        path.write_text(json.dumps({"format": baseline.FORMAT, "findings": []}))
        code, out, err = self.run_fix(*opts, "--candidate", self.name)
        self.assertEqual(code, 0, err)
        self.assertIn("--- a/", out)

    def test_independent_acceptance_loss_is_counted_without_accepting_anything(self):
        self.write("      - uses: actions/checkout@v4\n        with:\n"
                   "          persist-credentials: ${{ inputs.OBAAF_OWNER }}\n")
        result = checker.check(self.root)
        collateral = next(f for f in result.findings if f.rule == "OBAAF-GHA-023")
        path = self.accepted(collateral)
        code, out, err = self.run_fix(*self.options, "--candidate", self.name, "--baseline", path)
        self.assertEqual(code, 1, err)
        self.assertIn("1 previously accepted finding(s)", out)
        self.assertIn("OBAAF-GHA-023", out)
        self.assertNotIn("--- a/", out)
        self.assertIn("OBAAF_OWNER", self.path.read_text())

    def test_tightening_cannot_change_acceptance_or_select_a_nonexistent_step(self):
        for args in ((*self.options, "--owner", "@team"), ("--candidate", self.name),
                     (*self.options, "--candidate", "unknown")):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_fix(*args)[0], 0)

    def test_shared_input_is_withheld_and_separate_checkout_remains_eligible(self):
        self.write("      - name: shared\n        uses: actions/checkout@v4\n"
                   "        with: &inputs {persist-credentials: true}\n"
                   "      - name: also shared\n        uses: actions/checkout@v4\n        with: *inputs\n"
                   "      - name: individual\n        uses: actions/checkout@v4\n")
        code, out, err = self.run_fix(*self.options)
        self.assertEqual(code, 0, err)
        self.assertIn("shared", out)
        self.assertIn("/step-3: set", out)
        self.assertIn("--- a/", out)
        self.assertNotIn("-        with: &inputs", out)

    def test_second_checkout_still_offered_when_first_would_leave_stale_acceptance(self):
        self.write("      - name: first checkout\n        uses: actions/checkout@v4\n"
                   "      - name: second checkout\n        uses: actions/checkout@v4\n")
        first = next(f for f in checker.check(self.root).findings
                     if f.rule == "OBAAF-GHA-011" and f.step == "first checkout")
        path = self.accepted(first)
        code, out, err = self.run_fix(*self.options, "--baseline", path)
        self.assertEqual(code, 0, err)
        self.assertIn("/step-1: a baseline or ignore entry", out)
        self.assertIn("/step-2: set persist-credentials to false", out)
        self.assertEqual(out.count("+        with: {persist-credentials: false}"), 1)

    def test_explicit_empty_candidate_never_widens_to_all_checkouts(self):
        original = self.path.read_bytes()
        for value in ("", " ", "\t"):
            for flags in ([], ["--apply"]):
                with self.subTest(value=value, flags=flags):
                    code, out, error = self.run_fix(*self.options, "--candidate", value, *flags)
                    self.assertEqual(code, 2)
                    self.assertIn("nonblank", error)
                    self.assertNotIn("--- a/", out)
                    self.assertEqual(self.path.read_bytes(), original)

    def test_checkout_todo_command_replays_the_exact_check_scope(self):
        config = self.root / "team's config.yml"
        config.write_text("{}")
        policy = self.root / "accepted entries.json"
        policy.write_text(json.dumps({"format": baseline.FORMAT, "findings": []}))
        _, output, err = run_cli("check", self.path, "--format", "json", "--config", config,
                                 "--baseline", policy, "--platform", "github", "--fail-on", "never")
        self.assertFalse(err)
        group = next(g for g in json.loads(output)["todo"] if g["id"] == "checkout-credentials")
        command = shlex.split(group["command"])
        self.assertEqual(command, ["obaaf", "fix", str(self.path), "--tighten", "checkout-credentials",
                                   f"--config={config}", "--platform=github", f"--baseline={policy}",
                                   "--fail-on=never"])
        self.assertIn(group["command"], group["nextAction"])
        code, preview, error = run_cli(*command[1:])
        self.assertEqual(code, 0, error)
        self.assertIn("At --fail-on never", preview)
        self.assertIn(self.name, preview)

    def test_named_retry_command_includes_the_original_gate_options(self):
        found = next(f for f in checker.check(self.root).findings if f.rule == "OBAAF-GHA-011")
        policy = self.accepted(found)
        config = self.root / "config with spaces.yml"
        config.write_text("{}")
        code, out, error = self.run_fix(*self.options, "--candidate", self.name, "--config", config,
                                        "--baseline", policy, "--platform", "github", "--fail-on", "high")
        self.assertEqual(code, 1, error)
        line = next(line for line in out.splitlines() if "preview the same request again with: " in line)
        args = shlex.split(line.split("preview the same request again with: ", 1)[1])
        self.assertEqual(args, ["obaaf", "fix", str(self.root), "--tighten", "checkout-credentials",
                                f"--config={config}", "--platform=github", f"--baseline={policy}",
                                "--fail-on=high", "--candidate=" + self.name])
