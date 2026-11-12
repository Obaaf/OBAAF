"""`obaaf check --baseline`: adopt the checker without letting regressions through.

A finding that a valid baseline entry accepts is still reported and does not fail the check; a new
finding does, and so does a baseline entry that no longer matches, so improvements are locked in.
What makes an entry valid, and the old v0.1 format, are covered in test_finding_lifecycle.py.
"""

import json
import unittest
from datetime import date, timedelta

from helpers import TempDir, run_cli

from obaaf.checker import baseline

SHA = "1" * 40
SOON = (date.today() + timedelta(days=90)).isoformat()
ACCEPT = ("--owner", "@example/maintainers", "--reason", "Reviewed; tracked in issue 7", "--expires", SOON)

PR_SECRET = """\
name: ci
on: [pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: echo "${{{{ secrets.{name} }}}}" | wc -c
"""


def repo(tmp, *names, extra_lines=0):
    wf = tmp / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    for old in wf.glob("*.yml"):
        old.unlink()
    for i, name in enumerate(names):
        text = "\n" * extra_lines + PR_SECRET.format(name=name)
        (wf / f"ci{i}.yml").write_text(text, encoding="utf-8")
    (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
    return tmp


def ignore_entry(until, owner="'@example/maintainers'"):
    return ("ignore:\n  - rule: OBAAF-GHA-001\n    path: .github/workflows/ci0.yml\n"
            + (f"    owner: {owner}\n" if owner else "") + f"    reason: Reviewed with the build team\n    until: {until}\n")


def write_baseline(test, tmp):
    path = tmp / "obaaf-baseline.json"
    code, _, err = run_cli("check", tmp, "--write-baseline", path, "--fail-on", "low", *ACCEPT)
    test.assertEqual(code, 0, err)
    return path


class BaselineTest(unittest.TestCase):
    def write(self, tmp):
        return write_baseline(self, tmp)

    def check(self, tmp, path, *extra):
        return run_cli("check", tmp, "--baseline", path, "--fail-on", "low", *extra)

    def test_without_a_baseline_the_finding_fails(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            code, _, _ = run_cli("check", tmp, "--fail-on", "low")
            self.assertEqual(code, 1)

    def test_baselined_findings_are_reported_but_pass(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            data = json.loads(path.read_text())
            self.assertEqual(data["format"], baseline.FORMAT)
            self.assertEqual({e["rule"] for e in data["findings"]}, {"OBAAF-GHA-001"})
            code, out, err = self.check(tmp, path)
            self.assertEqual(code, 0, out + err)
            self.assertIn("(baseline)", out)
            self.assertIn("accepted by the baseline, 0 new", out)
            self.assertIn(f"Accepted by @example/maintainers until {SOON}: Reviewed; tracked in issue 7", out)

    def test_a_new_finding_fails(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            repo(tmp, "TOKEN_A", "TOKEN_B")
            code, out, _ = self.check(tmp, path)
            self.assertEqual(code, 1)
            self.assertIn("1 new", out)

    def test_a_job_that_receives_another_secret_is_new(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            repo(tmp, "TOKEN_B")   # the same job now receives a different secret
            code, out, _ = self.check(tmp, path)
            self.assertEqual(code, 1)
            self.assertIn("accepted by the baseline, 1 new", out)
            self.assertIn("no longer found: OBAAF-GHA-001 .github/workflows/ci0.yml [job test] - pull-request; "
                          "secrets: TOKEN_A", out)

    def test_moved_lines_still_match(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            repo(tmp, "TOKEN_A", extra_lines=5)
            code, out, err = self.check(tmp, path)
            self.assertEqual(code, 0, out + err)

    def test_a_fixed_finding_fails_until_the_baseline_is_regenerated(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A", "TOKEN_B")
            path = self.write(tmp)
            repo(tmp, "TOKEN_A")
            code, out, _ = self.check(tmp, path)
            self.assertEqual(code, 1)
            self.assertIn("1 baseline entry no longer matches", out)
            self.assertIn("no longer found: OBAAF-GHA-001", out)
            # Nothing is newly accepted, so regenerating needs nobody's name.
            code, _, err = run_cli("check", tmp, "--write-baseline", path, "--fail-on", "low")
            self.assertEqual(code, 0, err)
            self.assertIn("0 finding(s) newly accepted, 1 kept", err)
            code, _, _ = self.check(tmp, path)
            self.assertEqual(code, 0)

    def test_fail_on_never_reports_stale_entries_without_failing(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A", "TOKEN_B")
            path = self.write(tmp)
            repo(tmp, "TOKEN_A")
            code, out, _ = run_cli("check", tmp, "--baseline", path, "--fail-on", "never")
            self.assertEqual(code, 0)
            self.assertIn("no longer matches", out)

    def test_identical_findings_are_counted(self):
        from obaaf.checker import CheckResult, Config
        from obaaf.checker.rules import Finding

        def make():
            return Finding("OBAAF-GHA-001", "low", ".github/workflows/ci.yml", 3, "same", job="test")
        one = [make()]
        text = baseline.build(one, None, "@example/maintainers", "Reviewed; tracked in issue 7", SOON)
        path_entries = json.loads(text)["findings"]
        two = CheckResult(findings=[make(), make()], files=["x"], errors=[], config=Config())
        baseline.apply(two, baseline.Baseline(baseline.FORMAT, path_entries))
        self.assertEqual(sorted(f.baselined for f in two.findings), [False, True])

    def test_suppressed_findings_are_not_written(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            (tmp / ".github" / "obaaf.yml").write_text(ignore_entry(SOON))
            path = self.write(tmp)
            self.assertEqual(json.loads(path.read_text())["findings"], [])

    def test_json_and_sarif_mark_the_baseline_state(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            repo(tmp, "TOKEN_A", "TOKEN_B")
            _, out, _ = self.check(tmp, path, "--format", "json")
            data = json.loads(out)
            self.assertEqual(sorted(f["baselined"] for f in data["findings"]), [False, True])
            self.assertEqual(sorted(f["state"] for f in data["findings"]), ["accepted", "new"])
            self.assertEqual(data["baseline"]["stale"], [])
            self.assertEqual(data["baseline"]["format"], baseline.FORMAT)
            _, out, _ = self.check(tmp, path, "--format", "sarif")
            states = sorted(r["baselineState"] for r in json.loads(out)["runs"][0]["results"])
            self.assertEqual(states, ["new", "unchanged"])
            _, out, _ = run_cli("check", tmp, "--format", "json", "--fail-on", "never")
            self.assertNotIn("baseline", json.loads(out))
            self.assertNotIn("baselined", json.loads(out)["findings"][0])

    def test_bad_baselines_are_usage_errors(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            code, _, err = self.check(tmp, tmp / "missing.json")
            self.assertEqual(code, 2)
            self.assertIn("--write-baseline", err)
            bad = tmp / "bad.json"
            for content in ("not json", '{"format": "other", "findings": []}',
                            '{"format": "obaaf-baseline/v0.1", "findings": [{}]}',
                            '{"format": "obaaf-baseline/v0.2", "findings": [{}]}',
                            '{"format": "obaaf-baseline/v0.2", "findings": {}}',
                            '{"format": "obaaf-baseline/v0.2"}', "[]", "[" * 100_000):
                bad.write_text(content)
                code, _, err = self.check(tmp, bad)
                self.assertEqual(code, 2, content[:60])
                self.assertNotIn("Traceback", err)
            code, _, err = run_cli("check", tmp, "--baseline", bad, "--write-baseline", tmp / "x.json")
            self.assertEqual(code, 2)

    def test_baseline_does_not_hide_read_errors(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            (tmp / ".github" / "workflows" / "broken.yml").write_text("jobs: [unclosed\n")
            code, _, _ = self.check(tmp, path)
            self.assertEqual(code, 1)


class BaselineIntegrityTest(unittest.TestCase):
    """Findings from an independent review of the first version."""

    def write(self, tmp):
        return write_baseline(self, tmp)

    def test_stale_entries_follow_the_fail_on_threshold(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A", "TOKEN_B")
            path = self.write(tmp)
            repo(tmp, "TOKEN_A")   # a low finding disappears
            code, out, _ = run_cli("check", tmp, "--baseline", path, "--fail-on", "high")
            self.assertEqual(code, 0, out)
            self.assertIn("no longer matches", out)
            code, _, _ = run_cli("check", tmp, "--baseline", path, "--fail-on", "low")
            self.assertEqual(code, 1)
            code, _, _ = run_cli("check", tmp, "--baseline", path, "--fail-on", "hygiene:low")
            self.assertEqual(code, 0)

    def test_expired_ignores_are_not_written_into_the_baseline(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            (tmp / ".github" / "obaaf.yml").write_text(ignore_entry("2000-01-01"))
            path = tmp / "b.json"
            code, _, err = run_cli("check", tmp, "--write-baseline", path, "--fail-on", "low", *ACCEPT)
            self.assertEqual(code, 0)
            self.assertIn("expired", err)
            self.assertEqual(json.loads(path.read_text())["findings"], [])

    def test_an_entry_for_a_finding_now_ignored_is_not_stale(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            (tmp / ".github" / "obaaf.yml").write_text(ignore_entry(SOON))
            code, out, _ = run_cli("check", tmp, "--baseline", path, "--fail-on", "low")
            self.assertEqual(code, 0, out)
            self.assertNotIn("no longer match", out)


if __name__ == "__main__":
    unittest.main()
