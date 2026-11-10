"""`obaaf check --baseline`: adopt the checker in reporting mode without letting regressions through.

Findings recorded in a baseline are still reported but do not fail the check; a new finding does, and
so does a baseline entry that no longer matches, so improvements are locked in.
"""

import json
import unittest

from helpers import TempDir, run_cli

from obaaf.checker import baseline

SHA = "1" * 40

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


class BaselineTest(unittest.TestCase):
    def write(self, tmp):
        path = tmp / "obaaf-baseline.json"
        code, _, err = run_cli("check", tmp, "--write-baseline", path, "--fail-on", "low")
        self.assertEqual(code, 0, err)
        return path

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

    def test_a_new_finding_fails(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            repo(tmp, "TOKEN_A", "TOKEN_B")
            code, out, _ = self.check(tmp, path)
            self.assertEqual(code, 1)
            self.assertIn("1 new", out)

    def test_a_changed_message_is_new(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            repo(tmp, "TOKEN_B")   # the same job now receives a different secret
            code, out, _ = self.check(tmp, path)
            self.assertEqual(code, 1)
            self.assertIn("no longer found", out)

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
            self.write(tmp)
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
        one = CheckResult(findings=[make()], files=["x"], errors=[], config=Config())
        entries = json.loads(baseline.build(one))["findings"]
        two = CheckResult(findings=[make(), make()], files=["x"], errors=[], config=Config())
        baseline.apply(two, entries)
        self.assertEqual(sorted(f.baselined for f in two.findings), [False, True])

    def test_suppressed_findings_are_not_written(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            (tmp / ".github" / "obaaf.yml").write_text(
                "ignore:\n  - rule: OBAAF-GHA-001\n    path: .github/workflows/ci0.yml\n"
                "    reason: reviewed\n    until: 2999-01-01\n")
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
            self.assertEqual(data["baseline"]["stale"], [])
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
            for content in ("not json", '{"format": "other", "findings": []}', '{"format": "obaaf-baseline/v0.1", "findings": [{}]}'):
                bad.write_text(content)
                code, _, _ = self.check(tmp, bad)
                self.assertEqual(code, 2, content)
            code, _, err = run_cli("check", tmp, "--baseline", bad, "--write-baseline", tmp / "x.json")
            self.assertEqual(code, 2)

    def test_baseline_does_not_hide_read_errors(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = self.write(tmp)
            (tmp / ".github" / "workflows" / "broken.yml").write_text("jobs: [unclosed\n")
            code, _, _ = self.check(tmp, path)
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
