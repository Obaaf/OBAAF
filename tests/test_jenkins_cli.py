"""`obaaf check` on repositories with Jenkinsfiles (Jenkins design, section 2 and JT 01, JT 26)."""

import json
import textwrap
import unittest

from helpers import TempDir, run_cli

from obaaf import checker
from obaaf.checker import jenkins

RISKY = textwrap.dedent("""\
    pipeline {
      agent { label 'linux' }
      stages {
        stage('Test') {
          when { changeRequest() }
          steps {
            sh "echo ${env.CHANGE_TITLE}"
          }
        }
      }
    }
    """)
WORKFLOW = ("on: push\npermissions: {contents: read}\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo hi\n")


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class DiscoveryTest(unittest.TestCase):
    def test_names_depth_and_skipped_directories(self):
        with TempDir() as tmp:
            for rel in ("Jenkinsfile", "ci/Jenkinsfile.release", "ci/deploy.jenkinsfile", "a/b/Jenkinsfile-nightly",
                        "node_modules/pkg/Jenkinsfile", "docs/Jenkinsfile.md", "a/b/c/d/e/f/g/Jenkinsfile"):
                write(tmp, rel, RISKY)
            found = [p.relative_to(tmp.resolve()).as_posix() for p in jenkins.discover(tmp)]
            self.assertEqual(found, ["Jenkinsfile", "a/b/Jenkinsfile-nightly", "ci/Jenkinsfile.release",
                                     "ci/deploy.jenkinsfile"])

    def test_configured_files_and_exclusions(self):
        with TempDir() as tmp:
            write(tmp, "ci/pipeline.groovy", RISKY)
            write(tmp, "src/test/resources/Jenkinsfile", RISKY)
            write(tmp, "obaaf.yml", "jenkins:\n  files: ['ci/*.groovy']\n  exclude: ['src/test/**']\n")
            result = checker.check(tmp)
            self.assertEqual(result.jenkins_files, ["ci/pipeline.groovy"])

    def test_workflows_and_jenkinsfiles_together_and_by_platform(self):
        with TempDir() as tmp:
            write(tmp, ".github/workflows/ci.yml", WORKFLOW)
            write(tmp, "Jenkinsfile", RISKY)
            both = checker.check(tmp)
            self.assertEqual(sorted(both.files), [".github/workflows/ci.yml", "Jenkinsfile"])
            self.assertEqual(checker.check(tmp, platform="github").jenkins_files, [])
            only = checker.check(tmp, platform="jenkins")
            self.assertEqual(only.files, ["Jenkinsfile"])
            # Pointing at the workflows directory checks workflows only.
            self.assertEqual(checker.check(tmp / ".github" / "workflows").jenkins_files, [])

    def test_empty_jenkins_scan_is_a_usage_error(self):
        with TempDir() as tmp:
            write(tmp, ".github/workflows/ci.yml", WORKFLOW)
            code, _, err = run_cli("check", tmp, "--platform", "jenkins")
            self.assertEqual(code, 2)
            self.assertIn("Jenkinsfiles", err)
            self.assertIn("nothing was checked", err)


class OutputTest(unittest.TestCase):
    def test_text_report_states_the_advisory_status(self):
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", RISKY)
            code, out, _ = run_cli("check", tmp, "--fail-on", "high")
            self.assertEqual(code, 1)
            self.assertIn("OBAAF-JEN-009", out)
            self.assertIn("[stage Test]", out)
            self.assertIn("Exit status 0 is not a conformance decision", out)
            self.assertIn("1 Jenkinsfile(s) checked (advisory).", out)
            self.assertNotIn("workflow file(s) checked", out)

    def test_json_adds_coverage_only_when_jenkinsfiles_were_checked(self):
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", RISKY)
            _, out, _ = run_cli("check", tmp, "--format", "json", "--fail-on", "never")
            payload = json.loads(out)
            self.assertTrue(payload["jenkins"]["advisory"])
            self.assertEqual(payload["jenkins"]["files"][0]["path"], "Jenkinsfile")
            self.assertTrue(payload["jenkins"]["files"][0]["digest"].startswith("sha256:"))
            statuses = {row["rule"]: row["status"] for row in payload["jenkins"]["coverage"]}
            self.assertEqual(statuses["OBAAF-JEN-009"], "fail")
            self.assertEqual(len(statuses), len(jenkins.RULES))
            finding = next(f for f in payload["findings"] if f["rule"] == "OBAAF-JEN-009")
            self.assertEqual((finding["scope"], finding["job"]), ("stage", "Test"))
        with TempDir() as tmp:
            write(tmp, ".github/workflows/ci.yml", WORKFLOW)
            _, out, _ = run_cli("check", tmp, "--format", "json", "--fail-on", "never")
            self.assertNotIn("jenkins", json.loads(out))

    def test_sarif_includes_jenkins_rules(self):
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", RISKY)
            _, out, _ = run_cli("check", tmp, "--format", "sarif", "--fail-on", "never")
            sarif = json.loads(out)
            self.assertIn("OBAAF-JEN-009", [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]])

    def test_unreadable_jenkinsfile_is_an_error(self):
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", "x = " + "(" * 5000)
            code, out, _ = run_cli("check", tmp, "--fail-on", "never")
            self.assertEqual(code, 1)
            self.assertIn("error: Jenkinsfile: not analyzed", out)

    def test_lanes_lists_stages(self):
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", RISKY)
            code, out, _ = run_cli("check", tmp, "--lanes")
            self.assertEqual(code, 0)
            self.assertIn("Jenkinsfile#stage Test: untrusted (runs for change requests)", out)


class ConfigurationTest(unittest.TestCase):
    def test_codeowners_must_cover_jenkinsfiles(self):
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", RISKY)
            write(tmp, ".github/CODEOWNERS", "/docs/ @docs-team\n")
            findings = [f for f in checker.check(tmp).findings if f.rule == "OBAAF-REPO-001"]
            self.assertEqual(len(findings), 1)
            self.assertIn("Jenkinsfile", findings[0].message)
            write(tmp, ".github/CODEOWNERS", "/Jenkinsfile @platform-team\n")
            self.assertFalse([f for f in checker.check(tmp).findings if f.rule == "OBAAF-REPO-001"])

    def test_ignore_entries_name_a_stage(self):
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", RISKY)
            write(tmp, "obaaf.yml", "ignore:\n  - rule: OBAAF-JEN-009\n    path: Jenkinsfile\n    job: Test\n"
                                    "    reason: reviewed\n    until: 2999-01-01\n")
            result = checker.check(tmp)
            finding = next(f for f in result.findings if f.rule == "OBAAF-JEN-009")
            self.assertIsNotNone(finding.suppressed)
            row = next(r for r in result.coverage if r["rule"] == "OBAAF-JEN-009")
            self.assertEqual(row["status"], "ignored")

    def test_declared_agent_steps_and_lanes(self):
        text = RISKY.replace('sh "echo ${env.CHANGE_TITLE}"', "reviewWithModel()")
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", text)
            write(tmp, "obaaf.yml", "agents:\n  steps: [reviewWithModel]\n")
            self.assertIn("OBAAF-JEN-007", {f.rule for f in checker.check(tmp).findings})
            write(tmp, "obaaf.yml", "lanes:\n  'Jenkinsfile#Test': agent\n")
            write(tmp, "Jenkinsfile", RISKY.replace('sh "echo ${env.CHANGE_TITLE}"', "sh './review.sh'"))
            self.assertIn("OBAAF-JEN-007", {f.rule for f in checker.check(tmp).findings})

    def test_bad_jenkins_configuration_is_rejected(self):
        with TempDir() as tmp:
            write(tmp, "Jenkinsfile", RISKY)
            write(tmp, "obaaf.yml", "jenkins:\n  files: 'ci/*.groovy'\n")
            code, _, err = run_cli("check", tmp)
            self.assertEqual(code, 2)
            self.assertIn("jenkins.files", err)


if __name__ == "__main__":
    unittest.main()
