"""FR3: build outside contributions without secrets.

Acceptance criterion: in automated tests, a pull request from a fork cannot
read any secret or write to the repository. GitHub enforces this for
`pull_request` workflows; these tests check that the untrusted-lane template
stays within it (no secrets, read-only token, no privileged trigger, no
persistent runner), and that the checker catches workflows that break it. The
live test LAT-03 shows the platform behavior.
"""

import unittest

from helpers import RISKY, TempDir, install_templates, run_cli, template_workflow, workflow

from obaaf import checker
from obaaf.checker.workflow import PRIVILEGED_UNTRUSTED_TRIGGERS


class UntrustedLaneTemplateTest(unittest.TestCase):
    def setUp(self):
        self.wf = template_workflow("obaaf-untrusted-ci.yml")

    def test_runs_only_on_pull_request(self):
        self.assertEqual(set(self.wf.triggers), {"pull_request"})
        self.assertFalse(set(self.wf.triggers) & PRIVILEGED_UNTRUSTED_TRIGGERS)

    def test_token_is_read_only(self):
        for job in self.wf.jobs.values():
            perms = job.permissions
            self.assertIsNotNone(perms, f"{job.id} must declare permissions")
            self.assertEqual(perms.write_scopes(), [])
            self.assertFalse(perms.oidc)
            self.assertEqual(perms.scopes, {"contents": "read"})

    def test_no_secrets_and_no_environment(self):
        for job in self.wf.jobs.values():
            self.assertEqual(job.secret_names(), set())
            self.assertIsNone(job.environment)

    def test_runs_on_fresh_hosted_machines_without_persisted_credentials(self):
        for job in self.wf.jobs.values():
            self.assertFalse(job.self_hosted)
            for step in job.steps:
                if step.uses_action("actions/checkout"):
                    self.assertEqual(str(step.with_.get("persist-credentials")).lower(), "false")

    def test_lane_is_untrusted(self):
        self.assertTrue(all(job.lane == "untrusted" for job in self.wf.jobs.values()))


class CheckerCatchesFr3ViolationsTest(unittest.TestCase):
    def rules(self, name):
        result = checker.check(RISKY / name)
        return {f.rule for f in result.findings}

    def test_pwn_request_is_reported(self):
        self.assertTrue({"OBAAF-GHA-001", "OBAAF-GHA-002"} <= self.rules("pwn-request.yml"))

    def test_unsafe_checkout_opt_in_is_reported(self):
        self.assertIn("OBAAF-GHA-019", self.rules("unsafe-checkout-opt-in.yml"))

    def test_secrets_in_pull_request_workflows_are_reported_at_low_severity(self):
        wf_text = """
name: CI
on: pull_request
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./build.sh
        env:
          TOKEN: ${{ secrets.SOME_TOKEN }}
"""
        with TempDir() as tmp:
            path = tmp / "ci.yml"
            path.write_text(wf_text, encoding="utf-8")
            findings = [f for f in checker.check(path).findings if f.rule == "OBAAF-GHA-001"]
        self.assertEqual([f.severity for f in findings], ["low"])

    def test_installed_untrusted_lane_passes_the_checker(self):
        with TempDir() as tmp:
            install_templates(tmp)
            result = checker.check(tmp / ".github" / "workflows" / "obaaf-untrusted-ci.yml")
            self.assertEqual(result.findings, [])
            code, _, _ = run_cli("check", tmp)
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
