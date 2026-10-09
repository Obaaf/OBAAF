"""FR4: run release builds in isolation.

Acceptance criterion: release jobs start only from a protected branch, on a
fresh machine (Tier A) or a persistent machine reset under the profile's
compensating controls (Tier B), read no cache that other lanes can write, and
the build record states which tier applied.
"""

import unittest

from helpers import RISKY, TempDir, template_workflow

from obaaf import checker
from obaaf.attest import records
from obaaf.attest.common import RecordError
from obaaf.checker.workflow import UNTRUSTED_TRIGGERS

RELEASE_TEMPLATE = "obaaf-release.yml"


class ReleaseTemplateTest(unittest.TestCase):
    def setUp(self):
        self.wf = template_workflow(RELEASE_TEMPLATE)

    def test_starts_only_from_protected_tags(self):
        self.assertEqual(set(self.wf.triggers), {"push"})
        self.assertEqual(dict(self.wf.triggers["push"]), {"tags": ["v*"]})
        self.assertFalse(set(self.wf.triggers) & UNTRUSTED_TRIGGERS)

    def test_every_job_reads_no_cache(self):
        for job in self.wf.jobs.values():
            self.assertEqual(job.cache_mode, "none", job.id)

    def test_build_job_holds_no_credentials(self):
        build = self.wf.jobs["build"]
        self.assertEqual(build.permissions.scopes, {"contents": "read"})
        self.assertEqual(build.secret_names(), set())
        self.assertIsNone(build.environment)

    def test_all_jobs_are_in_the_release_lane(self):
        self.assertEqual({j.lane for j in self.wf.jobs.values()}, {"release"})


class TierFromWorkflowTest(unittest.TestCase):
    def write(self, tmp, runs_on, tier=None):
        env = f"\n    env:\n      OBAAF_TIER: {tier}" if tier else ""
        text = f"""
name: Release
on: {{push: {{tags: ["v*"]}}}}
permissions: {{}}
jobs:
  build:
    runs-on: {runs_on}{env}
    cache-mode: none
    permissions: {{contents: read}}
    steps:
      - run: ./build.sh
"""
        path = tmp / "release.yml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_template_build_job_is_tier_a(self):
        from helpers import TEMPLATES

        iso = records.isolation_from_workflow(TEMPLATES / "workflows" / RELEASE_TEMPLATE, "build")
        self.assertEqual((iso["tier"], iso["runnerEnvironment"], iso["slsaBuildLevel3"]), ("A", "github-hosted", True))

    def test_self_hosted_needs_a_declared_tier(self):
        with TempDir() as tmp:
            with self.assertRaisesRegex(RecordError, "OBAAF_TIER"):
                records.isolation_from_workflow(self.write(tmp, "[self-hosted, obaaf-release]"), "build")

    def test_tier_b_is_reported_below_build_level_3(self):
        with TempDir() as tmp:
            iso = records.isolation_from_workflow(self.write(tmp, "[self-hosted, obaaf-release]", "B"), "build")
        self.assertEqual((iso["tier"], iso["slsaBuildLevel3"], iso["runnerEnvironment"]), ("B", False, "self-hosted"))

    def test_hosted_runners_cannot_claim_tier_b(self):
        with TempDir() as tmp:
            with self.assertRaises(RecordError):
                records.isolation_from_workflow(self.write(tmp, "windows-latest", "B"), "build")

    def test_command_line_tier_must_agree_with_the_workflow(self):
        with TempDir() as tmp:
            with self.assertRaises(RecordError):
                records.isolation_from_workflow(self.write(tmp, "ubuntu-latest"), "build", declared_tier="B")


class CheckerCatchesFr4ViolationsTest(unittest.TestCase):
    def rules(self, name):
        return {f.rule for f in checker.check(RISKY / name).findings}

    def test_release_reading_a_shared_cache(self):
        self.assertIn("OBAAF-GHA-006", self.rules("clinejection-release.yml"))

    def test_low_trust_workflow_writing_the_cache(self):
        self.assertIn("OBAAF-GHA-007", self.rules("clinejection-triage.yml"))

    def test_release_started_by_a_comment(self):
        self.assertIn("OBAAF-GHA-015", self.rules("release-from-comment.yml"))

    def test_untrusted_work_on_self_hosted_runners(self):
        self.assertIn("OBAAF-GHA-013", self.rules("pytorch-self-hosted.yml"))

    def test_setup_actions_that_cache_by_default_are_caught(self):
        text = """
name: Release
on: {push: {tags: ["v*"]}}
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    env: {OBAAF_LANE: release}
    steps:
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
        with: {go-version: "1.25"}
"""
        with TempDir() as tmp:
            path = tmp / "r.yml"
            path.write_text(text, encoding="utf-8")
            findings = [f for f in checker.check(path).findings if f.rule == "OBAAF-GHA-006"]
        self.assertEqual([f.severity for f in findings], ["high"])


if __name__ == "__main__":
    unittest.main()
