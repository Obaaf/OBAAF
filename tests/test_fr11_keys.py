"""FR11: keep signing keys off build machines.

Acceptance criterion: templates sign through hardware or a managed signing
service, and no build step can read the key. The templates sign through
GitHub's Sigstore with the workflow's OIDC identity, so no long-lived key
exists; the jobs that may request that identity run no build or agent code.
"""

import re
import unittest

from helpers import RISKY, TEMPLATES, template_workflow

from obaaf import checker
from obaaf.catalog import load

SIGNING_ACTIONS = ("actions/attest", "actions/attest-build-provenance")


class TemplateSigningTest(unittest.TestCase):
    def workflows(self):
        return [template_workflow(p.name) for p in sorted((TEMPLATES / "workflows").glob("*.yml"))]

    def test_no_template_references_a_signing_key(self):
        patterns = [re.compile(p, re.I) for p in load().detection["signing_secret_patterns"]]
        for wf in self.workflows():
            for job in wf.jobs.values():
                for name in job.secret_names():
                    self.assertFalse(any(p.search(name) for p in patterns), f"{wf.path}#{job.id}: {name}")
            result = checker.check(TEMPLATES / "workflows" / wf.path)
            self.assertFalse([f for f in result.findings if f.rule == "OBAAF-GHA-018"])

    def test_only_signing_jobs_can_request_an_identity_and_they_run_no_build_or_agent_code(self):
        repo_code = re.compile(r"(^|[\s;&|(])\./|scripts/|agent\.sh|\bmake\b|\bnpm\b|\bcmake\b|msbuild|"
                               r"UnrealBuildTool|Unity\b|godot", re.I)
        for wf in self.workflows():
            for job in wf.jobs.values():
                perms = job.permissions
                if perms is None or not perms.oidc:
                    continue
                with self.subTest(workflow=wf.path, job=job.id):
                    self.assertTrue(any(s.uses_action(a) for s in job.steps for a in SIGNING_ACTIONS))
                    self.assertNotEqual(job.lane, "agent")
                    scripts = "\n".join(s.run for s in job.steps)
                    self.assertIsNone(repo_code.search(scripts), "a job holding the signing identity runs repo code")

    def test_release_build_job_cannot_request_an_identity(self):
        build = template_workflow("obaaf-release.yml").jobs["build"]
        self.assertFalse(build.permissions.oidc)


class CheckerCatchesKeysTest(unittest.TestCase):
    def test_signing_certificate_in_a_build_job_is_reported(self):
        findings = [f for f in checker.check(RISKY / "signing-key-in-build.yml").findings if f.rule == "OBAAF-GHA-018"]
        self.assertTrue(findings)
        self.assertTrue(all(f.severity == "high" for f in findings))


if __name__ == "__main__":
    unittest.main()
