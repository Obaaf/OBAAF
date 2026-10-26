"""OBAAF's own PyPI release signs provenance in a separate job and verifies it before uploading.

The build job holds no signing identity, the attest job runs no build code, and the
publish job uploads only after `gh attestation verify` passes for every file.
"""

import unittest

import yaml

from helpers import ROOT

WORKFLOW = ROOT / ".github" / "workflows" / "release-pypi.yml"


class ReleaseProvenanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]

    def test_build_job_holds_no_signing_identity(self):
        self.assertEqual(self.jobs["build"]["permissions"], {"contents": "read"})

    def test_attest_job_signs_provenance_and_runs_no_build(self):
        attest = self.jobs["attest"]
        self.assertEqual(attest["needs"], "build")
        self.assertEqual(attest["permissions"], {"id-token": "write", "attestations": "write"})
        uses = [s.get("uses", "") for s in attest["steps"]]
        self.assertTrue(any(u.startswith("actions/attest-build-provenance@") for u in uses))
        self.assertFalse(any("run" in s for s in attest["steps"]), "the attest job must run no commands")

    def test_publish_verifies_before_uploading(self):
        publish = self.jobs["publish"]
        self.assertIn("attest", publish["needs"])
        steps = publish["steps"]
        verify = next(i for i, s in enumerate(steps) if "gh attestation verify" in s.get("run", ""))
        upload = next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@"))
        self.assertLess(verify, upload)
        command = steps[verify]["run"]
        for flag in ("--signer-workflow", "--source-ref", "--deny-self-hosted-runners"):
            self.assertIn(flag, command)


if __name__ == "__main__":
    unittest.main()
