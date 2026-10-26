"""OBAAF's own PyPI release signs provenance and a build record, then verifies both before upload.

The build job holds no signing identity: it builds, checks the empty manifest, and writes
the unsigned build-record predicate. The attest job signs only (no package install). The
publish job uploads only after `gh attestation verify` passes for both predicate types.
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
        runs = "\n".join(s.get("run", "") for s in self.jobs["build"]["steps"])
        self.assertIn("manifest check --manifest obaaf-manifest.json --sources obaaf-sources.yaml", runs)
        self.assertIn("attest build-record", runs)
        self.assertIn("--manifest obaaf-manifest.json", runs)
        self.assertIn("--workflow-file .github/workflows/release-pypi.yml --build-job build", runs)
        self.assertNotIn("id-token", self.jobs["build"].get("permissions", {}))

    def test_attest_job_signs_only_without_installing_the_package(self):
        attest = self.jobs["attest"]
        self.assertEqual(attest["needs"], "build")
        self.assertEqual(attest["permissions"], {"id-token": "write", "attestations": "write"})
        uses = [s.get("uses", "") for s in attest["steps"]]
        self.assertTrue(any(u.startswith("actions/attest-build-provenance@") for u in uses))
        self.assertTrue(any(u.startswith("actions/attest@") for u in uses))
        runs = "\n".join(s.get("run", "") for s in attest["steps"])
        self.assertNotIn("pip install", runs)
        self.assertNotIn("obaaf ", runs)
        self.assertNotIn("dist/obaaf-", runs)
        attest_step = next(s for s in attest["steps"] if (s.get("uses") or "").startswith("actions/attest@"))
        self.assertEqual(
            attest_step["with"]["predicate-type"],
            "https://www.obaaf.com/attestation/build-record/v0.1",
        )
        self.assertEqual(attest_step["with"]["predicate-path"], "attest/build-record.json")

    def test_publish_verifies_both_predicates_before_uploading(self):
        publish = self.jobs["publish"]
        self.assertIn("attest", publish["needs"])
        steps = publish["steps"]
        verify = next(i for i, s in enumerate(steps) if "gh attestation verify" in s.get("run", ""))
        upload = next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@"))
        self.assertLess(verify, upload)
        command = steps[verify]["run"]
        for flag in ("--signer-workflow", "--source-ref", "--deny-self-hosted-runners"):
            self.assertIn(flag, command)
        self.assertIn("https://slsa.dev/provenance/v1", command)
        self.assertIn("https://www.obaaf.com/attestation/build-record/v0.1", command)


if __name__ == "__main__":
    unittest.main()
