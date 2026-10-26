"""OBAAF's own PyPI release: build-record, Sigstore attest, then full verify before upload.

The build job holds no signing identity. The attest job signs only. The publish job
checks out the default branch, installs the reviewed CLI via setup-obaaf, and runs
`obaaf verify release` (provenance body, build record, approvals, agent history)
before uploading.
"""

from __future__ import annotations

import unittest

import yaml

from helpers import ROOT
from obaaf.verify.policy import Policy

WORKFLOW = ROOT / ".github" / "workflows" / "release-pypi.yml"
POLICY = ROOT / ".github" / "obaaf-policy.yaml"


def _step_index(steps: list, pred) -> int:
    for i, step in enumerate(steps):
        if pred(step):
            return i
    raise AssertionError("no matching step")


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
        self.assertIn("python -m venv", runs)
        self.assertIn("pip install --no-deps dist/obaaf-*.whl", runs)
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

    def test_publish_runs_full_verify_release_before_uploading(self):
        publish = self.jobs["publish"]
        self.assertEqual(publish["needs"], ["build", "attest"])
        self.assertEqual(publish["environment"]["name"], "pypi")
        self.assertEqual(
            publish["permissions"],
            {
                "contents": "read",
                "actions": "read",
                "attestations": "read",
                "id-token": "write",
            },
        )
        steps = publish["steps"]
        checkout = _step_index(
            steps, lambda s: (s.get("uses") or "").startswith("actions/checkout@"))
        setup_py = _step_index(
            steps, lambda s: (s.get("uses") or "").startswith("actions/setup-python@"))
        setup_obaaf = _step_index(steps, lambda s: s.get("uses") == "./actions/setup-obaaf")
        download = _step_index(
            steps,
            lambda s: (s.get("uses") or "").startswith("actions/download-artifact@")
            and (s.get("with") or {}).get("name") == "obaaf-dist",
        )
        approvals = _step_index(
            steps, lambda s: "gh api" in s.get("run", "") and "approvals" in s.get("run", ""))
        verify = _step_index(steps, lambda s: "obaaf verify release" in s.get("run", ""))
        upload = _step_index(
            steps, lambda s: (s.get("uses") or "").startswith("pypa/gh-action-pypi-publish@"))
        self.assertLess(checkout, setup_py)
        self.assertLess(setup_py, setup_obaaf)
        self.assertLess(setup_obaaf, download)
        self.assertLess(download, approvals)
        self.assertLess(approvals, verify)
        self.assertLess(verify, upload)

        checkout_step = steps[checkout]
        self.assertEqual(checkout_step["with"]["ref"], "${{ github.event.repository.default_branch }}")
        self.assertEqual(checkout_step["with"]["fetch-depth"], 0)
        self.assertFalse(checkout_step["with"]["persist-credentials"])

        command = steps[verify]["run"]
        self.assertIn("--policy .github/obaaf-policy.yaml", command)
        self.assertIn("--artifacts dist", command)
        self.assertIn("--approvals", command)
        self.assertIn("--repo-dir .", command)
        self.assertIn('--source-revision "$GITHUB_SHA"', command)
        self.assertIn('--actor "$GITHUB_ACTOR"', command)
        self.assertIn('--actor "$GITHUB_TRIGGERING_ACTOR"', command)
        self.assertNotIn("--range", command)
        self.assertNotIn("--pre-approval", command)
        self.assertNotIn("continue-on-error", yaml.safe_dump(publish))
        self.assertNotIn("|| true", command)
        all_runs = "\n".join(s.get("run", "") for s in steps)
        self.assertNotIn("gh attestation verify", all_runs)
        self.assertNotIn("dist/obaaf-", all_runs)
        self.assertNotIn("pip install", all_runs)
        self.assertIn("actions/runs/$GITHUB_RUN_ID/approvals", steps[approvals]["run"])


class ObafReleasePolicyTest(unittest.TestCase):
    def test_committed_policy_matches_the_dogfood_contract(self):
        self.assertTrue(POLICY.is_file())
        text = POLICY.read_text(encoding="utf-8")
        self.assertIn("format: obaaf-policy/v0.1", text)
        policy = Policy.load(POLICY)
        self.assertEqual(policy.repository, "Obaaf/OBAAF")
        self.assertEqual(policy.signing, "sigstore")
        self.assertEqual(
            policy.provenance_workflow,
            "Obaaf/OBAAF/.github/workflows/release-pypi.yml",
        )
        self.assertIn("refs/tags/v*", policy.source_refs)
        self.assertEqual(policy.runner_environments, ["github-hosted"])
        self.assertFalse(policy.require_sdks)
        self.assertEqual(policy.release_environments, ["pypi"])
        self.assertEqual(policy.release_branch, "main")
        self.assertGreaterEqual(policy.min_approvals, 1)
        self.assertTrue(policy.approver_not_actor)
        self.assertTrue(policy.agents_check)
        self.assertIsNone(policy.agents_since)
        self.assertNotIn("OWNER/REPO", text)
        self.assertNotIn("obaaf-release.yml", text)


class ReleasePypiCheckerTest(unittest.TestCase):
    def test_release_pypi_publish_is_not_provenance_only(self):
        from obaaf import checker

        result = checker.check(WORKFLOW, config=checker.Config())
        self.assertFalse(result.errors, result.errors)
        gha016 = [f for f in result.findings if f.rule == "OBAAF-GHA-016" and not f.suppressed]
        self.assertEqual(gha016, [], [f.message for f in gha016])

    def test_releasing_doc_does_not_prescribe_gh_attestation_as_the_upload_gate(self):
        text = (ROOT / "docs" / "releasing.md").read_text(encoding="utf-8")
        self.assertIn("obaaf verify release", text)
        self.assertNotIn("gh attestation verify \"$file\"", text)
        self.assertNotIn("Full `obaaf verify release` remains a later dogfood step", text)


if __name__ == "__main__":
    unittest.main()
