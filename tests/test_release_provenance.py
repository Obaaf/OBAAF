"""OBAAF's own PyPI release: build-record, Sigstore attest, then full verify before upload.

The build job holds no signing identity. The attest job signs only. The publish job
checks out the default branch, installs the reviewed CLI via setup-obaaf, and runs
`obaaf verify release` (provenance body, build record, approvals, agent history)
before uploading.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

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
        # The commit of release 0.3.0, the first release that passed the full gate (D-025). A later
        # value must be the commit of a later release that passed, set in a reviewed change.
        self.assertEqual(policy.agents_since, "5162a177955b4f18ba190d048862e66246b4af05")
        self.assertNotIn("0123456789abcdef", text)   # the placeholder from before release 0.3.0
        self.assertNotIn("OWNER/REPO", text)
        self.assertNotIn("obaaf-release.yml", text)


class VersionAndTagTest(unittest.TestCase):
    """The build job refuses a version that is not the tag, and a development version bound for PyPI.

    Between two releases the version on main is a .devN number, so a tag pushed without setting the
    release version would upload one. The step is read from the workflow and its script is run here."""

    NAME = "Refuse a version that is not the tag, or a development version bound for PyPI"
    TEST_PYPI = "https://test.pypi.org/legacy/"

    @classmethod
    def setUpClass(cls):
        cls.jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
        cls.steps = cls.jobs["build"]["steps"]
        cls.index = _step_index(cls.steps, lambda s: s.get("name") == cls.NAME)
        cls.step = cls.steps[cls.index]

    def test_the_step_cannot_be_skipped_or_passed_over(self):
        self.assertEqual(sorted(self.step), ["env", "name", "run"])   # no `if`, no `continue-on-error`, no `shell`
        self.assertNotIn("continue-on-error", self.jobs["build"])
        # Everything from outside arrives through the environment. Pasted into the script, a ref name
        # such as v$(command) would be run.
        self.assertEqual(self.step["env"], {"REF_TYPE": "${{ github.ref_type }}", "REF_NAME": "${{ github.ref_name }}",
                                            "INDEX": "${{ github.event.inputs.repository-url }}"})
        self.assertNotIn("${{", self.step["run"])
        # The same input decides where the publish job uploads.
        upload = self.jobs["publish"]["steps"][-1]
        self.assertIn("gh-action-pypi-publish", upload["uses"])
        self.assertEqual(upload["with"]["repository-url"], self.step["env"]["INDEX"])

    def test_nothing_leaves_the_build_job_before_it_and_no_later_job_runs_without_it(self):
        def uploads(steps):
            return [s for s in steps if "upload-artifact" in str(s.get("uses", ""))]

        self.assertEqual(uploads(self.steps[:self.index]), [])
        self.assertEqual(len(uploads(self.steps[self.index + 1:])), 2)
        self.assertEqual(self.jobs["attest"]["needs"], "build")
        self.assertEqual(self.jobs["publish"]["needs"], ["build", "attest"])
        for job in ("attest", "publish"):
            self.assertNotIn("if", self.jobs[job], job)   # `if: always()` would run it after a failed build

    def run_step(self, version: str, ref_type: str, ref_name: str, index: str = "") -> tuple[int, str, list[str]]:
        """Run the step's script as the runner would, with a stand-in for the interpreter of the clean
        environment that answers ``version`` (or fails when it is empty). Returns the exit code, what was
        printed, and the files the script left in its working directory."""
        with tempfile.TemporaryDirectory() as tmp:
            stand_in = Path(tmp) / "runner" / "clean" / "bin" / "python"
            stand_in.parent.mkdir(parents=True)
            stand_in.write_text('#!/bin/sh\n[ -n "$STAND_IN_VERSION" ] || exit 3\nprintf "%s\\n" "$STAND_IN_VERSION"\n',
                                encoding="utf-8")
            stand_in.chmod(0o755)
            work = Path(tmp) / "work"
            work.mkdir()
            env = {"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": str(Path(tmp) / "runner"),
                   "REF_TYPE": ref_type, "REF_NAME": ref_name, "INDEX": index, "STAND_IN_VERSION": version}
            done = subprocess.run(["bash", "-e", "-c", self.step["run"]], env=env, cwd=work, capture_output=True,
                                  text=True, timeout=60, check=False)
            return done.returncode, done.stdout + done.stderr, sorted(p.name for p in work.iterdir())

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "the step is a bash script")
    def test_what_the_script_lets_through_and_what_it_stops(self):
        cases = [
            # version, ref type, ref name, index, passes
            ("0.4.0", "tag", "v0.4.0", "", True),                           # a release, tagged as itself
            ("0.4.0", "tag", "v0.4.0", self.TEST_PYPI, True),
            ("0.4.0.dev0", "tag", "v0.4.0", "", False),                     # the version was not set before tagging
            ("0.4.0.dev0", "tag", "v0.4.0", self.TEST_PYPI, False),
            ("0.4.0", "tag", "v0.4", "", False),                            # the tag is the mistake
            ("0.4.0", "tag", "V0.4.0", "", False),
            ("0.4.0", "tag", "0.4.0", "", False),
            ("0.4.0", "tag", "v0.4.0 ", "", False),
            ("0.4.0", "tag", "v0.4.1", "", False),
            ("0.4.0", "tag", "", "", False),
            ("0.4.0.dev0", "tag", "v0.4.0.dev0", "", False),                # a development version, bound for PyPI
            ("0.4.0.dev0", "tag", "v0.4.0.dev0", self.TEST_PYPI, True),     # a rehearsal on another index
            ("0.4.0.dev0", "branch", "main", "", False),                    # run by hand from a branch
            ("0.4.0.dev0", "branch", "main", self.TEST_PYPI, True),
            ("0.4.0", "branch", "main", "", True),                          # `obaaf verify release` refuses this one later
            ("0.4.0", "branch", "v0.4.1", "", True),                        # a branch named like a tag is not a tag
            ("", "tag", "v0.4.0", "", False),                               # the version could not be read
            ("", "branch", "main", self.TEST_PYPI, False),
        ]
        for version, ref_type, ref_name, index, passes in cases:
            with self.subTest(version=version, ref_type=ref_type, ref_name=ref_name, index=index):
                code, said, _ = self.run_step(version, ref_type, ref_name, index)
                self.assertEqual(code == 0, passes, said)
                if version and not passes:
                    self.assertIn("::error::", said)
                    self.assertIn("Nothing was uploaded", said)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "the step is a bash script")
    def test_a_ref_name_is_compared_and_never_run(self):
        # Git allows all of these in a tag's name.
        for ref_name in ("v$(touch made-by-the-tag)", "v`touch made-by-the-tag`", "v0.4.0;touch${IFS}made-by-the-tag",
                         "v0.4.0\"&&touch${IFS}made-by-the-tag&&\""):
            with self.subTest(ref_name=ref_name):
                code, said, left = self.run_step("0.4.0", "tag", ref_name)
                self.assertNotEqual(code, 0, said)
                self.assertEqual(left, [], said)

    def test_the_runbook_says_what_the_step_does(self):
        text = (ROOT / "docs" / "releasing.md").read_text(encoding="utf-8")
        self.assertIn("`obaaf docs build`", text)
        self.assertIn("never to PyPI", text)
        self.assertIn("`v` followed by the version", text)


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
