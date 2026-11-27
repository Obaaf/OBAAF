"""The release decision as JSON (#394): `allowed` says whether the upload may proceed.

`obaaf verify release --pre-approval` runs before anyone approves, so that the approver can read the
result, and skips the approvals. Its JSON decision said `"allowed": true` when the rest passed, the
same as a full verification that may be uploaded. Since slice 2d.24 a pre-approval run is never
`allowed`; `checksPassed` says whether what it checked passed, `preApproval` says it was one, and
`approvalsRequired` is the policy's `release.min_approvals`.
"""

import json
import os
import unittest
from unittest import mock

from helpers import TempDir, run_cli, write_json
from scenario import build_release, load

from obaaf.verify import release
from obaaf.verify.policy import Policy

FORMAT = "obaaf-release-decision/v0.2"
KEYS = ["format", "allowed", "checksPassed", "preApproval", "approvalsRequired", "blocks", "warnings",
        "artifacts", "agentCommits", "approvals"]


def cli_args(r):
    return ["verify", "release", "--policy", r.policy, "--artifacts", r.dist, "--dsse", r.attestations,
            "--actor", "releaser", "--repo-dir", r.repo, "--range", r.range, "--source-revision", r.head]


def run_json(*args):
    """Run `obaaf verify release ... --format json` and return the exit status and the decision."""
    code, out, err = run_cli(*args, "--format", "json")
    return code, json.loads(out), err


class ReleaseDecisionJsonTest(unittest.TestCase):
    def assertConsistent(self, code, doc):
        """What holds for every decision: the keys and their order, and how the fields agree."""
        self.assertEqual(list(doc), KEYS)
        self.assertEqual(doc["format"], FORMAT)
        for key in ("allowed", "checksPassed", "preApproval"):
            self.assertIs(type(doc[key]), bool, key)
        self.assertIs(type(doc["approvalsRequired"]), int)
        self.assertEqual(doc["checksPassed"], doc["blocks"] == [])
        self.assertEqual(doc["allowed"], doc["checksPassed"] and not doc["preApproval"])
        self.assertEqual(code, 0 if doc["checksPassed"] else 1)

    def test_a_full_verification_that_passes_is_allowed(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            code, doc, err = run_json(*cli_args(r), "--approvals", r.approvals)
            self.assertConsistent(code, doc)
            self.assertEqual(code, 0, err)
            self.assertEqual((doc["allowed"], doc["checksPassed"], doc["preApproval"], doc["approvalsRequired"]),
                             (True, True, False, 1))
            self.assertEqual(doc["approvals"], ["approver"])

    def test_a_full_verification_that_blocks_is_not_allowed(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            code, doc, _ = run_json(*cli_args(r))
            self.assertConsistent(code, doc)
            self.assertEqual((doc["allowed"], doc["checksPassed"], doc["preApproval"]), (False, False, False))
            self.assertTrue(any("no release approvals were supplied" in b for b in doc["blocks"]), doc["blocks"])

    def test_a_pre_approval_run_that_passes_is_not_allowed(self):
        # The case of #394: the run passed what it checked, and the upload may not proceed on it.
        with TempDir() as tmp:
            r = build_release(tmp)
            code, doc, err = run_json(*cli_args(r), "--pre-approval")
            self.assertConsistent(code, doc)
            self.assertEqual(code, 0, err)
            self.assertEqual((doc["allowed"], doc["checksPassed"], doc["preApproval"], doc["approvalsRequired"]),
                             (False, True, True, 1))
            self.assertEqual(doc["blocks"], [])
            self.assertEqual(doc["approvals"], [])
            self.assertIn("approvals were not checked (pre-approval run); the upload job checks them", doc["warnings"])

    def test_approvals_given_to_a_pre_approval_run_are_not_counted(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            code, doc, _ = run_json(*cli_args(r), "--pre-approval", "--approvals", r.approvals)
            self.assertConsistent(code, doc)
            self.assertEqual((doc["allowed"], doc["checksPassed"], doc["preApproval"]), (False, True, True))
            self.assertEqual(doc["approvals"], [])

    def test_a_pre_approval_run_that_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            write_json(r.attestations, load(r.attestations)[1:])  # drop the SLSA provenance
            code, doc, _ = run_json(*cli_args(r), "--pre-approval")
            self.assertConsistent(code, doc)
            self.assertEqual((doc["allowed"], doc["checksPassed"], doc["preApproval"]), (False, False, True))
            self.assertTrue(doc["blocks"])

    def test_no_approvals_required(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            r.policy.write_text(r.policy.read_text().replace("min_approvals: 1", "min_approvals: 0"))
            code, doc, err = run_json(*cli_args(r))
            self.assertConsistent(code, doc)
            self.assertEqual((doc["allowed"], doc["checksPassed"], doc["preApproval"], doc["approvalsRequired"]),
                             (True, True, False, 0), err)
            # A pre-approval run decides nothing about the upload, even where no approval is needed.
            code, doc, _ = run_json(*cli_args(r), "--pre-approval")
            self.assertConsistent(code, doc)
            self.assertEqual((doc["allowed"], doc["checksPassed"], doc["preApproval"], doc["approvalsRequired"]),
                             (False, True, True, 0))

    def test_json_to_a_file_keeps_the_text_on_the_console_and_in_the_summary(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            out_file, summary = tmp / "decision.json", tmp / "summary.md"
            with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                code, out, err = run_cli(*cli_args(r), "--pre-approval", "--format", "json", "--output", out_file)
            self.assertEqual(code, 0, err)
            doc = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertConsistent(code, doc)
            self.assertEqual((doc["allowed"], doc["checksPassed"], doc["preApproval"]), (False, True, True))
            heading = "Pre-approval checks: PASSED, release approval is still required"
            self.assertEqual(out.splitlines()[0], heading)
            self.assertEqual(summary.read_text(encoding="utf-8").splitlines()[3], heading)

    def test_the_text_report_of_a_pre_approval_run(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            code, out, err = run_cli(*cli_args(r), "--pre-approval")
            self.assertEqual(code, 0, err)
            lines = out.splitlines()
            self.assertEqual(lines[0], "Pre-approval checks: PASSED, release approval is still required")
            self.assertTrue(lines[1].startswith("  artifact "), lines)
            self.assertIn("warning: approvals were not checked (pre-approval run); the upload job checks them", lines)
            self.assertFalse(any(line.startswith("BLOCK:") for line in lines), lines)

    def test_approvals_of_another_shape_block_without_a_traceback(self):
        # Before this slice, JSON of another shape ended the run in a traceback with no decision.
        shapes = {"a list of texts": ["alice"], "a number": 3, "an object that is not a Jenkins build": {"a": 1},
                  "environments as text": [{"state": "approved", "environments": "release", "user": {"login": "a"}}],
                  "an environment's name as a list": [{"state": "approved", "environments": [{"name": ["release"]}],
                                                       "user": {"login": "a"}}],
                  "the user as text": [{"state": "approved", "environments": [{"name": "release"}], "user": "a"}],
                  "the login as a number": [{"state": "approved", "environments": [{"name": "release"}],
                                             "user": {"login": 7}}]}
        with TempDir() as tmp:
            r = build_release(tmp)
            for label, shape in shapes.items():
                with self.subTest(shape=label):
                    path = write_json(tmp / "approvals-shape.json", shape)
                    code, doc, err = run_json(*cli_args(r), "--approvals", path)
                    self.assertNotIn("Traceback", err)
                    self.assertConsistent(code, doc)
                    self.assertEqual((code, doc["allowed"], doc["checksPassed"]), (1, False, False))
                    self.assertTrue(any(b.startswith("--approvals ") and "no approval was counted" in b
                                        for b in doc["blocks"]), doc["blocks"])
                    self.assertEqual(doc["approvals"], [])
            # The shape GitHub gives, with fields that count for nothing, is still read.
            entries = load(r.approvals) + [{"state": "approved", "environments": [{"name": None}], "user": None},
                                           {"state": "approved", "environments": [], "user": {"login": None}}]
            code, doc, err = run_json(*cli_args(r), "--approvals", write_json(tmp / "approvals-extra.json", entries))
            self.assertConsistent(code, doc)
            self.assertEqual((code, doc["allowed"], doc["approvals"]), (0, True, ["approver"]), err)
            # A pre-approval run does not read the approvals, as before.
            code, doc, _ = run_json(*cli_args(r), "--pre-approval", "--approvals", tmp / "approvals-shape.json")
            self.assertEqual((code, doc["checksPassed"], doc["preApproval"]), (0, True, True))

    def test_a_step_summary_that_cannot_be_written_stops_before_the_decision(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            summary = tmp / "missing" / "summary.md"
            for extra in (["--format", "json"], ["--format", "json", "--output", tmp / "decision.json"], []):
                with self.subTest(extra=extra), mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                    code, out, err = run_cli(*cli_args(r), "--approvals", r.approvals, *extra)
                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertTrue(err.startswith("error: "), err)
                    self.assertNotIn("Traceback", err)
                    self.assertFalse((tmp / "decision.json").exists())

    def test_the_decision_object(self):
        # What the API gives a program that calls verify_release itself.
        with TempDir() as tmp:
            r = build_release(tmp)
            policy = Policy.load(r.policy)
            kwargs = dict(dsse_files=[r.attestations], actors=["releaser"], repo_dir=r.repo, git_range=r.range,
                          source_revision=r.head)
            before = release.verify_release(policy, [r.dist], pre_approval=True, **kwargs)
            self.assertTrue(before.ok, before.blocks)
            self.assertFalse(before.allowed)
            self.assertTrue(before.pre_approval)
            self.assertEqual(before.approvals_required, 1)
            after = release.verify_release(policy, [r.dist], approvals=load(r.approvals), **kwargs)
            self.assertTrue(after.ok, after.blocks)
            self.assertTrue(after.allowed)
            self.assertFalse(after.pre_approval)
            self.assertEqual(after.to_dict()["allowed"], True)
            self.assertEqual(before.to_dict()["allowed"], False)
            # A decision made by hand is a full one unless it says otherwise, as before.
            self.assertTrue(release.Decision().allowed)
            self.assertFalse(release.Decision(pre_approval=True).allowed)
            self.assertFalse(release.Decision(blocks=["x"]).allowed)


if __name__ == "__main__":
    unittest.main()
