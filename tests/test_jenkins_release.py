"""The release lane on Jenkins (FR5, FR6, FR11): records written in a Jenkins build, signed through a
key service, and verified with the approvals Jenkins records.

The key service is simulated with a throwaway ECDSA key that signs the digest `obaaf dsse prepare`
writes, as `aws kms sign --message-type DIGEST` does. Everything else runs the commands the
templates in templates/jenkins/ run.
"""

import base64
import json
import os
import re
import unittest
from unittest import mock

from helpers import ROOT, TempDir, git, init_repo, make_key, run_cli

from obaaf.attest import manifest
from obaaf.attest.common import ci_run
from obaaf.checker import check
from obaaf.verify import release
from obaaf.verify.policy import Policy

TEMPLATES = ROOT / "templates" / "jenkins"
SOURCES = """
components:
  - id: engine
    name: Example engine
    version: "5.4.1"
    source: Vendor portal
    kind: engine
    paths: ["Engine/**"]
  - id: analytics
    name: Example analytics SDK
    version: "2.0.0"
    source: Vendor archive
    kind: sdk
    paths: ["ThirdParty/Analytics/**"]
"""
JENKINS_ENV = {"JENKINS_URL": "https://ci.example.invalid/", "BUILD_URL":
               "https://ci.example.invalid/job/obaaf-release-publish/7/", "JOB_NAME": "obaaf-release-publish",
               "BUILD_NUMBER": "7", "NODE_NAME": "release-1", "GIT_URL": "https://git.example.invalid/studio/game.git"}
APPROVER = "org.jenkinsci.plugins.workflow.support.steps.input.ApproverAction"
USER_CAUSE = "hudson.model.Cause$UserIdCause"
UPSTREAM = "org.jenkinsci.plugins.workflow.support.steps.build.BuildUpstreamCause"
REPLAY = "org.jenkinsci.plugins.workflow.cps.replay.ReplayCause"
CTRL = "https://ci.example.invalid/"
TAG_BUILD_URL = CTRL + "job/studio/job/game/job/v1.0.0/3/"


def publish_run(approvers=("carol",), upstream=("studio/game/v1.0.0", 3, "job/studio/job/game/job/v1.0.0/"),
                started_by=None, extra_causes=()):
    """The publishing build's JSON, as BUILD_URL/api/json?tree=... returns it."""
    causes = []
    if upstream:
        causes.append({"_class": UPSTREAM, "shortDescription": "Started by upstream project",
                       "upstreamProject": upstream[0], "upstreamBuild": upstream[1], "upstreamUrl": upstream[2]})
    if started_by:
        causes.append({"_class": USER_CAUSE, "userId": started_by, "shortDescription": f"Started by {started_by}"})
    causes += [{"_class": c, "shortDescription": "Replayed #6"} for c in extra_causes]
    actions = [{"_class": "hudson.model.CauseAction", "causes": causes}, {}]
    actions += [{"_class": APPROVER, "userId": a} for a in approvers]
    return {"_class": "org.jenkinsci.plugins.workflow.job.WorkflowRun", "number": 7,
            "url": CTRL + "job/releases/job/obaaf-release-publish/7/", "actions": actions}


def tag_build(revision, started_by=None, extra_causes=(), url=TAG_BUILD_URL):
    """The JSON of the tag build that produced the artifacts."""
    causes = [{"_class": "jenkins.branch.BranchEventCause", "shortDescription": "Push event to tag v1.0.0"}]
    if started_by:
        causes.append({"_class": USER_CAUSE, "userId": started_by, "shortDescription": f"Started by {started_by}"})
    causes += [{"_class": c, "shortDescription": "Replayed #2"} for c in extra_causes]
    return {"_class": "org.jenkinsci.plugins.workflow.job.WorkflowRun", "number": 3, "url": url,
            "actions": [{"_class": "hudson.model.CauseAction", "causes": causes},
                        {"_class": "hudson.plugins.git.util.BuildData", "lastBuiltRevision": {"SHA1": revision}}]}


def kms_sign(key, digest_path, out_path, p1363=False):
    """What `aws kms sign --message-type DIGEST --output text` returns: base64 of a DER signature."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    der = key.sign(digest_path.read_bytes(), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    if p1363:
        r, s = utils.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        out_path.write_bytes(raw)
    else:
        out_path.write_text(base64.b64encode(der).decode("ascii") + "\n")


class JenkinsReleaseLaneTest(unittest.TestCase):
    def setUp(self):
        self._tmp = TempDir()
        self.tmp = self._tmp.__enter__()
        self.repo = init_repo(self.tmp / "game")
        (self.repo / "Engine").mkdir()
        (self.repo / "Engine" / "engine.dll").write_bytes(b"engine-binary")
        (self.repo / "ThirdParty" / "Analytics").mkdir(parents=True)
        (self.repo / "ThirdParty" / "Analytics" / "analytics.dll").write_bytes(b"sdk-binary")
        (self.repo / "obaaf-sources.yaml").write_text(SOURCES, encoding="utf-8")
        manifest.write(manifest.create(self.repo, self.repo / "obaaf-sources.yaml"), self.repo / "obaaf-manifest.json")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "Release 1.0.0")
        git(self.repo, "tag", "v1.0.0")
        self.rev = git(self.repo, "rev-parse", "HEAD").strip()
        self.dist = self.tmp / "dist"
        self.dist.mkdir()
        (self.dist / "Game-win64.zip").write_bytes(b"release build, windows")
        self.att = self.tmp / "attestations"
        self.att.mkdir()
        self.key, self.pub = make_key(self.tmp, "release")
        self.policy = self.tmp / "policy.yaml"
        self.policy.write_text(
            "format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: keys\n"
            f"keys: {{provenance: [{self.pub.name}], build_record: [{self.pub.name}]}}\n"
            "release: {branch: main, min_approvals: 1, jenkins_project: studio/game, approvers: [carol, dave]}\n"
            "agents: {check: true}\n", encoding="utf-8")

    def tearDown(self):
        self._tmp.__exit__(None, None, None)

    def write_records(self, p1363=False):
        with mock.patch.dict(os.environ, JENKINS_ENV, clear=False):
            for var in ("GITHUB_ACTIONS",):
                os.environ.pop(var, None)
            code, out, err = run_cli(
                "attest", "slsa", "--artifact", self.dist, "--builder-id", "https://ci.example.invalid/job/x/",
                "--repository-uri", JENKINS_ENV["GIT_URL"], "--source-revision", self.rev,
                "--source-ref", "refs/tags/v1.0.0", "--invocation-id", JENKINS_ENV["BUILD_URL"],
                "--out", self.att / "slsa.json", "--statement-out", self.att / "slsa.statement.json")
            self.assertEqual(code, 0, err)
            code, out, err = run_cli(
                "attest", "build-record", "--artifact", self.dist, "--source-revision", self.rev,
                "--source-ref", "refs/tags/v1.0.0", "--repository", JENKINS_ENV["GIT_URL"],
                "--asset-revision", self.rev, "--asset-system", "git", "--manifest", self.repo / "obaaf-manifest.json",
                "--builder-id", "https://ci.example.invalid/job/x/", "--tier", "B",
                "--out", self.att / "build-record.json", "--statement-out", self.att / "build-record.statement.json")
            self.assertEqual(code, 0, err)
        envelopes = []
        for record in ("slsa", "build-record"):
            stmt = self.att / f"{record}.statement.json"
            code, _, err = run_cli("dsse", "prepare", "--statement", stmt, "--out", self.att / f"{record}.to-sign",
                                   "--digest-out", self.att / f"{record}.digest")
            self.assertEqual(code, 0, err)
            kms_sign(self.key, self.att / f"{record}.digest", self.att / f"{record}.sig", p1363=p1363)
            code, _, err = run_cli("dsse", "assemble", "--statement", stmt, "--signature", self.att / f"{record}.sig",
                                   "--public-key", self.pub, "--out", self.att / f"{record}.dsse.json")
            self.assertEqual(code, 0, err)
            envelopes.append(self.att / f"{record}.dsse.json")
        return envelopes

    def verify(self, envelopes, approvals=None, release_run=None, pre_approval=False):
        return release.verify_release(Policy.load(self.policy), [self.dist], dsse_files=envelopes,
                                      approvals=approvals, release_run=release_run, repo_dir=self.repo,
                                      source_revision=self.rev, pre_approval=pre_approval)

    # -------------------------------------------------------------------------------- the lane
    def test_records_signed_through_a_key_service_verify(self):
        envelopes = self.write_records()
        before = self.verify(envelopes, pre_approval=True)
        self.assertTrue(before.ok, before.blocks)
        # What the publish template runs before anyone approves.
        before = self.verify(envelopes, release_run=tag_build(self.rev), pre_approval=True)
        self.assertTrue(before.ok, before.blocks)
        self.assertFalse(self.verify(envelopes, release_run=tag_build("b" * 40), pre_approval=True).ok)
        after = self.verify(envelopes, approvals=publish_run(), release_run=tag_build(self.rev))
        self.assertTrue(after.ok, after.blocks)
        self.assertEqual(after.approvals, ["carol"])
        self.assertEqual(after.artifacts[0]["tier"], "B")

    def test_raw_r_s_signatures_from_a_key_service_are_accepted(self):
        self.assertTrue(self.verify(self.write_records(p1363=True), pre_approval=True).ok)

    def test_the_cli_reads_jenkins_evidence(self):
        envelopes = self.write_records()
        (self.tmp / "publish-run.json").write_text(json.dumps(publish_run()))
        (self.tmp / "release-run.json").write_text(json.dumps(tag_build(self.rev)))
        args = ["verify", "release", "--policy", self.policy, "--artifacts", self.dist,
                "--approvals", self.tmp / "publish-run.json", "--release-run", self.tmp / "release-run.json",
                "--repo-dir", self.repo, "--source-revision", self.rev]
        for env in envelopes:
            args += ["--dsse", env]
        code, out, _ = run_cli(*args)
        self.assertEqual(code, 0, out)
        self.assertIn("release approved by: carol", out)

    def test_records_name_the_jenkins_build_and_say_it_is_self_reported(self):
        self.write_records()
        record = json.loads((self.att / "build-record.json").read_text())
        self.assertEqual(record["run"]["platform"], "jenkins")
        self.assertEqual(record["run"]["url"], JENKINS_ENV["BUILD_URL"])
        self.assertIn("self-reported", record["run"]["reportedBy"])
        self.assertEqual(record["source"]["reportedBy"], "Jenkins release job")
        self.assertEqual(record["isolation"]["reportedBy"], "command line")
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "studio/game",
                                          **JENKINS_ENV}):
            self.assertEqual(ci_run()["platform"], "github-actions")

    # ------------------------------------------------------------------------- what blocks
    def test_approvals_by_who_started_the_release_do_not_count(self):
        envelopes = self.write_records()
        decision = self.verify(envelopes, approvals=publish_run(approvers=["carol"]),
                               release_run=tag_build(self.rev, started_by="carol"))
        self.assertFalse(decision.ok)
        self.assertTrue(any("qualifying approval" in b for b in decision.blocks), decision.blocks)
        self.assertFalse(self.verify(envelopes, approvals=publish_run(approvers=()),
                                     release_run=tag_build(self.rev)).ok)

    def test_only_listed_approvers_count(self):
        # A Jenkins administrator can approve any input step, whatever its submitter says.
        envelopes = self.write_records()
        decision = self.verify(envelopes, approvals=publish_run(approvers=["admin"]), release_run=tag_build(self.rev))
        self.assertFalse(decision.ok)
        self.assertTrue(any("release.approvers" in w for w in decision.warnings))

    def test_replayed_or_restarted_builds_are_blocked(self):
        envelopes = self.write_records()
        for cause in (REPLAY,
                      "org.jenkinsci.plugins.pipeline.modeldefinition.causes.RestartDeclarativePipelineCause"):
            decision = self.verify(envelopes, approvals=publish_run(extra_causes=[cause]),
                                   release_run=tag_build(self.rev))
            self.assertFalse(decision.ok, cause)
            decision = self.verify(envelopes, approvals=publish_run(), release_run=tag_build(self.rev, extra_causes=[cause]))
            self.assertFalse(decision.ok, cause)

    def test_artifacts_must_come_from_the_build_that_started_the_publish_job(self):
        envelopes = self.write_records()
        # The publish build was started by build 4 (a replay or a branch build), but the evidence names build 3.
        swapped = publish_run(upstream=("studio/game/v1.0.0", 4, "job/studio/job/game/job/v1.0.0/"))
        decision = self.verify(envelopes, approvals=swapped, release_run=tag_build(self.rev))
        self.assertFalse(decision.ok)
        self.assertTrue(any("was started by" in b for b in decision.blocks), decision.blocks)
        # Started by a branch build of the project, not the tag build.
        branch = publish_run(upstream=("studio/game/feature-x", 3, "job/studio/job/game/job/v1.0.0/"))
        self.assertFalse(self.verify(envelopes, approvals=branch, release_run=tag_build(self.rev)).ok)
        # Started by hand, or by no build at all.
        self.assertFalse(self.verify(envelopes, approvals=publish_run(started_by="mallory"),
                                     release_run=tag_build(self.rev)).ok)
        self.assertFalse(self.verify(envelopes, approvals=publish_run(upstream=None),
                                     release_run=tag_build(self.rev)).ok)
        # Without release.jenkins_project, nothing says which project builds release tags.
        self.policy.write_text(self.policy.read_text().replace(" jenkins_project: studio/game,", ""))
        decision = self.verify(envelopes, approvals=publish_run(), release_run=tag_build(self.rev))
        self.assertFalse(decision.ok)
        self.assertTrue(any("release.jenkins_project" in b for b in decision.blocks), decision.blocks)

    def test_the_tag_build_must_have_checked_out_the_release_commit(self):
        envelopes = self.write_records()
        decision = self.verify(envelopes, approvals=publish_run(), release_run=tag_build("b" * 40))
        self.assertFalse(decision.ok)
        self.assertTrue(any("not the release commit" in b for b in decision.blocks), decision.blocks)
        unknown = tag_build(self.rev)
        unknown["actions"] = unknown["actions"][:1]
        self.assertFalse(self.verify(envelopes, approvals=publish_run(), release_run=unknown).ok)

    def test_incomplete_or_mixed_evidence_fails_closed(self):
        envelopes = self.write_records()
        # The publishing build without the producing build.
        self.assertFalse(self.verify(envelopes, approvals=publish_run()).ok)
        # GitHub-style approvals with a Jenkins producing build.
        github = [{"state": "approved", "environments": [{"name": "release"}], "user": {"login": "carol"}}]
        self.assertFalse(self.verify(envelopes, approvals=github, release_run=tag_build(self.rev)).ok)
        # Causes without a class, or no causes at all, could hide a Replay.
        hidden = publish_run()
        for cause in hidden["actions"][0]["causes"]:
            cause.pop("_class")
        self.assertFalse(self.verify(envelopes, approvals=hidden, release_run=tag_build(self.rev)).ok)
        bare = tag_build(self.rev)
        bare["actions"][0]["causes"] = []
        self.assertFalse(self.verify(envelopes, approvals=publish_run(), release_run=bare).ok)

    def test_r_s_signatures_that_start_like_der_are_accepted(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        from obaaf.verify import dsse

        stmt = json.loads(json.dumps({"_type": "x", "subject": [], "predicateType": "t", "predicate": {}}))
        key = dsse.PublicKey.load(self.pub)
        found = 0
        for i in range(4000):
            stmt["predicate"] = {"n": i}
            der = self.key.sign(dsse.to_sign(stmt), ec.ECDSA(hashes.SHA256()))
            r, s_ = utils.decode_dss_signature(der)
            raw = r.to_bytes(32, "big") + s_.to_bytes(32, "big")
            if raw[0] == 0x30:
                dsse.assemble(stmt, raw, key)        # raises if refused
                found += 1
                if found == 2:
                    break
        self.assertGreater(found, 0)

    def test_a_changed_artifact_is_blocked(self):
        envelopes = self.write_records()
        (self.dist / "Game-win64.zip").write_bytes(b"release build, windows, with a backdoor")
        decision = self.verify(envelopes, pre_approval=True)
        self.assertFalse(decision.ok)
        self.assertTrue(any("no verified SLSA provenance" in b for b in decision.blocks))

    def test_a_commit_not_on_the_protected_branch_is_blocked(self):
        envelopes = self.write_records()
        git(self.repo, "checkout", "-q", "-b", "side")
        (self.repo / "x.txt").write_text("x")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "side")
        side = git(self.repo, "rev-parse", "HEAD").strip()
        git(self.repo, "checkout", "-q", "main")
        decision = release.verify_release(Policy.load(self.policy), [self.dist], dsse_files=envelopes,
                                          repo_dir=self.repo, source_revision=side, pre_approval=True)
        self.assertFalse(decision.ok)

    def test_assemble_refuses_a_wrong_key_or_a_changed_statement(self):
        self.write_records()
        other, other_pub = make_key(self.tmp, "other")
        kms_sign(other, self.att / "slsa.digest", self.att / "other.sig")
        code, _, err = run_cli("dsse", "assemble", "--statement", self.att / "slsa.statement.json",
                               "--signature", self.att / "other.sig", "--public-key", self.pub,
                               "--out", self.att / "x.json")
        self.assertEqual(code, 1)
        self.assertIn("does not verify", err)
        stmt = json.loads((self.att / "slsa.statement.json").read_text())
        stmt["subject"][0]["digest"]["sha256"] = "0" * 64
        (self.att / "changed.json").write_text(json.dumps(stmt))
        code, _, _ = run_cli("dsse", "assemble", "--statement", self.att / "changed.json",
                             "--signature", self.att / "slsa.sig", "--public-key", self.pub, "--out", self.att / "y.json")
        self.assertEqual(code, 1)


class JenkinsReleaseTemplatesTest(unittest.TestCase):
    def test_templates_pass_the_jenkins_rules(self):
        for name in ("obaaf-release-build.Jenkinsfile", "obaaf-release-publish.Jenkinsfile", "obaaf-audit.Jenkinsfile"):
            result = check(TEMPLATES / name)
            self.assertEqual(result.errors, [])
            self.assertEqual([(f.rule, f.line, f.message) for f in result.active()], [], name)
            self.assertNotIn("fail", {row["status"] for row in result.coverage}, name)

    def test_publish_template_verifies_and_approves_before_it_uploads(self):
        text = (TEMPLATES / "obaaf-release-publish.Jenkinsfile").read_text()
        verify = text.index("--approvals publish-run.json")
        self.assertLess(text.index("submitter: 'release-managers'"), verify)
        self.assertLess(verify, text.index("./scripts/publish.sh"))
        self.assertIn("aws kms sign", text)
        # Pre-approval checks already tie the artifacts to the tag build.
        self.assertIn("--release-run release-run.json --repo-dir . --source-revision", text)

    def test_publish_template_ships_only_the_build_that_started_it(self):
        text = (TEMPLATES / "obaaf-release-publish.Jenkinsfile").read_text()
        self.assertNotIn("parameters {", text)
        self.assertNotIn("params.", text)
        self.assertIn("getBuildCauses('hudson.model.Cause$UserIdCause')", text)
        self.assertIn("getBuildCauses('org.jenkinsci.plugins.workflow.support.steps.build.BuildUpstreamCause')", text)
        self.assertIn("copyArtifacts(projectName: '/' + env.RELEASE_JOB, selector: specific(env.RELEASE_BUILD)", text)
        # The JSON the template requests is the JSON the verifier needs.
        from obaaf.verify.release import JENKINS_TREE
        self.assertEqual(text.count(f"tree='{JENKINS_TREE}'"), 2)
        build = (TEMPLATES / "obaaf-release-build.Jenkinsfile").read_text()
        self.assertNotIn("credentials(", build)
        self.assertNotIn("parameters:", build)
        self.assertIn("beforeAgent true", build)
        job = re.search(r"copyArtifactPermission\('(/[^']+)'\)", build).group(1)
        self.assertIn(f"build job: '{job}', wait: false", build)

    def test_policy_example_loads_and_matches_the_templates(self):
        policy = Policy.load(TEMPLATES / "obaaf-policy.example.yaml")
        self.assertEqual(policy.signing, "keys")
        self.assertEqual(policy.release_branch, "main")
        self.assertTrue(policy.approvers)
        text = (TEMPLATES / "obaaf-release-publish.Jenkinsfile").read_text()
        self.assertIn(f"RELEASE_PROJECT = '{policy.jenkins_project}'", text)
        self.assertIn(f"RELEASE_BRANCH = '{policy.release_branch}'", text)


if __name__ == "__main__":
    unittest.main()
