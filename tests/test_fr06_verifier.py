"""FR6: block uploads that fail verification.

Acceptance criterion: the upload step stops when provenance, required
approvals or agent-run records are missing or invalid.
"""

import base64
import json
import os
import unittest
from unittest import mock

from helpers import BOT, TempDir, git, make_key, run_cli, sign, template_workflow, write_json
from scenario import build_release, certificate, fake_gh, gh_entry, load

from obaaf.attest import agentrecord
from obaaf.verify import release
from obaaf.verify.policy import Policy, PolicyError


def verify(r, **overrides):
    kwargs = dict(dsse_files=[r.attestations], approvals=load(r.approvals), actors=["releaser"],
                  repo_dir=r.repo, git_range=r.range, source_revision=r.head)
    kwargs.update(overrides)
    return release.verify_release(Policy.load(r.policy), [r.dist], **kwargs)


def statements(envelopes):
    return [json.loads(base64.b64decode(e["payload"])) for e in envelopes]


class VerifierBlocksTest(unittest.TestCase):
    def test_a_complete_release_passes(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            decision = verify(r)
            self.assertTrue(decision.ok, decision.blocks)
            self.assertEqual(decision.approvals, ["approver"])
            self.assertEqual([c["status"] for c in decision.agent_commits], ["verified"])
            self.assertEqual(decision.artifacts[0]["tier"], "A")

    def test_missing_provenance_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            envs = load(r.attestations)
            write_json(r.attestations, envs[1:])  # drop the SLSA provenance
            decision = verify(r)
            self.assertFalse(decision.ok)
            self.assertTrue(any("no verified SLSA provenance" in b for b in decision.blocks))

    def test_missing_build_record_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            write_json(r.attestations, load(r.attestations)[:1])
            self.assertTrue(any("no verified OBAAF build record" in b for b in verify(r).blocks))

    def test_an_extra_unbuilt_file_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            (r.dist / "injected.dll").write_bytes(b"not built by the release lane")
            self.assertTrue(any("injected.dll" in b for b in verify(r).blocks))

    def test_wrong_signing_key_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            other, _ = make_key(tmp, "intruder")
            write_json(r.attestations, [sign(s, other) for s in statements(load(r.attestations))])
            decision = verify(r)
            self.assertFalse(decision.ok)
            self.assertTrue(any("no verified SLSA provenance" in b for b in decision.blocks))
            self.assertTrue(any("signature check failed" in w for w in decision.warnings))

    def test_a_bad_extra_attestation_does_not_block_a_valid_release(self):
        # Anyone who can add an attestation must not be able to block a release with it.
        with TempDir() as tmp:
            r = build_release(tmp)
            other, _ = make_key(tmp, "intruder")
            envs = load(r.attestations)
            write_json(r.attestations, envs + [sign(statements(envs)[0], other)])
            decision = verify(r)
            self.assertTrue(decision.ok, decision.blocks)

    def test_missing_approvals_block(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            self.assertTrue(any("no release approvals" in b for b in verify(r, approvals=None).blocks))
            self.assertTrue(any("qualifying approval" in b for b in verify(r, approvals=[]).blocks))

    def test_pre_approval_mode_checks_everything_but_the_approvals(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            decision = verify(r, approvals=None, pre_approval=True)
            self.assertTrue(decision.ok, decision.blocks)
            self.assertTrue(any("approvals were not checked" in w for w in decision.warnings))
            write_json(r.attestations, load(r.attestations)[1:])
            self.assertFalse(verify(r, approvals=None, pre_approval=True).ok)

    def test_approval_by_the_person_who_started_the_release_does_not_count(self):
        with TempDir() as tmp:
            r = build_release(tmp, release_approver="releaser")
            decision = verify(r)
            self.assertFalse(decision.ok)
            self.assertTrue(any("qualifying approval" in b for b in decision.blocks))

    def test_approval_by_whoever_re_ran_the_release_does_not_count(self):
        with TempDir() as tmp:
            r = build_release(tmp, release_approver="rerunner")
            self.assertTrue(verify(r).ok)
            decision = verify(r, actors=["releaser", "rerunner"])
            self.assertFalse(decision.ok)
            self.assertTrue(any("rerunner started or re-ran" in w for w in decision.warnings))

    def test_only_listed_approvers_count_when_the_policy_lists_them(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            text = r.policy.read_text()
            r.policy.write_text(text.replace("release: {", "release: {approvers: [someone-else], ", 1))
            decision = verify(r)
            self.assertFalse(decision.ok)
            self.assertTrue(any("not in release.approvers" in w for w in decision.warnings), decision.warnings)
            r.policy.write_text(text.replace("release: {", "release: {approvers: [Approver], ", 1))
            self.assertTrue(verify(r).ok)

    def test_agent_commit_without_a_record_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp, agent_commit="missing")
            decision = verify(r)
            self.assertTrue(any("carries no agent record" in b for b in decision.blocks))

    def test_tampered_agent_record_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp, agent_commit="tampered")
            decision = verify(r)
            self.assertFalse(decision.ok)
            self.assertTrue(any("covers different files" in b or "does not verify" in b for b in decision.blocks))

    def test_agent_change_approved_only_by_its_requester_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp, approver="maintainer")
            self.assertTrue(any("other than the requester" in b for b in verify(r).blocks))

    def test_agent_change_approved_by_the_author_of_its_task_blocks(self):
        # "outsider" wrote the issue the agent worked from; their approval does not count.
        with TempDir() as tmp:
            r = build_release(tmp, approver="outsider")
            self.assertTrue(any("other than the requester" in b for b in verify(r).blocks))

    def test_agent_run_with_write_permission_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp, agent_tokens="write")
            self.assertTrue(any("held write permissions" in b for b in verify(r).blocks))

    def test_agent_run_with_caches_an_environment_or_a_self_hosted_runner_blocks(self):
        for change, expected in (({"cacheMode": "default"}, "could use caches"),
                                 ({"environment": "prod"}, "used environment 'prod'"),
                                 ({"runner": {"labels": ["self-hosted"], "selfHosted": True, "kind": "self-hosted"}},
                                  "not GitHub-hosted")):
            with self.subTest(change=change), TempDir() as tmp:
                r = build_release(tmp, authority=change)
                self.assertTrue(any(expected in b for b in verify(r).blocks), verify(r).blocks)

    def test_a_record_must_be_added_by_the_commit_that_names_it(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            record = git(r.repo, "ls-files", ".obaaf/records")
            (r.repo / "src" / "later.txt").write_text("not approved\n")
            git(r.repo, "add", ".")
            git(r.repo, "commit", "-q", "-m", "Another change", "-m", f"OBAAF-Agent-Record: {record}", env=BOT)
            decision = verify(r, git_range=f"{r.range.split('..')[0]}..HEAD", source_revision=None)
            self.assertTrue(any("does not add" in b for b in decision.blocks), decision.blocks)

    def test_a_record_cannot_be_reused_for_a_second_commit(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            record = git(r.repo, "ls-files", ".obaaf/records")
            saved = (r.repo / record).read_text()
            git(r.repo, "rm", "-q", record)
            git(r.repo, "commit", "-q", "-m", "Remove the record")
            (r.repo / record).parent.mkdir(parents=True, exist_ok=True)
            (r.repo / record).write_text(saved)
            (r.repo / "src" / "fix.txt").write_text("fix for issue 42\nmore\n")
            git(r.repo, "add", ".")
            git(r.repo, "commit", "-q", "-m", "Second agent change", "-m", f"OBAAF-Agent-Record: {record}", env=BOT)
            decision = verify(r, git_range=f"{r.range.split('..')[0]}..HEAD", source_revision=None)
            self.assertTrue(any("reuses the agent record" in b for b in decision.blocks), decision.blocks)

    def test_a_record_must_be_named_after_its_digest(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            record = git(r.repo, "ls-files", ".obaaf/records")
            other = record.replace(".json", "-copy.json")
            (r.repo / other).write_text((r.repo / record).read_text())
            (r.repo / "src" / "fix.txt").write_text("fix for issue 42\nmore\n")
            git(r.repo, "add", ".")
            git(r.repo, "commit", "-q", "-m", "Second agent change", "-m", f"OBAAF-Agent-Record: {other}", env=BOT)
            decision = verify(r, git_range=f"{r.range.split('..')[0]}..HEAD", source_revision=None)
            self.assertTrue(any("not named after its bundle digest" in b for b in decision.blocks), decision.blocks)

    def test_a_record_without_a_patch_cannot_carry_code(self):
        with TempDir() as tmp:
            r = build_release(tmp, proposal_files={"comment.md": "Thanks, a maintainer will look.\n"})
            decision = verify(r)
            self.assertTrue(any("has no patch" in b for b in decision.blocks), decision.blocks)

    def test_an_edited_agent_change_blocks_by_default(self):
        with TempDir() as tmp:
            r = build_release(tmp, edit_after_approval=True)
            decision = verify(r)
            self.assertTrue(any("differs from the approved proposal" in b for b in decision.blocks), decision.blocks)
            r.policy.write_text(r.policy.read_text().replace("require_exact_diff: true", "require_exact_diff: false"))
            decision = verify(r)
            self.assertTrue(decision.ok, decision.blocks)
            self.assertTrue(any("differs from the approved proposal" in w for w in decision.warnings))

    def test_a_merge_made_under_the_effect_identity_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            base = r.range.split("..")[0]
            git(r.repo, "switch", "-q", "-c", "side", base)
            (r.repo / "src" / "side.txt").write_text("side\n")
            git(r.repo, "add", ".")
            git(r.repo, "commit", "-q", "-m", "Side change")
            git(r.repo, "switch", "-q", "main")
            git(r.repo, "merge", "-q", "--no-ff", "-m", "Merge side", "side", env=BOT)
            decision = verify(r, git_range=f"{base}..HEAD", source_revision=None)
            self.assertTrue(any("merge made under the effect lane's identity" in b for b in decision.blocks))

    def test_agent_records_must_be_checked_unless_the_policy_says_no_agents(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            decision = verify(r, repo_dir=None, git_range=None)
            self.assertTrue(any("agent records were not checked" in b for b in decision.blocks))

    def test_the_range_starts_at_the_policys_baseline(self):
        with TempDir() as tmp:
            r = build_release(tmp, agent_commit="missing")
            head = git(r.repo, "rev-parse", "HEAD")
            self.assertFalse(verify(r, git_range=None, source_revision=head).ok)
            base = git(r.repo, "rev-parse", "HEAD~1")  # after the unrecorded agent commit
            r.policy.write_text(r.policy.read_text().replace("agents: {", f"agents: {{since: {base}, "))
            decision = verify(r, git_range=None, source_revision=head)
            self.assertEqual(decision.agent_commits, [])

    def test_tier_not_allowed_by_policy_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            r.policy.write_text(r.policy.read_text().replace("allowed_tiers: [A, B]", "allowed_tiers: [B]"))
            self.assertTrue(any("Tier A" in b for b in verify(r).blocks))

    def test_release_commit_must_match_the_build_record(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            decision = verify(r, source_revision="f" * 40)
            self.assertTrue(any("not the release commit" in b for b in decision.blocks))

    def test_release_commit_must_be_on_the_protected_branch(self):
        with TempDir() as tmp:
            r = build_release(tmp, on_branch=False)
            decision = verify(r, source_revision=git(r.repo, "rev-parse", "release-candidate"))
            self.assertTrue(any("not on the protected branch 'main'" in b for b in decision.blocks), decision.blocks)

    def test_cli_exit_codes(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            args = ["verify", "release", "--policy", r.policy, "--artifacts", r.dist, "--dsse", r.attestations,
                    "--actor", "releaser", "--repo-dir", r.repo, "--range", r.range, "--source-revision", r.head]
            code, out, _ = run_cli(*args, "--approvals", r.approvals)
            self.assertEqual(code, 0, out)
            self.assertIn("PASSED", out)
            code, out, _ = run_cli(*args)
            self.assertEqual(code, 1)
            self.assertIn("BLOCKED", out)
            code, out, _ = run_cli(*args, "--pre-approval")
            self.assertEqual(code, 0, out)

    def test_cli_no_longer_trusts_unverified_gh_output(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            code, _, err = run_cli("verify", "release", "--policy", r.policy, "--artifacts", r.dist,
                                   "--gh-json", r.attestations)
            self.assertEqual(code, 2)
            self.assertIn("unrecognized arguments", err)


class ExactDiffTest(unittest.TestCase):
    """The committed change must be what applying the approved patch to the commit's parent gives."""

    BASE = "class Reader:\n    def allowed(self):\n        check()\n        return False\n\n" \
           "class Payer:\n    def allowed(self):\n        check()\n        return False\n"

    def repo_with(self, tmp, committed: str):
        from helpers import init_repo

        repo = init_repo(tmp / "repo")
        (repo / "perms.py").write_text(self.BASE)
        git(repo, "add", ".")
        git(repo, "commit", "-q", "-m", "base")
        (repo / "perms.py").write_text(self.BASE.replace("check()\n        return False\n\nclass Payer",
                                                         "check()\n        return True\n\nclass Payer"))
        patch = git(repo, "diff") + "\n"
        (repo / "perms.py").write_text(committed)
        git(repo, "commit", "-q", "-am", "change")
        return repo, git(repo, "rev-parse", "HEAD"), patch.encode()

    def test_the_approved_change_matches(self):
        with TempDir() as tmp:
            approved = self.BASE.replace("check()\n        return False\n\nclass Payer",
                                         "check()\n        return True\n\nclass Payer")
            repo, sha, patch = self.repo_with(tmp, approved)
            self.assertIsNone(release._patch_mismatch(repo, sha, patch, ".obaaf/records"))

    def test_the_same_lines_moved_to_an_identical_context_do_not_match(self):
        with TempDir() as tmp:
            moved = self.BASE[::-1].replace("eslaF nruter", "eurT nruter", 1)[::-1]  # change Payer, not Reader
            self.assertNotEqual(moved, self.BASE)
            repo, sha, patch = self.repo_with(tmp, moved)
            self.assertIn("differs in perms.py", release._patch_mismatch(repo, sha, patch, ".obaaf/records"))

    def test_other_files_in_the_records_directory_block(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            record = git(r.repo, "ls-files", ".obaaf/records")
            git(r.repo, "reset", "-q", "--soft", "HEAD~2")  # undo the agent commit and the bump, keep the files
            (r.repo / ".obaaf" / "records" / "build-hook.sh").write_text("echo hi\n")
            git(r.repo, "add", ".")
            git(r.repo, "commit", "-q", "-m", "Agent proposal for #42", "-m", f"OBAAF-Agent-Record: {record}",
                env=BOT)
            head = git(r.repo, "rev-parse", "HEAD")
            decision = verify(r, git_range=f"v0.9.0..{head}", source_revision=None)
            self.assertTrue(any("may add only its own record" in b for b in decision.blocks), decision.blocks)


class BranchAndRangeTest(unittest.TestCase):
    def test_without_the_release_commit_the_branch_check_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            decision = verify(r, source_revision=None)
            self.assertTrue(any("pass --repo-dir and --source-revision" in b for b in decision.blocks))
            r.policy.write_text(r.policy.read_text().replace("release: {", "release: {branch: '', "))
            self.assertTrue(verify(r, source_revision=None).ok, verify(r, source_revision=None).blocks)

    def test_a_range_cannot_override_the_policy_baseline(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            base = git(r.repo, "rev-parse", "v0.9.0")
            r.policy.write_text(r.policy.read_text().replace("agents: {", f"agents: {{since: '{base}', "))
            decision = verify(r)  # passes --range
            self.assertTrue(any("do not pass --range" in b for b in decision.blocks))
            self.assertTrue(verify(r, git_range=None).ok, verify(r, git_range=None).blocks)

    def test_a_shallow_clone_blocks(self):
        with TempDir() as tmp:
            r = build_release(tmp)
            shallow = tmp / "shallow"
            git(tmp, "clone", "-q", "--depth", "1", "--no-local", r.repo.as_uri(), str(shallow))
            decision = verify(r, repo_dir=shallow)
            self.assertTrue(any("shallow clone" in b for b in decision.blocks), decision.blocks)


class PolicyTest(unittest.TestCase):
    def test_sigstore_policy_must_name_its_source_refs(self):
        with TempDir() as tmp:
            path = tmp / "p.yaml"
            path.write_text("format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: sigstore\n")
            with self.assertRaises(PolicyError):
                Policy.load(path)

    def test_exact_diff_is_required_by_default(self):
        with TempDir() as tmp:
            path = tmp / "p.yaml"
            path.write_text("format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: sigstore\n"
                            "provenance: {source_refs: ['refs/tags/v*']}\n")
            self.assertTrue(Policy.load(path).require_exact_diff)


class SigstoreModeTest(unittest.TestCase):
    """The GitHub path: statements verified by `gh attestation verify`, identities checked by OBAAF."""

    def setUp(self):
        self.tmp_ctx = TempDir()
        self.tmp = self.tmp_ctx.__enter__()
        self.r = build_release(self.tmp, agent_commit="none")
        self.policy = self.tmp / "sigstore-policy.yaml"
        self.policy.write_text(
            "format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: sigstore\n"
            "provenance: {signer_workflow: studio/game/.github/workflows/obaaf-release.yml, source_refs: ['refs/tags/v*']}\n"
            "release: {min_approvals: 1}\nagents: {check: false}\n", encoding="utf-8")
        self.statements = statements(load(self.r.attestations))
        self.gh = release.GhRunner(str(fake_gh(self.tmp)))

    def tearDown(self):
        self.tmp_ctx.__exit__(None, None, None)

    def run_with(self, *certs):
        store = write_json(self.tmp / "store.json", [gh_entry(s, c) for c in certs for s in self.statements])
        with mock.patch.dict(os.environ, {"OBAAF_FAKE_GH_STORE": str(store)}):
            return release.verify_release(Policy.load(self.policy), [self.r.dist], gh=self.gh,
                                          approvals=load(self.r.approvals), actors=["releaser"],
                                          repo_dir=self.r.repo, source_revision=self.r.head)

    def test_expected_signer_passes(self):
        decision = self.run_with(certificate("studio/game/.github/workflows/obaaf-release.yml", "refs/tags/v1.0.0"))
        self.assertTrue(decision.ok, decision.blocks)

    def test_other_workflow_is_rejected(self):
        decision = self.run_with(certificate("studio/game/.github/workflows/ci.yml", "refs/tags/v1.0.0"))
        self.assertFalse(decision.ok)

    def test_unprotected_ref_is_rejected(self):
        decision = self.run_with(certificate("studio/game/.github/workflows/obaaf-release.yml", "refs/heads/feature"))
        self.assertTrue(any("refs/heads/feature" in b for b in decision.blocks))

    def test_other_repository_is_rejected(self):
        cert = certificate("studio/game/.github/workflows/obaaf-release.yml", "refs/tags/v1.0.0", repo="fork/game")
        self.assertTrue(any("not studio/game" in b for b in self.run_with(cert).blocks))

    def test_missing_certificate_fields_fail_closed(self):
        for field in ("issuer", "sourceRepositoryURI", "sourceRepositoryRef"):
            with self.subTest(field=field):
                cert = certificate("studio/game/.github/workflows/obaaf-release.yml", "refs/tags/v1.0.0")
                del cert[field]
                decision = self.run_with(cert)
                self.assertTrue(any(f"does not state {field}" in b for b in decision.blocks), decision.blocks)

    def test_a_rejected_attestation_next_to_a_valid_one_is_only_a_warning(self):
        good = certificate("studio/game/.github/workflows/obaaf-release.yml", "refs/tags/v1.0.0")
        bad = certificate("studio/game/.github/workflows/obaaf-release.yml", "refs/heads/feature")
        decision = self.run_with(good, bad)
        self.assertTrue(decision.ok, decision.blocks)
        self.assertTrue(any("refs/heads/feature" in w for w in decision.warnings))

    def test_without_gh_the_release_is_blocked(self):
        decision = release.verify_release(Policy.load(self.policy), [self.r.dist], gh=release.GhRunner("/nonexistent/gh"),
                                          approvals=load(self.r.approvals))
        self.assertTrue(any("gh) is not available" in b for b in decision.blocks))

    def test_agent_records_are_verified_through_gh(self):
        with TempDir() as tmp:
            r = build_release(tmp, sigstore_records=True)
            gh = fake_gh(tmp)
            policy = tmp / "sg.yaml"
            policy.write_text("format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: sigstore\n"
                              "provenance: {source_refs: ['refs/tags/v*']}\n"
                              "release: {min_approvals: 0}\nagents: {check: true}\n", encoding="utf-8")
            store = write_json(tmp / "store.json", [gh_entry(s, certificate(
                "studio/game/.github/workflows/obaaf-release.yml", "refs/tags/v1.0.0"))
                for s in statements(load(r.attestations))])
            with mock.patch.dict(os.environ, {"OBAAF_FAKE_GH_STORE": str(store)}):
                decision = release.verify_release(Policy.load(policy), [r.dist], gh=release.GhRunner(str(gh)),
                                                  repo_dir=r.repo, git_range=r.range, source_revision=r.head)
            agent = [c for c in decision.agent_commits if c["records"]]
            self.assertTrue(agent and all(c["status"] == "verified" for c in agent), decision.blocks)
            self.assertTrue(decision.ok, decision.blocks)


class AgentRunCheckTest(unittest.TestCase):
    """`obaaf verify agent-run`, which the effect lane runs before acting on a proposal (R8)."""

    def make(self, tmp, **kwargs):
        r = build_release(tmp, keep_agent_files=True, **kwargs)
        return r, r.agent["proposal"], r.agent["snapshot"], r.agent["run_bundle"]

    def check(self, r, proposal, snapshot, bundle, run_id=None):
        return release.verify_agent_run(Policy.load(r.policy), proposal, snapshot, bundle, run_id=run_id)

    def test_a_valid_record_passes_and_gives_the_issue_and_requesters(self):
        with TempDir() as tmp:
            r, proposal, snapshot, bundle = self.make(tmp)
            result = self.check(r, proposal, snapshot, bundle)
            self.assertTrue(result.ok, result.problems)
            outputs = result.outputs()
            self.assertEqual(outputs["issue-number"], "42")
            self.assertEqual(outputs["requesters"], "maintainer,outsider")
            self.assertEqual(outputs["bundle-digest"], agentrecord.bundle_digest(proposal))

    def test_an_added_proposal_file_is_refused(self):
        with TempDir() as tmp:
            r, proposal, snapshot, bundle = self.make(tmp)
            (proposal / "comment.md").write_text("Added after signing.\n")
            result = self.check(r, proposal, snapshot, bundle)
            self.assertTrue(any("covers different files" in p for p in result.problems), result.problems)

    def test_a_replaced_snapshot_is_refused(self):
        with TempDir() as tmp:
            r, proposal, snapshot, bundle = self.make(tmp)
            record = json.loads((snapshot / "snapshot.json").read_text())
            record["trigger"]["number"] = 7
            (snapshot / "snapshot.json").write_text(json.dumps(record))
            result = self.check(r, proposal, snapshot, bundle)
            self.assertTrue(any("not the one the agent read" in p for p in result.problems), result.problems)

    def test_a_record_from_another_run_is_refused(self):
        with TempDir() as tmp:
            r, proposal, snapshot, bundle = self.make(tmp)
            self.assertTrue(self.check(r, proposal, snapshot, bundle, run_id="1234").ok)
            result = self.check(r, proposal, snapshot, bundle, run_id="9999")
            self.assertTrue(any("not run 9999" in p for p in result.problems), result.problems)

    def test_an_agent_with_write_access_is_refused(self):
        with TempDir() as tmp:
            r, proposal, snapshot, bundle = self.make(tmp, agent_tokens="write")
            result = self.check(r, proposal, snapshot, bundle)
            self.assertTrue(any("held write permissions" in p for p in result.problems), result.problems)

    def test_cli_writes_outputs_only_when_verified(self):
        with TempDir() as tmp:
            r, proposal, snapshot, bundle = self.make(tmp)
            out = tmp / "github_output"
            out.write_text("")
            args = ["verify", "agent-run", "--policy", r.policy, "--proposal", proposal, "--snapshot", snapshot,
                    "--bundle", bundle]
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(out)}):
                code, text, _ = run_cli(*args)
            self.assertEqual(code, 0, text)
            self.assertIn("issue-number=42", out.read_text())
            (proposal / "labels.json").write_text('{"add": ["x"]}')
            out.write_text("")
            with mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(out)}):
                code, text, _ = run_cli(*args)
            self.assertEqual(code, 1)
            self.assertEqual(out.read_text(), "")


class PublishTemplateTest(unittest.TestCase):
    def test_verification_runs_before_upload_in_the_publish_job(self):
        wf = template_workflow("obaaf-publish.yml")
        publish = wf.jobs["publish"]
        names = [s.name for s in publish.steps]
        verify_index = next(i for i, s in enumerate(publish.steps) if "obaaf verify release" in s.run)
        upload_index = next(i for i, s in enumerate(publish.steps) if s.env.get("OBAAF_STEP") == "publish")
        self.assertLess(verify_index, upload_index, names)
        self.assertEqual(publish.environment, "release")
        self.assertIn("--approvals", publish.steps[verify_index].run)

    def test_the_approver_sees_a_verification_first(self):
        wf = template_workflow("obaaf-publish.yml")
        self.assertEqual(wf.jobs["publish"].needs, ["verify"])
        verify_job = wf.jobs["verify"]
        self.assertIsNone(verify_job.environment)
        self.assertTrue(any("--pre-approval" in s.run for s in verify_job.steps))

    def test_publish_runs_from_the_default_branch_after_a_tag_build(self):
        wf = template_workflow("obaaf-publish.yml")
        self.assertEqual(set(wf.triggers), {"workflow_run"})
        self.assertEqual(wf.triggers["workflow_run"]["workflows"], ["OBAAF release"])
        condition = wf.jobs["verify"].raw["if"]
        for text in ("workflow_run.event == 'push'", "head_repository.full_name == github.repository",
                     "workflow_run.path == '.github/workflows/obaaf-release.yml'"):
            self.assertIn(text, condition)
        for job in wf.jobs.values():
            self.assertIn("--source-revision", "\n".join(s.run for s in job.steps))
            self.assertTrue(all("--range" not in s.run for s in job.steps), "the range comes from the policy")

    def test_the_build_workflow_uploads_nothing(self):
        wf = template_workflow("obaaf-release.yml")
        self.assertEqual(set(wf.jobs), {"build", "attest"})
        self.assertTrue(all(not s.env.get("OBAAF_STEP") for j in wf.jobs.values() for s in j.steps))


if __name__ == "__main__":
    unittest.main()
