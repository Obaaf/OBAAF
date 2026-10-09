"""Builds complete, signed release scenarios for the verifier tests (FR6, FR8, FR10).

Signatures here use throwaway ECDSA keys and DSSE envelopes (the `signing: keys`
mode). In the GitHub Actions templates the same predicates are signed through
Sigstore; that path is covered with a stand-in `gh` and by the live tests.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from helpers import BOT, FIXTURES, TEMPLATES, git, init_repo, make_key, sign, write_json

from obaaf.attest import agentrecord, records, snapshot
from obaaf.attest.common import statement
from obaaf.predicates import AGENT_APPROVAL, AGENT_RUN, BUILD_RECORD, SLSA_PROVENANCE_V1

AGENT_WORKFLOW = TEMPLATES / "workflows" / "obaaf-agent-propose.yml"
RELEASE_WORKFLOW = TEMPLATES / "workflows" / "obaaf-release.yml"


def take_snapshot(out: Path, event: str = "issue_comment.json", name: str = "issue_comment",
                  roles: dict | None = None, visibility: str = "public") -> Path:
    roles = {"maintainer": "admin", "outsider": "read"} if roles is None else roles
    snapshot.take(FIXTURES / "events" / event, name, out, repository="studio/game", visibility=visibility, roles=roles)
    return out


def approvals(*reviewers: str, environment: str = "obaaf-agent-apply") -> list[dict]:
    return [{"state": "approved", "comment": "ok", "environments": [{"name": environment}],
             "user": {"login": r, "id": 100 + i}} for i, r in enumerate(reviewers)]


@dataclass
class Release:
    root: Path
    repo: Path
    dist: Path
    policy: Path
    attestations: Path
    approvals: Path
    range: str
    head: str = ""
    keys: dict = field(default_factory=dict)
    agent: dict = field(default_factory=dict)


AGENT_RUN_ENV = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "studio/game", "GITHUB_RUN_ID": "1234",
                 "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "issue_comment"}


def build_release(tmp: Path, *, agent_commit: str = "recorded", approver: str = "maintainer2",
                  release_approver: str = "approver", tier_from: Path = RELEASE_WORKFLOW,
                  agent_tokens: str = "read", authority: dict | None = None,
                  proposal_files: dict | None = None, edit_after_approval: bool = False,
                  on_branch: bool = True, sigstore_records: bool = False,
                  keep_agent_files: bool = False) -> Release:
    """A repository with one release range containing an agent-authored commit.

    agent_commit: "recorded" (a valid record), "missing" (bot commit with no record),
                  "tampered" (record whose proposal does not match its signature), or "none".
    authority: fields to override in the agent run's recorded authority.
    proposal_files: the proposal's files instead of a patch (the commit still changes code).
    edit_after_approval: the committed change differs from the approved patch.
    on_branch: False puts the release commit on a branch that is not merged into main.
    sigstore_records: the record holds stand-in Sigstore bundles for the fake gh, not DSSE envelopes.
    keep_agent_files: keep the proposal, snapshot and agent-run envelope (Release.agent).
    """
    import os
    from unittest import mock

    keys = {}
    for role in ("provenance", "agent_run", "approval"):
        keys[role] = make_key(tmp, role)

    # The repository and its previous release.
    repo = init_repo(tmp / "repo")
    (repo / "src").mkdir()
    (repo / "src" / "game.txt").write_text("game v0.9\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "Initial")
    git(repo, "tag", "v0.9.0")
    agent: dict = {}

    if agent_commit != "none":
        proposal = tmp / "proposal"
        proposal.mkdir()
        if proposal_files is None:
            (repo / "src" / "fix.txt").write_text("fix for issue 42\n", encoding="utf-8")
            git(repo, "add", "-N", "src/fix.txt")
            patch = git(repo, "diff") + "\n"
            git(repo, "reset", "-q")
            (repo / "src" / "fix.txt").unlink()
            (proposal / "patch.diff").write_text(patch, encoding="utf-8")
        else:
            for name, text in proposal_files.items():
                (proposal / name).write_text(text, encoding="utf-8")

        snap = take_snapshot(tmp / "snapshot")
        with mock.patch.dict(os.environ, AGENT_RUN_ENV):
            subjects, run_pred = records.agent_run_predicate(snap, proposal, AGENT_WORKFLOW, "agent")
        if agent_tokens == "write":
            run_pred["authority"]["tokenPermissions"] = {"declared": True, "scopes": {"contents": "write"}}
        run_pred["authority"].update(authority or {})
        run_stmt = statement(subjects, AGENT_RUN, run_pred)
        run_env = sign(run_stmt, keys["agent_run"][0])
        a_subjects, appr_pred = records.approval_predicate(proposal, approvals(approver) if approver != "maintainer"
                                                           else approvals("someone-else"), "obaaf-agent-apply",
                                                           requester="maintainer", snapshot_dir=snap) \
            if approver not in ("outsider",) else _forced_approval(proposal, snap, approver)
        if approver == "maintainer":  # simulate a forged approval by the requester
            appr_pred["approvals"][0]["reviewer"] = "maintainer"
        appr_stmt = statement(a_subjects, AGENT_APPROVAL, appr_pred)
        appr_env = sign(appr_stmt, keys["approval"][0])
        if sigstore_records:
            run_env = {"statement": run_stmt, "certificate": certificate(
                "studio/game/.github/workflows/obaaf-agent-propose.yml", "refs/heads/main")}
            appr_env = {"statement": appr_stmt, "certificate": certificate(
                "studio/game/.github/workflows/obaaf-agent-apply.yml", "refs/heads/main")}
        record = agentrecord.build(proposal, run_env, appr_env, "https://github.com/studio/game/actions/runs/1234")
        if agent_commit == "tampered":
            record["proposal"]["files"]["patch.diff"] = record["proposal"]["files"]["patch.diff"][:-8] + "AAAAAAA="
            record["bundleDigest"]["sha256"] = agentrecord.digest_of_listing(
                {"patch.diff": __import__("base64").b64decode(record["proposal"]["files"]["patch.diff"])})
        (repo / "src" / "fix.txt").write_text("fix for issue 42\n" + ("edited\n" if edit_after_approval else ""),
                                              encoding="utf-8")
        message = ["-m", "Agent proposal for #42"]
        if agent_commit in ("recorded", "tampered"):
            path = agentrecord.write(record, repo / ".obaaf" / "records")
            rel = path.relative_to(repo).as_posix()
            message += ["-m", f"OBAAF-Agent-Record: {rel}"]
        git(repo, "add", ".")
        git(repo, "commit", "-q", *message, env=BOT)
        if keep_agent_files:
            agent = {"proposal": proposal, "snapshot": snap,
                     "run_bundle": write_json(tmp / "agent-run.bundle.json", run_env)}

    # A human change in the same release (on a branch that is never merged when on_branch is False).
    if not on_branch:
        git(repo, "switch", "-q", "-c", "release-candidate")
    (repo / "src" / "game.txt").write_text("game v1.0\n", encoding="utf-8")
    git(repo, "commit", "-q", "-am", "Bump version")
    head = git(repo, "rev-parse", "HEAD")
    if not on_branch:
        git(repo, "switch", "-q", "main")

    # Release artifacts, manifest, provenance and build record.
    root = tmp / "build"
    (root / "Engine").mkdir(parents=True)
    (root / "Engine" / "engine.dll").write_bytes(b"engine")
    (root / "obaaf-sources.yaml").write_text(
        'components:\n  - {id: engine, name: Example engine, version: "5.4.1", source: Vendor, kind: engine, '
        'paths: ["Engine/**"]}\n', encoding="utf-8")
    from obaaf.attest import manifest

    manifest.write(manifest.create(root, root / "obaaf-sources.yaml"), root / "obaaf-manifest.json")
    dist = root / "dist"
    dist.mkdir()
    (dist / "Game-win64.zip").write_bytes(b"windows build " + head.encode())
    subjects, rec = records.build_record_predicate(
        [dist], source_revision=head, source_ref="refs/tags/v1.0.0", repository="studio/game", asset_revision=head,
        manifest_path=root / "obaaf-manifest.json", builder_id="https://github.com/studio/game/.github/workflows/obaaf-release.yml",
        workflow_file=tier_from, build_job="build", trigger_actor="releaser")
    slsa = records.slsa_provenance_predicate(builder_id="https://github.com/studio/game/.github/workflows/obaaf-release.yml",
                                             repository_uri="https://github.com/studio/game", source_revision=head)
    envs = [sign(statement(subjects, SLSA_PROVENANCE_V1, slsa), keys["provenance"][0]),
            sign(statement(subjects, BUILD_RECORD, rec), keys["provenance"][0])]
    attestations = write_json(tmp / "attestations.json", envs)
    release_approvals = write_json(tmp / "approvals.json", approvals(release_approver, environment="release"))

    policy = tmp / "policy.yaml"
    policy.write_text(
        "format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: keys\n"
        f"keys:\n  provenance: [{keys['provenance'][1].name}]\n  build_record: [{keys['provenance'][1].name}]\n"
        f"  agent_run: [{keys['agent_run'][1].name}]\n  approval: [{keys['approval'][1].name}]\n"
        "build_record: {allowed_tiers: [A, B]}\n"
        "release: {environments: [release], min_approvals: 1, approver_not_actor: true}\n"
        "agents: {check: true, require_exact_diff: true}\n", encoding="utf-8")
    return Release(root=root, repo=repo, dist=dist, policy=policy, attestations=attestations,
                   approvals=release_approvals, range=f"v0.9.0..{head}", head=head, keys=keys, agent=agent)


def _forced_approval(proposal: Path, snap: Path, reviewer: str):
    """An approval record naming `reviewer`, built as if the requester check were skipped."""
    subjects, predicate = records.approval_predicate(proposal, approvals("someone-else"), "obaaf-agent-apply",
                                                     requester="maintainer", snapshot_dir=snap)
    predicate["approvals"][0]["reviewer"] = reviewer
    return subjects, predicate


FAKE_GH = r'''#!{python}
"""A stand-in for `gh attestation verify` used only in tests.

With --bundle it reads a fake bundle {"statement": ..., "certificate": ...};
without, it looks the file's digest up in the JSON list named by the
OBAAF_FAKE_GH_STORE environment variable, as the real command looks it up in
the repository's attestations. It checks the subject digest, predicate type,
signer workflow and (if given) source ref, and prints what the real command
prints for verified attestations. Real signature checking is the GitHub CLI's
job and is covered by the live tests.
"""
import hashlib, json, os, sys
args = sys.argv[1:]
assert args[:2] == ["attestation", "verify"], args
path = args[2]
opts = dict(zip(args[3::2], args[4::2]))
digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
if "--bundle" in opts:
    entries = [json.load(open(opts["--bundle"]))]
else:
    entries = json.load(open(os.environ["OBAAF_FAKE_GH_STORE"]))
out = []
for entry in entries:
    stmt, cert = entry["statement"], entry["certificate"]
    if stmt["predicateType"] != opts["--predicate-type"]:
        continue
    if digest not in [s["digest"]["sha256"] for s in stmt["subject"]]:
        continue
    signer = cert.get("buildSignerURI", "")
    if not signer or not signer.split("://", 1)[1].split("/", 1)[1].startswith(opts["--signer-workflow"]):
        continue
    if "--source-ref" in opts and cert.get("sourceRepositoryRef") != opts["--source-ref"]:
        continue
    out.append({"attestation": {}, "verificationResult": {"statement": stmt, "signature": {"certificate": cert}}})
if not out:
    sys.exit("no attestations verified against the policy")
print(json.dumps(out))
'''


def fake_gh(directory: Path) -> Path:
    path = directory / "gh"
    path.write_text(FAKE_GH.replace("{python}", sys.executable), encoding="utf-8")
    path.chmod(0o755)
    return path


def certificate(workflow: str, ref: str, repo: str = "studio/game", env: str = "github-hosted") -> dict:
    return {"issuer": "https://token.actions.githubusercontent.com",
            "buildSignerURI": f"https://github.com/{workflow}@{ref}",
            "sourceRepositoryURI": f"https://github.com/{repo}", "sourceRepositoryRef": ref,
            "runnerEnvironment": env}


def gh_entry(stmt: dict, cert: dict) -> dict:
    """One entry for the stand-in gh's attestation store (or a fake bundle)."""
    return {"statement": stmt, "certificate": cert}


def load(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))
