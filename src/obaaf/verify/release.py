"""Decide whether release artifacts may be uploaded (FR6, G7.2, G8.3).

Everything here fails closed: a missing field, an unreadable record or an
unavailable tool blocks the release rather than being skipped.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from obaaf.attest import agentrecord
from obaaf.attest.common import RecordError, files_under, sha256_file, validate_predicate
from obaaf.predicates import AGENT_APPROVAL, AGENT_RUN, BUILD_RECORD, SLSA_PROVENANCE_V1
from obaaf.verify import dsse
from obaaf.verify.policy import Policy


# ------------------------------------------------------------------ verified statements
@dataclass
class Verified:
    statement: dict
    signer: dict
    origin: str

    @property
    def predicate_type(self) -> str:
        return self.statement.get("predicateType", "")

    @property
    def predicate(self) -> dict:
        return self.statement.get("predicate") or {}

    def covers(self, sha256: str) -> bool:
        return any((s.get("digest") or {}).get("sha256") == sha256 for s in self.statement.get("subject", []))

    def describe(self) -> str:
        if self.signer.get("kind") == "key":
            return f"key {self.signer['keyId'][:16]}"
        cert = self.signer.get("certificate", {})
        return cert.get("buildSignerURI") or cert.get("subjectAlternativeName") or "sigstore"


def from_gh_json(data: Any, origin: str) -> list[Verified]:
    """Parse `gh attestation verify --format json` output (verified by gh)."""
    if not isinstance(data, list):
        raise RecordError(f"{origin}: expected a JSON array from gh attestation verify")
    out = []
    for entry in data:
        result = entry.get("verificationResult") or {}
        statement = result.get("statement")
        cert = (result.get("signature") or {}).get("certificate") or {}
        if isinstance(statement, dict):
            out.append(Verified(statement=statement, signer={"kind": "sigstore", "certificate": cert}, origin=origin))
    return out


class GhRunner:
    """Runs `gh attestation verify`, which checks Sigstore signatures and the signer identity."""

    def __init__(self, executable: str = "gh") -> None:
        self.executable = executable

    def available(self) -> bool:
        return shutil.which(self.executable) is not None or Path(self.executable).is_file()

    def verify(self, artifact: Path, repo: str, signer_workflow: str, predicate_type: str,
               bundle: Path | None = None, source_ref: str | None = None) -> list[Verified]:
        args = [self.executable, "attestation", "verify", str(artifact), "--repo", repo,
                "--signer-workflow", signer_workflow, "--predicate-type", predicate_type, "--format", "json"]
        if bundle:
            args += ["--bundle", str(bundle)]
        if source_ref:
            args += ["--source-ref", source_ref]
        proc = subprocess.run(args, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout).strip().splitlines()
            raise dsse.SignatureError(message[-1] if message else f"gh exited with {proc.returncode}")
        try:
            data = json.loads(proc.stdout)
        except ValueError as exc:
            raise dsse.SignatureError(f"gh printed no JSON: {exc}") from exc
        return from_gh_json(data, origin=f"gh attestation verify {artifact.name}")


def load_keys(paths: list[Path]) -> list[dsse.PublicKey]:
    return [dsse.PublicKey.load(p) for p in paths]


def from_dsse_files(paths: list[Path], keys: list[dsse.PublicKey]) -> tuple[list[Verified], list[str]]:
    verified, problems = [], []
    for path in paths:
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            documents = document if isinstance(document, list) else [document]
            for doc in documents:
                statement, key = dsse.verify_envelope(doc, keys)
                verified.append(Verified(statement=statement, signer={"kind": "key", "keyId": key.key_id,
                                                                      "source": key.source}, origin=str(path)))
        except (ValueError, dsse.SignatureError, OSError) as exc:
            problems.append(f"{path}: {exc}")
    return verified, problems


# ------------------------------------------------------------------ decision
@dataclass
class Decision:
    blocks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    agent_commits: list[dict] = field(default_factory=list)
    approvals: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.blocks

    def to_dict(self) -> dict:
        return {"format": "obaaf-release-decision/v0.1", "allowed": self.ok, "blocks": self.blocks,
                "warnings": self.warnings, "artifacts": self.artifacts, "agentCommits": self.agent_commits,
                "approvals": self.approvals}

    def to_text(self) -> str:
        lines = ["Release verification: " + ("PASSED, upload may proceed" if self.ok else "BLOCKED, do not upload")]
        for a in self.artifacts:
            lines.append(f"  artifact {a['name']} sha256:{a['sha256'][:16]}… provenance: {a['provenance']}, "
                         f"build record: {a['buildRecord']}, tier: {a.get('tier') or '?'}")
        if self.approvals:
            lines.append(f"  release approved by: {', '.join(self.approvals)}")
        for c in self.agent_commits:
            lines.append(f"  agent commit {c['commit'][:12]}: {c['status']}")
        for b in self.blocks:
            lines.append(f"BLOCK: {b}")
        for w in self.warnings:
            lines.append(f"warning: {w}")
        return "\n".join(lines) + "\n"


REQUIRED_CERT_FIELDS = ("issuer", "buildSignerURI", "sourceRepositoryURI", "sourceRepositoryRef")


def _sigstore_signer_problem(v: Verified, policy: Policy, workflow: str, refs: list[str] | None) -> str | None:
    if v.signer.get("kind") != "sigstore":
        return "not signed through Sigstore"
    cert = v.signer.get("certificate") or {}
    missing = [f for f in REQUIRED_CERT_FIELDS if not cert.get(f)]
    if policy.runner_environments and not cert.get("runnerEnvironment"):
        missing.append("runnerEnvironment")
    if missing:
        return f"the signing certificate does not state {', '.join(missing)}"
    if cert["issuer"] != policy.issuer:
        return f"issuer {cert['issuer']} is not {policy.issuer}"
    signer = cert["buildSignerURI"]
    if not re.match(rf"^https://[^/]+/{re.escape(workflow)}@", signer):
        return f"signed by {signer}, not by {workflow}"
    repo_uri = cert["sourceRepositoryURI"]
    if not re.fullmatch(rf"https://[^/]+/{re.escape(policy.repository)}", repo_uri):
        return f"built from {repo_uri}, not {policy.repository}"
    ref = cert["sourceRepositoryRef"]
    if refs is not None and not any(fnmatch.fnmatchcase(ref, r) for r in refs):
        return f"built from ref {ref}, which the policy does not allow"
    env = cert.get("runnerEnvironment", "")
    if policy.runner_environments and env not in policy.runner_environments:
        return f"signed on a {env} runner, which the policy does not allow"
    return None


def _key_signer_problem(v: Verified, policy: Policy, role: str) -> str | None:
    if v.signer.get("kind") != "key":
        return "not signed with a policy key"
    allowed = {k.key_id for k in load_keys(policy.key_paths(role))}
    if v.signer["keyId"] not in allowed:
        return f"signed with key {v.signer['keyId'][:16]}, which is not a {role} key in the policy"
    return None


def _signer_problem(v: Verified, policy: Policy, role: str, workflow: str, refs: list[str] | None) -> str | None:
    if policy.signing == "keys":
        return _key_signer_problem(v, policy, role)
    return _sigstore_signer_problem(v, policy, workflow, refs)


def _provenance_commit(predicate: dict) -> str | None:
    for dep in (predicate.get("buildDefinition") or {}).get("resolvedDependencies") or []:
        commit = (dep.get("digest") or {}).get("gitCommit")
        if commit:
            return commit
    return None


def _check_approvals(decision: Decision, policy: Policy, approvals: list[dict] | None, actors: list[str]) -> None:
    if policy.min_approvals <= 0:
        return
    names = ", ".join(f"'{e}'" for e in policy.release_environments)
    if approvals is None:
        decision.blocks.append(f"no release approvals were supplied; the policy requires {policy.min_approvals} "
                               f"in environment(s) {names} (pass --approvals)")
        return
    excluded = {a.lower() for a in actors if a} if policy.approver_not_actor else set()
    reviewers = set()
    for entry in approvals:
        envs = [e.get("name") for e in entry.get("environments", [])]
        login = (entry.get("user") or {}).get("login", "")
        if entry.get("state") != "approved" or not set(envs) & set(policy.release_environments) or not login:
            continue
        if login.lower() in excluded:
            decision.warnings.append(f"approval by {login} is not counted: {login} started or re-ran the release")
            continue
        reviewers.add(login)
    decision.approvals = sorted(reviewers)
    if len(reviewers) < policy.min_approvals:
        decision.blocks.append(
            f"the release has {len(reviewers)} qualifying approval(s) from distinct people in environment(s) {names}; "
            f"the policy requires {policy.min_approvals}. (An administrator bypass of the environment leaves no "
            "approval and is blocked here.)")


# ------------------------------------------------------------------ Jenkins run evidence
# The publishing build's JSON from the controller (BUILD_URL/api/json) records who approved its input
# steps (ApproverAction, added by the Pipeline: Input Step plugin) and why it started (CauseAction).
JENKINS_APPROVER = "org.jenkinsci.plugins.workflow.support.steps.input.ApproverAction"
JENKINS_USER_CAUSE = "hudson.model.Cause$UserIdCause"
JENKINS_UNSAFE_CAUSES = {
    "org.jenkinsci.plugins.workflow.cps.replay.ReplayCause":
        "is a Replay, which can run an edited Jenkinsfile",
    "org.jenkinsci.plugins.pipeline.modeldefinition.causes.RestartDeclarativePipelineCause":
        "was restarted from a stage, which skips the stages before it",
}


def is_jenkins_run(document) -> bool:
    return isinstance(document, dict) and isinstance(document.get("actions"), list)


def jenkins_run_facts(document: dict) -> dict:
    """Approvers, the users who started the build, and unsafe causes, from a Jenkins build's JSON."""
    approvers, starters, unsafe = [], [], []
    for action in document.get("actions") or []:
        if not isinstance(action, dict):
            continue
        if action.get("_class") == JENKINS_APPROVER and action.get("userId"):
            approvers.append(str(action["userId"]))
        for cause in action.get("causes") or []:
            if not isinstance(cause, dict):
                continue
            cls = cause.get("_class", "")
            if cls == JENKINS_USER_CAUSE and cause.get("userId"):
                starters.append(str(cause["userId"]))
            if cls in JENKINS_UNSAFE_CAUSES:
                unsafe.append(JENKINS_UNSAFE_CAUSES[cls] + (f" ({cause['shortDescription']})"
                                                            if cause.get("shortDescription") else ""))
    return {"approvers": approvers, "starters": starters, "unsafe": unsafe,
            "url": str(document.get("url") or "")}


def _check_jenkins_approvals(decision: Decision, policy: Policy, run: dict, actors: list[str],
                             release_run: dict | None) -> None:
    """Release approvals from Jenkins input steps: distinct approvers recorded on the publishing build,
    none of whom started it or the build that produced the artifacts."""
    facts = jenkins_run_facts(run)
    excluded = {a.lower() for a in actors if a}
    excluded |= {s.lower() for s in facts["starters"]}
    if release_run is not None:
        excluded |= {s.lower() for s in jenkins_run_facts(release_run)["starters"]}
    if not policy.approver_not_actor:
        excluded = set()
    reviewers = set()
    for login in facts["approvers"]:
        if login.lower() in excluded:
            decision.warnings.append(f"approval by {login} is not counted: {login} started the release or the build "
                                     "that produced it")
            continue
        reviewers.add(login)
    decision.approvals = sorted(reviewers)
    if len(reviewers) < policy.min_approvals:
        decision.blocks.append(
            f"the Jenkins build records {len(reviewers)} qualifying approval(s) from distinct people (input steps "
            f"approved by someone who did not start the release); the policy requires {policy.min_approvals}")


def _check_jenkins_causes(decision: Decision, run: dict | None, label: str) -> None:
    if run is None:
        return
    for problem in jenkins_run_facts(run)["unsafe"]:
        decision.blocks.append(f"the {label} {problem}")


# ------------------------------------------------------------------ agent runs
def agent_authority_problems(predicate: dict, policy: Policy) -> list[str]:
    """What the agent-run record says the agent job could do, against R2, R3 and R7."""
    auth = predicate.get("authority") or {}
    token = auth.get("tokenPermissions") or {}
    writes = [s for s, lvl in (token.get("scopes") or {}).items() if lvl == "write"]
    problems = []
    if not token.get("declared") or token.get("mode") == "write-all" or writes:
        problems.append("the agent run held write permissions or undeclared ones")
    if auth.get("oidc"):
        problems.append("the agent run could request OIDC tokens")
    if auth.get("secrets"):
        problems.append(f"the agent run received secrets: {', '.join(auth['secrets'])}")
    if auth.get("environment"):
        problems.append(f"the agent run used environment '{auth['environment']}', whose secrets it could receive")
    if auth.get("cacheMode") != "none":
        problems.append(f"the agent run could use caches (cache-mode: {auth.get('cacheMode') or 'not set'})")
    runner = auth.get("runner") or {}
    if runner.get("kind", "self-hosted" if runner.get("selfHosted") else "github-hosted") != "github-hosted" \
            and not policy.allow_self_hosted_agents:
        problems.append(f"the agent run used runner {', '.join(runner.get('labels') or []) or '?'}, which is not "
                        "GitHub-hosted (set agents.allow_self_hosted_runners only for ephemeral runners)")
    return problems


def requesters_of(run: dict | None, approval: dict | None) -> set[str]:
    """Everyone who asked for or wrote the agent's task: none of them may approve its effect."""
    names = list((approval or {}).get("requester", []))
    if run:
        names.append(((run.get("trigger") or {}).get("principal") or {}).get("login", ""))
        names += [item.get("author", "") for item in (run.get("inputs") or {}).get("items", [])]
    return {n.lower() for n in names if n}


@dataclass
class AgentRunResult:
    ok: bool
    problems: list[str]
    predicate: dict = field(default_factory=dict)
    snapshot: dict = field(default_factory=dict)
    bundle_digest: str = ""

    def outputs(self) -> dict:
        trigger = self.predicate.get("trigger") or {}
        return {
            "issue-number": str(trigger.get("number") or ""),
            "requester": ((trigger.get("principal") or {}).get("login") or ""),
            "requesters": ",".join(sorted(requesters_of(self.predicate, None))),
            "integrity-level": (self.predicate.get("inputs") or {}).get("integrityLevel", ""),
            "bundle-digest": self.bundle_digest,
        }


def verify_agent_run(policy: Policy, proposal_dir: Path, snapshot_dir: Path, bundle: Path, *,
                     gh: "GhRunner | None" = None, run_id: str | None = None) -> AgentRunResult:
    """Check an agent run's signed record before its proposal is acted on (R8, FR8).

    The record must be signed by the agent workflow on the protected branch, cover
    exactly the proposal's files, name the snapshot that was downloaded, come from
    the expected run, and show an agent job without write access, OIDC, secrets,
    environments or caches.
    """
    from obaaf.attest import agentrecord, snapshot as snapshot_mod

    problems: list[str] = []
    try:
        files = files_under(proposal_dir)
    except RecordError as exc:
        return AgentRunResult(False, [str(exc)])
    try:
        doc = json.loads(Path(bundle).read_text(encoding="utf-8"))
        v = _verify_attestation(doc, "agent_run", Path(proposal_dir), policy, gh, bundle_path=Path(bundle))
    except (dsse.SignatureError, RecordError, ValueError, OSError) as exc:
        return AgentRunResult(False, [f"the agent-run record does not verify: {exc}"])
    expected = {(p.relative_to(proposal_dir).as_posix(), sha256_file(p)) for p in files}
    subjects = {(s.get("name"), (s.get("digest") or {}).get("sha256")) for s in v.statement.get("subject", [])}
    if subjects != expected:
        problems.append("the agent-run record covers different files than the proposal bundle")
    errors = validate_predicate(AGENT_RUN, v.predicate)
    if errors:
        problems.append(f"the agent-run record is invalid: {errors[0]}")
    predicate = v.predicate
    recorded = ((predicate.get("inputs") or {}).get("snapshotDigest") or {}).get("sha256", "")
    record: dict = {}
    try:
        record = snapshot_mod.verify(snapshot_dir, recorded or "missing")
    except RecordError as exc:
        problems.append(f"the snapshot is not the one the agent read: {exc}")
    if record and record.get("trigger") != predicate.get("trigger"):
        problems.append("the snapshot's trigger differs from the one in the agent-run record")
    if run_id and str((predicate.get("run") or {}).get("runId", "")) != str(run_id):
        problems.append(f"the agent-run record comes from run {(predicate.get('run') or {}).get('runId') or '?'}, "
                        f"not run {run_id}")
    problems += agent_authority_problems(predicate, policy)
    return AgentRunResult(not problems, problems, predicate, record, agentrecord.bundle_digest(proposal_dir))


# ------------------------------------------------------------------ agent commits
def _git(repo_dir: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo_dir), *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RecordError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def find_agent_commits(repo_dir: Path, git_range: str, policy: Policy) -> list[dict]:
    """Commits in the range that came through the agent path, with the record each names."""
    out = []
    records_prefix = policy.records_dir.rstrip("/") + "/"
    identities = [i.lower() for i in policy.effect_identities]
    for sha in _git(repo_dir, "rev-list", "--reverse", git_range).split():
        meta = _git(repo_dir, "log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce%x00%P%x00%B", sha)
        an, ae, cn, ce, parents, body = (meta.split("\x00") + [""] * 6)[:6]
        by_effect = any(i in value.lower() for i in identities for value in (an, ae, cn, ce) if value)
        if len(parents.split()) > 1:
            # A merge brings in commits that are checked themselves. The effect lane never merges,
            # so a merge made under its identity is not trusted.
            if by_effect:
                out.append({"commit": sha, "records": [], "byEffectIdentity": True, "merge": True})
            continue
        trailers = re.findall(rf"^{agentrecord.TRAILER}:\s*(\S+)\s*$", body, re.M)
        status = _git(repo_dir, "diff-tree", "--no-commit-id", "--no-renames", "--name-status", "-r", "--root", sha)
        added_records, record_changes, changed = [], [], []
        for line in status.splitlines():
            code, _, path = line.partition("\t")
            if path.lower().startswith(records_prefix.lower()):
                record_changes.append(path)
                if code == "A" and path.endswith(".json"):
                    added_records.append(path)
            elif path:
                changed.append(path)
        if trailers or added_records or by_effect:
            out.append({"commit": sha, "records": sorted(set(trailers) | set(added_records)),
                        "addedRecords": added_records, "recordChanges": record_changes, "changedPaths": changed,
                        "byEffectIdentity": by_effect})
    return out


def _verify_attestation(doc: Any, kind: str, files_dir: Path, policy: Policy, gh: GhRunner | None,
                        bundle_path: Path | None = None) -> Verified:
    predicate_type = AGENT_RUN if kind == "agent_run" else AGENT_APPROVAL
    workflow = policy.propose_workflow if kind == "agent_run" else policy.apply_workflow
    if policy.signing == "keys":
        statement, key = dsse.verify_envelope(doc, load_keys(policy.key_paths(kind)))
        v = Verified(statement, {"kind": "key", "keyId": key.key_id, "source": key.source}, origin=kind)
    else:
        if gh is None or not gh.available():
            raise dsse.SignatureError("verifying Sigstore bundles needs the GitHub CLI (gh)")
        files = sorted(p for p in Path(files_dir).iterdir() if p.is_file())
        if not files:
            raise dsse.SignatureError("no files to verify the bundle against")
        with tempfile.TemporaryDirectory(prefix="obaaf-bundle-") as tmp:
            if bundle_path is None:
                bundle_path = Path(tmp) / f"{kind}.bundle.json"
                bundle_path.write_text(json.dumps(doc), encoding="utf-8")
            results = [r for r in gh.verify(files[0], policy.repository, workflow, predicate_type, bundle_path,
                                            source_ref=policy.agent_source_ref)
                       if r.predicate_type == predicate_type]
        if not results:
            raise dsse.SignatureError(f"no {predicate_type} statement in the bundle")
        v = results[0]
    if v.predicate_type != predicate_type:
        raise dsse.SignatureError(f"expected predicate type {predicate_type}, found {v.predicate_type}")
    problem = _signer_problem(v, policy, kind, workflow, [policy.agent_source_ref])
    if problem:
        raise dsse.SignatureError(problem)
    return v


def verify_agent_commit(entry: dict, repo_dir: Path, policy: Policy, gh: GhRunner | None,
                        seen: dict[str, str] | None = None) -> list[str]:
    """Check one agent commit: its record is added by the commit itself, used once, verifies, and
    matches the change the commit makes."""
    sha = entry["commit"]
    short = sha[:12]
    seen = {} if seen is None else seen
    if entry.get("merge"):
        return [f"commit {short} is a merge made under the effect lane's identity, which never merges"]
    if not entry["records"]:
        return [f"commit {short} came through the agent path but carries no agent record"]
    if len(entry["records"]) > 1:
        return [f"commit {short} carries {len(entry['records'])} agent records; one change needs exactly one"]
    record_path = entry["records"][0]
    problems = []
    if record_path not in entry.get("addedRecords", []):
        return [f"commit {short} names agent record {record_path}, which the commit itself does not add"]
    try:
        text = _git(repo_dir, "show", f"{sha}:{record_path}")
        record, files = agentrecord.parse(text)
    except RecordError as exc:
        return [f"commit {short}: {exc}"]
    digest = record["bundleDigest"]["sha256"]
    if Path(record_path).name != f"{digest}.json":
        return [f"commit {short}: agent record {record_path} is not named after its bundle digest"]
    if digest in seen:
        return [f"commit {short} reuses the agent record of commit {seen[digest][:12]}"]
    seen[digest] = sha
    with tempfile.TemporaryDirectory(prefix="obaaf-record-") as tmp:
        files_dir = Path(tmp) / "proposal"
        files_dir.mkdir()
        for name, data in files.items():
            (files_dir / name).write_bytes(data)
        expected = {(n, sha256_file(files_dir / n)) for n in files}
        verified = {}
        for kind, key in (("agent_run", "agentRun"), ("approval", "approval")):
            doc = (record.get("attestations") or {}).get(key)
            if not doc:
                problems.append(f"commit {short}: record has no {key} attestation")
                continue
            try:
                v = _verify_attestation(doc, kind, files_dir, policy, gh)
            except (dsse.SignatureError, RecordError, ValueError) as exc:
                problems.append(f"commit {short}: {key} attestation does not verify: {exc}")
                continue
            subjects = {(s.get("name"), (s.get("digest") or {}).get("sha256")) for s in v.statement.get("subject", [])}
            if subjects != expected:
                problems.append(f"commit {short}: {key} attestation covers different files than the record")
                continue
            errors = validate_predicate(v.predicate_type, v.predicate)
            if errors:
                problems.append(f"commit {short}: {key} predicate is invalid: {errors[0]}")
                continue
            verified[kind] = v
    run, approval = verified.get("agent_run"), verified.get("approval")
    if run:
        problems += [f"commit {short}: {p}" for p in agent_authority_problems(run.predicate, policy)]
    if approval:
        requesters = requesters_of(run.predicate if run else None, approval.predicate)
        reviewers = [a.get("reviewer", "") for a in approval.predicate.get("approvals", [])]
        if not [r for r in reviewers if r and r.lower() not in requesters]:
            problems.append(f"commit {short}: no approval by someone other than the requester or an author of "
                            "the agent's inputs")
    other_records = [p for p in entry.get("recordChanges", []) if p != record_path]
    if other_records:
        problems.append(f"commit {short} also changes {', '.join(other_records[:3])} under {policy.records_dir}; "
                        "an agent commit may add only its own record")
    if run and approval:
        if "patch.diff" in files:
            mismatch = _patch_mismatch(repo_dir, sha, files["patch.diff"], policy.records_dir)
            if mismatch:
                message = f"commit {short}: the committed change differs from the approved proposal ({mismatch})"
                (problems if policy.require_exact_diff else entry.setdefault("warnings", [])).append(message)
        elif entry.get("changedPaths"):
            problems.append(f"commit {short} changes {len(entry['changedPaths'])} file(s), but its agent record "
                            "has no patch")
    return problems


def _patch_mismatch(repo_dir: Path, sha: str, patch: bytes, records_dir: str) -> str | None:
    """Apply the approved patch to the commit's parent in a temporary index and compare the result
    with the commit, outside the records directory. Returns why they differ, or None."""
    import os

    if not _has_parent(repo_dir, sha):
        return "the commit has no parent to apply the patch to"
    with tempfile.TemporaryDirectory(prefix="obaaf-reapply-") as tmp:
        patch_file = Path(tmp) / "patch.diff"
        patch_file.write_bytes(patch)
        env = {k: v for k, v in os.environ.items() if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")}
        env["GIT_INDEX_FILE"] = str(Path(tmp) / "index")

        def run(*args: str) -> subprocess.CompletedProcess:
            return subprocess.run(["git", "-C", str(repo_dir), *args], capture_output=True, text=True, env=env,
                                  check=False)

        if run("read-tree", f"{sha}^").returncode != 0:
            return "cannot read the parent commit"
        if run("apply", "--cached", "-p1", "--whitespace=nowarn", str(patch_file)).returncode != 0:
            return "the approved patch does not apply to the commit's parent"
        tree = run("write-tree")
        if tree.returncode != 0:
            return "cannot build the expected tree"
        diff = run("diff-tree", "-r", "--no-renames", "--name-only", tree.stdout.strip(), f"{sha}^{{tree}}", "--",
                   ".", f":(exclude){records_dir}")
        if diff.returncode != 0:
            return "cannot compare the expected tree with the commit"
        paths = [p for p in diff.stdout.splitlines() if p]
        return f"differs in {', '.join(paths[:3])}" if paths else None


def _has_parent(repo_dir: Path, sha: str) -> bool:
    return len(_git(repo_dir, "log", "-1", "--format=%P", sha).split()) > 0


def _is_shallow(repo_dir: Path) -> bool:
    proc = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "--is-shallow-repository"], capture_output=True,
                          text=True, check=False)
    return proc.stdout.strip() == "true"


def _is_ancestor(repo_dir: Path, commit: str, branch: str) -> bool | None:
    """Whether `commit` is on `branch` (tried as origin/<branch>, then <branch>); None if neither exists."""
    for ref in (f"refs/remotes/origin/{branch}", f"refs/heads/{branch}"):
        exists = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "--verify", "--quiet", ref],
                                capture_output=True, check=False)
        if exists.returncode == 0:
            proc = subprocess.run(["git", "-C", str(repo_dir), "merge-base", "--is-ancestor", commit, ref],
                                  capture_output=True, check=False)
            return proc.returncode == 0
    return None


# ------------------------------------------------------------------ main entry point
def verify_release(policy: Policy, artifacts: list[Path], *, gh: GhRunner | None = None,
                   dsse_files: list[Path] | None = None, approvals: list[dict] | dict | None = None,
                   actors: list[str] | None = None, repo_dir: Path | None = None, git_range: str | None = None,
                   source_revision: str | None = None, pre_approval: bool = False,
                   release_run: dict | None = None) -> Decision:
    """Verify everything before an upload. With pre_approval, skip the approvals (shown to the approver).

    `approvals` is GitHub's run approvals list, or a Jenkins build's JSON; `release_run` is the
    JSON of the Jenkins build that produced the artifacts."""
    decision = Decision()
    if release_run is not None and not is_jenkins_run(release_run):
        decision.blocks.append("--release-run is not a Jenkins build's JSON (expected an 'actions' list)")
        release_run = None
    _check_jenkins_causes(decision, release_run, "build that produced the artifacts")
    if is_jenkins_run(approvals):
        _check_jenkins_causes(decision, approvals, "publishing build")
    files: list[Path] = []
    for artifact in artifacts:
        try:
            files += files_under(artifact)
        except RecordError as exc:
            decision.blocks.append(str(exc))
    if not files:
        decision.blocks.append("no release artifacts to verify")

    # Gather verified statements.
    verified: list[Verified] = []
    if policy.signing == "keys":
        keys = load_keys(policy.key_paths("provenance") + policy.key_paths("build_record"))
        found, problems = from_dsse_files(list(dsse_files or []), keys)
        verified += found
        decision.warnings += [f"signature check failed (ignored unless nothing else verifies): {p}" for p in problems]
    elif gh is None or not gh.available():
        decision.blocks.append("cannot verify Sigstore attestations: the GitHub CLI (gh) is not available")
    else:
        for f in files:
            for ptype in (SLSA_PROVENANCE_V1, BUILD_RECORD):
                try:
                    verified += gh.verify(f, policy.repository, policy.provenance_workflow, ptype)
                except dsse.SignatureError as exc:
                    decision.blocks.append(f"{f.name}: no verified {ptype} attestation ({exc})")

    trigger_actors = [a for a in (actors or []) if a]
    for f in files:
        digest = sha256_file(f)
        entry = {"name": f.name, "sha256": digest, "provenance": "missing", "buildRecord": "missing"}
        prov = [v for v in verified if v.predicate_type == SLSA_PROVENANCE_V1 and v.covers(digest)]
        recs = [v for v in verified if v.predicate_type == BUILD_RECORD and v.covers(digest)]
        good_prov, rejected = [], []
        for v in prov:
            problem = _signer_problem(v, policy, "provenance", policy.provenance_workflow, policy.source_refs)
            (rejected.append(f"{f.name}: provenance rejected: {problem}") if problem else good_prov.append(v))
        good_rec = []
        for v in recs:
            problem = _signer_problem(v, policy, "build_record", policy.provenance_workflow, policy.source_refs)
            errors = validate_predicate(BUILD_RECORD, v.predicate)
            if problem:
                rejected.append(f"{f.name}: build record rejected: {problem}")
            elif errors:
                rejected.append(f"{f.name}: build record is invalid: {errors[0]}")
            else:
                good_rec.append(v)
        # An attestation that fails policy is ignored when a valid one exists, so that anyone able to
        # add attestations cannot block a release with a bad one.
        if good_prov and good_rec:
            decision.warnings += rejected
        else:
            decision.blocks += rejected
        if good_prov:
            entry["provenance"] = "verified"
        elif not prov:
            decision.blocks.append(f"{f.name}: no verified SLSA provenance")
        if not recs:
            decision.blocks.append(f"{f.name}: no verified OBAAF build record")
        if good_rec:
            entry["buildRecord"] = "verified"
            revisions = {v.predicate["source"]["revision"] for v in good_rec}
            if len(revisions) > 1:
                decision.blocks.append(f"{f.name}: build records name different source revisions")
            pred = good_rec[0].predicate
            tier = pred["isolation"]["tier"]
            entry["tier"] = tier
            if tier not in policy.allowed_tiers:
                decision.blocks.append(f"{f.name}: built at isolation Tier {tier}, which the policy does not allow")
            if tier == "B":
                decision.warnings.append(f"{f.name}: Tier B build (persistent host): below SLSA Build Level 3")
            if policy.require_sdks and not pred.get("sdks"):
                decision.blocks.append(f"{f.name}: the build record lists no SDK versions")
            revision = pred["source"]["revision"]
            if source_revision and revision != source_revision:
                decision.blocks.append(f"{f.name}: built from {revision}, not the release commit {source_revision}")
            for v in good_prov:
                commit = _provenance_commit(v.predicate)
                if commit and commit != revision:
                    decision.blocks.append(f"{f.name}: provenance names commit {commit} but the build record names "
                                           f"{revision}")
            cert_env = next((v.signer.get("certificate", {}).get("runnerEnvironment") for v in good_rec
                             if v.signer.get("kind") == "sigstore"), None)
            if cert_env:
                entry["attestedOn"] = cert_env
            recorded_actor = (pred.get("trigger") or {}).get("actor", "")
            if recorded_actor and recorded_actor not in trigger_actors:
                trigger_actors.append(recorded_actor)
        decision.artifacts.append(entry)

    if release_run is not None:
        trigger_actors += [a for a in jenkins_run_facts(release_run)["starters"] if a not in trigger_actors]
    if pre_approval:
        decision.warnings.append("approvals were not checked (pre-approval run); the upload job checks them")
    elif is_jenkins_run(approvals):
        if policy.min_approvals > 0:
            _check_jenkins_approvals(decision, policy, approvals, trigger_actors, release_run)
    else:
        _check_approvals(decision, policy, approvals, trigger_actors)

    if repo_dir is not None and _is_shallow(repo_dir):
        decision.blocks.append(f"{repo_dir} is a shallow clone, so commits outside its history cannot be checked; "
                               "fetch the full history (fetch-depth: 0)")

    if policy.release_branch:
        if repo_dir is None or not source_revision:
            decision.blocks.append(f"cannot check that the release commit is on the protected branch "
                                   f"'{policy.release_branch}': pass --repo-dir and --source-revision")
        else:
            on_branch = _is_ancestor(repo_dir, source_revision, policy.release_branch)
            if on_branch is None:
                decision.blocks.append(f"cannot find branch '{policy.release_branch}' in {repo_dir} to check that "
                                       "the release commit is on it")
            elif not on_branch:
                decision.blocks.append(f"the release commit {source_revision[:12]} is not on the protected branch "
                                       f"'{policy.release_branch}'")

    if policy.agents_check:
        if git_range is not None and policy.agents_since:
            decision.blocks.append("the policy sets agents.since, so the range of agent commits comes from the "
                                   "policy; do not pass --range")
            git_range = None
        if git_range is None and source_revision:
            git_range = f"{policy.agents_since}..{source_revision}" if policy.agents_since else source_revision
        if repo_dir is None or not git_range:
            decision.blocks.append("agent records were not checked: pass --repo-dir and --source-revision (or "
                                   "--range), or set agents.check: false in the policy if no agent can change "
                                   "this repository")
        else:
            try:
                commits = find_agent_commits(repo_dir, git_range, policy)
            except RecordError as exc:
                decision.blocks.append(str(exc))
                commits = []
            seen: dict[str, str] = {}
            for entry in commits:
                problems = verify_agent_commit(entry, repo_dir, policy, gh, seen)
                entry["status"] = "verified" if not problems else "blocked"
                decision.blocks += problems
                decision.warnings += entry.pop("warnings", [])
                for key in ("addedRecords", "recordChanges", "changedPaths"):
                    entry.pop(key, None)
                decision.agent_commits.append(entry)
    return decision
