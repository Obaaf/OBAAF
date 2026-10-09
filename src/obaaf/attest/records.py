"""Predicates for the agent-run record, the approval record and the build record.

Field sources follow Paper 1, Table 3: everything except the trace comes from
jobs the agent cannot influence (the snapshot job, the protected workflow
definition, the inference proxy, the effect lane). The trace is the agent's own
account and is marked untrusted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from obaaf.attest import manifest as manifest_mod
from obaaf.attest import snapshot as snapshot_mod
from obaaf.attest.common import RecordError, ci_run, files_under, now, obaaf_version, sha256_file, subjects_for
from obaaf.checker import workflow as wf_mod

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


# --------------------------------------------------------------------- agent run
def authority_from_workflow(workflow_file: str | Path, job_id: str) -> tuple[dict, list[dict]]:
    """The agent job's authority and the actions it runs, read from the protected workflow file."""
    path = Path(workflow_file)
    workflow = wf_mod.parse(path.as_posix(), path.read_text(encoding="utf-8"))
    if workflow.error:
        raise RecordError(f"{path}: {workflow.error}")
    job = workflow.jobs.get(job_id)
    if job is None:
        raise RecordError(f"{path}: no job named {job_id!r}")
    perms = job.permissions
    if perms is None:
        token = {"declared": False}
    elif perms.mode in ("read-all", "write-all"):
        token = {"declared": True, "mode": perms.mode}
    else:
        token = {"declared": True, "scopes": dict(sorted(perms.scopes.items()))}
    egress = job.env.get("OBAAF_EGRESS") or workflow.env.get("OBAAF_EGRESS")
    monitors = [s.uses for s in job.steps if s.uses_action("step-security/harden-runner")]
    authority = {
        "job": job_id,
        "tokenPermissions": token,
        "secrets": sorted(job.secret_names()),
        "environment": job.environment or None,
        "oidc": bool(perms and perms.oidc),
        "cacheMode": job.cache_mode or "default",
        "network": {"declaredPolicy": str(egress) if egress else None, "monitors": monitors},
        "runner": {"labels": job.runs_on, "selfHosted": job.self_hosted, "kind": job.runner_kind},
        "source": "protected workflow definition",
    }
    actions = []
    for step in job.steps:
        if step.uses and not step.uses.startswith("./"):
            name, _, ref = step.uses.partition("@")
            entry = {"uses": step.uses}
            if SHA_RE.match(ref):
                entry["digest"] = {"gitCommit": ref}
            actions.append(entry)
    return authority, actions


def agent_run_predicate(snapshot_dir: str | Path, proposal_dir: str | Path, workflow_file: str | Path,
                        job_id: str, snapshot_digest: str | None = None, model_receipt: str | Path | None = None,
                        trace: str | Path | None = None, harness: list[str] | None = None) -> tuple[list[dict], dict]:
    """(subjects, predicate) for the agent-run attestation."""
    record = snapshot_mod.verify(snapshot_dir, snapshot_digest)
    proposal_files = files_under(proposal_dir)
    subjects = subjects_for(proposal_files, base=proposal_dir)
    authority, actions = authority_from_workflow(workflow_file, job_id)

    model: dict = {"reportedBy": "none", "id": None, "version": None}
    if model_receipt:
        receipt = json.loads(Path(model_receipt).read_text(encoding="utf-8"))
        model = {"reportedBy": "inference-proxy", "id": receipt.get("model"), "version": receipt.get("version"),
                 "requests": receipt.get("requests"), "receiptDigest": {"sha256": sha256_file(model_receipt)}}

    trace_entry = None
    if trace and Path(trace).is_file():
        trace_entry = {"digest": {"sha256": sha256_file(trace)}, "trusted": False, "reportedBy": "agent harness"}

    predicate = {
        "obaafVersion": obaaf_version(),
        "trigger": record["trigger"],
        "inputs": {
            "snapshotDigest": {"sha256": snapshot_mod.digest(snapshot_dir)},
            "items": [{k: i[k] for k in ("name", "channel", "digest", "label", "author", "labelSource")}
                      for i in record["inputs"]],
            "floor": record["floor"],
            "integrityLevel": record["integrityLevel"],
            "takenAt": record["takenAt"],
        },
        "authority": authority,
        "agent": {"actions": actions, "harness": harness or [], "model": model},
        "trace": trace_entry,
        "run": ci_run(),
        "approvals": {"recordedIn": "agent-approval attestation", "producedBy": "effect lane"},
        "recordedAt": now(),
    }
    return subjects, predicate


# ---------------------------------------------------------------------- approval
def approval_predicate(proposal_dir: str | Path, approvals: list[dict], environment: str,
                       requester: str | list[str] | None, snapshot_dir: str | Path | None = None,
                       agent_run_url: str = "", checks: dict | None = None) -> tuple[list[dict], dict]:
    """(subjects, predicate) for the approval attestation; raises if no valid approval exists.

    `approvals` is the response of GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals
    for the effect lane's own run. That endpoint does not return when each review happened,
    so the time recorded is when the effect job read it (after the approval).

    Requesters, whose approvals do not count, are the people named in `requester` plus,
    from the snapshot, the principal who triggered the agent and every author of its inputs:
    someone who wrote the agent's task cannot approve what the agent did with it.
    """
    subjects = subjects_for(files_under(proposal_dir), base=proposal_dir)
    named = [requester] if isinstance(requester, str) else list(requester or [])
    requesters = {r.lower() for r in named if r}
    if snapshot_dir:
        record = snapshot_mod.verify(snapshot_dir)
        principal = record["trigger"]["principal"]["login"]
        requesters |= {login.lower() for login in [principal] + [i.get("author", "") for i in record["inputs"]]
                       if login}
    accepted, rejected = [], []
    for entry in approvals:
        envs = [e.get("name") for e in entry.get("environments", [])]
        login = (entry.get("user") or {}).get("login", "")
        if entry.get("state") != "approved" or environment not in envs:
            continue
        if login.lower() in requesters:
            rejected.append(login)
            continue
        accepted.append({
            "reviewer": login,
            "reviewerId": (entry.get("user") or {}).get("id"),
            "state": "approved",
            "environment": environment,
            "comment": entry.get("comment") or "",
            "recordedAt": now(),
            "timeSource": "effect job clock (the approvals API returns no review time)",
        })
    if not accepted:
        why = f"; approvals by the requester ({', '.join(rejected)}) do not count" if rejected else ""
        raise RecordError(f"no approval in environment '{environment}' by someone other than the requester{why}")
    predicate = {
        "obaafVersion": obaaf_version(),
        "approvals": accepted,
        "requester": sorted(requesters),
        "agentRun": {"url": agent_run_url} if agent_run_url else {},
        "checks": checks or {},
        "run": ci_run(),
        "recordedAt": now(),
    }
    return subjects, predicate


# ------------------------------------------------------------------ build record
HOSTED_LABEL_RE = re.compile(r"^(ubuntu|windows|macos)-[A-Za-z0-9.-]+$")


def isolation_from_workflow(workflow_file: str | Path, job_id: str, declared_tier: str | None = None) -> dict:
    """The build job's isolation tier, from the protected workflow definition (FR4).

    GitHub-hosted runners start every job on a new machine, so their builds are Tier A.
    For self-hosted runners the workflow must declare the tier in OBAAF_TIER: A for
    ephemeral runners, B for persistent hosts dedicated to the release lane.
    """
    path = Path(workflow_file)
    workflow = wf_mod.parse(path.as_posix(), path.read_text(encoding="utf-8"))
    if workflow.error:
        raise RecordError(f"{path}: {workflow.error}")
    job = workflow.jobs.get(job_id)
    if job is None:
        raise RecordError(f"{path}: no job named {job_id!r}")
    env_tier = str(job.env.get("OBAAF_TIER") or workflow.env.get("OBAAF_TIER") or "") or None
    if env_tier and "${{" in env_tier:
        raise RecordError("OBAAF_TIER must be a literal A or B in the workflow file, not an expression")
    if job.self_hosted:
        runner_env = "self-hosted"
        tier = env_tier
        if tier not in ("A", "B"):
            raise RecordError(f"job {job_id!r} runs on a self-hosted runner; set OBAAF_TIER to A (ephemeral) or B "
                              "(persistent, release-only, reimaged on a schedule) in its env")
    elif job.runs_on and all(HOSTED_LABEL_RE.match(label) for label in job.runs_on):
        runner_env, tier = "github-hosted", "A"
        if env_tier and env_tier != "A":
            raise RecordError(f"job {job_id!r} runs on GitHub-hosted runners, which are Tier A, but OBAAF_TIER says {env_tier}")
    else:
        runner_env = "unknown"
        tier = env_tier
        if tier not in ("A", "B"):
            raise RecordError(f"cannot tell whether job {job_id!r} runs on GitHub-hosted or self-hosted runners "
                              f"({job.runs_on}); set OBAAF_TIER to A or B in its env")
    if declared_tier and declared_tier != tier:
        raise RecordError(f"--tier {declared_tier} contradicts the workflow definition (Tier {tier})")
    return {
        "tier": tier,
        "slsaBuildLevel3": tier == "A",
        "runnerEnvironment": runner_env,
        "runnerLabels": job.runs_on,
        "buildJob": job_id,
        "reportedBy": "protected workflow definition",
    }


def build_record_predicate(artifacts: list[str | Path], *, source_revision: str, source_ref: str = "",
                           repository: str = "", asset_revision: str, asset_system: str = "git",
                           manifest_path: str | Path, builder_id: str, workflow_file: str | Path | None = None,
                           build_job: str = "build", tier: str | None = None,
                           extra_sdks: list[tuple[str, str]] | None = None,
                           trigger_actor: str = "") -> tuple[list[dict], dict]:
    """(subjects, predicate) for the OBAAF build record (FR4, FR5, G7.1).

    Release approvals are not part of the build record: they are given later, when the
    publish job's environment is approved, and the release verifier checks them there.
    """
    if workflow_file:
        isolation = isolation_from_workflow(workflow_file, build_job, tier)
    elif tier in ("A", "B"):
        isolation = {"tier": tier, "slsaBuildLevel3": tier == "A", "runnerEnvironment": "unknown",
                     "reportedBy": "command line"}
    else:
        raise RecordError("give --workflow-file (preferred) or --tier A|B")
    files = []
    for artifact in artifacts:
        files += files_under(artifact)
    subjects = subjects_for(files)
    names = [s["name"] for s in subjects]
    if len(set(names)) != len(names):
        raise RecordError("two artifacts share a file name; give every release artifact a unique name")
    manifest = manifest_mod.load(manifest_path)
    sdks = manifest_mod.sdk_versions(manifest)
    for name, version in extra_sdks or []:
        sdks.append({"name": name, "version": version, "reportedBy": "build job"})
    run = ci_run()
    predicate = {
        "obaafVersion": obaaf_version(),
        "source": {"repository": repository or run.get("repository", ""), "revision": source_revision,
                   "ref": source_ref, "reportedBy": "platform"},
        "assets": {"revision": asset_revision, "system": asset_system,
                   "reportedBy": "platform" if asset_system == "git" and asset_revision == source_revision else "build job"},
        "manifest": {"digest": {"sha256": sha256_file(manifest_path)}, "entries": len(manifest["entries"]),
                     "components": len(manifest["components"]), "reportedBy": "attestation job"},
        "sdks": sdks,
        "isolation": isolation,
        "builder": {"id": builder_id, "workflow": run.get("workflowRef", "") or str(workflow_file or "")},
        "trigger": {"actor": trigger_actor or run.get("triggeringActor") or run.get("actor", "")},
        "run": run,
        "recordedAt": now(),
    }
    return subjects, predicate


# ------------------------------------------------------------- SLSA provenance
GENERIC_BUILD_TYPE = "https://obaaf.example/buildtypes/generic/v0.1"


def slsa_provenance_predicate(*, builder_id: str, repository_uri: str, source_revision: str, source_ref: str = "",
                              invocation_id: str = "", started_on: str = "",
                              parameters: dict | None = None) -> dict:
    """A SLSA v1 provenance predicate for CI systems that do not generate one themselves.

    On GitHub Actions, use actions/attest-build-provenance instead: its provenance is
    generated by the platform. This generic form lets a studio on another CI system sign
    provenance with a key held in a key service (DSSE key mode).
    """
    return {
        "buildDefinition": {
            "buildType": GENERIC_BUILD_TYPE,
            "externalParameters": dict(parameters or {}, source={"uri": repository_uri, "ref": source_ref}),
            "internalParameters": {},
            "resolvedDependencies": [
                {"uri": f"git+{repository_uri}" + (f"@{source_ref}" if source_ref else ""),
                 "digest": {"gitCommit": source_revision}}
            ],
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": {k: v for k, v in (("invocationId", invocation_id), ("startedOn", started_on or now())) if v},
        },
    }
