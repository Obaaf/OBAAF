"""Shared helpers: digests, in-toto statements, schema validation, the CI environment."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from obaaf import __version__
from obaaf.catalog import data_text
from obaaf.predicates import SCHEMA_FOR_TYPE, STATEMENT_TYPE


class RecordError(ValueError):
    """A record cannot be produced or does not validate."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def files_under(path: str | Path) -> list[Path]:
    """Files under a directory (sorted, relative order stable), or the file itself."""
    path = Path(path)
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise RecordError(f"not found: {path}")
    return sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def subjects_for(paths: Iterable[str | Path], base: str | Path | None = None) -> list[dict]:
    """in-toto ResourceDescriptors (name + sha256) for files; names are relative to `base`."""
    out = []
    for path in paths:
        path = Path(path)
        name = path.relative_to(base).as_posix() if base else path.name
        out.append({"name": name, "digest": {"sha256": sha256_file(path)}})
    if not out:
        raise RecordError("no subjects: the record must cover at least one file")
    return out


def statement(subjects: list[dict], predicate_type: str, predicate: dict) -> dict:
    return {"_type": STATEMENT_TYPE, "subject": subjects, "predicateType": predicate_type, "predicate": predicate}


def validate_predicate(predicate_type: str, predicate: dict) -> list[str]:
    """Errors from validating a predicate against its JSON Schema (empty when valid)."""
    schema_path = SCHEMA_FOR_TYPE.get(predicate_type)
    if not schema_path:
        return []
    import jsonschema  # imported lazily: only the record commands need it

    schema = json.loads(data_text(schema_path))
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '(root)'}: {err.message}"
        for err in sorted(validator.iter_errors(predicate), key=lambda e: list(e.absolute_path))
    ]


def ci_run() -> dict:
    """Facts about the current CI run, from the process environment (GitHub Actions or Jenkins)."""
    env = os.environ
    if env.get("GITHUB_ACTIONS") != "true" and env.get("JENKINS_URL") and env.get("BUILD_URL"):
        return jenkins_run(env)
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    repo = env.get("GITHUB_REPOSITORY", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    out = {
        "platform": "github-actions" if env.get("GITHUB_ACTIONS") == "true" else "local",
        "repository": repo,
        "runId": run_id,
        "runAttempt": env.get("GITHUB_RUN_ATTEMPT", ""),
        "url": f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else "",
        "workflowRef": env.get("GITHUB_WORKFLOW_REF", ""),
        "workflowSha": env.get("GITHUB_WORKFLOW_SHA", ""),
        "eventName": env.get("GITHUB_EVENT_NAME", ""),
        "actor": env.get("GITHUB_ACTOR", ""),
        "triggeringActor": env.get("GITHUB_TRIGGERING_ACTOR", ""),
        "runnerEnvironment": env.get("RUNNER_ENVIRONMENT", ""),
    }
    return {k: v for k, v in out.items() if v}


def jenkins_run(env) -> dict:
    """Facts about a Jenkins build, from the variables Jenkins sets for it.

    The build's own process sets these values, so they are a locator, not proof of which
    controller, job or build produced a record: a step in the build could change them. The
    record says so in `reportedBy` (Jenkins design, section 9). The source revision and the
    signing key, not these fields, are what the release verifier relies on.
    """
    out = {
        "platform": "jenkins",
        "controller": env.get("JENKINS_URL", ""),
        "repository": env.get("GIT_URL", ""),
        "job": env.get("JOB_NAME", ""),
        "runId": env.get("BUILD_NUMBER", ""),
        "url": env.get("BUILD_URL", ""),
        "workflowRef": env.get("JOB_NAME", ""),
        "branch": env.get("BRANCH_NAME", ""),
        "tag": env.get("TAG_NAME", ""),
        "changeId": env.get("CHANGE_ID", ""),
        "node": env.get("NODE_NAME", ""),
        "actor": env.get("BUILD_USER_ID", ""),
        "reportedBy": "build process environment (self-reported)",
    }
    return {k: v for k, v in out.items() if v}


def write_json(path: str | Path, obj: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def obaaf_version() -> str:
    return __version__
