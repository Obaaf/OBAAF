"""The snapshot step of the agent lane (R1, FR7).

It runs before the agent, in a separate job. It captures the text of the
triggering event and any files the task needs, records each item's digest,
channel and trust label, and computes the run's integrity level: the lowest
label among everything the agent can read (Paper 1, section 5.1). The agent
then reads only from the snapshot.

Labels use the trust chain Public ⊑ Contributor ⊑ Maintainer ⊑ Release.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from obaaf.attest.common import RecordError, canonical_json, now, sha256_bytes, sha256_file, write_json

FORMAT = "obaaf-snapshot/v0.1"
LEVELS = ["Public", "Contributor", "Maintainer", "Release"]

# Repository roles (GitHub's role_name) to trust levels. `write` maps to Contributor:
# that is correct only when repository secrets live in protected environments,
# as the templates arrange (docs/guides/F8-agents.md, DECISIONS.md D-008).
ROLE_LEVELS = {"admin": "Maintainer", "maintain": "Maintainer", "write": "Contributor", "triage": "Contributor",
               "read": "Public", "none": "Public"}
# Fallback when no permission lookup is available: GitHub's author_association. MEMBER (any member
# of the owning organization) and COLLABORATOR (any access, even read-only) say nothing about write
# access to this repository, so without a lookup they count as Public.
ASSOCIATION_LEVELS = {"OWNER": "Maintainer"}

# (channel, path in the event payload, author login path, association path)
_PR = [
    ("pull_request.title", "pull_request.title", "pull_request.user.login", "pull_request.author_association"),
    ("pull_request.body", "pull_request.body", "pull_request.user.login", "pull_request.author_association"),
    ("pull_request.head.ref", "pull_request.head.ref", "pull_request.user.login", "pull_request.author_association"),
]
_ISSUE = [
    ("issue.title", "issue.title", "issue.user.login", "issue.author_association"),
    ("issue.body", "issue.body", "issue.user.login", "issue.author_association"),
]
_DISCUSSION = [
    ("discussion.title", "discussion.title", "discussion.user.login", "discussion.author_association"),
    ("discussion.body", "discussion.body", "discussion.user.login", "discussion.author_association"),
]
_COMMENT = [("comment.body", "comment.body", "comment.user.login", "comment.author_association")]
CHANNELS = {
    "issues": _ISSUE,
    "issue_comment": _COMMENT + _ISSUE,
    "pull_request": _PR,
    "pull_request_target": _PR,
    "pull_request_review": [("review.body", "review.body", "review.user.login", "review.author_association")] + _PR,
    "pull_request_review_comment": _COMMENT + _PR,
    "discussion": _DISCUSSION,
    "discussion_comment": _COMMENT + _DISCUSSION,
}


def _get(obj: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def meet(levels: list[str]) -> str:
    """The lowest (least trusted) level."""
    return min(levels, key=LEVELS.index)


@dataclass
class Principal:
    login: str
    level: str
    source: str


class Labeler:
    """Assigns trust levels to principals: permission lookups first, then author_association."""

    def __init__(self, roles: dict[str, str] | None = None) -> None:
        self.roles = {k.lower(): v for k, v in (roles or {}).items()}

    def principal(self, login: str | None, association: str | None) -> Principal:
        if not login:
            return Principal(login="", level="Public", source="unknown author")
        role = self.roles.get(login.lower())
        if role is not None:
            return Principal(login=login, level=ROLE_LEVELS.get(role, "Public"), source=f"repository role '{role}'")
        if association:
            return Principal(login=login, level=ASSOCIATION_LEVELS.get(association, "Public"),
                             source=f"author_association {association}")
        return Principal(login=login, level="Public", source="no role found")


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "item"


def take(event_path: str | Path, event_name: str, out_dir: str | Path, *, repository: str = "",
         visibility: str = "public", roles: dict[str, str] | None = None, floor: str | None = None,
         extra_files: list[tuple[str, str, str]] | None = None) -> dict:
    """Write the snapshot to `out_dir` and return the snapshot record.

    extra_files: (path, channel, label) for files the task needs, such as a pull
    request diff (labeled with the author's level) or repository files from the
    protected base branch (labeled Maintainer).
    """
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    out = Path(out_dir)
    inputs_dir = out / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    labeler = Labeler(roles)
    items = []

    fork = bool(_get(event, "pull_request.head.repo.fork")) or (
        _get(event, "pull_request.head.repo.full_name") not in (None, _get(event, "pull_request.base.repo.full_name"))
    )
    for index, (channel, value_path, login_path, assoc_path) in enumerate(CHANNELS.get(event_name, []), start=1):
        value = _get(event, value_path)
        if value is None:
            continue
        who = labeler.principal(_get(event, login_path), _get(event, assoc_path))
        level, source = who.level, who.source
        if channel == "pull_request.head.ref" and fork:
            level, source = "Public", "branch in a fork"
        data = str(value).encode("utf-8")
        rel = f"inputs/{index:02d}-{_slug(channel)}.txt"
        (out / rel).write_bytes(data)
        items.append({
            "name": channel, "channel": f"{event_name}.{channel}", "path": rel,
            "digest": {"sha256": sha256_bytes(data)}, "author": who.login, "label": level, "labelSource": source,
        })

    if event_name == "workflow_dispatch":
        sender = labeler.principal(_get(event, "sender.login"), None)
        for index, (key, value) in enumerate(sorted((event.get("inputs") or {}).items()), start=len(items) + 1):
            data = str(value).encode("utf-8")
            rel = f"inputs/{index:02d}-input-{_slug(key)}.txt"
            (out / rel).write_bytes(data)
            items.append({"name": f"inputs.{key}", "channel": "workflow_dispatch.inputs", "path": rel,
                          "digest": {"sha256": sha256_bytes(data)}, "author": sender.login,
                          "label": sender.level, "labelSource": sender.source})

    for index, (path, channel, label) in enumerate(extra_files or [], start=len(items) + 1):
        if label not in LEVELS:
            raise RecordError(f"unknown label {label!r} for {path}")
        src = Path(path)
        rel = f"inputs/{index:02d}-{_slug(src.name)}"
        (out / rel).write_bytes(src.read_bytes())
        items.append({"name": src.name, "channel": channel, "path": rel, "digest": {"sha256": sha256_file(out / rel)},
                      "author": "", "label": label, "labelSource": "declared by the workflow"})

    if floor not in (None, *LEVELS):
        raise RecordError(f"unknown floor {floor!r}")
    if floor is None:
        floor = "Public"
        floor_reason = (
            "public repository: the agent's token can read content that anyone can write"
            if visibility == "public" else
            f"{visibility} repository, default floor: the agent's token can read issues and comments whose "
            "authors were not looked up; raise it with --floor only after checking who can write them"
        )
    else:
        floor_reason = f"set by the workflow (--floor {floor}) for a {visibility} repository"

    sender = labeler.principal(_get(event, "sender.login"), None)
    trigger = {
        "event": event_name,
        "action": event.get("action", ""),
        "number": _get(event, "issue.number") or _get(event, "pull_request.number") or _get(event, "discussion.number"),
        "id": str(_get(event, "comment.id") or _get(event, "review.id") or _get(event, "issue.number")
                  or _get(event, "pull_request.number") or _get(event, "discussion.number") or ""),
        "url": str(_get(event, "comment.html_url") or _get(event, "review.html_url") or _get(event, "issue.html_url")
                   or _get(event, "pull_request.html_url") or _get(event, "discussion.html_url") or ""),
        "repository": repository or str(_get(event, "repository.full_name") or ""),
        "repositoryVisibility": visibility,
        "principal": {"login": sender.login, "level": sender.level, "labelSource": sender.source},
    }
    levels = [i["label"] for i in items] + [floor, sender.level]
    record = {
        "format": FORMAT,
        "takenAt": now(),
        "trigger": trigger,
        "inputs": items,
        "floor": {"label": floor, "reason": floor_reason},
        "integrityLevel": meet(levels),
    }
    write_json(out / "snapshot.json", record)
    return record


def digest(snapshot_dir: str | Path) -> str:
    """sha256 of snapshot.json as written (the value the agent lane passes between jobs)."""
    return sha256_file(Path(snapshot_dir) / "snapshot.json")


def verify(snapshot_dir: str | Path, expected_digest: str | None = None) -> dict:
    """Check snapshot.json against an expected digest, and every input file against its recorded digest."""
    snap_dir = Path(snapshot_dir)
    record_path = snap_dir / "snapshot.json"
    if not record_path.is_file():
        raise RecordError(f"no snapshot.json in {snap_dir}")
    if expected_digest:
        actual = sha256_file(record_path)
        if actual != expected_digest.removeprefix("sha256:"):
            raise RecordError(f"snapshot.json digest {actual} does not match the recorded {expected_digest}")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if record.get("format") != FORMAT:
        raise RecordError(f"unexpected snapshot format {record.get('format')!r}")
    for item in record["inputs"]:
        path = snap_dir / item["path"]
        if not path.is_file() or sha256_file(path) != item["digest"]["sha256"]:
            raise RecordError(f"snapshot input {item['path']} is missing or changed")
    if record["integrityLevel"] != meet([i["label"] for i in record["inputs"]] +
                                        [record["floor"]["label"], record["trigger"]["principal"]["level"]]):
        raise RecordError("integrity level does not match the labels")
    return record


def record_digest(record: dict) -> str:
    return sha256_bytes(canonical_json(record))
