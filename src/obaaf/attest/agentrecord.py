"""The agent record that travels with an agent-authored change (R8, G8.3).

When the effect lane applies a proposal, it commits a record file next to the
change, at `.obaaf/records/<bundle digest>.json`, and names it in a commit
trailer (`OBAAF-Agent-Record: <path>`). The record holds the proposal bundle and
the two signed attestations: the agent-run record from the agent lane and the
approval record from the effect lane. The release verifier reads it from the
commit, so the evidence is archived with the source and needs no network
lookups beyond signature verification.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from obaaf.attest.common import RecordError, canonical_json, files_under, sha256_bytes, write_json
from obaaf.attest.proposal import ALLOWED_FILES, bundle_digest

FORMAT = "obaaf-agent-record/v0.1"
TRAILER = "OBAAF-Agent-Record"


__all__ = ["FORMAT", "TRAILER", "bundle_digest", "digest_of_listing", "build", "write", "parse"]


def digest_of_listing(files: dict[str, bytes]) -> str:
    listing = sorted([name, sha256_bytes(data)] for name, data in files.items())
    return sha256_bytes(canonical_json(listing))


def build(proposal_dir: str | Path, agent_run: dict, approval: dict, agent_run_url: str = "") -> dict:
    root = Path(proposal_dir)
    files = {p.relative_to(root).as_posix(): base64.b64encode(p.read_bytes()).decode("ascii") for p in files_under(root)}
    return {
        "format": FORMAT,
        "bundleDigest": {"sha256": bundle_digest(root)},
        "proposal": {"files": files},
        "attestations": {"agentRun": agent_run, "approval": approval},
        "agentRunUrl": agent_run_url,
    }


def write(record: dict, records_dir: str | Path) -> Path:
    path = Path(records_dir) / f"{record['bundleDigest']['sha256']}.json"
    write_json(path, record)
    return path


def parse(text: str) -> tuple[dict, dict[str, bytes]]:
    """Return (record, proposal files) after checking the record's own digest."""
    try:
        record = json.loads(text)
    except ValueError as exc:
        raise RecordError(f"agent record is not JSON: {exc}") from exc
    if record.get("format") != FORMAT:
        raise RecordError(f"unexpected agent record format {record.get('format')!r}")
    files = {}
    for name, encoded in record["proposal"]["files"].items():
        if name not in ALLOWED_FILES:
            raise RecordError(f"unexpected file in agent record: {name!r}")
        files[name] = base64.b64decode(encoded)
    expected = record.get("bundleDigest", {}).get("sha256")
    if digest_of_listing(files) != expected:
        raise RecordError("the proposal files in the record do not match its bundle digest")
    return record, files
