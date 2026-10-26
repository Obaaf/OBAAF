"""The binary manifest (G2.1, item 2.6).

A manifest records every vendored binary, SDK, engine build and plugin with its
source, version and digest. `check` fails on any unrecorded change: a new file,
a changed file or a missing file under a tracked path. Symbolic links are
recorded with their targets, so replacing a file with a link, or retargeting a
link, is a change too.

Projects that vendor no binaries declare that in the sources file instead of
listing components:

    vendored_binaries: none

That claim is written into the manifest as `vendoredBinaries: "none"` with empty
`components` and `entries`, so the build-record digest binds it. `check` does
not scan the tree for undeclared binaries; switching from none to real
components is a reviewed change to the sources file and a regenerated manifest.

Components are declared in a small YAML file, for example:

    components:
      - id: steamworks-sdk
        name: Steamworks SDK
        version: "1.62"
        source: Steamworks partner site
        kind: sdk
        paths: ["ThirdParty/Steamworks/**"]
"""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path

from obaaf import yamlutil
from obaaf.attest.common import RecordError, now, sha256_bytes, sha256_file, write_json

FORMAT = "obaaf-manifest/v0.1"
KINDS = {"sdk", "engine", "plugin", "middleware", "binary", "asset-pack", "tool"}
VENDORED_NONE = "none"
# JSON field that binds an empty (no-vendored-binaries) claim into the digest.
VENDORED_FIELD = "vendoredBinaries"


def load_sources(path: str | Path) -> tuple[list[dict], bool]:
    """Return (components, vendored_none) from an obaaf-sources.yaml file.

    Either a non-empty `components` list, or `vendored_binaries: none` (with
    components absent or empty). The two are mutually exclusive.
    """
    data = yamlutil.load_file(path) or {}
    if not isinstance(data, dict):
        raise RecordError(f"{path}: expected a mapping with 'components' or vendored_binaries: none")
    vendored = data.get("vendored_binaries")
    components = data.get("components")
    if vendored is not None:
        if vendored != VENDORED_NONE:
            raise RecordError(f"{path}: vendored_binaries must be {VENDORED_NONE!r}, not {vendored!r}")
        if components is None:
            return [], True
        if not isinstance(components, list):
            raise RecordError(f"{path}: 'components' must be a list when present")
        if components:
            raise RecordError(f"{path}: vendored_binaries: none cannot be combined with components")
        return [], True
    if not isinstance(components, list) or not components:
        raise RecordError(f"{path}: declare components or set vendored_binaries: none")
    seen = set()
    for comp in components:
        for key in ("id", "name", "version", "source", "kind", "paths"):
            if not comp.get(key):
                raise RecordError(f"{path}: component {comp.get('id', '?')} is missing {key!r}")
        if comp["kind"] not in KINDS:
            raise RecordError(f"{path}: component {comp['id']} has unknown kind {comp['kind']!r}")
        if comp["id"] in seen:
            raise RecordError(f"{path}: duplicate component id {comp['id']}")
        seen.add(comp["id"])
        comp["version"] = str(comp["version"])
    return components, False


def load_components(path: str | Path) -> list[dict]:
    """Components from a sources file. Raises if the file declares vendored_binaries: none."""
    components, none = load_sources(path)
    if none:
        raise RecordError(f"{path}: vendored_binaries: none (no components)")
    return components


def _matches(rel: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatchcase(rel, pattern):
            return True
        if pattern.endswith("/**") and (rel == pattern[:-3] or rel.startswith(pattern[:-2])):
            return True
    return False


def _tracked_files(root: Path, components: list[dict]) -> dict[str, str]:
    """Map each tracked file (relative path) to its component id. First matching component wins."""
    owned: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not (path.is_symlink() or path.is_file()) or ".git" in path.relative_to(root).parts:
            continue
        rel = path.relative_to(root).as_posix()
        for comp in components:
            if _matches(rel, comp["paths"]):
                owned[rel] = comp["id"]
                break
    return owned


def validate_manifest(manifest: dict, *, path: str | Path | None = None) -> None:
    """Fail closed on empty manifests that lack the none claim, and on inconsistent claims."""
    where = f"{path}: " if path else ""
    components = manifest.get("components")
    entries = manifest.get("entries")
    if not isinstance(components, list) or not isinstance(entries, list):
        raise RecordError(f"{where}manifest must have list 'components' and 'entries'")
    claim = manifest.get(VENDORED_FIELD)
    empty = len(components) == 0 and len(entries) == 0
    if claim == VENDORED_NONE:
        if not empty:
            raise RecordError(f"{where}{VENDORED_FIELD}: none requires empty components and entries")
        return
    if claim is not None:
        raise RecordError(f"{where}unknown {VENDORED_FIELD} value {claim!r}")
    if empty:
        raise RecordError(
            f"{where}empty components and entries require {VENDORED_FIELD}: {VENDORED_NONE!r}"
        )
    if not components:
        raise RecordError(f"{where}entries without components require {VENDORED_FIELD}: {VENDORED_NONE!r}")


def create(root: str | Path, components_file: str | Path) -> dict:
    root = Path(root)
    components, none = load_sources(components_file)
    if none:
        return {
            "format": FORMAT,
            "createdAt": now(),
            VENDORED_FIELD: VENDORED_NONE,
            "components": [],
            "entries": [],
        }
    owned = _tracked_files(root, components)
    empty = [c["id"] for c in components if c["id"] not in owned.values()]
    if empty:
        raise RecordError(f"no files match the paths of component(s): {', '.join(empty)}")
    entries = [dict(_describe(root / rel), path=rel, component=comp) for rel, comp in sorted(owned.items())]
    return {
        "format": FORMAT,
        "createdAt": now(),
        "components": [
            {k: c[k] for k in ("id", "name", "version", "source", "kind", "paths")} for c in components
        ],
        "entries": entries,
    }


def _describe(path: Path) -> dict:
    """The digest of a file, or of a symbolic link's target text (the link is never followed)."""
    if path.is_symlink():
        target = os.readlink(path)
        return {"sha256": sha256_bytes(target.encode("utf-8", "surrogateescape")), "size": 0, "symlink": target}
    return {"sha256": sha256_file(path), "size": path.stat().st_size}


def load(path: str | Path) -> dict:
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    if manifest.get("format") != FORMAT:
        raise RecordError(f"{path}: not an OBAAF manifest ({manifest.get('format')!r})")
    validate_manifest(manifest, path=path)
    return manifest


def check(root: str | Path, manifest: dict) -> list[str]:
    """Differences between the files on disk and the manifest (empty when they match).

    For `vendoredBinaries: none`, there are no tracked paths: the reviewed claim is
    the check. `check` does not re-read obaaf-sources.yaml; regenerating the
    manifest after editing sources is what binds a new declaration.
    """
    validate_manifest(manifest)
    if manifest.get(VENDORED_FIELD) == VENDORED_NONE:
        return []
    root = Path(root)
    recorded = {e["path"]: e for e in manifest["entries"]}
    current = _tracked_files(root, manifest["components"])
    problems = []
    for rel in sorted(set(recorded) - set(current)):
        problems.append(f"missing: {rel} is in the manifest but not on disk")
    for rel in sorted(set(current) - set(recorded)):
        problems.append(f"unrecorded: {rel} ({current[rel]}) is not in the manifest")
    for rel in sorted(set(current) & set(recorded)):
        actual = _describe(root / rel)
        expected = recorded[rel]
        if ("symlink" in actual) != ("symlink" in expected):
            what = "a symbolic link" if "symlink" in actual else "a regular file"
            problems.append(f"changed: {rel} is now {what}")
        elif "symlink" in actual and actual["symlink"] != expected["symlink"]:
            problems.append(f"changed: {rel} now links to {actual['symlink']!r}, the manifest records "
                            f"{expected['symlink']!r}")
        elif actual["sha256"] != expected["sha256"]:
            problems.append(f"changed: {rel} has sha256 {actual['sha256']}, the manifest records {expected['sha256']}")
    return problems


def is_none_claim(manifest: dict) -> bool:
    return manifest.get(VENDORED_FIELD) == VENDORED_NONE


def sources_match(sources_file: str | Path, manifest: dict) -> list[str]:
    """Differences between a sources file and a loaded manifest (empty when they agree).

    `check` does not call this: digest checks stay against disk. Pass the sources file
    explicitly (CLI `--sources`) so a reviewed none claim cannot stay green after the
    sources file gains components without regenerating the JSON.
    """
    validate_manifest(manifest)
    components, none = load_sources(sources_file)
    problems = []
    if none:
        if not is_none_claim(manifest):
            problems.append("sources declare vendored_binaries: none but the manifest does not")
        return problems
    if is_none_claim(manifest):
        problems.append("manifest declares vendoredBinaries: none but sources list components")
        return problems
    source_ids = [c["id"] for c in components]
    manifest_ids = [c["id"] for c in manifest["components"]]
    if source_ids != manifest_ids:
        problems.append(
            f"component ids differ: sources have {source_ids}, manifest has {manifest_ids}"
        )
    return problems


def sdk_versions(manifest: dict) -> list[dict]:
    """Components that ship to players or build the game, for the build record."""
    return [
        {"name": c["name"], "id": c["id"], "version": c["version"], "kind": c["kind"], "reportedBy": "manifest"}
        for c in manifest["components"]
        if c["kind"] in ("sdk", "engine", "plugin", "middleware")
    ]


def write(manifest: dict, out: str | Path) -> None:
    write_json(out, manifest)
