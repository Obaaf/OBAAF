"""The settings snapshot as a file: writing it, and reading one back without trusting it."""

from __future__ import annotations

import json
from pathlib import Path

from obaaf.audit.settings import FORMAT, SETTINGS
from obaaf.catalog import data_text

MAX_SNAPSHOT_BYTES = 20 * 1024 * 1024


class SnapshotError(ValueError):
    """A snapshot file cannot be used."""


def dumps(snapshot: dict) -> str:
    # ASCII only, so a committed snapshot cannot carry characters that display as something else in review.
    return json.dumps(snapshot, indent=2, ensure_ascii=True) + "\n"


def write(snapshot: dict, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dumps(snapshot), encoding="utf-8")


def problems(snapshot: object) -> list[str]:
    """Why ``snapshot`` is not a usable snapshot of this version (empty when it is)."""
    if not isinstance(snapshot, dict):
        return ["the file does not hold a JSON object"]
    if snapshot.get("format") != FORMAT:
        return [f"format is {snapshot.get('format')!r}; this version of obaaf reads {FORMAT!r}"]
    import jsonschema  # imported lazily, like the record commands do

    schema = json.loads(data_text("schemas/settings-snapshot.schema.json"))
    validator = jsonschema.Draft202012Validator(schema)
    found = [f"{'/'.join(str(p) for p in err.absolute_path) or '(root)'}: {err.message}"[:300]
             for err in sorted(validator.iter_errors(snapshot), key=lambda e: list(e.absolute_path))]
    if found:
        return found[:20]
    # Every setting this version knows must be present. A missing entry would read as "nothing to report",
    # which is exactly what a snapshot must never let "not read" turn into.
    known = [s.key for s in SETTINGS]
    missing = [key for key in known if key not in snapshot["settings"]]
    extra = [key for key in snapshot["settings"] if key not in known]
    if missing:
        found.append("no entry for: " + ", ".join(missing))
    if extra:
        found.append("entries this version does not know: " + ", ".join(sorted(extra)))
    return found


def load(path: str | Path) -> dict:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_SNAPSHOT_BYTES:
            raise SnapshotError(f"{path}: larger than 20 MB; not a settings snapshot")
        data = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SnapshotError(f"{path}: {exc.strerror or exc}") from exc
    except (ValueError, RecursionError) as exc:
        raise SnapshotError(f"{path}: not JSON ({exc})") from exc
    found = problems(data)
    if found:
        raise SnapshotError(f"{path}: not a usable settings snapshot: " + "; ".join(found[:5]))
    return data
