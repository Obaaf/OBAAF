"""The settings snapshot as a file: writing it, and reading one back without trusting it.

A snapshot may be committed to a repository and read by a later run, so anyone who can open a pull request
can put one in front of this code. A file is therefore checked before it is used: its size, that it is
strict JSON with no key given twice, how deeply it is nested, and its whole shape, down to the value of
every setting, against the JSON Schema. What the file says is still only what the file says.
"""

from __future__ import annotations

import json
from pathlib import Path

from obaaf.audit.github import plain
from obaaf.audit.settings import BY_KEY, FORMAT, SETTINGS
from obaaf.catalog import data_text

MAX_SNAPSHOT_BYTES = 20 * 1024 * 1024
MAX_DEPTH = 40
# The only settings that can fail to exist for a repository. Any other marked "not applicable" is a file
# saying that something was looked at when it was not.
MAY_NOT_APPLY = ("ruleset_bypass_actors", "environment_secrets", "organization_secrets")


class SnapshotError(ValueError):
    """A snapshot file cannot be used."""


class ReaderFault(RuntimeError):
    """The reader built something that is not a snapshot. A fault in obaaf, not in a file or an answer."""


def dumps(snapshot: dict) -> str:
    # ASCII only, so a committed snapshot cannot carry characters that display as something else in review.
    return json.dumps(snapshot, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def write(snapshot: dict, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dumps(snapshot), encoding="utf-8")


def _no_duplicates(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            # With a key given twice, a reviewer reads the first and a parser keeps the last.
            raise ValueError(f"the key {plain(key, 60)!r} is given twice in one object")
        out[key] = value
    return out


def _no_constants(name: str):
    raise ValueError(f"{name} is not JSON")


def _finite(text: str) -> float:
    # 1e999 is valid JSON and Python reads it as infinity, which no setting holds and json.dumps refuses.
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError("a number is too large")
    return value


def _too_deep(value, depth: int = 0) -> bool:
    if depth > MAX_DEPTH:
        return True
    if isinstance(value, dict):
        return any(_too_deep(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(_too_deep(v, depth + 1) for v in value)
    return False


def problems(snapshot: object) -> list[str]:
    """Why ``snapshot`` is not a usable snapshot of this version (empty when it is). Safe to print."""
    if not isinstance(snapshot, dict):
        return ["the file does not hold a JSON object"]
    if snapshot.get("format") != FORMAT:
        return [f"its format is {plain(snapshot.get('format'), 60)!r}; this version of obaaf reads {FORMAT!r}"]
    try:
        if _too_deep(snapshot):
            return [f"it is nested more than {MAX_DEPTH} levels deep"]
    except RecursionError:
        return [f"it is nested more than {MAX_DEPTH} levels deep"]
    known = [s.key for s in SETTINGS]
    settings = snapshot.get("settings")
    if isinstance(settings, dict):
        # Every setting this version knows must be present. A missing entry would read as "nothing to
        # report", which is exactly what a snapshot must never let "not read" turn into.
        missing = [key for key in known if key not in settings]
        extra = sorted(plain(key, 40) for key in settings if key not in known)
        if missing or extra:
            return (["no entry for: " + ", ".join(missing)] if missing else []) + (
                ["entries this version does not know: " + ", ".join(extra[:10])] if extra else [])
        wrong = [key for key in known if isinstance(settings[key], dict)
                 and settings[key].get("status") == "not_applicable" and key not in MAY_NOT_APPLY]
        if wrong:
            return ["marked as not applicable, which these settings cannot be: " + ", ".join(wrong)]
    found = []
    for err in sorted(_validator().iter_errors(snapshot), key=lambda e: [str(p) for p in e.absolute_path]):
        where = "/".join(plain(p, 40) for p in err.absolute_path) or "(root)"
        # The validator's own message quotes the offending value; say where and which rule instead.
        found.append(f"{where}: does not match the snapshot format ({plain(err.validator, 30)})")
        if len(found) == 20:
            break
    return found


def _validator():
    import jsonschema  # imported lazily, like the record commands do

    return jsonschema.Draft202012Validator(json.loads(data_text("schemas/settings-snapshot.schema.json")))


def settle(snapshot: dict) -> dict:
    """Make a snapshot the reader has just built fit the format, or raise.

    The reader checks the shape of GitHub's answers and the schema checks the shape of a snapshot; the two
    were written separately and once disagreed (a wait of two million minutes was read, written and then
    refused when the file was read back). So every snapshot is checked before anyone gets it. A setting
    whose value the schema refuses is recorded as not read: the answer behind it was outside what this
    version understands, and that must not be written down as known. Anything else the schema refuses is
    a fault in the reader and is raised."""
    refused: dict[str, str] = {}
    for err in _validator().iter_errors(snapshot):
        path = list(err.absolute_path)
        if len(path) < 3 or path[0] != "settings" or path[1] not in BY_KEY or path[2] != "value":
            raise ReaderFault("the reader built a snapshot that is not in the snapshot format")
        where = "/".join(plain(part, 40) for part in path[3:]) or "the value"
        refused.setdefault(path[1], f"{where} ({plain(err.validator, 30)})")
    for key, where in sorted(refused.items()):
        snapshot["settings"][key] = {
            "status": "unread", "reason_code": "unexpected", "needs": BY_KEY[key].needs,
            "reason": f"the answer held a value outside what the snapshot format allows: {where}"}
    found = problems(snapshot)
    if found:
        raise ReaderFault("the reader built a snapshot that is not in the snapshot format: " + "; ".join(found[:3]))
    return snapshot


def load(path: str | Path) -> dict:
    source = Path(path)
    try:
        with open(source, "rb") as handle:
            raw = handle.read(MAX_SNAPSHOT_BYTES + 1)
    except OSError as exc:
        raise SnapshotError(f"cannot read the snapshot: {exc.strerror or type(exc).__name__}") from exc
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("the file is larger than 20 MB; that is not a settings snapshot")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constants,
                          parse_float=_finite)
    except (ValueError, RecursionError) as exc:
        detail = plain(exc, 120) if isinstance(exc, ValueError) and not isinstance(exc, UnicodeError) else (
            "it is not UTF-8 text" if isinstance(exc, UnicodeError) else "it is nested too deeply")
        raise SnapshotError(f"the file is not a usable JSON document ({detail})") from exc
    found = problems(data)
    if found:
        raise SnapshotError("the file is not a usable settings snapshot: " + "; ".join(found[:5]))
    return data
