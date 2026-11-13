"""Drift: compare a committed snapshot of the settings with the settings as they are now.

A setting can change without any file in the repository changing: someone opens an environment to every
branch, adds a bypass to a ruleset, drops a required check. A team commits a snapshot of the settings as they
should be (``obaaf audit --snapshot-out FILE``), and ``obaaf audit --expected FILE`` reads the live settings
and reports every difference from it as a finding of the rule ``OBAAF-DRIFT-001``.

Four outcomes for each setting and each part of one:

- **matches**: both snapshots read it, and the values are the same once lists are taken without regard to
  their order (the snapshot keeps GitHub's order inside a rule's parameters and a ruleset's conditions).
- **differs**: both read it and something is not the same. Each part that differs (one environment, one
  ruleset, one field) is one finding, with every change in it listed.
- **not compared**: one side read it (or a part of it) and the other did not. Whether it changed is not known,
  and that is never reported as "no drift". This includes a part the committed snapshot marks as not read
  and this run could read, so a hole in the committed file never hides a change.
- **not covered**: neither side read it in full, so there is nothing to compare (of an environment both read
  in part, what both read is compared, and the rest is not covered).

The committed file can be edited by anyone who can open a pull request, so it is read through
``snapshot.load``, which checks its whole shape, and then checked again here for what the schema does not
say: that two rulesets, environments or secrets do not share a name or id. Everything shown to a person
passes through ``plain`` or ``quoted``, or is JSON written with ASCII escapes.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from obaaf.audit.github import plain, quoted
from obaaf.audit.settings import BY_KEY, SETTINGS, check_branches

RULE = "OBAAF-DRIFT-001"
FORMAT = "obaaf-settings-drift/v0.1"
MAX_EXPECTED_BRANCHES = 50   # each branch costs three requests; a file listing thousands is not a snapshot
CHANGES_SHOWN = 20           # changes listed for one part in the text report; the JSON output has them all

# How each setting's value is divided into parts. A part is what one finding is about, and its key is the
# same text the reader uses for it in ``problems`` (a ruleset's id, a branch or environment name, a field),
# so that a part the reader could not read is known by the same key.
#   ("fields",)       an object: each field is a part
#   ("map", noun)     an object keyed by a branch or environment name: each entry is a part
#   ("list", field, noun)   a list of objects: each is a part, known by that field
#   ("names", noun)   a list of names: each name is a part
SHAPES: dict[str, tuple] = {
    "repository": ("fields",),
    "rulesets": ("list", "id", "ruleset"),
    "ruleset_bypass_actors": ("list", "ruleset_id", "the bypass list of ruleset"),
    "branch_rules": ("map", "branch"),
    "branches": ("map", "branch"),
    "branch_protection": ("map", "branch"),
    "environments": ("list", "name", "environment"),
    "environment_secrets": ("map", "environment"),
    "repository_secrets": ("names", "secret"),
    "organization_secrets": ("names", "secret"),
    "actions_permissions": ("fields",),
    "workflow_permissions": ("fields",),
    "fork_pull_requests": ("fields",),
    "actions_policies": ("list", "id", "policy"),
    "collaborators": ("fields",),
}
# Inside a part, a list of objects is matched element by element when every element carries these fields
# and no two share them, so that a change reads as "rules[pull_request].parameters...", not as one rule
# removed and another added. The first that fits is used; a list that none fits is compared as a multiset.
ELEMENT_KEYS = (("id",), ("name",), ("context",), ("type", "ruleset_id"), ("type",), ("ruleset_id",),
                ("actor_type", "actor_id"))
SIMPLE = re.compile(r"[A-Za-z0-9_-]{1,60}\Z")


class DriftError(ValueError):
    """The two snapshots cannot be compared. Safe to print."""


# ---------------------------------------------------------------- reading the committed snapshot
def branches_to_read(expected: dict) -> list[str]:
    """The branches the committed snapshot covers, so that the live audit reads the same ones."""
    branches = expected.get("branches")
    if not isinstance(branches, list) or not all(isinstance(b, str) for b in branches):
        raise DriftError("the expected snapshot's list of branches is not a list of names")
    if len(branches) > MAX_EXPECTED_BRANCHES:
        raise DriftError(f"the expected snapshot names {len(branches)} branches; at most {MAX_EXPECTED_BRANCHES} "
                         "can be compared")
    if len(set(branches)) != len(branches):
        raise DriftError("the expected snapshot names a branch twice")
    try:
        check_branches(branches)
    except ValueError:
        raise DriftError("the expected snapshot names a branch that is not one plain branch name") from None
    return list(branches)


def check_comparable(expected: dict, live: dict) -> None:
    """Refuse to compare snapshots of two different repositories, or of two different servers."""
    if str(expected.get("api", "")).rstrip("/").lower() != str(live.get("api", "")).rstrip("/").lower():
        raise DriftError(f"the expected snapshot was read from {plain(expected.get('api'), 100)}, and these "
                         f"settings from {plain(live.get('api'), 100)}")
    names = {str(live.get("repository", "")).lower(), str(live.get("requested_as", "")).lower()} - {""}
    theirs = {str(expected.get("repository", "")).lower(), str(expected.get("requested_as", "")).lower()} - {""}
    if not names & theirs:
        raise DriftError(f"the expected snapshot is of {plain(expected.get('repository'), 140)}, not of "
                         f"{plain(live.get('repository'), 140)}")


# ---------------------------------------------------------------- comparing values
def canon(value) -> str:
    """One text for a value, the same whatever order its lists and objects are in.

    Lists are taken as multisets: no list in a snapshot means anything by its order. Leaves are compared
    as JSON text, so ``true`` is not ``1`` and ``1`` is not ``1.0`` (Python's ``==`` would say both are)."""
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k) + ":" + canon(value[k]) for k in sorted(value)) + "}"
    if isinstance(value, list):
        return "[" + ",".join(sorted(canon(v) for v in value)) + "]"
    return json.dumps(value, ensure_ascii=True)


def _scalar(value) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _element_key(*lists: list) -> tuple[str, ...] | None:
    for fields in ELEMENT_KEYS:
        fits = True
        for items in lists:
            idents = []
            for item in items:
                if not isinstance(item, dict) or not all(f in item and _scalar(item[f]) for f in fields):
                    fits = False
                    break
                idents.append(tuple(canon(item[f]) for f in fields))
            if not fits or len(set(idents)) != len(idents):
                fits = False
                break
        if fits:
            return fields
    return None


def _segment(part) -> str:
    """One step of a path, for people."""
    if isinstance(part, tuple):  # an element of a list, known by its key fields
        shown = [p if isinstance(p, str) and SIMPLE.match(p) else json.dumps(p, ensure_ascii=True) for p in part]
        return "[" + plain(", ".join(shown), 80) + "]"
    text = str(part)
    return "." + (text if SIMPLE.match(text) else json.dumps(text, ensure_ascii=True)[:80])


def path_text(path: list) -> str:
    return plain("".join(_segment(p) for p in path).lstrip("."), 200)


def _change(path: list, kind: str, expected=None, live=None) -> dict:
    out = {"path": path_text(path), "change": kind}
    if kind in ("changed", "removed"):
        out["expected"] = expected
    if kind in ("changed", "added"):
        out["live"] = live
    return out


def changes(expected, live, path: list | None = None, out: list | None = None) -> list[dict]:
    """Every difference between two values, by where it is. Empty when they are the same."""
    path = [] if path is None else path
    out = [] if out is None else out
    if canon(expected) == canon(live):
        return out
    if isinstance(expected, dict) and isinstance(live, dict):
        for key in sorted(set(expected) | set(live)):
            if key not in live:
                out.append(_change(path + [key], "removed", expected=expected[key]))
            elif key not in expected:
                out.append(_change(path + [key], "added", live=live[key]))
            else:
                changes(expected[key], live[key], path + [key], out)
        return out
    if isinstance(expected, list) and isinstance(live, list):
        fields = _element_key(expected, live)
        if fields:
            # Keyed by canonical text, not by the values: in Python 5, 5.0 and True are one dict key, and
            # a file could use that to make two elements one.
            ours = {tuple(canon(item[f]) for f in fields): item for item in expected}
            theirs = {tuple(canon(item[f]) for f in fields): item for item in live}
            for ident in sorted(set(ours) | set(theirs)):
                shown = ours.get(ident, theirs.get(ident))
                where = path + [tuple(shown[f] for f in fields)]
                if ident not in theirs:
                    out.append(_change(where, "removed", expected=ours[ident]))
                elif ident not in ours:
                    out.append(_change(where, "added", live=theirs[ident]))
                else:
                    changes(ours[ident], theirs[ident], where, out)
            return out
        left, right = Counter(canon(v) for v in expected), Counter(canon(v) for v in live)
        only_left, only_right = left - right, right - left  # what each holds more of than the other
        for value in expected:
            if only_left[canon(value)] > 0:
                only_left[canon(value)] -= 1
                out.append(_change(path, "removed", expected=value))
        for value in live:
            if only_right[canon(value)] > 0:
                only_right[canon(value)] -= 1
                out.append(_change(path, "added", live=value))
        return out
    out.append(_change(path, "changed", expected=expected, live=live))
    return out


# ---------------------------------------------------------------- dividing a setting into parts
def parts(key: str, value, side: str = "") -> dict[str, object]:
    """A setting's value as its parts, by key. Raises DriftError when two parts share a key, which no
    snapshot the reader writes has, and which would otherwise hide one of them. ``side`` names the file in
    the message."""
    shape = SHAPES[key]
    where = (f"{side}: " if side else "") + BY_KEY[key].title
    if shape[0] == "fields":
        if not isinstance(value, dict):
            raise DriftError(f"{where}: the value is not an object")
        return dict(value)
    if shape[0] == "map":
        if not isinstance(value, dict):
            raise DriftError(f"{where}: the value is not an object")
        return dict(value)
    if shape[0] == "names":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise DriftError(f"{where}: the value is not a list of names")
        if len(set(value)) != len(value):
            raise DriftError(f"{where}: a name is listed twice")
        return {name: True for name in value}
    field = shape[1]
    out: dict[str, object] = {}
    if not isinstance(value, list):
        raise DriftError(f"{where}: the value is not a list")
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get(field), (str, int)) or isinstance(item.get(field), bool):
            raise DriftError(f"{where}: an entry has no {field}")
        ident = str(item[field])
        if ident in out:
            raise DriftError(f"{where}: two entries have the {field} {quoted(ident)}")
        out[ident] = item
    return out


def label(key: str, ident: str, *values) -> str:
    """How a part is named to people."""
    shape = SHAPES[key]
    if shape[0] == "fields":
        return plain(ident, 60) if SIMPLE.match(ident) else quoted(ident)
    noun = shape[-1]
    if shape[0] == "list" and shape[1] == "id":
        name = next((v.get("name") for v in values if isinstance(v, dict) and isinstance(v.get("name"), str)), None)
        return f"{noun} {plain(ident, 30)}" + (f" {quoted(name)}" if name is not None else "")
    if shape[0] == "list" and shape[1] == "ruleset_id":
        return f"{noun} {plain(ident, 30)}"
    return f"{noun} {quoted(ident)}"


# ---------------------------------------------------------------- the comparison
def _status(entry) -> str:
    return entry.get("status", "") if isinstance(entry, dict) else ""


def _problem_keys(entry: dict) -> dict[str, dict]:
    return {str(p.get("key")): p for p in entry.get("problems", []) if isinstance(p, dict)}


KNOWN = ("read", "partial", "not_applicable")
RETAKE = ("Take the expected snapshot again, with the token this check uses, so that it covers what this run can "
          "read.")


def _branch_gaps(key: str, snap: dict, names: set[str]) -> dict[str, dict]:
    """For a setting kept by branch, which of ``names`` a snapshot did not audit: it knows nothing of them, so
    a branch only one side audited is not compared, never "new" or "gone"."""
    if SHAPES[key] != ("map", "branch"):
        return {}
    audited = set(snap.get("branches") or [])
    return {name: {"reason_code": "not_audited", "reason": "this branch was not audited"}
            for name in names - audited}


def compare(expected: dict, live: dict, expected_name: str = "", live_name: str = "") -> dict:
    """Compare two snapshots of one repository's settings. Both must be in the snapshot format.

    For each setting, and for each part of it, there are four cases. Both read it: compared. Neither read it:
    not covered, listed, and not a failure. The expected snapshot read it and this run did not: not compared,
    a failure, because whether it changed is not known. This run read it and the expected snapshot did not:
    not compared too, and a failure for the same reason. The last case is what keeps a hole in the committed
    file from hiding a change: a part the file marks as not read (by GitHub's doing or by an edit) and that
    this run can read is never passed over."""
    their_side = f"the expected snapshot {expected_name}".rstrip()
    our_side = f"the snapshot {live_name}" if live_name else "the settings read now"
    differences: list[dict] = []
    not_compared: list[dict] = []
    not_covered: list[dict] = []
    outcome: dict[str, str] = {}  # each setting: matches, differs, in part, not compared, not covered
    parts_compared = 0

    def unknown(entry: dict, prefix: str) -> str:
        return prefix + str(entry.get("reason", "")) + (f" ({entry['reason_code']})" if entry.get("reason_code") else "")

    for setting in SETTINGS:
        key = setting.key
        theirs, ours = expected["settings"][key], live["settings"][key]
        e_status, l_status = _status(theirs), _status(ours)
        e_known, l_known = e_status in KNOWN, l_status in KNOWN
        for snap, side, entry in ((expected, their_side, theirs), (live, our_side, ours)):
            if SHAPES[key] == ("map", "branch") and _status(entry) in ("read", "partial"):
                # The reader records every audited branch, read or not, and nothing else. A file whose list of
                # branches says otherwise would have its branch data treated as never read. Checked whatever
                # the other side read, so that whether a file is refused does not depend on the run.
                value = entry.get("value")
                held = (set(value) if isinstance(value, dict) else set()) | set(_problem_keys(entry))
                if held != set(snap.get("branches") or []):
                    raise DriftError(f"{side}: {setting.title}: the branches it holds are not the branches it "
                                     "says were audited")
        if not e_known and not l_known:
            not_covered.append({"setting": key, "item": None, "what": setting.title,
                                "reason_code": theirs.get("reason_code"),
                                "why": unknown(theirs, "neither snapshot read it; the expected one: ")})
            outcome[key] = "not covered"
            continue
        if not l_known:
            not_compared.append({"setting": key, "item": None, "what": setting.title,
                                 "reason_code": ours.get("reason_code"),
                                 "why": unknown(ours, ("it did not apply in the expected snapshot" if
                                                       e_status == "not_applicable" else
                                                       "the expected snapshot holds it") + ", and it was not read "
                                                                                           "now: ")})
            outcome[key] = "not compared"
            continue
        if not e_known:
            not_compared.append({"setting": key, "item": None, "what": setting.title,
                                 "reason_code": theirs.get("reason_code"),
                                 "why": unknown(theirs, "it was read now, and the expected snapshot did not read it: ")
                                 + ". " + RETAKE})
            outcome[key] = "not compared"
            continue
        before = (len(differences), len(not_compared), len(not_covered), parts_compared)
        if (e_status == "not_applicable") != (l_status == "not_applicable"):
            differences.append({
                "setting": key, "item": None, "what": setting.title,
                "changes": [{"path": "", "change": "status", "expected": e_status, "live": l_status}]})
        e_parts = {} if e_status == "not_applicable" else parts(key, theirs.get("value"), their_side)
        l_parts = {} if l_status == "not_applicable" else parts(key, ours.get("value"), our_side)
        e_problems, l_problems = _problem_keys(theirs), _problem_keys(ours)
        names = set(e_parts) | set(l_parts) | set(e_problems) | set(l_problems)
        e_unknown = {**_branch_gaps(key, expected, names), **e_problems}
        l_unknown = {**_branch_gaps(key, live, names), **l_problems}
        for ident in sorted(set(e_parts) | set(l_parts) | set(e_unknown) | set(l_unknown)):
            what = label(key, ident, e_parts.get(ident), l_parts.get(ident))
            here = {"setting": key, "item": ident, "what": f"{setting.title}: {what}"}
            if ident in e_unknown and ident in l_unknown:
                if isinstance(e_parts.get(ident), dict) and isinstance(l_parts.get(ident), dict):
                    # Read in part on both sides (an environment whose branch and tag patterns failed to load):
                    # what was read is compared, and a difference in it counts. What was not read is listed
                    # as not covered whether or not the rest differs.
                    parts_compared += 1
                    found = changes(e_parts[ident], l_parts[ident])
                    if found:
                        differences.append({"setting": key, "item": ident, "what": what, "changes": found})
                    not_covered.append({**here, "reason_code": e_unknown[ident].get("reason_code"),
                                        "why": unknown(e_unknown[ident], "both read it only in part, and the rest was "
                                                                         "compared; not read by the expected one: ")})
                    continue
                not_covered.append({**here, "reason_code": e_unknown[ident].get("reason_code"),
                                    "why": unknown(e_unknown[ident], "neither snapshot read it; the expected one: ")})
                continue
            if ident in l_unknown:
                now = "it was read only in part now: " if ident in l_parts else "it could not be read now: "
                held = ("the expected snapshot holds it, and " if ident in e_parts else
                        "it is not in the expected snapshot (it may be new), and ") + now
                not_compared.append({**here, "reason_code": l_unknown[ident].get("reason_code"),
                                     "why": unknown(l_unknown[ident], held)})
                continue
            if ident in e_unknown:
                held = ("it was read now, and the expected snapshot did not read it in full: " if ident in l_parts
                        else "the expected snapshot did not read it in full, and it is not there now (it may have "
                             "been removed): ")
                not_compared.append({**here, "reason_code": e_unknown[ident].get("reason_code"),
                                     "why": unknown(e_unknown[ident], held) + ". " + RETAKE})
                continue
            parts_compared += 1
            if ident not in l_parts:
                differences.append({"setting": key, "item": ident, "what": what,
                                    "changes": [_change([], "removed", expected=e_parts[ident])]})
            elif ident not in e_parts:
                differences.append({"setting": key, "item": ident, "what": what,
                                    "changes": [_change([], "added", live=l_parts[ident])]})
            else:
                found = changes(e_parts[ident], l_parts[ident])
                if found:
                    differences.append({"setting": key, "item": ident, "what": what, "changes": found})
        if len(differences) > before[0]:
            outcome[key] = "differs"
        elif len(not_compared) > before[1]:
            outcome[key] = "in part"
        elif parts_compared == before[3] and len(not_covered) > before[2]:
            outcome[key] = "not covered"  # every part it has was unread on both sides
        else:
            outcome[key] = "matches"  # including a setting with no parts on either side, such as no environments
    tally = Counter(outcome.values())
    return {
        "format": FORMAT,
        "rule": RULE,
        "repository": live.get("repository"),
        "expected": {"file": expected_name, "taken_at": expected.get("taken_at"), "tool": expected.get("tool"),
                     "authenticated": bool(expected.get("viewer", {}).get("authenticated")),
                     "branches": list(expected.get("branches", []))},
        "live": {"file": live_name, "taken_at": live.get("taken_at"), "tool": live.get("tool"),
                 "authenticated": bool(live.get("viewer", {}).get("authenticated")),
                 "branches": list(live.get("branches", []))},
        "summary": {"settings": len(SETTINGS),
                    "compared": tally["matches"] + tally["differs"] + tally["in part"],
                    "matching": tally["matches"], "differing": tally["differs"], "compared_in_part": tally["in part"],
                    "not_compared": tally["not compared"], "not_covered": tally["not covered"],
                    "parts_compared": parts_compared, "findings": len(differences),
                    "parts_not_compared": len(not_compared), "parts_not_covered": len(not_covered)},
        "outcomes": outcome,
        "differences": differences,
        "not_compared": not_compared,
        "not_covered": not_covered,
    }


def failed(result: dict) -> bool:
    """A drift check passes only when everything both sides read matches, nothing was read by one side and
    not the other, and at least one setting was compared: a check that compared nothing has not shown that
    nothing changed."""
    return bool(result["differences"] or result["not_compared"] or not result["summary"]["compared"])


# ---------------------------------------------------------------- the report for people
def _shown(value, limit: int = 160) -> str:
    return plain(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(", ", ": ")), limit)


def _when(stamp) -> str:
    stamp = str(stamp or "")
    return plain(f"{stamp[:10]} {stamp[11:16]} UTC" if len(stamp) == 20 else stamp, 40)


def _change_text(change: dict) -> str:
    where = plain(change["path"], 200)
    kind = change["change"]
    if kind == "status":
        words = {"not_applicable": "does not apply", "read": "applies", "partial": "applies"}
        return (f"{words.get(change['expected'], plain(change['expected'], 20))} in the expected snapshot, "
                f"{words.get(change['live'], plain(change['live'], 20))} now")
    subject = f"{where}: " if where else ""
    if kind == "changed":
        return f"{subject}was {_shown(change['expected'])}, now {_shown(change['live'])}"
    if kind == "added":
        return f"{subject}new, not in the expected snapshot" + (
            "" if change.get("live") is True else f": {_shown(change['live'])}")
    return f"{subject}gone; the expected snapshot has" + (
        " it" if change.get("expected") is True else f" {_shown(change['expected'])}")


def to_text(result: dict) -> str:
    summary = result["summary"]
    expected, live = result["expected"], result["live"]
    how = {True: "with a token", False: "without a token"}
    lines = [f"Settings drift of {plain(result['repository'], 140)}",
             f"Expected: the snapshot {plain(expected['file'] or 'given', 140)}, taken {_when(expected['taken_at'])} "
             f"{how[expected['authenticated']]}.",
             (f"Now: the snapshot {plain(live['file'], 140)}, taken {_when(live['taken_at'])} "
              f"{how[live['authenticated']]}." if live["file"] else
              f"Now: read {_when(live['taken_at'])} {how[live['authenticated']]}.")]
    e_branches, l_branches = [plain(b, 60) for b in expected["branches"]], [plain(b, 60) for b in live["branches"]]
    lines.append(f"Branches: {', '.join(e_branches) or 'none'}" if e_branches == l_branches else
                 f"Branches: {', '.join(e_branches) or 'none'} in the expected snapshot; "
                 f"{', '.join(l_branches) or 'none'} now.")
    if expected["authenticated"] != live["authenticated"]:
        lines.append("The two were read with different access, so a setting one could read and the other could "
                     "not is listed as not compared, not as a difference.")
    lines.append("")
    if result["differences"]:
        lines.append(f"DRIFT: {summary['findings']} part(s) of {summary['differing']} setting(s) differ from the "
                     f"expected snapshot. Each is a finding ({RULE}).")
        current = None
        for difference in result["differences"]:
            if difference["setting"] != current:
                current = difference["setting"]
                lines.append(f"  {BY_KEY[current].title}")
            shown = difference["changes"][:CHANGES_SHOWN]
            if difference["item"] is None:
                lines.append(f"    {_change_text(shown[0])}")
                continue
            if len(shown) == 1 and not shown[0]["path"]:
                lines.append(f"    {difference['what']}: {_change_text(shown[0])}")
                continue
            lines.append(f"    {difference['what']}")
            lines.extend(f"      {_change_text(change)}" for change in shown)
            if len(difference["changes"]) > CHANGES_SHOWN:
                lines.append(f"      and {len(difference['changes']) - CHANGES_SHOWN} more (see --format json)")
        lines.append("  If the change was meant, take a new snapshot with the same access and commit it in a reviewed "
                     "pull request (obaaf audit --snapshot-out FILE). If it was not, put the setting back.")
        lines.append("")
    if result["not_compared"]:
        lines.append(f"NOT COMPARED: {summary['parts_not_compared']}. One snapshot read these and the other did not, "
                     "so whether they changed is not known. This fails the check.")
        for entry in result["not_compared"]:
            lines.append(f"  {plain(entry['what'], 160)}")
            lines.append(f"      {plain(entry['why'], 300)}")
        lines.append("")
    if not summary["compared"]:
        lines.append("NOTHING COMPARED. No setting was read both in the expected snapshot and now, so this check "
                     "shows nothing about drift. This fails the check.")
        lines.append("")
    elif not result["differences"] and not result["not_compared"]:
        lines.append(f"NO DRIFT in the {summary['compared']} setting(s) compared.")
        lines.append("")
    if result["not_covered"]:
        lines.append(f"NOT COVERED: {summary['parts_not_covered']}. Neither snapshot read these in full, so they "
                     "were not compared, or only what both read was:")
        for entry in result["not_covered"]:
            lines.append(f"  {plain(entry['what'], 160)}")
            if entry["item"] is not None:
                lines.append(f"      {plain(entry['why'], 300)}")
        lines.append("")
    in_part = f", {summary['compared_in_part']} only in part" if summary["compared_in_part"] else ""
    lines.append(f"{summary['settings']} settings: {summary['compared']} compared ({summary['matching']} match, "
                 f"{summary['differing']} differ{in_part}), {summary['not_compared']} not compared, "
                 f"{summary['not_covered']} not covered; {summary['parts_compared']} part(s) compared. "
                 f"{summary['findings']} finding(s).")
    return "\n".join(lines) + "\n"
