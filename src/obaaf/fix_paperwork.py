"""Read-only candidate generation for the adoption paperwork preview."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import fnmatch
import json
from pathlib import Path

import yaml

from obaaf import checker, yamlutil
from obaaf.checker import acceptance, baseline, workflow
from obaaf.checker.rules import ACCEPTED, FIXED
from obaaf.fix_proof import Approval, CheckOptions, Edit, Promise


@dataclass(frozen=True)
class Item:
    id: str
    kind: str
    description: str
    promises: tuple[Promise, ...] = ()
    removals: tuple[str, ...] = ()


@dataclass(frozen=True)
class Paperwork:
    edits: tuple[Edit, ...]
    promises: tuple[Promise, ...]
    items: tuple[Item, ...]
    refused: tuple[str, ...]


def _promise(f, made=None):
    approval = Approval(made.source, made.owner, made.reason, made.expires) if made else None
    return Promise(baseline.key(f), f.severity, f.state, ACCEPTED if made else "gone", approval)


def _matches(entry, finding):
    return (entry["rule"] == finding.rule and fnmatch.fnmatch(finding.path, str(entry["path"]))
            and (not entry.get("job") or entry["job"] == finding.job))


def _one_edit(a, b):
    """One insertion, deletion, substitution or transposition of adjacent letters."""
    if len(a) > len(b):
        a, b = b, a
    if len(b) - len(a) > 1 or a == b:
        return False
    index = next((i for i in range(len(a)) if a[i] != b[i]), len(a))
    if len(a) != len(b):
        return a[index:] == b[index + 1:]
    return (a[index + 1:] == b[index + 1:]
            or (a[index:index + 2] == b[index:index + 2][::-1] and a[index + 2:] == b[index + 2:]))


def _mapping(node):
    return {k.value: v for k, v in node.value} if isinstance(node, yaml.MappingNode) else {}


def _description(path, index, entry):
    # Keys are made text first: YAML allows `1:` or `true:` beside text keys, and sorting
    # mixed keys raised TypeError (found by the review of #278).
    shown = {str(k): v for k, v in entry.items()} if isinstance(entry, dict) else entry
    return (f"{path} entry {index + 1}: "
            + json.dumps(shown, sort_keys=True, ensure_ascii=True, default=str))


def _last_content(node):
    if isinstance(node, yaml.MappingNode) and not node.flow_style:
        return max(_last_content(v) for _, v in node.value)
    if isinstance(node, yaml.SequenceNode) and not node.flow_style:
        return max(_last_content(v) for v in node.value)
    return node.end_mark.index


def _comment_at(text, start, end, scalars):
    """Whether a YAML comment begins in text[start:end]: a `#` outside every scalar token."""
    return any(text[i] == "#" and not any(a <= i < b for a, b in scalars) for i in range(start, end))


def _delete_rows(text, sequence, indices, comments=True):
    """Delete whole adjacent groups, keeping separators needed by the surviving entries.

    In a flow-style list a deletion runs from one entry to the next, so a comment in it, or
    beside the last entries, would be lost from a kept entry or moved onto one: such a
    deletion is refused. `comments=False` is for JSON, which has none."""
    edits = []
    rows = sequence.value
    scalars = ([(t.start_mark.index, t.end_mark.index) for t in yaml.scan(text, Loader=yaml.SafeLoader)
                if isinstance(t, yaml.ScalarToken)] if comments and sequence.flow_style else [])
    for index in sorted(indices):
        if index - 1 in indices:
            continue
        last = index
        while last + 1 in indices:
            last += 1
        if sequence.flow_style:
            if last + 1 < len(rows):
                start, end = rows[index].start_mark.index, rows[last + 1].start_mark.index
            elif index:
                start, end = rows[index - 1].end_mark.index, rows[last].end_mark.index
            else:
                start, end = rows[index].start_mark.index, rows[last].end_mark.index
            line_end = text.find("\n", end)
            line_end = line_end if line_end >= 0 else len(text)
            if comments and (_comment_at(text, start, end, scalars)
                             or (last + 1 == len(rows) and _comment_at(text, end, line_end, scalars))):
                # Found by the review of #278: a comment above the next entry, or beside the
                # kept entry before the last ones, was deleted or moved onto another entry.
                raise ValueError("a comment in or beside the flow-style list entries to remove would "
                                 "be lost or moved to another entry")
            edits.append((start, end, ""))
        else:
            start = _dash(text, rows[index])
            end = _last_content(rows[last])
            if end > 0 and text[end - 1] != "\n":
                end = text.find("\n", end)
                end = end + 1 if end >= 0 else len(text)
            replacement = ""
            if len(indices) == len(rows):
                indent = sequence.start_mark.column
                replacement = " " * indent + "[]" + ("\r\n" if "\r\n" in text else "\n")
                # A top-level unindented sequence can follow a mapping key. Its empty
                # replacement is a flow scalar and needs at least one space of indentation.
                if indent == 0:
                    replacement = " " + replacement
            edits.append((start, end, replacement))
    return edits


def _dash(text, row):
    start = row.start_mark.index
    line = text.rfind("\n", 0, start) + 1
    if text[line:start].strip() != "-":
        raise ValueError("the ignore entry has no separate editable list marker")
    return line


def _splice(text, spans):
    limit = len(text)
    for start, end, value in sorted(spans, reverse=True):
        if end > limit:
            raise ValueError("the proposed text edits overlap")
        text = text[:start] + value + text[end:]
        limit = start
    return text


def _full_scope(root, options):
    # Only a check of the repository's own folder reads its Jenkinsfiles (checker.check's
    # `jenkins_sought`), so `.github` or `.github/workflows` is a partial check (review of #278).
    target = (root / options.path).resolve()
    return options.platform == "auto" and target.is_dir() and target == root


def _relative(root, path):
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("the paperwork file is outside the repository")
    return resolved.relative_to(root)


def _config_plan(root, result, owner, full, selected, items, refused):
    if not result.config.path:
        return None
    path = _relative(root, result.config.path)
    before = (root / path).read_bytes()
    text = before.decode("utf-8")
    doc = yaml.compose(text, Loader=yaml.SafeLoader)
    nodes = _mapping(doc)
    spans, keys, removed, added = [], [], [], []
    owners = []
    sequence = nodes.get("ignore")
    ignores = result.config.ignore
    drop = set()
    if ignores and (not isinstance(sequence, yaml.SequenceNode) or len(ignores) != len(sequence.value)):
        refused.append(f"{path}: ignore entries have no directly editable YAML sequence")
        ignores = []
    for i, entry in enumerate(ignores):
        matches = [f for f in result.findings if _matches(entry, f)]
        ident = f"ignore-{i}"
        label = _description(path, i, entry)
        if selected is not None and ident not in selected:
            continue
        row = sequence.value[i]
        if not matches:
            if not full:
                refused.append(f"{label}: a partial check cannot establish that this entry is stale")
                continue
            if not sequence.flow_style:
                try:
                    _dash(text, row)
                except ValueError as exc:
                    refused.append(f"{label}: {exc}")
                    continue
            drop.add(i)
            removed.append(("ignore", i))
            items.append(Item(ident, "removal", f"Remove unmatched ignore entry {i + 1} in {path}",
                              removals=(label,)))
            continue
        if entry.get("owner") is not None and not (isinstance(entry["owner"], str) and not entry["owner"].strip()):
            continue
        if not owner or not full:
            refused.append(f"{label}: completing an ignore needs --owner and a full repository check")
            continue
        made = acceptance.make(acceptance.IGNORE, owner, entry["reason"], entry["until"], result.today)
        if not made.valid:
            refused.append(f"{label}: {', '.join(made.problems)}")
            continue
        if any(sum(_matches(other, f) for other in ignores) != 1 for f in matches):
            refused.append(f"{label}: more than one ignore entry matches the same finding")
            continue
        if any(f.state in (ACCEPTED, FIXED) or not acceptance.acceptable(f) for f in matches):
            refused.append(f"{label}: a matching finding already has an acceptance, is fixed or cannot be accepted")
            continue
        owner_text = json.dumps(made.owner, ensure_ascii=True)
        fields = _mapping(row)
        if set(fields) != set(entry):
            refused.append(f"{label}: the mapping contains inherited fields")
            continue
        if "owner" in fields:
            node = fields["owner"]
            start, end = node.start_mark.index, node.end_mark.index
            replacement = " " + owner_text if start == end and text[:start].endswith(":") else owner_text
            spans.append((start, end, replacement))
        elif row.flow_style:
            offset = row.start_mark.index + 1
            spans.append((offset, offset, f"owner: {owner_text}, "))
        else:
            first = row.value[0][0].start_mark
            newline = "\r\n" if "\r\n" in text else "\n"
            spans.append((first.index, first.index, f"owner: {owner_text}{newline}" + " " * first.column))
        owners.append(i)
        items.append(Item(ident, "acceptance", f"Complete owner in {path} ignore entry {i + 1}",
                          tuple(_promise(f, made) for f in matches)))
    if drop:
        spans.extend(_delete_rows(text, sequence, drop))
    for i in owners:
        if "owner" in ignores[i]:
            removed.append(("ignore", i, "owner"))
        added.append(("ignore", i - sum(j < i for j in drop), "owner"))
    lanes = _mapping(nodes.get("lanes"))
    for i, (key, value) in enumerate(result.config.lanes.items()):
        ident = f"lane-{i}"
        if selected is not None and ident not in selected:
            continue
        if not isinstance(key, str) or workflow.declared_lane(value) is not None:
            continue
        matches = [f for f in result.findings if f.rule == checker.IDLE_DECLARATION
                   and f.kind == "entry-not-a-lane" and (f.facts or {}).get("entry") == workflow.bounded(key)]
        if not matches:
            continue
        if not full:
            # A job's lane can change findings in files a partial check does not read, such as
            # a workflow that calls it (review of #278).
            refused.append(f"{path} lane {key!r} ({value!r}): a partial check cannot establish "
                           "what the correction changes")
            continue
        targets = sorted(lane for lane in workflow.LANES if isinstance(value, str)
                         and _one_edit(value.strip().lower(), lane))
        if len(targets) != 1 or key not in lanes or not isinstance(lanes[key], yaml.ScalarNode):
            reason = "more than one lane is one edit away" if len(targets) > 1 else "no unique one-edit correction"
            refused.append(f"{path} lane {key!r} ({value!r}): {reason}")
            continue
        node = lanes[key]
        spans.append((node.start_mark.index, node.end_mark.index, targets[0]))
        keys.append(("lanes", key))
        items.append(Item(ident, "correction", f"Correct lane {key!r} from {value!r} to {targets[0]!r}",
                          tuple(_promise(f) for f in matches)))
    if not spans:
        return None
    after = _splice(text, spans)
    checker.Config.from_data(yamlutil.load(after) or {}, path)
    return Edit(path, before, after.encode(), tuple(keys), removed=tuple(removed), added=tuple(added))


def _baseline_plan(root, options, result, owner, reason, expires, full, selected, items, refused):
    if options.baseline is None:
        return None
    path = _relative(root, options.baseline)
    before = (root / path).read_bytes()
    old = baseline.load(root / path)
    doc = json.loads(before)
    # apply() returns entry objects from its own read. Match full values and count duplicates.
    stale = Counter(json.dumps(e, sort_keys=True) for e in result.baseline_stale)
    indices = set()
    for i in reversed(range(len(old.entries))):
        key = json.dumps(old.entries[i], sort_keys=True)
        if stale[key]:
            indices.add(i)
            stale[key] -= 1
    if old.legacy:
        ident = "baseline-migrate"
        if selected is not None and ident not in selected:
            return None
        made = acceptance.make(acceptance.BASELINE, owner, reason, expires, result.today)
        if not full or not made.valid:
            refused.append(f"{path}: migration needs a full repository check and valid --owner, --reason and --expires")
            return None
        covered = [f for f in result.findings if f.acceptance is not None and f.acceptance.source == acceptance.BASELINE]
        if ((old.entries and not covered) or len(covered) + len(indices) != len(old.entries)
                or any(not acceptance.acceptable(f) for f in covered)):
            refused.append(f"{path}: migration cannot account for every covered finding and unmatched entry")
            return None
        converted = json.loads(baseline.build(covered, None, made.owner, made.reason, made.expires))
        doc.update(converted)
        items.append(Item(ident, "acceptance", f"Convert {path} to {baseline.FORMAT}",
                          tuple(_promise(f, made) for f in covered),
                          tuple(_description(path, i, old.entries[i]) for i in sorted(indices))))
        return Edit(path, before, baseline.dumps(doc).encode(), tuple((k,) for k in converted))
    indices = {i for i in indices if selected is None or f"baseline-stale-{i}" in selected}
    if not indices:
        return None
    if not full:
        refused.append(f"{path}: a partial check cannot establish which baseline entries are stale")
        return None
    for i in sorted(indices):
        items.append(Item(f"baseline-stale-{i}", "removal", f"Remove unmatched baseline entry {i + 1} in {path}",
                          removals=(_description(path, i, old.entries[i]),)))
    text = before.decode()
    seq = _mapping(yaml.compose(text, Loader=yaml.SafeLoader))["findings"]
    after = _splice(text, _delete_rows(text, seq, indices, comments=False))
    return Edit(path, before, after.encode(), (), removed=tuple(("findings", i) for i in sorted(indices)))


def plan(root: Path, options: CheckOptions, result, *, owner=None, reason=None, expires=None, selected=None):
    """Plan from the pre-edit checker result including its requested baseline, without writing."""
    root = Path(root).resolve()
    items, refused, edits = [], [], []
    full = _full_scope(root, options)
    if result.errors or not result.files:
        return Paperwork((), (), (), ("A complete checker result with readable CI files is required.",))
    for generator, args in (
        (_config_plan, (root, result, owner, full)),
        (_baseline_plan, (root, options, result, owner, reason, expires, full)),
    ):
        generated = []
        try:
            edit = generator(*args, selected, generated, refused)
        except (ValueError, OSError, yaml.YAMLError, RecursionError, TypeError) as exc:
            refused.append(f"Could not prepare paperwork: {exc}")
            continue
        if edit is not None:
            edits.append(edit)
            items.extend(generated)
    return Paperwork(tuple(edits), tuple(p for item in items for p in item.promises), tuple(items),
                     tuple(workflow.one_line(line) for line in refused))
