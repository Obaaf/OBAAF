"""Plan explicit checkout credential tightening from the checker's reported steps."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import quote

import yaml

from obaaf import yamlutil
from obaaf.checker import baseline, workflow
from obaaf.fix_paperwork import Item, Paperwork, _splice
from obaaf.fix_proof import Edit, Promise


def _fields(node):
    if not isinstance(node, yaml.MappingNode) or getattr(node, "obaaf_shared", False):
        raise ValueError("the YAML mapping is absent or shared")
    if any(k.value == "<<" for k, _ in node.value):
        raise ValueError("the YAML mapping inherits keys")
    return {k.value: v for k, v in node.value}


def _flow_add(text, node, entry):
    end = node.end_mark.index - 1
    prefix = text[node.start_mark.index:end].rstrip()
    separator = "" if not node.value else (" " if prefix.endswith(",") else ", ")
    return end, end, separator + entry


def _patch(text, node):
    fields = _fields(node)
    key = "persist-credentials"
    newline = "\r\n" if "\r\n" in text else "\n"
    if "with" not in fields:
        value = "with: {persist-credentials: false}"
        if node.flow_style:
            span = _flow_add(text, node, value)
        else:
            # Insert one line after the uses scalar, retaining comments on the original line.
            uses = fields["uses"]
            if getattr(uses, "obaaf_shared", False) or uses.start_mark.line != uses.end_mark.line:
                raise ValueError("the uses scalar is shared or spans multiple lines")
            end = text.find("\n", uses.end_mark.index)
            indent = " " * node.value[0][0].start_mark.column
            if end < 0:
                span = (len(text), len(text), newline + indent + value)
            else:
                span = (end + 1, end + 1, indent + value + newline)
        return span, ("with",)

    inputs = fields["with"]
    input_fields = _fields(inputs)
    written = [k for k in input_fields if workflow.input_name(k) == key]
    if written:
        actual, = written
        value = input_fields[actual]
        if (not isinstance(value, yaml.ScalarNode) or getattr(value, "obaaf_shared", False)
                or value.start_mark.line != value.end_mark.line):
            raise ValueError("the existing input is shared or spans more than one line")
        start, end = value.start_mark.index, value.end_mark.index
        replacement = " false" if start == end and text[:start].endswith(":") else "false"
        return (start, end, replacement), ("with", actual)
    if inputs.flow_style:
        return _flow_add(text, inputs, key + ": false"), ("with", key)
    first = inputs.value[0][0].start_mark
    return (first.index, first.index, key + ": false" + newline + " " * first.column), ("with", key)


def _steps(text, path):
    doc = yaml.compose(text, Loader=yamlutil._Loader)
    jobs = _fields(_fields(doc).get("jobs"))
    parsed = workflow.parse(str(path), text)
    output = defaultdict(list)
    for job, raw in jobs.items():
        if job not in parsed.jobs:
            continue
        try:
            steps = _fields(raw).get("steps")
        except ValueError:
            continue
        if not isinstance(steps, yaml.SequenceNode) or getattr(steps, "obaaf_shared", False):
            continue
        raw_steps = parsed.jobs[job].raw.get("steps")
        if not isinstance(raw_steps, list) or len(raw_steps) != len(steps.value):
            continue
        for index, node in enumerate(steps.value):
            try:
                if "uses" not in _fields(node):
                    continue
            except ValueError:
                continue
            line = node.start_mark.line + 1
            if not isinstance(raw_steps[index], dict):
                continue
            step = workflow.Step(index, raw_steps[index], line)
            if step.uses_action("actions/checkout"):
                output[job, line, step.name].append((index, node))
    return output


def plan(root, options, result, *, candidate=None, selected=None):
    target = root / options.path
    base = target.parent if target.is_file() else workflow.locate(target)[0]
    grouped = defaultdict(list)
    for finding in result.findings:
        if finding.rule == "OBAAF-GHA-011":
            grouped[finding.path].append(finding)
    edits, items, refused = [], [], []
    seen = False
    for name, findings in grouped.items():
        path = (base / name).relative_to(root)
        before = (root / path).read_bytes()
        try:
            text = before.decode()
        except UnicodeDecodeError:
            # The checker reads such a file; an edit to it is not offered. Name it, and keep the other files'
            # checkouts available (review of #287: one Latin-1 workflow made every request exit 2).
            named = candidate is not None and candidate.startswith(quote(path.as_posix(), safe="/") + "#")
            seen = seen or named
            if named or candidate is None:
                refused.append(f"{path}: review its checkouts by hand; the file is not UTF-8 text, so no edit "
                               "is offered")
            continue
        try:
            steps = _steps(text, path)
        except (ValueError, yaml.YAMLError):
            steps = {}
        spans, keys = [], []
        for finding in findings:
            locations = steps[finding.job, finding.line, finding.step] if steps else []
            if len(locations) != 1:
                if candidate is None and selected is None:
                    refused.append(f"{path}:{finding.line}: review this checkout by hand; the checker could not "
                                   "identify one directly written checkout step")
                continue
            index, node = locations[0]
            ident = f"{quote(path.as_posix(), safe='/')}#{quote(finding.job, safe='')}/step-{index + 1}"
            if candidate is not None and ident != candidate:
                continue
            seen = True
            if selected is not None and ident not in selected:
                continue
            try:
                span, suffix = _patch(text, node)
            except ValueError as exc:
                refused.append(f"{ident}: {exc}. Review the checkout input by hand.")
                continue
            spans.append(span)
            keys.append(("jobs", finding.job, "steps", index, *suffix))
            promise = Promise(baseline.key(finding), finding.severity, finding.state, "gone")
            items.append(Item(ident, "tightening", f"{ident}: set persist-credentials to false", (promise,)))
        if spans:
            edits.append(Edit(path, before, _splice(text, spans).encode(), tuple(keys)))
    if candidate is not None and not seen:
        raise ValueError(f"no reported checkout matches candidate {candidate!r}; rerun --tighten checkout-credentials to list names")
    return Paperwork(tuple(edits), tuple(p for item in items for p in item.promises), tuple(items), tuple(refused))
