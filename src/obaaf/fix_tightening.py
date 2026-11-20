"""Plan requested one-step workflow edits from the checker's source evidence."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
import re
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


_PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
_NUMBER = r"(?:0|[1-9][0-9]*)"
_IDENTIFIERS = r"[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*"
_VERSION = re.compile(rf"({_NUMBER})\.({_NUMBER})\.({_NUMBER})(?:-({_IDENTIFIERS}))?(?:\+{_IDENTIFIERS})?")


def parse_pin(value):
    """An npm package and an exact SemVer accepted by node-semver's numeric limits."""
    package, _, version = value.partition("=")
    match = _VERSION.fullmatch(version) if len(version) <= 256 else None
    if not _PACKAGE.fullmatch(package) or len(package) > 214 or not match:
        raise ValueError("--pin needs PACKAGE=VERSION with an exact npm version, e.g. @openai/codex=1.2.3; "
                         "select a version by hand")
    if (any(int(n) > 2**53 - 1 for n in match.groups()[:3])
            or any(len(part) > 1 and part.startswith("0") and part.isdecimal()
                   for part in (match.group(4) or "").split("."))):
        raise ValueError("--pin needs an exact npm version with valid numeric components")
    return package, version


def _pin_patch(text, node, package, version):
    run = _fields(node).get("run")
    if not isinstance(run, yaml.ScalarNode) or getattr(run, "obaaf_shared", False):
        raise ValueError("the install is outside a directly written run scalar")
    # A folded YAML scalar can put the package on the next physical line. Locate
    # literal package tokens, then let the YAML reader establish which occurrence
    # corresponds to the package argument in the decoded install command.
    pattern = r"npm[ \t]+install[ \t]+-g[ \t]+" + re.escape(package)
    cooked = re.match(r"[ \t\r\n]*(?:sudo[ \t]+)?" + pattern + r"(?=\s|$)", run.value)
    if not cooked:
        raise ValueError("the decoded install no longer names the requested literal package")
    expected = run.value[:cooked.end()] + "@" + version + run.value[cooked.end():]
    start, end = run.start_mark.index, run.end_mark.index
    scalar = text[start:end]
    # Keep the column of the mapping key: explicit indentation indicators in block
    # scalars are relative to that column. A comment on the block header is outside
    # its content and cannot supply the install token.
    key = next(k for k, _ in node.value if k.value == "run")
    prefix = " " * key.start_mark.column + "run: "
    body = scalar.index("\n") + 1 if run.style in ("|", ">") else 0
    choices = []
    for occurrence in re.finditer(re.escape(package), scalar[body:]):
        offset = body + occurrence.end()
        patched = scalar[:offset] + "@" + version + scalar[offset:]
        try:
            decoded = yamlutil.load(prefix + patched)
        except yaml.YAMLError:
            continue
        if isinstance(decoded, dict) and decoded.get("run") == expected:
            choices.append(start + offset)
    if len(choices) != 1:
        raise ValueError("the package token cannot be identified uniquely in the literal install line")
    offset, = choices
    return (offset, offset, "@" + version), ("run",), expected


def _steps(text, path, pin):
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
                if ("run" if pin else "uses") not in _fields(node):
                    continue
            except ValueError:
                continue
            line = node.start_mark.line + 1
            if not isinstance(raw_steps[index], dict):
                continue
            step = workflow.Step(index, raw_steps[index], line)
            if pin or step.uses_action("actions/checkout"):
                output[job, line, step.name].append((index, node))
    return output, parsed


def _step_name(path, job, index):
    return f"{quote(path.as_posix(), safe='/')}#{quote(job, safe='')}/step-{index + 1}"


def _already_pinned(root, base, result, pin, candidate):
    """Report observed exact direct installs; never infer their version from a missing finding."""
    from obaaf.catalog import load
    from obaaf.checker.rules import WorkflowRules

    package, version = pin
    catalog = load()
    if package not in catalog.detection["agent_installs"]:
        return None
    direct = re.compile(r"[ \t\r\n]*(?:sudo[ \t]+)?npm[ \t]+install[ \t]+-g[ \t]+"
                        + re.escape(package) + r"(?P<suffix>@(?P<version>[^\s]+))")
    exact = []
    for name in result.workflow_files:
        path = (base / name).relative_to(root)
        try:
            steps, parsed = _steps((root / path).read_text(encoding="utf-8"), path, pin)
        except (ValueError, yaml.YAMLError):
            continue
        rules = WorkflowRules(parsed, catalog)
        for (job, line, _), locations in steps.items():
            if len(locations) != 1:
                continue
            index, node = locations[0]
            ident = _step_name(path, job, index)
            if candidate is not None and candidate != ident:
                continue
            run = _fields(node)["run"]
            if not isinstance(run, yaml.ScalarNode) or getattr(run, "obaaf_shared", False):
                continue
            match = direct.match(run.value)
            if not match:
                continue
            # Reuse the checker's shell, Windows-default and version-query eligibility
            # on an in-memory view of this step. No source file or finding changes.
            job_obj = parsed.jobs[job]
            step = workflow.Step(index, job_obj.raw["steps"][index], line)
            unpinned = run.value[:match.start("suffix")] + run.value[match.end("suffix"):]
            plain = replace(step, raw={**step.raw, "run": unpinned})
            shell = rules._shell(job_obj, step).strip().lower()
            windows = any("windows" in str(label).lower() for labels in (job_obj.runner_label_sets() or [])
                          for label in (labels or []))
            if rules._pin_candidate(plain, shell, windows) != package:
                continue
            if match["version"] != version:
                return None
            exact.append(ident)
    if not exact:
        return None
    if candidate is None:
        # A manual install may name the requested package even though its step has no
        # pin_candidate. The checker records the package in its installation facts.
        for f in result.findings:
            if f.rule != "OBAAF-GHA-025":
                continue
            facts = (f.facts or {}).get("installs", [])
            if f.pin_candidate == package or any(i.startswith(f"Agent CLI {package} is ") for i in facts):
                return None
    return f"Observed {package}@{version} in {', '.join(exact)}. Nothing to apply to those direct installs."


def plan(root, options, result, *, candidate=None, pin=None, selected=None):
    target = root / options.path
    base = target.parent if target.is_file() else workflow.locate(target)[0]
    rule = "OBAAF-GHA-025" if pin else "OBAAF-GHA-011"
    label = "install" if pin else "checkout"
    grouped = defaultdict(list)
    for finding in result.findings:
        if finding.rule == rule:
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
            # proposals available (review of #287: one Latin-1 workflow made every request exit 2).
            # A name in this file counts as known only for a job the checker reported here (the step
            # index cannot be checked without reading the file).
            named = candidate is not None and any(
                candidate.startswith(f"{quote(path.as_posix(), safe='/')}#{quote(f.job, safe='')}/step-")
                for f in findings if not pin or f.pin_candidate == pin[0])
            seen = seen or named
            if named or candidate is None:
                refused.append(f"{path}: review its {label}s by hand; the file is not UTF-8 text, so no edit "
                               "is offered")
            continue
        try:
            steps, _ = _steps(text, path, pin)
        except (ValueError, yaml.YAMLError):
            steps = {}
        spans, keys, expected_runs = [], [], []
        for finding in findings:
            if pin and finding.pin_candidate != pin[0]:
                if selected is None and candidate is None:
                    action = (f"select its package {finding.pin_candidate} and exact version separately"
                              if finding.pin_candidate else "review this install by hand; it is outside the supported direct npm form")
                    refused.append(f"{path}:{finding.line} {finding.job} {finding.step}: {action}")
                continue
            locations = steps[finding.job, finding.line, finding.step] if steps else []
            if len(locations) != 1:
                if candidate is None and selected is None:
                    refused.append(f"{path}:{finding.line}: review this {label} by hand; the checker could not "
                                   f"identify one directly written {label} step")
                continue
            index, node = locations[0]
            ident = _step_name(path, finding.job, index)
            if candidate is not None and ident != candidate:
                continue
            seen = True
            if selected is not None and ident not in selected:
                continue
            try:
                if pin:
                    span, suffix, expected = _pin_patch(text, node, *pin)
                    expected_runs.append((finding.job, index, expected))
                else:
                    span, suffix = _patch(text, node)
            except ValueError as exc:
                refused.append(f"{ident}: {exc}. Review the {label} by hand.")
                continue
            spans.append(span)
            keys.append(("jobs", finding.job, "steps", index, *suffix))
            promise = Promise(baseline.key(finding), finding.severity, finding.state, "gone")
            change = f"pin {pin[0]} to {pin[1]}" if pin else "set persist-credentials to false"
            items.append(Item(ident, "tightening", f"{ident}: {change}", (promise,)))
        if spans:
            changed = _splice(text, spans)
            if expected_runs:
                jobs = yamlutil.load(changed)["jobs"]
                if any(jobs[job]["steps"][i]["run"] != expected for job, i, expected in expected_runs):
                    raise ValueError(f"{path}: the textual edit did not produce exactly the requested package pin")
            edits.append(Edit(path, before, changed.encode(), tuple(keys)))
    settled = None
    if pin and not seen and selected is None:
        settled = _already_pinned(root, base, result, pin, candidate)
    if candidate is not None and not seen and settled is None:
        request = f"--pin {pin[0]}={pin[1]}" if pin else "--tighten checkout-credentials"
        raise ValueError(f"no reported {label} matches candidate {candidate!r}; rerun {request} to list names")
    if pin and not seen and selected is None and settled is None:
        refused.append(f"No eligible direct install of {pin[0]} was found in this check. Review other install forms by hand.")
    return Paperwork(tuple(edits), tuple(p for item in items for p in item.promises), tuple(items), tuple(refused), settled)
