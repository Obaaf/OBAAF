"""Draft one agent run step and check the draft without running the workflow."""

from datetime import date
import json
import re
import sys
import yaml

from obaaf import checker, yamlutil
from obaaf.catalog import load
from obaaf.checker import egress, workflow
from obaaf.checker.rules import WorkflowRules
from obaaf.fix import _paths
from obaaf.fix_copy import private_copy
from obaaf.fix_proof import check_copy_matches, check_inputs


def _job(copy, options, result, name):
    target = copy / options.path
    base = target.parent if target.is_file() else workflow.locate(target)[0]
    matches = []
    for rel in result.workflow_files:
        path = base / rel
        text = path.read_text(encoding="utf-8")
        wf = workflow.parse(rel, text)
        if name in wf.jobs:
            matches.append((path, text, wf.jobs[name]))
    if len(matches) != 1:
        raise ValueError(f"{len(matches)} workflows have that job ID. Select one workflow by path and its job ID.")
    return matches[0]


def _rewrite(job, text, name, catalog, agents, pin):
    if any(isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(text)):
        raise ValueError("workflow uses YAML aliases; review shared steps by hand")
    candidates = WorkflowRules(job.workflow, catalog, agents=agents).draft_agent_steps(job)
    if len(candidates) != 1:
        raise ValueError("the checker must recognise exactly one direct agent step; review this job by hand")
    step = candidates[0].raw
    if (not isinstance(step.get("run"), str) or set(step) - {"run", "id", "name", "if", "env",
                                                            "timeout-minutes", "continue-on-error"}
            or job.raw.get("defaults") or job.workflow.raw.get("defaults")):
        raise ValueError("only an ordinary run step with default shell and working directory can be drafted")
    env = step.get("env", {})
    if not isinstance(env, dict) or any(not isinstance(k, str) or not egress.NAME_RE.fullmatch(k) for k in env):
        raise ValueError("step env must list the variable names explicitly")
    proxy = [k for k in env if k in egress.MODEL_KEYS]
    passed = [k for k in env if k not in proxy]
    blocked = [k for k in passed if k.upper() in egress.WITHHELD_BY_AWF or egress.removed_before_inputs(k)]
    # The reserved name grants no real destination. The proxy reaches its own
    # provider API without also granting the command direct access to that host.
    inputs = {"allow": "replace-with-required-host.invalid", "run": step["run"]}
    if proxy:
        inputs["model-keys"] = " ".join(proxy)
    if passed:
        inputs["env"] = " ".join(passed)
    new = {k: v for k, v in step.items() if k != "run"}
    new.update(uses=f"Obaaf/OBAAF/actions/egress@{pin}", **{"with": inputs})

    def field(node, key):
        return next(value for k, value in node.value if k.value == key)

    doc = yaml.compose(text)
    steps = field(field(field(doc, "jobs"), name), "steps")
    raw_steps = job.raw["steps"]
    index = next(i for i, item in enumerate(raw_steps) if item is step)
    node = steps.value[index]
    start, end = node.start_mark.index, node.end_mark.index
    # A JSON object is a YAML flow mapping. Keep the surrounding document, including
    # indentation consumed by a block node's end mark, exactly as the checker saw it.
    tail = re.search(r"\s*\Z", text[start:end]).group()
    edited = text[:start] + json.dumps(new, ensure_ascii=True) + tail + text[end:]
    expected = yamlutil.load(text)
    expected["jobs"][name]["steps"][index] = new
    if yamlutil.load(edited) != expected:
        raise ValueError("could not preserve the surrounding workflow; review this job by hand")
    return edited, expected["jobs"][name], blocked, index


def run(args, catalog=None):
    if getattr(args, "settings", None) is not None:
        print("error: --settings is unsupported for egress drafts", file=sys.stderr)
        return 2
    catalog = catalog or load()
    pins = catalog.detection.get("egress_action_releases") or []
    if not pins:
        print("No released commit of the egress action is listed. Draft unavailable until #248 is approved.")
        return 0
    try:
        pin = pins[-1]
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{40}", pin):
            raise ValueError("the catalogue has no usable release pin")
        root, options = _paths(args)
        checker.parse_fail_on(options.fail_on)
        today = date.today()
        with private_copy(root) as copy:
            before = check_inputs(copy, options, today, catalog)
            check_copy_matches(root, check_inputs(root, options, today, catalog), before)
            path, text, job = _job(copy, options, before, args.job)
            edited, draft, blocked, index = _rewrite(job, text, args.job, catalog, before.config.agents, pin)
            path.write_text(edited, encoding="utf-8")
            after = check_inputs(copy, options, today, catalog)
            if args.brief:
                from obaaf.fix_egress_brief import work_order
                print(work_order(job, index, draft["steps"][index], blocked, options, after))
                return 0
            print("Draft only. Replace the reserved .invalid placeholder with required hosts. The checker "
                  "evaluates this exact placeholder list. If you adopt the draft, review the action's denied "
                  "output after a run. Under confinement, the command can write only to its scratch copy. "
                  "Each listed host and its subdomains are reachable, along with proxied provider APIs. "
                  "Other job secrets are unavailable unless passed in.")
            print("Only ANTHROPIC_API_KEY and OPENAI_API_KEY can be held by the proxy. If you pass another "
                  "provider key through env, the agent can read it. Review acceptance or use your own proxy.")
            if blocked:
                print("The action refuses these env names. Resolve their placement by hand: " + ", ".join(blocked))
            print("Use GitHub-hosted ubuntu-24.04 without a container. Keep credentials out of workflow and "
                  "job env and other steps. Remove OIDC and models permissions. List literal hosts with "
                  "no public suffix. Check steps that may run beside the agent.")
            print("Split later commit, comment or pull request steps into another job. Only artifact uploads "
                  "may follow the confined step.")
            print(f"Checked on a private copy of {job.workflow.path!r}, job {args.job!r}:")
            conditions = {}
            for rule in ("OBAAF-GHA-005", "OBAAF-GHA-020"):
                findings = [f for f in after.findings if f.path == job.workflow.path and f.job == args.job and f.rule == rule]
                if not findings:
                    print(f"{rule}: no finding reported")
                for f in findings:
                    print(f"{rule}: {f.state}")
                    for c in f.controls:
                        print(f"  {c.name}: {c.verdict}. {workflow.one_line(c.detail)}")
                        conditions.update(dict.fromkeys(c.action_conditions))
            if conditions:
                print("Conditions still requiring work on the egress action:")
                for condition in conditions:
                    print("  " + workflow.one_line(condition))
            # Convert the loader's annotated mappings to plain YAML data for display.
            print(yaml.safe_dump(json.loads(json.dumps({args.job: draft})), sort_keys=False), end="")
        return 0
    except (ValueError, OSError, StopIteration, TypeError, yaml.YAMLError) as error:
        if args.brief:
            print("Work order unavailable. Run the ordinary egress preview on a trusted branch "
                  "to inspect its diagnostic.", file=sys.stderr)
        else:
            print("Draft unavailable: " + workflow.one_line(str(error) or "unsupported workflow shape"), file=sys.stderr)
        return 2
