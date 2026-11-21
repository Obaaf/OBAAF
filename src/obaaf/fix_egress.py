"""Draft one agent run step and check the draft without running the workflow."""

from datetime import date
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
    if not matches:
        raise ValueError(f"no workflow checked here has a job with the ID {workflow.one_line(name, 80)!r}. "
                         "Give the ID under the workflow's jobs key.")
    if len(matches) != 1:
        raise ValueError(f"{len(matches)} workflows have that job ID. Select one workflow by path and its job ID.")
    return matches[0]


def _plain(value):
    """The loader's annotated mappings and lists as plain data. Dates, numbers and text are kept."""
    if isinstance(value, dict):
        return {_plain(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


class _DisplayDumper(yaml.SafeDumper):
    """Prints a script of several lines as a block, as it is usually written."""


def _text(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_DisplayDumper.add_representer(str, _text)


def _needs_escapes(value):
    """Whether any text in `value` holds a character other than a line feed or tab that Python does
    not count as printable."""
    if isinstance(value, str):
        return any(c not in "\n\t" and not c.isprintable() for c in value)
    if isinstance(value, dict):
        return any(_needs_escapes(k) or _needs_escapes(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_needs_escapes(v) for v in value)
    return False


def _flow(data):
    """One line of YAML for `data`. PyYAML escapes what YAML cannot hold as it is (a character outside
    the Basic Multilingual Plane as one `\\U` escape, the Unicode line separators), quotes text that would
    read as another type, and writes dates as dates. Review of A3a (review-gpt #283): the JSON written
    here before split an emoji into two halves that YAML reads as two characters, and refused a date."""
    return yaml.dump(data, Dumper=yaml.SafeDumper, default_flow_style=True, width=float("inf"),
                     allow_unicode=False, sort_keys=False).rstrip("\n")


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
    env = step.get("env")
    env = {} if env is None else env     # `env:` with no value names nothing
    if not isinstance(env, dict) or any(not isinstance(k, str) or not egress.NAME_RE.fullmatch(k) for k in env):
        raise ValueError("step env must list the variable names explicitly")
    proxy = [k for k in env if k in egress.MODEL_KEYS]
    passed = [k for k in env if k not in proxy]
    # The names the action refuses under `env`, matched as the action matches them: exactly, by its
    # lists (review of A3a: `GITHUB_PAT`'s lower-case spelling was named here though the action takes it,
    # and `NODE_OPTIONS` or `ANTHROPIC_BASE_URL` were not, though the action refuses them).
    blocked = [k for k in passed if k in egress.WITHHELD_BY_AWF or egress.removed_before_inputs(k)
               or egress.reserved_under_env(k)]
    # The action also refuses a value holding a line break or NUL, which AWF's environment file cannot
    # carry (second review pass: a prompt written as a block in `env` was drafted without a word).
    broken = [k for k in passed if k not in blocked and isinstance(env[k], str)
              and any(c in env[k] for c in "\n\r\0")]
    # The reserved name grants no real destination. The proxy reaches its own
    # provider API without also granting the command direct access to that host.
    inputs = {"allow": "replace-with-required-host.invalid", "run": step["run"]}
    if proxy:
        inputs["model-keys"] = " ".join(proxy)
    if passed:
        inputs["env"] = " ".join(passed)
    new = {k: v for k, v in step.items() if k != "run"}
    new.update(uses=f"Obaaf/OBAAF/actions/egress@{pin}", **{"with": inputs})
    new = _plain(new)

    def field(node, key):
        return next(value for k, value in node.value if k.value == key)

    doc = yaml.compose(text)
    steps = field(field(field(doc, "jobs"), name), "steps")
    raw_steps = job.raw["steps"]
    index = next(i for i, item in enumerate(raw_steps) if item is step)
    node = steps.value[index]
    start, end = node.start_mark.index, node.end_mark.index
    # A flow mapping on one line. Keep the surrounding document, including
    # indentation consumed by a block node's end mark, exactly as the checker saw it.
    tail = re.search(r"\s*\Z", text[start:end]).group()
    edited = text[:start] + _flow(new) + tail + text[end:]
    expected = yamlutil.load(text)
    expected["jobs"][name]["steps"][index] = new
    if yamlutil.load(edited) != expected:
        raise ValueError("could not preserve the surrounding workflow; review this job by hand")
    return edited, _plain(expected["jobs"][name]), blocked, broken, index


def run(args, catalog=None):
    if getattr(args, "settings", None) is not None:
        print("error: --settings is unsupported for egress drafts", file=sys.stderr)
        return 2
    catalog = catalog or load()
    pins = catalog.detection.get("egress_action_releases") or []
    if not pins:
        print("No released commit of the egress action is listed in the installed catalogue. Draft unavailable.")
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
            edited, draft, blocked, broken, index = _rewrite(job, text, args.job, catalog, before.config.agents, pin)
            path.write_text(edited, encoding="utf-8")
            after = check_inputs(copy, options, today, catalog)
        if getattr(args, "brief", False):
            from obaaf.fix_egress_brief import work_order
            print(work_order(job, index, draft["steps"][index], blocked, broken, options, after))
            return 0
        shown = path.relative_to(copy).as_posix()
        # Everything is worked out before anything is printed, so a refusal prints only itself
        # (review of A3a: a date in the job printed the verdicts and then refused).
        # Escapes for the whole job when any text holds a character Python does not count as printable
        # (a direction override, a zero-width space, U+0085, a private-use character): printed as it
        # is, it could make a script read otherwise, or read back as other text (second review pass).
        draft_text = yaml.dump({args.job: draft}, Dumper=_DisplayDumper, sort_keys=False,
                               allow_unicode=not _needs_escapes(draft))
        lines = [
            "Draft only. Replace the reserved .invalid placeholder with required hosts. The checker "
            "evaluates this exact placeholder list. If you adopt the draft, review the action's denied "
            "output after a run. Under confinement, the command's writes stay in the action's scratch "
            "directory, it reaches only the listed hosts, their subdomains and the proxied provider APIs, "
            "and it sees none of the runner's environment except the variables named under env. It can still read its copy of "
            "the workspace and the runner's /tmp; docs/egress-control.md lists what it can still do.",
            "Only ANTHROPIC_API_KEY and OPENAI_API_KEY can be held by the proxy. If you pass another "
            "provider key through env, the agent can read it. Review acceptance or use your own proxy.",
        ]
        if blocked:
            lines.append("The action refuses these env names. Resolve their placement by hand: " + ", ".join(blocked))
        if broken:
            lines.append("The action refuses an env value that holds a line break or NUL, so it would not run "
                         "with these as written, and the checker's verdicts below do not show it, because the checker "
                         "does not read env values. Pass them another way, for example in a file: " + ", ".join(broken))
        lines += [
            "For the checker to verify the egress control, the job runs on GitHub-hosted ubuntu-24.04 "
            "without a container; no other step and no job or workflow env holds a credential; the job "
            "cannot request OIDC tokens or the models permission; the allow-list holds literal hosts with "
            "no public suffix; and only artifact uploads follow the confined step (move later commit, "
            "comment or pull request steps to another job). The conditions this job does not meet are "
            "listed below.",
            f"Checked on a private copy of {shown!r}, job {args.job!r}:",
        ]
        conditions = {}
        for rule in ("OBAAF-GHA-005", "OBAAF-GHA-020"):
            findings = [f for f in after.findings if f.path == job.workflow.path and f.job == args.job and f.rule == rule]
            if not findings:
                lines.append(f"{rule}: no finding reported")
            for f in findings:
                lines.append(f"{rule}: {f.state}")
                for c in f.controls:
                    lines.append(f"  {c.name}: {c.verdict}. {workflow.one_line(c.detail)}")
                    conditions.update(dict.fromkeys(c.action_conditions))
        if conditions:
            lines.append("Conditions still requiring work on the egress action:")
            lines += ["  " + workflow.one_line(condition) for condition in conditions]
        print("\n".join(lines))
        print(draft_text, end="")
        return 0
    except (ValueError, OSError, StopIteration, TypeError, yaml.YAMLError) as error:
        if getattr(args, "brief", False):
            print("Work order unavailable. Run the ordinary egress preview on a trusted branch "
                  "to inspect its diagnostic.", file=sys.stderr)
            return 2
        print("Draft unavailable: " + workflow.one_line(str(error) or "unsupported workflow shape"), file=sys.stderr)
        return 2
