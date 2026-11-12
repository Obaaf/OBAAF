"""The settings audit's report for people. The JSON output is the snapshot itself.

The report leads with what was not read, because that is where a reader is most likely to assume more than
the audit knows. Everything that comes from GitHub or from a snapshot file passes through ``plain`` or
``quoted`` on its way to the terminal, numbers included: a snapshot file can hold anything.
"""

from __future__ import annotations

from obaaf.audit.github import plain, quoted
from obaaf.audit.settings import BY_KEY, SETTINGS

HEADINGS = (("unread", "NOT READ"), ("partial", "PARTLY READ"), ("read", "READ"),
            ("not_applicable", "DOES NOT APPLY"))
CHECKS_SHOWN = 30  # required checks named in one line before "and N more"; the snapshot always has them all


def counts(snapshot: dict) -> dict[str, int]:
    out = {status: 0 for status, _ in HEADINGS}
    for entry in snapshot["settings"].values():
        out[entry["status"]] += 1
    return out


def unread_keys(snapshot: dict) -> list[str]:
    """Settings that apply to the repository and were not read in full."""
    return [s.key for s in SETTINGS if snapshot["settings"][s.key]["status"] in ("unread", "partial")]


def _list(items, limit: int = 8) -> str:
    items = [plain(i, 60) for i in items]
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _join(texts, limit: int = 12) -> str:
    """Join texts this module composed itself. Each is already safe to print, and none is cut again: a rule
    such as the required checks names several things, and cutting it would hide some of them."""
    texts = list(texts)
    return ", ".join(texts[:limit]) + (f" and {len(texts) - limit} more" if len(texts) > limit else "")


def _count(n, noun: str, plural: str | None = None) -> str:
    return f"{plain(n, 20)} {noun if n == 1 else (plural or noun + 's')}"


def _yes(value) -> str:
    return {True: "yes", False: "no"}.get(value, "not given")


def _rule_text(rule: dict) -> str:
    parameters = rule.get("parameters") or {}
    kind = rule.get("type")
    if kind == "pull_request" and isinstance(parameters.get("required_approving_review_count"), int):
        return f"pull_request ({_count(parameters['required_approving_review_count'], 'approval')})"
    if kind == "required_status_checks" and isinstance(parameters.get("required_status_checks"), list):
        names = [c.get("context", "?") for c in parameters["required_status_checks"] if isinstance(c, dict)]
        return f"required_status_checks ({_list(names, CHECKS_SHOWN) if names else 'none named'})"
    return plain(kind, 60)


def _policy_rule_text(rule: dict) -> str:
    parameters = rule.get("parameters") or {}
    if isinstance(parameters.get("allowed_events"), list):
        return "only these events may start a workflow: " + (_list(parameters["allowed_events"], 12) or "none")
    if isinstance(parameters.get("allowed_actors"), list):
        return f"only {_count(len(parameters['allowed_actors']), 'listed actor')} may start a workflow"
    return plain(rule.get("type"), 60)


def _workflow_paths(conditions) -> str:
    paths = ((conditions or {}).get("workflow_path") or {}).get("include") if isinstance(conditions, dict) else None
    return f" for {_list(paths)}" if isinstance(paths, list) and paths else ""


def _source(item: dict) -> str:
    return f"{plain(item['source_type'] or 'a source not given', 20)} {plain(item['source'] or '', 60)}".strip()


def _check_names(checks: dict) -> str:
    names = sorted(set(checks["contexts"]) | {c["context"] for c in checks["checks"] or []})
    return f"required checks: {_list(names, CHECKS_SHOWN)}" if names else "required checks: none named"


def _ruleset_names(settings: dict) -> dict:
    value = settings.get("rulesets", {}).get("value")
    try:
        return {r["id"]: r["name"] for r in value or []}
    except (KeyError, TypeError):
        return {}


def _classic_text(rule: dict) -> str:
    if not rule["exists"]:
        return "no classic protection rule"
    reviews, checks = rule["required_pull_request_reviews"], rule["required_status_checks"]
    if not reviews["required"]:
        approvals = "no review required"
    elif reviews["required_approving_review_count"] is None:
        approvals = "review required (the number of approvals was not given)"
    else:
        approvals = _count(reviews["required_approving_review_count"], "approval") + " required"
    admins = "administrators are held to it" if rule["enforce_admins"] else "administrators are not held to it"
    return f"{approvals}; {_check_names(checks) if checks['required'] else 'no required checks'}; {admins}"


def _environment_text(env: dict) -> str:
    if env["deployment_branches"] == "any":
        branches = "any branch or tag may deploy"
    elif env["deployment_branches"] == "protected":
        branches = "only protected branches may deploy"
    elif env["branch_policies"] is None:
        branches = "only selected branches or tags may deploy (the patterns were not read)"
    else:
        # A pattern is for branches or for tags, and the same text means different things: "v*" as a tag
        # pattern admits a release tag, as a branch pattern it admits any branch someone names v-something.
        branches = "may deploy: " + (_list([f"{p['type'] or 'pattern'} {p['name']}" for p in env["branch_policies"]])
                                     if env["branch_policies"] else "nothing (no pattern is set)")
    if not env["reviewers"]:
        review = "no required reviewers"
    else:
        review = "reviewers: " + _list([r["name"] for r in env["reviewers"]])
        review += {True: " (self-review prevented)", False: " (self-review allowed)"}.get(
            env["prevent_self_review"], "")
    wait = f"; wait {plain(env['wait_timer'], 10)} min" if env["wait_timer"] else ""
    other = f"; other rules: {_list(env['other_protection_rules'])}" if env["other_protection_rules"] else ""
    # GitHub's setting "Allow administrators to bypass configured protection rules", as it gives it. It is
    # said only where there is a reviewer, a wait or another rule for an administrator to bypass.
    bypass = ""
    if env["reviewers"] or env["wait_timer"] or env["other_protection_rules"]:
        bypass = "; administrators may bypass these rules: " + {True: "yes", False: "no"}.get(
            env.get("can_admins_bypass"), "not given")
    return f"{quoted(env['name'])}: {branches}; {review}{wait}{other}{bypass}"


def _describe(key: str, value, settings: dict) -> list[str]:  # noqa: C901 - one branch per setting, kept flat
    if key == "repository":
        owner_kind = {"Organization": "the organisation", "User": "the user"}.get(value["owner_type"], "")
        extra = (", a fork" if value["fork"] else "") + (", archived" if value["archived"] else "")
        return [f"{plain(value['visibility'], 20)} repository, default branch {plain(value['default_branch'], 80)}, "
                f"owned by {owner_kind} {plain(value['owner'], 40)}{extra}".replace("  ", " ")]
    if key == "rulesets":
        if not value:
            return ["no ruleset applies to this repository"]
        return [f"{quoted(r['name'])} ({plain(r['enforcement'], 20)}, {plain(r['target'] or 'target not given', 20)}, "
                f"from {_source(r)}): " + (_join(_rule_text(x) for x in r["rules"]) if r["rules"] else "no rules")
                for r in value]
    if key == "ruleset_bypass_actors":
        names = _ruleset_names(settings)
        lines = []
        for entry in value:
            who = _list([f"{a['actor_type']}{'' if a['actor_id'] is None else ' ' + str(a['actor_id'])} "
                         f"({a['bypass_mode'] or 'mode not given'})" for a in entry["actors"]])
            name = f" {quoted(names[entry['ruleset_id']])}" if entry["ruleset_id"] in names else ""
            lines.append(f"ruleset {plain(entry['ruleset_id'], 20)}{name}: {who}")
        return lines or ["no ruleset's bypass list was read"]
    if key == "branch_rules":
        return [f"{plain(branch, 80)}: " + (_join(_rule_text(r) for r in rules) if rules else "no active rule")
                for branch, rules in value.items()]
    if key == "branches":
        lines = []
        for branch, entry in value.items():
            shown = entry["public_protection"]
            checks = shown["required_status_checks"] if shown else None
            named = bool(checks) and bool(checks["contexts"] or checks["checks"])
            # This view shows the checks of a classic protection rule only. Checks a ruleset requires are
            # under the rules in force, so an empty list here is "none shown", not "none required".
            lines.append(f"{plain(branch, 80)}: GitHub calls it {'protected' if entry['protected'] else 'not protected'}; "
                         + (_check_names(checks) if named else "no required checks shown in this view"))
        return lines
    if key == "branch_protection":
        return [f"{plain(branch, 80)}: {_classic_text(rule)}" for branch, rule in value.items()]
    if key == "environments":
        return [_environment_text(env) for env in value] or ["the repository has no environments"]
    if key == "environment_secrets":
        return [f"{quoted(name)}: " + (_list(secrets, 12) if secrets else "no secrets")
                for name, secrets in value.items()]
    if key in ("repository_secrets", "organization_secrets"):
        return [_list(value, 12) if value else "none"]
    if key == "actions_permissions":
        if not value["enabled"]:
            return ["GitHub Actions is turned off for this repository"]
        allowed = plain(value["allowed_actions"] or "not given", 20)
        if value["allowed_actions"] == "selected":
            selected = value["selected_actions"]
            allowed += " (the list was not read)" if selected is None else (
                f" (GitHub's own: {_yes(selected['github_owned_allowed'])}, verified creators: "
                f"{_yes(selected['verified_allowed'])}, {_count(len(selected['patterns_allowed']), 'pattern')})")
        return [f"allowed actions: {allowed}; pinning to a commit required: {_yes(value['sha_pinning_required'])}"]
    if key == "workflow_permissions":
        return [f"the workflow token defaults to {plain(value['default_workflow_permissions'], 20)}; workflows "
                f"{'may' if value['can_approve_pull_request_reviews'] else 'may not'} approve pull requests"]
    if key == "fork_pull_requests":
        line = f"approval is required for: {plain(value['approval_policy'], 60)}"
        if "private_repository" in value:
            private = value["private_repository"]
            line += "; on this private repository, " + (
                "the settings for fork pull requests were not read" if private is None else
                "fork pull requests do not run workflows" if not private["run_workflows_from_fork_pull_requests"] else
                f"fork pull requests run workflows (write tokens: {_yes(private['send_write_tokens_to_workflows'])}, "
                f"secrets: {_yes(private['send_secrets_and_variables'])})")
        return [line]
    if key == "actions_policies":
        if not value:
            return ["no Actions policy was listed for this repository"]
        return [f"{quoted(p['name'])} ({plain(p['enforcement'], 20)}, from {_source(p)})"
                f"{_workflow_paths(p['conditions'])}: "
                + ("; ".join(_policy_rule_text(r) for r in p["rules"]) or "no rules")
                for p in value]
    if key == "collaborators":
        roles = ", ".join(f"{plain(n, 20)} {role}" for role, n in value["by_role"].items()
                          if n and role in ("admin", "maintain", "write", "triage", "read"))
        return [f"{_count(value['total'], 'account')}" + (f": {roles}" if roles else "")]
    return [plain(value, 300)]


def to_text(snapshot: dict, origin: str = "") -> str:
    settings = snapshot["settings"]
    total = len(SETTINGS)
    tally = counts(snapshot)
    how = "with a token" if snapshot["viewer"].get("authenticated") else "without a token"
    lines = [f"Settings audit of {plain(snapshot['repository'], 140)}",
             origin or f"Read {when(snapshot)} from {plain(snapshot['api'], 100)}, {how}."]
    if snapshot.get("requested_as"):
        lines.append(f"Asked for as {plain(snapshot['requested_as'], 140)}; GitHub now calls it "
                     f"{plain(snapshot['repository'], 140)}.")
    lines.append("This command reads and records settings. It does not judge them yet: no rule runs on what it "
                 "read.")
    for status, heading in HEADINGS:
        chosen = [s for s in SETTINGS if settings[s.key]["status"] == status]
        if not chosen:
            continue
        lines.append("")
        suffix = {"unread": ". Nothing is known about these; they were not checked.",
                  "partial": ". What is missing is listed under each."}.get(status, "")
        lines.append(f"{heading}: {len(chosen)} of {total}{suffix}")
        if status == "unread":
            no_token = [s for s in chosen if settings[s.key]["reason_code"] == "no_token"]
            chosen = [s for s in chosen if s not in no_token]
            if no_token:
                lines.append("  Not requested, because no token was given and GitHub does not show these without one. "
                             "Each is followed by what GitHub's reference says a token needs:")
                width = max(len(s.title) for s in no_token)
                lines += [f"    {s.title:<{width}}  {plain(settings[s.key]['needs'], 200)}" for s in no_token]
                lines += [f"    {s.title}: {s.note}" for s in no_token if s.note]
        for setting in chosen:
            entry = settings[setting.key]
            lines.append(f"  {setting.title}")
            if status == "unread":
                lines.append(f"      Why: {plain(entry['reason'], 400)}")
                lines.append(f"      GitHub's reference says it needs: {plain(entry['needs'], 300)}")
                if entry.get("accepted_permissions"):
                    lines.append(f"      GitHub said it would accept: {plain(entry['accepted_permissions'], 200)}")
                if setting.note:
                    lines.append(f"      {setting.note}")
                continue
            if status == "not_applicable":
                lines.append(f"      {plain(entry['reason'], 300)}")
                continue
            try:
                described = _describe(setting.key, entry["value"], settings)
            except (KeyError, TypeError, AttributeError, IndexError, ValueError):
                # A loaded snapshot has been checked against the schema, so this should not happen; if it
                # does, the value is shown as not describable rather than guessed at.
                described = ["recorded, but not in a form this version can describe"]
            lines += [f"      {line}" for line in described]
            for problem in entry.get("problems", []):
                lines.append(f"      NOT READ: {plain(problem['what'], 160)}: {plain(problem['reason'], 400)}")
            if status == "partial" and setting.note:
                lines.append(f"      {setting.note}")
    lines.append("")
    requests = snapshot["requests"]
    lines.append(f"{total} settings: {tally['read']} read, {tally['partial']} partly read, {tally['unread']} not read, "
                 f"{tally['not_applicable']} that do not apply. {_count(len(requests), 'request')} sent, all GET.")
    return "\n".join(lines) + "\n"


def when(snapshot: dict) -> str:
    stamp = str(snapshot.get("taken_at", ""))
    return plain(f"{stamp[:10]} {stamp[11:16]} UTC" if len(stamp) == 20 else stamp, 40)


def why_unread(snapshot: dict) -> str:
    """One line for the case where not even the repository could be read."""
    entry = snapshot["settings"]["repository"]
    return f"{BY_KEY['repository'].title} could not be read: {plain(entry.get('reason', ''), 400)}"
