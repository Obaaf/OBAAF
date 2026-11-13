"""The settings audit's report for people.

The report begins with what the rules found and what they could not tell, then lists what was read. That
list leads with what was not read, because that is where a reader is most likely to assume more than the
audit knows. Everything that comes from GitHub or from a snapshot file passes through ``plain`` or
``quoted`` on its way to the terminal, numbers included: a snapshot file can hold anything.
"""

from __future__ import annotations

from obaaf.audit.github import plain, quoted
from obaaf.audit.settings import BY_KEY, SETTINGS

HEADINGS = (("unread", "NOT READ"), ("partial", "PARTLY READ"), ("read", "READ"),
            ("not_applicable", "DOES NOT APPLY"))
CHECKS_SHOWN = 30  # required checks named in one line before "and N more"; the snapshot always has them all
# A rule's note says what it compared. The longest the rules can write, OBAAF-SET-005's with two branch names of
# 40 characters in each of its clauses, is about 475 characters.
NOTE_LIMIT = 600


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


def _join(texts, limit: int = 30) -> str:
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
    approvals = parameters.get("required_approving_review_count")
    if kind == "pull_request" and isinstance(approvals, int) and not isinstance(approvals, bool):
        return f"pull_request ({_count(approvals, 'approval')})"
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
    """The workflow files a policy names, if its conditions have the usual shape; otherwise nothing is said."""
    scope = conditions.get("workflow_path") if isinstance(conditions, dict) else None
    paths = scope.get("include") if isinstance(scope, dict) else None
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
    else:
        count, allowed = reviews["required_approving_review_count"], reviews["bypass_allowances"]
        approvals = ("review required, number of approvals not given" if count is None
                     else _count(count, "approval") + " required")
        if allowed is None:
            approvals += ", who may bypass it not given"
        else:
            # A group GitHub did not list is null, which is "not known", not "nobody".
            unknown = [group for group in ("users", "teams", "apps") if allowed[group] is None]
            named = sum(len(allowed[group] or []) for group in ("users", "teams", "apps"))
            if len(unknown) == 3:
                approvals += ", who may bypass it not given"
            else:
                approvals += f", {_count(named, 'name')} may bypass it" if named else ", nobody listed may bypass it"
                approvals += f" ({', '.join(unknown)} not given)" if unknown else ""
    admins = "administrators are held to it" if rule["enforce_admins"] else "administrators are not held to it"
    force = {True: "; force pushes allowed", None: "; force pushes: not given"}.get(rule["allow_force_pushes"], "")
    return f"{approvals}; {_check_names(checks) if checks['required'] else 'no required checks'}; {admins}{force}"


def _environment_text(env: dict) -> str:
    if env["deployment_branches"] == "any":
        branches = "any branch or tag may deploy"
    elif env["deployment_branches"] == "protected":
        # GitHub's setting, in its words. What it lets through depends on which branches have a protection
        # rule, which this line does not judge.
        branches = "only branches GitHub counts as protected may deploy"
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
        bypass = "; administrators may bypass these rules: " + _yes(env["can_admins_bypass"])
    return f"{quoted(env['name'])}: {branches}; {review}{wait}{other}{bypass}"


def _describe(key: str, value, settings: dict, whole: bool = True) -> list[str]:  # noqa: C901 - kept flat
    """What was read of one setting. ``whole`` is false for a setting that was only partly read: an empty
    value then means that nothing of it was read, and must not be worded as "there is none"."""
    if key == "repository":
        owner_kind = {"Organization": "the organisation", "User": "the user"}.get(value["owner_type"], "")
        extra = (", a fork" if value["fork"] else "") + (", archived" if value["archived"] else "")
        return [f"{plain(value['visibility'], 20)} repository, default branch {plain(value['default_branch'], 80)}, "
                f"owned by {owner_kind} {plain(value['owner'], 40)}{extra}".replace("  ", " ")]
    if key == "rulesets":
        if not value:
            return ["no ruleset applies to this repository" if whole else "no ruleset was read"]
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
        return [f"{quoted(branch, 80)}: " + (_join(_rule_text(r) for r in rules) if rules else "no active rule")
                for branch, rules in value.items()]
    if key == "branches":
        lines = []
        for branch, entry in value.items():
            shown = entry["public_protection"]
            checks = shown["required_status_checks"] if shown else None
            named = bool(checks) and bool(checks["contexts"] or checks["checks"])
            # This view shows the checks of a classic protection rule only. Checks a ruleset requires are
            # under the rules in force, so an empty list here is "none shown", not "none required". A list
            # can also be shown for a rule that is switched off, so the enforcement level is said with it.
            level = f" (enforcement: {plain(checks['enforcement_level'] or 'not given', 20)})" if named else ""
            lines.append(f"{quoted(branch, 80)}: GitHub calls it {'protected' if entry['protected'] else 'not protected'}; "
                         + (_check_names(checks) + level if named else "no required checks shown in this view"))
        return lines
    if key == "branch_protection":
        return [f"{quoted(branch, 80)}: {_classic_text(rule)}" for branch, rule in value.items()]
    if key == "environments":
        return [_environment_text(env) for env in value] or [
            "the repository has no environments" if whole else "no environment was read"]
    if key == "environment_secrets":
        return [f"{quoted(name)}: " + (_list(secrets, 12) if secrets else "no secrets")
                for name, secrets in value.items()]
    if key in ("repository_secrets", "organization_secrets"):
        return [_list(value, 12) if value else "none" if whole else "none was read"]
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
            return ["no Actions policy was listed for this repository" if whole else "no Actions policy was read"]
        return [f"{quoted(p['name'])} ({plain(p['enforcement'], 20)}, from {_source(p)})"
                f"{_workflow_paths(p['conditions'])}: "
                + ("; ".join(_policy_rule_text(r) for r in p["rules"]) or "no rules")
                for p in value]
    if key == "collaborators":
        roles = ", ".join(f"{plain(n, 20)} {role}" for role, n in value["by_role"].items()
                          if n and role in ("admin", "maintain", "write", "triage", "read"))
        return [f"{_count(value['total'], 'account')}" + (f": {roles}" if roles else "")]
    return [plain(value, 300)]


SEVERITY_LABEL = {"high": "HIGH  ", "medium": "MEDIUM", "low": "LOW   "}
RULE_STATUS = {"findings": "", "cannot-tell": "cannot tell", "no-finding": "no finding",
               "not-applicable": "does not apply"}


def _usage_line(usage: dict) -> str:
    if not usage["read"]:
        return (f"The workflow files were not read: {plain(usage['reason'], 300)}. The twelve rules that compare "
                "a setting with what the workflows use answer \"cannot tell\"; OBAAF-SET-004, OBAAF-SET-005 and "
                "OBAAF-SET-013 read settings only and do not need the files.")
    files = usage["files"]
    unread = sum(1 for file in files if file["error"])
    line = f"Compared with {_count(len(files) - unread, 'workflow file')} in the directory {quoted(usage.get('shown') or '.', 200)}"
    if unread:
        line += f" ({_count(unread, 'more')} could not be read)"
    config = usage.get("config")
    if config:
        line += f" and the configuration {plain(config['path'], 100)}"
    line += "."
    if usage.get("config_error"):
        line += f" The checker's configuration could not be read: {plain(usage['config_error'], 300)}."
    if usage.get("note"):
        line += f" {plain(usage['note'], 300)}"
    return line


def findings_lines(assessment: dict, show_fixes: bool = True) -> list[str]:
    """The rules' part of the report: findings first, then what the rules could not tell, then one line
    for every rule, so that a rule that found nothing is never mistaken for a rule that did not run."""
    from obaaf.audit.rules import RULE_BY_ID

    summary, results = assessment["summary"], assessment["results"]
    lines = [f"FINDINGS: {summary['findings']} ({summary['high']} high, {summary['medium']} medium, "
             f"{summary['low']} low). CANNOT TELL: {summary['cannot_tell']}, from {summary['rules_cannot_tell']} of "
             f"{len(assessment['rules'])} rules. \"Cannot tell\" is never a pass: nothing is established there."]
    found = [r for r in results if r["state"] == "finding"]
    order = []
    for result in found:  # already sorted by severity; a rule's findings are kept together under its first
        if result["rule"] not in order:
            order.append(result["rule"])
    for rule_id in order:
        rule = RULE_BY_ID[rule_id]
        lines.append("")
        lines.append(f"  {rule.id}  {rule.title}")
        for result in (r for r in found if r["rule"] == rule_id):
            lines.append(f"    {SEVERITY_LABEL[result['severity']]}  {plain(result['subject'], 300)}")
            lines.append(f"            {plain(result['message'], 1500)}")
            lines += [f"            {plain(item, 400)}" for item in result["evidence"]]
        if show_fixes:
            lines.append(f"    Fix: {rule.fix}")
    unknown = [r for r in results if r["state"] == "cannot-tell"]
    if unknown:
        lines.append("")
        lines.append(f"CANNOT TELL: {len(unknown)}. A setting or a file the rule needs was not read, or was not "
                     "in a form the rule understands.")
        for rule_id in dict.fromkeys(r["rule"] for r in unknown):
            lines.append(f"  {rule_id}  {RULE_BY_ID[rule_id].title}")
            for result in (r for r in unknown if r["rule"] == rule_id):
                lines.append(f"    CANNOT TELL  {plain(result['subject'], 300)}")
                lines.append(f"            {plain(result['message'], 1500)}")
    lines.append("")
    lines.append(f"RULES: {len(assessment['rules'])}, one line each. A rule with no finding says what it compared, or "
                 "why it had nothing to compare.")
    for entry in assessment["rules"]:
        parts = []
        if entry["findings"]:
            parts.append(_count(entry["findings"], "finding"))
        if entry["cannot_tell"]:
            parts.append(f"cannot tell ({entry['cannot_tell']})")
        if not parts:
            parts.append(f"{RULE_STATUS[entry['status']]}: {plain(entry['note'], NOTE_LIMIT)}")
        lines.append(f"  {entry['id']}  {'; '.join(parts)}")
    return lines


def to_text(snapshot: dict, origin: str = "", assessment: dict | None = None, usage: dict | None = None,
            show_fixes: bool = True) -> str:
    """The report. With an ``assessment`` (what the rules made of the snapshot) it begins with the rules'
    findings; without one it lists what was read and what was not, and says that no rule was applied."""
    settings = snapshot["settings"]
    total = len(SETTINGS)
    tally = counts(snapshot)
    how = "with a token" if snapshot["viewer"].get("authenticated") else "without a token"
    lines = [f"Settings audit of {plain(snapshot['repository'], 140)}",
             origin or f"Read {when(snapshot)} from {plain(snapshot['api'], 100)}, {how}."]
    if snapshot.get("requested_as"):
        lines.append(f"Asked for as {plain(snapshot['requested_as'], 140)}; GitHub now calls it "
                     f"{plain(snapshot['repository'], 140)}.")
    if assessment is None:
        lines.append("This lists what was read and what was not. No rule was applied to it.")
    else:
        lines.append(_usage_line(usage))
        lines.append("")
        lines += findings_lines(assessment, show_fixes)
        lines.append("")
        lines.append("WHAT WAS READ. The rules above rest on this; what was not read is listed first.")
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
                described = _describe(setting.key, entry["value"], settings, whole=status == "read")
            except (KeyError, TypeError, AttributeError, IndexError, ValueError):
                # A loaded snapshot has been checked against the schema, so this should not happen; if it
                # does, the value is shown as not describable rather than guessed at.
                described = ["recorded, but not in a form this version can describe"]
            # An empty value with nothing to say about it (a file can hold one) is said to be empty.
            lines += [f"      {line}" for line in described or ["nothing is recorded"]]
            for problem in entry.get("problems", []):
                lines.append(f"      NOT READ: {plain(problem['what'], 160)}: {plain(problem['reason'], 400)}")
            if status == "partial" and setting.note:
                lines.append(f"      {setting.note}")
    lines.append("")
    requests = snapshot["requests"]
    # For a run that has just been made, the client can only send GET. For a file, the list of requests is
    # what the file says and nothing more.
    sent = f"The snapshot lists {_count(len(requests), 'request')}." if origin else (
        f"{_count(len(requests), 'request')} sent, all GET.")
    lines.append(f"{total} settings: {tally['read']} read, {tally['partial']} partly read, {tally['unread']} not read, "
                 f"{tally['not_applicable']} that do not apply. {sent}")
    return "\n".join(lines) + "\n"


def when(snapshot: dict) -> str:
    stamp = str(snapshot.get("taken_at", ""))
    return plain(f"{stamp[:10]} {stamp[11:16]} UTC" if len(stamp) == 20 else stamp, 40)


def why_unread(snapshot: dict) -> str:
    """One line for the case where not even the repository could be read."""
    entry = snapshot["settings"]["repository"]
    return f"{BY_KEY['repository'].title} could not be read: {plain(entry.get('reason', ''), 400)}"
