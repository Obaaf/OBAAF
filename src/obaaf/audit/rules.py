"""The settings rules: what a snapshot of GitHub settings means for the workflows that depend on them.

Each rule compares a setting with something a workflow in the repository uses or assumes: the environment
a job names, the checks its jobs report, the events that start it, the secrets it reads. A setting no
workflow depends on is not judged; this is not a checklist for an organisation.

Two rules, OBAAF-SET-004 and OBAAF-SET-005, read settings only: what they are about, who can skip a
branch's rules and whether its approvals can be given, is what every workflow's result feeds.

A rule gives one of two kinds of result, each about one thing (an environment, a branch, a job):

- a **finding**, with a severity, when what was read shows the problem;
- **cannot tell**, when a setting or a workflow file the rule needs was not read, or was read and is not
  in a form the rule understands. It is never counted as "nothing wrong".

A rule with neither says what it compared ("no finding") or why it had nothing to compare ("does not
apply"). Nothing here says "pass": a rule that found nothing has shown only that it found nothing.

Everything a rule reads from a snapshot has been through the snapshot's schema, except a rule's
``parameters`` and a ruleset's or policy's ``conditions``, which are kept as GitHub sent them. Those are
checked here, value by value, before they are used.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from obaaf.audit.github import plain, quoted
from obaaf.audit.settings import BY_KEY
from obaaf.audit.workflows import PULL_REQUEST_EVENTS
from obaaf.audit.workflows import called_path
from obaaf.checker.workflow import PRIVILEGED_UNTRUSTED_TRIGGERS

FORMAT = "obaaf-settings-findings/v0.1"
SEVERITIES = ("high", "medium", "low")
# The id of the GitHub Actions app. A required check tied to it is reported by a workflow job under the
# job's name, or by a step whose token may write checks or statuses, under any name.
ACTIONS_APP = 15368
# Built-in repository roles as a ruleset's bypass list names them.
ROLE_BY_ID = {2: "maintain", 4: "write", 5: "admin"}
PUSH_ROLES = ("admin", "maintain", "write")
DEFAULT_POLICY_DATE = "2026-12-02"
WILDCARDS = "*?["
# The characters that make an entry of a workflow's branch filter a pattern (GitHub's filter patterns also
# know `+`, and `!` negates an entry of `branches`).
FILTER_CHARS = "*?[]+!"
# Rules of a ruleset whose results come from workflows or from reviewers.
GATES = ("pull_request", "required_status_checks", "workflows", "code_scanning", "merge_queue")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str            # the highest severity it reports
    reads: tuple[str, ...]   # the settings it reads
    compares: str            # what in the workflow files it is compared with
    description: str
    fix: str
    files: bool = True       # whether it reads the workflow files at all


RULES: tuple[Rule, ...] = (
    Rule("OBAAF-SET-001", "An environment's secrets can be reached from any branch", "high",
         ("environments", "environment_secrets"), "the environment each job names",
         "A job names an environment, and the environment does not limit which branches may use it (or the "
         "limit is a pattern anyone with write access can match by naming a branch or pushing a tag). Anyone "
         "who can push a branch can add a job that names the environment and reads its secrets. With required "
         "reviewers the only gate left is one person's approval; without them there is none. An environment a "
         "job names that the settings do not have gets no protection from them.",
         "In the environment's settings, limit deployment to selected branches and name the default branch. "
         "Add required reviewers where a person should decide; a wildcard or a tag pattern is reported until "
         "there are reviewers."),
    Rule("OBAAF-SET-002", "A job outsiders can start gets an environment that asks nobody", "high",
         ("environments", "environment_secrets", "repository"),
         "jobs started by pull_request_target, issue and comment events",
         "A job that runs on an event people without write access can cause (pull_request_target, "
         "issue_comment, issues, workflow_run and the like) names an environment that has no required "
         "reviewers. Those events run as the default branch, and pull_request_target as the pull request's "
         "base branch, which can be any branch the workflow lets a pull request target. So a limit on which "
         "branches may deploy lets them through whenever it admits such a branch: nothing stands between the "
         "event and the environment's secrets.",
         "Add required reviewers to the environment, or move the step that needs the secret to a workflow "
         "that only people with write access can start."),
    Rule("OBAAF-SET-003", "A secret kept behind an environment is also stored where every job can read it", "high",
         ("environment_secrets", "repository_secrets", "organization_secrets", "environments"),
         "protected_secrets in .github/obaaf.yml, and the secrets jobs read",
         "A secret that the configuration says must stay behind an environment, or that is stored in one, "
         "also exists as a repository or organisation secret. A job that does not declare the environment "
         "gets that copy, on any branch, so the environment protects nothing. The same holds when the "
         "environment the configuration names does not exist.",
         "Delete the repository or organisation secret so that the environment holds the only copy, and "
         "create the environment the configuration names, limited to the default branch."),
    Rule("OBAAF-SET-004", "Those who author changes can bypass the branch's rules", "high",
         ("ruleset_bypass_actors", "branch_rules", "branch_protection", "branches", "rulesets", "collaborators",
          "repository"),
         "nothing in the workflow files: it reads who may skip the checks and reviews their results feed",
         "A ruleset in force on the branch requires checks or reviews and lists who may bypass it, or classic "
         "branch protection does not hold administrators to it, or names people who may skip its reviews. "
         "Whoever is on such a list can push or merge without what the rule requires. When everyone who can "
         "push is on it, the rules hold nobody.",
         "Remove the bypass. If one must stay for emergencies, give it to a team nobody works from day to "
         "day; it is still reported, at medium. For classic protection, hold administrators to the rule and "
         "empty the list of who may bypass required pull requests.", files=False),
    Rule("OBAAF-SET-005", "Required approvals cannot be given", "medium",
         ("branch_rules", "branch_protection", "branches", "collaborators"),
         "nothing in the workflow files: it reads the approvals a branch requires and who can give them",
         "The branch requires more approvals than the people who can approve can give: an author cannot "
         "approve their own pull request, and only accounts with write access count. Every merge then needs "
         "a bypass, which trains everyone to bypass.",
         "Lower the required approvals to what the team can give, or give a second person write access. Do "
         "not solve it with a bypass.", files=False),
    Rule("OBAAF-SET-006", "A required check that no workflow job reports", "medium",
         ("branch_rules", "branch_protection", "branches", "workflow_permissions"),
         "the check names the jobs report",
         "The branch requires a check from GitHub Actions under a name that no job in the workflow files "
         "reports (a job was renamed or removed, or the name was mistyped), and no job holds a token that "
         "could report it another way. The check stays pending on every pull request, so nothing merges "
         "without a bypass.",
         "Correct the name in the ruleset or branch protection to the one the job reports, or remove it."),
    Rule("OBAAF-SET-007", "A required check that does not report on every pull request", "medium",
         ("branch_rules", "branch_protection", "branches", "workflow_permissions"),
         "the triggers of the job that reports each required check, and their filters",
         "The branch requires a check, and the job that reports it does not run for every pull request into "
         "the branch: its workflow has a paths filter, or runs only for some kinds of pull request activity, "
         "or is started by something else altogether. On the pull requests it does not run for, the check "
         "never reports and the merge stays blocked.",
         "Let the workflow run on every pull request and skip inside the job instead (a job skipped by `if:` "
         "reports as passed), or stop requiring the check."),
    Rule("OBAAF-SET-008", "A pull-request job whose failure does not block a merge", "medium",
         ("branch_rules", "branch_protection", "branches"), "the jobs that run on every pull request",
         "A job runs on every pull request into the branch and is not among the required checks, so a merge "
         "goes through while it is red. If that is intended, the workflow should say so.",
         "Add the job's check to the required checks. If the job is advisory, give it "
         "`continue-on-error: true` at job level, which says in the workflow that its failure is not meant "
         "to block."),
    Rule("OBAAF-SET-009", "An Actions policy blocks an event a workflow uses", "medium",
         ("actions_policies",), "the events under each workflow's `on:`",
         "An Actions policy allows only some events to start a workflow, and the workflow names another. A "
         "run for that event fails at startup with no job, so whatever it was meant to check is not checked "
         "and nothing reports it.",
         "Add the event to the policy's allowed events, or remove the trigger from the workflow."),
    Rule("OBAAF-SET-010", "A pull_request_target workflow and GitHub's default policy of 2026-12-02", "medium",
         ("actions_policies", "repository"), "workflows started by pull_request_target",
         "By GitHub's changelog of 2026-11-02, from 2026-12-02 a default policy blocks the "
         "pull_request_target event in public repositories that have no policy allowing it. A workflow that "
         "uses the event then fails at startup.",
         "Move the workflow off pull_request_target where it does not need the base repository's secrets or "
         "write token. Where it does, add an Actions policy that allows the event for that workflow file, "
         "and read OBAAF-GHA-001 and OBAAF-GHA-002 on what such a workflow must not do."),
    Rule("OBAAF-SET-011", "A reusable workflow is passed a secret its caller cannot read", "medium",
         ("environment_secrets", "repository_secrets", "organization_secrets"),
         "the secrets a job passes to a reusable workflow",
         "A job that calls a reusable workflow cannot declare an environment, so it cannot read a secret "
         "that is stored only in one: what it passes on is empty. The tempting repair is to copy the secret "
         "to the repository, which removes the environment's protection.",
         "Declare the environment on the job inside the reusable workflow, let that job read the "
         "environment's secret under its own name, and stop passing it from the caller. Do not copy the "
         "secret to the repository."),
    Rule("OBAAF-SET-012", "Jobs with no permissions block get a token that can write", "medium",
         ("workflow_permissions",), "jobs that declare no `permissions`",
         "The repository's default for the workflow token is read and write, and a job declares no "
         "permissions, so it gets a token that can push, comment and release.",
         "Set the default to read in the repository's Actions settings, and give each job the permissions it "
         "needs."),
    Rule("OBAAF-SET-013", "A workflow can give a required approval", "medium",
         ("workflow_permissions", "branch_rules", "branch_protection", "branches"),
         "the approvals each audited branch requires (a workflow on any branch can ask for the token)",
         "Workflows are allowed to approve pull requests and a branch requires approvals. A workflow can ask "
         "for a token that writes to pull requests whatever the repository's default, and anyone who can push "
         "a branch can add such a workflow there, so a run of it can approve their own pull request, which is "
         "not the review by a person that a required approval is meant to be.",
         "Turn off \"Allow GitHub Actions to create and approve pull requests\" in the repository's Actions "
         "settings. Where a workflow has to open pull requests, which needs the same switch (OBAAF's effect "
         "lane does), require a code owner's review, keep the required approvals at one, and give every file "
         "a code owner: the rule then answers \"cannot tell\", because it does not read the CODEOWNERS file."),
    Rule("OBAAF-SET-014", "Fork pull requests run on the repository's runners or with its secrets", "high",
         ("fork_pull_requests", "repository"),
         "the runners pull_request jobs name (a fork's pull request runs its own copy of the workflows)",
         "In a public repository approval is not required for every outside contributor and the repository "
         "has a self-hosted runner: a stranger's code runs on a machine that keeps state, because a fork's "
         "pull request runs its own copy of the workflow files and can name any runner. Or, in a private "
         "repository, fork pull requests are sent secrets or a write token, which a fork's own workflow can "
         "read whatever the jobs here do.",
         "Require approval for all external contributors, or move the job to a GitHub-hosted runner. In a "
         "private repository, do not send secrets or write tokens to fork pull requests."),
    Rule("OBAAF-SET-015", "Pinning actions to a commit: the setting and the workflows disagree", "medium",
         ("actions_permissions",), "the actions each job's steps use",
         "The repository requires actions to be pinned to a full commit and a workflow uses one that is not, "
         "so that workflow is refused. Or every action is pinned today and the repository does not require "
         "it, so nothing stops the next change from adding one that is not.",
         "Pin each action to a full commit SHA, and turn on the requirement in the repository's Actions "
         "settings."),
)
RULE_BY_ID = {rule.id: rule for rule in RULES}


# ---------------------------------------------------------------- small helpers
def _q(name, limit: int = 80) -> str:
    return quoted(name, limit)


def _n(count: int, noun: str, plural: str | None = None) -> str:
    return f"{count} {noun if count == 1 else (plural or noun + 's')}"


def _do(count: int, noun: str, one: str, many: str) -> str:
    """A count, its noun and the verb that agrees with it: "1 job names", "2 jobs name"."""
    return f"{_n(count, noun)} {one if count == 1 else many}"


def _names(items, limit: int = 6) -> str:
    items = [str(i) for i in items]
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _strings(value) -> list[str] | None:
    """A list of text, or None when the value is not one."""
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return None


def _job_label(file: dict, job: dict) -> str:
    return f"{plain(file['path'], 120)}#{plain(job['id'], 80)}"


class _Run:
    """One rule's run: what it reports, and what it says it compared."""

    def __init__(self, rule: Rule, snapshot: dict, usage: dict) -> None:
        self.rule, self.snapshot, self.usage = rule, snapshot, usage
        self.settings = snapshot["settings"]
        self.results: list[dict] = []
        self.compared = ""       # what was compared, when something was
        self.idle = ""           # why there was nothing to compare
        self.failed = False

    # -- results
    def finding(self, subject: str, severity: str, message: str, evidence=()) -> None:
        self.results.append({"rule": self.rule.id, "state": "finding", "severity": severity, "subject": subject,
                             "message": message, "evidence": [str(e) for e in evidence]})

    def cannot_tell(self, subject: str, message: str, unread=()) -> None:
        self.results.append({"rule": self.rule.id, "state": "cannot-tell", "severity": None, "subject": subject,
                             "message": message, "unread": sorted(set(unread))})

    # -- settings
    def got(self, key: str):
        """(value, whole) for a setting: the value when anything of it was read (None otherwise), and
        whether all of it was. A setting that does not exist for the repository is an empty value, whole."""
        entry = self.settings[key]
        status = entry["status"]
        if status == "read":
            return entry["value"], True
        if status == "partial":
            return entry["value"], False
        if status == "not_applicable":
            return ({} if key == "environment_secrets" else []), True
        return None, False

    def why(self, key: str) -> str:
        """Why a setting was not read in full, for a "cannot tell"."""
        entry = self.settings[key]
        title = BY_KEY[key].title
        if entry["status"] == "partial":
            return f"\"{title}\" was only partly read"
        return f"\"{title}\" was not read ({plain(entry.get('reason_code', 'unread'), 30)})"

    def unread(self, subject: str, what: str, *keys: str) -> None:
        missing = [k for k in keys if self.settings[k]["status"] in ("unread", "partial")]
        because = f": {'; '.join(self.why(k) for k in missing)}" if missing else ""
        self.cannot_tell(subject, f"{what[:1].upper()}{what[1:]}{because}.", missing)

    # -- workflows
    def files(self) -> list[dict]:
        return [f for f in self.usage["files"] if not f["error"]]

    def broken(self) -> list[dict]:
        return [f for f in self.usage["files"] if f["error"]]

    def jobs(self):
        for file in self.files():
            for job in file["jobs"]:
                yield file, job


# ---------------------------------------------------------------- what a branch requires
def _branch_requirements(run: _Run, branch: str) -> dict:
    """The checks and approvals required on a branch, from rulesets and from classic protection, with
    whether each list is known to be whole."""
    out = {"checks": {}, "checks_whole": True, "approvals": None, "approvals_whole": True, "gaps": [],
           "rulesets": {}, "from_public_view": False, "classic": None, "classic_unknown": False,
           "code_owner": False}
    rules, _ = run.got("branch_rules")
    if rules is None or branch not in rules:
        out["checks_whole"] = out["approvals_whole"] = False
        out["gaps"].append("branch_rules")
    else:
        for rule in rules[branch]:
            out["rulesets"].setdefault(rule["ruleset_id"], []).append(rule["type"])
            parameters = rule["parameters"]
            if rule["type"] == "required_status_checks":
                listed = parameters.get("required_status_checks") if isinstance(parameters, dict) else None
                if not isinstance(listed, list) or not all(
                        isinstance(c, dict) and isinstance(c.get("context"), str) for c in listed):
                    out["checks_whole"] = False
                    out["gaps"].append("branch_rules")
                    continue
                for check in listed:
                    app = check.get("integration_id")
                    out["checks"][check["context"]] = app if _is_int(app) else None
            elif rule["type"] == "pull_request":
                count = parameters.get("required_approving_review_count") if isinstance(parameters, dict) else None
                if not _is_int(count) or count < 0:
                    out["approvals_whole"] = False
                    out["gaps"].append("branch_rules")
                    continue
                out["approvals"] = max(out["approvals"] or 0, count)
                out["code_owner"] = out["code_owner"] or parameters.get("require_code_owner_review") is True
    classic, _ = run.got("branch_protection")
    if classic is not None and branch in classic:
        rule = classic[branch]
        out["classic"] = rule
        if rule["exists"]:
            checks, reviews = rule["required_status_checks"], rule["required_pull_request_reviews"]
            if checks["required"]:
                apps = {c["context"]: c["app_id"] for c in checks["checks"] or []}
                for context in set(checks["contexts"]) | set(apps):
                    app = apps.get(context)
                    out["checks"].setdefault(context, app if _is_int(app) and app > 0 else None)
            if reviews["required"]:
                count = reviews["required_approving_review_count"]
                out["code_owner"] = out["code_owner"] or reviews["require_code_owner_reviews"] is True
                if _is_int(count) and count >= 0:
                    out["approvals"] = max(out["approvals"] or 0, count)
                else:
                    out["approvals_whole"] = False
                    out["gaps"].append("branch_protection")
        return out
    # Classic protection was not read. GitHub shows anyone the required checks of a classic rule; it
    # does not show the required reviews.
    branches, _ = run.got("branches")
    seen = branches.get(branch) if branches is not None else None
    shown = seen["public_protection"] if seen else None
    if seen is not None and (seen["protected"] is False or (shown is not None and shown["enabled"] is False)):
        return out  # GitHub says there is no classic rule in force on the branch
    checks = shown["required_status_checks"] if shown else None
    if checks is not None and checks["enforcement_level"] in ("non_admins", "everyone"):
        out["from_public_view"] = True
        apps = {c["context"]: c["app_id"] for c in checks["checks"] or []}
        for context in set(checks["contexts"]) | set(apps):
            app = apps.get(context)
            out["checks"].setdefault(context, app if _is_int(app) and app > 0 else None)
    else:
        out["checks_whole"] = False
    out["approvals_whole"] = False
    out["classic_unknown"] = True
    out["gaps"].append("branch_protection")
    return out


def _reports(job: dict, context: str):
    """Whether the job reports a check of this name: True, False, or None when it may (its names could
    not be written out, and the name fits the form they would have)."""
    check = job["check"]
    if check["kind"] == "computed":
        return None
    if check["names"] is not None:
        return context in check["names"]
    name = check["name"]
    if check["kind"] == "calls":
        fits = (context.startswith(name + " (") and " / " in context[len(name):] if check["matrix"]
                else context.startswith(name + " / "))
    else:
        fits = context.startswith(name + " (") and context.endswith(")")
    return None if fits else False


def _stands_alone(file: dict) -> bool:
    """Whether the file's jobs report under their own names: not so for a workflow that is only called."""
    return bool(set(file["triggers"]) - {"workflow_call"})


def _pattern(name: str) -> bool:
    return any(ch in name for ch in FILTER_CHARS)


def _admits(filters: dict, branch: str):
    """Whether an event's branch filters let the branch through: True, False, or None when a pattern
    decides it (patterns are not evaluated here). An entry that is the branch's name, written plainly,
    decides it whatever patterns stand beside it, except that a negated entry in `branches` can take it
    out again, so any `!` there leaves it to the patterns."""
    listed, ignored = filters["branches"], filters["branches_ignore"]
    if listed is not None:
        if any(name.startswith("!") for name in listed):
            return None
        if any(name == branch and not _pattern(name) for name in listed):
            return True
        return None if any(_pattern(name) for name in listed) else False
    if ignored is not None:
        if any(name == branch and not _pattern(name) for name in ignored):
            return False
        return None if any(_pattern(name) for name in ignored) else True
    return True


def _every_update(types) -> bool:
    """Whether a pull request event limited to these activity types still runs when a pull request is
    opened and whenever it gets new commits."""
    return types is None or {"opened", "synchronize"} <= set(types)


ORDER = ("always", "maybe", "paths", "types", "manual", "never")


def _report_run(file: dict, job: dict, branch: str, pushes: bool = True) -> str:
    """How the job comes to run on the head commit of a pull request into the branch:

    - "always": for every pull request, whenever it is opened or updated;
    - "maybe": a branch pattern decides, and patterns are not evaluated;
    - "paths": only when certain paths change;
    - "types": only for some kinds of activity (labeled, closed ...);
    - "manual": only when someone or something dispatches the workflow;
    - "never": nothing in its triggers runs it there.

    With ``pushes`` a push trigger with no filter counts as "always": a push to the pull request's branch
    runs the job on the same commit. That holds for a branch in this repository and not for a fork's."""
    found = "never"

    def better(kind: str) -> str:
        return kind if ORDER.index(kind) < ORDER.index(found) else found

    for event in PULL_REQUEST_EVENTS:
        filters = file["triggers"].get(event)
        if filters is None or event not in job["triggers"]:
            continue
        admitted = _admits(filters, branch)
        if admitted is False:
            continue
        found = better("maybe" if admitted is None else "paths" if filters["paths"]
                       else "always" if _every_update(filters["types"]) else "types")
    push = file["triggers"].get("push")
    if pushes and push is not None and "push" in job["triggers"]:
        if push["branches"] is None and push["branches_ignore"] is None:
            if not push["tags"]:
                found = better("paths" if push["paths"] else "always")
        elif any(_pattern(name) for name in (push["branches"] or []) + (push["branches_ignore"] or [])) \
                or push["branches_ignore"] is not None:
            found = better("maybe")
    if "workflow_dispatch" in file["triggers"] and "workflow_dispatch" in job["triggers"]:
        found = better("manual")
    return found


def _api_reporters(run: _Run) -> str:
    """Whether a step could report a check under a name of its choosing: "no" when no job's token may
    write checks or statuses, "yes" when one may, "unknown" when a job declares no permissions and the
    repository's default was not read."""
    default, _ = run.got("workflow_permissions")
    answer = "no"
    for _, job in run.jobs():
        permissions = job["permissions"]
        if permissions["writes_checks"]:
            return "yes"
        if not permissions["declared"]:
            if default is None or default["default_workflow_permissions"] not in ("read", "write"):
                answer = "unknown"
            elif default["default_workflow_permissions"] == "write":
                return "yes"
    return answer


# ---------------------------------------------------------------- rules about environments and secrets
def _environment_users(run: _Run) -> dict:
    """Environment name (lower case, as GitHub compares them) -> the jobs that name it."""
    users: dict = {}
    for file, job in run.jobs():
        env = job["environment"]
        if env and env.get("name"):
            users.setdefault(env["name"].lower(), []).append((file, job))
    return users


def _computed_environments(run: _Run) -> list:
    return [(file, job) for file, job in run.jobs() if job["environment"] and job["environment"].get("computed")]


def _protected(run: _Run) -> dict:
    config = run.usage.get("config") or {}
    return config.get("protected_secrets") or {}


def _config_unread(run: _Run, what: str) -> None:
    if run.usage.get("config_error"):
        run.cannot_tell("the checker's configuration",
                        f"The configuration could not be read ({plain(run.usage['config_error'], 200)}), so "
                        f"{what} is not known.")


def _open_pattern(policy: dict) -> bool:
    return bool(policy["name"]) and set(policy["name"]) <= {"*", "/"}


def _events(job: dict) -> set:
    """The events that reach the job, those of the jobs that call its workflow included."""
    return set(job["triggers"]) | set(job["called_from"])


def rule_001(run: _Run) -> None:
    users = _environment_users(run)
    computed = _computed_environments(run)
    named = {env.lower() for env in _protected(run).values() if env}
    wanted = sorted(set(users) | named)
    _config_unread(run, "which environments it names")
    for file, job in computed:
        run.cannot_tell(f"job {_job_label(file, job)}",
                        "The job names its environment with an expression, so which environment it reaches "
                        "was not compared.")
    if not wanted:
        if not run.results:
            run.idle = "no job names an environment"
        return
    environments, whole = run.got("environments")
    if environments is None:
        run.unread("environments", f"{_n(len(wanted), 'environment')} that jobs name could not be compared",
                   "environments")
        return
    by_name = {env["name"].lower(): env for env in environments}
    secrets, _ = run.got("environment_secrets")
    held = {name.lower(): names for name, names in (secrets or {}).items()}
    audited = set(_branches(run))
    run.compared = f"{_n(len(wanted), 'environment')} that jobs or the configuration name"
    for key in wanted:
        jobs = users.get(key, [])
        who = (f"{_do(len(jobs), 'job', 'names', 'name')} it ({_names(_job_label(f, j) for f, j in jobs)})" if jobs
               else "protected_secrets in the configuration names it")
        env = by_name.get(key)
        subject = f"environment {_q(env['name'] if env else key)}"
        if env is None:
            if not whole:
                run.unread(subject, "whether it exists is not known", "environments")
            elif jobs:
                run.finding(subject, "medium",
                            f"The environment {_q(key)} is not among the repository's environments, and {who}. "
                            "Whatever protection the job counts on from it is not in the settings.")
            continue
        reviewers = bool(env["reviewers"])
        gate = ("Its only protection is its required reviewers"
                + {True: ", and self-review is prevented", False: ", and a reviewer may approve their own run"}.get(
                    env["prevent_self_review"], "") + "." if reviewers else "It has no required reviewers.")
        # An environment read to hold no secret guards only what trusts its name (a deployment, an
        # identity token), which the audit does not read: the finding is then low and says so.
        empty = held.get(key) == []
        reach = ("It holds no secret, so what it guards is whatever trusts the environment's name, which "
                 "the audit does not read." if empty else
                 "A job on any such branch can name it and read whatever secrets it holds.")
        mode = env["deployment_branches"]
        if mode == "any":
            run.finding(subject, "low" if empty else "medium" if reviewers else "high",
                        f"Any branch or tag may use the environment {_q(env['name'])}, a pull request's branch "
                        f"included, and {who}. {reach} {gate}")
        elif mode == "protected":
            run.cannot_tell(subject, f"Only branches GitHub counts as protected may use {_q(env['name'])}. Which "
                                     "branches those are was not read, so whether that is only the default "
                                     "branch is not known.")
        elif env.get("branch_policies") is None:
            run.unread(subject, f"the branch and tag patterns of {_q(env['name'])} were not read", "environments")
        else:
            policies = env["branch_policies"]
            wide = [p for p in policies if p["type"] != "tag" and _open_pattern(p)]
            loose = [p for p in policies if p not in wide and (
                p["type"] == "tag" or any(ch in p["name"] for ch in WILDCARDS))]
            other = [p for p in policies if p not in wide and p not in loose and p["name"] not in audited]
            if wide:
                run.finding(subject, "low" if empty else "medium" if reviewers else "high",
                            f"The environment {_q(env['name'])} is limited to the branch pattern "
                            f"{_q(wide[0]['name'])}, which lets nearly every branch through, and {who}. "
                            f"{reach} {gate}")
            elif loose and not reviewers:
                shown = _names(f"{'tag' if p['type'] == 'tag' else 'branch'} pattern {_q(p['name'])}" for p in loose)
                run.finding(subject, "low" if empty else "medium",
                            f"The environment {_q(env['name'])} may be used from {shown}, it has no required "
                            f"reviewers, and {who}. Anyone with write access can push a branch or tag with such "
                            "a name from any commit, unless a ruleset restricts creating them, which this rule "
                            "does not read.")
            elif other and not reviewers:
                run.cannot_tell(subject, f"The environment {_q(env['name'])} may be used from the branch "
                                         f"{_names(_q(p['name']) for p in other)}, which was not audited, so who "
                                         "can push there is not known. Name it with --branch to have its rules "
                                         "read.")


def _admits_default(env: dict, default: str):
    """Whether the environment's branch limit lets the default branch through: True, False, or None when
    that was not read or a pattern decides it."""
    mode = env["deployment_branches"]
    if mode == "any":
        return True
    if mode == "protected" or env.get("branch_policies") is None:
        return None
    branches = [p["name"] for p in env["branch_policies"] if p["type"] != "tag"]
    if default in branches:
        return True
    return None if any(ch in name for name in branches for ch in WILDCARDS) else False


def _admits_a_base(env: dict, default: str):
    """For pull_request_target, which runs as the pull request's base branch: whether the limit lets some
    branch through. False only when it admits tags alone; a branch it names is one a pull request can
    target unless the workflow's filter says otherwise, which is not evaluated against the limit."""
    if _admits_default(env, default) is True:
        return True
    if env["deployment_branches"] == "selected" and env.get("branch_policies") is not None \
            and not [p for p in env["branch_policies"] if p["type"] != "tag"]:
        return False
    return None


def rule_002(run: _Run) -> None:
    exposed, unknown = [], []
    for file, job in run.jobs():
        events = sorted(_events(job) & PRIVILEGED_UNTRUSTED_TRIGGERS)
        if not events:
            continue
        env = job["environment"]
        if env and env.get("name"):
            exposed.append((file, job, env["name"], events))
        elif env:
            unknown.append((file, job, "names its environment with an expression"))
        elif job["calls"] and (called_path(job) is None or not _called(run, job)):
            unknown.append((file, job, f"calls {_q(job['calls'], 120)}, which was not read"))
    for file, job, why in unknown:
        run.cannot_tell(f"job {_job_label(file, job)}",
                        f"The job can be started by events people without write access can cause, and it {why}, "
                        "so whether it reaches an environment that asks nobody is not known.")
    if not exposed:
        if not run.results:
            run.idle = "no job that outsiders' events can start names an environment"
        return
    environments, whole = run.got("environments")
    repository, _ = run.got("repository")
    if environments is None or repository is None:
        run.unread("environments", f"{_do(len(exposed), 'job', 'that', 'that')} outsiders' events can start "
                                   f"{'names' if len(exposed) == 1 else 'name'} an environment",
                   "environments", "repository")
        return
    by_name = {env["name"].lower(): env for env in environments}
    secrets, _ = run.got("environment_secrets")
    held = {name.lower(): names for name, names in (secrets or {}).items()}
    run.compared = f"{_n(len(exposed), 'job')} that outsiders' events can start, each naming an environment"
    for file, job, name, events in exposed:
        env = by_name.get(name.lower())
        subject = f"job {_job_label(file, job)}"
        if env is None:
            if not whole:
                run.unread(subject, f"the environment {_q(name)} was not read", "environments")
            continue  # an environment that does not exist is OBAAF-SET-001's finding
        if env["reviewers"]:
            continue
        base = "pull_request_target" in events
        admitted = (_admits_a_base if base else _admits_default)(env, repository["default_branch"])
        if admitted is False:
            # The limit shuts the default branch out (or, for pull_request_target, admits tags alone), and
            # these events run as the default branch (pull_request_target as a branch, the pull request's base).
            continue
        stored = held.get(name.lower())
        reads = job["secrets"] or (["every secret"] if job["all_secrets"] else [])
        if stored is None and not reads:
            run.unread(subject, f"whether the environment {_q(name)} holds any secret is not known, and the job "
                                "names none", "environment_secrets")
            continue
        if stored is not None and not stored and not reads:
            continue
        what = (f"which holds {_n(len(stored), 'secret')}" if stored else
                f"and reads {_names(plain(r, 60) for r in reads)}")
        if base:
            limit = ("pull_request_target runs as the pull request's base branch, which can be any branch the "
                     "workflow lets a pull request target, and the other events as the default branch. "
                     + ("Its limit on which branches may deploy admits the default branch, so the limit does not stop "
                        "them." if admitted else
                        "Its limit on which branches may deploy admits branches, and whether a pull request can "
                        "target one of them is not established, so it is not counted as stopping them."))
        else:
            limit = ("Its limit on which branches may deploy admits the default branch, and these events run as "
                     "the default branch, so the limit does not stop them." if admitted else
                     "These events run as the default branch; whether its limit on which branches may deploy "
                     "admits the default branch was not read or rests on a pattern.")
        run.finding(subject, "high",
                    f"The job can be started by {_names(events)}, which people without write access can cause, "
                    f"and it names the environment {_q(name)}, {what}. The environment has no required "
                    f"reviewers. {limit}")


def _called(run: _Run, job: dict):
    """The file a job calls, when it is in this repository and was read."""
    path = called_path(job)
    return next((f for f in run.files() if f["path"] == path), None) if path else None


def rule_003(run: _Run) -> None:
    protected = _protected(run)
    env_secrets, env_whole = run.got("environment_secrets")
    repo, repo_whole = run.got("repository_secrets")
    org, org_whole = run.got("organization_secrets")
    environments, envs_whole = run.got("environments")
    read_by_jobs = {name.upper() for _, job in run.jobs() for name in job["secrets"]}
    # A job that can read every secret (toJSON(secrets), a computed index, `secrets: inherit`) reads each.
    reads_all = any(job["all_secrets"] or (job["passes"] and (job["passes"]["inherit"] or job["passes"]["all"]))
                    for _, job in run.jobs())
    _config_unread(run, "which secrets it protects")
    if not protected and not read_by_jobs and not reads_all:
        if not run.results:
            run.idle = "the configuration protects no secret, and no job reads one"
        return
    stored_wide = {}
    for names, where in ((repo, "a repository secret"), (org, "an organisation secret")):
        for name in names or []:
            stored_wide.setdefault(name.upper(), where)
    in_env: dict = {}
    for env, names in (env_secrets or {}).items():
        for name in names:
            in_env.setdefault(name.upper(), []).append(env)
    run.compared = (f"{_n(len(protected), 'protected_secrets entry', 'protected_secrets entries')} and the "
                    "secrets that jobs read")
    reported = set()
    for pattern, env in sorted(protected.items()):
        if env:
            known = {e["name"].lower() for e in environments} if environments is not None else set()
            if environments is None or (env.lower() not in known and not envs_whole):
                run.unread(f"environment {_q(env)}", f"whether the environment protected_secrets names for "
                                                     f"{_q(pattern)} exists is not known", "environments")
            elif env.lower() not in known:
                run.finding(f"environment {_q(env)}", "high",
                            f"protected_secrets says {_q(pattern)} must stay in the environment {_q(env)}, and "
                            "the repository has no such environment, so the declaration is met by a boundary "
                            "that is not there.")
        for name, where in sorted(stored_wide.items()):
            if fnmatch.fnmatchcase(name, pattern):
                reported.add(name)
                run.finding(f"secret {_q(name)}", "high",
                            f"{_q(name)} matches the protected_secrets entry {_q(pattern)} and is stored as "
                            f"{where}. Every job on every branch can read that copy, whichever environment the "
                            "jobs that should use it declare.")
        if env and env_secrets is not None and envs_whole and env_whole:
            kept = [n for n in in_env if fnmatch.fnmatchcase(n, pattern)
                    and env.lower() in {e.lower() for e in in_env[n]}]
            if not kept and env.lower() in {e.lower() for e in env_secrets}:
                run.finding(f"protected_secrets entry {_q(pattern)}", "low",
                            f"No secret that matches {_q(pattern)} is stored in the environment {_q(env)}, "
                            "which the configuration names for it. The entry protects nothing that is there.")
    for name in sorted(set(in_env) & set(stored_wide) - reported):
        if name in read_by_jobs or reads_all:
            run.finding(f"secret {_q(name)}", "medium",
                        f"{_q(name)} is stored in the environment {_names(_q(e) for e in sorted(in_env[name]))} "
                        f"and also as {stored_wide[name]}. A job that declares the environment gets the "
                        "environment's value; any other job, on any branch, gets the other copy.")
    missing = [k for k, known in (("repository_secrets", repo_whole), ("organization_secrets", org_whole),
                                  ("environment_secrets", env_whole)) if not known]
    if missing:
        what = (f"whether a secret named by protected_secrets ({_names(_q(p) for p in sorted(protected))}) is "
                "also stored where every job can read it" if protected else
                "whether a secret that jobs read is stored both in an environment and for every job")
        run.unread("where the secrets are stored", what + " is not known", *missing)


def rule_011(run: _Run) -> None:
    callers = [(file, job) for file, job in run.jobs()
               if job["passes"] and (job["passes"]["inherit"] or job["passes"]["names"] or job["passes"]["all"])]
    if not callers:
        run.idle = "no job passes a secret to a reusable workflow"
        return
    env_secrets, env_whole = run.got("environment_secrets")
    repo, repo_whole = run.got("repository_secrets")
    org, org_whole = run.got("organization_secrets")
    if not (env_whole and repo_whole and org_whole):
        run.unread("where the secrets are stored",
                   f"{_do(len(callers), 'job', 'passes', 'pass')} secrets to a reusable workflow, and whether any "
                   "of those secrets is stored only in an environment is not known",
                   "environment_secrets", "repository_secrets", "organization_secrets")
        return
    wide = {name.upper() for name in list(repo) + list(org)}
    only_env: dict = {}
    for env, names in env_secrets.items():
        for name in names:
            if name.upper() not in wide:
                only_env.setdefault(name.upper(), []).append(env)
    run.compared = f"{_n(len(callers), 'job')} passing secrets to a reusable workflow"
    if not only_env:
        return  # every secret is stored where a caller can read it
    listed = _names(_q(n) for n in sorted(only_env))
    for file, job in callers:
        subject = f"job {_job_label(file, job)}"
        target = job["calls"] or ""
        passes = job["passes"]
        # Passed by name, as a secret or as an input: the called workflow sees what the caller could read.
        for name in passes["names"]:
            envs = only_env.get(name.upper())
            if envs:
                run.finding(subject, "medium",
                            f"The job passes secrets.{plain(name, 60)} to {_q(target, 120)}. {_q(name)} is stored "
                            f"only in the environment {_names(_q(e) for e in sorted(envs))}, and a job that "
                            "calls a reusable workflow cannot declare an environment, so what it passes is "
                            "empty, whatever the called workflow declares.")
        if passes["all"]:
            run.cannot_tell(subject, f"The job passes a secret it picks with an expression to {_q(target, 120)}. "
                                     f"Whether that is one of {listed}, stored only in an environment, is not "
                                     "known.")
        if not passes["inherit"]:
            continue
        local = _called(run, job)
        if local is None:
            run.cannot_tell(subject, f"The job passes every secret to {_q(target, 120)}, which was not read "
                                     "(it is in another repository, or could not be parsed). Whether that "
                                     f"workflow reads {listed}, stored only in an environment, is not known.")
            continue
        for called in local["jobs"]:
            env = called["environment"] or {}
            where = f"whose job {_q(called['id'])}"
            if called["all_secrets"] or (called["passes"] and (called["passes"]["inherit"] or called["passes"]["all"])):
                run.cannot_tell(subject, f"The job passes every secret to {_q(target, 120)}, {where} can read "
                                         f"any of them or passes them on. Whether it relies on {listed}, "
                                         "stored only in an environment, is not known.")
                continue
            for name in called["secrets"]:
                envs = only_env.get(name.upper())
                if not envs:
                    continue
                if env.get("computed"):
                    run.cannot_tell(subject, f"The job passes every secret to {_q(target, 120)}, {where} reads "
                                             f"secrets.{plain(name, 60)} and names its environment with an "
                                             f"expression. {_q(name)} is stored only in the environment "
                                             f"{_names(_q(e) for e in sorted(envs))}; whether that is the "
                                             "environment the job gets is not known.")
                elif env.get("name", "").lower() not in {e.lower() for e in envs}:
                    run.finding(subject, "medium",
                                f"The job passes every secret to {_q(target, 120)}, {where} reads "
                                f"secrets.{plain(name, 60)}. {_q(name)} is stored only in the environment "
                                f"{_names(_q(e) for e in sorted(envs))}, and that job does not declare it, so "
                                "the value it gets is empty.")


# ---------------------------------------------------------------- rules about branches
def _branches(run: _Run) -> list[str]:
    return [b for b in run.snapshot.get("branches", []) if isinstance(b, str)]


def _viewer_bypass(run: _Run) -> dict:
    return {c["ruleset_id"]: c["can_bypass"] for c in run.snapshot["viewer"].get("can_bypass_rulesets", [])
            if isinstance(c, dict) and _is_int(c.get("ruleset_id")) and isinstance(c.get("can_bypass"), str)}


def _actor_text(actor: dict) -> str:
    kind, ident = actor["actor_type"], actor["actor_id"]
    if kind == "OrganizationAdmin":
        return "organisation administrators"
    if kind == "RepositoryRole":
        role = ROLE_BY_ID.get(ident)
        return f"the repository role {role}" if role else f"repository role {plain(ident, 20)}"
    return f"{plain(kind, 30)}{'' if ident is None else ' ' + plain(ident, 20)}"


def rule_004(run: _Run) -> None:
    branches = _branches(run)
    if not branches:
        run.idle = "no branch was audited"
        return
    rulesets, _ = run.got("rulesets")
    names = {r["id"]: r["name"] for r in rulesets or []}
    bypass, _ = run.got("ruleset_bypass_actors")
    listed = {entry["ruleset_id"]: entry["actors"] for entry in bypass or []}
    viewer = _viewer_bypass(run)
    collaborators, _ = run.got("collaborators")
    repository, _ = run.got("repository")
    roles = collaborators["by_role"] if collaborators else None
    pushers = sum(roles[r] for r in PUSH_ROLES) if roles else None
    counted = (f"{_n(pushers, 'account')} can push: {roles['admin']} admin, {roles['maintain']} maintain, "
               f"{roles['write']} write." if roles else "")
    compared = 0
    for branch in branches:
        need = _branch_requirements(run, branch)
        if "branch_rules" in need["gaps"] and run.settings["branch_rules"]["status"] != "read":
            run.unread(f"branch {_q(branch)}", "which rulesets are in force on it is not known", "branch_rules")
        for ruleset_id, types in sorted(need["rulesets"].items()):
            gates = sorted(set(types) & set(GATES))
            if not gates:
                continue  # a ruleset that asks for no check and no review: nothing a workflow's result feeds
            compared += 1
            label = f"ruleset {ruleset_id}" + (f" {_q(names[ruleset_id])}" if ruleset_id in names else "")
            subject = f"branch {_q(branch)}: {label}"
            asks = f"what it requires ({_names(gates)})"
            actors = listed.get(ruleset_id)
            mine = viewer.get(ruleset_id)
            if actors is None:
                # The list was not read. What GitHub says of the token's own account is still evidence
                # of one identity that can bypass, and never that nobody else can.
                run.unread(subject, "who may bypass it is not known", "ruleset_bypass_actors")
            # Only "pull_request" is the narrower mode. Any other (always, exempt, one this version does
            # not know, or none given) is read as the wider one.
            others = [a for a in actors or [] if a["bypass_mode"] == "pull_request"]
            always = [a for a in actors or [] if a not in others]
            covered = sum(roles[ROLE_BY_ID[a["actor_id"]]] for a in always
                          if roles and a["actor_type"] == "RepositoryRole" and a["actor_id"] in ROLE_BY_ID)
            by_role = bool(pushers) and covered >= pushers
            # An organisation always has an owner, and an owner administers every repository in it. So
            # when one account can push and it is an administrator, it is an organisation administrator.
            sole_owner = (pushers == 1 and roles["admin"] == 1 and repository is not None
                          and repository["owner_type"] == "Organization"
                          and any(a["actor_type"] == "OrganizationAdmin" for a in always))
            evidence = []
            if mine and mine != "never":
                evidence.append("GitHub says the account whose token ran this audit can bypass it: "
                                f"{plain(mine, 30)}.")
            if counted:
                evidence.append(counted)
            if always or mine == "always":
                who = _names(_actor_text(a) + ("" if a["bypass_mode"] == "always" else
                                               f" (mode: {plain(a['bypass_mode'] or 'not given', 30)})")
                             for a in always) or "the account whose token ran this audit"
                tail = (" Every account that can push holds one of those roles, so the ruleset holds nobody "
                        "who can author a change." if by_role else
                        " One account can push and it is an administrator. An organisation always has an "
                        "owner, who administers every repository, so that account is an organisation "
                        "administrator: the ruleset holds nobody who can author a change." if sole_owner else "")
                run.finding(subject, "high" if by_role or sole_owner else "medium",
                            f"The {label} is in force on {_q(branch)}, and {who} may always bypass it: push or "
                            f"merge without {asks}.{tail}", evidence)
                if always and not (by_role or sole_owner) and roles is None:
                    run.unread(subject + ": how many it covers",
                               "whether the bypass covers everyone who can push is not known", "collaborators")
            elif others or (mine and mine != "never"):
                who = _names(_actor_text(a) for a in others) or "the account whose token ran this audit"
                how = ("when merging a pull request" if others or mine in ("pull_request", "pull_requests_only")
                       else f"(GitHub's word for how: {plain(mine, 30)})")
                run.finding(subject, "low",
                            f"The {label} is in force on {_q(branch)}, and {who} may bypass it {how}: merge "
                            f"without {asks}.", evidence)
        classic = need["classic"]
        if classic is not None and classic["exists"]:
            compared += 1
            subject = f"branch {_q(branch)}: classic protection"
            if not classic["enforce_admins"]:
                admins = roles["admin"] if roles else None
                everyone = bool(pushers) and admins == pushers
                run.finding(subject, "high" if everyone else "medium",
                            f"The classic protection rule on {_q(branch)} does not hold administrators to it: "
                            "they can push or merge without its required checks and reviews."
                            + (f" All {_n(pushers, 'account')} that can push are administrators, so the rule "
                               "holds nobody who can author a change." if everyone else ""),
                            [counted] if counted else [])
                if roles is None:
                    run.unread(subject + ": how many it covers",
                               "whether every account that can push is an administrator is not known",
                               "collaborators")
            reviews = classic["required_pull_request_reviews"]
            if reviews["required"]:
                allowed = reviews["bypass_allowances"]
                groups = [] if allowed is None else [allowed[g] for g in ("users", "teams", "apps")]
                if allowed is None or any(g is None for g in groups):
                    run.cannot_tell(subject + ": who may skip its reviews",
                                    f"The classic rule on {_q(branch)} requires reviews, and GitHub's answer did "
                                    "not say who may bypass them.")
                named = sum(len(g or []) for g in groups)
                if named:
                    run.finding(subject + ": who may skip its reviews", "medium",
                                f"The classic protection rule on {_q(branch)} requires reviews and lets "
                                f"{_n(named, 'user, team or app', 'users, teams or apps')} bypass that: they "
                                "can change the branch without a reviewed pull request.")
        elif need["classic_unknown"]:
            run.unread(f"branch {_q(branch)}: classic protection",
                       "whether the branch has a classic protection rule, and whether administrators are held "
                       "to it, is not known", "branch_protection")
    if compared:
        run.compared = (f"{_n(compared, 'set')} of rules that ask for checks or reviews, in force on "
                        f"{_n(len(branches), 'audited branch', 'audited branches')}")
    elif not run.results:
        run.idle = "no ruleset or classic rule that asks for checks or reviews is in force on an audited branch"


def rule_005(run: _Run) -> None:
    branches = _branches(run)
    collaborators, people_known = run.got("collaborators")
    compared = 0
    for branch in branches:
        need = _branch_requirements(run, branch)
        subject = f"branch {_q(branch)}"
        required = need["approvals"]
        if not required:
            if not need["approvals_whole"]:
                run.unread(subject, "how many approvals it requires is not known",
                           *sorted(set(need["gaps"])))
            continue
        compared += 1
        if collaborators is None or not people_known:
            run.unread(subject, f"it requires {_n(required, 'approval')}, and how many accounts can give one is "
                                "not known", "collaborators")
            continue
        roles = collaborators["by_role"]
        can = sum(roles[r] for r in PUSH_ROLES)
        if can - 1 >= required and not need["approvals_whole"]:
            run.unread(subject, f"its rulesets require {_n(required, 'approval')}, which {_n(can, 'account')} "
                                "can give each other, and a classic protection rule may ask for more",
                       *sorted(set(need["gaps"])))
        elif can - 1 < required:
            run.finding(subject, "medium",
                        f"{_q(branch)} requires {_n(required, 'approval')}, and {_n(can, 'account')} "
                        f"{'has' if can == 1 else 'have'} the write access an approval needs. Nobody can "
                        "approve their own pull request, so a pull request from "
                        f"{'that account' if can == 1 else 'any of them'} can get at most "
                        f"{_n(max(can - 1, 0), 'approval')}: it merges only by a bypass."
                        + ("" if need["approvals_whole"] else " (The classic protection rule was not read; it "
                           "can only ask for more.)"))
    if compared:
        run.compared = f"the approvals required on {_n(compared, 'branch', 'branches')} and the accounts that can give them"
    elif not run.results:
        run.idle = "no audited branch requires an approval"


def _check_rules(run: _Run, kind: str) -> None:
    """OBAAF-SET-006, 007 and 008 share their reading of the required checks."""
    branches = _branches(run)
    reporting = [(f, j) for f, j in run.jobs() if _stands_alone(f)]
    broken = run.broken()
    compared = 0
    for branch in branches:
        need = _branch_requirements(run, branch)
        subject = f"branch {_q(branch)}"
        required = need["checks"]
        if not need["checks_whole"]:
            run.unread(subject, "the list of its required checks is not known to be whole",
                       *sorted(set(need["gaps"])))
        source = (" The checks of the classic protection rule are taken from what GitHub shows anyone; the "
                  "rule itself was not read." if need["from_public_view"] else "")
        if kind == "missing":
            for context, app in sorted(required.items()):
                compared += 1
                item = f"{subject}: required check {_q(context)}"
                if app is not None and app != ACTIONS_APP:
                    run.cannot_tell(item, f"{_q(branch)} requires {_q(context)} from the app with id "
                                          f"{plain(app, 20)}, which is not GitHub Actions. What that app reports "
                                          "is not something the audit reads.")
                    continue
                verdicts = [_reports(job, context) for _, job in reporting]
                if any(v is True for v in verdicts):
                    continue
                unsure = sum(1 for v in verdicts if v is None)
                if broken or unsure:
                    why = ([f"{_n(len(broken), 'workflow file')} could not be read"] if broken else []) + (
                        [f"{_do(unsure, 'job', 'reports', 'report')} under names that could not be written "
                         "out (a computed name, a matrix or a called workflow that was not read)"] if unsure else [])
                    run.cannot_tell(item, f"No job is known to report {_q(context)}, and {' and '.join(why)}, so "
                                          "whether anything reports it is not known.")
                    continue
                if app != ACTIONS_APP:
                    run.cannot_tell(item, f"No workflow job reports {_q(context)}. The requirement does not "
                                          "say it must come from GitHub Actions, so another app or a commit "
                                          "status may report it.")
                    continue
                writers = _api_reporters(run)
                if writers == "no":
                    run.finding(item, "medium",
                                f"{_q(branch)} requires the check {_q(context)} from GitHub Actions. No job in "
                                f"the {_n(len(run.files()), 'workflow file')} reports a check of that name, and "
                                "no job's token may write checks or statuses, so no step can report it either. "
                                f"It stays pending on every pull request, so nothing merges without a bypass.{source}")
                else:
                    run.cannot_tell(item, f"No job reports a check named {_q(context)}. "
                                          + ("A job's token may write checks or statuses" if writers == "yes" else
                                             "A job declares no permissions, and the repository's default for "
                                             "the token was not read") + ", so a step could report it under "
                                          "that name; whether one does is not known.")
        elif kind == "filtered":
            for context in sorted(required):
                matches = [(f, j) for f, j in reporting if _reports(j, context) is True]
                if not matches:
                    continue  # nothing is known to report it: OBAAF-SET-006's subject
                compared += 1
                runs = sorted(((_report_run(f, j, branch), f, j) for f, j in matches),
                              key=lambda item: ORDER.index(item[0]))
                how, file, job = runs[0]
                item = f"{subject}: required check {_q(context)}"
                lead = f"{_q(branch)} requires the check {_q(context)}, which {_job_label(file, job)} reports"
                if how == "always":
                    continue
                if how == "maybe":
                    run.cannot_tell(item, f"{lead}. Whether that workflow runs for pull requests into {_q(branch)} "
                                          "rests on a branch pattern, which is not evaluated.")
                elif how == "paths":
                    run.finding(item, "medium",
                                f"{lead}, and that workflow runs only when certain paths change. On any other "
                                f"pull request the check never reports and the merge stays blocked.{source}")
                elif how == "types":
                    kinds = sorted({plain(t, 40) for e in PULL_REQUEST_EVENTS if e in file["triggers"]
                                    for t in file["triggers"][e]["types"] or []})
                    run.finding(item, "medium",
                                f"{lead}, and that workflow runs only for some kinds of pull request activity "
                                f"({_names(kinds)}), not whenever a pull request is opened or updated. Until "
                                f"it runs the check does not report and the merge stays blocked.{source}")
                elif how == "manual":
                    run.cannot_tell(item, f"{lead}, and nothing in that workflow's triggers runs it for a pull "
                                          "request: it reports when someone or something dispatches it on the "
                                          "pull request's branch. Whether that happens for every pull request "
                                          "is not something the audit reads.")
                elif _api_reporters(run) == "no":
                    run.finding(item, "medium",
                                f"{lead}, and that job is started only by {_names(sorted(_events(job)))}, which "
                                f"never runs on the commit of a pull request into {_q(branch)}. No job's token "
                                "may write checks or statuses, so nothing else reports it there: the check "
                                f"stays pending and the merge stays blocked.{source}")
                else:
                    run.cannot_tell(item, f"{lead}, and that job is started only by "
                                          f"{_names(sorted(_events(job)))}, which never runs on the commit of a "
                                          f"pull request into {_q(branch)}. A job's token may write checks or "
                                          "statuses (or the default for it was not read), so a step could "
                                          "report it there; whether one does is not known.")
        else:
            if not need["checks_whole"]:
                continue
            unrequired, unsure = [], 0
            for file, job in reporting:
                if job["advisory"]:
                    continue
                how = _report_run(file, job, branch, pushes=False)
                if how == "maybe":
                    # A branch pattern decides whether it runs for pull requests into this branch.
                    unsure += 1
                    continue
                if how != "always":
                    continue
                names = job["check"]["names"]
                if job["check"]["kind"] != "computed" and names is not None:
                    # Every check the job reports must be required: one of a matrix's checks, or one of a
                    # called workflow's, being required leaves the others free to fail.
                    compared += 1
                    loose = [name for name in names if name not in required]
                    if loose:
                        unrequired.append((file, job, loose, len(names)))
                    continue
                verdicts = [_reports(job, context) for context in required]
                if job["check"]["kind"] != "computed" and not any(v is not False for v in verdicts):
                    compared += 1
                    unrequired.append((file, job, None, None))
                    continue
                # Its names could not be written out, so whether every one of them is required is not known.
                unsure += 1
            if unrequired and not required:
                run.finding(f"{subject}: no required check", "medium",
                            f"No check is required on {_q(branch)}, and "
                            f"{_do(len(unrequired), 'job', 'runs', 'run')} on every pull request into it "
                            f"({_names(_job_label(f, j) for f, j, *_ in unrequired)}). A pull request can merge "
                            f"while any of them is failing.{source}")
                unrequired = []
            for file, job, loose, total in unrequired:
                name = job["check"]["name"]
                if loose is not None and total > 1 and len(loose) < total:
                    shape = (f"reports {total} checks, of which {len(loose)} {'is' if len(loose) == 1 else 'are'} "
                             f"not ({_names(_q(n) for n in loose)})")
                elif loose is not None and total > 1:
                    shape = f"reports {total} checks ({_names(_q(n) for n in loose)}), none of which is"
                else:
                    shape = {"matrix": f"reports its checks as {_q(name + ' (...)')}, none of which is",
                             "calls": f"reports the checks of the workflow it calls as {_q(name + ' / ...')}, "
                                      "none of which is"}.get(job["check"]["kind"],
                                                              f"reports the check {_q(name)}, which is not")
                run.finding(f"{subject}: job {_job_label(file, job)}", "medium",
                            f"{_job_label(file, job)} runs on every pull request into {_q(branch)} and {shape} "
                            f"required ({_do(len(required), 'check', 'is', 'are')} required there). A pull "
                            f"request can merge while the job is failing.{source}")
            if unsure:
                run.cannot_tell(f"{subject}: jobs whose check names could not be written out",
                                f"{_n(unsure, 'job')} that may run on pull requests into {_q(branch)}: "
                                f"{'its' if unsure == 1 else 'their'} check names could not all be written out "
                                "(a computed name, a matrix or a called workflow that was not read), or a branch "
                                "pattern in the triggers decides whether it runs there (patterns are not "
                                f"evaluated), so whether {'it' if unsure == 1 else 'each'} can fail without "
                                "blocking a merge was not compared.")
    if compared:
        run.compared = {"missing": f"{_n(compared, 'required check')} and the names the jobs report",
                        "filtered": f"{_n(compared, 'required check')} that a job reports, and its triggers",
                        }.get(kind, f"{_n(compared, 'job')} running on every pull request, and the required checks")
    elif not run.results:
        run.idle = {"missing": "no audited branch requires a check",
                    "filtered": "no required check is known to be reported by a workflow job",
                    }.get(kind, "no job runs on every pull request into an audited branch")


def rule_006(run: _Run) -> None:
    _check_rules(run, "missing")


def rule_007(run: _Run) -> None:
    _check_rules(run, "filtered")


def rule_008(run: _Run) -> None:
    _check_rules(run, "not-required")


# ---------------------------------------------------------------- rules about Actions settings
def _policy_scope(policy: dict, path: str):
    """Whether a policy applies to a workflow file: True, False, or None when its conditions are not in
    the one form this rule understands (a list of workflow paths to include and to exclude)."""
    conditions = policy["conditions"]
    if not isinstance(conditions, dict):
        return None
    if set(conditions) - {"workflow_path", "repository_name", "repository_id"}:
        return None
    scope = conditions.get("workflow_path")
    if not isinstance(scope, dict) or set(scope) - {"include", "exclude"}:
        return None
    include, exclude = _strings(scope.get("include")), _strings(scope.get("exclude", []))
    if include is None or exclude is None:
        return None

    def hit(patterns) -> bool:
        return any(p == "~ALL" or p.lstrip("/") == path or fnmatch.fnmatchcase(path, p.lstrip("/")) for p in patterns)

    return hit(include) and not hit(exclude)


def _event_rules(policy: dict):
    """The lists of allowed events in a policy's rules. None when any of its rules is in a form this
    rule does not know: only a rule that carries a list of allowed events, or one that carries a list of
    allowed actors (who may start a workflow, which is not compared here), is understood."""
    found = []
    for rule in policy["rules"]:
        parameters = rule["parameters"]
        if not isinstance(parameters, dict):
            return None
        if "allowed_events" in parameters:
            events = _strings(parameters["allowed_events"])
            if events is None:
                return None
            found.append(events)
        elif not isinstance(parameters.get("allowed_actors"), list):
            return None
    return found


def _policy_verdicts(file: dict, policies: list):
    """For one workflow file: the event rules that apply to it, as (policy, allowed events), from policies
    that are enforced or in evaluate mode; and the policies this rule cannot read (their rules, their
    scope or their enforcement is not in the form it understands)."""
    applying, unclear = [], []
    for policy in policies:
        if policy["enforcement"] == "disabled":
            continue  # switched off: nothing for these rules to compare
        events = _event_rules(policy)
        if events is None or policy["enforcement"] not in ("active", "evaluate"):
            unclear.append(policy)
            continue
        if not events:
            continue  # only about who may start a workflow
        applies = _policy_scope(policy, file["path"])
        if applies is None:
            unclear.append(policy)
        elif applies:
            applying += [(policy, allowed) for allowed in events]
    return applying, unclear


def rule_009(run: _Run) -> None:
    files = [f for f in run.files() if f["triggers"]]
    if not files:
        run.idle = "no workflow file with a trigger was read"
        return
    policies, whole = run.got("actions_policies")
    if policies is None:
        events = sorted({e for f in files for e in f["triggers"]})
        run.unread("Actions policies",
                   f"{_do(len(files), 'workflow', 'uses', 'use')} {_n(len(events), 'event')} ({_names(events, 8)}), and "
                   "whether a policy blocks any of them is not known. An administrator can read the policies "
                   "in the repository's settings", "actions_policies")
        return
    if not whole:
        run.unread("Actions policies", "some policies were not read", "actions_policies")
    run.compared = (f"{_n(len(policies), 'Actions policy', 'Actions policies')} and the events of "
                    f"{_n(len(files), 'workflow')}")
    reported = set()
    for file in files:
        applying, unclear = _policy_verdicts(file, policies)
        for policy in unclear:
            if policy["id"] not in reported:
                reported.add(policy["id"])
                run.cannot_tell(f"policy {_q(policy['name'])}",
                                f"The policy {_q(policy['name'])} is not in a form this rule understands (its "
                                "rules, its conditions or its enforcement), so which workflows and events it "
                                "blocks is not known.")
        for policy, allowed in applying:
            # workflow_call is how a workflow is called by another, not an event of its own.
            blocked = sorted(e for e in file["triggers"] if e not in allowed and e != "workflow_call")
            if not blocked:
                continue
            active = policy["enforcement"] == "active"
            run.finding(f"workflow {plain(file['path'], 120)}: policy {_q(policy['name'])}",
                        "medium" if active else "low",
                        f"{plain(file['path'], 120)} is started by {_names(blocked)}, and the Actions policy "
                        f"{_q(policy['name'])} allows only {_names(allowed, 12) or 'no event'} for it. "
                        + ("A run for a blocked event fails at startup with no job, so nothing it was meant to "
                           "check is checked." if active else
                           "The policy is in evaluate mode: nothing is blocked today, and it will be once the "
                           "policy is enforced."))


def rule_010(run: _Run) -> None:
    files = [f for f in run.files() if "pull_request_target" in f["triggers"]]
    if not files:
        run.idle = "no workflow is started by pull_request_target"
        return
    repository, _ = run.got("repository")
    if repository is None or repository["visibility"] != "public":
        run.idle = "the repository is not public, and the default policy is for public repositories"
        return
    policies, whole = run.got("actions_policies")
    shown = _names(plain(f["path"], 120) for f in files)
    if policies is None or not whole:
        run.unread("pull_request_target",
                   f"{_n(len(files), 'workflow')} in this public repository {'is' if len(files) == 1 else 'are'} "
                   f"started by pull_request_target ({shown}). By GitHub's changelog of 2026-11-02, from "
                   f"{DEFAULT_POLICY_DATE} a default policy blocks that event in public repositories unless a "
                   "policy allows it. Whether one does is not known", "actions_policies")
        return
    run.compared = f"{_n(len(files), 'pull_request_target workflow')} and the Actions policies"
    for file in files:
        applying, unclear = _policy_verdicts(file, policies)
        if any(policy["enforcement"] == "active" and "pull_request_target" in allowed
               for policy, allowed in applying):
            continue
        subject = f"workflow {plain(file['path'], 120)}"
        if unclear or any(policy["enforcement"] != "active" for policy, _ in applying):
            run.cannot_tell(subject, f"{plain(file['path'], 120)} is started by pull_request_target, and a "
                                     "policy that may apply to it is in evaluate mode or is not in a form this "
                                     "rule understands, so whether the event stays allowed after "
                                     f"{DEFAULT_POLICY_DATE} is not known.")
        elif not applying:
            run.finding(subject, "medium",
                        f"{plain(file['path'], 120)} is started by pull_request_target in a public repository, "
                        "and no Actions policy that applies to it allows that event. By GitHub's changelog of "
                        f"2026-11-02, from {DEFAULT_POLICY_DATE} a default policy blocks the event in public "
                        "repositories that have no policy allowing it, and the workflow then fails at startup.")
        # An enforced policy that applies and does not allow the event is OBAAF-SET-009's finding.


def rule_012(run: _Run) -> None:
    bare = [(f, j) for f, j in run.jobs() if not j["permissions"]["declared"]]
    if not bare:
        run.idle = "every job declares its permissions"
        return
    value, _ = run.got("workflow_permissions")
    if value is None:
        run.unread("the default token permissions",
                   f"{_do(len(bare), 'job', 'declares no permissions and gets', 'declare no permissions and get')} "
                   "the repository's default, which is not known", "workflow_permissions")
        return
    default = value["default_workflow_permissions"]
    if default not in ("read", "write"):
        run.cannot_tell("the default token permissions",
                        f"GitHub gave the default for the workflow token as {_q(default, 30)}, a word this rule "
                        "does not know.")
        return
    run.compared = f"{_n(len(bare), 'job')} with no permissions block and the default for the workflow token"
    if default != "write":
        return
    by_file: dict = {}
    for file, job in bare:
        by_file.setdefault(file["path"], []).append(job["id"])
    for path, ids in sorted(by_file.items()):
        run.finding(f"workflow {plain(path, 120)}", "medium",
                    f"The repository's default for the workflow token is read and write, and "
                    f"{_n(len(ids), 'job')} in {plain(path, 120)} {'declares' if len(ids) == 1 else 'declare'} no "
                    f"permissions ({_names(plain(i, 60) for i in ids)}), so each gets a token that can write.")


def rule_013(run: _Run) -> None:
    # Not limited to the jobs in these files: anyone who can push a branch can add a workflow there that
    # asks for `pull-requests: write`, which a job may do whatever the repository's default, and run it.
    value, _ = run.got("workflow_permissions")
    if value is None:
        run.unread("whether workflows may approve pull requests",
                   "a workflow on any branch can ask for a token that writes to pull requests, and whether "
                   "workflows are allowed to approve them is not known", "workflow_permissions")
        return
    branches = _branches(run)
    run.compared = (f"whether workflows may approve pull requests, and the approvals {_n(len(branches), 'audited branch')} "
                    "require")
    if not value["can_approve_pull_request_reviews"]:
        return
    lead = ("The repository lets workflows approve pull requests. A workflow can ask for a token that writes to "
            "pull requests whatever the default, and anyone who can push a branch can add one there and run it.")
    for branch in branches:
        need = _branch_requirements(run, branch)
        subject = f"branch {_q(branch)}"
        count = need["approvals"]
        if not count:
            if not need["approvals_whole"]:
                run.unread(subject, f"{lead[:-1]}, and how many approvals {_q(branch)} requires is not known",
                           *sorted(set(need["gaps"])))
            continue
        if need["code_owner"] and count == 1:
            # The one approval must then come from a code owner where a file has one; a workflow is no code
            # owner. Whether every file has one (the CODEOWNERS file) is not read.
            run.cannot_tell(subject, f"{lead} {_q(branch)} requires 1 approval and a code owner's review. Where "
                                     "every changed file has a code owner, the workflow's approval cannot be the "
                                     "one that counts; where one has none, it can. The CODEOWNERS file is not "
                                     "read.")
            continue
        extra = (" A code owner's review is required as well, and a workflow's approval still counts towards the "
                 "number." if need["code_owner"] else "")
        run.finding(subject, "medium",
                    f"{lead} {_q(branch)} requires {_n(count, 'approval')}, so a run of such a workflow can give "
                    f"one.{extra}")


def rule_014(run: _Run) -> None:
    # A fork's pull request runs the workflow files of its own commit, not the ones here: it can add a job,
    # name any runner label and read any secret it is sent. So what the jobs in these files do decides
    # nothing on its own; it can only show that the repository has self-hosted runners.
    repository, _ = run.got("repository")
    if repository is None:
        run.unread("fork pull requests", "whether the repository is public is not known", "repository")
        return
    public = repository["visibility"] == "public"
    value, _ = run.got("fork_pull_requests")
    if value is None or (not public and value.get("private_repository") is None):
        run.unread("fork pull requests",
                   "what a fork's pull request may run here "
                   + ("(whose need approval first)" if public else "(and what it is sent)") + " is not known",
                   "fork_pull_requests")
        return
    if public:
        run.compared = "the approval rule for fork pull requests, and the runners the pull_request jobs name"
        policy = value["approval_policy"]
        if policy == "all_external_contributors":
            return
        hosted_here = [(f, j) for f, j in run.jobs() if "pull_request" in _events(j) and j["runner"] == "self-hosted"]
        if hosted_here:
            file, job = hosted_here[0]
            run.finding("fork pull requests on self-hosted runners", "high",
                        f"{_do(len(hosted_here), 'pull_request job', 'runs', 'run')} on a self-hosted runner (the "
                        f"first: {_job_label(file, job)}), and approval before a fork's workflows run is required "
                        f"only for {_q(policy)}. Anyone else can run their code on that machine by opening a pull "
                        "request, and a fork's copy of the workflow can name the runner whatever this one says.")
            return
        run.cannot_tell("fork pull requests and self-hosted runners",
                        f"Approval before a fork's workflows run is required only for {_q(policy)}. A fork's pull "
                        "request runs its own copy of the workflow files, so it can ask for any runner label. No "
                        "pull_request job here names a self-hosted runner, and whether the repository has any is "
                        "not something the audit reads; if it has, strangers' code can run there.")
        return
    private = value["private_repository"]
    run.compared = "what fork pull requests are sent in this private repository"
    if not private["run_workflows_from_fork_pull_requests"]:
        return
    sent = [what for key, what in (("send_secrets_and_variables", "secrets and variables"),
                                   ("send_write_tokens_to_workflows", "a write token")) if private[key]]
    if sent:
        run.finding("fork pull requests in a private repository", "high",
                    f"Fork pull requests run workflows here and are sent {' and '.join(sent)}. A fork's pull "
                    "request runs its own copy of the workflow files, so it can read every secret it is sent, "
                    "whatever the jobs here do.")


def rule_015(run: _Run) -> None:
    using = [(f, j) for f, j in run.jobs() if j["actions"]]
    unpinned = [(f, j) for f, j in using if j["unpinned"]]
    if not using:
        run.idle = "no job uses an action from another repository"
        return
    value, _ = run.got("actions_permissions")
    if value is None or value["sha_pinning_required"] is None:
        what = (f"{_do(len(unpinned), 'job', 'uses', 'use')} an action that is not pinned to a full commit, and whether "
                "the repository requires pinning is not known" if unpinned else
                "every action the jobs use is pinned to a full commit, and whether the repository requires "
                "that is not known")
        if value is None:
            run.unread("pinning to a commit", what, "actions_permissions")
        else:
            run.cannot_tell("pinning to a commit", f"{what[:1].upper()}{what[1:]}: GitHub's answer did not say.")
        return
    run.compared = f"the actions of {_n(len(using), 'job')} and the pinning requirement"
    if value["sha_pinning_required"]:
        by_file: dict = {}
        for file, job in unpinned:
            by_file.setdefault(file["path"], set()).update(job["unpinned"])
        for path, actions in sorted(by_file.items()):
            run.finding(f"workflow {plain(path, 120)}", "medium",
                        f"The repository requires actions to be pinned to a full commit, and {plain(path, 120)} "
                        f"uses {_names(sorted(_q(a, 100) for a in actions), 4)}. GitHub refuses a workflow "
                        "that uses an action that is not pinned.")
    elif not unpinned:
        run.finding("pinning to a commit is not required", "low",
                    f"Every action in the {_n(len(using), 'job')} that use one is pinned to a full commit, and "
                    "the repository does not require it, so nothing stops the next change from adding one that "
                    "is not.")


RULE_FUNCTIONS = {
    "OBAAF-SET-001": rule_001, "OBAAF-SET-002": rule_002, "OBAAF-SET-003": rule_003, "OBAAF-SET-004": rule_004,
    "OBAAF-SET-005": rule_005, "OBAAF-SET-006": rule_006, "OBAAF-SET-007": rule_007, "OBAAF-SET-008": rule_008,
    "OBAAF-SET-009": rule_009, "OBAAF-SET-010": rule_010, "OBAAF-SET-011": rule_011, "OBAAF-SET-012": rule_012,
    "OBAAF-SET-013": rule_013, "OBAAF-SET-014": rule_014, "OBAAF-SET-015": rule_015,
}


# ---------------------------------------------------------------- everything
def _order(result: dict):
    rank = SEVERITIES.index(result["severity"]) if result["severity"] in SEVERITIES else len(SEVERITIES)
    return (result["state"] != "finding", rank, result["rule"], result["subject"], result["message"])


def evaluate(snapshot: dict, usage: dict) -> dict:
    """Run every rule on a snapshot and the workflows' usage. Returns the results and, for each rule, what
    became of it: ``findings``, ``cannot-tell``, ``no-finding`` (with what was compared) or
    ``not-applicable`` (with why there was nothing to compare)."""
    results, rules = [], []
    repository_read = snapshot["settings"]["repository"]["status"] == "read"
    for rule in RULES:
        run = _Run(rule, snapshot, usage)
        if not repository_read:
            run.cannot_tell("the repository", "The repository itself was not read, so no setting was.",
                            ["repository"])
        elif rule.files and not usage["read"]:
            run.cannot_tell("the workflow files",
                            f"The workflow files were not read ({plain(usage['reason'], 200)}), and this rule "
                            f"compares settings with {rule.compares}.")
        else:
            try:
                RULE_FUNCTIONS[rule.id](run)
            except Exception as exc:  # noqa: BLE001 - a rule that fails must not read as a rule that found nothing
                run.results = []
                run.cannot_tell("this rule", f"The rule failed ({type(exc).__name__}). This is a bug in obaaf; "
                                             "the rule established nothing.")
                run.failed = True
            if rule.files and usage["read"] and run.broken():
                # What a rule did not find in the files that parsed says nothing of a file that did not.
                run.cannot_tell("workflow files that were not read",
                                f"{_n(len(run.broken()), 'workflow file')} could not be read "
                                f"({_names(plain(f['path'], 100) for f in run.broken())}), so what "
                                f"{'it uses' if len(run.broken()) == 1 else 'they use'} was not compared.")
        findings = [r for r in run.results if r["state"] == "finding"]
        unknown = [r for r in run.results if r["state"] == "cannot-tell"]
        status = ("findings" if findings else "cannot-tell" if unknown else
                  "no-finding" if run.compared else "not-applicable")
        note = run.compared if status == "no-finding" else run.idle if status == "not-applicable" else ""
        rules.append({"id": rule.id, "title": rule.title, "status": status, "findings": len(findings),
                      "cannot_tell": len(unknown),
                      "note": note or ("" if findings or unknown else "nothing to compare"),
                      "failed": run.failed})
        results += run.results
    results.sort(key=_order)
    findings = [r for r in results if r["state"] == "finding"]
    return {
        "format": FORMAT,
        "results": results,
        "rules": rules,
        "summary": {"findings": len(findings),
                    **{sev: sum(1 for r in findings if r["severity"] == sev) for sev in SEVERITIES},
                    "cannot_tell": sum(1 for r in results if r["state"] == "cannot-tell"),
                    "rules_cannot_tell": sum(1 for r in rules if r["cannot_tell"]),
                    "rules_failed": sum(1 for r in rules if r["failed"])},
    }


def fails(assessment: dict, fail_on: str) -> bool:
    """Whether any finding is at or above ``fail_on`` (high, medium, low or never)."""
    if fail_on == "never":
        return False
    floor = SEVERITIES.index(fail_on)
    return any(r["state"] == "finding" and SEVERITIES.index(r["severity"]) <= floor
               for r in assessment["results"])
