"""The settings rules: what a snapshot of GitHub settings means for the workflows that depend on them.

Each rule compares a setting with something a workflow in the repository uses or assumes: the environment
a job names, the checks its jobs report, the events that start it, the secrets it reads. A setting no
workflow depends on is not judged; this is not a checklist for an organisation.

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
from obaaf.checker.workflow import PRIVILEGED_UNTRUSTED_TRIGGERS

FORMAT = "obaaf-settings-findings/v0.1"
SEVERITIES = ("high", "medium", "low")
# The id of the GitHub Actions app. A required check tied to it can only be reported by a workflow job.
ACTIONS_APP = 15368
# Built-in repository roles as a ruleset's bypass list names them.
ROLE_BY_ID = {2: "maintain", 4: "write", 5: "admin"}
PUSH_ROLES = ("admin", "maintain", "write")
DEFAULT_POLICY_DATE = "2026-12-02"
WILDCARDS = "*?["


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str            # the highest severity it reports
    reads: tuple[str, ...]   # the settings it needs
    compares: str            # what in the workflow files it is compared with
    description: str
    fix: str


RULES: tuple[Rule, ...] = (
    Rule("OBAAF-SET-001", "An environment's secrets can be reached from any branch", "high",
         ("environments",), "the environment each job names",
         "A job names an environment, and the environment does not limit which branches may use it (or the "
         "limit is a pattern anyone with write access can match by naming a branch or pushing a tag). Anyone "
         "who can push a branch can add a job that names the environment and reads its secrets. With required "
         "reviewers the only gate left is one person's approval; without them there is none. An environment a "
         "job names that does not exist is created by GitHub on first use, with no protection at all.",
         "In the environment's settings, limit deployment to selected branches and name the default branch "
         "(and the release tags, behind a tag ruleset). Add required reviewers where a person should decide."),
    Rule("OBAAF-SET-002", "A job outsiders can start gets an environment that asks nobody", "high",
         ("environments", "environment_secrets"), "jobs started by pull_request_target, issue and comment events",
         "A job that runs on an event people without write access can cause (pull_request_target, "
         "issue_comment, issues, workflow_run and the like) names an environment that has no required "
         "reviewers. Those events run on the default branch, so a limit on which branches may deploy lets "
         "them through: nothing stands between the event and the environment's secrets.",
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
         ("ruleset_bypass_actors", "branch_protection", "collaborators", "branch_rules"),
         "the required checks and reviews the workflows' results feed",
         "A ruleset in force on the branch lists who may bypass it, or classic branch protection does not "
         "hold administrators to it. Whoever is on that list can push or merge without the required checks "
         "and reviews. When everyone who can push is on it, the rules hold nobody.",
         "Remove the bypass, or narrow it to an identity that does not author changes (a break-glass team). "
         "For classic protection, turn on \"Do not allow bypassing the above settings\"."),
    Rule("OBAAF-SET-005", "Required approvals cannot be given", "medium",
         ("branch_rules", "branch_protection", "collaborators"), "pull requests into the branch",
         "The branch requires more approvals than the people who can approve can give: an author cannot "
         "approve their own pull request, and only accounts with write access count. Every merge then needs "
         "a bypass, which trains everyone to bypass.",
         "Lower the required approvals to what the team can give, or give a second person write access. Do "
         "not solve it with a bypass."),
    Rule("OBAAF-SET-006", "A required check that no workflow job reports", "medium",
         ("branch_rules", "branch_protection", "branches"), "the check name each job reports",
         "The branch requires a check by a name that no job in the workflow files reports (a job was renamed, "
         "or removed, or the name was mistyped). The check stays pending on every pull request, so nothing "
         "merges without a bypass.",
         "Correct the name in the ruleset or branch protection to the one the job reports, or remove it."),
    Rule("OBAAF-SET-007", "A required check that a path filter can skip", "medium",
         ("branch_rules", "branch_protection", "branches"), "the paths filters on the workflows' triggers",
         "The branch requires a check whose workflow runs only when certain paths change. On a pull request "
         "that touches nothing in those paths the workflow is skipped, the check never reports, and GitHub "
         "leaves the merge blocked.",
         "Remove the paths filter and skip inside the job instead (a job skipped by `if:` reports as "
         "passed), or stop requiring the check."),
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
         "Declare the environment on the job inside the reusable workflow; that job then reads the "
         "environment's secret itself. Do not copy the secret to the repository."),
    Rule("OBAAF-SET-012", "Jobs with no permissions block get a token that can write", "medium",
         ("workflow_permissions",), "jobs that declare no `permissions`",
         "The repository's default for the workflow token is read and write, and a job declares no "
         "permissions, so it gets a token that can push, comment and release.",
         "Set the default to read in Settings, Actions, General, and give each job the permissions it needs."),
    Rule("OBAAF-SET-013", "A workflow can approve pull requests", "medium",
         ("workflow_permissions", "branch_rules"), "jobs whose token can write to pull requests",
         "Workflows are allowed to approve pull requests, and a job holds `pull-requests: write`. A run of "
         "that job can approve a pull request, which is not the review by a person that a required approval "
         "is meant to be.",
         "Turn off \"Allow GitHub Actions to create and approve pull requests\" in Settings, Actions, General."),
    Rule("OBAAF-SET-014", "Fork pull requests run on the repository's runners or with its secrets", "high",
         ("fork_pull_requests", "repository"), "pull_request jobs on self-hosted runners, or that read secrets",
         "In a public repository a pull_request job runs on a self-hosted runner, and approval is not "
         "required for every outside contributor: a stranger's code runs on a machine that keeps state. Or, "
         "in a private repository, fork pull requests are sent secrets or a write token.",
         "Require approval for all external contributors, or move the job to a GitHub-hosted runner. In a "
         "private repository, do not send secrets or write tokens to fork pull requests."),
    Rule("OBAAF-SET-015", "Pinning actions to a commit: the setting and the workflows disagree", "medium",
         ("actions_permissions",), "the actions each job's steps use",
         "The repository requires actions to be pinned to a full commit and a workflow uses one that is not, "
         "so that workflow is refused. Or every action is pinned today and the repository does not require "
         "it, so nothing stops the next change from adding one that is not.",
         "Pin each action to a full commit SHA, and turn on the requirement in Settings, Actions, General."),
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
           "ruleset_ids": set(), "from_public_view": False, "classic": None, "classic_unknown": False}
    rules, whole = run.got("branch_rules")
    if rules is None or branch not in rules:
        out["checks_whole"] = out["approvals_whole"] = False
        out["gaps"].append("branch_rules")
    else:
        for rule in rules[branch]:
            out["ruleset_ids"].add(rule["ruleset_id"])
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
    """Whether the job reports a check of this name: True, False, or None when its name is computed."""
    check = job["check"]
    if check["kind"] == "computed":
        return None
    name = check["name"]
    if check["kind"] == "matrix":
        return context.startswith(name + " (") and context.endswith(")")
    if check["kind"] == "calls":
        return context.startswith(name + " / ")
    return context == name


def _admits(filters: dict, branch: str):
    """Whether an event's branch filters let the branch through: True, False, or None when a pattern
    decides it (patterns are not evaluated here)."""
    listed, ignored = filters["branches"], filters["branches_ignore"]
    for names, hit in ((listed, True), (ignored, False)):
        if names is None:
            continue
        if any(ch in name for name in names for ch in WILDCARDS + "!"):
            return None
        return hit if branch in names else not hit
    return True


def _pull_request_run(file: dict, job: dict, branch: str) -> str:
    """How the job runs on pull requests into the branch: "always", "paths" (only when certain paths
    change), "maybe" (a branch pattern decides) or "" (not at all)."""
    found = ""
    for event in PULL_REQUEST_EVENTS:
        filters = file["triggers"].get(event)
        if filters is None or event not in job["triggers"]:
            continue
        admitted = _admits(filters, branch)
        if admitted is False:
            continue
        kind = "maybe" if admitted is None else "paths" if filters["paths"] else "always"
        if kind == "always":
            return kind
        found = found if found == "paths" else kind
    return found


def _runs_on_any_push(file: dict, job: dict) -> bool:
    filters = file["triggers"].get("push")
    return (filters is not None and "push" in job["triggers"] and not filters["paths"] and not filters["tags"]
            and filters["branches"] is None and filters["branches_ignore"] is None)


# ---------------------------------------------------------------- rules about environments and secrets
def _environment_users(run: _Run) -> dict:
    """Environment name (lower case, as GitHub compares them) -> the jobs that name it."""
    users: dict = {}
    for file, job in run.jobs():
        env = job["environment"]
        if env and env.get("name"):
            users.setdefault(env["name"].lower(), []).append((file, job))
    return users


def _protected(run: _Run) -> dict:
    config = run.usage.get("config") or {}
    return config.get("protected_secrets") or {}


def _open_pattern(policy: dict) -> bool:
    return bool(policy["name"]) and set(policy["name"]) <= {"*", "/"}


def rule_001(run: _Run) -> None:
    users = _environment_users(run)
    named = {env.lower() for env in _protected(run).values() if env}
    wanted = sorted(set(users) | named)
    if not wanted:
        run.idle = "no job names an environment"
        return
    environments, whole = run.got("environments")
    if environments is None:
        run.unread("environments", f"{_n(len(wanted), 'environment')} that jobs name could not be compared",
                   "environments")
        return
    by_name = {env["name"].lower(): env for env in environments}
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
                            f"The environment {_q(key)} does not exist in the repository's settings, and {who}. "
                            "GitHub creates an environment the first time a job names it, with no branch limit, "
                            "no reviewers and no secrets.")
            continue
        reviewers = bool(env["reviewers"])
        gate = ("Its only protection is its required reviewers"
                + {True: ", and self-review is prevented", False: ", and a reviewer may approve their own run"}.get(
                    env["prevent_self_review"], "") + "." if reviewers else "It has no required reviewers.")
        mode = env["deployment_branches"]
        if mode == "any":
            run.finding(subject, "medium" if reviewers else "high",
                        f"Any branch or tag may use the environment {_q(env['name'])}, and {who}. A job on any "
                        f"branch, a pull request's included, can name it and read its secrets. {gate}")
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
            if wide:
                run.finding(subject, "medium" if reviewers else "high",
                            f"The environment {_q(env['name'])} is limited to the branch pattern "
                            f"{_q(wide[0]['name'])}, which lets nearly every branch through, and {who}. {gate}")
            elif loose and not reviewers:
                shown = _names(f"{'tag' if p['type'] == 'tag' else 'branch'} pattern {_q(p['name'])}" for p in loose)
                run.finding(subject, "medium",
                            f"The environment {_q(env['name'])} may be used from {shown}, it has no required "
                            f"reviewers, and {who}. Anyone with write access can push a branch or tag with such "
                            "a name from any commit, unless a ruleset restricts creating them, which this rule "
                            "does not read.")


def rule_002(run: _Run) -> None:
    exposed = []
    for file, job in run.jobs():
        env = job["environment"]
        events = sorted(set(job["triggers"]) & PRIVILEGED_UNTRUSTED_TRIGGERS)
        if env and env.get("name") and events:
            exposed.append((file, job, env["name"], events))
    if not exposed:
        run.idle = "no job that outsiders' events can start names an environment"
        return
    environments, whole = run.got("environments")
    if environments is None:
        run.unread("environments", f"{_do(len(exposed), 'job', 'that', 'that')} outsiders' events can start "
                                   f"{'names' if len(exposed) == 1 else 'name'} an environment",
                   "environments")
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
        run.finding(subject, "high",
                    f"The job can be started by {_names(events)}, which people without write access can cause, "
                    f"and it names the environment {_q(name)}, {what}. The environment has no required "
                    "reviewers, and these events run on the default branch, so a limit on which branches may "
                    "deploy does not stop them.")


def rule_003(run: _Run) -> None:
    protected = _protected(run)
    env_secrets, env_whole = run.got("environment_secrets")
    repo, repo_whole = run.got("repository_secrets")
    org, org_whole = run.got("organization_secrets")
    environments, envs_whole = run.got("environments")
    read_by_jobs = {name.upper() for _, job in run.jobs() for name in job["secrets"]}
    if not protected and not read_by_jobs:
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
                    f"{_n(len(read_by_jobs), 'secret')} that jobs read")
    reported = set()
    for pattern, env in sorted(protected.items()):
        if env and environments is not None and env.lower() not in {e["name"].lower() for e in environments}:
            if envs_whole:
                run.finding(f"environment {_q(env)}", "high",
                            f"protected_secrets says {_q(pattern)} must stay in the environment {_q(env)}, and "
                            "the repository has no such environment. GitHub creates one the first time a job "
                            "names it, with no branch limit and no reviewers, so the declaration is met by a "
                            "boundary that is not there.")
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
        if name in read_by_jobs:
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
        run.unread("where the secrets are stored", what, *missing)


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
                   f"{_do(len(callers), 'job', 'passes', 'pass')} secrets to a reusable workflow, and whether any of those "
                   "secrets is stored only in an environment is not known",
                   "environment_secrets", "repository_secrets", "organization_secrets")
        return
    wide = {name.upper() for name in list(repo) + list(org)}
    only_env: dict = {}
    for env, names in env_secrets.items():
        for name in names:
            if name.upper() not in wide:
                only_env.setdefault(name.upper(), []).append(env)
    by_path = {file["path"]: file for file in run.usage["files"]}
    run.compared = f"{_n(len(callers), 'job')} passing secrets to a reusable workflow"
    for file, job in callers:
        subject = f"job {_job_label(file, job)}"
        target = job["calls"] or ""
        local = by_path.get(target[2:]) if target.startswith("./") else None
        passes = job["passes"]
        if passes["names"] and not passes["inherit"]:
            # The called workflow sees these under the names the caller gives them; a job in it that
            # declares the environment reads the environment's own secret of that name instead.
            for name in passes["names"]:
                envs = only_env.get(name.upper())
                if not envs:
                    continue
                run.finding(subject, "medium",
                            f"The job passes secrets.{plain(name, 60)} to {_q(target, 120)}. {_q(name)} is stored "
                            f"only in the environment {_names(_q(e) for e in sorted(envs))}, and a job that "
                            "calls a reusable workflow cannot declare an environment, so what it passes is "
                            "empty. A job inside the called workflow that declares the environment reads the "
                            "secret itself, and does not need it passed.")
            continue
        if not only_env:
            continue
        if local is None or local["error"]:
            run.cannot_tell(subject, f"The job passes every secret to {_q(target, 120)}, which was not read "
                                     "(it is in another repository, or could not be parsed). Whether that "
                                     f"workflow reads {_names(_q(n) for n in sorted(only_env))}, stored only in "
                                     "an environment, is not known.")
            continue
        for called in local["jobs"]:
            env = (called["environment"] or {}).get("name", "")
            for name in called["secrets"]:
                envs = only_env.get(name.upper())
                if envs and env.lower() not in {e.lower() for e in envs}:
                    run.finding(subject, "medium",
                                f"The job passes every secret to {_q(target, 120)}, whose job "
                                f"{_q(called['id'])} reads secrets.{plain(name, 60)}. {_q(name)} is stored only "
                                f"in the environment {_names(_q(e) for e in sorted(envs))}, and that job does "
                                "not declare it, so the value it gets is empty.")


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
    roles = collaborators["by_role"] if collaborators else None
    pushers = sum(roles[r] for r in PUSH_ROLES) if roles else None
    viewer_pushes = run.snapshot["viewer"].get("repository_permissions", {}).get("push") is True
    compared = 0
    for branch in branches:
        need = _branch_requirements(run, branch)
        if "branch_rules" in need["gaps"] and run.settings["branch_rules"]["status"] != "read":
            run.unread(f"branch {_q(branch)}", "which rulesets are in force on it is not known", "branch_rules")
        for ruleset_id in sorted(need["ruleset_ids"]):
            compared += 1
            label = f"ruleset {ruleset_id}" + (f" {_q(names[ruleset_id])}" if ruleset_id in names else "")
            subject = f"branch {_q(branch)}: {label}"
            actors = listed.get(ruleset_id)
            mine = viewer.get(ruleset_id)
            if actors is None and mine in (None, "never"):
                run.unread(subject, "who may bypass it is not known", "ruleset_bypass_actors")
                continue
            # Only "pull_request" is the narrower mode. Any other (always, exempt, one this version does
            # not know, or none given) is read as the wider one.
            others = [a for a in actors or [] if a["bypass_mode"] == "pull_request"]
            always = [a for a in actors or [] if a not in others]
            covered = sum(roles[ROLE_BY_ID[a["actor_id"]]] for a in always
                          if roles and a["actor_type"] == "RepositoryRole" and a["actor_id"] in ROLE_BY_ID)
            by_role = bool(pushers) and covered >= pushers
            only_me = bool(pushers) and pushers == 1 and mine == "always" and viewer_pushes
            everyone = by_role or only_me
            evidence = []
            if mine and mine != "never":
                evidence.append(f"GitHub says the account whose token ran this audit can bypass it: "
                                f"{plain(mine, 30)}.")
            if roles:
                evidence.append(f"{_n(pushers, 'account')} can push: {roles['admin']} admin, "
                                f"{roles['maintain']} maintain, {roles['write']} write.")
            if always or mine == "always":
                who = _names(_actor_text(a) + ("" if a["bypass_mode"] == "always" else
                                                   f" (mode: {plain(a['bypass_mode'] or 'not given', 30)})")
                             for a in always) or "the account whose token ran this audit"
                tail = (" Every account that can push holds one of those roles, so the ruleset holds nobody "
                        "who can author a change." if by_role else
                        " One account can push, it is the one whose token ran this audit, and GitHub says it "
                        "can always bypass: the ruleset holds nobody who can author a change." if only_me else "")
                run.finding(subject, "high" if everyone else "medium",
                            f"{label.capitalize()} is in force on {_q(branch)}, and {who} may always bypass it: "
                            f"push or merge without its required checks and reviews.{tail}", evidence)
            elif others or mine:
                who = _names(_actor_text(a) for a in others) or "the account whose token ran this audit"
                run.finding(subject, "low",
                            f"{label.capitalize()} is in force on {_q(branch)}, and {who} may bypass it when "
                            "merging a pull request.", evidence)
        classic = need["classic"]
        if classic is not None and classic["exists"]:
            compared += 1
            if not classic["enforce_admins"]:
                admins = roles["admin"] if roles else None
                everyone = bool(pushers) and admins == pushers
                run.finding(f"branch {_q(branch)}: classic protection", "high" if everyone else "medium",
                            f"The classic protection rule on {_q(branch)} does not hold administrators to it: "
                            "they can push or merge without its required checks and reviews."
                            + (f" All {_n(pushers, 'account')} that can push are administrators, so the rule "
                               "holds nobody who can author a change." if everyone else ""),
                            [f"{_n(pushers, 'account')} can push, {admins} of them administrators."]
                            if roles else [])
        elif need["classic_unknown"]:
            run.unread(f"branch {_q(branch)}: classic protection",
                       "whether the branch has a classic protection rule, and whether administrators are held "
                       "to it, is not known", "branch_protection")
    if compared:
        run.compared = f"{_n(compared, 'set')} of rules in force on {_n(len(branches), 'audited branch', 'audited branches')}"
    elif not run.results:
        run.idle = "no ruleset or classic protection rule is in force on an audited branch"


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
    all_jobs = list(run.jobs())
    computed = [(f, j) for f, j in all_jobs if j["check"]["kind"] == "computed"]
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
                if any(_reports(job, context) for _, job in all_jobs):
                    continue
                item = f"{subject}: required check {_q(context)}"
                if broken or computed:
                    why = ([f"{_n(len(broken), 'workflow file')} could not be read"] if broken else []) + (
                        [f"{_do(len(computed), 'job', 'reports', 'report')} under a computed name"] if computed else [])
                    run.cannot_tell(item, f"No job with a fixed name reports {_q(context)}, and "
                                          f"{' and '.join(why)}, so whether anything reports it is not known.")
                elif app == ACTIONS_APP:
                    run.finding(item, "medium",
                                f"{_q(branch)} requires the check {_q(context)} from GitHub Actions, and no job "
                                f"in the {_n(len(run.files()), 'workflow file')} reports a check of that name. "
                                f"It stays pending on every pull request, so nothing merges without a bypass.{source}")
                else:
                    run.cannot_tell(item, f"No workflow job reports {_q(context)}. The requirement does not "
                                          "say it must come from GitHub Actions, so another app or a commit "
                                          "status may report it.")
        elif kind == "filtered":
            for context in sorted(required):
                matches = [(f, j) for f, j in all_jobs if _reports(j, context)]
                if not matches:
                    continue
                compared += 1
                runs = [(_pull_request_run(f, j, branch), f, j) for f, j in matches]
                if any(how == "always" for how, _, _ in runs) or any(_runs_on_any_push(f, j) for f, j in matches):
                    continue
                filtered = [(f, j) for how, f, j in runs if how == "paths"]
                if filtered:
                    file, job = filtered[0]
                    run.finding(f"{subject}: required check {_q(context)}", "medium",
                                f"{_q(branch)} requires the check {_q(context)}, which {_job_label(file, job)} "
                                "reports, and that workflow runs on a pull request only when certain paths "
                                "change. On any other pull request the check never reports and GitHub leaves "
                                f"the merge blocked.{source}")
        else:
            if not need["checks_whole"]:
                continue
            for file, job in all_jobs:
                how = _pull_request_run(file, job, branch)
                if how != "always" or job["advisory"] or job["check"]["kind"] == "computed":
                    continue
                compared += 1
                if any(_reports(job, context) for context in required):
                    continue
                name = job["check"]["name"]
                shape = {"matrix": f"reports its checks as {_q(name + ' (...)')}, none of which is",
                         "calls": f"reports the checks of the workflow it calls as {_q(name + ' / ...')}, none "
                                  "of which is"}.get(job["check"]["kind"], f"reports the check {_q(name)}, which is not")
                count = (f"{_do(len(required), 'check', 'is', 'are')} required there" if required
                         else "no check is required there")
                run.finding(f"{subject}: job {_job_label(file, job)}", "medium",
                            f"{_job_label(file, job)} runs on every pull request into {_q(branch)} and {shape} "
                            f"required ({count}). A pull request can merge while the job is failing.{source}")
            skipped = [j for f, j in computed if _pull_request_run(f, j, branch)]
            if skipped:
                run.cannot_tell(f"{subject}: jobs with computed names",
                                f"{_do(len(skipped), 'job', 'that runs on pull requests reports', 'that run on pull requests report')} "
                                "under a name built from an expression, so whether "
                                f"{'it is' if len(skipped) == 1 else 'they are'} required was not compared.")
    if compared:
        run.compared = {"missing": f"{_n(compared, 'required check')} and the names the jobs report",
                        "filtered": f"{_n(compared, 'required check')} that a job reports, and its triggers",
                        }.get(kind, f"{_n(compared, 'job')} running on every pull request, and the required checks")
    elif not run.results:
        run.idle = {"missing": "no audited branch requires a check",
                    "filtered": "no required check is reported by a workflow job",
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
    """The lists of allowed events in a policy's rules, or None when a rule that names events is not a
    list of text."""
    found = []
    for rule in policy["rules"]:
        parameters = rule["parameters"]
        if isinstance(parameters, dict) and "allowed_events" in parameters:
            events = _strings(parameters["allowed_events"])
            if events is None:
                return None
            found.append(events)
    return found


def _policy_verdicts(file: dict, policies: list):
    """For one workflow file: the event rules that apply to it, as (policy, allowed events), from policies
    that are enforced or in evaluate mode; and the policies this rule cannot read (their scope, their
    enforcement or their list of events is not in the form it understands)."""
    applying, unclear = [], []
    for policy in policies:
        events = _event_rules(policy)
        if events is None:
            unclear.append(policy)
            continue
        if not events or policy["enforcement"] == "disabled":
            continue  # no rule about events, or switched off: nothing for these rules to compare
        applies = _policy_scope(policy, file["path"])
        if applies is None or policy["enforcement"] not in ("active", "evaluate"):
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
                                "conditions, its enforcement or its list of events), so which workflows and "
                                "events it blocks is not known.")
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
    value, whole = run.got("workflow_permissions")
    if value is None:
        run.unread("the default token permissions",
                   f"{_do(len(bare), 'job', 'declares no permissions and gets', 'declare no permissions and get')} "
                   "the repository's default, which is not known", "workflow_permissions")
        return
    run.compared = f"{_n(len(bare), 'job')} with no permissions block and the default for the workflow token"
    if value["default_workflow_permissions"] != "write":
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
    value, _ = run.got("workflow_permissions")
    default_write = value is not None and value["default_workflow_permissions"] == "write"
    holders = [(f, j) for f, j in run.jobs()
               if j["permissions"]["pull_requests_write"] or (not j["permissions"]["declared"] and (
                   value is None or default_write))]
    if not holders:
        run.idle = "no job's token can write to pull requests"
        return
    approvals = [(b, _branch_requirements(run, b)["approvals"]) for b in _branches(run)]
    wanted = [(b, n) for b, n in approvals if n]
    if value is None:
        run.unread("whether workflows may approve pull requests",
                   f"{_n(len(holders), 'job')} may hold a token that can write to pull requests, and whether "
                   "workflows are allowed to approve them is not known", "workflow_permissions")
        return
    run.compared = f"{_n(len(holders), 'job')} whose token can write to pull requests"
    if not value["can_approve_pull_request_reviews"]:
        return
    file, job = holders[0]
    tail = (f" {_q(wanted[0][0])} requires {_n(wanted[0][1], 'approval')}." if wanted else "")
    run.finding("workflows may approve pull requests", "medium" if wanted else "low",
                f"The repository lets workflows approve pull requests, and {_n(len(holders), 'job')} "
                f"{'holds' if len(holders) == 1 else 'hold'} a token that can write to them (the first: "
                f"{_job_label(file, job)}). A run of such a job can approve a pull request.{tail}")


def rule_014(run: _Run) -> None:
    jobs = [(f, j) for f, j in run.jobs() if "pull_request" in j["triggers"] and "pull_request" in f["triggers"]]
    repository, _ = run.got("repository")
    if not jobs or repository is None:
        run.idle = "no job runs on pull_request"
        return
    public = repository["visibility"] == "public"
    hosted_here = [(f, j) for f, j in jobs if j["self_hosted"]]
    readers = [(f, j) for f, j in jobs if j["secrets"] or j["all_secrets"]]
    relevant = hosted_here if public else jobs
    if not relevant:
        run.idle = "no pull_request job runs on a self-hosted runner"
        return
    value, whole = run.got("fork_pull_requests")
    if value is None or (not public and value.get("private_repository") is None):
        run.unread("fork pull requests",
                   f"{_n(len(relevant), 'pull_request job')} "
                   + (f"{'runs' if len(relevant) == 1 else 'run'} on a self-hosted runner, and whose fork pull "
                      "requests need approval first is not known"
                      if public else "may run for fork pull requests, and what those are sent is not known"),
                   "fork_pull_requests")
        return
    run.compared = f"{_n(len(relevant), 'pull_request job')} and the settings for fork pull requests"
    if public:
        if value["approval_policy"] != "all_external_contributors":
            file, job = hosted_here[0]
            run.finding("fork pull requests on self-hosted runners", "high",
                        f"{_do(len(hosted_here), 'pull_request job', 'runs', 'run')} on a self-hosted runner (the first: "
                        f"{_job_label(file, job)}), and approval before a fork's workflows run is required "
                        f"only for {_q(value['approval_policy'])}. Anyone else can run their code on that "
                        "machine by opening a pull request.")
        return
    private = value["private_repository"]
    if not private["run_workflows_from_fork_pull_requests"]:
        return
    sent = [what for key, what in (("send_secrets_and_variables", "secrets and variables"),
                                   ("send_write_tokens_to_workflows", "a write token")) if private[key]]
    if sent and (readers or private["send_write_tokens_to_workflows"]):
        file, job = (readers or jobs)[0]
        run.finding("fork pull requests in a private repository", "high",
                    f"Fork pull requests run workflows here and are sent {' and '.join(sent)}. "
                    f"{_do(len(jobs), 'job', 'runs', 'run')} on pull_request"
                    + (f", {len(readers)} of them reading secrets (the first: {_job_label(file, job)})."
                       if readers else "."))


def rule_015(run: _Run) -> None:
    using = [(f, j) for f, j in run.jobs() if j["steps"]]
    unpinned = [(f, j) for f, j in using if j["unpinned"]]
    if not using:
        run.idle = "no job with steps was read"
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
                    f"Every action in the {_n(len(using), 'job')} read is pinned to a full commit, and the "
                    "repository does not require it, so nothing stops the next change from adding one that is "
                    "not.")


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
        elif not usage["read"]:
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
            if run.broken() and not any(r["state"] == "cannot-tell" for r in run.results):
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
