"""The settings rules: what a snapshot of GitHub settings means for the workflows that depend on them.

Each rule compares a setting with something a workflow in the repository uses or assumes: the environment
a job names, the checks its jobs report, the events that start it, the secrets it reads. A setting no
workflow depends on is not judged; this is not a checklist for an organisation.

Three rules, OBAAF-SET-004, OBAAF-SET-005 and OBAAF-SET-013, read settings only: what they are about, who
can skip a branch's rules, whether its approvals can be given and whether a workflow can give one, is what
every workflow's result feeds (and a workflow on any branch can ask for the token the third is about).

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
import heapq
import json
import re
from dataclasses import dataclass, field

from obaaf.audit.github import plain, quoted
from obaaf.audit.settings import BY_KEY, CLASSIC_TOP
from obaaf.audit.workflows import HEAD_COMMIT_EVENTS, PULL_REQUEST_EVENTS
from obaaf.audit.workflows import called_path, self_repository_call
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
# The characters that make an environment's branch or tag policy a pattern. GitHub's reference names Ruby's
# File.fnmatch, where a backslash escapes the next character (`ma\\in` matches `main`; flagship slice 2d.2g).
WILDCARDS = "*?[\\"
# The characters that make an entry of a workflow's branch filter a pattern (GitHub's filter patterns also
# know `+`, and `!` negates an entry of `branches`).
FILTER_CHARS = "*?[]+!"


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
    # Why a finding of this rule matters, in one sentence of at most 160 characters (WHY_MAX), as for the
    # rules of `obaaf check` (flagship slice 3.2c, from #202). It must hold for every kind of finding the rule
    # gives, with "may" where a kind does not show the consequence; it is required, so a rule cannot be
    # added without one.
    why: str = field(kw_only=True)


RULES: tuple[Rule, ...] = (
    Rule("OBAAF-SET-001", "An environment's secrets can be reached from any branch", "high",
         ("environments", "environment_secrets", "branch_rules", "branch_protection", "branches"),
         "the environment each job names",
         "A job names an environment, and the environment does not limit which branches may use it (or the "
         "limit is a pattern anyone with write access can match by naming a branch or pushing a tag). Anyone "
         "who can push a branch can add a job that names the environment and reads its secrets. With required "
         "reviewers the only gate left is one person's approval; without them there is none. An environment a "
         "job names that the settings do not have gets no protection from them. Not followed: who may bypass the "
         "rules of a branch the environment is limited to (OBAAF-SET-004), approvals a new push does not dismiss "
         "and approvals a workflow can give (OBAAF-SET-013), which branches GitHub counts as protected, what a "
         "pattern matches, and what trusts an environment that holds no secret.",
         "In the environment's settings, limit deployment to selected branches and name the default branch. "
         "Add required reviewers where a person should decide; a wildcard or a tag pattern is reported until "
         "there are reviewers.",
         why="Anyone who can push a branch may run a job in the environment, using its secrets or whatever trusts "
             "it, with at most one reviewer's approval in the way."),
    Rule("OBAAF-SET-002", "A job outsiders can start gets an environment that asks nobody", "high",
         ("environments", "environment_secrets", "repository"),
         "jobs started by pull_request_target, issue and comment events",
         "A job that runs on an event people without write access can cause (pull_request_target, "
         "issue_comment, issues, workflow_run and the like) names an environment that has no required "
         "reviewers. Those events run as the default branch (pull_request_target too, since 2025-12-08), so a "
         "limit on which branches may deploy lets them through whenever it admits the default branch: nothing "
         "stands between the event and the environment's secrets. Not followed: what a pattern in the limit matches, "
         "and the callers of a reusable workflow in another repository.",
         "Add required reviewers to the environment, or move the step that needs the secret to a workflow "
         "that only people with write access can start.",
         why="An event people without write access can cause may run a job in the environment, with its secrets or "
             "those the job reads, and no reviewer to approve."),
    Rule("OBAAF-SET-003", "A secret kept behind an environment is also stored where every job can read it", "high",
         ("environment_secrets", "repository_secrets", "organization_secrets", "environments"),
         "protected_secrets in .github/obaaf.yml, and the secrets jobs read",
         "A secret that the configuration says must stay behind an environment, or that is stored in one, "
         "also exists as a repository or organisation secret. A job that does not declare the environment "
         "gets that copy, on any branch, so the environment protects nothing. The same holds when the "
         "environment the configuration names does not exist, and for a copy in another environment that any "
         "branch may use and that asks nobody. Not followed: a copy in an environment with a limit or reviewers, "
         "and Dependabot or Codespaces secrets.",
         "Delete the repository or organisation secret so that the environment holds the only copy, and "
         "create the environment the configuration names, limited to the default branch.",
         why="A job on any branch may read the secret without the environment meant to keep it, so whatever branch "
             "limit and reviewers that environment has may not apply."),
    Rule("OBAAF-SET-004", "Those who author changes can bypass the branch's rules", "high",
         ("ruleset_bypass_actors", "branch_rules", "branch_protection", "branches", "rulesets", "collaborators",
          "repository"),
         "nothing in the workflow files: it reads who may skip the checks and reviews their results feed",
         "A ruleset in force on the branch requires checks or reviews and lists who may bypass it, or classic "
         "branch protection does not hold administrators to it, or names people who may skip its reviews. "
         "Whoever is on such a list can push or merge without what the rule requires. When everyone who can "
         "push is on it, the rules hold nobody. Not followed: who is in a team, whether a role extends to higher "
         "roles, and a bypass list GitHub did not show.",
         "Remove the bypass. If one must stay for emergencies, give it to a team nobody works from day to "
         "day; it is still reported, at medium. For classic protection, hold administrators to the rule and "
         "empty the list of who may bypass required pull requests.", files=False,
         why="Anyone who may bypass, or an agent or token acting as them, can put a change on the branch without "
             "the checks, reviews or other results its rules require."),
    Rule("OBAAF-SET-005", "Required approvals cannot be given", "medium",
         ("branch_rules", "branch_protection", "branches", "collaborators"),
         "nothing in the workflow files: it reads the approvals a branch requires and who can give them",
         "The branch requires more approvals than the people who can approve can give: an author cannot "
         "approve their own pull request, and only accounts with write access count. Every merge then needs "
         "a bypass, which trains everyone to bypass. Not followed: the CODEOWNERS file and who is in a team.",
         "Lower the required approvals to what the team can give, or give a second person write access. Do "
         "not solve it with a bypass.", files=False,
         why="Pull requests by those who can push cannot get the approvals the branch requires from a person, so "
             "they may merge only by a bypass, making bypassing routine."),
    Rule("OBAAF-SET-006", "A required check that no workflow job reports", "medium",
         ("branch_rules", "branch_protection", "branches", "workflow_permissions", "actions_permissions",
          "actions_policies"),
         "the check names the jobs report",
         "The branch requires a check from GitHub Actions under a name that no job in the workflow files "
         "reports (a job was renamed or removed, or the name was mistyped), and no job holds a token that "
         "could report it another way. The check stays pending on every pull request, so nothing merges "
         "without a bypass. Not followed: check runs GitHub has recorded, other apps, and what a step with a "
         "token that may write checks reports.",
         "Correct the name in the ruleset or branch protection to the one the job reports, or remove it.",
         why="The required check never reports, so every pull request into the branch stays blocked and can merge "
             "only by a bypass of its rules."),
    Rule("OBAAF-SET-007", "A required check that does not report on every pull request", "medium",
         ("branch_rules", "branch_protection", "branches", "workflow_permissions", "actions_permissions",
          "actions_policies"),
         "the triggers of the job that reports each required check, and their filters",
         "The branch requires a check, and the job that reports it does not run for every pull request into "
         "the branch: its workflow has a paths filter, or runs only for some kinds of pull request activity, "
         "or is started by something else altogether. On the pull requests it does not run for, the check "
         "never reports and the merge stays blocked. Not followed: branch patterns, `concurrency`, fork pull "
         "requests (a push trigger counts for every pull request), and how GitHub counts a pull_request_target "
         "check.",
         "Let the workflow run on every pull request and skip inside the job instead (a job skipped by `if:` "
         "reports as passed), or stop requiring the check.",
         why="Pull requests the job does not run for wait on a required check that does not report, so they stay "
             "blocked until it reports on their commit or someone bypasses."),
    Rule("OBAAF-SET-008", "A pull-request job whose failure does not block a merge", "medium",
         ("branch_rules", "branch_protection", "branches", "actions_permissions", "actions_policies"),
         "the jobs that run on every pull request",
         "A job runs on every pull request into the branch and is not among the required checks, so a merge "
         "goes through while it is red. If that is intended, the workflow should say so. Not followed: a job "
         "that `if: false` or a called job's `if:` keeps from running, and how GitHub weighs two check runs of one "
         "name.",
         "Add the job's check to the required checks. If the job is advisory, give it "
         "`continue-on-error: true` at job level, which says in the workflow that its failure is not meant "
         "to block.",
         why="A pull request may merge while such a job is failing, so whatever it checks may not stop a change "
             "from reaching the branch."),
    Rule("OBAAF-SET-009", "An Actions policy blocks an event a workflow uses", "medium",
         ("actions_policies",), "the events under each workflow's `on:`",
         "An Actions policy allows only some events to start a workflow, and the workflow names another. A "
         "run for that event fails at startup with no job, so whatever it was meant to check is not checked "
         "and nothing reports it. Not followed: how GitHub matches a path pattern, and a policy's repository "
         "conditions other than \"every repository\".",
         "Add the event to the policy's allowed events, or remove the trigger from the workflow.",
         why="A run for the blocked event fails at startup with no job, now or once the policy is enforced, so "
             "whatever the workflow does for that event does not happen."),
    Rule("OBAAF-SET-010", "A pull_request_target workflow and GitHub's default policy of 2026-12-02", "medium",
         ("actions_policies", "repository"), "workflows started by pull_request_target",
         "By GitHub's changelog of 2026-11-02, from 2026-12-02 a default policy blocks the "
         "pull_request_target event in public repositories that have no policy allowing it. A workflow that "
         "uses the event then fails at startup. Not followed: GitHub Enterprise Server, and a policy's repository "
         "conditions other than \"every repository\".",
         "Move the workflow off pull_request_target where it does not need the base repository's secrets or "
         "write token. Where it does, add an Actions policy that allows the event for that workflow file, "
         "and read OBAAF-GHA-001 and OBAAF-GHA-002 on what such a workflow must not do.",
         why="From 2026-12-02 GitHub's announced default policy blocks this event here, so the workflow's runs for "
             "it will fail at startup and do nothing for pull requests."),
    Rule("OBAAF-SET-011", "A reusable workflow gets an empty value for a secret kept in an environment", "medium",
         ("environment_secrets", "repository_secrets", "organization_secrets"),
         "the secrets the jobs of a called workflow read, and what each calling job passes",
         "A job in a reusable workflow reads a secret that is kept in an environment. By GitHub's page on reusing "
         "workflows, the job that calls it cannot declare an environment, so the called job gets the "
         "environment's value only when it declares that environment itself and the caller still passes the "
         "secret, by name or with secrets: inherit. Otherwise it gets an empty value, and the run shows no "
         "error: the caller passes nothing, or passes a secret kept only in an environment, which the caller "
         "cannot read. The tempting repair is to copy the secret to the repository, which removes the "
         "environment's protection. Not followed: what a reusable workflow in another repository declares (it is "
         "\"cannot tell\"), and a secret kept outside every environment that the caller does not pass.",
         "Declare the environment on the job inside the reusable workflow, and pass the secret from the caller "
         "by name (NAME: ${{ secrets.NAME }}) or with secrets: inherit. Mark it required under "
         "on.workflow_call.secrets, so that a caller that does not pass it fails at the start. Do not copy the "
         "secret to the repository.",
         why="The called job may run with an empty secret and no error, and the tempting fix, copying it to the "
             "repository, would remove the environment's protection."),
    Rule("OBAAF-SET-012", "Jobs with no permissions block get a token that can write", "medium",
         ("workflow_permissions",), "jobs that declare no `permissions`",
         "The repository's default for the workflow token is read and write, and a job declares no "
         "permissions, so it gets a token that can push, comment and release. Not followed: the callers of a "
         "workflow in another repository, and an organisation's limit on the token.",
         "Set the default to read in the repository's Actions settings, and give each job the permissions it "
         "needs.",
         why="Any command run in such a job, its own or one injected into it, may get a token that can push, "
             "comment and release in the repository."),
    Rule("OBAAF-SET-013", "A workflow can give a required approval", "medium",
         ("workflow_permissions", "branch_rules", "branch_protection", "branches"),
         "nothing in the workflow files: a workflow on any branch can ask for the token, so it reads whether "
         "workflows may approve and the approvals each branch requires",
         "Workflows are allowed to approve pull requests and a branch requires approvals. A workflow can ask "
         "for a token that writes to pull requests whatever the repository's default, and anyone who can push "
         "a branch can add such a workflow there, so a run of it can approve their own pull request, which is "
         "not the review by a person that a required approval is meant to be. Not followed: the CODEOWNERS file.",
         "Turn off \"Allow GitHub Actions to create and approve pull requests\" in the repository's Actions "
         "settings. Where a workflow has to open pull requests, which needs the same switch (OBAAF's effect "
         "lane does), require a code owner's review, keep the required approvals at one, and give every file "
         "a code owner: the rule then answers \"cannot tell\", because it does not read the CODEOWNERS file.",
         files=False,
         why="Anyone who can push a branch can have a workflow approve their own pull request, so a required "
             "approval may not be a person's review."),
    Rule("OBAAF-SET-014", "Fork pull requests run on the repository's runners or with its secrets", "high",
         ("fork_pull_requests", "repository"),
         "the runners the jobs name (a fork's pull request runs its own copy of the workflows)",
         "In a public repository approval is not required for every outside contributor and the repository "
         "has a self-hosted runner: a stranger's code runs on a machine that keeps state, because a fork's "
         "pull request runs its own copy of the workflow files and can name any runner. Or, in a private "
         "repository, fork pull requests are sent secrets or a write token, which a fork's own workflow can "
         "read whatever the jobs here do. Not followed: whether the repository has self-hosted runners that no "
         "job here names.",
         "Require approval for all external contributors, or move the job to a GitHub-hosted runner. In a "
         "private repository, do not send secrets or write tokens to fork pull requests.",
         why="Code in a fork's pull request may run on the repository's self-hosted runner, which may keep state, "
             "or with its secrets or a write token."),
    Rule("OBAAF-SET-015", "Pinning actions to a commit: the setting and the workflows disagree", "medium",
         ("actions_permissions",), "the actions each job's steps use",
         "The repository requires actions to be pinned to a full commit and a workflow uses one that is not, "
         "so that workflow is refused. Or every action is pinned today and the repository does not require "
         "it, so nothing stops the next change from adding one that is not. Not followed: the actions a local "
         "composite action or a called workflow uses, and GitHub's lockfile (an action that is not pinned beside "
         "one is \"cannot tell\").",
         "Pin each action to a full commit SHA, and turn on the requirement in the repository's Actions "
         "settings.",
         why="Either a workflow is refused and runs nothing, or nothing stops the next change from adding an "
             "action whose code can change under the same reference."),
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
        self.assumed = ""        # what an answer took for granted, shown whatever the rule's status
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

    def unread(self, subject: str, what: str, *keys: str, clauses=()) -> None:
        """A "cannot tell" that says why: each part of an answer that could not be read (``clauses``), then
        each setting that was not read in full (``keys``)."""
        missing = [k for k in keys if self.settings[k]["status"] in ("unread", "partial")]
        reasons = list(dict.fromkeys(clauses)) + [self.why(k) for k in missing]
        because = f": {'; '.join(reasons)}" if reasons else ""
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
ACTIONS_OR_ANY = frozenset((None, ACTIONS_APP))

# The parameters of a ruleset's `pull_request` rule, as GitHub's REST reference lists them (the request body
# of "Create a repository ruleset", https://docs.github.com/en/rest/repos/rules, read on 2026-11-13). Every
# parameter is in one of the two sets below. One in neither is new, and the rules about approvals
# (OBAAF-SET-005 and OBAAF-SET-013) answer "cannot tell" for its branch, naming it, until it is placed here:
# a parameter that may add a requirement is never read as one that adds none.
#
# Read by the rules, each with what the reference and the page "Available rules for rulesets" say it does:
# - required_approving_review_count: "The number of approving reviews that are required".
# - require_code_owner_review: "Require an approving review in pull requests that modify files that have a
#   designated code owner".
# - require_last_push_approval: "Whether the most recent reviewable push must be approved by someone other
#   than the person who pushed it". With one approval or more it changes nothing the rules decide: an author
#   who pushes last needs an approval from someone else anyway. With none, whether it asks for an approval
#   of its own is not established, so it is "cannot tell".
# - require_extra_approval_for_unattributed_changes: "When Copilot opens a pull request without a human
#   collaborator, require one more approving review if a non-zero approval count is required"; the page
#   adds "This setting has no effect if the ruleset requires zero approvals" (public preview).
# - required_reviewers: teams that must approve changes to files matching patterns, each with
#   "minimum_approvals"; "If set to zero, the team will be added to the pull request but approval is
#   optional". Who is in a team is not read, so a minimum above zero is "cannot tell".
APPROVAL_PARAMETERS = frozenset((
    "required_approving_review_count", "require_code_owner_review", "require_last_push_approval",
    "require_extra_approval_for_unattributed_changes", "required_reviewers"))
# Known, and about neither how many approvals a branch needs nor who can give them: which merge methods are
# allowed, that approvals are dismissed by a new push (they can be given again), who may dismiss a review,
# and that conversations must be resolved.
OTHER_PULL_REQUEST_PARAMETERS = frozenset((
    "allowed_merge_methods", "dismiss_stale_reviews_on_push", "dismissal_restriction",
    "required_review_thread_resolution"))

# The rule types of a ruleset, as GitHub's REST reference lists them (the request body of "Create a repository
# ruleset", https://docs.github.com/en/rest/repos/rules, API version 2026-03-10, read on 2026-11-13: 25 types),
# each placed by what the rules about a branch's requirements (OBAAF-SET-004 to OBAAF-SET-008 and OBAAF-SET-013)
# make of it. A type in none of these places is new, and those rules answer "cannot tell" for its branch, naming
# it, until it is placed here: a rule that may ask for a check or an approval is never read as one that asks
# for none. The quotations are the reference's descriptions of each type.
RULE_TYPES = {
    # Read: the checks it requires (OBAAF-SET-006 to 008) and the approvals (OBAAF-SET-005 and 013).
    "required_status_checks": "checks",
    "pull_request": "approvals",
    # A merge waits for a result that workflows, other tools or deployments give: "Merges must be performed via
    # a merge queue"; "Choose which environments must be successfully deployed to before refs can be pushed into
    # a ref that matches this rule"; "Require all changes made to a targeted branch to pass the specified
    # workflows before they can be merged"; "Choose which tools must provide code scanning results before the
    # reference is updated"; "Choose which severity levels of code quality results should block pull request
    # merges"; "Enforce minimum line coverage thresholds on pull requests"; "Enforce any added or changed
    # dependencies to comply with the organization's license policy". OBAAF-SET-004 counts each as something a
    # bypass skips. What gives the result, and on which pull requests, is not compared with the workflow files:
    # OBAAF-SET-006 answers "cannot tell" for each (OBAAF-SET-007 for the merge queue, whose runs are not the
    # pull request's), and a finding of OBAAF-SET-008 names each but the merge queue, because a job that gives
    # such a result may hold the merge up when it fails.
    **dict.fromkeys(("merge_queue", "required_deployments", "workflows", "code_scanning", "code_quality",
                     "code_coverage", "license_compliance_scanning"), "gate"),
    # "Only allow users with bypass permission to update matching refs": who may merge may then be decided by who
    # may bypass that ruleset, not by the approvals alone (an inference: a merge updates the ref). OBAAF-SET-005
    # names it as something it cannot weigh.
    "update": "merge",
    # "Request Copilot code review for new pull requests automatically": a review, not a required approval. By
    # GitHub's changelog of 2026-09-01 (read for slice 2b.5) Copilot's review can approve, and count toward the
    # required approvals, where that is turned on, which is not read. OBAAF-SET-005 names it in a finding.
    "copilot_code_review": "review",
    # Neither asks for a check or a review nor decides who may merge: creating, deleting or force-pushing a ref,
    # linear history, signed commits, patterns for names, messages and e-mail addresses, and limits on the files
    # a push may hold ("Prevent commits that include ... from being pushed").
    **dict.fromkeys(("creation", "deletion", "required_linear_history", "required_signatures", "non_fast_forward",
                     "commit_message_pattern", "commit_author_email_pattern", "committer_email_pattern",
                     "branch_name_pattern", "tag_name_pattern", "file_path_restriction", "max_file_path_length",
                     "file_extension_restriction", "max_file_size"), "neither"),
}
RULE_TYPE_KINDS = ("checks", "approvals", "gate", "merge", "review", "neither")
# The parameters of a `required_status_checks` rule, by the same reference: the checks (each a `context` and an
# optional `integration_id`), "do_not_enforce_on_create" and "strict_required_status_checks_policy" (both true or
# false; neither changes which checks are required). A parameter or a field of a check outside these, or one of
# them in another form, makes the branch's list of required checks not whole: it may add a check.
CHECKS_PARAMETERS = ("do_not_enforce_on_create", "required_status_checks", "strict_required_status_checks_policy")
CHECK_FIELDS = ("context", "integration_id")
# Rules of a ruleset whose results come from workflows, other tools or reviewers: what a bypass lets someone
# merge without (OBAAF-SET-004).
GATES = tuple(sorted(t for t, kind in RULE_TYPES.items() if kind in ("checks", "approvals", "gate")))


def _held_by_actions(apps: set) -> bool:
    """Whether a check of this name from GitHub Actions is one the requirements wait for: required from
    GitHub Actions (whatever else), or from any app and no other. Where another app is named and GitHub
    Actions is not, how GitHub weighs a check of the same name from Actions is not established, so this is
    False and the rules say "cannot tell" or leave it to OBAAF-SET-006."""
    return ACTIONS_APP in apps or apps == {None}


def _branch_requirements(run: _Run, branch: str) -> dict:
    """The checks and approvals required on a branch, from rulesets and from classic protection, with
    whether each list is known to be whole.

    Every requirement holds at once (GitHub aggregates rulesets and layers them with classic protection),
    so one check name can be required from more than one app. ``apps`` keeps every app each name is
    required from (None: from any). ``checks`` gives one app per name for the rules that ask whether a
    workflow job can meet every requirement: an app that is not GitHub Actions if there is one, then
    GitHub Actions, then None."""
    out = _requirements(run, branch)
    _approval_parameters(out)
    out["checks"] = {context: next((a for a in sorted(apps, key=str) if a not in ACTIONS_OR_ANY),
                                   ACTIONS_APP if ACTIONS_APP in apps else None)
                     for context, apps in out["apps"].items()}
    return out


def _shown(value, limit: int = 100) -> str:
    """A parameter's value as JSON on one line, short and safe to print."""
    try:
        text = json.dumps(value, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError):
        text = repr(value)
    return plain(text, limit)


def _actor(item) -> bool:
    """An entry of `dismissal_restriction.allowed_actors` in the reference's form: an id and a type."""
    return (isinstance(item, dict) and set(item) <= {"id", "type"} and _is_int(item.get("id"))
            and isinstance(item.get("type"), str))


def _other_form(name: str, value) -> bool:
    """Whether a parameter about neither the count nor who approves has the form GitHub's reference gives it.
    One in another form may not be the parameter the code knows, so it is not passed over."""
    if name in ("dismiss_stale_reviews_on_push", "required_review_thread_resolution"):
        return isinstance(value, bool)
    if name == "allowed_merge_methods":
        return _strings(value) is not None
    if name == "dismissal_restriction":
        return (isinstance(value, dict) and set(value) <= {"enabled", "allowed_actors"}
                and isinstance(value.get("enabled"), bool)
                and isinstance(value.get("allowed_actors", []), list)
                and all(_actor(a) for a in value.get("allowed_actors", [])))
    return False


def _pull_request_parameters(out: dict, parameters: dict, count: int | None, ruleset) -> None:
    """Read the parameters of one `pull_request` rule beyond its count, into ``out``: whether it asks for a
    code owner's review, its parameters about approvals that the rules cannot judge (``parameters_unread``,
    each a clause naming the parameter), and what the rules make of the two whose effect depends on the
    branch's count once every rule is read (``last_push``, ``extra``)."""
    where = f"ruleset {plain(ruleset, 20)}"
    unread = out["parameters_unread"]
    for name in sorted(parameters, key=str):
        value = parameters[name]
        label = _q(name, 60)
        if name == "required_approving_review_count":
            continue
        if name in OTHER_PULL_REQUEST_PARAMETERS:
            if not _other_form(name, value):
                unread.append(f"{label} = {_shown(value)} ({where}), not in the form GitHub's reference gives")
        elif name not in APPROVAL_PARAMETERS:
            unread.append(f"{label} = {_shown(value)} ({where}), a parameter this audit does not know")
        elif name == "required_reviewers":
            teams = _required_reviewers(value)
            if teams is None:
                unread.append(f"{label} = {_shown(value)} ({where}), not in the form GitHub's reference gives")
            for team, minimum, patterns in teams or ():
                if minimum > 0:
                    files = _names([_q(p, 40) for p in patterns], 3) if patterns else "no pattern"
                    unread.append(f"required_reviewers asks team {plain(team, 20)} for {_n(minimum, 'approval')} "
                                  f"on changes to files matching {files} ({where}), and who is in the team is "
                                  "not read")
        elif not isinstance(value, bool):
            unread.append(f"{label} = {_shown(value)} ({where}), not true or false")
        elif value and name == "require_code_owner_review":
            out["code_owner"] = True
        elif value and name == "require_last_push_approval":
            out["last_push"].append(where)
        elif value and name == "require_extra_approval_for_unattributed_changes" and count is not None:
            out["extra"].append((where, count))  # with no count known, the rule is "cannot tell" anyway


def _required_reviewers(value):
    """The teams a `required_reviewers` parameter names, as (team id, minimum approvals, file patterns), or
    None when it is not in the form GitHub's reference gives (each entry a team with an id, file patterns and
    a minimum, and nothing else: a field the reference does not list could add a requirement)."""
    if not isinstance(value, list):
        return None
    teams = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"reviewer", "file_patterns", "minimum_approvals"}:
            return None
        reviewer, minimum, patterns = item["reviewer"], item["minimum_approvals"], _strings(item["file_patterns"])
        if (not isinstance(reviewer, dict) or set(reviewer) != {"id", "type"} or not _is_int(reviewer["id"])
                or reviewer["type"] != "Team" or not _is_int(minimum) or minimum < 0 or patterns is None):
            return None
        teams.append((reviewer["id"], minimum, patterns))
    return teams


def _approval_parameters(out: dict) -> None:
    """What the two parameters whose effect depends on the count come to, once every rule is read.

    - require_last_push_approval asks that the last push be approved by someone other than whoever pushed it.
      With one approval or more an author can always push last, and their pull request needs an approval
      from someone else anyway, so the rules' answers stand. With none, whether it asks for an approval of
      its own is not established.
    - require_extra_approval_for_unattributed_changes: when Copilot opens a pull request without a person,
      "the ruleset requires one more approval than the number you configured", from "people with write
      access", and "This setting has no effect if the ruleset requires zero approvals" (the rulesets page).
      So it adds one to its own rule's count, and nothing where that count is zero, whatever other rules
      ask. ``copilot`` is the approvals such a pull request needs on the branch."""
    approvals = out["approvals"] or 0
    if out["last_push"] and not approvals:
        out["parameters_unread"].append(
            f"require_last_push_approval is set ({', '.join(out['last_push'])}) where no approval is known to be "
            "required, and whether it then asks for an approval of its own is not established")
    for where, count in out["extra"]:
        if count:
            out["copilot"] = max(out["copilot"], approvals, count + 1)
        else:
            out["no_effect"].append(where)


def _gate_text(kind: str, parameters) -> str:
    """What a rule of a type in the "gate" group makes a merge wait for, short and safe to print."""
    parameters = parameters if isinstance(parameters, dict) else {}
    named = _strings(parameters.get("required_deployment_environments"))
    if kind == "required_deployments" and named:
        return f"a successful deployment to {_names([_q(n, 40) for n in named], 3)}"
    workflows = parameters.get("workflows")
    paths = [w["path"] for w in workflows if isinstance(w, dict) and isinstance(w.get("path"), str)] \
        if isinstance(workflows, list) else []
    if kind == "workflows" and paths:
        return f"the workflows {_names([_q(p, 60) for p in paths], 3)} to pass"
    tools = parameters.get("code_scanning_tools")
    tools = [t["tool"] for t in tools if isinstance(t, dict) and isinstance(t.get("tool"), str)] \
        if isinstance(tools, list) else []
    if kind == "code_scanning" and tools:
        return f"code scanning results from {_names([_q(t, 40) for t in tools], 3)}"
    return {"merge_queue": "a merge queue", "required_deployments": "the deployments it names",
            "workflows": "the workflows it names to pass", "code_scanning": "code scanning results",
            "code_quality": "code quality results", "code_coverage": "a minimum of line coverage",
            "license_compliance_scanning": "dependencies that comply with the organisation's license policy",
            }.get(kind, "a result this audit does not read")


def _classic_fields(out: dict, rule: dict) -> None:
    """Name the fields of a classic protection answer that this version does not know, for the rules they
    may change: one about the required checks may add a check, one about the reviews may add an approval or
    a way around one, and one anywhere else may do either."""
    for section, fields in sorted((rule.get("other_fields") or {}).items()):
        for name, value in sorted(fields.items()):
            path = name if section == CLASSIC_TOP else f"{section}.{name}"
            clause = f"{_q(path, 80)} = {_shown(value)} (the classic protection rule), a field this audit does not know"
            out["classic_fields"].append(clause)
            if not section.startswith("required_pull_request_reviews"):
                out["checks_whole"] = False
                out["checks_unread"].append(clause)
            if not section.startswith("required_status_checks"):
                out["parameters_unread"].append(clause)


def _classic_checks(out: dict, checks: dict) -> None:
    """The required checks of a classic rule, each with every app it is required from. A name listed twice
    keeps both apps (flagship slice 2d.2g: one was dropped, so a requirement from another app was lost); a
    name in ``contexts`` with no entry in ``checks`` is required from any app."""
    listed = checks["checks"] or []
    for check in listed:
        app = check["app_id"]
        out["apps"].setdefault(check["context"], set()).add(app if _is_int(app) and app > 0 else None)
    named = {check["context"] for check in listed}
    for context in checks["contexts"]:
        if context not in named:
            out["apps"].setdefault(context, set()).add(None)


def _requirements(run: _Run, branch: str) -> dict:
    out = {"apps": {}, "checks_whole": True, "approvals": None, "approvals_whole": True, "gaps": [],
           "rulesets": {}, "from_public_view": False, "classic": None, "classic_unknown": False,
           "code_owner": False, "parameters_unread": [], "last_push": [], "extra": [], "copilot": 0,
           "no_effect": [],
           # What could not be read in an answer that was read, each a clause naming it: for the checks, and
           # for the number of approvals. A setting that was not read is named by its key in ``gaps``.
           "checks_unread": [], "approvals_unread": [],
           # Rules of a known type that the rules do not read beyond their being there (see RULE_TYPES), as
           # (type, ruleset id, parameters); who may merge, as clauses; where Copilot is asked to review; and
           # the fields of a classic answer this version does not know, as clauses.
           "gates": [], "merge_unread": [], "copilot_review": [], "classic_fields": [], "rules_missing": []}
    rules, whole = run.got("branch_rules")
    if rules is None or branch not in rules:
        out["checks_whole"] = out["approvals_whole"] = False
        out["gaps"].append("branch_rules")
        if rules is not None and whole:
            # Read in full, and this branch is not in it: only a snapshot file can say that.
            missing = "the rules in force on it, which the snapshot does not hold"
            out["checks_unread"].append(missing)
            out["approvals_unread"].append(missing)
            out["rules_missing"].append(missing)
    else:
        for rule in rules[branch]:
            out["rulesets"].setdefault(rule["ruleset_id"], []).append(rule["type"])
            parameters = rule["parameters"]
            where = f"ruleset {plain(rule['ruleset_id'], 20)}"
            kind = RULE_TYPES.get(rule["type"])
            if kind is None:
                # A type GitHub added after this version: it may ask for a check, an approval, or both.
                clause = f"a rule of type {_q(rule['type'], 60)} ({where}), which this audit does not know"
                out["checks_whole"] = False
                out["checks_unread"].append(clause)
                out["parameters_unread"].append(clause)
            elif kind == "gate":
                out["gates"].append((rule["type"], rule["ruleset_id"], parameters))
            elif kind == "merge":
                out["merge_unread"].append(
                    f"a rule of type \"update\" ({where}), by which only those with bypass permission may push to "
                    "the branch, which may decide who can merge into it as well (an inference: the reference speaks "
                    "of updating the ref)")
            elif kind == "review":
                out["copilot_review"].append(where)
            elif rule["type"] == "required_status_checks":
                listed = parameters.get("required_status_checks") if isinstance(parameters, dict) else None
                if not isinstance(listed, list) or not all(
                        isinstance(c, dict) and isinstance(c.get("context"), str) for c in listed):
                    out["checks_whole"] = False
                    out["checks_unread"].append(f"the checks of the required_status_checks rule of {where}, which "
                                                "are not in the form GitHub's reference gives")
                    continue
                odd = [f"{_q(name, 60)} = {_shown(parameters[name])}" for name in sorted(parameters, key=str)
                       if name not in CHECKS_PARAMETERS or (name != "required_status_checks"
                                                            and not isinstance(parameters[name], bool))]
                odd += [f"a check with {_shown(check)}" for check in listed
                        if set(check) - set(CHECK_FIELDS) or ("integration_id" in check and check["integration_id"]
                                                               is not None and not _is_int(check["integration_id"]))]
                if odd:
                    out["checks_whole"] = False
                    out["checks_unread"].append(f"the required_status_checks rule of {where} has {_names(odd, 3)}, "
                                                "not in the form GitHub's reference gives")
                for check in listed:
                    app = check.get("integration_id")
                    out["apps"].setdefault(check["context"], set()).add(app if _is_int(app) else None)
            elif rule["type"] == "pull_request":
                count = parameters.get("required_approving_review_count") if isinstance(parameters, dict) else None
                if not _is_int(count) or count < 0:
                    out["approvals_whole"] = False
                    out["approvals_unread"].append(
                        f"the number of approvals the pull_request rule of {where} requires, which is "
                        + (f"{_shown(count, 40)}, not a whole number of 0 or more" if isinstance(parameters, dict)
                           and "required_approving_review_count" in parameters else "not given"))
                    if isinstance(parameters, dict):  # its other parameters are still named
                        _pull_request_parameters(out, parameters, None, rule["ruleset_id"])
                    continue
                out["approvals"] = max(out["approvals"] or 0, count)
                _pull_request_parameters(out, parameters, count, rule["ruleset_id"])
    classic, _ = run.got("branch_protection")
    if classic is not None and branch in classic:
        rule = classic[branch]
        out["classic"] = rule
        if rule["exists"]:
            checks, reviews = rule["required_status_checks"], rule["required_pull_request_reviews"]
            if checks["required"]:
                _classic_checks(out, checks)
            if reviews["required"]:
                count = reviews["required_approving_review_count"]
                out["code_owner"] = out["code_owner"] or reviews["require_code_owner_reviews"] is True
                if reviews["require_last_push_approval"] is True:
                    out["last_push"].append("the classic protection rule")
                if _is_int(count) and count >= 0:
                    out["approvals"] = max(out["approvals"] or 0, count)
                else:
                    out["approvals_whole"] = False
                    out["approvals_unread"].append("the number of approvals the classic protection rule requires, "
                                                   "which GitHub's answer did not give")
            # Who may push to the branch, and so merge into it, beside the approvals.
            if rule["restrictions"]["restricted"]:
                out["merge_unread"].append("the classic protection rule's restrictions on who may push to the branch "
                                           "(restrictions), which may decide who can merge into it as well (an "
                                           "inference: the reference speaks of pushing)")
            if rule["lock_branch"] is True:
                out["merge_unread"].append("the classic protection rule's lock_branch, by which, in GitHub's reference, "
                                           "\"users will not be able to push to the branch\"")
            _classic_fields(out, rule)
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
        _classic_checks(out, checks)
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
        # A job in a file GitHub may read otherwise (slice 2d.2g) is never counted as reporting.
        return (None if job.get("doubt") else True) if context in check["names"] else False
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
    decides it whatever patterns stand beside it, except that a negated entry can take it out again (or
    put it back), so any `!` leaves it to the patterns."""
    listed, ignored = filters["branches"], filters["branches_ignore"]
    if listed is not None:
        if any(name.startswith("!") for name in listed):
            return None
        if any(name == branch and not _pattern(name) for name in listed):
            return True
        return None if any(_pattern(name) for name in listed) else False
    if ignored is not None:
        if any(name.startswith("!") for name in ignored):
            return None
        if any(name == branch and not _pattern(name) for name in ignored):
            return False
        return None if any(_pattern(name) for name in ignored) else True
    return True


def _every_update(types) -> bool:
    """Whether a pull request event limited to these activity types still runs when a pull request is
    opened and whenever it gets new commits."""
    return types is None or {"opened", "synchronize"} <= set(types)


ORDER = ("always", "maybe", "target", "paths", "types", "manual", "never")


def _report_run(file: dict, job: dict, branch: str, pushes: bool = True, skipped: bool = False,
                blocked=frozenset()) -> str:
    """How the job comes to run on the head commit of a pull request into the branch:

    - "always": for every pull request, whenever it is opened or updated;
    - "maybe": a branch pattern decides, and patterns are not evaluated;
    - "target": only by pull_request_target, which runs on the base branch's latest commit (GitHub's
      changelog of 2025-11-07), so whether its check counts on the pull request is not established;
    - "paths": only when certain paths change;
    - "types": only for some kinds of activity (labeled, closed ...);
    - "manual": only when someone or something dispatches the workflow;
    - "never": nothing in its triggers runs it there.

    With ``pushes`` a push trigger with no filter counts as "always": a push to the pull request's branch
    runs the job on the same commit. That holds for a branch in this repository and not for a fork's.

    With ``skipped`` a job counts for every event its workflow runs on, whatever its `if:` or the jobs it
    needs: a job they skip still reports its check, as passed (slice 2d.2g; OBAAF-SET-007 asks whether the
    check reports, not whether the job's steps run). Events in ``blocked`` (an enforced Actions policy's)
    start nothing."""
    found = "never"
    events = set(file["triggers"]) if skipped else set(job["triggers"])
    events -= set(blocked)

    def better(kind: str) -> str:
        return kind if ORDER.index(kind) < ORDER.index(found) else found

    for event in PULL_REQUEST_EVENTS:
        filters = file["triggers"].get(event)
        if filters is None or event not in events:
            continue
        admitted = _admits(filters, branch)
        if admitted is False:
            continue
        kind = ("maybe" if admitted is None else "paths" if filters["paths"]
                else "always" if _every_update(filters["types"]) else "types")
        found = better("target" if event not in HEAD_COMMIT_EVENTS and kind == "always" else kind)
    push = file["triggers"].get("push")
    if pushes and push is not None and "push" in events:
        if push["branches"] is None and push["branches_ignore"] is None:
            if not push["tags"]:
                found = better("paths" if push["paths"] else "always")
        elif any(_pattern(name) for name in (push["branches"] or []) + (push["branches_ignore"] or [])) \
                or push["branches_ignore"] is not None:
            found = better("maybe")
    if "workflow_dispatch" in file["triggers"] and "workflow_dispatch" in events:
        found = better("manual")
    return found


def _stops(run: _Run):
    """What the settings say about whether GitHub runs each workflow file at all (flagship slice 2d.2g): the
    files it does not run, each with why; the events an enforced Actions policy blocks for each file; and the
    settings this depends on that were not read in full, as clauses. A check reported only by a job GitHub
    does not run never reports."""
    stopped: dict = {}
    maybe: dict = {}            # files GitHub may not run, with why: never counted as reporting
    blocked: dict = {}
    unread: list = []
    value, whole = run.got("actions_permissions")
    if value is None or not whole:
        unread.append(run.why("actions_permissions"))
    if value is not None:
        for file in run.files():
            path = file["path"]
            loose = sorted({a for job in file["jobs"] for a in job["unpinned"]})
            # An action from another repository, or a reusable workflow from one (the third review of 2d.2g).
            # A call written `./` or `$/` is this repository's (issue #182).
            actions = sorted({a for job in file["jobs"] for a in job["remote_actions"]})
            workflows = sorted({job["calls"] for job in file["jobs"] if job["calls"] and called_path(job) is None})
            remote = actions + workflows
            if value.get("enabled") is False:
                stopped[path] = "GitHub Actions is turned off for the repository"
            elif value.get("sha_pinning_required") is True and loose and not run.usage.get("actions_lock"):
                stopped[path] = (f"the repository requires actions pinned to a full commit and it uses "
                                 f"{_names([_q(a, 100) for a in loose], 2)}, so GitHub refuses it")
            elif value.get("sha_pinning_required") is True and loose:
                maybe[path] = (f"the repository requires actions pinned to a full commit and it uses "
                               f"{_names([_q(a, 100) for a in loose], 2)}; .github/workflows/actions.lock may pin "
                               "them, and it is not read")
            elif value.get("allowed_actions") == "local_only" and remote:
                # GitHub's own words for this value, by the second review of slice 2d.2g, are "Allow OWNER actions
                # and reusable workflows": which owner's actions that lets through is not matched here.
                maybe[path] = ("the repository allows only some owners' actions and reusable workflows "
                               "(allowed_actions: local_only), which is not matched against those it uses")
            elif value.get("allowed_actions") == "selected" and remote:
                # Issue #182: an empty list of selected actions was read as letting everything run.
                unsure = _not_selected(actions, workflows, value.get("selected_actions"))
                if unsure:
                    maybe[path] = _selection_doubt(unsure, value.get("selected_actions"))
            if path not in stopped and path not in maybe and value.get("allowed_actions") not in (
                    None, "all", "local_only", "selected"):
                # A value of its own (the second review of slice 2b.7: it counted every file as running).
                maybe[path] = (f"the repository's setting for which actions may run is {_q(value['allowed_actions'], 40)}, "
                               "a value the audit does not know")
            if path not in stopped and path not in maybe and value.get("allowed_actions") in ("local_only", "selected"):
                # A local action's own steps, and whether the setting covers a container image, are not read
                # (the review of slice 2b.7): a local composite action can use an action the setting blocks.
                unread_here = sorted({a for job in file["jobs"] for a in job["unread_actions"]})
                if unread_here:
                    maybe[path] = (f"the repository allows only some actions and reusable workflows (allowed_actions: "
                                   f"{value['allowed_actions']}), and it uses {_names([_q(a, 100) for a in unread_here], 2)}, "
                                   "whose own steps, or whether the setting covers it, the audit does not read")
    policies, whole = run.got("actions_policies")
    if policies is None or not whole:
        unread.append(run.why("actions_policies"))
    for file in run.files():
        applying, unclear = _policy_verdicts(file, policies or [])
        for policy, allowed in applying:
            if policy["enforcement"] == "active":
                blocked.setdefault(file["path"], set()).update(e for e in file["triggers"] if e not in allowed)
        events = set(file["triggers"]) - {"workflow_call"}
        for policy in unclear:
            if policy["enforcement"] == "evaluate" or file["path"] in stopped:
                continue            # evaluate mode blocks nothing
            lists = _event_rules(policy)
            if lists and all(events <= set(allowed) for allowed in lists):
                continue            # whatever it applies to, it allows every event the file uses
            maybe.setdefault(file["path"], f"the Actions policy {_q(policy['name'])}, which this audit does not "
                                           "understand, may block its events")
    for file in run.files():
        if file["path"] in stopped or file["path"] in maybe:
            continue
        # A call written with `$/`: whether GitHub takes `$/` in a job's `uses:` was not established (issue #182).
        odd = next((job for job in file["jobs"] if self_repository_call(job)), None)
        if odd is not None:
            maybe[file["path"]] = (f"it calls {_q(odd['calls'], 120)}, written with $/, and whether GitHub "
                                   "accepts $/ in a job's uses was not established")
        elif file.get("may_refuse"):
            maybe[file["path"]] = file["may_refuse"][0]     # a job id GitHub may refuse (slice 2b.7)
    _spread_to_callers(run, stopped, maybe)
    return stopped, maybe, blocked, unread


def _spread_to_callers(run: _Run, stopped: dict, maybe: dict) -> None:
    """A workflow that calls one GitHub does not run, or may not run, may not run either (the second review of
    slice 2d.2g): the whole calling file is taken as one GitHub may not run, and so are its own callers. A
    called file that is missing, or was not read (one GitHub refuses among them), counts the same, and so does
    `uses: ./` alone (issue #182: it was skipped). Each file is looked at once from each file it calls, so a
    chain of calls costs its length (it cost the square of it), and the reason a file is given is its first
    call, in the order the jobs are written, to a file found not to run, or not to be sure to run, one step
    nearer the cause (so a cycle of calls never gives a file its own caller as the reason)."""
    files = run.files()
    read = {file["path"] for file in files}
    calls = {file["path"]: [t for t in (called_path(job) for job in file["jobs"]) if t is not None] for file in files}
    for path, why in _call_graph_doubts(calls, read).items():
        if path not in stopped and path not in maybe:
            maybe[path] = why
    callers: dict = {}
    for path, targets in calls.items():
        for target in dict.fromkeys(targets):
            callers.setdefault(target, []).append(path)
    bad = set(stopped) | set(maybe) | {t for targets in calls.values() for t in targets if t not in read}
    frontier = set(bad)
    reasons: dict = {}
    while frontier:
        reached = {path for target in frontier for path in callers.get(target, ()) if path not in bad}
        for path in reached:
            reasons[path] = next(t for t in calls[path] if t in bad)
        bad |= reached
        frontier = reached
    for file in files:
        target = reasons.get(file["path"])
        if target is not None:
            maybe[file["path"]] = (f"it calls {plain(target, 120) if target else _q('./')}, which GitHub "
                                   + ("does not run" if target in stopped else "may not run" if target in read
                                      else "may not run: it is not among the workflow files that were read"))


# How deep calls may nest before GitHub refuses the run, at the least: its reference allowed "four levels of
# workflows", the caller and three levels of reusable workflows, as the author knew it; a later limit may be higher
# (not read in the session that wrote this, so a deeper chain is a doubt, the review of slice 2b.7).
MAX_CALL_DEPTH = 3


def _call_graph_doubts(calls: dict, read: set) -> dict:
    """The files GitHub may not run because of how they call one another (the review of slice 2b.7): one in a
    cycle of calls, which cannot be expanded (a file that calls itself included), and one that starts a chain of
    more nested calls than MAX_CALL_DEPTH. Iterative, so a long chain does not exhaust the stack."""
    graph = {path: list(dict.fromkeys(t for t in targets if t in read)) for path, targets in calls.items()}
    # Tarjan's strongly connected components, without recursion.
    index: dict = {}
    low: dict = {}
    on_stack: set = set()
    stack: list = []
    component: dict = {}
    counter = 0
    for root in graph:
        if root in index:
            continue
        work = [(root, 0)]
        while work:
            node, i = work.pop()
            if i == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            targets = graph.get(node, [])
            if i < len(targets):
                work.append((node, i + 1))
                target = targets[i]
                if target not in index:
                    work.append((target, 0))
                elif target in on_stack:
                    low[node] = min(low[node], index[target])
                continue
            for target in targets:
                if target in on_stack:
                    low[node] = min(low[node], low[target])
            if low[node] == index[node]:
                members = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    members.append(member)
                    if member == node:
                        break
                for member in members:
                    component[member] = members
    doubts: dict = {}
    cyclic = set()
    first: dict = {}     # each component's first three members, found once (the second review of 2b.7)
    for path, targets in graph.items():
        members = component[path]
        if len(members) > 1 or path in targets:
            cyclic.add(path)
            key = id(members)
            if key not in first:
                first[key] = heapq.nsmallest(3, members)
            others = [m for m in first[key] if m != path][:2]
            more = len(members) - 1 - len(others)
            named = ", ".join(plain(m, 120) for m in others) + (f" and {more} more" if more else "")
            doubts[path] = ("it calls itself, a cycle GitHub cannot expand" if len(members) == 1 else
                            f"it is in a cycle of calls with {named}, which GitHub cannot expand")
    # The longest chain of calls below each file outside a cycle, in calls: one past MAX_CALL_DEPTH is a doubt.
    # Callers of a file in a cycle are not measured through it: they become files GitHub may not run anyway.
    depth: dict = {}
    for root in graph:
        if root in cyclic or root in depth:
            continue
        work = [(root, False)]
        while work:
            node, done = work.pop()
            below = [t for t in graph[node] if t not in cyclic]
            if done:
                depth[node] = 1 + max((depth[t] for t in below), default=-1)
                continue
            if node in depth:
                continue
            work.append((node, True))
            work.extend((t, False) for t in below if t not in depth)
    for path, n in depth.items():
        if n > MAX_CALL_DEPTH and path not in doubts:
            doubts[path] = (f"it starts a chain of {n} nested calls, and GitHub allowed the caller and "
                            f"{MAX_CALL_DEPTH} levels of reusable workflows (as its reference was known when this was "
                            "written; a later limit was not read)")
    return doubts


# A reference to another repository's action or reusable workflow, `owner/repo[/path]@ref`, as plainly as it can be
# written (issue #182): each part letters, digits, `.`, `_` and `-`, no part `.` or `..`, a ref of the same with `/`
# and no `..` (which no git ref holds), no space, no wildcard. Only such a reference is matched against the list.
_PART = r"(?!\.\.?[/@])[A-Za-z0-9._-]+"
PLAIN_REFERENCE_RE = re.compile(rf"(?P<owner>{_PART})/{_PART}(?:/{_PART})*@(?!.*\.\.)[A-Za-z0-9._/-]+")


def _not_selected(actions: list[str], workflows: list[str], selected) -> list[str]:
    """The references, of actions or reusable workflows in another repository, that the list of selected
    actions (`allowed_actions: selected`), as written, does not allow (issue #182). What an allowed reference
    uses in turn (a remote composite action's steps, a remote reusable workflow's jobs) is not read. GitHub's matching of the list
    was not read from its pages in the session that wrote this, so only two things count: a step's action of
    the `actions` or `github` organisation, written so in lower case, where GitHub's own actions are allowed;
    and an entry that is the reference itself, character for character. Either only for a reference written
    plainly (PLAIN_REFERENCE_RE), and neither while any entry holds a `!`, which may block. Another
    repository's reusable workflow is never allowed as written, an equal entry included, because its jobs are
    not read; actions of the repository's own owner and of verified creators are not matched. A list that was
    not read lets nothing through."""
    if not isinstance(selected, dict):
        return actions + workflows
    patterns = [p for p in selected.get("patterns_allowed") or [] if isinstance(p, str)]
    if any("!" in p for p in patterns):
        return actions + workflows

    def allowed(uses: str) -> bool:
        plain_ref = PLAIN_REFERENCE_RE.fullmatch(uses)
        if plain_ref is None:
            return False        # a wildcard, a space or an odd part: never matched, even by an equal entry
        owned = selected.get("github_owned_allowed") is True and plain_ref["owner"] in ("actions", "github")
        return owned or uses in patterns

    # Another repository's reusable workflow is never taken as allowed: its jobs, and what they use, are not read
    # (the third review of 2b.7), as a local action's steps are not.
    return [uses for uses in actions if not allowed(uses)] + list(workflows)


def _selection_doubt(unsure: list[str], selected) -> str:
    """Why a file GitHub may refuse under `allowed_actions: selected` may not run."""
    names = ", ".join(_q(a, 100) for a in unsure[:2]) + (f" and {len(unsure) - 2} more" if len(unsure) > 2 else "")
    if not isinstance(selected, dict):
        return (f"the repository allows only selected actions and reusable workflows (allowed_actions: selected), "
                f"the list was not read, and it uses {names}")
    if any("!" in p for p in selected.get("patterns_allowed") or [] if isinstance(p, str)):
        return (f"the repository allows only selected actions and reusable workflows (allowed_actions: selected), an "
                f"entry of the list holds a !, which may block, so nothing is matched, and it uses {names}")
    return (f"the repository allows only selected actions and reusable workflows (allowed_actions: selected), and "
            f"it uses {names}, which the list as written does not allow: only a step's action of GitHub's own, "
            "where allowed, or one an entry names exactly is matched, and another repository's reusable workflow, "
            "whose jobs are not read, never is")


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
            named = [p for p in policies if p not in wide and p not in loose]
            other = [p for p in named if p["name"] not in audited]
            # A branch that was audited counts only for what its rules show (slice 2d.2g): one that anyone
            # with write access can push to, with no approval and no limit on who may push, limits nothing.
            gates = {p["name"]: _push_gate(run, p["name"]) for p in named if p["name"] in audited}
            pushable = [p for p in named if gates.get(p["name"], ("",))[0] == "open"]
            unsure = [p for p in named if gates.get(p["name"], ("",))[0] == "unknown"]
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
            elif pushable and not reviewers:
                run.finding(subject, "low" if empty else "medium",
                            f"The environment {_q(env['name'])} may be used from the branch "
                            f"{_names(_q(p['name']) for p in pushable)}, it has no required reviewers, and {who}. "
                            f"{gates[pushable[0]['name']][1]} Anyone with write access can push a job there that "
                            "names the environment, so the limit stops nobody who can push.")
            elif (other or unsure) and not reviewers:
                parts = ([f"{_names(_q(p['name']) for p in other)}, which was not audited (name it with --branch to "
                          "have its rules read)"] if other else []) + [
                    f"{_q(p['name'])}, whose rules were not read in full ({gates[p['name']][1]})" for p in unsure]
                run.cannot_tell(subject, f"The environment {_q(env['name'])} may be used from the branch "
                                         f"{'; and '.join(parts)}, so who can push there is not known.")


def _push_gate(run: _Run, branch: str) -> tuple[str, str]:
    """Whether anyone with write access can push to the branch, by the rules the snapshot holds for it:
    ("closed", why) when an approval by someone else, or a limit on who may push, stands in the way; ("open",
    why) when the rules were read in full and neither does; ("unknown", why) when they were not read in full.
    Who may bypass those rules is OBAAF-SET-004's subject, not this one's."""
    need = _branch_requirements(run, branch)
    if need["approvals"]:
        return "closed", f"it requires {_n(need['approvals'], 'approval')}"
    if need["code_owner"]:
        return "unknown", "it requires a code owner's review, and who the code owners are (CODEOWNERS) is not read"
    if need["merge_unread"]:
        # Who may push is then who may bypass that rule, or who the restrictions name, which is not compared
        # with who can push (the review of slice 2d.2g).
        return "unknown", need["merge_unread"][0]
    deployments = [g for g in need["gates"] if g[0] == "required_deployments"]
    if deployments:
        # A deployment that must succeed first may itself wait for a reviewer; that is not weighed here.
        return "unknown", (f"a required_deployments rule (ruleset {plain(deployments[0][1], 20)}), whose deployments "
                           "may wait for a reviewer, which is not weighed")
    if not need["approvals_whole"]:
        clauses = need["approvals_unread"] + [run.why(k) for k in sorted(set(need["gaps"]))
                                               if run.settings[k]["status"] in ("unread", "partial")]
        return "unknown", "; ".join(clauses) or "the rules in force on it were not read in full"
    if need["parameters_unread"]:
        return "unknown", need["parameters_unread"][0]
    return "open", (f"The branch {_q(branch)} has no rule that requires an approval or limits who may push "
                    "to it.")


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
        admitted = _admits_default(env, repository["default_branch"])
        if admitted is False:
            # The limit shuts the default branch out, and these events run as the default branch: for
            # pull_request_target too since 2025-12-08 (GitHub's changelog of 2025-11-07).
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
        if env and environments is not None:
            # A copy in another environment that any branch may use and that asks nobody is a copy every job
            # can reach: it only has to name that environment (slice 2d.2g).
            open_envs = {e["name"].lower(): e["name"] for e in environments
                         if not e["reviewers"] and e["name"].lower() != env.lower() and (
                             e["deployment_branches"] == "any" or any(
                                 p["type"] != "tag" and _open_pattern(p) for p in e.get("branch_policies") or []))}
            for name in sorted(n for n in in_env if fnmatch.fnmatchcase(n, pattern) and n not in reported):
                copies = sorted(open_envs[e.lower()] for e in in_env[name] if e.lower() in open_envs)
                if copies:
                    reported.add(name)
                    run.finding(f"secret {_q(name)}", "high",
                                f"{_q(name)} matches the protected_secrets entry {_q(pattern)}, which says it must stay "
                                f"in {_q(env)}, and it is also stored in the environment "
                                f"{_names(_q(c) for c in copies)}, which any branch may use and which has no required "
                                "reviewers. A job on any branch can name that environment and read the copy.")
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


def _given(names, only_env: dict) -> str:
    """"X is stored only in the environment E", for one or more secrets kept only in environments."""
    names = sorted(names)
    envs = sorted({e for n in names for e in only_env[n]})
    where = f"the environment {_names(_q(e) for e in envs)}" if len(envs) == 1 else \
        f"the environments {_names(_q(e) for e in envs)}"
    return f"{_names(_q(n) for n in names)} {'is' if len(names) == 1 else 'are'} stored only in {where}"


class _Secrets:
    """Where the settings say each secret is kept, in upper case as GitHub compares secret names."""

    def __init__(self, env_secrets: dict, wide: set) -> None:
        self.stored: dict = {}      # secret -> the environments that hold it
        self.by_env: dict = {}      # environment, in lower case as GitHub compares the names -> its secrets
        for env, names in env_secrets.items():
            self.by_env.setdefault(env.lower(), set()).update(n.upper() for n in names)
            for name in names:
                self.stored.setdefault(name.upper(), set()).add(env)
        self.wide = frozenset(wide)
        self.only_env = {name: envs for name, envs in self.stored.items() if name not in wide}
        self.only_env_names = frozenset(self.only_env)

    def held_by(self, env: dict, names) -> list[str]:
        """Which of the names the environment a job declares holds: only for a name written plainly (an
        expression, a number, or a name with space round it, whose reading by GitHub is not established, is
        never taken to hold anything)."""
        name = env.get("name")
        if name is None or name != name.strip():
            return []
        held = self.by_env.get(name.lower(), set())
        return sorted(n for n in names if n in held)


def _plainly_named(env: dict) -> bool:
    name = env.get("name")
    return not env or (name is not None and name == name.strip())


def _reaches_called_job(run: _Run, subject: str, target: str, passes: dict, called: dict, name: str,
                        kept: _Secrets, missing: dict) -> None:
    """What a job of a called workflow in this repository gets for a secret it reads, by GitHub's page on
    reusing workflows (https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows, read
    on 2026-11-26 for flagship slice 2b.9): "The job that calls the reusable workflow can't use the
    `environment` keyword"; "To use an environment secret in a reusable workflow, set `environment` on the
    job in the reusable workflow. The caller workflow must still pass the secret. Use `secrets: inherit` or
    pass the secret by name"; "You can pass a secret by name even if it only exists in the environment";
    "The job that sets `environment` receives the environment secret's value"; and "If the caller workflow
    doesn't pass an environment secret, the secret resolves to an empty string in the reusable workflow. The
    workflow run doesn't show an error." What the page does not say (a secret passed under another name or
    with another value to a job whose environment holds it, a second call that is not passed the secret) is
    "cannot tell"."""
    upper = name.upper()
    key = passes["keys"].get(upper)
    inherit = passes["inherit"] and not passes["odd_keys"]
    passed = inherit or key is not None
    where = f"whose job {_q(called['id'])} reads secrets.{plain(name, 60)}"
    env = called["environment"] or {}
    reads = set((key or {}).get("reads", ()))
    reads_env = sorted(reads & kept.only_env_names)
    concerns = upper in kept.stored or bool(reads_env) or bool(key and key["all"])
    if not concerns:
        return      # kept outside every environment, or nowhere, and passed from secrets every job can read
    if passes["odd_keys"] or (key and key.get("ambiguous")):
        run.cannot_tell(subject, f"The job calls {_q(target, 120)}, {where}. Its secrets: "
                                 + ("names it twice, in two letter cases" if key and key.get("ambiguous") else
                                    "holds a key this reader does not take as a plain name, or is text other than "
                                    "inherit")
                                 + f", so whether and how it passes {_q(name)} is not known.")
        return
    if called["calls"]:
        # The called job passes it on to a workflow of its own. That call is read as a caller of its own; this
        # call counts only when it hands the job the secret as the page documents, by name or with inherit.
        if not (inherit or (key is not None and key["plain"] == upper)):
            run.cannot_tell(subject, f"The job calls {_q(target, 120)}, {where} and passes it on to "
                                     f"{_q(called['calls'], 120)}. "
                                     + ("This job does not pass it" if not passed else
                                        "This job passes it under another name or with another value")
                                     + "; whether a job there that declares an environment holding it gets its "
                                       "value is not documented, so the second call was not followed.")
        return
    if not passed:
        if upper not in kept.stored:
            return
        # Reported once for the call, with every secret and job it concerns (see _missing_finding).
        entry = missing.setdefault(upper, {"name": name, "jobs": [], "declared": []})
        entry["jobs"].append(called["id"])
        if kept.held_by(env, [upper]):
            entry["declared"].append(called["id"])
        return
    if not _plainly_named(env):
        # Passed, so what the job gets depends on whether the environment it names holds the secret.
        run.cannot_tell(subject, f"The job passes {_q(name)} to {_q(target, 120)}, {where} and names its "
                                 "environment in a form this reader does not take as a plain name (an expression, "
                                 "a number, a mapping without a name, or space round it). Whether that is an "
                                 f"environment that holds {_q(name)}, and so which value the job gets, is not known.")
        return
    if inherit:
        if kept.held_by(env, [upper]):
            return      # the job declares the environment and is passed the secret: it gets the environment's value
        if upper in kept.only_env:
            run.finding(subject, "medium",
                        f"The job passes every secret to {_q(target, 120)}, {where}. {_given([upper], kept.only_env)}, "
                        "and that job does not declare it, so the value it gets is empty.")
        return
    held = kept.held_by(env, sorted({upper} | reads))
    if held:
        if key["plain"] == upper:
            return      # passed as NAME: ${{ secrets.NAME }} to a job whose environment holds NAME: documented
        if upper in held and key["plain"] in kept.wide and not kept.held_by(env, [key["plain"]]):
            return      # either the environment's NAME or a secret every job can read: neither is empty
        run.cannot_tell(subject, f"The job passes {_q(name)} to {_q(target, 120)} with a value other than "
                                 f"${{{{ secrets.{plain(name, 60)} }}}}, {where} and declares the environment "
                                 f"{_q(env['name'])}, which holds {_names(_q(n) for n in held)}. Which value that job "
                                 "gets is not documented.")
        return
    # The job's environment holds neither the name it reads nor what the value reads: it gets what the caller
    # passes, which the caller, which cannot declare an environment, evaluates without one.
    if key["all"]:
        run.cannot_tell(subject, f"The job passes {_q(name)} to {_q(target, 120)} as a secret it picks with an "
                                 f"expression, {where}. Whether that is one stored only in an environment is not "
                                 "known.")
        return
    if not reads_env:
        return      # the value comes from secrets every job can read, or from text
    shown = "" if key["plain"] == upper else f" as {_q(name)}"
    if key["plain"] in kept.only_env:
        run.finding(subject, "medium",
                    f"The job passes secrets.{plain(key['plain'], 60)} to {_q(target, 120)}{shown}, {where}. "
                    f"{_given([key['plain']], kept.only_env)}, and a job that calls a reusable workflow cannot "
                    "declare an environment, so what it passes is empty; the called job does not declare an "
                    "environment that holds either name.")
        return
    run.cannot_tell(subject, f"The job passes {_q(name)} to {_q(target, 120)} with a value that reads "
                             f"{_names(_q(n) for n in reads_env)} among other things, {where}. "
                             f"{_given(reads_env, kept.only_env)}, so that part of the value is empty; whether the "
                             "whole value is is not known.")


def _missing_finding(run: _Run, subject: str, target: str, missing: dict, kept: _Secrets,
                     declared: dict, passes: dict) -> None:
    """One finding for a call that does not pass secrets kept in an environment which jobs of the called
    workflow read: the first adopter's incident (Expectrail `ad3e0775`, 2026-11-10). A secret the called
    workflow marks required makes the run fail at its start, by the page; the others are empty."""
    if not missing:
        return
    names = [missing[k]["name"] for k in sorted(missing)]
    jobs = sorted({j for k in missing for j in missing[k]["jobs"]})
    envs = sorted({e for k in missing for e in kept.stored[k]})
    holds: dict = {}
    for k in sorted(missing):
        for j in missing[k]["declared"]:
            holds.setdefault(j, []).append(missing[k]["name"])
    by_names: dict = {}     # the secrets held -> the jobs whose environment holds just those
    for j, ns in sorted(holds.items()):
        by_names.setdefault(tuple(sorted(set(ns))), []).append(j)
    said = "".join(f" {'Its job' if len(js) == 1 else 'Its jobs'} {_names(_q(j) for j in js)} "
                   f"{'declares' if len(js) == 1 else 'declare'} an environment that holds {_names(_q(n) for n in ns)}, "
                   f"but the caller must still pass a secret for {'the job' if len(js) == 1 else 'a job'} to get it."
                   for ns, js in sorted(by_names.items()))
    listed, whole = declared.get("names") or {}, declared.get("whole", False)
    # A secret passed that the called workflow does not declare: by a GitHub community thread ("Invalid secret,
    # ... is not defined in the referenced workflow"), not by the page, the run may then fail at its start.
    refused = whole and any(k not in listed for k in passes["keys"])
    # Only a declaration read whole says what GitHub does; otherwise every one of them is "either".
    required = sorted(missing[k]["name"] for k in missing if whole and not refused and listed.get(k) is True)
    unsure = sorted(missing[k]["name"] for k in missing
                    if not whole or refused or (k in listed and listed[k] is None))
    empty = sorted(set(names) - set(required) - set(unsure))
    outcome = []
    if required:
        outcome.append(f"GitHub fails the run at its start for {_names(_q(n) for n in required)}, which the called "
                       "workflow marks required")
    if empty:
        outcome.append(f"{_names(_q(n) for n in empty)} {'is' if len(empty) == 1 else 'are'} empty in the called "
                       "workflow, and the run shows no error")
    if unsure:
        why = ("the call also passes a secret the called workflow does not declare" if refused else
               "the called workflow's declaration of its secrets was not read whole" if not whole else
               "the called workflow's declaration of it was not read as true or false")
        outcome.append(f"for {_names(_q(n) for n in unsure)} the run either fails at its start or gets an empty "
                       f"value ({why})")
    many = len(names) > 1
    run.finding(subject, "medium",
                f"The job calls {_q(target, 120)} without passing {_names(_q(n) for n in names)}, which "
                f"{'its job' if len(jobs) == 1 else 'its jobs'} {_names(_q(j) for j in jobs)} "
                f"{'reads' if len(jobs) == 1 and not many else 'read'}, and "
                f"{'which are' if many else 'which is'} stored in the "
                f"{'environment' if len(envs) == 1 else 'environments'} {_names(_q(e) for e in envs)}.{said} A "
                "called workflow gets only the secrets its caller passes, by name or with secrets: inherit, so "
                + "; ".join(outcome) + ".")


def _call_graph_parts(run: _Run) -> dict:
    """For each workflow file whose own calls reach a file in a cycle or a chain deeper than GitHub allows (by
    _call_graph_doubts), itself included, why: a run of it GitHub may refuse whole, so no job in it may run at
    all (the second review of slice 2b.9: a finding there said "the run shows no error"). Only what a file's
    own calls reach counts, never another caller of the same workflow (the third review: one cyclic file made
    every caller of a shared workflow "cannot tell"). One pass up the calls from every such file at once."""
    files = run.files()
    read = {file["path"] for file in files}
    calls = {file["path"]: [t for t in (called_path(job) for job in file["jobs"]) if t is not None] for file in files}
    doubts = _call_graph_doubts(calls, read)
    for file in files:
        if not file.get("triggers") and file["path"] not in doubts:
            # No event starts it, and GitHub calls only a workflow that has `workflow_call` (the fourth review).
            doubts[file["path"]] = "no event starts it, so GitHub never runs it"
    if not doubts:
        return {}
    callers: dict = {}
    for path, targets in calls.items():
        for target in dict.fromkeys(targets):
            callers.setdefault(target, []).append(path)
    out = {path: [f"{plain(path, 120)}: {why}"] for path, why in doubts.items()}
    frontier = list(out)
    while frontier:
        reached = []
        for target in frontier:
            for path in callers.get(target, ()):
                if path not in out:
                    out[path] = out[target]
                    reached.append(path)
        frontier = reached
    # A file that runs only when called runs only inside its callers' runs: when every caller in this repository
    # is a run GitHub may refuse, so is each of its own (the third review: a chain a→b→c→d→e, whose files below
    # `a` run only from it). Each file is settled once, when its last caller is.
    only_called = {f["path"] for f in files if f.get("triggers") and set(f["triggers"]) <= {"workflow_call"}}
    left = {path: len(set(callers.get(path, ()))) for path in only_called}
    frontier = list(out)
    settled = set(out)
    while frontier:
        reached = []
        for path in frontier:
            for target in dict.fromkeys(calls.get(path, ())):
                if target in left and target not in settled:
                    left[target] -= 1
                    if left[target] == 0:
                        out[target] = [f"{plain(target, 120)}: it runs only when called, and every workflow here "
                                       f"that calls it is one GitHub may refuse ({out[path][0]})"]
                        settled.add(target)
                        reached.append(target)
        frontier = reached
    return out


def _weighed_call(run: _Run, job: dict) -> bool:
    """Whether OBAAF-SET-011 has something to weigh for a calling job: it passes a secret (by name, with
    `secrets: inherit`, or as an input), it calls a workflow that was not read (in another repository, or one
    that does not parse or was not found), or a job of the workflow it calls reads one."""
    passes = job["passes"]
    if passes["inherit"] or passes["keys"] or passes["odd_keys"] or passes["inputs"] or passes["inputs_all"] \
            or passes["all"]:
        return True
    local = _called(run, job)
    return local is None or any(j["secrets"] or j["all_secrets"] or j["passes"] for j in local["jobs"])


def _weigh_call(run: _Run, file: dict, job: dict, kept: _Secrets, listed: str, graph: dict) -> None:
    """OBAAF-SET-011 for one calling job."""
    subject = f"job {_job_label(file, job)}"
    target = job["calls"] or ""
    passes = job["passes"]
    local = _called(run, job)
    doubt = list(job.get("doubt") or []) + list(file.get("may_refuse") or []) + \
        (list(local.get("may_refuse") or []) if local else []) + graph.get(file["path"], [])
    if doubt:
        # The caller's file, or the file it calls, may be read by GitHub otherwise than by this reader (a YAML
        # merge key may give the environment or the secrets passed), or not run.
        run.cannot_tell(subject, f"The job calls {_q(target, 120)}, and GitHub may read the files otherwise "
                                 f"than the audit does, or not run them ({_names(doubt, 2)}), so what the called "
                                 "jobs get for the secrets they read is not known.")
        return
    # Handed over as an input, under `with:`: an input is not a secret, so no environment the called job
    # declares stands in for it.
    for name in passes["inputs"]:
        if name.upper() in kept.only_env:
            run.finding(subject, "medium",
                        f"The job hands secrets.{plain(name, 60)} to {_q(target, 120)} as an input. "
                        f"{_given([name.upper()], kept.only_env)}, and a job that calls a reusable workflow "
                        "cannot declare an environment, so the called workflow cannot get its value that way, "
                        "whatever it declares.")
    if passes["inputs_all"]:
        run.cannot_tell(subject, f"The job hands {_q(target, 120)} a secret it picks with an expression as an "
                                 "input. Whether that is one stored only in an environment is not known.")
    if local is None:
        unread = "which was not read (it is in another repository, could not be parsed, or is not among the files read)"
        said = len(run.results)
        if passes["odd_keys"]:
            run.cannot_tell(subject, f"The job calls {_q(target, 120)}, {unread}, and its secrets: holds a key "
                                     "this reader does not take as a plain name, or is text other than inherit. "
                                     "What a job there gets for a secret kept in an environment is not known.")
        elif passes["inherit"]:
            run.cannot_tell(subject, f"The job passes every secret to {_q(target, 120)}, {unread}. Whether a "
                                     "job there reads a secret kept in an environment without declaring that "
                                     f"environment ({listed or 'none is kept only in one'}) is not known.")
        for name, key in sorted(passes["keys"].items()):
            reads = sorted(set(key["reads"]) & kept.only_env_names)
            if key["all"]:
                run.cannot_tell(subject, f"The job passes {_q(name)} to {_q(target, 120)} as a secret it picks "
                                         f"with an expression, {unread}. Whether that is one stored only in "
                                         "an environment is not known.")
            elif reads:
                run.cannot_tell(subject, f"The job passes {_q(name)} to {_q(target, 120)}, {unread}. "
                                         f"{_given(reads, kept.only_env)}: a job there gets a value for it only "
                                         "if it declares an environment that holds it, and whether one does is "
                                         "not known.")
        if len(run.results) == said:
            run.cannot_tell(subject, f"The job calls {_q(target, 120)}, {unread}. Whether a job there reads a "
                                     "secret kept in an environment that this job does not pass, which it would "
                                     "then get empty, is not known.")
        return
    missing: dict = {}
    for called in local["jobs"]:
        onward = called["passes"] and (called["passes"]["inherit"] or called["passes"]["all"])
        if called["all_secrets"] or onward:
            # It can read any secret, or passes them all on: which it relies on is not known.
            run.cannot_tell(subject, f"The job calls {_q(target, 120)}, whose job {_q(called['id'])} "
                                     + ("passes every secret on to another call" if onward and not
                                        called["all_secrets"] else "can read any secret")
                                     + ". Whether it relies on one kept in an environment, and what it gets "
                                       "for it, is not known.")
        # Each secret it names is still weighed, once in any letter case, as GitHub compares the names.
        spelled: dict = {}
        for name in called["secrets"]:
            spelled.setdefault(name.upper(), name)
        for name in spelled.values():
            _reaches_called_job(run, subject, target, passes, called, name, kept, missing)
    _missing_finding(run, subject, target, missing, kept, local.get("call_secrets") or {}, passes)


def rule_011(run: _Run) -> None:
    callers = [(file, job) for file, job in run.jobs() if job["calls"] and _weighed_call(run, job)]
    if not callers:
        run.idle = "no job passes a secret to a reusable workflow, or calls one that reads a secret or was not read"
        return
    env_secrets, env_whole = run.got("environment_secrets")
    repo, repo_whole = run.got("repository_secrets")
    org, org_whole = run.got("organization_secrets")
    if not (env_whole and repo_whole and org_whole):
        run.unread("where the secrets are stored",
                   f"{_do(len(callers), 'job', 'calls', 'call')} a reusable workflow, and whether a secret that "
                   "workflow reads is kept in an environment is not known",
                   "environment_secrets", "repository_secrets", "organization_secrets")
        return
    kept = _Secrets(env_secrets, {name.upper() for name in list(repo) + list(org)})
    run.compared = f"{_n(len(callers), 'job')} calling a reusable workflow"
    if not kept.stored:
        return  # no secret is kept in an environment
    listed = _names(_q(n) for n in sorted(kept.only_env))
    graph = _call_graph_parts(run)
    for file, job in callers:
        mark = len(run.results)
        _weigh_call(run, file, job, kept, listed, graph)
        if self_repository_call(job):
            # D-076 reads a `$/` call as this repository's, though whether GitHub takes `$/` in a job's `uses:` was
            # not established: a finding then rests on that, wherever the weighing ended (the third review).
            for result in run.results[mark:]:
                if result["state"] == "finding":
                    result["message"] += (" This holds if GitHub runs a call written with $/, which was not "
                                          "established.")


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
        if "branch_rules" in need["gaps"] and (run.settings["branch_rules"]["status"] != "read"
                                               or need["rules_missing"]):
            run.unread(f"branch {_q(branch)}", "which rulesets are in force on it is not known", "branch_rules",
                       clauses=need["rules_missing"])
        for ruleset_id, types in sorted(need["rulesets"].items()):
            gates = sorted(set(types) & set(GATES))
            # A type this version does not know may be a gate: it is never read as one that is not.
            unknown = sorted({t for t in types if t not in RULE_TYPES})
            if not gates and not unknown:
                continue  # a ruleset that asks for no check and no review: nothing a workflow's result feeds
            compared += 1
            label = f"ruleset {ruleset_id}" + (f" {_q(names[ruleset_id])}" if ruleset_id in names else "")
            subject = f"branch {_q(branch)}: {label}"
            unknown_text = (f"{_n(len(unknown), 'rule')} of a type this audit does not know "
                            f"({_names([_q(t, 60) for t in unknown], 3)})" if unknown else "")
            asks = f"what it requires ({_names(gates + ([unknown_text] if unknown_text else []))})"
            actors = listed.get(ruleset_id)
            mine = viewer.get(ruleset_id)

            def bypass(severity: str, message: str, evidence, label=label, subject=subject, gates=gates,
                       unknown_text=unknown_text) -> None:
                """A bypass of a ruleset that may ask for nothing a bypass skips is not a finding."""
                if gates:
                    run.finding(subject, severity, message, evidence)
                else:
                    run.cannot_tell(subject, f"{message} Its only rules that could ask for a check or a review "
                                             f"are {unknown_text}, so whether a bypass skips one is not known.")
            if actors is None:
                # The list was not read. What GitHub says of the token's own account is still evidence
                # of one identity that can bypass, and never that nobody else can.
                run.unread(subject, "who may bypass it is not known"
                           + (f", and it has {unknown_text}" if unknown_text else ""), "ruleset_bypass_actors")
            # Only "pull_request" is the narrower mode. Any other (always, exempt, one this version does
            # not know, or none given) is read as the wider one.
            others = [a for a in actors or [] if a["bypass_mode"] == "pull_request"]
            always = [a for a in actors or [] if a not in others]
            covered = sum(roles[ROLE_BY_ID[a["actor_id"]]] for a in always
                          if roles and a["actor_type"] == "RepositoryRole" and a["actor_id"] in ROLE_BY_ID)
            by_role = bool(pushers) and covered >= pushers
            # The GitHub Actions app may bypass: any workflow's token (github-actions[bot]) then can, and
            # anyone who can push a branch can add a workflow there that asks for `contents: write` and
            # pushes past the ruleset (slice 2d.2g; that the app's id is the actor id is not verified).
            by_actions = any(a["actor_type"] == "Integration" and a["actor_id"] == ACTIONS_APP for a in always)
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
            # GitHub's word for how the token's account may bypass: "pull_requests_only" (or "pull_request") is
            # the narrower mode and "never" none; "always", "exempt" and any word this version does not know
            # are read as the wider one, as for the listed actors (slice 2d.2g: "exempt" was read as narrower).
            mine_wide = bool(mine) and mine not in ("never", "pull_request", "pull_requests_only")
            if always or mine_wide:
                who = _names(_actor_text(a) + ("" if a["bypass_mode"] == "always" else
                                               f" (mode: {plain(a['bypass_mode'] or 'not given', 30)})")
                             for a in always) or "the account whose token ran this audit"
                tail = (" The GitHub Actions app is among them, so any workflow's token can bypass it, and "
                        "anyone who can push a branch can add a workflow that asks for `contents: write` and "
                        "pushes: the ruleset holds nobody who can author a change." if by_actions else
                        " Every account that can push holds one of those roles, so the ruleset holds nobody "
                        "who can author a change." if by_role else
                        " One account can push and it is an administrator. An organisation always has an "
                        "owner, who administers every repository, so that account is an organisation "
                        "administrator: the ruleset holds nobody who can author a change." if sole_owner else "")
                bypass("high" if by_role or sole_owner or by_actions else "medium",
                       f"The {label} is in force on {_q(branch)}, and {who} may always bypass it: push or "
                       f"merge without {asks}.{tail}", evidence)
                if always and not (by_role or sole_owner or by_actions) and roles is None:
                    run.unread(subject + ": how many it covers",
                               "whether the bypass covers everyone who can push is not known", "collaborators")
            elif others or (mine and mine != "never"):
                who = _names(_actor_text(a) for a in others) or "the account whose token ran this audit"
                how = ("when merging a pull request" if others or mine in ("pull_request", "pull_requests_only")
                       else f"(GitHub's word for how: {plain(mine, 30)})")
                bypass("low", f"The {label} is in force on {_q(branch)}, and {who} may bypass it {how}: merge "
                              f"without {asks}.", evidence)
        classic = need["classic"]
        if classic is not None and classic["exists"]:
            compared += 1
            subject = f"branch {_q(branch)}: classic protection"
            gating = classic["required_status_checks"]["required"] or classic["required_pull_request_reviews"]["required"]
            if not classic["enforce_admins"] and gating:
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
            if need["classic_fields"]:
                run.cannot_tell(subject + ": fields this audit does not know",
                                f"GitHub's answer for the classic protection rule on {_q(branch)} has "
                                f"{_n(len(need['classic_fields']), 'field')} this audit does not know: "
                                f"{_names(need['classic_fields'], 3)}. Whether they let someone skip the rule, or "
                                "name someone who may, is not known.")
        elif need["classic_unknown"]:
            run.unread(f"branch {_q(branch)}: classic protection",
                       "whether the branch has a classic protection rule, and whether administrators are held "
                       "to it, is not known", "branch_protection")
    if compared:
        run.compared = (f"{_n(compared, 'set')} of rules that ask for checks or reviews, in force on "
                        f"{_n(len(branches), 'audited branch', 'audited branches')}")
    elif not run.results:
        run.idle = "no ruleset or classic rule that asks for checks or reviews is in force on an audited branch"


def _parameters_text(need: dict) -> str:
    """The parameters about approvals that the rules could not judge on a branch, as one clause."""
    return "; ".join(need["parameters_unread"])


def _also(run: _Run, clause: str, who: str = "Its rules") -> None:
    """Name what was not weighed in the result just given, when that result was given for another reason."""
    if clause and run.results:
        run.results[-1]["message"] += f" {who} also ask for what this audit cannot weigh: {clause}."


OWNER_CLAUSE = ("a code owner's review where a changed file has a code owner (require_code_owner_review), and the "
                "CODEOWNERS file, which says who the code owners are, is not read")


def rule_005(run: _Run) -> None:
    branches = _branches(run)
    collaborators, people_known = run.got("collaborators")
    compared, copilot, no_effect = 0, [], []
    for branch in branches:
        need = _branch_requirements(run, branch)
        subject = f"branch {_q(branch)}"
        required = need["approvals"]
        odd = _parameters_text(need)
        # A code owner's review may be one nobody but the author can give; who the code owners are is not read.
        weigh = "; ".join(([OWNER_CLAUSE] if need["code_owner"] else []) + ([odd] if odd else [])
                          + need["merge_unread"])
        if not required:
            if not need["approvals_whole"]:
                run.unread(subject, "how many approvals it requires is not known",
                           *sorted(set(need["gaps"])), clauses=need["approvals_unread"])
                _also(run, weigh)
            elif weigh:
                run.cannot_tell(subject, f"{_q(branch)} requires no approval by count, and it asks for what this "
                                         f"audit cannot weigh: {weigh}. Whether a pull request needs an approval, "
                                         "and whether it can be given, is not known.")
            if need["no_effect"]:
                no_effect.append(branch)
            continue
        compared += 1
        if collaborators is None or not people_known:
            run.unread(subject, f"it requires {_n(required, 'approval')}, and how many accounts can give one is "
                                "not known", "collaborators")
            _also(run, weigh)
            continue
        roles = collaborators["by_role"]
        can = sum(roles[r] for r in PUSH_ROLES)
        if can - 1 >= required and not need["approvals_whole"]:
            run.unread(subject, f"it requires at least {_n(required, 'approval')}, which {_n(can, 'account')} "
                                "can give each other, and whether it requires more is not known",
                       *sorted(set(need["gaps"])), clauses=need["approvals_unread"])
            _also(run, weigh)
        elif can - 1 < required:
            copilot_text = ""
            if need["copilot"] > required:
                copilot_text = (f" A pull request Copilot opens without a person needs {need['copilot']} "
                                f"(require_extra_approval_for_unattributed_changes), more than {_n(can, 'account')} "
                                "can give.")
            unread = "; ".join(need["approvals_unread"] + [run.why(k) for k in sorted(set(need["gaps"]))
                                                           if run.settings[k]["status"] in ("unread", "partial")])
            review = (f" Copilot is asked to review pull requests here (copilot_code_review, "
                      f"{_names(need['copilot_review'], 2)}). By GitHub's changelog of 2026-09-01 its review can "
                      "approve, and count toward the required approvals, where that is turned on, which this audit "
                      "does not read: if it is on, this finding may not hold." if need["copilot_review"] else "")
            run.finding(subject, "medium",
                        f"{_q(branch)} requires {_n(required, 'approval')}, and {_n(can, 'account')} "
                        f"{'has' if can == 1 else 'have'} the write access an approval needs. Nobody can "
                        "approve their own pull request, so a pull request from "
                        f"{'that account' if can == 1 else 'any of them'} can get at most "
                        f"{_n(max(can - 1, 0), 'approval')}: it merges only by a bypass."
                        + copilot_text
                        + ("" if need["approvals_whole"] else f" (Not everything about its approvals was read, "
                           f"and what was not can only ask for more: {unread}.)")
                        + (f" Its rules also ask for what this audit cannot weigh: {weigh}." if weigh else "")
                        + review)
        elif weigh:
            run.cannot_tell(subject, f"{_q(branch)} requires {_n(required, 'approval')}, which {_n(can, 'account')} "
                                     f"can give each other, and it asks for what this audit cannot weigh: {weigh}. "
                                     "Whether more is required than they can give is not known.")
        elif need["copilot"] > required:
            copilot.append(branch)
        if need["no_effect"] and required:
            no_effect.append(branch)  # on a rule of its own that counts 0, beside one that asks for approvals
    zero = (f"require_extra_approval_for_unattributed_changes is on a rule counting 0 on "
            f"{_names([_q(b, 40) for b in no_effect], 2)}, where it adds none")
    if compared:
        run.compared = (f"the approvals required on {_n(compared, 'branch', 'branches')} and the accounts that can "
                        "give them")
        if copilot:
            # Nobody is the author of a pull request Copilot opens without a person, so every account with write
            # access may approve it, and one more than the count is at most what they can give when there is no
            # finding (the count is at most their number less one).
            run.compared += (f"; on {_names([_q(b, 40) for b in copilot], 2)} a pull request Copilot opens "
                             "without a person needs one more, which they can give, none being its author")
        if no_effect:
            run.compared += f"; {zero}"
    elif not run.results:
        run.idle = "no audited branch requires an approval" + (f" ({zero})" if no_effect else "")


def _check_rules(run: _Run, kind: str) -> None:
    """OBAAF-SET-006, 007 and 008 share their reading of the required checks."""
    branches = _branches(run)
    stopped, maybe, blocked, runs_unread = _stops(run)

    def reports(file: dict, job: dict, context: str):
        """_reports, and never True for a job in a file GitHub may not run (slice 2d.2g)."""
        verdict = _reports(job, context)
        return None if verdict is True and file["path"] in maybe else verdict

    reporting = [(f, j) for f, j in run.jobs() if _stands_alone(f) and f["path"] not in stopped]
    idle_files = [(f, j) for f, j in run.jobs() if _stands_alone(f) and f["path"] in stopped]
    broken = run.broken()
    compared = 0
    foreign_only = 0  # required checks OBAAF-SET-007 leaves to OBAAF-SET-006: another app is named

    for branch in branches:
        need = _branch_requirements(run, branch)
        subject = f"branch {_q(branch)}"
        required = need["checks"]
        if not need["checks_whole"]:
            run.unread(subject, "the list of its required checks is not known to be whole",
                       *sorted(set(need["gaps"])), clauses=need["checks_unread"])
        source = (" The checks of the classic protection rule are taken from what GitHub shows anyone; the "
                  "rule itself was not read." if need["from_public_view"] else "")
        # Rules that make a merge wait for a result workflows, tools or deployments give, beyond the required
        # checks. What gives it is not compared with the workflow files (RULE_TYPES).
        queue = [g for g in need["gates"] if g[0] == "merge_queue"]
        waits = [g for g in need["gates"] if g[0] != "merge_queue"]
        if kind == "missing":
            for gate, ruleset_id, parameters in waits:
                run.cannot_tell(f"{subject}: {_q(gate, 40)} rule of ruleset {plain(ruleset_id, 20)}",
                                f"{_q(branch)} also makes a merge wait for {_gate_text(gate, parameters)} "
                                f"({_q(gate, 40)}, ruleset {plain(ruleset_id, 20)}). What gives that result, and "
                                "whether it does on every pull request, is not compared with the workflow files.")
        if kind == "filtered":
            for _, ruleset_id, _ in queue:
                run.cannot_tell(f"{subject}: \"merge_queue\" rule of ruleset {plain(ruleset_id, 20)}",
                                f"{_q(branch)} merges through a merge queue (\"merge_queue\", ruleset "
                                f"{plain(ruleset_id, 20)}), whose runs are not the pull request's. Whether the jobs "
                                "that report its required checks run for the queue (the merge_group event) is not "
                                "compared.")
        waiting = (f" {_q(branch)} also makes a merge wait for "
                   f"{_names([f'{_gate_text(g, p)} ({_q(g, 40)}, ruleset {plain(r, 20)})' for g, r, p in waits], 3)}, "
                   "which is not compared with the jobs: if this job gives that result, its failure may hold the "
                   "merge up after all." if waits else "")
        if kind == "missing":
            for context, app in sorted(required.items()):
                compared += 1
                item = f"{subject}: required check {_q(context)}"
                if app is not None and app != ACTIONS_APP:
                    run.cannot_tell(item, f"{_q(branch)} requires {_q(context)} from the app with id "
                                          f"{plain(app, 20)}, which is not GitHub Actions. What that app reports "
                                          "is not something the audit reads.")
                    continue
                verdicts = [reports(file, job, context) for file, job in reporting]
                if any(v is True for v in verdicts):
                    continue
                idle = [(f, j) for f, j in idle_files if _reports(j, context) is not False]
                off = any(why == "GitHub Actions is turned off for the repository" for why in stopped.values())
                if idle and app == ACTIONS_APP and not broken and not any(v is None for v in verdicts) and (
                        off or _api_reporters(run) == "no"):
                    file, job = idle[0]
                    run.finding(item, "medium",
                                f"{_q(branch)} requires the check {_q(context)} from GitHub Actions. The only job "
                                f"known to report it, {_job_label(file, job)}, is in a workflow GitHub does not "
                                f"run: {stopped[file['path']]}. It stays pending on every pull request, so "
                                f"nothing merges without a bypass.{source}")
                    continue
                if idle:
                    file, job = idle[0]
                    run.cannot_tell(item, f"The only job known to report {_q(context)}, {_job_label(file, job)}, is "
                                          f"in a workflow GitHub does not run ({stopped[file['path']]}), and something "
                                          "else may report it (another file that could not be read or whose names "
                                          "could not be written out, or a step whose token may write checks), so "
                                          "whether anything does is not known.")
                    continue
                unsure = sum(1 for v in verdicts if v is None)
                if broken or unsure:
                    why = ([f"{_n(len(broken), 'workflow file')} could not be read"] if broken else []) + (
                        [f"{_do(unsure, 'job', 'reports', 'report')} under names that could not be written "
                         "out (a computed name, a matrix or a called workflow that was not read), or in a file "
                         "GitHub may read otherwise than the audit does or may not run"] if unsure else [])
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
                # A job in a file GitHub may not run counts here (the review of slice 2b.7): whether its paths filter,
                # its activity types or its triggers keep the check from reporting holds whether or not the file
                # runs, since a file that does not run reports nothing. One GitHub may read otherwise does not.
                matches = [(f, j) for f, j in reporting if _reports(j, context) is True]
                if not matches:
                    continue  # nothing is known to report it: OBAAF-SET-006's subject
                if not _held_by_actions(need["apps"][context]):
                    foreign_only += 1
                    continue  # required from another app: what that app reports is not read (OBAAF-SET-006)
                compared += 1
                # Only a plain job that is skipped reports its check as passed: `if:` is decided before a matrix
                # expands and before a called workflow runs, so a skipped matrix job or caller reports its bare
                # name, not the required one (the review of slice 2d.2g).
                runs = sorted(((_report_run(f, j, branch, skipped=j["check"]["kind"] == "static",
                                            blocked=blocked.get(f["path"], ())), f, j)
                               for f, j in matches), key=lambda item: ORDER.index(item[0]))
                item = f"{subject}: required check {_q(context)}"
                # A route through a file GitHub may not run never stands for the check (the second review of slice
                # 2b.7), and neither does a job that may report it under names that could not be written out, or in
                # a file GitHub may read otherwise (the third review). Where the route that decides gives a finding
                # (a paths filter, activity types, or no run on a pull request's commit where nothing else can
                # report it), the answer is "cannot tell" if any other job may report the check on a route that
                # gives no finding, or two filtered routes may cover every pull request between them (the fourth
                # review): ranks do not say which pull requests a route covers. A job that never runs on a pull
                # request's commit changes nothing (whatever its token: the fifth review). Jobs whose names could not
                # be written out are read at their widest: a plain job skipped by `if:` still reports, and one in a
                # file GitHub may read otherwise runs on every pull request.
                sure = [r for r in runs if r[1]["path"] not in maybe]
                how, file, job = sure[0] if sure else runs[0]
                writers = _api_reporters(run)
                failing = {"paths", "types"} | ({"never"} if writers == "no" else set())
                if how in failing:
                    unknown = []
                    for f, j in reporting:
                        if _reports(j, context) is None:
                            widest = j["check"]["kind"] in ("static", "computed")
                            unknown.append(("always" if j.get("doubt") else _report_run(
                                f, j, branch, skipped=widest, blocked=blocked.get(f["path"], ())), f, j))
                    # Two filtered routes in different files may cover every pull request between them (paths and
                    # paths-ignore); jobs of one file share its filters (the fifth review of 2b.7).
                    filtered = list({r[1]["path"]: r for r in runs if r[0] in ("paths", "types")}.values())
                    rival = next((r for r in runs if r[0] not in failing and r[0] != "never"), None) or next(
                        (r for r in unknown if r[0] != "never"), None) or (filtered[1] if len(filtered) > 1 else None)
                    if rival is not None:
                        _, other, other_job = rival
                        why = (f", in a workflow GitHub may not run ({maybe[other['path']]})," if other["path"] in maybe
                               else ", under names that could not be written out or in a file GitHub may read "
                               "otherwise than the audit does," if _reports(other_job, context) is None else "")
                        where = "on no pull request's commit" if how == "never" else "on only some pull requests"
                        run.cannot_tell(item, f"{_q(branch)} requires the check {_q(context)}. "
                                              f"{_job_label(file, job)} reports it {where}, and "
                                              f"{_job_label(other, other_job)}{why} may also report it, so whether "
                                              "it reports on every pull request is not known.")
                        continue
                    how, file, job = runs[0]    # the one route that reports it on some pull requests, if any
                elif how == "always" and not sure:
                    # Every known route is in a file GitHub may not run (the fifth review of 2b.7): if that file does
                    # not run, any other job that may report the check decides, so the answer is "cannot tell".
                    others = [r for r in runs[1:] if r[0] != "always"] + [
                        (None, f, j) for f, j in reporting if _reports(j, context) is None]
                    if others:
                        _, other, other_job = others[0]
                        run.cannot_tell(item, f"{_q(branch)} requires the check {_q(context)}. {_job_label(file, job)} "
                                              f"reports it on every pull request, in a workflow GitHub may not run "
                                              f"({maybe[file['path']]}), and {_job_label(other, other_job)} may also "
                                              "report it, on a route of its own, so whether it reports on every pull "
                                              "request is not known.")
                        continue
                lead = f"{_q(branch)} requires the check {_q(context)}, which {_job_label(file, job)} reports"
                if how == "always":
                    continue  # in a file GitHub may not run: whether it runs at all is OBAAF-SET-006's subject
                if how == "maybe":
                    run.cannot_tell(item, f"{lead}. Whether that workflow runs for pull requests into {_q(branch)} "
                                          "rests on a branch pattern, which is not evaluated.")
                elif how == "target":
                    run.cannot_tell(item, f"{lead}, and that job reaches pull requests only through "
                                          "pull_request_target, which runs on the latest commit of the default "
                                          "branch (GitHub's changelog of 2025-11-07), not on the pull request's. "
                                          "Whether its check counts for the pull request is not established.")
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
            unrequired, unsure, foreign, shared, targets = [], 0, [], [], []
            hows = {(file["path"], job["id"]): _report_run(file, job, branch, pushes=False,
                                                           blocked=blocked.get(file["path"], ()))
                    for file, job in reporting}
            # A check name more than one job that may run on a pull request into the branch reports: GitHub
            # weighs one check run of a name (not verified), so which job's result holds a merge up is not
            # known (slice 2d.2g).
            reported_by: dict = {}
            for file, job in reporting:
                if hows[(file["path"], job["id"])] not in ("manual", "never"):
                    for name in set(job["check"]["names"] or []):
                        reported_by[name] = reported_by.get(name, 0) + 1
            for file, job in reporting:
                if job["advisory"]:
                    continue
                how = hows[(file["path"], job["id"])]
                if how == "target":
                    # Whether its check counts on the pull request is OBAAF-SET-007's question; a check nobody
                    # requires fails without blocking a merge either way (the review of slice 2d.2g).
                    how = "always"
                if how == "always" and (job.get("doubt") or file["path"] in maybe):
                    targets.append((file, job, maybe.get(file["path"], "")))
                    continue
                if how == "maybe":
                    # A branch pattern decides whether it runs for pull requests into this branch.
                    unsure += 1
                    continue
                if how != "always":
                    continue
                names = job["check"]["names"]
                if job["check"]["kind"] != "computed" and names is not None:
                    # A job of a called workflow with `continue-on-error: true` reports as passed (slice 2d.2g).
                    advisory = set(job["check"].get("advisory_names") or [])
                    names = [name for name in names if name not in advisory]
                    twice = [name for name in names if reported_by.get(name, 0) > 1 and name in need["apps"]]
                    if twice:
                        shared.append((file, job, twice))
                        continue
                    # Every check the job reports must be required: one of a matrix's checks, or one of a
                    # called workflow's, being required leaves the others free to fail.
                    loose = [name for name in names if name not in need["apps"]]
                    if loose:
                        compared += 1
                        unrequired.append((file, job, loose, len(names)))
                    elif all(_held_by_actions(need["apps"][name]) for name in names):
                        compared += 1
                    else:
                        # A name required from another app: whether a failing Actions check of that name
                        # holds the merge up is not established.
                        foreign.append((file, job, [n for n in names if not _held_by_actions(need["apps"][n])]))
                    continue
                verdicts = [reports(file, job, context) for context in need["apps"]]
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
                            f"while any of them is failing.{source}{waiting}")
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
                            f"request can merge while the job is failing.{source}{waiting}")
            for file, job, stop in targets:
                why = (f"GitHub may not run its file ({stop})" if stop else
                       f"GitHub may read it otherwise than the audit does ({_names(job['doubt'], 2)})")
                run.cannot_tell(f"{subject}: job {_job_label(file, job)}",
                                f"{_job_label(file, job)} may run on pull requests into {_q(branch)}, and {why}, so "
                                "whether it can fail without blocking a merge was not compared.")
            for file, job, names in shared:
                run.cannot_tell(f"{subject}: job {_job_label(file, job)}",
                                f"{_job_label(file, job)} runs on every pull request into {_q(branch)} and reports "
                                f"{_names(_q(n) for n in names)}, which another job reports too. GitHub weighs one "
                                "check run of a name (not verified), so whether a failing run of this job holds a "
                                "merge up is not known.")
            for file, job, names in foreign:
                run.cannot_tell(f"{subject}: job {_job_label(file, job)}",
                                f"{_job_label(file, job)} runs on every pull request into {_q(branch)} and reports "
                                f"{_names(_q(n) for n in names)}, which {'is' if len(names) == 1 else 'are'} "
                                "required there from another app (and not from GitHub Actions). How GitHub weighs a "
                                f"check of {'that name' if len(names) == 1 else 'those names'} from GitHub Actions "
                                "against such a requirement is not established, so whether a failing run holds the "
                                "merge up is not known.")
            if unsure:
                run.cannot_tell(f"{subject}: jobs whose check names could not be written out",
                                f"{_n(unsure, 'job')} that may run on pull requests into {_q(branch)}: "
                                f"{'its' if unsure == 1 else 'their'} check names could not all be written out "
                                "(a computed name, a matrix or a called workflow that was not read), or a branch "
                                "pattern in the triggers decides whether it runs there (patterns are not "
                                f"evaluated), so whether {'it' if unsure == 1 else 'each'} can fail without "
                                "blocking a merge was not compared.")
    if runs_unread and (compared or run.results):
        # Not a "cannot tell": these settings need an administrator's token, and without one every check rule
        # would answer nothing. The rule's line says what its answers took for granted, whatever they are
        # (slice 2d.2g).
        run.assumed = ("every workflow file was taken as running, because whether GitHub Actions is on, requires "
                       "pinning, or has a policy that blocks an event was not read (" + "; ".join(runs_unread) + ")")
    if compared:
        run.compared = {"missing": f"{_n(compared, 'required check')} and the names the jobs report",
                        "filtered": f"{_n(compared, 'required check')} that a job reports, and its triggers",
                        }.get(kind, f"{_n(compared, 'job')} running on every pull request, and the required checks")

    elif not run.results:
        run.idle = {"missing": "no audited branch requires a check",
                    "filtered": ("the required checks a workflow job reports are required from another app, which "
                                 "OBAAF-SET-006 cannot tell about" if foreign_only else
                                 "no required check is known to be reported by a workflow job"),
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
    # Which repositories it is for (slice 2d.2g: these were accepted and ignored, so a policy that leaves this
    # repository out counted as one that applies). Only "every repository" is read; any other list is not
    # evaluated, and the policy is then one this rule does not understand.
    for key in ("repository_name", "repository_id"):
        if key in conditions and conditions[key] != {"include": ["~ALL"], "exclude": []} \
                and conditions[key] != {"include": ["~ALL"]}:
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


def _token_from_elsewhere(run: _Run, file: dict, job: dict) -> bool:
    """Whether a job with no permissions block still does not get the repository's default (flagship slice
    2d.2g). A job that calls a workflow in this repository whose every job declares its permissions passes
    on a token they narrow ("can be only downgraded", GitHub's page on reusing workflows). A job in a workflow
    only other workflows start gets its caller's token: when every job here that calls it declares its
    permissions, that token is theirs, not the default. A workflow nothing here calls may be called from
    elsewhere, so it is not taken to be covered."""
    called = _called(run, job) if job["calls"] else None
    if called is not None:
        return bool(called["jobs"]) and all(j["permissions"]["declared"] for j in called["jobs"])
    if _stands_alone(file):
        return False
    callers = [j for _, j in run.jobs() if called_path(j) == file["path"]]
    # A call written with `$/` may not be one GitHub makes (issue #182): it never counts as the caller that
    # covers the file, and an undeclared one still uncovers it.
    return any(not self_repository_call(j) for j in callers) and all(j["permissions"]["declared"] for j in callers)


def rule_012(run: _Run) -> None:
    bare = [(f, j) for f, j in run.jobs() if not j["permissions"]["declared"] and not _token_from_elsewhere(run, f, j)]
    if not bare:
        run.idle = "every job declares its permissions, or gets a token that another job declares"
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
        odd = [f"on {_q(b)}, {t}" for b in _branches(run) if (t := _parameters_text(_branch_requirements(run, b)))]
        _also(run, "; ".join(odd), "The audited branches' rules")
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
        odd = _parameters_text(need)
        also = f" Its rules also ask for what this audit cannot weigh: {odd}." if odd else ""
        if not count:
            if not need["approvals_whole"]:
                run.unread(subject, f"{lead[:-1]}, and how many approvals {_q(branch)} requires is not known",
                           *sorted(set(need["gaps"])), clauses=need["approvals_unread"])
                _also(run, odd)
            elif odd:
                run.cannot_tell(subject, f"{lead} {_q(branch)} requires no approval by count, and it asks for what "
                                         f"this audit cannot weigh: {odd}. Whether it requires an approval, and "
                                         "whether a workflow's could be it, is not known.")
            continue
        if count == 1 and not need["approvals_whole"]:
            run.unread(subject, f"{lead[:-1]}, and {_q(branch)} requires at least 1 approval"
                                + (" and a code owner's review. A rule about its reviews was not read in full, so "
                                   "whether it requires more approvals is not known; two or more would let the "
                                   "workflow's approval count" if need["code_owner"] else
                                   ". A rule about its reviews was not read in full, so whether it also requires a "
                                   "code owner's review is not known; that could stop the workflow's approval being "
                                   "the one that counts")
                       + (". What was not read" if need["approvals_unread"] or any(
                           run.settings[k]["status"] in ("unread", "partial") for k in need["gaps"]) else ""),
                       *sorted(set(need["gaps"])), clauses=need["approvals_unread"])
            _also(run, odd)
            continue
        if need["code_owner"] and count == 1:
            # The one approval must then come from a code owner where a file has one; a workflow is no code
            # owner. Whether every file has one (the CODEOWNERS file) is not read.
            run.cannot_tell(subject, f"{lead} {_q(branch)} requires 1 approval and a code owner's review. Where "
                                     "every changed file has a code owner, the workflow's approval cannot be the "
                                     "one that counts; where one has none, it can. The CODEOWNERS file is not "
                                     f"read.{also}")
            continue
        extra = (" A code owner's review is required as well, and a workflow's approval still counts towards the "
                 "number." if need["code_owner"] else "")
        run.finding(subject, "medium",
                    f"{lead} {_q(branch)} requires {_n(count, 'approval')}, so a run of such a workflow can give "
                    f"one.{extra}{also}")


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
        run.compared = "the approval rule for fork pull requests, and the runners the jobs name"
        policy = value["approval_policy"]
        if policy == "all_external_contributors":
            return
        # Any job on a self-hosted runner shows the repository has one; a fork's workflow can name it.
        hosted_here = [(f, j) for f, j in run.jobs() if j["runner"] == "self-hosted"]
        if hosted_here:
            file, job = hosted_here[0]
            run.finding("fork pull requests on self-hosted runners", "high",
                        f"{_do(len(hosted_here), 'job', 'runs', 'run')} on a self-hosted runner (the first: "
                        f"{_job_label(file, job)}), so the repository has one, and approval before a fork's "
                        f"workflows run is required only for {_q(policy)}. Anyone else can run their code on that "
                        "machine by opening a pull request: a fork's pull request runs its own copy of the "
                        "workflow files and can name the runner, whatever the jobs here say.")
            return
        run.cannot_tell("fork pull requests and self-hosted runners",
                        f"Approval before a fork's workflows run is required only for {_q(policy)}. A fork's pull "
                        "request runs its own copy of the workflow files, so it can ask for any runner label. No "
                        "job here names a self-hosted runner, and whether the repository has any is not something "
                        "the audit reads; if it has, strangers' code can run there.")
        return
    private = value["private_repository"]
    kind = plain(repository["visibility"] or "private", 20)
    article = "an" if kind[:1] in "aeiou" else "a"
    run.compared = f"what fork pull requests are sent in this {kind} repository"
    if not private["run_workflows_from_fork_pull_requests"]:
        return
    sent = [what for key, what in (("send_secrets_and_variables", "secrets and variables"),
                                   ("send_write_tokens_to_workflows", "a write token")) if private[key]]
    if sent:
        run.finding(f"fork pull requests in {article} {kind} repository", "high",
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
            if run.usage.get("actions_lock"):
                # GitHub's lockfile may pin a tag (its changelog of 2026-10-28, as the review of slice 2d.2g
                # read it); the lockfile is not read here.
                run.cannot_tell(f"workflow {plain(path, 120)}",
                                f"The repository requires actions to be pinned to a full commit, and {plain(path, 120)} "
                                f"uses {_names(sorted(_q(a, 100) for a in actions), 4)}. The repository has "
                                ".github/workflows/actions.lock, which may pin them; it is not read, so whether "
                                "GitHub refuses the workflow is not known.")
                continue
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
        # `why` and `fix` are the rule's own sentences, the same on every run (flagship slice 3.2c).
        rules.append({"id": rule.id, "title": rule.title, "why": rule.why, "fix": rule.fix, "status": status,
                      "findings": len(findings),
                      "cannot_tell": len(unknown),
                      "note": note or ("" if findings or unknown else "nothing to compare"),
                      "assumed": run.assumed, "failed": run.failed})
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
