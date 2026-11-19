"""A model of GitHub Actions workflow files for the OBAAF checker.

The model answers the questions the rules ask: what can start this job, what
can its token do, which secrets reach it, does it run an agent, does it upload
releases, and which caches can it read.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterator

from obaaf import yamlutil
from obaaf.catalog import load as load_catalog
from obaaf.checker import expr as expr_mod

LANES = ("untrusted", "agent", "effect", "release", "trusted")
# A job is in every lane it qualifies for, and gets the rules of each. This is the order they are
# shown in; the first one a job is in is the lane `--lanes` names. "trusted" means none of them.
LANE_ORDER = ("agent", "effect", "release", "untrusted")

# Triggers whose payload or initiating actor someone without write access can
# influence, and which run in the base repository's context with its token,
# secrets and default-branch cache scope.
PRIVILEGED_UNTRUSTED_TRIGGERS = {
    "pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment",
    "pull_request_review", "pull_request_review_comment", "workflow_run", "fork", "watch", "gollum",
}
# pull_request runs the pull request's code; forks get a read-only token and no secrets.
PR_TRIGGERS = {"pull_request"}
UNTRUSTED_TRIGGERS = PRIVILEGED_UNTRUSTED_TRIGGERS | PR_TRIGGERS
# Triggers allowed to start a release workflow.
RELEASE_TRIGGERS = {"push", "release", "workflow_dispatch", "workflow_call", "schedule", "repository_dispatch"}
# A workflow_run job whose `if:` admits only runs started by these events (only people with write
# access can cause them) is not outsider-triggerable. It is listed under this name instead.
TRUSTED_WORKFLOW_RUN = "workflow_run (after push, release, dispatch or schedule)"
# The events GitHub's page "Events that trigger workflows" names (as known to flagship slice 2d.4b1; the
# page was not read again in that slice), every event a rule names (a test holds them to it:
# `commit_comment`, which OBAAF-GHA-010 reads as an outsider's, may not be on the page), and the stand-in
# above. A caller's event outside them is
# passed on to the workflows it calls as OTHER_EVENT, which no rule names, as no rule names the event
# itself, so a chain of files that each invent an event cannot make every file hold every name (the
# third review of the slice: 4,800 such files took 1.1 GB).
GITHUB_EVENTS = frozenset({
    "branch_protection_rule", "check_run", "check_suite", "commit_comment", "create", "delete", "deployment",
    "deployment_status", "discussion", "discussion_comment", "fork", "gollum", "image_version",
    "issue_comment", "issues", "label", "merge_group", "milestone", "page_build", "project", "project_card",
    "project_column", "public", "pull_request", "pull_request_review", "pull_request_review_comment",
    "pull_request_target", "push", "registry_package", "release", "repository_dispatch", "schedule",
    "status", "watch", "workflow_call", "workflow_dispatch", "workflow_run", TRUSTED_WORKFLOW_RUN,
})
OTHER_EVENT = "an event GitHub does not document"
_TRUSTED_RUN_EVENTS = {"push", "release", "workflow_dispatch", "schedule"}

PERMISSION_SCOPES = {
    "actions", "artifact-metadata", "attestations", "checks", "code-quality", "contents", "deployments",
    "discussions", "id-token", "issues", "models", "packages", "pages", "pull-requests",
    "repository-projects", "security-events", "statuses", "vulnerability-alerts",
}

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
# What pins an action or a reusable workflow: a full commit SHA as github.com writes one, 40 hex
# digits in lower case and nothing else (flagship slice 2d.2f). github.com has no SHA-256
# repositories, so a 64-digit ref can only be a tag or a branch, which can move; `$` also matched
# before a line break at the end.
COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
# An image pinned by digest: `name@sha256:` and 64 hex digits, at the end (the OCI grammar's only
# registered SHA-256 form). A shorter or longer digest, or text after it, is not taken for a pin.
IMAGE_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}\Z")


def is_local_reference(uses) -> bool:
    """`./path` or `$/path`: an action or reusable workflow in the workflow's own repository."""
    return isinstance(uses, str) and uses.startswith(("./", "$/"))


def action_name(uses: str) -> str:
    """`owner/repo[/path]` of a `uses:` value that names another repository's action or workflow, without
    the `@ref`. Flagship slice 2d.2e: `actions/cache/save/../restore` is read as the path it names, whether
    or not GitHub resolves it (if it does not, the workflow fails and nothing runs); `..` never climbs out
    of `owner/repo`."""
    action = uses.split("@", 1)[0]
    if "/." in action:
        parts: list[str] = []
        for part in action.split("/"):
            if part == "..":
                if len(parts) > 2:
                    parts.pop()
            elif part not in (".", ""):
                parts.append(part)
        action = "/".join(parts)
    return action


def names_action(action: str, prefix: str) -> bool:
    """Whether `prefix` (`owner/repo` or `owner/repo/path`) names `action` (as `action_name` gives it): the
    same action, or one in a folder under it, in any letter case. `owner/repo-docs` is not under
    `owner/repo`: the next character must be a `/` (flagship slice 2d.11)."""
    low, pre = action.lower(), prefix.lower()
    return low == pre or low.startswith(pre + "/")


def leaves_repository(uses) -> bool:
    """Whether a step's `uses:` names a path that leaves its repository (flagship slice 2d.11,
    from its review): a local `./`, `$/` or `.\\` path whose `..` climbs above the workspace, or another
    repository's action whose `..` climbs to or above `owner/repo` (`action_name` stops `..` there, so the
    name it gives is not what the runner would look for). The runner puts every action a job uses in one
    folder beside the workspace, the whole repository of each, so such a path can reach an action the job
    never names (`./../../_actions/anthropics/claude-code-action/<ref>`). A backslash is read as a `/` too,
    and a local path is also read without what follows an `@`, as `_local_action_folders` reads them, since
    how GitHub reads either is not established."""
    if not isinstance(uses, str):
        return False
    text = uses.strip()
    if not text or text.startswith("docker://"):
        return False
    if text.startswith(("./", "$/", ".\\")):
        rest = text[2:]
        candidates = [rest, rest.split("@", 1)[0]]
        floor = 0
    else:
        candidates = [text.split("@", 1)[0]]
        floor = 2
    for candidate in candidates + [c.replace("\\", "/") for c in candidates if "\\" in c]:
        parts = candidate.split("/")
        if floor and any(part in (".", "..") for part in parts[:floor]):
            return True
        depth = 0
        for part in parts[floor:]:
            if part == "..":
                if depth == 0:
                    return True
                depth -= 1
            elif part not in (".", ""):
                depth += 1
    return False


def _configured_prefix(entry) -> str:
    """A repository's own `agents.actions` entry as a prefix to compare: without space round it, without
    an `@ref` (any ref of it is the agent) and without a `/` at its end, in lower case (flagship slice 2d.11,
    from its review: before, a called workflow was compared with the entry as written, `x.yml@v1` too)."""
    return action_name(str(entry).strip()).rstrip("/").lower()


def _repo_and_path(action: str) -> tuple[str, str]:
    """`owner/repo` in lower case, and the path under it as written: GitHub's owner and repository names
    are read in any case, a path in the repository is not (a git tree is case-sensitive)."""
    parts = action.split("/", 2)
    return "/".join(parts[:2]).lower(), parts[2] if len(parts) > 2 else ""


class AgentActions:
    """The actions the checker takes to run an agent (flagship slice 2d.11): each catalogue entry's
    actions and the paths under them (`agent_actions` in the detection data), except the paths the
    catalogue lists as running no agent (`agent_not_actions`, from each entry's `not_agents`), and a
    repository's own `agents.actions` with every path under them, which nothing narrows. (Where it is read,
    a step whose `uses:` leaves its repository, `leaves_repository`, is taken for an agent's too: it can run
    any action the runner downloaded for the job, the folders this list takes out included.)

    A path the catalogue lists is taken out only as it is written there: its `owner/repo` in any case,
    the folder under it exactly (`agent-approval-check`, not `Agent-Approval-Check`, which a Linux runner
    does not find and a macOS or Windows runner may; the wider reading keeps that one an agent), and only
    that folder, not one under it. A step's action is read with `..` worked out first, so
    `.../agent-approval-check/../base-action` is the base action."""

    __slots__ = ("catalogue", "excluded", "configured", "configured_local")

    def __init__(self, detection: dict, configured=()):
        self.catalogue = tuple(str(a).lower() for a in detection.get("agent_actions", ()) or ())
        self.excluded = frozenset(_repo_and_path(str(a)) for a in detection.get("agent_not_actions", ()) or ())
        given = [str(a).strip() for a in configured or ()]
        self.configured = tuple(p for p in (_configured_prefix(a) for a in given if not is_local_reference(a)) if p)
        # A local entry (`./.github/workflows/agent.yml`) names a called local workflow by its first
        # characters, in any case, as it did before slice 2d.11; no step's action is local.
        self.configured_local = tuple(a.lower() for a in given if is_local_reference(a))

    def names(self, action: str | None) -> str | None:
        """The prefix that makes `action` (`owner/repo[/path]`, as `Step.action` gives it) an agent action,
        as the catalogue or the configuration writes it in lower case, or None."""
        if not action:
            return None
        low = action.lower()
        for prefix in self.configured:
            if low == prefix or low.startswith(prefix + "/"):
                return prefix
        for prefix in self.catalogue:
            if low == prefix or low.startswith(prefix + "/"):
                return None if self.excluded and _repo_and_path(action) in self.excluded else prefix
        return None

    def excludes(self, action: str | None) -> bool:
        """Whether the catalogue lists `action` as one that runs no agent, though it is under an agent
        action's folder (OBAAF-GHA-026 reads no agent tool's settings on it)."""
        return bool(action and self.excluded and _repo_and_path(action) in self.excluded)

    def calls(self, reusable) -> bool:
        """Whether a job that calls the workflow `reusable` (its `uses:`) calls one in an agent action's
        repository or folder, read as a step's action is: `owner/repo/.github/workflows/x.yml@ref` is
        under `owner/repo`, and a workflow of `owner/repo-docs` is not (before slice 2d.11 a call was
        matched by the first characters alone). A call of the workflow's own repository is an agent's only
        where a repository's own local entry begins it."""
        if not isinstance(reusable, str) or not reusable.strip():
            return False
        if is_local_reference(reusable.strip()):
            low = reusable.strip().lower()
            return any(low.startswith(entry) for entry in self.configured_local)
        return self.names(action_name(reusable.strip())) is not None

# OBAAF's egress action (flagship slice 2c.2), as `owner/repo/path` in lower case.
EGRESS_ACTION = "obaaf/obaaf/actions/egress"
# The shape of a GitHub-hosted runner label. Only used to find a hosted label written inside a
# runtime selector; whether a label IS GitHub-hosted is decided by HOSTED_LABELS (flagship slice 2d.2d).
# `\Z`, not `$`, which also matches before a line break at the end (found by the review of 2d.7).
HOSTED_LABEL_RE = re.compile(r"^(ubuntu|windows|macos)-[a-z0-9.-]+\Z")
# The labels of GitHub's standard hosted runners and of its macOS larger runners, which GitHub names
# itself. Any other label, `ubuntu-gpu` or `windows-builder` included, may be a self-hosted runner's
# custom label or a larger runner's name (which the organization picks), so the checker cannot tell
# what runs the job (flagship slice 2d.2d; before, any `ubuntu-*`, `windows-*` or `macos-*` label was
# taken for GitHub-hosted). Written from GitHub's runner reference as the author knew it on
# 2026-11-14; the page could not be read from the session that wrote this. A label missing here
# gives a medium "cannot tell", never a missed self-hosted runner. Retired labels (ubuntu-20.04,
# windows-2019, macos-12, macos-13) are left out: no hosted runner takes them any more.
HOSTED_LABELS = frozenset({
    "ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04", "ubuntu-slim", "ubuntu-24.04-arm", "ubuntu-22.04-arm",
    "windows-latest", "windows-2025", "windows-2022", "windows-11-arm",
    "macos-latest", "macos-26", "macos-15", "macos-14", "macos-15-intel",
    "macos-latest-large", "macos-15-large", "macos-14-large",
    "macos-latest-xlarge", "macos-26-xlarge", "macos-15-xlarge", "macos-14-xlarge",
    # GitHub's native egress firewall runner (a technical preview), the label the firewall's README
    # names and `egress.FIREWALL_LABEL`. OBAAF-GHA-020 already reads it as GitHub's own runner, so
    # OBAAF-GHA-013 does too (flagship slice 2d.9, issue #172; before, a job that cleared
    # OBAAF-GHA-020 here still got a medium OBAAF-GHA-013 for an unknown label). A test keeps the two
    # names the same.
    "ubuntu-24.04-firewall",
})
# Events whose payload has `pull_request.head.repo`, which a fork-safe runner selector tests.
PULL_REQUEST_PAYLOAD_EVENTS = frozenset({"pull_request", "pull_request_target", "pull_request_review",
                                         "pull_request_review_comment"})


def is_self_hosted_label(label) -> bool:
    """Whether a runner label names a self-hosted runner: `self-hosted` in any letter case, with any
    space around it, also as one word of a label written with spaces or commas in it, or a runner
    group. Fails closed: a label GitHub might read differently is taken for the self-hosted one."""
    text = str(label).strip().lower()
    return text.startswith("group:") or "self-hosted" in re.split(r"[\s,]+", text)


def is_hosted_label(label) -> bool:
    return str(label).lower() in HOSTED_LABELS


def _group_text(value) -> str:
    """A `runs-on` group's name as a YAML value (`null`, `false`, `''`), not as Python prints it
    (flagship slice 2d.9). The text is in findings and their facts, which acceptances match."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value if value else "''"
    if isinstance(value, (int, float)):
        return str(value)
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):     # keys of mixed types, a circular alias
        return str(value)
# A plain value that YAML 1.2's core schema reads as null, true or false, or a number, where this
# reader (YAML 1.1) may keep it as text: `0o0`, `0e0`, `.5`.
_YAML12_SCALAR_RE = re.compile(r"~|null|Null|NULL|true|True|TRUE|false|False|FALSE"
                               r"|[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+"
                               r"|[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
                               r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")
# Step forms that hold no run or uses of their own (background steps, NGA features on GitHub.com).
CONTROL_STEP_KEYS = {"wait", "wait-all", "cancel"}


_LOUD_STATUS_RE = re.compile(r"(always|failure|cancelled)\s*\(", re.I)
_SUCCESS_RE = re.compile(r"success\s*\(", re.I)


def runs_after_failure(cond) -> bool:
    """Whether an `if:` can let a step or job run although an earlier step, or a job it needs,
    failed or was skipped.

    Without a status function GitHub adds an implicit `success() &&`, and the answer is no. The
    answer is yes when `always(`, `failure(` or `cancelled(` appears anywhere in the text, inside a
    string or outside `${{ }}` included: where the text is not what its tokens look like, a status
    function is taken for the worst. `success()` keeps the implicit meaning only when the text is
    one expression and every `success(` in it is a call that is itself one of the conditions joined
    by `&&` at the top (`success() && x`). Anywhere else (`success() || x`, `!success()`,
    `success() == false`, as an argument, inside a string, beside text outside `${{ }}`) the job or
    step is taken to run regardless.
    """
    text = str(cond or "")
    if _LOUD_STATUS_RE.search(text):
        return True
    written = len(_SUCCESS_RE.findall(text))
    if not written:
        return False
    try:
        body = condition_expression(text)
    except (expr_mod.TooComplex, RecursionError):
        return True
    if body is None or body.count("'") % 2:
        return True         # not one expression, or one that ends inside a string
    toks = expr_mod.tokens(body)
    if not _balanced(toks):
        return True
    close = expr_mod._closers(toks)
    lo, hi = _unwrapped(toks, close, 0, len(toks))
    if len(_split(toks, close, lo, hi, "|")) > 1:
        return True
    plain = 0
    for a, b in _split(toks, close, lo, hi, "&"):
        a, b = _unwrapped(toks, close, a, b)
        if b - a == 3 and toks[a][0] == "id" and toks[a][1].lower() == "success" \
                and toks[a + 1:b] == [("op", "("), ("op", ")")]:
            plain += 1
    # Every `success(` the text holds must be one of those calls. One more, in a string or anywhere
    # else, and the condition is not the plain form.
    return plain != written


def _unwrapped(toks: list, close: list, lo: int, hi: int) -> tuple[int, int]:
    """toks[lo:hi] without parentheses that enclose all of it, which change nothing."""
    while hi - lo >= 2 and toks[lo] == ("op", "(") and close[lo] == hi - 1:
        lo, hi = lo + 1, hi - 1
    return lo, hi


# Event fields an outsider can write (OBAAF-GHA-010). Matched inside ${{ }}.
UNTRUSTED_FIELDS = [
    r"github\.event\.(issue|pull_request|discussion)\.(title|body)\b",
    r"github\.event\.(comment|review|review_comment)\.body\b",
    r"github\.event\.pull_request\.head\.(ref|label)\b",
    r"github\.event\.pull_request\.head\.repo\.(name|full_name|description|homepage|default_branch)\b",
    r"github\.event\.(head_commit|commits(\[[^\]]*\]|\.\*)?)\.(message|author\.(name|email)|committer\.(name|email))\b",
    r"github\.event\.workflow_run\.(head_branch|display_title)\b",
    r"github\.event\.workflow_run\.head_commit\.(message|author\.(name|email))\b",
    r"github\.event\.pages(\[[^\]]*\]|\.\*)?\.(page_name|title|summary)\b",
    r"github\.head_ref\b",
]
UNTRUSTED_FIELDS_RE = re.compile("|".join(f"(?:{p})" for p in UNTRUSTED_FIELDS))

# The same fields as paths, one accepted set of names per segment (None accepts anything, for an
# array index). Used for the spellings a text pattern cannot follow: `github.event.*.title`,
# `github.event.issue.*`, `github.event[inputs.kind].body` (see expr.reaches).
_TEXT, _WHO, _IDENTITY = {"title", "body"}, {"author", "committer"}, {"name", "email"}
UNTRUSTED_PATHS = [
    ({"github"}, {"event"}, {"issue", "pull_request", "discussion"}, _TEXT),
    ({"github"}, {"event"}, {"comment", "review", "review_comment"}, {"body"}),
    ({"github"}, {"event"}, {"pull_request"}, {"head"}, {"ref", "label"}),
    ({"github"}, {"event"}, {"pull_request"}, {"head"}, {"repo"},
     {"name", "full_name", "description", "homepage", "default_branch"}),
    ({"github"}, {"event"}, {"head_commit"}, {"message"}),
    ({"github"}, {"event"}, {"head_commit"}, _WHO, _IDENTITY),
    ({"github"}, {"event"}, {"commits"}, None, {"message"}),
    ({"github"}, {"event"}, {"commits"}, None, _WHO, _IDENTITY),
    ({"github"}, {"event"}, {"workflow_run"}, {"head_branch", "display_title"}),
    ({"github"}, {"event"}, {"workflow_run"}, {"head_commit"}, {"message"}),
    ({"github"}, {"event"}, {"workflow_run"}, {"head_commit"}, {"author"}, _IDENTITY),
    ({"github"}, {"event"}, {"pages"}, None, {"page_name", "title", "summary"}),
    ({"github"}, {"head_ref"}),
    # Added by flagship slice 2d.2d, from a reviewer's attempts on OBAAF-GHA-010:
    # what an `edited` event says the title, body or base branch was before (`changes.title.from`);
    ({"github"}, {"event"}, {"changes"}, _TEXT, {"from"}),
    # a review comment's file path and diff hunk, which the pull request's files decide;
    ({"github"}, {"event"}, {"comment"}, {"path", "diff_hunk"}),
    # the committer of a commit, which its author writes like the author's own name and e-mail;
    ({"github"}, {"event"}, {"workflow_run"}, {"head_commit"}, {"committer"}, _IDENTITY),
    # the files a pushed commit adds, removes or changes, whose names its author picks;
    ({"github"}, {"event"}, {"head_commit"}, {"added", "removed", "modified"}),
    ({"github"}, {"event"}, {"head_commit"}, {"added", "removed", "modified"}, None),
    ({"github"}, {"event"}, {"commits"}, None, {"added", "removed", "modified"}),
    ({"github"}, {"event"}, {"commits"}, None, {"added", "removed", "modified"}, None),
    # the answer that marked a discussion answered;
    ({"github"}, {"event"}, {"answer"}, {"body"}),
    # the fork a run came from (`workflow_run.head_repository`), and the branches of its pull requests.
    ({"github"}, {"event"}, {"workflow_run"}, {"head_repository"},
     {"name", "full_name", "description", "homepage", "default_branch"}),
    ({"github"}, {"event"}, {"workflow_run"}, {"pull_requests"}, None, {"head"}, {"ref"}),
    # From the second reviewer of 2d.2d: a merge group's commit (its message holds the queued pull
    # requests' titles), an issue or discussion transferred here (`changes.new_issue`), the fork made
    # by a `fork` event, the path of the workflow a run came from (a fork's pull request can add one),
    # and the commits and branches `check_suite`, `check_run` and `status` events carry.
    ({"github"}, {"event"}, {"merge_group"}, {"head_commit"}, {"message"}),
    ({"github"}, {"event"}, {"merge_group"}, {"head_commit"}, _WHO, _IDENTITY),
    ({"github"}, {"event"}, {"merge_group"}, {"head_ref"}),
    ({"github"}, {"event"}, {"changes"}, {"new_issue", "new_discussion"}, _TEXT),
    ({"github"}, {"event"}, {"forkee"}, {"name", "full_name", "description", "homepage", "default_branch"}),
    ({"github"}, {"event"}, {"workflow_run"}, {"path"}),
    ({"github"}, {"event"}, {"check_suite"}, {"head_branch"}),
    ({"github"}, {"event"}, {"check_suite"}, {"head_commit"}, {"message"}),
    ({"github"}, {"event"}, {"check_suite"}, {"head_commit"}, _WHO, _IDENTITY),
    ({"github"}, {"event"}, {"check_run"}, {"check_suite"}, {"head_branch"}),
    ({"github"}, {"event"}, {"commit"}, {"commit"}, {"message"}),          # a `status` event's commit
    ({"github"}, {"event"}, {"commit"}, {"commit"}, _WHO, _IDENTITY),
    ({"github"}, {"event"}, {"branches"}, None, {"name"}),
]

# A pull request's code (OBAAF-GHA-002, OBAAF-GHA-012), as context references (flagship slice 2d.2c).
# Each is read with the expression reader, so letter case, index syntax, `format`, `join`, `fromJSON` and
# `toJSON` do not hide it, and a value given through `env` is followed to where it is set.
#
# What names the pull request's head commit, branch or repository. Under `head.repo` and
# `head_repository` everything but the few fields below names the fork (its name, owner, clone URLs).
_HEAD_REPO_FLAGS = {"fork", "private", "id", "node_id", "visibility", "archived", "disabled", "is_template"}
# What names a pull request by number (from which `refs/pull/N/head` is built) or its patch.
_PR_NUMBER_PATHS = [
    ("github", "event", "number"), ("github", "event", "pull_request", "number"),
    ("github", "event", "issue", "number"), ("github", "event", "pull_request", "patch_url"),
    ("github", "event", "pull_request", "diff_url"), ("github", "event", "pull_request", "url"),
    ("github", "event", "pull_request", "html_url"),
]
# References that name the base repository's own code, never the pull request's, in the events
# OBAAF-GHA-002 is about: on pull_request_target, workflow_run and the comment and review events,
# `github.sha` and `github.ref` are the base branch's (on pull_request they are the merge commit,
# which OBAAF-GHA-012 treats separately).
BASE_CODE_REFS = frozenset({
    "github.sha", "github.ref", "github.ref_name", "github.base_ref", "github.repository", "github.workflow_sha",
    "github.repository_owner", "github.event.repository.full_name", "github.event.repository.name",
    "github.event.repository.default_branch", "github.event.pull_request.base.sha",
    "github.event.pull_request.base.ref", "github.event.pull_request.base.repo.full_name",
    "github.event.pull_request.base.repo.name", "github.event.pull_request.base.repo.clone_url",
    "github.event.pull_request.base.label", "github.event.repository.owner.login",
    "github.event.repository.clone_url", "github.event.workflow_run.repository.full_name",
    "github.event.workflow_run.repository.default_branch",
})
# The references that are the merge commit when the event is a pull request's own (OBAAF-GHA-012).
MERGE_COMMIT_REFS = frozenset({"github.sha", "github.ref", "github.ref_name"})
# Events whose default checkout, and whose `github.sha` and `github.ref`, are the pull request's
# merge commit (refs/pull/N/merge).
MERGE_REF_EVENTS = frozenset({"pull_request", "pull_request_review", "pull_request_review_comment"})
# Text in a value or a script that names a pull request's code without an expression.
PR_CODE_TEXT_RE = re.compile(
    r"refs/pull/|(?<![\w-])pull/[^\s/'\"]+/(head|merge)\b|/pull/[^\s/'\"]+\.(patch|diff)\b", re.I)
# The same in a script: pull request fields read from the event file, the GitHub CLI or the API, and
# the runner's own variable for the head branch.
PR_CODE_SCRIPT_RE = re.compile(
    r"pull_request\s*\.\s*head\b|pull_request['\"]?\s*\]\s*\[\s*['\"]head|\.head\s*\.\s*(sha|ref)\b|"
    r"\bhead[_.]?(sha|ref)\b|\bheadRef(Oid|Name)\b|\bheadRepository(Owner)?\b|\bGITHUB_HEAD_REF\b|"
    r"\bmerge_commit_sha\b|(?<![\w.-])gh['\"]?\s+pr\s+diff\b", re.I)
# The subcommands of git that bring code into the workspace or read it from a ref.
GIT_CODE_COMMANDS = frozenset({
    "fetch", "pull", "clone", "checkout", "switch", "reset", "worktree", "merge", "rebase", "cherry-pick", "show",
    "apply", "am", "restore", "read-tree", "archive", "submodule", "cat-file",
})
# git's global options that take a value as the next word (`-C DIR`); `--opt=value` is one word.
_GIT_VALUE_OPTIONS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
                                "--config-env", "--exec-path", "--list-cmds", "--attr-source"})
_GH_VALUE_OPTIONS = frozenset({"-R", "--repo", "--hostname"})
# Downloads count when the line fetches an archive, the contents API, raw files or a diff or patch.
_FETCHED_RE = re.compile(r"tarball|zipball|/archive/|/contents/|codeload\.|raw\.githubusercontent|\.(diff|patch)\b|"
                         r"vnd\.github(\.v3)?\.(diff|patch|raw)|/git/(blobs|trees)|patch_url|diff_url", re.I)
_DOWNLOADERS = frozenset({"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm"})
_SCRIPT_API_RE = re.compile(r"\b(getContent|downloadTarballArchive|downloadZipballArchive|getArchive)\b|"
                            r"format\s*:\s*['\"](diff|patch)['\"]", re.I)
# A command written as an argument list (`['git', 'fetch', ...]`, `exec.exec('git', ['fetch', ...])`), for
# scripts in other languages. The quotes are required, so the pattern cannot backtrack.
_GIT_LIST_RE = re.compile(r"(?<![\w.-])['\"]git(?:\.exe)?['\"]\s*,\s*\[?\s*['\"](" +
                          "|".join(re.escape(c) for c in sorted(GIT_CODE_COMMANDS)) + r")['\"]", re.I)
def _names_pr_code(path: tuple, extracted: bool, numbers: bool) -> bool:
    """Whether a context reference names a pull request's code: its head commit, branch or
    repository, its merge commit, or (with `numbers`) its number or patch. A reference to an object
    that holds one of these counts when something can turn the object into text (`extracted`, a
    wildcard or a computed index); so does a wildcard or computed segment where a name is expected."""
    names = [s.value.lower() if s.kind == expr_mod.NAME else None for s in path]
    loose = extracted or any(n is None for n in names)

    def at(i: int, *accepted: str) -> bool:
        return i < len(names) and (names[i] is None or names[i] in accepted)

    def shorter(i: int) -> bool:          # the reference stops before position i: an object
        return len(names) <= i and loose

    if not at(0, "github"):
        return False
    if len(names) == 1:
        return loose
    if at(1, "head_ref"):
        return True
    if not at(1, "event"):
        return False
    if shorter(2):
        return True
    if at(2, "pull_request"):
        if shorter(3):
            return True
        if at(3, "merge_commit_sha"):
            return True
        if at(3, "head"):
            if shorter(4) or at(4, "sha", "ref", "label", "user"):
                return True
            if at(4, "repo"):
                return shorter(5) or (len(names) > 5 and (names[5] is None or names[5] not in _HEAD_REPO_FLAGS))
            return False
    if at(2, "workflow_run"):
        if shorter(3) or at(3, "head_sha", "head_branch", "head_commit", "pull_requests"):
            return True
        if at(3, "head_repository"):
            return shorter(4) or (len(names) > 4 and (names[4] is None or names[4] not in _HEAD_REPO_FLAGS))
    if at(2, "issue") and (shorter(3) or at(3, "pull_request")):
        return True
    # On a pull request's `synchronize`, `after` is its new head commit; a review and a review comment
    # name the head commit they are about.
    if at(2, "after") or (at(2, "review", "comment") and at(3, "commit_id")):
        return True
    if numbers:
        for wanted in _PR_NUMBER_PATHS:
            if len(names) == len(wanted) and all(n is None or n == w for n, w in zip(names, wanted)):
                return True
    return False


@dataclass
class PrCode:
    """What a value says about a pull request's code: "head" when it names it, "unresolved" when it
    is an expression the checker cannot read to a value (a step's or job's output, an input, a
    variable, an `env` name set nowhere in the file, a reference to anything else), "base" when it
    names only the base repository's code or nothing computed at all. `reads` are the references
    behind the answer (for "base", the base references read)."""

    state: str
    reads: list[str] = field(default_factory=list)


_HEAD, _UNRESOLVED, _BASE = "head", "unresolved", "base"
_NOT_SET = object()


class Env:
    """The env a value can read: mappings from the innermost (a step's) to the outermost (the
    workflow's). A value set in one of them reads only the ones outside it, as GitHub evaluates them,
    so a step's `REF: ${{ env.REF }}` reads the job's REF."""

    def __init__(self, *scopes: Any) -> None:
        self.scopes = [scope if isinstance(scope, dict) else {} for scope in scopes]
        self.names = sorted({str(key) for scope in self.scopes for key in scope})

    def find(self, name: str, start: int = 0, exact: bool = False) -> tuple[Any, int]:
        """The value of `name` in the first scope from `start` that sets it, and that scope's index.
        `${{ env.NAME }}` matches names without regard to case; a shell's `$NAME` (`exact`) does not."""
        wanted = name if exact else name.lower()
        for level in range(start, len(self.scopes)):
            for key, given in self.scopes[level].items():
                if (str(key) if exact else str(key).lower()) == wanted:
                    return given, level
        return _NOT_SET, len(self.scopes)


def env_lookup(*scopes: Any) -> Env:
    return Env(*scopes)


def pr_code(value: Any, env: "Env | None" = None, numbers: bool = True, runtime_only: bool = False,
            start: int = 0, _cache: dict | None = None, _stack: frozenset = frozenset()) -> PrCode:
    """Read a value (a checkout's `ref` or `repository`, or part of a script) for a pull request's
    code. `env` is the env the value can read, from scope `start` outward (None: it cannot read env).
    With `runtime_only` (for scripts, which read many values that name no code), only step and job
    outputs and fields an outsider writes are unresolved, and other references count as nothing.
    Each env name is read once however many values read it, so the time is linear in the env's size."""
    head: set[str] = set()
    unresolved: set[str] = set()
    base: set[str] = set()
    if not isinstance(value, (str, int, float, bool)) and value is not None:
        return PrCode(_UNRESOLVED, ["a value that is not text"])
    text = value if isinstance(value, str) else ""
    if PR_CODE_TEXT_RE.search(text):
        head.add("refs/pull/")
    try:
        bodies = list(expressions(text))
    except expr_mod.TooComplex:
        return PrCode(_UNRESOLVED, ["an expression too complex to read"])
    cache = {} if _cache is None else _cache
    for body in bodies:
        try:
            found = expr_mod.refs(body)
        except (expr_mod.TooComplex, RecursionError):
            unresolved.add("an expression too complex to read")
            continue
        for ref in found:
            shown = expr_mod.dotted(ref.path)
            first = ref.path[0].value.lower() if ref.path[0].kind == expr_mod.NAME else ""
            if _names_pr_code(ref.path, ref.extracted, numbers):
                head.add(shown)
            elif first == "env" and len(ref.path) > 1 and ref.path[1].kind == expr_mod.NAME and env is not None:
                given, level = env.find(ref.path[1].value, start)
                key = (ref.path[1].value.lower(), start)
                if given is _NOT_SET:
                    if not runtime_only:
                        unresolved.add(shown)
                    continue
                if key in _stack:
                    continue                    # a loop: GitHub cannot evaluate it either
                if key not in cache:
                    cache[key] = pr_code(given, env, numbers, runtime_only, level + 1, cache, _stack | {key})
                inner = cache[key]
                target = head if inner.state == _HEAD else unresolved if inner.state == _UNRESOLVED else base
                target.update(inner.reads or [shown])
            elif shown in BASE_CODE_REFS:
                base.add(shown)
            elif runtime_only:
                if first in ("steps", "needs") or any(
                        expr_mod.reaches(ref.path, pattern, ref.extracted) for pattern in UNTRUSTED_PATHS):
                    unresolved.add(shown)
            else:
                unresolved.add(shown)
    if head:
        return PrCode(_HEAD, sorted(head))
    if unresolved:
        return PrCode(_UNRESOLVED, sorted(unresolved))
    return PrCode(_BASE, sorted(base))


def script_lines(text: str, powershell: bool = False) -> list[str]:
    """A script's logical lines: a line ended by a backslash (or, in PowerShell, a backquote) is
    joined to the next."""
    joined = re.sub(r"[\\`][ \t]*\r?\n" if powershell else r"\\[ \t]*\r?\n", " ", text)
    return joined.splitlines()


def _sub_expressions(text: str, replace: "Callable[[str], str]") -> str:
    """`text` with each `${{ ... }}` (to the first `}}`) replaced by `replace(expression)`, in one pass:
    an expression with no end is left as it is."""
    out, pos = [], 0
    while True:
        begin = text.find("${{", pos)
        end = text.find("}}", begin + 3) if begin != -1 else -1
        if end == -1:
            out.append(text[pos:])
            return "".join(out)
        out.append(text[pos:begin])
        out.append(replace(text[begin:end + 2]))
        pos = end + 2


_PLACEHOLDER_RE = re.compile(r"\x00(\d+)\x00")
_SEPARATORS = frozenset({";", "&&", "||", "&", ";;", "\n"})
# How a script reads a variable: `$NAME`, `${NAME...}`, PowerShell's `$env:NAME`, cmd's `%NAME%`,
# Node's `process.env.NAME`, Python's `os.environ['NAME']`, `os.environ.get('NAME')`, `getenv('NAME')`.
_VARIABLE_RE = re.compile(
    r"\$\{?#?!?([A-Za-z_]\w*)|\$env:([A-Za-z_]\w*)|%([A-Za-z_]\w*)%|process\.env\.([A-Za-z_]\w*)|"
    r"os\.environ(?:\.get)?\s*[\[(]\s*['\"]([A-Za-z_]\w*)|getenv\s*\(\s*['\"]([A-Za-z_]\w*)", re.I)
# Where a script sets a variable: `NAME=...` at the start of a command (after `export`, `local`,
# `declare -x` and the like, or `const` and `let` in a script language), `read [-r] NAME`, `for NAME in`,
# `mapfile NAME`, `readarray NAME`.
_ASSIGN_RE = re.compile(
    r"(?:^|[;&|({]\s*|\b(?:export|local|readonly|typeset|declare|const|let|var|set)\s+(?:-\w+\s+)*)"
    r"\$?([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*:?\+?=\s*")
_READ_RE = re.compile(r"\b(?:read|mapfile|readarray)\s+(?:-\w+\s+(?:[^\s-]\S*\s+)?)*([A-Za-z_]\w*)|\bfor\s+([A-Za-z_]\w*)\s+in\b")
# A file a line writes: `> FILE`, `>> FILE`, `-o FILE`, `--output FILE`, `tee FILE`, `-OutFile FILE`.
_WRITES_RE = re.compile(r"(?:>>?|(?<![\w-])-o|--output(?:=|\s)|\btee(?:\s+-a)?|-OutFile)\s*['\"]?([^\s'\";&|<>]+)", re.I)
_PATH_WORD_RE = re.compile(r"[^\s'\"`;&|<>(){}\[\],+]+")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")
# Words after which a command starts (`a | git ...`, `then git ...`).
_COMMAND_STARTS = frozenset({"|", "|&", "(", ")", "{", "!", "then", "do", "else", "elif", "if", "while", "until"})
# Commands that run the command after them, with the options of theirs that take a value as the next word;
# for `timeout`, the duration is a word of its own too (`sudo -u runner git ...`, `timeout 300 git ...`).
_RUNNERS = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-R", "-T"}, "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir"}, "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "nice": {"-n", "--adjustment"}, "ionice": {"-c", "-n", "-t"}, "nohup": set(), "stdbuf": {"-i", "-o", "-e"},
    "xargs": {"-n", "-I", "-L", "-P", "-s", "-a", "-d", "-E", "--max-args", "--replace", "--delimiter"},
    "time": {"-f", "-o", "--format", "--output"}, "command": set(), "builtin": set(), "exec": {"-a"}, "chronic": set(), "unbuffer": set(),
    "runuser": {"-u", "-g"}, "setsid": set(), "flock": {"-w", "-E"}, "retry": {"-t", "--times", "-d", "--delay"},
}
# Runners whose first word after their options is theirs, not the command's: a duration or a count
# (`timeout 300`, `retry 3`), or a lock file (`flock /tmp/x.lock`).
_TAKES_NUMBER = frozenset({"timeout", "retry"})
_TAKES_WORD = frozenset({"flock"})
# `docker exec [options] CONTAINER COMMAND`: the options of `docker exec` that take a value.
_DOCKER_EXEC_OPTIONS = frozenset({"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "--detach-keys"})
# Shells and the option that hands them a script: a quoted script after it is read again.
_SCRIPT_OPTION_RE = re.compile(r"-[a-zA-Z]*c\Z")


def _strip_comment(line: str) -> str:
    """The line up to a `#` that starts a shell comment: at the start of a word and outside quotes."""
    quote, escaped, previous = "", False, " "
    for i, ch in enumerate(line):
        if escaped:
            escaped, previous = False, ch
            continue
        if ch == "\\" and quote != "'":
            escaped, previous = True, ch
            continue
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (previous.isspace() or previous in ";&|("):
            return line[:i]
        previous = ch
    return line


def _shell_words(line: str) -> list[str] | None:
    """A line split as a POSIX shell splits it, operators as words of their own. None when the line
    cannot be split (an unclosed quote)."""
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return None


def _commands(words: list[str]) -> list[list[str]]:
    """The commands of a split line: runs of words between `;`, `&&`, `||` and `&`. A pipeline stays
    one command, so `gh pr diff N | git apply` is read together."""
    out, current = [], []
    for word in words:
        if word in _SEPARATORS:
            if current:
                out.append(current)
            current = []
        else:
            current.append(word)
    if current:
        out.append(current)
    return out


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()


_CREATE_FLAGS = frozenset({"-c", "-C", "-b", "-B", "--create", "--force-create", "--orphan"})


def _command_name(word: str) -> str:
    """The name of the command a word starts: its base name, after a `NAME=` assignment, a backquote
    or `$(` that open it (`` OUT=`git ``)."""
    head, sep, tail = word.partition("=")
    if sep and _IDENTIFIER_RE.fullmatch(head):
        word = tail
    return _base(word.lstrip("`$("))


def _command_positions(words: list[str]) -> set[int]:
    """Where a command's name stands among a command's words: the first word, the word after `|`, `(`,
    `then` and the like, after `NAME=value` words, and after a command that runs the next one (`sudo`,
    `env`, `timeout 300`, `xargs -r`) and its options; and any word a backquote or `$(` opens."""
    positions, expecting, i = set(), True, 0
    while i < len(words):
        word = words[i]
        if word.startswith(("`", "$(")) and len(word) > 2:
            positions.add(i)
        if not expecting:
            expecting = word in _COMMAND_STARTS
            i += 1
            continue
        if word in _COMMAND_STARTS:
            i += 1
            continue
        head, sep, _ = word.partition("=")
        if sep and _IDENTIFIER_RE.fullmatch(head) and "`" not in word and "$(" not in word:
            i += 1                                   # an assignment before the command
            continue
        name = _command_name(word)
        positions.add(i)
        if name in _RUNNERS:
            options, i = _RUNNERS[name], i + 1
            while i < len(words) and (words[i].startswith("-") or (name == "env" and "=" in words[i])):
                i += 2 if words[i] in options else 1
            if (name in _TAKES_NUMBER and i < len(words) and words[i][:1].isdigit()) or (
                    name in _TAKES_WORD and i < len(words) and words[i] not in _COMMAND_STARTS):
                i += 1
            continue                                 # still expecting the command it runs
        if name in ("docker", "podman") and i + 1 < len(words) and words[i + 1] == "exec":
            i += 2
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in _DOCKER_EXEC_OPTIONS else 1
            i += 1                                   # the container
            continue
        expecting = False
        i += 1
    return positions


def _fetching(words: list[str], anywhere: bool = False) -> tuple[str | None, set[int]]:
    """What brings code in among a command's words, if anything ("git SUBCOMMAND", "gh pr checkout",
    which needs nothing else to be the pull request's code, "patch", "gh repo clone", "gh api", or a
    downloader), and the words not to read for what it brings in: the name of a branch that `git
    switch -c NAME` or `git checkout -b NAME` creates, which names nothing fetched. A name counts only
    where a command starts (see `_command_positions`), unless `anywhere` (for a script in another
    language, split roughly), where `patch` is not looked for: it is a word of HTTP and of APIs."""
    found, skip = None, set()
    positions = range(len(words)) if anywhere else _command_positions(words)
    for i in sorted(positions):
        word = words[i]
        name = _command_name(word)
        if name in ("git", "git.exe"):
            j = i + 1
            while j < len(words) and words[j].startswith("-"):
                j += 2 if words[j] in _GIT_VALUE_OPTIONS else 1
            if j < len(words) and words[j].lower() in GIT_CODE_COMMANDS:
                sub = words[j].lower()
                if sub in ("switch", "checkout"):
                    rest = range(j + 1, len(words))
                    created = {k + 1 for k in rest if words[k] in _CREATE_FLAGS and k + 1 < len(words)}
                    if created:
                        skip |= created
                        starts = [k for k in rest if k not in skip and not words[k].startswith("-")
                                  and words[k] not in ("|", "<", ">", "(", ")")]
                        if not starts:
                            continue        # a new branch at the current commit brings nothing in
                return f"git {sub}", skip
        elif name in ("gh", "gh.exe"):
            subs, j = [], i + 1
            while j < len(words) and len(subs) < 2 and words[j] not in ("|", "(", ")", "<", ">"):
                if words[j].startswith("-"):
                    j += 2 if words[j] in _GH_VALUE_OPTIONS else 1
                    continue
                subs.append(words[j].lower())
                j += 1
            if subs[:1] == ["pr"] and subs[1:2] in (["checkout"], ["co"]):
                return "gh pr checkout", skip
            if subs == ["repo", "clone"]:
                found = found or "gh repo clone"
            if subs[:1] == ["api"]:
                found = found or "gh api"
        elif name == "patch" and not anywhere:
            return "patch", skip
        elif name in _DOWNLOADERS:
            found = found or name
    return found, skip


# Flagship slice 2d.2e: which commands of a script stop it when they fail. The reader is strict and
# fails closed: it does not try to follow what bash would do with anything unusual, it stops counting.
_ASSIGN_WORD_RE = re.compile(r"[A-Za-z_]\w*(\[[^\]]*\])?\+?=")
_OPERATORS = ("<<<", "<<-", "&&", "||", ";;", "|&", ">>", "<<", ">&", "<&", "&>", ";", "&", "|", "(", ")", "<", ">")
_REDIRECTS = frozenset({">", ">>", "<", ">&", "<&", "&>", "<<<"})
_MASK = dict(zip(";&|()<>", ""))
_UNMASK = {v: k for k, v in _MASK.items()}
# What may not come before a check, anywhere in the script, outside quotes: a way to leave the script,
# to run text as commands, to change what a name runs, or to turn errexit off.
_DENIED_RE = re.compile(r"(?<![\w./-])(exit|return|eval|exec|trap|builtin|command|source|shopt|alias|unalias|hash|"
                        r"enable|unset|declare|typeset|readonly|coproc|function|case|esac|logout)(?![\w./-])")
_DOT_COMMAND_RE = re.compile(r"(^|[;&|(){}!]|\b(?:then|do|else|elif)\b)\s*\.(\s|$)")
_FUNCTION_RE = re.compile(r"[^\s;&|(){}=]+\s*\(\s*\)")
_EXPANDED_NAME_RE = re.compile(r"(^|[;&|(){}!]|\b(?:then|do|else|elif|if|while|until)\b)\s*"
                               r"(?:[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=[^\s(]*\s+)*[\"']?[$`\\]")
_SHELL_STATE_RE = re.compile(r"(?<![\w])(PATH|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|BASH_FUNC\w*|GITHUB_PATH)\+?=")
_ODD_CHARS_RE = re.compile("[\r\v\f\x00-\x08\x0e-\x1f\x7f\x85  ]")
_SET_OPTIONS = frozenset({"errexit", "pipefail", "nounset", "xtrace"})
_EXIT_CODE_RE = re.compile(r"(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])")
_OPENERS = frozenset({"if", "while", "until", "for", "select", "{"})
_CLOSERS = frozenset({"fi", "done", "}"})
_COMMAND_STARTERS = frozenset({";", "&&", "||", "|", "|&", "&", "!", "(", "{", "then", "do", "else", "elif", "if",
                               "while", "until"})
UNKNOWN_EXPRESSION = "OBAAF_UNKNOWN_EXPRESSION"


def _script_tokens(line: str) -> list[tuple[str, bool]] | None:
    """A line split as a POSIX shell splits it, each operator a word of its own, with whether any part
    of the word was quoted or escaped (a quoted `fi` is no keyword, a quoted `;` no operator). None
    when the line cannot be split (an unclosed quote)."""
    masked, marks, quote, escaped = [], [], "", False
    for ch in line:
        if escaped:
            masked.append(_MASK.get(ch, ch))
            marks.append(True)
            escaped = False
            continue
        if ch == "\\" and quote != "'":
            escaped = True
            masked.append(ch)
            marks.append(True)
            continue
        if quote:
            if ch == quote:
                quote = ""
            masked.append(_MASK.get(ch, ch) if ch != quote else ch)
            marks.append(True)
            continue
        if ch in "'\"":
            quote = ch
            masked.append(ch)
            marks.append(True)
            continue
        masked.append(ch)
        marks.append(False)
    if quote:
        return None
    try:
        lex = shlex.shlex("".join(masked), posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        words = list(lex)
    except ValueError:
        return None
    # Whether a word was quoted: it holds a mask character, or its text differs from the raw line's
    # characters (quotes or a backslash were taken out). Found by searching the raw text in order.
    out: list[tuple[str, bool]] = []
    raw = "".join(masked)
    at = 0
    for word in words:
        if word and all(ch in ";&|()<>" for ch in word):
            at = raw.find(word, at) + len(word) if raw.find(word, at) >= 0 else at
            while word:
                op = next(o for o in _OPERATORS if word.startswith(o))
                out.append((op, False))
                word = word[len(op):]
            continue
        found = raw.find(word, at)
        quoted = found < 0 or any(marks[found:found + len(word)])
        if found >= 0:
            at = found + len(word)
        text = "".join(_UNMASK.get(ch, ch) for ch in word)
        out.append((text, quoted or text != word))
    return out


def _unquoted(line: str) -> str:
    """The line with every quoted part blanked out, for searching what the shell reads as words."""
    out, quote, escaped = [], "", False
    for ch in line:
        if escaped:
            out.append(" ")
            escaped = False
        elif ch == "\\" and quote != "'":
            out.append(" ")
            escaped = True
        elif quote:
            if ch == quote:
                quote = ""
            out.append(" ")
        elif ch in "'\"":
            quote = ch
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


_RESERVED = frozenset({"if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do",
                       "done", "in", "function", "time", "coproc", "{", "}", "!"})
# Names a line before a check may not run: a way to leave the script, to run text as commands, to change
# what a name runs or how the shell behaves, or to read text into a variable that changes it.
_DENIED_NAMES = frozenset({"exit", "return", "exec", "eval", "source", ".", "builtin", "command", "trap", "shopt",
                           "alias", "unalias", "hash", "enable", "unset", "declare", "typeset", "readonly", "local",
                           "mapfile", "readarray", "logout", "set", "ulimit", "kill", "suspend", "wait", "fg", "bg",
                           "disown", "getopts", "let", "printf", "read", "export", "cd", "pushd", "popd", "time",
                           "shift"})
# Variables that change what a name runs or how the shell starts.
_SHELL_VARIABLE_RE = re.compile(r"(PATH|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|BASH_FUNC\w*|GITHUB_PATH)(\+?=|$)")


# Anywhere in a word before a check (flagship slice 2d.2e, third review): a name of the shell's own state
# that changes what a name runs (read or written: `BASH_CMDS[obaaf]=`, `$((PATH=5))`), an assignment to a
# variable an interpreter reads at start (`PYTHONPATH=`, `LD_PRELOAD=`), an arithmetic expansion, or a
# `${NAME=...}` or `${NAME:=...}`, which assigns in the current shell even inside quotes.
_SHELL_STATE_ANYWHERE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(PATH|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|BASH_FUNC\w*|GITHUB_PATH|BASH_CMDS|BASH_ALIASES|EXECIGNORE)"
    r"(?![A-Za-z0-9_])"
    r"|(?<![A-Za-z0-9_])(PS4|PROMPT_COMMAND|PYTHON\w*|LD_\w*|NODE_OPTIONS|PERL5OPT|PERL5LIB|RUBYOPT|JAVA_TOOL_OPTIONS)\+?="
    r"|\$\(\(|\(\(|\$\[|\$\{[#!]?[A-Za-z_]\w*(\[[^\]]*\])?:?="
    # Arithmetic a variable's value can carry (fourth review): an array subscript other than `@` or `*`, a
    # substring offset, an indirect expansion, and `[[`, each of which evaluates text as arithmetic.
    r"|\$\{#?[A-Za-z_]\w*\[(?![@*]\])|\$\{#?[A-Za-z_]\w*:(?![-+=?])|\$\{!|^\[\[$|^[A-Za-z_]\w*\[")


# Variables bash evaluates as arithmetic when assigned, or that steer the shell (fifth review).
_SPECIAL_VARIABLE_RE = re.compile(
    r"(RANDOM|SRANDOM|OPTIND|OPTERR|SECONDS|LINENO|HISTCMD|TMOUT|COLUMNS|LINES|FUNCNEST|MAILCHECK|GROUPS|DIRSTACK|"
    r"PIPESTATUS|FUNCNAME|BASH\w*|HIST\w*|EPOCH\w*|COMP_\w*|READLINE_\w*)(\[[^\]]*\])?\+?=")
_SIMPLE_NAME = r"[A-Za-z_][A-Za-z0-9_]*"


def _expansions_allowed(word: str) -> bool:
    """Whether every expansion in a word is one that cannot evaluate a value as arithmetic (fifth review:
    an allow-list). Allowed: `$NAME`, a special parameter read (`$1`, `$@`, `$?`), `$(...)` (it runs in a
    subshell, so nothing it does reaches this shell), and `${...}` as `${NAME}`, `${#NAME}`, `${NAME[@]}`,
    `${NAME[*]}`, `${#NAME[@]}`, or `${NAME` followed by `-`, `:-`, `+`, `:+`, `#`, `##`, `%` or `%%` and a
    word whose own expansions are allowed. Anything else (a subscript, an offset, `${!...}`, `$((`, `$[`)
    is not."""
    i = 0
    while True:
        j = word.find("$", i)
        if j < 0:
            return True
        rest = word[j + 1:]
        if rest.startswith("(("):
            return False
        if rest.startswith("("):
            depth, k = 0, j + 1
            while k < len(word):
                if word[k] == "(":
                    depth += 1
                elif word[k] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            if k >= len(word):
                return False
            i = k + 1
            continue
        if rest.startswith("{"):
            depth, k = 0, j + 1
            while k < len(word):
                if word[k] == "{":
                    depth += 1
                elif word[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            if k >= len(word):
                return False
            inner = word[j + 2:k]
            m = re.fullmatch(r"#?(" + _SIMPLE_NAME + r")(\[[@*]\])?", inner)
            if not m:
                m2 = re.match(r"(" + _SIMPLE_NAME + r")(:?[-+]|##?|%%?)", inner)
                if not m2 or not _expansions_allowed(inner[m2.end():]):
                    return False
            i = k + 1
            continue
        if re.match(_SIMPLE_NAME + r"|[0-9@*#?$!-]", rest) or not rest:
            i = j + 1
            continue
        return False


def _assignment(word: str) -> bool:
    return bool(_ASSIGN_WORD_RE.match(word))


def _safe_command(words: list[tuple[str, bool]], allowed: frozenset = frozenset()) -> bool:
    """Whether one simple command may come before a check: assignments to no shell variable, then a
    command named by a plain word (no quote, no expansion) that is not denied (except names in
    `allowed`), with no word naming a shell variable, a reserved word or a substitution that is not
    quoted."""
    if any(_SHELL_STATE_ANYWHERE_RE.search(word) or _SPECIAL_VARIABLE_RE.match(word) or not _expansions_allowed(word)
           for word, _quoted in words):
        return False
    i = 0
    while i < len(words) and _assignment(words[i][0]) and not words[i][0].startswith(("$", "`")):
        word = words[i][0]
        if _SHELL_VARIABLE_RE.match(word) or "`" in word or ("$(" in word and not words[i][1]):
            return False
        if word.endswith("=") and i + 1 < len(words) and words[i + 1][0] == "(":
            j = i + 2
            while j < len(words) and words[j][0] != ")":
                if words[j][0] in _OPERATORS and not words[j][1] or words[j][0].startswith("["):
                    return False
                j += 1
            if j >= len(words):
                return False
            i = j + 1
            continue
        i += 1
    if i >= len(words):
        return True
    name, quoted = words[i]
    if name in ("[", "test") and any(w == "-v" for w, _q in words[i + 1:]):
        return False            # `-v 'a[x]'` evaluates the subscript
    if quoted or not re.fullmatch(r"[A-Za-z0-9_][\w.+-]*|\[|\[\[|:", name) or name in _RESERVED or (
            name in _DENIED_NAMES and name not in allowed):
        return False
    for word, was_quoted in words[i + 1:]:
        if not was_quoted and word in _RESERVED - {"in"}:
            return False
        if _SHELL_VARIABLE_RE.match(word) or "`" in word:
            return False
        if word in ("(", ")") and not was_quoted:
            return False
    return True


def _set_words(words: list[str]) -> tuple[bool, bool] | None:
    """(errexit, pipefail) turned on by `set` with only `-e`, `-u`, `-x` and `-o errexit|pipefail|nounset|xtrace`;
    None for any other `set`."""
    errexit = pipefail = False
    i = 1
    while i < len(words):
        option = words[i]
        if not re.fullmatch(r"-[euxo]+", option):
            return None
        errexit = errexit or "e" in option
        if "o" in option:
            if i + 1 >= len(words) or words[i + 1] not in _SET_OPTIONS:
                return None
            errexit = errexit or words[i + 1] == "errexit"
            pipefail = pipefail or words[i + 1] == "pipefail"
            i += 1
        i += 1
    return errexit, pipefail


def _split_commands(tokens: list[tuple[str, bool]]) -> list[list[tuple[str, bool]]] | None:
    """A line's simple commands, split at `;`, `&&`, `||` and `|`; None when it holds another operator
    (`&`, `(`, `)` outside an array assignment, a here-document) or ends with one that continues it."""
    out, current, i = [], [], 0
    while i < len(tokens):
        word, quoted = tokens[i]
        if not quoted and word in (";", "&&", "||", "|", "|&"):
            if not current:
                return None
            out.append(current)
            current = []
        elif not quoted and word in ("&", ";;", "<<", "<<-"):
            return None
        else:
            current.append((word, quoted))
        i += 1
    if not current:
        return None        # empty, or a line that ends with `;`, `&&`, `||` or `|` and goes on below
    out.append(current)
    return out


def binding_commands(text: str, errexit: bool, pipefail: bool) -> tuple[list[list[str]], bool]:
    """The commands of a POSIX shell script whose failure ends the script with a failure, each as its
    words from the command's name on (flagship slice 2d.2e), and whether the whole script was read.

    The reader accepts only what it can vouch for, and stops at the first line it cannot. A command
    counts when its line is that one command (optionally followed by `|| exit N` with N from 1 to 255,
    `|| exit`, or `|| { plain; commands; exit N; }`, or piped under pipefail), it is not inside a
    compound command, errexit is on (from the shell or a `set -e` line before it), and every line before
    it is one of: simple commands joined by `;`, `&&`, `||` or `|`, each named by a plain word that is not
    a way to leave the script, run text, change what a name runs or how the shell behaves (`exit`,
    `exec`, `eval`, `source`, `.`, `builtin`, `command`, `trap`, `set` other than `-e`, `-u`, `-x`, `-o`,
    `export`, `read`, `printf`, `cd` and the like), assigning no shell variable (`PATH`, `BASH_ENV`,
    `IFS`), with no reserved word, no unquoted `(` or `)` but an array assignment, no `&`, no
    here-document and no expression the checker cannot read; or a line `if ...; then`, `elif ...; then`,
    `while ...; do`, `until ...; do`, `for NAME in ...; do`, `else`, `fi` or `done` whose other words are
    such commands. A line continued with a backslash is joined to the next as bash joins it, after the
    comment is taken off; any other backslash, a line break bash does not see (a carriage return, a form
    feed, U+2028) or `$'...'` ends the reading. `read`, `printf`, `export`, `cd` and `local` are allowed
    inside a loop's body and an `if` only as `read -r NAME` and the like, never naming a shell
    variable."""
    if _ODD_CHARS_RE.search(text) or "$'" in text or '$"' in text:
        return [], False
    physical = text.split("\n")
    lines: list[str] = []
    pending = ""
    for raw_line in physical:
        if "\\" in raw_line.rstrip()[:-1]:
            lines.append(pending + raw_line)       # a backslash other than at the end: reading stops here
            pending = ""
            continue
        line = _strip_comment(raw_line)
        if line.rstrip().endswith("\\") and not line.rstrip().endswith("\\\\"):
            pending += line.rstrip()[:-1]
            continue
        lines.append(pending + line)
        pending = ""
    if pending:
        lines.append(pending)
    out: list[list[str]] = []
    depth = 0
    readers = frozenset({"read", "printf", "export", "cd", "local"})
    for line in lines:
        if not line.strip():
            continue
        if "\\" in line or UNKNOWN_EXPRESSION in line:
            return out, False
        tokens = _script_tokens(line)
        if tokens is None:
            return out, False
        words = [w for w, _q in tokens]
        if depth == 0 and errexit:
            command = _check_line(tokens, pipefail)
            if command is not None:
                out.append(command)
        first = words[0] if not tokens[0][1] else ""
        if first in ("fi", "done") and len(words) == 1:
            if depth == 0:
                return out, False
            depth -= 1
            continue
        if first == "else" and len(words) == 1 and depth > 0:
            continue
        inner = tokens
        if first in ("if", "elif", "while", "until", "for"):
            closer = "then" if first in ("if", "elif") else "do"
            if words[-1] != closer or tokens[-1][1] or len(words) < 3 or words[-2] != ";" or (first == "elif" and depth == 0):
                return out, False
            inner = tokens[1:-2]
            if first == "for":
                if len(inner) < 2 or inner[1][0] != "in" or not re.fullmatch(r"[A-Za-z_]\w*", inner[0][0]) \
                        or _SHELL_VARIABLE_RE.match(inner[0][0] + "="):
                    return out, False
                if any(w in _OPERATORS or w in _RESERVED for w, q in inner[2:] if not q) or any(
                        _SHELL_STATE_ANYWHERE_RE.search(w) for w, _q in inner):
                    return out, False
                inner = []
            if first != "elif":
                depth += 1
        if inner:
            commands = _split_commands(inner)
            if commands is None:
                return out, False
            for command_words in commands:
                plain = [w for w, _q in command_words]
                name_at = next((k for k, w in enumerate(plain) if not _assignment(w)), len(plain))
                name = plain[name_at] if name_at < len(plain) else ""
                if name == "set":
                    change = _set_words(plain[name_at:])
                    if change is None or name_at:
                        return out, False
                    if depth == 0 and first not in ("if", "while", "until", "elif"):
                        errexit = errexit or change[0]
                        pipefail = pipefail or change[1]
                    continue
                if name in readers:
                    if any(_SHELL_VARIABLE_RE.match(w) or "[" in w for w in plain[name_at + 1:]) \
                            or any(w.startswith("-") and set(w[1:]) - set("rasneptd") for w in plain[name_at + 1:]):
                        return out, False
                    if name in ("read", "printf") and any("v" in w[1:] or "C" in w or "u" in w[1:]
                                                          for w in plain[name_at + 1:] if w.startswith("-")):
                        return out, False
                    if not _safe_command(command_words, allowed=readers):
                        return out, False
                    continue
                if not _safe_command(command_words):
                    return out, False
    return out, True


def _check_line(tokens: list[tuple[str, bool]], pipefail: bool) -> list[str] | None:
    """The command's words if a whole line is one command whose failure ends the script with a failure:
    `[NAME=value ...] NAME args [redirections]`, optionally followed by `|| exit N` (N from 1 to 255),
    `|| exit`, or `|| { plain; commands; exit N; }`, or, under pipefail, piped into plain commands."""
    words = [w for w, _q in tokens]
    i = 0
    while i < len(words) and _ASSIGN_WORD_RE.match(words[i]):
        if _SHELL_VARIABLE_RE.match(words[i]) or _SHELL_STATE_ANYWHERE_RE.search(words[i]) or "`" in words[i] \
                or "$(" in words[i]:
            return None
        i += 1
    if i >= len(words) or tokens[i][1] or not re.fullmatch(r"[A-Za-z0-9_][\w.+-]*", words[i]):
        return None
    start = i
    while i < len(words) and (words[i] not in _OPERATORS or words[i] in _REDIRECTS or tokens[i][1]):
        i += 1
    command = words[start:i]
    rest = tokens[i:]
    if UNKNOWN_EXPRESSION in " ".join(command):
        return None
    # The command's own words are expanded before `obaaf` is looked up, so they may not change it either.
    if any(_SHELL_STATE_ANYWHERE_RE.search(w) or not _expansions_allowed(w) for w in words):
        return None
    if not rest:
        return command
    ops = [w for w, q in rest if not q and w in _OPERATORS]
    if ops[0] == "||":
        tail = [w for w, _q in rest[1:]]
        if tail == ["exit"] or (len(tail) == 2 and tail[0] == "exit" and _EXIT_CODE_RE.fullmatch(tail[1])):
            return command
        if tail[:1] == ["{"] and tail[-1:] == ["}"]:
            body = tail[1:-1]
            if body and body[-1] == ";":
                body = body[:-1]
            parts, current = [], []
            for word in body:
                if word == ";":
                    parts.append(current)
                    current = []
                elif word in _OPERATORS and word not in _REDIRECTS or word in ("{", "}", "!"):
                    return None
                else:
                    current.append(word)
            parts.append(current)
            last = parts[-1]
            if len(last) == 2 and last[0] == "exit" and _EXIT_CODE_RE.fullmatch(last[1]) and all(
                    p and p[0] not in _DENIED_NAMES and p[0] not in _RESERVED for p in parts[:-1]):
                return command
        return None
    if pipefail and all(op in ("|",) or op in _REDIRECTS for op in ops):
        return command
    return None


def _remote(words: list[str]) -> tuple[str, str] | None:
    """`git remote add NAME URL` or `git remote set-url NAME URL`: the remote's name and address."""
    for i, word in enumerate(words):
        if _base(word) in ("git", "git.exe") and words[i + 1:i + 3] in (["remote", "add"], ["remote", "set-url"]):
            rest = [w for w in words[i + 3:] if not w.startswith("-")]
            if len(rest) >= 2:
                return rest[0], rest[1]
    return None


def _canonical(value: Any, _seen: set | None = None) -> Any:
    """A YAML value as JSON can hold it with sorted keys: keys as text, anything else as its text."""
    _seen = _seen if _seen is not None else set()
    if isinstance(value, (dict, list)):
        if id(value) in _seen:
            return "(alias)"
        _seen = _seen | {id(value)}
        if isinstance(value, dict):
            return {as_text(k): _canonical(v, _seen) for k, v in value.items()}
        return [_canonical(v, _seen) for v in value]
    if value is None or isinstance(value, (bool, str)):
        return value
    return as_text(value)


def digest_of(value: Any) -> str:
    """A short digest of how a YAML value is written, for a finding's facts."""
    written = json.dumps(_canonical(value), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(written.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _call_text(script: str, start: int, limit: int | None = None) -> str:
    """The argument list of a call whose name ends at `start`: from its `(` to the `)` that closes
    it, and never past `limit` (the next call), so reading every call reads the script once."""
    limit = len(script) if limit is None else limit
    begin = script.find("(", start, limit)
    if begin == -1:
        return ""
    depth = 0
    for i in range(begin, limit):
        if script[i] == "(":
            depth += 1
        elif script[i] == ")":
            depth -= 1
            if depth == 0:
                return script[begin:i + 1]
    return script[begin:limit]


def _definition(script: str, name: str) -> str:
    """Where a script defines a name (`const NAME = ...`, `let`, `var`, or a plain assignment): the
    value, to the end of its brackets when it opens one, else to the end of the line."""
    match = re.search(rf"(?:\b(?:const|let|var)\s+|^\s*){re.escape(name)}\s*=\s*", script, re.M)
    if not match:
        return ""
    rest = script[match.end():match.end() + 4000]
    if rest[:1] in "{[(":
        closer = {"{": "}", "[": "]", "(": ")"}[rest[0]]
        depth = 0
        for i, ch in enumerate(rest):
            depth += ch == rest[0]
            depth -= ch == closer
            if depth == 0:
                return rest[:i + 1]
        return rest
    return rest.split("\n", 1)[0]


def pr_fetch(step: "Step", env: "Env", shell: str = "") -> PrCode:
    """Whether a step's scripts bring a pull request's code into the workspace.

    Each line is split as a POSIX shell splits it (comments dropped, continued lines joined), command
    by command; a pipeline is one command, and a quoted script given to `sh -c`, `bash -c` or `eval`
    is read again. A line the shell reader cannot split, and the lines of a script in another
    language (`shell: python`, `node`, PowerShell, an `actions/github-script` script), are also split
    roughly (quotes and brackets dropped), where `git` counts anywhere.

    "head": a command that brings code in (git with a subcommand in GIT_CODE_COMMANDS, after any
    global options; `gh repo clone`; `gh api`, curl or wget of an archive, contents or a diff;
    `patch`) together with something in the same command that names the pull request's code: an
    expression or env value that names it, a field read from the event file or the GitHub CLI,
    `gh pr diff`, `refs/pull/...`, the pull request's number, a variable set earlier in the step
    from any of these, a file an earlier command wrote from them, or a git remote added with the
    head's address. `gh pr checkout` needs nothing more. "unresolved": such a command with a step's
    or job's output, or a field an outsider writes, instead. Values passed from other steps
    (GITHUB_ENV, files) are not followed."""
    text = step.scripts().replace("\x00", "�")
    if not text:
        return PrCode(_BASE)
    shell = (shell or as_text(step.raw.get("shell") or "")).lower()
    github_script = (step.action or "").lower().startswith("actions/github-script")
    language = github_script or any(name in shell for name in ("python", "node", "pwsh", "powershell", "ruby", "perl"))
    head: set[str] = set()
    unresolved: set[str] = set()
    tainted: dict[str, PrCode] = {}     # variables (and git remotes) set from the pull request's code
    files: dict[str, PrCode] = {}       # files written from it
    cache: dict = {}

    def collect(found: PrCode, hits: set, open_: set) -> None:
        if found.state == _HEAD:
            hits.update(found.reads)
        elif found.state == _UNRESOLVED:
            open_.update(found.reads)

    def read(fragment: str) -> PrCode:
        hits: set = set()
        open_: set = set()
        collect(pr_code(fragment, env, numbers=True, runtime_only=True, _cache=cache), hits, open_)
        marker = PR_CODE_SCRIPT_RE.search(fragment)
        if marker:
            hits.add(one_line(marker.group(0), 60))
        for match in _VARIABLE_RE.finditer(fragment):
            name = next(g for g in match.groups() if g)
            exact = match.group(1) is not None or match.group(4) is not None
            if name in tainted:
                collect(tainted[name], hits, open_)
                continue
            given, level = env.find(name, 0, exact=exact)
            if given is _NOT_SET:
                continue
            key = ("$" + (name if exact else name.lower()), 0)
            if key not in cache:
                cache[key] = pr_code(given, env, numbers=True, runtime_only=True, start=level + 1, _cache=cache)
            collect(cache[key], hits, open_)
        words = set(_PATH_WORD_RE.findall(fragment))
        for word in words:
            if word in files:
                collect(files[word], hits, open_)
            elif word.split("/", 1)[0] in tainted and not word.startswith("$"):
                collect(tainted[word.split("/", 1)[0]], hits, open_)     # a remote, or a variable read as a word
        if language:
            for name in set(_IDENTIFIER_RE.findall(fragment)) & tainted.keys():
                collect(tainted[name], hits, open_)
        if hits:
            return PrCode(_HEAD, sorted(hits))
        return PrCode(_UNRESOLVED, sorted(open_)) if open_ else PrCode(_BASE)

    def note(found: PrCode) -> None:
        collect(found, head, unresolved)

    queue = [(line, 0) for line in script_lines(text, powershell="pwsh" in shell or "powershell" in shell)]
    while queue:
        raw_line, depth = queue.pop(0)
        line = _strip_comment(raw_line) if not language else raw_line
        placeholders: list[str] = []

        def hold(expression: str) -> str:
            placeholders.append(expression)
            return f"\x00{len(placeholders) - 1}\x00"

        def put_back(fragment: str) -> str:
            return _PLACEHOLDER_RE.sub(
                lambda m: placeholders[int(m.group(1))] if int(m.group(1)) < len(placeholders) else m.group(0), fragment)

        words = None if language else _shell_words(_sub_expressions(line, hold))
        commands: list[tuple[str, str | None, list]] = []
        if words is not None:
            for command in _commands(words):
                tool, skip = _fetching(command)
                piece = put_back(" ".join(word for k, word in enumerate(command) if k not in skip))
                commands.append((piece, tool, [put_back(word) for word in command]))
                if depth < 2:
                    for k, word in enumerate(command):
                        if any(c.isspace() for c in word) and ("$(" in word or "`" in word or (k and (
                                _SCRIPT_OPTION_RE.match(command[k - 1]) or command[k - 1] == "eval"))):
                            queue.insert(0, (put_back(word), depth + 1))
        if words is None:
            # Split roughly: quotes, backquotes, brackets and commas dropped, operators set apart, each
            # `${{ }}` one word. In a script language `git` counts anywhere (`subprocess.run(['git',
            # 'fetch', ...])`, `execSync(`git fetch ...`)`); in a shell line that could not be split, only
            # where a command starts.
            rough = _sub_expressions(line, lambda expression: " EXPR ")
            rough = re.sub(r"(&&|\|\||[;&|<>])", r" \1 ", re.sub(r"[\"'`(),\[\]{}+]|\bf(?=[\"'])", " ", rough))
            found = [(_fetching(command, anywhere=language)[0], command) for command in _commands(rough.split())]
            tool = next((t for t, _ in found if t), None)
            # One entry for the line, so what it sets is recorded whether or not it fetches.
            commands.append((line, tool, next((c for t, c in found if t), rough.split())))
        for piece, tool, command in commands:
            if tool == "gh pr checkout":
                head.add("gh pr checkout")
            elif tool in _DOWNLOADERS or tool == "gh api":
                # A download brings code in when it fetches an archive, contents or a diff: written in the
                # line, or read from the pull request's patch or diff address.
                found = read(piece)
                if _FETCHED_RE.search(piece) or any(_FETCHED_RE.search(r) for r in found.reads):
                    note(found)
            elif tool:
                note(read(piece))
            # What this command sets or writes, for the commands after it.
            remote = _remote(command)
            assigned = [m.group(1) for m in _ASSIGN_RE.finditer(piece)] + \
                       [a or b for a, b in _READ_RE.findall(piece)]
            written = [name for name in _WRITES_RE.findall(piece) if not name.startswith("/dev/")]
            if remote or assigned or written:
                found = read(remote[1] if remote else piece)
                if found.state != _BASE:
                    for name in assigned + ([remote[0]] if remote else []):
                        tainted[name] = found
                    for name in written:
                        files[name] = found
    script = as_text(step.with_.get("script") or "") if github_script else ""
    matches = list(_SCRIPT_API_RE.finditer(script))
    for k, match in enumerate(matches):
        if match.group(1):
            # Contents or an archive, read from the call's own arguments (written over several lines,
            # and never past the next call): at the pull request's head, it is its code; without a
            # ref, the default branch's. An argument that is a name is read where it is defined.
            limit = matches[k + 1].start() if k + 1 < len(matches) else len(script)
            call = _call_text(script, match.end(), limit)
            found = read(call)
            if found.state == _BASE:
                for name in list(dict.fromkeys(_IDENTIFIER_RE.findall(call)))[:20]:
                    defined = _definition(script, name)
                    if defined:
                        found = read(defined)
                        if found.state != _BASE:
                            break
            note(found)
        elif re.search(r"['\"`](apply|am)['\"`]|\bgit\s+(apply|am)\b|\bpatch\s+-p", script):
            # The pull request's diff or patch, applied in the same script.
            head.add(one_line(match.group(0), 60))
    if head:
        return PrCode(_HEAD, sorted(head))
    if unresolved:
        return PrCode(_UNRESOLVED, sorted(unresolved))
    return PrCode(_BASE)


def _balanced(toks: list) -> bool:
    """Whether every parenthesis and bracket is closed by its own kind, in order. GitHub refuses an
    expression where they are not, so nothing is concluded from one."""
    stack: list[str] = []
    for kind, text in toks:
        if kind != "op":
            continue
        if text in "([":
            stack.append(text)
        elif text in ")]":
            if not stack or stack.pop() != ("(" if text == ")" else "["):
                return False
    return not stack


def _split(toks: list, close: list, lo: int, hi: int, op: str) -> list[tuple[int, int]]:
    """The parts of toks[lo:hi] between each `||` or `&&` (`op` is `|` or `&`) that is not inside
    parentheses or brackets."""
    parts, start, i = [], lo, lo
    while i < hi:
        token = toks[i]
        if token in (("op", "("), ("op", "[")):
            i = min(close[i], hi) + 1
        elif token == ("op", op) and i + 1 < hi and toks[i + 1] == ("op", op):
            parts.append((start, i))
            start = i = i + 2
        else:
            i += 1
    parts.append((start, hi))
    return parts


def _plain_path(toks: list, lo: int, hi: int) -> tuple | None:
    """The names of a context reference that is all of toks[lo:hi] (`github.event_name`,
    `github['event_name']`), in lower case; None for anything else."""
    if lo >= hi or toks[lo][0] != "id":
        return None
    names, i = [toks[lo][1]], lo + 1
    while i < hi:
        if toks[i] == ("op", ".") and i + 1 < hi and toks[i + 1][0] == "id":
            names.append(toks[i + 1][1])
            i += 2
        elif toks[i] == ("op", "[") and i + 2 < hi and toks[i + 1][0] == "str" and toks[i + 2] == ("op", "]"):
            names.append(toks[i + 1][1])
            i += 3
        else:
            return None
    if not all(name.isascii() for name in names):
        return None
    return tuple(name.lower() for name in names)


def _event_test(toks: list, lo: int, hi: int) -> tuple[tuple, bool, str] | None:
    """(path, equal, value) when toks[lo:hi] is exactly one comparison of a context reference with a
    string, `==` or `!=`, either way round. GitHub compares strings without regard to case, so the
    value is returned in lower case; a value with a letter outside ASCII is not read, because what
    GitHub's comparison makes of it has not been established."""
    if hi - lo < 4:
        return None
    if toks[hi - 1][0] == "str" and toks[hi - 2] == ("op", "=") and toks[hi - 3] in (("op", "="), ("op", "!")):
        path, operator, value = _plain_path(toks, lo, hi - 3), toks[hi - 3][1], toks[hi - 1][1]
    elif toks[lo][0] == "str" and toks[lo + 1] in (("op", "="), ("op", "!")) and toks[lo + 2] == ("op", "="):
        path, operator, value = _plain_path(toks, lo + 3, hi), toks[lo + 1][1], toks[lo][1]
    else:
        return None
    if path is None or not value.isascii():
        return None
    return path, operator == "=", value.lower()


_EVENT_NAME = ("github", "event_name")
_RUN_EVENT = ("github", "event", "workflow_run", "event")
_MAX_CONDITION_DEPTH = 200


def _admitted(toks: list, close: list, lo: int, hi: int, events: frozenset, depth: int = 0,
              named: set | None = None) -> frozenset:
    """The events, out of `events`, on which the condition toks[lo:hi] can be true.

    It is read as GitHub evaluates it: `||` binds loosest, then `&&`, then a comparison. Only a
    part that is exactly `github.event_name == '<event>'` (or `!=`), or
    `github.event.workflow_run.event == '<event>'`, rules an event out. Any other part (a function,
    a negation, a comparison of a comparison, text inside a string) is taken to be true on every
    event, so the answer can name an event the job never runs on and cannot leave out one it does.
    With `named`, every event a part `github.event_name == '<event>'` names is added to it.
    """
    if depth > _MAX_CONDITION_DEPTH:
        return events
    parts = _split(toks, close, lo, hi, "|")
    if len(parts) > 1:
        out: frozenset = frozenset()
        for a, b in parts:
            out |= _admitted(toks, close, a, b, events, depth + 1, named)
        return out
    parts = _split(toks, close, lo, hi, "&")
    if len(parts) > 1:
        out = events
        for a, b in parts:
            out &= _admitted(toks, close, a, b, events, depth + 1, named)
        return out
    if hi - lo >= 2 and toks[lo] == ("op", "(") and close[lo] == hi - 1:
        return _admitted(toks, close, lo + 1, hi - 1, events, depth + 1, named)
    test = _event_test(toks, lo, hi)
    if test is None:
        return events
    path, equal, value = test
    if path == _EVENT_NAME and equal and named is not None:
        named.add(value)
    if path == _EVENT_NAME:
        named = {"workflow_run", TRUSTED_WORKFLOW_RUN} if value == "workflow_run" else {value}
        # In a workflow another workflow calls, `github.event_name` is the caller's event, which the
        # checker does not know, so no test of it rules `workflow_call` out.
        called = events & {"workflow_call"}
        return (events & named if equal else events - named) | called
    if path == _RUN_EVENT and equal:
        # True only for a run that followed a run started by `value`. Other events are left in:
        # the test is false on them, and leaving them in can only add findings.
        return events - {"workflow_run" if value in _TRUSTED_RUN_EVENTS else TRUSTED_WORKFLOW_RUN}
    return events


def _outside_caller_runs(job: "Job", event: str, workflow: "Workflow") -> bool:
    """Whether a caller in another repository raising `event` may run `job` (flagship slice 2d.4b3b): it
    is one `workflow_call` can start, and its own `if:` does not rule the event out for such a caller.
    The jobs it needs in turn are not followed, the wider reading. Worked out once for each job and event,
    in the workflow's memo of triggers."""
    memo = workflow.__dict__["_job_triggers"][2]
    key = (job.id, event)
    if key not in memo:
        cond = job.raw.get("if")
        memo[key] = "workflow_call" in job.triggers() and (
            not isinstance(cond, str) or event in _narrow({"workflow_call", event}, cond))
    return memo[key]


def condition_expression(cond: str) -> str | None:
    """The expression an `if:` holds, or None when GitHub does not evaluate the text as one
    expression. Without `${{` the whole text is the expression. With it, the text must be exactly one
    `${{ ... }}`: anything outside it, even a space or the line break a block scalar adds, makes the
    value a string, and a string that is not empty counts as true whatever it says."""
    if expr_mod.OPEN not in cond:
        return cond
    if not (cond.startswith(expr_mod.OPEN) and cond.endswith(expr_mod.CLOSE)):
        return None
    body = cond[len(expr_mod.OPEN):-len(expr_mod.CLOSE)]
    return body if expr_mod.bodies(cond)[0] == body else None


@lru_cache(maxsize=4096)
def _narrowed(cond: str, events: frozenset) -> frozenset:
    try:
        body = condition_expression(cond)
        if body is None or body.count("'") % 2:
            return events       # not one expression, or one that ends inside a string
        toks = expr_mod.tokens(body)
        if not _balanced(toks):
            return events
        atoms = events | ({TRUSTED_WORKFLOW_RUN} if "workflow_run" in events else frozenset())
        close = expr_mod._closers(toks)
        if "workflow_call" in events:
            # Flagship slice 2d.4b3b: `workflow_call` stands for a caller in another repository, whose event
            # the checker does not know. A test `github.event_name == '<event>'` says the job is written to
            # run on that event, and such a caller can raise it, so each event GitHub documents that a test
            # names is one the job can run on: the wider reading. A test with `!=` adds nothing.
            named: set = set()
            _admitted(toks, close, 0, len(toks), atoms, named=named)
            extra = frozenset(name for name in named if name in GITHUB_EVENTS) - atoms
            if extra:
                atoms |= extra | ({TRUSTED_WORKFLOW_RUN} if "workflow_run" in extra else frozenset())
        out = _admitted(toks, close, 0, len(toks), atoms)
    except (expr_mod.TooComplex, RecursionError):
        return events
    # A run that follows another run is one event with two origins. When both can start the job it
    # is listed as `workflow_run`, the wider of the two.
    return out - {TRUSTED_WORKFLOW_RUN} if "workflow_run" in out else out


def _narrow(events: set[str], cond: str) -> set[str]:
    """Narrow a job's possible triggers by the tests on the event in its `if:`. The condition is
    read from its tokens (see `_admitted`), never by searching its text, so words inside a string, a
    comparison of a comparison, or text outside `${{ }}` cannot make an event disappear."""
    return set(_narrowed(cond, frozenset(events)))


def expressions(value: Any, _seen: set | None = None) -> Iterator[str]:
    """Yield the body of every ${{ }} expression found anywhere in a value (see expr.bodies).

    A mapping or list reached again through a YAML alias is read once: its expressions were already
    yielded, and a file of nested aliases would otherwise take time exponential in its size.
    """
    if isinstance(value, str):
        yield from expr_mod.bodies(value)
    elif isinstance(value, (dict, list)):
        if _seen is None:
            _seen = set()
        if id(value) in _seen:
            return
        _seen.add(id(value))
        if isinstance(value, dict):
            for k, v in value.items():
                yield from expressions(k, _seen)
                yield from expressions(v, _seen)
        else:
            for v in value:
                yield from expressions(v, _seen)


def secret_names(value: Any) -> set[str]:
    """Names of secrets referenced in a value; '*' means every secret: toJSON(secrets), secrets.*,
    a computed index, or any other use of the secrets context that is not one literal name."""
    names: set[str] = set()
    for body in expressions(value):
        names |= expr_mod.secret_refs(body)
    return {n for n in names if n.upper() != "GITHUB_TOKEN"}


@dataclass
class Permissions:
    """Effective token permissions. `declared` is False when the default applies."""

    declared: bool
    mode: str = "map"            # "map", "read-all" or "write-all"
    scopes: dict = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: Any) -> "Permissions | None":
        """The permissions written in a workflow, read the widest way where the text is not one of the
        forms GitHub documents: a string other than `read-all` or `write-all`, or a value of the
        wrong kind, counts as `write-all`, and a scope at any level other than `read` or `none`
        counts as `write`. Such text is also a problem of the file (`permissions_problem`), which
        fails the check; reading it widely keeps any rule that runs from passing it. `None` (the key
        written with no value) is handled by the caller as not declared."""
        if raw is None:
            return None
        if isinstance(raw, str):
            if raw in ("read-all", "write-all"):
                return cls(declared=True, mode=raw)
            return cls(declared=True, mode="write-all")
        if isinstance(raw, dict):
            scopes: dict = {}
            for key, value in raw.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    return cls(declared=True, mode="write-all")
                scopes[key] = value if value in ("read", "none") else "write"
            return cls(declared=True, mode="map", scopes=scopes)
        return cls(declared=True, mode="write-all")

    def level(self, scope: str) -> str:
        """The level of one scope. A scope written in another case, or with spaces round it, counts
        as that scope, so `ID-TOKEN: write` is `id-token` to OBAAF-GHA-004 as it is a write scope to
        OBAAF-GHA-003 (and a problem of the file either way)."""
        if self.mode == "write-all":
            return "write"
        if self.mode == "read-all":
            return "none" if scope == "id-token" else "read"
        levels = [v for k, v in self.scopes.items() if k.strip().translate(_ASCII_LOWER) == scope]
        return max(levels, key=_LEVEL_RANK.__getitem__, default="none")

    def write_scopes(self) -> list[str]:
        if self.mode == "write-all":
            return ["write-all"]
        return sorted(s for s, v in self.scopes.items() if v == "write"
                      and s.strip().translate(_ASCII_LOWER) != "id-token")

    @property
    def oidc(self) -> bool:
        return self.level("id-token") == "write"


_NUMBER_OR_BOOLEAN = re.compile(r"[-+]?(\.?[0-9][0-9a-zA-Z_.:+-]*|\.(inf|nan))|true|false|yes|no|on|off|null|~",
                                re.IGNORECASE)


def _spellings(source: str, value) -> set[str]:
    """The names a plain value written as `source` may be to one YAML reader or another: the text
    as written, and the number or true or false each reading makes of it, in decimal."""
    out = {source.strip().lower(), as_text(value).lower()}
    text = source.strip().lower()
    if len(text) > 100:
        return out
    readings = []
    for read in (lambda t: int(t, 10), lambda t: int(t, 0), lambda t: int(t.replace("_", ""), 0),
                 lambda t: int(t, 8) if re.fullmatch(r"[-+]?0[0-7]+", t) else None, float):
        try:
            readings.append(read(text))
        except (ValueError, OverflowError):
            pass
    for number in readings:
        if number is None:
            continue
        out.add(str(number).lower())
        if isinstance(number, float) and number.is_integer():
            out.add(str(int(number)))
    if text in ("true", "false"):
        out.add(text)
    return out


def scalar_environment_match(value, wanted: str | None, source: str | None = None) -> str:
    """Whether an environment written as a plain number or true or false (`environment: 010`), or
    as text another reader takes for one (`0o10`), can be the one a protected_secrets entry names.
    YAML readers do not agree on what such a value is, so "unsure" where the wanted name is one of
    the names it may be (`010` may be 8, 10 or "010"), else "differs". Where the text as written
    could not be found, "unsure" for any wanted name that looks like a number or true or false."""
    if wanted is None:
        return "unsure"
    if source is None:
        return "unsure" if _NUMBER_OR_BOOLEAN.fullmatch(wanted.strip()) else "differs"
    return "unsure" if wanted.strip().lower() in _spellings(source, value) else "differs"


def environment_match(declared: str, wanted: str | None) -> str:
    """Whether an environment named as text is the one a protected_secrets entry names: "same" for
    the same name, or the same name in another case where both are ASCII (GitHub's environment
    names do not differ by case); "unsure" where they differ only in the case of other letters,
    which Python folds and GitHub may not; "differs" otherwise. A `wanted` of None is any
    environment."""
    if wanted is None or declared == wanted:
        return "same"
    if declared.isascii() and wanted.isascii():
        return "same" if declared.lower() == wanted.lower() else "differs"
    return "unsure" if declared.casefold() == wanted.casefold() else "differs"


_LEVEL_RANK = {"none": 0, "read": 1, "write": 2}
_EVENT_SPELLING = re.compile(r"[a-z][a-z_]*\Z")
_SCOPE_NAME = re.compile(r"[a-z][a-z-]*\Z")


def permissions_problem(raw: Any, where: str) -> str | None:
    """What makes a `permissions` value one the checker cannot tell the meaning of, if anything.
    GitHub documents `read-all`, `write-all`, `{}`, and a mapping of scope names (lower-case letters
    and hyphens) to `read`, `write` or `none`. Anything else (another case, spaces in a quoted
    value, an expression, a number) may not be read as GitHub would read it, whatever that is; it
    is a problem of the file, so the check fails rather than pass a token it may have misread. A
    scope name written in lower-case letters and hyphens that GitHub does not know is read as
    written: GitHub adds scopes, and a list here would fail every file that uses a new one."""
    if raw is None:
        return None
    if isinstance(raw, str):
        if raw in ("read-all", "write-all"):
            return None
        return (f"{where} has permissions written as {shown_value(raw)}, which is not read-all, write-all or a "
                "mapping of scopes, so the checker cannot tell what the token may do")
    if isinstance(raw, dict):
        for key, value in raw.items():
            if not isinstance(key, str) or not _SCOPE_NAME.match(key):
                return (f"{where} names a permission scope as {shown_value(key)}; GitHub's scopes are written in "
                        "lower-case letters and hyphens, so the checker cannot tell which scope it is")
            if not isinstance(value, str) or value not in ("read", "write", "none"):
                return (f"{where} gives permission scope '{key}' the level {shown_value(value)}, which is not read, "
                        "write or none, so the checker cannot tell what the token may do")
        return None
    return (f"{where} has permissions that are neither text nor a mapping ({shown_value(raw)}), so the checker "
            "cannot tell what the token may do")


@dataclass
class Step:
    index: int
    raw: dict
    line: int
    group: int | None = None      # parallel group it belongs to, if any
    background: bool = False      # runs concurrently with later steps (background: true or parallel)
    # Flagship slice 2d.4b2: a step of a local composite action, read by the rules as a step of the job
    # that uses the action, has the job's step that uses it (`via`) and the name its findings give it
    # (`shown_name`), which says where in the action it is. A step of the job keeps its own name.
    via: "Step | None" = field(default=None, repr=False, compare=False)
    shown_name: str | None = field(default=None, compare=False)
    written: Any = field(default=None, repr=False, compare=False)     # the action's step as its file writes it

    @property
    def name(self) -> str:
        if self.shown_name is not None:
            return self.shown_name
        return as_text(self.raw.get("name") or self.raw.get("id") or self.uses or f"step {self.index + 1}")

    @property
    def uses(self) -> str | None:
        value = self.raw.get("uses")
        return as_text(value) if value is not None else None

    @property
    def is_local(self) -> bool:
        """Whether the step uses an action from the workflow's own repository: `./path` (in the
        workspace as the job has left it) or `$/path` (the repository at the running commit, GitHub's
        self-repository syntax of 2026-07-30). Neither has a ref of its own to pin."""
        return is_local_reference(self.uses)

    @property
    def run(self) -> str:
        value = self.raw.get("run")
        return as_text(value) if value is not None else ""

    @property
    def with_(self) -> dict:
        """The step's inputs, by name with ASCII letters in lower case. GitHub hands an action its
        inputs as environment variables named in upper case, so `REF:` and `ref:` are the same
        input. Only A to Z are folded: what GitHub's upper-casing makes of any other letter is not
        established, so a name with one is left as written and reported as a problem when the file
        is read. So are two names that are the same input. Here the values of such a pair are
        joined, which lets a rule that searches a value see both and can make a rule that compares
        the whole value miss; the problem, which fails the check, is what covers that."""
        value = self.raw.get("with")
        if not isinstance(value, dict):
            return {}
        out: dict = {}
        for name, given in value.items():
            key = input_name(name)
            out[key] = f"{out[key]} {given}" if key in out else given
        return out

    @property
    def env(self) -> dict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else {}

    @property
    def action(self) -> str | None:
        """'owner/repo[/path]' for a remote action, without the ref."""
        if not self.uses or self.is_local or self.uses.startswith("docker://"):
            return None
        return action_name(self.uses)

    def uses_action(self, prefix: str) -> bool:
        action = self.action
        if not action:
            return False
        return names_action(action, prefix)

    def text(self) -> str:
        """The run script plus a github-script script, for pattern matching."""
        parts = [self.run]
        if self.action and self.action.lower().startswith("actions/github-script"):
            parts.append(str(self.with_.get("script", "")))
        return "\n".join(p for p in parts if p)

    @property
    def confines(self) -> bool:
        """Whether the step uses OBAAF's egress action from OBAAF's repository, which runs its `run`
        input as a command with the network limited. A local copy (`./actions/egress`) is any
        repository's own action and is not taken for it."""
        return (self.action or "").lower() == EGRESS_ACTION

    def scripts(self) -> str:
        """Everything a step runs as a command line: `agent_text()` (the run script, a github-script
        script and the command OBAAF's egress action runs) and a `docker://` step's `entrypoint` and
        `args`, which GitHub hands to the container as its command."""
        parts = [self._command_text()]
        if self.uses and self.uses.strip().lower().startswith("docker://"):
            for key in ("entrypoint", "args"):
                given = self.with_.get(key)
                if isinstance(given, str):
                    parts.append(given)
        return "\n".join(p for p in parts if p)

    def _command_text(self) -> str:
        """`text()`, and the command OBAAF's egress action runs, which is an agent's command line like
        any other."""
        parts = [self.text()]
        if self.confines:
            given = self.with_.get("run")
            parts.append(given if isinstance(given, str) else "")
        return "\n".join(p for p in parts if p)

    def agent_text(self, commands=None) -> str:
        """What an agent CLI is looked for in, read the widest way (flagship slice 2d.2f): the run script,
        a github-script script and the command OBAAF's egress action runs, as before, each also with lines
        continued by a backslash joined and with quotes and backslashes taken out (`cl''aude -p`); and,
        from every other place a step can give a command line (every input of any other action, a fork
        or copy of OBAAF's egress action included, a `docker://` step's entrypoint and arguments, the
        step's `shell`, its `env` values), each command whose first word, after assignments and wrappers
        such as `sudo` or `npx`, is one `commands` (compiled patterns; the catalog's `agent_commands` by
        default) match. Free text in an input ("vous aider", "works with cline") is not a command and is
        not read as one (found by the review of 2d.2f). Before, only the first three were read, so an
        agent given to another action was in no lane and got no agent rule."""
        if commands is None:
            commands = [re.compile(p, re.M) for p in load_catalog().detection.get("agent_commands", [])]
        own = self._command_text()
        found: list[str] = []
        lines: list = []
        if self.uses and self.uses.strip().lower().startswith("docker://"):
            entry, args = self.with_.get("entrypoint"), self.with_.get("args")
            lines.append(" ".join(v for v in (entry, args) if isinstance(v, str)))
        elif self.uses and not self.confines:
            for name, given in self.with_.items():
                if isinstance(given, str) and not (name == "script" and self.uses_action("actions/github-script")):
                    lines.append(given)
        shell = self.raw.get("shell")
        if isinstance(shell, str):
            lines.append(shell)
        lines.extend(v for v in self.env.values() if isinstance(v, str))
        for value in lines:
            for variant in _readings(value):
                if any(matches_any(commands, candidate, anchored=True) for segment in command_segments(variant)
                       for candidate in _first_word_forms(segment)):
                    # The whole value, wrappers included: `npx` before a package is what runs it (2c.8).
                    found.append(variant)
                    break
        # `run: $AGENT -p x` with `env: {AGENT: claude}`: the script with the step's env values put in, read
        # as commands like an input, so prose in an env value (`--notes "$NOTES"`) is not an agent.
        env = {k: v for k, v in self.env.items() if isinstance(k, str) and isinstance(v, str)}
        if env and own and "$" in own:
            put = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: env.get(m.group(1), m.group(0)), own)
            if put != own:
                for variant in _readings(put):
                    if any(matches_any(commands, candidate, anchored=True) for segment in command_segments(variant)
                           for candidate in _first_word_forms(segment)):
                        found.append(variant)
                        break
        text = "\n".join(p for p in [own, *found] if p)
        return "\n".join(dict.fromkeys(v for v in _readings(text) if v))

    @property
    def clean_action(self) -> str | None:
        """The action as written, `owner/repo[/path]` in lower case, when its path has no `.`, `..` or
        empty part; else None. Used where a step is trusted for what it is (only actions/upload-artifact
        may run after a confined command): `actions/upload-artifact/../../x` is not taken for it, since
        where GitHub resolves such a path is not established (flagship slice 2d.2f)."""
        if not self.uses or self.is_local or self.uses.lower().startswith("docker://"):
            return None
        action = self.uses.split("@", 1)[0]
        parts = action.split("/")
        if any(part in ("", ".", "..") for part in parts) or "\\" in action:
            return None
        return action.lower()


@dataclass
class Job:
    id: str
    raw: dict
    line: int
    workflow: "Workflow"
    steps: list[Step] = field(default_factory=list)
    lane: str = "trusted"
    lane_reason: str = ""
    # Every lane the job is in, and why. The rules ask `in_lane`; `lane` and `lane_reason` are what
    # is shown for the job.
    lanes: dict = field(default_factory=dict)
    lane_notes: list = field(default_factory=list)
    # Indexes of the steps that run a repository script in which an agent CLI was found.
    agent_script_steps: set = field(default_factory=set)
    # Of those, the steps whose agent runs inside a local action, with what was found there (slice 2d.4a).
    agent_step_why: dict = field(default_factory=dict)
    # The steps of the local composite actions the job's steps use, by the index of the step that uses
    # each, in the order they run, with the using step's inputs put in (slice 2d.4b2). The rules read
    # them as the job's own steps in a second pass (`WorkflowRules.through_local_actions`).
    local_steps: dict = field(default_factory=dict)
    # For a job that calls workflows of the same repository by their path: those workflows, and what
    # their jobs do counted for this job (flagship slice 2d.4b3b; `rules.CallEffects`). Set by the
    # checker once every file is read and classified.
    called: list = field(default_factory=list, repr=False, compare=False)
    call_effects: Any = field(default=None, repr=False, compare=False)
    # Why the job was declared `trusted`, when that is all it was declared (set by `classify`), so that a
    # lane a call gives it later carries the same note as a lane its own steps give it.
    trusted_declared: str | None = field(default=None, repr=False, compare=False)
    _secret_names: frozenset | None = field(default=None, repr=False, compare=False)

    def in_lane(self, lane: str) -> bool:
        return lane in self.lanes if self.lanes else self.lane == lane

    def reason_for(self, lane: str) -> str:
        """Why the job is in `lane`, as a finding quotes it."""
        if lane not in self.lanes:
            return self.lane_reason
        notes = self.lane_notes if lane == self.lane else []
        return "; ".join([self.lanes[lane], *notes])

    def add_lane(self, lane: str, reason: str) -> None:
        """Put the job in one more lane. A job never leaves a lane."""
        if lane in LANE_ORDER:
            self.lanes[lane] = reason
        self.settle_lane()

    def settle_lane(self, default_reason: str = "default") -> None:
        present = [lane for lane in LANE_ORDER if lane in self.lanes]
        if not present:
            self.lane, self.lane_reason = "trusted", "; ".join([default_reason, *self.lane_notes])
            return
        self.lane = present[0]
        also = [f"also {lane}: {self.lanes[lane]}" for lane in present[1:]]
        self.lane_reason = "; ".join([self.lanes[self.lane], *also, *self.lane_notes])

    @property
    def name(self) -> str:
        return as_text(self.raw.get("name") or self.id)

    @property
    def env(self) -> dict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else {}

    @property
    def permissions(self) -> Permissions | None:
        """The job's token permissions: its own `permissions`, else the workflow's, else None (the
        default, or a calling workflow's). `permissions:` written with no value is taken as not
        written, the wider of the two readings: what GitHub makes of it is not established, and
        reading it as `{}` would hide a workflow-level `write-all`."""
        if self.raw.get("permissions") is not None:
            return Permissions.parse(self.raw.get("permissions"))
        return self.workflow.permissions

    @property
    def environment_reading(self) -> tuple[str, Any]:
        """How the job's environment is written: ("none", None) when it declares none, or a name
        that is blank or missing (most likely no environment to GitHub, which is the full risk);
        ("literal", name) for a name written as text; ("expression", text) for a name with an
        expression in it; ("scalar", value) for a number or true or false, whose text this reader
        and GitHub's may not agree on (`010`); ("unreadable", value) for a list or a mapping."""
        written = self.raw.get("environment")
        if isinstance(written, dict):
            written = written.get("name")
        if written is None or (isinstance(written, str) and not written.strip()):
            return ("none", None)
        if isinstance(written, str):
            if "${{" in written:
                return ("expression", written)
            # Text this reader keeps as text that another reads as a number or true or false
            # (`0o10`, `1e3`) is a scalar too, unless it was quoted.
            source = self.environment_source()
            if source is not None and source[1] is None and _YAML12_SCALAR_RE.fullmatch(written):
                return ("scalar", written)
            return ("literal", written)
        if isinstance(written, (bool, int, float)):
            return ("scalar", written)
        return ("unreadable", written)

    def environment_source(self) -> tuple[str, str | None] | None:
        """The text of the job's environment name as written in the file, and its quoting style
        (None for a plain value), read from the composed YAML; None where it cannot be found (a
        merge key, a job reached another way)."""
        return self.workflow.environment_sources().get(self.id)

    @property
    def environment(self) -> str | None:
        env = self.raw.get("environment")
        if isinstance(env, dict):
            return as_text(env.get("name") or "") or None
        return as_text(env) if env else None

    def environment_candidates(self) -> tuple[list[str], bool]:
        """The names the job's environment can have, and whether that is all of them (flagship slice
        2d.2d). A name written as text is itself. A name written as one expression gives the text values
        written in it (`github.ref == 'refs/heads/main' && 'production' || 'staging'`) and, for each
        `matrix.<key>` it reads, the values the matrix written out in the file gives that key; it is all
        of them only when the expression reads nothing but the matrix and every such value is plain
        text. Anything else (an input, a variable, the event, a computed matrix) leaves the list open."""
        kind, written = self.environment_reading
        if kind == "none":
            return [], True
        if kind != "expression":
            return [as_text(written)], kind == "literal"
        names: list[str] = []
        complete = True
        text = str(written)
        found = expr_mod.bodies(text)
        if len(found) != 1 or text.strip() != expr_mod.OPEN + found[0] + "}}":
            complete = False        # text around the expression, or several expressions
        for body in found:
            try:
                toks = expr_mod.tokens(body)
                refs = expr_mod.refs(body)
            except expr_mod.TooComplex:
                return names, False
            names += [value for kind_, value in toks if kind_ == "str"]
            # A function can build a name from pieces (`format('{0}{1}', 'pr', 'oduction')`), so a name
            # given by one is never all of them.
            if any(a[0] == "id" and b == ("op", "(") for a, b in zip(toks, toks[1:])):
                complete = False
            for ref in refs:
                root = ref.path[0].value.lower() if ref.path and ref.path[0].kind == expr_mod.NAME else ""
                if root != "matrix" or len(ref.path) != 2 or ref.path[1].kind != expr_mod.NAME:
                    complete = False
                    continue
                values = self._matrix_values(ref.path[1].value)
                if values is None:
                    complete = False
                else:
                    names += values
        return list(dict.fromkeys(names)), complete

    def _matrix_values(self, name: str) -> list[str] | None:
        """The text values a matrix written out in the file gives `name`, from its list and its
        `include` entries; None when they cannot all be read as text (the same limits as for runner
        labels: a merge key in the file, a computed matrix or entry, a key in another case or not plain
        ASCII text, a value that is not text or that YAML 1.2 could read as other than text)."""
        if self.workflow.has_merge_key:
            return None
        strategy = self.raw.get("strategy")
        matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
        if not isinstance(matrix, dict):
            return None
        include = matrix.get("include", [])
        if not isinstance(include, list) or not all(isinstance(entry, dict) for entry in include):
            return None
        keys = list(matrix) + [key for entry in include for key in entry]
        if not name.isascii() or any(not isinstance(key, str) or not key.isascii() or expr_mod.OPEN in key
                                     for key in keys):
            return None
        if any(key != name and key.lower() == name.lower() for key in keys):
            return None
        listed = matrix.get(name, [])
        if not isinstance(listed, list):
            return None
        out = []
        for value in list(listed) + [entry[name] for entry in include if name in entry]:
            if not isinstance(value, str) or "${{" in value or _YAML12_SCALAR_RE.fullmatch(value):
                return None
            out.append(value)
        return out

    @property
    def cache_mode(self) -> str | None:
        value = self.raw.get("cache-mode", self.workflow.raw.get("cache-mode"))
        # `as_text`: a number of thousands of digits is refused by `str` (the review of slice 2d.4b3b).
        return as_text(value) if value is not None else None

    @property
    def runs_on(self) -> list[str]:
        value = self.raw.get("runs-on")
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, dict):
            labels = value.get("labels")
            # The key counts whatever its value: `group: 0` or `group: false` is a group GitHub may name
            # "0" or "false", not the absence of one (found by the review of flagship slice 2d.9).
            out = ["group:" + _group_text(value.get("group"))] if "group" in value else []
            if isinstance(labels, str):
                out.append(labels)
            elif isinstance(labels, list):
                out += [str(v) for v in labels]
            return out
        return []

    @property
    def self_hosted(self) -> bool:
        return any(is_self_hosted_label(label) for label in self.runs_on)

    def runner_label_sets(self) -> list[list[str]] | None:
        """Each set of labels the job can run on, with `${{ matrix.x }}` and `${{ matrix.x || 'label' }}`
        resolved from a matrix written out in the file; None when a label comes from an expression that
        cannot be resolved.

        The expression is read from its tokens (flagship slice 2d.7, issue #141). For `matrix.x ||
        'label'` the default is one of the labels wherever a row may lack `x` or give it a value that
        is false to GitHub (an empty text): unless `x` is a key of the matrix with a list of values and
        every `include` entry sets it, a row may lack it, because an `include` entry that cannot be added
        to any combination makes a row of its own. So the sets can be more than the job runs on, never
        fewer. The values of `x` computed when the job runs, an `include` or an `include` entry computed
        when the job runs, a key written in another case (GitHub compares property names without
        regard to case), a key that is not plain ASCII text with no expression, a value YAML 1.2 could
        read as other than text, a YAML merge key (`<<`) anywhere in the file, or any other expression
        leaves the labels unresolved."""
        labels = self.runs_on
        expr = [label for label in labels if "${{" in label]
        if not expr:
            return [labels] if labels else None
        if len(labels) != 1:
            return None
        text = labels[0].strip()
        if not (text.startswith(expr_mod.OPEN) and text.endswith("}}")):
            return None
        found = expr_mod.bodies(text)
        if len(found) != 1 or len(expr_mod.OPEN) + len(found[0]) + 2 != len(text):
            return None
        body = found[0]
        toks = expr_mod.tokens(body)
        if len(toks) < 3 or toks[0] != ("id", "matrix") or toks[1] != ("op", ".") or toks[2][0] != "id":
            return None
        name, rest = toks[2][1], toks[3:]
        default = None
        if rest:
            # `|| 'label'`, and nothing else: the two bars written together, a closed string after them.
            if (len(rest) != 3 or rest[:2] != [("op", "|"), ("op", "|")] or rest[2][0] != "str"
                    or "||" not in body or not body.rstrip().endswith("'")):
                return None
            default = rest[2][1]
        if self.workflow.has_merge_key:
            return None         # a matrix read two ways (found by the second review of 2d.7)
        strategy = self.raw.get("strategy")
        matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
        if not isinstance(matrix, dict):
            return None
        include = matrix.get("include", [])
        if not isinstance(include, list) or not all(isinstance(entry, dict) for entry in include):
            return None
        # Every key must be plain ASCII text with no expression, so that the checker's comparison is
        # GitHub's: a key YAML reads as true or a number, one computed when the job runs, or one with a
        # letter outside ASCII (whose case GitHub may fold otherwise) leaves the labels unresolved
        # (found by the review of 2d.7).
        keys = list(matrix) + [key for entry in include for key in entry]
        if not name.isascii() or any(not isinstance(key, str) or not key.isascii() or expr_mod.OPEN in key
                                     for key in keys):
            return None
        if any(key != name and key.lower() == name.lower() for key in keys):
            return None
        if name in matrix and not isinstance(matrix[name], list):
            return None
        values = list(matrix.get(name) or [])
        extra = [entry[name] for entry in include if name in entry]
        if not values and not extra and default is None:
            return None
        out: list[list[str]] = []
        falsy = False
        for value in values + extra:
            if isinstance(value, str) and _YAML12_SCALAR_RE.fullmatch(value):
                return None     # text to this reader, and maybe a number or false to GitHub's (YAML 1.2)
            if isinstance(value, str) and "${{" not in value:
                if value == "" and default is not None:
                    falsy = True        # `'' || 'label'` is the label
                else:
                    out.append([value])
            elif isinstance(value, list) and all(isinstance(v, str) and "${{" not in v for v in value):
                out.append([str(v) for v in value])
            else:
                return None
        if default is not None:
            may_lack = not (name in matrix and values and all(name in entry for entry in include))
            if may_lack or falsy:
                out.append([default])
        return out or None

    @property
    def runner_kind(self) -> str:
        """github-hosted, self-hosted, or unknown (custom labels, larger runners, unresolved expressions)."""
        if self.self_hosted:
            return "self-hosted"
        sets = self.runner_label_sets()
        if not sets:
            return "unknown"
        kinds = set()
        for labels in sets:
            if any(is_self_hosted_label(label) for label in labels):
                kinds.add("self-hosted")
            elif len({str(label).lower() for label in labels}) == 1 and is_hosted_label(labels[0]):
                # One GitHub-hosted label, written once or more, in any letter case: one requirement,
                # as the native firewall's reading has it since flagship slice 2d.2f (slice 2d.10, #216).
                kinds.add("github-hosted")
            else:
                kinds.add("unknown")
        for kind in ("self-hosted", "unknown"):
            if kind in kinds:
                return kind
        return "github-hosted"

    @property
    def mixed_runner_expression(self) -> bool:
        """A runtime selector that sends a fork's pull request to a standard GitHub-hosted runner, in
        the form the checker recognises (flagship slice 2d.2d):
        `github.event.pull_request.head.repo.full_name == github.repository && <anything> || '<hosted>'`
        (or `!=` with the two values the other way round, or the two sides of the test swapped).

        Before 2d.2d any selector that mentioned a hosted label and `self-hosted` counted, so
        `false && 'ubuntu-latest' || 'self-hosted'` did. `head.repo.fork && '<hosted>' || '<self-hosted>'`
        no longer counts: for a pull request whose fork was deleted, `head.repo` is null and the selector
        picks the second value (whether GitHub starts a run then is not verified), where the form above
        picks the hosted one. The rule still decides whether the job's events carry
        `pull_request.head.repo`; on any other event the form picks the second value."""
        if self.runner_label_sets() is not None or self.self_hosted or len(self.runs_on) != 1:
            return False
        text = self.runs_on[0].strip()
        found = expr_mod.bodies(text)
        if len(found) != 1 or text != expr_mod.OPEN + found[0] + "}}":
            return False
        body = re.sub(r"\s+", "", found[0].replace('"', "'"))
        head = r"github\.event\.pull_request\.head\.repo"
        hosted = r"'([a-z0-9.-]+)'"
        value = r"(?:'[^']*'|[a-z0-9_.()\[\]',-]+)"
        forms = [
            rf"(?:{head}\.full_name==github\.repository|github\.repository=={head}\.full_name)&&{value}\|\|{hosted}",
            rf"(?:{head}\.full_name!=github\.repository|github\.repository!={head}\.full_name)&&{hosted}\|\|{value}",
        ]
        lowered = body.lower()
        for form in forms:
            match = re.fullmatch(form, lowered)
            if match and is_hosted_label(match.group(1)) and "'" not in body.split("&&")[0]:
                return True
        return False

    @property
    def selector(self) -> str:
        """The runtime selector as written, without the spaces, for a finding's facts."""
        return re.sub(r"\s+", "", " ".join(self.runs_on))

    @property
    def reusable(self) -> str | None:
        value = self.raw.get("uses")
        return as_text(value) if value else None

    @property
    def needs(self) -> list[str]:
        value = self.raw.get("needs")
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return []

    def triggers(self, _seen: frozenset = frozenset()) -> set[str]:
        """Workflow triggers that can reach this job, narrowed by simple `if:` tests on the event, and
        by the jobs it needs (a job runs only if they ran, unless its `if:` overrides that).

        Each job's answer is worked out once per workflow and kept (flagship slice 2d.2g): following
        `needs` afresh for every path took time that doubled with each job, so a 3 KB file of 25 jobs
        that each need every earlier one held up `obaaf check` and `obaaf audit` for minutes. In a file
        whose `needs` form a cycle, which GitHub refuses, no job is narrowed by the jobs it needs: the
        wider answer, so a finding is never lost to the order in which the cycle was walked."""
        memo = self.workflow.__dict__.get("_job_triggers")
        if memo is None or memo[0] != len(self.workflow.jobs):
            # The second mapping keeps whether a caller in another repository raising an event may run a
            # needed job (slice 2d.4b3b), once for each job and event: worked out afresh for every job that
            # needs it, a 79 KB file took 399 s (the third review).
            memo = (len(self.workflow.jobs), {}, {})
            self.workflow.__dict__["_job_triggers"] = memo
        known = memo[1]
        if self.id not in known:
            # The jobs it needs are worked out first, deepest first, so a long chain does not recurse.
            order: list[Job] = []
            stack = [(self, iter(self.needs))]
            visiting = {self.id}
            while stack:
                job, deps = stack[-1]
                name = next(deps, None)
                if name is None:
                    stack.pop()
                    order.append(job)
                    continue
                dep = self.workflow.jobs.get(name)
                if dep is None or dep.id in known or dep.id in visiting:
                    continue
                visiting.add(dep.id)
                stack.append((dep, iter(dep.needs)))
            for job in order:
                if job.id not in known:
                    known[job.id] = frozenset(job._triggers())
        return set(known[self.id])

    def _triggers(self) -> set[str]:
        # A called workflow's jobs run on whatever starts a job that calls it: `workflow_call` stands for a
        # caller the checker cannot see (another repository's), the callers' events for those it can.
        events = set(self.workflow.triggers) | set(self.workflow.caller_events)
        cond = self.raw.get("if")
        before = set(events)
        if isinstance(cond, str):
            events = _narrow(events, cond)
        # Events the job's own `if:` names for a caller in another repository (flagship slice 2d.4b3b): such
        # a caller runs a needed job too, whatever its event, wherever that job can run for one.
        outside = events - before
        if runs_after_failure(cond) or self.workflow.needs_cycle():
            return events
        for name in self.needs:
            dep = self.workflow.jobs.get(name)
            if dep is None:
                continue
            allowed = dep.triggers()
            narrowed = set()
            for event in events:
                if event in allowed or (event in outside and _outside_caller_runs(dep, event, self.workflow)):
                    narrowed.add(event)
                elif event == "workflow_run" and TRUSTED_WORKFLOW_RUN in allowed:
                    narrowed.add(TRUSTED_WORKFLOW_RUN)
                elif event == TRUSTED_WORKFLOW_RUN and "workflow_run" in allowed:
                    narrowed.add(event)
            events = narrowed
        return events

    def secret_names(self) -> set[str]:
        """Secrets the job can read. The whole job is read, not a list of keys known to take
        secrets, so a reference in a place the checker did not expect (for example `outputs`) is
        still found."""
        if self._secret_names is None:
            names = secret_names(self.workflow.raw.get("env")) | secret_names(self.raw)
            passed = self.raw.get("secrets")
            if isinstance(passed, str) and passed.strip():
                names.add("*inherit")      # the only string GitHub accepts here is `inherit`
            self._secret_names = frozenset(names)
        return set(self._secret_names)

    def passed_secrets(self, names) -> list[str]:
        """What the jobs of this repository that call the job's workflow pass for the secrets it reads
        (flagship slice 2d.4b1): a called workflow's `secrets.MODEL_KEY` is whatever the caller maps onto
        MODEL_KEY, so the secret that reaches the job is named here, with where it is passed. A caller
        that is itself a called workflow passes on what its own callers give it, so the chain is
        followed to its first caller, each workflow once for each name. Empty for a workflow no job of
        the repository calls. Names are compared as GitHub compares them, in any letter case; a job that
        reads every secret (`toJSON(secrets)`) reads every one passed. A key with space round it is read
        without it, and a key that is not text (`null:`, `true:`, a number) is taken for every name the
        job reads, since how GitHub spells it is not established: the wider readings. Each caller's
        mapping is indexed by name once, and each of its entries worked out once, so a walk costs what it
        visits (the review of slice 2d.4b1 found walks that went through every key again for each name).
        A finding keeps only its bounded fact (`_passed_fact` in the rules), never the whole list."""
        return self._passed_secrets(frozenset(names))

    def _passed_secrets(self, names) -> list[str]:
        out: set[str] = set()
        # Per workflow: the names asked for so far, and whether every secret is.
        asked: dict[int, tuple[set, bool]] = {}
        todo = [(self.workflow, {n.upper() for n in names if not n.startswith("*")},
                 any(n.startswith("*") for n in names))]
        while todo:
            workflow, wanted, every = todo.pop()
            known, known_every = asked.get(id(workflow), (set(), False))
            wanted = set() if known_every else wanted - known
            every = every and not known_every
            if not wanted and not every:
                continue
            asked[id(workflow)] = (known | wanted, known_every or every)
            for call in workflow.callers:
                where = f"{bounded(one_line(call.path))} job '{bounded(one_line(call.job))}'"
                passed = call.secrets
                if isinstance(passed, str):
                    if passed.strip():
                        # `inherit` is the only text GitHub takes here; anything else is read as it, the wider way.
                        out.add(f"{where} passes every secret it can read (secrets: inherit)")
                        todo.append((call.workflow, wanted, every))
                    continue
                if not isinstance(passed, dict):
                    if passed is not None:
                        out.add(f"{where} passes secrets written as {one_line(value_identity(passed))}, which "
                                "the checker cannot read, so any secret it can read")
                        todo.append((call.workflow, set(), True))
                    continue
                named, odd = call.by_name()
                pairs = [pair for found in named.values() for pair in found] if every else \
                    [pair for name in wanted for pair in named.get(name, [])]
                for key, value in pairs + odd:
                    marker = (id(key), id(value)) if not isinstance(key, str) else key
                    cached = call._entries.get(marker)
                    if cached is None:
                        refs: set[str] = set()
                        for body in expressions(value):
                            refs |= expr_mod.secret_refs(body)
                        if "*" in refs:
                            source = "a secret it computes, so any secret it can read"
                        elif refs:
                            source = bounded(", ".join(sorted({r.upper() for r in refs})))
                        else:
                            source = one_line(value_identity(value))
                        shown = bounded(one_line(key.strip().upper())) if isinstance(key, str) else \
                            f"{one_line(value_identity(key))} (a key that is not text)"
                        cached = (f"{where} passes {shown} as {source}", {r.upper() for r in refs if r != "*"},
                                  "*" in refs)
                        call._entries[marker] = cached
                    entry, upstream, computed = cached
                    out.add(entry)
                    if upstream or computed:
                        todo.append((call.workflow, upstream, computed))
        return sorted(out)

    def granted_by_callers(self, scope: str | None = None) -> list[str]:
        """What the jobs of this repository that call the job's workflow grant its token, where neither
        the job nor its workflow declares permissions (flagship slice 2d.4b3a): GitHub gives such a
        called job the calling job's token, so which scopes it holds is written in the caller. With
        `scope` (`id-token`), each entry gives that scope's level; without, the write scopes as
        OBAAF-GHA-003 counts them. A caller that declares none and is itself called holds what its own
        callers grant, so the chain is followed to the first caller that declares, each workflow once;
        one that declares none and can be started by its own triggers grants the repository's default,
        which this check does not read, and one that only another repository can call grants what that
        caller grants. A workflow that can also start by its own triggers holds the default then, and
        says so. Empty for a job that declares permissions, or whose workflow no job of the repository
        calls. Worked out once per workflow and scope (the review found it quadratic in agent jobs times
        callers)."""
        if self.permissions is not None or not self.workflow.callers:
            return []
        memo = self.workflow.__dict__.setdefault("_granted", {})
        if scope in memo:
            return list(memo[scope])
        out: set[str] = set()
        own = sorted(set(self.workflow.triggers) - {"workflow_call"})
        if own:
            out.add(f"its workflow can also start on {bounded(one_line(', '.join(own)))}, with the repository's "
                    "default, which this check does not read")
        seen: set[int] = set()
        todo = [self.workflow]
        while todo:
            workflow = todo.pop()
            if id(workflow) in seen:
                continue
            seen.add(id(workflow))
            for call in workflow.callers:
                where = f"{bounded(one_line(call.path))} job '{bounded(one_line(call.job))}'"
                job = call.workflow.jobs.get(call.job) if call.workflow is not None else None
                perms = job.permissions if job is not None else None
                if perms is not None:
                    if scope is not None:
                        out.add(f"{where} grants {scope}: {perms.level(scope)}")
                    else:
                        scopes = perms.write_scopes()
                        out.add(f"{where} grants " + (", ".join(f"{s}: write" if s != "write-all" else s
                                                                for s in scopes) if scopes else "no write scope"))
                    continue
                caller = call.workflow
                if caller is None:
                    out.add(f"{where} declares no permissions, and the checker cannot tell what it grants")
                    continue
                if set(caller.triggers) - {"workflow_call"} or not caller.triggers:
                    out.add(f"{where} declares no permissions, so it grants the repository's default, which this "
                            "check does not read")
                if caller.callable and caller.callers:
                    todo.append(caller)
                elif caller.callable:
                    out.add(f"{where} declares no permissions, so it grants what the job that calls its workflow "
                            "grants, which is not in this repository")
        memo[scope] = sorted(out)
        return list(memo[scope])

    def runs_agent(self, detection: dict, extra_actions=(), extra_commands=()) -> str | None:
        actions = AgentActions(detection, extra_actions)
        commands = [re.compile(p, re.M) for p in list(detection.get("agent_commands", [])) + list(extra_commands)]
        for step in self.steps:
            if actions.names(step.action):
                return f"uses {step.action}"
            if leaves_repository(step.uses):
                return f"uses {one_line(step.uses, 80)}, a path out of its repository that can reach any action the job downloads"
            text = step.agent_text(commands)
            if text and matches_any(commands, text):
                return f"runs an agent CLI in '{step.name}'"
        # The default shell a `run` step is given (flagship slice 2d.2f, from its review): `shell: claude -p
        # {0}` under `defaults.run` runs the agent with every script.
        if any(matches_any(commands, form, anchored=True) for form in self.default_shell_forms()):
            return "runs an agent CLI as the default shell"
        if actions.calls(self.reusable):
            return f"calls {self.reusable}"
        return None

    def default_shell_forms(self) -> list[str]:
        """The command lines the default shell (`defaults.run.shell`, the job's and the workflow's) is read
        as for an agent, each from its first word after assignments and wrappers, when a step of the job
        runs a script with it; empty when none does. `runs_agent` and the agents named in the agent rules'
        facts (flagship slice 2d.5b) match the agent patterns against these."""
        if not any(self.steps_run()):
            return []
        out: list[str] = []
        for defaults in (self.raw.get("defaults"), self.workflow.raw.get("defaults")):
            run = defaults.get("run") if isinstance(defaults, dict) else None
            if not isinstance(run, dict) or "shell" not in run:
                continue
            shell = run.get("shell")
            if isinstance(shell, str):
                out.extend(form for variant in _readings(shell) for segment in command_segments(variant)
                           for form in _first_word_forms(segment))
            # The job's own `shell` is the one its steps get: GitHub uses the most specific default
            # (found by the review of slice 2d.5b). One that is not text is read with the workflow's too.
            if isinstance(shell, str) and defaults is self.raw.get("defaults"):
                break
        return out

    def steps_run(self) -> list[Step]:
        """The steps that run a script (`run:`), which the default shell runs."""
        return [step for step in self.steps if step.raw.get("run") is not None and step.raw.get("shell") is None]

    def upload_steps(self, detection: dict) -> list[Step]:
        actions = detection.get("upload_actions", [])
        commands = [re.compile(p, re.M) for p in detection.get("upload_commands", [])]
        out = []
        for step in self.steps:
            if str(step.env.get("OBAAF_STEP", "")).lower() == "publish":
                out.append(step)
                continue
            if any(step.uses_action(a) for a in actions):
                out.append(step)
                continue
            # Flagship slice 2d.2e: an image build that pushes (`push: true`, or a value set when the job
            # runs) publishes.
            if (step.uses_action("docker/build-push-action") or step.uses_action("docker/bake-action")) and (
                    "${{" in as_text(step.with_.get("push", "")) or as_text(step.with_.get("push", "")).strip().lower()
                    in ("true", "1", "yes")):
                out.append(step)
                continue
            # Everything the step runs as a command line, also with each command continued on the next
            # line joined to it and with quotes taken out (`"npm" publish`), so that neither hides a
            # command a list names (flagship slice 2d.2d). Both readings are matched.
            text = step.scripts()
            if text and any(rx.search(variant) for variant in upload_readings(text) for rx in commands):
                out.append(step)
        return out

    def matching_steps(self, actions=(), commands=()) -> list[Step]:
        rxs = [re.compile(p, re.M) for p in commands]
        out = []
        for step in self.steps:
            if any(step.uses_action(a) for a in actions):
                out.append(step)
            elif step.text() and any(rx.search(step.text()) for rx in rxs):
                out.append(step)
        return out


# Asking whether any of a list of patterns matches (flagship slice 2d.5b, whose 23 agent tools made the
# list of agent patterns 2.6 times as long, and a large repository's check slower: by 40 % and more on
# Python 3.10 and 3.11, whose regular expressions are slower than 3.13's, where it went over CI's limit).
# Each pattern is tried only where the text holds a piece of literal text the pattern cannot match
# without (its "needle": the longest run of plain characters at its top level, read from Python's own
# parse of it); where every pattern of the list has one, one search for any needle answers first, and most
# command lines hold none. A pattern with no needle (one that ignores case, or holds no such run) is always
# tried. Each answer is the one trying every pattern gives.
try:
    from re import _parser as _re_parser          # Python 3.11 and later
except ImportError:                                 # pragma: no cover - Python 3.10
    import sre_parse as _re_parser                  # type: ignore[no-redef]
_NEEDLES: dict = {}
_LISTS: dict = {}
_LAST_LIST: list = [None]


def _needle(rx) -> "str | None":
    """The longest run of two or more literal characters at the top level of `rx`, which every match of
    it holds; None when there is none or the pattern ignores case."""
    key = (rx.pattern, rx.flags)
    if key in _NEEDLES:
        return _NEEDLES[key]
    needle = None
    try:
        parsed = _re_parser.parse(rx.pattern, rx.flags)
        flags = getattr(getattr(parsed, "state", None), "flags", rx.flags)
        if not (flags | rx.flags) & re.IGNORECASE:
            runs, run = [], []
            for op, arg in parsed.data:
                if op is _re_parser.LITERAL:
                    run.append(chr(arg))
                else:
                    runs.append("".join(run))
                    run = []
            runs.append("".join(run))
            best = max(runs, key=len)
            needle = best if len(best) >= 2 else None
    except Exception:       # anything the parser does not take is tried as it is
        needle = None
    if len(_NEEDLES) >= 4096:
        _NEEDLES.clear()
    _NEEDLES[key] = needle
    return needle


def _prepared(commands) -> tuple:
    """For a list of compiled patterns: each with its needle, and one pattern that finds any needle, or
    None when a pattern has none."""
    key = tuple(commands)
    last = _LAST_LIST[0]
    if last is not None and last[0] is commands and last[1] == key:
        return last[2]
    prepared = _LISTS.get(key)
    if prepared is None:
        pairs = tuple((_needle(rx), rx) for rx in key)
        needles = [n for n, _rx in pairs]
        gate = (re.compile("|".join(re.escape(n) for n in sorted(set(needles), key=len, reverse=True)))
                if pairs and all(n is not None for n in needles) else None)
        prepared = (pairs, gate)
        if len(_LISTS) >= 64:
            _LISTS.clear()
        _LISTS[key] = prepared
    if isinstance(commands, list):
        _LAST_LIST[0] = (commands, key, prepared)
    return prepared


def matches_any(commands, text: str, anchored: bool = False) -> bool:
    """Whether one of the compiled `commands` matches `text`: searched for, or at its start when
    `anchored`, as `re.search` and `re.match` do."""
    if not isinstance(commands, (list, tuple)):
        commands = tuple(commands)      # read more than once below (found by the review)
    pairs, gate = _prepared(commands)
    if gate is not None and gate.search(text) is None:
        return False
    for needle, rx in pairs:
        if needle is not None and needle not in text:
            continue
        if (rx.match(text) if anchored else rx.search(text)) is not None:
            return True
    return False

def _readings(text: str) -> list[str]:
    """`upload_readings`, and the last of them with each backslash before a character taken out, as the
    shell takes it out (`cl\\aude` runs claude)."""
    readings = upload_readings(text)
    readings.append(re.sub(r"\\(?=[^\n])", "", readings[-1]))
    return readings


_SEGMENT_SPLIT_RE = re.compile(r"\$\(|[;&|`(){}\n]")
_WRAPPERS = frozenset({"sudo", "env", "exec", "nohup", "time", "xargs", "npx", "bunx", "command", "builtin", "nice",
                       "stdbuf", "setsid", "doas", "ionice", "chrt", "taskset", "script", "unbuffer"})
_TWO_WORD_WRAPPERS = {("pnpm", "dlx"), ("pnpm", "exec"), ("yarn", "dlx"), ("npm", "exec"), ("npm", "x"), ("bun", "x")}
# Options of a wrapper that take the next word as their value (`sudo -u runner`, `nice -n 10`).
_WRAPPER_VALUE_OPTIONS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group", "--chdir"},
    "doas": {"-u", "-C"}, "nice": {"-n", "--adjustment"}, "env": {"-u", "-C", "-S", "--unset", "--chdir"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"}, "stdbuf": {"-i", "-o", "-e"}, "ionice": {"-c", "-n", "-p"},
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"}, "npx": {"-p", "--package"}, "script": {"-c"},
    "taskset": set(), "chrt": set(),
}
# Shells whose `-c` argument is itself a command line (`bash -c "claude -p x"`, `sh -lc ...`).
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"})


def command_segments(text: str, _depth: int = 0) -> list[str]:
    """The commands a line of text holds, split where a shell starts a new one (`;`, `&`, `|`, a line break,
    a substitution, a group), each without the assignments, wrappers (`sudo -u runner`, `env`, `npx`,
    `nice -n 10`, `timeout -s KILL 5m`) and their options before its first word. A shell's `-c` argument
    is read again as commands (`bash -c "claude -p x"`; quotes are taken out by the caller's readings).
    Word by word, so linear in the length of the text."""
    out: list[str] = []
    for segment in _SEGMENT_SPLIT_RE.split(text or ""):
        words = segment.split()
        i, wrapper, duration = 0, "", False
        while i < len(words):
            word = words[i]
            base = word.rsplit("/", 1)[-1]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", word):
                i += 1
            elif base in _WRAPPERS or base == "timeout":
                wrapper, duration = base, base == "timeout"
                i += 1
            elif word.startswith("-") and wrapper:
                i += 2 if word in _WRAPPER_VALUE_OPTIONS.get(wrapper, ()) else 1
            elif duration and re.fullmatch(r"[0-9.]+[smhd]?", word):
                duration = False
                i += 1
            elif i + 1 < len(words) and (word, words[i + 1]) in _TWO_WORD_WRAPPERS:
                wrapper = word
                i += 2
            elif base in _SHELLS and _depth < 3:
                flag = next((n for n in range(i + 1, min(i + 4, len(words)))
                             if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", words[n])), None)
                if flag is None:
                    break       # a shell running a script file: the shell is the command
                out.extend(command_segments(" ".join(words[flag + 1:]), _depth + 1))
                i = len(words)
            else:
                break
        if i < len(words):
            out.append(" ".join(words[i:]))
    return out


def _first_word_forms(segment: str) -> list[str]:
    """A command as written, and with its first word's directories taken off (`/usr/local/bin/claude`),
    unless the word is a package name (`@scope/name`)."""
    first, _, rest = segment.partition(" ")
    if "/" in first and not first.startswith("@"):
        return [segment, f"{first.rsplit('/', 1)[-1]} {rest}".rstrip()]
    return [segment]


def upload_readings(text: str) -> list[str]:
    """A script as written, with lines continued by a backslash, a backtick or a caret joined, and the
    same with quote characters taken out: the readings release commands are looked for in."""
    joined = re.sub(r"[\\`^]\r?\n[ \t]*", " ", text)
    unquoted = re.sub(r"[\"']", "", joined)
    return [text, joined, unquoted]


@dataclass(frozen=True)
class Call:
    """A job of the repository that calls a workflow of the same repository (flagship slice 2d.4b1)."""
    path: str          # the calling workflow's file
    job: str           # the calling job's id
    line: int
    secrets: Any       # what the calling job's `secrets` holds as written: a mapping, `inherit`, or None
    workflow: Any = field(default=None, compare=False, repr=False)   # the calling workflow
    # What `secrets` passes, indexed once by name (upper case, without space round it), the keys that are
    # not text apart; and each entry once worked out. Neither is part of what the call is.
    _index: dict = field(default_factory=dict, compare=False, repr=False)
    _entries: dict = field(default_factory=dict, compare=False, repr=False)

    def by_name(self) -> tuple[dict, list]:
        if "index" not in self._index:
            named: dict = {}
            odd: list = []
            if isinstance(self.secrets, dict):
                for key, value in self.secrets.items():
                    if isinstance(key, str):
                        named.setdefault(key.strip().upper(), []).append((key, value))
                    else:
                        odd.append((key, value))
            self._index["index"] = (named, odd)
        return self._index["index"]


@dataclass
class Workflow:
    path: str
    text: str
    raw: dict
    jobs: dict[str, Job] = field(default_factory=dict)
    error: str | None = None
    problems: list[str] = field(default_factory=list)  # parts the checker cannot see into
    lane_problems: list = field(default_factory=list)  # IdleDeclaration: declarations in the file that do nothing
    digest: str = ""            # sha256 of the file's bytes, when it was read from a file
    # Flagship slice 2d.4b1: the jobs of the same repository that call this workflow (`uses:
    # ./.github/workflows/...`), and the events that can start them, which can start this workflow's
    # jobs too. Set by the checker once every file is read; empty for a file read on its own.
    callers: list = field(default_factory=list)          # Call
    caller_events: frozenset = frozenset()
    # Flagship slice 2d.4b3a: what the checker could not work out of what those jobs give the workflow's
    # inputs, as notes; and whether their values were put into its `inputs` references.
    caller_input_notes: list = field(default_factory=list)
    caller_inputs_put_in: bool = False
    # Flagship slice 2d.4b3b: jobs of this workflow that call, by `owner/repo/<path>@ref`, a path at which
    # this repository has a workflow that can be called: (job id, the `uses` as written, that path). Such a
    # call is not read as a call of this repository's file, and a note says so.
    named_calls: list = field(default_factory=list)
    # And the other way: the jobs of this repository that call this workflow's path so (path, job id).
    named_callers: list = field(default_factory=list)

    def give_caller_events(self, events) -> bool:
        """Add events that can start a job calling this workflow; True if any was new. Forgets every
        job's worked-out triggers, which those events change. An event GitHub does not document is
        added as OTHER_EVENT."""
        merged = self.caller_events | frozenset(e if e in GITHUB_EVENTS else OTHER_EVENT for e in events)
        if merged == self.caller_events:
            return False
        self.caller_events = merged
        self.__dict__.pop("_job_triggers", None)
        return True

    @property
    def has_merge_key(self) -> bool:
        """Whether the file has a YAML merge key (`<<`) anywhere: this reader (YAML 1.1) merges it away,
        and a YAML 1.2 reader takes it for a key of that name, so what a mapping holds is read two ways.
        Read once, from the composed nodes; a file that cannot be composed counts as having one."""
        cached = self.__dict__.get("_has_merge_key")
        if cached is None:
            from obaaf.checker.egress import _has_merge_key
            try:
                cached = _has_merge_key(self.text)
            except Exception:       # a file the reader cannot compose: say yes, so nothing is resolved from it
                cached = True
            self.__dict__["_has_merge_key"] = cached
        return cached

    def needs_cycle(self) -> bool:
        """Whether the jobs' `needs` form a cycle (GitHub refuses such a file). Worked out once, without
        recursion, so a long chain of jobs cannot exhaust Python's stack."""
        cached = self.__dict__.get("_needs_cycle")
        if cached is not None and cached[0] == len(self.jobs):
            return cached[1]
        state: dict[str, int] = {}      # 1: on the current path, 2: done
        found = False
        for start in self.jobs:
            if start in state:
                continue
            stack = [(start, iter(self.jobs[start].needs))]
            state[start] = 1
            while stack and not found:
                node, deps = stack[-1]
                dep = next(deps, None)
                if dep is None:
                    state[node] = 2
                    stack.pop()
                elif dep not in self.jobs:
                    continue
                elif state.get(dep) == 1:
                    found = True
                elif dep not in state:
                    state[dep] = 1
                    stack.append((dep, iter(self.jobs[dep].needs)))
            if found:
                break
        self.__dict__["_needs_cycle"] = (len(self.jobs), found)
        return found

    @property
    def triggers(self) -> dict[str, Any]:
        on = self.raw.get("on")
        if isinstance(on, str):
            return {on: None}
        if isinstance(on, list):
            return {as_text(e): None for e in on}
        if isinstance(on, dict):
            return {as_text(k): v for k, v in on.items()}
        return {}

    @property
    def permissions(self) -> Permissions | None:
        """The workflow's own `permissions`, or None. Written with no value it is taken as not
        written (see Job.permissions)."""
        return Permissions.parse(self.raw.get("permissions"))

    def composed(self):
        """The file's YAML node tree (no values constructed), or None if it cannot be composed. Kept
        for the life of the workflow."""
        if "_composed" not in self.__dict__:
            try:
                self.__dict__["_composed"] = yamlutil.yaml.compose(self.text, Loader=yamlutil._Loader)
            except Exception:       # anything the reader refuses: the source is simply not known
                self.__dict__["_composed"] = None
        return self.__dict__["_composed"]

    def environment_sources(self) -> dict:
        """Job id (as written) -> (text, style) of its environment name, for every job whose name is
        a plain mapping entry in the composed file. Built once, so asking for every job costs one
        walk of the file."""
        if "_environment_sources" in self.__dict__:
            return self.__dict__["_environment_sources"]
        yaml = yamlutil.yaml

        def get(node, key):
            found = None
            if isinstance(node, yaml.MappingNode):
                for k, v in node.value:
                    if isinstance(k, yaml.ScalarNode) and k.value == key:
                        found = v
            return found

        out: dict = {}
        jobs = get(self.composed(), "jobs")
        for key, job in (jobs.value if isinstance(jobs, yaml.MappingNode) else []):
            if not isinstance(key, yaml.ScalarNode):
                continue
            env = get(job, "environment")
            if isinstance(env, yaml.MappingNode):
                env = get(env, "name")
            if isinstance(env, yaml.ScalarNode):
                out[key.value] = (env.value, env.style)
        self.__dict__["_environment_sources"] = out
        return out

    @property
    def callable(self) -> bool:
        """Whether another workflow can call this one (`workflow_call`). A called workflow's jobs get
        the token the calling job grants, narrowed by what the called workflow declares."""
        return "workflow_call" in self.triggers

    @property
    def env(self) -> dict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else {}

    def line_of(self, needle: str, after: int = 0) -> int:
        """First line (1-based) at or after `after` containing `needle`, or `after`."""
        for number, line in enumerate(self.text.splitlines(), start=1):
            if number >= after and needle in line:
                return number
        return after or 1


# Characters that some YAML readers treat as a line break and others as ordinary text. Where the
# readers disagree, text after one of them can be a comment to the checker and a value to GitHub.
_DISPUTED_BREAKS = {"\u0085": "U+0085", "\u2028": "U+2028", "\u2029": "U+2029"}


def _unreadable(value: Any, _seen: set | None = None) -> str | None:
    """The first value of a kind the checker does not read (a set, pairs or binary data, which only
    an explicit YAML tag produces), or None. Skipping one silently would be a pass on text nobody
    read."""
    if isinstance(value, (dict, list)):
        if _seen is None:
            _seen = set()
        if id(value) in _seen:
            return None
        _seen.add(id(value))
        for item in (list(value.keys()) + list(value.values())) if isinstance(value, dict) else value:
            found = _unreadable(item, _seen)
            if found:
                return found
        return None
    if isinstance(value, (set, frozenset, tuple, bytes, bytearray)):
        return type(value).__name__
    return None


def parse(path: str, text: str) -> Workflow:
    for char, name in _DISPUTED_BREAKS.items():
        if char in text:
            return Workflow(path=path, text=text, raw={}, error=(
                f"contains the character {name}, which YAML readers do not agree is a line break, so the "
                "checker cannot tell what GitHub would read; remove it"))
    try:
        raw = yamlutil.load(text)
    except Exception as exc:  # yaml errors, duplicate keys
        return Workflow(path=path, text=text, raw={}, error=f"cannot parse YAML: {exc}")
    if not isinstance(raw, dict):
        return Workflow(path=path, text=text, raw={}, error="not a workflow (top level is not a mapping)")
    try:
        odd = _unreadable(raw)
    except RecursionError:
        odd = "nesting too deep to read"
    if odd:
        return Workflow(path=path, text=text, raw={}, error=(
            f"contains a value the checker does not read ({odd}); write it as plain YAML text, lists and mappings"))
    workflow = Workflow(path=path, text=text, raw=raw)
    jobs = raw.get("jobs")
    if not isinstance(jobs, dict):
        workflow.error = "no jobs"
        return workflow
    on = raw.get("on")
    events = [on] if isinstance(on, str) else list(on) if isinstance(on, (list, dict)) else []
    odd = next((event for event in events if not isinstance(event, str) or not _EVENT_SPELLING.match(event)), None)
    if odd is not None:
        # GitHub's event names are lower-case letters and underscores. One written otherwise (another
        # case, a mapping inside the list) is not an event the rules know, and treating it as none
        # would drop an untrusted trigger without a word.
        workflow.problems.append(f"lists a trigger under 'on' written as {shown_value(odd)}, which is not an event "
                                 "name as GitHub writes them (lower-case letters and underscores), so the checker "
                                 "cannot tell which events start the workflow")
    problem = permissions_problem(raw.get("permissions"), "the workflow")
    if problem:
        workflow.problems.append(problem)
    if workflow.has_merge_key:
        # Flagship slice 2d.2f: this reader (YAML 1.1) merges `<<` away, so a merged `permissions`,
        # `env` or `runs-on` is read as written in the mapping; a YAML 1.2 reader takes `<<` for a key
        # of that name and merges nothing. Which GitHub does is not established, so the checker cannot
        # tell what GitHub reads, and says so rather than reading one way.
        workflow.problems.append("uses a YAML merge key (<<), which this checker's YAML reader merges and a YAML 1.2 "
                                 "reader takes for a key of that name, so the checker cannot tell what GitHub reads; "
                                 "write the keys out, or use an anchor and alias for a whole value")
    for job_id, job_raw in jobs.items():
        shown_id = job_id if isinstance(job_id, str) else _group_text(job_id)
        if not isinstance(job_id, str):
            # `null:`, `true:` or `1:` is the text `null`, `true` or `1` to GitHub; this reader gives None,
            # True or 1, whose text (`None`, `True`) can be another job's id, and the second would replace
            # the first and take it out of every rule (flagship slice 2d.2f).
            workflow.problems.append(f"has a job id written as {shown_value(job_id)}, which this checker's YAML "
                                     "reader takes for a value other than text; write the id in quotes or rename it")
        if shown_id in workflow.jobs:
            workflow.problems.append(f"has two jobs the checker reads as '{one_line(shown_id, 60)}', so it cannot tell "
                                     "them apart; rename one")
            n = 2
            while f"{shown_id} ({n})" in workflow.jobs:
                n += 1
            shown_id = f"{shown_id} ({n})"
        if not isinstance(job_raw, dict):
            workflow.problems.append(f"job '{shown_id}' is not a mapping, so the checker cannot check what it does")
            continue
        problem = permissions_problem(job_raw.get("permissions"), f"job '{shown_id}'")
        if problem:
            workflow.problems.append(problem)
        uses = job_raw.get("uses")
        if uses is not None and not isinstance(uses, str):
            workflow.problems.append(f"job '{one_line(shown_id, 60)}' has uses written as {shown_value(uses)}, which is "
                                     "not text, so the checker cannot tell which workflow it calls")
        job = Job(id=shown_id, raw=job_raw, line=getattr(job_raw, "line", 0) or jobs.line_of(job_id), workflow=workflow)
        steps = job_raw.get("steps")
        if isinstance(steps, list):
            _add_steps(workflow, job, steps)
        workflow.jobs[job.id] = job
    return workflow


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def input_name(name) -> str:
    """An input's name as the rules look it up: A to Z in lower case, every other character as
    written (the Kelvin sign is not `k`, and `\u017f` is not `s`)."""
    return str(name).translate(_ASCII_LOWER)


def _input_problem(step_raw: dict) -> str | None:
    """What is wrong with the names under a step's `with:`, if anything: two names that are one
    input to GitHub, or a name with a letter outside ASCII, which GitHub's upper-casing may or may
    not turn into another input's name. Either way the checker cannot tell what the action is given."""
    given = step_raw.get("with")
    seen: dict = {}
    for name in (given if isinstance(given, dict) else ()):
        if isinstance(name, str) and not name.isascii():
            return (f"has an input name with a letter outside ASCII ('{one_line(name, 60)}'), and the checker "
                    "cannot tell which input GitHub takes it for")
        key = input_name(name)
        if key in seen:
            return (f"gives the same input twice under two spellings ('{one_line(seen[key], 60)}' and "
                    f"'{one_line(name, 60)}'), so the checker cannot tell which value GitHub uses")
        seen[key] = name
    return None


def _add_steps(workflow: Workflow, job: Job, steps: list) -> None:
    """Flatten a job's steps, including the steps inside `parallel` groups, in order."""
    groups = 0

    def inputs_checked(raw: dict, number: int) -> None:
        problem = _input_problem(raw)
        if problem:
            workflow.problems.append(f"job '{job.id}', step {number} {problem}")
        uses = raw.get("uses")
        if uses is not None and not isinstance(uses, str):
            # A number, a list or a mapping names no action the checker can look up (flagship slice 2d.2f;
            # a number of thousands of digits ended the run with a traceback before).
            workflow.problems.append(f"job '{job.id}', step {number} has uses written as {shown_value(uses)}, which "
                                     "is not text, so the checker cannot tell which action it runs")
    for number, step_raw in enumerate(steps, start=1):
        if not isinstance(step_raw, dict):
            workflow.problems.append(f"job '{job.id}', step {number} is not a mapping, so the checker cannot "
                                     "check what it does")
            continue
        line = getattr(step_raw, "line", job.line)
        if "parallel" in step_raw:
            groups += 1
            inner = step_raw.get("parallel")
            if not isinstance(inner, list):
                workflow.problems.append(f"job '{job.id}', step {number}: 'parallel' is not a list of steps")
                continue
            for sub in inner:
                if isinstance(sub, dict):
                    inputs_checked(sub, number)
                    job.steps.append(Step(index=len(job.steps), raw=sub, line=getattr(sub, "line", line),
                                          group=groups, background=True))
            continue
        inputs_checked(step_raw, number)
        if not ({"run", "uses"} & set(step_raw)) and not (CONTROL_STEP_KEYS & set(step_raw)):
            workflow.problems.append(f"job '{job.id}', step {number} has no 'run' or 'uses' and is not a step form "
                                     "the checker knows, so it cannot check what the step does")
        background = as_text(step_raw.get("background", "")).strip().lower() not in ("", "false")
        job.steps.append(Step(index=len(job.steps), raw=step_raw, line=line, background=background))


def declared_lane(value) -> str | None:
    """The lane a declaration names, or None when it names none. Case and surrounding space do
    not matter, so `Agent` is not silently a different thing from `agent`."""
    if not isinstance(value, str):
        return None
    lane = value.strip().lower()
    return lane if lane in LANES else None


def one_line(text, limit: int | None = None) -> str:
    """`text` as it can be printed on one line. A line break, any other control character, and any
    character Python does not count as printable are shown as escapes (`\\n`, `\\x1b`, `\\u200b`), so
    a name that contains a line break cannot look like another line of a report. The escape is for a
    reader and cannot be undone: a name that spells out `\\n` prints the same way. A text longer than
    `limit` is cut, and its length given."""
    out = "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in str(text))
    if limit and len(out) > limit:
        out = f"{out[:limit]}... ({len(out)} characters)"
    return out


def as_text(value) -> str:
    """`str(value)`, for a value that came out of a YAML file. Python refuses to print an integer of
    more than a few thousand digits in decimal, and YAML reads `0xFF...` of any length as one; such
    a number is given in hexadecimal, which has no limit."""
    try:
        return str(value)
    except ValueError:
        return hex(value) if isinstance(value, int) else repr(type(value).__name__)


def shown_value(value) -> str:
    """A declared value as a note names it: what the author wrote, on one line and bounded."""
    if value is None or value == "":
        return "an empty value"
    if isinstance(value, bool):
        return f"'{str(value).lower()}'"
    if isinstance(value, (list, tuple, set, frozenset)):
        return "a list"
    if isinstance(value, dict):
        return "a mapping"
    text = as_text(value)
    if not text.isascii():
        # A look-alike letter reads exactly like the lane it imitates; the escape shows the difference.
        text = text.encode("unicode_escape").decode("ascii")
    return f"'{one_line(text, 60)}'"


VALUE_LIMIT = 200


def value_identity(value) -> str:
    """A declared value as what identifies a finding about it. Text, a number and true or false are
    all text to the CI system that reads the variable, so each is its text in quotes; a list, a
    mapping and an empty value are named without quotes, so none can be mistaken for text that
    spells the same words. Text longer than VALUE_LIMIT characters is its length and digest, which
    keeps an acceptance small and still tells two long values apart."""
    if value is None or value == "":
        return "an empty value"
    if isinstance(value, (list, tuple, set, frozenset)):
        return "a list"
    if isinstance(value, dict):
        return "a mapping"
    text = str(value).lower() if isinstance(value, bool) else as_text(value)
    return bounded(text, quoted=True)


def bounded(text: str, quoted: bool = False) -> str:
    """`text` as part of what identifies a finding: itself (in quotes when `quoted`), or its length
    and digest when it is longer than VALUE_LIMIT characters. Unquoted text that itself begins like
    a digest is given as its digest too, so no short text can stand for a long one."""
    if len(text) > VALUE_LIMIT or (not quoted and text.startswith("sha256:")):
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        return f"sha256:{digest} ({len(text)} characters)"
    return f"'{text}'" if quoted else text


_LANE_VARIABLE = "OBAAF_LANE"


# Letters from other scripts that look like the Latin capitals of OBAAF_LANE (Cyrillic and Greek), and
# the digits that do, mapped to them before a name is compared (flagship slice 2d.2f).
_LOOKALIKES = str.maketrans({
    "\u0410": "A", "\u0430": "A", "\u0391": "A", "\u03b1": "A", "\u0392": "B", "\u0412": "B", "\u0432": "B",
    "\u03b2": "B", "\u0415": "E", "\u0435": "E", "\u0395": "E", "\u03b5": "E", "\u041e": "O", "\u043e": "O",
    "\u039f": "O", "\u03bf": "O", "\u0424": "F", "\u0492": "F", "\u03dc": "F", "\u039d": "N", "\u03bd": "N",
    "\u041d": "N", "\u043d": "N", "\u0399": "L", "\u04c0": "L", "\u2113": "L", "0": "O", "1": "L", "3": "E",
    "8": "B", "4": "A",
})
_LANE_SKELETON = "OBAAFLANE"


def lane_variable_skeleton(name: str) -> str:
    """A name reduced to what it looks like: compatibility forms folded (NFKC), invisible format
    characters taken out, look-alike letters and digits mapped to the Latin capitals, and everything
    but letters dropped, in upper case."""
    import unicodedata
    text = unicodedata.normalize("NFKC", name)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf").translate(_LOOKALIKES).upper()
    return "".join(ch for ch in text if "A" <= ch <= "Z")


def _within_one_edit(a: str, b: str) -> bool:
    """Whether `a` becomes `b` by at most one insertion, deletion, substitution or swap of neighbours."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                                  and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(short) and short[i] == long_[i]:
        i += 1
    return short[i:] == long_[i + 1:]


def is_lane_variable_spelling(name) -> bool:
    """Whether a name is OBAAF_LANE in another spelling (flagship slice 2d.2f): what it looks like is
    `OBAAFLANE` or one edit from it, once case, spaces, separators, invisible characters and look-alike
    letters are set aside (`obaaf-lane`, `OBAAF.LANE`, `OBAAF_LANES`, `OBAAF LANE` with a zero-width
    space, a Cyrillic `О`). Before, only case, spaces and `-` or a space for `_` were set aside."""
    if not isinstance(name, str) or name == _LANE_VARIABLE:
        return False
    return _within_one_edit(lane_variable_skeleton(name), _LANE_SKELETON)


def misnamed_lane_variables(env) -> list:
    """The names in an `env` that are OBAAF_LANE in another spelling (`is_lane_variable_spelling`). The
    variable is read under its exact name only, as a runner's shell would read it, so such a name
    declares nothing."""
    return [name for name in (env if isinstance(env, dict) else ()) if is_lane_variable_spelling(name)]


@dataclass(frozen=True)
class IdleDeclaration:
    """A lane declaration that does nothing: its value is not a lane, it is written where the
    checker does not read it, or it names a job, a stage or a file that is not there. The job it was
    meant for gets none of the rules the declaration was meant to add, so it is reported as a
    finding (OBAAF-CFG-001) and never dropped without a word.

    This is one written in a workflow or a Jenkinsfile; a `lanes:` entry is judged by the caller,
    which knows every file the configuration covers. `kind` says which case it is. `value` is the
    declared value as `value_identity` gives it and `shown` as a report prints it; `lane` is the
    lane it names when it names one."""
    kind: str
    path: str = ""                # the file it is written in
    line: int = 0
    job: str | None = None
    step: str | None = None
    value: str = ""
    shown: str = ""
    lane: str | None = None
    service: str = ""             # the service whose env holds it
    name: str = ""                # the variable as it is written, when that is not OBAAF_LANE
    name_shown: str = ""          # and as a report prints it
    where: str = ""               # for `elsewhere`: the place it is written, as a path of keys
    # The Jenkins stages whose steps the declaration reaches, by label. Steps outside any stage are
    # the empty label, which no stage can have.
    stages: tuple = ()
    # Whether the job is already in the lane the declaration names, so nothing is missing because of it.
    redundant: bool = False

    @classmethod
    def of(cls, kind: str, value, **where) -> "IdleDeclaration":
        return cls(kind=kind, value=value_identity(value), shown=shown_value(value),
                   lane=declared_lane(value), **where)


def key_line(mapping, key, owner_line: int = 0) -> int:
    """The line a key of a parsed mapping is written on, for a mapping that belongs to something
    that starts on `owner_line` (a job, a step, the file). A mapping reached through a YAML alias
    was written above its owner, at the anchor; then the owner's own line is given, which is where
    a reader looks for it."""
    line_of = getattr(mapping, "line_of", None)
    try:
        return max(int(line_of(key)) if line_of else 0, owner_line)
    except (TypeError, ValueError):
        return owner_line


_UNSET = object()


TRUSTED_NOTE = "declared trusted, which cannot override what the job does"


def classify(workflow: Workflow, overrides: dict | None = None, extra_agents: dict | None = None,
             aliases: tuple = ()) -> None:
    """Put each job in every lane it belongs to.

    Inference comes first, and each lane is decided on its own: a job that runs an agent and
    publishes is in the agent lane and in the release lane, and gets the rules of both. A lane
    declared with OBAAF_LANE or in the checker configuration is added to those. A declaration never
    takes a job out of a lane, so it can add rules and cannot remove any. An OBAAF_LANE that does
    nothing (a value that is not a lane, or one set where it is not read) is recorded in
    `workflow.lane_problems`, never dropped without a word. A `lanes:` entry that does nothing is
    for the caller to report: it knows every file the configuration covers.

    `aliases` are other paths the configuration may know this file by: a workflow checked on its
    own is `ci.yml` to the checker and `.github/workflows/ci.yml` in the repository's configuration.
    """
    detection = load_catalog().detection
    overrides = overrides or {}
    extra_agents = extra_agents or {}
    workflow.lane_problems = []
    paths = tuple(dict.fromkeys((workflow.path, *aliases)))

    def problem(found: IdleDeclaration) -> None:
        if found not in workflow.lane_problems:
            workflow.lane_problems.append(found)

    for job in workflow.jobs.values():
        job.lanes = _inferred_lanes(job, detection, extra_agents)
        job.lane_notes = []
        configured = [f"{path}#{job.id}" for path in paths] + list(paths)
        declarations = [(overrides.get(key, _UNSET), "set in the checker configuration", None) for key in configured]
        declarations += [
            (job.env.get("OBAAF_LANE", _UNSET), "set by OBAAF_LANE",
             {"kind": "job-not-a-lane", "job": job.id, "line": key_line(job.env, "OBAAF_LANE", job.line)}),
            (workflow.env.get("OBAAF_LANE", _UNSET), "set by OBAAF_LANE",
             {"kind": "workflow-not-a-lane", "line": key_line(workflow.env, "OBAAF_LANE", 1)}),
        ]
        for name in misnamed_lane_variables(job.env):
            problem(IdleDeclaration.of("job-misnamed", job.env[name], path=workflow.path, job=job.id,
                                       line=key_line(job.env, name, job.line), name=bounded(name),
                                       name_shown=one_line(name, 60)))
        for name in misnamed_lane_variables(workflow.env):
            problem(IdleDeclaration.of("workflow-misnamed", workflow.env[name], path=workflow.path,
                                       line=key_line(workflow.env, name, 1), name=bounded(name),
                                       name_shown=one_line(name, 60)))
        declared: dict = {}
        trusted_why = None
        for value, why, where in declarations:
            if value is _UNSET:
                continue
            lane = declared_lane(value)
            if lane is None:
                if where is not None:
                    problem(IdleDeclaration.of(where["kind"], value, path=workflow.path, line=where["line"],
                                               job=where.get("job")))
            elif lane == "trusted":
                trusted_why = trusted_why or why
            else:
                # The first declaration of a lane gives the reason that is shown, as it did when a
                # job had one lane: the configuration before OBAAF_LANE, the job before the workflow.
                declared.setdefault(lane, why)
        if trusted_why and job.lanes and not declared:
            # `trusted` is all the job was declared, and what it does puts it in a lane anyway.
            job.lane_notes.append(TRUSTED_NOTE)
        job.trusted_declared = trusted_why if not declared else None
        job.lanes.update(declared)
        job.settle_lane(trusted_why or "default")
        for found in _stray_declarations(workflow, job, {id(workflow.raw.get("env")), id(job.raw.get("env"))}):
            problem(found)
    # Outside the jobs: the variable anywhere but the workflow's env (flagship slice 2d.2f), for example as
    # an input of `workflow_dispatch` or under `defaults`.
    top = {key: value for key, value in workflow.raw.items() if key not in ("jobs", "env")}
    for found in _declarations_elsewhere(workflow, top, None, 1, {id(workflow.raw.get("env"))}, {}):
        problem(found)
    env = workflow.raw.get("env")
    if isinstance(env, str) and _names_lane_variable(env):
        problem(IdleDeclaration.of("workflow-elsewhere", env, path=workflow.path, line=key_line(workflow.raw, "env", 1),
                                   name=_LANE_VARIABLE, name_shown=_LANE_VARIABLE,
                                   where="env (written as one expression)"))


def _stray_declarations(workflow: Workflow, job: Job, read: set) -> list:
    """Where a job sets OBAAF_LANE in an `env` the checker does not read it from: a step's, the
    container's, a service's. `read` holds the identities of the two env mappings that are read for
    this job (its own and the workflow's), so an env shared with one of them through a YAML anchor
    is not reported. From flagship slice 2d.2f, also the variable under another spelling there, and the
    name anywhere else in the job (`elsewhere`): a key of a step's `with`, of the matrix or of a called
    workflow's `with`, an `env` written as one expression that names it, and a script that writes it to
    `GITHUB_ENV`, none of which the checker reads as a declaration."""
    def stray(env) -> bool:
        return isinstance(env, dict) and "OBAAF_LANE" in env and id(env) not in read

    def found(kind: str, env, line: int, **where) -> IdleDeclaration:
        return IdleDeclaration.of(kind, env["OBAAF_LANE"], path=workflow.path, job=job.id,
                                  line=key_line(env, "OBAAF_LANE", line), **where)

    out = [found("step-env", step.raw["env"], step.line, step=step.name)
           for step in job.steps if stray(step.raw.get("env"))]
    # A `parallel` group is a step to a reader and holds no step of its own in the model.
    steps = job.raw.get("steps")
    for number, group in enumerate(steps if isinstance(steps, list) else (), start=1):
        if isinstance(group, dict) and "parallel" in group and stray(group.get("env")):
            name = as_text(group.get("name") or group.get("id") or f"parallel group at step {number}")
            out.append(found("step-env", group["env"], getattr(group, "line", job.line), step=name))
    container = job.raw.get("container")
    if isinstance(container, dict) and stray(container.get("env")):
        out.append(found("container-env", container["env"], job.line))
    services = job.raw.get("services")
    for name, service in (services.items() if isinstance(services, dict) else ()):
        if isinstance(service, dict) and stray(service.get("env")):
            out.append(found("service-env", service["env"], job.line, service=bounded(str(name))))
    step_names = {id(step.raw): step.name for step in job.steps}
    skip = set(read) | {id(job.raw.get("env"))}
    # The envs whose exact OBAAF_LANE is reported above, as step-env, container-env or service-env.
    handled = {id(step.raw.get("env")) for step in job.steps}
    handled |= {id(group.get("env")) for group in (steps if isinstance(steps, list) else ()) if isinstance(group, dict)}
    if isinstance(container, dict):
        handled.add(id(container.get("env")))
    handled |= {id(service.get("env")) for service in (services.values() if isinstance(services, dict) else ())
                if isinstance(service, dict)}
    handled.discard(id(None))
    out += _declarations_elsewhere(workflow, job.raw, job.id, job.line, skip, step_names, handled=handled)
    return list(dict.fromkeys(out))


# `OBAAF_LANE=` as a script writes it, in any spelling the name check allows, for `GITHUB_ENV`.
_LANE_ASSIGNMENT_RE = re.compile(r"([^\s=;&|'\"`$({]{4,64})\s*=")


def _declarations_elsewhere(workflow: Workflow, raw: dict, job_id: str | None, owner_line: int, skip: set,
                            step_names: dict, where: str = "", handled: set = frozenset()) -> list:
    """The lane variable, in any spelling, written where nothing reads it as a declaration: a key in a
    mapping the caller does not read for lanes (an exact OBAAF_LANE in a step's, container's or
    service's env is reported by the caller), an `env` written as one expression that names it, and a
    script that writes it to `GITHUB_ENV` (flagship slice 2d.2f)."""
    out: list = []
    seen: set = set()

    def report(path: str, name: str, value, line: int, step: str | None) -> None:
        out.append(IdleDeclaration.of("elsewhere" if job_id is not None else "workflow-elsewhere", value,
                                      path=workflow.path, job=job_id, step=step, line=line,
                                      name=bounded(name), name_shown=one_line(name, 60),
                                      where=bounded(path)))

    def visit(value, path: str, line: int, step: str | None) -> None:
        if isinstance(value, (dict, list)):
            if id(value) in seen:
                return
            seen.add(id(value))
        if isinstance(value, dict):
            step = step_names.get(id(value), step)
            if hasattr(value, "line") and id(value) in step_names:
                line = getattr(value, "line", line) or line
            for key, sub in value.items():
                name = key if isinstance(key, str) else as_text(key)
                here = f"{path}.{name}" if path else name
                # A key with a value: a mapping or a list of mappings under the name (an input's
                # definition under `workflow_call`) declares nothing and is not a declaration's form.
                declares = not isinstance(sub, dict) and not (isinstance(sub, list)
                                                              and any(isinstance(v, (dict, list)) for v in sub))
                if id(value) not in skip and declares:
                    exact_env_handled = name == _LANE_VARIABLE and id(value) in handled
                    if (name == _LANE_VARIABLE and not exact_env_handled) or is_lane_variable_spelling(name):
                        report(path or "the top level", name, sub, key_line(value, key, line), step)
                if path.rsplit(".", 1)[-1] == "with" and isinstance(sub, (dict, list)):
                    continue    # an input is text to GitHub; one written as a mapping or a list is not read
                if name == "env" and isinstance(sub, str) and _names_lane_variable(sub):
                    report(here + " (written as one expression)", _LANE_VARIABLE, sub, key_line(value, key, line), step)
                elif name == "run" and isinstance(sub, str) and "GITHUB_ENV" in sub.upper():
                    for match in _LANE_ASSIGNMENT_RE.finditer(sub):
                        candidate = match.group(1)
                        if candidate == _LANE_VARIABLE or is_lane_variable_spelling(candidate):
                            rest = sub[match.end():].split("\n", 1)[0].strip().strip("'\"")
                            report(here + " (written to GITHUB_ENV)", candidate, rest.split()[0] if rest.split() else "",
                                   key_line(value, key, line), step)
                visit(sub, here, line, step)
        elif isinstance(value, list):
            for n, sub in enumerate(value):
                visit(sub, f"{path}[{n}]", line, step)

    visit(raw, where, owner_line, None)
    return out


def _names_lane_variable(text: str) -> bool:
    """Whether a value names the lane variable in any spelling the name check allows."""
    return any(token == _LANE_VARIABLE or is_lane_variable_spelling(token)
               for token in re.findall(r"[^\s'\"`(){}\[\],:=]{4,64}", text))


# An environment whose name says where releases go, anywhere in the name (AppProd, awsprod, app-store,
# euproduction), as before slice 2d.2d, with two changes from its reviewers: words that only hold those
# letters (`kitchen`, `restore`, `keystore`, `reproducible`, `product`) are taken out first, and a few
# short names are added as whole words (`live`, `prd`, `cd`, `pypi`, `testpypi`, `npm`, `crates`,
# `rubygems`, `nuget`, `pages`, `testflight`). `switch` still counts: it is a game console a studio
# releases to.
# A name that says it is not production, or comes before it, is taken at its word.
RELEASE_ENVIRONMENT_RE = re.compile(r"release|prod|publish|store|steam|itch|deploy")
NOT_RELEASE_RE = re.compile(r"restor|datastore|keystore|firestore|filestore|objectstore|kitchen|stitch|pitch|"
                            r"glitch|twitch|(?<!s)witch|hitch|reproduc|product(?!ion)|prodigy")
RELEASE_WORD_RE = re.compile(r"(?<![a-z0-9])(live|prd|cd|pypi|testpypi|npm|crates|rubygems|nuget|pages|testflight)"
                             r"(?![a-z0-9])")
NOT_PRODUCTION_RE = re.compile(r"(?<![a-z])(non|pre)[-_. ]?prod")     # not the end of `canon-prod`


def release_environment(name) -> bool:
    text = NOT_PRODUCTION_RE.sub(" ", str(name or "").lower())
    if RELEASE_ENVIRONMENT_RE.search(NOT_RELEASE_RE.sub(" ", text)):
        return True
    # Whole words, with a capital after a lower-case letter starting one (`AppLive`).
    words = NOT_PRODUCTION_RE.sub(" ", re.sub(r"([a-z])([A-Z])", r"\1 \2", str(name or "")).lower())
    return bool(RELEASE_WORD_RE.search(words))


def _inferred_lanes(job: Job, detection: dict, extra_agents: dict) -> dict:
    """Every lane the job's own content puts it in, with the reason for each."""
    lanes: dict = {}
    agent = job.runs_agent(detection, extra_agents.get("actions", ()), extra_agents.get("commands", ()))
    if agent:
        lanes["agent"] = agent
    triggers = job.triggers()
    writes = bool(job.permissions and job.permissions.write_scopes())
    if triggers & {"workflow_run", TRUSTED_WORKFLOW_RUN} and writes and _downloads_from_trigger_run(job):
        lanes["effect"] = "applies the output of another workflow's run"
    if job.upload_steps(detection):
        lanes["release"] = "uploads or publishes artifacts"
    elif release_environment(job.environment):
        # Whatever starts the job: a job that a pull request or a comment can start and that uses
        # the production environment is the case OBAAF-GHA-015 exists for.
        lanes["release"] = f"uses the '{job.environment}' environment"
    else:
        # An environment named by an expression is a release environment when one of the names it can
        # have is (`${{ matrix.env }}` over staging and production), flagship slice 2d.2d.
        named = next((name for name in job.environment_candidates()[0] if release_environment(name)), None)
        if named is not None:
            lanes["release"] = f"uses the '{job.environment}' environment, which can be '{named}'"
    if triggers and triggers <= PR_TRIGGERS | {"merge_group"} | ({"push"} if "pull_request" in triggers else set()):
        lanes["untrusted"] = "builds pull requests"
    return lanes


ARTIFACT_API_RE = re.compile(
    r"gh\s+run\s+download\b|downloadArtifact|listWorkflowRunArtifacts|/actions/runs/\S*/artifacts|"
    r"/actions/artifacts/\S*/(zip|\{archive_format\})", re.I)


def _downloads_from_trigger_run(job: Job) -> bool:
    for step in job.steps:
        if step.uses_action("actions/download-artifact") or step.uses_action("dawidd6/action-download-artifact"):
            if "workflow_run" in str(step.with_) or step.uses_action("dawidd6/action-download-artifact"):
                return True
        if ARTIFACT_API_RE.search(step.text()):
            return True
    return False


def discover(root: Path) -> list[Path]:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    # Any letter case of the extension, and a file named only `.yml` or `.yaml`, whose `suffix` Python
    # gives as empty (flagship slice 2d.2f). Whether GitHub runs `ci.YML` or `.yml` is not established;
    # a file the checker skips while GitHub runs it would drop every finding in it without a word.
    return sorted(p for p in wf_dir.iterdir() if p.name.lower().endswith((".yml", ".yaml")) and p.is_file())


def locate(target: Path) -> tuple[Path, list[Path]]:
    """The repository root and workflow files for a directory a user points `obaaf check` at.

    Accepts a repository root or its `.github/workflows` directory itself (the form the
    quickstart once showed), so pointing at the workflows directory no longer checks zero
    files and passes. The root stays the repository root, so CODEOWNERS and instruction
    files are still found and paths read `.github/workflows/<file>`.
    """
    target = target.resolve()
    if target.name == "workflows" and target.parent.name == ".github" and not (target / ".github").exists():
        root = target.parent.parent
        return root, discover(root)
    if target.name == ".github" and (target / "workflows").is_dir():
        return target.parent, discover(target.parent)
    return target, discover(target)
