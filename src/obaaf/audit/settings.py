"""What the settings audit reads from GitHub, and how each answer is recorded.

Every setting in :data:`SETTINGS` ends up in the snapshot with one of four statuses:

- ``read``: the value is in the snapshot.
- ``partial``: some of it was read; ``problems`` names each part that was not.
- ``unread``: it was not read; ``reason_code`` and ``reason`` say why, and ``needs`` says what GitHub's
  reference asks of a caller.
- ``not_applicable``: the setting does not exist for this repository.

Nothing is left out. A setting that was not read is in the snapshot as ``unread``, never missing, so that
nothing built on the snapshot can mistake "not read" for "nothing there".

What each endpoint needs was read from GitHub's REST reference on 2026-11-12 (docs/settings-audit.md lists
the pages). Answers are checked against the documented shape; anything else is recorded as unread with the
code ``unexpected`` instead of being guessed at.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

from obaaf import __version__
from obaaf.audit.github import API_VERSION, Answer, Client, plain

FORMAT = "obaaf-settings-snapshot/v0.1"
STATUSES = ("read", "partial", "unread", "not_applicable")
# Why something was not read. The codes are stable; the wording beside them in a snapshot is for people.
REASONS = {
    "no_token": "not requested, because no token was given and GitHub does not show this without one",
    "unauthorized": "GitHub did not accept the token",
    "forbidden": "GitHub refused: the caller is not allowed to read it",
    "not_found": "GitHub answered 404, which it also sends when the caller may not see something",
    "rate_limited": "GitHub's rate limit was reached",
    "network": "no answer was received",
    "server_error": "GitHub had an error",
    "unexpected": "the answer did not have the shape GitHub documents",
    "withheld": "GitHub left it out of an answer it otherwise gave",
    "depends": "not requested, because something it depends on was not read",
}
OWNER_REPO = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/(?!\.{1,2}\Z)[A-Za-z0-9._-]{1,100}\Z")
ROLE_ORDER = ("admin", "maintain", "push", "triage", "pull")
ROLE_NAMES = {"admin": "admin", "maintain": "maintain", "push": "write", "triage": "triage", "pull": "read"}


@dataclass(frozen=True)
class Setting:
    key: str
    title: str
    needs: str        # what GitHub's REST reference says a caller needs to read it
    public: bool      # the reference says it can be read without a token on a public repository
    paths: tuple[str, ...]
    used_for: str     # the question it helps answer
    note: str = ""    # what to do when the audit cannot read it and should not be given the access to


SETTINGS: tuple[Setting, ...] = (
    Setting("repository", "The repository", '"Metadata" repository permission (read)', True,
            ("/repos/{owner}/{repo}",),
            "whether it is public, and which branch is the default"),
    Setting("rulesets", "Rulesets and their rules", '"Metadata" repository permission (read)', True,
            ("/repos/{owner}/{repo}/rulesets", "/repos/{owner}/{repo}/rulesets/{id}"),
            "required approvals, required checks and what else a branch or tag must satisfy"),
    Setting("ruleset_bypass_actors", "Who may bypass each ruleset", "write access to the ruleset", False,
            ("/repos/{owner}/{repo}/rulesets/{id}",),
            "whether someone can skip the required reviews and checks",
            "GitHub returns the bypass list to nobody else, and OBAAF asks nobody for write access. An "
            "administrator can read it in the repository's settings, under Rules."),
    Setting("branch_rules", "Rules in force on each audited branch", '"Metadata" repository permission (read)',
            True, ("/repos/{owner}/{repo}/rules/branches/{branch}",),
            "the active rules from every level (repository and organisation) taken together"),
    Setting("branches", "Each audited branch, as anyone may see it", '"Contents" repository permission (read)',
            True, ("/repos/{owner}/{repo}/branches/{branch}",),
            "whether GitHub calls the branch protected, and the required checks it shows publicly"),
    Setting("branch_protection", "Classic branch protection", '"Administration" repository permission (read)',
            False, ("/repos/{owner}/{repo}/branches/{branch}/protection",),
            "required reviews and checks set the older way, and whether administrators are held to them"),
    Setting("environments", "Environments: reviewers and which branches may deploy",
            '"Actions" repository permission (read)', True,
            ("/repos/{owner}/{repo}/environments",
             "/repos/{owner}/{repo}/environments/{name}/deployment-branch-policies"),
            "whether a job on any branch can reach an environment's secrets"),
    Setting("environment_secrets", "Names of the secrets in each environment",
            '"Environments" repository permission (read)', False,
            ("/repos/{owner}/{repo}/environments/{name}/secrets",),
            "which secrets are kept behind an environment (names only; GitHub never returns values)"),
    Setting("repository_secrets", "Names of the repository's secrets", '"Secrets" repository permission (read)',
            False, ("/repos/{owner}/{repo}/actions/secrets",),
            "which secrets every workflow on every branch can read (names only)"),
    Setting("organization_secrets", "Names of the organisation secrets this repository receives",
            '"Secrets" repository permission (read)', False, ("/repos/{owner}/{repo}/actions/organization-secrets",),
            "which organisation secrets every workflow on every branch can read (names only)"),
    Setting("actions_permissions", "Which actions may run, and whether they must be pinned",
            '"Administration" repository permission (read)', False,
            ("/repos/{owner}/{repo}/actions/permissions", "/repos/{owner}/{repo}/actions/permissions/selected-actions"),
            "whether a workflow's actions are allowed, and whether GitHub enforces pinning to a commit"),
    Setting("workflow_permissions", "What the workflow token may do by default",
            '"Administration" repository permission (read)', False,
            ("/repos/{owner}/{repo}/actions/permissions/workflow",),
            "what a job without a permissions block gets, and whether workflows may approve pull requests"),
    Setting("fork_pull_requests", "Approval before workflows run on fork pull requests",
            '"Administration" repository permission (read)', False,
            ("/repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval",
             "/repos/{owner}/{repo}/actions/permissions/fork-pr-workflows-private-repos"),
            "who can run a pull request workflow without a maintainer's approval"),
    Setting("actions_policies", "Actions policies: who and which events may start a workflow",
            '"Administration" repository permission (write)', False,
            ("/repos/{owner}/{repo}/actions/policies", "/repos/{owner}/{repo}/actions/policies/{id}"),
            "whether a trigger a workflow uses is blocked before any job starts",
            "GitHub's reference asks for write access even to read these, and OBAAF asks nobody for write "
            "access. An administrator can read them in the repository's settings."),
    Setting("collaborators", "How many accounts hold each role",
            "write, maintain or admin access to the repository", False, ("/repos/{owner}/{repo}/collaborators",),
            "whether a required approval can be given by anyone other than the author (counts only, no names)"),
)
BY_KEY = {s.key: s for s in SETTINGS}


class Shape(ValueError):
    """An answer did not have the shape GitHub documents."""


# ---------------------------------------------------------------- entries
def _read(value) -> dict:
    return {"status": "read", "value": value}


def _unread(setting: Setting, code: str, reason: str, accepted: str = "") -> dict:
    entry = {"status": "unread", "reason_code": code, "reason": reason, "needs": setting.needs}
    if accepted:
        entry["accepted_permissions"] = accepted
    return entry


def _failed(setting: Setting, answer: Answer) -> dict:
    return _unread(setting, answer.code, answer.why, answer.accepted)


def _problem(what: str, answer: Answer) -> dict:
    problem = {"what": what, "reason_code": answer.code, "reason": answer.why}
    if answer.accepted:
        problem["accepted_permissions"] = answer.accepted
    return problem


def _outcome(setting: Setting, value, problems: list[dict], total: int) -> dict:
    """read when every part was read, unread when none was, partial otherwise."""
    if not problems:
        return _read(value)
    if len(problems) >= total:
        first = problems[0]
        reason = first["reason"] if total == 1 else f"none of {total} could be read; the first: {first['reason']}"
        return _unread(setting, first["reason_code"], reason, first.get("accepted_permissions", ""))
    return {"status": "partial", "value": value, "problems": problems, "needs": setting.needs}


def _not_applicable(reason: str) -> dict:
    return {"status": "not_applicable", "reason": reason}


# ---------------------------------------------------------------- shape checks
def _obj(value, what: str) -> dict:
    if not isinstance(value, dict):
        raise Shape(f"{what} was not an object")
    return value


def _text(obj: dict, key: str, what: str, optional: bool = False):
    value = obj.get(key)
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise Shape(f"{what} had no text field {key!r}")
    return value


def _flag(obj: dict, key: str, what: str, optional: bool = False):
    value = obj.get(key)
    if value is None and optional:
        return None
    if not isinstance(value, bool):
        raise Shape(f"{what} had no true/false field {key!r}")
    return value


def _number(obj: dict, key: str, what: str, optional: bool = False):
    value = obj.get(key)
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise Shape(f"{what} had no whole-number field {key!r}")
    return value


def _json_safe(value, what: str, depth: int = 0):
    """A copy of ``value`` if it is plain JSON of modest depth; parameters are kept as GitHub sent them."""
    if depth > 12:
        raise Shape(f"{what} was nested too deeply")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [_json_safe(v, what, depth + 1) for v in value]
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise Shape(f"{what} had a key that was not text")
        return {k: _json_safe(v, what, depth + 1) for k, v in sorted(value.items())}
    raise Shape(f"{what} was not plain JSON")


def _rules(value, what: str) -> list[dict]:
    if not isinstance(value, list):
        raise Shape(f"{what} had no list of rules")
    rules = []
    for rule in value:
        rule = _obj(rule, f"a rule of {what}")
        parameters = rule.get("parameters")
        rules.append({"type": _text(rule, "type", f"a rule of {what}"),
                      "parameters": _json_safe(_obj(parameters, "a rule's parameters"), what)
                      if parameters is not None else {}})
    return sorted(rules, key=lambda r: (r["type"], json.dumps(r["parameters"], sort_keys=True)))


def _names(items: list, what: str) -> list[str]:
    return sorted(_text(_obj(item, what), "name", what) for item in items)


# ---------------------------------------------------------------- the reader
class _Reader:
    def __init__(self, client: Client, owner: str, repo: str, branches: tuple[str, ...]) -> None:
        self.client = client
        self.requested = f"{owner}/{repo}"
        self.base = f"/repos/{owner}/{repo}"
        self.extra_branches = branches
        self.branches: list[str] = []
        self.settings: dict[str, dict] = {}
        self.viewer: dict = {"authenticated": client.authenticated}
        self.repository: dict | None = None

    # -- helpers
    def _skip_without_token(self, key: str) -> bool:
        setting = BY_KEY[key]
        if self.client.authenticated or setting.public:
            return False
        self.settings[key] = _unread(setting, "no_token", "not requested: no token was given, and GitHub does "
                                                          "not show this without one")
        return True

    def _guarded(self, key: str, fn) -> None:
        """Run one reader; an answer of the wrong shape makes that setting unread, never a crash or a guess."""
        try:
            fn()
        except Shape as exc:
            self.settings[key] = _unread(BY_KEY[key], "unexpected",
                                         f"the answer did not have the shape GitHub documents: {plain(exc)}")
        except (TypeError, KeyError, AttributeError, IndexError, RecursionError) as exc:
            # Not foreseen above. It is still an answer this reader could not make sense of, and the honest
            # record of that is "unread", not a crash halfway through an audit.
            self.settings[key] = _unread(BY_KEY[key], "unexpected",
                                         "the answer could not be read as GitHub documents it "
                                         f"({type(exc).__name__})")
        self.settings.setdefault(key, _unread(BY_KEY[key], "unexpected", "the reader recorded no result"))

    # -- 1. the repository itself
    def read_repository(self) -> bool:
        setting = BY_KEY["repository"]
        answer = self.client.get(self.base)
        if not answer.ok:
            self.settings["repository"] = _failed(setting, answer)
            return False
        try:
            body = _obj(answer.data, "the repository")
            full_name = _text(body, "full_name", "the repository")
            if not OWNER_REPO.match(full_name):
                raise Shape("the repository's full name was not OWNER/REPO")
            owner = _obj(body.get("owner"), "the repository's owner")
            private = _flag(body, "private", "the repository")
            visibility = _text(body, "visibility", "the repository", optional=True) or (
                "private" if private else "public")
            value = {"full_name": full_name, "visibility": visibility,
                     "default_branch": _text(body, "default_branch", "the repository"),
                     "owner": _text(owner, "login", "the repository's owner"),
                     "owner_type": _text(owner, "type", "the repository's owner"),
                     "fork": bool(_flag(body, "fork", "the repository", optional=True)),
                     "archived": bool(_flag(body, "archived", "the repository", optional=True))}
        except Shape as exc:
            self.settings["repository"] = _unread(setting, "unexpected",
                                                  f"the answer did not have the shape GitHub documents: {plain(exc)}")
            return False
        permissions = body.get("permissions")
        if isinstance(permissions, dict):
            self.viewer["repository_permissions"] = {k: v for k, v in sorted(permissions.items())
                                                     if isinstance(k, str) and isinstance(v, bool)}
        self.repository = value
        self.settings["repository"] = _read(value)
        # Later requests use the name GitHub gave back, so a renamed or moved repository is not asked for
        # through a redirect every time.
        self.base = f"/repos/{value['full_name']}"
        self.branches = list(dict.fromkeys([value["default_branch"], *self.extra_branches]))
        return True

    # -- 2 and 3. rulesets, and who may bypass them
    def read_rulesets(self) -> None:
        setting, bypass_setting = BY_KEY["rulesets"], BY_KEY["ruleset_bypass_actors"]
        listing = self.client.get_all(f"{self.base}/rulesets?includes_parents=true")
        if not listing.ok:
            self.settings["rulesets"] = _failed(setting, listing)
            self.settings["ruleset_bypass_actors"] = _unread(
                bypass_setting, "depends", "not requested: the rulesets themselves were not read")
            return
        rulesets, problems, bypass, bypass_problems, can_bypass = [], [], {}, [], {}
        is_admin = self.viewer.get("repository_permissions", {}).get("admin") is True
        for item in listing.data:
            ruleset_id = _number(_obj(item, "a ruleset in the list"), "id", "a ruleset in the list")
            if ruleset_id <= 0:
                raise Shape("a ruleset's id was not a positive number")
            label = f'ruleset {ruleset_id} "{plain(item.get("name", ""), 60)}"'
            detail = self.client.get(f"{self.base}/rulesets/{ruleset_id}?includes_parents=true")
            if not detail.ok:
                problems.append(_problem(label, detail))
                bypass_problems.append({"what": label, "reason_code": "depends",
                                        "reason": "the ruleset itself was not read"})
                continue
            body = _obj(detail.data, label)
            conditions = body.get("conditions")
            source_type = _text(body, "source_type", label, optional=True)
            rulesets.append({
                "id": ruleset_id, "name": _text(body, "name", label),
                "target": _text(body, "target", label, optional=True),
                "source_type": source_type, "source": _text(body, "source", label, optional=True),
                "enforcement": _text(body, "enforcement", label),
                "conditions": _json_safe(_obj(conditions, f"the conditions of {label}"), label)
                if conditions is not None else None,
                "rules": _rules(body.get("rules"), label)})
            if isinstance(body.get("current_user_can_bypass"), str):
                can_bypass[str(ruleset_id)] = body["current_user_can_bypass"]
            actors = body.get("bypass_actors")
            if actors is None:
                bypass_problems.append({
                    "what": label, "reason_code": "withheld",
                    "reason": "GitHub left the bypass list out of its answer, as it does for a caller without "
                              "write access to the ruleset"})
            elif not isinstance(actors, list):
                raise Shape(f"the bypass list of {label} was not a list")
            elif not actors and not (self.client.authenticated and is_admin and source_type == "Repository"):
                # An empty list is evidence that nobody can bypass only when the caller would have been shown
                # a full one. That is established here for one case: an administrator of the repository
                # reading a ruleset that belongs to the repository.
                bypass_problems.append({
                    "what": label, "reason_code": "withheld",
                    "reason": "GitHub returned an empty bypass list, but it shows the real list only to a "
                              "caller with write access to the ruleset, and this caller is not known to have "
                              "it; an empty list here is not evidence that nobody can bypass"})
            else:
                bypass[str(ruleset_id)] = sorted(
                    ({"actor_type": _text(_obj(a, "a bypass actor"), "actor_type", "a bypass actor"),
                      "actor_id": _number(a, "actor_id", "a bypass actor", optional=True),
                      "bypass_mode": _text(a, "bypass_mode", "a bypass actor", optional=True)} for a in actors),
                    key=lambda a: (a["actor_type"], a["actor_id"] or 0, a["bypass_mode"] or ""))
        rulesets.sort(key=lambda r: r["id"])
        total = len(listing.data)
        self.settings["rulesets"] = _outcome(setting, rulesets, problems, total)
        if can_bypass:
            self.viewer["can_bypass_rulesets"] = dict(sorted(can_bypass.items()))
        if total == 0:
            self.settings["ruleset_bypass_actors"] = _not_applicable("no ruleset applies to this repository")
        else:
            self.settings["ruleset_bypass_actors"] = _outcome(bypass_setting, bypass, bypass_problems, total)

    # -- 4, 5 and 6. the audited branches
    def read_branch_rules(self) -> None:
        value, problems = {}, []
        for branch in self.branches:
            answer = self.client.get_all(f"{self.base}/rules/branches/{quote(branch, safe='')}")
            if not answer.ok:
                problems.append(_problem(f"branch {plain(branch, 80)}", answer))
                continue
            rules = []
            for rule in answer.data:
                rule = _obj(rule, "a branch rule")
                parameters = rule.get("parameters")
                rules.append({"type": _text(rule, "type", "a branch rule"),
                              "ruleset_id": _number(rule, "ruleset_id", "a branch rule", optional=True),
                              "ruleset_source_type": _text(rule, "ruleset_source_type", "a branch rule", optional=True),
                              "ruleset_source": _text(rule, "ruleset_source", "a branch rule", optional=True),
                              "parameters": _json_safe(_obj(parameters, "a rule's parameters"), "a branch rule")
                              if parameters is not None else {}})
            value[branch] = sorted(rules, key=lambda r: (r["type"], r["ruleset_id"] or 0,
                                                          json.dumps(r["parameters"], sort_keys=True)))
        self.settings["branch_rules"] = _outcome(BY_KEY["branch_rules"], value, problems, len(self.branches))

    def read_branches(self) -> None:
        value, problems = {}, []
        for branch in self.branches:
            answer = self.client.get(f"{self.base}/branches/{quote(branch, safe='')}")
            if not answer.ok:
                problems.append(_problem(f"branch {plain(branch, 80)}", answer))
                continue
            body = _obj(answer.data, "the branch")
            entry = {"protected": _flag(body, "protected", "the branch"), "public_protection": None}
            protection = body.get("protection")
            if protection is not None:
                protection = _obj(protection, "the branch's protection")
                entry["public_protection"] = {
                    "enabled": _flag(protection, "enabled", "the branch's protection", optional=True),
                    "required_status_checks": _status_checks(protection.get("required_status_checks"))}
            value[branch] = entry
        self.settings["branches"] = _outcome(BY_KEY["branches"], value, problems, len(self.branches))

    def read_branch_protection(self) -> None:
        if self._skip_without_token("branch_protection"):
            return
        value, problems = {}, []
        for branch in self.branches:
            answer = self.client.get(f"{self.base}/branches/{quote(branch, safe='')}/protection")
            if answer.status == 404 and answer.message == "Branch not protected":
                # GitHub's reference documents the 404 but not this message; it is what GitHub sends to a
                # caller who may read branch protection when the branch has none. Any other 404 stays unread.
                value[branch] = None
            elif not answer.ok:
                problems.append(_problem(f"branch {plain(branch, 80)}", answer))
            else:
                value[branch] = _classic_protection(_obj(answer.data, "the branch protection"))
        self.settings["branch_protection"] = _outcome(BY_KEY["branch_protection"], value, problems,
                                                      len(self.branches))

    # -- 7 and 8. environments and their secrets
    def read_environments(self) -> None:
        setting = BY_KEY["environments"]
        listing = self.client.get_all(f"{self.base}/environments", key="environments")
        if not listing.ok:
            self.settings["environments"] = _failed(setting, listing)
            return
        value, problems = [], []
        for item in listing.data:
            env = _environment(_obj(item, "an environment"))
            policy = env["deployment_branch_policy"]
            if policy and policy["custom_branch_policies"]:
                answer = self.client.get_all(
                    f"{self.base}/environments/{quote(env['name'], safe='')}/deployment-branch-policies",
                    key="branch_policies")
                if answer.ok:
                    env["branch_policies"] = sorted(
                        ({"name": _text(_obj(p, "a branch policy"), "name", "a branch policy"),
                          "type": _text(p, "type", "a branch policy", optional=True)} for p in answer.data),
                        key=lambda p: (p["name"], p["type"] or ""))
                else:
                    problems.append(_problem(
                        f'the branch and tag patterns of environment "{plain(env["name"], 60)}"', answer))
            value.append(env)
        value.sort(key=lambda e: e["name"])
        if problems:
            self.settings["environments"] = {"status": "partial", "value": value, "problems": problems,
                                             "needs": setting.needs}
        else:
            self.settings["environments"] = _read(value)

    def read_environment_secrets(self) -> None:
        setting = BY_KEY["environment_secrets"]
        if self._skip_without_token("environment_secrets"):
            return
        environments = self.settings.get("environments", {})
        if environments.get("status") not in ("read", "partial"):
            self.settings["environment_secrets"] = _unread(
                setting, "depends", "not requested: the list of environments was not read")
            return
        names = [e["name"] for e in environments["value"]]
        if not names:
            self.settings["environment_secrets"] = _not_applicable("the repository has no environments")
            return
        value, problems = {}, []
        for name in names:
            answer = self.client.get_all(f"{self.base}/environments/{quote(name, safe='')}/secrets", key="secrets")
            if answer.ok:
                value[name] = _names(answer.data, "a secret")
            else:
                problems.append(_problem(f'environment "{plain(name, 60)}"', answer))
        self.settings["environment_secrets"] = _outcome(setting, value, problems, len(names))

    # -- 9 and 10. secrets every job can read
    def read_secret_names(self, key: str, path: str) -> None:
        if key == "organization_secrets" and self.repository["owner_type"] != "Organization":
            self.settings[key] = _not_applicable("the repository belongs to a user, not an organisation")
            return
        if self._skip_without_token(key):
            return
        answer = self.client.get_all(f"{self.base}{path}", key="secrets")
        self.settings[key] = _read(_names(answer.data, "a secret")) if answer.ok else _failed(BY_KEY[key], answer)

    # -- 11, 12 and 13. Actions settings
    def read_actions_permissions(self) -> None:
        setting = BY_KEY["actions_permissions"]
        if self._skip_without_token("actions_permissions"):
            return
        answer = self.client.get(f"{self.base}/actions/permissions")
        if not answer.ok:
            self.settings["actions_permissions"] = _failed(setting, answer)
            return
        body = _obj(answer.data, "the Actions permissions")
        value = {"enabled": _flag(body, "enabled", "the Actions permissions"),
                 "allowed_actions": _text(body, "allowed_actions", "the Actions permissions", optional=True),
                 "sha_pinning_required": _flag(body, "sha_pinning_required", "the Actions permissions",
                                               optional=True),
                 "selected_actions": None}
        if value["allowed_actions"] == "selected":
            selected = self.client.get(f"{self.base}/actions/permissions/selected-actions")
            if not selected.ok:
                self.settings["actions_permissions"] = {
                    "status": "partial", "value": value, "needs": setting.needs,
                    "problems": [_problem("the list of selected actions", selected)]}
                return
            chosen = _obj(selected.data, "the selected actions")
            patterns = chosen.get("patterns_allowed", [])
            if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
                raise Shape("the selected actions had no list of patterns")
            value["selected_actions"] = {
                "github_owned_allowed": _flag(chosen, "github_owned_allowed", "the selected actions", optional=True),
                "verified_allowed": _flag(chosen, "verified_allowed", "the selected actions", optional=True),
                "patterns_allowed": sorted(patterns)}
        self.settings["actions_permissions"] = _read(value)

    def read_workflow_permissions(self) -> None:
        if self._skip_without_token("workflow_permissions"):
            return
        answer = self.client.get(f"{self.base}/actions/permissions/workflow")
        if not answer.ok:
            self.settings["workflow_permissions"] = _failed(BY_KEY["workflow_permissions"], answer)
            return
        body = _obj(answer.data, "the workflow permissions")
        self.settings["workflow_permissions"] = _read({
            "default_workflow_permissions": _text(body, "default_workflow_permissions", "the workflow permissions"),
            "can_approve_pull_request_reviews": _flag(body, "can_approve_pull_request_reviews",
                                                      "the workflow permissions")})

    def read_fork_pull_requests(self) -> None:
        setting = BY_KEY["fork_pull_requests"]
        if self._skip_without_token("fork_pull_requests"):
            return
        answer = self.client.get(f"{self.base}/actions/permissions/fork-pr-contributor-approval")
        if not answer.ok:
            self.settings["fork_pull_requests"] = _failed(setting, answer)
            return
        value = {"approval_policy": _text(_obj(answer.data, "the fork approval policy"), "approval_policy",
                                          "the fork approval policy"),
                 "private_repository": None}
        if self.repository["visibility"] != "public":
            private = self.client.get(f"{self.base}/actions/permissions/fork-pr-workflows-private-repos")
            if not private.ok:
                self.settings["fork_pull_requests"] = {
                    "status": "partial", "value": value, "needs": setting.needs,
                    "problems": [_problem("the settings for fork pull requests on a private repository", private)]}
                return
            body = _obj(private.data, "the private fork settings")
            value["private_repository"] = {
                k: _flag(body, k, "the private fork settings")
                for k in ("run_workflows_from_fork_pull_requests", "send_write_tokens_to_workflows",
                          "send_secrets_and_variables", "require_approval_for_fork_pr_workflows")}
        self.settings["fork_pull_requests"] = _read(value)

    # -- 14. Actions policies
    def read_actions_policies(self) -> None:
        setting = BY_KEY["actions_policies"]
        if self._skip_without_token("actions_policies"):
            return
        listing = self.client.get_all(f"{self.base}/actions/policies?has_parents=true", key="policies")
        if not listing.ok:
            self.settings["actions_policies"] = _failed(setting, listing)
            return
        value, problems = [], []
        for item in listing.data:
            policy_id = _number(_obj(item, "a policy in the list"), "id", "a policy in the list")
            if policy_id <= 0:
                raise Shape("a policy's id was not a positive number")
            label = f'policy {policy_id} "{plain(item.get("name", ""), 60)}"'
            detail = self.client.get(f"{self.base}/actions/policies/{policy_id}")
            if not detail.ok:
                problems.append(_problem(label, detail))
                continue
            body = _obj(detail.data, label)
            conditions = body.get("conditions")
            value.append({"id": policy_id, "name": _text(body, "name", label),
                          "source_type": _text(body, "source_type", label, optional=True),
                          "source": _text(body, "source", label, optional=True),
                          "enforcement": _text(body, "enforcement", label),
                          "target": _text(body, "target", label, optional=True),
                          "conditions": _json_safe(_obj(conditions, f"the conditions of {label}"), label)
                          if conditions is not None else None,
                          "rules": _rules(body.get("rules"), label)})
        value.sort(key=lambda p: p["id"])
        self.settings["actions_policies"] = _outcome(setting, value, problems, len(listing.data))

    # -- 15. collaborators, as counts
    def read_collaborators(self) -> None:
        if self._skip_without_token("collaborators"):
            return
        answer = self.client.get_all(f"{self.base}/collaborators?affiliation=all")
        if not answer.ok:
            self.settings["collaborators"] = _failed(BY_KEY["collaborators"], answer)
            return
        counts = {name: 0 for name in ROLE_NAMES.values()}
        for item in answer.data:
            permissions = _obj(_obj(item, "a collaborator").get("permissions"), "a collaborator's permissions")
            role = next((r for r in ROLE_ORDER if permissions.get(r) is True), None)
            if role is None:
                raise Shape("a collaborator had no permission set to true")
            counts[ROLE_NAMES[role]] += 1
        self.settings["collaborators"] = _read({"total": len(answer.data), "by_role": counts})

    # -- everything
    def run(self) -> None:
        if not self.read_repository():
            for setting in SETTINGS[1:]:
                self.settings[setting.key] = _unread(
                    setting, "depends", "not requested: the repository itself could not be read")
            return
        self._guarded("rulesets", self.read_rulesets)
        self.settings.setdefault("ruleset_bypass_actors", _unread(
            BY_KEY["ruleset_bypass_actors"], "depends", "the rulesets themselves were not read"))
        self._guarded("branch_rules", self.read_branch_rules)
        self._guarded("branches", self.read_branches)
        self._guarded("branch_protection", self.read_branch_protection)
        self._guarded("environments", self.read_environments)
        self._guarded("environment_secrets", self.read_environment_secrets)
        self._guarded("repository_secrets", lambda: self.read_secret_names("repository_secrets", "/actions/secrets"))
        self._guarded("organization_secrets",
                      lambda: self.read_secret_names("organization_secrets", "/actions/organization-secrets"))
        self._guarded("actions_permissions", self.read_actions_permissions)
        self._guarded("workflow_permissions", self.read_workflow_permissions)
        self._guarded("fork_pull_requests", self.read_fork_pull_requests)
        self._guarded("actions_policies", self.read_actions_policies)
        self._guarded("collaborators", self.read_collaborators)


def _status_checks(value) -> dict | None:
    if value is None:
        return None
    value = _obj(value, "the required status checks")
    contexts = value.get("contexts", [])
    checks = value.get("checks", [])
    if not isinstance(contexts, list) or not all(isinstance(c, str) for c in contexts) or not isinstance(checks, list):
        raise Shape("the required status checks had no list of names")
    return {"strict": _flag(value, "strict", "the required status checks", optional=True),
            "enforcement_level": _text(value, "enforcement_level", "the required status checks", optional=True),
            "contexts": sorted(contexts),
            "checks": sorted(({"context": _text(_obj(c, "a required check"), "context", "a required check"),
                               "app_id": _number(c, "app_id", "a required check", optional=True)} for c in checks),
                             key=lambda c: (c["context"], c["app_id"] or 0))}


def _enabled(body: dict, key: str):
    value = body.get(key)
    return value["enabled"] if isinstance(value, dict) and isinstance(value.get("enabled"), bool) else None


def _who(value, what: str) -> dict | None:
    """The users, teams and apps of a classic allowance or restriction, by login or slug."""
    if value is None:
        return None
    value = _obj(value, what)
    out = {}
    for group, field_name in (("users", "login"), ("teams", "slug"), ("apps", "slug")):
        members = value.get(group, [])
        if not isinstance(members, list):
            raise Shape(f"{what} had no list of {group}")
        out[group] = sorted(_text(_obj(m, what), field_name, what) for m in members)
    return out


def _classic_protection(body: dict) -> dict:
    reviews = body.get("required_pull_request_reviews")
    if reviews is not None:
        reviews = _obj(reviews, "the required reviews")
        reviews = {
            "required_approving_review_count": _number(reviews, "required_approving_review_count",
                                                       "the required reviews", optional=True),
            "dismiss_stale_reviews": _flag(reviews, "dismiss_stale_reviews", "the required reviews", optional=True),
            "require_code_owner_reviews": _flag(reviews, "require_code_owner_reviews", "the required reviews",
                                                optional=True),
            "require_last_push_approval": _flag(reviews, "require_last_push_approval", "the required reviews",
                                                optional=True),
            "bypass_allowances": _who(reviews.get("bypass_pull_request_allowances"), "the review bypass allowances")}
    return {"required_status_checks": _status_checks(body.get("required_status_checks")),
            "required_pull_request_reviews": reviews,
            "enforce_admins": _enabled(body, "enforce_admins"),
            "restrictions": _who(body.get("restrictions"), "the push restrictions"),
            **{key: _enabled(body, key) for key in (
                "required_linear_history", "allow_force_pushes", "allow_deletions", "block_creations",
                "required_conversation_resolution", "required_signatures", "lock_branch")}}


def _environment(item: dict) -> dict:
    name = _text(item, "name", "an environment")
    what = f'environment "{plain(name, 60)}"'
    if "deployment_branch_policy" not in item:
        # Missing is not the same as null: null means any branch may deploy, and that must not be assumed.
        raise Shape(f"{what} had no deployment_branch_policy field")
    policy = item["deployment_branch_policy"]
    if policy is not None:
        policy = _obj(policy, f"the branch policy of {what}")
        policy = {"protected_branches": _flag(policy, "protected_branches", what),
                  "custom_branch_policies": _flag(policy, "custom_branch_policies", what)}
    rules = item.get("protection_rules", [])
    if not isinstance(rules, list):
        raise Shape(f"{what} had no list of protection rules")
    env = {"name": name, "deployment_branch_policy": policy, "branch_policies": None, "wait_timer": None,
           "required_reviewers": None, "other_protection_rules": []}
    for rule in rules:
        rule = _obj(rule, f"a protection rule of {what}")
        kind = _text(rule, "type", f"a protection rule of {what}")
        if kind == "wait_timer":
            env["wait_timer"] = _number(rule, "wait_timer", what)
        elif kind == "required_reviewers":
            reviewers = rule.get("reviewers", [])
            if not isinstance(reviewers, list):
                raise Shape(f"{what} had no list of reviewers")
            listed = []
            for entry in reviewers:
                entry = _obj(entry, f"a reviewer of {what}")
                who = _obj(entry.get("reviewer"), f"a reviewer of {what}")
                kind_of = _text(entry, "type", f"a reviewer of {what}")
                listed.append({"type": kind_of,
                               "name": _text(who, "slug" if kind_of == "Team" else "login", f"a reviewer of {what}"),
                               "id": _number(who, "id", f"a reviewer of {what}", optional=True)})
            env["required_reviewers"] = {
                "prevent_self_review": _flag(rule, "prevent_self_review", what, optional=True),
                "reviewers": sorted(listed, key=lambda r: (r["type"], r["name"]))}
        elif kind != "branch_policy":  # branch_policy only says that deployment_branch_policy is set
            env["other_protection_rules"].append(kind)
    env["other_protection_rules"].sort()
    if isinstance(item.get("can_admins_bypass"), bool):
        env["can_admins_bypass"] = item["can_admins_bypass"]
    return env


def take(client: Client, repository: str, branches: tuple[str, ...] = (), now: datetime | None = None) -> dict:
    """Read every setting in :data:`SETTINGS` for ``OWNER/REPO`` and return the snapshot."""
    if not OWNER_REPO.match(repository or ""):
        raise ValueError(f"expected OWNER/REPO, got {repository!r}")
    for branch in branches:
        if not branch or any(ch in branch for ch in "*?[\\ ~^:") or branch.startswith("-"):
            raise ValueError(f"--branch takes one branch name without wildcards, got {branch!r}")
    owner, repo = repository.split("/")
    reader = _Reader(client, owner, repo, tuple(branches))
    reader.run()
    full_name = reader.repository["full_name"] if reader.repository else repository
    snapshot = {
        "format": FORMAT,
        "repository": full_name,
        "api": client.api,
        "api_version": API_VERSION,
        "taken_at": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": f"obaaf {__version__}",
        "viewer": reader.viewer,
        "branches": reader.branches,
        "settings": {s.key: reader.settings[s.key] for s in SETTINGS},
        "requests": list(client.requests),
    }
    if full_name.lower() != repository.lower():
        snapshot["requested_as"] = repository
    return snapshot
