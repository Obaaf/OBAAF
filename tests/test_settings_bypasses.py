"""Ways past the settings rules (flagship slice 2d.2g), each a test.

Two reviewers that did not write the settings rules attacked them: reviewer A OBAAF-SET-001, 002, 003, 009, 010,
011, 012, 014 and 015 (166 attempts), reviewer B OBAAF-SET-004, 005, 006, 007, 008 and 013 (149 attempts). Every
attempt is recorded in docs/bypass-attempts.md under "2d.2g". Each test here is one class they found, built from
the hand-written admin-token recording (GitHub's REST reference examples) with one answer changed, and a small
tree of workflow files. The attempt numbers (A004, B072 ...) are the record's.
"""

import copy
import os
import time
import unittest
from pathlib import Path

from helpers import TempDir
from test_settings_audit import R, REPO, TOKEN, entry_for, recording, take

from obaaf.audit import rules, workflows
from obaaf.checker import workflow as wf_mod

ADMIN = recording("admin-token")
ACTIONS = 15368
PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
ENVS = f"{R}/environments?per_page=100"
BRANCH_RULES = f"{R}/rules/branches/main?per_page=100"
RULESET_42 = f"{R}/rulesets/42?includes_parents=true"
COLLABORATORS = f"{R}/collaborators?affiliation=all&per_page=100"
PROTECTION = f"{R}/branches/main/protection"
POLICIES = f"{R}/actions/policies?has_parents=true&per_page=100"
POLICY_7 = f"{R}/actions/policies/7"
ACTIONS_PERMISSIONS = f"{R}/actions/permissions"
WORKFLOW_PERMISSIONS = f"{R}/actions/permissions/workflow"
PR = "  pull_request:\n"
MATRIX_313 = "    strategy:\n      matrix:\n        python: ['3.13']\n"


# ---------------------------------------------------------------- recordings
def ok(path: str, body) -> dict:
    return {"path": path, "status": 200, "headers": {}, "body": body}


def changed(entries, path, fn):
    out = copy.deepcopy(entries)
    fn(entry_for(out, path)["body"])
    return out


def answer(entries, path, body, status=200):
    out = copy.deepcopy(entries)
    entry_for(out, path).update(status=status, body=body)
    return out


def drop(entries, prefix):
    return [e for e in entries if not e["path"].startswith(prefix)]


def environment(name, mode=None, reviewers=False):
    """One environment as GitHub's list gives it. mode: None (any branch), or "custom"."""
    rules_ = []
    if reviewers:
        rules_.append({"id": 1, "node_id": "x", "type": "required_reviewers",
                       "reviewers": [{"type": "User", "reviewer": {"login": "octocat", "id": 1}}]})
    policy = None
    if mode == "custom":
        policy = {"protected_branches": False, "custom_branch_policies": True}
        rules_.append({"id": 2, "node_id": "b", "type": "branch_policy"})
    return {"id": abs(hash(name)) % 10**8, "node_id": "e", "name": name, "protection_rules": rules_,
            "deployment_branch_policy": policy}


def with_environments(entries, envs, policies=None, secrets=None):
    """Replace the environments, their branch policies (name -> [(pattern, type)]) and their secrets."""
    policies, secrets = policies or {}, secrets or {}
    out = drop(entries, f"{R}/environments")
    out.append(ok(ENVS, {"total_count": len(envs), "environments": envs}))
    for name, patterns in policies.items():
        out.append(ok(f"{R}/environments/{name}/deployment-branch-policies?per_page=100",
                      {"total_count": len(patterns), "branch_policies": [
                          {"id": n, "node_id": "p", "name": pattern, "type": kind}
                          for n, (pattern, kind) in enumerate(patterns, 1)]}))
    for env in envs:
        names = secrets.get(env["name"], [])
        out.append(ok(f"{R}/environments/{env['name']}/secrets?per_page=100",
                      {"total_count": len(names), "secrets": [
                          {"name": n, "created_at": "2026-11-09T14:59:22Z", "updated_at": "2026-11-09T14:59:22Z"}
                          for n in names]}))
    return out


def extra_branch(entries, branch, found_rules=()):
    """GitHub's answers for an audited branch other than the default one: unprotected unless rules are given."""
    out = copy.deepcopy(entries)
    out.append(ok(f"{R}/rules/branches/{branch}?per_page=100", list(found_rules)))
    out.append(ok(f"{R}/branches/{branch}", {"name": branch, "protected": False, "protection": {
        "enabled": False, "required_status_checks": {"enforcement_level": "off", "contexts": [], "checks": []}}}))
    out.append({"path": f"{R}/branches/{branch}/protection", "status": 404, "headers": {},
                "body": {"message": "Branch not protected", "documentation_url": "x", "status": "404"}})
    return out


def rule(kind, parameters=None, ruleset=42):
    out = {"type": kind, "ruleset_source_type": "Repository", "ruleset_source": REPO, "ruleset_id": ruleset}
    if parameters is not None:
        out["parameters"] = parameters
    return out


def pr_rule(count=1):
    return rule("pull_request", {"required_approving_review_count": count, "dismiss_stale_reviews_on_push": True,
                                 "require_code_owner_review": False, "require_last_push_approval": False,
                                 "required_review_thread_resolution": False})


def checks_rule(*checks):
    return rule("required_status_checks", {"strict_required_status_checks_policy": False,
                                           "do_not_enforce_on_create": False,
                                           "required_status_checks": [{"context": c, "integration_id": i}
                                                                      for c, i in checks]})


def requiring(*names, entries=ADMIN):
    """main requires these checks from GitHub Actions, and one approval."""
    return changed(entries, BRANCH_RULES, lambda body: body.__setitem__(
        slice(None), [pr_rule(1), checks_rule(*[(n, ACTIONS) for n in names])]))


def people(entries, *roles):
    order = ("pull", "triage", "push", "maintain", "admin")
    return changed(entries, COLLABORATORS, lambda body: body.__setitem__(slice(None), [
        {"login": f"user{n}", "id": 100 + n, "type": "User",
         "permissions": {r: order.index(r) <= order.index(role) for r in order},
         "role_name": {"push": "write", "pull": "read"}.get(role, role)} for n, role in enumerate(roles)]))


def policy(pid, conditions, events):
    return {"id": pid, "name": f"policy {pid}", "target": "actions", "source_type": "Organization",
            "source": "example-studio", "enforcement": "active", "conditions": conditions,
            "rules": [{"type": "restrict_action_events", "parameters": {"allowed_events": list(events)}}]}


def with_policies(entries, policies):
    out = drop(entries, f"{R}/actions/policies")
    out.append(ok(POLICIES, {"total_count": len(policies), "policies": [
        {k: p[k] for k in ("id", "name", "target", "source_type", "source", "enforcement")} for p in policies]}))
    for p in policies:
        out.append(ok(f"{R}/actions/policies/{p['id']}", p))
    return out


# ---------------------------------------------------------------- workflows
def wf(on: str, jobs: str, permissions: str = "permissions:\n  contents: read\n") -> str:
    return f"name: W\non:\n{on}{permissions}jobs:\n{jobs}"


def job(name: str, body: str = "", steps: str | None = None) -> str:
    steps = steps if steps is not None else "      - run: echo hello\n"
    return f"  {name}:\n    runs-on: ubuntu-latest\n{body}    steps:\n{steps}"


def assess(entries, files: dict, config: str | None = None, branches=(), extra: dict | None = None) -> dict:
    snap, _ = take(entries, token=TOKEN, repository=REPO, branches=branches)
    with TempDir() as tmp:
        root = tmp / "repo"
        target = root / ".github" / "workflows"
        target.mkdir(parents=True)
        for name, text in files.items():
            if isinstance(text, tuple):         # ("symlink", text of the file it points at)
                (tmp / "elsewhere.yml").write_text(text[1], encoding="utf-8")
                (target / name).symlink_to(tmp / "elsewhere.yml")
            else:
                (target / name).write_text(text, encoding="utf-8")
        if config is not None:
            (root / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")
        for rel, text in (extra or {}).items():
            (root / rel).write_text(text, encoding="utf-8")
        return rules.evaluate(snap, workflows.read(root))


def of(found: dict, rule_id: str, state: str | None = None, subject: str = "") -> list[dict]:
    return [r for r in found["results"] if r["rule"] == rule_id and state in (None, r["state"])
            and subject in r["subject"]]


def status(found: dict, rule_id: str) -> str:
    return next(r["status"] for r in found["rules"] if r["id"] == rule_id)


def answered(found: dict, rule_id: str, subject: str = "") -> str:
    """"finding <severity>", "cannot-tell", or the rule's status when it said nothing about the subject."""
    results = of(found, rule_id, subject=subject)
    findings = sorted((r["severity"] for r in results if r["state"] == "finding"), key=rules.SEVERITIES.index)
    if findings:
        return f"finding {findings[0]}"
    if any(r["state"] == "cannot-tell" for r in results):
        return "cannot-tell"
    return status(found, rule_id)


# ---------------------------------------------------------------- reviewer A
class EnvironmentNamesTest(unittest.TestCase):
    """A004, A028, A048: an environment named by a number, in the mapping form or as text YAML 1.2 reads as
    one, was read the YAML 1.1 way and compared under the wrong name."""

    def test_a_number_in_either_form_is_cannot_tell(self):
        entries = with_environments(ADMIN, [environment("010")], secrets={"010": ["DEPLOY_KEY"]})
        for written in ("\n      name: 010", "0o10", "010", "\n      name: 0o10"):
            found = assess(entries, {"d.yml": wf("  push:\n", job("deploy", f"    environment: {written}\n"))})
            self.assertEqual(answered(found, "OBAAF-SET-001"), "cannot-tell", written)
            self.assertFalse(of(found, "OBAAF-SET-001", "finding"), written)

    def test_a_quoted_name_is_still_read(self):
        entries = with_environments(ADMIN, [environment("010")], secrets={"010": ["DEPLOY_KEY"]})
        found = assess(entries, {"d.yml": wf("  push:\n", job("deploy", "    environment: '010'\n"))})
        self.assertEqual(answered(found, "OBAAF-SET-001"), "finding high")

    def test_a_job_outsiders_start_with_such_a_name_is_cannot_tell(self):
        entries = with_environments(ADMIN, [environment("010")], secrets={"010": ["DEPLOY_KEY"]})
        files = {"d.yml": wf("  pull_request_target:\n", job("deploy", "    environment:\n      name: 010\n"))}
        self.assertEqual(answered(assess(entries, files), "OBAAF-SET-002"), "cannot-tell")


class AuditedBranchTest(unittest.TestCase):
    """A016, A017: an environment limited to a branch that was audited was trusted without its rules being
    read; a branch anyone with write access can push to limits nothing."""

    ENTRIES = with_environments(ADMIN, [environment("production", "custom")],
                                policies={"production": [("release", "branch")]},
                                secrets={"production": ["DEPLOY_KEY"]})
    FILES = {"d.yml": wf("  push:\n", job("deploy", "    environment: production\n"))}

    def test_an_unprotected_audited_branch_is_a_finding(self):
        found = assess(extra_branch(self.ENTRIES, "release"), self.FILES, branches=("release",))
        finding, = of(found, "OBAAF-SET-001", "finding")
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("no rule that requires an approval or limits who may push", finding["message"])

    def test_an_audited_branch_that_requires_an_approval_is_not(self):
        found = assess(extra_branch(self.ENTRIES, "release", [pr_rule(1)]), self.FILES, branches=("release",))
        self.assertEqual(answered(found, "OBAAF-SET-001"), "no-finding")

    def test_an_audited_branch_whose_rules_were_not_read_is_cannot_tell(self):
        entries = extra_branch(self.ENTRIES, "release")
        entry_for(entries, f"{R}/rules/branches/release?per_page=100").update(
            status=403, body={"message": "Resource not accessible by integration"})
        found = assess(entries, self.FILES, branches=("release",))
        self.assertEqual(answered(found, "OBAAF-SET-001"), "cannot-tell")

    def test_a_code_owner_review_is_cannot_tell(self):
        found_rule = rule("pull_request", {"required_approving_review_count": 0, "require_code_owner_review": True,
                                           "dismiss_stale_reviews_on_push": False, "require_last_push_approval": False,
                                           "required_review_thread_resolution": False}, ruleset=77)
        found = assess(extra_branch(self.ENTRIES, "release", [found_rule]), self.FILES, branches=("release",))
        self.assertEqual(answered(found, "OBAAF-SET-001"), "cannot-tell")

    def test_a_limit_on_who_may_push_or_a_required_deployment_is_cannot_tell(self):
        for found_rule in (rule("update", {"update_allows_fetch_and_merge": False}, ruleset=77),
                           rule("required_deployments", {"required_deployment_environments": ["prod"]}, ruleset=77)):
            found = assess(extra_branch(self.ENTRIES, "release", [found_rule]), self.FILES, branches=("release",))
            self.assertEqual(answered(found, "OBAAF-SET-001"), "cannot-tell", found_rule["type"])

    def test_reviewers_still_gate_it(self):
        entries = with_environments(ADMIN, [environment("production", "custom", reviewers=True)],
                                    policies={"production": [("release", "branch")]},
                                    secrets={"production": ["DEPLOY_KEY"]})
        found = assess(extra_branch(entries, "release"), self.FILES, branches=("release",))
        self.assertFalse(of(found, "OBAAF-SET-001", "finding"))


class BranchPatternEscapeTest(unittest.TestCase):
    """A037: `ma\\in` is `main` to Ruby's File.fnmatch, which GitHub's reference names; a backslash makes a
    policy a pattern."""

    def test_a_backslash_is_a_pattern(self):
        entries = with_environments(ADMIN, [environment("production", "custom")],
                                    policies={"production": [("ma\\in", "branch")]},
                                    secrets={"production": ["DEPLOY_KEY"]})
        found = assess(entries, {"d.yml": wf("  pull_request_target:\n", job("deploy", "    environment: production\n"))})
        self.assertEqual(answered(found, "OBAAF-SET-002"), "finding high")
        self.assertIn("rests on a pattern", of(found, "OBAAF-SET-002", "finding")[0]["message"])


class OpenCopyOfAProtectedSecretTest(unittest.TestCase):
    """A053: a protected secret also stored in another environment that any branch may use and that asks
    nobody is a copy any job can reach by naming that environment."""

    def test_the_open_copy_is_a_finding(self):
        entries = with_environments(ADMIN, [environment("production", "custom"), environment("staging")],
                                    policies={"production": [("main", "branch")]},
                                    secrets={"production": ["DEPLOY_KEY"], "staging": ["DEPLOY_KEY"]})
        entries = changed(entries, f"{R}/actions/secrets?per_page=100",
                          lambda body: body.update(total_count=0, secrets=[]))
        found = assess(entries, {"d.yml": wf("  push:\n", job("deploy", "    environment: production\n"))},
                       config="protected_secrets:\n  DEPLOY_KEY: production\n")
        finding, = of(found, "OBAAF-SET-003", "finding", 'secret "DEPLOY_KEY"')
        self.assertEqual(finding["severity"], "high")
        self.assertIn('also stored in the environment "staging"', finding["message"])

    def test_a_copy_behind_an_all_star_pattern_is_open_too(self):
        entries = with_environments(ADMIN, [environment("production", "custom"), environment("staging", "custom")],
                                    policies={"production": [("main", "branch")], "staging": [("**", "branch")]},
                                    secrets={"production": ["DEPLOY_KEY"], "staging": ["DEPLOY_KEY"]})
        entries = changed(entries, f"{R}/actions/secrets?per_page=100",
                          lambda body: body.update(total_count=0, secrets=[]))
        found = assess(entries, {"d.yml": wf("  push:\n", job("deploy", "    environment: production\n"))},
                       config="protected_secrets:\n  DEPLOY_KEY: production\n")
        self.assertEqual(answered(found, "OBAAF-SET-003", 'secret "DEPLOY_KEY"'), "finding high")


class PolicyRepositoryConditionsTest(unittest.TestCase):
    """A076, A108: an Actions policy's repository conditions were accepted and ignored."""

    FILES = {"t.yml": wf("  pull_request_target:\n", job("t"))}

    def conditions(self, repositories):
        return {"workflow_path": {"include": ["~ALL"], "exclude": []}, "repository_name": repositories}

    def test_a_policy_that_leaves_this_repository_out_does_not_count_as_allowing(self):
        entries = with_policies(ADMIN, [policy(9, self.conditions({"include": ["~ALL"], "exclude": ["game"]}),
                                               ["pull_request_target"])])
        self.assertEqual(answered(assess(entries, self.FILES), "OBAAF-SET-010"), "cannot-tell")

    def test_a_policy_for_another_repository_does_not_count_as_blocking(self):
        entries = with_policies(ADMIN, [policy(9, self.conditions({"include": ["other-repo"], "exclude": []}),
                                               ["push"])])
        self.assertEqual(answered(assess(entries, self.FILES), "OBAAF-SET-009"), "cannot-tell")

    def test_a_policy_for_every_repository_still_applies(self):
        entries = with_policies(ADMIN, [policy(9, self.conditions({"include": ["~ALL"], "exclude": []}),
                                               ["push"])])
        self.assertEqual(answered(assess(entries, self.FILES), "OBAAF-SET-009"), "finding medium")


class ReusableWorkflowTokenTest(unittest.TestCase):
    """A144, A145: a called job gets its caller's token, and a caller passes on a token the called workflow
    narrows ("can be only downgraded"); neither gets the repository's default."""

    WRITE = answer(ADMIN, WORKFLOW_PERMISSIONS, {"default_workflow_permissions": "write",
                                                 "can_approve_pull_request_reviews": False})

    def test_a_called_job_whose_callers_declare_permissions(self):
        files = {"caller.yml": wf("  push:\n", "  call:\n    permissions:\n      contents: read\n"
                                              "    uses: ./.github/workflows/called.yml\n"),
                 "called.yml": wf("  workflow_call:\n", job("inner"), permissions="")}
        self.assertEqual(answered(assess(self.WRITE, files), "OBAAF-SET-012"), "not-applicable")

    def test_a_caller_whose_called_workflow_declares_permissions(self):
        files = {"caller.yml": wf("  push:\n", "  call:\n    uses: ./.github/workflows/called.yml\n", permissions=""),
                 "called.yml": wf("  workflow_call:\n", job("inner"))}
        self.assertEqual(answered(assess(self.WRITE, files), "OBAAF-SET-012"), "not-applicable")

    def test_a_called_job_with_a_caller_that_declares_nothing_is_still_reported(self):
        files = {"caller.yml": wf("  push:\n", "  call:\n    uses: ./.github/workflows/called.yml\n", permissions=""),
                 "called.yml": wf("  workflow_call:\n", job("inner"), permissions="")}
        found = assess(self.WRITE, files)
        self.assertEqual(sorted(r["subject"] for r in of(found, "OBAAF-SET-012", "finding")),
                         ["workflow .github/workflows/called.yml", "workflow .github/workflows/caller.yml"])

    def test_a_workflow_nothing_here_calls_is_still_reported(self):
        files = {"called.yml": wf("  workflow_call:\n", job("inner"), permissions="")}
        self.assertEqual(answered(assess(self.WRITE, files), "OBAAF-SET-012"), "finding medium")


class PinningTest(unittest.TestCase):
    """A182, A183, A186, A188: a pin is 40 lower-case hex digits and nothing else; `$/` is local; GitHub's
    lockfile may pin a tag."""

    @staticmethod
    def uses(target):
        return {"u.yml": wf("  push:\n", job("u", steps=f"      - uses: {target}\n"))}

    def test_a_64_digit_ref_and_a_sha_with_a_line_break_are_not_pins(self):
        for target in ("actions/checkout@" + "a" * 64, f'"{PIN}\\n"'):
            self.assertEqual(answered(assess(ADMIN, self.uses(target)), "OBAAF-SET-015"), "finding medium", target)

    def test_a_self_repository_action_is_local(self):
        found = assess(ADMIN, {"u.yml": wf("  push:\n", job("u", steps=f"      - uses: {PIN}\n"
                                                                       "      - uses: $/.github/actions/setup\n"))})
        self.assertEqual(answered(found, "OBAAF-SET-015"), "no-finding")

    def test_a_lockfile_makes_a_tag_cannot_tell(self):
        found = assess(ADMIN, self.uses("actions/checkout@v4"),
                       extra={".github/workflows/actions.lock": "version: 1\n"})
        self.assertEqual(answered(found, "OBAAF-SET-015"), "cannot-tell")


# ---------------------------------------------------------------- reviewer B
class BypassActorsTest(unittest.TestCase):
    """B002, B030, B011, B017."""

    @staticmethod
    def bypass(entries, actors, can="never"):
        def change(body):
            body["bypass_actors"] = [{"actor_id": i, "actor_type": t, "bypass_mode": m} for t, i, m in actors]
            body["current_user_can_bypass"] = can
        return changed(entries, RULESET_42, change)

    def test_the_actions_app_as_a_bypass_actor_holds_nobody(self):
        entries = people(self.bypass(ADMIN, [("Integration", ACTIONS, "always")]), "admin", "push", "push")
        finding, = of(assess(entries, {"ci.yml": wf(PR, job("test", MATRIX_313))}), "OBAAF-SET-004", "finding")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("GitHub Actions app", finding["message"])

    def test_another_app_is_still_medium(self):
        entries = people(self.bypass(ADMIN, [("Integration", 999, "always")]), "admin", "push", "push")
        finding, = of(assess(entries, {"ci.yml": wf(PR, job("test", MATRIX_313))}), "OBAAF-SET-004", "finding")
        self.assertEqual(finding["severity"], "medium")

    def test_exempt_is_the_wider_mode(self):
        entries = changed(ADMIN, RULESET_42, lambda body: (body.pop("bypass_actors", None),
                                                           body.update(current_user_can_bypass="exempt")))
        found = assess(entries, {"ci.yml": wf(PR, job("test", MATRIX_313))})
        severities = {r["severity"] for r in of(found, "OBAAF-SET-004", "finding", "ruleset 42")}
        self.assertNotIn("low", severities)
        self.assertTrue(severities)

    def test_classic_protection_that_requires_nothing_is_not_reported(self):
        body = {"url": "x", "enforce_admins": {"enabled": False}, "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False}}
        entries = people(answer(changed(ADMIN, BRANCH_RULES, lambda b: b.__setitem__(slice(None), [])),
                                PROTECTION, body), "admin", "push")
        found = assess(entries, {"ci.yml": wf(PR, job("test", MATRIX_313))})
        self.assertFalse(of(found, "OBAAF-SET-004", "finding", "classic"))


class CheckNamesTest(unittest.TestCase):
    """B072 to B076, B095, B142: a job name or a matrix value that this reader (YAML 1.1) and GitHub's (YAML
    1.2) read differently, or a `name` that is not text, is not a check name the audit can vouch for."""

    def test_a_name_that_is_not_text_or_reads_two_ways(self):
        for written, required in (("0", "build"), ("false", "build"), ("012", "10"), ("12:30", "750"),
                                  ("0o10", "0o10")):
            files = {"ci.yml": wf(PR, job("build", f"    name: {written}\n"))}
            self.assertEqual(answered(assess(requiring(required), files), "OBAAF-SET-006"), "cannot-tell", written)

    def test_a_matrix_value_that_reads_two_ways(self):
        for value, required in (("08", "test (08)"), ("08", "test (8)"), ("012", "test (10)"),
                                ("0o10", "test (0o10)")):
            files = {"ci.yml": wf(PR, job("test", f"    strategy:\n      matrix:\n        day: [{value}]\n"))}
            self.assertEqual(answered(assess(requiring(required), files), "OBAAF-SET-006"), "cannot-tell", value)

    def test_plain_and_quoted_values_are_still_read(self):
        for value, required in (("18", "test (18)"), ("'08'", "test (08)"), ("ubuntu", "test (ubuntu)")):
            files = {"ci.yml": wf(PR, job("test", f"    strategy:\n      matrix:\n        v: [{value}]\n"))}
            self.assertEqual(answered(assess(requiring(required), files), "OBAAF-SET-006"), "no-finding", value)
        files = {"ci.yml": wf(PR, job("b", "    name: '8'\n"))}
        self.assertEqual(answered(assess(requiring("8"), files), "OBAAF-SET-006"), "no-finding")


class FilesGitHubMayReadOtherwiseTest(unittest.TestCase):
    """B081 to B084: a file whose name GitHub may not run, a symbolic link, and a file the checker reads with
    a merge key are never counted as reporting a check."""

    def test_each_is_cannot_tell(self):
        text = wf(PR, job("build"))
        merged = ("name: W\non:\n  pull_request:\npermissions:\n  contents: read\n"
                  "x-base: &base\n  name: build\n  runs-on: ubuntu-latest\n"
                  "jobs:\n  b:\n    <<: *base\n    steps:\n      - run: echo hi\n")
        merged_id = ("name: W\non:\n  pull_request:\npermissions:\n  contents: read\n"
                     "x-base: &base\n  runs-on: ubuntu-latest\n"
                     "jobs:\n  build:\n    <<: *base\n    steps:\n      - run: echo hi\n")
        for files in ({"ci.YML": text}, {".yml": text}, {"ci.yml": ("symlink", text)}, {"ci.yml": merged},
                      {"ci.yml": merged_id}):
            found = assess(requiring("build"), files)
            self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell", list(files))

    def test_files_github_refuses_for_a_step_or_a_job(self):
        for extra in ("      - echo hi\n", "      - name: nothing\n", "      - parallel: 5\n"):
            body = job("build", steps="      - run: echo\n" + extra)
            found = assess(requiring("build"), {"ci.yml": wf(PR, body)})
            self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell", extra)
        found = assess(requiring("build"), {"ci.yml": wf(PR, job("build") + "  other:\n    uses: 5\n")})
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")

    def test_a_problem_that_quotes_the_harmless_words_still_counts(self):
        for text in ("name: W\non: [pull_request, 'gives the same input twice']\npermissions: {}\njobs:\n" + job("build"),
                     wf(PR, job("build"), permissions="permissions:\n  contents: 'gives the same input twice'\n")):
            self.assertEqual(answered(assess(requiring("build"), {"ci.yml": text}), "OBAAF-SET-006"), "cannot-tell")

    def test_a_problem_about_a_steps_input_names_does_not_count(self):
        steps = "      - uses: " + PIN + "\n        with:\n          ref: a\n          REF: b\n"
        found = assess(requiring("build"), {"ci.yml": wf(PR, job("build", steps=steps))})
        self.assertEqual(answered(found, "OBAAF-SET-006"), "no-finding")

    def test_a_caller_of_such_a_file_and_a_linked_directory(self):
        caller = wf(PR, "  ci:\n    uses: ./.github/workflows/r.yml\n")
        callee = wf("  workflow_call:\n", job("build"))
        found = assess(requiring("ci / build"), {"ci.yml": caller, "r.yml": ("symlink", callee)})
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")
        snap, _ = take(requiring("build"), token=TOKEN, repository=REPO)
        with TempDir() as tmp:
            real = tmp / "real"
            real.mkdir()
            (real / "ci.yml").write_text(wf(PR, job("build")), encoding="utf-8")
            (tmp / "repo" / ".github").mkdir(parents=True)
            (tmp / "repo" / ".github" / "workflows").symlink_to(real)
            found = rules.evaluate(snap, workflows.read(tmp / "repo"))
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")

    def test_an_ordinary_file_still_reports(self):
        self.assertEqual(answered(assess(requiring("build"), {"ci.yml": wf(PR, job("build"))}), "OBAAF-SET-006"),
                         "no-finding")


class ClassicChecksTest(unittest.TestCase):
    """B098, B125: a classic rule that requires one check from two apps keeps both."""

    def test_both_apps_are_kept(self):
        protection = {"url": "x", "enforce_admins": {"enabled": True},
                      "required_status_checks": {"strict": False, "contexts": ["build"], "checks": [
                          {"context": "build", "app_id": 999}, {"context": "build", "app_id": ACTIONS}]}}
        entries = answer(changed(ADMIN, BRANCH_RULES, lambda b: b.__setitem__(slice(None), [pr_rule(1)])),
                         PROTECTION, protection)
        found = assess(entries, {"ci.yml": wf(PR, job("build"))})
        result, = of(found, "OBAAF-SET-006", subject='"build"')
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("999", result["message"])


class WhenACheckReportsTest(unittest.TestCase):
    """B103, B104, B106: a job its `if:` skips still reports (as passed); pull_request_target runs on the
    default branch's latest commit."""

    ON = "  push:\n    branches: [main]\n  pull_request:\n"

    def test_a_plain_job_skipped_on_pull_requests_still_reports(self):
        for jobs in (job("test", "    if: github.event_name == 'push'\n"),
                     job("gate", "    if: github.event_name == 'push'\n") + job("test", "    needs: gate\n")):
            found = assess(requiring("test"), {"ci.yml": wf(self.ON, jobs)})
            self.assertEqual(answered(found, "OBAAF-SET-007"), "no-finding")

    def test_a_skipped_matrix_job_or_caller_reports_its_bare_name(self):
        # `if:` is decided before the matrix expands or the called workflow runs (the review of slice 2d.2g).
        found = assess(ADMIN, {"ci.yml": wf(self.ON, job("test", MATRIX_313 + "    if: github.event_name == 'push'\n"))})
        self.assertEqual(answered(found, "OBAAF-SET-007"), "finding medium")
        files = {"ci.yml": wf(self.ON, "  ci:\n    if: github.event_name == 'push'\n    uses: ./.github/workflows/r.yml\n"),
                 "r.yml": wf("  workflow_call:\n", job("test"))}
        self.assertEqual(answered(assess(requiring("ci / test"), files), "OBAAF-SET-007"), "finding medium")

    def test_pull_request_target_is_cannot_tell(self):
        found = assess(ADMIN, {"ci.yml": wf("  pull_request_target:\n", job("test", MATRIX_313))})
        self.assertEqual(answered(found, "OBAAF-SET-007"), "cannot-tell")
        self.assertIn("pull_request_target", of(found, "OBAAF-SET-007", "cannot-tell")[0]["message"])

    def test_a_pull_request_target_filtered_by_a_pattern_is_cannot_tell(self):
        files = {"ci.yml": wf(PR, job("test", MATRIX_313)),
                 "sec.yml": wf("  pull_request_target:\n    branches: ['release/**']\n", job("sec"))}
        self.assertEqual(answered(assess(ADMIN, files), "OBAAF-SET-008", "sec.yml#sec"), "cannot-tell")

    def test_an_unrequired_pull_request_target_check_is_still_a_finding(self):
        files = {"ci.yml": wf(PR, job("test", MATRIX_313)), "scan.yml": wf("  pull_request_target:\n", job("scan"))}
        self.assertEqual(answered(assess(ADMIN, files), "OBAAF-SET-008", "scan.yml#scan"), "finding medium")


class SettingsThatStopEveryRunTest(unittest.TestCase):
    """B152 to B155: Actions turned off, a workflow GitHub refuses for an unpinned action, and an enforced
    policy that blocks pull_request all stop the job that reports a required check."""

    CI = {"ci.yml": wf(PR, job("test", MATRIX_313))}

    def test_actions_turned_off(self):
        found = assess(answer(ADMIN, ACTIONS_PERMISSIONS, {"enabled": False}), self.CI)
        finding, = of(found, "OBAAF-SET-006", "finding")
        self.assertIn("GitHub Actions is turned off", finding["message"])

    def test_a_workflow_refused_for_an_unpinned_action(self):
        steps = "      - uses: actions/checkout@v4\n      - run: echo\n"
        found = assess(ADMIN, {"ci.yml": wf(PR, job("test", MATRIX_313, steps=steps))})
        finding, = of(found, "OBAAF-SET-006", "finding")
        self.assertIn("GitHub refuses it", finding["message"])

    def test_a_policy_that_blocks_pull_request(self):
        def change(body):
            body["conditions"] = {"workflow_path": {"include": [".github/workflows/ci.yml"], "exclude": []}}
            body["rules"] = [{"type": "restrict_action_events", "parameters": {"allowed_events": ["push"]}}]
        files = {"ci.yml": wf("  pull_request:\n  push:\n    branches: [main]\n", job("test", MATRIX_313))}
        self.assertEqual(answered(assess(changed(ADMIN, POLICY_7, change), files), "OBAAF-SET-007"), "finding medium")

    def test_a_refused_workflow_beside_a_token_that_may_write_checks_is_cannot_tell(self):
        steps = "      - uses: actions/checkout@v4\n      - run: echo\n"
        files = {"ci.yml": wf(PR, job("test", MATRIX_313, steps=steps)),
                 "other.yml": wf("  push:\n", job("o"), permissions="permissions:\n  checks: write\n")}
        self.assertEqual(answered(assess(ADMIN, files), "OBAAF-SET-006"), "cannot-tell")

    def test_a_workflow_github_may_refuse_is_never_counted_as_reporting(self):
        steps = "      - uses: actions/checkout@v4\n      - run: echo\n"
        found = assess(ADMIN, {"ci.yml": wf(PR, job("test", MATRIX_313, steps=steps))},
                       extra={".github/workflows/actions.lock": "version: 1\n"})
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")

    def test_a_policy_the_audit_does_not_understand_leaves_the_checks_cannot_tell(self):
        def change(body):
            body["conditions"] = {"workflow_path": {"include": ["~ALL"], "exclude": []},
                                  "repository_name": {"include": ["game"], "exclude": []}}
            body["rules"] = [{"type": "restrict_action_events", "parameters": {"allowed_events": ["push"]}}]
        found = assess(changed(ADMIN, POLICY_7, change), self.CI)
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")
        self.assertEqual(status(found, "OBAAF-SET-007"), "not-applicable")

    def test_only_some_owners_actions_allowed(self):
        # GitHub calls the value "Allow OWNER actions and reusable workflows"; which owners is not matched.
        entries = answer(ADMIN, ACTIONS_PERMISSIONS, {"enabled": True, "allowed_actions": "local_only"})
        found = assess(entries, {"ci.yml": wf(PR, job("test", MATRIX_313, steps=f"      - uses: {PIN}\n"))})
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")

    def test_a_remote_reusable_workflow_under_local_only(self):
        entries = answer(ADMIN, ACTIONS_PERMISSIONS, {"enabled": True, "allowed_actions": "local_only"})
        files = {"ci.yml": wf(PR, job("lint") + "  scan:\n    uses: someone-else/tools/.github/workflows/scan.yml@"
                              + "a" * 40 + "\n")}
        self.assertEqual(answered(assess(requiring("lint", entries=entries), files), "OBAAF-SET-006"), "cannot-tell")

    def test_pinning_is_weighed_before_local_only(self):
        entries = answer(ADMIN, ACTIONS_PERMISSIONS, {"enabled": True, "allowed_actions": "local_only",
                                                      "sha_pinning_required": True})
        found = assess(entries, {"ci.yml": wf(PR, job("test", MATRIX_313, steps="      - uses: actions/checkout@v4\n"))})
        self.assertEqual(answered(found, "OBAAF-SET-006"), "finding medium")

    def test_a_caller_of_a_missing_workflow(self):
        files = {"ci.yml": wf(PR, job("lint") + "  ci:\n    uses: ./.github/workflows/r.yml\n")}
        self.assertEqual(answered(assess(requiring("lint"), files), "OBAAF-SET-006"), "cannot-tell")

    def test_a_caller_of_a_refused_workflow(self):
        files = {"ci.yml": wf(PR, "  ci:\n    uses: ./.github/workflows/r.yml\n"),
                 "r.yml": wf("  workflow_call:\n", job("test", steps="      - uses: actions/checkout@v4\n"))}
        found = assess(requiring("ci / test"), files)
        self.assertEqual(answered(found, "OBAAF-SET-006"), "cannot-tell")

    def test_a_policy_that_allows_every_event_the_file_uses_or_only_evaluates(self):
        for enforcement, events in (("active", ["pull_request", "push"]), ("evaluate", ["push"])):
            def change(body, enforcement=enforcement, events=events):
                body["enforcement"] = enforcement
                body["conditions"] = {"workflow_path": {"include": ["~ALL"], "exclude": []},
                                      "repository_name": {"include": ["~ALL"], "exclude": ["legacy"]}}
                body["rules"] = [{"type": "restrict_action_events", "parameters": {"allowed_events": events}}]
            found = assess(changed(ADMIN, POLICY_7, change), self.CI)
            self.assertEqual(answered(found, "OBAAF-SET-006"), "no-finding", enforcement)

    def test_unread_settings_are_named_on_the_rules_line_whatever_its_answers(self):
        entries = answer(ADMIN, ACTIONS_PERMISSIONS, {"message": "Must have admin rights"}, status=403)
        for found, wanted in ((assess(entries, self.CI), "no-finding"),
                              (assess(requiring("ghost", "test (3.13)", entries=entries), self.CI), "findings")):
            entry = next(r for r in found["rules"] if r["id"] == "OBAAF-SET-006")
            self.assertEqual(entry["status"], wanted)
            self.assertIn("every workflow file was taken as running", entry["assumed"])


class SharedCheckNamesTest(unittest.TestCase):
    """B132, B133: two jobs that report one check name; GitHub weighs one check run of a name."""

    def test_two_jobs_with_one_name(self):
        for files in ({"a.yml": wf(PR, job("test", MATRIX_313)), "b.yml": wf(PR, job("slow", "    name: test\n" + MATRIX_313))},
                      {"ci.yml": wf(PR, job("test", MATRIX_313) + job("t2", "    name: test\n" + MATRIX_313))}):
            self.assertEqual(answered(assess(ADMIN, files), "OBAAF-SET-008"), "cannot-tell", list(files))

    def test_two_jobs_with_one_name_nobody_requires_are_still_findings(self):
        files = {"ci.yml": wf(PR, job("test", MATRIX_313)),
                 "a.yml": wf(PR, job("lint")), "b.yml": wf(PR, job("l2", "    name: lint\n"))}
        found = assess(ADMIN, files)
        self.assertEqual(len(of(found, "OBAAF-SET-008", "finding")), 2)

    def test_a_job_with_the_same_name_that_never_runs_on_pull_requests_does_not_count(self):
        files = {"a.yml": wf(PR, job("test", MATRIX_313)),
                 "b.yml": wf("  push:\n    tags: ['v*']\n", job("slow", "    name: test\n" + MATRIX_313))}
        self.assertEqual(answered(assess(ADMIN, files), "OBAAF-SET-008"), "no-finding")


class CalledAdvisoryJobTest(unittest.TestCase):
    """B135: a called workflow's job with `continue-on-error: true` reports as passed."""

    def test_it_is_not_asked_to_be_required(self):
        files = {"ci.yml": wf(PR, "  ci:\n    uses: ./.github/workflows/r.yml\n"),
                 "r.yml": wf("  workflow_call:\n", job("test") + job("lint", "    continue-on-error: true\n"))}
        self.assertEqual(answered(assess(requiring("ci / test"), files), "OBAAF-SET-008"), "no-finding")


class TimeTest(unittest.TestCase):
    """A200, A201, B150, B151: following `needs` afresh on every path doubled the time with each job; the
    names of called matrix jobs were all written out before the cap dropped them."""

    def test_a_ladder_of_needs_is_read_quickly(self):
        lines = ["name: W", "on: [push, pull_request]", "permissions: {}", "jobs:"]
        for n in range(40):
            needs = f"    needs: [{', '.join(f'j{k}' for k in range(n))}]\n" if n else ""
            lines.append(f"  j{n}:\n    runs-on: ubuntu-latest\n{needs}    steps:\n      - run: echo")
        text = "\n".join(lines) + "\n"
        start = time.monotonic()
        found = assess(ADMIN, {"ci.yml": text})
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(status(found, "OBAAF-SET-002"), "not-applicable")
        workflow = wf_mod.parse(".github/workflows/ci.yml", text)
        self.assertEqual(workflow.jobs["j39"].triggers(), {"push", "pull_request"})

    def test_a_long_chain_does_not_exhaust_the_stack(self):
        lines = ["name: W", "on: push", "permissions: {}", "jobs:"]
        for n in range(1500):
            needs = f"    needs: j{n - 1}\n" if n else ""
            lines.append(f"  j{n}:\n    runs-on: ubuntu-latest\n{needs}    steps:\n      - run: echo")
        workflow = wf_mod.parse(".github/workflows/ci.yml", "\n".join(lines) + "\n")
        self.assertEqual(workflow.jobs["j1499"].triggers(), {"push"})

    def test_a_cycle_of_needs_narrows_nothing(self):
        text = ("on: [push, pull_request]\npermissions: {}\njobs:\n"
                "  a:\n    runs-on: ubuntu-latest\n    needs: b\n    if: github.event_name == 'push'\n    steps:\n      - run: x\n"
                "  b:\n    runs-on: ubuntu-latest\n    needs: a\n    steps:\n      - run: x\n")
        workflow = wf_mod.parse(".github/workflows/ci.yml", text)
        self.assertTrue(workflow.needs_cycle())
        self.assertEqual(workflow.jobs["b"].triggers(), {"push", "pull_request"})

    def test_many_called_matrix_names_are_counted_before_they_are_written(self):
        matrix = ("    strategy:\n      matrix:\n        a: [" + ",".join(f"a{i}" for i in range(16)) + "]\n        b: ["
                  + ",".join(f"b{i}" for i in range(16)) + "]\n")
        callers = "".join(f"  c{k}:\n{matrix}    uses: ./.github/workflows/r.yml\n" for k in range(4))
        inner = "".join(f"  i{j}:\n    runs-on: ubuntu-latest\n{matrix}    steps:\n      - run: echo\n" for j in range(60))
        files = {"ci.yml": "on: pull_request\npermissions: {}\njobs:\n" + callers,
                 "r.yml": "on: workflow_call\npermissions: {}\njobs:\n" + inner}
        start = time.monotonic()
        found = assess(requiring("build"), files)
        self.assertLess(time.monotonic() - start, 2)
        # Nothing can report "build": the callers' checks are all named "c<k> (...) / ...".
        self.assertEqual(answered(found, "OBAAF-SET-006"), "finding medium")


if __name__ == "__main__":
    unittest.main()
