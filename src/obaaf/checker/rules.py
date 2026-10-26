"""The OBAAF checker rules. Metadata (title, severity, fix) lives in data/rules.yaml."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from obaaf.catalog import Catalog
from obaaf.checker import repo as repo_checks
from obaaf.checker.workflow import (
    FULL_SHA_RE, PR_FETCH_CMD_RE, PR_HEAD_REF_RE, PR_TRIGGERS, PRIVILEGED_UNTRUSTED_TRIGGERS, UNTRUSTED_FIELDS_RE,
    UNTRUSTED_TRIGGERS, Job, Step, Workflow, expressions, runs_after_failure,
)

PLACEHOLDER_SHA = "0" * 40
PLACEHOLDER_RE = re.compile(r"OBAAF_OWNER|@" + PLACEHOLDER_SHA)


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str
    job: str | None = None
    step: str | None = None
    suppressed: str | None = None
    scope: str | None = None   # what `job` names: a GitHub Actions job (None) or a Jenkins stage ("stage")

    def sort_key(self) -> tuple:
        order = {"high": 0, "medium": 1, "low": 2}
        return (self.path, self.line, order.get(self.severity, 3), self.rule)


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def _falsy(value) -> bool:
    return str(value).strip().lower() in ("false", "0", "no")


def _fmt_triggers(events: set[str]) -> str:
    return ", ".join(sorted(events))


def normalize_expression(expr: str) -> str:
    """Lower-case an expression and turn index syntax (github.event['issue']) into dots.

    Contexts and property names are case-insensitive in GitHub Actions expressions.
    """
    out = re.sub(r"\[\s*'([^']*)'\s*\]", r".\1", expr)
    out = re.sub(r'\[\s*"([^"]*)"\s*\]', r".\1", out)
    out = re.sub(r"\s*\.\s*", ".", out)
    return out.lower()


# toJSON of these serializes text that outsiders write.
_UNTRUSTED_OBJECTS = r"(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|workflow_run|pages)"
TOJSON_UNTRUSTED_RE = re.compile(rf"tojson\s*\(\s*(github|github\.event|github\.event\.{_UNTRUSTED_OBJECTS}(\.[a-z_]+)*)\s*\)")


def _bypasses_failure(raw) -> bool:
    """Whether an `if:` lets a step or job run after an earlier failure."""
    return isinstance(raw, dict) and runs_after_failure(raw.get("if", ""))


class WorkflowRules:
    """Applies every workflow rule to one parsed workflow."""

    def __init__(self, workflow: Workflow, catalog: Catalog) -> None:
        self.wf = workflow
        self.catalog = catalog
        self.detection = catalog.detection
        self.findings: list[Finding] = []

    def add(self, rule: str, line: int, message: str, job: Job | None = None, step: Step | None = None,
            severity: str | None = None) -> None:
        self.findings.append(Finding(
            rule=rule,
            severity=severity or self.catalog.rules[rule]["severity"],
            path=self.wf.path,
            line=line or 1,
            message=message,
            job=job.id if job else None,
            step=step.name if step else None,
        ))

    def run(self) -> list[Finding]:
        self.placeholders()
        for job in self.wf.jobs.values():
            self.permissions_declared(job)
            self.secrets_untrusted(job)
            self.untrusted_checkout(job)
            self.script_injection(job)
            self.agent_rules(job)
            self.release_rules(job)
            self.unpinned(job)
            self.persisted_credentials(job)
            self.self_hosted(job)
            self.cache_write_low_trust(job)
            self.signing_keys(job)
            self.effect_rules(job)
        self.provenance_missing()
        return self.findings

    # -------------------------------------------------------------- GHA-023
    def placeholders(self) -> None:
        match = PLACEHOLDER_RE.search(self.wf.text)
        if match:
            line = self.wf.text.count("\n", 0, match.start()) + 1
            self.add("OBAAF-GHA-023", line, f"Template placeholder '{match.group(0).lstrip('@')}' is still present.")

    # -------------------------------------------------------------- GHA-009
    def permissions_declared(self, job: Job) -> None:
        if job.permissions is None:
            self.add("OBAAF-GHA-009", job.line,
                     f"Job '{job.id}' does not declare permissions, and neither does the workflow, so its token "
                     "gets the repository default.", job)

    # -------------------------------------------------------------- GHA-001
    def secrets_untrusted(self, job: Job) -> None:
        names = job.secret_names()
        if not names:
            return
        triggers = job.triggers()
        shown = ", ".join(sorted(n.replace("*inherit", "all secrets (secrets: inherit)").replace("*", "all secrets")
                                 for n in names))
        privileged = triggers & PRIVILEGED_UNTRUSTED_TRIGGERS
        if privileged:
            severity = "medium" if job.environment else "high"
            gate = f" It references environment '{job.environment}'; confirm that environment requires reviewers." \
                if job.environment else ""
            self.add("OBAAF-GHA-001", job.line,
                     f"Job '{job.id}' receives {shown} and can be started by {_fmt_triggers(privileged)}.{gate}",
                     job, severity=severity)
        elif triggers & PR_TRIGGERS:
            self.add("OBAAF-GHA-001", job.line,
                     f"Job '{job.id}' receives {shown} and runs on pull requests. Forks get no secrets, but "
                     "branches pushed by anyone with write access do.", job, severity="low")

    # -------------------------------------------------------------- GHA-002, GHA-019
    def untrusted_checkout(self, job: Job) -> None:
        privileged = job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS
        for step in job.steps:
            if step.uses_action("actions/checkout"):
                if _truthy(step.with_.get("allow-unsafe-pr-checkout", "false")):
                    self.add("OBAAF-GHA-019", step.line,
                             f"Step '{step.name}' sets allow-unsafe-pr-checkout: true.", job, step)
                if not privileged:
                    continue
                target = f"{step.with_.get('ref', '')} {step.with_.get('repository', '')}"
                if PR_HEAD_REF_RE.search(target):
                    self.add("OBAAF-GHA-002", step.line,
                             f"Step '{step.name}' checks out pull-request code in a workflow started by "
                             f"{_fmt_triggers(privileged)}.", job, step)
            elif privileged and PR_FETCH_CMD_RE.search(step.text()):
                self.add("OBAAF-GHA-002", step.line,
                         f"Step '{step.name}' fetches pull-request code in a workflow started by "
                         f"{_fmt_triggers(privileged)}.", job, step)

    # -------------------------------------------------------------- GHA-010
    def script_injection(self, job: Job) -> None:
        untrusted = bool(job.triggers() & UNTRUSTED_TRIGGERS)
        for step in job.steps:
            text = step.text()
            if not text:
                continue
            for expr in expressions(text):
                normalized = normalize_expression(expr)
                match = UNTRUSTED_FIELDS_RE.search(normalized) or TOJSON_UNTRUSTED_RE.search(normalized)
                if match:
                    self.add("OBAAF-GHA-010", step.line,
                             f"Step '{step.name}' expands {match.group(0)} inside its script.", job, step,
                             severity="high" if untrusted else "medium")
                    break

    # -------------------------------------------------------------- GHA-003/004/005/012/020
    def agent_rules(self, job: Job) -> None:
        if job.lane != "agent":
            return
        perms = job.permissions
        if perms is None:
            self.add("OBAAF-GHA-003", job.line,
                     f"Agent job '{job.id}' ({job.lane_reason}) does not declare permissions, so it may inherit "
                     "write access.", job)
        elif perms.write_scopes():
            self.add("OBAAF-GHA-003", job.line,
                     f"Agent job '{job.id}' ({job.lane_reason}) holds write permissions: "
                     f"{', '.join(perms.write_scopes())}.", job)
        if perms is not None and perms.oidc:
            self.add("OBAAF-GHA-004", job.line,
                     f"Agent job '{job.id}' can request OIDC tokens (id-token: write).", job)
        names = job.secret_names()
        if names:
            shown = ", ".join(sorted(n.replace("*inherit", "all secrets (secrets: inherit)").replace("*", "all secrets")
                                     for n in names))
            self.add("OBAAF-GHA-005", job.line, f"Agent job '{job.id}' receives {shown}.", job)
        elif job.environment:
            self.add("OBAAF-GHA-005", job.line,
                     f"Agent job '{job.id}' uses environment '{job.environment}', whose secrets it receives "
                     "after approval.", job)

        # GHA-012: instructions from the change under review.
        triggers = job.triggers()
        for step in job.steps:
            if step.uses_action("actions/checkout"):
                ref = str(step.with_.get("ref", ""))
                if PR_HEAD_REF_RE.search(ref) and "base" not in ref:
                    self.add("OBAAF-GHA-012", step.line,
                             f"Agent job '{job.id}' checks out the pull request's code in step '{step.name}', so "
                             "instruction files come from the change under review.", job, step)
                elif "pull_request" in triggers and not ref:
                    self.add("OBAAF-GHA-012", step.line,
                             f"Agent job '{job.id}' runs on pull_request and step '{step.name}' checks out the "
                             "merge commit, which includes the pull request's instruction files.", job, step)
            elif PR_FETCH_CMD_RE.search(step.text()):
                self.add("OBAAF-GHA-012", step.line,
                         f"Agent job '{job.id}' fetches the pull request's code in step '{step.name}'.", job, step)

        # GHA-020: egress restriction. Only a blocking monitor that always runs enforces anything here;
        # a declaration or a conditional monitor is reported, at the same severity, so it is not mistaken
        # for enforcement.
        declared = job.env.get("OBAAF_EGRESS") or self.wf.env.get("OBAAF_EGRESS")
        monitors = [step for step in job.steps
                    if any(step.uses_action(a) for a in self.detection.get("egress_actions", []))
                    and str(step.with_.get("egress-policy", "")).lower() == "block"]
        enforced = [m for m in monitors if "if" not in m.raw]
        if enforced:
            pass
        elif monitors or declared:
            how = (f"its blocking egress monitor runs only if {monitors[0].raw.get('if')}" if monitors else
                   f"it declares OBAAF_EGRESS ({declared}) but nothing in the job enforces it")
            self.add("OBAAF-GHA-020", job.line,
                     f"Agent job '{job.id}': {how}. Make sure the runner's network enforces the policy.", job)
        else:
            self.add("OBAAF-GHA-020", job.line,
                     f"Agent job '{job.id}' shows no egress restriction (no OBAAF_EGRESS declaration and no "
                     "blocking egress monitor).", job)

    # -------------------------------------------------------------- GHA-006/014/015/016
    def release_rules(self, job: Job) -> None:
        if job.lane != "release":
            return
        triggers = job.triggers()
        bad = triggers & UNTRUSTED_TRIGGERS
        if bad:
            self.add("OBAAF-GHA-015", job.line,
                     f"Release job '{job.id}' can be started by {_fmt_triggers(bad)}.", job)

        cache_steps = [s for s in job.steps if self._restores_cache(s)]
        mode = job.cache_mode
        hosted_note = (" This job also runs on a self-hosted runner, where local caches (such as an engine's "
                       "derived-data cache) are outside what this check can see.") if job.self_hosted else ""
        if cache_steps and mode not in ("none", "write-only"):
            names = ", ".join(f"'{s.name}'" for s in cache_steps)
            self.add("OBAAF-GHA-006", cache_steps[0].line,
                     f"Release job '{job.id}' restores caches in {names} and its cache-mode is "
                     f"{mode or 'not set'}.{hosted_note}", job, cache_steps[0])
        elif not cache_steps and mode != "none":
            self.add("OBAAF-GHA-006", job.line,
                     f"Release job '{job.id}' does not set cache-mode: none, so a cache step added later would "
                     f"read caches other workflows wrote.{hosted_note}", job, severity="low")

        uploads = job.upload_steps(self.detection)
        if uploads:
            if not job.environment:
                self.add("OBAAF-GHA-014", job.line,
                         f"Release job '{job.id}' uploads in '{uploads[0].name}' without a protected environment.",
                         job, uploads[0])
            first = uploads[0]
            kinds = set()
            if not _bypasses_failure(first.raw):
                kinds |= {self._verify_kind(s) for s in job.steps[: first.index]
                          if not (s.group is None and s.background) and not (s.group and s.group == first.group)}
            kinds |= self._needs_gate(job, lambda dep: {self._verify_kind(s) for s in dep.steps})
            kinds.discard(None)
            if "full" not in kinds:
                if "provenance" in kinds:
                    self.add("OBAAF-GHA-016", first.line,
                             f"Step '{first.name}' uploads after a provenance check only; approvals and agent "
                             "records are not checked (use obaaf verify release).", job, first, severity="medium")
                else:
                    self.add("OBAAF-GHA-016", first.line,
                             f"Step '{first.name}' uploads without an earlier check that stops it when "
                             "verification fails.", job, first)

    @staticmethod
    def _binding_matches(step: Step, patterns: list[str]) -> list[re.Match]:
        """Matches of `patterns` in the step's script that stop the job when the command fails: not
        ignored with `|| …`, sent to the background, `set +e`, `continue-on-error` or a condition."""
        coe = step.raw.get("continue-on-error")
        if coe not in (None, False) and str(coe).strip().lower() != "false":
            return []
        cond = str(step.raw.get("if", "")).strip()
        if cond and cond not in ("success()", "${{ success() }}"):
            return []
        text = step.text()
        if not text or re.search(r"(^|[\n;&])\s*set\s+\+e\b", text):
            return []
        out = []
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.M):
                line_end = text.find("\n", match.end())
                rest = text[match.end(): None if line_end == -1 else line_end]
                if "||" in rest or re.search(r"(?<![&])&\s*$", rest):
                    continue
                out.append(match)
        return out

    def _verify_kind(self, step: Step) -> str | None:
        """'full' for a release verification that stops the job on failure, 'provenance' for a
        provenance-only one, None otherwise (including checks whose failure is ignored)."""
        kind = None
        text = step.text()
        for match in self._binding_matches(step, self.detection.get("verify_commands", [])):
            if any(re.match(p, text[match.start():]) for p in self.detection.get("release_verify_commands", [])):
                return "full"
            kind = "provenance"
        return kind

    def _needs_gate(self, job: Job, found, seen: set | None = None) -> set:
        """What `found(dep)` returns for the jobs this one needs, followed transitively, stopping at a
        job whose `if:` lets it run after a failure (it would run even if the gate failed)."""
        if seen is None:
            seen = set()
        if _bypasses_failure(job.raw):
            return set()
        out: set = set()
        for name in job.needs:
            if name in seen or name not in self.wf.jobs:
                continue
            seen.add(name)
            dep = self.wf.jobs[name]
            out |= set(found(dep)) | self._needs_gate(dep, found, seen)
        return out

    @staticmethod
    def _restores_cache(step: Step) -> bool:
        w = step.with_
        if step.uses_action("actions/cache") or step.uses_action("actions/cache/restore"):
            return not step.uses_action("actions/cache/save")
        if step.uses_action("actions/setup-node"):
            return bool(w.get("cache")) or not _falsy(w.get("package-manager-cache", "true"))
        if step.uses_action("actions/setup-go"):
            return not _falsy(w.get("cache", "true"))
        if step.uses_action("actions/setup-python") or step.uses_action("actions/setup-java"):
            return bool(w.get("cache"))
        if step.uses_action("actions/setup-dotnet"):
            return _truthy(w.get("cache", "false"))
        if step.uses_action("gradle/actions/setup-gradle") or step.uses_action("gradle/gradle-build-action"):
            return not (_truthy(w.get("cache-disabled", "false")) or _truthy(w.get("cache-write-only", "false")))
        if step.uses_action("Swatinem/rust-cache"):
            return True
        if step.uses_action("ruby/setup-ruby"):
            return _truthy(w.get("bundler-cache", "false"))
        if step.uses_action("astral-sh/setup-uv"):
            return not _falsy(w.get("enable-cache", "auto"))
        if step.uses_action("docker/build-push-action"):
            return "type=gha" in str(w.get("cache-from", ""))
        return False

    # -------------------------------------------------------------- GHA-007
    def cache_write_low_trust(self, job: Job) -> None:
        mode = job.cache_mode
        privileged = job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS
        if mode in ("write", "write-only") and privileged:
            line = job.raw.line_of("cache-mode") if "cache-mode" in job.raw else self.wf.raw.line_of("cache-mode")
            self.add("OBAAF-GHA-007", line,
                     f"Job '{job.id}' can be started by {_fmt_triggers(privileged)} and declares "
                     f"cache-mode: {mode}.", job)

    # -------------------------------------------------------------- GHA-008
    def unpinned(self, job: Job) -> None:
        permissions = job.permissions
        privileged = (not permissions or not permissions.declared or permissions.write_scopes()
                      or permissions.oidc or job.secret_names()
                      or job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS)
        severity = ("high" if job.lane in ("release", "agent", "effect") else
                    "medium" if privileged else "low")
        refs = [(s, s.uses, s.line) for s in job.steps if s.uses]
        if job.reusable and not job.reusable.startswith("./"):
            refs.append((None, job.reusable, job.line))
        for step, uses, line in refs:
            if uses.startswith("./"):
                continue
            if uses.startswith("docker://"):
                if "@sha256:" not in uses:
                    self.add("OBAAF-GHA-008", line, f"Container '{uses}' is not pinned to a sha256 digest.", job,
                             step, severity)
                continue
            ref = uses.split("@", 1)[1] if "@" in uses else ""
            if not FULL_SHA_RE.match(ref):
                what = "Reusable workflow" if step is None else "Action"
                self.add("OBAAF-GHA-008", line,
                         f"{what} '{uses}' is pinned to '{ref or 'nothing'}', not a full commit SHA.", job, step,
                         severity)
        images = []
        container = job.raw.get("container")
        if isinstance(container, str):
            images.append(container)
        elif isinstance(container, dict) and container.get("image"):
            images.append(str(container["image"]))
        services = job.raw.get("services")
        if isinstance(services, dict):
            for svc in services.values():
                if isinstance(svc, dict) and svc.get("image"):
                    images.append(str(svc["image"]))
        for image in images:
            if "${{" in image or "@sha256:" in image:
                continue
            self.add("OBAAF-GHA-008", job.line, f"Image '{image}' is not pinned to a sha256 digest.", job,
                     severity=severity)

    # -------------------------------------------------------------- GHA-011
    def persisted_credentials(self, job: Job) -> None:
        exposed = job.lane in ("agent", "untrusted") or bool(job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS)
        if not exposed:
            return
        for step in job.steps:
            if step.uses_action("actions/checkout") and not _falsy(step.with_.get("persist-credentials", "true")):
                self.add("OBAAF-GHA-011", step.line,
                         f"Step '{step.name}' persists the job token for later steps.", job, step)

    # -------------------------------------------------------------- GHA-013
    def self_hosted(self, job: Job) -> None:
        kind = job.runner_kind
        if kind == "github-hosted":
            return
        untrusted = job.triggers() & UNTRUSTED_TRIGGERS
        if untrusted or job.lane == "agent":
            why = f"can be started by {_fmt_triggers(untrusted)}" if untrusted else "runs an agent"
            labels = ", ".join(job.runs_on) or "no labels"
            if kind == "self-hosted":
                self.add("OBAAF-GHA-013", job.line, f"Job '{job.id}' runs on a self-hosted runner ({labels}) and {why}.",
                         job)
            else:
                if job.mixed_runner_expression:
                    self.add("OBAAF-GHA-013", job.line,
                             f"Job '{job.id}' selects between hosted and self-hosted runners at runtime and {why}. "
                             "The checker cannot prove which runner receives untrusted work. Review the selector "
                             "and pool isolation; this informational finding does not certify it as safe.",
                             job, severity="info")
                else:
                    self.add("OBAAF-GHA-013", job.line,
                             f"Job '{job.id}' runs on {labels}, which are not standard GitHub-hosted labels, and {why}. "
                             "If this is a self-hosted runner, it must be ephemeral.", job, severity="medium")

    # -------------------------------------------------------------- GHA-018
    def signing_keys(self, job: Job) -> None:
        severity = "high" if job.lane == "release" else "medium"
        patterns = [re.compile(p, re.I) for p in self.detection.get("signing_secret_patterns", [])]
        keys = sorted(n for n in job.secret_names() if not n.startswith("*") and any(p.search(n) for p in patterns))
        if keys:
            self.add("OBAAF-GHA-018", job.line,
                     f"Job '{job.id}' loads signing material from secret(s): {', '.join(keys)}.", job,
                     severity=severity)
        commands = [re.compile(p, re.M) for p in self.detection.get("signing_commands", [])]
        for step in job.steps:
            text = step.text()
            if text and any(rx.search(text) for rx in commands):
                self.add("OBAAF-GHA-018", step.line,
                         f"Step '{step.name}' loads a signing key into the build environment.", job, step,
                         severity=severity)

    # -------------------------------------------------------------- GHA-021/022
    def effect_rules(self, job: Job) -> None:
        if job.lane != "effect":
            return
        verify_patterns = self.detection.get("record_verify_commands", [])
        proposal_patterns = self.detection.get("proposal_check_commands", [])

        def checks(j: Job) -> set:
            found = set()
            for step in j.steps:
                if self._binding_matches(step, verify_patterns):
                    found.add("record")
                if self._binding_matches(step, proposal_patterns):
                    found.add("proposal")
            return found

        def gated(j: Job) -> set:
            return {True} if j.environment else set()

        # The checks and the approval may happen in a job this one needs, as long as this job cannot
        # run when that job fails.
        done = checks(job) | self._needs_gate(job, checks)
        if not done:
            self.add("OBAAF-GHA-021", job.line,
                     f"Job '{job.id}' applies another run's output without verifying the agent-run record or "
                     "checking the proposal.", job)
        elif done != {"record", "proposal"}:
            missing = "verify the agent-run record" if "record" not in done else "check the proposal"
            self.add("OBAAF-GHA-021", job.line,
                     f"Job '{job.id}' applies another run's output but does not {missing} before applying it.",
                     job, severity="medium")
        if not (gated(job) or self._needs_gate(job, gated)):
            self.add("OBAAF-GHA-022", job.line,
                     f"Job '{job.id}' applies another run's output with write access but has no approval "
                     "environment.", job)

    # -------------------------------------------------------------- GHA-017
    def provenance_missing(self) -> None:
        uploading = [j for j in self.wf.jobs.values() if j.lane == "release" and j.upload_steps(self.detection)]
        if not uploading:
            return
        actions = self.detection.get("provenance_actions", [])
        commands = self.detection.get("provenance_commands", [])
        if any(j.matching_steps(actions, commands) for j in self.wf.jobs.values()):
            return
        # Provenance signed by another workflow counts when the upload is gated on verifying it.
        unverified = [j for j in uploading
                      if not ({self._verify_kind(s) for s in j.steps} | self._needs_gate(
                          j, lambda dep: {self._verify_kind(s) for s in dep.steps})) - {None}]
        if not unverified:
            return
        job = unverified[0]
        self.add("OBAAF-GHA-017", job.line,
                 f"Job '{job.id}' publishes artifacts, but no job in this workflow signs provenance for them.", job)


# ------------------------------------------------------------------- repository
def repo_findings(root: Path, workflow_paths: list[str], catalog: Catalog) -> list[Finding]:
    findings: list[Finding] = []
    codeowners_path, rules = repo_checks.read_codeowners(root)
    instruction_files = repo_checks.find_instruction_files(root, catalog.detection.get("instruction_files", []))

    if codeowners_path is None:
        findings.append(Finding("OBAAF-REPO-001", catalog.rules["OBAAF-REPO-001"]["severity"], ".github/CODEOWNERS",
                                1, "The repository has no CODEOWNERS file."))
        if instruction_files:
            findings.append(Finding("OBAAF-REPO-002", catalog.rules["OBAAF-REPO-002"]["severity"], instruction_files[0],
                                    1, f"No CODEOWNERS file covers the {len(instruction_files)} agent instruction "
                                       f"file(s): {', '.join(instruction_files[:5])}."))
    else:
        uncovered = [p for p in workflow_paths if not repo_checks.owners_for(rules, p)]
        if uncovered:
            findings.append(Finding("OBAAF-REPO-001", catalog.rules["OBAAF-REPO-001"]["severity"], codeowners_path, 1,
                                    f"No code owner for {len(uncovered)} CI definition file(s): "
                                    f"{', '.join(uncovered[:5])}."))
        uncovered = [p for p in instruction_files if not repo_checks.owners_for(rules, p)]
        if uncovered:
            findings.append(Finding("OBAAF-REPO-002", catalog.rules["OBAAF-REPO-002"]["severity"], codeowners_path, 1,
                                    f"No code owner for {len(uncovered)} agent instruction file(s): "
                                    f"{', '.join(uncovered[:5])}."))

    for rel in instruction_files:
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hidden = repo_checks.scan_hidden(text)
        if hidden:
            detail = "; ".join(h.label for h in hidden[:3])
            more = f" and {len(hidden) - 3} more" if len(hidden) > 3 else ""
            findings.append(Finding("OBAAF-INS-001", catalog.rules["OBAAF-INS-001"]["severity"], rel, hidden[0].line,
                                    f"{len(hidden)} hidden character(s): {detail}{more}."))
    return findings
