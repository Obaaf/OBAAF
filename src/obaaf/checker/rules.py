"""The OBAAF checker rules. Metadata (title, severity, fix) lives in data/rules.yaml."""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from obaaf.catalog import Catalog
from obaaf.checker import egress as egress_mod
from obaaf.checker import expr as expr_mod
from obaaf.checker import repo as repo_checks
from obaaf.checker.workflow import (
    FULL_SHA_RE, PR_FETCH_CMD_RE, PR_HEAD_REF_RE, PR_TRIGGERS, PRIVILEGED_UNTRUSTED_TRIGGERS, UNTRUSTED_FIELDS_RE,
    UNTRUSTED_PATHS, UNTRUSTED_TRIGGERS, Job, Step, Workflow, expressions, input_name, one_line,
    runs_after_failure,
)

PLACEHOLDER_SHA = "0" * 40
PLACEHOLDER_RE = re.compile(r"OBAAF_OWNER|@" + PLACEHOLDER_SHA)


VERIFIED, NOT_MET, CANNOT_TELL = "verified", "not met", "cannot tell"
NEW, ACCEPTED, FIXED, UNDECIDED = "new", "accepted", "fixed", "cannot-tell"


@dataclass
class Control:
    """One control that would clear a finding, and what the checker could establish about it:
    `verified` (the checker read it and it holds), `not met` (it read it and it does not), or
    `cannot tell` (it could not read what decides it). There is no verdict that means "assumed"."""
    name: str
    verdict: str
    detail: str = ""
    id: str = ""        # a short name that stays the same when `name` is reworded

    def __post_init__(self) -> None:
        if self.verdict not in (VERIFIED, NOT_MET, CANNOT_TELL):
            raise ValueError(f"a control is {VERIFIED}, {NOT_MET} or {CANNOT_TELL}, not {self.verdict!r}")


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
    baselined: bool = False    # accepted by a valid baseline entry: reported, but does not fail the check
    # What the finding is, apart from how its message words it. `kind` names which of a rule's cases
    # this is and `facts` holds the values the message prints (which secrets, which triggers). With
    # the rule, file, job and step they identify the finding for an acceptance. `facts` is None for a
    # finding that has not been given any (the Jenkins rules): its message identifies it, as before.
    kind: str = ""
    facts: dict | None = None
    controls: list = field(default_factory=list)   # Control: what would clear the finding, and what was established
    acceptance: object | None = None               # acceptance.Acceptance: the entry that matched, valid or not

    def sort_key(self) -> tuple:
        order = {"high": 0, "medium": 1, "low": 2}
        return (self.path, self.line, order.get(self.severity, 3), self.rule)

    @property
    def state(self) -> str:
        """Where the finding stands: `fixed` (every control that clears it was verified), `accepted`
        (a valid acceptance: owner, reason and an expiry date not yet passed), `cannot-tell` (no
        control is known to be missing, but at least one could not be verified), or `new`. Only
        `fixed` and `accepted` keep a finding from failing the check."""
        verdicts = [c.verdict for c in self.controls]
        if verdicts and all(v == VERIFIED for v in verdicts):
            return FIXED
        if self.suppressed or self.baselined:
            return ACCEPTED
        if verdicts and NOT_MET not in verdicts:
            return UNDECIDED
        return NEW


class Note(str):
    """Text a finding's message shows that is not one of its facts, because the facts already hold
    it: a count of the files or characters that are listed in full as a fact. Every other value
    given to `compose` is a fact. A note must never say something the facts do not."""


class Fact:
    """A value that is part of what a finding is, with the text the message shows for it when that
    is not simply the value: `*inherit` is shown as "all secrets (secrets: inherit)", an empty
    cache-mode as "not set". The one thing `shown` may add to the value is a line and column, which
    are never part of a finding (a hidden character is a fact by the text of its line)."""

    def __init__(self, value, shown: str) -> None:
        self.value, self.shown = value, shown


# (rule, kind) -> the template it was first used with, and the pairs seen with two templates. A
# rule's cases must have different kinds, or an acceptance of one would cover another. The test
# suite fails if CONFLICTS is not empty after the fixtures have run.
TEMPLATES: dict[tuple[str, str], str] = {}
CONFLICTS: list[tuple[str, str]] = []


def compose(rule: str, kind: str, template: str, job: str | None, step: str | None, values: dict) -> tuple[str, dict]:
    """A finding's message and its facts, from one template and its named values.

    The message can only show the template's own words, the job, the step and `values`; each value
    is a fact unless it is a `Note`. So what the message says about a finding is in what identifies
    it, apart from line and column numbers, and the template's wording can change without changing
    which finding it is. Two facts are themselves text the checker wrote, and rewording them does
    change the finding: why a job is an agent job (OBAAF-GHA-003), until agents are named data.
    """
    if TEMPLATES.setdefault((rule, kind), template) != template and (rule, kind) not in CONFLICTS:
        CONFLICTS.append((rule, kind))
    shown = {"job": job or "", "step": step or ""}
    facts: dict = {}
    for name, value in values.items():
        if isinstance(value, Note):
            shown[name] = str(value)
        elif isinstance(value, Fact):
            facts[name], shown[name] = value.value, value.shown
        elif isinstance(value, (list, tuple, set, frozenset)):
            items = [str(v) for v in value]
            facts[name], shown[name] = items, ", ".join(items)
        elif isinstance(value, (bool, int)):
            facts[name], shown[name] = value, str(value)
        else:
            facts[name] = shown[name] = str(value)
    return template.format(**shown), facts


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def _falsy(value) -> bool:
    return str(value).strip().lower() in ("false", "0", "no")


def normalize_expression(expr: str) -> str:
    """Lower-case an expression and turn index syntax (github.event['issue']) into dots.

    Contexts and property names are case-insensitive in GitHub Actions expressions.
    """
    out = re.sub(r"\[\s*'([^']*)'\s*\]", r".\1", expr)
    out = re.sub(r'\[\s*"([^"]*)"\s*\]', r".\1", out)
    # The look-behind starts a match only at the beginning of a run of spaces, so a long run with no
    # dot after it is scanned once, not once per space.
    out = re.sub(r"(?<!\s)\s*\.\s*", ".", out)
    return out.lower()


# toJSON of these serializes text that outsiders write.
_UNTRUSTED_OBJECTS = r"(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|workflow_run|pages)"
TOJSON_UNTRUSTED_RE = re.compile(rf"tojson\s*\(\s*(github|github\.event|github\.event\.{_UNTRUSTED_OBJECTS}(\.[a-z_]+)*)\s*\)")


def _bypasses_failure(raw) -> bool:
    """Whether an `if:` lets a step or job run after an earlier failure."""
    return isinstance(raw, dict) and runs_after_failure(raw.get("if", ""))


class WorkflowRules:
    """Applies every workflow rule to one parsed workflow."""

    def __init__(self, workflow: Workflow, catalog: Catalog, protected: dict | None = None,
                 agents: dict | None = None, firewall: "egress_mod.FirewallPolicy | None" = None) -> None:
        self.wf = workflow
        self.catalog = catalog
        self.detection = catalog.detection
        self.protected = dict(protected or {})
        # The `agents` section of the configuration, and what was read of the repository's policy for
        # GitHub's native egress firewall (None when no repository was checked, only files).
        self.agents = dict(agents or {})
        self.firewall = firewall
        self.findings: list[Finding] = []

    def add(self, rule: str, line: int, template: str, job: Job | None = None, step: Step | None = None,
            severity: str | None = None, *, kind: str = "", controls: list | None = None, **values) -> None:
        """Report a finding. `template` is the message, with `{job}`, `{step}` and one `{name}` for
        each of `values`; `kind` tells a rule's cases apart (see `compose`). `controls` are the
        controls that would clear the finding, each with what the checker established about it."""
        job_id, step_name = (job.id if job else None), (step.name if step else None)
        message, facts = compose(rule, kind, template, job_id, step_name, values)
        self.findings.append(Finding(
            rule=rule,
            severity=severity or self.catalog.rules[rule]["severity"],
            path=self.wf.path,
            line=line or 1,
            message=message,
            job=job_id,
            step=step_name,
            kind=kind,
            facts=facts,
            controls=list(controls or []),
        ))

    def run(self) -> list[Finding]:
        self.placeholders()
        for job in self.wf.jobs.values():
            self.permissions_declared(job)
            self.secrets_untrusted(job)
            self.protected_secrets(job)
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
            self.add("OBAAF-GHA-023", line, "Template placeholder '{placeholder}' is still present.",
                     placeholder=match.group(0).lstrip('@'))

    # -------------------------------------------------------------- GHA-009
    def permissions_declared(self, job: Job) -> None:
        if job.permissions is None:
            self.add("OBAAF-GHA-009", job.line,
                     "Job '{job}' does not declare permissions, and neither does the workflow, so its token "
                     "gets the repository default.", job)

    # -------------------------------------------------------------- GHA-001
    def secrets_untrusted(self, job: Job) -> None:
        names = job.secret_names()
        if not names:
            return
        triggers = job.triggers()
        shown = ", ".join(sorted(n.replace("*inherit", "all secrets (secrets: inherit)").replace("*", "all secrets")
                                 for n in names))
        secrets = Fact(sorted(names), shown)
        privileged = triggers & PRIVILEGED_UNTRUSTED_TRIGGERS
        if privileged and job.environment:
            self.add("OBAAF-GHA-001", job.line,
                     "Job '{job}' receives {secrets} and can be started by {triggers}. It references environment "
                     "'{environment}'; confirm that environment requires reviewers.",
                     job, severity="medium", kind="privileged-environment", secrets=secrets,
                     triggers=sorted(privileged), environment=job.environment)
        elif privileged:
            self.add("OBAAF-GHA-001", job.line,
                     "Job '{job}' receives {secrets} and can be started by {triggers}.",
                     job, severity="high", kind="privileged", secrets=secrets, triggers=sorted(privileged))
        elif triggers & PR_TRIGGERS:
            self.add("OBAAF-GHA-001", job.line,
                     "Job '{job}' receives {secrets} and runs on pull requests. Forks get no secrets, but "
                     "branches pushed by anyone with write access do.", job, severity="low", kind="pull-request",
                     secrets=secrets)

    # -------------------------------------------------------------- GHA-024
    def protected_secrets(self, job: Job) -> None:
        if not self.protected:
            return
        names = job.secret_names()
        caller = bool(job.reusable)
        # A reusable-workflow call with `secrets: inherit` passes repository and organization secrets
        # only, never an environment's, and the caller cannot declare an environment. Whether a
        # protected secret still has such a copy is a settings question, not a workflow one.
        if caller:
            names = names - {"*inherit"}
        takes_all = "*" in names or "*inherit" in names
        # Every protected entry a secret matches applies, so an overlapping, looser pattern can never
        # relax a stricter one.
        hits: list[tuple[str, str, str | None]] = []   # (secret shown, pattern, required environment)
        for pattern, env in self.protected.items():
            if takes_all:
                hits.append((pattern, pattern, env))
                continue
            for name in sorted(names):
                if fnmatch.fnmatchcase(name.upper(), pattern):
                    hits.append((name.upper(), pattern, env))
        if not hits:
            return
        declared = job.environment
        dynamic = bool(declared and "${{" in declared)
        via = " (it can take every secret)" if takes_all else ""
        reported: set[tuple] = set()
        for name, pattern, wanted in hits:
            ok = declared and not dynamic and (wanted is None or declared.casefold() == wanted.casefold())
            if ok:
                continue
            # One finding for each secret and the environment it needs, however many entries ask for it.
            if (name, wanted) in reported:
                continue
            reported.add((name, wanted))
            values = {"secret": name, "via": Fact(takes_all, via),
                      "need": Fact(wanted or "", f"environment '{wanted}'" if wanted else "an environment")}
            if caller:
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' passes protected secret {secret}{via} to the reusable workflow "
                         "{workflow}. A calling job cannot declare an environment, so the secret can only "
                         "come from the repository or organization; pass none, and declare {need} in the called "
                         "workflow's job instead.", job, kind="caller", workflow=job.reusable, **values)
            elif dynamic:
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' uses protected secret {secret}{via} with environment '{declared}', an "
                         "expression the checker cannot confirm is {need}.", job, severity="medium",
                         kind="environment-expression", declared=declared, **values)
            elif declared:
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' uses protected secret {secret}{via} in environment '{declared}', not {need}.",
                         job, kind="other-environment", declared=declared, **values)
            else:
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' uses protected secret {secret}{via} without declaring {need}, so it "
                         "can only get the secret from the repository or organization, where any branch can "
                         "read it.", job, kind="no-environment", **values)

    # -------------------------------------------------------------- GHA-002, GHA-019
    def untrusted_checkout(self, job: Job) -> None:
        privileged = job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS
        for step in job.steps:
            if step.uses_action("actions/checkout"):
                if _truthy(step.with_.get("allow-unsafe-pr-checkout", "false")):
                    self.add("OBAAF-GHA-019", step.line,
                             "Step '{step}' sets allow-unsafe-pr-checkout: true.", job, step)
                if not privileged:
                    continue
                target = f"{step.with_.get('ref', '')} {step.with_.get('repository', '')}"
                if PR_HEAD_REF_RE.search(target):
                    self.add("OBAAF-GHA-002", step.line,
                             "Step '{step}' checks out pull-request code in a workflow started by "
                             "{triggers}.", job, step, kind="checkout", triggers=sorted(privileged))
            elif privileged and PR_FETCH_CMD_RE.search(step.text()):
                self.add("OBAAF-GHA-002", step.line,
                         "Step '{step}' fetches pull-request code in a workflow started by "
                         "{triggers}.", job, step, kind="fetch", triggers=sorted(privileged))

    # -------------------------------------------------------------- GHA-010
    def script_injection(self, job: Job) -> None:
        untrusted = bool(job.triggers() & UNTRUSTED_TRIGGERS)
        for step in job.steps:
            text = step.text()
            if not text:
                continue
            view = None
            for body in expressions(text):
                severity = "high" if untrusted else "medium"
                found = self._untrusted_text(body)
                if found:
                    self.add("OBAAF-GHA-010", step.line,
                             "Step '{step}' expands {field} inside its script.", job, step,
                             severity=severity, field=found)
                    break
                if view is None:
                    view = self._indirect(job, step)
                through = self._untrusted_indirectly(body, view)
                if through:
                    how, reference, found = through
                    held = "which holds" if how == "through-env" else "from a matrix that holds"
                    self.add("OBAAF-GHA-010", step.line,
                             "Step '{step}' expands {reference}, " + held + " {field}, inside its script.", job, step,
                             severity=severity, kind=how, reference=reference, field=found)
                    break

    @staticmethod
    def _untrusted_text(body: str) -> str | None:
        """The outsider-written field an expression expands, if any."""
        normalized = normalize_expression(body)
        match = UNTRUSTED_FIELDS_RE.search(normalized) or TOJSON_UNTRUSTED_RE.search(normalized)
        if match:
            return match.group(0)
        # Spellings the patterns above cannot follow. A wildcard or a computed index stands for any
        # field, and a function may turn the object it is given into text, so each is treated as
        # reaching the outsider-written fields inside the object it names.
        for ref in expr_mod.refs(body):
            if any(expr_mod.reaches(ref.path, pattern, ref.extracted) for pattern in UNTRUSTED_PATHS):
                return expr_mod.dotted(ref.path)
        return None

    def _held(self, value, objects: bool = False) -> str | None:
        """The outsider-written field a workflow value holds, if any. With `objects`, a value that
        is the object containing such a field counts too (a matrix entry can be a whole object,
        whose fields the script then reads)."""
        for body in expressions(value):
            held = self._untrusted_text(body)
            if held:
                return held
            if objects:
                for ref in expr_mod.refs(body):
                    if any(expr_mod.reaches(ref.path, pattern, True) for pattern in UNTRUSTED_PATHS):
                        return expr_mod.dotted(ref.path)
        return None

    @staticmethod
    def _env_refs(value) -> tuple[set, bool]:
        """Names (lower case) a value reads from the env context, and whether it reads all of it."""
        names, everything = set(), False
        for body in expressions(value):
            for path in expr_mod.paths(body):
                if path[0].value.lower() != "env":
                    continue
                if len(path) > 1 and path[1].kind == expr_mod.NAME:
                    names.add(path[1].value.lower())
                else:
                    everything = True
        return names, everything

    def _env_taint(self, scopes: list[dict], base: dict, matrix: str | None = None) -> dict:
        """Env name -> the outsider-written field its value holds, directly, through other env
        values (`B: ${{ env.A }}`), or through the job's matrix when that holds one (`matrix`).
        Later scopes override earlier ones key for key. `base` is taint from the enclosing scopes,
        which these values can read but do not replace."""
        entries: dict = {}
        for scope in scopes:
            entries.update(scope)
        tainted: dict = {}
        readers: dict = {}          # lower-case name -> keys whose value reads env.<name>
        read_all: list = []         # keys whose value reads the whole env context
        for key, value in entries.items():
            held = self._held(key) or self._held(value)
            if not held and matrix and any(path[0].value.lower() == "matrix"
                                           for body in expressions(value) for path in expr_mod.paths(body)):
                held = matrix
            if held:
                tainted[key] = held
                continue
            names, everything = self._env_refs(value)
            if everything:
                read_all.append(key)
            for name in names:
                readers.setdefault(name, []).append(key)
        inherited = {str(k).lower(): v for k, v in base.items()}
        queue = [(str(k).lower(), v) for k, v in tainted.items()] + list(inherited.items())
        seen_all = False
        while queue:
            name, held = queue.pop()
            dependants = readers.pop(name, [])
            if not seen_all:
                dependants = dependants + read_all
                seen_all = True
            for key in dependants:
                if key not in tainted:
                    tainted[key] = held
                    queue.append((str(key).lower(), held))
        return tainted

    def _indirect(self, job: Job, step: Step) -> dict:
        """What a step's script can reach through the env and matrix contexts: env names that hold
        outsider-written text (lower case), whether the job's matrix does, and whether an `env:`
        written as one expression (so its names cannot be read) does."""
        cache = self.__dict__.setdefault("_job_views", {})
        if job.id not in cache:
            matrix = self._held(job.raw.get("strategy"), objects=True)
            whole = next((held for held in (self._held(raw.get("env"), objects=True)
                                            for raw in (self.wf.raw, job.raw)
                                            if isinstance(raw.get("env"), str)) if held), None)
            cache[job.id] = (self._env_taint([self.wf.env, job.env], {}, matrix), matrix, whole)
        job_taint, matrix, whole = cache[job.id]
        if isinstance(step.raw.get("env"), str):
            whole = whole or self._held(step.raw.get("env"), objects=True)
        step_taint = self._env_taint([step.env], job_taint, matrix) if step.env else {}
        env: dict = {}
        for key, held in job_taint.items():
            if key not in step.env:             # a step value of the same name replaces the job's
                env.setdefault(str(key).lower(), held)
        for key, held in step_taint.items():
            env.setdefault(str(key).lower(), held)
        return {"env": env, "matrix": matrix, "env_whole": whole}

    @staticmethod
    def _untrusted_indirectly(body: str, view: dict) -> tuple[str, str, str] | None:
        """`${{ env.TITLE }}` or `${{ matrix.title }}` in a script is expanded before the shell runs,
        like any expression. If TITLE is set from an outsider-written field, the script expands that
        field. (`"$TITLE"`, which the shell reads, is the safe form.) Returns how the field is
        reached (`through-env` or `through-matrix`), the reference in the script, and the field."""
        for path in expr_mod.paths(body):
            root = path[0].value.lower()
            if root == "env" and (view["env"] or view["env_whole"]):
                if len(path) > 1 and path[1].kind == expr_mod.NAME:
                    held = view["env"].get(path[1].value.lower())
                else:
                    held = next(iter(view["env"].values()), None)
                held = held or view["env_whole"]
                if held:
                    return "through-env", expr_mod.dotted(path), held
            elif root == "matrix" and view["matrix"]:
                return "through-matrix", expr_mod.dotted(path), view["matrix"]
        return None

    # -------------------------------------------------------------- GHA-003/004/005/012/020
    def agent_rules(self, job: Job) -> None:
        if not job.in_lane("agent"):
            return
        perms = job.permissions
        # Why the job is an agent job is part of the finding, as the text the checker shows for it,
        # so that an acceptance stops covering the job when the recognised action, the step or the
        # declaration changes. The text does not tell every agent apart (another command in a step
        # of the same name, any agent in a declared job), and rewording it changes the finding;
        # both end when agents are named data.
        why = job.reason_for('agent')
        if perms is None:
            self.add("OBAAF-GHA-003", job.line,
                     "Agent job '{job}' ({why}) does not declare permissions, so it may inherit "
                     "write access.", job, kind="undeclared", why=why)
        elif perms.write_scopes():
            self.add("OBAAF-GHA-003", job.line,
                     "Agent job '{job}' ({why}) holds write permissions: "
                     "{scopes}.", job, kind="write", why=why, scopes=perms.write_scopes())
        if perms is not None and perms.oidc:
            self.add("OBAAF-GHA-004", job.line,
                     "Agent job '{job}' can request OIDC tokens (id-token: write).", job)
        names = job.secret_names()
        if names:
            shown = ", ".join(sorted(n.replace("*inherit", "all secrets (secrets: inherit)").replace("*", "all secrets")
                                     for n in names))
            egress = self._egress(job)[0]
            routes = self._key_routes(job)
            if routes:
                # Where a key given to OBAAF's egress action goes, whatever the egress control's verdict:
                # a model key under model-keys is out of the command's reach, one passed in env is not.
                egress = Control(egress.name, egress.verdict,
                                 f"{egress.detail.rstrip('.')}. Where the confined step's credentials go: {routes}",
                                 egress.id)
            self.add("OBAAF-GHA-005", job.line, "Agent job '{job}' receives {secrets}.", job, kind="secrets",
                     secrets=Fact(sorted(names), shown),
                     controls=[*self._secret_controls(job, names), self._input_control(job), egress])
        elif job.environment:
            self.add("OBAAF-GHA-005", job.line,
                     "Agent job '{job}' uses environment '{environment}', whose secrets it receives "
                     "after approval.", job, kind="environment", environment=job.environment)

        # GHA-012: instructions from the change under review.
        triggers = job.triggers()
        for step in job.steps:
            if step.uses_action("actions/checkout"):
                ref = str(step.with_.get("ref", ""))
                if PR_HEAD_REF_RE.search(ref) and "base" not in ref:
                    self.add("OBAAF-GHA-012", step.line,
                             "Agent job '{job}' checks out the pull request's code in step '{step}', so "
                             "instruction files come from the change under review.", job, step, kind="head")
                elif "pull_request" in triggers and not ref:
                    self.add("OBAAF-GHA-012", step.line,
                             "Agent job '{job}' runs on pull_request and step '{step}' checks out the "
                             "merge commit, which includes the pull request's instruction files.", job, step,
                             kind="merge-commit")
            elif PR_FETCH_CMD_RE.search(step.text()):
                self.add("OBAAF-GHA-012", step.line,
                         "Agent job '{job}' fetches the pull request's code in step '{step}'.", job, step,
                         kind="fetch")

        # GHA-020: egress restriction. The finding is always there for an agent job; what was
        # established about the one control that clears it decides where the finding stands.
        egress, kind, values = self._egress(job)
        templates = {
            "none": "Agent job '{job}' shows no egress restriction (no OBAAF_EGRESS declaration and no "
                    "blocking egress monitor).",
            "declared": "Agent job '{job}': it declares OBAAF_EGRESS ({declared}) but nothing in the job enforces "
                        "it. Make sure the runner's network enforces the policy.",
            "conditional": "Agent job '{job}': its blocking egress monitor runs only if {condition}. Make sure the "
                           "runner's network enforces the policy.",
            "late-monitor": "Agent job '{job}' does not start its blocking egress monitor ({monitor}) before "
                            "everything else: it runs {place}.",
            "unverified-monitor": "Agent job '{job}' runs a blocking egress monitor ({monitor}) as its first "
                                  "step (workflow file sha256 {written}). The checker cannot yet tell whether "
                                  "it limits the agent.",
            "weak-monitor": "Agent job '{job}' runs a blocking egress monitor ({monitor}) as its first step, but: "
                            "{weaknesses}.",
            "firewall-runner": "Agent job '{job}' runs on {runner}, GitHub's native egress firewall, and "
                               "{policy} (workflow file sha256 {written}).",
            "egress-action": "Agent job '{job}' runs a command under OBAAF's egress action ({action}), allowing "
                             "{allow} (workflow file sha256 {written}).",
            "awf": "Agent job '{job}' runs a command under the Agent Workflow Firewall in step '{where}' "
                   "(workflow file sha256 {written}).",
        }
        self.add("OBAAF-GHA-020", job.line, templates[kind], job, kind=kind, controls=[egress], **values)

    # ---------------------------------------------------- controls for GHA-005 and GHA-020
    EGRESS_NAME = "a control the checker recognises limits the job's network access to an allow-list"
    EGRESS_ID = "egress-enforced"

    def _egress(self, job: Job) -> tuple[Control, str, dict]:
        """What the checker can establish about a limit on the job's network access: the control,
        which case of OBAAF-GHA-020 it is, and that case's values.

        Each control the job might have is read on its own (GitHub's native firewall, OBAAF's egress
        action, Harden-Runner, the Agent Workflow Firewall in a script), and the one that comes out
        best stands: one real control is enough. A control is `verified` only where every condition
        that makes it hold was read and holds; where one does not hold it is "not met", and where one
        cannot be read it is "cannot tell". A declaration (`OBAAF_EGRESS`) is never a control."""
        cache = self.__dict__.setdefault("_egress_cache", {})
        if job.id not in cache:
            cache[job.id] = self._egress_reading(job)
        return cache[job.id]

    def _egress_reading(self, job: Job) -> tuple[Control, str, dict]:
        readings = [r for r in (self._native_firewall(job), self._egress_action(job), self._harden_runner(job),
                                self._awf(job)) if r is not None]
        if readings:
            rank = {VERIFIED: 0, CANNOT_TELL: 1, NOT_MET: 2}
            best = min(readings, key=lambda r: rank[r.verdict])     # the first of the best, in the order above
            return Control(self.EGRESS_NAME, best.verdict, best.detail, self.EGRESS_ID), best.kind, best.values
        declared = job.env.get("OBAAF_EGRESS") or self.wf.env.get("OBAAF_EGRESS")
        kind, values = ("declared", {"declared": str(declared)}) if declared else ("none", {})
        if declared:
            return (Control(self.EGRESS_NAME, NOT_MET, "OBAAF_EGRESS is a declaration, and nothing in the job "
                                                       "enforces it", self.EGRESS_ID), kind, values)
        return Control(self.EGRESS_NAME, NOT_MET, "no blocking egress control in the job", self.EGRESS_ID), kind, values

    def _written(self) -> str:
        # An acceptance of "cannot tell" is for the workflow file that was looked at, byte for
        # byte. Anything narrower has to say which differences GitHub cannot see, and the reader
        # this checker uses does not read YAML as GitHub's does (numbers, groups, aliases).
        return (self.wf.digest or hashlib.sha256(self.wf.text.encode("utf-8", "surrogatepass")).hexdigest())[:32]

    def _no_egress_kind(self, job: Job) -> tuple[str, dict]:
        declared = job.env.get("OBAAF_EGRESS") or self.wf.env.get("OBAAF_EGRESS")
        return ("declared", {"declared": str(declared)}) if declared else ("none", {})

    # ---- GitHub's native egress firewall
    def _native_firewall(self, job: Job) -> egress_mod.Reading | None:
        """The firewall covers every step of the job, post steps included, from outside the runner's
        virtual machine. It holds when the job runs on `ubuntu-24.04-firewall` and the repository's
        `.github/egress-firewall.yaml` sets `mode: enforce`, with a token that can read the file
        (without `contents: read` the README says no file-based policy is enforced, and no warning is
        given). Larger runners with the firewall image carry labels of their owner's choosing, so a
        job on labels the checker cannot name, in a repository whose policy enforces, is "cannot tell"."""
        if job.reusable:
            return None
        sets = job.runner_label_sets()
        firewall = egress_mod.FIREWALL_LABEL
        on = [s for s in (sets or []) if len(s) == 1 and s[0].strip().lower() == firewall]
        policy = self.firewall
        if not on:
            # A larger runner can be in a runner group (`group:`), which the checker otherwise counts as
            # self-hosted; a runner labelled `self-hosted` never has GitHub's firewall.
            plain_self_hosted = any(label.strip().lower() == "self-hosted" for label in job.runs_on)
            if (policy is not None and policy.state == "read" and policy.mode == "enforce"
                    and job.runner_kind != "github-hosted" and not plain_self_hosted):
                detail = (f"{egress_mod.FIREWALL_POLICY} sets mode: enforce, and the job runs on "
                          f"{one_line(', '.join(job.runs_on) or 'labels the checker cannot read', 120)}, which "
                          "may or may not be a larger runner with GitHub's firewall image: its labels do not say")
                return egress_mod.Reading(CANNOT_TELL, detail, "firewall-runner",
                                          {"runner": ", ".join(job.runs_on) or "unknown labels",
                                           "policy": self._policy_shown(policy), "written": self._written()})
            return None
        problems: list[str] = []
        unsure: list[str] = []
        if len(on) != len(sets):
            others = sorted({", ".join(s) for s in sets if s not in on})
            problems.append(f"some runs of the job use {one_line('; '.join(others), 120)}, without the firewall")
        if policy is None:
            unsure.append(f"{egress_mod.FIREWALL_POLICY} was not read, because a single workflow file was checked "
                          "rather than a repository")
        elif policy.state == "missing":
            problems.append(f"the repository has no {egress_mod.FIREWALL_POLICY}, so the firewall enforces no policy")
        elif policy.state == "misnamed":
            problems.append(f"the policy file is {policy.detail}, and the firewall reads only "
                            f"{egress_mod.FIREWALL_POLICY} (the name is case sensitive), so it enforces nothing")
        elif policy.state == "unreadable":
            unsure.append(f"{egress_mod.FIREWALL_POLICY} could not be read: {policy.detail}")
        elif policy.mode == "log":
            problems.append(f"{egress_mod.FIREWALL_POLICY} sets mode: log, which records traffic and blocks nothing")
        elif policy.mode != "enforce":
            unsure.append(f"{egress_mod.FIREWALL_POLICY} sets mode to "
                          f"{one_line(repr(policy.mode) if policy.mode is not None else 'nothing the checker can read', 60)}, "
                          "which is neither enforce nor log")
        if "workflow_call" in job.triggers():
            unsure.append("other workflows can call this one, and whose policy file and token the firewall uses "
                          "for a called workflow is not established")
        perms = job.permissions
        if perms is not None and perms.level("contents") not in ("read", "write"):
            problems.append("the job's token has no contents permission, and without contents: read the firewall "
                            "enforces no policy file and gives no warning")
        if policy is not None and policy.state == "read":
            odd = [entry for entry in policy.allow if not egress_mod.HOST_RE.match(entry.strip().lower())]
            wide = [entry for entry in policy.allow
                    if entry not in odd and egress_mod.public_suffix_at_or_under(entry.strip())]
            if odd:
                unsure.append(f"the policy allows {one_line(', '.join(odd[:5]), 120)}, which is not a plain host name, "
                              "and the firewall's README describes no other kind of entry")
            if wide:
                unsure.append(f"the policy allows {one_line(', '.join(wide[:5]), 120)}, which is or has under it "
                              "a public suffix (where anyone can register a name), and the firewall's README does "
                              "not say whether an allowed name covers the names under it")
        verdict = egress_mod.worst(problems, unsure)
        if verdict == VERIFIED:
            listed = ", ".join(policy.allow) or "nothing"
            listed += " and nothing else" if policy.no_defaults else " and GitHub's default endpoints"
            detail = (f"the job runs on {firewall} and {egress_mod.FIREWALL_POLICY} sets mode: enforce, allowing "
                      f"{one_line(listed, 160)}. The firewall is a technical preview, and anything sent to an allowed host, "
                      "printed to the job's log or saved as an artifact is not blocked")
        else:
            detail = egress_mod.joined(problems or unsure)
        return egress_mod.Reading(verdict, detail, "firewall-runner",
                                  {"runner": firewall, "policy": self._policy_shown(policy), "written": self._written()})

    @staticmethod
    def _policy_shown(policy) -> str:
        if policy is None:
            return "its policy file was not read"
        if policy.state == "read":
            return f"its policy file sets mode {policy.mode or 'unreadable'} (file sha256 {policy.digest})"
        if policy.state == "missing":
            return "the repository has no policy file"
        if policy.state == "misnamed":
            return f"its policy file is misnamed ({policy.detail})"
        return f"its policy file cannot be read (file sha256 {policy.digest or 'none'})"

    # ---- OBAAF's egress action
    @staticmethod
    def _without_registry_credentials(rest: dict) -> dict:
        """A job's keys without the `credentials` of its container and services, which GitHub uses to
        pull their images and hands to no step."""
        out = dict(rest)
        container = out.get("container")
        if isinstance(container, dict):
            out["container"] = {k: v for k, v in container.items() if k != "credentials"}
        services = out.get("services")
        if isinstance(services, dict):
            out["services"] = {name: ({k: v for k, v in svc.items() if k != "credentials"}
                                      if isinstance(svc, dict) else svc) for name, svc in services.items()}
        return out

    def _credentials(self, value) -> list[str]:
        """The credentials a part of the workflow is given: every secret, GITHUB_TOKEN included, and
        `github.token` (also through `toJSON(github)` or a computed index). A condition written without
        `${{ }}` is read too."""
        found: list[str] = []
        bodies = list(expressions(value))
        seen: set = set()

        def conditions(item) -> None:
            if id(item) in seen:
                return
            if isinstance(item, dict):
                seen.add(id(item))
                cond = item.get("if")
                if isinstance(cond, str) and expr_mod.OPEN not in cond:
                    bodies.append(cond)
                for sub in item.values():
                    conditions(sub)
            elif isinstance(item, list):
                seen.add(id(item))
                for sub in item:
                    conditions(sub)
        conditions(value)
        for body in bodies:
            for ref in expr_mod.refs(body):
                path = ref.path
                head = path[0].value.lower()
                if head == "secrets":
                    name = (path[1].value if len(path) > 1 and path[1].kind == expr_mod.NAME else "all secrets")
                    shown = f"secrets.{one_line(name, 60)}" if name != "all secrets" else name
                    if shown not in found:
                        found.append(shown)
                elif head == "github" and expr_mod.reaches(path, ({"github"}, {"token"}), ref.extracted):
                    if "github.token" not in found:
                        found.append("github.token")
        return found

    def _agent_step(self, step: Step, text: str) -> str | None:
        """Why the checker takes the step to run an agent, or None."""
        actions = list(self.detection.get("agent_actions", [])) + list(self.agents.get("actions", ()) or ())
        commands = [re.compile(p, re.M) for p in
                    list(self.detection.get("agent_commands", [])) + list(self.agents.get("commands", ()) or ())]
        for prefix in actions:
            if step.uses_action(prefix):
                return f"uses {one_line(step.action, 80)}"
        if text and any(rx.search(text) for rx in commands):
            return "runs an agent CLI"
        return None

    _OUTPUTS = frozenset({"workspace", "scratch"})

    def _reads_output(self, step: Step, ids: set) -> list[str]:
        """Where a step refers to what a confined command could write: an `outputs.workspace` or
        `outputs.scratch` of a confined step (also through `steps.*`, a computed index or `toJSON`),
        or the scratch directory by its name, `obaaf-egress`. Returns the input names it does so in
        (`run`, `with.path`, `env.X`, ...)."""
        where: list[str] = []

        pattern = ({"steps"}, ids, {"outputs"}, set(self._OUTPUTS))

        def refers(text: str) -> bool:
            # The scratch directory is /tmp/obaaf-egress.<random>, so a step that names /tmp can reach it
            # through a pattern (`/tmp/obaaf*`, `/tmp/*`) as well as by its name.
            if "obaaf-egress" in text.lower() or "/tmp" in text:
                return True
            return any(expr_mod.reaches(ref.path[:len(pattern)], pattern, ref.extracted or len(ref.path) > len(pattern))
                       for body in expr_mod.bodies(text) for ref in expr_mod.refs(body))

        seen: set = set()

        def walk(label: str, value) -> None:
            if isinstance(value, (dict, list)):
                if id(value) in seen:
                    return
                seen.add(id(value))
            if isinstance(value, str):
                if refers(value):
                    where.append(label)
            elif isinstance(value, dict):
                for key, sub in value.items():
                    if not label and key == "name":
                        continue        # a step's name is only shown
                    walk(f"{label}.{input_name(key) if label == 'with' else key}" if label else str(key), sub)
            elif isinstance(value, list):
                for n, sub in enumerate(value):
                    walk(f"{label}[{n}]", sub)
            elif value is not None:
                if refers(str(value)):
                    where.append(label)
        walk("", step.raw)
        return where

    @staticmethod
    def _env_keys(value) -> set | None:
        """The variable names an `env` mapping sets, or None when it is computed when the job runs."""
        if value is None:
            return set()
        return {str(key) for key in value} if isinstance(value, dict) else None

    def _placement(self, job: Job, step: Step) -> egress_mod.Placement:
        """Where each credential given to a step that uses OBAAF's egress action goes (slice 2c.5),
        read as the action reads its inputs: `model-keys` names variables of the step's environment for
        AWF's API proxy, `env` names variables for the command, and the `run` input is the command's
        text. A credential anywhere else in the step, or inputs or an `env` computed when the job runs,
        cannot be placed. A name the action refuses makes it refuse to run."""
        cache = self.__dict__.setdefault("_placement_cache", {})
        key = (job.id, step.index)
        if key in cache:
            return cache[key]
        where = f"step '{one_line(step.name, 80)}'"
        place = egress_mod.Placement(where)
        cache[key] = place
        given = step.raw.get("with")
        names: dict = {"env": None, "model-keys": None}     # None: not readable (the caller says why for `with`)
        if isinstance(given, dict):
            for label in names:
                value = step.with_.get(label)
                if value is None:
                    names[label] = []
                elif not isinstance(value, str):
                    kind = ("a list" if isinstance(value, list) else "a mapping" if isinstance(value, dict)
                            else "true or false" if isinstance(value, bool) else "a number")
                    place.unsure.append(f"{where} gives its {label} input as {kind}, not as text, and how GitHub "
                                        "turns that into the text the action reads is not established")
                elif expr_mod.OPEN in value:
                    place.unsure.append(f"{where} computes its {label} input when the job runs ({one_line(value, 80)})")
                else:
                    names[label] = egress_mod.split_list(value)
        env_names, key_names = names["env"], names["model-keys"]
        for name in env_names or []:
            if not egress_mod.NAME_RE.match(name):
                place.problems.append(f"{where} names {one_line(name, 60)!r} under env, which is not a variable name, "
                                      "so the action refuses to run")
            elif name in egress_mod.WITHHELD_BY_AWF:
                place.problems.append(f"{where} names {name} under env, a name AWF withholds from the command, so "
                                      "the action refuses to run (a model key goes under model-keys)")
        step_env = step.raw.get("env")
        here = self._env_keys(step_env)
        beyond = [self._env_keys(job.raw.get("env")), self._env_keys(self.wf.raw.get("env"))]
        for name in key_names or []:
            if name not in egress_mod.MODEL_KEYS:
                place.problems.append(f"{where} names {one_line(name, 60)!r} under model-keys, which takes only "
                                      f"{', '.join(sorted(egress_mod.MODEL_KEYS))}, so the action refuses to run")
                continue
            host = egress_mod.MODEL_KEYS[name]
            if host not in place.hosts:
                place.hosts.append(host)
            unset = all(keys is not None and name not in keys for keys in [here, *beyond])
            if unset:
                place.problems.append(f"{where} names {name} under model-keys and no env of the step, the job or "
                                      "the workflow sets it, so the action refuses to run")
        # The step's environment, which the action reads names from, and which GitHub also puts in the
        # `env` context its inputs are written with: `${{ env.KEY }}` in `run` hands the command the
        # value whatever `model-keys` says.
        held: dict = {}          # step env name -> the credentials its value holds
        folded: dict = {}        # step env name in upper case -> the names written
        if isinstance(step_env, dict):
            for name in step_env:
                folded.setdefault(str(name).upper(), []).append(str(name))
            said: set = set()
            for name, value in step_env.items():
                found = self._credentials(value)
                if not found:
                    continue
                name = str(name)
                held[name] = found
                same = folded[name.upper()]
                if len(same) > 1 and name.upper() not in said:
                    said.add(name.upper())
                    place.unsure.append(f"{where} sets {' and '.join(one_line(n, 60) for n in same)} in its env, "
                                        "which differ only in case, and which of them the action reads is not "
                                        "established")
        elif step_env is not None:
            found = self._credentials(step_env)
            if found:
                place.unsure.append(f"{where} computes its env when the job runs, with {self._names(found)}, so the "
                                    "checker cannot tell which variables hold them")
        # The inputs. Only `run` reaches the command, as its text, with what it writes in from `secrets`,
        # `github.token` or the step's env (the env context's names are not case sensitive); a
        # credential in any other input is not placed (an allow-list or a list of names computed from
        # one is reported above).
        through_run: set = set()
        if isinstance(given, dict):
            for name, value in given.items():
                found = self._credentials(value)
                refs, everything = self._env_refs(value)
                via = [env for env in held if everything or env.lower() in refs]
                if input_name(name) == "run":
                    if found:
                        place.command.append(("in its run input", found))
                    for env in via:
                        through_run.add(env)
                        place.command.append((f"in its run input, through env.{env}", held[env]))
                    if everything and held:
                        place.unsure.append(f"{where} writes the whole env context, or a part of it the checker "
                                            "cannot name, into its run input")
                elif found or via:
                    shown = found + [f"env.{env}" for env in via]
                    place.unsure.append(f"{where} gives {self._names(shown)} in its {one_line(name, 40)} input, "
                                        "which the action does not pass on as a variable")
        elif given is not None:
            found = self._credentials(given)
            if found:
                place.unsure.append(f"{where} computes its inputs when the job runs, with {self._names(found)}")
        # Each credential of the step's env, by the name it is set under.
        for name, found in held.items():
            if len(folded[name.upper()]) > 1 or name in through_run:
                continue        # said above
            if env_names is None or key_names is None:
                continue        # said above: an input is not readable
            if name in key_names and name in egress_mod.MODEL_KEYS and name not in env_names:
                place.proxy.append((name, found))
            elif name in env_names:
                if name in egress_mod.WITHHELD_BY_AWF or not egress_mod.NAME_RE.match(name):
                    continue    # the action refuses to run, which `problems` says
                place.command.append((f"as {name}", found))
            else:
                place.neither.append((name, found))
        rest = {name: value for name, value in step.raw.items() if name not in ("with", "env")}
        found = self._credentials(rest)
        if found:
            place.unsure.append(f"{where} is given {self._names(found)} outside its env and its inputs, where the "
                                "checker does not place it")
        return place

    @staticmethod
    def _names(items: list, limit: int = 3) -> str:
        """Names joined for a report, saying how many more there are rather than cutting them off."""
        items = list(dict.fromkeys(items))
        more = f" and {len(items) - limit} more" if len(items) > limit else ""
        return ", ".join(items[:limit]) + more

    def _key_routes(self, job: Job) -> str:
        """Where the credentials given to the job's steps that use OBAAF's egress action go, in words,
        for OBAAF-GHA-005's controls, with what the checker could not place and what makes the action
        refuse to run; empty when there is none of these."""
        if job.reusable:
            return ""
        parts: list[str] = []
        for step in job.steps:
            if not step.confines:
                continue
            place = self._placement(job, step)
            bits: list[str] = []
            for name, found in place.proxy:
                bits.append(f"{name} ({self._names(found)}) goes to AWF's API proxy, which the command can use and "
                            f"cannot read, and which reaches {egress_mod.MODEL_KEYS[name]} whatever the allow-list says")
            for how, found in place.command:
                bits.append(f"{self._names(found)} is passed to the command {how}, which can send it to a listed host "
                            "or print it to the job's log")
            for name, found in place.neither:
                bits.append(f"{name} ({self._names(found)}) is named under neither env nor model-keys and written "
                            "nowhere in the inputs, so the action passes it to neither")
            if place.unsure:
                bits.append("the checker could not place: " + egress_mod.joined(place.unsure, 3))
            if place.problems:
                bits.append("the action would refuse to run: " + egress_mod.joined(place.problems, 3))
            if bits:
                parts.append(f"in {place.step}, " + "; ".join(bits))
        return "; ".join(parts)

    def _leaks(self, placements: list) -> str:
        """What a cleared OBAAF-GHA-020 under OBAAF's egress action does not stop, so the report never
        reads as more: the listed hosts and what they can be made to do, names under them, the provider
        behind each model key, and the job's log and artifacts."""
        passed = [cred for place in placements for _how, found in place.command for cred in found]
        keys = sorted({name for place in placements for name, _found in place.proxy})
        hosts = sorted({host for place in placements for host in place.hosts})
        parts = ["anything the confined command sends to a listed host"
                 + (f", the credentials passed to it included ({self._names(passed)}), with which a listed host "
                    "can be made to act for it" if passed else ""),
                 "data in a name under a listed name, which leaves the runner in a DNS query to that name's DNS servers"]
        if hosts:
            given = f"with {', '.join(keys)} given to AWF's API proxy" if keys else "through AWF's API proxy"
            parts.append(f"{given}: anything the command sends {' or '.join(hosts)} through the proxy, and whatever "
                         "the provider is asked to fetch or connect to for it (remote MCP servers, URLs); the proxy "
                         "refuses the providers' hosted web search and fetch tools, in the requests it can read, and "
                         "nothing else of that kind")
        parts.append("and anything the command prints to the job's log or leaves for a later actions/upload-artifact "
                     "step to save")
        return "Not blocked: " + "; ".join(parts)

    def _egress_action(self, job: Job) -> egress_mod.Reading | None:
        """OBAAF's egress action confines one command: its `run` input. The control holds for the job
        only when every condition below can be read and holds (decision D-050):

        - the action is used from a commit OBAAF lists as released, on the runner it was tested on;
        - its allow-list is written out, every entry a host name the action accepts and none a public
          suffix (a listed name covers the names under it);
        - the agent is the confined command: no other step, and no `env` of the job or workflow, is
          given a credential, and no other step runs an agent the checker recognises. A job in which
          no credential reaches the confined command or AWF's API proxy is "cannot tell" unless the
          checker recognises the agent in the confined command itself, because an agent that needs no
          key could run in any step;
        - every credential given to the confined step is placed (`_placement`, slice 2c.5, decision
          D-052): a model key named in `model-keys` goes to AWF's API proxy, which the command can use
          and cannot read, and which reaches the provider's API host whatever the allow-list says, so
          that host is shown with the allow-list; one passed to the command can be sent to a listed
          host. Both limit the network as the allow-list says, and both are said beside a cleared
          finding. A credential the checker cannot place is "cannot tell";
        - no step that can run after or beside it reads its `workspace` or `scratch` output or the
          scratch directory, except to upload it as an artifact. Saving them to a cache is "not met";
          any other use is "cannot tell", because the checker cannot tell reading from running."""
        confined = [step for step in job.steps if step.confines]
        if not confined or job.reusable:
            return None
        released = {str(sha).lower() for sha in self.detection.get("egress_action_releases", []) or []}
        problems: list[str] = []
        unsure: list[str] = []
        allow_shown: list[str] = []
        for step in confined:
            where = f"step '{one_line(step.name, 80)}'"
            uses = (step.uses or "").strip()
            ref = uses.split("@", 1)[1] if "@" in uses else ""
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                unsure.append(f"{where} uses the action at '{one_line(ref, 60)}', not a commit; a tag or "
                              "branch can move")
            elif ref not in released:
                unsure.append(f"{where} uses the action at {ref[:12]}, which is not a commit OBAAF lists as "
                              f"released ({len(released) or 'none'} listed)")
            given = step.raw.get("with")
            if not isinstance(given, dict):
                unsure.append(f"{where} gives the action its inputs {'from an expression' if given else 'not at all'}")
                continue
            allow = step.with_.get("allow")
            if not isinstance(allow, str) or not allow.strip():
                if allow is None or (isinstance(allow, str) and not allow.strip()):
                    problems.append(f"{where} gives no allow input, so the action refuses to run")
                else:
                    unsure.append(f"{where} gives allow as {type(allow).__name__}, not as text")
            elif expr_mod.OPEN in allow:
                unsure.append(f"{where} computes its allow-list when the job runs ({one_line(allow, 80)})")
                allow_shown.append(allow)
            else:
                for entry in egress_mod.split_list(allow):
                    name = entry.lower()
                    allow_shown.append(name)
                    if "*" in name or len(name) > 253 or not egress_mod.HOST_RE.match(name):
                        problems.append(f"{where} allows '{one_line(entry, 60)}', which the action refuses, so it "
                                        "does not run")
                    elif egress_mod.public_suffix_at_or_under(name):
                        suffix = egress_mod.public_suffix_at_or_under(name)
                        what = "a public suffix" if suffix == name else f"which has the public suffix {suffix} under it"
                        problems.append(f"{where} allows {name}, {what}: anyone can register a name there, and a "
                                        "listed name covers every name under it")
            command = step.with_.get("run")
            if not isinstance(command, str) or not command.strip():
                problems.append(f"{where} gives no run input, so the action refuses to run")
        # The runner the action was tested on.
        sets = job.runner_label_sets()
        if job.raw.get("container") is not None:
            unsure.append("the job runs in a container, where the action has not been tried")
        if not sets or any(len(s) != 1 or s[0].strip().lower() != "ubuntu-24.04" for s in sets):
            unsure.append(f"the job runs on {one_line(', '.join(job.runs_on) or 'labels the checker cannot read', 80)}; "
                          "the action was tested only on GitHub-hosted ubuntu-24.04 runners")
        # Where the agent is.
        others = [step for step in job.steps if not step.confines]
        outside: list[str] = []
        for label, value in (("the workflow's env", self.wf.raw.get("env")),):
            names = self._credentials(value)
            if names:
                outside.append(f"{label} holds {', '.join(names[:3])}")
        rest = self._without_registry_credentials({key: value for key, value in job.raw.items() if key != "steps"})
        names = self._credentials(rest)
        if names:
            outside.append(f"the job gives {', '.join(names[:3])} outside its steps")
        for step in others:
            names = self._credentials(step.raw)
            if names:
                outside.append(f"step '{one_line(step.name, 80)}' is given {', '.join(names[:3])}")
        # Credentials no expression hands over: every step can ask for an OIDC token when the job may
        # (and turn it into a cloud credential, a model provider's included), and every action is given
        # the job's token without being asked, which calls GitHub Models when the token has `models`.
        # The confined command gets neither: the action passes it only the variables it names, and
        # refuses names starting ACTIONS_ and the GitHub token names.
        perms = job.permissions
        if perms is not None and perms.oidc:
            outside.append("the job can request OIDC tokens (id-token: write), which any step can turn into a "
                           "cloud credential")
        if perms is not None and perms.level("models") in ("read", "write"):
            outside.append("the job's token can call GitHub Models (models permission), and every action is given "
                           "that token")
        unread_token = perms is None
        agents_outside = []
        for step in others:
            why = self._agent_step(step, step.agent_text())
            if why or step.index in job.agent_script_steps:
                agents_outside.append(f"step '{one_line(step.name, 80)}' {why or 'runs an agent in a script'}")
        # Where each credential given to a confined step goes (slice 2c.5). A name the action refuses
        # makes it refuse to run; a credential that reaches the command or AWF's API proxy is the
        # evidence that the agent is the confined command.
        placements = [self._placement(job, step) for step in confined]
        for place in placements:
            problems.extend(place.problems)
            unsure.extend(place.unsure)
            for host in place.hosts:
                shown = f"{host} (through AWF's API proxy)"
                if shown not in allow_shown:
                    allow_shown.append(shown)
        if agents_outside:
            problems.append(f"{egress_mod.joined(agents_outside, 3)}, outside the confined command")
        if outside:
            problems.append(f"{egress_mod.joined(outside, 3)}, so the agent may run outside the confined command "
                            "(the checker tells where an agent runs by where its key goes)")
        elif not agents_outside and not any(place.reaches for place in placements):
            recognised = [step for step in confined if self._agent_step(step, step.agent_text())
                          or step.index in job.agent_script_steps]
            if not recognised:
                unsure.append("no credential reaches the confined command or AWF's API proxy, no other step is given "
                              "one, and the checker recognises no agent in the confined command, so it cannot tell "
                              "where the agent runs: an agent that needs no key could run in any step")
        if unread_token and not outside:
            unsure.append("the job does not declare its token's permissions, so the repository's default applies, "
                          "which the checker does not read, and every action is given that token")
        # What runs after (or beside) the confined command. Only `actions/upload-artifact` may: it saves
        # files as data. A script, or any other action, could run or load what the command wrote, and
        # the checker cannot tell reading from running. Steps before it are read for what their post
        # steps or the processes they leave running could reach: the outputs, the scratch directory by
        # its name, or /tmp.
        first = min(step.index for step in confined)
        groups = {step.group for step in confined if step.group is not None}
        concurrent = any(step.background for step in confined)
        ids = {str(step.raw.get("id")).lower() for step in confined if step.raw.get("id") is not None}
        defaults = job.raw.get("defaults")
        if defaults is not None and self._reads_output(Step(index=-1, raw={"defaults": defaults}, line=0), ids):
            unsure.append("the job's defaults name /tmp or the confined command's output, and the checker cannot "
                          "tell whether a step runs or loads anything from it")
        services = job.raw.get("services")
        if isinstance(services, dict) and any(isinstance(svc, dict) and ("volumes" in svc or "options" in svc)
                                              for svc in services.values()):
            unsure.append("the job's service containers are given volumes or options, and run beside the confined "
                          "command, which the checker does not read")
        after: list[str] = []
        for step in others:
            before = (step.index < first and not step.background and not concurrent
                      and (step.group is None or step.group not in groups))
            where = f"step '{one_line(step.name, 80)}'"
            refs = self._reads_output(step, ids)
            if refs and step.uses_action("actions/cache"):
                problems.append(f"{where} saves /tmp or the confined command's output to a cache (its post step "
                                "saves after the job), from which a later run can load it")
                continue
            if not before:
                if step.uses_action("actions/upload-artifact"):
                    continue
                after.append(where)
            elif refs:
                unsure.append(f"{where}, before it, names /tmp or the scratch directory ({', '.join(refs[:3])}), "
                              "and its post step or a process it leaves running could reach what the command wrote")
            elif egress_mod.leaves_process(step.run):
                unsure.append(f"{where}, before it, may leave a process running beside it "
                              f"({egress_mod.leaves_process(step.run)}), which could reach what the command wrote")
        if after:
            unsure.append(f"{egress_mod.joined(after, 3)} can run after it or beside it, and the checker cannot tell "
                          "whether it runs or loads anything the command wrote (only actions/upload-artifact is "
                          "taken to save files as data)")
        verdict = egress_mod.worst(problems, unsure)
        if verdict == VERIFIED:
            detail = (f"the agent's command runs under OBAAF's egress action at a commit OBAAF lists as released, "
                      f"allowing {one_line(', '.join(allow_shown), 200)}, and nothing but actions/upload-artifact "
                      f"runs after it. {self._leaks(placements)}")
        else:
            detail = egress_mod.joined(problems or unsure)
        action = ", ".join(sorted({one_line(step.uses or "", 120) for step in confined}))
        return egress_mod.Reading(verdict, detail, "egress-action",
                                  {"action": action, "allow": allow_shown or ["nothing"], "written": self._written()})

    # ---- Harden-Runner
    def _harden_runner(self, job: Job) -> egress_mod.Reading | None:
        """Harden-Runner runs beside the job on the same machine. It covers the job only when it starts
        first, in block mode, with no condition; at v2.16.0 or later (two published bypasses of the block
        policy are fixed there), the version read from a commit OBAAF lists and never from a comment;
        with `sudo` and containers removed (`disable-sudo-and-containers: true`), or a step with either
        can undo its rules; with its policy written in the step rather than fetched from StepSecurity's
        policy store, which it falls back from to audit mode when the fetch fails; on a GitHub-hosted
        runner; and in a repository its tier covers (the free tier does not cover private ones). The
        last is not in the workflow, so the best it can be from `obaaf check` is "cannot tell"."""
        known = [step for step in job.steps
                 if any(step.uses_action(a) for a in self.detection.get("egress_actions", []))]
        if not known:
            return None
        name_kind, name_values = self._no_egress_kind(job)
        monitors = [step for step in known if input_name(step.with_.get("egress-policy", "")) == "block"]
        enforced = [m for m in monitors if "if" not in m.raw]
        if enforced:
            first = enforced[0]
            uses = str(first.uses)
            where = f"step '{one_line(first.name, 80)}'"
            steps = job.raw.get("steps")
            # First means the first entry of `steps:` as written, started and finished before the
            # next one: not a member of a `parallel` group, and not a background step.
            if not (isinstance(steps, list) and steps and steps[0] is first.raw):
                place = ("in a parallel group" if first.group is not None else
                         f"after {first.index} other step(s)" if first.index else
                         "after another entry of steps")
            elif first.background:
                place = "in the background"
            else:
                place = ""
            if place:
                return egress_mod.Reading(NOT_MET, f"{where} starts the blocking egress monitor {place}, so other "
                                                   "steps can run without it",
                                          "late-monitor", {"monitor": uses, "place": place})
            weaknesses: list[str] = []
            unsure: list[str] = []
            ref = uses.split("@", 1)[1] if "@" in uses else ""
            releases = {str(k).lower(): str(v) for k, v in (self.detection.get("harden_runner_releases") or {}).items()}
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                unsure.append(f"it is used at '{one_line(ref, 60)}', not a commit, and the checker reads its version only "
                              "from a commit OBAAF lists, never from a tag or a comment")
            elif ref not in releases:
                unsure.append(f"{ref[:12]} is not a commit OBAAF lists as a release of Harden-Runner, so its version "
                              "is not known")
            else:
                version = tuple(int(part) for part in releases[ref].split("."))
                if version < (2, 16, 0):
                    weaknesses.append(f"it is v{releases[ref]}, before v2.16.0, which fixed two published bypasses "
                                      "of the block policy")
            given = first.with_
            raw_with = first.raw.get("with") if isinstance(first.raw.get("with"), dict) else {}
            # The value as written: GitHub hands a YAML true to the action as "true", and Harden-Runner
            # reads it with getBooleanInput, which takes true, True and TRUE (src/setup.ts at v2.16.0).
            flag = next((value for key, value in raw_with.items() if input_name(key) == "disable-sudo-and-containers"),
                        None)
            if flag is True or (isinstance(flag, str) and flag.strip() in ("true", "True", "TRUE")):
                pass
            elif isinstance(flag, str) and expr_mod.OPEN in flag:
                unsure.append("whether sudo and containers are removed is computed when the job runs")
            else:
                kept = "containers are kept" if _truthy(given.get("disable-sudo", "")) else "sudo and containers are kept"
                weaknesses.append(f"{kept} (disable-sudo-and-containers is not true), so a step can undo its rules")
            if job.raw.get("container") is not None and job.runner_kind == "github-hosted":
                weaknesses.append("the job runs in a container on a GitHub-hosted runner, where it sets up nothing "
                                  "(src/setup.ts at v2.16.0 returns at once)")
            store = given.get("policy")
            if (isinstance(store, str) and store.strip()) or (store is not None and not isinstance(store, str)) \
                    or str(given.get("use-policy-store", "")).strip().lower() not in ("", "false"):
                unsure.append("its policy comes from StepSecurity's policy store, which the checker cannot read, and "
                              "it falls back to audit mode on some errors in fetching it")
            if str(given.get("deploy-on-self-hosted-vm", "")).strip().lower() not in ("", "false") \
                    or job.runner_kind != "github-hosted":
                unsure.append(f"the job runs on a {job.runner_kind} runner, where how it works was not read")
            unsure.append("whether the repository is public, or covered by a paid tier (the free tier does not "
                          "cover private repositories), is not in the workflow, and obaaf check does not read it")
            if weaknesses:
                return egress_mod.Reading(NOT_MET, f"{where} uses {one_line(first.action, 80)} as the job's first step, "
                                                   f"but {egress_mod.joined(weaknesses)}",
                                          "weak-monitor", {"monitor": uses,
                                                           "weaknesses": Fact(weaknesses, "; ".join(weaknesses))})
            detail = (f"{where} uses {one_line(first.action, 80)} in block mode as the job's first step, but "
                      f"{egress_mod.joined(unsure)}")
            return egress_mod.Reading(CANNOT_TELL, detail, "unverified-monitor", {"monitor": uses, "written": self._written()})
        if monitors:
            condition = str(monitors[0].raw.get("if"))
            return egress_mod.Reading(NOT_MET, f"its blocking egress monitor runs only if {one_line(condition, 120)}",
                                      "conditional", {"condition": condition})
        unread = [step for step in known
                  if not isinstance(step.raw.get("with"), dict) and step.raw.get("with") is not None
                  or "${{" in str(step.with_.get("egress-policy", ""))]
        if unread:
            # The step is there and what it is set to is computed when the job runs. The finding is
            # the one reported before (no blocking monitor that can be read); the verdict says why.
            return egress_mod.Reading(CANNOT_TELL, f"step '{one_line(unread[0].name, 80)}' uses an egress monitor "
                                                   "whose egress-policy is not written out, so the checker cannot "
                                                   "tell whether it blocks", name_kind, name_values)
        return None

    # ---- the Agent Workflow Firewall in a script
    def _awf(self, job: Job) -> egress_mod.Reading | None:
        """A `run:` script that starts a command under AWF. Which AWF it is, with which options, and
        whether the agent is the command it wraps are read from a shell command line, which the checker
        does not do well enough to call it verified, so the best it is is "cannot tell". With
        `--enable-dind`, which AWF's documentation says allows a bypass, it is "not met"."""
        found = [step for step in job.steps
                 if not step.confines and egress_mod.AWF_RE.search(egress_mod.uncommented(step.run))]
        if not found:
            return None
        step = found[0]
        where = one_line(step.name, 80)
        if any(egress_mod.AWF_UNSAFE_RE.search(s.run) for s in found):
            return egress_mod.Reading(NOT_MET, f"step '{where}' runs AWF with --enable-dind, which hands the "
                                               "command the Docker socket and, in AWF's documentation, allows "
                                               "a bypass", "awf", {"where": where, "written": self._written()})
        detail = (f"step '{where}' runs a command under AWF, and the checker does not read a shell command line well "
                  "enough to establish which AWF version runs, with which options, and that the agent is the "
                  "command it wraps")
        return egress_mod.Reading(CANNOT_TELL, detail, "awf", {"where": where, "written": self._written()})

    def _secret_controls(self, job: Job, names: set) -> list[Control]:
        """Two controls about where an agent job's secrets come from. The first is read from the
        workflow and the checker configuration: every secret the job receives is listed in
        `protected_secrets`, and the job declares the environment the entry names, which is what
        OBAAF-GHA-024 checks for the secrets that are listed. The second is a repository setting
        (the environment holds the secrets, nothing outside it does, and only protected branches
        may use it), which `obaaf check` does not read, so it is "cannot tell" for a job that
        declares an environment and "not met" for one that declares none."""
        scoped = "each of the job's secrets is listed in protected_secrets, and the job declares the environment named there"
        setting = "the secrets are stored only in that environment, and only protected branches may use it"
        declared = job.environment
        written = job.raw.get("environment")
        written = written.get("name") if isinstance(written, dict) else written
        # `010` is the number 8 to this reader and may be the number 10, or text, to GitHub's, and
        # `0` or `false` may be a name to GitHub and is nothing here.
        odd = written is not None and not isinstance(written, str)
        shown = "the job's environment" if odd else f"environment '{one_line(declared, 120)}'"

        def both(verdict: str, detail: str, second: str = CANNOT_TELL) -> list[Control]:
            if second == NOT_MET:
                about = "the job declares no environment, so its secrets come from the repository or organization"
            else:
                about = (f"where a secret is stored and which branches may use {shown} are repository "
                         "settings, which obaaf check does not read; obaaf audit reads environments and their "
                         "branch rules")
            return [Control(scoped, verdict, detail, "secrets-protected"),
                    Control(setting, second, about, "environment-restricted")]

        if job.reusable:
            return both(NOT_MET, "a job that calls a reusable workflow cannot declare an environment, so the "
                                 "secrets it passes come from the repository or organization", NOT_MET)
        second = CANNOT_TELL if declared or odd else NOT_MET
        if "*" in names or "*inherit" in names:
            return both(NOT_MET, "the job can take every secret, so it is not limited to protected ones", second)
        upper = sorted({str(n).upper() for n in names})
        wanted: dict = {}     # secret -> the environments its protected_secrets entries name (None: any)
        for secret in upper:
            wanted[secret] = [env for pattern, env in self.protected.items() if fnmatch.fnmatchcase(secret, pattern)]
        unlisted = [secret for secret in upper if not wanted[secret]]
        if unlisted:
            more = f", and {len(unlisted) - 5} more" if len(unlisted) > 5 else ""
            return both(NOT_MET, "not listed in protected_secrets: "
                                 f"{', '.join(one_line(secret, 60) for secret in unlisted[:5])}{more}", second)
        if odd:
            return both(CANNOT_TELL, "the job's environment is not written as text (it is a number, true or "
                                     "false, a list or a mapping), so the checker cannot tell which name "
                                     "GitHub takes it for")
        if not declared:
            return both(NOT_MET, "the job declares no environment", NOT_MET)
        if "${{" in declared:
            return both(CANNOT_TELL, f"the job's environment is an expression ({one_line(declared, 120)}), which "
                                     "the checker cannot compare with the one protected_secrets names")
        named = sorted({env for envs in wanted.values() for env in envs if env is not None})
        # The same name, or the same name in another case where both are ASCII. What GitHub makes of
        # other letters that differ only in case has not been established.
        differs = [env for env in named if env != declared and not (env.isascii() and declared.isascii()
                                                                    and env.lower() == declared.lower())]
        unsure = [env for env in differs if env.casefold() == declared.casefold()]
        if len(unsure) < len(differs):
            return both(NOT_MET, f"the job declares environment '{one_line(declared, 120)}', and protected_secrets "
                                 f"names {', '.join(repr(one_line(env, 120)) for env in differs)}")
        if unsure:
            return both(CANNOT_TELL, f"the job declares environment '{one_line(declared, 120)}' and "
                                     f"protected_secrets names {', '.join(repr(one_line(env, 120)) for env in unsure)}"
                                     ", which differ only in the case of letters outside ASCII")
        listed = ", ".join(upper[:5]) + (f", and {len(upper) - 5} more" if len(upper) > 5 else "")
        return both(VERIFIED, f"{listed} in environment '{one_line(declared, 120)}'")

    # Events that only someone with write access can cause, and whose payload outsiders do not write.
    _WRITE_ACCESS_EVENTS = frozenset({"push", "workflow_dispatch", "schedule", "release"})
    # More ways a script names a pull request's code than PR_FETCH_CMD_RE has. Used for the control
    # only: a script can always be written so that no pattern finds it, and the control's name
    # claims nothing about scripts.
    _PR_CODE_IN_SCRIPT_RE = re.compile(r"\bpr\s+(checkout|diff)\b|\bpull/[^\s/]+/(head|merge)\b|refs/pull/|/pull/\d+\.(patch|diff)\b")

    def _input_control(self, job: Job) -> Control:
        """Whether anything a pull request, an issue or a comment controls reaches the job through
        the three places the checker reads: the events that can start it, its `actions/checkout`
        steps, and the event fields its expressions and conditions read. A script that fetches a
        pull request's code by a command the checker knows is reported as well. What a script, another
        action or the agent itself fetches while the job runs is otherwise not read, and the control's
        name names only the three places."""
        name = ("no pull request, issue or comment starts the job, and its checkout steps and the event fields it "
                "reads take nothing from one")
        ident = "no-outsider-input"
        events = job.triggers()
        outsider = sorted(events & UNTRUSTED_TRIGGERS)
        if outsider:
            return Control(name, NOT_MET, f"it can be started by {', '.join(outsider)}", ident)
        unsure: list[str] = []
        other = sorted(one_line(event, 60) for event in events - self._WRITE_ACCESS_EVENTS)
        if not events:
            unsure.append("the checker found no event that starts the job")
        elif other:
            unsure.append(f"it can be started by {', '.join(other[:5])}{' and more' if len(other) > 5 else ''}, "
                          f"and the checker does not know what {'that event carries' if len(other) == 1 else 'those events carry'}")
        if job.reusable:
            unsure.append("its steps are in the reusable workflow it calls, which the checker does not read")
        default = fixed = 0
        for step in job.steps:
            where = f"step '{one_line(step.name, 80)}'"
            if step.uses_action("actions/checkout"):
                given = step.raw.get("with")
                if given is not None and not isinstance(given, dict):
                    unsure.append(f"{where} takes its inputs from an expression, so the checker cannot tell what "
                                  "it checks out")
                    continue
                ref, repository = str(step.with_.get("ref") or ""), str(step.with_.get("repository") or "")
                if PR_HEAD_REF_RE.search(f"{ref} {repository}") or self._PR_CODE_IN_SCRIPT_RE.search(ref.lower()):
                    return Control(name, NOT_MET, f"{where} checks out a pull request's code", ident)
                if repository:
                    unsure.append(f"{where} checks out another repository ({one_line(repository, 120)})")
                elif "${{" in ref:
                    unsure.append(f"{where} checks out a ref that is computed when the job runs "
                                  f"({one_line(ref, 120)})")
                elif ref:
                    fixed += 1
                else:
                    default += 1
            elif PR_FETCH_CMD_RE.search(step.text()) or self._PR_CODE_IN_SCRIPT_RE.search(step.text()):
                return Control(name, NOT_MET, f"{where} fetches a pull request's code", ident)
        # An `if:` is an expression with or without `${{ }}`, so a condition written without them
        # is read as well as every `${{ }}` in the job.
        conditions = [raw.get("if") for raw in [job.raw, *(step.raw for step in job.steps)]]
        bodies = [cond for cond in conditions if isinstance(cond, str) and expr_mod.OPEN not in cond]
        for value in (self.wf.raw.get("env"), job.raw):
            bodies.extend(expressions(value))
        for body in bodies:
            field = self._untrusted_text(body)
            if field:
                return Control(name, NOT_MET, f"it reads {one_line(field, 120)}, which someone without write "
                                              "access can write", ident)
        if unsure:
            more = f"; and {len(unsure) - 5} more" if len(unsure) > 5 else ""
            return Control(name, CANNOT_TELL, "; ".join(unsure[:5]) + more, ident)
        took = "; ".join(text for count, text in (
            (default, f"{default} checkout step(s) take the ref the event names"),
            (fixed, f"{fixed} checkout step(s) take a ref written in the workflow")) if count) or "no checkout step"
        return Control(name, VERIFIED, f"started only by {', '.join(sorted(events))}; {took}", ident)

    # -------------------------------------------------------------- GHA-006/014/015/016
    def release_rules(self, job: Job) -> None:
        if not job.in_lane("release"):
            return
        triggers = job.triggers()
        bad = triggers & UNTRUSTED_TRIGGERS
        if bad:
            self.add("OBAAF-GHA-015", job.line,
                     "Release job '{job}' can be started by {triggers}.", job, triggers=sorted(bad))

        cache_steps = [s for s in job.steps if self._restores_cache(s)]
        mode = job.cache_mode
        hosted_note = (" This job also runs on a self-hosted runner, where local caches (such as an engine's "
                       "derived-data cache) are outside what this check can see.") if job.self_hosted else ""
        runner = "-self-hosted" if job.self_hosted else ""
        if cache_steps and mode not in ("none", "write-only"):
            names = ", ".join(f"'{s.name}'" for s in cache_steps)
            self.add("OBAAF-GHA-006", cache_steps[0].line,
                     "Release job '{job}' restores caches in {steps} and its cache-mode is "
                     "{mode}." + hosted_note, job, cache_steps[0], kind="restores" + runner,
                     steps=Fact([s.name for s in cache_steps], names), mode=Fact(mode or "", mode or 'not set'))
        elif not cache_steps and mode != "none":
            self.add("OBAAF-GHA-006", job.line,
                     "Release job '{job}' does not set cache-mode: none, so a cache step added later would "
                     "read caches other workflows wrote." + hosted_note, job, severity="low",
                     kind="no-cache-mode" + runner)

        uploads = job.upload_steps(self.detection)
        if uploads:
            if not job.environment:
                self.add("OBAAF-GHA-014", job.line,
                         "Release job '{job}' uploads in '{step}' without a protected environment.",
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
                             "Step '{step}' uploads after a provenance check only; approvals and agent "
                             "records are not checked (use obaaf verify release).", job, first, severity="medium",
                             kind="provenance-only")
                else:
                    self.add("OBAAF-GHA-016", first.line,
                             "Step '{step}' uploads without an earlier check that stops it when "
                             "verification fails.", job, first, kind="unchecked")

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
                     "Job '{job}' can be started by {triggers} and declares "
                     "cache-mode: {mode}.", job, triggers=sorted(privileged), mode=mode)

    # -------------------------------------------------------------- GHA-008
    def unpinned(self, job: Job) -> None:
        permissions = job.permissions
        privileged = (not permissions or not permissions.declared or permissions.write_scopes()
                      or permissions.oidc or job.secret_names()
                      or job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS)
        severity = ("high" if any(job.in_lane(lane) for lane in ("release", "agent", "effect")) else
                    "medium" if privileged else "low")
        refs = [(s, s.uses, s.line) for s in job.steps if s.uses]
        if job.reusable and not job.reusable.startswith("./"):
            refs.append((None, job.reusable, job.line))
        for step, uses, line in refs:
            if uses.startswith("./"):
                continue
            if uses.startswith("docker://"):
                if "@sha256:" not in uses:
                    self.add("OBAAF-GHA-008", line, "Container '{uses}' is not pinned to a sha256 digest.", job,
                             step, severity, kind="container", uses=uses)
                continue
            ref = uses.split("@", 1)[1] if "@" in uses else ""
            if not FULL_SHA_RE.match(ref):
                what = "Reusable workflow" if step is None else "Action"
                self.add("OBAAF-GHA-008", line,
                         what + " '{uses}' is pinned to '{ref}', not a full commit SHA.", job, step,
                         severity, kind="reusable-workflow" if step is None else "action", uses=uses,
                         ref=Fact(ref, ref or 'nothing'))
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
            self.add("OBAAF-GHA-008", job.line, "Image '{image}' is not pinned to a sha256 digest.", job,
                     severity=severity, kind="image", image=image)

    # -------------------------------------------------------------- GHA-011
    def persisted_credentials(self, job: Job) -> None:
        exposed = (job.in_lane("agent") or job.in_lane("untrusted")
                   or bool(job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS))
        if not exposed:
            return
        for step in job.steps:
            if step.uses_action("actions/checkout") and not _falsy(step.with_.get("persist-credentials", "true")):
                self.add("OBAAF-GHA-011", step.line,
                         "Step '{step}' persists the job token for later steps.", job, step)

    # -------------------------------------------------------------- GHA-013
    def self_hosted(self, job: Job) -> None:
        kind = job.runner_kind
        if kind == "github-hosted":
            return
        untrusted = job.triggers() & UNTRUSTED_TRIGGERS
        if untrusted or job.in_lane("agent"):
            # Two cases of each message: the job can be started from outside, or it runs an agent.
            if untrusted:
                why, case, values = "can be started by {triggers}", "", {"triggers": sorted(untrusted)}
            else:
                why, case, values = "runs an agent", "-agent", {}
            labels = Fact(list(job.runs_on), ", ".join(job.runs_on) or "no labels")
            if kind == "self-hosted":
                self.add("OBAAF-GHA-013", job.line,
                         "Job '{job}' runs on a self-hosted runner ({labels}) and " + why + ".",
                         job, kind="self-hosted" + case, labels=labels, **values)
            else:
                if job.mixed_runner_expression:
                    self.add("OBAAF-GHA-013", job.line,
                             "Job '{job}' selects between hosted and self-hosted runners at runtime and " + why + ". "
                             "The checker cannot prove which runner receives untrusted work. Review the selector "
                             "and pool isolation; this informational finding does not certify it as safe.",
                             job, severity="info", kind="runtime-choice" + case, **values)
                else:
                    self.add("OBAAF-GHA-013", job.line,
                             "Job '{job}' runs on {labels}, which are not standard GitHub-hosted labels, and "
                             + why + ". If this is a self-hosted runner, it must be ephemeral.", job,
                             severity="medium", kind="other-labels" + case, labels=labels, **values)

    # -------------------------------------------------------------- GHA-018
    def signing_keys(self, job: Job) -> None:
        severity = "high" if job.in_lane("release") else "medium"
        patterns = [re.compile(p, re.I) for p in self.detection.get("signing_secret_patterns", [])]
        keys = sorted(n for n in job.secret_names() if not n.startswith("*") and any(p.search(n) for p in patterns))
        if keys:
            self.add("OBAAF-GHA-018", job.line,
                     "Job '{job}' loads signing material from secret(s): {secrets}.", job,
                     severity=severity, kind="secrets", secrets=keys)
        commands = [re.compile(p, re.M) for p in self.detection.get("signing_commands", [])]
        for step in job.steps:
            text = step.text()
            if text and any(rx.search(text) for rx in commands):
                self.add("OBAAF-GHA-018", step.line,
                         "Step '{step}' loads a signing key into the build environment.", job, step,
                         severity=severity, kind="command")

    # -------------------------------------------------------------- GHA-021/022
    def effect_rules(self, job: Job) -> None:
        if not job.in_lane("effect"):
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
                     "Job '{job}' applies another run's output without verifying the agent-run record or "
                     "checking the proposal.", job, kind="unchecked")
        elif done != {"record", "proposal"}:
            missing = "verify the agent-run record" if "record" not in done else "check the proposal"
            self.add("OBAAF-GHA-021", job.line,
                     "Job '{job}' applies another run's output but does not " + missing + " before applying it.",
                     job, severity="medium", kind="no-record" if "record" not in done else "no-proposal")
        if not (gated(job) or self._needs_gate(job, gated)):
            self.add("OBAAF-GHA-022", job.line,
                     "Job '{job}' applies another run's output with write access but has no approval "
                     "environment.", job)

    # -------------------------------------------------------------- GHA-017
    def provenance_missing(self) -> None:
        uploading = [j for j in self.wf.jobs.values() if j.in_lane("release") and j.upload_steps(self.detection)]
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
        # One finding for the workflow. It is reported on the first publishing job that is a release
        # job before anything else, as it was when a job had one lane, so an accepted finding stays
        # where the baseline has it; a job that is also an agent or effect job is named only when
        # there is no other.
        job = next((j for j in unverified if j.lane == "release"), unverified[0])
        self.add("OBAAF-GHA-017", job.line,
                 "Job '{job}' publishes artifacts, but no job in this workflow signs provenance for them.", job)


def _line_digests(text: str, hidden: list) -> list[str]:
    """For each hidden character, a digest of the line it is on. A line here ends only at a line
    feed. The line numbers the scanner reports come from `str.splitlines`, which also ends a line at
    a form feed, a vertical tab, U+0085, U+2028 and several more; text after one of those is still
    beside the character for a reader and for a direction override, so it is part of what is
    digested. An instruction file is read with every carriage return, alone or before a line feed,
    already turned into a line feed, so in a file each of those ends a line as well. If a carriage
    return does reach this function before a line feed, it is left out of the digest."""
    starts, at = [], 0
    for line in text.splitlines(keepends=True):
        starts.append(at)
        at += len(line)
    digests = []
    for h in hidden:
        offset = starts[h.line - 1] + h.column - 1
        begin = text.rfind("\n", 0, offset) + 1
        end = text.find("\n", offset)
        line = text[begin: len(text) if end == -1 else end]
        if line.endswith("\r"):
            line = line[:-1]
        digests.append(hashlib.sha256(line.encode("utf-8", "surrogatepass")).hexdigest()[:32])
    return digests


# ------------------------------------------------------------------- repository
def repo_findings(root: Path, workflow_paths: list[str], catalog: Catalog) -> list[Finding]:
    findings: list[Finding] = []
    codeowners_path, rules = repo_checks.read_codeowners(root)
    instruction_files = repo_checks.find_instruction_files(root, catalog.detection.get("instruction_files", []))

    def add(rule: str, path: str, line: int, template: str, kind: str = "", **values) -> None:
        message, facts = compose(rule, kind, template, None, None, values)
        findings.append(Finding(rule, catalog.rules[rule]["severity"], path, line, message, kind=kind, facts=facts))

    def files(paths: list[str]) -> dict:
        """The message names the first five files and counts them all; every one is part of the finding."""
        return {"count": Note(str(len(paths))), "files": Fact(sorted(paths), ", ".join(paths[:5]))}

    if codeowners_path is None:
        add("OBAAF-REPO-001", ".github/CODEOWNERS", 1, "The repository has no CODEOWNERS file.", kind="no-codeowners")
        if instruction_files:
            add("OBAAF-REPO-002", instruction_files[0], 1,
                "No CODEOWNERS file covers the {count} agent instruction file(s): {files}.", kind="no-codeowners",
                **files(instruction_files))
    else:
        uncovered = [p for p in workflow_paths if not repo_checks.owners_for(rules, p)]
        if uncovered:
            add("OBAAF-REPO-001", codeowners_path, 1, "No code owner for {count} CI definition file(s): {files}.",
                kind="no-owner", **files(uncovered))
        uncovered = [p for p in instruction_files if not repo_checks.owners_for(rules, p)]
        if uncovered:
            add("OBAAF-REPO-002", codeowners_path, 1, "No code owner for {count} agent instruction file(s): {files}.",
                kind="no-owner", **files(uncovered))

    for rel in instruction_files:
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hidden = repo_checks.scan_hidden(text)
        if hidden:
            detail = "; ".join(h.label for h in hidden[:3])
            more = f" and {len(hidden) - 3} more" if len(hidden) > 3 else ""
            # The finding is which characters the file hides and the text of the line each is on (as a
            # digest: the line may be long, and a baseline is not the place for it). A line that moves
            # up or down is the same finding; a character on other text is another one, because where
            # a direction override or an invisible instruction sits is what it does. The message
            # shows the first three with their line and column, and the count of all of them.
            marks = sorted(f"U+{h.codepoint:04X} ({h.kind}) on a line with sha256 {digest}"
                           for h, digest in zip(hidden, _line_digests(text, hidden)))
            add("OBAAF-INS-001", rel, hidden[0].line, "{count} hidden character(s): {characters}{more}.",
                count=Note(str(len(hidden))), more=Note(more), characters=Fact(marks, detail))
    return findings
