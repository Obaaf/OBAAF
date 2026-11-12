"""The OBAAF checker rules. Metadata (title, severity, fix) lives in data/rules.yaml."""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from obaaf.catalog import Catalog
from obaaf.checker import expr as expr_mod
from obaaf.checker import repo as repo_checks
from obaaf.checker.workflow import (
    FULL_SHA_RE, PR_FETCH_CMD_RE, PR_HEAD_REF_RE, PR_TRIGGERS, PRIVILEGED_UNTRUSTED_TRIGGERS, UNTRUSTED_FIELDS_RE,
    UNTRUSTED_PATHS, UNTRUSTED_TRIGGERS, Job, Step, Workflow, expressions, one_line, runs_after_failure,
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

    def __init__(self, workflow: Workflow, catalog: Catalog, protected: dict | None = None) -> None:
        self.wf = workflow
        self.catalog = catalog
        self.detection = catalog.detection
        self.protected = dict(protected or {})
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
            "unverified-monitor": "Agent job '{job}' runs a blocking egress monitor ({action}). The checker "
                                  "cannot yet tell whether it limits the agent.",
        }
        self.add("OBAAF-GHA-020", job.line, templates[kind], job, kind=kind, controls=[egress], **values)

    # ---------------------------------------------------- controls for GHA-005 and GHA-020
    def _egress(self, job: Job) -> tuple[Control, str, dict]:
        """What the checker can establish about a limit on the job's network access: the control,
        which case of OBAAF-GHA-020 it is, and that case's values.

        Nothing is `verified` yet. A step that uses a known monitor in block mode with no condition
        is "cannot tell": whether it holds depends on its version, on its running before the agent,
        and on the job being unable to undo it with sudo or a container, none of which is read. A
        monitor behind a condition, or a declaration alone, enforces nothing and is "not met"."""
        name = "a control the checker recognises limits the job's network access to an allow-list"
        declared = job.env.get("OBAAF_EGRESS") or self.wf.env.get("OBAAF_EGRESS")
        monitors = [step for step in job.steps
                    if any(step.uses_action(a) for a in self.detection.get("egress_actions", []))
                    and str(step.with_.get("egress-policy", "")).lower() == "block"]
        enforced = [m for m in monitors if "if" not in m.raw]
        if enforced:
            first = enforced[0]
            detail = (f"step '{one_line(first.name, 80)}' uses {first.action} in block mode, but the checker does "
                      "not read what makes that hold: its version, that it starts before the agent does, and "
                      "that the job cannot undo it with sudo or a container")
            return (Control(name, CANNOT_TELL, detail, "egress-enforced"), "unverified-monitor",
                    {"action": str(first.action)})
        if monitors:
            condition = str(monitors[0].raw.get("if"))
            return (Control(name, NOT_MET, f"its blocking egress monitor runs only if {one_line(condition, 120)}",
                            "egress-enforced"), "conditional", {"condition": condition})
        if declared:
            return (Control(name, NOT_MET, "OBAAF_EGRESS is a declaration, and nothing in the job enforces it",
                            "egress-enforced"), "declared", {"declared": str(declared)})
        return Control(name, NOT_MET, "no blocking egress control in the job", "egress-enforced"), "none", {}

    def _secret_controls(self, job: Job, names: set) -> list[Control]:
        """Two controls about where an agent job's secrets come from. The first is read from the
        workflow and the checker configuration: every secret the job receives is listed in
        `protected_secrets`, and the job declares the environment the entry names, which is what
        OBAAF-GHA-024 checks for the secrets that are listed. The second is a repository setting
        (the environment holds the secrets, nothing outside it does, and only protected branches
        may use it), which `obaaf check` does not read, so it is "cannot tell"."""
        scoped = "each of the job's secrets is listed in protected_secrets, and the job declares the environment named there"
        setting = "the secrets are stored only in that environment, and only protected branches may use it"
        declared = job.environment
        environment = f"environment '{one_line(declared, 120)}'" if declared else "the environment"
        unread = Control(setting, CANNOT_TELL,
                         f"where a secret is stored and which branches may use {environment} are repository "
                         "settings, which obaaf check does not read; obaaf audit reads environments and their "
                         "branch rules", "environment-restricted")

        def first(verdict: str, detail: str) -> list[Control]:
            return [Control(scoped, verdict, detail, "secrets-protected"), unread]

        if "*" in names or "*inherit" in names:
            return first(NOT_MET, "the job can take every secret, so it is not limited to protected ones")
        if job.reusable:
            return first(NOT_MET, "a job that calls a reusable workflow cannot declare an environment, so the "
                                  "secrets it passes come from the repository or organization")
        upper = sorted({str(n).upper() for n in names})
        wanted: dict = {}     # secret -> the environments its protected_secrets entries name (None: any)
        for secret in upper:
            wanted[secret] = [env for pattern, env in self.protected.items() if fnmatch.fnmatchcase(secret, pattern)]
        unlisted = [secret for secret in upper if not wanted[secret]]
        if unlisted:
            return first(NOT_MET, f"not listed in protected_secrets: {', '.join(unlisted)}")
        if not declared:
            return first(NOT_MET, "the job declares no environment")
        if "${{" in declared:
            return first(CANNOT_TELL, f"the job's environment is an expression ({one_line(declared, 120)}), which "
                                      "the checker cannot compare with the one protected_secrets names")
        elsewhere = sorted({env for envs in wanted.values() for env in envs
                            if env is not None and env.casefold() != declared.casefold()})
        if elsewhere:
            return first(NOT_MET, f"the job declares environment '{one_line(declared, 120)}', and "
                                  f"protected_secrets names {', '.join(repr(env) for env in elsewhere)}")
        return first(VERIFIED, f"{', '.join(upper)} in environment '{one_line(declared, 120)}'")

    # Events that only someone with write access can cause, and whose payload outsiders do not write.
    _WRITE_ACCESS_EVENTS = frozenset({"push", "workflow_dispatch", "schedule", "release"})

    def _input_control(self, job: Job) -> Control:
        """Whether anything a pull request, an issue or a comment controls reaches the job through
        the three places the checker reads: the events that can start it, its checkout steps (and
        the commands known to fetch a pull request), and the event fields its expressions read.
        What a script, an action or the agent itself fetches while the job runs is not read, and
        the control's name does not claim it."""
        name = "no pull request, issue or comment starts the job, and it takes no code or text from one"
        ident = "no-outsider-input"
        events = job.triggers()
        outsider = sorted(events & UNTRUSTED_TRIGGERS)
        if outsider:
            return Control(name, NOT_MET, f"it can be started by {', '.join(outsider)}", ident)
        unsure: list[str] = []
        other = sorted(events - self._WRITE_ACCESS_EVENTS)
        if not events:
            unsure.append("the checker found no event that starts the job")
        elif other:
            unsure.append(f"it can be started by {', '.join(other)}, and the checker does not know what "
                          f"{'that event carries' if len(other) == 1 else 'those events carry'}")
        if job.reusable:
            unsure.append("its steps are in the reusable workflow it calls, which the checker does not read")
        checkouts = 0
        for step in job.steps:
            where = f"step '{one_line(step.name, 80)}'"
            if step.uses_action("actions/checkout"):
                checkouts += 1
                given = step.raw.get("with")
                if given is not None and not isinstance(given, dict):
                    unsure.append(f"{where} takes its inputs from an expression, so the checker cannot tell what "
                                  "it checks out")
                    continue
                ref, repository = str(step.with_.get("ref") or ""), str(step.with_.get("repository") or "")
                if PR_HEAD_REF_RE.search(f"{ref} {repository}"):
                    return Control(name, NOT_MET, f"{where} checks out a pull request's code", ident)
                if repository:
                    unsure.append(f"{where} checks out another repository ({one_line(repository, 120)})")
                elif "${{" in ref:
                    unsure.append(f"{where} checks out a ref that is computed when the job runs "
                                  f"({one_line(ref, 120)})")
            elif PR_FETCH_CMD_RE.search(step.text()):
                return Control(name, NOT_MET, f"{where} fetches a pull request's code", ident)
        for value in (self.wf.raw.get("env"), job.raw):
            for body in expressions(value):
                field = self._untrusted_text(body)
                if field:
                    return Control(name, NOT_MET, f"it reads {field}, which someone without write access can "
                                                  "write", ident)
        if unsure:
            return Control(name, CANNOT_TELL, "; ".join(unsure), ident)
        took = {0: "it has no checkout step", 1: "its checkout step takes the ref the event names"}.get(
            checkouts, f"its {checkouts} checkout steps take the ref the event names or a fixed one")
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
