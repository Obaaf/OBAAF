"""The OBAAF checker rules. Metadata (title, severity, fix) lives in data/rules.yaml."""

from __future__ import annotations

import bisect
import collections
import copy
import fnmatch
import hashlib
import json
import re
import shlex
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from obaaf.settings_evidence import SettingsEvidence

from obaaf import agent_tools
from obaaf.catalog import Catalog
from obaaf.checker import agent_flags, artifact_consumers
from obaaf.checker import egress as egress_mod
from obaaf.checker import expr as expr_mod
from obaaf.checker import repo as repo_checks
from obaaf.checker.workflow import (
    COMMIT_SHA_RE, FULL_SHA_RE, IMAGE_DIGEST_RE, MERGE_COMMIT_REFS, MERGE_REF_EVENTS, PR_TRIGGERS, PRIVILEGED_UNTRUSTED_TRIGGERS,
    PULL_REQUEST_PAYLOAD_EVENTS, TRUSTED_WORKFLOW_RUN, EGRESS_ACTION, AgentActions, leaves_repository,
    UNTRUSTED_FIELDS_RE, UNTRUSTED_PATHS, UNTRUSTED_TRIGGERS, Job, PrCode, Step, Workflow, as_text, env_lookup, image_outputs_push, through_matrix,
    bounded, digest_of, environment_match, expressions, input_name, matches_any, one_line, pr_code, pr_fetch, runs_after_failure,
    LANE_ORDER, TRUSTED_NOTE, UNKNOWN_EXPRESSION, _inferred_lanes, _script_tokens, _sub_expressions, binding_commands, is_hosted_label, is_local_reference, scalar_environment_match, shown_value, upload_readings, value_identity,
)

PLACEHOLDER_SHA = "0" * 40


def _strings_in(value, limit: int) -> list:
    """The strings in a value of lists and mappings (a matrix), at most `limit` of them, each node once."""
    out: list = []
    stack, seen = [value], set()
    while stack and len(out) < limit:
        node = stack.pop()
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, (list, dict)) and id(node) not in seen:
            seen.add(id(node))
            stack.extend(node.values() if isinstance(node, dict) else node)
    return out
_OWNER_PLACEHOLDER_RE = re.compile(r"obaaf_owner", re.I)
_SHA_PLACEHOLDER_RE = re.compile(r"@0{40}(?![0-9a-fA-F])")


# Where a shell line starts another command (`_fetches_over` reads a fetch and its target in one command).
_COMMAND_SPLIT_RE = re.compile(r"\$\(|[;&|`\n]")


def _placeholders_in(text: str, where: str) -> list[str]:
    """The template placeholders a value holds: `OBAAF_OWNER` in any letter case, and the all-zero SHA
    after `@` (or as the whole ref of a `uses`)."""
    out = []
    if _OWNER_PLACEHOLDER_RE.search(text):
        out.append("OBAAF_OWNER")
    if _SHA_PLACEHOLDER_RE.search(text) or (where.rsplit(".", 1)[-1] == "uses" and text.strip() == PLACEHOLDER_SHA):
        out.append(PLACEHOLDER_SHA)
    return out


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

    action_conditions: tuple[str, ...] = field(default=(), compare=False, repr=False)

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
    # The message 0.3.0 wrote for this finding, where a later version words it differently, so that a
    # v0.1 baseline entry (identified by its message) still names it and `obaaf baseline migrate` carries
    # it over. Empty where the message is unchanged. It is never shown and is not part of a v0.2 identity.
    legacy: str = ""
    # Display-only evidence for the to-do list. A checked patch still needs an exact version and proof.
    pin_candidate: str | None = field(default=None, compare=False, repr=False)

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
    it: a count of the files or characters that are listed in full as a fact, or what the catalogue
    gives for a fact (the words of documentation an OBAAF-GHA-026 finding's `setting` names, and where
    they are, flagship slice 2d.5c1). Every other value given to `compose` is a fact. A note must never
    say something the facts do not."""


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
    which finding it is. One fact is itself text the checker wrote, and rewording it does change the
    finding: why a job is an agent job (`why`, in OBAAF-GHA-003 and 025). Since flagship slice 2d.5b the
    agents a job runs are also named, as the fact `agents`, by the catalogue's entries.
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


# How many entries of what callers pass a secrets finding names in full (flagship slice 2d.4b1): up to
# PASSED_NAMED (and 1,000 characters), every one; beyond that, at most the first PASSED_SHOWN that fit in
# 1,000 characters, and a digest of all.
PASSED_NAMED = 5
PASSED_SHOWN = 3


def _truthy(value) -> bool:
    return as_text(value).strip().lower() in ("true", "1", "yes")


def _falsy(value) -> bool:
    return as_text(value).strip().lower() in ("false", "0", "no")


_CONSTANT_RE = re.compile(r"\s*\$\{\{\s*(true|false|'[^']*'|[0-9]{1,9})\s*\}\}\s*", re.I)


def _constant(value):
    """An input written as one expression that is a constant (`${{ false }}`, `${{ 'true' }}`) as
    the text GitHub hands the action; anything else as it is."""
    if isinstance(value, str):
        match = _CONSTANT_RE.fullmatch(value)
        if match:
            literal = match.group(1)
            return literal[1:-1].replace("''", "'") if literal.startswith("'") else literal.lower()
    return value


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


def _continues_on_error(raw) -> bool:
    """Whether a job's or step's `continue-on-error` may be true: anything but absent or false."""
    value = raw.get("continue-on-error") if isinstance(raw, dict) else None
    return value not in (None, False) and "".join(as_text(value).split()).lower() not in ("false", "${{false}}")


# Expressions whose value cannot hold shell syntax: numbers, commit hashes, names GitHub restricts to
# letters, digits, `-`, `_` and `.`, and runner paths (flagship slice 2d.2e).
_SHELL_SAFE_EXPRESSIONS = frozenset({
    "github.sha", "github.run_id", "github.run_number", "github.run_attempt", "github.repository",
    "github.repository_owner", "github.repository_id", "github.workspace", "github.job", "github.server_url",
    "github.api_url", "runner.temp", "runner.os", "runner.arch", "runner.tool_cache", "github.event.number",
    "github.event.workflow_run.id", "github.event.workflow_run.head_sha", "github.event.workflow_run.run_number",
    "github.event.pull_request.number", "github.event.release.id",
})


def _expressions_for_shell(script: str) -> str:
    """A script as bash will read it, as far as the checker can tell (flagship slice 2d.2e). GitHub puts
    an expression's value into the script before the shell reads it, so a value can add shell syntax:
    a text written in the expression (`${{ '|| true' }}`) is put in as it is, an expression whose value
    cannot hold shell syntax becomes one plain word, and any other is marked as unknown, which ends what
    the reader counts."""
    def put(expression: str) -> str:
        body = expression[3:-2].strip()
        if "".join(body.split()).lower() in _SHELL_SAFE_EXPRESSIONS:
            return "OBAAF_EXPRESSION"
        text = re.fullmatch(r"'((?:[^']|'')*)'", body)
        if text:
            return text.group(1).replace("''", "'")
        if re.fullmatch(r"[0-9]{1,9}|true|false", body, re.I):
            return body.lower()
        return UNKNOWN_EXPRESSION
    return _sub_expressions(script, put)


def _strip_comment_text(line: str) -> str:
    from obaaf.checker.workflow import _strip_comment
    return _strip_comment(line)


# Actions that restore a GitHub Actions cache whatever their inputs, or that hand the cache service's
# token to the steps after them (flagship slice 2d.2e).
# Flagship slice 2d.13 (F-278). Names that, given to a bash or sh step, change what its shell runs or what
# the programs it names run: which program a name finds (`PATH`); bash's start and its reading
# (`BASH_ENV`, `ENV`, `SHELLOPTS`, whose `noexec` makes bash read the script and run none of it,
# `BASHOPTS`, `BASH_FUNC_NAME%%`, `BASH_COMPAT`, `PS4`, `EXECIGNORE` and the rest of `BASH...`); the
# loader's (`LD_...` and `GCONV_PATH` on Linux, `DYLD_...` on macOS, whose `DYLD_INSERT_LIBRARIES` the runner
# keeps for each step's process there), which load code into every program the step starts, bash included;
# Python's, which load code into `obaaf` (`PYTHONPATH`, `PYTHONHOME`, `PYTHONWARNINGS`, `PYTHONUSERBASE`
# and the rest of `PYTHON...`), and `HOME`, under which an interpreter outside a virtual environment
# finds the user's own packages; and `ACTIONS_ALLOW_UNSECURE_COMMANDS`, with which any line a later step
# prints can set the others. The checks OBAAF counts are `obaaf` (Python) and `gh`, `cosign` and
# `slsa-verifier` (Go); Node.js's, Perl's, Ruby's and Java's variables (`NODE_OPTIONS`, `PERL5OPT`,
# `RUBYOPT`, `JAVA_TOOL_OPTIONS`) change none of them and not bash, so they are not here. What the
# programs read for their own settings (`GIT_...`, `GH_...`, `SSL_CERT_FILE`) is not read.
_STEERING_NAMES = frozenset({"PATH", "ENV", "SHELLOPTS", "PS4", "PROMPT_COMMAND", "EXECIGNORE", "GCONV_PATH", "HOME",
                             "ACTIONS_ALLOW_UNSECURE_COMMANDS"})
_STEERING_PREFIXES = ("BASH", "LD_", "DYLD_", "PYTHON")
# Python's variables that load nothing: output buffering, bytecode files, the standard streams' encoding
# (looked up only among the standard library's `encodings` modules, a name with a dot refused), UTF-8
# mode, the hash seed, and turning the user's own packages off.
_PYTHON_PLAIN = frozenset({"PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PYTHONIOENCODING", "PYTHONUTF8",
                           "PYTHONHASHSEED", "PYTHONNOUSERSITE"})


def steers(name) -> bool:
    """Whether a variable's name, read the widest way (space around it trimmed, any letter case), is one
    that changes what a bash or sh step runs or what the programs it names run (`_STEERING_NAMES`)."""
    text = str(name).strip().upper()
    return text in _STEERING_NAMES or (text.startswith(_STEERING_PREFIXES) and text not in _PYTHON_PLAIN)


_NAMES_GITHUB_ENV = re.compile(r"GITHUB_ENV", re.I)
# The runner's file commands. It names a step's files side by side with one suffix
# (`FileCommandManager.InitializeFiles`, v2.338.2), so the path of any of them leads to GITHUB_ENV's.
_NAMES_FILE_VAR = re.compile(r"GITHUB_(ENV|PATH|OUTPUT|STATE|STEP_SUMMARY)", re.I)
_ANSI_C_RE = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.S)


def _squeeze(text: str) -> str:
    """Text as bash puts a word together, for searching names: a backslash and the line break after it (a
    continued line) taken out, `$'...'` decoded, `$""` taken out, then quotes, backslashes and the
    lexer's `\x03` marks. So `$GITHUB_\\<line break>ENV`, `GITHUB_E""NV`, `GITHUB_E\\NV` and
    `$'GITHUB_\x45NV'` are found (the reviews of slice 2d.13; the lexer reads the first as `$GITHUB_` and
    `ENV`). It can join what bash keeps apart, which only finds more."""
    text = re.sub(r"\\\r?\n", "", text)

    def decoded(match):
        try:
            return agent_flags._ansi_c(match.group(1))
        except (AttributeError, ValueError, OverflowError):
            return match.group(0)

    text = _ANSI_C_RE.sub(decoded, text).replace('$""', "")
    return re.sub(r"[\"'\\\x03]", "", text)


def _names_file_var(text: str) -> bool:
    return bool(_NAMES_FILE_VAR.search(text) or _NAMES_FILE_VAR.search(_squeeze(text)))


# A redirection's target as the lexer gives it, naming one of the files plainly: `$NAME`, `${NAME}`, or
# `${NAME:-/dev/stdout}` (or stderr, or null), which keeps a script runnable outside Actions.
_FILE_TARGET_RE = re.compile(r"\x03\$(?:(GITHUB_[A-Z_]+)|\{(GITHUB_[A-Z_]+)(?::-/dev/(?:stdout|stderr|null))?\})\x03\Z")
_ENV_LINE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# Words that may begin a command before its name; the lexer gives `then echo ...` as one command.
_LEADING_WORDS = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!", "{"})
# The redirections that write to GITHUB_ENV from its end, or from its start after emptying it.
_WRITE_OPS = frozenset({">>", ">", "&>>", "&>", ">|", ">&"})
# A continued line beside an operator's character: bash joins the line first, so `<\<line break>>` is
# `<>`, while the lexer reads `<` and `>` (the fourth review of slice 2d.13).
_SPLIT_OPERATOR_RE = re.compile(r"[<>&|]\\\r?\n|\\\r?\n[<>&|]")
# What a write's output may also be sent to beside GITHUB_ENV: a duplicated descriptor (`2>&1`) or nothing.
_OTHER_TARGETS = frozenset({"/dev/null"})
# A `printf` format the checker reads: `NAME=` (or `NAME<<`) and text, `%s` its only conversion, and at
# most one escape, a line break at its end.
_PRINTF_FORMAT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(=|<<)([^%\\\n\r\x03]|%s)*(\\n)?\Z")
# An assignment in a command substitution in a written value could print it on a line of its own. Upper
# case only, as a variable's name is written (`--home=` is an option); anchored, so a long word is cheap.
_ASSIGNED_NAME_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Z_][A-Z0-9_]*)\s*(=|<<)")
# `${!PREFIX*}` and `${!PREFIX@}` list the names of variables; with a prefix of a file command's name
# (or none) they reach its path without naming it (`${!GITHUB_E*}`, the first review of slice 2d.13).
_NAMES_LISTED_RE = re.compile(r"\$\{!\s*([A-Za-z_][A-Za-z0-9_]*)?\s*[*@]\s*\}")
# `tee` writing an output, the step summary or the state: its options that change nothing else.
_TEE_OPTIONS = frozenset({"-a", "--append", "-i", "--ignore-interrupts", "-p"})
# Ways a script can make `echo` or `printf` something other than bash's own: a function, a builtin
# loaded or turned off, an alias (which bash expands only after `shopt -s expand_aliases`).
_ECHO_REPLACED_RE = re.compile(r"(?<![\w./-])(function|enable|alias|shopt)(?![\w./-])|"
                               r"(?<![\w./-])(echo|printf)\s*\(\s*\)")


def _lists_file_vars(text: str) -> bool:
    for match in _NAMES_LISTED_RE.finditer(text):
        prefix = (match.group(1) or "").upper()
        if any(name.startswith(prefix) for name in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STATE",
                                                       "GITHUB_STEP_SUMMARY")):
            return True
    return False


def _file_target(word) -> str | None:
    match = _FILE_TARGET_RE.match(word.text) if word.redirect else None
    return (match.group(1) or match.group(2)) if match else None


def _github_env_names(script: str) -> set | None:
    """The names a bash or sh script writes to GITHUB_ENV, or None when the checker cannot read them all
    (flagship slice 2d.13). The script is read with the lexer. A file command's variable (`GITHUB_ENV`,
    `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE`, `GITHUB_STEP_SUMMARY`, found with `_squeeze`) may
    appear only as a redirection's target written plainly (`$NAME`, `${NAME}`, `${NAME:-/dev/stdout}`) of
    a command other than `exec`, or as a file `tee` writes an output, the summary or the state to, its own
    output sent to no file command; anywhere else (an argument,
    an assignment, `set --`, `for`, `read`, `printf -v`, a name reference, a here-document, a command
    substitution, a parameter expansion that changes it) gives None, because the runner's files sit side
    by side and any of their paths leads to GITHUB_ENV's (the second review of slice 2d.13), and so does
    listing names with `${!GITHUB_E*}` and any write to GITHUB_PATH. A write to GITHUB_ENV is read in two
    forms, redirected with `>>`, `>`, `&>>`, `&>`, `>|` or `>&` (`<>` writes over what is there, and is
    refused, and so is a script with a continued line beside an operator's character, which bash joins
    into an operator the lexer reads in two), `2>&1` or `/dev/null` beside it, and no `$'...'` in a word
    (dash, Ubuntu's sh, does not read it, and its `echo` reads the backslash): `echo` with words and no
    option, the name
    before the first `=` (or `<<`, the runner's multi-line form) a plain word written out in the
    script; and `printf` with a literal format that begins with such a name, has `%s` for its only
    conversion and no escape but a line break at its end. Any other write gives None, as does a name put
    together from a variable, an expression, a glob or a brace expansion, a word that can put a line
    break in what is printed (a backslash, which sh's `echo` reads as an escape, or a line break written
    inside quotes), a written value with a command substitution, nested or not, whose script assigns a
    steering name in upper case (it could print it on a line of its own), a script that can replace
    `echo` or `printf`, and a script the lexer cannot read. A value is otherwise read as one line: a line
    break that a variable, a file or a command's output puts in it at run time, which would let the write
    set a second name, is not read (an outsider's text there is also #232). Every line the runner reads
    begins where a write begins, and the lines of the runner's multi-line form are each read as a name,
    so this is never fewer names than the runner sets."""
    if _lists_file_vars(_squeeze(script)):
        return None
    commands, problem = agent_flags.lex(script)
    if problem:
        return None
    names: set = set()
    for command in commands:
        if any(_names_file_var(text) for _kind, text, _literal in command.stdin):
            return None             # a here-document or here-string that names one
        if any(_names_file_var(inner) for word in command.words for inner in word.inner):
            return None             # a command substitution that names one
        mentions = [w for w in command.words if _names_file_var(w.text) or _names_file_var(w.shown)]
        if not mentions:
            continue
        words = list(command.words)
        while words and not words[0].redirect and not words[0].computed and words[0].text in _LEADING_WORDS:
            words.pop(0)
        if not words:
            return None
        targets = {_file_target(w) for w in mentions}
        if words[0].text == "tee" and not words[0].computed and all(
                (w.redirect and not (_names_file_var(w.text) or _names_file_var(w.shown))) or w.text in _TEE_OPTIONS
                or (not w.redirect and _FILE_TARGET_RE.match(w.text) and
                    (_FILE_TARGET_RE.match(w.text).group(1) or _FILE_TARGET_RE.match(w.text).group(2))
                    in ("GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"))
                for w in words[1:]):
            continue                # `tee -a "$GITHUB_OUTPUT"`, its own output not sent to a file command
        if None in targets or "GITHUB_PATH" in targets or not targets <= {
                "GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"}:
            return None
        if words[0].text == "exec":
            return None             # a descriptor left open on a file command, whose path `/proc` then gives
        if "GITHUB_ENV" not in targets:
            continue                # a write to an output, the summary or the state
        if _ECHO_REPLACED_RE.search(script) or _SPLIT_OPERATOR_RE.search(script):
            return None
        if words[0].redirect or words[0].computed or words[0].text not in ("echo", "printf"):
            return None
        arguments = [w for w in words[1:] if not w.redirect]
        # Only a redirection that writes from where the file ends, or from its start after emptying it: `<>`
        # writes over what is there, which can turn an earlier line into another name (the third review).
        if any(_file_target(w) == "GITHUB_ENV" and w.redirect_op not in _WRITE_OPS for w in words[1:]):
            return None
        # sh is dash on Ubuntu, which does not read `$'...'` and passes the backslash to its `echo`.
        if any("$'" in w.shown or '$"' in w.shown for w in arguments):
            return None
        if not arguments or any(_file_target(w) not in (None, "GITHUB_ENV") for w in words[1:] if w.redirect) or any(
                w.redirect and _file_target(w) is None and w.text not in _OTHER_TARGETS and not w.text.isdigit()
                for w in words[1:]):
            return None
        for word in arguments:
            shown = _squeeze(word.shown)
            if ("$(" in word.shown or "`" in word.shown) and any(
                    steers(m.group(1)) for m in _ASSIGNED_NAME_RE.finditer(shown)):
                return None
        if words[0].text == "printf":
            form = arguments[0]
            if form.computed or not _PRINTF_FORMAT_RE.match(form.text) or any(
                    c in w.text for w in arguments[1:] for c in "\\\n\r"):
                return None
            line = form.text
        else:
            if arguments[0].text.startswith("-") or any(c in w.text for w in arguments for c in "\\\n\r"):
                return None
            line = " ".join(w.text for w in arguments)
        equals, heredoc = line.find("="), line.find("<<")
        cut = equals if equals >= 0 and (heredoc < 0 or equals < heredoc) else heredoc
        # The name is a plain word: no unknown expansion (marked `\x03`), glob or brace in it.
        if cut < 0 or not _ENV_LINE_NAME_RE.match(line[:cut]):
            return None
        names.add(line[:cut])
    return names


_ALWAYS_CACHES = ("Swatinem/rust-cache", "hendrikmuhs/ccache-action", "mozilla-actions/sccache-action",
                  "DeterminateSystems/magic-nix-cache-action", "crazy-max/ghaction-github-runtime")


def _through_view(workflow: Workflow, detection: dict | None = None, agents: dict | None = None) -> Workflow:
    """A copy of `workflow` whose jobs have, after each step that uses a local composite action, the
    steps of that action (`Job.local_steps`), numbered in the order they run (flagship slice 2d.4b2). A
    job's own steps keep their names, so a finding on one is the finding the first pass would give, and
    the steps that run an agent are renumbered with them. Nothing of `workflow` is changed."""
    view = copy.copy(workflow)
    view.jobs = {job_id: through_job(job, view, detection, agents) if job.local_steps else job
                 for job_id, job in workflow.jobs.items()}
    return view


def through_job(job: Job, workflow: Workflow, detection: dict | None = None, agents: dict | None = None) -> Job:
    """A copy of `job` in `workflow` whose steps are its own, each followed by the steps of the local
    composite action it uses, numbered in the order they run (flagship slice 2d.4b2). With `detection`,
    the copy is also put in each lane those steps put a job in (a step that publishes makes a release
    job), as the job's own steps would; the job itself is left in its lanes, so its findings and their
    reasons in the first pass are as they were."""
    copied = copy.copy(job)
    steps: list = []
    renumbered: dict = {}
    for step in job.steps:
        renumbered[step.index] = len(steps)
        steps.append(replace(step, index=len(steps), shown_name=step.name))
        for inner in job.local_steps.get(step.index, ()):
            steps.append(replace(inner, index=len(steps)))
    copied.steps = steps
    copied.workflow = workflow
    copied.lanes = dict(job.lanes)
    copied.agent_script_steps = {renumbered[i] for i in job.agent_script_steps if i in renumbered}
    copied.agent_step_why = {renumbered[i]: why for i, why in job.agent_step_why.items() if i in renumbered}
    if detection is not None:
        for lane, why in _inferred_lanes(copied, detection, agents or {}).items():
            if lane not in copied.lanes and lane in LANE_ORDER:
                copied.lanes[lane] = f"{why}, in a local action it uses"
        # The lane the job is shown in is left as it was: it decides which lane's reason carries the job's
        # lane notes, a fact of the release rules' findings (the first review found a trusted job that an
        # action made an effect job lose "declared trusted" from its OBAAF-GHA-015). `--lanes` settles it.
    return copied


# What the jobs of a called local workflow do, counted for the job that calls it (flagship slice 2d.4b3b):
# at most CALL_EFFECTS_KEPT entries of each kind are kept to be named, and at most CALL_EFFECTS_DISTINCT
# distinct entries are counted and digested; past that a summary holds the digests of what it was made
# from, so a chain or a fan of calls costs what it reads and no more, and a change to any entry changes
# the finding. Two paths to one step are one entry (the first review found a lattice of 30 calls
# counted 1,073,741,824 entries for one step).
CALL_EFFECTS_KEPT = 50
CALL_EFFECTS_DISTINCT = 2000


@dataclass(frozen=True)
class CallSummary:
    """Entries of one kind: the first CALL_EFFECTS_KEPT in the order they were found, every distinct one
    up to CALL_EFFECTS_DISTINCT, and, past that, the digests of the parts that did not fit."""
    kept: tuple = ()
    entries: frozenset = frozenset()
    overflow: frozenset = frozenset()       # digests of parts whose entries did not fit

    @classmethod
    def of(cls, entries: list) -> "CallSummary":
        distinct = list(dict.fromkeys(entries))
        if len(distinct) <= CALL_EFFECTS_DISTINCT:
            return cls(tuple(distinct[:CALL_EFFECTS_KEPT]), frozenset(distinct))
        rest = cls(entries=frozenset(distinct[CALL_EFFECTS_DISTINCT:]))
        return cls(tuple(distinct[:CALL_EFFECTS_KEPT]), frozenset(distinct[:CALL_EFFECTS_DISTINCT]),
                   frozenset({rest.digest}))

    @property
    def count(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries or self.overflow)

    @property
    def more(self) -> bool:
        """Whether entries did not fit, so `count` is a lower bound."""
        return bool(self.overflow)

    @property
    def digest(self) -> str:
        text = "\n".join(sorted(self.entries)) + "".join(f"\n+{d}" for d in sorted(self.overflow))
        return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()

    def __add__(self, other: "CallSummary") -> "CallSummary":
        if not other.entries and not other.overflow:
            return self
        if not self.entries and not self.overflow and len(other.entries) <= CALL_EFFECTS_DISTINCT:
            return other
        kept = tuple(dict.fromkeys(self.kept + other.kept))[:CALL_EFFECTS_KEPT]
        entries = self.entries | other.entries
        overflow = self.overflow | other.overflow
        if len(entries) > CALL_EFFECTS_DISTINCT:
            # The larger part's entries are kept (each part holds at most CALL_EFFECTS_DISTINCT), so the
            # count stays a true lower bound; the other part is kept by its digest, so past the bound the
            # digest can depend on the order the parts were added in.
            bigger, smaller = (self, other) if len(self.entries) >= len(other.entries) else (other, self)
            entries = bigger.entries
            overflow = overflow | {smaller.digest}
        return CallSummary(kept, entries, overflow)


@dataclass
class CallEffects:
    """What the jobs of the workflows a job calls by their path do, followed through the calls they make
    in turn (flagship slice 2d.4b3b). `releasing` names each called job in the release lane, and why;
    `restoring` each step that may restore a cache in a called job that is not a release job (a release
    job's own are its own finding), where neither that job's cache-mode nor that of a calling job between
    forbids it; `downloads` is whether a called release job downloads the run's artifacts, and
    `downloads_any` whether any called job does. `lane_given` is whether the call is what put the calling
    job in the release lane."""
    releasing: CallSummary = field(default_factory=CallSummary)
    restoring: CallSummary = field(default_factory=CallSummary)
    downloads: bool = False
    first_release: tuple = ()          # (called workflow's path, path, job id, reason) of the first releasing job
    lane_given: bool = False
    downloads_any: bool = False
    restores_any: bool = False      # whether any called job, release job or not, may restore a cache


def _forbids_restores(mode) -> bool:
    """Whether a cache-mode as the checker reads it forbids restoring caches: exactly `none` or `write-only`."""
    return mode in ("none", "write-only")


def _local_like(uses) -> bool:
    """A `uses` that may name an action of the repository itself (`./`, `$/` or `.\\` at its start, after any
    space), read as the checker reads a local action for an agent."""
    return isinstance(uses, str) and uses.strip().startswith(("./", "$/", ".\\"))


def _image_build_only(step: Step, job: Job | None = None) -> bool:
    """Whether a step that uses `docker/build-push-action` can only build an image (flagship slice 2d.14):
    its `with`, if written, is a mapping; `push` (in any letter case, as GitHub reads inputs) is not given
    or is `false` in any case; and no output of its `outputs` may push (`workflow.image_outputs_push`).
    Any other value, `push:` with no value included, is read as one that may push. `docker/bake-action` reads what it
    pushes from files the checker does not read, so it is never taken to build only."""
    raw = step.raw.get("with")
    if not step.uses_action("docker/build-push-action") or (raw is not None and not isinstance(raw, dict)):
        return False
    push = as_text(step.with_.get("push", "")).strip().lower()
    return push in ("", "false") and not through_matrix(step.with_.get("outputs", ""), job, image_outputs_push)


# What a workflow's jobs give a job that calls it: (releasing, restoring, a release job downloads, the first
# release, any job downloads, any job may restore a cache).
_NO_PARTS = (CallSummary(), CallSummary(), False, (), False, False)


def _joined(a: tuple, b: tuple) -> tuple:
    return (a[0] + b[0], a[1] + b[1], a[2] or b[2], a[3] or b[3], a[4] or b[4], a[5] or b[5])


def give_call_effects(groups: list, detection: dict, agents: dict | None = None) -> None:
    """Give each job that calls workflows of the repository what their jobs do (`Job.call_effects`), and put
    it in the release lane when one of them is a release job (flagship slice 2d.4b3b). A called workflow's
    jobs run as jobs of the caller's run, with the caller's token and secrets and its run's artifacts, and
    GitHub gives them no more cache access than the calling job has, so a release made inside one is the
    calling job's too. `groups` are the groups of workflows that call each other, callers' groups first, as
    `checker._give_callers` returns them; they are worked out callees first, so a chain of calls is one
    pass. The files of a cycle, which GitHub refuses, are read as one: each calling job in it is given
    everything any of them does, the wider reading, and a calling job's cache-mode inside it forbids
    nothing. Only the jobs of a workflow some job calls are read for it.

    A job in the release lane only through a call passes up what the jobs it calls restore, which nothing
    reports for it; a job declared a release job does not, because those restores are its own finding
    (`called-restores`), and every job it calls counts as part of the release it declares."""
    summaries: dict = {}

    def own(workflow, job) -> tuple:
        view = through_job(job, workflow, detection, agents) if job.local_steps else job
        downloads = any(step.uses_action("actions/download-artifact") for step in view.steps)
        restores = not _forbids_restores(job.cache_mode) and any(WorkflowRules._restores_cache(s) for s in view.steps)
        if view.in_lane("release"):
            reason = one_line(view.reason_for("release"), 200)
            entry = f"job '{one_line(job.id, 60)}' of {one_line(workflow.path, 120)} ({reason})"
            return (CallSummary.of([entry]), CallSummary(), downloads, (workflow.path, job.id, reason), downloads,
                    restores)
        restoring = CallSummary()
        if restores:
            restoring = CallSummary.of([
                f"job '{one_line(job.id, 60)}' of {one_line(workflow.path, 120)}, {WorkflowRules._cache_step(step)}"
                for step in view.steps if WorkflowRules._restores_cache(step)])
        return CallSummary(), restoring, False, (), downloads, restores

    for group in reversed(groups):
        members = {id(workflow) for workflow in group}
        cycle = len(group) > 1 or any(target is workflow for workflow in group for job in workflow.jobs.values()
                                      for target in job.called)
        # What each file of the group that some job calls does by its own jobs.
        outside: dict = {}
        for workflow in group:
            part = _NO_PARTS
            if workflow.callers:
                for job in workflow.jobs.values():
                    if not job.called:
                        part = _joined(part, own(workflow, job))
            outside[id(workflow)] = part
        together = _NO_PARTS
        if cycle:
            for workflow in group:
                together = _joined(together, outside[id(workflow)])
                for job in workflow.jobs.values():
                    for target in job.called:
                        if id(target) not in members:
                            together = _joined(together, summaries[id(target)])
        for workflow in group:
            summary = outside[id(workflow)]
            for job in workflow.jobs.values():
                if not job.called:
                    continue
                effects = CallEffects()
                for target in job.called:
                    got = together if cycle and id(target) in members else summaries[id(target)]
                    effects.releasing = effects.releasing + got[0]
                    effects.restoring = effects.restoring + got[1]
                    effects.downloads = effects.downloads or got[2]
                    effects.downloads_any = effects.downloads_any or got[4]
                    effects.restores_any = effects.restores_any or got[5]
                    if not effects.first_release and got[3]:
                        effects.first_release = (target.path, *got[3])
                job.call_effects = effects
                if effects.releasing and not job.in_lane("release"):
                    target_path, path, job_id, reason = effects.first_release
                    where = "whose job" if path == target_path else f"where, in {one_line(path, 120)}, job"
                    if job.trusted_declared and TRUSTED_NOTE not in job.lane_notes:
                        # As `classify` says of a job declared trusted that its own steps put in a lane.
                        job.lane_notes.append(TRUSTED_NOTE)
                    job.add_lane("release", one_line(f"calls {one_line(target_path, 120)}, {where} "
                                                     f"'{one_line(job_id, 60)}' is a release job ({reason})", 300))
                    effects.lane_given = True
                open_ = not _forbids_restores(job.cache_mode) or cycle
                restoring = effects.restoring if open_ else CallSummary()
                restores_any = effects.restores_any and open_
                if job.in_lane("release") and not effects.lane_given:
                    # Declared a release job: what it calls is the release it declares, and its restores are its
                    # own finding (`called-restores`).
                    reason = one_line(job.reason_for("release"), 200)
                    releasing = effects.releasing or CallSummary.of(
                        [f"job '{one_line(job.id, 60)}' of {one_line(workflow.path, 120)} ({reason})"])
                    first = effects.first_release[1:] if effects.first_release else (workflow.path, job.id, reason)
                    part = (releasing, CallSummary(), effects.downloads_any, first, effects.downloads_any, restores_any)
                else:
                    first = effects.first_release[1:] if effects.first_release else ()
                    part = (effects.releasing, restoring, effects.downloads, first, effects.downloads_any, restores_any)
                summary = _joined(summary, part)
            summaries[id(workflow)] = summary


class WorkflowRules:
    """Applies every workflow rule to one parsed workflow."""

    def __init__(self, workflow: Workflow, catalog: Catalog, protected: dict | None = None,
                 agents: dict | None = None, firewall: "egress_mod.FirewallPolicy | None" = None,
                 settings: SettingsEvidence | None = None, artifact_sources=None) -> None:
        self.artifact_sources = artifact_sources if artifact_sources is not None else artifact_consumers.uploads([workflow])
        self.wf = workflow
        self.catalog = catalog
        self.detection = catalog.detection
        self.protected = dict(protected or {})
        # The `agents` section of the configuration, and what was read of the repository's policy for
        # GitHub's native egress firewall (None when no repository was checked, only files).
        self.agents = dict(agents or {})
        self.settings = settings
        self.firewall = firewall
        self.findings: list[Finding] = []

    def add(self, rule: str, line: int, template: str, job: Job | None = None, step: Step | None = None,
            severity: str | None = None, *, kind: str = "", controls: list | None = None, legacy: str = "",
            pin_candidate: str | None = None, **values) -> None:
        """Report a finding. `template` is the message, with `{job}`, `{step}` and one `{name}` for
        each of `values`; `kind` tells a rule's cases apart (see `compose`). `controls` are the
        controls that would clear the finding, each with what the checker established about it."""
        job_id, step_name = (job.id if job else None), (step.name if step else None)
        message, facts = compose(rule, kind, template, job_id, step_name, values)
        if legacy:
            legacy = legacy.format(job=job_id or "", step=step_name or "", **{
                name: (value.shown if isinstance(value, Fact) else ", ".join(str(v) for v in value)
                       if isinstance(value, (list, tuple, set, frozenset)) else str(value))
                for name, value in values.items()})
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
            legacy=legacy if legacy != message else "",
            pin_candidate=pin_candidate,
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
            self.artifact_consumer(job)
            self.agent_tool_installs(job)
            self.agent_tool_settings(job)
            self.release_rules(job)
            self.unpinned(job)
            self.persisted_credentials(job)
            self.self_hosted(job)
            self.cache_write_low_trust(job)
            self.signing_keys(job)
            self.effect_rules(job)
        self.provenance_missing()
        self.through_local_actions()
        return self.findings

    # ------------------------------------------------- the steps of local composite actions
    def through_local_actions(self) -> None:
        """Read the steps of the local composite actions the jobs use as the jobs' own steps (flagship
        slice 2d.4b2). A job's step that uses `./path` runs that action's steps in the job, on its runner,
        with its token, workspace and cache, so a checkout, a cache, a publish or an unpinned action there
        is the job's. Every rule is run again on a copy of the workflow in which each such step is followed
        by the action's steps (`Job.local_steps`, with the inputs put in), and the job is in the lanes they
        put it in. The second pass's findings are taken:

        - every finding on a step of a local action, which names the action and the step;
        - a finding on a job's own step, or on the job, of a case the first pass gave there, in its place;
        - a finding of another case, where the first pass has none of that rule there as severe, or where
          the action's steps put the job in a lane it was not in.

        A first-pass finding replaced so has what the action's steps do in its facts and controls, as for
        steps written in the job, unless the replacement is less severe or nearer to cleared: reading
        through never clears a finding, lowers one, or drops one the second pass does not give (a check
        inside an action does not clear an upload in the job)."""
        if getattr(self, "_through", False) or not any(job.local_steps for job in self.wf.jobs.values()):
            return
        view = _through_view(self.wf, self.detection, self.agents)
        second = WorkflowRules(view, self.catalog, protected=self.protected, agents=self.agents,
                               firewall=self.firewall, settings=self.settings, artifact_sources=self.artifact_sources)
        second._through = True
        second._problems = self.wf.problems      # a problem the second pass finds is the file's
        found = second.run()
        order = {"high": 0, "medium": 1, "low": 2}
        standing = {FIXED: 0, UNDECIDED: 1, NEW: 2}
        inner = {step.name for job in view.jobs.values() for step in job.steps if step.via is not None}
        # The first pass's findings by rule, job, step and case, each matched once, in order.
        first: dict = {}
        at: dict = {}
        for finding in self.findings:
            first.setdefault((finding.rule, finding.job, finding.step, finding.kind), []).append(finding)
            at.setdefault((finding.rule, finding.job, finding.step), []).append(finding)
        # The jobs the action's steps put in a lane they were not in: their other cases are the new lane's.
        relaned = {job_id for job_id, job in view.jobs.items() if set(job.lanes) != set(self.wf.jobs[job_id].lanes)}
        place = {id(finding): n for n, finding in enumerate(self.findings)}
        added: list = []
        answered: set = set()
        for finding in found:
            if finding.step in inner:
                # A step of an action: one finding for each step, as for steps written in the job.
                added.append(finding)
                continue
            mates = first.get((finding.rule, finding.job, finding.step, finding.kind))
            if mates:
                # The same case of the rule on the same step or job. What the action's steps do (a fetch of a
                # pull request's code, what feeds a value the checker cannot read) is part of it, as for steps
                # written in the job, unless that would leave it less severe or nearer to cleared.
                mate = mates.pop(0)
                if standing.get(finding.state, 2) < standing.get(mate.state, 2):
                    continue
                if order.get(finding.severity, 3) > order.get(mate.severity, 3):
                    finding.severity = mate.severity
                self.findings[place[id(mate)]] = finding
                continue
            # Another case of the rule: added where the first pass has none of that rule there as severe, or
            # where the action's steps put the job in a lane it was not in (the third review found the release
            # case dropped beside the first pass's "cannot tell whether it releases").
            there = at.get((finding.rule, finding.job, finding.step), [])
            if finding.job not in relaned and there and all(
                    order.get(f.severity, 3) <= order.get(finding.severity, 3) for f in there):
                continue
            if finding.job in relaned and not finding.kind.startswith("capability"):
                # Flagship slice 2d.14: where the action's steps made the job a release job, the first pass's
                # "cannot tell whether it releases" case of the same rule there (OBAAF-GHA-006's and 015's
                # `capability...`) is answered by the release case, when that is at least as severe.
                for mate in there:
                    if (mate.kind.startswith("capability") and mate.kind != "capability-call"
                            and order.get(finding.severity, 3) <= order.get(mate.severity, 3)):
                        answered.add(id(mate))
            added.append(finding)
        if answered:
            self.findings = [f for f in self.findings if id(f) not in answered]
        self.findings.extend(added)

    # -------------------------------------------------------------- GHA-023
    # Values OBAAF-GHA-023 reaches in one file, each place counted on its own: a large workflow reaches
    # some thousands.
    _PLACEHOLDER_WALK = 500_000

    class _WalkExceeded(Exception):
        pass

    def placeholders(self) -> None:
        """Every template placeholder in a value GitHub reads, one finding each (flagship slice 2d.2f).
        The values are read as YAML gives them, so an escape (`OBAAF\\x5FOWNER`, a line joined inside
        double quotes) is the placeholder it spells, and a comment, which GitHub never reads, is not.
        `OBAAF_OWNER` is found in any letter case (GitHub owner names are compared without regard to
        case); the all-zero SHA as a ref, or after `@` anywhere in a value, as exactly 40 zeros.

        A value written once under a YAML anchor and reached through aliases is one object to the
        reader. Each place (a top-level key, a job's key, a step) is walked on its own, each list and
        mapping in it once, so a step shared by two jobs, or used twice in one job, is reported at each
        (slice 2d.3: it was reported at the first place only). Each text is searched once, however
        often it is reached, and a text with a placeholder reached again in the same place is that
        place's once. A file whose places together reach more values than the checker reads is an
        error for the file, never a pass; the rule's findings so far, and the other rules', stand."""
        found: list = []
        budget = [self._PLACEHOLDER_WALK]
        searched: dict = {}

        def held(text: str, where: str) -> list:
            key = (text, where.rsplit(".", 1)[-1] == "uses")
            if key not in searched:
                searched[key] = _placeholders_in(text, where)
            return searched[key]

        def visit(value, where: str, line: int, job: Job | None, step: Step | None) -> None:
            seen: set = set()

            def walk(value, where: str, line: int) -> None:
                budget[0] -= 1
                if budget[0] < 0:
                    raise self._WalkExceeded()
                if isinstance(value, (dict, list)):
                    if id(value) in seen:
                        return
                    seen.add(id(value))
                if isinstance(value, str):
                    placeholders = held(value, where)
                    if placeholders:
                        # A text reached again through an alias in the same place is that place's once,
                        # as a list or mapping is; a text written out twice is two objects, and two places.
                        if id(value) in seen:
                            return
                        seen.add(id(value))
                    for placeholder in placeholders:
                        found.append((line, job, step, where, placeholder))
                elif isinstance(value, dict):
                    for key, sub in value.items():
                        name = as_text(key)
                        for placeholder in held(name, where):
                            found.append((line, job, step, f"{where}.{name}" if where else name, placeholder))
                        sub_line = line
                        if hasattr(value, "line_of"):
                            try:
                                sub_line = max(int(value.line_of(key) or 0), line)
                            except (TypeError, ValueError):
                                pass
                        walk(sub, f"{where}.{name}" if where else name, sub_line)
                elif isinstance(value, list):
                    for n, sub in enumerate(value):
                        walk(sub, f"{where}[{n}]", line)

            walk(value, where, line)

        try:
            self._placeholder_places(visit)
        except self._WalkExceeded:
            message = ("values reached through YAML aliases are too many to read for template placeholders; the "
                       "checker cannot tell whether one is left")
            problems = getattr(self, "_problems", None)
            problems = self.wf.problems if problems is None else problems
            if message not in problems:
                problems.append(message)
        self._placeholder_findings(found)

    def _placeholder_places(self, visit) -> None:
        jobs_raw = self.wf.raw.get("jobs")
        for key, sub in self.wf.raw.items():
            if key != "jobs":
                visit({key: sub}, "", 1, None, None)
        # Each job and step is matched to its raw value in order, so that two places holding the same
        # value through an alias are two jobs or two steps, not one.
        by_raw: dict = collections.defaultdict(collections.deque)
        for job in self.wf.jobs.values():
            by_raw[id(job.raw)].append(job)
        if isinstance(jobs_raw, dict):
            for key, job_raw in jobs_raw.items():
                queue = by_raw.get(id(job_raw))
                job = queue.popleft() if queue else None
                if job is None:
                    visit({key: job_raw}, "jobs", 1, None, None)
                    continue
                steps: dict = collections.defaultdict(collections.deque)
                for step in job.steps:
                    steps[id(step.raw)].append(step)
                for name, sub in job_raw.items():
                    if name == "steps" and isinstance(sub, list):
                        for n, step_raw in enumerate(sub):
                            queue = steps.get(id(step_raw))
                            step = queue.popleft() if queue else None
                            visit(step_raw, f"steps[{n}]", step.line if step else job.line, job, step)
                    else:
                        visit({name: sub}, "", job.line, job, None)
        if getattr(self, "_through", False):
            # The second pass reads the local actions' steps as the action's file writes them (slice 2d.4b2):
            # a placeholder the using step hands in is the first pass's finding already.
            for job in self.wf.jobs.values():
                for step in job.steps:
                    if step.via is not None and isinstance(step.written, dict):
                        # each use of an action is read, as each step written in a job is
                        visit(step.written, "step", step.line, job, step)

    def _placeholder_findings(self, found: list) -> None:
        done: set = set()
        for line, job, step, where, placeholder in found:
            key = (job.id if job else None, step.index if step else None, where, placeholder)
            if key in done:
                continue        # the placeholder in a key and in its value is one place
            done.add(key)
            self.add("OBAAF-GHA-023", line, "Template placeholder '{placeholder}' is still present in {where}.",
                     job, step, placeholder=placeholder, where=Fact(where, f"'{one_line(where, 80)}'"),
                     legacy="Template placeholder '{placeholder}' is still present.")

    # -------------------------------------------------------------- GHA-009
    def permissions_declared(self, job: Job) -> None:
        if job.permissions is None:
            self.add("OBAAF-GHA-009", job.line,
                     "Job '{job}' does not declare permissions, and neither does the workflow, so its token "
                     "gets the repository default (or, when another workflow calls this one, what the calling "
                     "job grants).", job)

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
        # Only an environment named in plain text lowers the finding: it may require a reviewer. A
        # name with an expression in it can be one GitHub creates on first use, with no protection
        # rules, or one the event's author picks; a name that is not text cannot be checked at all.
        reviewed = job.environment_reading[0] == "literal"
        passed = self._passed_fact(job, names)
        if privileged and reviewed:
            self.add("OBAAF-GHA-001", job.line,
                     "Job '{job}' receives {secrets}{passed} and can be started by {triggers}. It references "
                     "environment '{environment}'; confirm that environment requires reviewers.",
                     job, severity="medium", kind="privileged-environment", secrets=secrets, passed=passed,
                     triggers=sorted(privileged), environment=job.environment)
        elif privileged:
            self.add("OBAAF-GHA-001", job.line,
                     "Job '{job}' receives {secrets}{passed}{environment} and can be started by {triggers}.",
                     job, severity="high", kind="privileged", secrets=secrets, passed=passed,
                     triggers=sorted(privileged), environment=self._environment_fact(job))
        elif triggers & PR_TRIGGERS:
            self.add("OBAAF-GHA-001", job.line,
                     "Job '{job}' receives {secrets}{passed}{environment} and runs on pull requests. Forks get no "
                     "secrets, but branches pushed by anyone with write access do.", job, severity="low",
                     kind="pull-request", secrets=secrets, passed=passed, environment=self._environment_fact(job))

    # -------------------------------------------------------------- GHA-024
    def protected_secrets(self, job: Job) -> None:
        if not self.protected:
            return
        names = job.secret_names()
        caller = bool(job.reusable)
        # A reusable-workflow call passes repository and organization secrets only, never an
        # environment's, and the caller cannot declare an environment. `secrets: inherit` passes all
        # of them, so it passes a protected secret's repository or organization copy wherever one
        # exists, as naming the secret does; whether one exists is a setting `obaaf audit` reads.
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
        state, declared = job.environment_reading
        via = (" (it passes every secret: secrets: inherit)" if "*inherit" in names
               else " (it can take every secret)" if takes_all else "")
        every = sorted(n for n in names if n.startswith("*"))
        found = job.environment_source() if state == "scalar" else None
        source = found[0] if found else None
        reported: set[tuple] = set()
        for name, pattern, wanted in hits:
            match = (environment_match(declared, wanted) if state == "literal"
                     else scalar_environment_match(declared, wanted, source) if state == "scalar" else None)
            if not caller and match == "same":
                continue
            # One finding for each secret and the environment it needs, however many entries ask for it.
            if (name, wanted) in reported:
                continue
            reported.add((name, wanted))
            values = {"secret": name, "via": Fact(every, via),
                      "need": Fact(wanted or "", f"environment '{wanted}'" if wanted else "an environment")}
            if caller:
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' passes protected secret {secret}{via} to the reusable workflow "
                         "{workflow}. A calling job cannot declare an environment, so the secret can only "
                         "come from the repository or organization; pass none, and declare {need} in the called "
                         "workflow's job instead.", job, kind="caller", workflow=job.reusable, **values)
            elif state == "expression":
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' uses protected secret {secret}{via} with environment '{declared}', an "
                         "expression the checker cannot confirm is {need}.", job, severity="medium",
                         kind="environment-expression", declared=declared, **values)
            elif match == "unsure":
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' uses protected secret {secret}{via} with environment {declared}, which the "
                         "checker cannot tell GitHub reads as {need}: it is a number or true or false, whose text "
                         "YAML readers do not agree on, or it differs from that name only in the case of letters "
                         "outside ASCII.", job, severity="medium", kind="environment-unsure",
                         declared=Fact(value_identity(source if source is not None else declared),
                                       shown_value(source if source is not None else declared)), **values)
            elif state == "unreadable":
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' uses protected secret {secret}{via} with an environment written as {declared}, "
                         "which is not a name, so it is not {need}.", job, kind="environment-not-a-name",
                         declared=Fact(value_identity(declared), shown_value(declared)), **values)
            elif state in ("literal", "scalar"):
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' uses protected secret {secret}{via} in environment '{declared}', not {need}.",
                         job, kind="other-environment", declared=(
                             declared if state == "literal" else source if source is not None
                             else as_text(declared).lower() if isinstance(declared, bool) else as_text(declared)),
                         **values)
            else:
                self.add("OBAAF-GHA-024", job.line,
                         "Job '{job}' uses protected secret {secret}{via} without declaring {need}, so it "
                         "can only get the secret from the repository or organization, where any branch can "
                         "read it.", job, kind="no-environment", **values)

    # -------------------------------------------------------------- GHA-002, GHA-019
    def _env_for(self, job: Job, step: Step | None = None):
        """The env a step's values can read: its own, its job's and its workflow's."""
        return env_lookup(step.env if step else None, job.env, self.wf.env)

    def _checkout_reading(self, job: Job, step: Step) -> tuple[PrCode, PrCode]:
        """What an actions/checkout step's `ref` and `repository` say about a pull request's code.
        Inputs written as one expression are unresolved: the checker cannot tell what they hold."""
        given = step.raw.get("with")
        if given is not None and not isinstance(given, dict):
            unread = PrCode("unresolved", ["inputs written as one expression"])
            return unread, unread
        look = self._env_for(job, step)
        return pr_code(step.with_.get("ref") or "", look), pr_code(step.with_.get("repository") or "", look)

    @staticmethod
    def _combined(*readings: PrCode) -> PrCode:
        for state in ("head", "unresolved"):
            reads = sorted({r for reading in readings if reading.state == state for r in reading.reads})
            if any(reading.state == state for reading in readings):
                return PrCode(state, reads)
        return PrCode("base", sorted({r for reading in readings for r in reading.reads}))

    @staticmethod
    def _condition(job: Job, step: Step | None) -> Fact:
        """The `if:` of a job and a step, as part of what a finding is: a guard is what makes one
        checkout of a pull request's code safe and another not, so an acceptance of a guarded step
        does not cover the same step without its guard."""
        values, shown = [], []
        for where, raw in (("job", job.raw.get("if")), ("step", step.raw.get("if") if step else None)):
            if raw is not None and as_text(raw).strip():
                values.append(f"{where}: {value_identity(raw)}")
                shown.append(f"the {where}'s if: {shown_value(raw)}")
        return Fact(values, f" (it runs only where {' and '.join(shown)} holds)" if shown else "")

    def _sources(self, job: Job, step: Step, reads: list) -> Fact:
        """For a value the checker cannot read, everything in the file it can depend on, as part of
        what the finding is: the workflow's and the job's env, the job's strategy, the job's steps
        before this one (which can write GITHUB_ENV or outputs), and each job a `needs` output comes
        from; as one digest of how they are written. An acceptance of a "cannot tell" finding is an
        acceptance of all of that, so changing any of it (a producing step that now gives the head
        instead of the base, a matrix, an env value) makes the finding new."""
        if not reads:
            return Fact([], "")
        needed = sorted({read.split(".")[1] for read in reads if read.startswith("needs.") and "." in read[6:]})
        upstream = {
            "workflow-env": self.wf.raw.get("env"), "job-env": job.raw.get("env"),
            "strategy": job.raw.get("strategy"), "steps": [s.raw for s in job.steps[:step.index]],
            "needs": {name: other.raw for name, other in self.wf.jobs.items() if str(name).lower() in needed},
        }
        return Fact([f"upstream: {digest_of(upstream)}"], "")

    def _shell(self, job: Job, step: Step) -> str:
        """The shell a step's `run` is given to: its own, else the job's or the workflow's default."""
        for raw in (step.raw, (job.raw.get("defaults") or {}).get("run") if isinstance(job.raw.get("defaults"), dict) else None,
                    (self.wf.raw.get("defaults") or {}).get("run") if isinstance(self.wf.raw.get("defaults"), dict) else None):
            if isinstance(raw, dict) and raw.get("shell"):
                return as_text(raw.get("shell"))
        return ""

    @staticmethod
    def _unsafe_checkout_allowed(step: Step) -> bool:
        """Whether a checkout step opts in to checking out a fork's pull request. Anything but a
        plainly false value counts, an expression included: GitHub hands the action what it
        evaluates to."""
        if "allow-unsafe-pr-checkout" not in step.with_:
            return False
        return not _falsy(_constant(step.with_.get("allow-unsafe-pr-checkout")))

    def untrusted_checkout(self, job: Job) -> None:
        privileged = job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS
        for step in job.steps:
            if step.uses_action("actions/checkout"):
                if self._unsafe_checkout_allowed(step):
                    self.add("OBAAF-GHA-019", step.line,
                             "Step '{step}' sets allow-unsafe-pr-checkout to {value}.", job, step,
                             legacy="Step '{step}' sets allow-unsafe-pr-checkout: true.",
                             triggers=Fact(sorted(job.triggers()), ""),
                             value=Fact(value_identity(step.with_.get("allow-unsafe-pr-checkout")),
                                        shown_value(step.with_.get("allow-unsafe-pr-checkout"))))
                if not privileged:
                    continue
                reading = self._combined(*self._checkout_reading(job, step))
                if reading.state == "head":
                    self.add("OBAAF-GHA-002", step.line,
                             "Step '{step}' checks out pull-request code ({reads}) in a workflow started by "
                             "{triggers}{condition}.", job, step, kind="checkout", triggers=sorted(privileged),
                             reads=reading.reads, condition=self._condition(job, step),
                             legacy="Step '{step}' checks out pull-request code in a workflow started by {triggers}.")
                elif reading.state == "unresolved":
                    self.add("OBAAF-GHA-002", step.line,
                             "Step '{step}' checks out a ref or repository taken from {reads} in a workflow started "
                             "by {triggers}{condition}. The checker cannot tell whether that is a pull request's "
                             "code; if it is not, accept this finding and say why.", job, step, severity="medium",
                             kind="checkout-unresolved", triggers=sorted(privileged), reads=reading.reads,
                             condition=self._condition(job, step), sources=self._sources(job, step, reading.reads))
            elif privileged:
                reading = pr_fetch(step, self._env_for(job, step), self._shell(job, step))
                if reading.state == "head":
                    self.add("OBAAF-GHA-002", step.line,
                             "Step '{step}' fetches pull-request code ({reads}) in a workflow started by "
                             "{triggers}{condition}.", job, step, kind="fetch", triggers=sorted(privileged),
                             reads=reading.reads, condition=self._condition(job, step),
                             legacy="Step '{step}' fetches pull-request code in a workflow started by {triggers}.")
                elif reading.state == "unresolved":
                    self.add("OBAAF-GHA-002", step.line,
                             "Step '{step}' runs a command that fetches or checks out code, with a value taken from "
                             "{reads}, in a workflow started by {triggers}{condition}. The checker cannot tell "
                             "whether that is a pull request's code; if it is not, accept this finding and say why.",
                             job, step, severity="medium", kind="fetch-unresolved", triggers=sorted(privileged),
                             reads=reading.reads, condition=self._condition(job, step),
                             sources=self._sources(job, step, reading.reads))

    # -------------------------------------------------------------- GHA-010
    # Events outsiders can cause that UNTRUSTED_TRIGGERS does not list, for this rule's severity only
    # (flagship slice 2d.2d): anyone who can read a public repository can comment on its commits.
    # `check_suite`, `check_run` and `status` carry a commit and a branch that may be a fork's (not
    # verified), so they count too.
    _INJECTION_UNTRUSTED = frozenset(UNTRUSTED_TRIGGERS | {"commit_comment", "check_suite", "check_run", "status"})
    # Events on which a commit's message, author, committer and file names can be an outsider's: a
    # merged pull request's title and branch name are in its merge commit's message, and a commit keeps
    # the author its writer gave it.
    _COMMITS_PUSHED = frozenset({"push", "merge_group", TRUSTED_WORKFLOW_RUN})

    def script_injection(self, job: Job) -> None:
        """Every outsider-written field a step expands in what it runs (flagship slice 2d.2d). The
        fields, the references that reach them, the expressions that hold those references and the
        job's triggers are the finding's facts, so an accepted step that later expands one more field,
        expands it another way, or that a new trigger can start, is a new finding."""
        triggers = job.triggers()
        # A workflow another workflow calls gets the caller's event, which the checker does not read,
        # so it is taken as one an outsider may have caused.
        untrusted = bool(triggers & self._INJECTION_UNTRUSTED) or "workflow_call" in triggers
        commits_pushed = bool(triggers & self._COMMITS_PUSHED)
        for step in job.steps:
            texts = self._script_texts(job, step)
            if not texts:
                continue
            view = None
            fields: set = set()
            references: set = set()
            written: set = set()        # the expressions that reach a field, as the finding's facts
            ways: set = set()           # how the indirect references reach their field
            for text in texts:
                for body in expressions(text):
                    direct = self._untrusted_fields(body)
                    reached = bool(direct)
                    fields |= direct
                    references |= direct
                    if view is None:
                        view = self._indirect(job, step)
                    for how, reference, held in self._untrusted_indirectly(body, view):
                        fields |= held
                        references.add(reference)
                        ways.add(how)
                        reached = True
                    if reached:
                        written.add(self._expression_identity(body))
            if not fields:
                continue
            commit_text = any(self._commit_field(f) for f in fields)
            severity = "high" if untrusted or (commits_pushed and commit_text) else "medium"
            values = {"fields": sorted(fields), "triggers": Fact(sorted(triggers), ""),
                      "expressions": Fact(sorted(written), ""), "legacy": self._legacy_injection(job, step)}
            if not ways:
                self.add("OBAAF-GHA-010", step.line,
                         "Step '{step}' expands {fields} inside its script.", job, step, severity=severity, **values)
            elif len(references) == 1 and ways == {"through-env"}:
                self.add("OBAAF-GHA-010", step.line,
                         "Step '{step}' expands {reference}, which holds {fields}, inside its script.", job, step,
                         severity=severity, kind="through-env", reference=next(iter(references)), **values)
            elif len(references) == 1 and ways == {"through-matrix"}:
                self.add("OBAAF-GHA-010", step.line,
                         "Step '{step}' expands {reference}, from a matrix that holds {fields}, inside its script.",
                         job, step, severity=severity, kind="through-matrix", reference=next(iter(references)),
                         **values)
            else:
                self.add("OBAAF-GHA-010", step.line,
                         "Step '{step}' expands {references}, which reach {fields}, inside its script.", job, step,
                         severity=severity, kind="indirect", references=sorted(references), **values)

    @staticmethod
    def _expression_identity(body: str) -> str:
        """An expression as part of a finding: its text with runs of space made one, or, beyond 200
        characters, its length and digest. The checker does not work out whether an expression gives
        text or only true or false (`contains(github.event.issue.title, 'bug')`), so it reports both;
        naming the expression keeps an acceptance of the harmless one from covering a later edit that
        expands the field itself."""
        text = " ".join(body.split())
        if len(text) <= 200:
            return text
        return f"{len(text)} characters, sha256 {hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()}"

    @staticmethod
    def _commit_field(field: str) -> bool:
        """Whether a field reached is, or may be, a commit's text: under `head_commit`, `commits`,
        `merge_group`, `check_suite` or a `status` event's `commit`, a run's `display_title` (the head
        commit's message for a run after a push), or a whole object or computed path that can hold one
        (`toJSON(github)`, `toJSON(github.event.workflow_run)`, `github.event[...]`)."""
        lowered = field.lower()
        whole = ("github", "github.event", "github.event.workflow_run", "github.event.commit", "github.event.check_run")
        return (lowered in whole or "*" in lowered or "[" in lowered or "tojson(" in lowered
                or any(part in lowered for part in ("head_commit", "commits", "merge_group", "check_suite",
                                                    "event.commit.", "workflow_run.display_title")))

    def _script_texts(self, job: Job, step: Step) -> list:
        """What a step runs as a script or a command line: its `run`, a github-script script, the
        command OBAAF's egress action runs (also under a spelling of its path that `confines` does not
        take for the action), a `docker://` step's `entrypoint` and `args`, the inputs of the actions
        listed under `script_inputs` in the detection data, and the `shell` that runs `run` (the
        step's, the job's or the workflow's `defaults.run.shell`), which is the command line the runner
        starts. A value that is not text (a mapping, a list) is read as the text of everything in it."""
        texts = [step.scripts()]
        for action, names in (self.detection.get("script_inputs") or {}).items():
            if step.uses_action(action):
                for name in names:
                    given = step.with_.get(str(name).lower())     # `with_` folds input names to lower case
                    if given is not None:
                        texts.append(str(given))
        if not step.confines and self._spelled_egress(step) and step.with_.get("run") is not None:
            texts.append(str(step.with_.get("run")))
        if step.run:
            for raw in (step.raw, job.raw.get("defaults"), self.wf.raw.get("defaults")):
                shell = raw.get("shell") if raw is step.raw else (
                    raw.get("run", {}).get("shell") if isinstance(raw, dict) and isinstance(raw.get("run"), dict)
                    else None)
                if shell is not None:
                    texts.append(str(shell))
                    break
        return [text for text in texts if text]

    @staticmethod
    def _spelled_egress(step: Step) -> bool:
        """Whether a step's `uses` names OBAAF's egress action with extra slashes or dots in its path
        (`actions/egress/`, `actions/./egress`, `obaaf//actions/egress`). Whether GitHub runs the action
        for such a path is not verified; its `run` input is read as a script either way."""
        action = (step.action or "").lower()
        parts = [part for part in action.split("/") if part not in ("", ".")]
        return "/".join(parts) == EGRESS_ACTION

    def _legacy_injection(self, job: Job, step: Step) -> str:
        """The message the checker wrote for this step before slice 2d.2d (the first field of the first
        expression of `run` or a github-script script, read as it was read then), as a template for
        `add`, so that a v0.1 baseline entry still names the finding. Empty where that reading found
        nothing or wrote the same message."""
        def literal(text) -> str:
            return str(text).replace("{", "{{").replace("}", "}}")
        view = None
        for body in expressions(step.text()):
            found = self._untrusted_text(body)
            if found:
                return "Step '{step}' expands " + literal(found) + " inside its script."
            if view is None:
                view = self._v1_indirect(job, step)
            through = self._v1_untrusted_indirectly(body, view)
            if through:
                how, reference, held = through
                held_text = "which holds" if how == "through-env" else "from a matrix that holds"
                return ("Step '{step}' expands " + literal(reference) + ", " + held_text + " " + literal(held)
                        + ", inside its script.")
        return ""

    def _untrusted_fields(self, body: str, objects: bool = False) -> frozenset:
        """Every outsider-written field an expression expands, as dotted names. With `objects`, an
        object that contains such a field counts too (a matrix entry or an output can be a whole
        object, whose fields a script then reads)."""
        out = set()
        for ref in expr_mod.refs(body):
            if any(expr_mod.reaches(ref.path, pattern, ref.extracted or objects) for pattern in UNTRUSTED_PATHS):
                out.add(expr_mod.dotted(ref.path))
        if not out:
            found = self._untrusted_text(body)
            if found:
                out.add(found)
        return frozenset(out)

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

    def _held(self, value, objects: bool = False) -> frozenset:
        """Every outsider-written field a workflow value holds (empty when none). With `objects`, a
        value that is the object containing such a field counts too (a matrix entry can be a whole
        object, whose fields the script then reads). An output of another job that holds one counts
        too (`needs.a.outputs.title`, flagship slice 2d.2d)."""
        out: set = set()
        for body in expressions(value):
            out |= self._untrusted_fields(body, objects)
            for path in expr_mod.paths(body):
                out |= self._output_held(path)
        return frozenset(out)

    def _output_taint(self) -> dict:
        """Job id (lower case) -> {output name (lower case) or "*": the outsider-written fields it holds},
        for job outputs written in the file (`outputs: {title: ${{ github.event.issue.title }}}`),
        directly, through another job's output, or through the job's env or matrix. Outputs set by a
        step while the job runs (`steps.x.outputs.y`) are not followed.

        Worked out once per file, with a work list: a job's outputs are read again only when an output
        of a job it reads (in its outputs, env, matrix or the workflow's env) gains a field, so a chain of
        jobs costs about one reading per job, in any order. The views of jobs built while it runs are
        dropped at the end, because they were built from outputs not yet complete."""
        cached = self.__dict__.get("_outputs")
        if cached is not None:
            return cached
        self.__dict__["_outputs"] = taint = {}      # an output reading an output: read as not yet held
        views = self.__dict__.setdefault("_job_views", {})
        jobs = {str(job.id).lower(): job for job in self.wf.jobs.values() if job.raw.get("outputs") is not None}
        readers: dict = {}                          # job id or "*" -> ids of jobs with outputs that read it
        for name, job in jobs.items():
            for value in (job.raw.get("outputs"), job.raw.get("env"), job.raw.get("strategy"), self.wf.raw.get("env")):
                for body in expressions(value):
                    for path in expr_mod.paths(body):
                        if path[0].kind != expr_mod.NAME or path[0].value.lower() != "needs":
                            continue
                        target = path[1].value.lower() if len(path) > 1 and path[1].kind == expr_mod.NAME else "*"
                        readers.setdefault(target, set()).add(name)
        queue = list(jobs)
        waiting = set(queue)
        while queue:
            name = queue.pop(0)
            waiting.discard(name)
            job = jobs[name]
            outputs = job.raw.get("outputs")
            pairs = [("*", outputs)] if isinstance(outputs, str) else \
                [(str(k).lower(), v) for k, v in outputs.items()] if isinstance(outputs, dict) else []
            views.pop(job.id, None)                 # read the job's env and matrix with the outputs as they are now
            view = self._job_view(job)
            own = taint.setdefault(name, {})
            changed = False
            for output, value in pairs:
                held = set(self._held(value, objects=True))
                for body in expressions(value):
                    for _how, _reference, fields in self._untrusted_indirectly(body, view):
                        held |= fields
                if held and not held <= own.get(output, frozenset()):
                    own[output] = frozenset(held | own.get(output, frozenset()))
                    changed = True
            if changed:
                for reader in readers.get(name, set()) | readers.get("*", set()):
                    if reader not in waiting:
                        queue.append(reader)
                        waiting.add(reader)
        views.clear()
        return taint

    def _output_held(self, path: tuple) -> frozenset:
        """The fields a `needs.<job>.outputs.<name>` reference reaches, if that output holds any. A
        reference that names no single job or output (`needs.*`, `needs[x]`, `toJSON(needs)`) reaches
        every output that holds one."""
        if not path or path[0].kind != expr_mod.NAME or path[0].value.lower() != "needs":
            return frozenset()
        taint = self._output_taint()
        exact = (len(path) >= 4 and all(s.kind == expr_mod.NAME for s in path[:4])
                 and path[2].value.lower() == "outputs")
        if exact:
            own = taint.get(path[1].value.lower(), {})
            return own.get(path[3].value.lower(), frozenset()) | own.get("*", frozenset())
        if len(path) >= 3 and path[1].kind == expr_mod.NAME and path[2].kind == expr_mod.NAME \
                and path[2].value.lower() != "outputs":
            return frozenset()                  # needs.<job>.result and the like
        if len(path) >= 2 and path[1].kind == expr_mod.NAME:
            return frozenset().union(*taint.get(path[1].value.lower(), {}).values())
        return frozenset().union(*(held for own in taint.values() for held in own.values()))

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

    def _env_taint(self, scopes: list[dict], base: dict, matrix: frozenset = frozenset()) -> dict:
        """Env name -> the outsider-written fields its value holds, directly, through other env
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
            held = set(self._held(key) | self._held(value))
            if matrix and any(path[0].value.lower() == "matrix"
                              for body in expressions(value) for path in expr_mod.paths(body)):
                held |= matrix
            if held:
                tainted[key] = frozenset(held)
            names, everything = self._env_refs(value)
            if everything:
                read_all.append(key)
            for name in names:
                readers.setdefault(name, []).append(key)
        inherited = {str(k).lower(): v for k, v in base.items()}
        queue = [(str(k).lower(), v) for k, v in tainted.items()] + list(inherited.items())
        while queue:
            name, held = queue.pop()
            for key in readers.get(name, []) + read_all:
                if not held <= tainted.get(key, frozenset()):
                    tainted[key] = tainted.get(key, frozenset()) | held
                    queue.append((str(key).lower(), tainted[key]))
        return tainted

    def _whole_env(self, value, matrix: frozenset, env: dict) -> frozenset:
        """The fields an `env:` written as one expression can hold: those it reads directly or through
        another job's output, the matrix's when it reads the matrix, and those of the env values it
        can read (flagship slice 2d.2d)."""
        held = set(self._held(value, objects=True))
        for body in expressions(value):
            for path in expr_mod.paths(body):
                root = path[0].value.lower() if path[0].kind == expr_mod.NAME else ""
                if root == "matrix":
                    held |= matrix
                if root == "env":
                    held |= frozenset().union(*env.values()) if env else frozenset()
        return frozenset(held)

    def _job_view(self, job: Job) -> dict:
        """What any step of a job can reach through the env and matrix contexts: env names that hold
        outsider-written text (lower case), the fields the job's matrix holds, and those an `env:`
        written as one expression (so its names cannot be read) holds."""
        cache = self.__dict__.setdefault("_job_views", {})
        if job.id not in cache:
            matrix = self._held(job.raw.get("strategy"), objects=True)
            whole = frozenset()
            if isinstance(self.wf.raw.get("env"), str):
                whole = self._whole_env(self.wf.raw.get("env"), frozenset(), {})
            taint = self._env_taint([self.wf.env, job.env], {}, matrix)
            if isinstance(job.raw.get("env"), str):
                whole = whole | self._whole_env(job.raw.get("env"), matrix, taint)
            cache[job.id] = (taint, matrix, whole)
        taint, matrix, whole = cache[job.id]
        return {"env": {str(k).lower(): v for k, v in taint.items()}, "matrix": matrix, "env_whole": whole}

    def _indirect(self, job: Job, step: Step) -> dict:
        """What a step's script can reach through the env and matrix contexts: env names that hold
        outsider-written text (lower case), the fields the job's matrix holds, and those an `env:`
        written as one expression (so its names cannot be read) holds."""
        self._output_taint()                        # first, so no view is built from outputs not yet complete
        self._job_view(job)
        job_taint, matrix, whole = self.__dict__["_job_views"][job.id]
        if isinstance(step.raw.get("env"), str):
            whole = whole | self._whole_env(step.raw.get("env"), matrix, job_taint)
        step_taint = self._env_taint([step.env], job_taint, matrix) if step.env else {}
        env: dict = {}
        for key, held in job_taint.items():
            if key not in step.env:             # a step value of the same name replaces the job's
                env.setdefault(str(key).lower(), held)
        for key, held in step_taint.items():
            env.setdefault(str(key).lower(), held)
        return {"env": env, "matrix": matrix, "env_whole": whole}

    def _untrusted_indirectly(self, body: str, view: dict) -> list:
        """`${{ env.TITLE }}` or `${{ matrix.title }}` in a script is expanded before the shell runs,
        like any expression. If TITLE is set from an outsider-written field, the script expands that
        field. (`"$TITLE"`, which the shell reads, is the safe form.) Returns every reference that
        reaches such a field, as (how: `through-env`, `through-matrix` or `through-output`, the
        reference in the script, the fields it reaches)."""
        out = []
        for path in expr_mod.paths(body):
            root = path[0].value.lower()
            if root == "env" and (view["env"] or view["env_whole"]):
                if len(path) > 1 and path[1].kind == expr_mod.NAME:
                    held = view["env"].get(path[1].value.lower(), frozenset())
                else:
                    held = frozenset().union(*view["env"].values()) if view["env"] else frozenset()
                held = held | view["env_whole"]
                if held:
                    out.append(("through-env", expr_mod.dotted(path), held))
            elif root == "matrix" and view["matrix"]:
                out.append(("through-matrix", expr_mod.dotted(path), view["matrix"]))
            elif root == "needs":
                held = self._output_held(path)
                if held:
                    out.append(("through-output", expr_mod.dotted(path), held))
        return out

    # How the checker read OBAAF-GHA-010 before slice 2d.2d, kept only to write the message 0.3.0 wrote
    # for a finding (`legacy`), so that a v0.1 baseline entry still names it. Nothing else uses these.
    def _v1_held(self, value, objects: bool = False) -> str | None:
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

    def _v1_env_taint(self, scopes: list[dict], base: dict, matrix: str | None = None) -> dict:
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
            held = self._v1_held(key) or self._v1_held(value)
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

    def _v1_indirect(self, job: Job, step: Step) -> dict:
        """What a step's script can reach through the env and matrix contexts: env names that hold
        outsider-written text (lower case), whether the job's matrix does, and whether an `env:`
        written as one expression (so its names cannot be read) does."""
        cache = self.__dict__.setdefault("_v1_views", {})
        if job.id not in cache:
            matrix = self._v1_held(job.raw.get("strategy"), objects=True)
            whole = next((held for held in (self._v1_held(raw.get("env"), objects=True)
                                            for raw in (self.wf.raw, job.raw)
                                            if isinstance(raw.get("env"), str)) if held), None)
            cache[job.id] = (self._v1_env_taint([self.wf.env, job.env], {}, matrix), matrix, whole)
        job_taint, matrix, whole = cache[job.id]
        if isinstance(step.raw.get("env"), str):
            whole = whole or self._v1_held(step.raw.get("env"), objects=True)
        step_taint = self._v1_env_taint([step.env], job_taint, matrix) if step.env else {}
        env: dict = {}
        for key, held in job_taint.items():
            if key not in step.env:             # a step value of the same name replaces the job's
                env.setdefault(str(key).lower(), held)
        for key, held in step_taint.items():
            env.setdefault(str(key).lower(), held)
        return {"env": env, "matrix": matrix, "env_whole": whole}

    @staticmethod
    def _v1_untrusted_indirectly(body: str, view: dict) -> tuple[str, str, str] | None:
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
    def _agents_fact(self, job: Job) -> dict:
        """The agents the job runs that the checker can name (flagship slice 2d.5b), as the fact `agents`:
        each catalogue entry's `id`, and `agents.actions: ...` or `agents.commands: ...` for a configured
        one, sorted. It is a fact of every agent rule's finding, so an acceptance stops covering a job when
        another named agent is added to it or takes the place of the one it ran. A job that runs no agent
        the checker can name (one declared an agent job, or one whose agent is in a repository script) has
        no such fact, so its findings are the ones they were before the slice."""
        cache = self.__dict__.setdefault("_agents_cache", {})
        if id(job) not in cache:
            named = agent_tools.named_agents(job, self.detection, self.agents)
            cache[id(job)] = (job, {"agents": named} if named else {})
        return dict(cache[id(job)][1])

    def agent_rules(self, job: Job) -> None:
        if not job.in_lane("agent"):
            return
        perms = job.permissions
        # Why the job is an agent job is part of the finding, as the text the checker shows for it,
        # so that an acceptance stops covering the job when the recognised action, the step or the
        # declaration changes. The text does not tell every agent apart (another command in a step
        # of the same name, any agent in a declared job), and rewording it changes the finding. Since
        # flagship slice 2d.5b the agents the checker can name are a fact of their own, `agents`, so
        # adding or swapping a named agent changes the finding whatever the text says.
        why = job.reason_for('agent')
        agents = self._agents_fact(job)
        if perms is None and self.wf.callable:
            # A called workflow's job holds what the calling job grants (it can only be narrowed), so
            # what it holds is not read from this file at all.
            # What the jobs of this repository that call it grant is part of the finding (slice 2d.4b3a).
            self.add("OBAAF-GHA-003", job.line,
                     "Agent job '{job}' ({why}) does not declare permissions, and its workflow can be called "
                     "by another (workflow_call), so it holds whatever the calling job grants, write access "
                     "included{granted}.", job, kind="inherited", why=why, granted=self._granted_fact(job),
                     **agents)
        elif perms is None:
            self.add("OBAAF-GHA-003", job.line,
                     "Agent job '{job}' ({why}) does not declare permissions, so it may inherit "
                     "write access.", job, kind="undeclared", why=why, **agents)
        elif perms.write_scopes():
            self.add("OBAAF-GHA-003", job.line,
                     "Agent job '{job}' ({why}) holds write permissions: "
                     "{scopes}.", job, kind="write", why=why, scopes=perms.write_scopes(), **agents)
        if perms is not None and perms.oidc:
            self.add("OBAAF-GHA-004", job.line,
                     "Agent job '{job}' can request OIDC tokens (id-token: write).", job, **agents)
        elif perms is None and self.wf.callable:
            self.add("OBAAF-GHA-004", job.line,
                     "Agent job '{job}' does not declare permissions, and its workflow can be called by another "
                     "(workflow_call), so it can request OIDC tokens whenever the calling job grants "
                     "id-token: write{granted}.", job, kind="inherited", granted=self._granted_fact(job, "id-token"),
                     **agents)
        names = job.secret_names()
        if names:
            shown = ", ".join(sorted(n.replace("*inherit", "all secrets (secrets: inherit)").replace("*", "all secrets")
                                     for n in names))
            # Where each key given to OBAAF's egress action goes is the fifth control's detail (2c.7): a model
            # key under model-keys is out of the command's reach, one passed in env is not.
            egress = self._egress(job)[0]
            self.add("OBAAF-GHA-005", job.line, "Agent job '{job}' receives {secrets}{passed}{environment}.", job,
                     kind="secrets", secrets=Fact(sorted(names), shown), passed=self._passed_fact(job, names),
                     environment=self._environment_fact(job),
                     controls=[*self._secret_controls(job, names), self._input_control(job), egress,
                               self._key_control(job)], **agents)
        elif job.environment:
            self.add("OBAAF-GHA-005", job.line,
                     "Agent job '{job}' uses environment '{environment}', whose secrets it receives "
                     "after approval.", job, kind="environment", environment=job.environment, **agents)

        # GHA-012: instructions from the change under review.
        triggers = job.triggers()
        outside = sorted(triggers & UNTRUSTED_TRIGGERS)
        merge_events = sorted(triggers & MERGE_REF_EVENTS)
        for step in job.steps:
            if step.uses_action("actions/checkout"):
                ref, repository = self._checkout_reading(job, step)
                reading = self._combined(ref, repository)
                if reading.state == "head":
                    self.add("OBAAF-GHA-012", step.line,
                             "Agent job '{job}' checks out the pull request's code ({reads}) in step '{step}', so "
                             "instruction files come from the change under review.", job, step, kind="head",
                             reads=reading.reads, triggers=outside, condition=self._condition(job, step),
                             legacy="Agent job '{job}' checks out the pull request's code in step '{step}', so "
                                    "instruction files come from the change under review.", **agents)
                elif reading.state == "unresolved" and outside:
                    self.add("OBAAF-GHA-012", step.line,
                             "Agent job '{job}' can be started by {triggers} and step '{step}' checks out a ref or "
                             "repository taken from {reads}. The checker cannot tell whether that is the pull "
                             "request's code, whose instruction files the agent would then read.", job, step,
                             severity="medium", kind="unresolved", reads=reading.reads, triggers=outside,
                             condition=self._condition(job, step), sources=self._sources(job, step, reading.reads),
                             **agents)
                elif merge_events and self._merge_commit(step, ref, repository):
                    self.add("OBAAF-GHA-012", step.line,
                             "Agent job '{job}' runs on {triggers} and step '{step}' checks out the "
                             "merge commit, which includes the pull request's instruction files.", job, step,
                             kind="merge-commit", triggers=merge_events, condition=self._condition(job, step),
                             legacy="Agent job '{job}' runs on pull_request and step '{step}' checks out the merge "
                                    "commit, which includes the pull request's instruction files."
                             if "pull_request" in merge_events else "", **agents)
            else:
                reading = pr_fetch(step, self._env_for(job, step), self._shell(job, step))
                if reading.state == "head":
                    self.add("OBAAF-GHA-012", step.line,
                             "Agent job '{job}' fetches the pull request's code ({reads}) in step '{step}'.", job, step,
                             kind="fetch", reads=reading.reads, triggers=outside, condition=self._condition(job, step),
                             legacy="Agent job '{job}' fetches the pull request's code in step '{step}'.", **agents)
                elif reading.state == "unresolved" and outside:
                    self.add("OBAAF-GHA-012", step.line,
                             "Agent job '{job}' can be started by {triggers} and step '{step}' fetches or checks out "
                             "code with a value taken from {reads}. The checker cannot tell whether that is the pull "
                             "request's code.", job, step, severity="medium", kind="fetch-unresolved",
                             reads=reading.reads, triggers=outside, condition=self._condition(job, step),
                             sources=self._sources(job, step, reading.reads), **agents)

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
        self.add("OBAAF-GHA-020", job.line, templates[kind], job, kind=kind, controls=[egress], **values, **agents)

    def artifact_consumer(self, job: Job) -> None:
        for source, download, step, path in artifact_consumers.consumers(self.wf, job, self.artifact_sources):
            self.add("OBAAF-GHA-027", step.line,
                     "Job '{job}' downloads artifact '{artifact}' in '{download}' from agent job '{producer}' "
                     "({workflow}). Step '{step}' can run '{path}' from the download with the consuming job's "
                     "network and permissions. Review the artifact as data before running its contents.",
                     job, step, artifact=source.name, producer=source.job,
                     workflow=source.workflow, download=download.name, path=path)

    # -------------------------------------------------------------- GHA-025
    _INSTALL_SCRIPT_LIMIT = 400_000     # characters of one step's scripts, after variables are put in
    # Programs that run what they are given on standard input, or as the text of `-c`, as code.
    _RUNS_CODE = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "pwsh",
                            "powershell", "powershell.exe", "pwsh.exe", "python", "python2", "python3", "node",
                            "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "iex", "invoke-expression"})
    # Words that run the text they are given (`eval "$(curl ...)"`, `source <(curl ...)`, `iex (irm ...)`).
    _EVALUATES = frozenset({"eval", "source", ".", "iex", "invoke-expression"})
    # What may stand before the program in one element of a pipeline, and is not the program.
    _WRAPPERS = frozenset({"sudo", "env", "exec", "command", "builtin", "nice", "nohup", "time", "stdbuf",
                           "timeout", "doas", "xargs", "unbuffer", "setsid", "chroot", "su", "busybox"})
    _WRAPPER_VALUE_OPTIONS = frozenset({"-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D", "-R", "-n", "-k",
                                        "-s", "-o", "-e", "-i", "-c", "--user", "--group", "--chdir"})
    _DOWNLOADER_RE = re.compile(r"(?<![\w-])(curl|wget|irm|iwr|invoke-webrequest|invoke-restmethod|aria2c)"
                                r"(?:\.exe)?(?![\w-])", re.I)
    _EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)

    def _install_reader(self):
        """The reader OBAAF-JEN-008 uses for agent CLI installs (flagship slice 2d.2k), with no Jenkinsfile
        behind it: only the script and the variables given to it are read. Imported here because the
        Jenkins rules import this module. One per check; `_agent_installed` is set per job by the caller."""
        if getattr(self, "_jenkins_installs", None) is None:
            from obaaf.checker.jenkins.model import Pipeline
            from obaaf.checker.jenkins.rules import JenkinsRules
            self._jenkins_installs = JenkinsRules(self.wf.path, Pipeline(), self.catalog, None)
        return self._jenkins_installs

    def _literal_env(self, job: Job, step: Step, written: bool) -> dict:
        """The env names the step's scripts can read that the workflow, the job or the step sets to one
        literal (the nearest wins), as the shell variables the install reader puts in; None for a name
        set to anything else. A scope written as one expression may set any name, so every name from the
        scopes outside it is unknown (`"*"`). When an earlier step writes `GITHUB_ENV` (`written`), which
        outranks the job's and the workflow's env and not the step's own, their values are unknown too."""
        out: dict = {}

        def unknown_so_far() -> None:
            for name in list(out):
                out[name] = None
            out["*"] = None

        for n, scope in enumerate((self.wf.raw.get("env"), job.raw.get("env"), step.raw.get("env"))):
            if n == 2 and written:
                unknown_so_far()
            if scope is None:
                continue
            if not isinstance(scope, dict):
                unknown_so_far()
                continue
            for name, value in scope.items():
                if not isinstance(name, str):
                    continue
                if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                    out[name] = None
                    continue
                try:
                    text = str(value)
                except ValueError:          # an integer too long for Python to print (found by 2d.5c2a's review)
                    out[name] = None
                    continue
                out[name] = None if "$" in text or len(text) > 10_000 else text
        return out

    @staticmethod
    def _quotes_neutral(text: str) -> str:
        """The text with `;`, `&` and `|` inside single or double quotes made spaces, so that a quoted
        separator does not split one command in two for the install reader (the review of 2d.5a). Linear."""
        if "'" not in text and '"' not in text:
            return text
        out, quote = [], ""
        for c in text:
            if quote:
                if c == quote:
                    quote = ""
                elif c in ";&|":
                    c = " "
            elif c in "'\"":
                quote = c
            elif c == "\n":
                quote = ""
            out.append(c)
        return "".join(out)

    def _expressions_put_in(self, text: str, env: dict) -> str:
        """A script with each `${{ ... }}` as the runner hands it to the shell: `${{ env.NAME }}` is the
        literal the env sets, where it sets one, and any other expression a value set at run time, written
        as `$` and its text without spaces so that a version shows which expression gives it."""
        def sub(m):
            body = m.group(1).strip()
            name = re.fullmatch(r"env\.([A-Za-z_][A-Za-z0-9_]*)", body)
            if name and env.get(name.group(1)) is not None:
                return env[name.group(1)]
            # No braces or spaces, which the install reader takes for the end of a version.
            return "$__OBAAF_EXPR__" + re.sub(r"[^\w.\-\[\]]", "_", body)[:200]
        return self._EXPRESSION_RE.sub(sub, text) if "${{" in text else text

    @classmethod
    def _program(cls, element: str) -> tuple[str, list]:
        """The program one element of a pipeline runs, after wrappers (`sudo -u root`, `env A=1`, `exec`)
        and their options, as a lower-case base name with its quotes taken off, and the words after it.
        A program written as a variable is returned as written (`$SHELL`)."""
        words = element.split()
        i = 0
        while i < len(words):
            word = words[i].strip("\"'")
            base = word.rsplit("/", 1)[-1].lower()
            if base in cls._WRAPPERS:
                i += 1
                while i < len(words) and (words[i].startswith("-") or re.fullmatch(r"[A-Za-z_]\w*=\S*", words[i])):
                    i += 2 if words[i] in cls._WRAPPER_VALUE_OPTIONS else 1
                if base == "timeout" and i < len(words) and re.fullmatch(r"[\d.]+[smhd]?", words[i]):
                    i += 1          # `timeout 60 bash`: the duration
                continue
            if re.fullmatch(r"[A-Za-z_]\w*=\S*", word):
                i += 1
                continue
            return base, words[i + 1:]
        return "", []

    @classmethod
    def _runs_input(cls, program: str, rest: list) -> bool:
        """Whether a program given a download on standard input runs it: a shell or another interpreter
        with no script file named (`bash`, `bash -s`, `bash -`, `python3 -`), PowerShell's `iex`, or a
        program the checker cannot name (a variable, a substitution). `bash ./consume.sh` runs the file and
        reads the download as data."""
        if not program or program.startswith(("$", "`", "(")) or "$(" in program:
            return True
        if program not in cls._RUNS_CODE:
            return False
        if program in ("iex", "invoke-expression"):
            return True
        for word in rest:
            if word in ("-", "-s", "--"):
                return True
            if word.startswith("-"):
                continue
            return False      # a script file: the download is its input
        return True

    def _downloads_run(self, line: str) -> bool:
        """Whether one line of a script runs, as code, what it downloads: the download's output piped to a
        program that runs its input, or the download inside `$(...)`, backticks, `<(...)` or `(...)` on a
        line that evaluates or interprets (`eval`, `source`, `.`, `iex`, `bash -c`, `bash <(...)`). Quotes
        are not read: the line is taken as a whole, so a download and a shell another command feeds on the
        same line are taken together, the wider reading."""
        m = self._DOWNLOADER_RE.search(line)
        if not m:
            return False
        after = line[m.start():]
        # Piped: every element after a `|` (not `||`), `|&` included; `tee` passes its input on.
        elements = re.split(r"\|&?(?!\|)", after.replace("||", "\x00"))
        for element in elements[1:]:
            # The element ends where its command does: at `;`, `&&`, `||`, `&` or a closing bracket.
            program, rest = self._program(re.split(r"&&|;|\x00|&|[)}]", element, maxsplit=1)[0])
            if program == "tee":
                continue
            if self._runs_input(program, rest):
                return True
        # Substituted: the download is inside a substitution, a process substitution or parentheses.
        # Substituted: the download is inside a substitution, a process substitution, parentheses or a
        # here-string, and what stands before it on the line evaluates or interprets.
        for n, m in enumerate(self._DOWNLOADER_RE.finditer(line)):
            if n >= 100:
                return True         # more downloads on one line than are read: the wider reading
            before = line[max(0, m.start() - 4000):m.start()]
            if not re.search(r"(\$\(|`|<\(|\(|<<<)[^)`]*$", before):
                continue
            words = {w.strip("\"'").rsplit("/", 1)[-1].lower() for w in re.split(r"[\s;&|(){}<>=\"']+", before) if w}
            if words & self._EVALUATES or words & self._RUNS_CODE:
                return True
        return False

    def _pin_candidate(self, step: Step, shell: str, windows: bool = False) -> str | None:
        """One literal package in a direct workflow run. Normalized detection text loses its origin."""
        raw = step.raw.get("run")
        if step.via is not None or step.uses is not None or not isinstance(raw, str):
            return None
        # A `run` written once under a YAML anchor and reached through aliases is one edit for every
        # step that reaches it, so none of them is a candidate (review of #258).
        if "run" in getattr(step.raw, "shared_keys", ()):
            return None
        # A called workflow may already contain values substituted from a caller. A Windows runner's
        # default shell is PowerShell, as agent_tool_installs reads it.
        if self.wf.caller_inputs_put_in or shell not in ("", "sh", "bash") or (windows and not shell):
            return None
        # Exactly one package token on one install line. The optional second line may
        # only query the installed CLI's version, using the catalogue's own spelling.
        match = re.fullmatch(r"(?:sudo[ \t]+)?npm[ \t]+install[ \t]+-g[ \t]+([^\s]+)"
                             r"(?:[ \t]*\r?\n[ \t]*([^\s]+)[ \t]+--version)?", raw.strip(" \t\r\n"))
        if not match:
            return None
        package, queried_cli = match.groups()
        cli = (self.detection.get("agent_installs") or {}).get(package)
        if cli and (queried_cli == cli or queried_cli is None and not raw.lstrip().startswith("sudo")):
            return package
        return None

    def agent_tool_installs(self, job: Job) -> None:
        """OBAAF-GHA-025: an agent job installs or runs a tool at a version it does not fix (flagship slice
        2d.5a, control R6). One finding per step and case, with what was found as its facts."""
        if not job.in_lane("agent"):
            return
        from obaaf.checker.jenkins.rules import JenkinsRules
        why = job.reason_for("agent")
        agents = self._agents_fact(job)
        reader = self._install_reader()
        reader._agent_installed = False       # an update counts after an install in an earlier step of the job
        install_urls = [re.compile(x, re.I) for x in self.detection.get("agent_install_urls", [])]
        windows = any("windows" in str(label).lower()
                      for labels in (job.runner_label_sets() or []) for label in (labels or []))
        env_written = False
        for step in job.steps:
            texts = list(self._script_texts(job, step))
            if step.uses and step.uses.strip().lower().startswith("docker://"):
                # GitHub starts the container with its entrypoint and then its args, as one command line.
                parts = []
                for key in ("entrypoint", "args"):
                    given = step.with_.get(key)
                    if isinstance(given, list):
                        parts += [str(x) for x in given if isinstance(x, (str, int, float))]
                    elif isinstance(given, (str, int, float)) and given != "":
                        parts.append(str(given))
                texts.append(" ".join(parts))
            texts = [t for t in texts if t]
            if not texts:
                continue
            shell = self._shell(job, step).strip().lower()
            dialect = "pwsh" if shell.startswith(("pwsh", "powershell")) or (not shell and windows) \
                else "bat" if shell.startswith("cmd") else "sh"
            shell_vars = self._literal_env(job, step, env_written)
            if any(re.search(r"github_env|exportvariable", t, re.I) for t in texts):
                env_written = True
            # As the shell reads it: expressions put in, comments dropped, continued lines joined (a line
            # that ends with `|` continues too), then each command's variables put in, within the bound.
            scripts = []
            total = 0
            for text in texts:
                text = JenkinsRules._prepared(self._expressions_put_in(text, shell_vars), dialect)
                text = re.sub(r"\|[ \t]*\r?\n[ \t]*", "| ", text)
                variables = dict(shell_vars)
                lines = []
                for line in text.splitlines():
                    if total > self._INSTALL_SCRIPT_LIMIT:
                        break
                    resolved = reader._resolve_line(line, variables) if "$" in line else line
                    total += len(resolved) + 1
                    lines.append(resolved)
                scripts.append((text, "\n".join(lines)))
                if total > self._INSTALL_SCRIPT_LIMIT:
                    break
            if total > self._INSTALL_SCRIPT_LIMIT:
                self.add("OBAAF-GHA-025", step.line,
                         "Agent job '{job}' ({why}): step '{step}' runs scripts too long for the checker to read "
                         "(more than {limit} characters with their variables put in), so it cannot tell whether "
                         "they install a tool at a version that can change.", job, step, severity="medium",
                         kind="too-long", why=why, limit=Note(str(self._INSTALL_SCRIPT_LIMIT)), **agents)
                continue
            piped: dict = {}
            installs: set = set()
            for raw, resolved in scripts:
                for line in resolved.splitlines():
                    if not line.lstrip().startswith("#") and self._downloads_run(line):
                        command = line.strip()
                        key = command if len(command) <= 1000 else (
                            command[:1000] + " sha256:" + hashlib.sha256(command.encode()).hexdigest()[:16])
                        piped[key] = command
                # Installs from inside `$(...)`, backticks, parentheses and a script's string read as commands.
                spaced = re.sub(r"\$\(|[`(){}]", " ; ", self._quotes_neutral(raw))
                reader._seen = set()
                for message in reader._install_problems(spaced, shell_vars=shell_vars):
                    if message.startswith("An agent CLI is installed by piping a downloaded script"):
                        continue        # the first case, read above for any download
                    if message.startswith("An agent CLI is installed by a downloaded install script"):
                        urls = sorted({m.group(0) for rx in install_urls for m in rx.finditer(raw)})
                        message = "An agent CLI's own install script is downloaded and run (" + ", ".join(urls) + \
                            "), which installs whatever version the script chooses"
                    installs.add(message)
                reader.unknowns = []
            if piped:
                shown = "; ".join(sorted(c if len(c) <= 160 else c[:160] + "..." for c in piped.values()))
                self.add("OBAAF-GHA-025", step.line,
                         "Agent job '{job}' ({why}) runs a script downloaded while the job runs, in step '{step}': "
                         "{commands}. Whatever it installs runs with what the agent job holds.",
                         job, step, kind="piped-download", why=why, commands=Fact(sorted(piped), shown),
                         **agents)
            if installs:
                self.add("OBAAF-GHA-025", step.line,
                         "Agent job '{job}' ({why}) installs an agent CLI at a version that can change, in step "
                         "'{step}': {installs}.", job, step, kind="agent-cli", why=why, installs=sorted(installs),
                         pin_candidate=self._pin_candidate(step, shell, windows) if len(installs) == 1 and not piped
                         else None,
                         **agents)

    # -------------------------------------------------------------- GHA-026
    _SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

    def agent_tool_settings(self, job: Job) -> None:
        """OBAAF-GHA-026: a step gives an agent action a setting the tool's own documentation warns about
        (flagship slice 2d.5c1). The settings are data, under each agent tool's entry in the detection
        data, each with the documentation's words and where they are. One finding per step and input: for
        the first of the settings for that input whose values the given value is (compared trimmed and in
        any letter case, the wider reading), or, where the value is not plain text (an expression, a list,
        a mapping), case `computed`, "cannot tell", at the highest of those settings' severities but at
        most medium. An input that is not given has the action's default, which no setting names."""
        known = agent_tools.settings(self.detection)
        readers = agent_tools.flag_readers(self.detection)
        if not known and not readers:
            return
        if readers:
            self._agent_flags(job, readers)
        for step in job.steps:
            if not step.uses or step.is_local or step.uses.strip().lower().startswith("docker://"):
                continue
            written = step.raw.get("with")
            if written is not None and not isinstance(written, dict):
                # `with: ${{ fromJSON(...) }}`: GitHub evaluates it into the inputs, which the checker cannot
                # read, so every setting of the action is "cannot tell" (found by 2d.5c1's review), and so is
                # every flag of an input it hands the program as options (slice 2d.5c2a).
                mine = [c for c in known if self._tool_action(step, c[2]["action"])]
                mine += [(tool, name, flag) for tool, name, flags, _programs, _packages, args in readers
                         if any(self._tool_action(step, a) for a in args) for flag in flags]
                if mine:
                    self._agent_setting(job, step, written, mine, whole=True)
                continue
            given = step.with_
            if not given:
                continue
            by_input: dict = {}
            for tool, name, setting in known:
                if self._tool_action(step, setting["action"]):
                    key = input_name(setting["input"])
                    if key in given:
                        by_input.setdefault(key, []).append((tool, name, setting))
            for key, candidates in by_input.items():
                self._agent_setting(job, step, given[key], candidates)

    def _tool_action(self, step: Step, action: str) -> bool:
        """Whether the step uses `action`, an agent tool's action, or one in a folder under it that the
        catalogue does not list as running no agent (flagship slice 2d.11): the approval check under
        `anthropics/claude-code-action` is not given that action's settings."""
        return step.uses_action(action) and not self._agent_actions().excludes(step.action)

    def _agent_flags(self, job: Job, readers: list) -> None:
        """OBAAF-GHA-026 for command-line options (flagship slice 2d.5c2a): an option an agent tool's own
        files warn about, given where the tool's program is run in a step's script (its `run`, a
        github-script script, the command OBAAF's egress action runs, and any other input, `env` value or
        `docker://` argument that is a command running the program) or in an input one of the tool's actions
        hands the program as options (`claude_args`, `codex-args`). `agent_flags` says how each is read and
        what is "cannot tell"."""
        for step in job.steps:
            given = step.with_ if step.uses and not step.is_local else {}
            written = step.raw.get("with")
            for tool, name, flags, programs, packages, args in readers:
                # The inputs an action of the tool hands its program as options. A `with:` that is one
                # expression is "cannot tell" for them in `agent_tool_settings`.
                if given and isinstance(written, dict):
                    for action, inputs in args.items():
                        if not self._tool_action(step, action):
                            continue
                        for key in dict.fromkeys(input_name(i) for i in inputs):
                            if key in given:
                                self._agent_args(job, step, tool, name, flags, action, key, given[key])
                self._agent_command(job, step, tool, name, flags, programs, packages)

    def _agent_args(self, job: Job, step: Step, tool: str, name: str, flags: list, action: str, key: str,
                    raw) -> None:
        if raw is None:
            return
        text = ("true" if raw else "false") if isinstance(raw, bool) else as_text(raw) if isinstance(
            raw, (str, int, float)) else None
        candidates = [(tool, name, dict(flag, input=key)) for flag in flags]
        if text is None or "${{" in text:
            # The same case as a setting's value the checker cannot read (a list, a mapping, an expression).
            self._agent_setting(job, step, raw, candidates)
            return
        codex = action.lower() == "openai/codex-action"
        # claude-code-action leaves out a line that starts with `#` and puts in an unset variable as nothing
        # (shell-quote); codex-action reads `[` as JSON and keeps every other word (string-argv).
        reading, unknown = agent_flags.read_args(text, flags, json_array=codex, comments=not codex,
                                                 expands=not codex)
        odd = any(unicodedata.category(ch)[0] in "CZ" and ch not in agent_flags.JS_SPACE for ch in text)
        if odd or unknown:
            # A character either side may read otherwise, or a variable the action may put in as nothing.
            self._agent_setting(job, step, raw, [c for c in candidates if c[2]["id"] not in reading.hits],
                                force_computed=True)
        shown_action = (step.action or "").lower()
        for flag, option, value in reading.hits.values():
            written_as = option if value is None else f"{option} {value}"
            self.add("OBAAF-GHA-026", step.line,
                     "Step '{step}' of job '{job}' gives {action} `{input}` the option `{option}`, which {tool}'s "
                     "own documentation warns about: \"{says}\" ({source}).", job, step,
                     severity=flag["severity"], kind="option", action=shown_action, input=key,
                     option=Fact(bounded(written_as), one_line(written_as, 120)), setting=f"{tool}/{flag['id']}",
                     tool=Note(name), says=Note(" ".join(str(flag["says"]).split())),
                     source=Note(str(flag["source"])))

    _COMMAND_INPUTS = frozenset({"run", "command", "commands", "cmd", "script", "shell", "args", "arguments",
                                 "entrypoint", "exec", "execute", "build-command", "test-command"})

    _FOREIGN_SPECIAL_RE = re.compile(r"[$@`%^(]")

    def _later_writes(self, job: Job) -> list:
        """The indexes of the job's steps that can set a variable for the steps after them, worked out once."""
        cache = self.__dict__.setdefault("_later_writes_cache", {})
        if job.id not in cache:
            cache[job.id] = [n for n, s in enumerate(job.steps) if self._SETS_FOR_LATER_RE.search(
                (s.run or "") + " " + " ".join(str(v) for v in s.with_.values() if isinstance(v, str)) + " "
                + " ".join(str(v) for v in s.env.values() if isinstance(v, str)))]
        return cache[job.id]

    _EXEC_CALL_RE = re.compile(r"\b(exec|execSync|execFile|execFileSync|spawn|spawnSync|getExecOutput|run|call|"
                               r"check_call|check_output|Popen|system)\s*\(|\$`|child_process|\.apply\s*\(")

    def _step_shell(self, job: Job, step: Step) -> str:
        """The shell a `run` step's script is given to: its `shell`, else the job's and then the workflow's
        `defaults.run.shell`, else bash (pwsh on a Windows runner)."""
        shell = step.raw.get("shell")
        if not isinstance(shell, str):
            for defaults in (job.raw.get("defaults"), self.wf.raw.get("defaults")):
                run = defaults.get("run") if isinstance(defaults, dict) else None
                if isinstance(run, dict) and isinstance(run.get("shell"), str):
                    shell = run["shell"]
                    break
        if not isinstance(shell, str):
            windows = any("windows" in str(label).lower() for label in job.runs_on)
            return "pwsh" if windows else "bash"
        first = shell.split()[0] if shell.split() else ""
        return first.rsplit("/", 1)[-1].lower()

    def _step_language(self, job: Job, step: Step, shell_name: str) -> str:
        """The language a `run` step's script is read as by `agent_code`: the shell's program, after `env`
        and its options (`/usr/bin/env python3 {0}`), and python for `uv run --script {0}`."""
        shell = step.raw.get("shell")
        if not isinstance(shell, str):
            return shell_name
        words = [w.rsplit("/", 1)[-1].lower() for w in shell.split() if w != "{0}"]
        while words and (words[0] == "env" or words[0].startswith("-")):
            words = words[1:]
        if words and words[0] in ("uv", "uvx") and ("--script" in words or "run" in words):
            return "python"
        return words[0] if words else shell_name

    def _agent_command(self, job: Job, step: Step, tool: str, name: str, flags: list, programs: list,
                       packages: list) -> None:
        # What the step gives a shell, and in what language: (text, read as bash, the step names the tool).
        parts: list = []
        languages: dict = {}
        if step.run:
            shell_name = self._step_shell(job, step)
            # cmd takes a `^` out before the program sees the word (`claude ^--yolo`).
            # A caret at a line's end continues the line (found by slice 2d.5c2c's review).
            parts.append((re.sub(r"\^[ \t]*\r?\n", " ", step.run).replace("^", "")
                          if shell_name in ("cmd", "cmd.exe") else step.run, shell_name in ("bash", "sh")))
            languages[id(parts[-1][0])] = self._step_language(job, step, shell_name)
        given = step.with_ if step.uses else {}
        script = given.get("script") if step.uses_action("actions/github-script") else None
        if isinstance(script, str):
            parts.append((script, False))
            languages[id(script)] = "github-script"
        if step.confines and isinstance(given.get("run"), str):
            parts.append((given["run"], True))
        # A `shell` is itself a command line GitHub runs (`shell: claude ... {0}`), the step's or the default.
        if step.run:
            for shell in (step.raw.get("shell"), *(d.get("run", {}).get("shell") for d in (
                    job.raw.get("defaults"), self.wf.raw.get("defaults")) if isinstance(d, dict) and isinstance(
                    d.get("run"), dict))):
                if isinstance(shell, str):
                    parts.append((shell.replace("{0}", "script.sh"), True))
                    break
        own = {id(text) for text, _bash in parts}
        # (text, whether its input's name says it is a command): other inputs, `env` values, and a
        # `docker://` step's entrypoint and arguments, which GitHub hands the container as one command line.
        others = [(v, k in self._COMMAND_INPUTS) for k, v in given.items() if isinstance(v, str) and id(v) not in own
                  and not (k == "script" and script is not None) and not (k == "run" and step.confines)]
        if step.uses and step.uses.strip().lower().startswith("docker://"):
            entry, args = given.get("entrypoint"), given.get("args")
            others.append((" ".join(v for v in (entry, args) if isinstance(v, str)), True))
        others += [(v, False) for v in step.env.values() if isinstance(v, str)]
        named = [text for text, _bash in parts] + [v for v, _c in others] + [
            v for scope in (job.env, self.wf.env) if isinstance(scope, dict) for v in scope.values() if isinstance(v, str)]
        matrix = job.raw.get("strategy")
        if isinstance(matrix, dict):
            named += _strings_in(matrix.get("matrix"), 2000)
        scopes = [step.raw.get("env"), job.raw.get("env"), self.wf.raw.get("env")]
        # An `env` written as one expression (`env: ${{ fromJSON(...) }}`) can set any name: none is known.
        scoped = not any(scope is not None and not isinstance(scope, dict) for scope in scopes)
        scopes = [scope if isinstance(scope, dict) else {} for scope in scopes]
        if not any(agent_flags.appears(t, programs, packages) for t in named):
            # A name put together from variables the script sets (`a=cla; b=ude; $a$b`) is looked for only
            # where the script has a `$` and an assignment, with a regular expression (kept cheap).
            if not any("$" in text and "=" in text and agent_flags.appears(agent_flags.put_in_cheaply(
                    text, scopes), programs, packages) for text, _b in parts):
                return              # the tool's name is nowhere in the step (the common case, kept cheap)
        # A step before this one that can set a variable for later steps (GITHUB_ENV, `exportVariable`):
        # the job's and workflow's `env` values are then not known; the step's own `env` is.
        writes = self._later_writes(job)
        index = next((n for n, other_step in enumerate(job.steps) if other_step is step), 0)
        later = any(n < index for n in writes)
        trust_env = [scoped, scoped and not later, scoped and not later]
        known = {id(text): agent_flags.known_variables(scopes, text, trust_env) for text, _b in parts}
        mentioned = any(agent_flags.mentions(t, programs, packages) for t in named)
        reading = agent_flags.Reading()
        for text, bash in parts:
            variables, unread = known[id(text)]
            if bash:
                reading.merge(agent_flags.read_script(text, programs, packages, flags, variables,
                                                      mentioned=mentioned, unread=unread, loose=True))
            else:
                # JavaScript (github-script) or another shell: "cannot tell" only where a line names the tool
                # and runs a command (an exec call, or in a shell, a character its quoting or variables use).
                # JavaScript or another shell is read the widest way; "cannot tell" where it names the tool and
                # holds the start of a warned option it cannot complete (`"--dangerously-" + "skip-..."`).
                # The language is read by its tokens too (`agent_code`, flagship slice 2d.5c2c): argument lists
                # held in variables, command lines joined with values, options in pieces; in another shell, a
                # variable or splat among the program's words (`claude @a`, `& claude $flags`, `claude %F%`)
                # is "cannot tell", as an unquoted one is in bash.
                if agent_flags.appears(text, programs, packages):
                    reading.merge(agent_flags.read_script(text, programs, packages, flags, variables,
                                                          mentioned=agent_flags.mentions(text, programs, packages),
                                                          bash=False, loose=True,
                                                          language=languages.get(id(text), "")))
        for other, command_like in others:
            # Another input, an `env` value or a `docker://` command line that runs the program: one whose text
            # starts a command with it, or that names the tool in an input whose name says it is a command.
            if agent_flags.starts_program(other, programs, packages) or (
                    command_like and agent_flags.appears(other, programs, packages)):
                variables, unread = agent_flags.known_variables(scopes, other, trust_env)
                reading.merge(agent_flags.read_script(other, programs, packages, flags, variables, mentioned=True,
                                                      unread=unread, prose=not command_like))
        for flag, option, value in reading.hits.values():
            written_as = option if value is None else f"{option} {value}"
            self.add("OBAAF-GHA-026", step.line,
                     "Step '{step}' of job '{job}' runs {program} with `{option}`, which {tool}'s own "
                     "documentation warns about: \"{says}\" ({source}).", job, step, severity=flag["severity"],
                     kind="command-option", program=tool,
                     option=Fact(bounded(written_as), one_line(written_as, 120)), setting=f"{tool}/{flag['id']}",
                     tool=Note(name), says=Note(" ".join(str(flag["says"]).split())),
                     source=Note(str(flag["source"])))
        open_ = [flag for flag in flags if flag["id"] in reading.unknown and flag["id"] not in reading.hits]
        if open_ and agent_tools.other_program_only(self.detection, tool, programs, [
                text for text, _bash in parts] + [v for v, _c in others]):
            # Another well-known program has this name (AWS's `copilot`, pressly's `goose`): no "cannot tell"
            # where every place the step names the program is followed by that other program's own words
            # (flagship slice 2d.5c2b).
            open_ = []
        if open_:
            words = sorted({w for flag in open_ for w in reading.unknown[flag["id"]]})
            shown = "; ".join(one_line(w, 60) for w in words[:5]) + ("; ..." if len(words) > 5 else "")
            worst = max((f["severity"] for f in open_), key=lambda sev: self._SEVERITY_RANK.get(sev, 2))
            severity = "medium" if self._SEVERITY_RANK.get(worst, 2) > 1 else worst
            self.add("OBAAF-GHA-026", step.line,
                     "Step '{step}' of job '{job}' runs {program} with words the checker cannot read ({words}), "
                     "so it cannot tell whether they hold an option that {tool}'s own documentation warns about "
                     "({settings}).", job, step, severity=severity, kind="command-computed", program=tool,
                     words=Fact([bounded(w) for w in words], shown), tool=Note(name),
                     settings=sorted(f"{tool}/{f['id']}" for f in open_))

    # What both the checker's Python and the actions' JavaScript take off the ends of a value (`str.strip`
    # and `String.prototype.trim`): the union, so a value either reads as warned is read as warned.
    _TRIMMED = "".join(ch for ch in map(chr, range(0x3001)) if ch.isspace()) + "\ufeff"

    def _agent_setting(self, job: Job, step: Step, raw, candidates: list, whole: bool = False,
                       force_computed: bool = False) -> None:
        action = (step.action or "").lower()
        tool_name = candidates[0][1]
        input_shown = "with" if whole else candidates[0][2]["input"]
        if raw is None:
            return          # `input:` with nothing after it is an empty value, which no setting names
        if whole:
            text = None
        elif isinstance(raw, bool):
            text = "true" if raw else "false"
        elif isinstance(raw, (str, int, float)):
            text = as_text(raw)
        else:
            text = None
        core = text.strip(self._TRIMMED) if text is not None else None
        # A control, format or separator character left inside the value (a NUL, which ends an environment
        # variable, U+200B, a no-break space) can make the action read another value than the one written.
        odd = core is not None and any(unicodedata.category(ch)[0] in "CZ" and ch not in " \t\r\n" for ch in core)
        # A value that starts with a comment, read by `fromJSON` (`/* x */ true`): what the runner's reader
        # makes of it was not tested, so it is "cannot tell" (2d.5c2b's second review).
        commented = core is not None and core.startswith("/") and any(c[2].get("json") is True for c in candidates)
        if text is None or "${{" in text or odd or force_computed or commented:
            if not candidates:
                return
            # The value is the fact (its digest beyond 200 characters), so an acceptance stops matching when
            # any of it changes (found by 2d.5c1's second review: a fact cut to 60 characters let `drop-sudo`
            # become `unsafe`). A list or a mapping, which GitHub refuses as inputs, is named by its kind, as
            # `value_identity` names it: walking it would expand every YAML alias in it (the fourth review).
            if text is None:
                fact = shown = value_identity(raw)
            else:
                fact, shown = bounded(text), one_line(text, 120)
            worst = max((c[2]["severity"] for c in candidates), key=lambda sev: self._SEVERITY_RANK.get(sev, 2))
            severity = "medium" if self._SEVERITY_RANK.get(worst, 2) > 1 else worst
            self.add("OBAAF-GHA-026", step.line,
                     "Step '{step}' of job '{job}' gives {action} `{input}` a value the checker cannot read "
                     "({value}), so it cannot tell whether it is one that {tool}'s own documentation warns "
                     "about ({settings}).", job, step, severity=severity, kind="computed", action=action,
                     input=input_shown, value=Fact(fact, shown),
                     tool=Note(tool_name), settings=sorted(f"{c[0]}/{c[2]['id']}" for c in candidates))
            return
        value = core
        folded = value.casefold()
        decoded = self._json_text(value)
        for tool, name, setting in candidates:
            # An action that reads the input through `fromJSON` (`json: true`) takes `'"true"'` as `true`.
            compared = decoded.strip(self._TRIMMED).casefold() if setting.get("json") is True and (
                decoded is not None) else folded
            if "equals" in setting:
                hit = any(compared == str(v).strip().casefold() for v in setting["equals"])
            else:
                hit = compared != ""
            if not hit:
                continue
            self.add("OBAAF-GHA-026", step.line,
                     "Step '{step}' of job '{job}' gives {action} `{input}: {value}`, which {tool}'s own "
                     "documentation warns about: \"{says}\" ({source}).", job, step, severity=setting["severity"],
                     kind="setting", action=action, input=setting["input"],
                     value=Fact(value, one_line(value, 120)), setting=f"{tool}/{setting['id']}",
                     tool=Note(name), says=Note(" ".join(str(setting["says"]).split())),
                     source=Note(str(setting["source"])))
            return

    _JSON_WORD_RE = re.compile(r"[^\s,/\]\}:\[\{]+")

    @classmethod
    def _json_text(cls, value: str):
        """What GitHub's `fromJSON` makes of a value, as text, the way the runner's reader (Newtonsoft's
        `JToken.ReadFrom`) does: the first token, a string in double or single quotes (`'"true"'`, `"'true'"`)
        or a word up to a separator (`true // off`, `true off`); anything after it is not read. None where the
        first token is neither (the runner refuses it). Found by 2d.5c2b's reviews."""
        text = value.lstrip(" \t\r\n")
        if text[:1] in ("'", '"'):
            quote = text[0]
            i, out = 1, []
            while i < len(text):
                ch = text[i]
                if ch == "\\" and i + 1 < len(text):
                    try:
                        piece = json.loads('"' + text[i:i + (6 if text[i + 1] == "u" else 2)] + '"')
                    except ValueError:
                        piece = text[i + 1]
                    out.append(piece)
                    i += 6 if text[i + 1] == "u" else 2
                    continue
                if ch == quote:
                    return "".join(out)
                out.append(ch)
                i += 1
            return None
        m = cls._JSON_WORD_RE.match(text)
        return m.group(0) if m else None

    # ---------------------------------------------------- controls for GHA-005 and GHA-020
    EGRESS_NAME = "a control the checker recognises limits the job's network access to an allow-list"
    EGRESS_ID = "egress-enforced"

    # Actions whose ordinary operation the checker can identify without reading repository code: they are not
    # artifact uploads, and they start only git (git-lfs or ssh when asked for), tar and the compressors tar
    # uses (zstd, gzip), whose code-loading variables the checker reads (`steers`, `_UPLOAD_STEERING_*`). What they save to a cache is not read here (only the egress action's route reads a
    # cache of its output, as "not met"). The second review of #357 (run `ouzel`) took the `actions/setup-`
    # actions out: they start the tools they install, which read the repository's files and variables the
    # checker does not read (by their source, not run: setup-node runs `yarn --version`, which Yarn 1 hands to
    # a `yarn-path` in the repository's `.yarnrc`; setup-go runs `go`, which `GOTOOLCHAIN` can switch to a
    # toolchain it downloads).
    _NON_UPLOAD_ACTIONS = frozenset({
        "actions/checkout", "actions/download-artifact", "actions/cache", "actions/cache/save",
        "actions/cache/restore",
    })

    # Literal arguments only. The step's shell must be known, but errexit and pipefail
    # do not affect whether one of these commands uploads an artifact.
    _LITERAL_COMMAND = re.compile(
        r"""([\w.:-]+)(?:[ \t]+(?:[\w/.,:@%+=-]+|'[^'\n]*'|"[^"$`\\\n]*"))*[ \t]*"""
    )
    _PLAIN_COMMANDS = frozenset({"echo", "pwd", "true", ":"})

    # Review of #357 (run `ouzel`): names that, in an `env`, make an action from the list above, Harden-Runner, an
    # agent's CLI or `echo` run code the checker did not read, besides `steers` (bash's, the loader's, Python's,
    # `PATH`, `HOME`): Node.js's, since every action above, Harden-Runner and most agents' CLIs are Node.js
    # programs, run with the token that uploads artifacts; git's (identity names excepted) and
    # `XDG_CONFIG_HOME`, where git finds its global configuration, since actions/checkout runs git; and
    # `TAR_OPTIONS`, since actions/cache runs tar. What other programs read for their settings is not read.
    # Slice 2c.13 (found by the review of #366, run `rosefinch`): OpenSSL's names too, any beginning `OPENSSL_`.
    # Node.js initialises OpenSSL when it starts and loads the configuration `OPENSSL_CONF` names, and the
    # modules or engines it names, into the action's process (the review's attacker reproduced a library's
    # constructor running on Node.js 22). Slice 2c.11a found the same of the egress action's own Python, which
    # drops them before it loads libcrypto; a JavaScript action does not.
    _UPLOAD_STEERING_NAMES = frozenset({"NODE_OPTIONS", "NODE_PATH", "XDG_CONFIG_HOME", "TAR_OPTIONS"})
    _UPLOAD_STEERING_PREFIXES = ("GIT_", "OPENSSL_")
    _UPLOAD_PLAIN_PREFIXES = ("GIT_AUTHOR_", "GIT_COMMITTER_")

    def _upload_env_steers(self, job: Job, step: Step) -> bool:
        """Whether a variable given to the step, or an earlier step, can make it run code the checker did not
        read: `_bash_env` (bash's, the loader's, Python's, `PATH`, `HOME`, an `env` written as one expression, a
        container's `env` or `options`, an earlier step that may change later steps), or a name in
        `_UPLOAD_STEERING_NAMES` or under `_UPLOAD_STEERING_PREFIXES` in the step's, the job's or the
        workflow's `env`."""
        if self._bash_env(job, step):
            return True
        for scope in (step.raw, job.raw, self.wf.raw):
            env = scope.get("env") if isinstance(scope, dict) else None
            if not isinstance(env, dict):
                continue
            for key in env:
                name = str(key).strip().upper()
                if name in self._UPLOAD_STEERING_NAMES or (name.startswith(self._UPLOAD_STEERING_PREFIXES)
                                                           and not name.startswith(self._UPLOAD_PLAIN_PREFIXES)):
                    return True
        return False

    def _literal_script(self, job: Job, step: Step, programs) -> bool:
        """Whether a `run` step's script, in a POSIX shell the checker reads and with no `${{`, is lines of one
        command each with literal arguments, every command one of `programs` (comment lines skipped)."""
        if step.uses is not None or self._failfast_shell(job, step) is None or expr_mod.OPEN in step.run:
            return False
        lines = [line.strip(" \t") for line in step.run.split("\n")]
        commands = (self._LITERAL_COMMAND.fullmatch(line) for line in lines if line and not line.startswith("#"))
        return all(match and match[1] in programs for match in commands)

    def _artifact_upload(self, job: Job, *, egress: bool = False) -> str | None:
        """Return producer-side evidence. A later job's existence or behavior is immaterial."""
        direct_agents = set((self.detection.get("agent_installs") or {}).values())
        releases = self.detection.get("egress_action_releases") or ()
        monitors = self.detection.get("harden_runner_releases") or {}
        steered = "a variable in an env, or an earlier step, can make it run code the checker did not read"
        if job.raw.get("container") is not None and job.steps:
            return (f"job '{one_line(job.id, 80)}' runs in a container, whose image the checker does not read, and "
                    "its scripts and JavaScript actions run in it")
        for step in job.steps:
            action = step.clean_action
            where = f"step '{one_line(step.name, 80)}' in job '{one_line(job.id, 80)}'"
            if action in ("actions/upload-artifact", "actions/upload-artifact/merge", "actions/upload-pages-artifact"):
                if not egress:
                    return f"{where} uploads an artifact"
                if self._upload_env_steers(job, step):
                    return f"{where} uploads an artifact, but {steered}"
                continue
            if step.uses is not None:
                ref = step.uses.partition("@")[2]
                if step.confines and ref in releases:
                    continue    # its own steps' variables were examined by slices 2c.9 to 2c.12
                if action in self._NON_UPLOAD_ACTIONS or (action == "step-security/harden-runner" and ref in monitors):
                    if self._upload_env_steers(job, step):
                        return (f"{where} uses an action that does not upload, but {steered}, with the token "
                                "that uploads artifacts")
                    continue
                return f"{where} uses an action whose implementation may upload an artifact"
            if self._installs_only(job, step) or self._literal_script(job, step, direct_agents | self._PLAIN_COMMANDS):
                if self._upload_env_steers(job, step):
                    return f"{where} runs a script, and {steered}"
                continue
            return f"{where} runs a script whose artifact uploads the checker cannot rule out"
        return None

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
            conditions = tuple(c for reading in readings for c in reading.conditions)
            detail = best.detail
            if best.verdict == VERIFIED:
                detail += (" This verdict covers the producing job. A later job can run uploaded files with its own "
                           "network and credentials. The checker follows actions/upload-artifact and actions/download-artifact "
                           "in this workflow and named workflow_run subscriptions, when it can match the artifact "
                           "and execution path. Other actions, downloads in scripts, computed values, other repositories, "
                           "caches and job outputs can carry files or code beyond that check.")
            return Control(self.EGRESS_NAME, best.verdict, detail, self.EGRESS_ID, conditions), best.kind, best.values
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
        # Read as OBAAF-GHA-013's hosted list reads it (`is_hosted_label`: any letter case, no space
        # trimmed), so the two rules agree on what runs the job (flagship slice 2d.9, issue #172).
        # The same label written twice is one requirement to GitHub, so it is read once (flagship slice 2d.2f).
        on = [s for s in (sets or []) if len({label.lower() for label in s}) == 1 and is_hosted_label(s[0])
              and s[0].lower() == firewall]
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
            listed += " and nothing else" if policy.no_defaults else f" and the firewall's defaults ({egress_mod.DEFAULT_ENDPOINTS})"
            detail = (f"the job runs on {firewall} and {egress_mod.FIREWALL_POLICY} sets mode: enforce, allowing "
                      f"{one_line(listed, 300)}. The firewall is a technical preview, the runner is taken at its label (a "
                      "self-hosted runner given that label would have no firewall), and anything sent to an allowed host, "
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

    # A name that says it holds a credential: `ANTHROPIC_API_KEY`, `deploy-token`, `DB_PASSWORD`; not
    # `author` or `cache-key` (found by the review of 2d.2f).
    _CREDENTIAL_NAME_RE = re.compile(
        r"api[_-]?key|access[_-]?key|private[_-]?key|secret|token|passw|credential|bearer|cookie|authorization"
        r"|(?:^|[_-])auth(?:$|[_-])|(?:anthropic|openai|gemini|claude|codex|model|llm)[_-]?key", re.I)

    def _credential_like(self, value) -> list[str]:
        """Values a part of the workflow is given that are not secrets but whose name says they may be a
        credential: `vars.X`, `inputs.X`, `github.event.inputs.X`, `needs.J.outputs.X` and
        `steps.S.outputs.X`, with X named like a key, a token or a password, and an `env` name of a model
        key (`MODEL_KEYS`, `WITHHELD_BY_AWF`) given text that is not a secret."""
        found: list[str] = []
        for body in expressions(value):
            for ref in expr_mod.refs(body):
                path = ref.path
                names = [part.value for part in path if part.kind == expr_mod.NAME]
                if not names:
                    continue
                head = names[0].lower()
                routed = head in ("vars", "inputs") or (head == "github" and len(names) > 2
                                                        and names[1].lower() == "event"
                                                        and names[2].lower() == "inputs") \
                    or (head in ("needs", "steps") and len(names) > 2 and names[2].lower() == "outputs")
                last = names[-1] if len(names) > 1 else ""
                whole = len(names) < (4 if head in ("needs", "steps") or (head == "github") else 2)
                if routed and (whole or self._CREDENTIAL_NAME_RE.search(last)):
                    shown = ".".join(one_line(n, 40) for n in names[:4])
                    if shown not in found:
                        found.append(shown)
        keys = set(egress_mod.MODEL_KEYS) | set(egress_mod.WITHHELD_BY_AWF)

        def envs(item, depth=0) -> None:
            if depth > 6:
                return
            if isinstance(item, dict):
                env = item.get("env")
                if isinstance(env, dict):
                    for name, given in env.items():
                        if isinstance(name, str) and name.upper() in keys and given not in (None, "") and \
                                not self._credentials(given) and f"env.{name}" not in found:
                            found.append(f"env.{one_line(name, 40)}")
                for key, sub in item.items():
                    if key != "env":
                        envs(sub, depth + 1)
            elif isinstance(item, list):
                for sub in item:
                    envs(sub, depth + 1)
        envs(value)
        return found

    def _agent_patterns(self) -> list:
        """The agent command patterns, the catalog's and the configuration's, compiled once."""
        cached = self.__dict__.get("_agent_patterns_cache")
        if cached is None:
            cached = [re.compile(p, re.M) for p in
                      list(self.detection.get("agent_commands", [])) + list(self.agents.get("commands", ()) or ())]
            self.__dict__["_agent_patterns_cache"] = cached
        return cached

    def _agent_actions(self) -> AgentActions:
        """The agent actions, the catalog's (less the paths it lists as running no agent) and the
        configuration's, built once (flagship slice 2d.11)."""
        cached = self.__dict__.get("_agent_actions_cache")
        if cached is None:
            cached = AgentActions(self.detection, self.agents.get("actions", ()) or ())
            self.__dict__["_agent_actions_cache"] = cached
        return cached

    def _agent_step(self, step: Step, text: str) -> str | None:
        """Why the checker takes the step to run an agent, or None."""
        if self._agent_actions().names(step.action):
            return f"uses {one_line(step.action, 80)}"
        if leaves_repository(step.uses):
            return f"uses {one_line(step.uses, 80)}, a path out of its repository that can reach any action the job downloads"
        if text and matches_any(self._agent_patterns(), text):
            return "runs an agent CLI"
        return None

    def draft_agent_steps(self, job: Job) -> list[Step]:
        """Direct agent candidates for a draft, excluding steps that only install or mention a CLI."""
        candidates = []
        for step in job.steps:
            reason = self._agent_step(step, step.agent_text(self._agent_patterns()))
            if reason == "runs an agent CLI" and (self._installs_only(job, step) or self._package_mention_only(step)):
                continue
            if reason:
                candidates.append(step)
        return candidates

    _OUTPUTS = frozenset({"workspace", "scratch"})

    # A command that installs packages with a JavaScript package manager, with `sudo` and its short
    # options before it (slice 2c.8). What follows it is read token by token in `_installs_only`.
    _INSTALL_RE = re.compile(r"(?:sudo(?:[ \t]+-[EHn]+)*[ \t]+)?"
                             r"(npm[ \t]+(?:install|i|add)|pnpm[ \t]+(?:add|install|i)|yarn[ \t]+global[ \t]+add"
                             r"|bun[ \t]+(?:add|install|i))((?:[ \t]+[^ \t]+)+)")
    # Options that take no value and run nothing (found by the review of 2c.8: `--script-shell`,
    # `--userconfig` and `--prefix` take a path, and a value can be a listed package's name).
    _INSTALL_OPTIONS = frozenset({"-g", "--global", "--no-fund", "--no-audit", "--ignore-scripts", "--silent"})
    # Commands that fetch a package and run it.
    _PACKAGE_RUNNER_RE = re.compile(r"\b(?:npx|bunx)\b|\bnpm[ \t]+(?:exec|x)\b|\bpnpm[ \t]+(?:dlx|exec)\b"
                                    r"|\byarn[ \t]+dlx\b|\bbun[ \t]+x\b")
    # Characters that let a shell line do more than its words say: substitutions, pipes, redirections,
    # groups, background jobs, quotes, globs, escapes and comments after a command. A script that has
    # any of them is not read as installs only.
    _SHELL_MORE_RE = re.compile(r"[`$|<>(){}&'\"\\*?!#\[\]]")

    def _installs_only(self, job: Job, step: Step) -> bool:
        """Whether a step does nothing but install agents' packages (`agent_installs` in detection.yaml) and print their
        CLIs' versions, read from its shell script (slice 2c.8): `sudo npm install -g
        @anthropic-ai/claude-code` and then `claude --version`, for one. Each line, and each command
        on it separated by `&&` or `;`, must be one of those two and nothing else; comment lines are
        skipped. Anything else makes it False, as does a script in another shell, an action, or a
        key of the step beyond the plain ones, so that a step running an agent in a form the patterns
        miss is not read as an install from its words alone (the limits are below). Each install must be
        `npm`'s, global, and name a listed package, with only
        options that take no value, and `sudo` only with `-E`, `-H` or `-n`: since the review of #248,
        `pnpm add -g`, `yarn global add` and `bun add -g` are not read as installs only, because each
        reads configuration from the working directory, and Yarn 1 runs the program a `.yarnrc` names
        there (`yarn-path`) in its place, outside the sandbox. The step may have no `env`
        or `working-directory`, and neither the job nor the workflow may set any `env` or
        `defaults.run`: each can make the same words run something else (`BASH_ENV`, `NODE_OPTIONS`,
        `PATH`, `npm_config_*`, a shell of the author's choosing). Found by the review of 2c.8. Not read,
        and not readable from the workflow: what earlier steps put in the environment (`GITHUB_ENV`,
        `GITHUB_PATH`, files in the home directory)."""
        packages = self.detection.get("agent_installs") or {}
        if not packages or step.uses is not None or not isinstance(step.raw.get("run"), str):
            return False
        if set(step.raw) - {"name", "id", "run", "shell", "if", "timeout-minutes", "continue-on-error"}:
            return False
        for defaults in (job.raw.get("defaults"), self.wf.raw.get("defaults")):
            if defaults is not None and not (isinstance(defaults, dict) and "run" not in defaults):
                return False
        for env in (job.raw.get("env"), self.wf.raw.get("env")):
            if env is not None and env != {}:
                return False    # the step inherits it (second review of 2c.8)
        shell = step.raw.get("shell")
        if shell is not None and shell not in ("bash", "sh"):
            return False
        clis = {str(cli) for cli in packages.values()}
        names = {str(name) for name in packages}
        version_re = re.compile(rf"(?:{'|'.join(re.escape(cli) for cli in sorted(clis))})[ \t]+--version")
        installed = False
        for line in step.run.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            commands = [part.strip() for part in re.split(r"&&|;", line)]
            for command in commands:
                if not command or self._SHELL_MORE_RE.search(command):
                    return False
                if version_re.fullmatch(command):
                    continue
                found = self._INSTALL_RE.fullmatch(command)
                if not found:
                    return False
                if not found.group(1).startswith("npm"):
                    # pnpm, yarn and bun read configuration from the working directory, which a checkout
                    # fills, and Yarn 1 runs the file a `.yarnrc` names in `yarn-path` instead of itself
                    # (review of #248, reproduced with Yarn 1.22.22). npm reads no project configuration
                    # in global mode.
                    return False
                tokens = found.group(2).split()
                if not {"-g", "--global"} & set(tokens):
                    return False        # a local install brings in the whole project's packages and scripts
                named = False
                for token in tokens:
                    if token in self._INSTALL_OPTIONS:
                        continue
                    if token.startswith("@"):
                        rest, at, version = token[1:].partition("@")
                        name = "@" + rest
                    else:
                        name, at, version = token.partition("@")
                    if name not in names or (at and not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.^~_-]*", version)):
                        return False
                    if at and re.search(r"[.](?:tgz|tar.gz|tar)$", version, re.I):
                        return False    # npm reads `name@x.tgz` as a file in the working directory (npm-package-arg's
                                        # `isFilename`), which a checkout fills (second review of #248)
                    named = True
                if not named:
                    return False        # options alone install the project, and run its scripts
                installed = True
        return installed

    def _package_mention_only(self, step: Step) -> bool:
        """Whether the only thing that makes the checker take a step for running an agent is the name of
        a package in `agent_installs`, with no command that fetches and runs a package (`npx`, `npm
        exec`, `pnpm dlx`, `yarn dlx`, `bunx`) and no other agent pattern. Such a step, when it is not
        read as an install, is "cannot tell" rather than an agent outside (slice 2c.8)."""
        packages = {str(name) for name in (self.detection.get("agent_installs") or {})}
        text = step.agent_text(self._agent_patterns())
        if not packages or not text or self._PACKAGE_RUNNER_RE.search(text):
            return False
        if any(f"{name}/" in text for name in packages):
            return False        # a path into the package (`…/claude-code/cli.js`) runs it
        patterns = list(self.detection.get("agent_commands", [])) + list(self.agents.get("commands", ()) or ())
        # A package's own pattern is its name, or its name with `(?![\w-])` after it so that a longer name
        # (`@github/copilot-language-server`) is not it (slice 2d.5b).
        own = packages | {name + r"(?![\w-])" for name in packages}
        others = [re.compile(p, re.M) for p in patterns if p not in own]
        return not any(rx.search(text) for rx in others) and any(name in text for name in packages)

    @staticmethod
    def _unread_cache_path(step: Step) -> str | None:
        """Why the `path` of an `actions/cache` step, whose post step saves that path after the job, cannot
        be read to the end, or None (review of #248). `_reads_output` finds /tmp and the confined command's
        output where the path names them; a path built from an expression (`${{ env.OUT }}`), one with a
        `..` part (`../../../../../t?p`, `~/../../t?p`), one that starts `~` and a user's name, the root
        folder (`/`, `//`, `/.`) and any other absolute path outside `/home` (`/proc/self/root/t?p`
        reaches /tmp, second review of #248) can reach them without naming them, so each is "cannot
        tell"; so are inputs that are not a mapping and a path that is not text. Leading `!`s and
        spaces are read past, as `actions/cache` reads them. Only the step with a post step is read:
        `actions/cache/save` saves when it runs, before the command, and `actions/cache/restore` saves
        nothing. Not read: a path into the workspace (relative, or absolute under `/home`) through a symbolic link
        that a checkout put there, and links the runner image has under `/home`."""
        if not step.uses_action("actions/cache") or step.uses_action("actions/cache/save") \
                or step.uses_action("actions/cache/restore"):
            return None
        given = step.raw.get("with")
        if given is None:
            return None
        if not isinstance(given, dict):
            return "its inputs are not written out"
        paths = [value for key, value in given.items() if str(key).strip().lower() == "path"]   # inputs ignore case
        if not paths:
            return None
        if not all(isinstance(path, str) for path in paths):
            return "its path is not text"
        path = "\n".join(paths)
        if "${{" in path:
            return "an expression"
        for line in path.splitlines():
            line = re.sub(r"^[\s\ufeff!]+", "", line).strip().strip("\ufeff")    # `! !/` negates twice
            if not line:
                continue
            if re.search(r"(?:^|[/\\])\.\.(?:[/\\]|$)", line):
                return "a '..' part, which can leave the folder it starts from"
            if line.startswith("~") and not re.match(r"~(?:[/\\]|$)", line):
                return "a '~' with a user's name, whose home the checker does not read"
            if re.fullmatch(r"[\"']?/[/\\.]*[\"']?", line):
                return "the root folder, which holds /tmp"
            if line.startswith("/") and not re.match(r"/home/[^/\s]", line):
                return "an absolute path outside /home, which can reach /tmp through a link the checker does not read"
        return None

    def _reads_output(self, step: Step, ids: set) -> list[str]:
        """Where a step refers to what a confined command could write: an `outputs.workspace` or
        `outputs.scratch` of a confined step (also through `steps.*`, a computed index or `toJSON`),
        or the scratch directory by its name, `obaaf-egress`. Returns the input names it does so in
        (`run`, `with.path`, `env.X`, ...)."""
        where: list[str] = []

        pattern = ({"steps"}, ids, {"outputs"}, set(self._OUTPUTS))

        def refers(text: str) -> bool:
            # The scratch directory is /tmp/obaaf-egress.<random>, so a step that names /tmp can reach it
            # through a pattern (`/tmp/obaaf*`, `/tmp/*`) as well as by its name. Read the widest way
            # (flagship slice 2d.2f): also with quotes and backslashes taken out and slashes collapsed,
            # a top-level path written as a pattern or built from a variable (`/t[m]p`, `/t?p`, `/*/`,
            # `/$D`), and a temporary directory asked for by name (`mktemp`, `TMPDIR`, `tempfile`).
            if egress_mod.names_temporary(text):
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
        # What the action does with an OPENSSL_ name under `env` is known only for a commit OBAAF lists:
        # from the floor on it refuses it (2c.11b's review: the refusal was said of every version).
        uses = (step.uses or "").strip()
        ref = uses.split("@", 1)[1] if "@" in uses else ""
        listed = ref in {str(sha).lower() for sha in self.detection.get("egress_action_releases", []) or []}
        for name in env_names or []:
            if not egress_mod.NAME_RE.match(name):
                place.problems.append(f"{where} names {one_line(name, 60)!r} under env, which is not a variable name, "
                                      "so the action refuses to run")
            elif name in egress_mod.WITHHELD_BY_AWF:
                place.problems.append(f"{where} names {name} under env, a name AWF withholds from the command, so "
                                      "the action refuses to run (a model key goes under model-keys)")
            elif listed and egress_mod.removed_before_inputs(name):
                place.problems.append(f"{where} names {name} under env, and the action at a listed commit removes "
                                      "every OPENSSL_ variable from its own steps before it reads env (slice 2c.11a), "
                                      "so it finds the name unset and refuses to run (issue #197)")
            elif listed and egress_mod.reserved_under_env(name):
                # Known only for a listed commit, as above (added by the review of A3a, review-gpt #283).
                place.problems.append(f"{where} names {name} under env, a name the action at a listed commit "
                                      "sets, withholds or reads as AWF's own configuration, so the action "
                                      "refuses to run")
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
                if not isinstance(name, str):
                    # `true:` or `1:` is not text to this reader; what GitHub names the variable is not
                    # established. Found by the second review: `true` was compared as "True".
                    place.unsure.append(f"{where} sets a variable whose name is not written as text "
                                        f"({one_line(str(name), 40)}) to {self._names(found)}, and what GitHub "
                                        "names it is not established")
                    continue
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
        # `github.token` or the step's env (names matched without regard to case, which covers an exact
        # match however GitHub compares them); a credential in any other input is not placed. An
        # allow-list or a list of names computed from one is reported above as computed.
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
                elif (found or via) and not (input_name(name) in ("allow", "env", "model-keys")
                                             and isinstance(value, str) and expr_mod.OPEN in value):
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
                if name in egress_mod.WITHHELD_BY_AWF or not egress_mod.NAME_RE.match(name) \
                        or (listed and (egress_mod.removed_before_inputs(name)
                                        or egress_mod.reserved_under_env(name))):
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
        hosts = sorted({host for place in placements for host in place.hosts})
        keys = sorted(name for name, host in egress_mod.MODEL_KEYS.items() if host in hosts)
        parts = ["anything the confined command sends to a listed host"
                 + (f", the credentials passed to it included ({self._names(passed)}), with which a listed host "
                    "can be made to act for it" if passed else ""),
                 "data in a name under a listed name, which leaves the runner in a DNS query to that name's DNS servers"]
        if hosts:
            given = f"with {', '.join(keys)} given to AWF's API proxy"
            parts.append(f"{given}: anything the command sends {' or '.join(hosts)} through the proxy, and whatever "
                         "the provider is asked to fetch or connect to for it (remote MCP servers, URLs); the proxy "
                         "refuses the providers' hosted web search and fetch tools, in the requests it can read, and "
                         "nothing else of that kind")
        parts.append("and anything the command prints to the job's log")
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
          scratch directory. A possible artifact upload is "cannot tell". Saving them to a cache is "not met";
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
        # A key can reach a step by a route that is not a secret: a variable, an input, another step's or
        # job's output (flagship slice 2d.2f). The checker cannot see what such a value holds, so one
        # whose name says it is a credential, given outside the confined command, is "cannot tell".
        for label, value in [("the workflow's env", {"env": self.wf.raw.get("env")}), ("the job", rest)] + \
                [(f"step '{one_line(step.name, 80)}'", step.raw) for step in others]:
            names = self._credential_like(value)
            if names:
                unsure.append(f"{label} is given {', '.join(names[:3])}, which by its name may be a credential the "
                              "checker cannot see into, so the agent may run outside the confined command with it")
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
        # Which steps can run after (or beside) the confined command: read here, and below for what
        # they could run of what the command wrote.
        first = min(step.index for step in confined)
        groups = {step.group for step in confined if step.group is not None}
        concurrent = any(step.background for step in confined)
        agents_outside = []
        for step in others:
            why = self._agent_step(step, step.agent_text(self._agent_patterns()))
            before = (step.index < first and not step.background and not concurrent
                      and (step.group is None or step.group not in groups))
            if why == "runs an agent CLI" and before and step.index not in job.agent_script_steps:
                if self._installs_only(job, step):
                    continue    # it installs the agent's CLI, which the confined command then runs (2c.8)
                if self._package_mention_only(step):
                    unsure.append(f"step '{one_line(step.name, 80)}', before it, names an agent's package in a "
                                  "script the checker reads as neither an install it can vouch for nor a run")
                    continue
            if why or step.index in job.agent_script_steps:
                agents_outside.append(f"step '{one_line(step.name, 80)}' "
                                      f"{why or job.agent_step_why.get(step.index, 'runs an agent in a script')}")
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
        # The ordinary report summarises these groups and prioritises definite
        # problems. Keep the complete evidence for the one-job draft as well.
        grouped = {}

        def group(bucket, entries, explanation):
            summary = egress_mod.joined(entries, 3) + explanation
            # Retain each subject with its explanation. A length-limited work
            # order can then show why each named step matters before truncation.
            grouped[summary] = tuple(entry + explanation for entry in entries)
            bucket.append(summary)

        if agents_outside:
            group(problems, agents_outside, ", outside the confined command")
        if outside:
            group(problems, outside, ", so the agent may run outside the confined command "
                  "(the checker tells where an agent runs by where its key goes)")
        elif not agents_outside and not any(place.reaches for place in placements):
            recognised = [step for step in confined if self._agent_step(step, step.agent_text(self._agent_patterns()))
                          or step.index in job.agent_script_steps]
            if not recognised:
                unsure.append("no credential reaches the confined command or AWF's API proxy, no other step is given "
                              "one, and the checker recognises no agent in the confined command, so it cannot tell "
                              "where the agent runs: an agent that needs no key could run in any step")
        if unread_token and not outside:
            unsure.append("the job does not declare its token's permissions, so the repository's default applies, "
                          "which the checker does not read, and every action is given that token")
        # What runs after (or beside) the confined command. `actions/upload-artifact` is read by
        # `_artifact_upload` as an upload (decision D-133). A script, or any other action, could run or
        # load what the command wrote, and the checker cannot tell reading from running. Steps before it are read for what their post
        # steps or the processes they leave running could reach: the outputs, the scratch directory by
        # its name, or /tmp.
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
            unread = self._unread_cache_path(step) if before else None
            if unread:
                unsure.append(f"{where}, before it, saves a cache whose path the checker cannot read to the end "
                              f"({unread}); its post step saves after the job, from which a later run can load it, "
                              "and the path may reach /tmp or the confined command's output")
                continue
            if not before:
                if step.clean_action in ("actions/upload-artifact", "actions/upload-artifact/merge", "actions/upload-pages-artifact"):
                    continue
                after.append(where)
            elif refs:
                unsure.append(f"{where}, before it, names /tmp or the scratch directory ({', '.join(refs[:3])}), "
                              "and its post step or a process it leaves running could reach what the command wrote")
            elif egress_mod.leaves_process(step.run):
                unsure.append(f"{where}, before it, may leave a process running beside it "
                              f"({egress_mod.leaves_process(step.run)}), which could reach what the command wrote")
        if after:
            group(unsure, after, " can run after it or beside it, and the checker cannot tell "
                  "whether it runs or loads anything the command wrote (an actions/upload-artifact step is "
                  "read as an upload instead)")
        upload = self._artifact_upload(job, egress=True)
        if upload:
            unsure.append(f"{upload}. The checker cannot establish what this step runs outside the confined command")
        verdict = egress_mod.worst(problems, unsure)
        if verdict == VERIFIED:
            detail = (f"the agent's command runs under OBAAF's egress action at a commit OBAAF lists as released, "
                      f"allowing {one_line(', '.join(allow_shown), 200)}, and no later step other than an artifact upload was recognised. "
                      f"{self._leaks(placements)}")
        else:
            detail = egress_mod.joined(problems or unsure)
        action = ", ".join(sorted({one_line(step.uses or "", 120) for step in confined}))
        conditions = tuple(condition for message in (*problems, *unsure)
                           for condition in grouped.get(message, (message,)))
        return egress_mod.Reading(verdict, detail, "egress-action",
                                  {"action": action, "allow": allow_shown or ["nothing"], "written": self._written()},
                                  conditions)

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
        which an explicit audit snapshot can establish for a concrete secret and environment."""
        scoped = "each of the job's secrets is listed in protected_secrets, and the job declares the environment named there"
        setting = "the secrets are stored only in that environment, and only protected branches may use it"
        declared = job.environment
        written = job.raw.get("environment")
        written = written.get("name") if isinstance(written, dict) else written
        # `010` is the number 8 to this reader and may be the number 10, or text, to GitHub's, and
        # `0` or `false` may be a name to GitHub and is nothing here.
        odd = written is not None and not isinstance(written, str)
        shown = "the job's environment" if odd else f"environment '{one_line(declared, 120)}'"

        def both(verdict: str, detail: str, second: str = CANNOT_TELL, *, named_secrets=()) -> list[Control]:
            if second == NOT_MET:
                about = "the job declares no environment, so its secrets come from the repository or organization"
            else:
                about = (f"where a secret is stored and which branches may use {shown} are repository "
                         "settings, which obaaf check does not read; obaaf audit reads environments and their "
                         "branch rules")
            if self.settings is not None:
                if verdict != VERIFIED:
                    about = detail
                elif self.wf.callable:
                    about = "the snapshot cannot establish the storage of caller-supplied secrets"
                elif job.environment_reading[0] != "literal" or not named_secrets:
                    about = "each secret needs a literal environment named by protected_secrets and the job"
                else:
                    results = [self.settings.assess(secret, declared) for secret in named_secrets]
                    verdicts = {result.verdict for result in results}
                    if NOT_MET in verdicts:
                        second = NOT_MET
                    elif verdicts == {VERIFIED}:
                        second = VERIFIED
                    about = "; ".join(dict.fromkeys(result.reason for result in results))
                about = f"Settings snapshot taken {self.settings.taken_at}: {about}"
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
        return both(VERIFIED, f"{listed} in environment '{one_line(declared, 120)}'",
                    named_secrets=upper if all(any(envs) for envs in wanted.values()) else ())

    # Events that only someone with write access can cause, and whose payload outsiders do not write.
    _WRITE_ACCESS_EVENTS = frozenset({"push", "workflow_dispatch", "schedule", "release"})
    # More ways a script names a pull request's code than `pr_fetch` reads. Used for the control
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
                if self._combined(*self._checkout_reading(job, step)).state == "head" \
                        or self._PR_CODE_IN_SCRIPT_RE.search(ref.lower()):
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
            elif pr_fetch(step, self._env_for(job, step), self._shell(job, step)).state == "head" \
                    or self._PR_CODE_IN_SCRIPT_RE.search(step.text()):
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

    # Variables that still reach the action's own steps, which hold the key outside the sandbox, at every
    # commit that can be listed (from `egress_action_floor`, slice 2c.12b's last change to the action, on).
    # Slice 2c.10b (decision D-070) dropped the rest of the list slice 2c.7 began with (issue #139): since
    # 2c.9 those steps are `/usr/bin/python3 -I -S` by its full path, so bash's variables (`BASH_ENV`,
    # `ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `IFS`, `BASH_FUNC_*`) and Python's (`PYTHONPATH`,
    # `PYTHONSTARTUP`, `PYTHONHOME`) have nothing to act on; every program they start is given an `env`
    # of its own with a fixed `PATH`, and found through that `PATH`, so the job's `PATH` finds nothing
    # for them; and their own `env` empties the loader's variables (`LD_PRELOAD`, `LD_AUDIT`,
    # `LD_LIBRARY_PATH` and the rest), which outranks the job's `env`, the workflow's and `GITHUB_ENV`
    # (the escape tests' job `own-steps` shows it for the job's, the step's and `GITHUB_ENV`).
    # Slice 2c.11b (decision D-072) dropped OpenSSL's, which 2c.10b had added: the action's Python
    # imports `hashlib`, and `OPENSSL_CONF` (or, with Ubuntu's libcrypto, `OPENSSL_FORCE_FIPS_MODE` or
    # `OPENSSL_FIPS_MODE_SWITCH_PATH` beside `OPENSSL_MODULES`) made libcrypto load into that process a
    # module the job named; from slice 2c.11a's change on, `egress.py` removes every variable whose name,
    # trimmed and upper-cased, begins `OPENSSL_` from its own process before that import (decision
    # D-071), and the escape tests' job `openssl-modules` shows on a GitHub-hosted runner that a module
    # named that way through the job's `env`, the step's `env` and `GITHUB_ENV` loads at slice 2c.9's
    # floor and not since. Slice 2c.12 (decision D-075) added no name: from the floor on, each step's own
    # `env` fixes `LC_ALL` and `TZ`, which glibc and Python read as Python starts, and `egress.py`
    # empties its environment before it imports anything but `os`, so the steps read nothing else a
    # workflow can set for them (the escape tests' job `own-steps-environment` shows it for the
    # locale, the time-zone file, the CA file and the proxy, on a GitHub-hosted runner).
    # `ACTIONS_ALLOW_UNSECURE_COMMANDS` lets any line a step prints set variables
    # for the steps after it (`::set-env::`; found by the second review of 2c.7), as a write to
    # `GITHUB_ENV` does, and it stays with that write (below).
    _REACHES_OWN_STEPS = frozenset({"ACTIONS_ALLOW_UNSECURE_COMMANDS"})
    # A step that sets variables for the steps after it, the action's own included. The `PATH` it can
    # change for them (`GITHUB_PATH`, `addPath`) and bash's `BASH_ENV` no longer reach them (2c.10b).
    # The runner's folder for those files (`_runner_file_commands`) counts too, and the words are looked
    # for in the step's `env` values and inputs as well as its script (2c.10b's review: `eval "$CMD"`
    # with the write in `env`, or the file written by its path).
    _SETS_FOR_LATER_RE = re.compile(r"GITHUB_ENV|exportVariable|_runner_file_commands", re.I)

    @classmethod
    def _reaches_own_steps(cls, key) -> bool:
        """Whether an `env` key names a variable that would still set what the egress action's own
        steps obey (slices 2c.10b and 2c.11b), read the widest way: any letter case, space around it,
        and a key written as an expression, whose name the checker does not work out."""
        if expr_mod.OPEN in str(key):
            return True
        return str(key).strip().upper() in cls._REACHES_OWN_STEPS

    KEY_NAME = ("the agent's command cannot read any of the job's secrets: each goes only to a proxy that holds it "
                "for the command, or to nothing the command runs")
    KEY_ID = "key-out-of-reach"

    @staticmethod
    def _secret_refs(found: list) -> list:
        """The credentials `_credentials` found that are secrets OBAAF-GHA-005 is about: every named
        secret but GITHUB_TOKEN, and every secret where the name is computed. The job's own token is
        OBAAF-GHA-003's, as it is for `secret_names`."""
        return [cred for cred in found if cred == "all secrets"
                or (cred.startswith("secrets.") and cred[len("secrets."):].upper() != "GITHUB_TOKEN")]

    def _key_control(self, job: Job) -> Control:
        """Whether the agent's command can read the job's secrets (flagship slice 2c.7). A key the
        agent can read can leave in the job's log or an artifact whatever the network allows, so a
        limit on the network protects it less than it protects data, and only a key the command cannot
        read is out of that reach. The one way the checker can establish that today is OBAAF's egress
        action with the key named in `model-keys`: the action gives it to AWF's API proxy, which the
        command can use and cannot read (2c.4, tested with made-up keys). So the control is verified
        only when every secret the job receives is set in the `env` of steps that use the action, at a
        commit OBAAF lists as released, on the runner it was tested on, and each goes to the proxy or
        to nothing the command runs (`_placement`). A secret anywhere else in the job (another step, the
        job's or the workflow's `env`) is where an agent outside the sandbox could read it, and the
        checker tells where the agent runs by where its key goes, so that is "not met"; so is a secret
        passed to the command. GitHub's native firewall holds no key. The step that uses the action
        still holds the key in its own process, outside the sandbox: a write to `GITHUB_ENV` or a line
        printed under `ACTIONS_ALLOW_UNSECURE_COMMANDS`, which set variables for those steps that the
        checker does not read to the end, an `env` key computed when the job runs, or a process an
        earlier step leaves running could reach it there, and each is "cannot tell". OpenSSL's
        variables no longer count since slice 2c.11b: the action removes them before libcrypto loads."""
        name, ident = self.KEY_NAME, self.KEY_ID
        reach = "a key the agent can read can leave in the job's log or an artifact whatever the network allows"
        if job.reusable:
            return Control(name, CANNOT_TELL, "its steps are in the reusable workflow it calls, which the checker "
                                              "does not read", ident)
        confined = [step for step in job.steps if step.confines]
        if not confined:
            if self._awf(job) is not None:
                return Control(name, CANNOT_TELL, "a step runs the Agent Workflow Firewall from a script, whose API "
                                                  "proxy can hold a model key, and the checker does not read a shell "
                                                  "command line well enough to tell which key it holds", ident)
            native = self._native_firewall(job)
            how = (" GitHub's native egress firewall limits the network and holds no key." if native is not None
                   else "")
            return Control(name, NOT_MET, "no step of the job runs the agent's command behind a proxy that holds its "
                                          "keys, so the agent runs where the job's secrets are and can read them, or "
                                          f"reach them through what it leaves for later steps.{how} "
                                          f"{reach[0].upper()}{reach[1:]}",
                           ident)
        problems: list[str] = []
        unsure: list[str] = []
        # Where else in the job the secrets are: each place is one an agent outside the sandbox could
        # read (registry credentials go to GitHub to pull images and to no step).
        outside: list[str] = []
        found = self._secret_refs(self._credentials(self.wf.raw.get("env")))
        if found:
            outside.append(f"the workflow's env holds {self._names(found)}, which every step is given")
        rest = self._without_registry_credentials({key: value for key, value in job.raw.items() if key != "steps"})
        found = self._secret_refs(self._credentials(rest))
        if found:
            outside.append(f"the job gives {self._names(found)} outside its steps")
        for step in job.steps:
            if step.confines:
                continue
            found = self._secret_refs(self._credentials(step.raw))
            if found:
                outside.append(f"step '{one_line(step.name, 80)}' is given {self._names(found)}")
        if outside:
            problems.append(f"{egress_mod.joined(outside, 3)}, outside the command the egress action confines, "
                            "where an agent outside the sandbox could read it (the checker tells where an agent runs "
                            f"by where its key goes); {reach}")
        released = {str(sha).lower() for sha in self.detection.get("egress_action_releases", []) or []}
        held: list[str] = []         # what goes to the proxy or to nothing the command runs, for the report
        keyed: list = []             # the confined steps that hold a secret of the job
        placements: list = []
        for step in confined:
            place = self._placement(job, step)
            placements.append(place)
            where = place.step
            given = self._secret_refs(self._credentials(step.raw))
            if not given:
                continue
            keyed.append(step)
            problems.extend(place.problems)
            unsure.extend(place.unsure)
            passed = [(how, self._secret_refs(creds)) for how, creds in place.command]
            passed = [(how, creds) for how, creds in passed if creds]
            for how, creds in passed:
                problems.append(f"{self._names(creds)} is passed to the command {how}, so the agent can read it; "
                                f"{reach}")
            placed: set = set()
            for _how, creds in place.command:
                placed.update(creds)
            for variable, creds in place.proxy:
                placed.update(creds)
                held.append(f"{variable} ({self._names(creds)}) goes to AWF's API proxy in {where}")
            for variable, creds in place.neither:
                placed.update(creds)
                held.append(f"{variable} ({self._names(creds)}) is set in {where}'s env and passed to neither the "
                            "command nor the proxy")
            unplaced = [cred for cred in given if cred not in placed]
            if unplaced and not place.unsure and not place.problems:
                unsure.append(f"{where} is given {self._names(unplaced)} where the checker does not place it")
            uses = (step.uses or "").strip()
            ref = uses.split("@", 1)[1] if "@" in uses else ""
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                unsure.append(f"{where} uses the action at '{one_line(ref, 60)}', not a commit, so what that version "
                              "does with the key is not established")
            elif ref not in released:
                unsure.append(f"{where} uses the action at {ref[:12]}, which is not a commit OBAAF lists as released "
                              f"({len(released) or 'none'} listed), so what that version does with the key is not "
                              "established")
        # The proxy and the sandbox that keeps the command from the key were tested on one runner.
        sets = job.runner_label_sets()
        if job.raw.get("container") is not None:
            unsure.append("the job runs in a container, where the action and its API proxy have not been tried")
        if not sets or any(len(s) != 1 or s[0].strip().lower() != "ubuntu-24.04" for s in sets):
            unsure.append(f"the job runs on {one_line(', '.join(job.runs_on) or 'labels the checker cannot read', 80)}; "
                          "the action and its API proxy were tested only on GitHub-hosted ubuntu-24.04 runners")
        # The step that uses the action holds the key in its own process, outside the sandbox, and the
        # action's own steps run there with the key in their environment. What the workflow's, the
        # job's and the step's env set reaches them; so does anything a step before or beside it
        # writes to GITHUB_ENV, leaves running, or is: an agent outside the sandbox can reach the key
        # through any of those. Found by the review of 2c.7: an agent CLI in the step before, a decoy
        # use of the action first, parallel steps and service containers all passed. Which variables
        # still reach those steps is slice 2c.10b's (`_REACHES_OWN_STEPS`).
        envs = [self.wf.raw.get("env"), job.raw.get("env"), *(step.raw.get("env") for step in keyed)]
        loaded = [str(key) for env in envs if isinstance(env, dict) for key in env if self._reaches_own_steps(key)]
        if loaded or any(env is not None and not isinstance(env, dict) for env in envs):
            what = self._names(sorted(set(loaded))) if loaded else "an env computed when the job runs"
            unsure.append(f"the job sets {what}, which may set a variable for the action's own steps outside the "
                          "sandbox, where the key is held: ACTIONS_ALLOW_UNSECURE_COMMANDS lets any line a step "
                          "prints set one, as a write to GITHUB_ENV does, and a key written as an expression, or an "
                          "env computed when the job runs, holds names the checker does not work out (slices 2c.10b "
                          "and 2c.11b)")
        services = job.raw.get("services")
        if isinstance(services, dict) and any(isinstance(svc, dict) and ("volumes" in svc or "options" in svc)
                                              for svc in services.values()):
            unsure.append("the job's service containers are given volumes or options, and run beside the step that "
                          "holds the key for the whole job")
        perms = job.permissions
        if perms is not None and perms.oidc:
            problems.append("the job can request OIDC tokens (id-token: write), which any step can turn into a "
                            "credential, so the agent may run outside the sandbox, before the step that holds the key")
        if perms is not None and perms.level("models") in ("read", "write"):
            problems.append("the job's token can call GitHub Models (models permission), and every action is given "
                            "that token, so the agent may run outside the sandbox, before the step that holds the key")
        if perms is None:
            unsure.append("the job does not declare its token's permissions, so the repository's default applies, "
                          "which the checker does not read, and every action is given that token")
        nearby: dict = {}            # step index -> the step, for every step that can run before or beside a key
        for holder in keyed:
            for step in job.steps:
                if step is holder:
                    continue
                if (step.index < holder.index or holder.background
                        or (holder.group is not None and step.group == holder.group)):
                    nearby[step.index] = step
        evidence = any(place.reaches for place in placements) or any(
            self._agent_step(step, step.agent_text(self._agent_patterns())) or step.index in job.agent_script_steps for step in confined)
        first = min(holder.index for holder in keyed) if keyed else 0
        agent_seen = False           # an agent recognised in a step before or beside a key, said as "not met"
        for step in sorted(nearby.values(), key=lambda s: s.index):
            where = f"step '{one_line(step.name, 80)}'"
            if step.confines:
                if step in keyed:
                    continue        # read above as a step that holds a key
                # Its env is not read for ACTIONS_ALLOW_UNSECURE_COMMANDS: the third review of 2c.7 found every
                # line the action prints that the command can influence is under `::stop-commands::` or kept to
                # the characters of a host name, path or DNS name, so none can start with `::`.
                uses = (step.uses or "").strip()
                ref = uses.split("@", 1)[1] if "@" in uses else ""
                if not re.fullmatch(r"[0-9a-f]{40}", ref) or ref not in released:
                    unsure.append(f"{where} uses the action at '{one_line(ref, 60)}', which is not a commit OBAAF "
                                  "lists as released, before or beside the step that holds the key, and what that "
                                  "version's own steps do outside the sandbox is not established")
                continue
            why = self._agent_step(step, step.agent_text(self._agent_patterns()))
            plain_before = step.index < first and not step.background and step.group is None
            if why == "runs an agent CLI" and plain_before and step.index not in job.agent_script_steps:
                if self._installs_only(job, step):
                    why = None      # it installs the agent's CLI, which the confined command runs (2c.8)
                elif self._package_mention_only(step):
                    unsure.append(f"{where}, before the step that holds the key, names an agent's package in a "
                                  "script the checker reads as neither an install it can vouch for nor a run")
                    why = None
            if why or step.index in job.agent_script_steps:
                agent_seen = True
                problems.append(f"{where} {why or job.agent_step_why.get(step.index, 'runs an agent in a script')}, "
                                "outside the sandbox, before or beside "
                                "the step that holds the key, as the same user, and can reach the key through what "
                                "it leaves for that step (its environment, its PATH, a process left running)")
                continue
            given = self._credentials(step.raw)
            if given and not self._secret_refs(given):      # a secret of the job is said above
                problems.append(f"{where} is given {self._names(given)}, before or beside the step that holds the "
                                "key, so the agent may be that step (the checker tells where an agent runs by where "
                                "its key goes)")
                continue
            text = step.text()
            beside = any((step.background and step.index < holder.index)
                         or (holder.background and step.index > holder.index)
                         or (holder.group is not None and step.group == holder.group) for holder in keyed)
            if beside:
                unsure.append(f"{where} runs beside the step that holds the key, as the same user, and could read it "
                              "from that step's process")
            elif egress_mod.leaves_process(text):
                unsure.append(f"{where}, before the step that holds the key, may leave a process running "
                              f"({egress_mod.leaves_process(text)}) as the same user, which could read the key "
                              "from that step's process")
            own_env = step.raw.get("env")
            # The same widest read as the step that holds the key: any letter case, space around the
            # name, and a key written as an expression (slice 2c.11b; before, only the letter case).
            unsecure = sorted(str(key) for key in own_env if self._reaches_own_steps(key)) \
                if isinstance(own_env, dict) else []
            if unsecure:
                unsure.append(f"{where}, before or beside the step that holds the key, sets "
                              f"{one_line(', '.join(repr(key) for key in unsecure), 120)} in its env "
                              "(ACTIONS_ALLOW_UNSECURE_COMMANDS, or a key written as an expression, whose name the "
                              "checker does not work out), and ACTIONS_ALLOW_UNSECURE_COMMANDS lets any line it "
                              "prints set a variable for the steps after it")
            elif own_env is not None and not isinstance(own_env, dict):
                # A whole env computed when the job runs may hold it too (found by 2c.11b's review: it was
                # read as no env at all, where the key's own step, the job and the workflow read it as
                # "cannot tell").
                unsure.append(f"{where}, before or beside the step that holds the key, has an env that is not a "
                              "mapping the checker can read (one computed when the job runs, say), which may hold "
                              "ACTIONS_ALLOW_UNSECURE_COMMANDS, and "
                              "ACTIONS_ALLOW_UNSECURE_COMMANDS lets any line it prints set a variable for the steps "
                              "after it")
            if self._SETS_FOR_LATER_RE.search(text + " " + str(step.raw.get("env", "")) + " "
                                              + str(step.raw.get("with", ""))):
                unsure.append(f"{where}, before or beside the step that holds the key, writes to GITHUB_ENV, which "
                              "can set variables for the steps after it, the action's own included, and the "
                              "checker does not read which: one may be ACTIONS_ALLOW_UNSECURE_COMMANDS, which lets "
                              "any line a step prints set more (slices 2c.10b and 2c.11b)")
        if nearby and not evidence and not agent_seen:
            unsure.append("no key goes to AWF's API proxy or the command, and the checker recognises no agent in the "
                          "confined command, so it cannot tell where the agent runs: an agent that needs no key "
                          "could run in a step before or beside the one that holds the key")
        upload = self._artifact_upload(job)
        if upload:
            unsure.append(f"{upload}. Another job could load the artifact with access to its own credentials")
        if not held and not problems and not unsure:
            # Every secret of the job is in a confined step and none was placed: nothing to show.
            unsure.append("no secret of the job is placed by the checker in a step that uses the action")
        verdict = egress_mod.worst(problems, unsure)
        # Where each credential given to a confined step goes, whatever the verdict (it was the egress
        # control's detail from 2c.5 until this control existed).
        routes = self._key_routes(job)
        said = f" Where the confined step's credentials go: {routes}." if routes else ""
        if verdict == VERIFIED:
            detail = ("every secret of the job goes to AWF's API proxy, or to nothing the command runs, in steps that "
                      "use OBAAF's egress action at a commit OBAAF lists as released, on the runner it was tested on: "
                      f"the command can use a key the proxy holds and cannot read it.{said} The step's own process "
                      "holds each key outside the sandbox. The steps that can run before or beside it were read for "
                      "an agent, a credential, and, by the words in their scripts, a process left running and a write "
                      "to GITHUB_ENV; what an action used before it does, what an accepted install's "
                      "own scripts do, and what a script file a step runs writes, were not. Not stopped: "
                      "the command can use the key through the proxy, so it can make the provider act for it (calls "
                      "charged to the key, remote MCP servers, URLs the provider fetches)")
        else:
            detail = f"{egress_mod.joined(problems or unsure, 3)}.{said}".rstrip(".")
        return Control(name, verdict, detail, ident)

    def _release_step(self, step: Step) -> str:
        """A release step as one of OBAAF-GHA-015's facts: its written name or id, if any, and what makes
        it publish: `OBAAF_STEP: publish`, the action it uses without the ref, or the command matched, with
        its runs of space made one."""
        name = as_text(step.raw.get("name") or step.raw.get("id") or "")
        if str(step.env.get("OBAAF_STEP", "")).lower() == "publish":
            what = "OBAAF_STEP: publish"
        elif any(step.uses_action(a) for a in self.detection.get("upload_actions", [])):
            what = step.action or ""
        else:
            what = ""
            for variant in upload_readings(step.scripts()):
                for pattern in self.detection.get("upload_commands", []):
                    match = re.search(pattern, variant, re.M)
                    if match:
                        what = " ".join(match.group(0).split())
                        break
                if what:
                    break
        return f"{name} ({what})" if name else what

    @staticmethod
    def _environment_written(job: Job):
        written = job.raw.get("environment")
        return written.get("name") if isinstance(written, dict) else written

    def _publishing_capabilities(self, job: Job, builds: bool = True) -> list[str]:
        """What a job holds that publishing needs: `packages: write`, a step that uses an action listed
        under `publishing_actions`, a secret whose name says it publishes. `id-token: write` alone is not
        counted: OBAAF's own templates use it to sign and attest, which is what a repository should do,
        and OBAAF-GHA-004 reports it for an agent job. With `builds=False` (OBAAF-GHA-006 on a job that is
        not a release job, flagship slice 2d.14), a `docker/build-push-action` step that cannot push is not
        counted: it builds an image, and an image build with a GitHub Actions cache is common in jobs that
        publish nothing."""
        capabilities = []
        permissions = job.permissions
        if permissions is not None and permissions.level("packages") == "write":
            capabilities.append("packages: write")
        for step in job.steps:
            action = next((a for a in self.detection.get("publishing_actions", []) if step.uses_action(a)), None)
            if action and (builds or not _image_build_only(step, job)):
                capabilities.append(f"uses {step.action}")
        patterns = [re.compile(p, re.I) for p in self.detection.get("publishing_secret_patterns", [])]
        capabilities += [f"secret {name}" for name in sorted(job.secret_names())
                         if not name.startswith("*") and any(rx.search(name) for rx in patterns)]
        return capabilities

    def release_capability(self, job: Job, effects: "CallEffects | None" = None) -> None:
        """OBAAF-GHA-015 for a job nothing marks a release job, but that untrusted input can start and
        that holds what publishing needs: `packages: write`, a secret whose name says it publishes, an
        environment
        named by an expression the checker cannot read, or a step that uses an action listed under
        `publishing_actions` (flagship slice 2d.2d). Release jobs are
        recognised by lists of actions and commands and by environment names, which miss many; this
        fails closed on what the job can do instead."""
        triggers = job.triggers()
        bad = triggers & UNTRUSTED_TRIGGERS
        if not bad:
            return
        capabilities = self._publishing_capabilities(job)
        kind_, _written = job.environment_reading
        if kind_ in ("expression", "scalar", "unreadable") and not job.environment_candidates()[1]:
            capabilities.append("an environment whose name the checker cannot read")
        if not capabilities:
            return
        severity = "low" if not bad - self._FORK_SAFE_EVENTS else "medium"
        if effects is not None:
            # A job in the release lane because a workflow it calls releases (flagship slice 2d.4b3b): it is
            # known to release, through the called jobs, which carry the release rules with its triggers.
            workflows = list(dict.fromkeys(target.path for target in job.called))
            self.add("OBAAF-GHA-015", job.line,
                     "Job '{job}' can be started by {triggers}, holds what publishing needs ({capabilities}) and "
                     "calls {workflows}, where a job releases; the called release jobs are read with these "
                     "triggers, after their own if:.", job, severity=severity, kind="capability-call",
                     triggers=sorted(bad), capabilities=capabilities, workflows=self._workflows_fact(workflows),
                     environment=Fact(value_identity(self._environment_written(job)), ""))
            return
        self.add("OBAAF-GHA-015", job.line,
                 "Job '{job}' can be started by {triggers} and holds what publishing needs ({capabilities}). The "
                 "checker cannot tell whether it releases; if it does not, accept this finding and say why.", job,
                 severity=severity, kind="capability", triggers=sorted(bad), capabilities=capabilities,
                 environment=Fact(value_identity(self._environment_written(job)), ""))

    # -------------------------------------------------------------- GHA-006/014/015/016
    # Events whose runs from a fork get a read-only token and no secrets (OBAAF-GHA-015 only; the
    # review events still count as privileged for other rules, a false positive recorded in
    # docs/bypass-attempts.md).
    _FORK_SAFE_EVENTS = frozenset(PR_TRIGGERS | {"pull_request_review", "pull_request_review_comment"})

    def release_rules(self, job: Job) -> None:
        effects = job.call_effects if job.called else None
        if not job.in_lane("release"):
            self.release_capability(job)
            self.may_publish_caches(job)
            return
        if effects is not None and effects.lane_given:
            # Flagship slice 2d.4b3b: a job in the release lane only because a workflow it calls releases has
            # no steps and cannot name an environment; the called jobs carry OBAAF-GHA-006, 014, 015 and 016,
            # with this job's events (slice 2d.4b1). What it holds is read as before, and what the jobs it
            # needs built reaches the called jobs as the run's artifacts.
            self.release_capability(job, effects)
            feeding = self._jobs_feeding(job)
            if feeding:
                self.add("OBAAF-GHA-006", job.line,
                         "Release job '{job}' downloads artifacts and needs {jobs}, which restore caches and whose "
                         "cache-mode does not forbid it, so a poisoned cache entry can reach what it releases.",
                         job, kind="needed-job-restores",
                         controls=self._callers_cache_controls("on the jobs it needs that restore"),
                         jobs=Fact(feeding, ", ".join(f"'{j}'" for j in feeding)))
            return
        triggers = job.triggers()
        bad = triggers & UNTRUSTED_TRIGGERS
        if bad:
            # Flagship slice 2d.2d: why the job is a release job and its environment are facts, and the
            # severity follows OBAAF-GHA-001's: an environment named in plain text may require a
            # reviewer, and a run from a fork on a pull request event gets no secrets and a read-only token.
            # The steps that make it a release job are facts too, so an acceptance written for a job that
            # pushes to a registry inside the job does not cover one that later publishes to npm.
            # A step is named here by the name or id written for it, not by the default name (its `uses`
            # with the ref), and by what makes it publish (the action without its ref, or the command
            # matched), so a new pin of the same action is the same finding and another command is not.
            releasing = [self._release_step(s) for s in job.upload_steps(self.detection)]
            values = {"triggers": sorted(bad), "reason": job.reason_for("release"),
                      "environment": Fact(value_identity(self._environment_written(job)), ""),
                      "steps": Fact(releasing, ""),
                      "legacy": "Release job '{job}' can be started by {triggers}."}
            if not bad - self._FORK_SAFE_EVENTS:
                self.add("OBAAF-GHA-015", job.line,
                         "Release job '{job}' can be started by {triggers}. A run from a fork gets no secrets and a "
                         "read-only token, but a branch pushed by anyone with write access gets both; it is a "
                         "release job because it {reason}.", job, severity="medium", kind="pull-request", **values)
            elif job.environment_reading[0] == "literal":
                self.add("OBAAF-GHA-015", job.line,
                         "Release job '{job}' can be started by {triggers}; it is a release job because it {reason}. "
                         "Confirm that its environment requires reviewers.", job, severity="medium",
                         kind="environment", **values)
            else:
                self.add("OBAAF-GHA-015", job.line,
                         "Release job '{job}' can be started by {triggers}; it is a release job because it "
                         "{reason}.", job, **values)

        # Flagship slice 2d.2e. What decides a cache finding: the steps that may restore one, named by
        # their written name and what restores (the action without its ref, or the command), and the
        # cache-mode as written. A cache-mode forbids restores only when it is exactly `none` or
        # `write-only`; a value in another case, an expression or a null at the job is read as not set.
        cache_steps = [s for s in job.steps if self._restores_cache(s)]
        mode = job.cache_mode
        forbids = mode in ("none", "write-only")
        hosted_note = (" This job also runs on a self-hosted runner, where local caches (such as an engine's "
                       "derived-data cache) are outside what this check can see.") if job.self_hosted else ""
        runner = "-self-hosted" if job.self_hosted else ""
        # Flagship slice 2d.4b3b: in a workflow only jobs of this repository call, the callers' cache-mode is
        # what the job gets at most; a caller in another repository is not seen.
        callers = self._callers_cache_controls()
        if effects is not None and effects.restoring and not forbids:
            # A release job, by a declaration, that calls workflows whose steps restore caches (slice 2d.4b3b).
            self._called_caches(job, effects)
        elif cache_steps and not forbids:
            names = ", ".join(f"'{s.name}'" for s in cache_steps)
            self.add("OBAAF-GHA-006", cache_steps[0].line,
                     "Release job '{job}' restores caches in {steps} and its cache-mode is "
                     "{mode}." + hosted_note, job, cache_steps[0], kind="restores" + runner, controls=callers,
                     steps=Fact([self._cache_step(s) for s in cache_steps], names),
                     mode=Fact(mode or "", mode or 'not set'))
        elif not cache_steps and not forbids:
            self.add("OBAAF-GHA-006", job.line,
                     "Release job '{job}' does not set cache-mode: none, so a cache step added later would "
                     "read caches other workflows wrote." + hosted_note, job, severity="low",
                     kind="no-cache-mode" + runner, controls=callers)
        feeding = self._jobs_feeding(job)
        if feeding:
            self.add("OBAAF-GHA-006", job.line,
                     "Release job '{job}' downloads artifacts and needs {jobs}, which restore caches and whose "
                     "cache-mode does not forbid it, so a poisoned cache entry can reach what it releases.",
                     job, kind="needed-job-restores",
                     controls=self._callers_cache_controls("on the jobs it needs that restore"),
                     jobs=Fact(feeding, ", ".join(f"'{j}'" for j in feeding)))

        uploads = job.upload_steps(self.detection)
        releasing = Fact([self._release_step(s) for s in uploads], "")
        state = self._environment_state(job)
        # Flagship slice 2d.2e: a release job with no upload the lists know is reported when it holds what
        # publishing needs, so a publish the lists miss (`mvn deploy`, a script) is still held to this rule.
        holds = [] if uploads else self._publishing_capabilities(job)
        if state != "set" and (uploads or holds):
            first = uploads[0] if uploads else None
            line = first.line if first else job.line
            extra = {} if uploads else {"capabilities": holds, "reason": job.reason_for("release")}
            doing = ("uploads in '{step}'" if uploads else
                     "holds what publishing needs ({capabilities}; in the release lane: {reason})")
            if state == "none":
                self.add("OBAAF-GHA-014", line, "Release job '{job}' " + doing + " without a protected environment.",
                         job, first, kind="" if uploads else "capability", steps=releasing, **extra)
            else:
                said = {"blank": "a name that is blank", "open": "an expression that can be blank or name an "
                        "environment the checker cannot list", "unreadable": "a value that is not a name"}[state]
                self.add("OBAAF-GHA-014", line,
                         "Release job '{job}' " + doing + ", and its environment is written as " + said + ", so the "
                         "checker cannot tell whether a protected environment holds it back.",
                         job, first, kind=state + ("" if uploads else "-capability"), steps=releasing,
                         environment=Fact(value_identity(self._environment_written(job)), ""), **extra)

        if uploads:
            checked = self._upload_checks(job, uploads)
            unchecked = [s for s, k in checked if k is None]
            partial = [s for s, k in checked if k == "provenance"]
            unvouched = self._unvouched_checks(job, unchecked[0]) if unchecked else []
            if unchecked and unvouched:
                self.add("OBAAF-GHA-016", unchecked[0].line,
                         "Step '{step}' uploads after a check the checker cannot vouch for: {checks} names "
                         "`obaaf verify release` or another check, but not on a line of its own in a bash step "
                         "that stops when it fails, or after a line the checker does not read. Write the check "
                         "that way, or accept this finding and say why the check stops the upload.", job,
                         unchecked[0], kind="cannot-tell", steps=Fact([self._release_step(s) for s in unchecked], ""),
                         checks=Fact(unvouched, ", ".join(f"'{c}'" for c in unvouched[:3])))
            elif unchecked:
                self.add("OBAAF-GHA-016", unchecked[0].line,
                         "Step '{step}' uploads without an earlier check that stops it when "
                         "verification fails.", job, unchecked[0], kind="unchecked",
                         steps=Fact([self._release_step(s) for s in unchecked], ""))
            elif partial:
                self.add("OBAAF-GHA-016", partial[0].line,
                         "Step '{step}' uploads after a provenance check only; approvals and agent "
                         "records are not checked (use obaaf verify release).", job, partial[0], severity="medium",
                         kind="provenance-only", steps=Fact([self._release_step(s) for s in partial], ""))

    def may_publish_caches(self, job: Job) -> None:
        """OBAAF-GHA-006 for a job nothing puts in the release lane that holds what publishing needs and
        restores a cache, directly or through a job it needs and downloads from (flagship slice 2d.14, #289).
        Release jobs are recognised by lists of actions and commands, which miss many (`uv build publish`
        in zizmor's test workflow `cache-poisoning.yml`), and code from a poisoned cache entry runs with
        what the job holds whether or not the job itself publishes: it can publish with it. So such a job is
        reported at medium, as one the checker cannot tell releases. What it holds is a fact, so an
        acceptance written for one credential does not cover another one added later. Nothing when the job
        holds nothing for publishing, or restores nothing its cache-mode lets through; a job with no cache
        step gets no `no-cache-mode` finding, which is for release jobs. A job that calls a workflow of the
        repository is read for the jobs it needs, as for a release job (`_jobs_feeding`); a cache restored in
        the workflow it calls is read there, with the secret names that workflow's jobs use, so a credential
        the caller passes under another name is not counted."""
        mode = job.cache_mode
        # A step that uses a local action is taken to restore unless its steps were read as the job's, which
        # then decide (slice 2d.4b2's second pass): a local action is not a cache step by being local.
        # In the second pass a local action inside one is followed at once by its steps, named after it.
        read = {id(steps[0].via.raw) for steps in job.local_steps.values() if steps and steps[0].via is not None}
        read |= {id(s.via.raw) for s in job.steps if s.via is not None}

        def restores(n: int, step: Step) -> bool:
            if not _local_like(step.uses):
                return self._restores_cache(step)
            if step.via is None:
                return id(step.raw) not in read
            after = job.steps[n + 1] if n + 1 < len(job.steps) else None
            return not (after is not None and after.via is step.via
                        and after.name.startswith((f"{step.name}: ", f"{step.name} > ")))

        cache_steps = [] if _forbids_restores(mode) else [s for n, s in enumerate(job.steps) if restores(n, s)]
        # What the job holds is worked out only for a job that restores or downloads, and the jobs it needs
        # only for one that holds something: reading what callers grant costs, and so does following a long
        # chain of `needs` (the lead found a benchmark of 2,000 callers eight times slower when the first was
        # worked out for every job, and the review a chain of 2,000 downloading jobs eighteen times slower
        # when the second was).
        downloads = self._downloads_artifacts(job)
        if not cache_steps and not downloads:
            return
        held = self._may_publish_holds(job)
        if not held:
            return
        feeding = self._jobs_feeding(job) if downloads else []
        if cache_steps:
            names = ", ".join(f"'{s.name}'" for s in cache_steps)
            values = {"capabilities": held, "steps": Fact([self._cache_step(s) for s in cache_steps], names),
                      "mode": Fact(mode or "", mode or "not set")}
            controls = self._callers_cache_controls()
            if job.self_hosted:
                self.add("OBAAF-GHA-006", cache_steps[0].line,
                         "Job '{job}' holds what publishing needs ({capabilities}) and restores caches in {steps}, "
                         "and its cache-mode is {mode}. The checker cannot tell whether it releases; either way, "
                         "code from a poisoned cache entry would run while it holds them. This job also runs on a "
                         "self-hosted runner, where local caches (such as an engine's derived-data cache) are "
                         "outside what this check can see.", job, cache_steps[0], severity="medium",
                         kind="capability-restores-self-hosted", controls=controls, **values)
            else:
                self.add("OBAAF-GHA-006", cache_steps[0].line,
                         "Job '{job}' holds what publishing needs ({capabilities}) and restores caches in {steps}, "
                         "and its cache-mode is {mode}. The checker cannot tell whether it releases; either way, "
                         "code from a poisoned cache entry would run while it holds them.", job, cache_steps[0],
                         severity="medium", kind="capability-restores", controls=controls, **values)
        if feeding:
            self.add("OBAAF-GHA-006", job.line,
                     "Job '{job}' holds what publishing needs ({capabilities}), downloads artifacts and needs {jobs}, "
                     "which restore caches and whose cache-mode does not forbid it. The checker cannot tell whether "
                     "it releases what they built; if it does, a poisoned cache entry can reach what it releases.",
                     job, severity="medium", kind="capability-needed-job-restores",
                     controls=self._callers_cache_controls("on the jobs it needs that restore"), capabilities=held,
                     jobs=Fact(feeding, ", ".join(f"'{j}'" for j in feeding)))

    def _may_publish_holds(self, job: Job) -> list[str]:
        """What a job holds that publishing needs, for OBAAF-GHA-006 on a job that is not a release job
        (flagship slice 2d.14): what OBAAF-GHA-015 counts (`_publishing_capabilities`), less an image build
        that cannot push; a reference that can read every secret (`toJSON(secrets)`, a computed name,
        `secrets: inherit`), since which secrets exist is not in the workflow (as OBAAF-GHA-018 reads it);
        and a token with `contents: write`, which can create a GitHub release and upload its assets, in a job
        that a release event, a tag push, a tag's creation or another workflow's call can start
        (`_release_or_tag_events`). On other events `contents: write` is not counted: it is common in jobs
        that commit back, which this rule would then take for jobs that may release. A job of a called
        workflow that declares no permissions holds what the jobs of this repository that call it grant
        (`Job.granted_by_callers`, as OBAAF-GHA-003 and 004 read it); permissions nobody declares, the
        repository's default, are not counted (OBAAF-GHA-009 reports them)."""
        held = self._publishing_capabilities(job, builds=False)
        if any(name.startswith("*") for name in job.secret_names()):
            held.append("every secret, through a reference that is not one literal name or secrets: inherit")
        permissions = job.permissions
        if permissions is None:
            granted = {scope: [entry for entry in job.granted_by_callers(scope) if entry.endswith(f"{scope}: write")]
                       for scope in ("packages", "contents")}
        else:
            granted = {scope: [""] if permissions.level(scope) == "write" else [] for scope in ("packages", "contents")}
        events = self._release_or_tag_events(job) if granted["contents"] else []
        for scope in ("packages", "contents"):
            if not granted[scope] or (scope == "contents" and not events):
                continue
            on = f", on {' or '.join(events)}" if scope == "contents" else ""
            # The callers that grant it, as one bounded entry: the first three named, and a digest of all, so
            # the fact does not grow with the callers and a change to any changes it.
            wheres = sorted({entry[:-len(f" grants {scope}: write")] for entry in granted[scope] if entry})
            if not wheres:
                text = f"{scope}: write{on}"
            elif len(wheres) <= 3:
                text = f"{scope}: write{on}, granted by {', '.join(wheres)}"
            else:
                digest = hashlib.sha256("\n".join(wheres).encode("utf-8", "surrogatepass")).hexdigest()[:16]
                text = (f"{scope}: write{on}, granted by {', '.join(wheres[:3])} and {len(wheres) - 3} more "
                        f"(sha256:{digest})")
            if text not in held:
                held.append(text)
        return held

    def _release_or_tag_events(self, job: Job) -> list[str]:
        """The events among those that can start the job that can be for a release or a tag: `release`,
        `create` (a branch's or a tag's creation), a `push` unless its filters keep tags out, and
        `workflow_call`, which stands for a calling workflow's event, any event. GitHub runs a push workflow
        for a tag unless it names `branches` or `branches-ignore` and neither `tags` nor `tags-ignore` (path
        filters are not applied to tags). A filter written as anything but a mapping, or with its keys in
        another spelling, is read as letting tags through, the wider reading."""
        triggers = job.triggers()
        events = [event for event in ("release", "create") if event in triggers]
        if "push" in triggers and "push" in self.wf.triggers:
            config = self.wf.triggers.get("push")
            keys = {key for key in config if isinstance(key, str)} if isinstance(config, dict) else set()
            if keys & {"tags", "tags-ignore"} or not keys & {"branches", "branches-ignore"}:
                events.append("a tag push")
        if "workflow_call" in triggers:
            events.append("a call from another workflow")
        return events

    def _called_caches(self, job: Job, effects: CallEffects) -> None:
        """OBAAF-GHA-006 for a release job that calls workflows of the repository (flagship slice 2d.4b3b):
        the steps of the called jobs that may restore a cache, where neither their own cache-mode nor
        that of a calling job between forbids it, restore into what this job releases, and GitHub gives
        a called workflow no more cache access than the job that calls it. Nothing when this job's
        cache-mode forbids restoring, or when no called step restores."""
        mode = job.cache_mode
        if _forbids_restores(mode) or not effects.restoring:
            return
        workflows = list(dict.fromkeys(target.path for target in job.called))
        self.add("OBAAF-GHA-006", job.line,
                 "Release job '{job}' calls {workflows} and its cache-mode is {mode}, and steps there may restore "
                 "caches ({steps}). GitHub gives a called workflow no more cache access than the job that calls it, "
                 "so cache-mode: none here, or on each called job that restores, keeps a poisoned cache entry out "
                 "of what it releases.", job, kind="called-restores", controls=self._callers_cache_controls(),
                 workflows=self._workflows_fact(workflows),
                 steps=self._summary_fact(effects.restoring), mode=Fact(mode or "", mode or "not set"))

    @staticmethod
    def _workflows_fact(workflows: list) -> Fact:
        return Fact(workflows, ", ".join(one_line(w, 120) for w in workflows[:3])
                    + (f" and {len(workflows) - 3} more" if len(workflows) > 3 else ""))

    @staticmethod
    def _summary_fact(summary: CallSummary) -> Fact:
        """Entries a called workflow's jobs give, as one bounded fact (flagship slice 2d.4b3b): every entry
        when there are at most PASSED_NAMED and they fit in 1,000 characters; otherwise the first few that
        fit and a digest of all."""
        # Sorted, so that the order of the jobs, which changes nothing on GitHub, does not change the finding
        # (the third review); past CALL_EFFECTS_DISTINCT entries it still can, through which part was kept.
        entries = sorted(summary.entries)
        if (not summary.more and len(entries) <= PASSED_NAMED
                and sum(map(len, entries)) <= 1000):
            return Fact(entries, "; ".join(entries))
        named: list = []
        for entry in entries[:PASSED_SHOWN]:
            if sum(len(e) for e in named) + len(entry) > 1000:
                break
            named.append(entry)
        count = f"more than {summary.count}" if summary.more else str(summary.count)
        tail = (f"{count} in all" if summary.more else f"{summary.count - len(named)} more, {count} in all")
        shown = "; ".join([*named, f"{tail}, by digest sha256:{summary.digest}"])
        return Fact([*named, f"sha256:{summary.digest} ({count} entries)"], shown)

    def _callers_cache_controls(self, fix: str = "on this job") -> list:
        """For a job of a workflow that only jobs of this repository can be seen to call (its `on` names
        nothing but `workflow_call`), and every one of them forbids restoring caches, directly or through
        its own callers: a control that cannot be told, because a caller in another repository is not seen
        (flagship slice 2d.4b3b). GitHub gives a called workflow no more cache access than its caller, so
        for the callers the checker sees the job restores nothing. Nothing otherwise."""
        memo = self.__dict__.setdefault("_callers_cache", {})
        if "forbids" not in memo:
            memo["forbids"] = self._only_called_forbidding(self.wf, {}, 0)
        if not memo["forbids"]:
            return []
        names = sorted({f"{call.path} job '{call.job}'" for call in self.wf.callers})
        shown = ", ".join(one_line(n, 120) for n in names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
        return [Control(
            "Every job that calls it forbids restoring caches", CANNOT_TELL,
            f"every job of this repository that calls its workflow sets cache-mode: none or write-only, or is "
            f"called only by such jobs ({shown}), and GitHub gives a called workflow no more cache access than its "
            f"caller; a caller in another repository is not seen. Set cache-mode: none {fix} to clear it",
            "callers-cache-mode")]

    @staticmethod
    def _only_called_forbidding(workflow: Workflow, memo: dict, depth: int) -> bool:
        """Whether `workflow` can be started only by jobs of this repository that call it, each of which
        forbids restoring caches by its own cache-mode or is itself in such a workflow. A workflow some job
        calls by a repository's name (`owner/repo/<path>@ref`, which may be this repository) is not. A caller
        in a file the checker could not read is not seen (the check fails on that file's error anyway). A workflow reached again while it is being worked out (a cycle) is
        taken there as not forbidding, and so is one more than ten calls up; each answer is kept from the
        first time it is worked out, so a cycle can make the answer depend on where the walk began, in the
        direction of not forbidding."""
        key = id(workflow)
        if key in memo:
            return memo[key]
        memo[key] = False           # a cycle reached again is not
        found = (bool(workflow.callers) and not workflow.named_callers
                 and not set(workflow.triggers) - {"workflow_call"} and depth < 10)
        if found:
            for call in workflow.callers:
                caller = call.workflow.jobs.get(call.job) if call.workflow is not None else None
                if caller is None or not (_forbids_restores(caller.cache_mode) or
                                          WorkflowRules._only_called_forbidding(call.workflow, memo, depth + 1)):
                    found = False
                    break
        memo[key] = found
        return found

    # Flagship slice 2d.2e: which checks stop a step when they fail.
    _GITHUB_SHELLS = {"bash": (True, True), "sh": (True, False), "bash -e {0}": (True, False),
                      "bash --noprofile --norc -eo pipefail {0}": (True, True), "sh -e {0}": (True, False)}
    _NOT_A_CHECK = frozenset({"-h", "--help", "--version"})

    def _failfast_shell(self, job: Job, step: Step) -> tuple[bool, bool] | None:
        """(errexit, pipefail) for the shell a `run` step's script runs in, or None when it is not a
        POSIX shell the checker reads: PowerShell, cmd, Python, an expression, a login or interactive
        shell (it reads files an earlier step can write), an option it does not know, or the default
        shell of a runner it cannot show is Linux or macOS (on Windows the default is PowerShell)."""
        shell = step.raw.get("shell")
        for scope in (job.raw, self.wf.raw):
            if shell is not None:
                break
            defaults = scope.get("defaults")
            run = defaults.get("run") if isinstance(defaults, dict) else None
            shell = run.get("shell") if isinstance(run, dict) else None
        if shell is None:
            sets = job.runner_label_sets()
            if not sets:
                return None
            for labels in sets:
                names = [str(label).strip().lower() for label in labels]
                if any("windows" in name for name in names):
                    return None
                if not (all(is_hosted_label(name) for name in names)
                        or any(name in ("linux", "macos") for name in names)):
                    return None
            return (True, False)
        if not isinstance(shell, str) or "${{" in shell:
            return None
        text = " ".join(shell.split())
        if text in self._GITHUB_SHELLS:
            return self._GITHUB_SHELLS[text]
        words = text.split()
        if len(words) < 2 or words[-1] != "{0}" or words[0].rsplit("/", 1)[-1] not in ("bash", "sh"):
            return None
        errexit = pipefail = False
        options = words[1:-1]
        i = 0
        while i < len(options):
            word = options[i]
            if word in ("--noprofile", "--norc"):
                i += 1
                continue
            # Only options known to change nothing but errexit, pipefail, unset variables and tracing.
            if not re.fullmatch(r"-[euxo]+", word):
                return None
            on = word[0] == "-"
            if "e" in word[1:]:
                errexit = on
            if "o" in word[1:]:
                if i + 1 >= len(options) or options[i + 1] not in ("errexit", "pipefail", "nounset", "xtrace"):
                    return None
                if options[i + 1] == "errexit":
                    errexit = on
                elif options[i + 1] == "pipefail":
                    pipefail = on
                i += 1
            i += 1
        return (errexit, pipefail)

    @staticmethod
    def _step_runs_on_success(step: Step) -> bool:
        """Whether a step runs exactly when the steps before it succeeded, and fails the job when it
        fails: no `continue-on-error` that may be true, and no `if:` other than `success()` or `true`."""
        coe = step.raw.get("continue-on-error")
        if coe not in (None, False) and "".join(as_text(coe).split()).lower() not in ("false", "${{false}}"):
            return False
        cond = "".join(as_text(step.raw.get("if", "")).split()).lower()
        return cond in ("", "success()", "${{success()}}", "true", "${{true}}")

    def _binding_matches(self, job: Job, step: Step, patterns: list[str]) -> list[list[str]]:
        """The commands of a `run` step that match one of `patterns` at their start and whose failure
        stops the job (flagship slice 2d.2e): the step runs on success only, its shell stops on a failing
        command, `BASH_ENV` is not set, and the command is one `binding_commands` counts. A command given
        `--help` or `--version` is not a check. Before 2d.2e the step's text was searched for the pattern,
        so a comment, an `echo`, an `if` condition or an `&&` list counted."""
        if step.uses or not step.run or not self._step_runs_on_success(step):
            return []
        shell = self._failfast_shell(job, step)
        if shell is None or self._bash_env(job, step):
            return []
        commands, _complete = binding_commands(_expressions_for_shell(step.run), *shell)
        out = []
        for words in commands:
            joined = " ".join(words)
            if any(re.match(p, joined) for p in patterns) and not self._NOT_A_CHECK & set(words):
                out.append(words)
        return out

    def _bash_env(self, job: Job, step: Step) -> bool:
        """Whether the shell's start or what a name runs may have been changed for the step: `BASH_ENV` in
        its own, the job's or the workflow's `env`, an `env` written as one expression (it may set
        anything), or an earlier step of the job whose script names `BASH_ENV`, `BASH_FUNC` or
        `GITHUB_PATH` (it can write them for the steps after it). What an action used earlier does is not
        read."""
        for scope in (step.raw, job.raw, self.wf.raw):
            env = scope.get("env") if isinstance(scope, dict) else None
            if isinstance(env, str):
                return True
            # Flagship slice 2d.13: every name that changes what the step's shell or the check's program
            # runs (`steers`), where only `BASH_ENV`, `ENV` and `BASH_FUNC...` counted, and a name written
            # as an expression, which may be any of them.
            if isinstance(env, dict) and any(steers(key) or expr_mod.OPEN in str(key) for key in env):
                return True
        # A container job's steps run with the container's `env` and its `options` (`-e NAME=...`); the
        # runner takes the PATH from the container too (the third review of slice 2d.13). What its image
        # holds, the `obaaf` it ships included, is not read.
        container = job.raw.get("container")
        if isinstance(container, dict):
            env = container.get("env")
            if (env is not None and not isinstance(env, dict)) or (isinstance(env, dict) and any(
                    steers(key) or expr_mod.OPEN in str(key) for key in env)):
                return True
            options = container.get("options")
            if options is not None and (not isinstance(options, str) or self._CONTAINER_ENV_RE.search(options)):
                return True
        return self._first_shell_change(job) < step.index

    # In a container's `options`: an environment variable given to it, by name or from a file.
    # Short options may be joined (`-ite NAME`) and a value written beside them (`-eNAME=...`).
    _CONTAINER_ENV_RE = re.compile(r"(?<![\w-])(-[A-Za-z]*e|--env)", re.I)

    def _first_shell_change(self, job: Job) -> int:
        """Where the first step of `job` that may change, for the steps after it, what their shell or the
        programs they name run is (`_changes_later_steps`), or the number of its steps when none may,
        worked out once per job: each check of each upload read every earlier step again, which took a
        job of 1,000 steps (as slice 2d.4b2's reading of local actions can give one) a minute and a half."""
        memo = self.__dict__.setdefault("_shell_changes", {})
        found = memo.get(id(job))
        if found is None or found[0] is not job:
            first = 0 if job.steps and self._job_sets_later_steps(job) else len(job.steps)
            for position, earlier in enumerate(job.steps[:first]):
                if self._changes_later_steps(job, earlier):
                    first = position
                    break
            found = memo[id(job)] = (job, first)
        return found[1]

    # What a step's text may use to set variables or the PATH for the steps after it, other than a write
    # to a file command `_github_env_names` reads: bash's own names, the toolkit's calls (github-script and
    # JavaScript actions), the workflow commands a runner obeys when `ACTIONS_ALLOW_UNSECURE_COMMANDS` is
    # true, and the runner's folder that holds the file commands' files. Any letter case.
    _SETS_LATER_STEPS_RE = re.compile(r"BASH_ENV|BASH_FUNC|GITHUB_PATH|addPath|add-path|set-env|exportVariable|"
                                      r"_runner_file_commands|ACTIONS_ALLOW_UNSECURE_COMMANDS", re.I)
    # The runner's own contexts for its files (`github.env`, `github.path` and the others), or the whole
    # `github` context, which holds them and can be written out as text.
    _FILE_CONTEXTS = ({"github"}, {"env", "path", "output", "state", "step_summary"})

    def _sets_later_steps_text(self, text: str) -> bool:
        """Whether text that is not a bash script the checker reads names a way to set variables or the PATH
        for later steps: one of `_SETS_LATER_STEPS_RE`, a file command's variable, `${!GITHUB_E*}`, or an
        expression that reaches the runner's contexts for its files."""
        squeezed = _squeeze(text)
        if self._SETS_LATER_STEPS_RE.search(squeezed) or _NAMES_FILE_VAR.search(squeezed) \
                or _lists_file_vars(squeezed):
            return True
        try:
            return any(expr_mod.reaches(ref.path, self._FILE_CONTEXTS, ref.extracted)
                       for body in expr_mod.bodies(text) for ref in expr_mod.refs(body))
        except expr_mod.TooComplex:
            return True

    _VALUES_READ = 20_000

    @classmethod
    def _values_text(cls, value) -> str:
        """The keys, strings and other values in a value of lists and mappings, as plain text, each node once
        (a YAML alias can make one hold itself): a line break stays a line break, which `str()` of a mapping
        writes as two characters (the second review of slice 2d.13). More than `_VALUES_READ` of them
        give text that names GITHUB_ENV, so the reading fails closed."""
        out: list = []
        stack, seen = [value], set()
        while stack:
            if len(out) > cls._VALUES_READ:
                return "GITHUB_ENV (more values than the checker reads)"
            node = stack.pop()
            if isinstance(node, (list, dict)):
                if id(node) in seen:
                    continue
                seen.add(id(node))
                if isinstance(node, dict):
                    for key, item in node.items():
                        out.append(str(key))
                        stack.append(item)
                else:
                    stack.extend(node)
            elif node is not None:
                out.append(str(node))
        return "\n".join(out)

    def _job_sets_later_steps(self, job: Job) -> bool:
        """Whether the workflow's or the job's `env`, `defaults` or the job's `strategy` hold such text: a
        step can run it (`eval "$CMD"`, `${{ env.CMD }}`, `${{ matrix.cmd }}`, a default `shell`), so every
        step of the job may set variables for the steps after it (the second review of slice 2d.13)."""
        parts = [self.wf.raw.get("env"), self.wf.raw.get("defaults"), job.raw.get("env"), job.raw.get("defaults"),
                 job.raw.get("strategy")]
        return self._sets_later_steps_text(self._values_text(parts))

    def _changes_later_steps(self, job: Job, step: Step) -> bool:
        """Whether a step's text may change, for the steps after it in the job, what their shell or the
        programs they name run (flagship slices 2d.2e and 2d.13). Before 2d.13 only `BASH_ENV`,
        `BASH_FUNC` and `GITHUB_PATH` were looked for, so a step that wrote `PATH=...` (or
        `SHELLOPTS=noexec`, with which bash reads a step's script and runs none of it) to GITHUB_ENV
        left a later check counted. The runner gives every later step of the job what a step writes to
        that file, and refuses only `NODE_OPTIONS` (actions/runner v2.338.2, `SetEnvFileCommand` in
        src/Runner.Worker/FileCommandManager.cs).

        A bash or sh `run` script is read by `_github_env_names`: True when it cannot read the script's
        writes to the runner's files or a name written to GITHUB_ENV `steers`. Everything else about the
        step (its `shell`, `env` and inputs, and the whole of a step that is not such a script, as code
        in another language or an action) is text the checker does not read as bash: True when
        `_sets_later_steps_text` finds a way to set variables for later steps in it, a file command's
        variable included. Only the workflow's text is read: a name or a path a script puts together
        otherwise, and what a program or an action the step runs writes, are not."""
        shell = step.raw.get("shell")
        beside = self._values_text([step.raw.get("env"), step.raw.get("with"), shell])
        bash = isinstance(step.raw.get("run"), str) and bool(step.run) and not step.uses \
            and self._step_shell(job, step) in ("bash", "sh")
        if not bash:
            return self._sets_later_steps_text(step.scripts() + "\n" + beside)
        if self._sets_later_steps_text(beside):
            return True
        squeezed = _squeeze(step.run)
        if self._SETS_LATER_STEPS_RE.search(squeezed):
            return True
        try:
            if any(expr_mod.reaches(ref.path, self._FILE_CONTEXTS, ref.extracted)
                   for body in expr_mod.bodies(step.run) for ref in expr_mod.refs(body)):
                return True
        except expr_mod.TooComplex:
            return True
        if not _NAMES_FILE_VAR.search(squeezed) and not _lists_file_vars(squeezed):
            return False
        names = _github_env_names(step.run)
        return names is None or any(steers(name) for name in names)

    def _verify_kind(self, job: Job, step: Step) -> str | None:
        """'full' for a release verification that stops the job on failure, 'provenance' for a
        provenance-only one (`gh attestation verify`, or `obaaf verify release --pre-approval`, which
        skips the approvals), None otherwise (including checks whose failure is ignored). Worked out once
        for each step (flagship slice 2d.4b2)."""
        memo = self.__dict__.setdefault("_verify_kinds", {})
        found = memo.get((id(job), id(step)))
        if found is None or found[0] is not step:
            found = memo[(id(job), id(step))] = (step, self._verify_kind_of(job, step))
        return found[1]

    def _verify_kind_of(self, job: Job, step: Step) -> str | None:
        kind = None
        for words in self._binding_matches(job, step, self.detection.get("verify_commands", [])):
            joined = " ".join(words)
            if any(re.match(p, joined) for p in self.detection.get("release_verify_commands", [])) \
                    and "--pre-approval" not in words:
                return "full"
            kind = "provenance"
        return kind

    def _upload_checks(self, job: Job, uploads: list[Step]) -> list[tuple[Step, str | None]]:
        """Each upload step with the strongest check that stops it: 'full', 'provenance' or None. A
        check counts for an upload when it is an earlier step of the job that does not run beside it and
        the upload does not run after a failure, or when it is in a job this one needs (flagship slice
        2d.2e: every upload, where before only the first was looked at)."""
        gate = self._needs_gate(job, lambda dep: {self._verify_kind(dep, s) for s in dep.steps})
        out = []
        for up in uploads:
            kinds = set(gate)
            if not _bypasses_failure(up.raw):
                kinds |= {self._verify_kind(job, s) for s in job.steps[: up.index]
                          if not (s.group is None and s.background) and not (s.group and s.group == up.group)}
            kinds.discard(None)
            out.append((up, "full" if "full" in kinds else "provenance" if kinds else None))
        return out

    def _unvouched_checks(self, job: Job, upload: Step) -> list[str]:
        """Earlier steps of the job, and steps of the jobs it needs, whose script names a release check that
        `_binding_matches` could not vouch for (flagship slice 2d.2e): the finding then says the checker
        cannot tell, not that there is no check."""
        patterns = [re.compile(p) for p in self.detection.get("verify_commands", [])]
        steps = [(job, s) for s in job.steps[: upload.index]]
        for name in self._needed_jobs(job):
            steps += [(self.wf.jobs[name], s) for s in self.wf.jobs[name].steps]
        return [f"{j.id}: {s.name}" for j, s in steps
                if s.text() and any(p.search(s.text()) for p in patterns) and self._verify_kind(j, s) is None]

    def _needed_jobs(self, job: Job) -> list[str]:
        out, todo = [], list(job.needs)
        while todo:
            name = todo.pop(0)
            if name in out or name not in self.wf.jobs or name == job.id:
                continue
            out.append(name)
            todo += self.wf.jobs[name].needs
        return out

    def _environment_state(self, job: Job) -> str:
        """Whether a job's environment is established (flagship slice 2d.2e): 'set' for a name written
        as text, or an expression whose every value the checker can list and none blank; 'none' when it
        has none; 'blank' for a name that is only space; 'open' for an expression that may be blank or
        name something the checker cannot list; 'unreadable' for a number, true or false, a list or a
        mapping. Whether the environment named has required reviewers is not read here (`obaaf audit`
        reads it)."""
        kind, _written = job.environment_reading
        raw = job.raw.get("environment")
        named = raw.get("name") if isinstance(raw, dict) else raw
        if kind == "none":
            return "blank" if isinstance(named, str) and named and not named.strip() else "none"
        if kind == "literal":
            return "set"
        if kind == "expression":
            names, complete = job.environment_candidates()
            return "set" if complete and names and all(n.strip() for n in names) else "open"
        return "unreadable"

    def _jobs_feeding(self, job: Job) -> list[str]:
        """The jobs a release job needs, followed transitively, that restore a cache while their
        cache-mode does not forbid it, when the release job downloads artifacts: what they built can
        carry a poisoned cache entry into the release (Clinejection). Outputs are not followed."""
        # Flagship slice 2d.4b3b: a job that calls workflows of the repository downloads what a called job
        # downloads: a called release job's, for a job the call makes a release job, and any called job's, for
        # one declared a release job, whose call is the release it declares. A needed job that calls a workflow
        # restores what the jobs it calls restore.
        if not self._downloads_artifacts(job):
            return []
        out, seen, todo = [], {job.id}, list(job.needs)
        while todo:
            name = todo.pop(0)
            if name in seen or name not in self.wf.jobs:
                continue
            seen.add(name)
            dep = self.wf.jobs[name]
            # Any called job's restores, release job or not, as for a needed job written in the workflow
            # (the third review found a called release job's left out).
            through = dep.call_effects is not None and dep.called and dep.call_effects.restores_any
            if dep.cache_mode not in ("none", "write-only") and (
                    through or any(self._restores_cache(s) for s in dep.steps)):
                out.append(name)
            todo += dep.needs
        return sorted(out)

    @staticmethod
    def _downloads_artifacts(job: Job) -> bool:
        """Whether a job downloads the run's artifacts: a step that uses `actions/download-artifact`, or, for a
        job that calls workflows of the repository, a called job that does (`_jobs_feeding`)."""
        effects = job.call_effects if job.called else None
        called = effects is not None and (effects.downloads if effects.lane_given else effects.downloads_any)
        return called or any(s.uses_action("actions/download-artifact") for s in job.steps)

    @staticmethod
    def _cache_step(step: Step) -> str:
        """A cache step as one of OBAAF-GHA-006's facts: its written name or id and what restores."""
        name = as_text(step.raw.get("name") or step.raw.get("id") or "")
        what = step.action or (step.uses or "").split("@", 1)[0] or "run"
        return f"{name} ({what})" if name else what

    def _needs_gate(self, job: Job, found, seen: set | None = None) -> set:
        """What `found(dep)` returns for the jobs this one needs, followed transitively, stopping at a
        job whose `if:` lets it run after a failure (it would run even if the gate failed). A needed job
        with a `continue-on-error` that may be true is no gate itself (its failure does not stop the jobs
        that need it), but the jobs it needs still are (flagship slice 2d.2e)."""
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
            if not _continues_on_error(dep.raw):
                out |= set(found(dep))
            out |= self._needs_gate(dep, found, seen)
        return out

    @staticmethod
    def _restores_cache(step: Step) -> bool:
        """Whether a step may restore a GitHub Actions cache. An input written as an expression is read
        as the value that restores, and so are inputs written as one expression (flagship slice 2d.2e).
        A local action is not read (slice 2d.4) and is taken to restore. A `docker://` step is not
        counted."""
        w = step.with_

        def expr(key: str) -> bool:
            return "${{" in as_text(w.get(key, ""))

        def on(key: str, default: str) -> bool:
            return expr(key) or _truthy(w.get(key, default))

        def not_off(key: str, default: str) -> bool:
            return expr(key) or not _falsy(w.get(key, default))

        if isinstance(step.raw.get("with"), str):
            return bool(step.action)
        if (step.uses or "").startswith("./"):
            return True
        if step.uses_action("actions/cache/save"):
            return False
        if step.uses_action("actions/cache") or step.uses_action("actions/cache/restore"):
            return not (_truthy(w.get("lookup-only", "false")) and not expr("lookup-only"))
        if step.uses_action("actions/setup-node"):
            return bool(w.get("cache")) or not_off("package-manager-cache", "true")
        if step.uses_action("actions/setup-go"):
            return not_off("cache", "true")
        if step.uses_action("actions/setup-python") or step.uses_action("actions/setup-java"):
            return bool(w.get("cache"))
        if step.uses_action("actions/setup-dotnet"):
            return on("cache", "false")
        if step.uses_action("gradle/actions/setup-gradle") or step.uses_action("gradle/gradle-build-action"):
            return expr("cache-disabled") or expr("cache-write-only") or not (
                _truthy(w.get("cache-disabled", "false")) or _truthy(w.get("cache-write-only", "false")))
        if any(step.uses_action(a) for a in _ALWAYS_CACHES):
            return True
        if step.uses_action("actions-rust-lang/setup-rust-toolchain") or step.uses_action("jdx/mise-action") \
                or step.uses_action("mlugg/setup-zig"):
            return not_off("cache", "true")
        if step.uses_action("oven-sh/setup-bun"):
            return expr("no-cache") or not _truthy(w.get("no-cache", "false"))
        if step.uses_action("pnpm/action-setup"):
            return on("cache", "false")
        if step.uses_action("ruby/setup-ruby"):
            return on("bundler-cache", "false")
        if step.uses_action("astral-sh/setup-uv"):
            return not_off("enable-cache", "auto")
        if step.uses_action("docker/build-push-action") or step.uses_action("docker/bake-action"):
            given = (as_text(w.get("cache-from", "")) + as_text(w.get("set", ""))).replace(" ", "")
            return "type=gha" in given or "${{" in given
        if step.uses_action("actions/github-script"):
            return bool(re.search(r"@actions/cache|restoreCache", as_text(w.get("script", ""))))
        return bool(step.run and re.search(r"type\s*=\s*gha\b", step.run))

    # -------------------------------------------------------------- GHA-007
    _CACHE_MODES = ("none", "read", "write", "write-only")

    def cache_write_low_trust(self, job: Job) -> None:
        """A job outsiders can start that declares a cache-mode that can write. The value is read the
        widest way (flagship slice 2d.2e): a value that is not exactly one of the four GitHub documents
        (another case, an expression, a number, a block scalar) may write, a null at the job does not hide
        the workflow's value, and a key written in another spelling is read as the key."""
        privileged = job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS
        if not privileged:
            return
        found = None
        for scope in (job.raw, self.wf.raw):
            exact = scope.get("cache-mode") if isinstance(scope, dict) else None
            variants = [k for k in scope if isinstance(k, str) and k != "cache-mode"
                        and k.strip().lower() == "cache-mode"] if isinstance(scope, dict) else []
            if variants:
                found = (scope, variants[0], scope.get(variants[0]), "unreadable")
                break
            if exact is not None:
                text = as_text(exact) if isinstance(exact, str) else None
                if text in ("write", "write-only"):
                    found = (scope, "cache-mode", text, "")
                elif text not in ("none", "read"):
                    found = (scope, "cache-mode", exact, "unreadable")
                break
        if found is None:
            return
        scope, key, value, kind = found
        line = scope.line_of(key) if hasattr(scope, "line_of") else job.line
        if kind:
            self.add("OBAAF-GHA-007", line,
                     "Job '{job}' can be started by {triggers} and declares a cache-mode the checker cannot read "
                     "({mode}); GitHub documents none, read, write and write-only, and a value that can write "
                     "lets an outsider's run write the default branch's cache.", job, kind=kind,
                     triggers=sorted(privileged), mode=Fact(value_identity(value), shown_value(f"{key}: {as_text(value)}")))
        else:
            self.add("OBAAF-GHA-007", line,
                     "Job '{job}' can be started by {triggers} and declares "
                     "cache-mode: {mode}.", job, triggers=sorted(privileged), mode=value)

    # -------------------------------------------------------------- GHA-008
    # Where a job's images are written: the container, and each service. Read by one function, so a form
    # the checker does not know is "cannot tell" rather than nothing (flagship slice 2d.2f).
    _IMAGE_KEYS = ("container", "services", "image", "uses")

    def unpinned(self, job: Job) -> None:
        permissions = job.permissions
        # A called workflow's triggers are its callers', which this file does not show: its job is taken
        # to be startable by anything, so it is never low (flagship slice 2d.2f; a caller on
        # pull_request_target made the called job low before).
        privileged = (not permissions or not permissions.declared or permissions.write_scopes()
                      or permissions.oidc or job.secret_names()
                      or job.triggers() & PRIVILEGED_UNTRUSTED_TRIGGERS or self.wf.callable)
        severity = ("high" if any(job.in_lane(lane) for lane in ("release", "agent", "effect")) else
                    "medium" if privileged else "low")
        refs = [(s, s.uses, s.line) for s in job.steps if s.uses is not None]
        if job.reusable is not None and isinstance(job.raw.get("uses"), str):
            refs.append((None, job.reusable, job.line))
        for step, uses, line in refs:
            what = "Reusable workflow" if step is None else "Action"
            if is_local_reference(uses):
                if step is not None and uses.startswith("./"):
                    self._local_from_elsewhere(job, step, severity)
                continue
            if uses.lower().startswith("docker://"):
                if not IMAGE_DIGEST_RE.search(uses):
                    self.add("OBAAF-GHA-008", line, "Container '{uses}' is not pinned to a sha256 digest.", job,
                             step, severity, kind="container", uses=uses)
                continue
            ref = uses.split("@", 1)[1] if "@" in uses else ""
            if not COMMIT_SHA_RE.fullmatch(ref):
                self.add("OBAAF-GHA-008", line,
                         what + " '{uses}' is pinned to '{ref}', not a full commit SHA.", job, step,
                         severity, kind="reusable-workflow" if step is None else "action", uses=uses,
                         ref=Fact(ref, ref or 'nothing'))
        for where, image, line in self._images(job):
            if image is None:
                self.add("OBAAF-GHA-008", line,
                         "Job '{job}' gives {where} an image the checker cannot read, so it cannot tell whether it "
                         "is pinned to a sha256 digest.", job, severity=severity, kind="image-unreadable",
                         where=where)
                continue
            for value in self._image_values(job, image):
                if value is not None and not value.strip():
                    continue    # an empty image is no container (a matrix row run on the runner itself)
                if value is None:
                    self.add("OBAAF-GHA-008", line,
                             "Image '{image}' of {where} is computed when the job runs, so the checker cannot tell "
                             "whether it is pinned to a sha256 digest.", job, severity=severity,
                             kind="image-expression", image=image, where=where)
                elif not IMAGE_DIGEST_RE.search(value):
                    self.add("OBAAF-GHA-008", line, "Image '{image}' is not pinned to a sha256 digest.", job,
                             severity=severity, kind="image", image=value)

    def _images(self, job: Job) -> list:
        """(where, image, line) for the job's container and every service: the image as text, or None
        when it is written in a form the checker does not read (not text, a mapping without `image`, a
        key in another letter case, services not written as a mapping). GitHub may refuse some of these
        forms; which, is not established, and none is taken for no image."""
        out: list = []
        raw = job.raw
        for key in raw:
            if isinstance(key, str) and key != key.lower() and key.lower() in ("container", "services"):
                out.append((f"'{one_line(key, 40)}'", None, raw.line_of(key) if hasattr(raw, "line_of") else job.line))

        def one(where: str, value, line: int) -> None:
            if value is None:
                return
            if isinstance(value, str):
                out.append((where, value, line))
                return
            if isinstance(value, dict):
                odd = [k for k in value if isinstance(k, str) and k != "image" and k.lower() == "image"]
                image = value.get("image")
                if odd or not isinstance(image, str):
                    out.append((where, None, line))
                else:
                    out.append((where, image, line))
                return
            out.append((where, None, line))

        one("its container", raw.get("container"), job.line)
        services = raw.get("services")
        if isinstance(services, dict):
            for name, service in services.items():
                one(f"service '{one_line(as_text(name), 60)}'", service, job.line)
        elif services is not None:
            out.append(("its services", None, job.line))
        return out

    def _image_values(self, job: Job, image: str) -> list:
        """The images a value names: itself when it has no expression; each value of a matrix written out
        in the file when it is exactly `${{ matrix.x }}`; otherwise [None], computed when the job runs."""
        if "${{" not in image:
            return [image]
        text = image.strip()
        bodies = expr_mod.bodies(text)
        if (len(bodies) == 1 and text.startswith(expr_mod.OPEN) and text.endswith("}}")
                and len(expr_mod.OPEN) + len(bodies[0]) + 2 == len(text)):
            toks = expr_mod.tokens(bodies[0])
            if len(toks) == 3 and toks[0] == ("id", "matrix") and toks[1] == ("op", ".") and toks[2][0] == "id":
                values = job._matrix_values(toks[2][1])
                if values:
                    return list(dict.fromkeys(values))
        return [None]

    def _local_from_elsewhere(self, job: Job, step: Step, severity: str) -> None:
        """A `./` action is the files at that path in the workspace when the step runs. Where an earlier
        step put code from outside the run's own commit there, the action is that code, which can move
        (flagship slice 2d.2f): a checkout with `repository:` whose `path` holds the action's path, at a ref
        that is not a full commit SHA (`local-from-checkout`); an artifact downloaded from another run or
        repository, or a cache restored, over that path; or a script line that clones or downloads
        (`git clone`, `gh repo clone`, `git worktree add`, `git submodule add`, `curl`, `wget`,
        `gh release download`, `gh run download`, `degit`, `tar x`, `unzip`, `bsdtar`, `7z`) and names
        the action's top directory (`local-after-download`). Paths are compared after `.` and `..` are
        resolved; an absolute path, or one written with an expression or a variable, is taken to hold
        the action."""
        target = self._workspace_path(step.uses[2:])
        if target is None:
            return
        top = target.split("/", 1)[0]
        for earlier in reversed(job.steps[:step.index]):
            if earlier.uses_action("actions/checkout"):
                given = earlier.with_
                if not self._covers(given.get("path", ""), target):
                    continue
                repository = given.get("repository")
                repo_text = as_text(repository).strip() if repository is not None else ""
                if not repo_text or re.fullmatch(r"\$\{\{\s*github\.repository\s*\}\}", repo_text, re.I):
                    return      # the workflow's own repository: what a `./` action normally is
                ref = given.get("ref")
                ref_text = as_text(ref).strip() if ref is not None else ""
                if COMMIT_SHA_RE.fullmatch(ref_text):
                    return
                self.add("OBAAF-GHA-008", step.line,
                         "Action '{uses}' is taken from {repository}, which step '{checkout}' checks out at "
                         "{ref}, not a full commit SHA.", job, step, severity, kind="local-from-checkout",
                         uses=step.uses, repository=Fact(repo_text, f"'{one_line(repo_text, 80)}'"),
                         checkout=Fact(earlier.name, one_line(earlier.name, 80)),
                         ref=Fact(ref_text, f"'{one_line(ref_text, 60)}'" if ref_text else "its default branch"))
                return
            if self._fetches_over(earlier, target, top):
                self.add("OBAAF-GHA-008", step.line,
                         "Action '{uses}' runs from the workspace after step '{clone}' puts code from outside this "
                         "run's commit there, so the checker cannot tell which repository and commit the action "
                         "comes from.", job, step, severity, kind="local-after-download", uses=step.uses,
                         clone=Fact(earlier.name, one_line(earlier.name, 80)))
                return

    # A download that can bring another run's or repository's files: actions/download-artifact given a run,
    # a repository or a token, and any other repository's download-artifact action.
    _CROSS_RUN_INPUTS = ("run-id", "repository", "github-token")
    # Words that clone, download or unpack code on a script line (`_fetches_over`), as whole words.
    _FETCH_WORDS = frozenset({"curl", "wget", "degit", "unzip", "bsdtar", "7z", "unrar"})

    def _fetches_over(self, earlier: Step, target: str, top: str) -> bool:
        if earlier.uses_action("actions/cache") or earlier.uses_action("actions/cache/restore"):
            paths = as_text(earlier.with_.get("path", "") or "")
            return any(self._covers(line, target, literal_only=True) for line in paths.splitlines() if line.strip())
        action = (earlier.action or "").lower()
        if action.endswith("download-artifact") or "/download-artifact" in action:
            given = earlier.with_
            if action == "actions/download-artifact" and not any(given.get(k) for k in self._CROSS_RUN_INPUTS):
                return False    # this run's own artifact
            return self._covers(given.get("path", ""), target)
        if not top:
            return False        # `uses: ./`: a download's target is not read for the workspace root (stated)
        for line in earlier.scripts().splitlines():
            if top not in line:
                continue        # cheap test first: the line must name the action's top directory
            for command in _COMMAND_SPLIT_RE.split(line):
                if top in command and self._fetches_into(command, top):
                    return True
        return False

    # Options of `git clone` that take the next word as their value.
    _CLONE_VALUE_OPTIONS = frozenset({"--depth", "-b", "--branch", "-o", "--origin", "--reference",
                                      "--reference-if-able", "-c", "--config", "--filter", "-j", "--jobs",
                                      "--separate-git-dir", "--template", "-u", "--upload-pack", "--shallow-since",
                                      "--shallow-exclude", "--server-option", "--bundle-uri", "--revision"})

    def _fetches_into(self, command: str, top: str) -> bool:
        """Whether one command (no `;`, `&&`, `|` in it) clones or downloads into a workspace path at or
        under `top`, or clones a repository named `top` with no folder given."""
        words = [w for w in re.split(r"[\s()`'\"]+", command) if w]
        fetches = bool(self._FETCH_WORDS & set(words))
        clone_into = None
        for n, word in enumerate(words[:-1]):
            nxt = words[n + 1]
            if word == "git" and "clone" in words[n + 1:n + 4]:
                fetches = True
                rest, k = [], words.index("clone", n) + 1
                while k < len(words):
                    if words[k] in self._CLONE_VALUE_OPTIONS:
                        k += 2
                    elif words[k].startswith("-"):
                        k += 1
                    else:
                        rest.append(words[k])
                        k += 1
                if len(rest) == 1:      # no folder named: git makes one from the repository's name
                    clone_into = rest[0].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
                break
            if word == "gh" and words[n + 1:n + 3] == ["repo", "clone"]:
                fetches = True
                rest = []
                for w in words[n + 3:]:
                    if w == "--":
                        break
                    if not w.startswith("-"):
                        rest.append(w)
                if len(rest) == 1:
                    clone_into = rest[0].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
                break
            if (word == "git" and any(w in ("worktree", "submodule") for w in words[n + 1:n + 4])) \
                    or (word == "gh" and nxt in ("repo", "release", "run")
                        and any(w in ("download", "clone") for w in words[n + 1:n + 4])) \
                    or (word == "tar" and re.fullmatch(r"-?[A-Za-z]*x[A-Za-z]*|--extract|--get", nxt)):
                fetches = True
                break
        if not fetches:
            return False
        if clone_into == top:
            return True
        for word in words:
            # A path in the workspace, written as a word or as an option's value (`--output=x`); not a
            # URL, an absolute path, a home path or one built from a variable.
            value = word.split("=", 1)[1] if word.startswith("-") and "=" in word else word
            if "://" in value or value.startswith(("/", "~", "$", "-")):
                continue
            path = self._workspace_path(value)
            if path is not None and (path == top or path.startswith(top + "/")):
                return True
        return False

    def _covers(self, path, target: str, literal_only: bool = False) -> bool:
        """Whether files put at `path` (as a step's input gives it) can be the action at `target`: the
        workspace root, the target or a folder above it, after `.` and `..` are resolved. An absolute
        path, `~`, or one with an expression or a variable is taken to hold the action, unless
        `literal_only` (a cache's paths), where it is taken not to (a cache path is usually outside the
        workspace, `~/.cargo`)."""
        text = as_text(path).strip() if path is not None else ""
        for prefix in ("${{ github.workspace }}/", "$GITHUB_WORKSPACE/", "${GITHUB_WORKSPACE}/"):
            if text.startswith(prefix):
                text = text[len(prefix):]
        if text.startswith(("/", "~")) or "${{" in text or "$" in text or "*" in text:
            return not literal_only
        root = self._workspace_path(text)
        if root is None:
            return False        # outside the workspace
        return root == "" or target == root or target.startswith(root + "/")

    @staticmethod
    def _workspace_path(text: str) -> str | None:
        """A path in the workspace as written in a step, with `.` and `..` resolved and no slashes at its
        ends; None when it points outside the workspace."""
        parts: list[str] = []
        for part in str(text).replace("\\", "/").split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if not parts:
                    return None
                parts.pop()
            else:
                parts.append(part)
        return "/".join(parts)

    # -------------------------------------------------------------- GHA-011
    def persisted_credentials(self, job: Job) -> None:
        outside = sorted(job.triggers() & UNTRUSTED_TRIGGERS)
        agent = job.in_lane("agent")
        if not (agent or outside or job.in_lane("untrusted")):
            return
        perms = job.permissions
        if perms is None:
            scopes = Fact(["undeclared"], "its permissions are not declared")
        elif perms.write_scopes():
            scopes = Fact(perms.write_scopes(), "it can write " + ", ".join(perms.write_scopes()))
        else:
            scopes = Fact([], "it can only read")
        exposure = " and ".join(part for part in (
            "runs an agent" if agent else "",
            f"can be started by {', '.join(outside)}" if outside else "",
            "builds pull requests" if not agent and not outside else "") if part)
        for step in job.steps:
            if step.uses_action("actions/checkout") and self._keeps_token(step):
                token, key = step.with_.get("token"), step.with_.get("ssh-key")
                if key not in (None, ""):
                    credential = Fact(f"ssh-key: {value_identity(key)}",
                                      f"the SSH key given in its ssh-key input ({shown_value(key)})")
                    given = Fact(scopes.value, "")
                elif token not in (None, ""):
                    credential = Fact(f"token: {value_identity(token)}",
                                      f"the token given in its token input ({shown_value(token)})")
                    given = Fact(scopes.value, "")
                else:
                    credential = Fact("job token", "the job token")
                    given = Fact(scopes.value, f" ({scopes.shown})")
                self.add("OBAAF-GHA-011", step.line,
                         "Step '{step}' persists {credential} for later steps{scopes}, in a job that {exposure}.",
                         job, step, credential=credential, scopes=given, agent=agent, triggers=outside,
                         exposure=Note(exposure), legacy="Step '{step}' persists the job token for later steps.")

    @staticmethod
    def _keeps_token(step: Step) -> bool:
        """Whether an actions/checkout step keeps the job token. actions/checkout keeps it only when the
        input, trimmed, is `true` in any case (`(getInput('persist-credentials') || 'false').toUpperCase()
        === 'TRUE'`, read in its v3.5.0 source; later versions not read), and its default is `true`. So
        a written value other than that keeps nothing; no value, an empty one and an expression the
        checker cannot evaluate are taken to keep it."""
        if "persist-credentials" not in step.with_:
            return True
        given = _constant(step.with_.get("persist-credentials"))
        if not isinstance(given, (str, bool, int, float)) or isinstance(given, str) and "${{" in given:
            return True
        text = as_text(given).strip()
        return not text or text.upper() == "TRUE"

    @staticmethod
    def _merge_commit(step: Step, ref: PrCode, repository: PrCode) -> bool:
        """Whether a checkout step takes the merge commit of the pull request the event is about: no
        `ref`, or one that is only `github.sha`, `github.ref` or `github.ref_name`, of this repository."""
        written = as_text(step.with_.get("ref") or "").strip()
        own = {"github.repository", "github.event.repository.full_name"}
        if as_text(step.with_.get("repository") or "").strip() and not (
                repository.state == "base" and repository.reads and set(repository.reads) <= own):
            return False
        if not written:
            return True
        return ref.state == "base" and bool(ref.reads) and set(ref.reads) <= MERGE_COMMIT_REFS

    # -------------------------------------------------------------- GHA-013
    def self_hosted(self, job: Job) -> None:
        if job.reusable:
            # A job that calls a reusable workflow has no runner of its own: the called workflow's
            # jobs choose theirs, in their own file (flagship slice 2d.2d; it was "runs on no labels").
            return
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
            # The labels as written and, where a matrix gives them, every set they resolve to, so that an
            # acceptance written for one pool does not cover another (flagship slice 2d.2d).
            sets = job.runner_label_sets()
            written = list(job.runs_on) if sets is None or sets == [list(job.runs_on)] else \
                list(job.runs_on) + ["resolved: " + " | ".join(", ".join(s) for s in sets)]
            labels = Fact(written, ", ".join(job.runs_on) or "no labels")
            if kind == "self-hosted":
                self.add("OBAAF-GHA-013", job.line,
                         "Job '{job}' runs on a self-hosted runner ({labels}) and " + why + ".",
                         job, kind="self-hosted" + case, labels=labels, **values)
            else:
                # A selector that sends a fork's pull request to a hosted runner is informational only
                # where every outside event that starts the job carries the pull request it tests,
                # and the job runs no agent, which the selector would put on the other runner for a
                # branch of this repository (flagship slice 2d.2d).
                if (job.mixed_runner_expression and untrusted and untrusted <= PULL_REQUEST_PAYLOAD_EVENTS
                        and not job.in_lane("agent")):
                    self.add("OBAAF-GHA-013", job.line,
                             "Job '{job}' selects between hosted and self-hosted runners at runtime and " + why + ". "
                             "The checker cannot prove which runner receives untrusted work. Review the selector "
                             "and pool isolation; this informational finding does not certify it as safe.",
                             job, severity="info", kind="runtime-choice" + case, selector=Fact(job.selector, ""),
                             **values)
                else:
                    self.add("OBAAF-GHA-013", job.line,
                             "Job '{job}' runs on {labels}, which are not standard GitHub-hosted labels, and "
                             + why + ". If this is a self-hosted runner, it must be ephemeral.", job,
                             severity="medium", kind="other-labels" + case, labels=labels, **values)

    # -------------------------------------------------------------- GHA-018
    def signing_keys(self, job: Job) -> None:
        severity = "high" if job.in_lane("release") else "medium"
        patterns = [re.compile(p, re.I) for p in self.detection.get("signing_secret_patterns", [])]
        names = job.secret_names()
        keys = sorted(n for n in names if not n.startswith("*") and any(p.search(n) for p in patterns))
        environment = self._environment_fact(job)
        if keys:
            self.add("OBAAF-GHA-018", job.line,
                     "Job '{job}' loads signing material from secret(s): {secrets}{passed}{environment}.", job,
                     severity=severity, kind="secrets", secrets=keys, passed=self._passed_fact(job, keys),
                     environment=environment)
        # A job that can read every secret (a computed name, toJSON(secrets), secrets: inherit) can read
        # any signing key the repository or the job's environment holds; which secrets those are is
        # not in the workflow, so the checker cannot tell that none is one.
        every = sorted(n for n in names if n.startswith("*"))
        if every:
            shown = " and ".join("secrets: inherit" if n == "*inherit" else "a reference that is not one literal name"
                                 for n in every)
            self.add("OBAAF-GHA-018", job.line,
                     "Job '{job}' can read every secret ({how}){passed}{environment}, so any signing key stored "
                     "for it is available to what it runs.", job, severity=severity, kind="any-secret",
                     how=Fact(every, shown), passed=self._passed_fact(job, every), environment=environment)
        commands = [re.compile(p, re.M) for p in self.detection.get("signing_commands", [])]
        actions = list(self.detection.get("signing_actions", []))
        for step in job.steps:
            # A command continued on the next line is one command to the shell: a backslash in sh and
            # bash, a backtick in PowerShell, a caret in cmd.
            # Both readings are matched, so joining never hides what a line alone shows (a later
            # command on the joined line can stop a pattern that looks ahead, such as cosign's).
            raw = step.text()
            joined = re.sub(r"[\\`^][ \t]*\r?\n", " ", raw)
            if any(step.uses_action(a) for a in actions):
                self.add("OBAAF-GHA-018", step.line,
                         "Step '{step}' loads a signing key into the build environment.", job, step,
                         severity=severity, kind="action")
            elif raw and any(rx.search(raw) or rx.search(joined) for rx in commands):
                self.add("OBAAF-GHA-018", step.line,
                         "Step '{step}' loads a signing key into the build environment.", job, step,
                         severity=severity, kind="command")

    @staticmethod
    def _callers_fact(entries: list, lead: str) -> Fact | Note:
        """Entries about what the jobs of this repository that call a job's workflow give it, as one
        bounded fact: up to PASSED_NAMED entries (and 1,000 characters) each named; beyond that, the
        first few that fit and a digest of all. Nothing for no entries, so a finding on a workflow no job
        of the repository calls is as before."""
        if not entries:
            return Note("")
        if len(entries) <= PASSED_NAMED and sum(len(entry) for entry in entries) <= 1000:
            return Fact(entries, f" ({lead}: {'; '.join(entries)})")
        # The finding grows with what each caller gives; what identifies it must not (the review of slice
        # 2d.4b1 made a 290 KB repository print 249 MB). The first few entries are named, and every one is
        # in the digest, so a change to any changes the finding.
        digest = hashlib.sha256("\n".join(entries).encode("utf-8", "surrogatepass")).hexdigest()
        # Entries are named while they fit in the budget, at most PASSED_SHOWN of them; an entry is itself
        # bounded (a long list of secrets in one value is its digest).
        named: list = []
        for entry in entries[:PASSED_SHOWN]:
            if sum(len(e) for e in named) + len(entry) > 1000:
                break
            named.append(entry)
        rest = (f"{len(entries) - len(named)} more, {len(entries)} in all, by digest sha256:{digest}" if named
                else f"{len(entries)} entries, by digest sha256:{digest}")
        return Fact([*named, f"sha256:{digest} ({len(entries)} entries)"], f" ({lead}: {'; '.join([*named, rest])})")

    @staticmethod
    def _passed_fact(job: Job, names) -> Fact | Note:
        """What the jobs of this repository that call the job's workflow pass for the secrets it reads,
        as part of a finding about those secrets (flagship slice 2d.4b1): the called job reads a
        parameter (`secrets.MODEL_KEY`), and which secret that is depends on the caller, so an
        acceptance written for one mapping must not cover another. Nothing for a workflow no job of the
        repository calls, so such a finding is as before."""
        memo = job.workflow.__dict__.setdefault("_passed_facts", {})
        asked_for = frozenset(names)
        if asked_for not in memo:
            memo[asked_for] = WorkflowRules._callers_fact(job.passed_secrets(names), "from the jobs that call its workflow")
        found = memo[asked_for]
        return Fact(list(found.value), found.shown) if isinstance(found, Fact) else found

    @staticmethod
    def _granted_fact(job: Job, scope: str | None = None) -> Fact | Note:
        """What the jobs of this repository that call the job's workflow grant its token, where the job
        declares no permissions (flagship slice 2d.4b3a), as part of OBAAF-GHA-003's and 004's
        `inherited` finding: an acceptance written while every caller granted read only must not cover a
        caller that grants `contents: write` or `id-token: write`. Nothing for a workflow no job of the
        repository calls."""
        return WorkflowRules._callers_fact(job.granted_by_callers(scope), "the jobs of this repository that call it")

    @staticmethod
    def _environment_fact(job: Job) -> Fact | Note:
        """The job's environment as part of a finding about its secrets: a secret of the same name is
        another secret in another environment (an environment's secret takes precedence over the
        repository's), so an acceptance written for one environment does not cover another."""
        written = job.raw.get("environment")
        written = written.get("name") if isinstance(written, dict) else written
        if written is None:
            return Note("")         # nothing shown and no fact, so a job with no environment is as before
        return Fact(value_identity(written), f" in environment {shown_value(written)}")

    # -------------------------------------------------------------- GHA-021/022
    @staticmethod
    def _inert(step: Step) -> bool:
        """A step that only prepares what an effect job applies: a checkout, a download of artifacts, a
        setup action (GitHub's or OBAAF's). Anything else may apply (flagship slice 2d.2e)."""
        action = (step.action or "").lower()
        return (step.uses_action("actions/checkout") or step.uses_action("actions/download-artifact")
                or step.uses_action("dawidd6/action-download-artifact") or action.startswith("actions/setup-")
                or bool(re.fullmatch(r"[^/]+/obaaf/actions/setup-obaaf", action)))

    # Commands that only read or prepare, which may come in a step beside the checks of an effect job
    # (flagship slice 2d.2e): any other command in that step may apply, and the step's checks do not count.
    _PREPARING = frozenset({"set", "cd", "echo", "printf", "mkdir", "test", "[", "[[", "true", ":", "read", "export",
                            "for", "in", "do", "done", "while", "if", "then", "else", "elif", "fi", "sha256sum",
                            "shasum", "jq", "cat", "ls", "pwd", "grep", "wc", "head", "tail", "sort", "tr", "cut",
                            "basename", "dirname", "mapfile", "readarray", "obaaf"})

    def _only_prepares_and_checks(self, step: Step) -> bool:
        """Whether every command of a `run` step, where a command starts, is one of `_PREPARING` (the
        contents of an array assigned with `NAME=(...)` are no commands)."""
        assignment = re.compile(r"[A-Za-z_]\w*(\[[^\]]*\])?\+?=")
        if "`" in step.run or "$(" in step.run or "<(" in step.run or ">(" in step.run:
            return False        # a substitution runs commands, quoted or not
        for line in re.sub(r"\\\n", " ", step.run).split("\n"):
            tokens = _script_tokens(_strip_comment_text(line))
            if tokens is None:
                return False
            expecting, i = True, 0
            while i < len(tokens):
                word, quoted = tokens[i]
                if expecting and assignment.match(word):
                    if word.endswith("=") and i + 1 < len(tokens) and tokens[i + 1][0] == "(":
                        while i < len(tokens) and tokens[i][0] != ")":
                            i += 1
                    i += 1
                    continue
                if not quoted and word in (";", "&&", "||", "|", "&", "|&", ";;"):
                    expecting = True
                    i += 1
                    continue
                if expecting and (quoted or word not in self._PREPARING and word not in ("(", ")", "{", "}", "!")):
                    return False
                expecting = word in (";", "&&", "||", "|", "&", "(", "{", "!", "then", "do", "else", "elif", "if",
                                     "while", "until")
                i += 1
        return True

    def effect_rules(self, job: Job) -> None:
        if not job.in_lane("effect"):
            return
        verify_patterns = self.detection.get("record_verify_commands", [])
        proposal_patterns = self.detection.get("proposal_check_commands", [])

        def checks(j: Job) -> set:
            """The checks that come before any step of `j` that may apply, each binding (flagship slice
            2d.2e: before, any check anywhere in the job counted, after the step that applies included).
            None count when a step after them that may apply runs after a failure."""
            found: set = set()
            applying = False
            for step in j.steps:
                hit = set()
                if not applying and self._only_prepares_and_checks(step):
                    if self._binding_matches(j, step, verify_patterns):
                        hit.add("record")
                    if self._binding_matches(j, step, proposal_patterns):
                        hit.add("proposal")
                found |= hit
                if hit or self._inert(step):
                    continue
                applying = True
                if _bypasses_failure(step.raw) or step.background:
                    return set()
            return found

        def gated(j: Job) -> set:
            return {True} if self._environment_state(j) == "set" else set()

        writes = Fact(sorted(job.permissions.write_scopes()) if job.permissions else ["(not declared)"], "")
        # The checks and the approval may happen in a job this one needs, as long as this job cannot
        # run when that job fails.
        done = checks(job) | self._needs_gate(job, checks)
        if not done:
            self.add("OBAAF-GHA-021", job.line,
                     "Job '{job}' applies another run's output without verifying the agent-run record or "
                     "checking the proposal.", job, kind="unchecked", writes=writes)
        elif done != {"record", "proposal"}:
            missing = "verify the agent-run record" if "record" not in done else "check the proposal"
            self.add("OBAAF-GHA-021", job.line,
                     "Job '{job}' applies another run's output but does not " + missing + " before applying it.",
                     job, severity="medium", kind="no-record" if "record" not in done else "no-proposal",
                     writes=writes)
        if not (gated(job) or self._needs_gate(job, gated)):
            self.add("OBAAF-GHA-022", job.line,
                     "Job '{job}' applies another run's output with write access but has no approval "
                     "environment.", job, writes=writes, environment=Fact(self._environment_state(job), ""))

    # -------------------------------------------------------------- GHA-017
    def _signs_provenance(self, job: Job) -> bool:
        """Whether a job signs provenance (flagship slice 2d.2e): a step that uses a provenance action and
        runs on success, or a `run` step with a provenance command that stops the job when it fails.
        An attestation of an SBOM only (`sbom-path` with no `predicate-type`, `cosign attest --type` of an
        SBOM format) is not provenance, and a job no trigger reaches signs nothing."""
        if not job.triggers() or "".join(as_text(job.raw.get("if", "")).split()).lower() in ("false", "${{false}}") \
                or _continues_on_error(job.raw):
            return False
        actions = self.detection.get("provenance_actions", [])
        commands = self.detection.get("provenance_commands", [])
        for step in job.steps:
            if any(step.uses_action(a) for a in actions) and self._step_runs_on_success(step):
                w = step.with_
                if step.uses_action("actions/attest") and not step.uses_action("actions/attest-build-provenance") \
                        and w.get("sbom-path") and not w.get("predicate-type"):
                    continue
                return True
            for words in self._binding_matches(job, step, commands):
                kind = next((words[i + 1] for i, w in enumerate(words[:-1]) if w == "--type"), "")
                kind = kind or next((w.split("=", 1)[1] for w in words if w.startswith("--type=")), "")
                if not re.match(r"(spdx|cyclonedx|vuln)", kind, re.I):
                    return True
        return False

    # What `npm publish` may be given for its provenance to be credited (flagship slice 2d.12, from its
    # review). npm's option reader (nopt) takes `true` or `false` after a boolean option as its value,
    # reads `no-` in any case after any number of dashes, and gives an option that takes a value the next
    # word, `--provenance` included, so only a closed list of words is read: anything else, a folder or a
    # package to publish among them, keeps the upload counted.
    _NPM_PUBLISH_FLAGS = frozenset({"--provenance", "--provenance=true", "--access=public"})
    _NPM_PUBLISH_VALUES = {"--access": re.compile(r"public\Z"), "--tag": re.compile(r"[A-Za-z0-9][A-Za-z0-9._]*\Z")}
    _NPM_TAG_RE = re.compile(r"--tag=[A-Za-z0-9][A-Za-z0-9._]*\Z")
    # Characters in a word that the shell may turn into other words, or that say a value is not known.
    _NPM_UNREAD_RE = re.compile(r"[$`*?\[\]{}~\\]|OBAAF_EXPRESSION")
    # The Node.js versions that ship npm 9.5.0 or later, which npm's documentation asks for (line 37 of
    # generating-provenance-statements.mdx at 507a73e): Node.js 20.0.0 shipped npm 9.6.4; an older one
    # may ship npm 8, which does not know `--provenance`.
    _NODE_VERSION_RE = re.compile(r"v?([0-9]+)(\.([0-9]+|x|\*)){0,2}\Z")
    _NODE_ALIASES = frozenset({"lts/*", "latest", "current", "node"})
    _SETUP_NODE_INPUTS = frozenset({"node-version", "registry-url", "scope", "cache", "package-manager-cache",
                                    "always-auth", "check-latest"})
    # The commands an earlier step may run: they install the package's dependencies and run its own scripts,
    # and change neither npm nor the job's environment in the workflow's text.
    _NPM_EARLIER_RE = re.compile(r"npm (ci|install|test|run [A-Za-z0-9:_.-]+)\Z")
    # Variables that change what `npm`, Node.js or the shell runs, or where npm sends the package, in the
    # publishing step's, the job's or the workflow's `env`; also any `BASH...`, `LD_...`, `NPM_CONFIG_...`
    # and `NODE_...` name but `NODE_AUTH_TOKEN` (`_npm_env_changes`). Bash runs `SHELLOPTS` and expands
    # `PS4` at start (found by the second review of slice 2d.12).
    _NPM_ENV_KEYS = frozenset({"PATH", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "EXECIGNORE"})
    _NPM_REGISTRY = frozenset({"https://registry.npmjs.org", "https://registry.npmjs.org/"})

    def _npm_env_changes(self, env) -> bool:
        """Whether an `env` mapping may change what `npm`, Node.js or the shell runs, or where npm sends the
        package; an `env` that is not a mapping (one expression) may."""
        if env is None:
            return False
        if not isinstance(env, dict):
            return True
        for key in env:
            name = str(key).strip().upper()
            if name in self._NPM_ENV_KEYS or name.startswith(("BASH", "LD_", "NPM_CONFIG_")) or (
                    name.startswith("NODE_") and name != "NODE_AUTH_TOKEN"):
                return True
        return False

    def _npm_provenance_publish(self, job: Job, step: Step) -> bool:
        """Whether a step publishes to npm with provenance that npm signs as it publishes (flagship slice
        2d.12, #201). npm's CLI signs in `buildMetadata` before the request that sends the package, and
        throws when it cannot (libnpmpublish's `publish.js` at 787f152), so such a step publishes nothing
        without provenance. It is read only in the form npm's documentation gives, and only where the
        workflow's text leaves nothing that could change npm or what it is given:

        - the step's whole script is one command, `npm publish` followed only by `--provenance` (or
          `--provenance=true`), `--access public` and `--tag NAME`, each read as written;
        - the job's permissions, or its workflow's when it declares none, give `id-token: write`;
        - every runner it may run on is GitHub-hosted, and it has no `container` and no `services`;
        - its shell is a POSIX shell the checker reads, nothing runs beside it, and no `env` of the step, the
          job or the workflow is one expression or names `PATH`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`,
          `EXECIGNORE`, a `BASH...`, `LD_...` or `NPM_CONFIG_...` variable, or a `NODE_...` one but
          `NODE_AUTH_TOKEN`;
        - an earlier step is `actions/setup-node` with a Node.js version that ships npm 9.5.0 or later (20
          and up, or `lts/*`, `latest`, `current` or `node`), and every earlier step, with no `env`, `if` or
          `continue-on-error`, is `actions/checkout`, such a setup-node step with no input beyond
          `node-version`, `registry-url` (npm's own registry), `scope`, `cache`, `package-manager-cache`,
          `always-auth` and `check-latest`, or a `run` step whose lines are `npm ci`, `npm install`,
          `npm test` or `npm run NAME`, in the runner's default shell (neither the job nor the workflow sets
          a default `shell`).

        Any other form (`NPM_CONFIG_PROVENANCE`, `publishConfig`, `.npmrc`, trusted publishing, pnpm, Yarn,
        an action that publishes, a folder or package to publish, any other option or earlier step) is not
        read, and the upload is counted as it was before."""
        if step.uses or not isinstance(step.run, str) or not step.run.strip():
            return False
        perms = job.permissions
        if perms is None or perms.level("id-token") != "write":
            return False
        sets = job.runner_label_sets()
        if not sets or not all(labels and all(is_hosted_label(str(label).strip()) for label in labels)
                               for labels in sets) or job.raw.get("container") is not None \
                or job.raw.get("services") is not None:
            return False        # a container or a service is another image, which can change npm (third review)
        shell = self._failfast_shell(job, step)
        if shell is None or self._bash_env(job, step):
            return False
        if any(self._npm_env_changes(scope.get("env")) for scope in (step.raw, job.raw, self.wf.raw)
               if isinstance(scope, dict)):
            return False
        # Nothing runs beside it (a parallel group, or an earlier step left running in the background), and
        # the steps before it read with the job's and the workflow's own default shell, if they set one.
        earlier = job.steps[:step.index]
        if step.group is not None or any(other.background or other.group is not None for other in earlier):
            return False
        for scope in (job.raw, self.wf.raw):
            defaults = scope.get("defaults") if isinstance(scope, dict) else None
            if defaults is not None and not (isinstance(defaults, dict) and set(map(str, defaults)) <= {"run"} and (
                    isinstance(defaults.get("run"), dict) and "shell" not in defaults["run"])):
                return False
        if not all(self._npm_earlier_step_reads(job, other) for other in earlier) or not any(
                other.action and other.action.lower() == "actions/setup-node" for other in earlier):
            return False
        words = self._one_command(job, step)
        if words is None or words[:2] != ["npm", "publish"]:
            return False
        rest = words[2:]
        provenance = False
        at = 0
        while at < len(rest):
            word = rest[at]
            if word in self._NPM_PUBLISH_FLAGS or self._NPM_TAG_RE.match(word):
                provenance = provenance or word.startswith("--provenance")
                at += 1
            elif word in self._NPM_PUBLISH_VALUES and at + 1 < len(rest) and \
                    self._NPM_PUBLISH_VALUES[word].match(rest[at + 1]):
                at += 2
            else:
                return False
        return provenance

    def _one_command(self, job: Job, step: Step) -> list[str] | None:
        """The words of a `run` step's script when it is one command, on one line or continued with a
        backslash at a line's end, with nothing else but comment lines and blank ones, every word read as
        written; else None."""
        lines = [line for line in step.run.replace("\\\n", "").split("\n")
                 if line.strip() and not line.strip().startswith("#")]
        shell = self._failfast_shell(job, step)
        if len(lines) != 1 or "${{" in step.run or shell is None:
            return None
        commands, complete = binding_commands(_expressions_for_shell(step.run), *shell)
        if not complete or len(commands) != 1:
            return None
        words = commands[0]
        if any(not w or self._NPM_UNREAD_RE.search(w) for w in words):
            return None
        try:
            if shlex.split(lines[0], comments=True) != words:
                return None     # an `|| exit` after it, or quoting the reader turned into other words
        except ValueError:
            return None
        return words

    def _npm_earlier_step_reads(self, job: Job, step: Step) -> bool:
        """Whether a step before `npm publish --provenance` is one that leaves npm as it is (see
        `_npm_provenance_publish`)."""
        # No earlier step is given an `env` (an action runs in its own Node.js, which `NODE_OPTIONS` can
        # make load a file; found by the second review of slice 2d.12), and none may be skipped or fail
        # without stopping the job.
        if step.raw.get("env") is not None or step.raw.get("if") is not None or step.raw.get("continue-on-error") \
                is not None:
            return False
        if step.uses:
            if step.action and step.action.lower() == "actions/checkout":
                return True
            if not (step.action and step.action.lower() == "actions/setup-node"):
                return False
            given = step.raw.get("with")
            if not isinstance(given, dict) or set(map(str, given)) - self._SETUP_NODE_INPUTS:
                return False
            registry = given.get("registry-url")
            if registry is not None and as_text(registry).strip() not in self._NPM_REGISTRY:
                return False
            version = given.get("node-version")
            if version is None or isinstance(version, (bool, float)) or not isinstance(version, (str, int)):
                return False        # the runner's own Node.js, whose npm the checker does not know
            text = as_text(version).strip()
            match = self._NODE_VERSION_RE.match(text)
            return text in self._NODE_ALIASES or bool(match and int(match.group(1)) >= 20)
        if not isinstance(step.run, str) or step.raw.get("shell") is not None:
            return False
        lines = [" ".join(line.split()) for line in step.run.split("\n") if line.strip() and not line.strip().startswith("#")]
        return bool(lines) and all(self._NPM_EARLIER_RE.match(line) for line in lines)

    def provenance_missing(self) -> None:
        uploading = [j for j in self.wf.jobs.values() if j.in_lane("release") and j.upload_steps(self.detection)]
        if not uploading:
            return
        if any(self._signs_provenance(j) for j in self.wf.jobs.values()):
            return
        # An upload that is `npm publish --provenance`, in the form `_npm_provenance_publish` reads, signs
        # its own provenance (flagship slice 2d.12); the other uploads are weighed as before.
        def unsigned(j: Job) -> list[Step]:
            return [s for s in j.upload_steps(self.detection) if not self._npm_provenance_publish(j, s)]

        uploading = [j for j in uploading if unsigned(j)]
        if not uploading:
            return
        # Provenance signed by another workflow counts when every upload is gated on verifying it, by a
        # check that comes before it and stops it (flagship slice 2d.2e: before, any verify text anywhere
        # in the job counted, after the upload or in an `echo` included).
        unverified = [j for j in uploading
                      if any(kind is None for _s, kind in self._upload_checks(j, unsigned(j)))]
        if not unverified:
            return
        # One finding for the workflow. It is reported on the first publishing job that is a release
        # job before anything else, as it was when a job had one lane, so an accepted finding stays
        # where the baseline has it; a job that is also an agent or effect job is named only when
        # there is no other. A job whose every upload is a credited `npm publish --provenance` is not
        # among them (slice 2d.12), so the finding can move to the next publishing job, and an acceptance
        # that names the first one no longer matches.
        job = next((j for j in unverified if j.lane == "release"), unverified[0])
        self.add("OBAAF-GHA-017", job.line,
                 "Job '{job}' publishes artifacts, but no job in this workflow signs provenance for them.", job)


def _line_digests(text: str, hidden: list) -> list[str]:
    """For each hidden character, a digest of the text it acts on. A line here ends only at a line
    feed; the text is expected with every carriage return, alone or before a line feed, already turned
    into a line feed (if one reaches this function before a line feed it is left out of the digest).
    A form feed, a vertical tab, U+0085 or U+2028 does not end a line: text after one is still beside
    the character for a reader and for a direction override. A direction control (U+202A to U+202E,
    U+2066 to U+2069, the marks) is digested with its whole paragraph, from the blank line before it
    to the blank line after it, because rendered Markdown joins those lines and the control reorders
    them (slice 2d.2h). Line and paragraph bounds are found once and each is hashed once, so the cost
    is linear in the text."""
    def digest(piece: str) -> str:
        if piece.endswith("\r"):
            piece = piece[:-1]
        return hashlib.sha256(piece.encode("utf-8", "surrogatepass")).hexdigest()[:32]

    starts = [0]
    at = text.find("\n")
    while at != -1:
        starts.append(at + 1)
        at = text.find("\n", at + 1)
    # Paragraphs: the text between blank lines (a blank line holds only spaces and tabs).
    breaks = [0]
    for m in re.finditer(r"\n[ \t]*(?=\n)", text):
        breaks.append(m.start() + 1)
    cache: dict[tuple[str, int], str] = {}
    digests = []
    for h in hidden:
        offset = h.offset if h.offset >= 0 else starts[h.line - 1] + h.column - 1
        if h.kind == "bidirectional control":
            index = bisect.bisect_right(breaks, offset) - 1
            key = ("p", index)
            if key not in cache:
                end = breaks[index + 1] if index + 1 < len(breaks) else len(text)
                cache[key] = digest(text[breaks[index]:end].strip("\n"))
        else:
            index = bisect.bisect_right(starts, offset) - 1
            key = ("l", index)
            if key not in cache:
                end = text.find("\n", starts[index])
                cache[key] = digest(text[starts[index]: len(text) if end == -1 else end])
        digests.append(cache[key])
    return digests


# The largest instruction file the checker scans for hidden characters; a larger one is a finding.
INSTRUCTION_LIMIT = 2_000_000


# ------------------------------------------------------------------- repository
def repo_findings(root: Path, workflow_paths: list[str], catalog: Catalog, errors: list | None = None,
                  notes: list | None = None, local_actions: list[str] | None = None,
                  gate_files: list[str] | None = None) -> list[Finding]:
    """The repository rules. A CODEOWNERS or instruction file that is there and cannot be read is
    an error in `errors` (the check fails), never taken for missing or clean; a directory that
    cannot be listed is a note in `notes`, because git cannot make a checked-out directory
    unreadable, so only a local run meets one.

    `workflow_paths` are the CI definition files as found (a link by its own path); `local_actions`
    the action files workflows use from this repository; `gate_files` other files that decide what
    the check accepts, such as a baseline given on the command line (slice 2d.2h)."""
    findings: list[Finding] = []
    errors = errors if errors is not None else []
    unlisted: list = []
    how: dict = {}
    try:
        codeowners = repo_checks.load_codeowners(root)
        unread = False
    except repo_checks.UnreadableFile as exc:
        errors.append(str(exc))
        codeowners, unread = repo_checks.Codeowners(exc.rel), True
    try:
        entries = repo_checks.find_instruction_entries(root, catalog.detection.get("instruction_files", []), unlisted,
                                                       errors, how)
    except repo_checks.TooManyFiles as exc:
        errors.append(str(exc))
        entries = []
    if notes is not None and how.get("listing") == "walk" and (root / ".git").exists():
        notes.append(f"The checker looked for agent instruction files in every folder, untracked ones included, "
                     f"because {how.get('why', 'git did not list the tracked files')}; a file git does not "
                     "track (an installed node_modules, a local build) may be reported, and a pull request "
                     "cannot add one.")
    if notes is not None and unlisted:
        shown = ", ".join(f"{one_line(d, 60)}/" for d in unlisted[:3]) + (", ..." if len(unlisted) > 3 else "")
        notes.append(f"{len(unlisted)} director(ies) could not be listed or entered ({shown}), so agent instruction files in "
                     "them were not looked for.")
    outside = [e.rel for e in entries if e.outside]
    if notes is not None and outside:
        shown = ", ".join(one_line(p, 60) for p in outside[:3]) + (", ..." if len(outside) > 3 else "")
        notes.append(f"{len(outside)} agent instruction file(s) or folder(s) are links that lead out of the repository or "
                     f"to nothing ({shown}); the checker did not read them, and an agent on a machine where the "
                     "target exists would.")
    # Who must own what: each instruction file where an agent finds it, and the file in the repository
    # it reads when that is a link.
    instruction_files = sorted({e.rel.rstrip("/") for e in entries} | {e.real for e in entries if e.real}
                               | {e.link for e in entries if e.link})

    # A file inside a submodule changes in a pull request only through the submodule's own entry,
    # so that entry is what needs an owner (the third review of slice 2d.2h).
    gitlinks = set(how.get("gitlinks") or [])

    def owned_as(path: str) -> str:
        if gitlinks:
            at = path.find("/")
            while at != -1:
                if path[:at] in gitlinks:
                    return path[:at]
                at = path.find("/", at + 1)
        return path

    instruction_files = sorted({owned_as(p) for p in instruction_files})

    def add(rule: str, path: str, line: int, template: str, kind: str = "", **values) -> None:
        message, facts = compose(rule, kind, template, None, None, values)
        findings.append(Finding(rule, catalog.rules[rule]["severity"], path, line, message, kind=kind, facts=facts))

    def files(paths: list[str]) -> dict:
        """The message names the first five files and counts them all; every one is part of the finding."""
        paths = sorted(paths)
        return {"count": Note(str(len(paths))), "files": Fact(paths, ", ".join(paths[:5]))}

    # The CI definitions: workflow files and Jenkinsfiles, the local actions they use, the workflow
    # lockfile, and a workflow file not written yet, so that owning each file by name is not owning
    # the folder a new workflow lands in.
    ci_files = {owned_as(p) for p in set(workflow_paths) | set(local_actions or [])}
    probes: list[str] = []
    if (root / ".github" / "workflows").is_dir():
        if (root / ".github" / "workflows" / "actions.lock").is_file():
            ci_files.update(owned_as(p) for p in _with_target(root, ".github/workflows/actions.lock"))
        probes = list(NEW_WORKFLOW_PROBES)
    # The files that decide what the check accepts. A configuration file that is not there yet can be
    # added by any change, so while there is none, each place the checker looks for one counts; so do
    # the firewall policy's place, and each CODEOWNERS place GitHub looks in before the one in use.
    gate = set(gate_files or [])
    present = [loc for loc in CONFIG_FILES if (root / loc).is_file() or (root / loc).is_symlink()]
    for loc in present or CONFIG_FILES:
        gate.update(_with_target(root, loc))
    gate.update(_with_target(root, egress_mod.FIREWALL_POLICY))
    if codeowners.path:
        places = repo_checks.CODEOWNERS_LOCATIONS
        gate.update(places[:places.index(codeowners.path) + 1] if codeowners.path in places else [codeowners.path])
    gate = {owned_as(p) for p in gate}

    if unread:
        pass        # the error stands for both rules: who owns what cannot be read
    elif codeowners.path is None:
        add("OBAAF-REPO-001", ".github/CODEOWNERS", 1, "The repository has no CODEOWNERS file.", kind="no-codeowners")
        if instruction_files:
            add("OBAAF-REPO-002", instruction_files[0], 1,
                "No CODEOWNERS file covers the {count} agent instruction file(s): {files}.", kind="no-codeowners",
                **files(instruction_files))
    elif codeowners.not_loaded:
        add("OBAAF-REPO-001", codeowners.path, 1, "GitHub does not load {codeowners}: {why}.", kind="not-loaded",
            codeowners=codeowners.path, why=Note(codeowners.not_loaded))
        if instruction_files:
            add("OBAAF-REPO-002", codeowners.path, 1,
                "GitHub does not load {codeowners}, so it covers none of the {count} agent instruction file(s): "
                "{files}.", kind="not-loaded", codeowners=codeowners.path, **files(instruction_files))
    else:
        index = repo_checks.OwnerIndex(codeowners.rules, codeowners.path)
        try:
            def uncovered(paths):
                out, problems = [], []
                for path in paths:
                    rule = index.rule_for(path)
                    if rule is None or not rule.valid_owners:
                        out.append(path)
                        if rule is not None and rule.problem:
                            problems.append(rule.problem)
                return out, problems

            def why(problems):
                if not problems:
                    return Note("")
                first = sorted(set(problems))
                return Note(" (" + "; ".join(first[:2]) + (", and more" if len(first) > 2 else "")
                            + ", so GitHub assigns no owner)")

            missing, problems = uncovered(sorted(ci_files))
            # A new workflow file: owned only when every name it could have gets an owner, decided from
            # the rules themselves (slice 2d.2h's second review), not from names the checker tries.
            for label in probes:
                owned, why_not = index.new_file_owned(".github/workflows", "." + label.rsplit(".", 1)[1])
                if not owned:
                    missing.append(label)
                    if why_not:
                        problems.append(why_not)
            missing = sorted(missing)
            if missing:
                add("OBAAF-REPO-001", codeowners.path, 1, "No code owner for {count} CI definition file(s): {files}{why}.",
                    kind="no-owner", why=why(problems), **files(missing))
            missing, problems = uncovered(sorted(gate))
            if missing:
                add("OBAAF-REPO-001", codeowners.path, 1,
                    "No code owner for {count} file(s) that decide what the checks accept: {files}{why}. Without "
                    "one, a change to them needs no owner's review, and it can take ownership away or accept a "
                    "finding.", kind="gate-no-owner", why=why(problems), **files(missing))
            missing, problems = uncovered(instruction_files)
            if missing:
                add("OBAAF-REPO-002", codeowners.path, 1,
                    "No code owner for {count} agent instruction file(s): {files}{why}.", kind="no-owner",
                    why=why(problems), **files(missing))
        except repo_checks.UnreadableFile as exc:
            errors.append(str(exc))

    # Each file is read and scanned once, and reported once, however many names an agent finds it by
    # (a link to a folder gives every file in it another name; the third review of slice 2d.2h found
    # 400 links to one large file took 66 s when each name was read again, and the sixth's re-review
    # that 300 links to a file of 100,000 hidden characters made a 2 GB report when each name was a
    # finding). The finding is on the file's own path when that is an instruction file, otherwise on
    # the first name that leads to it; the message names the others.
    groups: dict[tuple, list[str]] = {}
    for entry in entries:
        if entry.outside:
            continue
        rel = entry.rel
        source = entry.real or rel
        binary_name = Path(rel).suffix.lower() in repo_checks.BINARY_SUFFIXES or \
            Path(rel).name.lower() in repo_checks.BINARY_NAMES
        groups.setdefault((source, binary_name), []).append(rel)
    for (source, binary_name), names in sorted(groups.items()):
        names = sorted(set(names))
        rel = source if source in names else names[0]
        others = [n for n in names if n != rel]
        results = _examine_instruction_file(root, rel, source, binary_name, errors)
        for line, template, kind, values in results or []:
            if others:
                shown = ", ".join(one_line(n, 80) for n in others[:3]) + (", ..." if len(others) > 3 else "")
                values = {**values, "names": Fact(others, ""),
                          "more": Note(f"{values['more']} (an agent also reads the file as {len(others)} other "
                                       f"name(s): {shown})")}
            add("OBAAF-INS-001", rel, line, template, kind=kind, **values)
    return findings


_STRAY_CONTROLS = re.compile(rb"[\x00-\x08\x0b\x0e-\x1f\x7f]")
_STRAY_BYTES = re.compile("[\udc80-\udcff]")
# How pictures, archives, documents, fonts and compiled files begin. A file with such a name that
# begins so is not scanned: its bytes are not what an agent reads as text, and GitHub shows no diff of
# it (the fourth review of slice 2d.2h found a tar of a text file, a stored zip and a PDF reported).
_BINARY_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"%PDF-", b"PK\x03\x04", b"PK\x05\x06",
                 b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"RIFF", b"OggS", b"ID3", b"wOFF", b"wOF2",
                 b"OTTO", b"\x00\x01\x00\x00", b"\x7fELF", b"MZ", b"\x00asm", b"SQLite format 3\x00",
                 b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"8BPS", b"II*\x00",
                 b"MM\x00*", b"\x00\x00\x01\x00", b"\x93NUMPY", b"PAR1", b"\x80\x04\x95", b"\x80\x05\x95",
                 b"Bud1", b"\x00\x00\x00\x01Bud1")


def _begins_binary(data: bytes) -> bool:
    return data.startswith(_BINARY_MAGIC) or data[257:262] == b"ustar" or data[4:8] == b"ftyp"


def _looks_binary(data: bytes) -> bool:
    """Whether bytes that are not UTF-8 text, or hold a NUL, are a binary file rather than text with a
    few stray bytes. A stray byte is a NUL, another control character (but tab, line feed, form feed and
    carriage return) or a byte that is part of no UTF-8 character (a U+FFFD written in the text is not
    one); in the first 64 KiB, more than one byte in eight is stray, or at least eight and more than one
    in 64 are. A compressed picture or archive is far above that; text with a stray byte or two, which
    hid hidden characters from the scan before the slice's third review, is below."""
    head = data[:1 << 16]
    stray = len(_STRAY_CONTROLS.findall(head)) + len(_STRAY_BYTES.findall(head.decode("utf-8", "surrogateescape")))
    return stray * 8 > len(head) or (stray >= 8 and stray * 64 > len(head))


def _examine_instruction_file(root: Path, rel: str, source: str, binary_name: bool, errors: list) -> list | None:
    """The OBAAF-INS-001 findings for one file, as (line, template, kind, values); None when it could
    not be read (the error is added to `errors`)."""
    try:
        with open(root / source, "rb") as handle:
            data = handle.read(INSTRUCTION_LIMIT + 1)
            whole = hashlib.sha256(data)
            if len(data) > INSTRUCTION_LIMIT:
                # The whole file is digested, so an acceptance does not cover what is added later.
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    whole.update(chunk)
    except OSError as exc:
        errors.append(str(repo_checks.UnreadableFile(rel, exc)))
        return None
    if binary_name:
        # A picture, an archive or a compiled file is not scanned, whatever its size: one that begins
        # as such a file begins, or whose bytes look binary. A file with such a name whose bytes are
        # text, or text with a few stray bytes, is read like any other: a name is no reason to skip text
        # an agent could read.
        head = data[:INSTRUCTION_LIMIT]
        if _begins_binary(head):
            return []
        try:
            if b"\0" in head:
                raise UnicodeDecodeError("utf-8", head, 0, 1, "NUL")
            head.decode("utf-8")
        except UnicodeDecodeError:
            if _looks_binary(head):
                return []
    if len(data) > INSTRUCTION_LIMIT:
        return [(1, "The file is larger than {limit} bytes, more than the checker scans, so it cannot tell what the "
                 "file hides{more}.", "too-large", {"limit": Note(f"{INSTRUCTION_LIMIT:,}"), "more": Note(""),
                                                   "digest": Fact(whole.hexdigest()[:32], "")})]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A file in another encoding (UTF-16, a working-tree-encoding in .gitattributes) is text an
        # agent may still read and a reviewer may see otherwise; the scan cannot see what it hides.
        return [(1, "The file is not UTF-8 text (byte {byte}), so the checker cannot tell what it hides; an agent "
                 "may still read it{more}.", "not-utf8", {"byte": Note(str(exc.start + 1)), "more": Note(""),
                                                          "digest": Fact(hashlib.sha256(data).hexdigest()[:32], "")})]
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    hidden = repo_checks.scan_hidden(text)
    if not hidden:
        return []
    detail = "; ".join(h.label for h in hidden[:3])
    more = f" and {len(hidden) - 3} more" if len(hidden) > 3 else ""
    # The finding is which characters the file hides and the text each acts on (as a digest: the line
    # may be long, and a baseline is not the place for it). A line that moves up or down is the same
    # finding; a character on other text is another one, because where a direction override or an
    # invisible instruction sits is what it does. The message shows the first three with their line and
    # column, and the count of all of them.
    marks = sorted(f"U+{h.codepoint:04X} ({h.kind}) "
                   f"{'in a paragraph' if h.kind == 'bidirectional control' else 'on a line'} with sha256 {digest}"
                   for h, digest in zip(hidden, _line_digests(text, hidden)))
    return [(hidden[0].line, "{count} hidden character(s): {characters}{more}.", "",
             {"count": Note(str(len(hidden))), "more": Note(more), "characters": Fact(marks, detail)})]


# The places `obaaf check` looks for its configuration (checker.CONFIG_LOCATIONS).
CONFIG_FILES = (".github/obaaf.yml", ".github/obaaf.yaml", "obaaf.yml")
# Names standing for a workflow file nobody has written yet: whoever may add one changes what runs.
NEW_WORKFLOW_PROBES = (".github/workflows/(a new workflow).yml", ".github/workflows/(a new workflow).yaml")


def _with_target(root: Path, rel: str) -> list[str]:
    """`rel`, and when it is a link, the file it leads to: its path in the repository, or a label that
    says it leads out (which no CODEOWNERS rule can own)."""
    out = [rel]
    path = root / rel
    try:
        if not path.is_symlink():
            return out
        target = path.resolve(strict=False)
        out.append(target.relative_to(root.resolve()).as_posix())
    except (OSError, ValueError, RuntimeError):
        out.append(f"{rel} (a link out of the repository)")
    return out
