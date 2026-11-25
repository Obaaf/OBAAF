"""Find a job that may run files from an agent job's artifact (OBAAF-GHA-027, plan decision F-359's second step).

The reading fails closed (review of #366, run `rosefinch`). After a download that may fetch an agent job's
artifact, a later step that is not plainly read-only (`_read_only`) is reported when it may run files from
the download's folder (`_step_meets`): it runs in the folder, uses a local action from it, names it in an
`env` or input value, runs a program from it, gives an interpreter a file or code from it (or code on its
input in a step that names the folder), gives a package manager, build tool, test runner, container or git
a path there or runs one in a folder at or above it, writes what it read from the folder elsewhere, or names
the folder in a script that cannot be read word by word. When the folder is the workspace, or a value the
checker cannot read, every such step is. A variable or an earlier step that can change what a step runs
makes naming the folder enough, read-only steps included. The layout of the upload is not used to rule a
file out: the agent writes what it uploads, so a path that looks like one file may be a folder of anything.

Followed: `actions/upload-artifact`, its merge action and `actions/upload-pages-artifact` in a job of the
agent lane (inside a local composite action too), a merge in any job whose pattern may take one, and
`actions/download-artifact` in another job of the same run (workflows of this repository that call one
another count as one run) or of a run started by `workflow_run` from the producer's run. Not followed
(stated beside a cleared egress control): downloads by other actions or in scripts, a computed run ID or
repository, an artifact a job outside the agent lane uploads again, caches, job outputs, a folder named
through a shell variable, and what the repository's own programs do with a downloaded file they are given.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from dataclasses import dataclass

from obaaf.checker.workflow import Job, Step, Workflow

# Each upload action, with the artifact name it uses when `name` is not given.
UPLOAD_ACTIONS = {
    "actions/upload-artifact": "artifact",
    "actions/upload-artifact/merge": "merged-artifacts",
    "actions/upload-pages-artifact": "github-pages",
}
# Actions that only move or publish files: they run nothing they download.
READ_ONLY_ACTIONS = frozenset({*UPLOAD_ACTIONS, "actions/download-artifact", "actions/attest",
                               "actions/attest-build-provenance", "actions/attest-sbom"})
# Commands that read files and run none: a script of only these, with literal words, is read-only.
READ_ONLY_COMMANDS = frozenset({
    "cat", "echo", "printf", "ls", "jq", "grep", "egrep", "fgrep", "head", "tail", "wc", "diff", "cmp",
    "sha256sum", "sha1sum", "sha512sum", "md5sum", "stat", "file", "test", "[", "true", ":", "pwd", "du",
})
# Where a read-only command may write: nowhere a later step or job reads as settings or code.
_HARMLESS_TARGETS = frozenset({"/dev/null", "$GITHUB_STEP_SUMMARY", "${GITHUB_STEP_SUMMARY}"})
_SEPARATORS = frozenset({"|", "||", "&&", ";"})
_TRIGGERING_RUN = re.compile(r"\s*\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}\s*", re.IGNORECASE)
_THIS_REPOSITORY = re.compile(r"\s*\$\{\{\s*github\.repository\s*\}\}\s*", re.IGNORECASE)
_CURRENT_RUN = re.compile(r"\s*\$\{\{\s*github\.run_id\s*\}\}\s*", re.IGNORECASE)
# Expressions and variables that name a known folder, put in before a text is read (second review pass:
# `${{ github.workspace }}/result` split at its spaces, and `$PWD/result` was not read).
_KNOWN_EXPRESSIONS = (
    (re.compile(r"\$\{\{\s*github\.workspace\s*\}\}", re.IGNORECASE), "$GITHUB_WORKSPACE"),
    (re.compile(r"\$\{\{\s*runner\.temp\s*\}\}", re.IGNORECASE), "$RUNNER_TEMP"),
    (re.compile(r"\$\(\s*pwd\s*\)"), "$PWD"),
    (re.compile(r"`\s*pwd\s*`"), "$PWD"),
)
_WORKSPACE_PREFIX = re.compile(r"^(?:\$GITHUB_WORKSPACE|\$\{GITHUB_WORKSPACE\}|\$PWD|\$\{PWD\})(?=/|$)")
_TEMP_PREFIX = re.compile(r"^(?:\$RUNNER_TEMP|\$\{RUNNER_TEMP\})(?=/|$)")
_HOME_PREFIX = re.compile(r"^(?:\$HOME|\$\{HOME\})(?=/|$)")
_GLOB = re.compile(r"[*?\[]")
_MAX_PARTS = 64
_FILE_COMMANDS = re.compile(r"GITHUB_ENV|GITHUB_PATH|_runner_file_commands|exportVariable|addPath", re.IGNORECASE)
_TOKEN = re.compile(r"""[^\s'"`;|&()<>=,]+""")

ANYWHERE = "a location the checker cannot read"     # a download whose folder is not a literal value
WORKSPACE = "."


@dataclass(frozen=True)
class Upload:
    workflow: str           # the file's path, as the checker names it
    run: str                # the run it belongs to: the files that call one another share one
    job: str
    name: str | None        # None: computed, so any name
    path: str


@dataclass(frozen=True)
class Sources:
    items: tuple
    run_of: dict            # workflow path -> run key
    names: dict             # run key -> the names a workflow_run trigger may give for it

    def __bool__(self) -> bool:
        return bool(self.items)


def _text(value) -> str | None:
    """A scalar input as GitHub hands it to an action; None for a mapping, a list or nothing."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


def _runs(workflows) -> tuple[dict, dict]:
    """The workflows of this repository that call one another, read as one run (a called workflow's jobs
    are jobs of the caller's run, with its artifacts). Callers of the same file are joined too: wider."""
    parent: dict = {}

    def find(key):
        while parent.setdefault(key, key) != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    by_id = {id(workflow): workflow for workflow in workflows}
    for workflow in workflows:
        find(workflow.path)
        for job in workflow.jobs.values():
            for target in getattr(job, "called", None) or ():
                if id(target) in by_id:
                    a, b = find(workflow.path), find(target.path)
                    if a != b:
                        parent[max(a, b)] = min(a, b)
    run_of = {workflow.path: find(workflow.path) for workflow in workflows}
    names: dict = {}
    for workflow in workflows:
        given = _text(workflow.raw.get("name")) if isinstance(workflow.raw, dict) else None
        # An unnamed workflow is named by its path (wider: both are taken for a named one too).
        names.setdefault(run_of[workflow.path], set()).update(n.casefold() for n in (given, workflow.path) if n)
    return run_of, {key: frozenset(value) for key, value in names.items()}


def _name(step: Step, default: str) -> str | None:
    name = _text(step.with_.get("name", default))
    return None if name is None or "${{" in name else name


def uploads(workflows, expand=None) -> Sources:
    """Index the artifacts agent jobs upload, once per check. `expand(workflow, job)` gives the job with the
    steps of the local composite actions it uses, so an upload inside one counts. An
    `actions/upload-artifact/merge` step in any job of the run whose `pattern` may match an agent job's
    artifact makes a new one that holds its files, so it is indexed too, as the agent job's."""
    workflows = list(workflows)
    run_of, names = _runs(workflows)
    found = []
    merges = []
    for workflow in workflows:
        for job in workflow.jobs.values():
            agent = job.in_lane("agent")    # an agent inside a local action puts its job there (slice 2d.4a)
            view = expand(workflow, job) if expand is not None and job.local_steps and agent else job
            for step in view.steps:
                default = UPLOAD_ACTIONS.get(step.clean_action)
                if default is None:
                    continue
                if agent:
                    path = _text(step.with_.get("path", "")) or ""
                    found.append(Upload(workflow.path, run_of[workflow.path], job.id, _name(step, default), path))
                elif step.clean_action == "actions/upload-artifact/merge":
                    merges.append((workflow, job, step))
    for workflow, job, step in merges:
        pattern = _text(step.with_.get("pattern"))
        run = run_of[workflow.path]
        if any(u.run == run and (u.name is None or pattern is None or "${{" in pattern
                                 or fnmatch.fnmatchcase(u.name, pattern)) for u in found):
            found.append(Upload(workflow.path, run, job.id, _name(step, "merged-artifacts"), ""))
    return Sources(tuple(found), run_of, names)


def _matched(workflow: Workflow, job: Job, download: Step, sources: Sources) -> list:
    """The uploads `download` may fetch. Computed values that decide which run or repository it reads
    from are a stated limit; a computed name or pattern is read as any."""
    given = download.with_
    repository = given.get("repository")
    if (repository is not None and not _THIS_REPOSITORY.fullmatch(str(repository))) or "artifact-ids" in given:
        return []
    run = sources.run_of.get(workflow.path, workflow.path)
    if (given.get("run-id") is not None and given.get("github-token")
            and not _CURRENT_RUN.fullmatch(str(given["run-id"]))):
        if not _TRIGGERING_RUN.fullmatch(str(given["run-id"])):
            return []
        trigger = workflow.triggers.get("workflow_run") if isinstance(workflow.triggers, dict) else None
        listed = trigger.get("workflows") if isinstance(trigger, dict) else None
        if not isinstance(listed, list):
            listed = [listed]
        wanted = {text.casefold() for text in map(_text, listed) if text}
        candidates = [u for u in sources.items if sources.names.get(u.run, frozenset()) & wanted]
    else:
        candidates = [u for u in sources.items if u.run == run and not (u.workflow == workflow.path and u.job == job.id)]
    if "name" in given:
        name = _text(given["name"])
        if name is None or "${{" in name:
            return candidates
        # Matched in any letter case, the wider reading.
        return [u for u in candidates if u.name is None or u.name.casefold() == name.casefold()]
    pattern = _text(given.get("pattern"))
    if pattern is None or "${{" in pattern:
        return candidates
    return [u for u in candidates if u.name is None or fnmatch.fnmatchcase(u.name, pattern)]


def _known(text: str) -> str:
    for pattern, name in _KNOWN_EXPRESSIONS:
        text = pattern.sub(name, text)
    return text


def _normal(value: str) -> str | None:
    """A literal path as the steps after it would name it: relative to the workspace, absolute, under `~`
    or under `$RUNNER_TEMP`. None for a value the checker does not read (an expression, `..` above the
    workspace, `~user`)."""
    value = _known(value).strip()
    if not value or "${{" in value or "\n" in value:
        return None
    value = _WORKSPACE_PREFIX.sub(".", value)
    value = _TEMP_PREFIX.sub("$RUNNER_TEMP", value)
    value = _HOME_PREFIX.sub("~", value)
    if value.startswith("~") and not (value == "~" or value.startswith("~/")):
        return None
    shown = posixpath.normpath(value)
    if shown == ".." or shown.startswith("../"):
        return None
    return shown


def _roots(download: Step, matched: list) -> list:
    """The folders the download writes. A download with no `name` and no `merge-multiple: true` writes each
    artifact into a folder of its name under `path`."""
    given = download.with_
    raw = given.get("path")
    base = WORKSPACE if raw is None else _normal(_text(raw) or "")
    if base is None:
        return [ANYWHERE]
    if "name" in given or str(given.get("merge-multiple", "")).strip().lower() == "true":
        return [base]
    roots = []
    for upload in matched:
        if upload.name is None:
            return [base]
        roots.append(posixpath.normpath(posixpath.join(base, upload.name)))
    return roots


def _kind(path: str) -> str:
    if path.startswith("/"):
        return "absolute"
    if path.startswith("~"):
        return "home"
    if path.startswith("$RUNNER_TEMP"):
        return "temp"
    return "workspace"


def _join(directory: str | None, path: str) -> str | None:
    """`path`, read from a step whose working directory is `directory` (None: a folder not read)."""
    if _kind(path) != "workspace":
        return path
    if directory is None:
        return None
    return path if directory == "." else _normal(posixpath.join(directory, path))


def _parts_meet(path: str, root: str) -> bool:
    """Whether `path` is `root`, under it or above it, part by part. A part of `path` with a glob is matched
    as a pattern (wider: `*` is taken to match `/` too)."""
    if root in (WORKSPACE, ANYWHERE):
        return True
    if _kind(path) != _kind(root):
        return False
    if path == ".":
        return True
    for x, y in zip(path.split("/"), root.split("/")):
        if x != y and not (_GLOB.search(x) and fnmatch.fnmatchcase(y, x)):
            return False
    return True


class _Roots:
    """The folders the downloads before a step wrote, indexed so that a path is matched against all of them
    in the time of its own parts (second review pass: matching each word against each folder made 700
    downloads and 700 steps take 20 seconds)."""

    def __init__(self) -> None:
        self.roots: list = []
        self.every = False
        self.exact: dict = {}
        self.above: dict = {}
        self.workspace = None
        self.globs = 0

    def add(self, root: str) -> None:
        """Index one more folder, as the steps reach the download that wrote it."""
        if root in self.exact:
            return
        self.roots.append(root)
        self.every = self.every or root in (WORKSPACE, ANYWHERE)
        if self.workspace is None and _kind(root) == "workspace":
            self.workspace = root
        self.exact[root] = root
        parts = root.split("/")
        for end in range(1, len(parts) + 1):
            self.above.setdefault("/".join(parts[:end]), root)

    def meets(self, path: str) -> str | None:
        """The first folder `path` is, is under or is above."""
        if self.every:
            return self.roots[0]
        if path == ".":
            return self.workspace
        if _GLOB.search(path):
            self.globs += 1
            if self.globs * len(self.roots) > 200_000:
                return self.roots[0]        # too many to compare: taken to meet (third review pass)
            return next((root for root in self.roots if _parts_meet(path, root)), None)
        hit = self.above.get(path)
        if hit is not None:
            return hit
        return self.under(path)

    def under(self, path: str | None) -> str | None:
        """The first folder `path` is or is under (None: a folder not read, taken to be)."""
        if path is None or self.every:
            return self.roots[0]
        parts = path.split("/")
        for end in range(1, len(parts) + 1):
            hit = self.exact.get("/".join(parts[:end]))
            if hit is not None:
                return hit
        return None


def _meets(word: str, directory: str | None, idx: "_Roots") -> str | None:
    """The first folder of `idx` that `word`, as a path read from `directory`, is, is under or is above."""
    shown = _normal(word)
    if shown is None:
        return None
    if shown.count("/") > _MAX_PARTS:
        return idx.roots[0]                 # too deep to read part by part: taken to meet
    joined = _join(directory, shown)
    if joined is None or joined.count("/") > _MAX_PARTS:
        return idx.roots[0]                 # relative to a working directory the checker cannot read
    return idx.meets(shown) or (idx.meets(joined) if joined != shown else None)


def _working_directory(step: Step, job: Job, workflow: Workflow) -> str | None:
    directory = "."
    for scope in (workflow.raw, job.raw):
        defaults = scope.get("defaults") if isinstance(scope, dict) else None
        run = defaults.get("run") if isinstance(defaults, dict) else None
        if isinstance(run, dict) and run.get("working-directory") is not None:
            directory = _text(run.get("working-directory")) or "."
    if step.raw.get("working-directory") is not None:
        directory = _text(step.raw.get("working-directory")) or "."
    shown = _normal(directory)
    return None if shown is not None and shown.count("/") > _MAX_PARTS else shown


def _env_texts(scope) -> list:
    env = scope.get("env") if isinstance(scope, dict) else None
    if isinstance(env, dict):
        return [str(value) for value in env.values()]
    return [] if env is None else [str(env)]


def _words(text: str) -> list:
    return _TOKEN.findall(_known(text))


# Programs that run the file they are given first, or code given with -c/-e: their later words are the
# script's data. `source` and `.` are bash's.
INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "dash", "ksh", "mksh", "fish", "python", "python2", "python3", "pypy", "pypy3",
    "node", "nodejs", "deno", "bun", "ruby", "perl", "php", "pwsh", "powershell", "lua", "Rscript", "tclsh",
    "source", ".",
})
_CODE_OPTIONS = frozenset({"-c", "-e", "-E", "--eval", "-p", "--print", "-Command", "-command", "-r"})
_SCRIPT_SUFFIX = re.compile(r"\.(?:sh|bash|py|pyw|js|mjs|cjs|ts|rb|pl|pm|php|ps1|lua|r|tcl)$", re.IGNORECASE)
# Programs that run or load code from a path they are given, or from the folder they run in: package
# managers and their scripts, build tools, test runners (which collect files from the folders below them),
# containers, git (a folder's `.git/config` can name programs), and the programs that move files or run
# commands on them. Their every word is read, and the folder they run in.
TOOLS = frozenset({
    "npm", "npx", "pnpm", "pnpx", "yarn", "bunx", "pip", "pip3", "pipx", "uv", "uvx", "poetry", "pdm", "hatch",
    "make", "gmake", "cmake", "ninja", "meson", "bazel", "go", "cargo", "rustc", "gcc", "g++", "cc", "clang",
    "docker", "podman", "buildah", "nerdctl", "pytest", "py.test", "tox", "nox", "jest", "vitest", "mocha",
    "gradle", "gradlew", "mvn", "mvnw", "ant", "java", "javac", "dotnet", "composer", "bundle", "rake", "gem",
    "mix", "just", "task", "git", "cd", "pushd", "chmod", "cp", "mv", "ln", "install", "rsync", "tar", "unzip",
    "7z", "find", "eval", "trap", "alias", "tee", "dd", "sed", "awk", "patch",
})
# Of TOOLS, those that act only on the words they are given, so the folder they run in does not count.
_ARGUMENTS_ONLY = frozenset({"git", "cd", "pushd", "chmod", "cp", "mv", "ln", "install", "rsync", "tar",
                             "unzip", "7z", "find", "eval", "trap", "alias", "tee", "dd", "sed", "awk", "patch"})
_WRITES = frozenset({">", ">>", ">|", "&>", "&>>", "<>"})
# Words that run the command after them.
WRAPPERS = frozenset({"sudo", "env", "exec", "time", "nohup", "timeout", "nice", "command", "builtin",
                      "stdbuf", "xargs", "then", "do", "else", "elif", "if", "while", "until", "!", "{", "(",
                      "watch", "parallel", "setsid", "unbuffer", "doas"})
_KEYWORDS_SKIPPED = frozenset({"fi", "done", "esac", "}", ")", ";;"})
_COMMAND_BREAKS = frozenset({"|", "||", "&&", ";", "&", "(", ")", "|&", ";;", "\n"})
_REDIRECTS = frozenset({">", ">>", "<", "<<<", ">|", "&>", "&>>", ">&", "<&", "<>"})


def _comment_free(line: str) -> str:
    """The line without its comment, where bash would start one: a `#` that begins a word outside quotes
    (second review pass: shlex also started one inside `build#1`, hiding what followed)."""
    quote, escaped = None, False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t;|&()<>"):
            return line[:index]
    return line


def _substitutions(text: str):
    """`text` with each command substitution `$( ... )` outside single quotes put as a word of its own, and
    the scripts inside them; None where they cannot be read (unbalanced, nested past 20, arithmetic)."""
    inner, out, index, quote = [], [], 0, None
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'":
            out.append(text[index:index + 2])
            index += 2
            continue
        if quote == "'":
            quote = None if char == "'" else quote
        elif char == "'" and quote is None:
            quote = "'"
        elif char == '"':
            quote = None if quote == '"' else '"'
        elif text.startswith("$(", index):
            if text.startswith("$((", index):
                return None
            depth, end = 0, index + 1
            while end < len(text):
                depth += {"(": 1, ")": -1}.get(text[end], 0)
                if depth == 0:
                    break
                end += 1
            if depth != 0 or len(inner) > 20:
                return None
            inner.append(text[index + 2:end])
            out.append(" __substitution__ ")
            index = end + 1
            continue
        out.append(char)
        index += 1
    return "".join(out), inner


def _commands(script: str, _depth: int = 0):
    """The script's simple commands as lists of words, those inside command substitutions included, or
    None where it cannot be read word by word: backquotes, process substitution, arithmetic, an unbalanced
    quote or parenthesis."""
    text = _known(script).replace("\\\n", " ").replace("\\`", "")
    if any(mark in text for mark in ("`", "<(", ">(", "$((")) or _depth > 3:
        return None
    flattened = _substitutions(text)
    if flattened is None:
        return None
    text, inner = flattened
    commands, current = [], []
    for part in inner:
        found = _commands(part, _depth + 1)
        if found is None:
            return None
        commands.extend(found)
    ending = None
    for line in text.split("\n"):
        if ending is not None:
            # A here-document's lines are its command's input, not commands: read with the step's names
            # (an interpreter given one reads its code from it, below).
            if line.strip() == ending or (line.lstrip("\t") == ending):
                ending = None
            continue
        line = _comment_free(line)
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            words = list(lexer)
        except ValueError:
            return None
        # A here-document is the lexer's own `<<` token (not one in quotes, not `<<<`), and its delimiter
        # the next word, a leading `-` (`<<-`) taken off (third review pass).
        if "<<" in words:
            at = words.index("<<")
            if at + 1 >= len(words):
                return None
            ending = words[at + 1][1:] if words[at + 1].startswith("-") else words[at + 1]
            words = words[:at] + words[at + 2:]
        for word in words + ["\n"]:
            if word in _COMMAND_BREAKS or (set(word) <= set("();<>|&") and word not in _REDIRECTS):
                if current:
                    commands.append(current)
                current = []
            else:
                current.append(word)
    return commands


def _command_meets(words: list, directory: str | None, idx: "_Roots", names_root: bool) -> str | None:
    """Whether one simple command may run files of `roots`: the program is a path there; an interpreter's
    file, its options or its code is there, or it reads code from its input in a step that names the folder;
    one of TOOLS is given a path there, or runs in a folder there or above it."""
    index = 0
    while index < len(words):
        word = words[index]
        if word in _KEYWORDS_SKIPPED:
            index += 1
            continue
        assignment = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", word)
        if assignment and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", w) for w in words[index:]):
            return None                         # assignments alone set the shell's variables (a stated limit)
        if word in WRAPPERS or assignment:
            if assignment:
                hit = _meets(word.split("=", 1)[1], directory, idx)
                if hit:
                    return hit
            index += 1
            while index < len(words) and (words[index].startswith("-") or words[index].isdigit()):
                index += 1                      # a wrapper's options (timeout's duration, nice's -n 10)
            continue
        if word == "for" or word == "case" or word == "select":
            return None                         # its words are data until `do`/`in`; the body is its own command
        break
    if index >= len(words):
        return None
    command, rest = words[index], [w for w in words[index + 1:]]
    args = []
    targets = []
    skip = None
    for word in rest:
        if skip is not None:
            if skip in _WRITES and word not in _HARMLESS_TARGETS:
                targets.append(word)
            skip = None
            continue
        if word in _REDIRECTS:
            skip = word
            continue
        args.append(word)
    # Writing what a command read from the download where the checker does not follow it (a file a later
    # command or step runs, `GITHUB_ENV`, `GITHUB_PATH`) is moving the download, as `cp` is.
    if targets and any(_meets(w, directory, idx) for w in [command, *args]):
        return idx.roots[0]
    hit = _meets(command, directory, idx) if "/" in command or command.startswith(("~", "$")) else None
    if hit:
        return hit
    base = posixpath.basename(command)
    if base in INTERPRETERS:
        before_operand = True
        index = 0
        while index < len(args):
            word = args[index]
            if word in _CODE_OPTIONS and index + 1 < len(args):
                code = args[index + 1]
                if any(_meets(w, directory, idx) for w in _words(code)):
                    return idx.roots[0]
                return None
            if base.startswith("python") and word == "-m" and index + 1 < len(args):
                module = args[index + 1]
                if module in TOOLS or module.split(".")[0] in TOOLS:
                    return _command_meets([module] + args[index + 2:], directory, idx, names_root)
                return _meets(module.replace(".", "/"), directory, idx)
            hit = _meets(word, directory, idx)
            if hit:
                return hit
            if not word.startswith("-") and ("/" in word or _SCRIPT_SUFFIX.search(word) or base in ("source", ".")):
                return None                     # the file it runs; what follows is that file's data
            index += 1
        return idx.roots[0] if names_root else None     # reads its code from input, or from a word not read
    if base == "tee" and names_root and any(not w.startswith("-") and w not in _HARMLESS_TARGETS for w in args):
        return idx.roots[0]                 # writes what it reads (in a step that names the folder), as `>` does
    if base in TOOLS:
        for word in args:
            hit = _meets(word, directory, idx)
            if hit:
                return hit
        if base not in _ARGUMENTS_ONLY:
            return idx.roots[0] if directory is None else idx.meets(directory)
    return None


def _named(step: Step, job_texts: list, directory: str | None) -> list:
    """The texts of a step other than its script that can name a path: working directory, `uses`, inputs
    and `env`, with the job's and the workflow's `env`."""
    texts = [step.uses if step.uses and step.uses.startswith("./") else "", *job_texts, *_env_texts(step.raw)]
    raw_with = step.raw.get("with")
    if isinstance(raw_with, dict):
        texts.extend(str(value) for value in raw_with.values())
    elif raw_with is not None:
        texts.append(str(raw_with))
    return texts


def _step_meets(step: Step, job: Job, workflow: Workflow, idx: "_Roots", job_texts: list, steered: bool) -> str | None:
    """Whether a step after the download may run files of `idx`. A step that is read-only runs none,
    unless a variable or an earlier step can make it run code the checker did not read (`steered`)."""
    if not steered and _read_only(step, job, workflow):
        return None
    if idx.every:
        return idx.roots[0]
    directory = _working_directory(step, job, workflow)
    inside = idx.under(directory)
    if inside is not None:
        return inside                       # it runs in the download (or in a folder not read)
    for text in _named(step, job_texts, directory):
        for word in _words(text):
            hit = _meets(word, directory, idx)
            if hit:
                return hit
    if step.uses is not None:
        return None
    hit = next((h for h in (_meets(word, directory, idx) for word in _words(step.run)) if h), None)
    names_root = hit is not None
    shell = _shell(step, job, workflow)
    if shell not in (None, "bash", "sh") and not (isinstance(shell, str) and shell.split()[:1] in (["bash"], ["sh"])):
        return hit
    commands = _commands(step.run)
    if commands is None:
        return hit
    for words in commands:
        found = _command_meets(words, directory, idx, names_root)
        if found:
            return found
    # Steered, naming the folder is enough, and the commands are read as well (third review pass).
    return hit if steered else None


def _shell(step: Step, job: Job, workflow: Workflow):
    shell = step.raw.get("shell")
    for scope in (job.raw, workflow.raw):
        defaults = scope.get("defaults") if isinstance(scope, dict) else None
        run = defaults.get("run") if isinstance(defaults, dict) else None
        if shell is None and isinstance(run, dict):
            shell = run.get("shell")
    return shell


_PLAIN_VARIABLE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})")


def _read_only(step: Step, job: Job, workflow: Workflow) -> bool:
    """A step that runs nothing it may have downloaded: one of `READ_ONLY_ACTIONS` with no `env` of its own,
    or a bash or sh script with no expression of whose lines each is commands of `READ_ONLY_COMMANDS` with
    literal words (a variable only as `$NAME` or `${NAME}`, no `-v`), joined by `|`, `||`, `&&` or `;`,
    writing at most to /dev/null or the step summary, in `{ ... }` groups at most."""
    if step.uses is not None:
        return step.clean_action in READ_ONLY_ACTIONS and not step.raw.get("env")
    shell = _shell(step, job, workflow)
    if shell not in (None, "bash", "sh") or "${{" in step.run:
        return False
    for line in step.run.split("\n"):
        line = _comment_free(line).strip()
        if not line:
            continue
        if any(mark in line for mark in ("`", "$(", "<(", ">(", "<<")) or line.endswith("\\"):
            return False
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            words = list(lexer)
        except ValueError:
            return False
        if words == ["{"]:
            continue
        if any("$" in word and _PLAIN_VARIABLE.sub("", word).count("$") for word in words):
            return False                        # ${X@P}, ${X:-$(...)} and other expansions
        expect_command = True
        index = 0
        while index < len(words):
            word = words[index]
            if word == "}":
                expect_command = False
            elif expect_command:
                if word not in READ_ONLY_COMMANDS:
                    return False
                expect_command = False
            elif word in _SEPARATORS:
                expect_command = True
            elif word in (">", ">>"):
                index += 1
                if index >= len(words) or words[index] not in _HARMLESS_TARGETS:
                    return False
            elif word == ">&":
                index += 1
                if index >= len(words) or words[index] not in ("1", "2"):
                    return False
            elif set(word) <= set("();<>|&") or word == "-v":
                return False
            index += 1
        if expect_command:
            return False
    return True


_RUNNER_FILES = re.compile(r"\$\{?(?:GITHUB_ENV|GITHUB_PATH)\b\}?")


def _writes_runner_files(step: Step, job: Job, workflow: Workflow, idx: "_Roots") -> bool:
    """Whether a step writes a value that names a download's folder into `GITHUB_ENV` or `GITHUB_PATH`, so
    that later steps run with it (`NODE_OPTIONS=--require ./result/x.js`, `PATH`): a command that names the
    folder and writes one of them, or a step the checker cannot read word by word that names both."""
    texts = " ".join([step.run, str(step.raw.get("with") or "")])
    if not _FILE_COMMANDS.search(texts):
        return False
    directory = _working_directory(step, job, workflow)
    names = any(_meets(word, directory, idx) for word in _words(texts))
    if not names:
        return False
    commands = _commands(step.run) if step.uses is None else None
    if commands is None:
        return True
    for words in commands:
        if any(_RUNNER_FILES.search(w) for w in words) and any(_meets(t, directory, idx) for w in words
                                                                for t in _words(w)):
            return True
    return False


def consumers(workflow: Workflow, job: Job, sources: Sources, steered=None):
    """Yield (uploads, download step, step, what it may run) for each step of `job` after a download of an
    agent job's artifact that may run files from it, at most once per step. `steered(step)` says whether a
    variable or an earlier step can make the step run code the checker did not read."""
    if not sources:
        return
    downloads = []
    for index, step in enumerate(job.steps):
        if step.clean_action != "actions/download-artifact":
            continue
        matched = _matched(workflow, job, step, sources)
        if matched:
            downloads.append((index, step, tuple(dict.fromkeys(_roots(step, matched))), matched))
    if not downloads:
        return
    job_texts = _env_texts(job.raw) + _env_texts(workflow.raw)
    # A step, before the download or after it, that writes a value naming its folder into the runner's files
    # for later steps (`GITHUB_ENV`, `GITHUB_PATH`) can make any later step run the download, read-only ones
    # included (second review pass).
    every_root = _Roots()
    for download in downloads:
        for root in download[2]:
            every_root.add(root)
    writes = next((i for i, step in enumerate(job.steps) if _writes_runner_files(step, job, workflow, every_root)),
                  len(job.steps))
    idx = _Roots()
    passed = 0
    for index, step in enumerate(job.steps):
        while passed < len(downloads) and downloads[passed][0] < index:
            for root in downloads[passed][2]:
                idx.add(root)
            passed += 1
        if not passed:
            continue
        reaching = downloads[:passed]
        is_steered = index > writes or bool(steered is not None and steered(step))
        hit = _step_meets(step, job, workflow, idx, job_texts, is_steered)
        if hit is None:
            continue
        start, download, _, matched = next((d for d in reversed(reaching) if hit in d[2]), reaching[-1])
        yield matched, download, step, hit
