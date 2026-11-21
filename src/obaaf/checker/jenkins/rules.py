"""Advisory rules for Jenkinsfiles (OBAAF-JEN-*). Metadata lives in data/rules.yaml.

The rules read only the Jenkinsfile and files it names in the repository. Jenkins decides much
of what matters on the controller: security realm and authorization, build authorization
(builds run as SYSTEM unless configured), which agents carry executors, library trust and
version overrides, Replay permission, script approval, credential scopes, and network policy.
None of that is in the file, so the rules report it as coverage unknowns rather than passing
it. A finding describes what the file shows; an unknown says what the file cannot show.
"""

from __future__ import annotations

import bisect
import csv
import functools
import posixpath
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from obaaf.catalog import Catalog
from obaaf.checker.jenkins import steps as known
from obaaf.checker.jenkins.model import (
    COMPUTED_ENV, CONTROLLER_LABELS, CR_NO, CR_POSSIBLE, CR_UNKNOWN, CR_YES, GIT_PUSH, JAVA_TRIM, SHELL_STEPS, Binding,
    KEY_SEP, Pipeline, StepUse, guard_key, shown,
    chain_name, code_text_arg, find_nodes, first_arg, literal, named_arg, shell_script, source_texts,
    untrusted_source,
)
from obaaf.checker.jenkins.parser import (
    Assign, Binary, Call, Closure, Decl, Import, Index, ListLit, Loop, MapLit, MethodDef, Name, Num, Prop, Str,
    callee_name, path_of,
)
from obaaf.checker.rules import Finding
from obaaf.checker.workflow import binding_commands, declared_lane

RULES = ("OBAAF-JEN-001", "OBAAF-JEN-002", "OBAAF-JEN-003", "OBAAF-JEN-004", "OBAAF-JEN-005", "OBAAF-JEN-006",
         "OBAAF-JEN-007", "OBAAF-JEN-008", "OBAAF-JEN-009", "OBAAF-JEN-010", "OBAAF-JEN-011", "OBAAF-JEN-012",
         "OBAAF-JEN-013", "OBAAF-JEN-014", "OBAAF-JEN-015")
ALL = "*"

# post conditions (and Scripted catch/finally blocks) that run when the build failed, was aborted, or
# is unstable: a publish there can run after a failed or skipped check.
FAILURE_PATHS = {"always", "changed", "regression", "aborted", "failure", "unstable", "unsuccessful", "cleanup",
                 "catch/finally"}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")
CHECKSUM_VERIFY = re.compile(r"(^|[\s;&|(])(sha256sum|sha512sum|shasum)\b[^\n]*\s(-c|--check)\b"
                             r"|(^|[\s;&|(])cosign\s+verify|(^|[\s;&|(])obaaf\s+verify\b", re.M)
INSTALLER = re.compile(r"\b(npm|pnpm|yarn|bun|npx|bunx|pip3?|pipx|uv|uvx)\b")
# Commands that run code from the checkout: build tools, test runners, package scripts, and scripts
# by path. Best effort; anything else is treated as a fixed tool, one severity level lower.
REPO_CODE = re.compile(
    r"(^|[\s;&|(\"'}=])(\./|\.\\|bash\s+|sh\s+|source\s+|\.\s+|python3?\s+|node\s+|ruby\s+|perl\s+|"
    r"pwsh\s+|powershell(\.exe)?\s+(-File\s+)?)?[\w./\\-]+\.(sh|bash|py|js|mjs|rb|pl|ps1|bat|cmd|groovy)\b"
    r"|(^|[\s;&|(])(\./)?(mvn|mvnw|gradle|gradlew|ant|make|gmake|cmake|ninja|meson|npm|npx|yarn|pnpm|bun|node|"
    r"python3?|pip3?|pytest|tox|nox|poetry|uv|go|cargo|dotnet|msbuild|bazel|bazelisk|buck2?|sbt|lein|mix|rake|"
    r"bundle|composer|php|xcodebuild|swift|flutter|dart|tsc|jest|ctest|yetus|test-patch|docker\s+build|"
    r"docker\s+compose|docker-compose|buildah|kaniko|terraform|ansible-playbook|UnrealBuildTool|RunUAT|"
    r"Unity|godot)\b", re.M)
# Steps that read a file in the workspace: a value read from one is the change's own for a change request.
WORKSPACE_READ = re.compile(r"\b(readFile|readJSON|readYaml|readProperties|readCSV|readMavenPom|findFiles)\b")
MUTABLE_SELECTORS = {"lastSuccessful", "lastCompleted", "latestSavedBuild", "permalink", "lastWithArtifacts",
                     "workspace", "buildParameter"}
# Flagship slice 2d.2m: the copyartifact plugin's selector classes, for `step([$class: 'CopyArtifact', selector:
# [$class: ...]])` and a selector map, by the symbol each has in Pipeline.
SELECTOR_CLASSES = {"StatusBuildSelector": "lastSuccessful", "LastCompletedBuildSelector": "lastCompleted",
                    "SavedBuildSelector": "latestSavedBuild", "PermalinkBuildSelector": "permalink",
                    "WorkspaceSelector": "workspace", "ParameterizedBuildSelector": "buildParameter",
                    "SpecificBuildSelector": "specific", "TriggeredBuildSelector": "upstream",
                    "DownstreamBuildSelector": "downstream", "LastWithArtifactsBuildSelector": "lastWithArtifacts"}
# A Jenkins URL of another job's artifacts (`.../job/b/lastSuccessfulBuild/artifact/app.jar`), with folders.
PERMALINK_ARTIFACT = re.compile(r"(?<![\w.-])job/(?P<job>[^/\s'\"]+(?:/job/[^/\s'\"]+)*)/(?P<ref>[^/\s'\"]+)/artifact/")
JENKINS_PERMALINKS = {"lastBuild", "lastStableBuild", "lastSuccessfulBuild", "lastFailedBuild", "lastUnstableBuild",
                      "lastUnsuccessfulBuild", "lastCompletedBuild"}
# A digest check at the start of a command (flagship slice 2d.2m): what it compares against is not known.
FETCH_DIGEST_CHECK = re.compile(r"(sha1sum|sha224sum|sha256sum|sha384sum|sha512sum|shasum|b2sum|md5sum)\b.*\s"
                                r"(-c|--check)\b|cosign\s+verify|gpg\s+--verify|minisign\s+-V")
UNREAD = object()      # an argument a spread map (`*: m`) may set
# A condition on the build's parameters alone, as a condition's label shows it: `if params.RELEASE`, with `!`,
# digits, true or false. A word that could be a string or a variable makes the condition one that may change.
PARAMS_ONLY_GUARD = re.compile(r"if(?: (?:!|params\.\w+|\d+|true|false))+")
# Writes to the script's binding or properties, which can set a variable by a name the file computes.
BINDING_WRITE = re.compile(r"\bbinding\b|\bsetVariable\b|\bsetProperty\b|\bthis\s*\[|\bgetBinding\b")
SELECTOR_POSITIONAL = {"specific": "buildNumber", "permalink": "id"}   # a selector's one unnamed argument


def call_entries(call: Call, positional: str | None) -> dict:
    """A step's arguments by name, as Groovy builds them (flagship slice 2d.2m): the named arguments, or a map given
    as the only argument; the last of a repeated key wins; a spread map (`*: m`) may set any key it comes after or
    that is not written later, which reads as UNREAD; a single positional argument is `positional`."""
    entries = list(call.named)
    if call.args:
        if len(call.args) == 1 and isinstance(call.args[0], MapLit) and not call.named:
            entries = [(k if isinstance(k, str) else (literal(k) or "*"), v) for k, v in call.args[0].entries]
        elif len(call.args) == 1 and positional:
            entries = [(positional, call.args[0])] + entries
        else:
            entries = [("*", None)] + entries
    out: dict = {}
    spread = False
    for key, value in entries:
        if key == "*":
            spread = True
            out = {k: UNREAD for k in out}
        else:
            out[key] = value
    if spread:
        return _SpreadDict(out)
    return out


class _SpreadDict(dict):
    """Arguments after a spread map: a key not written after it may be in the map."""
    def get(self, key, default=None):
        return super().get(key, UNREAD)


# A permalink's artifacts wherever the URL starts (`${JOB_URL}../b/lastSuccessfulBuild/artifact/x`), a job's
# workspace (`job/b/ws/app.jar`), and a `..` in a URL to artifacts, which curl removes before it asks.
PERMALINK_ANYWHERE = re.compile(r"(?<![\w-])(?P<ref>" + "|".join(sorted(JENKINS_PERMALINKS)) + r")/artifact/")
WORKSPACE_URL = re.compile(r"(?<![\w.-])job/(?P<job>[^/\s'\"]+(?:/job/[^/\s'\"]+)*)/ws/")
DOT_ARTIFACT = re.compile(r"/\.\./\S*/(artifact|ws)/|/(artifact|ws)/\S*/\.\./")


def artifact_urls(text: str) -> list[tuple[str, str]]:
    """How a text fetches another job's artifacts through Jenkins URLs (flagship slice 2d.2m)."""
    out = []
    for m in PERMALINK_ARTIFACT.finditer(text):
        ref, job = m.group("ref"), m.group("job")
        if ref in JENKINS_PERMALINKS:
            out.append(("moving", f"job '{job}' by its permalink {ref} (a URL)"))
        elif not (ref.isascii() and ref.isdigit()):
            out.append(("unknown", f"job '{job}' by the build reference '{ref}' in a URL"))
    if not out:
        for m in PERMALINK_ANYWHERE.finditer(text):
            out.append(("moving", f"a job by its permalink {m.group('ref')} (a URL)"))
    for m in WORKSPACE_URL.finditer(text):
        out.append(("moving", f"the workspace of job '{m.group('job')}' (a URL)"))
    if not out and DOT_ARTIFACT.search(text):
        out.append(("unknown", "a URL to another build's artifacts with a `..` in it"))
    return out


def text_or_expr(node) -> str:
    """A string's text, with interpolation shown as ${...}, or "" for anything else."""
    return node.text() if isinstance(node, Str) else ""

# Docker run options that reach the host (JEN-006). Flagship slice 2d.2j replaced a list of patterns, which
# missed `-v/var/run/docker.sock`, `-itv`, `--mount type=bind,source=/`, a quoted `"/:/host"`, `CAP_SYS_ADMIN`
# and `--device`, and took `--privileged=false` for privileged, with a reader of the options as docker does.
_HOST_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "SYS_MODULE", "SYS_RAWIO",
              "SYS_BOOT", "DAC_OVERRIDE", "SYS_CHROOT", "MKNOD", "BPF", "PERFMON", "SYSLOG"}
# Host folders whose mount gives a container the host, written or read: the root, the kernel's file systems,
# the container runtimes' state and sockets (rootless Docker's under /run/user). Their subfolders count too.
_HOST_TREES = ("/proc", "/sys", "/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet", "/run/containerd",
               "/run/docker", "/var/run/docker", "/run/podman", "/var/run/podman", "/run/crio", "/var/run/crio",
               "/run/user", "/var/run/user")
# The controller's home in the Debian and Red Hat packages and in the official image (secrets, jobs, plugins,
# init scripts run at the next start, the Git plugin's mirrors under `caches`), and an agent's root (every job's
# workspace): each counts whole and in every part but the caches and tools a build keeps there.
_JENKINS_HOMES = ("/var/lib/jenkins", "/var/jenkins_home", "/home/jenkins/agent", "/home/jenkins/workspace")
_CACHE_DIRS = (".m2", ".gradle", ".cache", ".npm", ".ivy2", ".sbt", ".pip", ".yarn", ".pnpm-store", "tools")
# Files that hold credentials for other hosts and registries, wherever they are.
_CREDENTIAL_FILES = (".netrc", ".git-credentials", ".npmrc", ".pypirc", ".dockercfg")
# Folders whose whole mount does, but whose subfolders are ordinary (`/etc/localtime`, `/root/.m2`, `/dev/shm`):
# the runtime sockets' folders, devices, configuration, homes (a user's home holds its keys and, for the agent's
# user, every job's workspace), the controller's home, the system's programs.
_HOST_FOLDERS = ("/run", "/var/run", "/dev", "/etc", "/root", "/home", "/boot", "/usr", "/bin", "/sbin", "/lib",
                 "/lib64", "/var", "/var/lib", "/opt")
# Of those, the ones only programs live in: reading them gives nothing, so a read-only mount of them is ordinary.
_READ_ONLY_HARMLESS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/boot")
# Folders inside a home that hold credentials for other hosts and registries.
_CREDENTIAL_DIRS = (".ssh", ".docker", ".kube", ".aws", ".gnupg", ".azure", ".config/gcloud")
_HOST_NAMESPACES = {"--pid": "the host PID namespace", "--ipc": "the host IPC namespace",
                    "--userns": "the host user namespace", "--uts": "the host UTS namespace",
                    "--cgroupns": "the host cgroup namespace"}
# Short options of docker run that take no value, and those that take one.
_SHORT_BOOL = set("dtiP")
_SHORT_VALUE = set("vewhlmpuca")
# Go's strconv.ParseBool, which docker's flags use: anything else is an error, so only these are false.
_FALSE = {"0", "f", "F", "false", "FALSE", "False"}
_WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]")


def _clean(path: str) -> str:
    """A host path as docker cleans it: repeated slashes, `.` and `..` resolved (Go's filepath.Clean)."""
    if path.startswith("/"):
        return posixpath.normpath("/" + path.lstrip("/"))
    return path


def _host_path(source: str, readonly: bool = False) -> str | None:
    """What mounting this host path gives a container, or None for an ordinary folder."""
    path = source.strip().strip("'\"")
    low = path.lower().replace("\\", "/")
    if "docker_engine" in low or low.endswith("docker.sock") or "/docker.sock" in low:
        return "a mount of the Docker socket"
    if low.endswith(".sock") or "/pipe/" in low:
        return "a mount of a container runtime socket"
    if _WINDOWS_PATH.match(path):
        rest = path[2:].replace("\\", "/").strip("/")
        if not rest or rest.lower() in ("windows", "programdata/docker", "windows/system32"):
            return "a mount of the host root file system" if not rest else f"a mount of the host's {path}"
        return None
    if not path.startswith("/"):
        if ".." in path.replace("\\", "/").split("/"):
            return "a mount of a host path outside the workspace"
        return None
    norm = _clean(path)
    if norm == "/":
        return "a mount of the host root file system"
    if readonly and (norm == "/sys/fs/cgroup" or norm.startswith("/sys/fs/cgroup/")):
        return None            # read-only cgroups, which systemd in a container reads
    if any(norm == p or norm.startswith(p + "/") for p in _HOST_TREES):
        return f"a mount of the host's {norm}"
    for home in _JENKINS_HOMES:
        if norm == home or (norm.startswith(home + "/") and norm[len(home) + 1:].split("/")[0] not in _CACHE_DIRS):
            return (f"a mount of the controller's home ({norm})" if home.startswith(("/var/lib", "/var/jenkins"))
                    else f"a mount of the agent's workspaces ({norm})")
    name = norm.rsplit("/", 1)[-1]
    if name in _CREDENTIAL_FILES:
        return f"a mount of the host's credentials ({norm})"
    if norm in _HOST_FOLDERS and not (readonly and norm in _READ_ONLY_HARMLESS):
        return f"a mount of the host's {norm}"
    parts = norm.strip("/").split("/")
    if len(parts) == 2 and parts[0] == "home":
        return f"a mount of the host's {norm}"          # a user's whole home
    if any(f"/{d}/" in norm + "/" for d in _CREDENTIAL_DIRS) and name not in ("known_hosts", "known_hosts2"):
        return f"a mount of the host's credentials ({norm})"
    return None


def _split_options(args: str) -> tuple[list[list[str]], list[str]]:
    """The ways the options may be split, and why that is not certain. Jenkins splits `args` itself, and not
    exactly as a shell does (a backslash is read differently), so the words a shell would see and the words
    between blanks are both read, and anything either finds counts (the second review of slice 2d.2j)."""
    unread: list[str] = []
    readings = [[w.strip("'\"") for w in args.split()]]
    try:
        readings.insert(0, shlex.split(args, comments=False, posix=True))
    except ValueError:
        unread.append("docker run options could not be split as the shell would")
    if "\\" in args:
        unread.append("docker run options hold a backslash, which Jenkins and a shell split differently")
    return readings, unread


def _mount_fields(value: str) -> dict:
    """`--mount` fields as docker reads them: comma-separated values with CSV quoting, keys in any case."""
    try:
        row = next(csv.reader([value]))
    except (csv.Error, StopIteration):
        row = value.split(",")
    fields = {}
    for item in row:
        key, eq, val = item.partition("=")
        fields[key.strip().lower()] = val if eq else "true"
    return fields


def _read_words(words: list[str], problems: list, unread: list, networks: list, mounts: list) -> None:
    i = 0
    while i < len(words):
        w = words[i]
        i += 1
        if w.startswith("--"):
            flag, eq, value = w.partition("=")
            takes = flag in _DOCKER_VALUE or flag in ("--mount", "--volumes-from", "--device", "--cap-add",
                                                      "--security-opt", "--network", "--net", "--device-cgroup-rule")
            if not eq and takes and flag not in _DOCKER_BOOL:
                value = words[i] if i < len(words) else ""
                i += 1
            if flag == "--privileged":
                if not eq or value.strip() not in _FALSE:
                    problems.append("--privileged")
            elif flag == "--use-api-socket":
                if not eq or value.strip() not in _FALSE:
                    problems.append("a mount of the Docker socket")
            elif flag == "--volume":
                _volume(value, problems, mounts)
            elif flag == "--mount":
                fields = _mount_fields(value)
                source = fields.get("source") or fields.get("src") or ""
                kind = fields.get("type", "volume").lower()
                if kind == "bind" or source.startswith("/") or _WINDOWS_PATH.match(source):
                    mounts.append(source)
                    ro = fields.get("readonly", fields.get("ro", "false")).strip() not in _FALSE
                    found = _host_path(source, ro)
                    if found:
                        problems.append(found)
            elif flag == "--volumes-from":
                unread.append(f"--volumes-from {value} mounts what another container holds, which the file does "
                              "not show (a controller running in a container passes its own volumes this way)")
                mounts.append(f"the volumes of {value}")
            elif flag in ("--network", "--net"):
                networks.append(value)
                if value == "host":
                    problems.append("host networking")
            elif flag in _HOST_NAMESPACES and value == "host":
                problems.append(_HOST_NAMESPACES[flag])
            elif flag == "--cap-add":
                caps = {c.strip().upper().removeprefix("CAP_") for c in value.split(",")}
                if caps & _HOST_CAPS:
                    problems.append("extra capabilities")
            elif flag in ("--device", "--device-cgroup-rule"):
                problems.append("a host device")
            elif flag == "--security-opt":
                v = value.replace(":", "=", 1)
                if v in ("seccomp=unconfined", "apparmor=unconfined", "label=disable", "systempaths=unconfined") \
                        or v.startswith("label=type"):
                    problems.append("an unconfined security profile")
            continue
        if w.startswith("-") and len(w) > 1:
            # Short options, possibly grouped (-itv /x:/y, -v/x:/y): docker's parser reads them one by one.
            for k, ch in enumerate(w[1:], start=1):
                if ch in _SHORT_BOOL:
                    continue
                if ch in _SHORT_VALUE:
                    value = w[k + 1:].lstrip("=") if k + 1 < len(w) else (words[i] if i < len(words) else "")
                    if k + 1 >= len(w):
                        i += 1
                    if ch == "v":
                        _volume(value, problems, mounts)
                    break
                unread.append(f"docker run option -{ch} is not one the checker reads")
                break


def _volume(value: str, problems: list, mounts: list) -> None:
    """`-v SOURCE:TARGET[:OPTIONS]`. One field is an anonymous volume at that path in the container; a source
    without a slash is a named volume."""
    if _WINDOWS_PATH.match(value):
        cut = value.find(":", 2)
        source, rest = (value, "") if cut == -1 else (value[:cut], value[cut + 1:])
    elif value.startswith("\\\\") or value.startswith("//./"):
        cut = value.find(":")
        source, rest = (value, "") if cut == -1 else (value[:cut], value[cut + 1:])
    else:
        source, sep, rest = value.partition(":")
        if not sep:
            return
    if not (source.startswith(("/", ".", "~", "$", "\\")) or _WINDOWS_PATH.match(source)):
        return
    mounts.append(source)
    ro = "ro" in rest.rsplit(":", 1)[-1].split(",") if ":" in rest else False
    found = _host_path(source, ro)
    if found:
        problems.append(found)


def docker_options(args: str) -> tuple[list[str], list[str], list[str]]:
    """(what reaches the host, why the options cannot all be read, the networks named) for docker run options
    written in a Jenkinsfile. A value the file does not fix, or text that cannot be split for certain, is a
    reason, never a pass."""
    found = _docker_read(args)
    return list(found[0]), list(found[1]), list(found[2])


def docker_bind_sources(args: str) -> list[str]:
    """The host paths that docker run options bind into a container; named volumes are not host paths."""
    return list(_docker_read(args)[3])


@functools.lru_cache(maxsize=512)
def _docker_read(args: str) -> tuple[list, list, list, list]:
    problems: list[str] = []
    unread: list[str] = []
    networks: list[str] = []
    mounts: list[str] = []
    if "${" in args or "$(" in args or "`" in args:
        unread.append("docker run options are computed at run time")
    readings, why = _split_options(args)
    unread += why
    for n, words in enumerate(readings):
        nets: list[str] = []
        _read_words(words, problems, unread if n == 0 else [], nets, mounts)
        if n == 0:
            networks = nets
        elif nets != networks:
            networks = networks + ["(read differently)"]
    return (list(dict.fromkeys(problems)), list(dict.fromkeys(unread)), networks, list(dict.fromkeys(mounts)))


def pod_settings(text: str) -> tuple[list[str], str | None, bool, list[str]]:
    found, account, no_token, unread = _pod_settings(text)
    return list(found), account, no_token, list(unread)


@functools.lru_cache(maxsize=256)
def _pod_settings(text: str) -> tuple:
    """(what reaches the host, the service account named, whether the token is not mounted, why the spec could
    not all be read) for a pod spec. The spec is read as YAML, which JSON also is (flagship slice 2d.2j: a JSON
    spec's `"privileged": true` was missed by the line patterns); text that does not parse falls back to the
    patterns and says so. Only the first document is the pod; a later one is reported, not read."""
    unread: list[str] = []
    depth = max((len(m.group(0)) for m in re.finditer(r"[\[{]+|^[ \t]+", text, re.M)), default=0)
    docs = None
    if depth > 400:
        unread.append("the pod spec is nested too deeply to read")
    elif text.strip():
        try:
            docs = [d for d in yaml.safe_load_all(text) if d is not None]
        except Exception:      # not YAML (or a tag safe_load refuses): the patterns below still read it
            docs = None
    else:
        docs = []
    if docs is None or any(not isinstance(d, dict) for d in docs):
        if text.strip() and depth <= 400:
            unread.append("the pod spec could not be read as YAML")
        found = [label for rx, label in POD_HOST_SETTINGS if rx.search(text)]
        account = re.search(r"[\"']?serviceAccount(?:Name)?[\"']?\s*:\s*['\"]?([\w.-]+)", text)
        no_token = bool(re.search(r"[\"']?automountServiceAccountToken[\"']?\s*:\s*['\"]?false", text)) and \
            "serviceAccountToken" not in text.replace("automountServiceAccountToken", "")
        return found, account.group(1) if account else None, no_token, unread
    if len(docs) > 1:
        unread.append("the pod spec holds more than one YAML document; only the first is read for the token")
    found: list[str] = []
    account = None
    no_token = False
    projected = False
    for n, doc in enumerate(docs):
        stack: list = [doc]
        seen = 0
        while stack:
            seen += 1
            if seen > 50_000:
                unread.append("the pod spec is too large to read in full")
                break
            node = stack.pop()
            if isinstance(node, list):
                stack += node
                continue
            if not isinstance(node, dict):
                continue
            for key, value in node.items():
                key = str(key)
                true = value is True or (isinstance(value, int) and not isinstance(value, bool) and value != 0) or (
                    isinstance(value, str) and value.strip().lower() in ("true", "yes", "on", "1"))
                if key == "privileged" and true:
                    found.append("a privileged container")
                elif key == "allowPrivilegeEscalation" and true:
                    found.append("allowPrivilegeEscalation: true")
                elif key in ("hostNetwork", "hostPID", "hostIPC") and true:
                    found.append({"hostNetwork": "host networking", "hostPID": "the host PID namespace",
                                  "hostIPC": "the host IPC namespace"}[key])
                elif key == "hostPath":
                    path = value.get("path", "") if isinstance(value, dict) else str(value or "")
                    found.append("a mount of the Docker socket" if "docker.sock" in str(path) else
                                 "a mount of the host root file system" if _clean(str(path)) == "/" else
                                 "a hostPath volume")
                elif key == "add" and isinstance(value, list) and {str(c).upper().removeprefix("CAP_")
                                                                    for c in value} & _HOST_CAPS:
                    found.append("extra capabilities")
                elif key == "serviceAccountToken":
                    projected = True          # a projected token volume mounts a token whatever automount says
                elif n == 0 and key in ("serviceAccountName", "serviceAccount") and isinstance(value, str) \
                        and account is None:
                    account = value
                elif n == 0 and key == "automountServiceAccountToken" and (
                        value is False or (isinstance(value, str) and value.strip().lower() == "false")):
                    no_token = True
                stack.append(value)
    return list(dict.fromkeys(found)), account, no_token and not projected, list(dict.fromkeys(unread))


POD_HOST_SETTINGS = [
    (re.compile(r"[\"']?privileged[\"']?[ \t]*:[ \t]*[\"']?true\b", re.M), "a privileged container"),
    (re.compile(r"[\"']?allowPrivilegeEscalation[\"']?[ \t]*:[ \t]*[\"']?true\b", re.M),
     "allowPrivilegeEscalation: true"),
    (re.compile(r"[\"']?hostNetwork[\"']?[ \t]*:[ \t]*[\"']?true\b", re.M), "host networking"),
    (re.compile(r"[\"']?hostPID[\"']?[ \t]*:[ \t]*[\"']?true\b", re.M), "the host PID namespace"),
    (re.compile(r"[\"']?hostIPC[\"']?[ \t]*:[ \t]*[\"']?true\b", re.M), "the host IPC namespace"),
    (re.compile(r"docker\.sock"), "a mount of the Docker socket"),
    (re.compile(r"[\"']?hostPath[\"']?[ \t]*:", re.M), "a hostPath volume"),
    (re.compile(r"\b(SYS_ADMIN|SYS_PTRACE|NET_ADMIN)\b"), "extra capabilities"),
]


# OBAAF-JEN-008 (flagship slice 2d.2k).
PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
EXACT_NPM = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
EXACT_PIP = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*(?:\+[0-9A-Za-z.]+)?$")
# ${env.NAME} (Groovy reading the environment), ${NAME}, $NAME.
_REF = re.compile(r"\$\{env\.([A-Za-z_]\w*)\}|\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
# Commands of a script line: a line is cut at `&&`, `||` and `;`; a pipe stays inside its command.
_SEGMENTS = re.compile(r"&&|\|\||;")
# Commands that set variables other than by NAME=value (read, for, declare, printf -v, mapfile, unset), and
# those that may set any (eval, and source or `.` of a file not plainly outside the checkout): what they set
# is not a fixed value (the third and sixth reviews of 2d.2k).
_OTHER_ASSIGN = re.compile(r"^[ \t]*(?:(?:then|do|else|elif|\{|\()[ \t]+)*"
                           r"(read|for|select|declare|typeset|mapfile|readarray|unset|printf[ \t]+-v|source|\.|eval)"
                           r"(?=[ \t]|$)(.*)$")
# A shell assignment at the start of a command (after `then`, `do`, `else`, `{`): its literal value, single
# quoted (never expanded), double quoted or bare; any other value makes the variable unknown.
_ASSIGN_START = re.compile(r"^[ \t]*(?:(?:then|do|else|elif|\{|\()[ \t]+)*(?:export[ \t]+|local[ \t]+|readonly[ \t]+)?"
                           r"([A-Za-z_]\w*)=")
_SHELL_ASSIGN = re.compile(r"^[ \t]*(?:(?:then|do|else|elif|\{|\()[ \t]+)*(?:export[ \t]+|local[ \t]+|readonly[ \t]+)?"
                           r"([A-Za-z_]\w*)=(?:'([^']*)'|\"([^\"$`\\]*)\"|([^\s'\"$`;&|\\]*))[ \t]*$")
# Subcommands of npm, pnpm, yarn, bun, pip, pipx and uv, by what they do with a package named after them.
_SUBCOMMAND = re.compile(r"(?:(?<=\s)|^)([a-z]+)(?=\s|$)")
_INSTALL_WORDS = {"install", "i", "add", "a", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
                  "isntall", "dlx", "x", "exec", "run", "inject", "global", "tool"}
_UPDATE_WORDS = {"update", "upgrade", "up"}
_OTHER_WORDS = {"uninstall", "remove", "rm", "r", "un", "unlink", "ls", "list", "la", "ll", "view", "info", "show",
                "outdated", "why", "explain", "search", "audit", "cache", "config", "help", "download", "freeze",
                "check", "prune", "dedupe", "pack", "publish", "root", "prefix", "bin", "docs", "home", "repo",
                "fund", "wheel", "hash", "inspect", "uninject"}
_RUNNERS = {"npx", "bunx", "uvx", "pnpx"}
# Subcommands of npm, pnpm, yarn and bun that install what a package.json asks for.
_MANIFEST_INSTALLS = {"install", "i", "ci", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta",
                      "isntal", "isntall", "clean-install", "install-clean", "it", "install-test", "cit"}
_INSTALLER_NAMES = {"npm", "pnpm", "yarn", "bun", "npx", "bunx", "pip", "pip3", "pipx", "uv", "uvx", "pnpx"}
_AGENT_SELF_UPDATE = re.compile(r"^(?:\S*/)?claude[ \t]+(?:update|upgrade)\b")
# What may stand before a command in the same segment: keywords, assignments, and wrappers that run the
# rest (sudo, env, timeout, nohup, exec, time, nice, stdbuf, xargs, bash -c "..."), each with its options.
_COMMAND_PREFIX = re.compile(
    r"^[ \t]*(?:(?:then|do|else|elif|if|while|until|!|\{|\()(?=[ \t])|[A-Za-z_]\w*=(?:'[^']*'|\"[^\"]*\"|\S*)|"
    r"sudo(?:[ \t]+(?:-[ugCDhprtUT][ \t]+\S+|--[\w-]+=\S+|-[A-Za-z]+|--[\w-]+))*|"
    r"env(?:[ \t]+(?:-[uCS][ \t]*\S+|--(?:unset|chdir|split-string)[= ]\S+|-\S+|[A-Za-z_]\w*=\S*))*|"
    r"timeout(?:[ \t]+(?:-[ks][ \t]*\S+|--(?:kill-after|signal)[= ]\S+|-\S+))*[ \t]+\S+|"
    r"xargs(?:[ \t]+(?:-[IEdLnPsa][ \t]*\S+|--\S+|-\S+))*|"
    r"nohup|exec|time|nice(?:[ \t]+-n[ \t]*\S+)?|stdbuf(?:[ \t]+-\S+)*|"
    r"(?:\S*/)?(?:ba|z|da)?sh[ \t]+-c[ \t]+[\"']?|[\"'])")
# docker, podman and nerdctl run, create and pull, where a command starts: the start of a line, after a
# separator, `$(`, a quote (bash -c "..."), sudo, exec, time or nohup; global options before the subcommand.
_CONTAINER_CMD = re.compile(
    r"^(?:[\w./-]*/)?(docker|podman|nerdctl)"
    r"((?:[ \t]+--?[A-Za-z][\w-]*(?:=\S*|[ \t]+(?!(?:run|create|pull|container|image)\b)[^\s-]\S*)?)*)"
    r"[ \t]+(?:(?:container|image)[ \t]+)?(run|create|pull)(?=[ \t]|$)", re.I)
_BUILD_CMD = re.compile(r"^(?:\S*/)?(?:docker|podman|nerdctl|buildah)(?:[ \t]+(?:image|buildx))?[ \t]+(?:build|bud)\b")
_TAG_OPTION = re.compile(r"(?:^|\s)(?:-t|--tag)(?:[ \t]+|=)(['\"]?)([^\s'\"]+)\1")
_TAG_CMD = re.compile(r"^(?:\S*/)?(?:docker|podman|nerdctl)(?:[ \t]+image)?[ \t]+tag[ \t]+\S+[ \t]+(['\"]?)([^\s'\"]+)\1")
# Where a command ends and another starts in a script.
_COMMAND_SPLIT = re.compile(r"&&|\|\||[;&|\n(`]|\$\(")
_DOCKER_BOOL = {"--rm", "-d", "--detach", "-i", "--interactive", "-t", "--tty", "--privileged", "--init",
                "--read-only", "-P", "--publish-all", "-q", "--quiet", "--no-healthcheck", "--oom-kill-disable",
                "--sig-proxy", "--disable-content-trust", "--all-tags", "--help", "--use-api-socket"}
_DOCKER_VALUE = {"--add-host", "--annotation", "--attach", "--blkio-weight", "--cap-add", "--cap-drop",
                 "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota", "--cpu-shares", "-c",
                 "--cpus", "--cpuset-cpus", "--cpuset-mems", "--device", "--device-cgroup-rule", "--dns",
                 "--dns-option", "--dns-search", "--domainname", "--entrypoint", "-e", "--env", "--env-file",
                 "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval", "--health-retries",
                 "--health-start-period", "--health-timeout", "-h", "--hostname", "--ip", "--ip6", "--ipc",
                 "--isolation", "--kernel-memory", "-l", "--label", "--label-file", "--link", "--log-driver",
                 "--log-opt", "--mac-address", "-m", "--memory", "--memory-reservation", "--memory-swap",
                 "--memory-swappiness", "--mount", "--name", "--network", "--net", "--network-alias", "--pid",
                 "--pids-limit", "--platform", "-p", "--publish", "--pull", "--restart", "--runtime",
                 "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl",
                 "--tmpfs", "--ulimit", "-u", "--user", "--userns", "--uts", "-v", "--volume", "--volume-driver",
                 "--volumes-from", "-w", "--workdir", "--detach-keys"}
# docker build options: those that take a value, and those that do not; any other makes the Dockerfile unknown.
_BUILD_VALUE = {"-t", "--tag", "--build-arg", "--target", "--label", "--platform", "--network", "--cache-from",
                "--cache-to", "--secret", "--ssh", "--add-host", "--iidfile", "--progress", "--shm-size", "--ulimit",
                "--cpuset-cpus", "--cpu-shares", "-m", "--memory", "--memory-swap", "--isolation", "--output", "-o",
                "--build-context", "--metadata-file", "--provenance", "--sbom", "--allow", "--annotation",
                "--cgroup-parent", "--builder"}
_BUILD_BOOL = {"-q", "--quiet", "--no-cache", "--pull", "--rm", "--force-rm", "--squash", "--compress", "--load",
               "--push", "--disable-content-trust", "--check"}
_PIP_INSTALL = re.compile(r"(?<![\w-])(?:pip3?|uv[ \t]+pip|python3?[ \t]+-m[ \t]+pip)(?:[ \t]+-\S+)*[ \t]+install\b")
_REQUIREMENT_FLAG = re.compile(r"(?:^|\s)(?:-r|--requirement|-c|--constraint)(?:[ \t]+|=)?(['\"]?)([^\s'\";&|]+)\1")
_CD_WORKSPACE = re.compile(r"^(?:cd|pushd)[ \t]+[\"']?\$(?:\{(?:env\.)?WORKSPACE\}|WORKSPACE(?![\w]))"
                           r"(?:/([^\s\"']*))?[\"']?$")
_CD = re.compile(r"^[ \t]*(?:cd|pushd)[ \t]+(['\"]?)([^\s'\";&|]+)\1[ \t]*$")
_NPM_PREFIX = re.compile(r"(?:--prefix|-C|--cwd|--dir)(?:[ \t]+|=)(['\"]?)([^\s'\";&|]+)\1")
# Options of npm, pip and uv before the subcommand that take a value (`npm --loglevel info install`).
_INSTALLER_VALUE_OPTIONS = {"--loglevel", "--registry", "--prefix", "--cache", "--userconfig", "--globalconfig",
                            "--workspace", "-w", "--tag", "--cache-dir", "--index-url", "-i", "--extra-index-url",
                            "--find-links", "-f", "--target", "-t", "--python", "-p", "--proxy", "--cert",
                            "--client-cert", "--log", "--src", "--root", "--upgrade-strategy", "--trusted-host",
                            "--timeout", "--retries", "--platform", "--python-version", "--implementation", "--abi",
                            "--directory", "--project", "--config-file", "--cwd", "-C", "--dir", "--filter",
                            "--default-index", "--index", "--color", "--progress-bar"}
_NPM_INSTALL = re.compile(r"(?<![\w-])(?:npm[ \t]+(?:install|i|ci|add)|pnpm[ \t]+(?:install|i|add)|"
                          r"yarn(?:[ \t]+install)?|bun[ \t]+(?:install|i))(?=$|[ \t;&|])", re.M)
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")
_DOWNLOAD = re.compile(r"(?<![\w-])(curl|wget|irm|iwr|Invoke-WebRequest|Invoke-RestMethod)(?![\w-])", re.I)
# `[^\s|]`, not `\S`, before the shell's name: `\S*` ran on through every later `|` of the line, so a line of
# many pipes was quadratic (the review of slice 2d.5a: 400 KB took 97 s). A path holds no `|`.
_TO_SHELL = re.compile(r"\|[ \t]*(?:sudo[ \t]+(?:-[^\s|]+[ \t]+)*)?(?:[^\s|]*/)?(?:ba|z|da|k)?sh\b|\|[ \t]*iex\b|"
                       r"(?:ba|z)?sh[ \t]+<\(|(?:ba|z)?sh[ \t]+-c[ \t]+[\"']?\$\(", re.I)
_HEREDOC = re.compile(r"(?:^|(?<=\s))<<(-?)[\"']?([A-Za-z_]\w*)[\"']?")


def _shown(text: str, limit: int = 120) -> str:
    """Text from a file, as a finding shows it: quotes, backslashes and control characters escaped, so it
    cannot end the quoted part of a message or start a new line (the review of 2d.2k), and cut short."""
    out = []
    for c in str(text):
        if c in "'\\`":
            out.append("\\" + c)
        elif not c.isprintable():
            out.append(f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}")
        else:
            out.append(c)
    shown = "".join(out)
    return shown if len(shown) <= limit else shown[:limit] + "..."


def _global_update(command: str) -> bool:
    """`npm update -g` (pnpm, bun), with any options, and no package named: every global package moves."""
    words = re.split(r"[ \t]\d*(?:[<>]|&>)", " " + command)[0].split()     # `> /dev/null 2>&1` is not a word
    if not words or words[0].rsplit("/", 1)[-1] not in ("npm", "pnpm", "bun"):
        return False
    rest, i, verb = [], 1, None
    while i < len(words):
        w = words[i]
        if w.startswith("-"):
            rest.append(w)
            i += 2 if w in _INSTALLER_VALUE_OPTIONS else 1
            continue
        if verb is None:
            verb = w
        else:
            return False
        i += 1
    return verb in _UPDATE_WORDS and any(w in ("-g", "--global") or w.startswith("--location=global") for w in rest)


def _exact_version(ver: str) -> bool:
    """An exact version after a package name: `@1.2.3` (npm) or `==1.2.3`/`===x` (pip, spaces allowed);
    not a range, a tag, a wildcard or a value set at run time."""
    ver = ver.strip()
    if "$" in ver:
        return False
    if ver.startswith("@"):
        return bool(EXACT_NPM.match(ver[1:]))
    if ver.startswith("==="):
        return len(ver[3:].strip()) > 0
    if ver.startswith("=="):
        return bool(EXACT_PIP.match(ver[2:].strip()))
    return False


def _build_options(options: str) -> tuple:
    """(Dockerfile, build args) for docker.build's options: `-f`/`--file`, else Dockerfile in the build
    context; `--build-arg NAME=VALUE`. The Dockerfile is "?" when it cannot be told (an option the checker
    does not know, a value set at run time)."""
    try:
        words = shlex.split(options)
    except ValueError:
        return "?", {}
    file, context, args, i = None, ".", {}, 0
    while i < len(words):
        w = words[i]
        flag, eq, value = w.partition("=")
        if flag in ("-f", "--file"):
            file = value if eq else (words[i + 1] if i + 1 < len(words) else None)
            i += 1 if eq else 2
            continue
        if flag == "--build-arg":
            value = value if eq else (words[i + 1] if i + 1 < len(words) else "")
            name, _, val = value.partition("=")
            args[name] = val
            i += 1 if eq else 2
            continue
        if w.startswith("-"):
            if flag in _BUILD_BOOL or (eq and flag in _BUILD_VALUE):
                i += 1
            elif flag in _BUILD_VALUE:
                i += 2
            else:
                return "?", args
            continue
        context = w
        i += 1
    if file is None:
        file = context.rstrip("/") + "/Dockerfile" if context not in (".", "./") else "Dockerfile"
    if "$" in file or "$" in context:
        return "?", args
    return (file[2:] if file.startswith("./") else file), args


def _build_dockerfile(options: str) -> str:
    return _build_options(options)[0]


def _join(folder: str, rel: str) -> str:
    """`rel` inside the folder dir() moved into; "?" when that folder is computed."""
    if folder == "?":
        return "?"
    return "/".join(x for x in (folder, rel) if x and x != ".") if folder else rel


@dataclass
class Unknown:
    rule: str          # a rule ID, or ALL when nothing in the file can be decided
    line: int
    reason: str


@dataclass
class Info:
    """What one step does, as far as the file shows."""
    use: StepUse
    index: int
    shell: bool = False
    script: str = ""
    exprs: list = field(default_factory=list)
    dynamic: bool = False
    ai: str | None = None
    publish: str | None = None
    verify: str | None = None      # full | provenance
    swallowed: str | None = None   # why a failure of this step does not stop the build
    push: bool = False
    trigger: str | None = None
    unresolved: bool = False

    @property
    def ctx(self):
        return self.use.ctx

    @property
    def line(self) -> int:
        return self.use.line

    @property
    def runs_code(self) -> bool:
        return self.shell or bool(self.ai) or self.use.name.startswith("docker.build")


# Steps that copy files to another host. They are not counted as publishing on their own, because
# they mostly copy reports and logs; in a stage declared a release lane they are the upload.
TRANSFER_STEPS = ("sshPublisher", "ftpPublisher")


# Names in an interpolated expression, outside quoted text, that are not called (`f(`, `tool "x"`).
_QUOTED = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")
_NAME_IN_EXPR = re.compile(r"(?<![.\w$])[A-Za-z_]\w*\b(?!\s*\(|\s+(?!(?:as|in|instanceof)\b)[\"'\w$])")


def _skip_quoted(expr: str, i: int, depth: int = 0) -> int:
    """The index just after the quoted text that starts at `i`, following `${...}` inside double quotes."""
    n = len(expr)
    triple = expr.startswith(expr[i] * 3, i)
    q = expr[i] * 3 if triple else expr[i]
    j = i + len(q)
    while j < n and not expr.startswith(q, j):
        if expr[j] == "\\":
            j += 2
        elif q[0] == '"' and expr.startswith("${", j) and depth < 50:
            j = _skip_braces(expr, j + 2, depth + 1)
        else:
            j += 1
    return min(j + len(q), n)


def _skip_braces(expr: str, k: int, depth: int = 0) -> int:
    """The index just after the `}` that closes a `${` whose body starts at `k`."""
    n, level = len(expr), 1
    while k < n and level:
        ch = expr[k]
        if ch == "\\":
            k += 2
            continue
        if ch in "\"'" and depth < 50:
            k = _skip_quoted(expr, k, depth + 1)
            continue
        level += 1 if ch == "{" else -1 if ch == "}" else 0
        k += 1
    return k


_DOLLAR_NAME = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")


@functools.lru_cache(maxsize=4096)
def _unquoted(expr: str, depth: int = 0) -> str:
    """The expression with each quoted text replaced by what it interpolates (`"a-${v}"` and `"a-$v"` by `v`,
    each read the same way again), and text that interpolates nothing by a placeholder; quotes and `${...}` are
    followed together, so a quote inside `${...}` does not end the text (the third to fifth reviews of
    2d.2i). Past 50 levels the rest is left as it is, so its names are still read."""
    if depth > 50:
        return expr
    out: list[str] = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c == "'":
            # A placeholder that reads as an argument: `tool 'maven'` is a step called with one.
            i = _skip_quoted(expr, i, depth)
            out.append(" _q_ ")
            continue
        if c == '"':
            q = '"""' if expr.startswith('"""', i) else '"'
            j = i + len(q)
            parts: list[str] = []
            while j < n and not expr.startswith(q, j):
                if expr[j] == "\\":
                    j += 2
                elif expr.startswith("${", j):
                    k = _skip_braces(expr, j + 2, depth + 1)
                    body = expr[j + 2:k - 1] if k <= n and expr[k - 1:k] == "}" else expr[j + 2:k]
                    parts.append(_unquoted(body, depth + 1))
                    j = k
                elif expr[j] == "$" and j + 1 < n and (expr[j + 1].isalpha() or expr[j + 1] == "_"):
                    m = _DOLLAR_NAME.match(expr, j + 1)      # in place: no copy of the rest of the text
                    parts.append(m.group(0))
                    j = m.end()
                else:
                    j += 1
            i = min(j + len(q), n)
            # What it interpolates, ended by `;` so a name after it is not read as a step call; a text that
            # interpolates nothing reads as an argument, as above.
            out.append(" " + " ; ".join(parts) + " ; " if parts else " _q_ ")
            continue
        out.append(c)
        i += 1
    return "".join(out)
# Names a Jenkinsfile can read without defining them, which hold no secret of a binding.
_JENKINS_GLOBALS = {"env", "params", "currentBuild", "scm", "docker", "pipeline", "manager", "build", "true", "false",
                    "null", "this", "steps", "binding", "args", "out", "jenkins", "hudson", "Jenkins", "workspace",
                    "new", "in", "as", "instanceof", "def", "return"}


def stage_label(stage: tuple) -> str:
    return " > ".join(stage) if stage else "pipeline"


def script_parts(node) -> tuple[str, list, bool]:
    """(text, interpolated expressions, dynamic) of a script argument. Groovy concatenation
    (`"make " + env.X`) counts as interpolation, and so does any value a computed script reads
    (String.format('...', env.X)). dynamic: some text comes from a variable or call. Iterative."""
    if node is None:
        return "", [], True
    texts: list[str] = []
    exprs: list = []
    dynamic = False
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, Str):
            texts.append(n.text())
            exprs += n.exprs
        elif isinstance(n, Binary) and n.op == "+":
            stack += [n.right, n.left]
        elif isinstance(n, Call) and isinstance(n.callee, Prop) and not n.args and \
                n.callee.name in ("stripIndent", "trim", "stripMargin", "toString", "replaceAll", "denormalize"):
            stack.append(n.callee.target)        # """...""".stripIndent().trim()
        else:
            p = path_of(n)
            texts.append("${" + (p or "...") + "}")
            exprs += [p] if p else source_texts(n)
            dynamic = True
    return "".join(texts), exprs, dynamic


def step_arg(call: Call, key: str):
    """A step argument given by name, or inside a map passed as the only argument: sh([script: ..])."""
    value = named_arg(call, key)
    if value is None and call.args and isinstance(call.args[0], MapLit):
        for k, v in call.args[0].entries:
            if k == key:
                return v
    return value


def base_stage(stage: tuple) -> tuple:
    """A stage without its post blocks: ('Build', 'post success') -> ('Build',)."""
    out = list(stage)
    while out and out[-1].startswith("post "):
        out.pop()
    return tuple(out)


def guard_keys(step) -> set:
    """The conditions a step runs under, as they are compared (flagship slice 2d.2l)."""
    return {guard_key(g) for g in step.ctx.guards}


def concurrent(a, b) -> bool:
    """Whether two steps are in different branches of the same parallel block."""
    for x, y in zip(a.branch, b.branch):
        if x[0] == y[0] and x[1] != y[1]:
            return True
        if x != y:
            return False
    return False


# Terms and operators of a Jenkins label expression (flagship slice 2d.2j). A label may hold `-` (built-in) but
# not the `->` operator.
_LABEL_TOKEN = re.compile(r"&&|\|\||<->|->|!|\(|\)|\"[^\"]*\"|[^\s&|!()<>\"-]+(?:-(?!>)[^\s&|!()<>\"-]*)*|-")


def _label_tree(label: str):
    """A Jenkins label expression as a tree, by its operators from tightest to loosest: `!`, `&&`, `||`, `->`,
    `<->`, with brackets. None when it cannot be read (flagship slice 2d.2j)."""
    tokens = _LABEL_TOKEN.findall(label)
    if "".join(tokens) != re.sub(r"\s+", "", label) or not tokens:
        return None
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def binary(op, lower):
        nonlocal pos
        left = lower()
        while peek() == op:
            pos += 1
            left = (op, left, lower())
        return left

    def unary():
        nonlocal pos
        tok = peek()
        if tok == "!":
            pos += 1
            return ("!", unary())
        if tok == "(":
            pos += 1
            inner = binary("<->", lambda: binary("->", lambda: binary("||", lambda: binary("&&", unary))))
            if peek() != ")":
                raise ValueError(label)
            pos += 1
            return inner
        if tok is None or tok in ("&&", "||", "->", "<->", ")", "-"):
            raise ValueError(label)
        pos += 1
        return ("atom", tok.strip('"'))

    try:
        tree = binary("<->", lambda: binary("->", lambda: binary("||", lambda: binary("&&", unary))))
    except (ValueError, RecursionError):
        return None
    return tree if pos == len(tokens) else None


def _required(tree) -> set:
    """The labels every agent the expression selects must carry."""
    op = tree[0]
    if op == "atom":
        return {tree[1]}
    if op == "&&":
        return _required(tree[1]) | _required(tree[2])
    if op == "||":
        return _required(tree[1]) & _required(tree[2])
    return set()           # `!a`, `a -> b` (`!a || b`), `a <-> b` (both false holds) require nothing


def _positive(tree, sign: bool = True) -> set:
    """The labels the expression names where a match can require them: under no negation, or two, on the
    right of `->`, on either side of `<->`."""
    op = tree[0]
    if op == "atom":
        return {tree[1].lower()} if sign else set()
    if op == "!":
        return _positive(tree[1], not sign)
    if op == "->":
        return _positive(tree[1], not sign) | _positive(tree[2], sign)
    if op == "<->":
        return set().union(*(_positive(t, b) for t in tree[1:] for b in (True, False)))
    return _positive(tree[1], sign) | _positive(tree[2], sign)


def _possible_on(tree, present: set) -> set:
    """Truth values on the built-in node when it carries the controller labels in `present` and not the others,
    with any other label it may also carry."""
    op = tree[0]
    if op == "atom":
        name = tree[1].lower()
        if name in CONTROLLER_LABELS:
            return {name in present}
        return {True, False}
    if op == "!":
        return {not v for v in _possible_on(tree[1], present)}
    a, b = _possible_on(tree[1], present), _possible_on(tree[2], present)
    combine = {"&&": lambda x, y: x and y, "||": lambda x, y: x or y, "->": lambda x, y: (not x) or y,
               "<->": lambda x, y: x == y}[op]
    return {combine(x, y) for x in a for y in b}


def controller_label(label: str) -> str | None:
    """"exact" for the built-in node's own label; "expression" for a label expression that names it and can
    hold on it (`built-in || linux`, `linux -> built-in`); None otherwise, also when it cannot be read."""
    text = label.strip()
    if text.lower() in CONTROLLER_LABELS:
        return "exact"
    tree = _label_tree(text)
    if tree is None or not (_positive(tree) & CONTROLLER_LABELS):
        return None
    # The built-in node carries `built-in` since Jenkins 2.307, `master` before it, and both where an
    # administrator kept the old label: an expression that names one of them where a match can require it, and
    # holds on any of these, can place work there (the third review of 2d.2j: `built-in && !master`).
    holds = any(True in _possible_on(tree, set(labels)) for labels in ({"built-in"}, {"master"}, CONTROLLER_LABELS))
    return "expression" if holds else None


@functools.lru_cache(maxsize=4096)
def _label_terms(label: str) -> frozenset | None:
    tree = _label_tree(label)
    if tree is None:
        return None
    return frozenset(_required(tree)) or None


def label_terms(label: str) -> set | None:
    """The labels a label expression requires every agent it selects to carry; None when it requires none
    (`!windows`, `docker -> linux`, `linux || !linux`) or cannot be read, which selects like `agent any`.
    Whitespace, brackets and quotes do not make two expressions different."""
    terms = _label_terms(label)
    return set(terms) if terms is not None else None


def _last_command(script: str, start: int) -> bool:
    """Whether nothing but blank lines and comments follows position `start`'s line in the script."""
    end = script.find("\n", start)
    if end == -1:
        return True
    rest = [ln.strip() for ln in script[end + 1:].splitlines()]
    return all(not ln or ln.startswith(("#", "REM ", "::")) for ln in rest)


class JenkinsRules:
    def __init__(self, path: str, pipeline: Pipeline, catalog: Catalog, root: Path | None,
                 extra_agents: dict | None = None, lane_overrides: dict | None = None) -> None:
        self.path = path
        self.p = pipeline
        self.catalog = catalog
        self._script_texts: dict[int, tuple] = {}     # id(call) -> (call, the script as the shell reads it)
        self.detection = catalog.detection
        self.root = root
        extra_agents = extra_agents or {}
        self.agent_cmds = [re.compile(x, re.M) for x in
                           list(self.detection.get("agent_commands", [])) + list(extra_agents.get("commands") or [])]
        self.agent_steps = set(extra_agents.get("steps") or []) | set(self.detection.get("jenkins_agent_steps", []))
        self.upload_cmds = [re.compile(x, re.M) for x in list(self.detection.get("upload_commands", []))
                            + list(self.detection.get("jenkins_upload_commands", []))]
        self.upload_steps = set(self.detection.get("jenkins_upload_steps", []))
        self.verify_cmds = [re.compile(x, re.M) for x in self.detection.get("verify_commands", [])]
        self.release_verify = [re.compile(x) for x in self.detection.get("release_verify_commands", [])]
        # A package name, its extras (`aider-chat[playwright]`) and any version after it, in npm's form
        # (`@1.2.3`, `@^1`, `@latest`) or PEP 440's (`==`, `~=`, `>=`, ..., spaces allowed). A name without a
        # scope matches as pip compares names, ignoring case and runs of `-`, `_` and `.` (flagship slice 2d.2k).
        def name_pattern(pkg: str) -> str:
            if pkg.startswith("@"):
                return re.escape(pkg)
            return "(?i:" + r"[-_.]+".join(re.escape(x) for x in re.split(r"[-_.]+", pkg)) + ")"
        self.packages = [(pkg, re.compile(r"(?<![\w@/.-])" + name_pattern(pkg) + r"(?:\[[^\]\s'\"]*\])?"
                                          r"(?P<ver>@[^\s;&|'\"]*|[ \t]*(?:===|==|~=|!=|>=|<=|>|<)[ \t]*[^\s;&|'\"]*)?"
                                          r"(?=[\s;&|'\",)]|$)"))
                         for pkg in self.detection.get("agent_packages", [])]
        self.agent_package_names = set(self.detection.get("agent_packages", []))
        self.install_urls = [re.compile(x, re.I) for x in self.detection.get("agent_install_urls", [])]
        self._line = 1                 # the step whose script OBAAF-JEN-008 is reading, for its unknowns
        self._agent_installed = False  # an earlier step installed an agent CLI (for `npm update -g`)
        self._local_images: set = set()  # tags the job builds itself
        self._pod_cache: dict = {}
        self._dockerfile_cache: dict = {}
        self._script_cache: dict = {}
        self._req_cache: dict = {}
        self._package_cache: dict = {}
        self._agent_words = re.compile(r"(?<![\w-])(claude|gemini|codex|opencode|aider|copilot|qodo)(?![\w])", re.I)
        self.lane_overrides = lane_overrides or {}
        self.findings: list[Finding] = []
        self.unknowns: list[Unknown] = []
        self.applicable: set[str] = set()
        self.infos: list[Info] = []
        self._seen: set = set()
        self._files: dict = {}
        self.by_agent: dict[int, list[Info]] = {}
        self.by_stage: dict[tuple, list[Info]] = {}
        self.publishing_stages: set = set()
        self._elsewhere: set | None = None

    # ------------------------------------------------------------------ plumbing
    def add(self, rule: str, line: int, message: str, stage: tuple | None = None, severity: str | None = None,
            step: str | None = None) -> None:
        key = (rule, line, message)
        if key in self._seen:      # a method of the file expanded at several calls
            return
        self._seen.add(key)
        self.findings.append(Finding(rule=rule, severity=severity or self.catalog.rules[rule]["severity"],
                                     path=self.path, line=line or 1, message=message,
                                     job=stage_label(stage) if stage is not None else None, step=step,
                                     scope="stage"))

    def unknown(self, rule: str, line: int, reason: str) -> None:
        key = (rule, line, reason)
        if key in self._seen:
            return
        self._seen.add(key)
        self.unknowns.append(Unknown(rule, line or 1, reason))

    def run(self) -> tuple[list[Finding], list[Unknown], set[str]]:
        self.classify()
        self.file_unknowns()
        self.credentials_exposed()        # JEN-001
        self.controller_and_placement()   # JEN-002
        self.agent_effects()              # JEN-003
        self.pipeline_code()              # JEN-004
        self.approvals()                  # JEN-005
        self.host_access()                # JEN-006
        self.agent_egress()               # JEN-007
        self.mutable_references()         # JEN-008
        self.injection()                  # JEN-009
        self.artifact_transfer()          # JEN-010
        self.failure_paths()              # JEN-011
        self.provenance_check()           # JEN-012
        self.secret_interpolation()       # JEN-013
        self.signing_keys()               # JEN-014
        self.webhook_tokens()             # JEN-015
        return self.findings, self.unknowns, self.applicable

    # ------------------------------------------------------------------ classification
    def classify(self) -> None:
        defined = self.p.local_names
        # A method of the file called many times records the same step once per call; what a step is
        # depends only on its call, so it is worked out once (flagship slice 2d.2i: a 2.9 KB file of
        # nested calls took 7.5 seconds).
        seen: dict[int, tuple] = {}
        for index, use in enumerate(self.p.steps):
            info = Info(use, index)
            call = use.call
            name = use.name
            if name in SHELL_STEPS:
                info.shell = True
                if _truthy(step_arg(call, "returnStatus")):
                    info.swallowed = "returnStatus: true"
            if use.ctx.swallowed:
                info.swallowed = use.ctx.swallowed
            hit = seen.get(id(call))
            if hit is not None and hit[0] is call and hit[1] == name:
                info.script, info.exprs, info.dynamic, info.ai, info.publish, info.verify, info.push = hit[2:]
            else:
                if info.shell:
                    info.script, info.exprs, info.dynamic = script_parts(shell_script(call))
                info.ai = self._ai(info)
                info.publish = self._publish(info)
                info.verify = self._verify(info)
                info.push = bool(info.shell and GIT_PUSH.search(info.script))
                seen[id(call)] = (call, name, info.script, info.exprs, info.dynamic, info.ai, info.publish,
                                  info.verify, info.push)
            if name == "build":
                job = named_arg(call, "job") or first_arg(call)
                info.trigger = literal(job) or "a computed job name"
            # A call the file does not define and the checker does not know: most likely a shared-library
            # step, whose code is not in this file. Method calls on a step's result (sh(...).trim()) and
            # on local variables are not steps.
            receiver_is_call = isinstance(call.callee, Prop) and isinstance(call.callee.target, Call)
            base = name.split(".")[0]
            if name and not receiver_is_call and not name.startswith("new ") and name not in known.KNOWN_STEPS \
                    and base not in defined and base not in known.KNOWN_OBJECTS and name not in self.agent_steps \
                    and name not in self.upload_steps and not base[:1].isupper():
                info.unresolved = True
            self.infos.append(info)
        # A stage declared as an agent lane (OBAAF_LANE or configuration) runs agents in every code step.
        for info in self.infos:
            lanes = self.lanes_of(info.ctx)
            # A shell step, or a step whose code is not in this file (most likely a shared-library
            # step): in a stage declared an agent or release lane, that is where the agent runs or
            # the upload happens. Not in a post block, where such a step is most often a notice.
            code = info.shell or (info.unresolved and info.ctx.post is None)
            if "agent" in lanes and code and not info.ai:
                info.ai = "the stage is declared an agent lane"
            if "release" in lanes and (code or info.use.name in TRANSFER_STEPS) and not info.publish:
                info.publish = "the stage is declared a release lane"
        # Indexes, so no rule compares every step with every agent or stage.
        for info in self.infos:
            if info.ctx.agent is not None:
                self.by_agent.setdefault(id(info.ctx.agent), []).append(info)
            self.by_stage.setdefault(info.ctx.stage, []).append(info)
            if info.publish:
                self.publishing_stages.add(info.ctx.stage)

    def lane_keys(self, stage: tuple) -> list[str]:
        """The `lanes:` keys that apply to a step in `stage`: the file, the stage by its full label or
        its own name, and every stage it is nested in."""
        keys = [self.path, f"{self.path}#{stage_label(stage)}"]
        for depth in range(1, len(stage) + 1):
            keys += [f"{self.path}#{stage_label(stage[:depth])}", f"{self.path}#{stage[depth - 1]}"]
        return list(dict.fromkeys(keys))

    def lanes_of(self, ctx) -> set:
        """Every lane declared for a step: in the configuration, and with OBAAF_LANE anywhere on the
        way to the step. A declaration adds a lane and none hides another, as in a workflow; a value
        that is not a lane adds nothing."""
        values = [self.lane_overrides.get(key) for key in self.lane_keys(ctx.stage)]
        values += [value for value, _ in ctx.lanes]
        return {lane for lane in map(declared_lane, values) if lane}

    def _ai(self, info: Info) -> str | None:
        if info.use.name in self.detection.get("jenkins_agent_steps", []):
            return f"the {info.use.name} step runs an agent"
        if info.use.name in self.agent_steps:
            return f"step {info.use.name} is declared an agent in the checker configuration"
        if not info.shell:
            return None
        # The script as the shell reads it: continued lines joined, literal variables of this file put in
        # (flagship slice 2d.2i: `sh cmd` and `claude \\` + `-p` on the next line were not recognised).
        script = self.script_text(info)
        for rx in self.agent_cmds:
            m = rx.search(script)
            if m:
                return f"runs an agent CLI ({m.group(0).strip()})"
        for rel in self._scripts(info.script):
            text = self._read(rel)
            if text and any(rx.search(text) for rx in self.agent_cmds):
                return f"runs an agent in the script {rel}"
        return None

    def _publish(self, info: Info) -> str | None:
        name = info.use.name
        if name in self.upload_steps:
            return f"{name} step"
        if name.endswith(".push"):
            base = name.rsplit(".", 1)[0]
            if base.startswith("docker.") or base.split(".")[0] in self.p.docker_vars:
                return "docker push"
        if info.shell:
            for rx in self.upload_cmds:
                m = rx.search(info.script)
                if m:
                    return m.group(0).strip()
        return None

    def _verify(self, info: Info) -> str | None:
        """'full' or 'provenance' for a verification step; info.swallowed says why one cannot stop the
        build: `|| ...`, a pipe without pipefail, `set +e`, or a later command when the script does not
        stop at the first failure (a #! line without -e, bat, powershell)."""
        if not info.shell or not info.script:
            return None
        text = info.script
        kind = None
        errexit = info.use.name == "sh" and not text.lstrip().startswith("#!")
        if info.use.name == "sh" and text.lstrip().startswith("#!"):
            first = text.lstrip().splitlines()[0]
            errexit = bool(re.search(r"\s-[a-z]*e", first))
        if re.search(r"(^|[\n;&])\s*set\s+(-[a-z]*e|-o\s+errexit)\b", text):
            errexit = True
        pipefail = bool(re.search(r"set\s+(-[a-z]*o\s+pipefail|-o\s+pipefail)", text))
        for pattern in self.verify_cmds:
            for m in pattern.finditer(text):
                end = text.find("\n", m.end())
                rest = text[m.end(): None if end == -1 else end]
                before = text[: m.start()]
                why = None
                if re.search(r"(^|[\n;&])\s*set\s+\+e\b", before):
                    why = "set +e before the command"
                elif "||" in rest or re.search(r"(?<![&])&\s*$", rest):
                    why = "|| or & after the command"
                elif re.search(r"(?<![|])\|(?![|])", rest) and not pipefail:
                    why = "a pipe without pipefail: the step's status is the last command's"
                elif not errexit and not _last_command(text, m.start()):
                    why = (f"the {info.use.name} script does not stop at a failed command, and more commands "
                           "follow it")
                if why:
                    info.swallowed = info.swallowed or why
                    kind = kind or "swallowed"
                    continue
                if any(r.match(text, m.start()) for r in self.release_verify):
                    return "full"
                kind = "provenance"
        return kind

    def _scripts(self, script: str) -> list[str]:
        if self.root is None:
            return []
        from obaaf.checker import _copied_script_targets, _script_targets   # shared with the workflow checker
        out = _script_targets(script)
        try:
            out += _copied_script_targets(script, self.root)
        except Exception:      # best-effort: never let a helper stop the check
            pass
        return out

    def _read(self, rel: str) -> str | None:
        if self.root is None:
            return None
        if rel in self._files:
            return self._files[rel]
        self._files[rel] = None
        try:
            root = self.root.resolve()
            path = (self.root / rel).resolve()
            if root not in path.parents or not path.is_file():
                return None
            with path.open(encoding="utf-8", errors="replace") as fh:
                self._files[rel] = fh.read(200_000)
        except (OSError, RuntimeError):
            return None
        return self._files[rel]

    # ------------------------------------------------------------------ helpers
    def stages(self) -> dict:
        return self.by_stage

    def stage_publishes(self, stage: tuple) -> bool:
        return stage in self.publishing_stages

    def under(self, agent) -> list:
        return self.by_agent.get(id(agent), [])

    def gates(self, check: Info, target: Info) -> bool:
        """Whether a check step can stop `target`: it runs before it, its failure stops the build, it
        is not in a failure path or a sibling parallel branch, and every condition that could skip the
        check also guards the target."""
        return (check.index < target.index and not check.swallowed and check.ctx.post not in FAILURE_PATHS
                and not concurrent(check.ctx, target.ctx) and guard_keys(check) <= guard_keys(target))

    def bindings(self) -> dict[Binding, list[Info]]:
        out: dict[Binding, list[Info]] = {}
        for info in self.infos:
            for b in info.ctx.creds:
                out.setdefault(b, []).append(info)
        return out

    @staticmethod
    def ids(b: Binding) -> str:
        shown = [i for i in b.ids if i != "?"]
        return ", ".join(f"'{i}'" for i in shown) if shown else "computed credential IDs"

    def file_unknowns(self) -> None:
        for line, what in self.p.opaque:
            self.unknown(ALL, line, what)
        unresolved = [i for i in self.infos if i.unresolved]
        if unresolved:
            names = sorted({i.use.name for i in unresolved})
            shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
            self.unknown(ALL, unresolved[0].line,
                         f"calls {len(names)} step(s) that are not built into Jenkins or defined in this file "
                         f"({shown}); they are probably shared-library or plugin code the checker did not read")

    # ------------------------------------------------------------------ JEN-001
    def credentials_exposed(self) -> None:
        """One finding per binding, at its worst exposure. A step 'runs repository code' when it calls a
        build tool, test runner or script from the checkout; steps that only run fixed tools (curl, a
        vendor CLI) still expose the credential if a tool reads files from the checkout, so they are
        reported one level lower rather than dropped."""
        scopes = self.bindings()
        if scopes:
            self.applicable.add("OBAAF-JEN-001")
        # A step that runs an agent and takes a credential itself (aiAgent(apiCredentialsId: ...)).
        for info in self.infos:
            if not info.ai:
                continue
            for key in ("apiCredentialsId", "credentialsId"):
                cred = named_arg(info.use.call, key)
                if cred is None:
                    continue
                self.applicable.add("OBAAF-JEN-001")
                shown = f"'{literal(cred)}'" if literal(cred) else "a computed credential"
                yolo = path_of(named_arg(info.use.call, "yoloMode")) == "true"
                self.add("OBAAF-JEN-001", info.line,
                         f"The {info.use.name} step at line {info.line} gives the agent credential {shown} ({key})"
                         + (" and runs its tools without confirmation (yoloMode)" if yolo else "")
                         + ". Text the agent reads can make it use or disclose the credential.", info.ctx.stage,
                         severity="high")
        for b, infos in scopes.items():
            code = [i for i in infos if i.runs_code]
            where = f"bound by {b.how} (line {b.line}, {b.origin})"
            ai = [i for i in code if i.ai]
            if ai:
                first = ai[0]
                self.add("OBAAF-JEN-001", b.line,
                         f"Credential(s) {self.ids(b)} {where} are available to the AI agent at line {first.line} "
                         f"in stage '{stage_label(first.ctx.stage)}' ({first.ai}). Text the agent reads can make it "
                         "use or disclose them." + self._also(code, first), first.ctx.stage, severity="high")
                continue
            reached = [i for i in code if i.ctx.cr in (CR_YES, CR_POSSIBLE)]
            if reached:
                yes = any(i.ctx.cr == CR_YES for i in reached)
                repo = [i for i in reached if self.runs_repo_code(i)]
                first = (repo or reached)[0]
                levels = ["low", "medium", "high"]
                level = (2 if yes else 1) - (0 if repo else 1)
                when = ("run for change requests" if yes else
                        "nothing in the Jenkinsfile keeps away from change requests")
                how = ("It runs code from the checkout, which for a change request is the change's own code, so "
                       "its author can read the credential, even when Jenkins takes the Jenkinsfile from a trusted "
                       "branch." if repo else
                       "The steps seem to run fixed tools rather than code from the checkout; the credential is "
                       "still exposed if a tool reads configuration or scripts from the checkout.")
                cond = "" if yes else " This matters if the job builds pull requests."
                self.add("OBAAF-JEN-001", b.line,
                         f"Credential(s) {self.ids(b)} {where} are available to the step at line {first.line} in stage "
                         f"'{stage_label(first.ctx.stage)}', which {when}. {how}{cond}" + self._also(reached, first),
                         first.ctx.stage, severity=levels[max(level, 0)])
                continue
            unknown = [i for i in code if i.ctx.cr == CR_UNKNOWN]
            if unknown:
                self.unknown("OBAAF-JEN-001", unknown[0].ctx.cr_line or b.line,
                             f"credential(s) {self.ids(b)} (line {b.line}) reach steps whose stage condition the checker "
                             "cannot evaluate, so it cannot tell whether change requests reach them")
            hidden = [i for i in infos if i.unresolved and i.ctx.cr != CR_NO]
            if hidden:
                self.unknown("OBAAF-JEN-001", hidden[0].line,
                             f"credential(s) {self.ids(b)} (line {b.line}) are available to {hidden[0].use.name}, "
                             "whose code is not in this file")

    @staticmethod
    def _also(infos: list, first) -> str:
        others = sorted({stage_label(i.ctx.stage) for i in infos if i.ctx.stage != first.ctx.stage})
        if not others:
            return ""
        shown = ", ".join(f"'{o}'" for o in others[:3]) + (f" and {len(others) - 3} more" if len(others) > 3 else "")
        return f" The same binding also reaches stage(s) {shown}."

    def _reviewed_text(self, node) -> bool:
        """Code text the reviewed Jenkinsfile fixes: a string literal with no interpolation, a variable that
        holds one, or text read with readTrusted or libraryResource (whose pin is OBAAF-JEN-008's)."""
        if isinstance(node, Str):
            return not node.interpolated
        if isinstance(node, Name) and node.name in self.p.literals:
            return not self.p.literals[node.name].interpolated and node.name not in self.p.nonliteral_names
        if isinstance(node, Call):
            name = chain_name(node.callee) or ""
            return name.split(".")[-1] in ("readTrusted", "libraryResource") and \
                not name.startswith(("new ", "Eval."))
        return False

    def runs_repo_code(self, info: Info) -> bool:
        if info.ai or info.use.name.startswith("docker.build") or info.unresolved:
            return True
        return bool(info.shell and (REPO_CODE.search(info.script) or info.dynamic))

    # ------------------------------------------------------------------ JEN-002
    def controller_and_placement(self) -> None:
        self.applicable.add("OBAAF-JEN-002")
        floating = []
        labels: dict[str, list] = {}
        for agent, ctx in self.p.agents:
            under = self.under(agent)
            on_controller = controller_label(agent.label or "") if agent.kind != "kubernetes" else None
            if on_controller:
                risky = [i for i in under if i.ai or i.ctx.cr in (CR_YES, CR_POSSIBLE)]
                severity = "high" if risky or not under else "medium"
                why = ("steps that change requests or an AI agent can steer" if risky else
                       "steps from branches without change requests")
                where = ("runs on the controller (label '{}')" if on_controller == "exact" else
                         "can run on the controller (label expression '{}')").format(agent.label)
                self.add("OBAAF-JEN-002", agent.line,
                         f"Stage '{stage_label(ctx.stage)}' {where}, with "
                         f"{why}. Code on the built-in node can read $JENKINS_HOME, including the keys that decrypt "
                         "every stored credential.", ctx.stage, severity=severity)
            elif agent.kind in ("any", "unknown") or (agent.kind in ("label", "node") and (
                    not agent.label or "${" in agent.label or label_terms(agent.label) is None)):
                # A label expression that requires no label (`!windows`) selects like `agent any` (2d.2j).
                floating.append((agent, ctx))
            elif agent.kind in ("label", "node") and agent.label:
                labels.setdefault(agent.label, []).append((agent, ctx, under))
        exposed = sorted(label for label, uses in labels.items() if any(
            i.ai or (i.runs_code and i.ctx.cr in (CR_YES, CR_POSSIBLE)) for _, _, under in uses for i in under))
        if exposed:
            first = labels[exposed[0]][0][0]
            self.unknown("OBAAF-JEN-002", first.line,
                         f"agents labelled {', '.join(repr(x) for x in exposed)} run work that change requests or an "
                         "AI agent can steer; whether those agents are ephemeral, and whether other jobs run "
                         "privileged work on them, is controller configuration")
        if floating:
            agent, ctx = floating[0]
            self.unknown("OBAAF-JEN-002", agent.line,
                         f"{len(floating)} agent selection(s) (agent any, node without a label, a computed label, or a label "
                         "expression that requires none) "
                         "can place work on any agent, including the built-in node if it has executors; which agents "
                         "exist and who else uses them is controller configuration")
        # One persistent agent label shared by change-request work and privileged work.
        # An AI agent is steered by the text it reads, so its work counts like a change request's (flagship slice
        # 2d.2j, as the rule's own description and the unknown above already said). Work an agent alone steers
        # pairs only with another allocation: the agent's own stage holding a credential is OBAAF-JEN-001's.
        # Labels pair when they are the same text or require a common label (`linux && docker`, `linux`).
        entries = [(label, label_terms(label), a, c, under) for label, uses in labels.items() for a, c, under in uses]
        privileged = [e for e in entries if any(i.ctx.cr == CR_NO and (i.ctx.creds or i.publish) for i in e[4])]
        if not privileged:
            return
        # Indexed, so a file of thousands of allocations is not compared pair by pair.
        by_change: dict = {}
        by_agent: dict = {}
        term_index: dict = {}
        for e in entries:
            lu, tu, au, _, under = e
            if lu not in by_change and any(i.runs_code and i.ctx.cr in (CR_YES, CR_POSSIBLE) for i in under):
                by_change[lu] = e
            if any(i.ai for i in under):
                kept = by_agent.setdefault(lu, [])
                if len(kept) < 2 and all(x[2] is not au for x in kept):
                    kept.append(e)
            for term in tu or ():
                term_index.setdefault(term, set()).add(lu)
        done: set = set()
        for steer, table in (("change requests", by_change), ("an AI agent", by_agent)):
            for lp, tp, ap, cp, _ in privileged:
                if (lp, ap.line) in done:
                    continue
                candidates = [lp] + sorted({x for t in tp or () for x in term_index.get(t, ())} - {lp})
                for lu in candidates:
                    hit = table.get(lu)
                    if hit is None:
                        continue
                    u = hit if steer == "change requests" else next((x for x in hit if x[2] is not ap), None)
                    if u is None:
                        continue
                    tu, cu = u[1], u[3]
                    common = (tu & tp) if tu and tp else set()
                    done.add((lp, ap.line))
                    labelled = (f"Agents labelled '{lp}'" if lp == lu else
                                f"Agents labelled '{lu}' and '{lp}', which can be the same machines (both require "
                                f"{', '.join(repr(x) for x in sorted(common))}),")
                    if steer == "change requests":
                        self.add("OBAAF-JEN-002", ap.line,
                                 f"{labelled} run both work that change requests reach (stage "
                                 f"'{stage_label(cu.stage)}') and stage '{stage_label(cp.stage)}', which holds "
                                 "credentials or publishes. Code from a change request can leave files or processes on "
                                 "a persistent agent that the privileged stage then uses.", cp.stage, severity="medium")
                    else:
                        self.add("OBAAF-JEN-002", ap.line,
                                 f"{labelled} run both an AI agent (stage '{stage_label(cu.stage)}') and stage "
                                 f"'{stage_label(cp.stage)}', which holds credentials or publishes. An agent steered by "
                                 "what it reads can leave files or processes on a persistent agent that the privileged "
                                 "stage then uses.", cp.stage, severity="medium")
                    break

    # ------------------------------------------------------------------ JEN-003
    def ws_key(self, info: Info) -> tuple:
        """What a step shares files with (flagship slice 2d.2j): the node its workspace is on, since ws() on the
        same node is written by the same user; when the model knows no workspace for the step, its stage and
        that stage's post blocks, as the rule read every step before 2d.2j."""
        if info.ctx.ws:
            machine = self.p.workspaces[self.p.workspaces[info.ctx.ws].machine]
            if machine.kind == "kubernetes" and machine.custom and machine.custom.startswith(("claim:", "nfs:")):
                return ("volume", machine.custom)    # pods on one named claim share its directory
            return ("machine", machine.id)
        return ("stage", base_stage(info.ctx.stage))

    @staticmethod
    def may_follow(first: Info, later: Info) -> bool:
        """Whether `later` can run after `first` in the same build: later in the file's order, in a sibling
        parallel branch, or inside a loop, retry or waitUntil around both."""
        if later.index > first.index or concurrent(first.ctx, later.ctx):
            return True
        loops = {g for g in first.ctx.guards if g.startswith("loop ")} | set(first.ctx.repeats)
        return bool(loops & (set(later.ctx.guards) | set(later.ctx.repeats)))

    @staticmethod
    def stash_name(info: Info) -> tuple:
        """What a stash or unstash step names, ("stash", name) with "?" for a name the file does not fix; the
        build's own archived artifacts, which unarchive brings back, are ("archive", "?")."""
        if info.use.name in ("archiveArtifacts", "archive", "unarchive"):
            return ("archive", "?")
        call = info.use.call
        node = step_arg(call, "name")
        if node is None and call.args and not isinstance(call.args[0], MapLit):
            node = call.args[0]
        return ("stash", literal(node) if node is not None and literal(node) is not None else "?")

    def _where(self, info: Info) -> str:
        w = self.p.workspaces.get(info.ctx.ws)
        return w.how if w else "the same stage"

    def _cleaned(self, agent: Info, effect: Info) -> bool:
        """Whether the workspace is emptied between what the agent leaves in it and the effect of a later build:
        cleanWs() or deleteDir() at its root, before the effect and certain to run, or in a post always or
        cleanup block after the agent."""
        for info in self._cleans.get(effect.ctx.ws, ()):
            if self.gates(info, effect) or (info.ctx.post in ("always", "cleanup") and self.may_follow(agent, info)):
                return True
        return False

    @staticmethod
    def full_clean(info: Info) -> bool:
        """deleteDir(), a checkout that wipes the workspace first, or cleanWs() (or the WsCleanup step) that empties
        the whole workspace whatever the build's result: no patterns,
        no external command, no condition left false (the review of slice 2d.2j: `cleanWs(patterns: ...)` and
        `cleanWhenSuccess: false` keep `.git`)."""
        if info.ctx.dir:
            return False
        if info.use.name == "deleteDir":
            return True
        call = info.use.call
        entries_all = list(call.named) + ([(k, v) for k, v in call.args[0].entries]
                                          if call.args and isinstance(call.args[0], MapLit) else [])
        if info.use.name == "checkout":
            # extensions: [[$class: 'WipeWorkspace']] (or wipeWorkspace()) deletes the workspace before checkout;
            # CleanBeforeCheckout runs `git clean`, which keeps .git.
            return any(literal(n) == "WipeWorkspace" or (isinstance(n, Call) and callee_name(n) == "wipeWorkspace")
                       for _, v in entries_all for n in find_nodes(v, lambda x: isinstance(x, (Str, Call)), 500))
        if info.use.name == "step":
            if not any((k if isinstance(k, str) else literal(k)) == "$class" and literal(v) in (
                    "WsCleanup", "hudson.plugins.ws_cleanup.WsCleanup") for k, v in entries_all):
                return False
        elif info.use.name != "cleanWs":
            return False
        for key, value in entries_all:
            key = key if isinstance(key, str) else literal(key)
            if key in ("patterns", "externalDelete"):
                return False
            if key == "skipWhenFailed" and path_of(value) != "false":
                return False
            if (key or "").startswith("cleanWhen") and path_of(value) != "true":
                return False
        return True

    def _may_share_machine(self, a: Info, b: Info) -> bool:
        """Whether two steps in separate allocations may still run on the same agent, where Jenkins keeps a
        job's workspace directory between allocations: neither is a pod of its own, and their labels do not
        tell their agents apart (the same label, any agent, or one the file does not fix)."""
        if not a.ctx.ws or not b.ctx.ws:
            return False
        wa = self.p.workspaces[self.p.workspaces[a.ctx.ws].machine]
        wb = self.p.workspaces[self.p.workspaces[b.ctx.ws].machine]
        if wa.id == wb.id:
            return False       # one allocation: decided above, not a question of which agent
        kinds = {wa.kind, wb.kind}
        if "closure" in kinds:
            return False
        if "kubernetes" in kinds:
            # A pod is the build's own, unless its workspace volume outlives it and another pod mounts the same.
            return kinds == {"kubernetes"} and bool(wa.custom and wb.custom) and (
                wa.custom == wb.custom or "?" in (wa.custom, wb.custom))
        if kinds & {"any", "unknown", "context"}:
            return True
        if wa.custom and wa.custom == wb.custom:
            return True
        da, db = self.p.workspaces[a.ctx.ws], self.p.workspaces[b.ctx.ws]
        if da.kind == db.kind == "ws" and (da.custom == db.custom or "?" in (da.custom, db.custom)):
            return True        # ws() with the same path
        la, lb = wa.label, wb.label
        if la is None or lb is None or "${" in la or "${" in lb:
            return True
        ta, tb = label_terms(la), label_terms(lb)
        # Expressions that share a label they require (`linux && docker`, `linux`) can select the same agent.
        return ta is None or tb is None or bool(ta & tb)

    def redundant(self, info: Info) -> bool:
        """A step read where its closure is written, when the closure is also read where it is called (flagship
        slice 2d.2j): the call is where it runs, so the reading where it is written adds nothing."""
        w = self.p.workspaces.get(info.ctx.ws)
        if w is None or w.kind != "closure":
            return False
        if self._elsewhere is None:
            self._elsewhere = {id(i.use.call) for i in self.infos
                               if self.p.workspaces.get(i.ctx.ws) is None
                               or self.p.workspaces[i.ctx.ws].kind != "closure"}
        return id(info.use.call) in self._elsewhere

    def agent_effects(self) -> None:
        ai = [i for i in self.infos if i.ai and not self.redundant(i)]
        if not ai:
            return
        self.applicable.add("OBAAF-JEN-003")
        self._cleans: dict[int, list] = {}
        for info in self.infos:
            if self.full_clean(info):
                self._cleans.setdefault(info.ctx.ws, []).append(info)
        # Where what an agent wrote may be: the workspace it ran in, from that step on, and any workspace that
        # unstashes a stash taken there after the agent ran, or unarchives what was archived there (flagship
        # slice 2d.2j). Each source is (key, from step, agent, via), indexed by key.
        sources: list[tuple] = [(self.ws_key(i), i, i, None) for i in ai]
        by_key: dict[tuple, list] = {}
        for item in sources:
            by_key.setdefault(item[0], []).append(item)
        stashes: dict[tuple, list] = {}
        for i in self.infos:
            if i.use.name in ("stash", "archiveArtifacts", "archive"):
                stashes.setdefault(self.ws_key(i), []).append(i)
        unstashes = [i for i in self.infos if i.use.name in ("unstash", "unarchive")]
        seen = {(key, src.index) for key, src, _, _ in sources}
        queue = list(sources)
        while queue:
            key, src, agent, _ = queue.pop()
            for st in stashes.get(key, ()):
                if not (st is src or self.may_follow(src, st)):
                    continue
                kind, name = self.stash_name(st)
                for un in unstashes:
                    other_kind, other = self.stash_name(un)
                    if kind != other_kind or (name != other and "?" not in (name, other)) or \
                            not self.may_follow(st, un):
                        continue
                    target = self.ws_key(un)
                    if (target, un.index) in seen:
                        continue
                    seen.add((target, un.index))
                    item = (target, un, agent, (st, un))
                    by_key.setdefault(target, []).append(item)
                    queue.append(item)
        shared_cache: dict[tuple, bool] = {}
        # One AI step for each workspace stands for the others in the question of which machine it may be.
        ai_by_machine = list({i.ctx.ws: i for i in reversed(ai) if i.ctx.ws}.values())[::-1]
        for info in self.infos:
            if not (info.push or info.trigger or info.publish) or self.redundant(info):
                continue
            effect = ("pushes to the repository" if info.push else
                      f"starts job {info.trigger} (as SYSTEM unless build authorization is configured)"
                      if info.trigger else f"publishes ({info.publish})")
            key = self.ws_key(info)
            here = by_key.get(key, [])
            stage = base_stage(info.ctx.stage)
            if key[0] == "stage":
                # No workspace known: every agent of the stage counts, in any order, as before slice 2d.2j.
                direct = [s for s in here if s[3] is None]
                if direct:
                    self.add("OBAAF-JEN-003", info.line,
                             f"Stage '{stage_label(stage)}' runs an AI agent at line {direct[0][2].line} and the step at "
                             f"line {info.line} {effect}, in the same workspace. What the agent wrote or was told can "
                             "reach that effect without review.", stage, severity="high")
                    continue
            after = [s for s in here if s[1] is info or self.may_follow(s[1], info)]
            direct = [s for s in after if s[3] is None]
            if direct:
                agent = direct[0][2]
                if base_stage(agent.ctx.stage) == stage and agent.ctx.ws == info.ctx.ws:
                    message = (f"Stage '{stage_label(stage)}' runs an AI agent at line {agent.line} and the step at line "
                               f"{info.line} {effect}, in the same workspace.")
                elif key[0] == "volume" and agent.ctx.ws != info.ctx.ws:
                    kind, _, name = key[1].partition(":")
                    shown = f"claim '{name}'" if kind == "claim" else f"NFS export '{name}'"
                    message = (f"The step at line {info.line} in stage '{stage_label(stage)}' {effect} in a pod whose "
                               f"workspace is the same volume ({shown}) as the AI agent's at line {agent.line} in stage "
                               f"'{stage_label(base_stage(agent.ctx.stage))}'.")
                elif agent.ctx.ws == info.ctx.ws:
                    message = (f"The step at line {info.line} in stage '{stage_label(stage)}' {effect}, in the same "
                               f"workspace as the AI agent at line {agent.line} in stage "
                               f"'{stage_label(base_stage(agent.ctx.stage))}' ({self._where(agent)}).")
                else:
                    message = (f"The step at line {info.line} in stage '{stage_label(stage)}' {effect} in another "
                               f"workspace ({self._where(info)}) on the same node as the AI agent at line {agent.line} in "
                               f"stage '{stage_label(base_stage(agent.ctx.stage))}', which runs as the same user and can "
                               "write into it.")
                self.add("OBAAF-JEN-003", info.line, message + " What the agent wrote or was told can reach that effect "
                         "without review.", stage, severity="high")
                continue
            if after:
                _, un, agent, (st, _) = after[0]
                kind, name = self.stash_name(st)
                what = (f"stash '{name}', taken" if kind == "stash" and name != "?" else
                        "a stash whose name the file does not fix, taken" if kind == "stash" else "artifacts archived")
                self.add("OBAAF-JEN-003", info.line,
                         f"The step at line {info.line} in stage '{stage_label(stage)}' {effect}, after {un.use.name} at "
                         f"line {un.line} brings in {what} at line {st.line} after the AI agent at line {agent.line} in "
                         f"stage '{stage_label(base_stage(agent.ctx.stage))}' ran in that workspace. What the agent "
                         "wrote can reach that effect without review.", stage, severity="high")
                continue
            before = [s for s in here if s[3] is None]
            fresh = info.ctx.ws and self.p.workspaces[info.ctx.ws].kind == "kubernetes" and \
                not self.p.workspaces[info.ctx.ws].custom
            kept = [s for s in before if not fresh and not self._cleaned(s[2], info)]
            if kept:
                agent = kept[0][2]
                self.add("OBAAF-JEN-003", info.line,
                         f"The step at line {info.line} in stage '{stage_label(stage)}' {effect} before the AI agent at "
                         f"line {agent.line} in stage '{stage_label(base_stage(agent.ctx.stage))}' runs in the same "
                         "workspace. Jenkins keeps that workspace between builds, so what the agent leaves there (a Git "
                         "hook, .git/config, a script the step runs) is in place for this step in the next build, "
                         "unless the step runs after cleanWs() or deleteDir() or in a fresh pod.", stage,
                         severity="medium")
                continue
            for agent in ai_by_machine:
                pair = (agent.ctx.ws, info.ctx.ws)
                if pair not in shared_cache:
                    if len(shared_cache) > 200_000:
                        self.unknown("OBAAF-JEN-003", 1, "the file has too many allocations to compare each AI "
                                     "agent's with each effect's")
                        break
                    shared_cache[pair] = self._may_share_machine(agent, info)
                if shared_cache[pair]:
                    self.unknown("OBAAF-JEN-003", info.line,
                                 f"the AI agent at line {agent.line} (stage '{stage_label(base_stage(agent.ctx.stage))}') "
                                 f"and the step at line {info.line} that {effect.split(' (')[0]} run in separate "
                                 "allocations that may be the same agent, where Jenkins keeps the job's workspace "
                                 "directory between allocations; which agents carry which labels is controller "
                                 "configuration")
                    break

    # ------------------------------------------------------------------ JEN-004
    def pipeline_code(self) -> None:
        self.applicable.add("OBAAF-JEN-004")
        for lib in self.p.libraries:
            shown = _shown(lib.name + (f"@{lib.version}" if lib.version else ""))
            if lib.retriever == "self":
                self.add("OBAAF-JEN-004", lib.line,
                         f"Library '{shown}' is loaded with legacySCM(scm), from the build's own checkout. For a "
                         "change request that is the change's own code, so its author chooses the library code that "
                         "runs.", None, severity="high")
            elif lib.retriever == "computed":
                source = lib.retriever_source
                self.add("OBAAF-JEN-004", lib.line,
                         f"Library '{shown}' is fetched by a retriever built from "
                         + (f"{source[0]}, so whoever sets that value chooses" if source else
                            "values computed at run time, so the reviewed Jenkinsfile does not fix")
                         + " where the library's code comes from.", None,
                         severity="high" if source else "medium")
            if lib.name == "?":
                self.unknown("OBAAF-JEN-004", lib.line, f"{lib.how} names a library computed at run time")
                continue
            if lib.dynamic:
                what = "a name" if "${" in lib.name else "a version"
                source = untrusted_source(list(lib.exprs), self.p)
                if source is None and any(WORKSPACE_READ.search(x) or set(re.findall(r"[A-Za-z_]\w*", x)) &
                                          self.p.workspace_vars for x in lib.exprs):
                    # A file in the workspace is the change's own for a change request (flagship slice 2d.2k).
                    source = ("a file in the workspace", "high")
                if source:
                    self.add("OBAAF-JEN-004", lib.line,
                             f"Library '{shown}' is loaded with {what} taken from {source[0]}, so whoever sets that "
                             "value chooses the pipeline code that runs. A trusted global library runs outside the "
                             "Groovy sandbox.", None, severity="high")
                else:
                    self.add("OBAAF-JEN-004", lib.line,
                             f"Library '{shown}' is loaded with {what} computed at run time, so the reviewed "
                             "Jenkinsfile does not fix which code runs.", None, severity="medium")
        # Every call that runs Groovy the file does not hold, on any receiver (flagship slice 2d.2k).
        for kind, name, call, ctx, certain in self.p.code_loads:
            if not certain:
                # props.load(...), xpath.evaluate(...): a receiver that may not be the script or a Groovy shell.
                self.unknown("OBAAF-JEN-004", call.line, f"{name}() at line {call.line} may run Groovy text or a "
                             "file from the workspace; the checker cannot tell what its receiver is")
                continue
            arg = code_text_arg(kind, name, call)
            if kind == "jobDsl":
                if named_arg(call, "targets") is None and arg is not None and self._reviewed_text(arg):
                    continue
                what = ("runs Job DSL scripts from the workspace on the controller"
                        if named_arg(call, "targets") is not None or arg is None else
                        "runs Job DSL script text read at run time on the controller")
            elif kind == "evaluate":
                if arg is not None and self._reviewed_text(arg):
                    continue
                what = f"evaluates Groovy text read at run time ({name})"
            else:
                what = f"loads Groovy from the workspace ({_shown(literal(arg)) if literal(arg) else 'a computed path'})"
            cr = ctx.cr
            source = untrusted_source(source_texts(arg), self.p) if kind != "load" and arg is not None else None
            if source is not None:
                # Text built from a parameter or a change's text: whoever sets it writes the code, on any
                # branch (flagship slice 2d.2k: `evaluate("${params.GROOVY}")` was only "unknown").
                self.add("OBAAF-JEN-004", call.line,
                         f"Stage '{stage_label(ctx.stage)}' runs Groovy built from {source[0]} ({name}), so whoever "
                         "sets that value writes pipeline code.", ctx.stage,
                         severity="high" if source[1] == "high" or kind == "jobDsl" else "medium")
                continue
            if cr in (CR_YES, CR_POSSIBLE):
                privileged = bool(ctx.creds) or self.stage_publishes(ctx.stage) or kind == "jobDsl"
                self.add("OBAAF-JEN-004", call.line,
                         f"Stage '{stage_label(ctx.stage)}' {what}. For a change request the workspace holds the "
                         "change's own files, so its author controls this pipeline code even when Jenkins takes the "
                         "Jenkinsfile from a trusted branch" + (", and the code runs where credentials are bound."
                                                               if ctx.creds or self.stage_publishes(ctx.stage) else
                                                               ", and Job DSL can create and change jobs."
                                                               if kind == "jobDsl" else "."),
                         ctx.stage, severity="high" if privileged or cr == CR_YES else "medium")
            elif cr == CR_UNKNOWN:
                self.unknown("OBAAF-JEN-004", call.line,
                             f"{name} at line {call.line} runs under a condition the checker cannot evaluate")
        if self.p.libraries:
            self.unknown("OBAAF-JEN-004", self.p.libraries[0].line,
                         "whether each library is trusted (global, outside the sandbox) or untrusted (folder), and "
                         "whether the Jenkinsfile may override its version, is controller configuration")
        if any(i.ctx.creds or i.publish for i in self.infos):
            self.unknown("OBAAF-JEN-004", 1,
                         "Replay lets users with Run/Replay permission run an edited Jenkinsfile with this job's "
                         "credentials; whether that permission is restricted is controller configuration")

    # ------------------------------------------------------------------ JEN-005
    def approval_gates(self, check: Info, target: Info) -> bool:
        """Whether an input step stops `target` until someone approves (flagship slice 2d.2l): it runs before
        it on every path that reaches it, and an abort stops the build or skips the target. As `gates`, except
        that an input in the same catchError or try block as the target, before it, still skips it when
        aborted; and an input read where a closure or an uncalled method is written does not count."""
        if check.ctx.deferred or check.index >= target.index or target.ctx.post in FAILURE_PATHS:
            return False      # a publish in a failure path runs when the input is aborted
        if check.swallowed and not (check.swallowed == check.ctx.swallowed and check.ctx.swallow_id
                                    and check.ctx.swallow_id == target.ctx.swallow_id):
            return False      # caught, unless the abort skips the rest of the very block the publish is in
        return (check.ctx.post not in FAILURE_PATHS and not concurrent(check.ctx, target.ctx)
                and guard_keys(check) <= guard_keys(target))

    def approvals(self) -> None:
        publishes = [i for i in self.infos if i.publish]
        if publishes or self.p.approvals:
            self.applicable.add("OBAAF-JEN-005")
        for approval in self.p.approvals:
            names = [n.strip(JAVA_TRIM) for n in (approval.submitter or "").split(",")]
            if approval.submitter is None:
                self.add("OBAAF-JEN-005", approval.line,
                         f"The input step at line {approval.line} sets no submitter (or a blank one), so any user "
                         "with Build permission on the job can approve it, including the person who started the "
                         "build.", approval.ctx.stage, severity="medium")
            elif approval.submitter == "?":
                self.unknown("OBAAF-JEN-005", approval.line, "the input step's submitter list is computed at run time")
            elif any(n.casefold() == "authenticated" for n in names):
                self.add("OBAAF-JEN-005", approval.line,
                         f"The input step at line {approval.line} names the group 'authenticated' as a submitter, "
                         "which every signed-in user is in, so the person who started the build can approve it.",
                         approval.ctx.stage, severity="medium")
        inputs = [i for i in self.infos if i.use.name == "input"]
        # A step the checker could not read, or a call it did not expand, may hold the input.
        incomplete = bool(self.p.opaque)
        reported: set = set()
        for target in publishes:
            if target.ctx.stage in reported or any(self.approval_gates(i, target) for i in inputs):
                continue
            label = stage_label(target.ctx.stage)
            if target.ctx.deferred:
                # Read where the closure or method is written; where it runs (after an input or not) is not read.
                if not any(t.use.call is target.use.call and not t.ctx.deferred for t in publishes):
                    self.unknown("OBAAF-JEN-005", target.line,
                                 f"the publish at line {target.line} is in {target.ctx.deferred}; whether an input "
                                 "step stops it until someone approves depends on where that code runs")
                continue
            if target.ctx.post in FAILURE_PATHS:
                where = "a catch or finally block" if target.ctx.post == "catch/finally" else \
                    f"a post {{ {target.ctx.post} }} block"
                reported.add(target.ctx.stage)
                self.add("OBAAF-JEN-005", target.line,
                         f"Stage '{label}' publishes ({target.publish}) in {where}, which runs when an approval "
                         "is aborted or a step fails, so no input step stops it.", target.ctx.stage,
                         severity="medium")
            elif incomplete:
                self.unknown("OBAAF-JEN-005", target.line,
                             f"the publish at line {target.line} has no input step before it that the checker "
                             "read, but part of the file was not read, and it may hold one")
            elif [i for i in inputs if i.index < target.index]:
                reported.add(target.ctx.stage)
                self.add("OBAAF-JEN-005", target.line,
                         f"Stage '{label}' publishes ({target.publish}) and no input step stops it on every path: "
                         "each input before it is caught when aborted, may be skipped by a condition, runs in "
                         "another parallel branch or a failure path, or is in code that may not run there.",
                         target.ctx.stage, severity="medium")
            else:
                reported.add(target.ctx.stage)
                self.add("OBAAF-JEN-005", target.line,
                         f"Stage '{label}' publishes ({target.publish}) with no input step before "
                         "it, so no person approves the release in the pipeline.", target.ctx.stage,
                         severity="medium")
        if self.p.approvals:
            self.unknown("OBAAF-JEN-005", self.p.approvals[0].line,
                         "whether approvers are independent of the person who started or changed the build, and "
                         "whether the approval is bound to the exact artifacts, is not visible in the Jenkinsfile")

    # ------------------------------------------------------------------ JEN-006
    def host_access(self) -> None:
        for agent, ctx in self.p.agents:
            if agent.kind not in ("docker", "dockerfile", "kubernetes"):
                continue
            self.applicable.add("OBAAF-JEN-006")
            problems: list[str] = []
            if agent.args:
                found, unread, _ = docker_options(agent.args)
                problems += found
                for reason in unread:
                    self.unknown("OBAAF-JEN-006", agent.line, reason)
            pod = self.pod_spec(agent, "OBAAF-JEN-006")
            under = self.under(agent)
            problems += agent.pod_settings
            if pod is None and agent.kind == "kubernetes" and not (agent.yaml_ref is not None or agent.yaml_file
                                                                   or agent.inherit):
                pod = ""      # no pod spec at all: the plugin's default pod, which mounts the token (2d.2j)
            if pod is not None:
                settings, account, no_token, unread = pod_settings(pod)
                problems += settings
                for reason in unread:
                    self.unknown("OBAAF-JEN-006", agent.line, reason)
                if account:
                    self.unknown("OBAAF-JEN-006", agent.line,
                                 f"the pod runs as service account '{account}', whose permissions are cluster "
                                 "configuration")
                elif any(i.ai for i in under) and not no_token:
                    problems.append("the namespace's service account token, mounted by default")
            if agent.inherit:
                shown = f"'{agent.inherit}'" if agent.inherit != "?" else "computed at run time"
                self.unknown("OBAAF-JEN-006", agent.line,
                             f"pod template {shown} is defined on the controller, not in the repository")
            if not problems:
                continue
            risky = [i for i in under if i.ai or i.ctx.cr in (CR_YES, CR_POSSIBLE)]
            unique = list(dict.fromkeys(problems))
            self.add("OBAAF-JEN-006", agent.line,
                     f"The {agent.kind} agent for stage '{stage_label(ctx.stage)}' uses {', '.join(unique)}. Code in "
                     "the container can then reach the host and other builds on it"
                     + (", and change requests or an AI agent can steer that code." if risky else "."),
                     ctx.stage, severity="high" if risky or not under else "medium")

    def pod_spec(self, agent, rule: str) -> str | None:
        """The pod YAML of a Kubernetes agent: inline, from a variable assigned a literal in this file, or
        from a file in the repository. Anything else is reported as unknown for `rule`."""
        if agent.yaml:
            return agent.yaml
        if agent.yaml_ref is not None:
            lit = self.p.literals.get(agent.yaml_ref) if agent.yaml_ref else None
            if lit is not None:
                return lit.text()
            self.unknown(rule, agent.line, "the pod spec is computed at run time"
                         + (f" ({agent.yaml_ref})" if agent.yaml_ref else " (for example libraryResource)"))
            return None
        if agent.yaml_file:
            text = self._read(agent.yaml_file) if agent.yaml_file != "?" else None
            if text is None:
                self.unknown(rule, agent.line, f"pod definition {agent.yaml_file if agent.yaml_file != '?' else ''}"
                             " is not in the repository checkout".replace("  ", " "))
            return text
        return None

    # ------------------------------------------------------------------ JEN-007
    @staticmethod
    def no_network(info: Info) -> bool | list:
        """Whether a step's process runs inside a container started with no network (flagship slice 2d.2j): a
        shell step under a docker or dockerfile agent, or docker.image().inside, whose run options fix one
        network, `none`, and hold nothing that reaches the host (OBAAF-JEN-006's reading), so the process cannot
        give itself a route out. Docker Pipeline puts only the processes a step launches in the container: a
        step the plugin runs itself (aiAgent) is not in it. Host paths mounted besides the workspace may hold a
        socket, a way out whatever the network: then the list of those paths, for the message."""
        agent = info.ctx.agent
        if not info.shell or agent is None or agent.kind not in ("docker", "dockerfile") or not agent.args:
            return False
        problems, unread, networks = docker_options(agent.args)
        if networks != ["none"] or problems or unread:
            return False
        mounts = docker_bind_sources(agent.args)
        return mounts or True

    def agent_egress(self) -> None:
        declared = "OBAAF_EGRESS" in self.p.env_values
        for stage, infos in self.stages().items():
            ai = [i for i in infos if i.ai and not self.redundant(i)]
            if not ai:
                continue
            self.applicable.add("OBAAF-JEN-007")
            states = [self.no_network(i) for i in ai]
            if all(state is True for state in states):
                continue
            if all(states):
                mounts = sorted({m for state in states if isinstance(state, list) for m in state})
                shown = ", ".join(mounts[:3]) + (f" and {len(mounts) - 3} more" if len(mounts) > 3 else "")
                self.add("OBAAF-JEN-007", ai[0].line,
                         f"The AI agent in stage '{stage_label(stage)}' runs in a container started with --network "
                         f"none, but host paths are mounted into it ({shown}). A socket there is a way out whatever "
                         "the network, and what listens on it is not in the Jenkinsfile.", stage)
                continue
            note = (" OBAAF_EGRESS declares a policy, but a declaration is not enforcement." if declared else "")
            self.add("OBAAF-JEN-007", ai[0].line,
                     f"Nothing in the Jenkinsfile limits the network access of the AI agent in stage "
                     f"'{stage_label(stage)}'. Jenkins has no egress control of its own; a limit has to come from "
                     f"the agent's network (for example a Kubernetes NetworkPolicy).{note}", stage)

    # ------------------------------------------------------------------ JEN-008
    def _resolve(self, text: str, shell_vars: dict | None = None, groovy: bool = False, env: bool = True) -> str:
        """`${env.NAME}`, `${NAME}` and `$NAME` replaced by what the file fixes (flagship slice 2d.2k): a
        variable the script set earlier to one literal (`shell_vars`; None there means the script sets it
        otherwise, and a "*" entry that it ran eval or sourced a file that may set anything); else, for `${NAME}` when Groovy
        interpolates the text (`groovy`), a variable of the file; else, when `env`, an environment value.
        `${env.NAME}` is always the environment value. A name the file assigns anything but one literal,
        anywhere (two different literals included), is not put in. What is left with a `$` is computed.
        Bounded: three passes, and no pass adds more than 100,000 characters."""
        shell_vars = shell_vars or {}

        def from_node(node):
            return node.text() if isinstance(node, Str) and not node.interpolated else None

        def value(m):
            if m.group(1):
                name = m.group(1)
                return None if name in self.p.nonliteral_names else from_node(self.p.env_values.get(name))
            name, braced = m.group(2) or m.group(3), bool(m.group(2))
            if name in shell_vars:
                return shell_vars[name]
            if "*" in shell_vars or name in self.p.nonliteral_names:
                return None       # after eval or a sourced file, or a name given more than one value
            if braced and groovy and name in self.p.literals:
                return from_node(self.p.literals[name])
            return from_node(self.p.env_values.get(name)) if env else None

        for _ in range(3):
            budget = [100_000]

            def sub(m):
                got = value(m)
                if got is None or len(got) > budget[0]:
                    return m.group(0)
                budget[0] -= len(got)
                return got

            changed = _REF.sub(sub, text)
            if changed == text:
                break
            text = changed
        return text

    def _env_vars(self) -> dict:
        """The environment values the file sets once to a literal, as a script's starting variables: a
        command of the script that sets one again, or sources a file, overrides them in order."""
        return {name: node.text() for name, node in self.p.env_values.items()
                if isinstance(node, Str) and not node.interpolated and name not in self.p.nonliteral_names}

    @staticmethod
    def _prepared(text: str, shell: str = "sh") -> str:
        """A script as its shell reads it: full-line comments dropped first (a comment's last character does
        not continue it, the second review of 2d.2k), then lines continued with the shell's own character
        joined: a backslash for sh, `^` for bat, a backtick for PowerShell."""
        comment = "rem" if shell == "bat" else "#"
        lines = [x for x in text.splitlines()
                 if not (x.lstrip().lower().startswith(comment) or (shell == "bat" and x.lstrip().startswith("::")))]
        joiner = {"bat": "^", "powershell": "`", "pwsh": "`"}.get(shell, "\\")
        # Only an odd run of the character continues a line: `echo done\\` ends with an escaped backslash.
        return re.sub("(" + re.escape(joiner) + r"+)\r?\n[ \t]*",
                      lambda m: m.group(1)[:-1] + " " if len(m.group(1)) % 2 else m.group(0), "\n".join(lines))

    def _pin_script(self, info: Info) -> str:
        """The step's script for OBAAF-JEN-008: as the shell reads it, with what the file fixes put in.
        Groovy's own variables go in only when Groovy interpolates the script (a double-quoted string)."""
        node = shell_script(info.use.call)
        interpolated = isinstance(node, Str) and node.interpolated
        return self._resolve(self._prepared(info.script, info.use.name), groovy=interpolated, env=False)

    def _image(self, ref, line: int, stage: tuple | None, where: str, severity: str, groovy: bool = True) -> None:
        """One image reference: pinned to a digest, computed (unknown), or a finding. `groovy` is False for
        an image a shell command names, where the file's Groovy variables are not seen."""
        self.applicable.add("OBAAF-JEN-008")
        if ref is None:
            self.unknown("OBAAF-JEN-008", line, f"an image {where} is not written as text")
            return
        if "$" in ref:
            ref = self._resolve(ref, groovy=groovy)
        if "$" in ref or not ref.strip() or ref == "?":
            self.unknown("OBAAF-JEN-008", line, f"image reference '{_shown(ref)}' {where} is computed at run time")
        elif not PINNED_IMAGE.match(ref.strip()):
            self.add("OBAAF-JEN-008", line, f"Image '{_shown(ref)}' {where} is not pinned to a sha256 digest.", stage,
                     severity=severity)

    def _pod_images(self, text: str) -> list | None:
        """Every `image` a pod spec names, read as YAML (flagship slice 2d.2k: a line pattern missed flow
        mappings, JSON, quoted keys and `image :`, and took a block scalar's `>-` for the image). None when
        the text is not YAML the checker can read; an image that is not text is None in the list. Read once
        per text."""
        if text in self._pod_cache:
            return self._pod_cache[text]
        self._pod_cache[text] = None
        try:
            docs = list(yaml.load_all(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)))
        except Exception:      # any parse failure is "cannot read", never "no images"
            return None
        out: list = []
        stack, seen, visits = list(docs), set(), 0
        while stack:
            node = stack.pop()
            visits += 1
            if visits > 50_000:
                return None
            if isinstance(node, (dict, list)):
                if id(node) in seen:       # an alias: the same object, read once
                    continue
                seen.add(id(node))
            if isinstance(node, dict):
                for key, item in node.items():
                    if key == "image":
                        out.append(item if isinstance(item, str) else None)
                    else:
                        stack.append(item)
            elif isinstance(node, list):
                stack.extend(node)
        self._pod_cache[text] = out
        return out

    def _dockerfile_refs(self, rel: str, build_args: dict | None) -> list:
        """What a Dockerfile in the repository pulls in (flagship slice 2d.2k: `dockerfile true` and
        docker.build were never read): ("image", ref), ("unknown", why) and ("install", message) entries,
        read once per file and build arguments. ARGs before the first FROM, with build arguments over their
        defaults, feed FROM lines; a stage's ARG and ENV values feed its RUN lines; heredoc bodies belong to
        their instruction; a stage name is not an image."""
        key = (rel, tuple(sorted((build_args or {}).items())))
        if key in self._dockerfile_cache:
            return self._dockerfile_cache[key]
        out: list = []
        self._dockerfile_cache[key] = out
        text = self._read(rel) if rel != "?" else None
        if text is None:
            out.append(("unknown", "the Dockerfile " + (f"'{_shown(rel)}' is not in the repository checkout"
                                                       if rel != "?" else "is named at run time")))
            return out
        build_args = build_args or {}
        # Comment lines go before continuations are joined, as BuildKit does; `# escape=` sets the character.
        escape = "\\"
        for first in text.splitlines():              # parser directives: leading `# key=value` lines
            directive = re.match(r"[ \t]*#[ \t]*([A-Za-z]+)[ \t]*=[ \t]*(\S*)", first)
            if not directive:
                break
            if directive.group(1).lower() == "escape" and directive.group(2):
                escape = directive.group(2)[0]
        kept = [x for x in text.splitlines() if not x.lstrip().startswith("#")]
        lines = re.sub(re.escape(escape) + r"[ \t]*\r?\n", " ", "\n".join(kept)).splitlines()
        aliases: set = set()
        global_args: dict = {}
        stage_vars: dict = {}
        env_names: set = set()
        seen_from = False
        i = 0
        while i < len(lines):
            raw = lines[i]
            i += 1
            m = re.match(r"[ \t]*([A-Za-z]+)[ \t]+(.*)", raw)
            if not m or raw.lstrip().startswith("#"):
                continue
            word, rest = m.group(1).upper(), m.group(2).strip()
            body = []
            for doc in (_HEREDOC.finditer(rest) if word in ("RUN", "COPY", "ADD") else ()):
                strip_tabs, end_word = doc.group(1) == "-", doc.group(2)
                while i < len(lines):
                    got = lines[i]
                    i += 1
                    if (got.lstrip("\t") if strip_tabs else got) == end_word:
                        break
                    body.append(got)
            if word == "ARG":
                name, eq, default = rest.partition("=")
                name = name.strip()
                value = build_args.get(name, default.strip().strip("'\"") if eq else None)
                if not seen_from:
                    global_args[name] = value
                elif name not in env_names:          # an ENV of the same name wins over an ARG
                    stage_vars[name] = value if value is not None else global_args.get(name)
                continue
            if word == "ENV":
                pairs = [(em.group(1), em.group(2).strip("'\"")) for em in
                         re.finditer(r"([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|\S*)", rest)]
                if "=" not in rest and len(rest.split(None, 1)) == 2:
                    pairs = [tuple(x.strip() for x in rest.split(None, 1))]
                for name, value in pairs:
                    stage_vars[name] = value
                    env_names.add(name)
                continue
            if word == "RUN" and rest.startswith("["):
                try:                                  # exec form: RUN ["npm", "install", ...]
                    rest = " ".join(str(x) for x in json.loads(rest))
                except (ValueError, TypeError, RecursionError):
                    pass
            if word == "RUN":
                for mount in re.finditer(r"--mount=\S*?\bfrom=([^,\s]+)", rest):
                    if mount.group(1).lower() not in aliases and not mount.group(1).isdigit():
                        out.append(("image", mount.group(1)))
                known = {k: v for k, v in stage_vars.items() if v is not None and "$" not in v}
                for message in self._install_problems(rest + "\n" + "\n".join(body), shell_vars=known):
                    out.append(("install", f"{message} (in {_shown(rel)})"))
                continue
            if word in ("COPY", "ADD"):
                for fm in re.finditer(r"--from=(\S+)", rest):
                    ref = fm.group(1)
                    if ref.lower() not in aliases and not ref.isdigit():
                        out.append(("image", ref))
                continue
            if word != "FROM":
                continue
            seen_from = True
            stage_vars = {}
            env_names = set()
            tokens = [t for t in rest.split() if not t.startswith("--")]
            if not tokens:
                continue

            def arg(a):
                got = global_args.get(a.group(1))
                return got if got is not None else a.group(0)
            image = re.sub(r"\$\{?([A-Za-z_]\w*)\}?", arg, tokens[0])
            if "$" in image or any("$" in (build_args.get(n) or "") for n in re.findall(r"\$\{?(\w+)", tokens[0])):
                out.append(("unknown", f"the base image '{_shown(tokens[0])}' in '{_shown(rel)}' is set at build "
                                       "time"))
            elif image.lower() != "scratch" and image.lower() not in aliases:
                out.append(("base", image))
            if len(tokens) >= 3 and tokens[1].lower() == "as":
                aliases.add(tokens[2].lower())
        return out

    def _dockerfile(self, rel: str, line: int, stage: tuple | None, severity: str, build_args=None) -> None:
        self.applicable.add("OBAAF-JEN-008")
        self._line = line
        if build_args == "?":
            self.unknown("OBAAF-JEN-008", line, "the build arguments of the Dockerfile are computed at run time")
            build_args = {}
        for kind, value in self._dockerfile_refs(rel, build_args):
            if kind == "unknown":
                self.unknown("OBAAF-JEN-008", line, value)
            elif kind == "install":
                self.add("OBAAF-JEN-008", line, value + ".", stage, severity="high")
            elif not PINNED_IMAGE.match(value):
                what = "Base image" if kind == "base" else "Image copied from"
                self.add("OBAAF-JEN-008", line, f"{what} '{_shown(value)}' in '{_shown(rel)}' is not pinned to a "
                         "sha256 digest.", stage, severity=severity)

    @staticmethod
    def _commands(text: str):
        """Each command of a script, with what may stand before it (keywords, assignments, sudo, env,
        timeout, `bash -c "`) taken off: (command, the segment it came from). Linear in the text."""
        for segment in _COMMAND_SPLIT.split(text):
            command = segment
            for _ in range(8):
                m = _COMMAND_PREFIX.match(command)
                if not m or not m.group(0).strip():
                    break
                command = command[m.end():]
            yield command.strip(), segment

    def _assignments(self, text: str, variables: dict, depth: int = 0) -> None:
        """Record the variables a script line sets: one literal value, or None when the script sets it to
        anything else or to two different values."""
        for segment in _COMMAND_SPLIT.split(text):
            # `IFS= read -r VER`, `if read VER`: the verb after keywords, assignments and wrappers.
            other = _OTHER_ASSIGN.match(segment) or _OTHER_ASSIGN.match(next(self._commands(segment), ("", ""))[0])
            if other:
                verb, rest = other.group(1), other.group(2)
                if verb in ("source", "."):
                    # A file plainly outside the checkout (an absolute path, ~, $HOME or $NVM_DIR: nvm, a
                    # tool's profile) or a virtual environment's bin/activate is not the change's, so the
                    # variables keep their values (the fifth review of 2d.2k). Any other file may set anything:
                    # every variable becomes unknown, as for eval (the sixth review: reading the file in place
                    # was wrong in folders and slow).
                    target = (rest.split() or [""])[0].strip("'\"")
                    if "<(" not in rest and (re.match(r"(/|~|\$\{?(HOME|NVM_DIR)\b)", target) or re.search(
                            r"(^|/)bin/activate$", target)):
                        continue          # outside the checkout, or a virtual environment's activate script
                    for key in list(variables):
                        variables[key] = None
                    variables["*"] = None
                elif verb == "eval":
                    for key in list(variables):
                        variables[key] = None
                    variables["*"] = None
                else:
                    for word in rest.split():
                        if re.fullmatch(r"[A-Za-z_]\w*", word.split("=")[0]) and word != "in":
                            variables[word.split("=")[0]] = None
                continue
            plus = re.match(r"^[ \t]*([A-Za-z_]\w*)\+=", segment)
            if plus:
                variables[plus.group(1)] = None
                continue
            start = _ASSIGN_START.match(segment)
            if not start:
                continue
            full = _SHELL_ASSIGN.match(segment)
            name = start.group(1)
            if full is None:
                variables[name] = None
                continue
            single, double, bare = full.group(2), full.group(3), full.group(4)
            value = single if single is not None else self._resolve(double if double is not None else bare or "",
                                                                    variables, env=False)
            if "$" in value and single is None or len(value) > 10_000:
                value = None
            if name in variables and variables[name] != value:
                value = None
            variables[name] = value

    def _substituted(self, text: str, start: dict | None = None) -> str:
        """The script with each variable it sets put into the commands after it (`IMAGE=node:20; docker run
        $IMAGE`), as _install_problems reads it, for the container commands."""
        if "$" not in text or len(text) > 400_000:
            return text
        variables: dict = dict(start or {})
        return "\n".join(self._resolve_line(line, variables) for line in text.splitlines())

    def _resolve_line(self, line: str, variables: dict) -> str:
        """One script line with each command's variables put in from the assignments before it, on this line
        or earlier ones, and the assignments it makes recorded."""
        parts = re.split(r"(&&|\|\||;)", line)
        for k in range(0, len(parts), 2):
            original = parts[k]
            if "$" in original and variables:
                parts[k] = self._resolve(original, variables, env=False)
            self._assignments(original, variables)
        return "".join(parts)

    def _shell_images(self, text: str) -> list:
        """(image or None, command) for each `docker`/`podman`/`nerdctl` run, create or pull that a script
        runs as a command (after keywords, assignments, sudo, env, timeout or `bash -c`; not inside echo or a
        comment). None when an option the checker does not know stands before the image, so it cannot tell
        which word is the image (flagship slice 2d.2k: images in shell steps were never checked). At most 200
        are read; ("cut", ...) says the rest were not."""
        out = []
        for command, _ in self._commands(text):
            m = _CONTAINER_CMD.match(command)
            if not m:
                continue
            if len(out) >= 200:
                out.append(("cut", "more than 200 container commands"))
                break
            sub = m.group(3).lower()
            rest = command[m.end(): m.end() + 4000]
            try:
                words = shlex.split(rest)
            except ValueError:
                words = [w.strip("\"'") for w in rest.split()]
            image, i = None, 0
            while i < len(words):
                w = words[i]
                if w == "--":
                    image = words[i + 1] if i + 1 < len(words) else None
                    break
                if not w.startswith("-") or w == "-":
                    image = w
                    break
                flag = w.split("=", 1)[0]
                if flag in ("-a", "--attach"):
                    i += 1 if sub == "pull" or "=" in w else 2
                elif "=" in w or flag in _DOCKER_BOOL:
                    i += 1
                elif flag in _DOCKER_VALUE:
                    i += 2
                elif re.fullmatch(r"-[ditPq]+", w):
                    i += 1
                else:
                    image = "?"
                    break
            out.append((None if image in (None, "?") else image, sub))
        return out

    def _install_problems(self, text: str, where: str = "", shell_vars: dict | None = None) -> list:
        """What in a script installs an agent CLI at a version that can move (flagship slice 2d.2k): a
        downloaded install script, a package without an exact version (a range, a tag, a version set at run
        time), a package named at run time, or an update. `text` is the script as its shell reads it (see
        _prepared). Read command by command; a variable the script sets is put into the commands after it,
        and the subcommand after the installer decides whether a package is installed. Marks the rule
        applicable when an agent CLI is installed at all, pinned or not."""
        out: list = []
        if len(text) > 400_000:
            return ["An agent CLI may be installed in a script too long to read" + where] \
                if self._agent_words.search(text) else []
        variables = dict(shell_vars or {})
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            seg_line = self._resolve_line(line, variables)
            for segment in _SEGMENTS.split(seg_line):
                agent = self._agent_words.search(segment)
                if _DOWNLOAD.search(segment) and agent and _TO_SHELL.search(segment):
                    self.applicable.add("OBAAF-JEN-008")
                    out.append("An agent CLI is installed by piping a downloaded script into a shell, which "
                               "installs whatever version the script fetches" + where)
                elif any(rx.search(segment) for rx in self.install_urls):
                    self.applicable.add("OBAAF-JEN-008")
                    out.append("An agent CLI is installed by a downloaded install script, which installs "
                               "whatever version the script chooses" + where)
                for command in segment.split("|"):
                    found = self._package_problems(command, where)
                    if found is not None:
                        self._agent_installed = True
                        out += found
                for command, _ in self._commands(segment):
                    if _AGENT_SELF_UPDATE.match(command):
                        self.applicable.add("OBAAF-JEN-008")
                        out.append("An agent CLI updates itself to the newest version (claude update)" + where)
                    elif self._agent_installed and _global_update(command):
                        out.append("Agent CLIs installed globally are updated to the newest version (an update "
                                   "of every global package)" + where)
        return out

    @staticmethod
    def _non_options(words: list):
        """The words that are not options, skipping the values of options that take one."""
        j = 0
        while j < len(words):
            w = words[j]
            if w.startswith("-"):
                j += 2 if w in _INSTALLER_VALUE_OPTIONS else 1
                continue
            if re.match(r"\d*(?:[<>]|&>)", w):
                break
            yield w
            j += 1

    def _installer_action(self, words: list, k: int) -> str:
        """What the installer at words[k] does with the packages after it: install (or run), update or
        other, from its first word that is not an option (options that take a value skip it). A runner
        (npx) runs; a word the checker does not know is taken for install."""
        base = words[k].rsplit("/", 1)[-1]
        if base in _RUNNERS:
            return "install"
        j = k + 1
        while j < len(words):
            w = words[j]
            if w.startswith("-"):
                j += 2 if w in _INSTALLER_VALUE_OPTIONS else 1
                continue
            if w in ("tool", "pip", "global", "-m"):      # uv tool install, uv pip install, yarn global add
                j += 1
                continue
            if w in _UPDATE_WORDS:
                return "update"
            if w in _OTHER_WORDS:
                return "other"
            return "install"
        return "other"

    def _package_problems(self, command: str, where: str) -> list | None:
        """Problems of one command that installs or runs an agent CLI from a registry; None when it names
        none. The last installer before a package decides, by its subcommand, what the command does."""
        if not INSTALLER.search(command):
            return None
        # Shell quotes are not part of a word: @anthropic-ai/claude-code@"1.0.17" is @1.0.17 (fifth review).
        command = re.sub(r"[\"']", "", command)
        tokens = [(m.start(), m.group(0)) for m in re.finditer(r"\S+", command)]
        words = [w.strip("'\"") for _, w in tokens]
        installer_at = [i for i, w in enumerate(words) if w.rsplit("/", 1)[-1] in _INSTALLER_NAMES]
        if not installer_at:
            return None
        actions = {k: self._installer_action(words, k) for k in installer_at}
        starts = [tokens[k][0] for k in installer_at]
        lowered = command.lower()
        out: list | None = None
        for pkg, rx in self.packages:
            if pkg.split("/")[-1].split("-")[0].lower() not in lowered:
                continue
            for m in rx.finditer(command):
                n = bisect.bisect_right(starts, m.start()) - 1
                if n < 0 or tokens[installer_at[n]][0] == m.start():
                    continue
                action = actions[installer_at[n]]
                if action == "other":
                    continue
                self.applicable.add("OBAAF-JEN-008")
                out = out if out is not None else []
                ver = (m.group("ver") or "").strip()
                if action == "update":
                    out.append(f"Agent CLI {pkg} is updated to the newest version" + where)
                elif not _exact_version(ver):
                    shown = f" ({_shown(ver)})" if ver else ""
                    reason = " at a version set at run time" if "$" in ver else " without a fixed version"
                    out.append(f"Agent CLI {pkg} is installed{reason}{shown}" + where)
        # A package named at run time, given to an installer that installs it.
        for n_at, k in enumerate(installer_at):
            if actions[k] != "install":
                continue
            # By position, not `installer_at.index(k)`, which made a line of many installers quadratic (the
            # review of slice 2d.5a: 75,000 `npm` words took 35 s).
            following = installer_at[n_at + 1] if n_at + 1 < len(installer_at) else len(words)
            named = []
            args = words[k + 1: following]
            for n, w in enumerate(args):
                if w.startswith("-"):
                    if "=" in w:
                        named.append(w.split("=", 1)[1])
                    elif w in ("-p", "--package") and n + 1 < len(args):
                        named.append(args[n + 1])
                else:
                    named.append(w)
            if any("$" in w or "`" in w for w in named):
                self.applicable.add("OBAAF-JEN-008")
                self.unknown("OBAAF-JEN-008", self._line, f"a package is named at run time in "
                             f"`{_shown(command.strip(), 80)}`, so whether it is an agent CLI at a fixed version "
                             "is not checked")
                break
        return out

    def _manifests(self, text: str, folder: str, builds: list | None = None, builds_only: bool = False) -> list:
        """Agent CLIs that pip requirements files and package.json ask for, where a script installs from
        them: `pip install -r FILE` (every -r and -c, `-rFILE` too) and `npm install` with no lockfile beside
        package.json, in the folder the command runs in (`cd DIR`, `--prefix DIR`, dir()). With `builds`, each
        `docker build` (podman, nerdctl, buildah, buildx) is added to it as (Dockerfile, build arguments,
        tags), in that folder."""
        out: list = []
        parts = re.split(r"(&&|\|\||[;&|\n(`]|\$\()", text)
        stack: list = []
        # One stack for `(`, `$(` and backticks: a cd inside a subshell or a command substitution ends with it.
        # A `)` drops any open backticks above it, then closes the innermost `(` or `$(` (the sixth and seventh
        # reviews of 2d.2k); an unmatched `)`, such as a case pattern's, closes one too early.
        openers: list = []
        previous = folder
        for k in range(0, len(parts), 2):
            if k > 0 and parts[k - 1] in ("(", "$("):
                openers.append((parts[k - 1], folder))
            elif k > 0 and parts[k - 1] == "`":
                if openers and openers[-1][0] == "`":
                    folder = openers.pop()[1]
                else:
                    openers.append(("`", folder))
            closes = parts[k].count(")") - parts[k].count("(")
            command = next(self._commands(parts[k]), ("", ""))[0]
            command = re.split(r"[ \t]\d*(?:[<>]|&>)", " " + command)[0].strip()    # `pushd x > /dev/null`
            command = re.sub(r"\)+[ \t]*$", "", command)                            # `npm install)`
            words = [w.strip("\"'") for w in command.split()]
            restore = None
            for _ in range(max(closes, 0)):
                while openers and openers[-1][0] == "`":
                    openers.pop()
                if openers:
                    restore = openers.pop()[1]
            try:
                if words and words[0] == "pushd":
                    stack.append(folder)               # every pushd pushes, whatever its folder (ninth review)
                if words and words[0] in ("cd", "pushd") and k + 1 < len(parts) and parts[k + 1] in ("$(", "`"):
                    previous, folder = folder, "?"     # cd ./$(cat .appdir): a folder computed at run time
                    continue
                at_root = _CD_WORKSPACE.match(command)
                if at_root and re.search(r"[$*?\[]", at_root.group(1) or ""):
                    previous, folder = folder, "?"     # cd "$WORKSPACE/$APP_DIR" (the eighth review of 2d.2k)
                    continue
                if at_root:
                    # cd $WORKSPACE/x: the checkout's own folder x, wherever the script was.
                    joined = posixpath.normpath(at_root.group(1) or ".")
                    previous, folder = folder, ("?" if joined.startswith("..") else ("" if joined == "." else joined))
                    continue
                built = _BUILD_CMD.match(command)
                if built and builds is not None:
                    rel, args = _build_options(command[built.end():])
                    if any("$" in v for v in args.values()):
                        args = "?"
                    tags = [m.group(2) for m in _TAG_OPTION.finditer(command)]
                    builds.append((_join(folder, rel) if rel != "?" else "?", args, tags))
                    continue
                if words and words[0] == "popd":
                    previous, folder = folder, (stack.pop() if stack and len(words) == 1 else "?")
                    continue
                if command == "cd -":
                    previous, folder = folder, previous
                    continue
                moved = _CD.match(command)
                if words and words[0] in ("cd", "pushd") and not moved:
                    previous, folder = folder, "?"     # home, options, `$(...)`: a folder the checker cannot tell
                    continue
                if moved:
                    target = moved.group(2)
                    previous = folder
                    if re.search(r"[$*?\[]", target) or folder == "?" or target.startswith(("/", "~")):
                        folder = "?"
                    else:
                        joined = posixpath.normpath(_join(folder, target.strip("/")) or ".")
                        folder = "?" if joined.startswith("..") else ("" if joined == "." else joined)
                    continue
                if builds_only:
                    continue
                if _PIP_INSTALL.search(command):
                    for m in _REQUIREMENT_FLAG.finditer(command):
                        out += self._requirements(_join(folder, m.group(2)), "given to pip")
                base = words[0].rsplit("/", 1)[-1] if words else ""
                sub = next((w for w in self._non_options(words[1:])), None) if words else None
                if base in ("npm", "pnpm", "yarn", "bun") and (sub in _MANIFEST_INSTALLS or (
                        sub is None and base in ("yarn", "bun"))):
                    prefix = _NPM_PREFIX.search(command)
                    where = folder if prefix is None else ("?" if "$" in prefix.group(2) else _join(folder, prefix.group(2)))
                    out += self._package_json_problems(where)
            finally:
                if restore is not None:
                    folder = restore
        return out

    def _requirements(self, rel: str, where_from: str, depth: int = 0) -> list:
        """Agent CLIs a pip requirements file installs at a version that can move, nested -r and -c included
        (three levels; nested paths are relative to the file that names them)."""
        if rel in self._req_cache:
            return self._req_cache[rel]
        self._req_cache[rel] = []
        body = self._read(rel) if "$" not in rel and rel != "?" else None
        if body is None:
            self.unknown("OBAAF-JEN-008", self._line, f"the requirements file '{_shown(rel)}' {where_from} is not read")
            return []
        out = []
        folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
        for req in body.splitlines():
            req = req.split("#", 1)[0].strip()
            nested = re.match(r"(?:-r|--requirement|-c|--constraint)(?:[ \t]+|=)?(\S+)", req)
            if nested:
                if depth < 3:
                    out += self._requirements(_join(folder, nested.group(1)), f"named in '{_shown(rel)}'", depth + 1)
                continue
            if req:
                out += self._package_problems("pip install " + req, f" (in the requirements file {_shown(rel)})") or []
        self._req_cache[rel] = out
        return out

    def mutable_references(self) -> None:
        def severity_for(infos: list[Info]) -> str:
            if any(i.ai or i.publish for i in infos):
                return "high"
            if any(i.ctx.creds for i in infos):
                return "medium"
            return "low"

        env_vars = self._env_vars()
        self._collect_local_images(env_vars)
        for agent, ctx in self.p.agents:
            under = self.under(agent)
            severity = severity_for(under)
            where = f"for stage '{stage_label(ctx.stage)}'"
            if agent.image and not agent.from_step:      # step images are checked with the step below
                self._image(agent.image, agent.line, ctx.stage, where, severity)
            for img, line in agent.images:
                self._image(img, line, ctx.stage, where, severity)
            if agent.images_unknown:
                self.applicable.add("OBAAF-JEN-008")
                self.unknown("OBAAF-JEN-008", agent.line, "a pod template's containers are a list the checker "
                             "cannot read, so their images are not checked")
            if agent.kind == "dockerfile":
                args = agent.build_args
                build_args = "?" if args and "${" in args else (_build_options(args)[1] if args else {})
                self._dockerfile(agent.dockerfile or "Dockerfile", agent.line, ctx.stage, severity, build_args)
            pod = self.pod_spec(agent, "OBAAF-JEN-008") if agent.kind == "kubernetes" else None
            if pod:
                images = self._pod_images(pod)
                if images is None:
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", agent.line, "the pod spec is not YAML the checker can read, so its "
                                 "images are not checked")
                else:
                    for img in images:
                        self._image(img, agent.line, ctx.stage, f"in the pod spec {where}", severity)
        for info in self.infos:
            name = info.use.name
            users = self.by_stage.get(info.ctx.stage, [])
            where = f"in stage '{stage_label(info.ctx.stage)}'"
            if name in ("docker.image", "withDockerContainer"):
                call = info.use.call
                node = first_arg(call) if name == "docker.image" else (named_arg(call, "image") or first_arg(call))
                if node is None:
                    continue
                ref = literal(node)
                if ref is None:
                    ref = node.text() if isinstance(node, Str) else (
                        "${" + path_of(node) + "}" if path_of(node) else "${computed}")
                if self._resolve(ref, groovy=True) in self._local_images:
                    continue           # docker.build('app') then docker.image('app'): the job's own image
                self._image(ref, info.line, info.ctx.stage, where, severity_for(users))
            elif name == "docker.build":
                call = info.use.call
                options = call.args[1] if len(call.args) > 1 else None
                text = literal(options) if options is not None else "."
                if text is None:
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", info.line, "docker.build's options are computed at run time, so "
                                 "the Dockerfile it builds is not checked")
                    continue
                rel, build_args = _build_options(text)
                if any("$" in v for v in build_args.values()):
                    build_args = "?"
                self._dockerfile(_join(info.ctx.dir, rel) if rel != "?" else "?", info.line, info.ctx.stage,
                                 severity_for(users), build_args)
        for lib in self.p.libraries:
            name, version = lib.name, lib.version
            if lib.name == "?" or lib.dynamic:
                # A library named by a value: put in what the file fixes (flagship slice 2d.2k).
                text = None
                if lib.name == "?" and lib.ref:
                    base = lib.ref[4:] if lib.ref.startswith("env.") else lib.ref
                    text = self._resolve("${" + base + "}", groovy=True)
                elif lib.dynamic:
                    text = self._resolve(lib.name + (f"@{lib.version}" if lib.version else ""), groovy=True)
                if text is None or "$" in text:
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", lib.line, f"{lib.how} names a library or version computed at run "
                                 "time, so its pin is not checked")
                    continue
                name, _, version = text.partition("@")
                version = version or None
            self.applicable.add("OBAAF-JEN-008")
            # A library's code runs in every stage: high when any of them runs an agent or publishes.
            severity = "high" if any(i.ai or i.publish for i in self.infos) else "medium"
            if version is None:
                self.add("OBAAF-JEN-008", lib.line,
                         f"Library '{_shown(name)}' is loaded at its default version, which an administrator can change "
                         "and which may follow a branch.", None, severity=severity)
            elif not FULL_SHA.match(version):
                self.add("OBAAF-JEN-008", lib.line,
                         f"Library '{_shown(name)}' is loaded at '{_shown(version)}', a branch or tag that can move.", None,
                         severity=severity)
        scanned: set = set()
        for info in self.infos:
            # A method of the file expanded at many calls records its steps once per call; each step's
            # script is scanned once per call and folder (flagship slices 2d.2i, B097, and 2d.2k).
            if not info.shell or (id(info.use.call), info.ctx.dir) in scanned:
                continue
            scanned.add((id(info.use.call), info.ctx.dir))
            self._line = info.line
            folder = info.ctx.dir
            text = self._pin_script(info)
            problems = self._install_problems(text, shell_vars=env_vars)
            builds: list = []
            problems += self._manifests(self._substituted(text, env_vars), folder, builds)
            images = self._shell_images(self._substituted(text, env_vars))
            for rel in self._scripts(info.script):
                body_problems, body_images, body_builds = self._script_scan(_join(folder, rel), folder, env_vars)
                problems += body_problems
                images += body_images
                builds += body_builds
            for dockerfile, build_args, _ in builds:
                self._dockerfile(dockerfile, info.line, info.ctx.stage,
                                 severity_for(self.by_stage.get(info.ctx.stage, [])), build_args)
            for image, command in images:
                where = f"in a `{command}` command in stage '{stage_label(info.ctx.stage)}'"
                if image == "cut":
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", info.line, f"stage '{stage_label(info.ctx.stage)}' runs more than "
                                 "200 container commands in one script; the images after the 200th are not checked")
                elif image is None:
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", info.line, f"a `{command}` command in stage "
                                 f"'{stage_label(info.ctx.stage)}' names its image in a way the checker cannot read")
                elif command == "pull" or image not in self._local_images:
                    self._image(image, info.line, info.ctx.stage, where,
                                severity_for(self.by_stage.get(info.ctx.stage, [])), groovy=False)
            for message in dict.fromkeys(problems):
                self.applicable.add("OBAAF-JEN-008")
                self.add("OBAAF-JEN-008", info.line, message + ".", info.ctx.stage, severity="high")

    def _script_scan(self, rel: str, folder: str, env_vars: dict) -> tuple:
        """(install problems, container images, docker builds) of a repository script a step runs, read
        once per path and folder."""
        key = (rel, folder)
        if key not in self._script_cache:
            body = self._read(rel) if rel != "?" else None
            body = self._prepared(body) if body else None
            builds: list = []
            if body:
                resolved = self._substituted(body, env_vars)
                self._script_cache[key] = (
                    self._install_problems(body, f" (in the script {_shown(rel)})", shell_vars=env_vars)
                    + self._manifests(resolved, folder, builds), self._shell_images(resolved), builds)
            else:
                self._script_cache[key] = ([], [], [])
        return self._script_cache[key]

    def _collect_local_images(self, env_vars: dict) -> None:
        """Images the job builds or tags itself (`docker build -t`, `docker tag`, docker.build), after
        variables are put in, in steps and in the repository scripts they run: a `run` of one is not a pull
        from a registry (the third and fourth reviews of 2d.2k). A `pull` is always checked."""
        self._local_images = set()

        def add(tag: str) -> None:
            if "$" not in tag:
                self._local_images.update({tag, tag if ":" in tag.rsplit("/", 1)[-1] else tag + ":latest"})

        seen: set = set()
        texts: dict = {}

        def scan(text: str, folder: str) -> None:
            """Builds and `docker tag` targets of a script, once per text and folder, with no other effect."""
            if (text, folder) in texts or not re.search(r"\b(build|bud|tag)\b", text):
                return
            texts[(text, folder)] = True
            resolved = self._substituted(text, env_vars)
            builds: list = []
            self._manifests(resolved, folder, builds, builds_only=True)
            for _, _, tags in builds:
                for tag in tags:
                    add(tag)
            for command, _ in self._commands(resolved):
                tagged = _TAG_CMD.match(command)
                if tagged:
                    add(tagged.group(2))

        for info in self.infos:
            if (id(info.use.call), info.ctx.dir) in seen:
                continue
            seen.add((id(info.use.call), info.ctx.dir))
            if info.use.name == "docker.build":
                tag = self._resolve(literal(first_arg(info.use.call)) or (
                    first_arg(info.use.call).text() if isinstance(first_arg(info.use.call), Str) else "$"),
                    groovy=True)
                add(tag)
            elif info.shell:
                # The builds a step and its scripts run; their Dockerfiles are checked in the main loop.
                scan(self._pin_script(info), info.ctx.dir)
                for rel in self._scripts(info.script):
                    path = _join(info.ctx.dir, rel)
                    body = self._read(path) if path != "?" else None
                    if body:
                        scan(self._prepared(body), info.ctx.dir)

    def _package_json_problems(self, folder: str) -> list:
        """Agent CLIs that package.json asks for at a version that can move, when no lockfile beside it
        fixes them: dependencies of every kind, npm aliases (`npm:@scope/name@range`) included."""
        if folder == "?":
            self.unknown("OBAAF-JEN-008", self._line, "npm installs in a folder computed at run time or that "
                         "the checker does not follow, so its package.json is not read")
            return []
        if folder in self._package_cache:
            return self._package_cache[folder]
        self._package_cache[folder] = out = []
        text = self._read(_join(folder, "package.json"))
        if text is None or any(self._read(_join(folder, x)) is not None for x in LOCKFILES):
            return out
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            if self._agent_words.search(text):
                out.append("An agent CLI may be installed from a package.json the checker cannot read")
            return out
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(key) if isinstance(data, dict) else None
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                target = pkg
                if isinstance(ver, str) and ver.startswith("npm:"):
                    target, _, ver = ver[4:].rpartition("@") if ver[4:].count("@") > (1 if ver[4:].startswith("@")
                                                                                     else 0) else (ver[4:], "", "")
                if target in self.agent_package_names:
                    self.applicable.add("OBAAF-JEN-008")
                    if not (isinstance(ver, str) and EXACT_NPM.match(ver)):
                        out.append(f"Agent CLI {target} is installed from {_shown(_join(folder, 'package.json'))} "
                                   f"at '{_shown(str(ver))}', a version that can move, with no lockfile")
        return out

    # ------------------------------------------------------------------ JEN-009
    def injection(self) -> None:
        for info in self.infos:
            name = info.use.name
            if info.shell:
                self.applicable.add("OBAAF-JEN-009")
                source = untrusted_source(info.exprs, self.p)
                if source:
                    self.add("OBAAF-JEN-009", info.line,
                             f"The {name} step in stage '{stage_label(info.ctx.stage)}' builds its script with Groovy "
                             f"interpolation of {source[0]}. The value becomes part of the command before the shell "
                             "runs, so it can run commands of its own.", info.ctx.stage, severity=source[1])
                elif any(e.split(".")[0] in self.p.method_params for e in info.exprs if e):
                    # A method nothing in this file calls: its callers, and what they pass, are elsewhere.
                    self.unknown("OBAAF-JEN-009", info.line,
                                 f"the {name} step at line {info.line} uses a value passed in by a method's caller "
                                 "outside this file")
            elif name in ("load", "evaluate"):
                arg = first_arg(info.use.call)
                source = untrusted_source(source_texts(arg), self.p) if arg is not None else None
                if source:
                    self.add("OBAAF-JEN-009", info.line,
                             f"{name} at line {info.line} takes Groovy {('code' if name == 'evaluate' else 'from a path')} "
                             f"built from {source[0]}.", info.ctx.stage, severity="high")
            elif info.trigger:
                self.applicable.add("OBAAF-JEN-009")
                params = named_arg(info.use.call, "parameters")
                exprs = []
                for item in (params.items if isinstance(params, ListLit) else []):
                    # Booleans and choices cannot carry commands; string, text and run parameters can.
                    if isinstance(item, Call) and chain_name(item.callee) in ("booleanParam", "choice"):
                        continue
                    for st in _strings(item):
                        exprs += st.exprs
                    for node in _values(item):
                        p = path_of(node)
                        if p:
                            exprs.append(p)
                source = untrusted_source(exprs, self.p)
                if source and source[1] != "low":
                    job = f"Job '{info.trigger}'" if info.trigger != "a computed job name" else "A job with a computed name"
                    self.add("OBAAF-JEN-009", info.line,
                             f"{job} is started with a parameter taken from {source[0]}. Check that the job treats it "
                             "as data, never as part of a command.", info.ctx.stage, severity="medium")

    # ------------------------------------------------------------------ JEN-010
    def artifact_transfer(self) -> None:
        """Another job's artifacts fetched by a reference that moves, then published with no check that ties them
        to a build record first (flagship slice 2d.2m). Before 2d.2m the rule read only `copyArtifacts(...)` called by
        that name, judged a selector by its name (`specific('lastSuccessfulBuild')` was fixed), took a map given as
        the only argument for the default selector, and accepted any later shell step of the same stage whose text
        held `sha256sum -c`, `cosign verify` or `obaaf verify` anywhere (an `echo`, a comment, `|| true`, after the
        publish); it read every later step of the stage once per copy, so nested helpers took seconds."""
        publishes = [i for i in self.infos if i.publish]
        if not publishes:
            return
        fetches = []           # (info, kind, what): kind is "moving", "unknown" or "fixed"
        named = set()          # ids of the nodes that name copyArtifacts in a copy the checker read
        seen_calls: dict[int, list] = {}
        for info in self.infos:
            found = seen_calls.get(id(info.use.call))
            if found is None or found[0] is not info.use.call:
                found = [info.use.call, self._fetches_of(info, named)]
                seen_calls[id(info.use.call)] = found
            for kind, what in found[1]:
                fetches.append((info, kind, what))
        stray = self._unread_copy_names(named)
        if not fetches and stray is None:
            return
        self.applicable.add("OBAAF-JEN-010")
        if stray is not None:
            self.unknown("OBAAF-JEN-010", stray,
                         f"line {stray} names copyArtifacts in a form the checker does not read (a method pointer, a "
                         "computed method name, invokeMethod or a call it could not expand), so what it copies, and "
                         "by which reference, is not known")
        fetches = [f for f in fetches if f[1] != "fixed"]
        checks = [(i, self._fetch_check(i)) for i in self.infos]
        checks = sorted(((i, kind) for i, kind in checks if kind and not i.ctx.deferred), key=lambda c: c[0].index)
        keys: dict[int, frozenset] = {}

        def guards(info: Info) -> frozenset:
            found = keys.get(id(info))
            if found is None:
                found = keys[id(info)] = frozenset(guard_keys(info))
            return found

        def fixed_guards(info: Info) -> frozenset:
            """The copy's conditions that cannot change between the copy and a check: those on the build's
            parameters alone (`if (params.RELEASE)`). Others (`if (!fileExists('app.jar'))`) may be false at the
            check because of the copy."""
            return frozenset(guard_key(g) for g in info.ctx.guards if PARAMS_ONLY_GUARD.fullmatch(g.split(KEY_SEP, 1)[0]))

        sets = {fixed_guards(info) for info, _k, _w in fetches}
        if fetches and (max(len(fetches), len(checks)) * len(publishes) > 150_000
                        or len(sets) * len(publishes) * max(1, len(checks)) > 1_500_000):
            self.unknown("OBAAF-JEN-010", fetches[0][0].line,
                         f"{len(fetches)} copies of another job's artifacts, {len(checks)} checks and {len(publishes)} "
                         "publishes, as the file's methods expand, are too many to compare")
            return

        # For each publish and set of conditions the copy runs under, the latest check before the publish that can
        # stop it, worked out once: comparing every copy with every step of its stage took 11.7 seconds on 744
        # bytes of nested helpers. A check counts as `gates` says, except that a condition the copy runs under
        # may also skip the check: when it does not hold, nothing was copied.
        memo: dict[tuple, tuple[int, int]] = {}

        def latest(publish: Info, copy_guards: frozenset) -> tuple[int, int]:
            key = (publish.index, copy_guards)
            found = memo.get(key)
            if found is None:
                full = digest = -1
                allowed = guards(publish) | copy_guards
                for check, kind in checks:
                    if check.index >= publish.index:
                        break
                    # the script itself is read by _fetch_check; here, a catchError, warnError or catch around it
                    if check.ctx.swallowed or check.ctx.post in FAILURE_PATHS or concurrent(check.ctx, publish.ctx) \
                            or not guards(check) <= allowed:
                        continue
                    if kind == "full":
                        full = check.index
                    else:
                        digest = check.index
                found = memo[key] = (full, digest)
            return found

        for info, kind, what in fetches:
            if info.ctx.deferred:
                # Even when the same closure is also read where it is called: it may run again where the checker
                # does not see a call (`parallel a: c`), after the check
                self.unknown("OBAAF-JEN-010", info.line,
                             f"the copy at line {info.line} is in {info.ctx.deferred}; whether and where it runs is "
                             "not known")
                continue
            # A retry or waitUntil block, or a loop, around the copy runs a publish before it again after it
            again = set(info.ctx.repeats) | {guard_key(g) for g in info.ctx.guards if g.startswith("loop ")}
            def repeated(p: Info) -> bool:
                return bool(again) and bool(again & (set(p.ctx.repeats) | guards(p)))
            later = [p for p in publishes if p.index > info.index or concurrent(info.ctx, p.ctx) or repeated(p)]
            unchecked, digest_only = [], []
            for publish in later:
                if publish.ctx.post in FAILURE_PATHS or publish.index < info.index or concurrent(info.ctx, publish.ctx):
                    # a publish in a failure path runs when the check failed; one before the copy in the same retry
                    # block runs after the copy of the try before; one beside the copy is checked by nothing after it
                    unchecked.append(publish)
                    continue
                full, digest = latest(publish, fixed_guards(info))
                if full > info.index and not self._beside(info, full):
                    continue
                if digest > info.index and not self._beside(info, digest):
                    digest_only.append(publish)
                else:
                    unchecked.append(publish)
            if kind == "unknown":
                if unchecked or digest_only:
                    self.unknown("OBAAF-JEN-010", info.line,
                                 f"the copy at line {info.line} copies artifacts from {what}, which the file does not "
                                 "fix, and the pipeline publishes after it")
                continue
            if not unchecked:
                if digest_only:
                    self.unknown("OBAAF-JEN-010", info.line,
                                 f"the copy at line {info.line} copies artifacts from {what}; a digest check runs before "
                                 "the publish, but whether its digests come from somewhere other than the build it "
                                 "copied from is not known (obaaf verify release checks them against the signed record)")
                continue
            if all(p.ctx.deferred for p in unchecked):
                self.unknown("OBAAF-JEN-010", info.line,
                             f"the copy at line {info.line} copies artifacts from {what}, and the only publish after it "
                             f"with no check is in {unchecked[0].ctx.deferred}")
                continue
            here = base_stage(info.ctx.stage)
            same = any(base_stage(p.ctx.stage) == here and not p.ctx.deferred
                       and (p.index > info.index or repeated(p)) for p in unchecked)
            self.add("OBAAF-JEN-010", info.line,
                     f"Stage '{stage_label(info.ctx.stage)}' copies artifacts from {what}, a reference that moves, "
                     "and does not check their digests before "
                     + ("publishing them in the same stage." if same else "the pipeline publishes."),
                     info.ctx.stage, severity="high" if same else "medium")

    def _beside(self, copy: Info, check_index: int) -> bool:
        """Whether the check at `check_index` runs in a parallel branch beside the copy, so it may run first."""
        return concurrent(copy.ctx, self.infos[check_index].ctx)

    def _fetch_check(self, info: Info) -> str | None:
        """'full' for a step that runs `obaaf verify release`, 'digest' for one that runs another digest or
        signature check, as a command whose failure stops the `sh` script (flagship slice 2d.2m): read with the
        reader of slice 2d.2e, so a command in an `echo`, a comment, after `|| true`, `&`, `set +e` or `exit`, or in a
        script that does not stop at a failed command, is no check. `bat`, `powershell` and `pwsh` are not read."""
        cached = self._script_cache.get(("fetch-check", id(info.use.call)))
        if cached is not None and cached[0] is info.use.call:
            return cached[1]
        kind = None
        status = call_entries(info.use.call, "script").get("returnStatus")
        stops = status is None or (isinstance(status, Name) and status.name == "false") or literal(status) == "false"
        if stops and info.shell and info.use.name.rsplit(".", 1)[-1] == "sh" and info.script:
            text = info.script
            errexit, pipefail = True, False      # Jenkins runs an `sh` script without a #! line as `sh -xe`
            if text.startswith("#!"):           # durable-task reads a #! line only at the very start
                first, _, text = text.partition("\n")
                words = first[2:].split()
                program = words[0].rsplit("/", 1)[-1] if words else ""
                if program == "env" and len(words) > 1:
                    program, words = words[1].rsplit("/", 1)[-1], words[1:]
                if program not in ("sh", "bash", "dash"):
                    text = ""
                errexit = any(re.fullmatch(r"-[a-zA-Z]*e[a-zA-Z]*", w) for w in words[1:])
                pipefail = False
            lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            if text and not errexit and len(lines) == 1:
                errexit = True                    # one command: the script's status is that command's
            if text:
                commands, _complete = binding_commands(text, errexit, pipefail)
                for words in commands:
                    if {"--help", "-h", "--version"} & set(words):
                        continue
                    joined = " ".join(words)
                    if any(r.match(joined) for r in self.release_verify):
                        kind = "full"
                        break
                    if FETCH_DIGEST_CHECK.match(joined) or any(r.match(joined) for r in self.verify_cmds):
                        kind = "digest"
        self._script_cache[("fetch-check", id(info.use.call))] = (info.use.call, kind)
        return kind

    def _fetches_of(self, info: Info, named: set) -> list[tuple[str, str]]:
        """How a step fetches another job's artifacts: [(kind, what)], kind "moving", "fixed" or "unknown"."""
        call = info.use.call
        last = info.use.name.rsplit(".", 1)[-1]
        out = []
        if last == "copyArtifacts":
            named.add(id(call.callee))
            if len(call.args) == 1 and not call.named and not isinstance(call.args[0], (MapLit, Str)):
                # copyArtifacts(args): a variable given one map and nothing else is that map; anything else
                # (`base + [...]`, a call) may hold any argument
                value = self._single_value(call.args[0].name) if isinstance(call.args[0], Name) else None
                if isinstance(value, MapLit):
                    call = Call(callee=call.callee, args=[value], line=call.line)
                else:
                    call = Call(callee=call.callee, named=[("*", None)], line=call.line)
            out.append(self._copy_reference(call_entries(call, "projectName")))
        elif last == "step":
            if len(call.args) == 1 and isinstance(call.args[0], Name) and not call.named:
                value = self._single_value(call.args[0].name)
                if isinstance(value, MapLit):
                    call = Call(callee=call.callee, args=[value], line=call.line)
            entries = call_entries(call, None)
            cls = entries.get("$class")
            if isinstance(cls, Str) and not cls.interpolated and cls.text().rsplit(".", 1)[-1] == "CopyArtifact":
                named.add(id(cls))
                out.append(self._copy_reference(entries))
            elif cls is not None and not (isinstance(cls, Str) and not cls.interpolated):
                out.append(("unknown", "a step whose $class the file computes"))
        elif last == "invokeMethod" and call.args and literal(call.args[0]) == "copyArtifacts":
            named.add(id(call.args[0]))
            out.append(("unknown", "a copy called through invokeMethod"))
        urls = []
        if info.shell:
            urls.append(self._expanded(info.script).replace("'", "").replace('"', ""))
        elif last == "httpRequest":
            target = step_arg(call, "url") or first_arg(call)
            if isinstance(target, Name):
                target = self._single_value(target.name)
            urls.append(self._expanded(text_or_expr(target)))
        for text in urls:
            out += artifact_urls(text or "")
        return out

    def _expanded(self, text: str) -> str:
        """`text` with `$NAME`, `${NAME}` and `${env.NAME}` replaced by the literal value the file's `environment`
        gives NAME, so a URL kept there is read where it is used."""
        if "$" not in text:
            return text
        def value(m) -> str:
            name = m.group(1) or m.group(2)
            node = self.p.env_values.get(name)
            if node is None:
                node = self._single_value(name)
            return node.text() if isinstance(node, Str) else m.group(0)
        return re.sub(r"\$\{(?:env\.)?([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", value, text)

    def _copy_reference(self, entries: dict) -> tuple[str, str]:
        """What a copy's projectName and selector fix (flagship slice 2d.2m)."""
        project = entries.get("projectName")
        shown_project = (f"'{literal(project)}'" if literal(project) is not None else "a computed project") \
            if project is not UNREAD else "a project the file does not show"
        name = literal(project) if project not in (None, UNREAD) else None
        project_text = name or "another job"
        selector = entries.get("selector")
        if selector is UNREAD:
            return ("unknown", f"{shown_project} with a selector that a spread map may set")
        if selector is None or (isinstance(selector, Name) and selector.name == "null"):
            return ("moving", f"{project_text} by the default selector (last successful build)")
        kind, what = self._selector(selector)
        if kind == "moving":
            return ("moving", f"{project_text} by {what}")
        if kind == "fixed" and name is None:
            return ("unknown", f"{shown_project}, by {what}")
        return (kind, f"{project_text} by {what}")

    def _selector(self, node) -> tuple[str, str]:
        """("fixed" | "moving" | "unknown", how it reads) for a copyArtifacts selector: a symbol call
        (`lastSuccessful()`), a map with `$class` (`[$class: 'StatusBuildSelector']`), or a variable that is given
        one of them and nothing else."""
        if isinstance(node, Name):
            node = self._single_value(node.name)
        symbol, entries = None, {}
        if isinstance(node, Call):
            # A plugin symbol only when called by its bare name and the file defines nothing by that name
            # (`def specific(n) { lastSuccessful() }`, `s.specific('42')` are not the plugin's)
            if isinstance(node.callee, Name) and node.callee.name not in self.p.local_names:
                symbol = node.callee.name
            entries = call_entries(node, SELECTOR_POSITIONAL.get(symbol))
        elif isinstance(node, MapLit):
            entries = call_entries(Call(callee=Name("[:]", line=node.line), args=[node], line=node.line), None)
            cls = entries.get("$class")
            if isinstance(cls, Str) and not cls.interpolated:
                symbol = SELECTOR_CLASSES.get(cls.text().rsplit(".", 1)[-1], "?" + cls.text())
        if symbol is None:
            return ("unknown", "a selector the file computes")
        if symbol in MUTABLE_SELECTORS:
            return ("moving", f"{symbol}()")
        if symbol == "specific":
            return self._build_number(entries.get("buildNumber"))
        if symbol == "upstream":
            fallback = entries.get("fallbackToLastSuccessful")
            if fallback is None or (isinstance(fallback, Name) and fallback.name == "false"):
                return ("fixed", "upstream()")
            if isinstance(fallback, Name) and fallback.name == "true":
                return ("moving", "upstream(fallbackToLastSuccessful: true), which takes the last successful build "
                                  "when no upstream build started this one")
            return ("unknown", "upstream() with a fallback the file computes")
        return ("unknown", f"the selector {symbol.lstrip('?')}")

    def _build_number(self, node) -> tuple[str, str]:
        """A SpecificBuildSelector's build number: fixed only for digits written in the file, or the number of a
        build the file started (`def b = build(...)`, then `"${b.number}"`). Other text is read by Jenkins as a
        permalink or a build's display name, and `${...}` in it is expanded at run time (the plugin's help)."""
        if node is None or node is UNREAD:
            return ("unknown", "specific() with a build number the file does not show")
        text = literal(node)
        if text is not None:
            if text.isascii() and text.isdigit():
                return ("fixed", f"specific('{text}')")
            if "$" in text:
                return ("unknown", f"specific('{text}'), whose value is expanded at run time")
            return ("moving", f"specific('{text}'), which Jenkins reads as a permalink or a build's display name")
        if isinstance(node, Num):
            return ("fixed", f"specific({node.value})") if node.value.isdigit() else \
                ("unknown", f"specific({node.value})")
        ref = None
        if isinstance(node, Str) and len(node.exprs) == 1 and node.text() == "${" + str(node.exprs[0]) + "}":
            ref = node.exprs[0]
        elif isinstance(node, (Prop, Name)):
            ref = path_of(node)
        elif isinstance(node, Call) and isinstance(node.callee, Prop) and not node.args \
                and node.callee.name in ("toString", "getNumber"):
            ref = path_of(node.callee.target) if node.callee.name == "toString" else \
                f"{path_of(node.callee.target)}.number"
        if ref and "." in ref:
            var, _, attr = ref.partition(".")
            value = self._single_value(var) if attr in ("number", "getNumber()") else None
            if isinstance(value, Call) and isinstance(value.callee, Name) and value.callee.name == "build" \
                    and "build" not in self.p.local_names:
                return ("fixed", f"the number of the build it started ({ref})")
        return ("unknown", "specific() with a build number computed at run time")

    def _single_value(self, name: str):
        """The one value the file gives a variable, or None (flagship slice 2d.2m, from its two reviews): the file
        must declare the name once, with a value, and name it in exactly one other place, the read; anything else
        (a second assignment, a change through a property, index or method, an alias, an argument, a parameter or
        loop variable of the same name, a use inside an interpolated string or a comment) may give it another value
        where the step runs, and so does any write to the script's binding or properties (`binding.x =`,
        `setVariable`, `setProperty`, `this[...] =`), which may name it in a computed way."""
        table = self.__dict__.get("_values_cache")
        if table is None:
            table = self._values_cache = self._value_table()
        return table.get(name)

    def _value_table(self) -> dict:
        tree, source = self.p.tree, self.p.source
        if tree is None or BINDING_WRITE.search(source or ""):
            return {}
        decls: dict[str, list] = {}
        uses: dict[str, int] = {}

        def use(name: str, times: int = 1) -> None:
            uses[name] = uses.get(name, 0) + times

        for n in find_nodes(tree, lambda n: True):
            if isinstance(n, Decl):
                decls.setdefault(n.name, []).append(n.value)
            elif isinstance(n, (Name, Prop)):
                use(n.name)
            elif isinstance(n, Str) and n.interpolated:
                for expr in n.exprs:
                    for word in re.findall(r"(?<![\w$])[A-Za-z_]\w*", str(expr)):
                        use(word)
            params = getattr(n, "params", None)
            if isinstance(params, list):
                for param in params:
                    use(param if isinstance(param, str) else str(getattr(param, "name", "")))
        return {name: values[0] for name, values in decls.items()
                if len(values) == 1 and values[0] is not None and uses.get(name, 0) == 1}

    def _unread_copy_names(self, named: set) -> int | None:
        """The line of the first place the file names copyArtifacts (or the CopyArtifact class) other than a copy
        the checker read: a method pointer, a computed method name, a call it did not expand."""
        tree = self.p.tree
        if tree is None:
            return None
        def names_copy(n) -> bool:
            if isinstance(n, (Name, Prop)):
                return n.name in ("copyArtifacts", "CopyArtifact")
            if isinstance(n, Import):
                return n.path.rsplit(".", 1)[-1] in ("CopyArtifact", "*") and "copyartifact" in n.path
            if isinstance(n, Str):
                text = n.text()
                return text == "copyArtifacts" or text.rsplit(".", 1)[-1] == "CopyArtifact"
            if isinstance(n, Call):
                return isinstance(n.callee, Str) and n.callee.interpolated     # "$m"(...): a computed method name
            return False
        lines = [n.line for n in find_nodes(tree, names_copy) if id(n) not in named and n.line]
        return min(lines) if lines else None

    # ------------------------------------------------------------------ JEN-011
    def failure_paths(self) -> None:
        publishes = [i for i in self.infos if i.publish]
        if not publishes:
            return
        self.applicable.add("OBAAF-JEN-011")
        for info in publishes:
            if info.ctx.post in FAILURE_PATHS:
                where = "a catch or finally block" if info.ctx.post == "catch/finally" else \
                    f"post {{ {info.ctx.post} }}"
                self.add("OBAAF-JEN-011", info.line,
                         f"The step at line {info.line} publishes ({info.publish}) in {where}, which runs when the "
                         "build failed, was aborted or is unstable, so it can publish after a check failed or was "
                         "skipped.", info.ctx.stage, severity="high")
        checks = [i for i in self.infos if i.verify or (i.shell and CHECKSUM_VERIFY.search(i.script))]
        for check in checks:
            if check.ctx.post in FAILURE_PATHS:
                continue
            later = [p for p in publishes if p.index > check.index or concurrent(check.ctx, p.ctx)]
            target = next((p for p in later if not self.gates(check, p)), None)
            if target is None:
                continue
            if check.swallowed:
                why = f"its failure is ignored ({check.swallowed})"
            elif concurrent(check.ctx, target.ctx):
                why = "it runs in a parallel branch beside the publish, not before it"
            else:
                extra = [shown(g) for g in check.ctx.guards if guard_key(g) not in guard_keys(target)]
                why = (f"it runs only when a condition holds ({extra[0][:80]}) that does not also guard the publish, "
                       "so it can be skipped" if extra else "it does not run before the publish")
            self.add("OBAAF-JEN-011", check.line,
                     f"The check at line {check.line} cannot stop the publish at line {target.line}: {why}.",
                     check.ctx.stage, severity="high")

    # ------------------------------------------------------------------ JEN-012
    def provenance_check(self) -> None:
        publishes = [i for i in self.infos if i.publish]
        if not publishes:
            return
        self.applicable.add("OBAAF-JEN-012")
        checks = [i for i in self.infos if i.verify in ("full", "provenance")]
        unchecked = []
        for publish in publishes:
            found = {c.verify for c in checks if self.gates(c, publish)}
            if "full" not in found:
                unchecked.append((publish, found))
        if not unchecked:
            return
        # One finding for the file, on the worst step: a step that publishes with no check at all
        # before one that has a provenance check only. Taking the first in the file let an earlier,
        # better checked step stand in for a later one that nothing checks, at a lower severity.
        first, kinds = next((pair for pair in unchecked if "provenance" not in pair[1]), unchecked[0])
        if "provenance" in kinds:
            self.add("OBAAF-JEN-012", first.line,
                     f"The step at line {first.line} publishes after a provenance check only; approvals and agent "
                     "records are not checked (use obaaf verify release).", first.ctx.stage, severity="medium")
        else:
            self.add("OBAAF-JEN-012", first.line,
                     f"The step at line {first.line} publishes ({first.publish}) without an earlier check that stops "
                     "the build when verification fails.", first.ctx.stage)

    # ------------------------------------------------------------------ JEN-013
    def secret_names(self, variables: set) -> set:
        """The secret's variables and every variable of this file whose assigned values read one of them,
        transitively: `def t = TOKEN`, `def cmd = "curl ${TOKEN}"`, a method parameter given TOKEN,
        withEnv(["T2=${TOKEN}"]) (flagship slice 2d.2i)."""
        names = set(variables)
        changed = True
        while changed:
            changed = False
            for name, refs in self.p.refs.items():
                if name not in names and refs & names:
                    names.add(name)
                    changed = True
        return names

    def secret_interpolation(self) -> None:
        if any(info.ctx.creds for info in self.infos):
            self.applicable.add("OBAAF-JEN-013")
        for info in self.infos:
            if not info.ctx.creds:
                continue
            exprs = info.exprs
            if not info.shell:
                # The arguments of docker.image(...).inside/withRun/run and withDockerContainer become the
                # `docker run` command line (flagship slice 2d.2i).
                name = info.use.name
                if not (name.endswith((".inside", ".withRun", ".run")) and name.startswith("docker.") or
                        name == "withDockerContainer"):
                    continue
                exprs = [e for a in list(info.use.call.args) + [v for _, v in info.use.call.named]
                         for e in source_texts(a)]
            variables = {v for b in info.ctx.creds for v in b.variables if v not in b.paths and v != "?"}
            secrets = self.secret_names(variables)
            used = sorted({w for e in exprs for w in re.findall(r"[A-Za-z_]\w*", e) if w in secrets})
            envs = {"env"} | {n for n, refs in self.p.refs.items() if refs == {"env"}}
            computed_env = re.compile(
                r"\b(" + "|".join(sorted(map(re.escape, envs))) + r")\s*(\[\s*[^'\"\s\]]|\.\s*[\"']|"
                r"\.\s*(getProperty|getAt|get)\s*\(\s*[^'\"\s)])|\bSystem\s*\.\s*getenv\s*\(\s*[^'\"\s)]|"
                r"(^|[^.\w])(getProperty|getVariable)\s*\(\s*[^'\"\s)]|\bbinding\s*\.\s*(getVariable|getProperty)\s*\("
                r"\s*[^'\"\s)]")
            if not used and any(computed_env.search(e) for e in exprs):
                self.unknown("OBAAF-JEN-013", info.line,
                             f"the {info.use.name} step at line {info.line} interpolates an environment variable whose "
                             "name is computed, inside a credential binding; the checker cannot tell whether it is the "
                             "secret")
                continue
            # A name of this file whose value the checker never saw (a closure's parameter, `it`, a name a
            # destructuring assignment sets) may be the secret (the review of slice 2d.2i).
            # The first name of each path a step interpolates, when it starts with a lower-case letter (upper-case
            # names are environment variables), is not one of Jenkins's globals, and the file never gave it a
            # value the checker saw; and any name whose value reads an environment variable by a computed name.
            computed = self.secret_names({COMPUTED_ENV}) - {COMPUTED_ENV}
            unaccounted = sorted({w for e in exprs for w in _NAME_IN_EXPR.findall(_unquoted(e))
                                  if (w in computed) or (w[:1].islower() and w not in _JENKINS_GLOBALS
                                                         and w not in self.p.refs and w not in self.p.literals
                                                         and w not in self.p.lists)})
            if not used and unaccounted:
                self.unknown("OBAAF-JEN-013", info.line,
                             f"the {info.use.name} step at line {info.line} interpolates {', '.join(unaccounted[:3])} "
                             "inside a credential binding, and the checker cannot tell what it holds")
                continue
            if not used and any(b.variables == () or "?" in b.variables for b in info.ctx.creds) and exprs:
                self.unknown("OBAAF-JEN-013", info.line,
                             f"the {info.use.name} step at line {info.line} interpolates values inside a credential "
                             "binding whose variables the Jenkinsfile does not name; the checker cannot tell whether "
                             "one of them is the secret")
                continue
            if used:
                where = "script" if info.shell else "arguments"
                fix = ("Reference it as a shell variable inside single quotes." if info.shell else
                       "Pass it as `-e NAME` with no value, so docker takes it from the environment.")
                self.add("OBAAF-JEN-013", info.line,
                         f"The {info.use.name} step at line {info.line} puts secret variable(s) {', '.join(used)} into "
                         f"its {where} with Groovy interpolation, so the secret appears in the command line, where "
                         f"other processes on the agent can read it. {fix}",
                         info.ctx.stage)

    # ------------------------------------------------------------------ JEN-014
    def publishes_near(self, stage: tuple) -> bool:
        """The stage, or the stage a `post` block belongs to, publishes (flagship slice 2d.2i: a publish
        in `post { success { } }` did not make a signing finding high)."""
        base = base_stage(stage)
        return any(base_stage(s) == base and self.stage_publishes(s) for s in self.stages())

    def script_text(self, info: Info) -> str:
        """The script as the shell reads it: backslash-continued lines joined, and `${name}` placeholders
        for variables of this file that hold a literal replaced by it (flagship slice 2d.2i)."""
        cached = self._script_texts.get(id(info.use.call))
        if cached is not None and cached[0] is info.use.call:
            return cached[1]
        text = info.script
        for _ in range(3):
            changed = re.sub(r"\$\{([A-Za-z_]\w*)\}", lambda m: (
                self.p.literals[m.group(1)].text() if m.group(1) in self.p.literals else m.group(0)), text)
            if changed == text:
                break
            text = changed
        # A line continued with `\` (shell), `^` (cmd) or a backtick (PowerShell) is one line.
        text = re.sub(r"[\\^`]\r?\n[ \t]*", " ", text)
        self._script_texts[id(info.use.call)] = (info.use.call, text)
        return text

    def signing_keys(self) -> None:
        patterns = [re.compile(x, re.I) for x in self.detection.get("signing_secret_patterns", [])]
        commands = [re.compile(x, re.M) for x in self.detection.get("signing_commands", [])]
        scopes = self.bindings()
        if scopes or any(i.shell for i in self.infos):
            self.applicable.add("OBAAF-JEN-014")
        for b, infos in scopes.items():
            names = [n for n in list(b.ids) + list(b.variables) if n != "?"]
            hits = [n for n in names if any(p.search(re.sub(r"[-.]", "_", n)) for p in patterns)]
            # A certificate binding is a PKCS#12 keystore: signing material whatever it is called.
            if b.how.endswith((":certificate", ":CertificateMultiBinding")):
                hits.append(f"certificate binding {self.ids(b)}")
            if hits:
                stage = infos[0].ctx.stage if infos else ()
                severity = "high" if any(self.publishes_near(i.ctx.stage) for i in infos) else "medium"
                self.add("OBAAF-JEN-014", b.line,
                         f"Signing material ({', '.join(sorted(set(hits)))}) is bound by {b.how} for the steps of "
                         f"stage '{stage_label(stage)}', so any build step there can read the key.", stage,
                         severity=severity)
        loads: dict[int, tuple] = {}
        for info in self.infos:
            if not info.shell:
                continue
            hit = loads.get(id(info.use.call))
            if hit is None or hit[0] is not info.use.call:
                # Once per call, however many times the method holding it is expanded.
                hit = (info.use.call, any(rx.search(self.script_text(info)) for rx in commands))
                loads[id(info.use.call)] = hit
            if hit[1]:
                severity = "high" if self.publishes_near(info.ctx.stage) else "medium"
                self.add("OBAAF-JEN-014", info.line,
                         f"The step at line {info.line} loads a signing key into the build environment.",
                         info.ctx.stage, severity=severity)


    # ------------------------------------------------------------------ JEN-015
    def resolve_text(self, node, depth: int = 0) -> str | None:
        """The text of an expression built only from literals written in this file: a string, a variable
        whose last assignment is one, `+` of those, `.trim()` and similar; None otherwise."""
        if node is None or depth > 20:
            return None
        if isinstance(node, Str):
            if not node.interpolated:
                return node.text()
            parts = []
            for kind, value in node.tok.parts:
                if kind == "lit":
                    parts.append(value)
                else:
                    inner = self.p.literals.get(value.strip().removeprefix("env.")) if \
                        re.fullmatch(r"\s*(env\.)?[A-Za-z_]\w*\s*", value) else None
                    text = self.resolve_text(inner, depth + 1) if inner is not None else None
                    if text is None:
                        return None
                    parts.append(text)
            return "".join(parts)
        if isinstance(node, Binary) and node.op == "+":
            left, right = self.resolve_text(node.left, depth + 1), self.resolve_text(node.right, depth + 1)
            return None if left is None or right is None else left + right
        if isinstance(node, Call) and isinstance(node.callee, Prop) and not node.args and \
                node.callee.name in ("trim", "toString", "stripIndent"):
            text = self.resolve_text(node.callee.target, depth + 1)
            return text.strip() if text is not None and node.callee.name == "trim" else text
        p = path_of(node)
        if p:
            name = p.removeprefix("env.")
            value = self.p.literals.get(name)
            if value is None:
                env = self.p.env_values.get(name)
                value = env if env is not None else None
            return self.resolve_text(value, depth + 1) if value is not None else None
        return None

    def webhook_tokens(self) -> None:
        for trig in self.p.triggers:
            self.applicable.add("OBAAF-JEN-015")
            token = trig.token
            if not token and trig.token_node is not None:
                # A token built from literals in this file is written in the file (flagship slice 2d.2i).
                token = self.resolve_text(trig.token_node)
                if token is None:
                    self.unknown("OBAAF-JEN-015", trig.line,
                                 f"{trig.name}'s {trig.token_key} is computed; the checker cannot tell whether it is "
                                 "written in the repository")
                    continue
            if not token:
                continue
            privileged = any(i.ctx.creds or i.publish or i.ai for i in self.infos)
            hint = token[:3] + "..." if len(token) > 6 else "..."
            self.add("OBAAF-JEN-015", trig.line,
                     f"{trig.name} at line {trig.line} has its webhook token written in the Jenkinsfile ('{hint}'), "
                     "so anyone who can read the file can start the job and choose every webhook value it reads. "
                     "The Generic Webhook Trigger plugin runs token-started builds as SYSTEM."
                     + (" The pipeline holds credentials, publishes or runs an AI agent." if privileged else ""),
                     None, severity="high" if privileged else "medium")


def _truthy(node) -> bool:
    if node is None:
        return False
    p = path_of(node)
    return p == "true" or (isinstance(node, Str) and node.text().strip().lower() == "true")


def _strings(node):
    from obaaf.checker.jenkins.model import all_strings
    if node is None:
        return []
    return list(all_strings(node))


def _values(node):
    """Leaf argument values in a parameters list: string(name: 'x', value: env.CHANGE_TITLE)."""
    out = []
    if isinstance(node, ListLit):
        for item in node.items:
            out += _values(item)
    elif isinstance(node, Call):
        for _, value in node.named:
            out.append(value)
        out += list(node.args)
    return out
