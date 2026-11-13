#!/usr/bin/env python3
"""OBAAF egress control: run one command with its network limited to an allow-list.

This file is the whole of the action's logic. ``action.yml`` calls it with
``python3 -I`` (so nothing in the working directory can be imported in place of
the standard library) in two steps: ``install`` and ``run``.

The command runs under the Agent Workflow Firewall (AWF, github/gh-aw-firewall,
MIT licence) at one version that OBAAF's CI has tested, in AWF's default mode
(the command's container sits on a Docker network with no route out; a Squid
proxy is the only way out and allows only the listed host names). What this
wrapper adds, and why, is in docs/egress-control.md:

* every part of AWF is pinned: the binary by SHA-256, each container image by
  digest; nothing is fetched as "latest";
* the AWF command line is built here from a fixed list of options; no input
  reaches an AWF option;
* the allow-list is plain host names only;
* the command sees none of the runner's environment, except the variables the
  workflow names;
* the command can write only to a scratch directory under /tmp: a copy of the
  workspace, a scratch home directory and a scratch TMPDIR. The runner's real
  workspace, home directory, /tmp and RUNNER_TEMP are not writable from inside;
* before the command starts, a probe inside the same sandbox must fail to get
  out (a direct address, a host that is not listed, IPv6, sudo, the Docker
  socket); if any attempt succeeds the command does not run and the step fails;
* the runner's workflow commands are stopped while the command's output is
  printed, and the step fails if the runner's GITHUB_ENV, GITHUB_PATH,
  GITHUB_OUTPUT, GITHUB_STATE or GITHUB_STEP_SUMMARY files changed;
* the hosts the proxy refused are listed in the job summary, and the proxy's
  log is kept outside the scratch directory.

Only the Python standard library is used.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# What OBAAF has tested. Changing any of these is a change to the control and
# must go through the escape tests in .github/workflows/egress-escape-tests.yml.
# The values were read on 2026-11-13 from the v0.29.13 release's checksums.txt
# and containers.txt, which its release-identity.txt binds to refs/tags/v0.29.13.
# ---------------------------------------------------------------------------
AWF_VERSION = "v0.29.13"
AWF_BINARY = "awf-linux-x64"
AWF_SHA256 = "f82abe3974ae84107398cee47b79f4cb7150ff5c2a6d6abc187c86e358ad10bf"
AWF_IMAGE_DIGESTS = {
    "squid": "sha256:6c746bfa88dfa13cd7f21b26ac0028cbde8975830d447f649173acd9fb629fef",
    "agent": "sha256:ba33f16e83150bdc87af596c29c76a251256eb678159d93f2754b73b3cf9225e",
    "agent-act": "sha256:68754e8754ced096aa991f8faf041458e84cfd13fd400b95d1a78d55197f0e15",
    "api-proxy": "sha256:5d980a4a883db7b59b09427a9add4c0b1a32ff8659847afcaa9b82821d3376bd",
    "router": "sha256:3e05c9b26c463c00b3dd7049ca6ece3454324788f7e238da5e3c7edca84bd5dd",
    "cli-proxy": "sha256:0c590164caac6adcec76c242c9a2b2fc4f4127afcf65994922e3e8360745784e",
    "enclave-script": "sha256:9b8a228b3b4c1897b37316ae9ea1aae5265bced651243a8b811827addda60f48",
    "enclave-agent": "sha256:4cc2b31238440b485915618876ba0138202f4958dd7f4cc8168707a0d2a29fcd",
    "enclave-mcp-server": "sha256:fbf3c0033c84a2bb23439b147b0f8ccc5a92f14570d0f2e99334ba02c99f74e5",
}

# AWF mounts an empty tmpfs over these places inside the command's container,
# to hide them. With the host's /tmp read-only to the container (see
# run()), Docker cannot create the mount points, so they must exist on the
# host first. From AWF v0.29.13, src/sensitive-paths.ts.
AWF_TMP_MOUNTPOINTS = (
    "/tmp/gh-aw/mcp-logs",
    "/tmp/gh-aw/mcp-payloads",
    "/tmp/gh-aw/sandbox/firewall/logs",
    "/tmp/gh-aw/sandbox/firewall/audit",
)

# A fixed PATH for AWF and for the command: the runner's own PATH puts
# directories under the home directory first.
FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Exit status of the step when the sandbox did not hold or did not start.
EXIT_NOT_CONFINED = 3

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Variables the workflow may not pass to the command: they change how the
# command, its shell or its network behave, or they point at the runner's
# own files.
RESERVED_NAMES = frozenset(
    {
        "PATH", "HOME", "TMPDIR", "SHELL", "BASH_ENV", "ENV", "IFS", "CDPATH",
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONSTARTUP",
        "PYTHONHOME", "NODE_OPTIONS", "PERL5LIB", "PERL5OPT", "RUBYOPT",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy",
        "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM", "GIT_EXEC_PATH",
        "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT",
        "GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STATE",
        "GITHUB_STEP_SUMMARY", "GITHUB_WORKSPACE", "RUNNER_TEMP",
    }
)
RESERVED_PREFIXES = ("AWF_", "OBAAF_EGRESS_", "ACTIONS_", "SQUID_", "OTEL_", "FOUNDRY_")
# Names AWF reads from the environment file for its own configuration (an
# OpenTelemetry endpoint is added to the proxy's allow-list, for one), so a
# value would reconfigure AWF rather than reach the command.
RESERVED_SUFFIXES = ("_API_TARGET", "_API_BASE_PATH", "_BASE_URL", "_ENDPOINT_OVERRIDE")
# Model keys and GitHub tokens: AWF v0.29.13 withholds these from the command
# and hands model keys to its API proxy (src/services/agent-environment/
# excluded-vars.ts). This action does not set up the API proxy (OBAAF has not
# tested it), so passing one would silently give the command nothing.
WITHHELD_BY_AWF = frozenset(
    {
        "AGENT_API_KEY", "OPENAI_API_KEY", "OPENAI_KEY", "CODEX_API_KEY",
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_API_KEY",
        "COPILOT_GITHUB_TOKEN", "COPILOT_PROVIDER_API_KEY", "GEMINI_API_KEY",
        "GOOGLE_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN",
        "GITHUB_API_TOKEN", "GITHUB_PAT", "GH_ACCESS_TOKEN",
    }
)

RUNNER_FILES = ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_STEP_SUMMARY")

# Probe targets used before the command starts. The direct addresses are
# public resolvers; nothing on the list can make them reachable, because AWF
# allows names, not addresses.
PROBE_IPV4 = "1.1.1.1"
PROBE_IPV6 = "2606:4700:4700::1111"
PROBE_HOSTS = ("example.com", "example.net", "example.org")


class UsageError(Exception):
    """A problem with the step's inputs. Reported as an error; exit 2."""


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def parse_allow_list(text: str) -> list[str]:
    """Return the allow-list as plain, lower-case host names, or raise UsageError.

    Entries are separated by commas, spaces or new lines. Each must be a host
    name of at least two labels whose last label starts with a letter (so no
    IP address), with no wildcard, port, scheme, path or trailing dot. AWF
    allows every subdomain of a listed name, so a listed name stands for all
    names under it.
    """
    entries = [item for item in re.split(r"[\s,]+", text or "") if item]
    if not entries:
        raise UsageError("allow: give at least one host name (an empty list would block everything, use a command that needs no network instead)")
    seen: list[str] = []
    for raw in entries:
        name = raw.lower()
        if "*" in name:
            raise UsageError(f"allow: {raw!r} has a wildcard; list plain host names (a listed name already covers its subdomains)")
        if len(name) > 253 or not _HOST_RE.match(name):
            raise UsageError(f"allow: {raw!r} is not a plain host name of two labels or more (no scheme, port, path, address or trailing dot)")
        if name not in seen:
            seen.append(name)
    return seen


def covered(host: str, allow: list[str]) -> bool:
    """True if ``host`` is a listed name or under one."""
    return any(host == name or host.endswith("." + name) for name in allow)


def probe_host(allow: list[str]) -> str:
    """A host the probe must fail to reach: one the allow-list does not cover."""
    for host in PROBE_HOSTS:
        if not covered(host, allow):
            return host
    raise UsageError("allow: the list covers example.com, example.net and example.org, so the probe has no host to try; remove one of them")


def parse_env_names(text: str, environ: dict[str, str]) -> dict[str, str]:
    """Return the named variables with their values, or raise UsageError."""
    names = [item for item in re.split(r"[\s,]+", text or "") if item]
    result: dict[str, str] = {}
    for name in names:
        if not _NAME_RE.match(name):
            raise UsageError(f"env: {name!r} is not a variable name")
        if name in WITHHELD_BY_AWF:
            raise UsageError(f"env: {name} is a model key or GitHub token name, which AWF withholds from the command and this action does not route to AWF's API proxy (untested); see docs/egress-control.md")
        if name in RESERVED_NAMES or name.startswith(RESERVED_PREFIXES) or name.endswith(RESERVED_SUFFIXES):
            raise UsageError(f"env: {name} cannot be passed to the command; the action sets or withholds it on purpose, or AWF reads it as its own configuration")
        if name not in environ:
            raise UsageError(f"env: {name} is not set in the step's environment; set it under the step's env: key")
        value = environ[name]
        if "\n" in value or "\r" in value or "\0" in value:
            raise UsageError(f"env: the value of {name} holds a line break or NUL, which AWF's environment file cannot carry")
        result[name] = value
    return result


def image_tag() -> str:
    """The value of AWF's --image-tag: the version and a digest for each image."""
    version = AWF_VERSION.lstrip("v")
    pins = ",".join(f"{name}={digest}" for name, digest in AWF_IMAGE_DIGESTS.items())
    return f"{version},{pins}"


def awf_argv(awf: str, allow: list[str], config: str, env_file: str, workdir: str,
             awf_work: str, logs: str, inner: str) -> list[str]:
    """The whole AWF command line. Nothing here comes from the workflow but
    the allow-list, which parse_allow_list has reduced to host names."""
    return [
        awf,
        "--allow-domains", ",".join(allow),
        "--config", config,
        "--env-file", env_file,
        "--container-workdir", workdir,
        "--work-dir", awf_work,
        "--proxy-logs-dir", logs,
        "--image-tag", image_tag(),
        "--log-level", "info",
        "--",
        "/bin/bash", inner,
    ]


# ---------------------------------------------------------------------------
# The probe and the wrapper script that run inside the sandbox
# ---------------------------------------------------------------------------

def inner_script(scratch: str, workdir: str, command_file: str, marker: str, nonce: str,
                 blocked_host: str) -> str:
    """Bash run inside the sandbox: the probe, then the workflow's command.

    The marker file is written only when every probe attempt failed to get
    out; the step trusts the command's exit status only if the marker holds
    the nonce. The command cannot fake a failed probe as a passed one,
    because it never runs after a failed probe.
    """
    return f"""#!/bin/bash
set -u
failed=0
attempt() {{
  # attempt <what> <command...>: the command must fail.
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "obaaf-egress: probe: $what GOT OUT"
    failed=1
  else
    echo "obaaf-egress: probe: $what blocked"
  fi
}}
attempt "direct IPv4 {PROBE_IPV4}:443" curl -sS --noproxy '*' --max-time 5 -o /dev/null https://{PROBE_IPV4}/
attempt "direct IPv6 [{PROBE_IPV6}]:443" curl -sS -6 --noproxy '*' --max-time 5 -o /dev/null "https://[{PROBE_IPV6}]/"
attempt "unlisted host {blocked_host} through the proxy" curl -sS --max-time 10 -o /dev/null https://{blocked_host}/
attempt "unlisted host {blocked_host} without the proxy" curl -sS --noproxy '*' --max-time 5 -o /dev/null https://{blocked_host}/
attempt "sudo" sudo -n true
attempt "Docker socket" bash -c "curl -sS --max-time 5 --unix-socket /var/run/docker.sock http://localhost/_ping || curl -sS --max-time 5 --unix-socket /run/docker.sock http://localhost/_ping"
if [ "$failed" -ne 0 ]; then
  echo "obaaf-egress: the sandbox did not hold; the command was not run"
  exit {EXIT_NOT_CONFINED}
fi
printf '%s\\n' '{nonce}' > '{marker}'
# AWF sets HOME to the runner user's home, which is read-only in here; give
# the command the scratch home, whose tool directories AWF mounts writable.
export HOME='{scratch}/home'
export TMPDIR='{scratch}/tmp'
cd '{workdir}' || exit {EXIT_NOT_CONFINED}
exec /bin/bash -e '{command_file}'
"""


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _state_dir() -> Path:
    base = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
    return Path(base) / "obaaf-egress"


def install() -> int:
    """Download AWF's binary and check it against the pinned SHA-256."""
    state = _state_dir()
    (state / "bin").mkdir(parents=True, exist_ok=True)
    target = state / "bin" / "awf"
    if target.exists() and _sha256(target) == AWF_SHA256:
        print(f"obaaf-egress: AWF {AWF_VERSION} already installed")
        return 0
    url = f"https://github.com/github/gh-aw-firewall/releases/download/{AWF_VERSION}/{AWF_BINARY}"
    partial = target.with_suffix(".download")
    with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as out:
        shutil.copyfileobj(response, out)
    actual = _sha256(partial)
    if actual != AWF_SHA256:
        partial.unlink()
        print(f"::error::AWF {AWF_VERSION}: SHA-256 {actual} is not the pinned {AWF_SHA256}")
        return 1
    partial.chmod(0o755)
    partial.replace(target)
    print(f"obaaf-egress: AWF {AWF_VERSION} installed, SHA-256 {AWF_SHA256}")
    return 0


def _runner_file_hashes(environ: dict[str, str]) -> dict[str, str | None]:
    hashes: dict[str, str | None] = {}
    for name in RUNNER_FILES:
        value = environ.get(name)
        if not value:
            continue
        path = Path(value)
        hashes[name] = _sha256(path) if path.is_file() else None
    return hashes


def _denied_hosts(log_dir: Path) -> list[str]:
    """Hosts the proxy refused, from Squid's access log.

    AWF v0.29.13 writes the log in its format ``firewall_detailed``:
    ``time client:port host dest:port version method status code:hierarchy url "agent"``,
    where ``host`` is the request's Host header (``name:443`` for CONNECT).
    """
    hosts: list[str] = []
    for log in sorted(log_dir.rglob("access*.log")):
        try:
            text = log.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 9 or "DENIED" not in fields[7]:
                continue
            host = fields[2] if fields[2] != "-" else fields[8].split("://", 1)[-1].split("/", 1)[0]
            host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def _remove(path: Path) -> None:
    """Delete a file or directory tree that AWF or the action made.

    AWF's entrypoint creates some directories in the command's home as root
    (.m2 and .gradle), so the runner user cannot always delete them; on a
    hosted runner the action can use sudo, which the command cannot. A
    symlink is removed, never followed, and rm does not follow symlinks
    inside the tree or cross into another file system.
    """
    try:
        if path.is_symlink() or not path.is_dir():
            path.unlink()
            return
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)
    if path.exists() and not path.is_symlink():
        subprocess.run(["sudo", "-n", "rm", "-rf", "--one-file-system", "--", str(path)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False, env={"PATH": FIXED_PATH})


def _set_output(environ: dict[str, str], name: str, value: str) -> None:
    path = environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def _summary(environ: dict[str, str], text: str) -> None:
    path = environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def run(environ: dict[str, str]) -> int:
    """Run the workflow's command under AWF. Returns the step's exit status."""
    allow = parse_allow_list(environ.get("INPUT_ALLOW", ""))
    passed = parse_env_names(environ.get("INPUT_ENV", ""), environ)
    command = environ.get("INPUT_RUN", "")
    if not command.strip():
        raise UsageError("run: give the command to run")
    blocked = probe_host(allow)

    state = _state_dir()
    awf = state / "bin" / "awf"
    if not awf.is_file() or _sha256(awf) != AWF_SHA256:
        print("::error::AWF is not installed at the pinned version; the install step did not run or failed")
        return EXIT_NOT_CONFINED
    if shutil.which("docker", path=FIXED_PATH) is None:
        print("::error::Docker is not available on this runner; the egress control needs it")
        return EXIT_NOT_CONFINED

    for mountpoint in AWF_TMP_MOUNTPOINTS:
        Path(mountpoint).mkdir(parents=True, exist_ok=True)

    # The only place the command can write. Under /tmp because AWF mounts the
    # host's /tmp and narrows writes to the listed paths inside mounts it has.
    scratch = Path(tempfile.mkdtemp(prefix="obaaf-egress.", dir="/tmp"))
    for sub in ("home", "tmp", "workspace"):
        (scratch / sub).mkdir()
    workspace = Path(environ.get("GITHUB_WORKSPACE") or os.getcwd())
    git_config = workspace / ".git" / "config"
    if git_config.is_file() and "extraheader" in git_config.read_text(errors="replace").lower():
        shutil.rmtree(scratch, ignore_errors=True)
        raise UsageError("the workspace's .git/config holds a credential (actions/checkout without persist-credentials: false); the copy the command works on would carry it")
    copy = scratch / "workspace"
    shutil.copytree(workspace, copy, symlinks=True, dirs_exist_ok=True)

    # AWF's own files and the proxy's log: outside the scratch directory, in a
    # directory AWF requires to be private.
    run_id = scratch.name.split(".", 1)[1]
    private = state / run_id
    awf_work = private / "work"
    logs = private / "proxy-logs"
    # AWF moves its log, session, audit and diagnostics directories into its
    # temporary directory when it cleans up (src/artifact-preservation.ts),
    # and the command can write the first two. Give AWF a temporary
    # directory inside the private one, so that they are deleted with it.
    awf_tmp = private / "awf-tmp"
    for path in (private, awf_work, awf_tmp):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)

    config = private / "awf-config.json"
    config.write_text(json.dumps({"filesystem": {"allowWrite": [str(scratch)]}}) + "\n")
    env_file = private / "command.env"
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        for name, value in passed.items():
            handle.write(f"{name}={value}\n")

    command_file = scratch / "command.sh"
    command_file.write_text(command if command.endswith("\n") else command + "\n")
    nonce = secrets.token_hex(16)
    # The marker must be written from inside, so it lives in the scratch
    # directory; the step reads it from there and checks the nonce.
    marker = scratch / ".obaaf-egress-probe"
    inner = scratch / ".obaaf-egress-inner.sh"
    inner.write_text(inner_script(str(scratch), str(copy), str(command_file), str(marker), nonce, blocked))

    child_env = {
        "PATH": FIXED_PATH,
        "HOME": str(scratch / "home"),
        "TMPDIR": str(awf_tmp),
        "LANG": "C.UTF-8",
    }
    argv = awf_argv(str(awf), allow, str(config), str(env_file), str(copy), str(awf_work), str(logs), str(inner))

    before = _runner_file_hashes(environ)
    token = secrets.token_hex(16)
    print(f"obaaf-egress: AWF {AWF_VERSION}; allowed: {', '.join(allow)}")
    print(f"obaaf-egress: the command can write only under {scratch}")
    sys.stdout.flush()
    print(f"::stop-commands::{token}", flush=True)
    started = time.monotonic()
    try:
        completed = subprocess.run(argv, env=child_env, cwd=str(copy), stdin=subprocess.DEVNULL, check=False)
        status = completed.returncode
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        print(f"\n::{token}::", flush=True)
    elapsed = time.monotonic() - started
    try:
        env_file.unlink()
    except OSError:
        pass
    # AWF's own directories for this run, some of which it mounts writable
    # for the command: its log and session directories inside the working
    # directory, and the command's home, which AWF creates beside it as
    # "work-chroot-home". Nothing later should find them. Only the proxy's
    # log, which the command cannot write, is kept.
    left = []
    for path in sorted(private.iterdir()):
        if path == logs:
            continue
        _remove(path)
        if path.exists() or path.is_symlink():
            left.append(str(path))
    if left:
        print(f"::error::obaaf-egress: could not remove {', '.join(left)}, which the command could write; the step fails")
        changed_left = True
    else:
        changed_left = False

    after = _runner_file_hashes(environ)
    changed = [name for name in before if before[name] != after.get(name)]

    try:
        probe_ok = marker.read_text().strip() == nonce
    except OSError:
        probe_ok = False

    denied = _denied_hosts(logs)
    _set_output(environ, "workspace", str(copy))
    _set_output(environ, "scratch", str(scratch))
    _set_output(environ, "log-dir", str(logs))
    _set_output(environ, "exit-code", str(status))
    _set_output(environ, "denied", ",".join(denied))

    lines = ["### OBAAF egress control\n\n",
             f"- AWF {AWF_VERSION}, allowed: {', '.join('`' + h + '`' for h in allow)}\n",
             f"- command exit status: {status}, {elapsed:.0f} s\n"]
    if denied:
        lines.append(f"- refused by the proxy: {', '.join('`' + h + '`' for h in denied)}\n")
    else:
        lines.append("- refused by the proxy: none logged\n")
    if not probe_ok:
        lines.append("- **the sandbox did not start or did not hold: the command did not run**\n")
    _summary(environ, "".join(lines) + "\n")
    print(f"obaaf-egress: refused by the proxy: {', '.join(denied) if denied else 'none logged'}")

    if changed:
        print(f"::error::The runner's {', '.join(changed)} changed while the command ran; the step fails")
        _set_output(environ, "confined", "false")
        return EXIT_NOT_CONFINED
    if changed_left:
        _set_output(environ, "confined", "false")
        return EXIT_NOT_CONFINED
    if not probe_ok:
        print("::error::The egress sandbox did not start or did not hold, so the command did not run. See the probe lines above.")
        _set_output(environ, "confined", "false")
        return EXIT_NOT_CONFINED
    # Set only when the step's status is the command's own, from a sandbox
    # that held and left nothing behind.
    _set_output(environ, "confined", "true")
    return status


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("install", "run", "check-allow"):
        print("usage: egress.py install|run|check-allow", file=sys.stderr)
        return 2
    try:
        if argv[1] == "install":
            return install()
        if argv[1] == "check-allow":
            parse_allow_list(os.environ.get("INPUT_ALLOW", ""))
            parse_env_names(os.environ.get("INPUT_ENV", ""), dict(os.environ))
            return 0
        return run(dict(os.environ))
    except UsageError as error:
        print(f"::error::{error}")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
