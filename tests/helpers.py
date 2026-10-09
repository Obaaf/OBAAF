"""Shared helpers for OBAAF's offline acceptance tests."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from obaaf import cli, yamlutil  # noqa: E402
from obaaf.checker import workflow as wf_mod  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
RISKY = FIXTURES / "workflows" / "risky"
TEMPLATES = ROOT / "templates" / "github-actions"
TEST_SHA = "1" * 40
TEST_OWNER_REPO = "example-studio/obaaf"
# Findings the installed templates are expected to keep, because they are true until the adopter acts:
# GitHub-hosted runners have no egress allow-list, so the agent job's egress policy is declared but
# not enforced until a monitor or a network policy is added (FR7, docs/github-settings.md).
KNOWN_TEMPLATE_FINDINGS = {("OBAAF-GHA-020", ".github/workflows/obaaf-agent-propose.yml", "low")}


def unexpected_findings(findings) -> list:
    return [(f.rule, f.path, f.message) for f in findings
            if (f.rule, f.path, f.severity) not in KNOWN_TEMPLATE_FINDINGS]


def run_cli(*args: str) -> tuple[int, str, str]:
    """Run the obaaf command line in-process and capture its output."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main([str(a) for a in args])
        except SystemExit as exc:  # argparse errors
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class TempDir:
    def __enter__(self) -> Path:
        self._dir = tempfile.mkdtemp(prefix="obaaf-test-")
        return Path(self._dir)

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)


def install_templates(dest: Path, repository: str = "example-studio/game") -> Path:
    """Install the templates into `dest` as an adopting studio would, with CODEOWNERS."""
    code, out, err = run_cli("templates", "install", "--dest", dest, "--obaaf-repo", TEST_OWNER_REPO,
                             "--obaaf-sha", TEST_SHA, "--repository", repository)
    if code != 0:
        raise AssertionError(f"templates install failed: {err or out}")
    shutil.copyfile(TEMPLATES / "CODEOWNERS.example", dest / ".github" / "CODEOWNERS")
    return dest


def workflow(path: Path) -> wf_mod.Workflow:
    wf = wf_mod.parse(path.name, path.read_text(encoding="utf-8"))
    assert wf.error is None, wf.error
    wf_mod.classify(wf)
    return wf


def template_workflow(name: str) -> wf_mod.Workflow:
    return workflow(TEMPLATES / "workflows" / name)


def all_steps(wf: wf_mod.Workflow):
    for job in wf.jobs.values():
        for step in job.steps:
            yield job, step


# ---------------------------------------------------------------- signing
def make_key(directory: Path, name: str):
    """An ECDSA P-256 key pair; returns (private key, public key path)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pub = directory / f"{name}.pub.pem"
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
    return key, pub


def sign(statement: dict, key) -> dict:
    from obaaf.verify.dsse import sign_envelope

    return sign_envelope(statement, key)


def write_json(path: Path, obj) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------- git
def git(repo: Path, *args: str, env: dict | None = None) -> str:
    full_env = dict(os.environ)
    full_env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                     "GIT_AUTHOR_DATE": "2026-10-01T12:00:00Z", "GIT_COMMITTER_DATE": "2026-10-01T12:00:00Z"})
    full_env.update(env or {})
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=full_env, check=False)
    if proc.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout.strip()


def init_repo(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Maintainer")
    git(repo, "config", "user.email", "maintainer@example.com")
    git(repo, "config", "commit.gpgsign", "false")
    return repo


# The effect lane's commit identity (obaaf-agent-apply.yml).
BOT = {"GIT_AUTHOR_NAME": "OBAAF effect lane",
       "GIT_AUTHOR_EMAIL": "obaaf-effect-lane@noreply.invalid",
       "GIT_COMMITTER_NAME": "OBAAF effect lane",
       "GIT_COMMITTER_EMAIL": "obaaf-effect-lane@noreply.invalid"}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def load_yaml(path: Path):
    return yamlutil.load_file(path)
