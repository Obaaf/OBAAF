"""Run one generated companion-scanner step against a disposable Git repository.

Written for the `companion-scanner` job of `.github/workflows/ci.yml`: it needs Docker, network
access to the scanner's registry, and the runner's `RUNNER_TEMP`.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

import yaml

from obaaf.init import WORKFLOW
from obaaf.init_scanners import SCANNERS


# The fixture workflow is scanned as data. It is never pushed, so it is never dispatched.
FIXTURE = """\
name: Scanner fixture
on: workflow_dispatch
permissions: {}
env:
  ACTIONS_STEP_DEBUG: 'true'
jobs:
  sample:
    permissions: read-all
    runs-on: scanner-fixture-runner
    steps:
      - run: 'true'
"""

FINDINGS = {
    "actionlint": 'label "scanner-fixture-runner" is unknown',
    "zizmor": "excessive-permissions",
    "poutine": "Rule: CI Runner Debug Enabled",
}


def check_scanner(name, workspace):
    source = workspace / "source"
    workflows = source / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "sample.yml").write_text(FIXTURE, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=source, check=True)
    options = [arg for scanner in SCANNERS for arg in ("--with-scanner", scanner)]
    subprocess.run(["obaaf", "init", ".", *options, "--apply"], cwd=source, check=True)
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "Scanner input"], cwd=source, check=True)

    workflow = yaml.safe_load((source / WORKFLOW).read_text(encoding="utf-8"))
    step, = [step for step in workflow["jobs"]["check"]["steps"]
             if step["name"] == f"Report {name} findings"]
    image, _ = SCANNERS[name]
    subprocess.run(["docker", "manifest", "inspect", "--verbose", image], check=True)
    run = subprocess.run(["bash", "-eo", "pipefail", "-c", step["run"]], cwd=workspace,
                         env={**os.environ, "GITHUB_WORKSPACE": str(workspace)},
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = run.stdout.splitlines()
    for line in lines:
        print(f"| {line}")
    run.check_returncode()
    marker = re.fullmatch(r"::stop-commands::([0-9a-f-]+)", lines[0]) if lines else None
    if not marker or lines[-1] != f"::{marker[1]}::":
        raise SystemExit(f"{name} output was not enclosed by matching workflow command markers")
    if not any(FINDINGS[name] in line for line in lines[1:-1]):
        raise SystemExit(f"{name} did not report the expected fixture finding")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", choices=FINDINGS)
    args = parser.parse_args()
    with TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temp:
        check_scanner(args.scanner, Path(temp))
