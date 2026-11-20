"""Enable a gate only on the complete workflow emitted by init."""

from dataclasses import replace
from hashlib import sha256
from importlib.resources import files
from itertools import combinations
from pathlib import Path
import re
import shlex
import sys

from obaaf import init_scanners
from obaaf.catalog import load
from obaaf.fix_apply import apply_edits
from obaaf.fix_proof import Edit, ProofError, check_copy_matches, prove
from obaaf.init import WORKFLOW
from obaaf.checker.workflow import one_line

BASELINE = Path(".github/obaaf-baseline.json")
REPORT = b'obaaf check source "${config[@]}" --fail-on never\n'
LEGACY_DIGEST = "58b64917ab435b974f4d6defac5b9c6f2dab3c536097cdef8e7e8402f4977b5c"


def _gate_workflow(template, path, level):
    cmd = f"gate_check {shlex.quote(path.as_posix())} --fail-on {level}\n".encode()
    return template.replace(b"/.github/obaaf-baseline.json\n", b"/" + path.as_posix().encode() + b"\n").replace(REPORT, cmd)


def _candidate(original, path, level):
    template = files("obaaf.data").joinpath("init-workflow.yaml").read_bytes()
    desired = _gate_workflow(template, path, level)
    names = tuple(init_scanners.SCANNERS)
    for count in range(len(names) + 1):
        for selected in combinations(names, count):
            tail = init_scanners.steps(selected)
            if not original.endswith(tail):
                continue
            body = original.removesuffix(tail)
            if body in (template, desired) or sha256(body).hexdigest() == LEGACY_DIGEST:
                return desired + tail
            # A gate previously set by this command may change thresholds under the same policy.
            if any(body == _gate_workflow(template, path, old) for old in ("low", "medium", "high")):
                return desired + tail
    return None


def run(args, root, options, lock, show_diff):
    if options.path != Path(".") or options.platform != "auto" or options.config is not None:
        raise ProofError("--gate checks the whole repository with the configuration the workflow uses")
    if any(getattr(args, field) is not None for field in ("owner", "reason", "expires", "fail_on")):
        raise ProofError("--gate is a separate operation; omit acceptance metadata and --fail-on")
    path = options.baseline or BASELINE
    if not re.fullmatch(r"[a-zA-Z0-9_./ -]+", path.as_posix()) or any(
            part in (".git", "..") or part.endswith(" ") for part in path.parts):
        raise ProofError("this baseline path cannot be written literally in the checkout pattern; edit the workflow by hand")
    workflow = root / WORKFLOW
    for target in (workflow, root / path):
        for part in (target, *target.parents):
            if part == root:
                break
            if part.is_symlink():
                raise ProofError(f"gate policy path contains a link: {part.relative_to(root)}")
    original = workflow.read_bytes() if workflow.is_file() else b""
    updated = _candidate(original, path, args.gate)
    if updated is None:
        print(f"Review your CI workflow by hand. Use --fail-on {args.gate} in its obaaf check command. "
              f"Read the configuration and --baseline {one_line(shlex.quote(str(path)))} from the target commit "
              "on pull requests. If that commit has no baseline, omit --baseline.")
        return 0
    if options.baseline is not None:
        if not (root / path).is_file():
            raise ProofError("the explicitly selected baseline must exist in the repository")
        if original == updated:
            from obaaf.checker import baseline
            baseline.load(root / path)
    if original == updated:
        print(f"The generated workflow already gates at --fail-on {args.gate}.")
        return 0
    options = replace(options, fail_on=args.gate, baseline=path if (root / path).exists() else None)
    edit = Edit(Path(WORKFLOW), original, updated, (
        ("jobs", "check", "steps", 2, "with", "sparse-checkout"),
        ("jobs", "check", "steps", 3, "run")))
    after = prove(root, options, (edit,), ())
    gated = len(after.gating(args.gate, load()))
    print(f"Gate preview at --fail-on {args.gate}: {gated} "
          f"{'finding currently counts' if gated == 1 else 'findings currently count'}. "
          f"Baseline: {one_line(str(options.baseline)) if options.baseline else 'absent; zero baseline acceptances'}.")
    show_diff(edit)
    if args.apply:
        sys.stdout.flush()
        if (root / path).is_file() != (options.baseline is not None):
            raise ProofError("the baseline appeared or disappeared since the preview; rerun to review it")
        final = prove(root, options, (edit,), ())
        check_copy_matches(root, after, final)
        for warning in apply_edits(root, lock, (edit,)):
            print(one_line(warning), file=sys.stderr)
        print("Applied the displayed gate change.")
    else:
        print("Run again with --apply to enable the displayed gate.")
    return 0
