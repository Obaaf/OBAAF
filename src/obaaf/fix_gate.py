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
SETTINGS = Path(".github/obaaf-settings.json")
REPORT = b'obaaf check source "${config[@]}" --fail-on never\n'
# Every gate-capable template init has shipped, as it landed, with the checker it installed. A team
# keeps its workflow's checker when only the gate changes, so each is recognised at its own pin and,
# after the pin-only update docs/upgrading.md describes, at the current template's pin. The bytes are
# package data, not rebuilt from the current template: a later edit of the template then cannot stop
# workflows installed from an earlier one being recognised (review-gpt #306, #367). A test holds each
# file to the SHA-256 it had when it landed, so add a file here whenever the template changes.
SETUP = rb"uses: Obaaf/OBAAF/actions/setup-obaaf@[0-9a-f]{40}"
FIRST_GATE = files("obaaf.data").joinpath("init-gate-27b15c9.yaml")
ORIGINAL_SETUP = b"uses: Obaaf/OBAAF/actions/setup-obaaf@4e2ba222d31f9ce8e7e352f18e8f88c75aabcbd8"
SETTINGS_GATE = files("obaaf.data").joinpath("init-gate-settings-8caddd6.yaml")
SETTINGS_SETUP = b"uses: Obaaf/OBAAF/actions/setup-obaaf@8caddd6f06c50b9266d8116fd672f39b55770477"
LANDED = ((FIRST_GATE, ORIGINAL_SETUP), (SETTINGS_GATE, SETTINGS_SETUP))
LEGACY_DIGEST = "58b64917ab435b974f4d6defac5b9c6f2dab3c536097cdef8e7e8402f4977b5c"


def _gate_workflow(template, path, level):
    cmd = f"gate_check {shlex.quote(path.as_posix())} --fail-on {level}\n".encode()
    return template.replace(b"/.github/obaaf-baseline.json\n", b"/" + path.as_posix().encode() + b"\n").replace(REPORT, cmd)


def _candidate(original, path, level):
    crlf = b"\r\n" in original
    if crlf:
        if original.count(b"\r\n") != original.count(b"\n"):
            return None
        original = original.replace(b"\r\n", b"\n")
    template = files("obaaf.data").joinpath("init-workflow.yaml").read_bytes()
    current = re.findall(SETUP, template)
    templates = [template]
    for landed, pin in LANDED:
        body = landed.read_bytes()
        for moved in (body, *(body.replace(pin, setup) for setup in current[:1])):
            if moved not in templates:
                templates.append(moved)
    first = FIRST_GATE.read_bytes()
    names = tuple(init_scanners.SCANNERS)
    for count in range(len(names) + 1):
        for selected in combinations(names, count):
            tail = init_scanners.steps(selected)
            if not original.endswith(tail):
                # Workflows generated before #340 used separate output streams. Preserve their
                # exact scanner steps when a user requests only a gate threshold change.
                tail = tail.replace(b"          exec 2>&1\n", b"")
                if not original.endswith(tail):
                    continue
            body = original.removesuffix(tail)
            for source in templates:
                legacy = source == first and sha256(body).hexdigest() == LEGACY_DIGEST
                if body == source or legacy or any(
                    body == _gate_workflow(source, path, old) for old in ("low", "medium", "high")
                ):
                    updated = _gate_workflow(source, path, level) + tail
                    return updated.replace(b"\n", b"\r\n") if crlf else updated
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
              f"On pull requests, read the target configuration and compare {one_line(shlex.quote(str(path)))} "
              "in both commits. Use only identical baseline entries, up to the count present in both. "
              "If either file is missing, omit --baseline. On pushes, use the pushed policy.")
        return 1 if args.patch is not None else 0
    if options.baseline is not None:
        if not (root / path).is_file():
            raise ProofError("the explicitly selected baseline must exist in the repository")
        if original == updated:
            from obaaf.checker import baseline
            baseline.load(root / path)
    if original == updated:
        print(f"The generated workflow already gates at --fail-on {args.gate}.")
        return 1 if args.patch is not None else 0
    options = replace(options, fail_on=args.gate, baseline=path if (root / path).exists() else None)
    edit = Edit(Path(WORKFLOW), original, updated, (
        ("jobs", "check", "steps", 2, "with", "sparse-checkout"),
        ("jobs", "check", "steps", 3, "run")))
    after = prove(root, options, (edit,), ())
    gated = len(after.gating(args.gate, load()))
    print(f"Gate preview at --fail-on {args.gate}: {gated} "
          f"{'finding currently counts' if gated == 1 else 'findings currently count'}. "
          f"Baseline: {one_line(str(options.baseline)) if options.baseline else 'absent; zero baseline acceptances'}.")
    if b"OBAAF_USE_SETTINGS" in updated and (root / SETTINGS).exists():
        # The preview cannot take --settings (D-112), and the workflow's runs may read the snapshot.
        print(f"This count does not use {SETTINGS.as_posix()}. If the repository variable OBAAF_USE_SETTINGS "
              "is true, the workflow's runs give the checker a snapshot (on a pull request, the target "
              "commit's), so their count can differ.")
    show_diff(edit)
    if args.patch is not None:
        from obaaf.fix_patch import save_patch
        save_patch(args.patch, (edit,))
    elif args.apply:
        sys.stdout.flush()
        if (root / path).is_file() != (options.baseline is not None):
            raise ProofError("the baseline appeared or disappeared since the preview; rerun to review it")
        final = prove(root, options, (edit,), ())
        check_copy_matches(root, after, final)
        for warning in apply_edits(root, lock, (edit,)):
            print(one_line(warning), file=sys.stderr)
        print("Applied the displayed gate change.")
    else:
        from obaaf.fix import apply_preview_guidance
        print(apply_preview_guidance())
    return 0
