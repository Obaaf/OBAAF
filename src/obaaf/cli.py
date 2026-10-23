"""The `obaaf` command line."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from obaaf import __version__

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _repo_root() -> Path:
    """The OBAAF repository this package runs from (for docs and templates)."""
    return Path(__file__).resolve().parents[2]


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _github_output(pairs: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            for key, value in pairs.items():
                value = str(value)
                if "\n" in value or "\r" in value:
                    delimiter = "OBAAF_" + os.urandom(12).hex()
                    handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
                else:
                    handle.write(f"{key}={value}\n")


# ------------------------------------------------------------------ assess
def cmd_assess_init(args) -> int:
    from obaaf import assess

    text = assess.template()
    if args.output and Path(args.output).exists() and not args.force:
        print(f"{args.output} exists; pass --force to overwrite", file=sys.stderr)
        return EXIT_USAGE
    _write(text, args.output)
    return EXIT_OK


def cmd_assess_score(args) -> int:
    from obaaf import assess

    try:
        answers = assess.load_answers(args.answers)
    except (assess.AnswerError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    result = assess.score(answers)
    if args.format == "json":
        text = assess.to_json(result)
    elif args.format == "md":
        text = assess.to_markdown(result, link_base=args.link_base)
    else:
        text = assess.to_text(result, limit=0 if args.all else 10)
    _write(text, args.output)
    return EXIT_OK


def cmd_assess_form(args) -> int:
    from obaaf import render

    _write(render.form_html(link_base=args.link_base), args.output)
    return EXIT_OK


# ------------------------------------------------------------------ check
def cmd_check(args) -> int:
    from obaaf import checker
    from obaaf.catalog import load
    from obaaf.checker import report

    target = Path(args.path)
    try:
        config = checker.Config.load(target if target.is_dir() else target.parent, args.config)
    except (checker.ConfigError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.lanes:
        for wf, job, lane, reason in checker.lanes(target, config):
            print(f"{wf}#{job}: {lane} ({reason})")
        return EXIT_OK
    if not target.exists():
        print(f"error: {target} not found", file=sys.stderr)
        return EXIT_USAGE
    try:
        checker.parse_fail_on(args.fail_on)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    result = checker.check(target, config=config)
    if args.format == "json":
        text = report.to_json(result)
    elif args.format == "sarif":
        text = report.to_sarif(result)
    else:
        text = report.to_text(result, show_fixes=not args.no_fixes)
    _write(text, args.output)
    if result.errors:
        return EXIT_FAIL
    if result.gating(args.fail_on, load()):
        return EXIT_FAIL
    return EXIT_OK


# ------------------------------------------------------------------ snapshot
def _parse_roles(values: list[str], roles_file: str | None) -> dict[str, str]:
    roles = {}
    if roles_file:
        data = json.loads(Path(roles_file).read_text(encoding="utf-8"))
        roles.update({str(k): str(v) for k, v in data.items()})
    for value in values or []:
        login, _, role = value.partition("=")
        if not role:
            raise ValueError(f"--role expects LOGIN=ROLE, got {value!r}")
        roles[login] = role
    return roles


def cmd_snapshot(args) -> int:
    from obaaf.attest import snapshot
    from obaaf.attest.common import RecordError

    try:
        roles = _parse_roles(args.role, args.roles_file)
        extra = []
        for spec in args.file or []:
            parts = spec.rsplit(":", 2)
            if len(parts) != 3:
                raise ValueError(f"--file expects PATH:CHANNEL:LABEL, got {spec!r}")
            extra.append((parts[0], parts[1], parts[2]))
        record = snapshot.take(args.event, args.event_name, args.out, repository=args.repository or "",
                               visibility=args.visibility, roles=roles, floor=args.floor, extra_files=extra)
    except (RecordError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    digest = snapshot.digest(args.out)
    print(f"snapshot: {len(record['inputs'])} input(s), integrity level {record['integrityLevel']}, "
          f"sha256:{digest}")
    _github_output({"snapshot-digest": digest, "integrity-level": record["integrityLevel"]})
    return EXIT_OK


# ------------------------------------------------------------------ manifest
def cmd_manifest_create(args) -> int:
    from obaaf.attest import manifest
    from obaaf.attest.common import RecordError

    try:
        data = manifest.create(args.root, args.components)
    except (RecordError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    manifest.write(data, args.out)
    print(f"manifest: {len(data['entries'])} file(s) in {len(data['components'])} component(s) written to {args.out}")
    return EXIT_OK


def cmd_manifest_check(args) -> int:
    from obaaf.attest import manifest
    from obaaf.attest.common import RecordError

    try:
        problems = manifest.check(args.root, manifest.load(args.manifest))
    except (RecordError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    if problems:
        print(f"Manifest check FAILED: {len(problems)} unrecorded change(s) (G2.1)")
        for problem in problems:
            print(f"  {problem}")
        print("If the change is intended, review it and regenerate the manifest with 'obaaf manifest create'.")
        return EXIT_FAIL
    print("Manifest check passed: every tracked file matches its recorded digest.")
    return EXIT_OK


# ------------------------------------------------------------------ proposal
def cmd_proposal_check(args) -> int:
    from obaaf.attest import proposal

    report = proposal.check(args.bundle, protected=args.protect,
                            allowed_labels=args.allow_label if args.allow_label else None,
                            allow_dot_paths=args.allow_dot_path, repo=args.repo, expect_digest=args.expect_digest)
    if args.json:
        _write(json.dumps(report.to_dict(), indent=2) + "\n", args.output)
    else:
        status = "passed" if report.ok else "FAILED"
        lines = [f"Proposal check {status}: {len(report.files)} file(s), {len(report.touched)} path(s) touched"]
        lines += [f"  {p}" for p in report.problems]
        if report.applied:
            lines.append(f"Applied to a temporary index of {args.repo}: {len(report.applied)} change(s)")
        _write("\n".join(lines) + "\n", args.output)
    return EXIT_OK if report.ok else EXIT_FAIL


# ------------------------------------------------------------------ attest
def _emit(args, subjects, predicate_type, predicate) -> int:
    from obaaf.attest.common import statement, validate_predicate, write_json

    errors = validate_predicate(predicate_type, predicate)
    if errors:
        print("error: the predicate does not match its schema:", file=sys.stderr)
        for e in errors[:10]:
            print(f"  {e}", file=sys.stderr)
        return EXIT_FAIL
    write_json(args.out, predicate)
    if args.statement_out:
        write_json(args.statement_out, statement(subjects, predicate_type, predicate))
    print(f"wrote {args.out} ({predicate_type}, {len(subjects)} subject(s))")
    _github_output({"predicate-path": args.out, "predicate-type": predicate_type})
    return EXIT_OK


def cmd_attest_agent_run(args) -> int:
    from obaaf.attest import records
    from obaaf.attest.common import RecordError
    from obaaf.predicates import AGENT_RUN

    try:
        subjects, predicate = records.agent_run_predicate(
            args.snapshot, args.proposal, args.workflow_file, args.job, snapshot_digest=args.snapshot_digest,
            model_receipt=args.model_receipt, trace=args.trace, harness=args.harness)
    except (RecordError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    return _emit(args, subjects, AGENT_RUN, predicate)


def cmd_attest_approval(args) -> int:
    from obaaf.attest import records
    from obaaf.attest.common import RecordError
    from obaaf.predicates import AGENT_APPROVAL

    try:
        approvals = json.loads(Path(args.approvals).read_text(encoding="utf-8"))
        checks = json.loads(Path(args.checks).read_text(encoding="utf-8")) if args.checks else {}
        requesters = [r.strip() for value in (args.requester or []) for r in value.split(",") if r.strip()]
        subjects, predicate = records.approval_predicate(
            args.proposal, approvals, args.environment, requesters, snapshot_dir=args.snapshot,
            agent_run_url=args.agent_run_url or "", checks=checks)
    except (RecordError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    return _emit(args, subjects, AGENT_APPROVAL, predicate)


def cmd_attest_build_record(args) -> int:
    from obaaf.attest import records
    from obaaf.attest.common import RecordError
    from obaaf.predicates import BUILD_RECORD

    try:
        sdks = []
        for value in args.sdk or []:
            name, _, version = value.partition("=")
            if not version:
                raise ValueError(f"--sdk expects NAME=VERSION, got {value!r}")
            sdks.append((name, version))
        subjects, predicate = records.build_record_predicate(
            args.artifact, source_revision=args.source_revision, source_ref=args.source_ref or "",
            repository=args.repository or "", asset_revision=args.asset_revision, asset_system=args.asset_system,
            manifest_path=args.manifest, builder_id=args.builder_id, workflow_file=args.workflow_file,
            build_job=args.build_job, tier=args.tier, extra_sdks=sdks, trigger_actor=args.actor or "")
    except (RecordError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    return _emit(args, subjects, BUILD_RECORD, predicate)


def cmd_attest_slsa(args) -> int:
    from obaaf.attest import records
    from obaaf.attest.common import RecordError, files_under, statement, subjects_for, write_json
    from obaaf.predicates import SLSA_PROVENANCE_V1

    try:
        files = []
        for artifact in args.artifact:
            files += files_under(artifact)
        subjects = subjects_for(files)
    except RecordError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    predicate = records.slsa_provenance_predicate(builder_id=args.builder_id, repository_uri=args.repository_uri,
                                                  source_revision=args.source_revision, source_ref=args.source_ref or "",
                                                  invocation_id=args.invocation_id or "")
    write_json(args.out, predicate)
    if args.statement_out:
        write_json(args.statement_out, statement(subjects, SLSA_PROVENANCE_V1, predicate))
    print(f"wrote {args.out} ({SLSA_PROVENANCE_V1}, {len(subjects)} subject(s))")
    return EXIT_OK


# ------------------------------------------------------------------ records
def cmd_record_write(args) -> int:
    from obaaf.attest import agentrecord
    from obaaf.attest.common import RecordError

    try:
        agent_run = json.loads(Path(args.agent_run_bundle).read_text(encoding="utf-8"))
        approval = json.loads(Path(args.approval_bundle).read_text(encoding="utf-8"))
        record = agentrecord.build(args.proposal, agent_run, approval, args.agent_run_url or "")
        path = agentrecord.write(record, args.records_dir)
    except (RecordError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    from obaaf.attest.common import sha256_file

    print(path.as_posix())
    _github_output({"record-path": path.as_posix(), "bundle-digest": record["bundleDigest"]["sha256"],
                    "record-sha256": sha256_file(path)})
    return EXIT_OK


# ------------------------------------------------------------------ verify
def cmd_verify_release(args) -> int:
    from obaaf.attest.common import RecordError
    from obaaf.verify import release
    from obaaf.verify.policy import Policy, PolicyError

    try:
        policy = Policy.load(args.policy)
        approvals = json.loads(Path(args.approvals).read_text(encoding="utf-8")) if args.approvals else None
    except (PolicyError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    gh = release.GhRunner(args.gh) if policy.signing == "sigstore" or policy.agents_check else None
    try:
        decision = release.verify_release(
            policy, [Path(a) for a in args.artifacts], gh=gh, dsse_files=[Path(p) for p in args.dsse or []],
            approvals=approvals, actors=args.actor or [], repo_dir=Path(args.repo_dir) if args.repo_dir else None,
            git_range=args.range, source_revision=args.source_revision, pre_approval=args.pre_approval)
    except (RecordError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    text = json.dumps(decision.to_dict(), indent=2) + "\n" if args.format == "json" else decision.to_text()
    _write(text, args.output)
    if args.format == "json" and args.output:
        sys.stdout.write(decision.to_text())
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## OBAAF release verification\n\n```\n" + decision.to_text() + "```\n")
    return EXIT_OK if decision.ok else EXIT_FAIL


def cmd_verify_agent_run(args) -> int:
    from obaaf.verify import release
    from obaaf.verify.policy import Policy, PolicyError

    try:
        policy = Policy.load(args.policy)
    except (PolicyError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    gh = release.GhRunner(args.gh) if policy.signing == "sigstore" else None
    result = release.verify_agent_run(policy, Path(args.proposal), Path(args.snapshot), Path(args.bundle), gh=gh,
                                      run_id=args.run_id)
    outputs = result.outputs()
    if args.json:
        _write(json.dumps({"format": "obaaf-agent-run-check/v0.1", "ok": result.ok, "problems": result.problems,
                           "outputs": outputs}, indent=2) + "\n", args.output)
    else:
        lines = ["Agent-run record " + ("verified" if result.ok else "REJECTED")]
        lines += [f"  {p}" for p in result.problems]
        if result.ok:
            lines += [f"  {k}: {v}" for k, v in outputs.items()]
        _write("\n".join(lines) + "\n", args.output)
    if result.ok:
        _github_output(outputs)
    return EXIT_OK if result.ok else EXIT_FAIL


# ------------------------------------------------------------------ templates and docs
def cmd_templates_install(args) -> int:
    import re

    source = Path(args.source) if args.source else _repo_root() / "templates" / "github-actions"
    if not (source / "workflows").is_dir():
        print(f"error: templates not found in {source}; run from a clone of the OBAAF repository or pass --source",
              file=sys.stderr)
        return EXIT_USAGE
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", args.obaaf_repo or ""):
        print("error: --obaaf-repo must be OWNER/REPO", file=sys.stderr)
        return EXIT_USAGE
    if not re.fullmatch(r"[0-9a-f]{40}", args.obaaf_sha or "") or set(args.obaaf_sha) == {"0"}:
        print("error: --obaaf-sha must be the full 40-character commit SHA of the OBAAF release to use",
              file=sys.stderr)
        return EXIT_USAGE
    owner = args.obaaf_repo.split("/")[0]
    dest = Path(args.dest) / ".github" / "workflows"
    dest.mkdir(parents=True, exist_ok=True)
    written = []
    for src in sorted((source / "workflows").glob("*.yml")):
        target = dest / src.name
        if target.exists() and not args.force:
            print(f"skip {target} (exists; pass --force to overwrite)")
            continue
        text = src.read_text(encoding="utf-8")
        text = text.replace("OBAAF_OWNER/obaaf", args.obaaf_repo).replace("OBAAF_OWNER", owner)
        text = text.replace("0" * 40, args.obaaf_sha)
        target.write_text(text, encoding="utf-8")
        written.append(target)
    dest_root = Path(args.dest)
    copies = {
        "obaaf-policy.example.yaml": dest_root / ".github" / "obaaf-policy.yaml",
        "obaaf.yml.example": dest_root / ".github" / "obaaf.yml",
        "obaaf-sources.example.yaml": dest_root / "obaaf-sources.yaml",
        "agent/agent.sh": dest_root / ".github" / "obaaf" / "agent.sh",
    }
    for name, target in copies.items():
        src = source / name
        if src.is_file() and (not target.exists() or args.force):
            target.parent.mkdir(parents=True, exist_ok=True)
            text = src.read_text(encoding="utf-8").replace("OWNER/REPO", args.repository or "OWNER/REPO")
            target.write_text(text, encoding="utf-8")
            if target.suffix == ".sh":
                target.chmod(0o755)
            written.append(target)
    for path in written:
        print(f"wrote {path}")
    print("Next: copy templates/github-actions/CODEOWNERS.example into .github/CODEOWNERS, edit the build and "
          "publish steps, set up the environments in docs/github-settings.md, then run 'obaaf check'.")
    return EXIT_OK


def cmd_docs_build(args) -> int:
    from obaaf import render

    root = Path(args.root) if args.root else _repo_root()
    stale = render.build(root, check_only=args.check)
    if args.check:
        if stale:
            print("Out of date (run 'obaaf docs build'):")
            for path in stale:
                print(f"  {path.relative_to(root)}")
            return EXIT_FAIL
        print("Generated files are up to date.")
        return EXIT_OK
    for path in stale:
        print(f"wrote {path.relative_to(root)}")
    if not stale:
        print("Generated files were already up to date.")
    return EXIT_OK


def cmd_catalog_check(args) -> int:
    from obaaf.catalog import load

    problems = load().problems()
    for problem in problems:
        print(problem)
    if not problems:
        print("Catalog is consistent: 28 profile requirements, 34 assessment items, R1–R8, and all cross-references.")
    return EXIT_FAIL if problems else EXIT_OK


# ------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="obaaf", description="Open Build and Agent Assurance Framework tools (draft).")
    p.add_argument("--version", action="version", version=f"obaaf {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # assess
    a = sub.add_parser("assess", help="the self-assessment").add_subparsers(dest="sub", required=True)
    x = a.add_parser("init", help="write an answer file to fill in")
    x.add_argument("--output", "-o")
    x.add_argument("--force", action="store_true")
    x.set_defaults(func=cmd_assess_init)
    x = a.add_parser("score", help="score an answer file and rank the fixes")
    x.add_argument("answers")
    x.add_argument("--format", choices=("text", "md", "json"), default="text")
    x.add_argument("--output", "-o")
    x.add_argument("--all", action="store_true", help="list every open item, not the first ten")
    x.add_argument("--link-base", default="", help="prefix for fix links in Markdown output")
    x.set_defaults(func=cmd_assess_score)
    x = a.add_parser("form", help="write the offline HTML form")
    x.add_argument("--output", "-o")
    x.add_argument("--link-base", default="../")
    x.set_defaults(func=cmd_assess_form)

    # check
    x = sub.add_parser("check", help="check workflow files and repository settings for risky pipeline settings")
    x.add_argument("path", nargs="?", default=".", help="repository root (default) or one workflow file")
    x.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    x.add_argument("--output", "-o")
    x.add_argument("--fail-on", default="medium",
                   help="fail on findings at or above a severity (high, medium, low), or never. "
                        "Prefix a category to gate on it alone: authority:medium, hygiene:low, or just authority.")
    x.add_argument("--config", help="checker configuration (default: .github/obaaf.yml if present)")
    x.add_argument("--lanes", action="store_true", help="show how each job was classified and exit")
    x.add_argument("--no-fixes", action="store_true", help="omit fix text in text output")
    x.set_defaults(func=cmd_check)

    # snapshot
    x = sub.add_parser("snapshot", help="agent lane: capture and label the inputs an agent will read (R1)")
    x.add_argument("--event", required=True, help="path to the event payload ($GITHUB_EVENT_PATH)")
    x.add_argument("--event-name", required=True)
    x.add_argument("--out", required=True)
    x.add_argument("--repository")
    x.add_argument("--visibility", choices=("public", "private", "internal"), default="public")
    x.add_argument("--role", action="append", help="LOGIN=ROLE from the repository permission API")
    x.add_argument("--roles-file", help="JSON mapping of login to repository role")
    x.add_argument("--floor", choices=("Public", "Contributor", "Maintainer", "Release"))
    x.add_argument("--file", action="append", help="PATH:CHANNEL:LABEL for an extra input file")
    x.set_defaults(func=cmd_snapshot)

    # manifest
    m = sub.add_parser("manifest", help="the binary manifest (G2.1)").add_subparsers(dest="sub", required=True)
    x = m.add_parser("create")
    x.add_argument("--components", required=True, help="YAML file declaring vendored components")
    x.add_argument("--root", default=".")
    x.add_argument("--out", required=True)
    x.set_defaults(func=cmd_manifest_create)
    x = m.add_parser("check")
    x.add_argument("--manifest", required=True)
    x.add_argument("--root", default=".")
    x.set_defaults(func=cmd_manifest_check)

    # proposal
    pr = sub.add_parser("proposal", help="agent proposals (R4)").add_subparsers(dest="sub", required=True)
    x = pr.add_parser("check", help="deterministic checks before applying a proposal")
    x.add_argument("bundle")
    x.add_argument("--protect", action="append", help="extra protected path glob (e.g. scripts a release job runs)")
    x.add_argument("--allow-label", action="append", help="a label the agent may add or remove")
    x.add_argument("--allow-dot-path", action="append",
                   help="glob of paths under names starting with '.' that the agent may change (never protected ones)")
    x.add_argument("--repo", help="also apply the patch to a temporary index of this repository at HEAD and check "
                                  "the result, including file modes (use this before applying)")
    x.add_argument("--expect-digest", help="fail unless the bundle's digest (as in its agent record) is this")
    x.add_argument("--json", action="store_true")
    x.add_argument("--output", "-o")
    x.set_defaults(func=cmd_proposal_check)

    # attest
    at = sub.add_parser("attest", help="write predicates to sign").add_subparsers(dest="sub", required=True)
    x = at.add_parser("agent-run", help="the agent-run record (R8)")
    x.add_argument("--snapshot", required=True)
    x.add_argument("--snapshot-digest")
    x.add_argument("--proposal", required=True)
    x.add_argument("--workflow-file", required=True)
    x.add_argument("--job", required=True)
    x.add_argument("--model-receipt")
    x.add_argument("--trace")
    x.add_argument("--harness", action="append")
    x.add_argument("--out", required=True)
    x.add_argument("--statement-out")
    x.set_defaults(func=cmd_attest_agent_run)
    x = at.add_parser("approval", help="the approval record (R4)")
    x.add_argument("--proposal", required=True)
    x.add_argument("--approvals", required=True, help="JSON from the workflow run approvals API")
    x.add_argument("--environment", required=True)
    x.add_argument("--requester", action="append",
                   help="who asked for the work (repeatable or comma-separated); the snapshot adds its principal "
                        "and every author of the agent's inputs")
    x.add_argument("--snapshot")
    x.add_argument("--agent-run-url")
    x.add_argument("--checks", help="JSON report from 'obaaf proposal check --json'")
    x.add_argument("--out", required=True)
    x.add_argument("--statement-out")
    x.set_defaults(func=cmd_attest_approval)
    x = at.add_parser("build-record", help="the build record (G7.1)")
    x.add_argument("--artifact", action="append", required=True)
    x.add_argument("--source-revision", required=True)
    x.add_argument("--source-ref")
    x.add_argument("--repository")
    x.add_argument("--asset-revision", required=True)
    x.add_argument("--asset-system", default="git")
    x.add_argument("--manifest", required=True)
    x.add_argument("--builder-id", required=True)
    x.add_argument("--workflow-file")
    x.add_argument("--build-job", default="build")
    x.add_argument("--tier", choices=("A", "B"))
    x.add_argument("--sdk", action="append", help="NAME=VERSION reported by the build")
    x.add_argument("--actor")
    x.add_argument("--out", required=True)
    x.add_argument("--statement-out")
    x.set_defaults(func=cmd_attest_build_record)
    x = at.add_parser("slsa", help="generic SLSA v1 provenance for CI systems without their own")
    x.add_argument("--artifact", action="append", required=True)
    x.add_argument("--builder-id", required=True)
    x.add_argument("--repository-uri", required=True)
    x.add_argument("--source-revision", required=True)
    x.add_argument("--source-ref")
    x.add_argument("--invocation-id")
    x.add_argument("--out", required=True)
    x.add_argument("--statement-out")
    x.set_defaults(func=cmd_attest_slsa)

    # record
    r = sub.add_parser("record", help="agent records that travel with a change").add_subparsers(dest="sub", required=True)
    x = r.add_parser("write")
    x.add_argument("--proposal", required=True)
    x.add_argument("--agent-run-bundle", required=True)
    x.add_argument("--approval-bundle", required=True)
    x.add_argument("--agent-run-url")
    x.add_argument("--records-dir", default=".obaaf/records")
    x.set_defaults(func=cmd_record_write)

    # verify
    v = sub.add_parser("verify", help="verification before upload").add_subparsers(dest="sub", required=True)
    x = v.add_parser("release", help="block an upload unless provenance, approvals and agent records verify (FR6)")
    x.add_argument("--policy", required=True)
    x.add_argument("--artifacts", nargs="+", required=True)
    x.add_argument("--gh", default="gh", help="path to the GitHub CLI")
    x.add_argument("--dsse", action="append", help="DSSE envelope or bundle (signing: keys)")
    x.add_argument("--approvals", help="JSON from the workflow run approvals API")
    x.add_argument("--actor", action="append",
                   help="someone who started or re-ran the release; their approvals do not count (repeatable)")
    x.add_argument("--pre-approval", action="store_true",
                   help="skip the approvals check, to show the result to the approver before they approve")
    x.add_argument("--repo-dir", help="git checkout with history, to read agent records from")
    x.add_argument("--range", help="git range to check for agent commits (default: from the policy's "
                                   "agents.since to --source-revision)")
    x.add_argument("--source-revision", help="the commit being released")
    x.add_argument("--format", choices=("text", "json"), default="text")
    x.add_argument("--output", "-o")
    x.set_defaults(func=cmd_verify_release)
    x = v.add_parser("agent-run", help="check an agent run's signed record before acting on its proposal (R8)")
    x.add_argument("--policy", required=True)
    x.add_argument("--proposal", required=True, help="the downloaded proposal bundle")
    x.add_argument("--snapshot", required=True, help="the downloaded snapshot")
    x.add_argument("--bundle", required=True, help="the agent-run attestation bundle (or DSSE envelope)")
    x.add_argument("--run-id", help="the agent run's ID, which the record must name")
    x.add_argument("--gh", default="gh", help="path to the GitHub CLI")
    x.add_argument("--json", action="store_true")
    x.add_argument("--output", "-o")
    x.set_defaults(func=cmd_verify_agent_run)

    # templates, docs, catalog
    t = sub.add_parser("templates", help="pipeline templates").add_subparsers(dest="sub", required=True)
    x = t.add_parser("install", help="copy the GitHub Actions templates into a repository")
    x.add_argument("--dest", default=".")
    x.add_argument("--obaaf-repo", required=True, help="OWNER/REPO of the OBAAF repository to pin")
    x.add_argument("--obaaf-sha", required=True, help="full commit SHA of the OBAAF release to pin")
    x.add_argument("--repository", help="OWNER/REPO of the repository being set up (fills in the policy file)")
    x.add_argument("--source", help="templates directory (default: this repository's)")
    x.add_argument("--force", action="store_true")
    x.set_defaults(func=cmd_templates_install)
    d = sub.add_parser("docs", help="maintainer tasks").add_subparsers(dest="sub", required=True)
    x = d.add_parser("build", help="regenerate spec/ and the offline form from the data files")
    x.add_argument("--check", action="store_true", help="fail if any generated file is out of date")
    x.add_argument("--root")
    x.set_defaults(func=cmd_docs_build)
    x = sub.add_parser("catalog", help="check the data files for consistency")
    x.set_defaults(func=cmd_catalog_check)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)
