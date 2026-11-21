"""Offline evidence for a named secret in a GitHub environment (adoption slice A4a)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import stat
import sys

from obaaf.audit import snapshot
from obaaf.audit.github import plain
from obaaf.checker.workflow import environment_match

MAX_AGE = timedelta(days=30)


def fix_input_root(target: Path) -> Path:
    """Find the proof root for a directory scan or a single workflow."""
    from obaaf.checker.workflow import locate

    if any(part.casefold() == ".git" for part in target.resolve().parts):
        raise ValueError(f"check path is in excluded .git metadata: {target}")
    if target.is_dir():
        return locate(target)[0]
    parent = target.absolute().parent.resolve(strict=True)
    for folder in (parent, *parent.parents):
        if (folder / ".git/HEAD").is_file() or (folder / ".git").is_file() or (folder / ".github/workflows").is_dir():
            return folder
    return parent


def fix_input_relative(value, root: Path, *, settings: bool = False) -> Path:
    """Map the input into the proof copy, retaining its ownership name where reproducible."""
    path = Path(value).absolute()
    selected = path
    try:
        folder = path.parent.resolve(strict=True)
        path = folder / path.name
        root = root.resolve(strict=True)
        if path.name == "..":
            path = path.resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError(f"check input must be inside the repository: {value}")
        relative = path.relative_to(root)
        if any(part.casefold() == ".git" for part in relative.parts):
            raise ValueError(f"check input is in excluded .git metadata: {value}")
        # Check the physical location even when the checker also names an in-tree alias. The proof
        # names the input as the checker's ownership rule does (`_as_found`: the typed path with `..`
        # collapsed as text) whenever that name leads to the same file, so both name the same paths.
        # Where it does not (a `..` after a linked folder, #332), the physical location is used.
        proof_path = relative
        textual = Path(os.path.abspath(selected))
        if textual.is_relative_to(root) and _same_path(textual, path):
            proof_path = textual.relative_to(root)
            if any(part.casefold() == ".git" for part in proof_path.parts):
                raise ValueError(f"check input is in excluded .git metadata: {value}")
        if settings:
            _check_snapshot_path(root, selected, relative)
        return proof_path
    except (FileNotFoundError, NotADirectoryError) as exc:
        if settings:
            raise ValueError("--settings: the settings path must name a regular snapshot file") from exc
        raise ValueError(f"cannot resolve check input {value}: {exc}") from exc
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot resolve check input {value}: {exc}") from exc


def _same_path(first: Path, second: Path) -> bool:
    """Whether both names lead to the same path once links are followed (not merely the same inode).
    A missing last component compares by name, as it did before `..` was considered."""
    try:
        return first.resolve() == second.resolve()
    except (OSError, RuntimeError):
        return False


def _check_snapshot_path(root: Path, selected: Path, relative: Path) -> None:
    """Check the selected components that the private copy must be able to reproduce."""
    from obaaf.fix_copy import check_link

    device = root.stat().st_dev

    def lookup(path: Path) -> Path | None:
        entry = root / path
        info = entry.lstat()
        if info.st_dev != device:
            raise ValueError(f"nested filesystem at {str(path)!r}")
        return entry.readlink() if stat.S_ISLNK(info.st_mode) else None

    # An outside alias may enter the repository. Once inside, check each selected
    # component before resolving it, including a linked folder followed by "..".
    folder = Path(selected.anchor)
    for part in selected.parent.parts[1:]:
        if folder.is_relative_to(root) and part != "..":
            check_link(folder.relative_to(root) / part, lookup)
        folder = (folder / part).resolve(strict=True)

    # An outside alias may also enter below a mount point inside the repository.
    for parent in relative.parents:
        if parent != Path("."):
            lookup(parent)
    check_link(relative, lookup)
    info = (root / relative).stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("--settings: the settings path must name a regular snapshot file")
    if info.st_nlink != 1:
        raise ValueError("--settings is a hard-linked file")


@dataclass(frozen=True)
class Assessment:
    verdict: str
    reason: str


@dataclass
class SettingsEvidence:
    data: dict
    limitations: tuple[str, ...]
    source: Path

    @property
    def taken_at(self) -> str:
        return self.data["taken_at"]

    @classmethod
    def load(cls, path: Path, repository: str | None, now: datetime | None = None) -> SettingsEvidence:
        try:
            regular = path.is_file()
        except OSError as exc:      # a name too long for the file system, for one
            raise snapshot.SnapshotError(f"the settings path cannot be read: {exc.strerror or exc}") from exc
        if not regular:
            raise snapshot.SnapshotError("the settings path must name a regular snapshot file")
        data = snapshot.load(path)
        try:
            taken = datetime.strptime(data["taken_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise snapshot.SnapshotError("taken_at is not a valid UTC timestamp") from exc
        age = (now or datetime.now(timezone.utc)) - taken
        issues = []
        if age < timedelta(0):
            issues.append("the snapshot is dated in the future")
        elif age > MAX_AGE:
            issues.append("the snapshot is older than 30 days")
        if not repository:
            issues.append("the checked repository has no established github.com identity")
        elif repository.lower() != data["repository"].lower() or data["api"].rstrip("/") != "https://api.github.com":
            issues.append("the snapshot repository or API host differs from the checked repository")
        repo = data["settings"]["repository"]
        if repo["status"] == "read" and repo["value"]["full_name"].lower() != data["repository"].lower():
            issues.append("the repository named by the snapshot differs from its observed repository identity")
        evidence = cls(data, tuple(issues), path.absolute())
        if repo["status"] != "read":
            evidence.limitations += (evidence._unread("repository"),)
        return evidence

    def for_scan(self, root: Path, repository_scan: bool) -> SettingsEvidence:
        """Restrict evidence to scans that can check its source file for code ownership."""
        from obaaf.checker import _as_found

        if not repository_scan:
            reason = ("this scan does not check snapshot code ownership; run obaaf check "
                      "on the repository directory without --lanes")
        elif not (self.source.resolve().is_relative_to(root.resolve())
                  and _as_found(self.source, root.resolve(), strict=True)):
            # A link outside the repository may point inside without being checked for ownership.
            reason = ("the snapshot is outside the checked repository; use a repository snapshot "
                      "so its code ownership can be checked")
        else:
            return self
        return replace(self, limitations=(*self.limitations, reason))

    def _unread(self, key: str) -> str:
        entry = self.data["settings"][key]
        if entry["status"] == "read":
            return ""
        why = entry.get("reason") or ", ".join(
            f"{plain(p['key'], 60)}: {plain(p['reason'], 160)}" for p in entry.get("problems", [])[:3])
        return f"{key} {entry['status']}: {plain(why, 400)}"

    def inventory_limitations(self) -> list[str]:
        """Recorded reasons a full inventory cannot be compared, including when no names are configured."""
        entries = self.data["settings"]
        repo = entries["repository"]
        personal = (repo["status"] == "read" and repo["value"]["owner_type"] == "User"
                    and entries["organization_secrets"]["status"] == "not_applicable")
        needed = ["environments", "environment_secrets", "repository_secrets"]
        if not personal:
            needed.append("organization_secrets")
        return [reason for key in needed if (reason := self._unread(key))]

    def assess(self, name: str, environment: str) -> Assessment:
        """Assess one literal name from a job, independently of the finding's other controls."""
        from obaaf.checker.rules import CANNOT_TELL, NOT_MET, VERIFIED

        if self.limitations:
            return Assessment(CANNOT_TELL, "; ".join(self.limitations))
        if not name.isascii() or not name or not all(c.isalnum() or c == "_" for c in name):
            return Assessment(CANNOT_TELL, "a literal secret name is needed")
        if not environment or "${{" in environment:
            return Assessment(CANNOT_TELL, "a literal environment name is needed")
        entries = self.data["settings"]
        missing = self.inventory_limitations()
        if missing:
            return Assessment(CANNOT_TELL, "; ".join(missing))
        environments = entries["environments"]["value"]
        inventory = entries["environment_secrets"]["value"]
        labels = [env["name"] for env in environments]
        if len(set(labels)) != len(labels) or set(labels) != set(inventory):
            return Assessment(CANNOT_TELL, "the environment list and environment secret inventories disagree")
        matches = [env for env in environments if environment_match(env["name"], environment) != "differs"]
        if not matches:
            return Assessment(NOT_MET, "the required environment was absent from the complete environment list")
        if len(matches) != 1 or environment_match(matches[0]["name"], environment) != "same":
            return Assessment(CANNOT_TELL, "the required environment name is ambiguous")
        env = matches[0]
        where = env["name"]
        name = name.upper()
        held = {key for key, names in inventory.items() if name in (n.upper() for n in names)}
        if held != {where}:
            return Assessment(NOT_MET, "the secret is absent from its required environment or present in another")
        for scope in ("repository_secrets", "organization_secrets"):
            if name in (n.upper() for n in entries[scope].get("value", [])):
                return Assessment(NOT_MET, f"the name also occurs in {scope}")
        mode = env["deployment_branches"]
        if mode == "any":
            return Assessment(NOT_MET, "the environment permits any branch")
        if mode == "protected":
            # GitHub permits all branches in this mode when no branch protection rule exists.
            reason = self._unread("branch_protection")
            if reason:
                return Assessment(CANNOT_TELL, reason)
            if not any(b["exists"] for b in entries["branch_protection"]["value"].values()):
                return Assessment(CANNOT_TELL, "no classic branch protection rule was observed")
        else:
            policies = env.get("branch_policies")
            if not policies:
                return Assessment(CANNOT_TELL, "no selected branch policy establishes protected-branch access")
            if any(p["type"] == "tag" for p in policies):
                return Assessment(NOT_MET, "the selected policy permits a tag")
            # GitHub matches policy names with Ruby's File.fnmatch; `{` is refused too, in case braces
            # are expanded, so only a name that can be nothing but itself counts as literal.
            if any(p["type"] != "branch" or not p["name"] or any(c in p["name"] for c in "*?[{\\")
                   for p in policies):
                return Assessment(CANNOT_TELL, "the selected policy does not name only literal branches")
            reason = self._unread("branches")
            if reason:
                return Assessment(CANNOT_TELL, reason)
            branches = entries["branches"]["value"]
            if any(p["name"] not in branches for p in policies):
                return Assessment(CANNOT_TELL, "a selected branch was not observed")
            if any(not branches[p["name"]]["protected"] for p in policies):
                return Assessment(NOT_MET, "a selected branch was observed as unprotected")
        return Assessment(VERIFIED, "the name appears only in the required environment and only protected branches may use it")


def scan_identity(target: Path, base: Path) -> str | None:
    from obaaf.audit.cli import _origin
    base = base.resolve()
    if target.is_file() and base.name == "workflows" and base.parent.name == ".github":
        base = base.parent.parent
    return _origin(str(base))


def report_settings(evidence, base, repository_scan, config):
    diagnostic = evidence.for_scan(base, repository_scan)
    print(f"Settings snapshot for {plain(evidence.data['repository'])}, taken {evidence.taken_at}.",
          file=sys.stderr)
    reasons = list(diagnostic.limitations)
    if not config.protected_secrets:
        reasons.extend(evidence.inventory_limitations())
    for reason in reasons:
        print(f"Settings evidence: {reason}.", file=sys.stderr)
    for name, environment in sorted(config.protected_secrets.items()):
        assessment = diagnostic.assess(name, environment or "")
        print(f"Settings evidence for {plain(name)}: {assessment.verdict}: {assessment.reason}.",
              file=sys.stderr)
    if any(not environment or any(c in name for c in "*?")
           for name, environment in config.protected_secrets.items()):
        # These lines judge the entries; the finding judges each name a job reads (review of #301).
        print("Settings evidence: the lines above judge the configuration's entries, and one with a glob "
              "or with no environment cannot be verified there. OBAAF-GHA-005 judges each secret name a "
              "job reads, in the environment the job declares, and can verify it only when "
              "protected_secrets names that environment for every secret of the job, through a glob or not.",
              file=sys.stderr)
