"""Offline evidence for a named secret in a GitHub environment (adoption slice A4a)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from obaaf.audit import snapshot
from obaaf.audit.github import plain
from obaaf.checker.workflow import environment_match

MAX_AGE = timedelta(days=30)


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
        if not path.is_file():
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
        if not repository_scan:
            reason = ("this scan does not check snapshot code ownership; run obaaf check "
                      "on the repository directory without --lanes")
        elif not self.source.resolve().is_relative_to(root.resolve()):
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
            if any(p["type"] != "branch" or not p["name"] or any(c in p["name"] for c in "*?[\\")
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
