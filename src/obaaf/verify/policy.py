"""The release policy: who may sign what, and what a release needs before upload."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

from obaaf import yamlutil

FORMAT = "obaaf-policy/v0.1"


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    repository: str
    signing: str = "sigstore"
    provenance_workflow: str = ""
    source_refs: list = field(default_factory=list)
    runner_environments: list = field(default_factory=list)
    issuer: str = "https://token.actions.githubusercontent.com"
    keys: dict = field(default_factory=dict)
    allowed_tiers: list = field(default_factory=lambda: ["A", "B"])
    require_sdks: bool = True
    release_environments: list = field(default_factory=lambda: ["release"])
    min_approvals: int = 1
    approver_not_actor: bool = True
    release_branch: str = "main"
    agents_check: bool = True
    agents_since: str | None = None
    records_dir: str = ".obaaf/records"
    propose_workflow: str = ""
    apply_workflow: str = ""
    agent_source_ref: str = "refs/heads/main"
    effect_identities: list = field(default_factory=lambda: ["obaaf-effect-lane"])
    require_exact_diff: bool = True
    allow_self_hosted_agents: bool = False
    base_dir: Path = Path(".")

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        data = yamlutil.load_file(path) or {}
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            raise PolicyError(f"{path}: expected 'format: {FORMAT}'")
        repo = data.get("repository")
        if not repo or "/" not in str(repo):
            raise PolicyError(f"{path}: 'repository' must be OWNER/REPO")
        signing = data.get("signing", "sigstore")
        if signing not in ("sigstore", "keys"):
            raise PolicyError(f"{path}: 'signing' must be sigstore or keys")
        prov = data.get("provenance") or {}
        build = data.get("build_record") or {}
        release = data.get("release") or {}
        agents = data.get("agents") or {}
        policy = cls(
            repository=str(repo),
            signing=signing,
            provenance_workflow=str(prov.get("signer_workflow") or f"{repo}/.github/workflows/obaaf-release.yml"),
            source_refs=[str(r) for r in prov.get("source_refs") or []],
            runner_environments=list(prov.get("runner_environments") or []),
            issuer=str(prov.get("issuer") or "https://token.actions.githubusercontent.com"),
            keys={k: list(v) for k, v in (data.get("keys") or {}).items()},
            allowed_tiers=list(build.get("allowed_tiers") or ["A", "B"]),
            require_sdks=bool(build.get("require_sdks", True)),
            release_environments=[str(e) for e in (release.get("environments") or [release.get("environment") or "release"])],
            min_approvals=int(release.get("min_approvals", 1)),
            approver_not_actor=bool(release.get("approver_not_actor", True)),
            # `branch: ""` turns the check off, for repositories that release from several branches.
            release_branch=str(release["branch"] or "") if "branch" in release else "main",
            agents_check=bool(agents.get("check", True)),
            agents_since=str(agents["since"]) if agents.get("since") else None,
            records_dir=str(agents.get("records_dir") or ".obaaf/records"),
            propose_workflow=str(agents.get("propose_workflow") or f"{repo}/.github/workflows/obaaf-agent-propose.yml"),
            apply_workflow=str(agents.get("apply_workflow") or f"{repo}/.github/workflows/obaaf-agent-apply.yml"),
            agent_source_ref=str(agents.get("source_ref") or "refs/heads/main"),
            effect_identities=[str(i) for i in agents.get("effect_identities") or ["obaaf-effect-lane"]],
            require_exact_diff=bool(agents.get("require_exact_diff", True)),
            allow_self_hosted_agents=bool(agents.get("allow_self_hosted_runners", False)),
            base_dir=Path(path).parent,
        )
        if policy.signing == "sigstore" and not policy.source_refs:
            # No default: which refs may produce a release is the policy's main decision (FR4).
            raise PolicyError(f"{path}: provenance.source_refs is required (for example ['refs/tags/v*'])")
        if policy.agents_since and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", policy.agents_since):
            raise PolicyError(f"{path}: agents.since must be a full commit SHA")
        for tier in policy.allowed_tiers:
            if tier not in ("A", "B"):
                raise PolicyError(f"{path}: unknown tier {tier!r}")
        if policy.signing == "keys":
            for role in ("provenance", "build_record"):
                if not policy.keys.get(role):
                    raise PolicyError(f"{path}: signing: keys needs keys.{role}")
        return policy

    def key_paths(self, role: str) -> list[Path]:
        return [(self.base_dir / p) if not Path(p).is_absolute() else Path(p) for p in self.keys.get(role, [])]

    def ref_allowed(self, ref: str) -> bool:
        return any(fnmatch.fnmatchcase(ref, pattern) for pattern in self.source_refs)
