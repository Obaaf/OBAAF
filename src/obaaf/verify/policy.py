"""The release policy: who may sign what, and what a release needs before upload.

The policy decides what may ship, so it is read strictly (slice 2d.21, #395). Each field must have its
YAML type: text, true or false, a whole number, or a list of texts. A value of another type, a key the
policy does not read, and YAML that cannot be read are each a `PolicyError` that names the field and its
line. Before, values were converted with `int()`, `bool()`, `str()` and `list()`, so `"false"` was true,
`0.5` approvals turned the approvals check off and `source_refs: "refs/tags/v*"` allowed any ref.
"""

from __future__ import annotations

import datetime
import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from obaaf import yamlutil

FORMAT = "obaaf-policy/v0.1"

# The keys the policy reads, by section. Any other key is an error: a misspelt key (`min_aprovals: 2`)
# would otherwise leave its default in force without a word, as the checker's configuration refuses one.
SECTIONS = {
    "provenance": ("signer_workflow", "source_refs", "runner_environments", "issuer"),
    "build_record": ("allowed_tiers", "require_sdks"),
    "release": ("branch", "environments", "environment", "min_approvals", "approver_not_actor", "approvers",
                "jenkins_project"),
    "agents": ("check", "since", "records_dir", "propose_workflow", "apply_workflow", "source_ref",
               "effect_identities", "require_exact_diff", "allow_self_hosted_runners"),
}
# The roles a key may have under `keys`: release provenance and build records, and the agent lane's
# agent-run and approval records.
KEY_ROLES = ("provenance", "build_record", "agent_run", "approval")
TOP_KEYS = ("format", "repository", "signing", "keys") + tuple(SECTIONS)
TIERS = ("A", "B")

_MISSING = object()


class PolicyError(ValueError):
    pass


def _short(text: str, limit: int = 60) -> str:
    """`text` quoted for a message: control and format characters escaped, at most `limit` characters."""
    shown = text if len(text) <= limit else text[:limit] + "..."
    return repr(shown)


def describe(value: Any) -> str:
    """What a YAML value is, in plain words, for an error message."""
    if value is None:
        return "nothing (null)"
    if isinstance(value, bool):
        return f"true or false ({'true' if value else 'false'})"
    if isinstance(value, int):
        return f"a whole number ({value})" if abs(value) < 10 ** 30 else "a whole number"
    if isinstance(value, float):
        return f"a number with a fraction ({value!r})"
    if isinstance(value, str):
        return f"text ({_short(value)})" if value else "empty text"
    if isinstance(value, (datetime.date, datetime.datetime)):
        return f"a date ({value.isoformat()}); quote it to write text"
    if isinstance(value, bytes):
        return "binary data"
    if isinstance(value, dict):
        return "a mapping"
    if isinstance(value, (set, frozenset)):
        return "a set"
    if isinstance(value, tuple):
        return "a pair"
    if isinstance(value, list):
        return "a list"
    return f"a {type(value).__name__}"


class _Section:
    """One mapping of the policy, read key by key with each value's type checked."""

    def __init__(self, path: str | Path, mapping: dict, name: str | None, line: int = 0):
        self.path = path
        self.mapping = mapping
        self.name = name
        self.line = getattr(mapping, "line", 0) or line

    def where(self, key: Any = _MISSING, item: Any = None) -> str:
        line = getattr(item, "line", 0) if item is not None else 0
        if not line and key is not _MISSING and hasattr(self.mapping, "line_of"):
            line = self.mapping.line_of(key)
        line = line or self.line
        return f"{self.path}, line {line}" if line else str(self.path)

    def full(self, key: str) -> str:
        return key if self.name is None else f"{self.name}.{key}"

    def fail(self, key: str, what: str, value: Any) -> PolicyError:
        return PolicyError(f"{self.where(key)}: {self.full(key)} must be {what}; it is {describe(value)}")

    def check_keys(self, known: tuple[str, ...]) -> None:
        for key in self.mapping:
            if key not in known:
                where = f" in {self.name}" if self.name else ""
                shown = _short(key) if isinstance(key, str) else repr(key)
                raise PolicyError(f"{self.where(key)}: unknown key {shown}{where}; the policy reads "
                                  f"{', '.join(known)} here")

    def section(self, key: str) -> "_Section":
        """A mapping under `key`. Nothing there (the key absent, or written with no value) is an empty one."""
        value = self.mapping.get(key)
        if value is None:
            value = {}
        if not isinstance(value, dict):
            raise self.fail(key, "a mapping", value)
        return _Section(self.path, value, self.full(key), self.mapping.line_of(key)
                        if hasattr(self.mapping, "line_of") else 0)

    def text(self, key: str, default: str) -> str:
        """Text. Absent gives `default`; an empty text gives `default` too, as it did before."""
        if key not in self.mapping:
            return default
        value = self.mapping[key]
        if not isinstance(value, str):
            raise self.fail(key, "text", value)
        return value or default

    def flag(self, key: str, default: bool) -> bool:
        if key not in self.mapping:
            return default
        value = self.mapping[key]
        if not isinstance(value, bool):
            # YAML 1.2, as OBAAF reads it: `no`, `off` and "false" are text, and text is not false.
            raise self.fail(key, "true or false", value)
        return value

    def count(self, key: str, default: int) -> int:
        if key not in self.mapping:
            return default
        value = self.mapping[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise self.fail(key, "a whole number, 0 or more", value)
        return value

    def names(self, key: str, default: list[str], *, at_least_one: bool = False) -> list[str]:
        """A list of non-empty texts. Absent gives `default`."""
        if key not in self.mapping:
            return list(default)
        value = self.mapping[key]
        if not isinstance(value, list):
            raise self.fail(key, "a list (for example [" + (default[0] if default else "name") + "])", value)
        if at_least_one and not value:
            raise PolicyError(f"{self.where(key)}: {self.full(key)} must name at least one entry; remove the key "
                              "to use the default" + (f" ({', '.join(default)})" if default else ""))
        out = []
        for index, item in enumerate(value, 1):
            if not isinstance(item, str):
                raise PolicyError(f"{self.where(key, value)}: {self.full(key)}[{index}] must be text; it is "
                                  f"{describe(item)}")
            if not item:
                raise PolicyError(f"{self.where(key, value)}: {self.full(key)}[{index}] is empty text")
            out.append(item)
        return out


def _read(path: str | Path) -> Any:
    try:
        return yamlutil.load_file(path)
    except OSError:
        raise
    except Exception as exc:    # YAML errors, duplicate keys, text that is not UTF-8, nesting too deep
        detail = " ".join(str(exc).split()) or type(exc).__name__
        raise PolicyError(f"{path}: cannot be read as YAML: {detail[:300]}") from exc


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
    approvers: list = field(default_factory=list)   # if set, only these people's approvals count
    jenkins_project: str = ""                       # Jenkins: full name of the multibranch project that builds tags
    base_dir: Path = Path(".")

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        data = _read(path)
        if data is None:
            data = {}
        if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("format"), str):
            raise PolicyError(f"{path}: expected 'format: {FORMAT}'")
        top = _Section(path, data, None)
        top.check_keys(TOP_KEYS)
        repo = data.get("repository")
        if not isinstance(repo, str) or "/" not in repo:
            raise PolicyError(f"{top.where('repository')}: 'repository' must be OWNER/REPO"
                              + (f"; it is {describe(repo)}" if "repository" in data else ""))
        signing = data.get("signing", "sigstore")
        if not isinstance(signing, str) or signing not in ("sigstore", "keys"):
            raise PolicyError(f"{top.where('signing')}: 'signing' must be sigstore or keys; it is {describe(signing)}")

        prov = top.section("provenance")
        prov.check_keys(SECTIONS["provenance"])
        build = top.section("build_record")
        build.check_keys(SECTIONS["build_record"])
        release = top.section("release")
        release.check_keys(SECTIONS["release"])
        agents = top.section("agents")
        agents.check_keys(SECTIONS["agents"])
        keys = top.section("keys")
        keys.check_keys(KEY_ROLES)

        if "environments" in release.mapping and "environment" in release.mapping:
            raise PolicyError(f"{release.where('environment')}: write release.environments or release.environment, "
                              "not both")
        if "environments" in release.mapping:
            environments = release.names("environments", ["release"], at_least_one=True)
        else:
            environments = [release.text("environment", "release")]
        if "branch" in release.mapping:
            # `branch: ""` turns the check off, for repositories that release from several branches.
            branch = release.mapping["branch"]
            if not isinstance(branch, str):
                raise release.fail("branch", "text (write '' to turn the check off)", branch)
        else:
            branch = "main"
        since = None
        if "since" in agents.mapping:
            since = agents.mapping["since"]
            if not isinstance(since, str):
                raise agents.fail("since", "a full commit SHA written as text (quote it)", since)
            since = since or None
        tiers = build.names("allowed_tiers", ["A", "B"], at_least_one=True)
        for index, tier in enumerate(tiers, 1):
            if tier not in TIERS:
                raise PolicyError(f"{build.where('allowed_tiers', build.mapping.get('allowed_tiers'))}: "
                                  f"build_record.allowed_tiers[{index}] is {_short(tier)}; a tier is A or B")

        policy = cls(
            repository=repo,
            signing=signing,
            provenance_workflow=prov.text("signer_workflow", f"{repo}/.github/workflows/obaaf-release.yml"),
            source_refs=prov.names("source_refs", []),
            runner_environments=prov.names("runner_environments", []),
            issuer=prov.text("issuer", "https://token.actions.githubusercontent.com"),
            keys={role: keys.names(role, []) for role in keys.mapping},
            allowed_tiers=tiers,
            require_sdks=build.flag("require_sdks", True),
            release_environments=environments,
            min_approvals=release.count("min_approvals", 1),
            approver_not_actor=release.flag("approver_not_actor", True),
            release_branch=branch,
            agents_check=agents.flag("check", True),
            agents_since=since,
            records_dir=agents.text("records_dir", ".obaaf/records"),
            propose_workflow=agents.text("propose_workflow", f"{repo}/.github/workflows/obaaf-agent-propose.yml"),
            apply_workflow=agents.text("apply_workflow", f"{repo}/.github/workflows/obaaf-agent-apply.yml"),
            agent_source_ref=agents.text("source_ref", "refs/heads/main"),
            effect_identities=agents.names("effect_identities", ["obaaf-effect-lane"], at_least_one=True),
            require_exact_diff=agents.flag("require_exact_diff", True),
            allow_self_hosted_agents=agents.flag("allow_self_hosted_runners", False),
            approvers=release.names("approvers", []),
            jenkins_project=release.text("jenkins_project", "").strip("/"),
            base_dir=Path(path).parent,
        )
        if policy.signing == "sigstore" and not policy.source_refs:
            # No default: which refs may produce a release is the policy's main decision (FR4).
            raise PolicyError(f"{prov.where('source_refs')}: provenance.source_refs is required "
                              "(for example ['refs/tags/v*'])")
        if policy.agents_since and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", policy.agents_since):
            raise PolicyError(f"{agents.where('since')}: agents.since must be a full commit SHA; it is "
                              f"{describe(policy.agents_since)}")
        if policy.signing == "keys":
            for role in ("provenance", "build_record"):
                if not policy.keys.get(role):
                    raise PolicyError(f"{path}: signing: keys needs keys.{role}")
        return policy

    def key_paths(self, role: str) -> list[Path]:
        return [(self.base_dir / p) if not Path(p).is_absolute() else Path(p) for p in self.keys.get(role, [])]

    def ref_allowed(self, ref: str) -> bool:
        return any(fnmatch.fnmatchcase(ref, pattern) for pattern in self.source_refs)
