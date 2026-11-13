"""What the checker reads about an egress control for an agent job (flagship slice 2c.3).

Four kinds of control are recognised, each from the workflow and, for GitHub's native firewall, from
the policy file in the repository:

- GitHub's native egress firewall: the job runs on `ubuntu-24.04-firewall` and
  `.github/egress-firewall.yaml` sets `mode: enforce`. It sits outside the runner's virtual machine and
  covers the whole job.
- OBAAF's egress action, `Obaaf/OBAAF/actions/egress`: it confines one command, so it holds only when
  the agent is that command and nothing later in the job runs what the command wrote.
- Harden-Runner, which runs beside the job and covers it only when its version, the removal of `sudo`
  and containers, its place in the job and the repository's tier can all be established.
- The Agent Workflow Firewall used directly, from a `run:` script.

Nothing here decides that a control holds from a declaration or a comment. What cannot be read is
"cannot tell".
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

from obaaf import yamlutil

# The host names OBAAF's action accepts, as its own parser does (actions/egress/egress.py): two labels
# or more, the last starting with a letter, no wildcard, port, scheme, path or trailing dot.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?$")

FIREWALL_LABEL = "ubuntu-24.04-firewall"
FIREWALL_POLICY = ".github/egress-firewall.yaml"


def split_list(text: str) -> list[str]:
    """Entries separated by commas, spaces or new lines, as OBAAF's action splits `allow`."""
    return [item for item in re.split(r"[\s,]+", text or "") if item]


# ------------------------------------------------------------------ the public suffix list
@lru_cache(maxsize=1)
def _suffix_rules() -> tuple[frozenset, frozenset, frozenset]:
    """(rules, wildcard parents, exceptions) from the public suffix list OBAAF ships, ICANN and private
    sections both, with every name in its ASCII (punycode) form."""
    text = resources.files("obaaf.data").joinpath("public_suffix_list.dat").read_text(encoding="utf-8")
    rules: set = set()
    wild: set = set()
    exceptions: set = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        target = rules
        if rule.startswith("!"):
            target, rule = exceptions, rule[1:]
        elif rule.startswith("*."):
            target, rule = wild, rule[2:]
        try:
            ascii_rule = ".".join(label.encode("idna").decode("ascii") if label else label
                                  for label in rule.split("."))
        except UnicodeError:
            ascii_rule = rule
        target.add(ascii_rule)
        target.add(rule)
    return frozenset(rules), frozenset(wild), frozenset(exceptions)


def is_public_suffix(name: str) -> bool:
    """Whether `name` is itself a public suffix: a name under which anyone may register a host (`com`,
    `github.io`, `workers.dev`). A single label is one, by the list's default rule."""
    name = name.lower().rstrip(".")
    if "." not in name:
        return True
    rules, wild, exceptions = _suffix_rules()
    if name in exceptions:
        return False
    if name in rules:
        return True
    parent = name.split(".", 1)[1]
    return parent in wild


# ------------------------------------------------------------------ the native firewall's policy
@dataclass
class FirewallPolicy:
    """What the checker read of `.github/egress-firewall.yaml`. `state` is `read`, `missing`,
    `misnamed` (a file of another spelling, which the firewall does not discover) or `unreadable`."""
    state: str
    mode: str | None = None
    allow: list = field(default_factory=list)
    no_defaults: bool = False       # `no-default-urls: true`: GitHub's default endpoints are not allowed
    digest: str = ""
    detail: str = ""


def read_firewall_policy(root) -> FirewallPolicy:
    """Read the policy file GitHub's native egress firewall uses, from a repository root. The name is
    case sensitive and must be exactly `.github/egress-firewall.yaml` (the firewall's README), so the
    directory is listed rather than the path opened, which a case-insensitive file system would match
    with any spelling."""
    github = os.path.join(str(root), ".github")
    try:
        names = os.listdir(github)
    except OSError:
        return FirewallPolicy("missing")
    if "egress-firewall.yaml" not in names:
        others = sorted(n for n in names if n.lower() in ("egress-firewall.yaml", "egress-firewall.yml"))
        if others:
            return FirewallPolicy("misnamed", detail=f".github/{others[0]}")
        return FirewallPolicy("missing")
    path = os.path.join(github, "egress-firewall.yaml")
    if os.path.islink(path) or not os.path.isfile(path):
        return FirewallPolicy("unreadable", detail="it is not a plain file (a link or a directory), and what the "
                                                   "firewall reads from such an entry has not been established")
    try:
        with open(path, "rb") as handle:
            data = handle.read(1_000_000)
    except OSError as exc:
        return FirewallPolicy("unreadable", detail=f"it cannot be read ({exc.strerror or exc})")
    digest = hashlib.sha256(data).hexdigest()[:32]
    try:
        raw = yamlutil.load(data.decode("utf-8"))
    except Exception as exc:     # YAML errors, duplicate keys, bytes that are not UTF-8
        return FirewallPolicy("unreadable", digest=digest, detail=f"it is not YAML the checker can read ({_short(exc)})")
    if not isinstance(raw, dict):
        return FirewallPolicy("unreadable", digest=digest, detail="its top level is not a mapping")
    mode = raw.get("mode")
    allow = raw.get("allow")
    entries: list = []
    if isinstance(allow, list) and all(isinstance(entry, str) for entry in allow):
        entries = [entry for entry in allow]
    elif allow is not None:
        return FirewallPolicy("unreadable", mode=str(mode) if isinstance(mode, str) else None, digest=digest,
                              detail="its allow is not a list of host names")
    return FirewallPolicy("read", mode=mode if isinstance(mode, str) else None, allow=entries,
                          no_defaults=raw.get("no-default-urls") is True, digest=digest,
                          detail="" if isinstance(mode, str) else "its mode is not written as text")


def _short(exc: Exception) -> str:
    text = " ".join(str(exc).split())
    return text[:120] + ("..." if len(text) > 120 else "")


# ------------------------------------------------------------------ verdicts
@dataclass
class Reading:
    """What one control was found to be: its verdict, why, which case of OBAAF-GHA-020 it is and the
    values that case's message shows."""
    verdict: str
    detail: str
    kind: str
    values: dict


def worst(problems: list, unsure: list) -> str:
    """The verdict from the conditions read: any that does not hold makes it "not met", any that cannot
    be read makes it "cannot tell"."""
    from obaaf.checker.rules import CANNOT_TELL, NOT_MET, VERIFIED
    return NOT_MET if problems else CANNOT_TELL if unsure else VERIFIED


def joined(items: list, limit: int = 5) -> str:
    more = f"; and {len(items) - limit} more" if len(items) > limit else ""
    return "; ".join(items[:limit]) + more


# Whether an AWF command line is in a script: `awf`, `sudo awf`, `sudo -E awf` or a path ending in `/awf`,
# as a command, followed by an option or `--`.
AWF_RE = re.compile(r"(?:^|[\s;&|(`])(?:sudo\s+(?:-[A-Za-z]+\s+)*)?(?:[^\s;&|()`]*/)?awf\s+(?:-|\S)", re.M)
# The AWF option its own documentation says "allows firewall bypass" (landscape.md, part 2).
AWF_UNSAFE_RE = re.compile(r"--enable-dind\b")
