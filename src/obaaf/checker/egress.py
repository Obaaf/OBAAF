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
LIMIT = 1_000_000       # bytes of the policy file the checker reads; a larger file is "cannot tell"


def split_list(text: str) -> list[str]:
    """Entries separated by commas, spaces or new lines, as OBAAF's action splits `allow`."""
    return [item for item in re.split(r"[\s,]+", text or "") if item]


# ------------------------------------------------------------------ the public suffix list
@lru_cache(maxsize=1)
def _suffix_rules() -> tuple[frozenset, frozenset, frozenset, frozenset]:
    """(rules, wildcard parents, exceptions, ancestors) from the public suffix list OBAAF ships, ICANN
    and private sections both, with every name in its ASCII (punycode) form as well as as written.
    `ancestors` holds every name that has a public suffix under it (`amazonaws.com`, for
    `s3.amazonaws.com`)."""
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
    ancestors: set = set()
    for name in (*rules, *wild):
        labels = name.split(".")
        start = 1 if name in rules and name not in wild else 0
        for n in range(start, len(labels)):
            ancestors.add(".".join(labels[n:]))
    ancestors -= {""}
    return frozenset(rules), frozenset(wild), frozenset(exceptions), frozenset(ancestors)


def is_public_suffix(name: str) -> bool:
    """Whether `name` is itself a public suffix: a name under which anyone may register a host (`com`,
    `github.io`, `workers.dev`). A single label is one, by the list's default rule."""
    name = name.lower().rstrip(".")
    if "." not in name:
        return True
    rules, wild, exceptions, _ = _suffix_rules()
    if name in exceptions:
        return False
    if name in rules:
        return True
    parent = name.split(".", 1)[1]
    return parent in wild


def public_suffix_at_or_under(name: str) -> str | None:
    """A public suffix that a listed name covers, or None. A listed name covers itself and every name
    under it, so `github.io` and `amazonaws.com` (which has `s3.amazonaws.com` under it) both let in
    hosts anyone can register; `example.github.io` does not."""
    name = name.lower().rstrip(".")
    if is_public_suffix(name):
        return name
    rules, wild, _, ancestors = _suffix_rules()
    if name in ancestors:
        under = sorted((r for r in (*rules, *(f"*.{w}" for w in wild)) if r.endswith("." + name)),
                       key=lambda r: (r.startswith("*"), len(r), r))
        return under[0] if under else name
    return None


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
            data = handle.read(LIMIT + 1)
    except OSError as exc:
        return FirewallPolicy("unreadable", detail=f"it cannot be read ({exc.strerror or exc})")
    if len(data) > LIMIT:
        return FirewallPolicy("unreadable", detail=f"it is larger than {LIMIT} bytes, more than the checker reads")
    digest = hashlib.sha256(data).hexdigest()[:32]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return FirewallPolicy("unreadable", digest=digest, detail="it is not UTF-8")
    for char, shown in (("\u0085", "U+0085"), ("\u2028", "U+2028"), ("\u2029", "U+2029")):
        if char in text:
            return FirewallPolicy("unreadable", digest=digest,
                                  detail=f"it contains {shown}, which YAML readers do not agree is a line break")
    try:
        merged = _has_merge_key(text)
        raw = yamlutil.load(text)
    except Exception as exc:     # YAML errors, duplicate keys, bytes that are not UTF-8
        return FirewallPolicy("unreadable", digest=digest, detail=f"it is not YAML the checker can read ({_short(exc)})")
    if merged:
        return FirewallPolicy("unreadable", digest=digest,
                              detail="it uses a merge key (<<), which YAML 1.1 readers merge and YAML 1.2 readers "
                                     "take for a key of that name")
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


def _has_merge_key(text: str) -> bool:
    """Whether any mapping in the document has a merge key: a key node the YAML reader tags as a merge
    (`<<`, `? <<`, `!!merge ...`), however it is spelt. Read from the composed nodes, before the
    reader merges them away."""
    import yaml
    seen: set = set()
    stack = [yaml.compose(text, Loader=yamlutil._Loader)]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if key.tag == "tag:yaml.org,2002:merge":
                    return True
                stack.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
    return False


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


# An AWF command line in a script: `awf`, `sudo awf`, `sudo -E awf` or a path ending in `/awf`, where a
# command starts (the start of a line, or after `;`, `&`, `|`, `(` or a backtick), followed by an
# argument. Comments are taken out first (`uncommented`), so a note that mentions awf is not one.
AWF_RE = re.compile(r"(?:^|[;&|(`])[ \t]*(?:sudo[ \t]+(?:-\S+[ \t]+)*)?(?:[^\s;&|()`]*/)?awf[ \t]+\S", re.M)


def uncommented(script: str) -> str:
    """A shell script without its comments: from a `#` at the start of a word, outside quotes, to the
    end of the line, following `'`, `"` and backslashes. Approximate: shell has more quoting than
    this (`$'...'`, here-documents), so it can take text for a comment that is not one, or the other
    way round. It is used only for AWF, where hiding a match gives the stricter answer ("not met"
    rather than "cannot tell")."""
    out: list[str] = []
    quote = ""
    i, text = 0, script or ""
    while i < len(text):
        ch = text[i]
        if quote == "'":
            out.append(ch)
            quote = "" if ch == "'" else quote
        elif ch == "\\" and i + 1 < len(text):
            out.append(text[i:i + 2])
            i += 1
        elif quote == '"':
            out.append(ch)
            quote = "" if ch == '"' else quote
        elif ch in "'\"":
            out.append(ch)
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1].isspace()):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


# A process a step leaves running after it ends, in the forms the checker recognises. The whole
# script is searched, comments and quoted text included, so a form written in a comment or a string
# only adds a "cannot tell". Every pattern is linear in the length of the script.
_AMPERSAND_RE = re.compile(r"(?<![&|>])&(?![&>])")
_DETACHING_WORD_RE = re.compile(r"\b(?:nohup|setsid|disown|daemonize|start-stop-daemon|systemd-run|coproc)\b")
_AT_RE = re.compile(r"(?:^|[;&|(`])[ \t]*at[ \t]", re.M)
_SHORT_D_RE = re.compile(r"-[A-Za-z]*d[A-Za-z]*")


def leaves_process(script: str) -> str | None:
    """How a script may leave a process running after its step ends, or None: `&` as an operator
    (not `&&`, `2>&1`, `&>` or `|&`); `nohup`, `setsid`, `disown`, `daemonize`, `start-stop-daemon`,
    `systemd-run`, `coproc` or `at`; a container started detached (`docker` or `podman` with `run`
    and `-d` among its short options or `--detach`, any `start`, or `compose up -d`, `up --wait`,
    `compose start`); `screen -d...`; `tmux new -d`."""
    text = script or ""
    if _AMPERSAND_RE.search(text):
        return "&"
    word = _DETACHING_WORD_RE.search(text)
    if word:
        return word.group(0)
    if _AT_RE.search(text):
        return "at"
    for line in text.splitlines():
        tokens = line.replace(";", " ").replace("|", " ").replace("(", " ").replace(")", " ").split()
        if not tokens:
            continue
        names = set(tokens)
        short_d = any(_SHORT_D_RE.fullmatch(t) for t in tokens)
        engines = names & {"docker", "podman"}
        composes = names & {"docker-compose", "podman-compose"} or (engines and "compose" in names)
        if composes and (("up" in names and (short_d or "--detach" in names or "--wait" in names))
                         or "start" in names):
            return "compose"
        if engines and (("run" in names and (short_d or "--detach" in names)) or "start" in names):
            return "a detached container"
        if "screen" in names and short_d:
            return "screen"
        if "tmux" in names and names & {"new", "new-session"} and short_d:
            return "tmux"
    return None


# The AWF option its own documentation says "allows firewall bypass" (landscape.md, part 2).
AWF_UNSAFE_RE = re.compile(r"--enable-dind\b")
