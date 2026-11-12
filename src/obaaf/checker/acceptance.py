"""What makes an acceptance of a finding valid.

A finding that is not fixed can be accepted for a time: by an `ignore` entry in the checker
configuration, or by an entry in a baseline file. Either way the acceptance has to say who accepts
the risk, why, and until when, and the checker enforces all three. An acceptance that lacks one of
them, has expired, or expires further ahead than MAX_DAYS does not accept anything: the finding it
names counts as if the entry were not there, and the report says what is wrong with the entry.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date, timedelta

# An acceptance is looked at again at least once a year. Without an upper limit an expiry date of
# 2999 would be a permanent acceptance with a date on it.
MAX_DAYS = 366

# The forms a CODEOWNERS file takes for an owner: @user, @org/team, or an e-mail address. The
# checker cannot tell whether the account exists or whether the name is a placeholder; it can tell
# that the entry has the form of a name. A user or organisation name is letters and digits with
# single hyphens inside, as GitHub requires, and may end in an underscore and a short code, as the
# names of managed users do (octocat_corp).
_HANDLE = re.compile(r"^@[A-Za-z0-9](?:-?[A-Za-z0-9]){0,38}(?:_[A-Za-z0-9]{1,39})?"
                     r"(?:/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?)?$")
# A reason has to say something. The checker cannot judge what it says; it refuses one with fewer
# than this many letters, digits or marks, which rules out an empty one, a dot, "n/a" and "tbd"
# and lets through a ticket number or a few words in any script.
MIN_REASON = 4
# Letters, by their Unicode category, that show nothing: the Hangul fillers.
_BLANK_LETTERS = frozenset("\u115f\u1160\u3164\uffa0")


def _is_email(text: str) -> bool:
    """Whether `text` has the form of an e-mail address: one @; before it a name of visible
    characters with a letter or digit among them and no empty part between dots; after it two or
    more labels of letters, digits and inner hyphens, the last with a letter in it. Letters of any
    script count (søren@x.dk, jo@münchen.de)."""
    if len(text) > 254 or text.count("@") != 1:
        return False
    local, domain = text.split("@")
    if not local or len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    if not all(ch.isprintable() and not ch.isspace() for ch in local) or not any(ch.isalnum() for ch in local):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or not (label[0].isalnum() and label[-1].isalnum()) \
                or not all(ch.isalnum() or ch == "-" for ch in label):
            return False
    return any(ch.isalpha() for ch in labels[-1])


def _says(reason: str) -> int:
    """How many letters, digits and marks a reason has (a mark is a vowel sign or an accent written
    as its own character, which several scripts cannot do without)."""
    return sum(1 for ch in reason
               if (ch.isalnum() or unicodedata.category(ch) in ("Mn", "Mc")) and ch not in _BLANK_LETTERS)

BASELINE, IGNORE = "baseline", "ignore"


@dataclass
class Acceptance:
    """An acceptance that matched a finding. `problems` is empty when it is valid."""
    source: str                      # BASELINE or IGNORE
    owner: str | None = None
    reason: str | None = None
    expires: str | None = None       # YYYY-MM-DD when it is a date; otherwise the text that was given
    problems: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.problems

    def as_dict(self) -> dict:
        return {"source": self.source, "owner": self.owner, "reason": self.reason, "expires": self.expires,
                "valid": self.valid, "problems": list(self.problems)}


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def parse_date(value) -> date | None:
    """A calendar date from a `date` or from text of the form YYYY-MM-DD, and nothing else."""
    if isinstance(value, date) and not hasattr(value, "hour"):
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value.strip()):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def owner_problem(owner) -> str | None:
    if not _text(owner):
        return "it names no owner"
    if not (_HANDLE.match(_text(owner)) or _is_email(_text(owner))):
        return (f"its owner {_text(owner)[:60]!r} is not a user (@name), a team (@org/team) or an e-mail "
                "address")
    return None


def problems(owner, reason, expires, today: date) -> list[str]:
    """Every reason an acceptance with these three values does not count, in the words of the report."""
    found = []
    problem = owner_problem(owner)
    if problem:
        found.append(problem)
    if not _text(reason):
        found.append("it gives no reason")
    elif _says(_text(reason)) < MIN_REASON:
        found.append(f"its reason says too little (fewer than {MIN_REASON} letters or digits)")
    if expires is None or (isinstance(expires, str) and not expires.strip()):
        found.append("it has no expiry date")
    else:
        day = parse_date(expires)
        if day is None:
            found.append(f"its expiry date {str(expires)[:40]!r} is not a date (YYYY-MM-DD)")
        elif day < today:
            found.append(f"it expired on {day.isoformat()}")
        elif day > today + timedelta(days=MAX_DAYS):
            found.append(f"it expires on {day.isoformat()}, more than {MAX_DAYS} days ahead; an acceptance is "
                         "looked at again at least once a year")
    return found


def make(source: str, owner, reason, expires, today: date) -> Acceptance:
    day = parse_date(expires)
    shown = day.isoformat() if day else (str(expires) if expires not in (None, "") else None)
    return Acceptance(source=source, owner=_text(owner) or None, reason=_text(reason) or None, expires=shown,
                      problems=problems(owner, reason, expires, today))
