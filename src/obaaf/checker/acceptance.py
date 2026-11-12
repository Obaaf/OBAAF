"""What makes an acceptance of a finding valid.

A finding that is not fixed can be accepted for a time: by an `ignore` entry in the checker
configuration, or by an entry in a baseline file. Either way the acceptance has to say who accepts
the risk, why, and until when, and the checker enforces all three. An acceptance that lacks one of
them, has expired, or expires further ahead than MAX_DAYS does not accept anything: the finding it
names counts as if the entry were not there, and the report says what is wrong with the entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, timedelta

# An acceptance is looked at again at least once a year. Without an upper limit an expiry date of
# 2999 would be a permanent acceptance with a date on it.
MAX_DAYS = 366

# The forms a CODEOWNERS file takes for an owner: @user, @org/team, or an e-mail address. The
# checker cannot tell whether the account exists; it can tell that somebody is named.
_OWNER = re.compile(r"^(?:@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,99})?"
                    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")

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
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip()):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def owner_problem(owner) -> str | None:
    if not _text(owner):
        return "it names no owner"
    if not _OWNER.match(_text(owner)):
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
