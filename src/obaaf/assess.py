"""Score an OBAAF self-assessment and rank the fixes (FR2).

Scoring follows Paper 2, design requirement DR6: a studio reaches a tier when
every item at that tier and below is answered yes. An item may be marked not
applicable only when its condition is absent, and then counts as satisfied.

Fixes are ranked lowest tier first, then lowest effort, then by the number of
documented compromises for which the item is a deciding control (Paper 2,
Table 7). See DECISIONS.md, D-006.

Everything here runs locally. Nothing is sent over the network (NFR5).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from obaaf import __version__, yamlutil
from obaaf.catalog import Catalog, load

ANSWER_FORMAT = "obaaf-assessment/v0.1"
VALID = {"yes", "no", "na", "unanswered"}
ALIASES = {
    "y": "yes", "true": "yes", "n": "no", "false": "no", "n/a": "na", "not applicable": "na",
    "": "unanswered", "?": "unanswered", "unknown": "unanswered", "unsure": "unanswered",
}


class AnswerError(ValueError):
    """The answer file cannot be scored as written."""


@dataclass
class Answer:
    value: str
    evidence: str = ""
    note: str = ""


@dataclass
class AnswerSet:
    answers: dict[str, Answer]
    studio: str = ""
    respondent: str = ""
    date: str = ""


@dataclass
class Fix:
    rank: int
    item: dict
    answer: str
    prevents: list[dict]
    limits: list[dict]


@dataclass
class Result:
    tier: int
    tier_name: str
    per_tier: dict[int, dict[str, int]]
    fixes: list[Fix]
    answers: AnswerSet
    warnings: list[str] = field(default_factory=list)

    @property
    def next_tier(self) -> int | None:
        return self.tier + 1 if self.tier < 4 else None


def _normalize(raw: Any, iid: str) -> Answer:
    evidence = note = ""
    if isinstance(raw, dict):
        evidence = str(raw.get("evidence") or "")
        note = str(raw.get("note") or "")
        raw = raw.get("answer")
    if raw is True:
        raw = "yes"
    elif raw is False:
        raw = "no"
    elif raw is None:
        raw = "unanswered"
    value = str(raw).strip().lower()
    value = ALIASES.get(value, value)
    if value not in VALID:
        raise AnswerError(f"item {iid}: answer {raw!r} is not one of yes, no, na or unanswered")
    return Answer(value=value, evidence=evidence, note=note)


def parse_answers(data: Any, catalog: Catalog | None = None) -> AnswerSet:
    catalog = catalog or load()
    if not isinstance(data, dict) or "answers" not in data:
        raise AnswerError("the file must be a mapping with an 'answers' key (run 'obaaf assess init' for a template)")
    fmt = data.get("format", ANSWER_FORMAT)
    if fmt != ANSWER_FORMAT:
        raise AnswerError(f"unsupported answer format {fmt!r}; expected {ANSWER_FORMAT}")
    raw_answers = data["answers"]
    if isinstance(raw_answers, list):
        pairs = []
        for entry in raw_answers:
            if not isinstance(entry, dict) or "item" not in entry:
                raise AnswerError("each entry in a list of answers needs an 'item' key")
            pairs.append((entry["item"], entry))
    elif isinstance(raw_answers, dict):
        pairs = list(raw_answers.items())
    else:
        raise AnswerError("'answers' must be a mapping or a list")

    answers: dict[str, Answer] = {}
    for key, raw in pairs:
        if not isinstance(key, str):
            raise AnswerError(
                f"item ID {key!r} must be quoted (write \"2.10\", not 2.10, or YAML reads it as the number 2.1)"
            )
        iid = key.strip()
        if iid not in catalog.items:
            raise AnswerError(f"unknown item {iid!r}")
        if iid in answers:
            raise AnswerError(f"item {iid} is answered twice")
        answer = _normalize(raw, iid)
        if answer.value == "na" and not catalog.items[iid].get("na_when"):
            raise AnswerError(
                f"item {iid} cannot be marked not applicable; only items whose condition can be absent can "
                "(Paper 2, DR6). Answer yes or no."
            )
        answers[iid] = answer
    for iid in catalog.items:
        answers.setdefault(iid, Answer(value="unanswered"))
    return AnswerSet(
        answers=answers,
        studio=str(data.get("studio") or ""),
        respondent=str(data.get("respondent") or ""),
        date=str(data.get("date") or ""),
    )


def load_answers(path: str | Path, catalog: Catalog | None = None) -> AnswerSet:
    text = Path(path).read_text(encoding="utf-8")
    if str(path).endswith(".json"):
        data = json.loads(text)
    else:
        try:
            data = yamlutil.load(text)
        except yamlutil.DuplicateKeyError as exc:
            raise AnswerError(str(exc)) from exc
    return parse_answers(data, catalog)


def _item_order(iid: str) -> tuple[int, int]:
    tier, num = iid.split(".")
    return int(tier), int(num)


def score(answers: AnswerSet, catalog: Catalog | None = None) -> Result:
    catalog = catalog or load()
    per_tier: dict[int, dict[str, int]] = {}
    for tier in sorted(catalog.tiers):
        counts = {"items": 0, "yes": 0, "na": 0, "no": 0, "unanswered": 0}
        for iid, item in catalog.items.items():
            if item["tier"] == tier:
                counts["items"] += 1
                counts[answers.answers[iid].value] += 1
        per_tier[tier] = counts

    reached = 0
    for tier in sorted(per_tier):
        counts = per_tier[tier]
        if counts["yes"] + counts["na"] == counts["items"]:
            reached = tier
        else:
            break

    effort_rank = {k: v["rank"] for k, v in catalog.assessment["effort"].items()}
    open_items = [
        (iid, item) for iid, item in catalog.items.items()
        if answers.answers[iid].value in ("no", "unanswered")
    ]

    def key(entry: tuple[str, dict]) -> tuple:
        iid, item = entry
        cases = catalog.item_cases(iid)
        return (item["tier"], effort_rank[item["effort"]], -len(cases["prevent"]), -len(cases["limit"]), _item_order(iid))

    fixes = []
    for rank, (iid, item) in enumerate(sorted(open_items, key=key), start=1):
        cases = catalog.item_cases(iid)
        fixes.append(Fix(rank=rank, item=item, answer=answers.answers[iid].value,
                         prevents=cases["prevent"], limits=cases["limit"]))

    warnings = []
    unanswered = [iid for iid, a in answers.answers.items() if a.value == "unanswered"]
    if unanswered:
        warnings.append(
            f"{len(unanswered)} item(s) unanswered; they count as 'no' until answered: "
            + ", ".join(sorted(unanswered, key=_item_order))
        )
    tier_name = catalog.tiers[reached]["name"] if reached else "Not yet Accounted"
    return Result(tier=reached, tier_name=tier_name, per_tier=per_tier, fixes=fixes, answers=answers, warnings=warnings)


# ---------------------------------------------------------------------- output
def template(catalog: Catalog | None = None) -> str:
    """An answer file with every question, ready to fill in."""
    catalog = catalog or load()
    lines = [
        "# OBAAF self-assessment answers. Answer each item yes, no, or na where allowed.",
        "# Keep this file inside your studio: it is never sent anywhere.",
        "# Score it with:  obaaf assess score this-file.yaml",
        f"format: {ANSWER_FORMAT}",
        'studio: ""',
        'respondent: ""',
        f'date: "{date.today().isoformat()}"',
        "answers:",
    ]
    for tier in sorted(catalog.tiers):
        t = catalog.tiers[tier]
        lines.append(f"  # Tier {tier}, {t['name']}: {t['summary']}")
        for iid, item in sorted(catalog.items.items(), key=lambda kv: _item_order(kv[0])):
            if item["tier"] != tier:
                continue
            lines.append(f"  # {iid} {item['question']}")
            lines.append(f"  #     Evidence: {item['evidence']}.")
            if item.get("na_when"):
                lines.append(f"  #     Answer na only if: {item['na_when']}")
            lines.append(f'  "{iid}": {{answer: unanswered, evidence: ""}}')
    return "\n".join(lines) + "\n"


def _case_names(cases: list[dict]) -> str:
    return ", ".join(f"{c['name']} ({c['reported']})" for c in cases)


def to_text(result: Result, catalog: Catalog | None = None, limit: int = 10) -> str:
    catalog = catalog or load()
    out = []
    who = f" for {result.answers.studio}" if result.answers.studio else ""
    out.append(f"OBAAF self-assessment{who}")
    out.append(f"Tier reached: {result.tier} ({result.tier_name})")
    for tier, counts in result.per_tier.items():
        satisfied = counts["yes"] + counts["na"]
        out.append(f"  Tier {tier} {catalog.tiers[tier]['name']:<11} {satisfied:>2}/{counts['items']} satisfied")
    for warning in result.warnings:
        out.append(f"Note: {warning}")
    if result.fixes:
        shown = result.fixes[:limit] if limit else result.fixes
        out.append("")
        out.append(f"Fix next ({len(shown)} of {len(result.fixes)}, lowest tier and effort first):")
        effort = catalog.assessment["effort"]
        for fix in shown:
            item = fix.item
            label = effort[item["effort"]]["label"].lower()
            out.append(f"{fix.rank:>3}. {item['id']} {item['short']} [tier {item['tier']}, {label}]")
            if fix.prevents:
                out.append(f"       Would have prevented: {_case_names(fix.prevents)}")
            if fix.limits:
                out.append(f"       Detects or limits: {_case_names(fix.limits)}")
            out.append(f"       How: {item['fix'][0]}")
    else:
        out.append("All items satisfied.")
    return "\n".join(out) + "\n"


def to_markdown(result: Result, catalog: Catalog | None = None, link_base: str = "") -> str:
    catalog = catalog or load()
    who = f" - {result.answers.studio}" if result.answers.studio else ""
    out = [f"# OBAAF self-assessment{who}", ""]
    meta = []
    if result.answers.date:
        meta.append(f"Date: {result.answers.date}")
    if result.answers.respondent:
        meta.append(f"Respondent: {result.answers.respondent}")
    meta.append(f"Scored by obaaf {__version__}")
    out += [" · ".join(meta), ""]
    out.append(f"**Tier reached: {result.tier} ({result.tier_name}).** "
               "A tier describes controls in place, not a guarantee of security.")
    out.append("")
    out.append("| Tier | Satisfied | No | Unanswered |")
    out.append("| --- | --- | --- | --- |")
    for tier, counts in result.per_tier.items():
        out.append(f"| {tier} {catalog.tiers[tier]['name']} | {counts['yes'] + counts['na']} of {counts['items']} "
                   f"| {counts['no']} | {counts['unanswered']} |")
    out.append("")
    if result.fixes:
        out.append("## What to fix next")
        out.append("")
        out.append("Ranked lowest tier first, then lowest effort, then by the documented compromises each item "
                   "addresses.")
        out.append("")
        out.append("| # | Item | Tier | Effort | Documented cases it addresses | How to fix |")
        out.append("| --- | --- | --- | --- | --- | --- |")
        effort = catalog.assessment["effort"]
        for fix in result.fixes:
            item = fix.item
            cases = _case_names(fix.prevents + fix.limits) or "-"
            links = ", ".join(f"[{_label(link)}]({link_base}{link})" for link in item["fix"])
            out.append(f"| {fix.rank} | {item['id']} {item['short']} | {item['tier']} | "
                       f"{effort[item['effort']]['label']} | {cases} | {links} |")
        out.append("")
    if result.warnings:
        out.append("## Notes")
        out.append("")
        out.extend(f"- {w}" for w in result.warnings)
        out.append("")
    return "\n".join(out)


def _label(link: str) -> str:
    from obaaf.render import _label as render_label

    return render_label(link)


def to_json(result: Result) -> str:
    payload = {
        "format": "obaaf-assessment-result/v0.1",
        "scoredBy": f"obaaf {__version__}",
        "studio": result.answers.studio,
        "date": result.answers.date,
        "tier": result.tier,
        "tierName": result.tier_name,
        "perTier": {str(k): v for k, v in result.per_tier.items()},
        "fixes": [
            {
                "rank": f.rank,
                "item": f.item["id"],
                "short": f.item["short"],
                "tier": f.item["tier"],
                "effort": f.item["effort"],
                "answer": f.answer,
                "profile": f.item["profile"],
                "prevents": [c["id"] for c in f.prevents],
                "limits": [c["id"] for c in f.limits],
                "fix": f.item["fix"],
            }
            for f in result.fixes
        ],
        "warnings": result.warnings,
    }
    return json.dumps(payload, indent=2) + "\n"
