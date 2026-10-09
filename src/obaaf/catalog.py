"""The OBAAF catalog: profile, agent controls, self-assessment, rules and cases.

The YAML files in ``obaaf/data`` are the single source of truth. Everything
else (the Markdown specifications, the offline form, the checker's messages)
is generated from them, and ``Catalog.problems()`` checks that they agree.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from obaaf import yamlutil

DATA_FILES = ("profile", "assessment", "agent_controls", "compromises", "frameworks", "rules", "detection")


def _read(name: str) -> Any:
    text = resources.files("obaaf.data").joinpath(f"{name}.yaml").read_text(encoding="utf-8")
    return yamlutil.load(text)


def data_text(relpath: str) -> str:
    """Read any file shipped in obaaf/data, such as a JSON Schema."""
    return resources.files("obaaf.data").joinpath(relpath).read_text(encoding="utf-8")


@dataclass
class Catalog:
    profile: dict
    assessment: dict
    controls: dict
    compromises: dict
    frameworks: dict
    rules_data: dict
    detection: dict
    requirements: dict = field(default_factory=dict)  # G-id -> requirement (with "family")
    families: dict = field(default_factory=dict)      # F-id -> family
    items: dict = field(default_factory=dict)         # item id -> item
    tiers: dict = field(default_factory=dict)         # tier number -> tier
    agent_requirements: dict = field(default_factory=dict)  # R-id -> requirement
    rules: dict = field(default_factory=dict)         # rule id -> rule

    def __post_init__(self) -> None:
        for fam in self.profile["families"]:
            self.families[fam["id"]] = fam
            for req in fam["requirements"]:
                self.requirements[req["id"]] = dict(req, family=fam["id"])
        for tier in self.assessment["tiers"]:
            self.tiers[tier["id"]] = tier
        for item in self.assessment["items"]:
            self.items[str(item["id"])] = item
        for req in self.controls["requirements"]:
            self.agent_requirements[req["id"]] = req
        for rule in self.rules_data["rules"]:
            self.rules[rule["id"]] = rule

    # ------------------------------------------------------------------ lookups
    def items_for_requirement(self, gid: str) -> list[dict]:
        return [item for item in self.items.values() if gid in item["profile"]]

    def item_cases(self, item_id: str) -> dict[str, list[dict]]:
        """Documented compromises for which the item is a deciding control (Paper 2, Table 7)."""
        prevent, limit = [], []
        for case in self.compromises["game_cases"] + self.compromises["transfer_cases"]:
            if item_id in case.get("prevent_items", []):
                prevent.append(case)
            if item_id in case.get("limit_items", []):
                limit.append(case)
        return {"prevent": prevent, "limit": limit}

    def rules_for_requirement(self, rid: str) -> list[dict]:
        return [r for r in self.rules.values() if rid in r.get("requirements", []) or rid in r.get("agent_controls", [])]

    def ssdf_title(self, ref: str) -> str:
        ssdf = self.frameworks["ssdf"]
        if ref in ssdf["practices"]:
            return ssdf["practices"][ref]["title"]
        if ref in ssdf["tasks"]:
            return ssdf["tasks"][ref]["summary"]
        return ref

    # ------------------------------------------------------------------ checks
    def problems(self) -> list[str]:
        """Return every inconsistency between the data files (empty when consistent)."""
        out: list[str] = []
        ssdf = self.frameworks["ssdf"]
        known_ssdf = set(ssdf["practices"]) | set(ssdf["tasks"])
        known_slsa = set(self.frameworks["slsa"]["requirements"])
        attack_paths = set(self.profile["attack_paths"])
        properties = set(self.profile["properties"])

        # Profile (FR1): 28 requirements in nine families, each with an ID, a test and a mapping.
        if len(self.families) != 9:
            out.append(f"profile: expected 9 families, found {len(self.families)}")
        if len(self.requirements) != 28:
            out.append(f"profile: expected 28 requirements, found {len(self.requirements)}")
        for gid, req in self.requirements.items():
            if not re.fullmatch(r"G[1-9]\.[1-9]", gid):
                out.append(f"{gid}: malformed requirement ID")
            if not gid.startswith("G" + req["family"][1:] + "."):
                out.append(f"{gid}: ID does not match family {req['family']}")
            for key in ("title", "statement", "rationale", "test", "evidence"):
                if not str(req.get(key, "")).strip():
                    out.append(f"{gid}: missing {key}")
            if not req.get("ssdf") and not req.get("slsa") and not req.get("other"):
                out.append(f"{gid}: no SSDF, SLSA or other mapping")
            for ref in req.get("ssdf", []):
                if ref not in known_ssdf:
                    out.append(f"{gid}: unknown SSDF reference {ref}")
            for ref in req.get("slsa", []):
                if ref not in known_slsa:
                    out.append(f"{gid}: unknown SLSA reference {ref}")
            for ap in req["addresses"]["attack_paths"]:
                if ap not in attack_paths:
                    out.append(f"{gid}: unknown attack path {ap}")
            for prop in req["addresses"]["properties"]:
                if prop not in properties:
                    out.append(f"{gid}: unknown property {prop}")
            for rule_id in req.get("checks", []):
                if rule_id not in self.rules:
                    out.append(f"{gid}: unknown checker rule {rule_id}")
            for rid in req.get("agent_controls", []):
                if rid not in self.agent_requirements:
                    out.append(f"{gid}: unknown agent control {rid}")

        # Self-assessment (FR2): 34 items in four tiers.
        counts = {t: 0 for t in self.tiers}
        for iid, item in self.items.items():
            if not re.fullmatch(r"[1-4]\.[0-9]{1,2}", iid):
                out.append(f"item {iid}: malformed ID")
            if int(iid.split(".")[0]) != item["tier"]:
                out.append(f"item {iid}: ID does not match tier {item['tier']}")
            counts[item["tier"]] = counts.get(item["tier"], 0) + 1
            if item["effort"] not in self.assessment["effort"]:
                out.append(f"item {iid}: unknown effort {item['effort']}")
            for gid in item["profile"]:
                if gid not in self.requirements:
                    out.append(f"item {iid}: unknown profile requirement {gid}")
            if not item.get("fix"):
                out.append(f"item {iid}: no fix link (FR2 requires one for every 'no')")
            for key in ("question", "evidence", "short"):
                if not str(item.get(key, "")).strip():
                    out.append(f"item {iid}: missing {key}")
        if len(self.items) != 34:
            out.append(f"assessment: expected 34 items, found {len(self.items)}")
        if counts != {1: 8, 2: 12, 3: 9, 4: 5}:
            out.append(f"assessment: tier sizes {counts} differ from Paper 2 (8, 12, 9, 5)")

        # Traceability (Paper 2, Table 8; FR1).
        traced_refs = set()
        for row in self.assessment["traceability"]:
            traced_refs.add(row["ref"])
            for iid in row["items"]:
                if iid not in self.items:
                    out.append(f"traceability {row['ref']}: unknown item {iid}")
            if not row["items"]:
                out.append(f"traceability {row['ref']}: no items")
        for group in self.frameworks["slsa"]["build_track_groups"]:
            if group not in traced_refs:
                out.append(f"FR1: SLSA Build-track group {group} maps to no assessment item")

        # Cases.
        for case in self.compromises["game_cases"] + self.compromises["transfer_cases"]:
            for iid in case.get("prevent_items", []) + case.get("limit_items", []):
                if iid not in self.items:
                    out.append(f"case {case['id']}: unknown item {iid}")
            for iid in case.get("prevent_items", []):
                if self.items.get(iid, {}).get("tier") != case["prevented_at"]:
                    out.append(f"case {case['id']}: item {iid} is not at the 'prevented at' tier {case['prevented_at']}")
        for case in self.compromises["agent_cases"]:
            for rid in case["prevented_by"] + case["contained_by"]:
                if rid not in self.agent_requirements:
                    out.append(f"agent case {case['id']}: unknown requirement {rid}")

        # Agent controls.
        if sorted(self.agent_requirements) != [f"R{i}" for i in range(1, 9)]:
            out.append("agent controls: expected R1 to R8")
        for rid, req in self.agent_requirements.items():
            for rule_id in req.get("obaaf", {}).get("checks", []):
                if rule_id not in self.rules:
                    out.append(f"{rid}: unknown checker rule {rule_id}")
            for ref in req.get("ssdf", []):
                if ref not in known_ssdf:
                    out.append(f"{rid}: unknown SSDF reference {ref}")

        # Rules.
        for rule_id, rule in self.rules.items():
            if rule["severity"] not in ("high", "medium", "low"):
                out.append(f"{rule_id}: unknown severity {rule['severity']}")
            for gid in rule.get("requirements", []):
                if gid not in self.requirements:
                    out.append(f"{rule_id}: unknown profile requirement {gid}")
            for rid in rule.get("agent_controls", []):
                if rid not in self.agent_requirements:
                    out.append(f"{rule_id}: unknown agent control {rid}")
            for key in ("title", "description", "fix"):
                if not str(rule.get(key, "")).strip():
                    out.append(f"{rule_id}: missing {key}")

        # Mappings between rules and requirements must agree in both directions.
        for gid, req in self.requirements.items():
            for rule_id in req.get("checks") or []:
                if rule_id in self.rules and gid not in self.rules[rule_id].get("requirements", []):
                    out.append(f"{gid} lists {rule_id}, but {rule_id} does not list {gid}")
        for rid, req in self.agent_requirements.items():
            for rule_id in (req.get("obaaf") or {}).get("checks") or []:
                if rule_id in self.rules and rid not in self.rules[rule_id].get("agent_controls", []):
                    out.append(f"{rid} lists {rule_id}, but {rule_id} does not list {rid}")
        for rule_id, rule in self.rules.items():
            for gid in rule.get("requirements", []):
                if gid in self.requirements and rule_id not in (self.requirements[gid].get("checks") or []):
                    out.append(f"{rule_id} lists {gid}, but {gid} does not list {rule_id}")
            for rid in rule.get("agent_controls", []):
                checks = (self.agent_requirements.get(rid, {}).get("obaaf") or {}).get("checks") or []
                if rid in self.agent_requirements and rule_id not in checks:
                    out.append(f"{rule_id} lists {rid}, but {rid} does not list {rule_id}")
        return out


@functools.lru_cache(maxsize=1)
def load() -> Catalog:
    data = {name: _read(name) for name in DATA_FILES}
    return Catalog(
        profile=data["profile"],
        assessment=data["assessment"],
        controls=data["agent_controls"],
        compromises=data["compromises"],
        frameworks=data["frameworks"],
        rules_data=data["rules"],
        detection=data["detection"],
    )
