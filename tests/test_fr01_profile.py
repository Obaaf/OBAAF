"""FR1: publish each profile requirement with its rationale, a test, and its SSDF and SLSA mappings.

Acceptance criterion: all 28 requirements have an ID, a test procedure and at
least one mapping, and every SLSA Build-track requirement maps to at least one
assessment item.
"""

import re
import unittest

from helpers import ROOT  # noqa: F401  (adds src to the path)

from obaaf.catalog import load


class ProfileTest(unittest.TestCase):
    def setUp(self):
        self.c = load()

    def test_data_files_are_consistent(self):
        self.assertEqual(self.c.problems(), [])

    def test_28_requirements_in_nine_families(self):
        sizes = {fid: len(f["requirements"]) for fid, f in self.c.families.items()}
        self.assertEqual(sizes, {"F1": 3, "F2": 3, "F3": 4, "F4": 3, "F5": 3, "F6": 5, "F7": 3, "F8": 3, "F9": 1})
        self.assertEqual(len(self.c.requirements), 28)

    def test_every_requirement_has_id_rationale_test_and_mapping(self):
        for gid, req in self.c.requirements.items():
            with self.subTest(requirement=gid):
                self.assertRegex(gid, r"^G[1-9]\.[1-9]$")
                self.assertGreater(len(req["rationale"].split()), 10)
                self.assertGreater(len(req["test"].split()), 10)
                self.assertRegex(req["test"].lower(), r"pass|confirm|verify|check")
                self.assertTrue(req["ssdf"] or req["slsa"] or req.get("other"))

    def test_every_slsa_build_track_group_maps_to_an_assessment_item(self):
        traced = {row["ref"]: row["items"] for row in self.c.assessment["traceability"]}
        for group in self.c.frameworks["slsa"]["build_track_groups"]:
            with self.subTest(group=group):
                self.assertTrue(traced.get(group), f"{group} has no assessment item")
                for item in traced[group]:
                    self.assertIn(item, self.c.items)

    def test_statements_match_paper_2_table_4(self):
        # Spot checks against the paper's wording.
        self.assertIn("reported as below Build L3", self.c.requirements["G3.2"]["statement"])
        self.assertIn("asset revision, manifest digest, SDK versions, and builder identity",
                      self.c.requirements["G7.1"]["statement"])
        self.assertEqual(self.c.requirements["G6.2"]["ssdf"], ["PS.4"])
        self.assertEqual(self.c.requirements["G8.1"]["agent_controls"], ["R1", "R2", "R3", "R4", "R7"])
        self.assertEqual(self.c.requirements["G2.1"]["ssdf"], ["PW.4", "PS.3.2"])

    def test_every_requirement_is_covered_by_an_item_or_is_listed_as_uncovered(self):
        # Paper 2's items cover these requirements; G2.1/G3.2 etc. have several items.
        uncovered = sorted(gid for gid in self.c.requirements if not self.c.items_for_requirement(gid))
        self.assertEqual(uncovered, [], "every profile requirement should be reachable from the assessment")

    def test_generated_profile_document_lists_every_requirement(self):
        text = (ROOT / "spec" / "profile.md").read_text(encoding="utf-8")
        for gid, req in self.c.requirements.items():
            with self.subTest(requirement=gid):
                self.assertIn(f"### {gid} {req['title']}", text)
                section = text.split(f"### {gid} ")[1].split("\n### ")[0]
                self.assertIn("**Test.**", section)
                self.assertIn("**Maps to.** SSDF:", section)

    def test_agent_controls_document_has_r1_to_r8(self):
        text = (ROOT / "spec" / "agent-controls.md").read_text(encoding="utf-8")
        for rid in [f"R{i}" for i in range(1, 9)]:
            self.assertRegex(text, rf"### {rid} ")
        self.assertIn(r"\bigsqcap", text)

    def test_checker_rules_referenced_by_the_profile_exist(self):
        for gid, req in self.c.requirements.items():
            for rule in req.get("checks", []):
                self.assertIn(rule, self.c.rules, f"{gid} references {rule}")

    def test_ids_are_stable_format(self):
        for rid in self.c.rules:
            self.assertRegex(rid, r"^OBAAF-(GHA|REPO|INS)-\d{3}$")
        for iid in self.c.items:
            self.assertTrue(re.fullmatch(r"[1-4]\.\d{1,2}", iid))


if __name__ == "__main__":
    unittest.main()
