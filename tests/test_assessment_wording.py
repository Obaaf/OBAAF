"""Slice 4.9 (#152): the self-assessment says what its answers are and what a tier means.

The form, the paper checklist and the score reports name every answer they accept,
say that the tier comes from the answers given (which OBAAF does not check), and
describe the catalogue's cases as mapped to an item, not as cases the item would
have prevented.
"""

import re
import unittest

from helpers import ROOT

from obaaf import assess, render
from obaaf.catalog import load

# Phrases the site's truth table cuts or narrows (docs/site-truth-table.md, C109 and C123).
CUT = ("yes-or-no", "Would have prevented", "would have prevented", "controls in place",
       "Detects or limits", "cases it addresses")
TIER_SENTENCE = "The tier reflects the answers you supplied; OBAAF does not check them."


def all_no():
    c = load()
    return assess.score(assess.parse_answers(
        {"format": assess.ANSWER_FORMAT, "answers": {iid: "no" for iid in c.items}}))


class AssessmentWordingTest(unittest.TestCase):
    def setUp(self):
        self.c = load()
        self.texts = {
            "form template": (ROOT / "src/obaaf/form_template.html").read_text(encoding="utf-8"),
            "offline form": (ROOT / "assessment/obaaf-self-assessment.html").read_text(encoding="utf-8"),
            "checklist": render.self_assessment_md(self.c),
            "text report": assess.to_text(all_no(), self.c, limit=34),
            "Markdown report": assess.to_markdown(all_no(), self.c),
            "answer template": assess.template(self.c),
        }

    def test_no_surface_uses_a_cut_phrase(self):
        for name, text in self.texts.items():
            for phrase in CUT:
                with self.subTest(surface=name, phrase=phrase):
                    self.assertNotIn(phrase, text)

    def test_each_place_that_states_a_tier_says_where_it_comes_from(self):
        for name in ("form template", "offline form", "checklist", "text report", "Markdown report"):
            with self.subTest(surface=name):
                self.assertIn(TIER_SENTENCE, self.texts[name])

    def test_the_checklist_offers_not_sure_everywhere_and_na_only_where_allowed(self):
        rows = [line for line in self.texts["checklist"].splitlines()
                if re.match(r"\| \d\.\d+ \|", line) and "☐ Yes" in line]
        self.assertEqual(len(rows), len(self.c.items))
        for line in rows:
            iid = line.split("|")[1].strip()
            with self.subTest(item=iid):
                self.assertIn("☐ Yes ☐ No ☐ Not sure", line)
                self.assertEqual("☐ N/A" in line, bool(self.c.items[iid].get("na_when")))
        self.assertIn("Not sure counts as No", self.texts["checklist"])

    def test_the_form_offers_not_sure_and_names_it(self):
        for name in ("form template", "offline form"):
            with self.subTest(surface=name):
                text = self.texts[name]
                self.assertIn('["unanswered", "Not sure"]', text)
                self.assertIn("Choose Yes, No or Not sure.", text)

    def test_the_answer_template_names_not_sure(self):
        self.assertIn("if you are not sure; it counts as no", self.texts["answer template"])

    def test_reports_call_the_cases_mapped(self):
        self.assertIn("Cases mapped to prevention:", self.texts["text report"])
        self.assertIn("Cases mapped to detection or containment:", self.texts["text report"])
        self.assertIn("| Mapped cases |", self.texts["Markdown report"])
        for name in ("form template", "offline form"):
            with self.subTest(surface=name):
                self.assertIn("Cases mapped to prevention: ", self.texts[name])
                self.assertIn("Cases mapped to detection or containment: ", self.texts[name])


if __name__ == "__main__":
    unittest.main()
