"""Slice 4.9 (#152): the self-assessment says what its answers are and what a tier means.

The form (offline and on the site), the paper checklist and the answer file name the answers
they offer; where a tier is stated, it is said to reflect the answers given, which OBAAF does
not verify; and the catalogue's cases are described as mapped to an item, not as cases the item
would have prevented. The pages that describe the self-assessment say the same.
"""

import importlib.util
import re
import unittest

from helpers import ROOT

from obaaf import assess, render
from obaaf.catalog import load

# What the site's truth table cuts or narrows (docs/site-truth-table.md, C109, C110, C123 and
# C124), matched without regard to case or spacing.
CUT = re.compile(r"yes[\s-]*or[\s-]*no\b|would\s+have\s+prevented|would\s+prevent\b|controls\s+in\s+place|"
                 r"detects\s+or\s+limits|cases\s+it\s+addresses", re.IGNORECASE)
TIER_SENTENCE = "The tier reflects the answers you supplied; OBAAF does not verify that they are true."


def all_no():
    c = load()
    return assess.score(assess.parse_answers(
        {"format": assess.ANSWER_FORMAT, "answers": {iid: "no" for iid in c.items}}))


def built_assessment_page():
    spec = importlib.util.spec_from_file_location("obaaf_site_build_4_9", ROOT / "site" / "build.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    return build.assessment_page()


class AssessmentWordingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = load()
        read = lambda path: (ROOT / path).read_text(encoding="utf-8")
        cls.texts = {
            "form template": read("src/obaaf/form_template.html"),
            "offline form": read("assessment/obaaf-self-assessment.html"),
            "built form": built_assessment_page(),
            "checklist": render.self_assessment_md(cls.c),
            "text report": assess.to_text(all_no(), cls.c, limit=34),
            "Markdown report": assess.to_markdown(all_no(), cls.c),
            "answer file": assess.template(cls.c),
        }
        # Pages that describe the self-assessment. The papers' own pages (site/papers.html) and
        # the dated truth table quote the old words on purpose and are not read.
        cls.pages = {path: read(path) for path in
                     ("site/index.html", "README.md", "docs/architecture.md", "docs/threat-model.md")}

    def test_no_surface_uses_a_cut_phrase(self):
        for name, text in self.texts.items():
            with self.subTest(surface=name):
                self.assertEqual(CUT.findall(text), [])

    def test_the_pages_that_describe_it_do_not_either(self):
        for path, text in self.pages.items():
            # The home page says, of the papers' catalogue, that a mapping is not a test that a
            # control "would have prevented" a case: that sentence narrows the claim, so it stays.
            text = text.replace("A mapping is not a test that a control would have prevented the case.", "")
            with self.subTest(page=path):
                self.assertEqual(CUT.findall(text), [])

    def test_the_home_page_no_longer_warns_about_the_form(self):
        self.assertNotIn("issues/152", self.pages["site/index.html"])

    def test_each_place_that_states_a_tier_says_where_it_comes_from(self):
        for name in ("form template", "offline form", "built form", "checklist", "text report",
                     "Markdown report"):
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

    def test_the_form_offers_not_sure_and_says_where_it_starts(self):
        for name in ("form template", "offline form", "built form"):
            with self.subTest(surface=name):
                text = self.texts[name]
                opts = re.search(r"const opts = (.*);", text).group(1)
                self.assertIn('["yes", "Yes"], ["no", "No"]', opts)
                self.assertIn('["na", "N/A"]', opts)
                self.assertIn('["unanswered", "Not sure"]', opts)
                self.assertIn("Choose Yes, No or Not sure; each item starts at Not sure, which counts as No.", text)

    def test_the_checklists_not_sure_is_an_answer_the_scorer_takes(self):
        for written in ("not sure", "Not sure", " NOT SURE ", "unanswered", "unsure"):
            with self.subTest(answer=written):
                self.assertEqual(assess._normalize(written, "1.1").value, "unanswered")
        self.assertIn("If you are not sure, leave it unanswered (or write not sure); it counts as no.",
                      self.texts["answer file"])

    def test_reports_call_the_cases_mapped(self):
        self.assertIn("Cases mapped to prevention:", self.texts["text report"])
        self.assertIn("Cases mapped to detection or containment:", self.texts["text report"])
        self.assertIn("| Mapped cases |", self.texts["Markdown report"])
        for name in ("form template", "offline form", "built form"):
            with self.subTest(surface=name):
                self.assertIn("Cases mapped to prevention: ", self.texts[name])
                self.assertIn("Cases mapped to detection or containment: ", self.texts[name])


if __name__ == "__main__":
    unittest.main()
