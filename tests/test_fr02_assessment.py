"""FR2: score a self-assessment and rank the fixes.

Acceptance criterion: runs offline; each "no" links to the template or guide
that fixes it; nothing is sent over the network.
"""

import json
import random
import re
import shutil
import socket
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from helpers import ROOT, TempDir, run_cli

from obaaf import assess, render, yamlutil
from obaaf.catalog import load


def answers_with(default="no", **overrides):
    c = load()
    data = {"format": assess.ANSWER_FORMAT, "answers": {iid: default for iid in c.items}}
    for key, value in overrides.items():
        data["answers"][key.replace("_", ".")] = value
    return data


class ScoringTest(unittest.TestCase):
    def setUp(self):
        self.c = load()

    def score(self, data):
        return assess.score(assess.parse_answers(data))

    def test_34_items_in_tiers_of_8_12_9_5(self):
        counts = {}
        for item in self.c.items.values():
            counts[item["tier"]] = counts.get(item["tier"], 0) + 1
        self.assertEqual(counts, {1: 8, 2: 12, 3: 9, 4: 5})

    def test_all_yes_reaches_tier_4_with_nothing_to_fix(self):
        result = self.score(answers_with("yes"))
        self.assertEqual(result.tier, 4)
        self.assertEqual(result.fixes, [])

    def test_all_no_is_tier_0_and_ranks_every_item(self):
        result = self.score(answers_with("no"))
        self.assertEqual(result.tier, 0)
        self.assertEqual(len(result.fixes), 34)
        tiers = [f.item["tier"] for f in result.fixes]
        self.assertEqual(tiers, sorted(tiers), "lower tiers come first")

    def test_tiers_are_cumulative(self):
        # Everything yes except one tier 1 item: still tier 0 (DR6).
        result = self.score(answers_with("yes", **{"1_5": "no"}))
        self.assertEqual(result.tier, 0)
        self.assertEqual([f.item["id"] for f in result.fixes], ["1.5"])

    def test_ranking_within_a_tier_puts_lower_effort_first_then_more_documented_cases(self):
        tier1_yes = {f"1_{i}": "yes" for i in range(1, 9)}
        result = self.score(answers_with("no", **tier1_yes))
        first = [f.item["id"] for f in result.fixes[:6]]
        # Tier 2 items with effort L come first; 2.12 limits four documented cases.
        self.assertEqual(first[0], "2.12")
        self.assertEqual(set(first[:3]), {"2.12", "2.8", "2.9"})
        # Among effort M, 2.1 would have prevented four documented cases.
        self.assertEqual(first[3], "2.1")

    def test_not_applicable_counts_as_yes_only_where_allowed(self):
        data = answers_with("yes", **{"2_10": "na", "3_3": "na", "3_4": "na", "3_6": "na", "3_7": "na", "4_5": "na"})
        self.assertEqual(self.score(data).tier, 4)
        with self.assertRaises(assess.AnswerError):
            assess.parse_answers(answers_with("yes", **{"1_1": "na"}))

    def test_unanswered_counts_as_no_and_is_reported(self):
        data = answers_with("yes")
        del data["answers"]["1.4"]
        result = self.score(data)
        self.assertEqual(result.tier, 0)
        self.assertIn("1.4", result.warnings[0])

    def test_unquoted_numeric_ids_are_rejected_with_a_hint(self):
        text = "format: obaaf-assessment/v0.1\nanswers:\n  2.10: yes\n"
        with self.assertRaisesRegex(assess.AnswerError, "quoted"):
            assess.parse_answers(yamlutil.load(text))

    def test_yaml_yes_and_no_are_read_as_answers(self):
        text = 'format: obaaf-assessment/v0.1\nanswers:\n  "1.1": yes\n  "1.2": no\n'
        parsed = assess.parse_answers(yamlutil.load(text))
        self.assertEqual(parsed.answers["1.1"].value, "yes")
        self.assertEqual(parsed.answers["1.2"].value, "no")

    def test_unknown_items_and_answers_are_rejected(self):
        with self.assertRaises(assess.AnswerError):
            assess.parse_answers({"format": assess.ANSWER_FORMAT, "answers": {"9.9": "yes"}})
        with self.assertRaises(assess.AnswerError):
            assess.parse_answers({"format": assess.ANSWER_FORMAT, "answers": {"1.1": "maybe"}})


class FixLinksTest(unittest.TestCase):
    """Each 'no' links to the template or guide that fixes it."""

    def test_every_item_has_a_fix_link_that_resolves(self):
        for iid, item in load().items.items():
            with self.subTest(item=iid):
                self.assertTrue(item["fix"])
                for link in item["fix"]:
                    path, _, anchor = link.partition("#")
                    target = ROOT / path
                    self.assertTrue(target.is_file(), f"{link}: file missing")
                    if anchor:
                        text = target.read_text(encoding="utf-8")
                        self.assertTrue(f'id="{anchor}"' in text or anchor in _anchors(text),
                                        f"{link}: anchor missing")

    def test_each_item_guide_names_the_item(self):
        for iid, item in load().items.items():
            guide = next(link for link in item["fix"] if link.startswith("docs/guides/"))
            path, _, anchor = guide.partition("#")
            text = (ROOT / path).read_text(encoding="utf-8")
            self.assertIn(f"## Item {iid}:", text)

    def test_reports_carry_the_fix_links(self):
        result = assess.score(assess.parse_answers(answers_with("no")))
        md = assess.to_markdown(result)
        for item in load().items.values():
            self.assertIn(item["fix"][0], md)
        payload = json.loads(assess.to_json(result))
        self.assertTrue(all(f["fix"] for f in payload["fixes"]))


def _anchors(text):
    from obaaf.render import anchor

    return {anchor(line.lstrip("#").strip()) for line in text.splitlines() if line.startswith("#")}


class OfflineTest(unittest.TestCase):
    def test_scoring_uses_no_network(self):
        def refuse(*args, **kwargs):
            raise AssertionError("network access attempted")

        with TempDir() as tmp, mock.patch.object(socket, "socket", refuse), \
                mock.patch.object(socket, "create_connection", refuse):
            answers = tmp / "answers.yaml"
            self.assertEqual(run_cli("assess", "init", "--output", answers)[0], 0)
            code, out, _ = run_cli("assess", "score", answers)
            self.assertEqual(code, 0)
            self.assertIn("Tier reached: 0", out)
            self.assertEqual(run_cli("assess", "score", answers, "--format", "json")[0], 0)

    def test_offline_form_cannot_make_network_requests(self):
        page = (ROOT / "assessment" / "obaaf-self-assessment.html").read_text(encoding="utf-8")
        self.assertIn("default-src 'none'", page)
        self.assertNotRegex(page, r"""<(script|link|img)[^>]+(src|href)=["']https?:""")
        self.assertNotIn("fetch(", page)
        self.assertNotIn("XMLHttpRequest", page)
        data = json.loads(re.search(r'<script id="obaaf-data" type="application/json">(.*?)</script>', page, re.S)
                          .group(1).replace("<\\/", "</"))
        self.assertEqual(len(data["items"]), 34)
        self.assertTrue(all(item["fix"] for item in data["items"]))

    def test_cli_round_trip_from_template(self):
        with TempDir() as tmp:
            path = tmp / "answers.yaml"
            run_cli("assess", "init", "--output", path)
            text = path.read_text(encoding="utf-8")
            for iid in [f"1.{i}" for i in range(1, 9)]:
                text = text.replace(f'"{iid}": {{answer: unanswered', f'"{iid}": {{answer: yes')
            path.write_text(text, encoding="utf-8")
            code, out, _ = run_cli("assess", "score", path)
            self.assertEqual(code, 0)
            self.assertIn("Tier reached: 1 (Accounted)", out)

    def test_cli_reports_bad_answer_files(self):
        with TempDir() as tmp:
            path = tmp / "bad.yaml"
            path.write_text("answers:\n  '1.1': perhaps\n", encoding="utf-8")
            code, _, err = run_cli("assess", "score", path)
            self.assertEqual(code, 2)
            self.assertIn("perhaps", err)


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class FormParityTest(unittest.TestCase):
    """The offline form's scoring must agree with the Python scorer."""

    def test_random_answer_sets_score_identically(self):
        page = (ROOT / "assessment" / "obaaf-self-assessment.html").read_text(encoding="utf-8")
        code = page.split("// BEGIN OBAAF SCORING")[1].split("// END OBAAF SCORING")[0]
        data = render.form_data()
        rng = random.Random(7)
        cases = []
        for _ in range(60):
            answers = {}
            for item in data["items"]:
                choices = ["yes", "no", "unanswered"] + (["na"] if item["naWhen"] else [])
                weights = [6, 2, 1] + ([1] if item["naWhen"] else [])
                answers[item["id"]] = {"answer": rng.choices(choices, weights)[0]}
            cases.append(answers)
        with TempDir() as tmp:
            script = tmp / "parity.js"
            script.write_text(code + "\nconst data = " + json.dumps(data) + ";\nconst cases = " + json.dumps(cases)
                              + ";\nconsole.log(JSON.stringify(cases.map((c) => obaafScore(data, c))));\n",
                              encoding="utf-8")
            proc = subprocess.run(["node", str(script)], capture_output=True, text=True, check=True)
        js_results = json.loads(proc.stdout)
        for answers, js in zip(cases, js_results):
            py = assess.score(assess.parse_answers({"format": assess.ANSWER_FORMAT, "answers": answers}))
            self.assertEqual(js["tier"], py.tier)
            self.assertEqual([f["id"] for f in js["fixes"]], [f.item["id"] for f in py.fixes])


if __name__ == "__main__":
    unittest.main()
