"""Paperwork candidates list the precise changes the private-copy checker proves."""

from dataclasses import replace
from datetime import date, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from obaaf import checker
from obaaf.checker import baseline
from obaaf.fix_paperwork import plan
from obaaf.fix_proof import CheckOptions, ProofError, prove


class PaperworkTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.file = ".github/workflows/build.yml"
        self.config = self.root / ".github/obaaf.yml"
        self.base = self.root / "accepted.json"
        workflow_file = self.root / self.file
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text("name: Build\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                                 "    steps:\n      - uses: actions/checkout@v4\n")
        self.options = CheckOptions()
        self.expiry = (date.today() + timedelta(days=30)).isoformat()

    def result(self):
        target = self.root / self.options.path
        cfg = checker.Config.load(self.root)
        result = checker.check(target, config=cfg, platform=self.options.platform,
                               gate_files=[self.base] if self.options.baseline else [])
        if self.options.baseline:
            baseline.apply(result, baseline.load(self.base))
        return result

    def planned(self, **kwargs):
        return plan(self.root, self.options, self.result(), **kwargs)

    def prove(self, candidate):
        return prove(self.root, self.options, candidate.edits, candidate.promises)

    def ignore(self, path):
        return (f"  - rule: OBAAF-GHA-008\n    path: {path}\n    reason: already reviewed\n"
                f"    until: {self.expiry}\n")

    def test_completes_exact_ignore_with_other_fields_and_comments_preserved(self):
        text = "ignore:\n" + self.ignore(self.file) + "# end\n"
        self.config.write_text(text)
        self.assertFalse(self.planned().edits)
        candidate = self.planned(owner="@team")
        self.assertEqual(len(candidate.promises), 1)
        made = candidate.promises[0].approval
        self.assertEqual((made.source, made.owner, made.reason, made.expires),
                         ("ignore", "@team", "already reviewed", self.expiry))
        self.assertIn(b"# end", candidate.edits[0].after)
        self.prove(candidate)
        self.assertEqual(self.config.read_text(), text)

    def test_stale_ignore_listed_and_owner_at_shifted_index_proved_together(self):
        self.config.write_text("ignore:\n" + self.ignore("absent.yml") + self.ignore(self.file))
        both = self.planned(owner="@team")
        self.assertEqual([i.kind for i in both.items], ["removal", "acceptance"])
        self.assertIn("absent.yml", both.items[0].removals[0])
        self.prove(both)
        removal = self.planned(owner="@team", selected={both.items[0].id})
        self.assertEqual(len(removal.items), 1)
        self.assertFalse(removal.promises)
        self.prove(removal)

    def test_last_ignore_removal_keeps_empty_sequence(self):
        for text in ("ignore:\n" + self.ignore("absent.yml"),
                     'ignore: [{rule: missing, path: absent.yml, reason: review, until: "'
                     + self.expiry + '"}]\n'):
            with self.subTest(text=text):
                self.config.write_text(text)
                candidate = self.planned()
                self.assertEqual(len(candidate.items), 1)
                self.prove(candidate)

    def test_unique_lane_and_ambiguous_or_distant_lane(self):
        key = self.file + "#build"
        self.config.write_text(f"lanes:\n  {key}: trused # retain me\n")
        candidate = self.planned()
        self.assertEqual(len(candidate.items), 1)
        self.assertEqual(candidate.promises[0].outcome, "gone")
        self.assertIn(b"trusted # retain me", candidate.edits[0].after)
        self.prove(candidate)
        self.config.write_text(f"lanes:\n  {key}: ntrusted\n")
        ambiguous = self.planned()
        self.assertFalse(ambiguous.items)
        self.assertIn("more than one", str(ambiguous.refused))
        self.config.write_text(f"lanes:\n  {key}: probe\n")
        self.assertFalse(self.planned().edits)

    def test_stale_current_baseline_removal_retains_valid_owner(self):
        f = next(f for f in self.result().findings if f.rule == "OBAAF-GHA-008")
        valid = baseline.entry_for(f, "@prior", "prior review", self.expiry)
        stale = dict(valid, path="missing")
        self.base.write_text(json.dumps({"format": baseline.FORMAT, "findings": [stale, valid, stale]}))
        self.options = replace(self.options, baseline=Path("accepted.json"))
        c = self.planned()
        self.assertEqual(len(c.items), 2)
        self.assertTrue(all(i.removals for i in c.items))
        self.assertEqual(json.loads(c.edits[0].after)["findings"], [valid])
        self.prove(c)
        self.options = replace(self.options, platform="github")
        self.assertFalse(self.planned().edits)

    def test_migration_carries_only_old_match_and_names_each_stale_entry(self):
        self.options = replace(self.options, baseline=Path("accepted.json"))
        self.base.write_text(json.dumps({"format": baseline.FORMAT_V1, "findings": []}))
        found = next(f for f in self.result().findings if f.rule == "OBAAF-GHA-008")
        entries = []
        for f in (found, replace(found, path="other.yml")):
            entry = {key: getattr(f, key) for key in ("rule", "severity", "path", "job", "step", "scope")
                     if getattr(f, key)}
            entry.update(message=f.legacy or f.message, fingerprint=baseline.fingerprint(f))
            entries.append(entry)
        self.base.write_text(json.dumps({"format": baseline.FORMAT_V1, "findings": entries}))
        self.assertFalse(self.planned(owner="@team").edits)
        c = self.planned(owner="@team", reason="accepted at adoption", expires=self.expiry)
        self.assertEqual(len(c.promises), 1)
        self.assertEqual(c.promises[0].identity, baseline.key(found))
        self.assertIn("other.yml", c.items[0].removals[0])
        self.prove(c)
        self.assertEqual(json.loads(self.base.read_bytes())["format"], baseline.FORMAT_V1)

    def test_partial_check_cannot_remove_ignores_or_complete_broad_entries(self):
        self.config.write_text("ignore:\n" + self.ignore("absent.yml") + self.ignore(self.file))
        self.options = replace(self.options, path=Path(self.file))
        self.assertFalse(self.planned(owner="@team").edits)

    def test_lane_that_disturbs_existing_acceptance_is_withheld_by_proof(self):
        key = self.file + "#build"
        self.config.write_text(f"lanes:\n  {key}: trused\n")
        f = next(f for f in self.result().findings if f.kind == "entry-not-a-lane")
        entry = baseline.entry_for(f, "@prior", "prior review", self.expiry)
        self.base.write_text(json.dumps({"format": baseline.FORMAT, "findings": [entry]}))
        self.options = replace(self.options, baseline=Path("accepted.json"))
        candidate = self.planned()
        self.assertEqual(len(candidate.items), 1)
        with self.assertRaises(ProofError):
            self.prove(candidate)

    def test_blank_owner_can_be_completed_without_overwriting_an_invalid_named_owner(self):
        for owner_line, eligible in (("    owner:\n", True), ("    owner: '  '\n", True),
                                     ("    owner: bogus\n", False), ("    owner: false\n", False)):
            with self.subTest(owner_line=owner_line):
                self.config.write_text("ignore:\n" + self.ignore(self.file) + owner_line)
                candidate = self.planned(owner="@team")
                self.assertEqual(bool(candidate.edits), eligible)
                if eligible:
                    self.prove(candidate)

    def test_overlapping_ignores_are_withheld_instead_of_promising_the_same_finding_twice(self):
        self.config.write_text("ignore:\n" + self.ignore(self.file) + self.ignore(self.file))
        candidate = self.planned(owner="@team")
        self.assertFalse(candidate.edits)
        self.assertIn("more than one ignore", str(candidate.refused))
