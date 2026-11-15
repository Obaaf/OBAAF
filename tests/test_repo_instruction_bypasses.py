"""Plan slice 2d.2h: the ways past OBAAF-REPO-001, OBAAF-REPO-002 and OBAAF-INS-001 that two reviewers
found, each as a test of its class. The record of every attempt is docs/bypass-attempts.md, section
"2d.2h"; the attempt ids (A..., B...) are named in each test."""

from __future__ import annotations

import json
import os
import random
import re
import time
import unittest

from helpers import TempDir, run_cli

from obaaf import checker
from obaaf.checker import baseline, repo

WORKFLOW = "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n"
# Owns everything the gate needs except what a test leaves out.
GATE = ("/.github/CODEOWNERS @octocat\n/.github/obaaf.yml @octocat\n/.github/obaaf.yaml @octocat\n/obaaf.yml @octocat\n"
        "/.github/egress-firewall.yaml @octocat\n")


def tree(root, files: dict) -> None:
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW, encoding="utf-8")
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


def found(root, *rules, **kw):
    result = checker.check(root, **kw)
    return [f for f in result.findings if not rules or f.rule in rules], result


def unowned(root, kind="no-owner", rule="OBAAF-REPO-001"):
    findings, _ = found(root, rule)
    out = []
    for f in findings:
        if f.kind == kind:
            out.extend(f.facts["files"])
    return sorted(out)


class OwnerFormTest(unittest.TestCase):
    """A001-A016, A025, A026, A052, A092, A094, A099, A105-A109, A113: any owner list counted."""

    def test_an_owner_in_a_form_github_does_not_read_gives_no_owner(self):
        for owner in ("octocat", "@", "@org/", "TODO", "*", "\uff20octocat", '"@octocat"',
                      "@your-org/build-owners", "@a#b"):
            with self.subTest(owner=owner), TempDir() as tmp:
                tree(tmp, {".github/CODEOWNERS": GATE + f"/.github/workflows/ {owner}\n"})
                self.assertIn(".github/workflows/ci.yml", unowned(tmp))

    def test_one_bad_owner_on_a_line_takes_the_line_away(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/ @octocat octocat\n"})
            findings, _ = found(tmp, "OBAAF-REPO-001")
            message = next(f.message for f in findings if f.kind == "no-owner")
            self.assertIn("line 6", message)
            self.assertIn("so GitHub assigns no owner", message)

    def test_valid_owners_still_own(self):
        for owner in ("@octocat", "@my-org/build", "dev@example.com", "@octocat @my-org/build"):
            with self.subTest(owner=owner), TempDir() as tmp:
                tree(tmp, {".github/CODEOWNERS": GATE + f"/.github/workflows/ {owner}\n"})
                self.assertEqual(unowned(tmp), [])


class LinesAndFieldsTest(unittest.TestCase):
    """A017-A024, A093, A095 (separators Python takes and GitHub may not), A028, A096, A029 (`#`)."""

    def test_only_a_line_feed_ends_a_line(self):
        for sep in ("\u2028", "\u2029", "\x85", "\x0c", "\x0b", "\x1c", "\x1e", "\r"):
            with self.subTest(sep=repr(sep)), TempDir() as tmp:
                tree(tmp, {".github/CODEOWNERS": GATE + f"# a comment{sep}/.github/workflows/ @octocat\n"})
                self.assertIn(".github/workflows/ci.yml", unowned(tmp))

    def test_only_space_and_tab_separate_fields(self):
        for sep in ("\u00a0", "\u3000", "\x1f", "\u2003"):
            with self.subTest(sep=repr(sep)), TempDir() as tmp:
                tree(tmp, {".github/CODEOWNERS": GATE + f"/.github/workflows/{sep}@octocat\n"})
                self.assertIn(".github/workflows/ci.yml", unowned(tmp))

    def test_a_crlf_file_and_tabs_still_own(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": (GATE + "/.github/workflows/\t@octocat\n").replace("\n", "\r\n")})
            self.assertEqual(unowned(tmp), [])

    def test_a_comment_begins_only_at_the_start_or_after_whitespace(self):
        rules = repo.parse_codeowners("/a/ @x #c\n/b/#x @y\n/c/ @z#w\n#/d/ @q\n")
        self.assertEqual([(r.pattern, r.owners) for r in rules],
                         [("/a/", ["@x"]), ("/b/#x", ["@y"]), ("/c/", ["@z#w"])])
        self.assertIsNotNone(rules[2].problem)


class FileTest(unittest.TestCase):
    """A025 (bytes), A057, A058 (3 MB), A060-A062, A111 (links and case at the three places)."""

    def test_a_file_that_is_not_utf8_is_an_error(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE.encode() + b"/.github/workflows/ @octo\xffcat\n"})
            findings, result = found(tmp, "OBAAF-REPO-001")
            self.assertEqual(findings, [])
            self.assertTrue(any("not UTF-8" in e for e in result.errors), result.errors)

    def test_a_file_of_3_mb_or_more_is_not_loaded(self):
        with TempDir() as tmp:
            filler = "# " + "x" * 98 + "\n"
            text = GATE + "/.github/workflows/ @octocat\n" + filler * (repo.CODEOWNERS_LIMIT // 100 + 1)
            tree(tmp, {".github/CODEOWNERS": text, "AGENTS.md": "x\n"})
            findings, _ = found(tmp, "OBAAF-REPO-001", "OBAAF-REPO-002")
            self.assertEqual(sorted((f.rule, f.kind) for f in findings),
                             [("OBAAF-REPO-001", "not-loaded"), ("OBAAF-REPO-002", "not-loaded")])

    def test_a_link_at_a_codeowners_place_is_an_error_and_never_a_reason_to_look_further(self):
        with TempDir() as tmp:
            tree(tmp, {"elsewhere": GATE + "/.github/workflows/ @octocat\n", "CODEOWNERS": GATE})
            (tmp / ".github" / "CODEOWNERS").symlink_to(tmp / "elsewhere")
            findings, result = found(tmp, "OBAAF-REPO-001")
            self.assertEqual(findings, [])
            self.assertTrue(any("symbolic link" in e for e in result.errors), result.errors)
        with TempDir() as tmp:
            tree(tmp, {"CODEOWNERS": GATE + "/.github/workflows/ @octocat\n"})
            (tmp / ".github" / "CODEOWNERS").symlink_to(tmp / "missing")
            _, result = found(tmp)
            self.assertTrue(any("symbolic link" in e for e in result.errors), result.errors)

    def test_the_name_is_matched_exactly(self):
        with TempDir() as tmp:
            tree(tmp, {".github/codeowners": GATE + "/.github/workflows/ @octocat\n"})
            findings, _ = found(tmp, "OBAAF-REPO-001")
            self.assertEqual([f.kind for f in findings], ["no-codeowners"])


class PatternTest(unittest.TestCase):
    """A037-A039, A097 (`**` not beside a slash), A101-A104 (time)."""

    def test_double_star_is_a_folder_wildcard_only_beside_slashes(self):
        cases = [("/.github/work**", ".github/workflows/ci.yml", False), ("/.github**", ".github/workflows/ci.yml", False),
                 ("/.github/**.yml", ".github/workflows/ci.yml", False), ("/.cursor**", ".cursor/rules/a.mdc", False),
                 ("**/logs", "a/b/logs/x", True), ("/a/**/b", "a/b", True), ("/a/**/b", "a/x/y/b", True),
                 ("/a/**", "a/x/y", True), ("docs/*", "docs/a.md", True), ("docs/*", "docs/b/a.md", False),
                 ("apps/", "lib/apps/x", True), ("*.yml", ".github/workflows/ci.yml", True)]
        for pattern, path, expected in cases:
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(repo.Pattern(pattern).match(path), expected)

    def test_the_automaton_agrees_with_the_regular_expression(self):
        rnd = random.Random(2)
        for _ in range(20000):
            pattern = ("/" if rnd.random() < 0.3 else "") + "".join(rnd.choice("ab/*?") for _ in range(rnd.randint(1, 9)))
            path = re.sub("/+", "/", "".join(rnd.choice("ab/") for _ in range(rnd.randint(1, 12)))).strip("/")
            if not path:
                continue
            compiled = repo.Pattern(pattern)
            expected = compiled._regex().fullmatch(path) is not None
            compiled._build_automaton()
            compiled.regex = None
            self.assertEqual(compiled.match(path), expected, (pattern, path))
            rules = [repo.OwnerRule(pattern, ["@o"], 1)]
            self.assertEqual(repo.owners_for(rules, path) is not None, expected, (pattern, path))

    def test_patterns_written_to_backtrack_take_no_time(self):
        with TempDir() as tmp:
            nasty = "/" + "*a" * 30 + "*b @octocat\n" + "**/" * 50 + "x*x*x*x*x*x*x*y @octocat\n"
            many = "".join(f"/area{i}/module/*.txt @octocat\n" for i in range(60000))
            tree(tmp, {".github/CODEOWNERS": many + GATE + "/.github/workflows/ @octocat\n" + nasty,
                       "a" * 200 + "/AGENTS.md": "x\n"})
            start = time.monotonic()
            found(tmp)
            self.assertLess(time.monotonic() - start, 5)

    def test_more_comparisons_than_the_budget_are_an_error(self):
        from unittest import mock
        rules = [repo.OwnerRule("?b?", ["@o"], i) for i in range(10)]     # its plain text is in "ab"; no match
        with mock.patch.object(repo, "MATCH_BUDGET", 15):
            index = repo.OwnerIndex(rules)
            index.owners("ab")
            with self.assertRaises(repo.UnreadableFile):
                index.owners("ab")
        rules = [repo.OwnerRule(f"/x{i}/", ["@o"], i) for i in range(10)]   # skipped by its plain text
        with mock.patch.object(repo, "STEP_BUDGET", 15):
            index = repo.OwnerIndex(rules)
            index.owners("ab")
            with self.assertRaises(repo.UnreadableFile):
                index.owners("ab")


class GateFilesTest(unittest.TestCase):
    """A066-A074: CODEOWNERS, the configuration, a baseline and the firewall policy need an owner,
    and the finding for them cannot be accepted by the files it names (A069, A070)."""

    def test_codeowners_itself_needs_an_owner(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": "/.github/workflows/ @octocat\n/.github/obaaf.yml @octocat\n"
                                             "/.github/obaaf.yaml @octocat\n/obaaf.yml @octocat\n"
                                             "/.github/egress-firewall.yaml @octocat\n"})
            self.assertEqual(unowned(tmp, "gate-no-owner"), [".github/CODEOWNERS"])

    def test_every_configuration_place_counts_while_there_is_none(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": "/.github/ @octocat\n"})
            self.assertEqual(unowned(tmp, "gate-no-owner"), ["obaaf.yml"])

    def test_the_configuration_in_use_counts(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": "/.github/workflows/ @octocat\n/.github/CODEOWNERS @octocat\n",
                       ".github/obaaf.yml": "agents:\n  commands: []\n"})
            # The firewall policy's place counts whether or not there is a policy.
            self.assertEqual(unowned(tmp, "gate-no-owner"), [".github/egress-firewall.yaml", ".github/obaaf.yml"])

    def test_the_baseline_and_the_firewall_policy_count(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE.replace("/.github/egress-firewall.yaml @octocat\n", "")
                       + "/.github/workflows/ @octocat\n",
                       "ci/baseline.json": json.dumps({"format": baseline.FORMAT, "findings": []}),
                       ".github/egress-firewall.yaml": "mode: enforce\n"})
            code, out, err = run_cli("check", str(tmp), "--baseline", str(tmp / "ci" / "baseline.json"),
                                     "--format", "json", "--fail-on", "never")
            self.assertEqual(code, 0, err)
            files = [x for f in json.loads(out)["findings"] if f.get("kind") == "gate-no-owner"
                     for x in f["facts"]["files"]]
            self.assertEqual(sorted(files), [".github/egress-firewall.yaml", "ci/baseline.json"])

    def test_an_ignore_entry_cannot_accept_it(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": "/.github/workflows/ @octocat\n/.github/CODEOWNERS @octocat\n",
                       ".github/obaaf.yml": "ignore:\n  - rule: OBAAF-REPO-001\n    path: .github/CODEOWNERS\n    owner: '@octocat'\n"
                                           "    reason: The owner reviews this file by hand\n    until: 2026-12-31\n"})
            from datetime import date
            findings, _ = found(tmp, "OBAAF-REPO-001", today=date(2026, 11, 15))
            gate = [f for f in findings if f.kind == "gate-no-owner"]
            self.assertEqual(len(gate), 1)
            self.assertIsNone(gate[0].suppressed)
            self.assertFalse(gate[0].acceptance.valid)
            self.assertTrue(any("vouching for itself" in p for p in gate[0].acceptance.problems))


class CiDefinitionTest(unittest.TestCase):
    """A075, A076 (local actions), A078 (lockfile), A079, A080 (a new workflow), A081-A083 (links)."""

    def test_local_actions_a_workflow_uses_need_an_owner(self):
        wf = WORKFLOW.replace("- run: true", "- uses: ./.github/actions/build\n      - uses: ./")
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/ @octocat\n",
                       ".github/actions/build/action.yml": "runs: {using: composite, steps: []}\n",
                       "action.yml": "runs: {using: composite, steps: []}\n"})
            (tmp / ".github" / "workflows" / "ci.yml").write_text(wf, encoding="utf-8")
            self.assertEqual(unowned(tmp), [".github/actions/build/action.yml", "action.yml"])

    def test_owning_each_workflow_by_name_leaves_a_new_one_unowned(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/ci.yml @octocat\n"})
            self.assertEqual(unowned(tmp), [".github/workflows/(a new workflow).yaml",
                                            ".github/workflows/(a new workflow).yml"])
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/ @octocat\n"})
            self.assertEqual(unowned(tmp), [])

    def test_the_workflow_lockfile_needs_an_owner(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/*.yml @octocat\n/.github/workflows/*.yaml @octocat\n",
                       ".github/workflows/actions.lock": "{}\n"})
            self.assertEqual(unowned(tmp), [".github/workflows/actions.lock"])

    def test_a_linked_workflow_needs_an_owner_by_its_own_path(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/ @octocat\n/ci/ @octocat\n"
                                                    "/.github/workflows/ci.yml\n", "ci/real.yml": WORKFLOW})
            (tmp / ".github" / "workflows" / "ci.yml").unlink()
            (tmp / ".github" / "workflows" / "ci.yml").symlink_to(tmp / "ci" / "real.yml")
            # A rule with no owner that can match a name in the folder leaves a new workflow unowned too.
            self.assertEqual(unowned(tmp), [".github/workflows/(a new workflow).yml", ".github/workflows/ci.yml"])
            # The file it leads to needs an owner too.
            (tmp / ".github" / "CODEOWNERS").write_text(GATE + "/.github/workflows/ @octocat\n", encoding="utf-8")
            self.assertEqual(unowned(tmp), ["ci/real.yml"])


class DiscoveryTest(unittest.TestCase):
    """B001-B025, B037-B056: names, folders, letter case and links."""

    def instruction_files(self, files, links=()):
        from obaaf.catalog import load
        with TempDir() as tmp:
            tree(tmp, files)
            for link, target in links:
                (tmp / link).parent.mkdir(parents=True, exist_ok=True)
                (tmp / link).symlink_to(target if str(target).startswith("/") else tmp / target)
            return repo.find_instruction_entries(tmp, load().detection["instruction_files"])

    def test_names_from_the_tools_documentation(self):
        for rel in ("AGENTS.override.md", "svc/api/AGENTS.override.md", "REVIEW.md", "pkg/CLAUDE.local.md",
                    ".github/skills/release/SKILL.md", ".agents/skills/x/SKILL.md", ".github/hooks/policy.json",
                    ".cursor/mcp.json", "pkg/web/.cursor/rules/a.mdc", "pkg/.windsurf/rules/a.md",
                    ".cline/rules/a.md", ".junie/guidelines.md", ".amazonq/rules/a.md", ".kiro/steering/a.md",
                    ".kiro/settings/mcp.json", ".rules", ".augment/rules/a.md", ".augment-guidelines",
                    "pkg/.claude/skills/lint/SKILL.md", "svc/.aider.conf.yml"):
            with self.subTest(rel=rel):
                self.assertIn(rel, [e.rel for e in self.instruction_files({rel: "x\n"})])

    def test_no_folder_is_skipped_but_git_history(self):
        for rel in ("build/AGENTS.md", "dist/CLAUDE.md", "node_modules/t/AGENTS.md", ".venv/CLAUDE.md",
                    ".claude/skills/build/SKILL.md", ".cursor/rules/dist/a.mdc", "Binaries/CLAUDE.md"):
            with self.subTest(rel=rel):
                self.assertIn(rel, [e.rel for e in self.instruction_files({rel: "x\n"})])
        self.assertEqual(self.instruction_files({".git/AGENTS.md": "x\n"}), [])

    def test_names_are_matched_without_regard_to_case(self):
        for rel in ("agents.md", "Agents.md", "CLAUDE.MD", "src/claude.md"):
            with self.subTest(rel=rel):
                self.assertIn(rel, [e.rel for e in self.instruction_files({rel: "x\n"})])

    def test_links_inside_the_repository_are_followed_and_both_paths_need_an_owner(self):
        entries = self.instruction_files({"notes/style.txt": "x\n", "shared/rules/a.md": "y\n"},
                                         links=[("CLAUDE.md", "notes/style.txt"), (".claude/rules", "shared/rules")])
        by_rel = {e.rel: e for e in entries}
        self.assertEqual(by_rel["CLAUDE.md"].real, "notes/style.txt")
        self.assertEqual(by_rel[".claude/rules/a.md"].real, "shared/rules/a.md")
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/ @octocat\n/CLAUDE.md @octocat\n",
                       "notes/style.txt": "Hidden\u200b\n"})
            (tmp / "CLAUDE.md").symlink_to(tmp / "notes" / "style.txt")
            findings, _ = found(tmp, "OBAAF-REPO-002", "OBAAF-INS-001")
            self.assertEqual(sorted(f.rule for f in findings), ["OBAAF-INS-001", "OBAAF-REPO-002"])
            self.assertEqual(next(f for f in findings if f.rule == "OBAAF-REPO-002").facts["files"], ["notes/style.txt"])

    def test_a_link_out_of_the_repository_is_named(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/ @octocat\n"})
            (tmp / "CLAUDE.md").symlink_to("/etc/hostname")
            (tmp / ".claude").symlink_to("/nonexistent-folder")
            findings, result = found(tmp, "OBAAF-REPO-002")
            self.assertTrue(any("lead out of the repository" in n for n in result.notes), result.notes)
            self.assertIn("CLAUDE.md", findings[0].facts["files"])

    def test_a_link_cycle_ends(self):
        entries = self.instruction_files({".claude/a.md": "x\n"}, links=[(".claude/loop", ".claude")])
        self.assertIn(".claude/a.md", [e.rel for e in entries])
        self.assertLess(len(entries), 50)


class HiddenCharacterTest(unittest.TestCase):
    """B058-B072 (by property), B077 (keycap channel), B083, B085, B093, B126 (decoding), B095, B096
    (time), B103 (a direction control's paragraph), B108-B112 (ordinary text)."""

    def test_every_format_and_control_character_and_the_invisible_letters(self):
        for cp in (0x206A, 0x206F, 0xFFF9, 0xFFFB, 0x1D173, 0x13430, 0x1BCA0, 0x180B, 0x115F, 0x1160, 0x3164,
                   0xFFA0, 0x2800, 0x17B4, 0x17B5, 0x2065, 0xFFF0, 0xE00E3, 0xE01F5, 0x1B, 0x80, 0x0, 0x0C, 0x2028):
            with self.subTest(cp=hex(cp)):
                self.assertEqual(len(repo.scan_hidden(f"ab{chr(cp)}cd")), 1)

    def test_a_selector_after_a_digit_counts_unless_it_makes_a_keycap(self):
        self.assertEqual(len(repo.scan_hidden("1\ufe0f 2\ufe0e")), 2)
        self.assertEqual(repo.scan_hidden("#\ufe0f\u20e3 1\ufe0f\u20e3"), [])

    def test_ordinary_text_in_other_scripts_and_emoji_passes(self):
        for text in ("\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", "\u0d36\u0d4d\u200d\u0d30",
                     "\u0915\u094d\u200d\u0937", "\U0001F3F4\U000E0067\U000E0062\U000E0065"
                     "\U000E006E\U000E0067\U000E007F", "\u25b6\ufe0f \u3030\ufe0f \u303d\ufe0f \u24c2\ufe0f",
                     "Release notes \U0001F3AE \U0001F469\u200d\U0001F4BB \u2764\ufe0f #\ufe0f\u20e3"):
            with self.subTest(text=text):
                self.assertEqual(repo.scan_hidden(text), [])

    def test_joiners_between_marks_or_before_a_space_count(self):
        # The second review: 60 marks with a joiner, a non-joiner or nothing between them carry 1.58 bits
        # each; a joiner after a virama counts unless a letter follows (Malayalam's old chillu spelling
        # is reported: Unicode 5.1 has the chillu letters).
        self.assertEqual(len(repo.scan_hidden("\u0915" + "\u0902\u200d\u0902\u200c" * 10)), 20)
        self.assertEqual(len(repo.scan_hidden("\u0628\u064e\u200d\u064e")), 1)
        self.assertEqual(len(repo.scan_hidden("\u0d28\u0d4d\u200d ")), 1)

    def test_tags_outside_the_three_flags_still_count(self):
        self.assertEqual(len(repo.scan_hidden("\U0001F3F4\U000E0061\U000E0062\U000E007F")), 3)
        self.assertEqual(len(repo.scan_hidden("x\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F")), 6)

    def test_a_file_that_is_not_utf8_is_a_finding(self):
        for data in ("Hidden\u200b\n".encode("utf-16"), b"\xff\xfeH\x00", "x".encode("utf-32"), b"ok\xc0\xafno\n"):
            with self.subTest(data=data[:6]), TempDir() as tmp:
                tree(tmp, {"AGENTS.md": data})
                findings, _ = found(tmp, "OBAAF-INS-001")
                self.assertEqual([f.kind for f in findings], ["not-utf8"])

    def test_pictures_in_an_instruction_folder_are_not_scanned(self):
        with TempDir() as tmp:
            tree(tmp, {".claude/skills/x/logo.png": b"\x89PNG\r\n\x1a\n\x00\xff"})
            self.assertEqual(found(tmp, "OBAAF-INS-001")[0], [])

    def test_many_hidden_characters_take_little_time(self):
        with TempDir() as tmp:
            tree(tmp, {"AGENTS.md": "a" + "\u200b" * 80000 + "\n" + ("\u200b" * 2000 + "\n") * 200})
            start = time.monotonic()
            findings, _ = found(tmp, "OBAAF-INS-001")
            self.assertLess(time.monotonic() - start, 10)
            self.assertIn("480000 hidden", findings[0].message)

    def test_a_direction_control_is_digested_with_its_paragraph(self):
        def key(text):
            with TempDir() as tmp:
                tree(tmp, {"AGENTS.md": text})
                findings, _ = found(tmp, "OBAAF-INS-001")
                return findings[0].facts["characters"]
        one = key("Intro.\n\u202e\nNever push to main.\n")
        self.assertNotEqual(one, key("Intro.\n\u202e\nAlways push to main.\n"))
        self.assertEqual(one, key("Intro.\n\u202e\nNever push to main.\n\nAnything else.\n"))
        zero_width = key("Read this.\u200b\nNext.\n")
        self.assertEqual(zero_width, key("Read this.\u200b\nOther.\n"))

    def test_a_file_too_large_to_scan_is_a_finding(self):
        with TempDir() as tmp:
            tree(tmp, {"AGENTS.md": "x" * (2_000_001)})
            findings, _ = found(tmp, "OBAAF-INS-001")
            self.assertEqual([f.kind for f in findings], ["too-large"])



class ReviewFixesTest(unittest.TestCase):
    """What the slice's review found past the first fixes (docs/bypass-attempts.md, 2d.2h, "Review")."""

    def test_links_to_one_folder_do_not_multiply_and_the_file_is_still_found(self):
        with TempDir() as tmp:
            tree(tmp, {".claude/CLAUDE.md": "Hidden\U000E0041\n", "z/0/f.txt": "x\n"})
            for level in range(18):                    # each level links twice to the one below it
                for side in ("a", "b"):
                    (tmp / "z" / str(level + 1)).mkdir(parents=True, exist_ok=True)
                    (tmp / "z" / str(level + 1) / side).symlink_to(tmp / "z" / str(level))
            start = time.monotonic()
            findings, result = found(tmp, "OBAAF-INS-001")
            self.assertLess(time.monotonic() - start, 30)
            self.assertTrue(findings or result.errors, "neither a finding nor an error")
            self.assertTrue(any(f.path == ".claude/CLAUDE.md" for f in findings), (findings, result.errors))

    def test_only_tracked_files_count_in_a_git_work_tree(self):
        import shutil
        import subprocess
        if shutil.which("git") is None:
            self.skipTest("needs git")
        with TempDir() as tmp:
            tree(tmp, {"AGENTS.md": "x\n", "node_modules/pkg/AGENTS.md": "y\n"})
            env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True, env=env)
            subprocess.run(["git", "add", "AGENTS.md", ".github"], cwd=tmp, check=True, env=env)
            from obaaf.catalog import load
            self.assertEqual(repo.find_instruction_files(tmp, load().detection["instruction_files"]), ["AGENTS.md"])

    def test_a_selector_after_any_symbol_and_a_joiner_between_any_letters_count(self):
        self.assertEqual(len(repo.scan_hidden("|\ufe0f|\ufe0e=\ufe0f")), 3)
        self.assertEqual(len(repo.scan_hidden("\u4e2d\u200d\u6587\u200c\u5b57")), 2)
        self.assertEqual(len(repo.scan_hidden("\U0001D400\u200d\U0001D401")), 1)

    def test_paragraph_digests_take_little_time(self):
        text = "".join(f"line {i} \u202e\n" for i in range(40000))
        start = time.monotonic()
        from obaaf.checker.rules import _line_digests
        _line_digests(text, repo.scan_hidden(text))
        self.assertLess(time.monotonic() - start, 5)

    def test_a_large_file_is_digested_whole(self):
        def facts(extra):
            with TempDir() as tmp:
                tree(tmp, {"AGENTS.md": "x" * 2_000_001 + extra})
                return found(tmp, "OBAAF-INS-001")[0][0].facts
        self.assertNotEqual(facts(""), facts("\U000E0041"))

    def test_a_codeowners_place_before_the_one_in_use_needs_an_owner(self):
        with TempDir() as tmp:
            tree(tmp, {"docs/CODEOWNERS": GATE.replace("/.github/CODEOWNERS", "/docs/CODEOWNERS")
                       + "/.github/ @octocat\n"})
            self.assertEqual(unowned(tmp, "gate-no-owner"), ["CODEOWNERS"])

    def test_a_configuration_that_is_a_link_needs_its_target_owned(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": "/.github/ @octocat\n/obaaf.yml @octocat\n", "tools/obaaf.yml": "{}\n"})
            (tmp / ".github" / "obaaf.yml").symlink_to(tmp / "tools" / "obaaf.yml")
            self.assertEqual(unowned(tmp, "gate-no-owner"), ["tools/obaaf.yml"])

    def test_a_baseline_given_through_a_linked_folder_still_counts(self):
        with TempDir() as tmp:
            tree(tmp / "repo", {".github/CODEOWNERS": GATE + "/.github/workflows/ @octocat\n",
                                "bl.json": json.dumps({"format": baseline.FORMAT, "findings": []})})
            (tmp / "link").symlink_to(tmp / "repo")
            code, out, err = run_cli("check", str(tmp / "link"), "--baseline", str(tmp / "link" / "bl.json"),
                                     "--format", "json", "--fail-on", "never")
            files = [x for f in json.loads(out)["findings"] if f.get("kind") == "gate-no-owner" for x in f["facts"]["files"]]
            self.assertEqual(files, ["bl.json"])

    def test_local_actions_written_with_dot_dot_or_behind_a_link(self):
        wf = WORKFLOW.replace("- run: true", "- uses: ./.github/../tools/evil\n      - uses: ./act")
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/ @octocat\n/act/ @octocat\n",
                       "tools/evil/action.yml": "runs: {using: composite, steps: []}\n",
                       "tools/real.yml": "runs: {using: composite, steps: []}\n"})
            (tmp / "act").mkdir()
            (tmp / "act" / "action.yml").symlink_to(tmp / "tools" / "real.yml")
            (tmp / ".github" / "workflows" / "ci.yml").write_text(wf, encoding="utf-8")
            self.assertEqual(unowned(tmp), ["tools/evil/action.yml", "tools/real.yml"])

    def test_with_no_codeowners_no_acceptance_counts(self):
        from datetime import date
        with TempDir() as tmp:
            tree(tmp, {"obaaf.yml": "ignore:\n  - rule: OBAAF-REPO-001\n    path: .github/CODEOWNERS\n    owner: '@octocat'\n"
                                    "    reason: Nobody reviews anything here\n    until: 2026-12-31\n"})
            findings, _ = found(tmp, "OBAAF-REPO-001", today=date(2026, 11, 15))
            self.assertEqual([(f.kind, f.suppressed) for f in findings], [("no-codeowners", None)])

    def test_an_owner_with_a_space_or_control_character_gives_no_owner(self):
        for owner in ("@octocat\u00a0", "\u00a0@octocat", "@octocat\u2028", "@octocat\x0b", "@octocat\x1c", "@octocat\x85"):
            with self.subTest(owner=repr(owner)):
                self.assertIsNotNone(repo.parse_codeowners(f"/a/ {owner}\n")[0].problem)

    def test_office_files_and_compiled_files_in_a_skill_are_not_scanned(self):
        with TempDir() as tmp:
            tree(tmp, {".claude/skills/r/" + name: b"PK\x03\x04\x00\xff" for name in
                       ("a.docx", "b.xlsx", "c.pptx", "d.wasm", "e.pyc", ".DS_Store")})
            self.assertEqual(found(tmp, "OBAAF-INS-001")[0], [])

    def test_cheap_looks_at_a_rule_do_not_use_up_the_comparison_budget(self):
        rules = [repo.OwnerRule("*", ["@o"], 0)] + [repo.OwnerRule(f"/packages/p{i}/", ["@o"], i) for i in range(3000)]
        index = repo.OwnerIndex(rules)
        for i in range(700):
            self.assertEqual(index.owners(f".claude/skills/s/f{i}.md"), ["@o"])

    def test_a_new_workflow_is_decided_from_the_rules(self):
        cases = [("/.github/workflows/ @a\n", True), ("/.github/ @a\n", True), ("*.yml @a\n*.yaml @a\n", True),
                 ("/.github/workflows/?* @a\n", True), ("/.github/workflows/ci.yml @a\n", False),
                 ("/.github/workflows/*.yml @o\n/.github/workflows/*.*.yml\n/.github/workflows/R*\n", False),
                 ("/.github/workflows/ @a\n/.github/workflows/d* octocat\n", False),
                 ("/.github/ @a\n/apps/github\n", True), ("/.github/workflows/\ue000* @a\n", False)]
        for text, owned in cases:
            with self.subTest(text=text):
                index = repo.OwnerIndex(repo.parse_codeowners(text))
                self.assertEqual(index.new_file_owned(".github/workflows", ".yml")[0], owned)
                self.assertEqual(index.new_file_owned(".github/workflows", ".yml"),
                                 index.new_file_owned(".github/workflows", ".yml"))

    def test_links_to_a_folder_above_them_are_not_followed_and_deep_chains_are_an_error(self):
        from obaaf.catalog import load
        patterns = load().detection["instruction_files"]
        with TempDir() as tmp:
            tree(tmp, {f"f{i}.txt": "x\n" for i in range(300)} | {"AGENTS.md": "x\n"})
            (tmp / "docs").mkdir()
            (tmp / "docs" / "up").symlink_to(tmp)
            (tmp / "docs" / "examples").mkdir()
            (tmp / "docs" / "examples" / "project").symlink_to(tmp)
            errors = []
            self.assertEqual(repo.find_instruction_files(tmp, patterns, errors=errors), ["AGENTS.md"])
            self.assertEqual(errors, [])
            code, out, err = run_cli("check", str(tmp), "--fail-on", "never")
            self.assertNotIn("Traceback", err)
        with TempDir() as tmp:
            tree(tmp, {"d9/evil.instructions.md": "x\U000E0041\n"})
            (tmp / ".github" / "instructions").mkdir(parents=True)
            (tmp / ".github" / "instructions" / "a").symlink_to(tmp / "d1")
            for level in range(1, 9):
                (tmp / f"d{level}").mkdir()
                (tmp / f"d{level}" / "a").symlink_to(tmp / f"d{level + 1}")
            errors = []
            repo.find_instruction_entries(tmp, patterns, errors=errors)
            self.assertTrue(any("links lead one through another" in e for e in errors), errors)

    def test_a_text_file_with_a_binary_name_is_scanned(self):
        with TempDir() as tmp:
            tree(tmp, {".claude/skills/x/reference.bin": "Hidden\U000E0041\n", ".claude/.DS_Store": "x\u202ey\n"})
            self.assertEqual(sorted(f.path for f in found(tmp, "OBAAF-INS-001")[0]),
                             [".claude/.DS_Store", ".claude/skills/x/reference.bin"])

    def test_a_local_action_path_too_long_for_the_file_system_is_no_traceback(self):
        wf = WORKFLOW.replace("- run: true", "- uses: ./" + "a" * 300)
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/ @octocat\n"})
            (tmp / ".github" / "workflows" / "ci.yml").write_text(wf, encoding="utf-8")
            found(tmp)

    def test_probes_cannot_be_owned_by_a_pattern_for_their_label(self):
        with TempDir() as tmp:
            tree(tmp, {".github/CODEOWNERS": GATE + "/.github/workflows/ci.yml @octocat\n/.github/workflows/(a* @octocat\n"})
            self.assertEqual(unowned(tmp), [".github/workflows/(a new workflow).yaml", ".github/workflows/(a new workflow).yml"])

    def test_a_workflow_reached_by_a_link_and_reported_by_a_relative_path(self):
        """A082 and A083: a link's target outside the repository is never named by an absolute path."""
        with TempDir() as tmp:
            outside = tmp / "elsewhere.yml"
            outside.write_text(WORKFLOW, encoding="utf-8")
            tree(tmp / "repo", {".github/CODEOWNERS": GATE + "/.github/workflows/ @octocat\n"})
            (tmp / "repo" / ".github" / "workflows" / "ci.yml").unlink()
            (tmp / "repo" / ".github" / "workflows" / "ci.yml").symlink_to(outside)
            findings, _ = found(tmp / "repo", "OBAAF-REPO-001")
            for f in findings:
                for path in f.facts.get("files", []):
                    self.assertFalse(path.startswith("/"), path)


if __name__ == "__main__":
    unittest.main()
