"""FR9: protect agent instructions.

Acceptance criterion: agents read instruction and workflow files only from the
protected base branch, so a pull request cannot change what the agent obeys
during its own run.
"""

import unittest

from helpers import RISKY, TEMPLATES, TempDir, install_templates, template_workflow, unexpected_findings

from obaaf import checker
from obaaf.checker import repo
from obaaf.checker.workflow import PR_HEAD_REF_RE


class TemplateTest(unittest.TestCase):
    def test_agent_lane_has_no_pull_request_trigger_and_checks_out_the_default_branch(self):
        wf = template_workflow("obaaf-agent-propose.yml")
        self.assertNotIn("pull_request", wf.triggers)
        self.assertNotIn("pull_request_target", wf.triggers)
        for job in wf.jobs.values():
            for step in job.steps:
                if step.uses_action("actions/checkout"):
                    ref = str(step.with_.get("ref", ""))
                    self.assertFalse(PR_HEAD_REF_RE.search(ref), f"{job.id}: {ref}")

    def test_pull_request_changes_reach_the_agent_only_as_labeled_data(self):
        wf = template_workflow("obaaf-agent-propose.yml")
        snap = wf.jobs["snapshot"]
        text = "\n".join(s.run for s in snap.steps)
        self.assertIn("gh pr diff", text)
        self.assertIn("pull_request.diff:Public", text)
        self.assertIn("instructions@default-branch:Maintainer", text)


class CheckerTest(unittest.TestCase):
    def test_agent_on_pull_request_with_default_checkout_is_reported(self):
        rules = {f.rule for f in checker.check(RISKY / "claude-action-toctou.yml").findings}
        self.assertIn("OBAAF-GHA-012", rules)

    def test_instruction_files_without_owners_are_reported(self):
        with TempDir() as tmp:
            install_templates(tmp)
            (tmp / "AGENTS.md").write_text("Be helpful.\n", encoding="utf-8")
            (tmp / ".cursor" / "rules").mkdir(parents=True)
            (tmp / ".cursor" / "rules" / "style.mdc").write_text("Use tabs.\n", encoding="utf-8")
            self.assertEqual(unexpected_findings(checker.check(tmp).findings), [])  # CODEOWNERS.example covers both
            (tmp / ".github" / "CODEOWNERS").write_text("/src/ @studio/dev\n", encoding="utf-8")
            rules = {f.rule for f in checker.check(tmp).findings}
            self.assertTrue({"OBAAF-REPO-001", "OBAAF-REPO-002"} <= rules)
            (tmp / ".github" / "CODEOWNERS").unlink()
            rules = {f.rule for f in checker.check(tmp).findings}
            self.assertTrue({"OBAAF-REPO-001", "OBAAF-REPO-002"} <= rules)

    def test_hidden_characters_in_instruction_files_are_reported(self):
        with TempDir() as tmp:
            install_templates(tmp)
            hidden = "Follow the style guide.​‮esrever‬ and tag\U000E0041\U000E0042 text\n"
            (tmp / "AGENTS.md").write_text(hidden, encoding="utf-8")
            findings = [f for f in checker.check(tmp).findings if f.rule == "OBAAF-INS-001"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")
            self.assertIn("5 hidden character(s)", findings[0].message)
            self.assertIn("U+202E RIGHT-TO-LEFT OVERRIDE", findings[0].message)


class HiddenCharacterScanTest(unittest.TestCase):
    def test_detects_each_class(self):
        kinds = {h.kind for h in repo.scan_hidden("a​b‮c\U000E0020d\U000E0101e")}
        self.assertEqual(kinds, {"zero-width or invisible", "bidirectional control", "tag character",
                                 "variation selector"})

    def test_ordinary_text_and_emoji_pass(self):
        text = "﻿Release notes 🎮 👩‍💻 ❤️ #️⃣ café naïve 日本語\n"
        self.assertEqual(repo.scan_hidden(text), [])


class CodeownersMatchingTest(unittest.TestCase):
    def rules(self, text):
        out = []
        for n, line in enumerate(text.strip().splitlines(), start=1):
            parts = line.split()
            out.append(repo.OwnerRule(parts[0], parts[1:], n))
        return out

    def test_github_documented_semantics(self):
        rules = self.rules("""
*.js @js
/build/logs/ @logs
docs/* @docs
apps/ @apps
/scripts/ @scripts
/apps/github
""")
        self.assertEqual(repo.owners_for(rules, "src/a/b.js"), ["@js"])
        self.assertEqual(repo.owners_for(rules, "build/logs/x/y.txt"), ["@logs"])
        self.assertEqual(repo.owners_for(rules, "docs/getting-started.md"), ["@docs"])
        self.assertIsNone(repo.owners_for(rules, "docs/build-app/troubleshooting.md"))
        self.assertEqual(repo.owners_for(rules, "lib/apps/x.txt"), ["@apps"])
        self.assertEqual(repo.owners_for(rules, "apps/github/x.txt"), [])  # no owners: last match wins
        self.assertEqual(repo.owners_for(rules, "scripts/build.sh"), ["@scripts"])

    def test_example_codeowners_covers_templates_and_instruction_files(self):
        rules = self.rules("\n".join(line for line in (TEMPLATES / "CODEOWNERS.example").read_text().splitlines()
                                     if line.strip() and not line.startswith("#")))
        for path in (".github/workflows/obaaf-release.yml", "AGENTS.md", "tools/AGENTS.md", ".claude/settings.json",
                     ".github/obaaf-policy.yaml", ".mcp.json", "Plugins/Foo/Foo.uplugin", ".obaaf/records/x.json"):
            with self.subTest(path=path):
                self.assertTrue(repo.owners_for(rules, path))

    def test_example_codeowners_covers_every_instruction_file_pattern(self):
        from obaaf.catalog import load

        rules = self.rules("\n".join(line for line in (TEMPLATES / "CODEOWNERS.example").read_text().splitlines()
                                     if line.strip() and not line.startswith("#")))
        for pattern in load().detection["instruction_files"]:
            # A concrete path for each pattern, at the root and in a subdirectory where it allows one.
            sample = pattern.replace("**/", "sub/dir/").replace("/**", "/nested/file.md")
            with self.subTest(pattern=pattern, path=sample):
                self.assertTrue(repo.owners_for(rules, sample), f"{sample} has no code owner")


if __name__ == "__main__":
    unittest.main()
