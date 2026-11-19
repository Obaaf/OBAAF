"""Flagship slice 2d.5c2b: the other agent tools' settings and options their own documentation warns about.

Slices 2d.5c1 and 2d.5c2a read the settings and options of Claude Code, Codex and Gemini CLI. This slice
read the other twenty entries' action files, READMEs, documentation and CLI help text at named commits
(decision F-279): where a sentence warns about a value it is data under `settings` or `flags`, with the
words and the file, commit and lines; where nothing warns, the entry says in `no_warnings` what was read.
The workflows here are written for these tests from that documentation; none is copied from another
project.
"""

import datetime
import unittest

from helpers import TempDir

from obaaf import agent_tools, checker
from obaaf.catalog import load
from obaaf.checker import agent_flags

CODEOWNERS = "* @example/maintainers\n"
RULE = "OBAAF-GHA-026"
GEMINI = "google-github-actions/run-gemini-cli@387c8ddb7a72078825da941758b811b9153c71e8"
QWEN = "QwenLM/qwen-code-action@05f81718976f3b7da657422e6e8e4d372b8621d7"
PR_REVIEW = "OpenHands/extensions/plugins/pr-review@1902359eb285eb09bfb488e392831b86883dda3d"

# Every entry, and what this slice found in its own files (S: a setting, F: an option, N: nothing).
FOUND = {
    "claude-code": "SF", "gemini-cli": "SF", "codex": "SF", "github-models": "N", "pr-agent": "N",
    "coderabbit": "N", "openhands": "SF", "opencode": "N", "cline": "F", "aider": "N", "copilot-cli": "F",
    "qodo": "N", "claude-code-security-review": "N", "auggie": "N", "continue": "N", "jules": "N",
    "goose": "F", "kilo": "F", "kiro": "N", "qwen-code": "SF", "swe-agent": "N", "warp": "N", "amp": "N",
}


def raw_detection():
    from obaaf.catalog import _read
    return _read("detection")


def check(workflow_text):
    with TempDir() as tmp:
        root = tmp / "repo"
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "wf.yml").write_text(workflow_text, encoding="utf-8")
        (root / ".github" / "CODEOWNERS").write_text(CODEOWNERS, encoding="utf-8")
        return checker.check(root)


def run_step(script):
    body = "\n".join("          " + line for line in script.split("\n"))
    return ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - name: agent\n        run: |\n{body}\n")


def one_step(uses, inputs):
    return ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - name: agent\n        uses: {uses}\n        with:\n          prompt: review this\n{inputs}")


def found(result, kind=None):
    return [f for f in result.findings if f.rule == RULE and (kind is None or f.kind == kind)]


class TheDataTest(unittest.TestCase):
    """Each entry has settings, options or says what was read; each fact cites a file at a commit."""

    def test_every_entry_has_settings_flags_or_says_it_found_none(self):
        entries = {e["id"]: e for e in raw_detection()["agent_tools"]}
        self.assertEqual(sorted(entries), sorted(FOUND))
        self.assertEqual(agent_tools.problems(raw_detection()), [])
        for tool, what in FOUND.items():
            entry = entries[tool]
            with self.subTest(tool=tool):
                self.assertEqual(bool(entry.get("settings")), "S" in what)
                self.assertEqual(bool(entry.get("flags")), "F" in what)
                self.assertEqual(bool(entry.get("no_warnings")), what == "N")
                for fact in [*(entry.get("settings") or []), *(entry.get("flags") or [])]:
                    self.assertRegex(fact["source"], r"^https://github\.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/.+#L\d+")
                    self.assertIsInstance(fact["read"], datetime.date)
                    # The file a fact was read from is one of the entry's sources.
                    self.assertIn(fact["source"].split("#")[0], entry["sources"])

    def test_no_warnings_and_prefixes_are_checked(self):
        base = {"id": "t", "name": "T", "read": datetime.date(2026, 11, 19), "sources": [], "actions": {},
                "commands": ["x"], "packages": {}, "install_urls": [], "settings": [], "programs": ["t"]}
        flag = {"id": "f", "options": ["--x-y"], "severity": "high", "read": datetime.date(2026, 11, 19),
                "says": "words", "source": "https://github.com/o/r/blob/" + "a" * 40 + "/f.md#L1"}

        def problems(**entry):
            return agent_tools.problems({"agent_tools": [dict(base, **entry)]})

        self.assertEqual(problems(no_warnings="Read README.md at abc1234; nothing warns."), [])
        self.assertEqual(problems(flags=[flag]), [])
        self.assertEqual(problems(flags=[dict(flag, prefixes=True)]), [])
        for entry, why in [
            ({}, "must say in no_warnings"),
            ({"no_warnings": ""}, "no_warnings must say"),
            ({"no_warnings": "   "}, "no_warnings must say"),
            ({"no_warnings": ["read"]}, "no_warnings must say"),
            ({"flags": [dict(flag, prefixes="yes")]}, "prefixes must be true"),
            ({"flags": [dict(flag, prefixes=False)]}, "prefixes must be true"),
            ({"flags": [dict(flag, options=["-x"], prefixes=True)]}, "prefixes needs a long option"),
        ]:
            with self.subTest(why=why, entry=entry):
                found_problems = problems(**entry)
                self.assertTrue(any(why in p for p in found_problems), found_problems)

    def test_a_prefixes_flag_takes_every_beginning_of_its_long_options(self):
        flag = {"id": "f", "options": ["--always-approve", "--yolo", "-y"], "prefixes": True}
        options, letters = agent_flags._table([flag])
        for word in ("--always-approve", "--always", "--alw", "--al", "--a", "--yolo", "--yol", "--yo", "--y"):
            self.assertIn(word, options, word)
        self.assertNotIn("--", options)
        self.assertNotIn("--always-approvex", options)
        self.assertEqual(letters, {"y": [flag]})
        plain = {"id": "g", "options": ["--auto"]}
        self.assertEqual(sorted(agent_flags._table([plain])[0]), ["--auto"])


class SettingsTest(unittest.TestCase):
    """The actions' inputs the tools' own files warn about."""

    CASES = [
        (GEMINI, "          gemini_debug: true\n", "gemini-cli/debug", "medium"),
        (GEMINI, "          gemini_debug: 'TRUE'\n", "gemini-cli/debug", "medium"),
        (QWEN, "          qwen_debug: true\n", "qwen-code/debug", "medium"),
        (PR_REVIEW, "          enable-uv-cache: true\n", "openhands/uv-cache", "medium"),
        (PR_REVIEW, "          enable-uv-cache: auto\n", "openhands/uv-cache", "medium"),
        (PR_REVIEW, "          ENABLE-UV-CACHE: ' Auto '\n", "openhands/uv-cache", "medium"),
    ]

    def test_each_documented_setting_is_reported_with_its_words(self):
        known = {f"{t}/{s['id']}": s for t, _n, s in agent_tools.settings(load().detection)}
        for uses, inputs, setting, severity in self.CASES:
            with self.subTest(uses=uses, inputs=inputs):
                hits = found(check(one_step(uses, inputs)))
                self.assertEqual([(h.facts["setting"], h.severity) for h in hits], [(setting, severity)],
                                 [h.message for h in hits])
                self.assertIn(" ".join(known[setting]["says"].split()), hits[0].message)
                self.assertIn(known[setting]["source"], hits[0].message)

    def test_the_default_and_the_safe_values_are_not_reported(self):
        for uses, inputs in [
            (GEMINI, "          gemini_debug: false\n"),
            (GEMINI, "          gemini_model: gemini-2.5-pro\n"),
            (QWEN, "          qwen_debug: false\n"),
            (PR_REVIEW, "          enable-uv-cache: false\n"),
            (PR_REVIEW, "          llm-model: some-model\n"),
        ]:
            with self.subTest(uses=uses, inputs=inputs):
                self.assertEqual(found(check(one_step(uses, inputs))), [])

    def test_a_value_the_checker_cannot_read_is_cannot_tell(self):
        for uses, inputs, setting in [
            (GEMINI, "          gemini_debug: ${{ vars.DEBUG }}\n", "gemini-cli/debug"),
            (QWEN, "          qwen_debug: ${{ inputs.debug }}\n", "qwen-code/debug"),
            (PR_REVIEW, "          enable-uv-cache: ${{ vars.CACHE }}\n", "openhands/uv-cache"),
        ]:
            with self.subTest(uses=uses):
                hits = found(check(one_step(uses, inputs)))
                self.assertEqual([(h.kind, h.severity) for h in hits], [("computed", "medium")],
                                 [h.message for h in hits])


class CommandLineTest(unittest.TestCase):
    """The options the tools' own files warn about, wherever a step runs the program."""

    CASES = [
        ('qwen -p "fix it" --yolo', "qwen-code/yolo", "high"),
        ('qwen -p "fix it" -y', "qwen-code/yolo", "high"),
        ('qwen -yp "fix it"', "qwen-code/yolo", "high"),
        ('qwen -p "fix it" --y', "qwen-code/yolo", "high"),
        ('qwen --approval-mode yolo -p "fix it"', "qwen-code/approval-mode-yolo", "high"),
        ('qwen --approval-mode=YOLO -p "fix it"', "qwen-code/approval-mode-yolo", "high"),
        ('qwen --approvalMode yolo -p "fix it"', "qwen-code/approval-mode-yolo", "high"),
        ('npx @qwen-code/qwen-code -p "fix it" --yolo', "qwen-code/yolo", "high"),
        ('kilo run --auto "fix the tests"', "kilo/auto", "high"),
        ('kilo run --yolo "fix the tests"', "kilo/auto", "high"),
        ('kilo run --dangerously-skip-permissions "fix"', "kilo/auto", "high"),
        ('kilo run --dangerouslySkipPermissions "fix"', "kilo/auto", "high"),
        ('npx @kilocode/cli run --auto "fix"', "kilo/auto", "high"),
        ('cline --yolo "fix the tests"', "cline/yolo", "high"),
        ('cline -y "fix the tests"', "cline/yolo", "high"),
        ('copilot -p "fix the tests" --allow-all-tools', "copilot-cli/allow-all", "high"),
        ('copilot -p "fix the tests" --allow-all', "copilot-cli/allow-all", "high"),
        ('copilot --yolo -p "fix the tests"', "copilot-cli/allow-all", "high"),
        ("goose serve --dangerously-unauthenticated", "goose/unauthenticated", "medium"),
        ('openhands --headless --always-approve -t "fix"', "openhands/always-approve", "high"),
        ('openhands --headless --yolo -t "fix"', "openhands/always-approve", "high"),
        # Python's argparse takes any beginning of a long option that is not ambiguous.
        ('openhands --headless --always -t "fix"', "openhands/always-approve", "high"),
        ('openhands --headless --yol -t "fix"', "openhands/always-approve", "high"),
        ('openhands --headless --ALWAYS-APP -t "fix"', "openhands/always-approve", "high"),
    ]

    def test_each_documented_option_is_reported_once_with_its_words(self):
        flags = {f"{r[0]}/{f['id']}": f for r in agent_tools.flag_readers(load().detection) for f in r[2]}
        for script, setting, severity in self.CASES:
            with self.subTest(script=script):
                hits = found(check(run_step(script)))
                self.assertEqual([(h.kind, h.facts["setting"], h.severity) for h in hits],
                                 [("command-option", setting, severity)], [h.message for h in hits])
                self.assertIn(" ".join(flags[setting]["says"].split()), hits[0].message)
                self.assertIn(flags[setting]["source"], hits[0].message)

    def test_options_nobody_warns_about_are_not_reported(self):
        for script in [
            'qwen -p "fix it" --approval-mode auto',       # the CLI's default (config.ts, line 2009)
            'qwen -p "fix it" --approval-mode auto-edit',
            'qwen -p "fix it" --yolo=false',
            'opencode run --auto "fix"',                    # described, not warned about (F-267)
            'opencode run --dangerously-skip-permissions "fix"',
            'cn -p "fix" --auto',
            'aider --yes-always --message "fix"',
            'cline --auto-approve false "fix"',
            'copilot -p "fix" --allow-all-paths',
            'copilot -p "fix" --allow-all-urls',
            'openhands --headless --llm-approve -t "fix"',
            'openhands --headless -t "fix"',              # always approves; no option says so
            'openhands --headless --exit-without-confirmation -t "fix"',
            'kilo run --au "fix"',                          # yargs takes no beginnings of options
            'goose run --no-session -t "fix"',
            'sweagent run --agent.model.name=x',
            'auggie --print "fix"',
            'kiro-cli chat --no-interactive "fix"',
            'amp -x "fix"',
        ]:
            with self.subTest(script=script):
                self.assertEqual(found(check(run_step(script))), [])

    def test_what_the_checker_cannot_read_is_cannot_tell_for_the_new_tools(self):
        for script in ['qwen -p "fix" $FLAGS', 'kilo run $FLAGS "fix"', 'cline $FLAGS "fix"',
                       'copilot -p "fix" $FLAGS', 'openhands --headless "--al$X" -t "fix"',
                       'goose serve $FLAGS']:
            with self.subTest(script=script):
                hits = found(check(run_step(script)))
                self.assertTrue(hits, script)
                self.assertEqual({(h.kind, h.severity) for h in hits}, {("command-computed", "medium")},
                                 [h.message for h in hits])


if __name__ == "__main__":
    unittest.main()
