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
    "claude-code": "SF", "gemini-cli": "SF", "codex": "SF", "github-models": "N", "pr-agent": "F",
    "coderabbit": "N", "openhands": "SF", "opencode": "F", "cline": "F", "aider": "N", "copilot-cli": "F",
    "qodo": "N", "claude-code-security-review": "N", "auggie": "N", "continue": "F", "jules": "N",
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
        self.assertEqual(problems(flags=[flag], shared_program="Another tool is also `t`.", other_program=r"\s+up"), [])
        self.assertEqual(problems(flags=[dict(flag, unless=["false"])]), [])
        for entry, why in [
            ({"flags": [flag], "no_warnings": "nothing"}, "must not also say no_warnings"),
            ({"flags": [flag], "shared_program": ""}, "shared_program must name"),
            ({"flags": [flag], "shared_program": "x"}, "go together"),
            ({"flags": [flag], "other_program": "x"}, "go together"),
            ({"flags": [flag], "shared_program": "x", "other_program": "("}, "other_program must be a pattern"),
            ({"flags": [dict(flag, equals=["a"], unless=["b"])]}, "equals or unless, not both"),
            ({"flags": [dict(flag, unless=[])]}, "unless must be a list"),
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
        # Both actions read the input through `fromJSON`: a JSON string is what it decodes to (the review).
        (GEMINI, "          gemini_debug: '\"true\"'\n", "gemini-cli/debug", "medium"),
        (QWEN, "          qwen_debug: '\"tr\\u0075e\"'\n", "qwen-code/debug", "medium"),
        # The runner's reader (Newtonsoft) takes single quotes and reads only the first token (second review).
        (GEMINI, "          gemini_debug: \"'true'\"\n", "gemini-cli/debug", "medium"),
        (GEMINI, "          gemini_debug: 'true // off'\n", "gemini-cli/debug", "medium"),
        (QWEN, "          qwen_debug: 'true off'\n", "qwen-code/debug", "medium"),
        (QWEN, "          qwen_debug: '\"true\" x'\n", "qwen-code/debug", "medium"),
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
            (GEMINI, "          gemini_debug: '\"false\"'\n"),
            (PR_REVIEW, "          enable-uv-cache: '\"true\"'\n"),      # setup-uv compares the raw text
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
            (QWEN, "          qwen_debug: '/* off */ true'\n", "qwen-code/debug"),
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
        ('openhands --always-approve -t "fix"', "openhands/always-approve", "high"),
        ('openhands --yolo -t "fix"', "openhands/always-approve", "high"),
        # Python's argparse takes any beginning of a long option that is not ambiguous.
        ('openhands --always -t "fix"', "openhands/always-approve", "high"),
        ('openhands --yol -t "fix"', "openhands/always-approve", "high"),
        ('openhands --ALWAYS-APP -t "fix"', "openhands/always-approve", "high"),
        ('openhands --headless -t "fix"', "openhands/headless", "high"),
        ('openhands --head -t "fix"', "openhands/headless", "high"),
        ('uvx openhands@latest --headless -t "fix"', "openhands/headless", "high"),
        ('uv tool run --python 3.12 openhands==1.2.0 --head -t "fix"', "openhands/headless", "high"),
        ('qwen -dy=true -p hi', "qwen-code/yolo", "high"),       # yargs: `y` takes the value
        ('qwen --insecure -p "fix"', "qwen-code/insecure", "medium"),
        ('cline --zen "fix"', "cline/yolo", "high"),
        ('cline -z "fix"', "cline/yolo", "high"),
        ('cline --auto-approve true "fix"', "cline/auto-approve-true", "high"),
        ('cline --auto-approve=TRUE "fix"', "cline/auto-approve-true", "high"),
        ('copilot mcp add foo --show-secrets -- npx foo', "copilot-cli/show-secrets", "medium"),
        ('copilot -p "fix" --trust-folder', "copilot-cli/trust-folder", "medium"),
        ('copilot -p "fix" --share-gist', "copilot-cli/share-gist", "medium"),
        ('cn -p "fix" --auto', "continue/auto", "medium"),
        ("opencode serve --hostname 0.0.0.0", "opencode/hostname-any", "medium"),
        ("opencode web --hostname=0.0.0.0", "opencode/hostname-any", "medium"),
        ('uv --quiet tool run openhands --head -t "fix"', "openhands/headless", "high"),
        ('uv tool --quiet run openhands --head -t "fix"', "openhands/headless", "high"),
        ('uv -q run openhands --head -t "fix"', "openhands/headless", "high"),
        ('uvx openhands[all] --head -t "fix"', "openhands/headless", "high"),
        ('cline --auto-approve "fix"', "cline/auto-approve-true", "high"),
        ('cline --autoapprove true "fix"', "cline/auto-approve-true", "high"),
        ('cline --autoapprove=true "fix"', "cline/auto-approve-true", "high"),
        ('cline --autoapprove', "cline/auto-approve-true", "high"),
        ('copilot -p "fix" --share=transcript.md', "copilot-cli/share", "medium"),
        ('pr-agent --pr_url "$U" --config-branch "$GITHUB_HEAD_REF" review', "pr-agent/config-branch", "high"),
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
            'qwen -dy=false -p hi',
            'cline --auto-approve false "fix"',
            'opencode serve --hostname 127.0.0.1',
            'cline --autoapprove false "fix"',
            'pr-agent --pr_url "$U" --config-branch=main review',
            'pipx install openhands==1.0',
            'opencode run --auto "fix"',                    # described, not warned about (F-267)
            'opencode run --dangerously-skip-permissions "fix"',
            'aider --yes-always --message "fix"',
            'cline --auto-approve false "fix"',
            'copilot -p "fix" --allow-all-paths',
            'copilot -p "fix" --allow-all-urls',
            'openhands --llm-approve -t "fix"',
            'openhands --exit-without-confirmation -t "fix"',
            'kilo run --au "fix"',                          # yargs takes no beginnings of options
            'goose run --no-session -t "fix"',
            'sweagent run --agent.model.name=x',
            'auggie --print "fix"',
            'kiro-cli chat --no-interactive "fix"',
            'amp -x "fix"',
        ]:
            with self.subTest(script=script):
                self.assertEqual(found(check(run_step(script))), [])

    def test_a_name_another_well_known_program_shares_is_cannot_tell_only_beside_the_tools_command(self):
        # AWS's Copilot CLI and pressly's goose (found by the review): no finding where the step does not run
        # the agent's own command; "cannot tell" where it does.
        for script in ['copilot svc deploy --name api --env ${{ inputs.env }}', 'copilot deploy --app "$APP" --env $ENV',
                       'goose -dir ./migrations postgres ${{ secrets.DATABASE_URL }} up', 'goose postgres $DB up']:
            with self.subTest(script=script):
                self.assertEqual(found(check(run_step(script))), [])
        for script in ['copilot -p "fix" $FLAGS', 'goose run -t "fix" $FLAGS', 'goose serve $FLAGS',
                       'echo "$P" | copilot $FLAGS', 'copilot mcp add foo $X', 'copilot ${{ inputs.args }}',
                       'copilot svc deploy --env $E\necho "use copilot -p for agents"']:
            with self.subTest(script=script):
                self.assertEqual({(h.kind, h.severity) for h in found(check(run_step(script)))},
                                 {("command-computed", "medium")})

    def test_what_the_checker_cannot_read_is_cannot_tell_for_the_new_tools(self):
        for script in ['qwen -p "fix" $FLAGS', 'kilo run $FLAGS "fix"', 'cline $FLAGS "fix"',
                       'openhands "--al$X" -t "fix"', 'cn -p "fix" $FLAGS', 'opencode serve --hostname $H',
                       'cline --auto-approve $V "fix"', 'pr-agent --pr_url "$U" --config-branch=${{ github.head_ref }} review',
                       'BR=${{ github.head_ref }}\npr-agent --pr_url "$U" --config-branch=$BR review']:
            with self.subTest(script=script):
                hits = found(check(run_step(script)))
                self.assertTrue(hits, script)
                self.assertEqual({(h.kind, h.severity) for h in hits}, {("command-computed", "medium")},
                                 [h.message for h in hits])


if __name__ == "__main__":
    unittest.main()
