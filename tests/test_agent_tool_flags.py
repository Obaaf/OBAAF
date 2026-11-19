"""Flagship slice 2d.5c2a: OBAAF-GHA-026 for command-line options an agent tool's own files warn about.

The plan (decisions F-22, F-24 and F-264) asks that the settings an agent tool's own documentation warns
about be reported when they are given as command-line options: in an action's argument input
(`claude_args`, `codex-args`) or in a script that runs the tool (`--dangerously-skip-permissions`, Codex's
`--dangerously-bypass-approvals-and-sandbox`, Gemini CLI's `--yolo`), each citing its sentence, and a value
the checker cannot read as "cannot tell". The workflows here are written for these tests from that
documentation; none is copied from another project.
"""

import datetime
import time
import unittest

from helpers import TempDir

from obaaf import agent_tools, checker
from obaaf.catalog import load
from obaaf.checker import agent_flags

CODEOWNERS = "* @example/maintainers\n"
RULE = "OBAAF-GHA-026"
CODEX = "openai/codex-action@4aac6da4b686168e147798ca841cf64ff0f027b8"
CLAUDE = "anthropics/claude-code-action@5a856893345e332afa621934082d8c660c26d689"
CLAUDE_BASE = "anthropics/claude-code-base-action@78702a3c36b5baa51f6fa2e298a962cae8bb55d8"


def raw_detection():
    from obaaf.catalog import _read
    return _read("detection")


def check(workflow_text, files=None):
    with TempDir() as tmp:
        root = tmp / "repo"
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "wf.yml").write_text(workflow_text, encoding="utf-8")
        (root / ".github" / "CODEOWNERS").write_text(CODEOWNERS, encoding="utf-8")
        for rel, body in (files or {}).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return checker.check(root)


def run_step(script, env=None, job_env=None):
    """A workflow with one job whose one step runs `script` (a block scalar)."""
    body = "\n".join("          " + line for line in script.split("\n"))
    lines = ["on: push", "permissions: {contents: read}", "jobs:", "  a:", "    runs-on: ubuntu-latest"]
    if job_env:
        lines.append("    env:")
        lines += [f"      {k}: {v}" for k, v in job_env.items()]
    lines += ["    steps:", "      - name: agent"]
    if env:
        lines.append("        env:")
        lines += [f"          {k}: {v}" for k, v in env.items()]
    lines += ["        run: |", body]
    return "\n".join(lines) + "\n"


def one_step(uses, inputs):
    return ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - name: agent\n        uses: {uses}\n        with:\n          prompt: review this\n{inputs}")


def found(result, kind=None):
    return [f for f in result.findings if f.rule == RULE and (kind is None or f.kind == kind)]


def settings_of(result, kind):
    return sorted(f.facts["setting"] for f in found(result, kind))


class TheDataTest(unittest.TestCase):
    """The flags are data, each with words from the tool's own files at a commit."""

    def test_the_catalogue_has_no_problem_and_each_flag_cites_a_file_at_a_commit(self):
        detection = load().detection
        self.assertEqual(agent_tools.problems(raw_detection()), [])
        readers = {r[0]: r for r in agent_tools.flag_readers(detection)}
        self.assertEqual(sorted(readers), ["claude-code", "codex", "gemini-cli"])
        for tool, (_t, _n, flags, programs, _packages, args) in readers.items():
            self.assertTrue(programs, tool)
            for flag in flags:
                with self.subTest(tool=tool, flag=flag["id"]):
                    self.assertRegex(flag["source"], r"^https://github\.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/.+#L\d+")
                    self.assertIsInstance(flag["read"], datetime.date)
                    self.assertTrue(flag["says"].strip())
        self.assertEqual(readers["claude-code"][5], {"anthropics/claude-code-action": ["claude_args"],
                                                    "anthropics/claude-code-base-action": ["claude_args"]})
        self.assertEqual(readers["codex"][5], {"openai/codex-action": ["codex-args"]})

    def test_a_malformed_flag_is_a_problem(self):
        base = {"agent_tools": [{
            "id": "t", "name": "T", "read": datetime.date(2026, 11, 19), "sources": [], "actions": {},
            "commands": ["x"], "packages": {}, "install_urls": [], "settings": [], "programs": ["t"],
            "flags": []}]}
        good = {"id": "f", "options": ["--x"], "severity": "high", "read": datetime.date(2026, 11, 19),
                "says": "words", "source": "https://github.com/o/r/blob/" + "a" * 40 + "/f.md#L1"}
        self.assertEqual(agent_tools.problems(dict(base, agent_tools=[dict(base["agent_tools"][0], flags=[good])])), [])
        for bad, why in [
            (dict(good, options=["x"]), "options must be a list of option words"),
            (dict(good, options=[]), "options must be a list of option words"),
            (dict(good, options=["--a b"]), "options must be a list of option words"),
            (dict(good, equals=[]), "equals must be a list"),
            (dict(good, severity="critical"), "severity must be one of"),
            (dict(good, source="https://example.com/x"), "source must be a file at a commit"),
            (dict(good, extra=1), "unknown key"),
            ({k: v for k, v in good.items() if k != "says"}, "missing says"),
        ]:
            with self.subTest(why=why):
                problems = agent_tools.problems(dict(base, agent_tools=[dict(base["agent_tools"][0], flags=[bad])]))
                self.assertTrue(any(why in p for p in problems), problems)
        twice = dict(base["agent_tools"][0], flags=[good, dict(good, id="g")])
        self.assertTrue(any("is also flag f's" in p for p in agent_tools.problems(dict(base, agent_tools=[twice]))))
        nothing = dict(base["agent_tools"][0], flags=[good], programs=[])
        self.assertTrue(any("nothing reads them" in p for p in agent_tools.problems(dict(base, agent_tools=[nothing]))))


class CommandLineTest(unittest.TestCase):
    """Where a step runs the tool's program, each warned option is reported with its words and source."""

    CASES = [
        ('claude -p "review" --dangerously-skip-permissions', "claude-code/skip-permissions", "high"),
        ("claude --allow-dangerously-skip-permissions -p x", "claude-code/skip-permissions", "high"),
        ("claude -p x --permission-mode bypassPermissions", "claude-code/bypass-permissions-mode", "high"),
        ("claude -p x --permission-mode=bypasspermissions", "claude-code/bypass-permissions-mode", "high"),
        ('codex exec --dangerously-bypass-approvals-and-sandbox "fix it"', "codex/bypass-approvals-and-sandbox", "high"),
        ('codex --yolo exec "fix it"', "codex/bypass-approvals-and-sandbox", "high"),
        ('codex exec --dangerously-bypass-hook-trust "fix it"', "codex/bypass-hook-trust", "medium"),
        ('gemini --yolo -p "triage"', "gemini-cli/yolo", "medium"),
        ('gemini -y -p "triage"', "gemini-cli/yolo", "medium"),
        ('gemini -yp "triage"', "gemini-cli/yolo", "medium"),
        ('gemini --approval-mode yolo -p "triage"', "gemini-cli/approval-mode-yolo", "medium"),
        ('gemini --approval-mode=YOLO -p "triage"', "gemini-cli/approval-mode-yolo", "medium"),
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

    def test_the_program_is_found_however_it_is_started(self):
        for script in [
            "npx -y @anthropic-ai/claude-code -p x --dangerously-skip-permissions",
            "npx @anthropic-ai/claude-code@2.1.0 -p x --dangerously-skip-permissions",
            "pnpm dlx @anthropic-ai/claude-code -p x --dangerously-skip-permissions",
            "/usr/local/bin/claude -p x --dangerously-skip-permissions",
            "./node_modules/.bin/claude -p x --dangerously-skip-permissions",
            "sudo -u runner env HOME=/tmp timeout 600 claude -p x --dangerously-skip-permissions",
            "bash -c 'claude -p x --dangerously-skip-permissions'",
            "sh -lc \"claude -p x --dangerously-skip-permissions\"",
            'eval "claude -p x --dangerously-skip-permissions"',
            "OUT=$(claude -p x --dangerously-skip-permissions)",
            "echo go | claude -p --dangerously-skip-permissions",
            "if true; then claude -p x --dangerously-skip-permissions; fi",
            "claude -p x \\\n  --model y \\\n  --dangerously-skip-permissions",
        ]:
            with self.subTest(script=script):
                self.assertEqual(settings_of(check(run_step(script)), "command-option"), ["claude-code/skip-permissions"])

    def test_an_option_hidden_by_quotes_escapes_case_or_ansi_c_is_read(self):
        for script in [
            'claude -p x "--dangerously-skip-permissions"',
            "claude -p x '--dangerously-skip-permissions'",
            'claude -p x --danger"ously"-skip-permissions',
            "claude -p x --dangerously\\-skip\\-permissions",
            "claude -p x --DANGEROUSLY-SKIP-PERMISSIONS",
            "claude -p x $'\\x2d-dangerously-skip-permissions'",
            "claude -p x $'\\055\\055dangerously-skip-permissions'",
            'cl"aude" -p x --dangerously-skip-permissions',
        ]:
            with self.subTest(script=script):
                self.assertEqual(settings_of(check(run_step(script)), "command-option"), ["claude-code/skip-permissions"])

    def test_a_variable_with_a_plain_value_is_put_in(self):
        for env, job_env in [({"FLAGS": "--dangerously-skip-permissions"}, None),
                             (None, {"FLAGS": "--dangerously-skip-permissions"}),
                             ({"FLAGS": '"--model x --dangerously-skip-permissions"'}, None)]:
            with self.subTest(env=env, job_env=job_env):
                result = check(run_step("claude -p x $FLAGS", env=env, job_env=job_env))
                self.assertEqual(settings_of(result, "command-option"), ["claude-code/skip-permissions"])
                self.assertEqual(found(result, "command-computed"), [])
        result = check(run_step('claude -p x "${MODE_FLAG}" --permission-mode "$MODE"',
                                env={"MODE": "bypassPermissions", "MODE_FLAG": "--model"}))
        self.assertEqual(settings_of(result, "command-option"), ["claude-code/bypass-permissions-mode"])

    def test_what_the_checker_cannot_read_is_cannot_tell_at_most_medium(self):
        for script, words in [
            ("claude -p x $FLAGS", ["$FLAGS"]),
            ("claude -p x ${FLAGS}", ["${FLAGS}"]),
            ('claude -p x "${ARGS[@]}"', None),
            ("claude -p x $(cat flags.txt)", None),
            ("claude -p x `cat flags.txt`", None),
            ("claude -p x ${{ inputs.flags }}", ["${{ inputs.flags }}"]),
            ('claude -p "${{ inputs.prompt }}"', None),
            ("cat flags | xargs claude -p x", ["xargs"]),
            ('claude -p x --permission-mode "$MODE"', None),
            ('claude -p x --permission-mode=$MODE', None),
            ('claude -p x "--dangerously-$REST"', None),
            ("FLAGS=--dangerously-skip-permissions; claude -p x $FLAGS", None),
        ]:
            with self.subTest(script=script):
                result = check(run_step(script))
                hits = found(result, "command-computed")
                self.assertEqual(len(hits), 1, [h.message for h in found(result)])
                self.assertEqual(hits[0].severity, "medium")
                if words is not None:
                    self.assertEqual(hits[0].facts["words"], words)

    def test_a_script_that_sets_the_variable_itself_is_not_trusted_for_its_env_value(self):
        result = check(run_step("FLAGS=\"$(cat x)\"\nclaude -p x $FLAGS", env={"FLAGS": "--model"}))
        self.assertEqual(len(found(result, "command-computed")), 1)

    def test_nothing_is_reported_for_the_safe_and_the_unrelated(self):
        for script in [
            'claude -p "$PROMPT" --permission-mode acceptEdits --allowedTools "Read"',
            "claude -p x --permission-mode auto",
            "claude --version",
            'codex exec --sandbox workspace-write "fix"',
            'codex exec --sandbox danger-full-access "fix"',
            'gemini --approval-mode auto_edit -p x',
            'gemini -m gemini-pro -p "do it"',
            "npm install -g @anthropic-ai/claude-code@2.1.0",
            "echo '--yolo'",
            "my-gemini-wrapper --yolo",
            "git commit -m 'claude-ish --yolo'",
            "claude-code-router --dangerously-skip-permissions",
        ]:
            with self.subTest(script=script):
                self.assertEqual(found(check(run_step(script))), [], script)

    def test_a_prompt_that_names_the_option_is_read_as_giving_it_the_wider_reading(self):
        hits = found(check(run_step('claude -p "never pass --dangerously-skip-permissions"')))
        self.assertEqual([h.kind for h in hits], ["command-option"])

    def test_the_egress_actions_command_and_github_script_are_read(self):
        egress = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                  "      - uses: Obaaf/OBAAF/actions/egress@" + "a" * 40 + "\n        with:\n"
                  "          allow: api.anthropic.com\n          run: claude -p x --dangerously-skip-permissions\n")
        self.assertEqual(settings_of(check(egress), "command-option"), ["claude-code/skip-permissions"])
        script = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                  "      - uses: actions/github-script@" + "b" * 40 + "\n        with:\n"
                  "          script: |\n            await exec.exec('codex exec --yolo fix')\n")
        self.assertEqual(settings_of(check(script), "command-option"), ["codex/bypass-approvals-and-sandbox"])

    def test_a_local_composite_action_is_read_as_the_jobs_steps(self):
        workflow = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - uses: actions/checkout@" + "c" * 40 + "\n        with: {persist-credentials: false}\n"
                    "      - uses: ./.github/actions/agent\n")
        action = ("name: agent\nruns:\n  using: composite\n  steps:\n    - shell: bash\n"
                  "      run: gemini --yolo -p x\n")
        result = check(workflow, {".github/actions/agent/action.yml": action})
        self.assertEqual(settings_of(result, "command-option"), ["gemini-cli/yolo"])

    def test_the_facts_tell_two_options_apart(self):
        a = found(check(run_step("claude -p x --dangerously-skip-permissions")))[0]
        b = found(check(run_step("claude -p x --allow-dangerously-skip-permissions")))[0]
        self.assertNotEqual(a.facts, b.facts)
        self.assertEqual(a.facts["option"], "--dangerously-skip-permissions")


class ArgsInputTest(unittest.TestCase):
    """`claude_args` and `codex-args` are read as the options they hand the program."""

    def test_claude_args(self):
        for uses in (CLAUDE, CLAUDE_BASE):
            for value in ["--dangerously-skip-permissions", '"--model x --dangerously-skip-permissions"',
                          "|\n            --model x\n            --dangerously-skip-permissions",
                          "--permission-mode bypassPermissions --max-turns 3"]:
                with self.subTest(uses=uses, value=value):
                    hits = found(check(one_step(uses, f"          claude_args: {value}\n")), "option")
                    self.assertEqual(len(hits), 1, [h.message for h in hits])
                    self.assertTrue(hits[0].facts["setting"].startswith("claude-code/"))
                    self.assertEqual(hits[0].facts["input"], "claude_args")
                    self.assertEqual(hits[0].severity, "high")

    def test_codex_args_as_a_json_array_and_as_a_string(self):
        for value in ["'[\"--yolo\"]'", "'[\"--model\", \"x\", \"--dangerously-bypass-approvals-and-sandbox\"]'",
                      "--yolo", "'--model x --yolo'"]:
            with self.subTest(value=value):
                hits = found(check(one_step(CODEX, f"          codex-args: {value}\n")), "option")
                self.assertEqual([h.facts["setting"] for h in hits], ["codex/bypass-approvals-and-sandbox"])

    def test_a_comment_line_in_claude_args_is_left_out_as_the_action_leaves_it_out(self):
        value = "|\n            # --dangerously-skip-permissions\n            --model x"
        self.assertEqual(found(check(one_step(CLAUDE, f"          claude_args: {value}\n"))), [])

    def test_a_value_the_checker_cannot_read_is_cannot_tell(self):
        for value in ["${{ inputs.args }}", "'--model x ${{ vars.EXTRA }}'", "[--yolo]", "{a: b}"]:
            with self.subTest(value=value):
                hits = found(check(one_step(CODEX, f"          codex-args: {value}\n")))
                self.assertEqual([h.kind for h in hits], ["computed"], [h.message for h in hits])
                self.assertEqual(hits[0].severity, "medium")

    def test_with_as_one_expression_names_the_flags_too(self):
        text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                f"      - uses: {CLAUDE}\n        with: ${{{{ fromJSON(vars.INPUTS) }}}}\n")
        hits = found(check(text))
        self.assertEqual([h.kind for h in hits], ["computed"])
        self.assertIn("claude-code/skip-permissions", hits[0].facts["settings"])
        self.assertIn("claude-code/non-write-users", hits[0].facts["settings"])

    def test_a_safe_value_is_not_reported(self):
        for uses, line in [(CLAUDE, "claude_args: --permission-mode auto --allowedTools Read"),
                           (CODEX, "codex-args: '[\"--model\", \"gpt-5\"]'"),
                           (CODEX, "codex-args: --search")]:
            with self.subTest(line=line):
                self.assertEqual(found(check(one_step(uses, f"          {line}\n"))), [])


class ReaderTest(unittest.TestCase):
    """The reader on its own, and its cost."""

    def flags(self, tool):
        return next(r for r in agent_tools.flag_readers(load().detection) if r[0] == tool)

    def test_a_script_without_the_program_is_not_read(self):
        _t, _n, flags, programs, packages, _a = self.flags("claude-code")
        reading = agent_flags.read_script("echo --dangerously-skip-permissions", programs, packages, flags)
        self.assertEqual((reading.hits, reading.unknown), ({}, {}))

    def test_a_long_script_is_read_in_linear_time(self):
        _t, _n, flags, programs, packages, _a = self.flags("claude-code")
        for n in (2000, 8000):
            script = "\n".join(f'claude -p "step {i}" --model m{i} "$P{i}"' for i in range(n))
            start = time.perf_counter()
            agent_flags.read_script(script, programs, packages, flags)
            if n == 2000:
                small = time.perf_counter() - start
            else:
                self.assertLess(time.perf_counter() - start, max(1.0, small * 8))


if __name__ == "__main__":
    unittest.main()
