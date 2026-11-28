"""Flagship slice 2d.28 (#227): the same findings for less work.

The second pass over local composite actions (slice 2d.4b2) reads every step of an action again for each
job that uses it, so a repository of many jobs that share an action asks the same questions of the same
scripts hundreds of times. `test_a_large_repository_with_realistic_actions_passes` in
tests/test_local_composite_actions.py took 12.9 s on this session's machine on `flagship` `d6410ce` and
failed its 30 s limit on CI's Python 3.10 on four heads of #426. The slice keeps what those questions
answer by their text, and works out once for a step what OBAAF-GHA-026 read again for each agent tool.

None of that may change a finding. These tests hold each short cut to the reading it stands for: the
lexer's targets with and without the test that skips it, on seeded random lines; `appears`, `_command_reading`,
`_uploads_in` and `_signing_command_in` against the loops they replace; OBAAF-GHA-026's findings with the step's
command lines shared by the tools and worked out again for each, on steps that name tools; and a count that it
works them out once per step. The seeds are fixed, so CI runs the same cases every time.

A script that names a path with a NUL byte or a lone surrogate (`cp a\0b dest`, `bash ./a\0b.sh`) still ends
the check in a traceback, as before the slice: its review found that reading such a path as no file is narrower
than bash, which drops a NUL after a script's first line (#429).
"""

import random
import re
import tempfile
import unittest
from pathlib import Path

from helpers import TempDir

from obaaf import checker
from obaaf.checker import _copied_script_targets, _lexed_script_targets, agent_flags, rules
from obaaf.checker import workflow as wf_mod
from obaaf.catalog import load

SEED = 20261128

# Pieces a line is made of: words that make a target only with quotes or backslashes inside them, the
# commands the lexer follows, separators, comments, variables and plain words.
PIECES = ["bash", "sh", "source", ".", "exec", "timeout", "env", "cp", "-r", "-f", "x.sh", "x.bash",
          "./scripts/run.sh", "scripts/run.sh", "$D/run.sh", "${D}/run.sh", "$D", "${D}", "scripts", "out",
          ".s'h'", '.s"h"', ".s\\h", "'.sh'", '".bash"', ".\\sh", "x.s", "h", "'", '"', "\\", "#", "# a.sh",
          ";", "&&", "||", "|", "&", " ", "  ", "\t", "\n", "echo", "make", "x" * 40, "run.s", "h.sh", ".ba",
          "sh;", "a.sh#", "$(", ")", "`", "=", "D=out", ".SH", "run.BASH", "\u00a0", "é", "\x00", "a\x00b.sh",
          "\ud800", "\ud800.sh", "\r", "\x0b", "\x0c", "\x1c", "\x85", "\u2028", "a.s\x00h"]


class TheLexerShortCutTest(unittest.TestCase):
    """`_copied_script_targets` skips the lexer where the text cannot hold a target: on random lines, and
    with real scripts in the repository, it gives what the lexer gives."""

    def test_random_lines_give_what_the_lexer_gives(self):
        rng = random.Random(SEED)
        with TempDir() as tmp:
            root = (tmp / "repo").resolve()
            (root / "scripts").mkdir(parents=True)
            for name in ("run.sh", "x.sh", "x.bash", "h.sh", "run.BASH"):
                (root / "scripts" / name).write_text("echo\n", encoding="utf-8")
                (root / name).write_text("echo\n", encoding="utf-8")
            (root / "out").mkdir()
            skipped = 0
            for _ in range(4000):
                text = "".join(rng.choice(PIECES) + rng.choice(["", " ", " ", "\n"])
                               for _ in range(rng.randint(1, 14)))
                with self.subTest(text=text):
                    self.assertEqual(outcome(_copied_script_targets, text, root),
                                     outcome(_lexed_script_targets, text, root))
                    bare = re.sub(r"[\"'\\]", "", text)
                    skipped += ".sh" not in bare and ".bash" not in bare
            # The test is worth something only if both sides of the short cut are taken often.
            self.assertGreater(skipped, 400)
            self.assertLess(skipped, 3600)

    def test_a_path_with_a_nul_or_a_lone_surrogate_fails_as_before(self):
        # Resolving such a `cp` argument raises, as before the slice; the short cut does not hide it (#429).
        with TempDir() as tmp:
            root = (tmp / "repo").resolve()
            root.mkdir()
            for text in ("cp a\0b dest", "cp \ud800 dest", "cp a\0b.sh out"):
                with self.subTest(text=text):
                    self.assertIsInstance(outcome(_copied_script_targets, text, root), type)
                    self.assertEqual(outcome(_copied_script_targets, text, root),
                                     outcome(_lexed_script_targets, text, root))

    def test_a_target_behind_quotes_is_still_found(self):
        with TempDir() as tmp:
            root = (tmp / "repo").resolve()
            (root / "scripts").mkdir(parents=True)
            (root / "scripts" / "run.sh").write_text("claude -p x\n", encoding="utf-8")
            for text in ("bash scripts/run.s'h'", 'bash scripts/run.s"h"', "bash scripts/run.s\\h",
                         "cp scripts/run.sh out; bash out/run.s''h"):
                with self.subTest(text=text):
                    self.assertEqual(_copied_script_targets(text, root), ["scripts/run.sh"])


def outcome(function, *args):
    """What `function(*args)` gives, or the type of what it raised."""
    try:
        return function(*args)
    except Exception as exc:        # noqa: BLE001 - the type is what is compared
        return type(exc)


def _appears_before(text, programs, packages):
    """`agent_flags.appears` as it was before the slice."""
    names = [n.casefold() for n in programs + packages]
    low = re.sub(r"[\"'\\]", "", text).casefold()
    if any(n in low for n in names):
        return True
    if "$'" in text:
        decoded = re.sub(r"[\"'\\]", "", re.sub(r"\$'((?:[^'\\]|\\.)*)'",
                                                  lambda m: agent_flags._ansi_c(m.group(1)), text)).casefold()
        return any(n in decoded for n in names)
    return False


WORDS = ["claude", "CLAUDE", "cl'aude", 'cla"ude', "cl\\aude", "$'cl\\x61ude'", "$'\\u0063laude'", "codex",
         "co$'d'ex", "cn", "acne", "goose", "aider", "echo", "-p", "x", " ", "'", '"', "\\", "$'", "\n", "ß", "ǅ"]


class TheKeptAnswersTest(unittest.TestCase):
    """Each answer kept by its text is the answer the loop it replaces gives."""

    def test_appears_is_as_before(self):
        rng = random.Random(SEED + 1)
        tools = [(["claude"], ["@anthropic-ai/claude-code"]), (["codex"], []), (["cn"], ["@continuedev/cli"]),
                 (["goose"], []), (["aider"], ["aider-chat"])]
        for _ in range(3000):
            text = "".join(rng.choice(WORDS) for _ in range(rng.randint(0, 10)))
            programs, packages = rng.choice(tools)
            with self.subTest(text=text, programs=programs):
                self.assertEqual(agent_flags.appears(text, programs, packages),
                                 _appears_before(text, programs, packages))
                # Asked again, from what was kept.
                self.assertEqual(agent_flags.appears(text, programs, packages),
                                 _appears_before(text, programs, packages))

    def test_command_reading_is_the_loop_it_replaces(self):
        detection = load().detection
        commands = [re.compile(p, re.M) for p in detection.get("agent_commands", [])]
        signature = tuple((p.pattern, p.flags) for p in commands)
        rng = random.Random(SEED + 2)
        pieces = WORDS + ["sudo ", "npx ", "bash -c '", "env A=1 ", "/usr/bin/", "Start-Process ", "call ",
                          "& ", "; ", "| ", "\\\n", "@anthropic-ai/claude-code", "gemini", "-FilePath "]
        for _ in range(3000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 12)))
            family = rng.choice([None, "pwsh", "cmd"])
            expected = None
            for variant in wf_mod._readings(text):
                hit = next((candidate for segment in wf_mod.command_segments(variant)
                            for form in [segment, *wf_mod.shell_env.command_forms(segment, family)]
                            for candidate in wf_mod._first_word_forms(form)
                            if wf_mod.matches_any(commands, candidate, anchored=True)), None)
                if hit is not None:
                    expected = (variant, hit)
                    break
            with self.subTest(text=text, family=family):
                self.assertEqual(wf_mod._command_reading(text, family, signature, commands), expected)
                self.assertEqual(wf_mod._command_reading(text, family, signature, commands), expected)

    def test_two_pattern_lists_are_kept_apart(self):
        # The same text asked with a repository's own agent pattern and without it (`agents.commands`).
        detection = load().detection
        plain = [re.compile(p, re.M) for p in detection.get("agent_commands", [])]
        own = plain + [re.compile(r"^my-bot\b", re.M)]
        for text in ("my-bot --go", "sudo my-bot --go", "echo my-bot"):
            with self.subTest(text=text):
                first = wf_mod._command_reading(text, None, tuple((p.pattern, p.flags) for p in own), own)
                second = wf_mod._command_reading(text, None, tuple((p.pattern, p.flags) for p in plain), plain)
                self.assertEqual(second, None)
                self.assertEqual(first is None, text == "echo my-bot")

    def test_release_and_signing_commands_are_as_before(self):
        detection = load().detection
        uploads = tuple(detection.get("upload_commands", []))
        signing = tuple(detection.get("signing_commands", []))
        rng = random.Random(SEED + 3)
        pieces = ["npm publish", "npm \\\n  publish", "'npm' publish", "twine upload", "gh release upload",
                  "docker push", "cosign sign", "gpg --import", "gpg \\\n --import", "echo", "\n", " ", "`\n",
                  "^\n", '"', "'", "x"]
        for _ in range(2000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 8)))
            with self.subTest(text=text):
                self.assertEqual(wf_mod._uploads_in(text, uploads), any(
                    re.compile(p, re.M).search(v) for v in wf_mod.upload_readings(text) for p in uploads))
                joined = re.sub(r"[\\`^][ \t]*\r?\n", " ", text)
                self.assertEqual(rules._signing_command_in(text, signing), any(
                    re.compile(p, re.M).search(text) or re.compile(p, re.M).search(joined) for p in signing))


def _workflow(steps):
    return ("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + "".join(
        f"      - run: echo step {n} \"$KEY\"\n        env:\n          KEY: k{n}\n" for n in range(steps)))


# Steps that name agent tools, each read by OBAAF-GHA-026 through the command lines the tools now share: bash,
# PowerShell and cmd, a value put in from `env`, github-script, a `${{ env }}` expression, an input that is a
# command, and a matrix over Windows and Linux. Several steps name more than one tool, so that a tool read after
# another reads what the first was given (the review's mutants of the shared tuple fail on them); job `b` names
# codex only through `$A$B`, with no `codex` in any `env`.
NAMING = """on: pull_request
permissions: {}
env:
  FLAGS: --dangerously-skip-permissions
jobs:
  a:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    env:
      AGENT: codex
    steps:
      - run: claude --dangerously-skip-permissions -p "review"
      - run: claude ${{ env.FLAGS }} -p x
      - run: $AGENT --yolo exec x
      - run: '& $env:AGENT --dangerously-bypass-approvals-and-sandbox exec x'
        shell: pwsh
      - run: '%AGENT% --yolo exec x'
        shell: cmd
      - uses: actions/github-script@0000000000000000000000000000000000000000
        with:
          script: await exec.exec('gemini', ['--yolo', '-p', 'x'])
      - uses: some/retry@0000000000000000000000000000000000000000
        with:
          command: claude --permission-mode bypassPermissions -p x
      - run: |
          claude --dangerously-skip-permissions -p x
          $AGENT --yolo exec x
          gemini --yolo -p x
      - run: |
          & claude --dangerously-skip-permissions -p x
          & $env:AGENT --yolo exec x
          gemini --yolo -p x
        shell: pwsh
      - run: |
          claude --dangerously-skip-permissions -p x
          %AGENT% --yolo exec x
          gemini --yolo -p x
        shell: cmd
      - run: echo $TOOLS
        env:
          TOOLS: claude --dangerously-skip-permissions -p x && codex --yolo exec x && gemini --yolo -p x
      - uses: actions/github-script@0000000000000000000000000000000000000000
        with:
          script: |
            await exec.exec('claude', flags)
            await exec.exec('gemini', more)
            await exec.exec('codex', other)
      - run: echo nothing to see
  b:
    runs-on: ubuntu-latest
    steps:
      - run: claude --dangerously-skip-permissions -p x; $A$B --yolo exec x
        env:
          A: cod
          B: ex
"""


class OneReadingForEveryToolTest(unittest.TestCase):
    """OBAAF-GHA-026 works out what a step gives a shell once for the step, not once for each of the agent
    tools whose options it reads (a dozen): before the slice, `_agent_command` worked it out for every step
    and tool."""

    def _check(self, text):
        with TempDir() as tmp:
            root = tmp / "repo"
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "wf.yml").write_text(text, encoding="utf-8")
            result = checker.check(root)
        return sorted((f.rule, f.job, f.step, f.kind, f.severity, f.message, repr(f.facts)) for f in result.findings
                      if f.rule == "OBAAF-GHA-026"), result.errors

    def test_the_shared_reading_gives_what_a_reading_for_each_tool_gives(self):
        shared, errors = self._check(NAMING)
        real = rules.WorkflowRules._agent_command

        def alone(self, job, step, tool, name, flags, programs, packages, command=None):
            # As before the slice: each tool works the step's command lines out for itself.
            return real(self, job, step, tool, name, flags, programs, packages, None)

        rules.WorkflowRules._agent_command = alone
        try:
            each, errors_each = self._check(NAMING)
        finally:
            rules.WorkflowRules._agent_command = real
        self.assertEqual(shared, each)
        self.assertEqual(errors, errors_each)
        # The steps above are read: several tools' options are reported, among them a "cannot tell".
        self.assertGreaterEqual(len({row[2] for row in shared}), 5, shared)
        self.assertTrue({"codex", "claude", "gemini"} <= {
            word for row in shared for word in ("codex", "claude", "gemini") if word in row[5].lower()}, shared)

    def test_each_step_is_worked_out_once(self):
        calls = []
        real = rules.WorkflowRules._command_parts

        def counted(self, job, step):
            calls.append((id(self), job.id, step.index))
            return real(self, job, step)

        rules.WorkflowRules._command_parts = counted
        try:
            with TempDir() as tmp:
                root = tmp / "repo"
                (root / ".github" / "workflows").mkdir(parents=True)
                (root / ".github" / "workflows" / "wf.yml").write_text(_workflow(7), encoding="utf-8")
                result = checker.check(root)
        finally:
            rules.WorkflowRules._command_parts = real
        self.assertEqual(result.errors, [])
        self.assertTrue(len(agent_flags_readers()) > 5, "the catalogue reads options of several tools")
        self.assertEqual(len(calls), 7)
        self.assertEqual(len(set(calls)), 7)


def agent_flags_readers():
    from obaaf import agent_tools
    return agent_tools.flag_readers(load().detection)


if __name__ == "__main__":
    unittest.main()
