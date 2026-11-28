"""Flagship slice 2d.28 (#227): the same findings for less work.

The second pass over local composite actions (slice 2d.4b2) reads every step of an action again for each
job that uses it, so a repository of many jobs that share an action asks the same questions of the same
scripts hundreds of times. `test_a_large_repository_with_realistic_actions_passes` in
tests/test_local_composite_actions.py took 14.8 s on this session's machine on `flagship` `d6410ce` and
failed its 30 s limit on CI's Python 3.10 on four heads of #426. The slice keeps what those questions
answer by their text, and works out once for a step what OBAAF-GHA-026 read again for each agent tool.

None of that may change a finding. These tests hold each short cut to the reading it stands for: the
lexer's targets with and without the test that skips it, on seeded random lines; `appears`, `_command_reading`,
`_uploads_in` and `_signing_command_in` against the loops they replace; and a count that GHA-026 works out a
step's command lines once, not once for each tool. The seeds are fixed, so CI runs the same cases every time.
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
          "sh;", "a.sh#", "$(", ")", "`", "=", "D=out", ".SH", "run.BASH", "\u00a0", "é"]


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
                    self.assertEqual(_copied_script_targets(text, root), _lexed_script_targets(text, root))
                    bare = re.sub(r"[\"'\\]", "", text)
                    skipped += ".sh" not in bare and ".bash" not in bare
            # The test is worth something only if both sides of the short cut are taken often.
            self.assertGreater(skipped, 400)
            self.assertLess(skipped, 3600)

    def test_a_target_behind_quotes_is_still_found(self):
        with TempDir() as tmp:
            root = (tmp / "repo").resolve()
            (root / "scripts").mkdir(parents=True)
            (root / "scripts" / "run.sh").write_text("claude -p x\n", encoding="utf-8")
            for text in ("bash scripts/run.s'h'", 'bash scripts/run.s"h"', "bash scripts/run.s\\h",
                         "cp scripts/run.sh out; bash out/run.s''h"):
                with self.subTest(text=text):
                    self.assertEqual(_copied_script_targets(text, root), ["scripts/run.sh"])


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


class OneReadingForEveryToolTest(unittest.TestCase):
    """OBAAF-GHA-026 works out what a step gives a shell once for the step, not once for each of the agent
    tools whose options it reads (a dozen): before the slice, `_step_shell` ran for every step and tool."""

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
