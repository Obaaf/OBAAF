"""The Jenkins rules' search shortcut gives the same answers as the pattern itself (flagship unblock run `gannet`).

`obaaf.checker.jenkins.prefilter` skips a pattern over a text that does not contain the plain letters every match
of the pattern contains. It may only ever save time: these tests compare it with `re` on every detection pattern
the Jenkins rules use and on random patterns and texts, and pin the reading of the parse for the cases where a
mistake would hide a finding (case-insensitive parts, optional parts, alternatives, lookarounds).
"""

from __future__ import annotations

import importlib
import random
import re
import time
import unittest

from obaaf.catalog import load
from obaaf.checker.jenkins import prefilter


def _texts_of(value, out: list[str]) -> None:
    if isinstance(value, str):
        if len(value) >= 20:
            out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _texts_of(item, out)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _texts_of(item, out)


def jenkins_case_texts() -> list[str]:
    """Every Jenkinsfile written in the Jenkins rules' bypass tests, shortened so the comparison stays quick."""
    out: list[str] = []
    for module in ("test_jenkins_approvals", "test_jenkins_artifact_transfer", "test_jenkins_code_pins",
                   "test_jenkins_failure_paths", "test_jenkins_files_credentials", "test_jenkins_provenance",
                   "test_jenkins_workspaces"):
        mod = importlib.import_module(module)
        for name in ("CASES", "REVIEW_CASES"):
            _texts_of(getattr(mod, name, None), out)
    return [t if len(t) <= 20_000 else t[:10_000] + t[-10_000:] for t in out]


def detection_patterns() -> list[re.Pattern]:
    """Every pattern of every list in detection.yaml that compiles, with the flags the Jenkins rules give it."""
    detection = load().detection
    out = []
    for key, value in detection.items():
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            continue
        flags = re.I if key.endswith("_secret_patterns") else re.M
        for text in value:
            try:
                out.append(re.compile(text, flags))
            except re.error:
                pass
    return out


def same_answer(test: unittest.TestCase, rx: re.Pattern, text: str) -> None:
    m, n = rx.search(text), prefilter.search(rx, text)
    test.assertEqual(m and (m.span(), m.group(0)), n and (n.span(), n.group(0)), (rx.pattern, text[:200]))
    if m is not None:
        test.assertTrue(prefilter.possible(rx, text))
    test.assertEqual([x.span() for x in rx.finditer(text)], [x.span() for x in prefilter.finditer(rx, text)],
                     (rx.pattern, text[:200]))


class Needles(unittest.TestCase):
    def needles(self, pattern: str, flags: int = 0):
        return prefilter.needles(re.compile(pattern, flags))

    def test_a_command_word_is_required(self):
        self.assertEqual(self.needles(r"(^|[\s;&|(])(npm|pnpm|yarn)\s+publish\b", re.M), {"publish"})
        self.assertEqual(self.needles(r"(^|[\s;&|(])(\./)?(mvn|mvnw)\b[^\n;&|]*\s(deploy|release:perform)\b"),
                         {"deploy", "release:perform"})
        self.assertEqual(self.needles(r"\bclaude\b"), {"claude"})

    def test_case_insensitive_parts_give_nothing(self):
        self.assertIsNone(self.needles(r"claude", re.I))
        self.assertIsNone(self.needles(r"(?i)claude"))
        self.assertIsNone(self.needles(r"(?i:claude)"))
        self.assertEqual(self.needles(r"(?i:claude)x"), {"x"})
        self.assertEqual(self.needles(r"(?i:a(?-i:bcd))"), {"bcd"})

    def test_optional_parts_and_alternatives_with_an_empty_side_give_nothing(self):
        self.assertIsNone(self.needles(r"a?"))
        self.assertIsNone(self.needles(r"(abc)*"))
        self.assertIsNone(self.needles(r"(abc){0,3}"))
        self.assertIsNone(self.needles(r"(abc|)"))
        self.assertIsNone(self.needles(r"(abc|d*)"))
        self.assertEqual(self.needles(r"(abc){2,}"), {"abc"})
        self.assertEqual(self.needles(r"a*bc"), {"bc"})

    def test_lookarounds_classes_and_references_give_nothing(self):
        self.assertIsNone(self.needles(r"(?=abc)"))
        self.assertIsNone(self.needles(r"(?!abc)."))
        self.assertIsNone(self.needles(r"(?<=abc)\w"))
        self.assertIsNone(self.needles(r"[^a]"))
        self.assertIsNone(self.needles(r"[a-z]"))
        self.assertIsNone(self.needles(r"(a)?\1"))
        self.assertIsNone(self.needles(r"(?P<q>a)?(?(q)b|c)"))
        self.assertEqual(self.needles(r"(a)\1"), {"a"})
        self.assertEqual(self.needles(r"(?=abc)x"), {"x"})
        self.assertEqual(self.needles(r"[ab]"), {"a", "b"})

    def test_a_longer_string_that_holds_a_shorter_one_is_dropped(self):
        self.assertEqual(self.needles(r"(xgradle|gradle)z"), {"gradle"})
        self.assertEqual(self.needles(r"(gradle|gradlew) "), {"gradle"})

    def test_verbose_patterns_are_read_as_re_reads_them(self):
        self.assertEqual(self.needles(r"(?x) c l a u d e  # comment"), {"claude"})

    def test_a_pattern_the_parser_refuses_or_bytes_give_nothing(self):
        self.assertIsNone(prefilter.needles(re.compile(rb"claude")))


class SameAnswers(unittest.TestCase):
    def test_every_detection_pattern_on_every_jenkins_case(self):
        patterns = detection_patterns()
        texts = jenkins_case_texts()
        self.assertGreater(len(patterns), 100)
        self.assertGreater(len(texts), 300)
        for rx in patterns:
            for text in texts:
                same_answer(self, rx, text)

    def test_every_detection_pattern_on_text_made_of_its_own_words(self):
        rng = random.Random(20261121)
        patterns = detection_patterns()
        words = sorted({w for rx in patterns for w in (prefilter.needles(rx) or ())})
        pieces = words + [" ", "\n", ";", "&&", "|", "./", "-", "--dry-run", "=", "'", '"', "x", "\\\n", "#"]
        for rx in patterns:
            for _ in range(40):
                text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
                same_answer(self, rx, text)

    def test_random_patterns_and_texts(self):
        rng = random.Random(1121)
        alphabet = "abcAB \n-"

        def atom(depth: int) -> str:
            choice = rng.randrange(12 if depth < 3 else 5)
            if choice <= 2:
                return rng.choice("abcAB")
            if choice == 3:
                return rng.choice([r"\s", r"\b", "^", "$", ".", r"\w", "[ab]", "[^a]", "[a-c]", "[Aa]", r"\n"])
            if choice == 4:
                return "-"
            if choice == 5:
                return "(" + seq(depth + 1) + ")"
            if choice == 6:
                return "(?:" + "|".join(seq(depth + 1) for _ in range(rng.randint(2, 3))) + ")"
            if choice == 7:
                return "(?i:" + seq(depth + 1) + ")"
            if choice == 8:
                return rng.choice(["(?=", "(?!"]) + seq(depth + 1) + ")" if rng.random() < 0.6 \
                    else rng.choice(["(?<=a)", "(?<!b)", "(?<=ab)", "(?<!A)"])
            if choice == 9:
                return "(?:" + seq(depth + 1) + ")" + rng.choice(["*", "+", "?", "{2}", "{0,2}", "{1,3}", "*?", "+?"])
            if choice == 10:
                return "(?-i:" + seq(depth + 1) + ")"
            return rng.choice("abc") + rng.choice(["*", "+", "?"])

        def seq(depth: int) -> str:
            return "".join(atom(depth) for _ in range(rng.randint(0, 4)))

        compared = 0
        for _ in range(3000):
            source = seq(0)
            flags = rng.choice([0, 0, 0, re.M, re.I, re.S])
            try:
                rx = re.compile(source, flags)
            except re.error:
                continue
            for _ in range(8):
                text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14)))
                same_answer(self, rx, text)
                compared += 1
        self.assertGreater(compared, 15_000)


class Cost(unittest.TestCase):
    def test_a_long_script_without_the_commands_is_searched_far_faster(self):
        # The lists the Jenkins rules search whole scripts with, on PERF_20k_line_script's kind of script.
        detection = load().detection
        patterns = [re.compile(x, re.M) for key in ("agent_commands", "upload_commands", "jenkins_upload_commands",
                                                     "signing_commands") for x in detection.get(key, [])]
        # The three case-insensitive Windows signing commands give no string, and are run as before.
        self.assertGreaterEqual(sum(1 for rx in patterns if prefilter.needles(rx)), len(patterns) - 3)
        text = "".join(f"echo line {i} with some words here and there\n" for i in range(20_000))
        started = time.monotonic()
        plain = [rx.search(text) for rx in patterns]
        plain_seconds = time.monotonic() - started
        started = time.monotonic()
        fast = [prefilter.search(rx, text) for rx in patterns]
        fast_seconds = time.monotonic() - started
        self.assertEqual(plain, fast)
        # A ratio, not a time, so a slow machine does not fail it: about ten times faster where it was written.
        self.assertLess(fast_seconds * 3, plain_seconds)


if __name__ == "__main__":
    unittest.main()
