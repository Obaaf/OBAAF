"""Flagship slice 2d.29 (#425): a number too long for Python to print ends no check in a traceback.

YAML reads `0x` and thousands of hex digits as one integer, and Python's `str()` refuses to print an integer of
more than 4,300 decimal digits. `workflow.as_text` gives such a number in hexadecimal, and some readers treat it as
a value they do not know; others called `str()` and raised `ValueError`. Before this slice `obaaf check` and
`--lanes` ended in a traceback where such a number stood as a github-script `script:`, a step's `shell:` (or a
default one), a job's `if:` or `needs:`, a `docker://` step's arguments, the egress action's step `id`, a
harden-runner input, or the `env` and `with` of a step before a key the egress action holds. Found by #423's
reviewer and by this slice's probes, which put such a number at every place a probe workflow has and at 2,000
places sampled from real workflows (`tests/fixtures`, the templates, this repository's workflows and the first
adopter's).
"""

import contextlib
import io
import random
import unittest

from helpers import TempDir

from obaaf import checker, cli
from obaaf.checker.workflow import as_text, printed

LONG = "0x" + "F" * 6000
SHA = "1111111111111111111111111111111111111111"


def workflow(steps, job="", top="", on="pull_request_target"):
    return (f"on: {on}\n{top}permissions: {{}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n{job}    steps:\n{steps}")


PLACES = {
    "github-script script": workflow(f"      - uses: actions/github-script@{SHA}\n        with:\n          script: {LONG}\n"),
    "step shell": workflow(f"      - run: echo hi\n        shell: {LONG}\n"),
    "job default shell": workflow("      - run: echo hi\n", job=f"    defaults:\n      run:\n        shell: {LONG}\n"),
    "workflow default shell": workflow("      - run: echo hi\n", top=f"defaults:\n  run:\n    shell: {LONG}\n"),
    "job if": workflow("      - run: echo hi\n", job=f"    if: {LONG}\n"),
    "job needs": workflow("      - run: echo hi\n", job=f"    needs: [{LONG}]\n"),
    "code input": workflow(f"      - uses: mikefarah/yq@{SHA}\n        with:\n          cmd: {LONG}\n"),
    "docker arguments": workflow(f"      - uses: docker://node:20\n        with:\n          args: [{LONG}]\n"
                                 f"          entrypoint: {LONG}\n"),
    "egress step id": workflow(f"      - uses: Obaaf/OBAAF/actions/egress@{SHA}\n        id: {LONG}\n        with:\n"
                               "          run: claude -p x\n          allow: api.anthropic.com\n"),
    "harden-runner inputs": workflow(f"      - uses: step-security/harden-runner@{SHA}\n        with:\n"
                                     f"          egress-policy: block\n          use-policy-store: {LONG}\n"
                                     f"          deploy-on-self-hosted-vm: {LONG}\n      - run: claude -p x\n"),
    "env beside a held key": workflow(
        f"      - run: echo GITHUB_ENV\n        env:\n          A: {LONG}\n          {LONG}: b\n        with:\n"
        f"          b: {LONG}\n      - uses: Obaaf/OBAAF/actions/egress@{SHA}\n        with:\n          run: claude -p x\n"
        "          allow: api.anthropic.com\n          model-keys: ANTHROPIC_API_KEY\n",
        job="    env:\n      ANTHROPIC_API_KEY: ${{ secrets.K }}\n"),
}


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(args))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class ALongNumberEndsNoCheckInATracebackTest(unittest.TestCase):

    def test_each_place(self):
        for place, text in PLACES.items():
            with self.subTest(place=place), TempDir() as tmp:
                (tmp / ".github" / "workflows").mkdir(parents=True)
                (tmp / ".github" / "workflows" / "w.yml").write_text(text, encoding="utf-8")
                (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
                result = checker.check(tmp)
                self.assertEqual([e for e in result.errors if "Traceback" in e], [])
                checker.lanes(tmp, notes=[], errors=[], seen=[])
                for options in ((), ("--format", "json"), ("--format", "sarif"), ("--summary",), ("--lanes",)):
                    code, out, err = run_cli("check", str(tmp), *options)
                    self.assertIn(code, (0, 1), (options, err[-500:]))
                    self.assertNotIn("Traceback", err)
                    # The number is never written out whole: a finding or a fact shows it bounded.
                    self.assertNotIn("F" * 5000, out)


class PrintedTest(unittest.TestCase):
    """`printed` is `str` wherever `str` prints, and prints a long integer in hexadecimal anywhere in a value."""

    def test_it_is_str_for_what_str_prints(self):
        rng = random.Random(20261128)

        def value(depth=0):
            kind = rng.randrange(8 if depth < 3 else 5)
            if kind == 0:
                return rng.randint(-10**30, 10**30)
            if kind == 1:
                return rng.choice(["", "a", "line\nbreak", "é", "'", '"', "\\"])
            if kind == 2:
                return rng.choice([True, False, None, 1.5, float("inf")])
            if kind in (3, 4):
                return rng.random()
            if kind == 5:
                return [value(depth + 1) for _ in range(rng.randrange(4))]
            if kind == 6:
                return tuple(value(depth + 1) for _ in range(rng.randrange(3)))
            return {rng.choice(["k", 1, True, None, "é"]): value(depth + 1) for _ in range(rng.randrange(4))}

        for _ in range(2000):
            item = value()
            self.assertEqual(printed(item), str(item))

    def test_a_long_integer_prints_in_hexadecimal_where_it_stands(self):
        number = int("F" * 6000, 16)
        self.assertEqual(printed(number), as_text(number))
        self.assertEqual(printed({"A": number, "b": [1, number]}), "{'A': %s, 'b': [1, %s]}" % (hex(number), hex(number)))
        self.assertEqual(printed({number: "x"}), "{%s: 'x'}" % hex(number))
        self.assertEqual(printed((number,)), "(%s,)" % hex(number))

    def test_a_value_that_holds_itself(self):
        number = int("F" * 6000, 16)
        loop: list = [number]
        loop.append(loop)
        self.assertEqual(printed(loop), "[%s, [...]]" % hex(number))
        mapping: dict = {"n": number}
        mapping["self"] = mapping
        self.assertEqual(printed(mapping), "{'n': %s, 'self': {...}}" % hex(number))


if __name__ == "__main__":
    unittest.main()
