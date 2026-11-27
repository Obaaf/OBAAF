"""Flagship slice 2d.20a (#401): a value put into a local action's text never joins the text around it into an
expression.

The second pass (slice 2d.4b2) reads a local composite action's steps as the job's own, with the caller's `with:` put
into the action's text (`_inputs_put_in`). GitHub works the action's template out once, so a value put in is text and
never starts an expression: in `# ${{ inputs.a }}{{ x` given `$`, the `{{` the action writes stays text, and bash
runs the lines after it. The second pass's text was `# ${{ x`, which every reader of the text after it takes for an
expression, up to the next `}}`: a `claude ${{ env.F }} -p hi` or `npm install -g @anthropic-ai/claude-code` on the
next line was inside it, so OBAAF-GHA-026 and OBAAF-GHA-025 said nothing where GitHub runs both. Slice 2d.19f
refused such a line for its own reading (`_given_text`) and fell back to the second pass's text.

Now a value that would join the text around it into `${{` (a `$` before `{{`, `${` before `{`, a `$` and a `{{` from
two values or from the action's folder) is written as an expression that gives it, `${{ '$' }}`, in the second
pass's text and in 2d.19f's lines, so no reader finds an expression GitHub does not; and a text the checker cannot
build so is an error of the check.
"""

import random
import re
import unittest

from helpers import TempDir
from test_local_composite_actions import check

from obaaf import checker as checker_mod
from obaaf.checker import env_expr, expr as expr_mod

SKIP = "--dangerously-skip-permissions"
HIGH_026 = ("OBAAF-GHA-026", "high", "command-option")
ACTION = ".github/actions/x/action.yml"
RULES = ("OBAAF-GHA-025", "OBAAF-GHA-026")


def composite(script, inputs="a: {required: false}, b: {required: false}"):
    """An action with one bash step whose `run` is `script`, a block scalar."""
    return ("inputs: {" + inputs + "}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n"
            + "".join(f"        {line}\n" for line in script.split("\n")))


def caller(with_, env=f"F: {SKIP}", path="./.github/actions/x"):
    """A workflow whose job holds a model key, sets `env` and uses the action at `path` with `with_`."""
    return ("on: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    permissions: {contents: read}\n"
            "    env:\n      ANTHROPIC_API_KEY: ${{ secrets.K }}\n      " + env + "\n    steps:\n"
            f"      - uses: {path}\n" + (f"        with: {with_}\n" if with_ else ""))


def found(action_text, workflow_text, action_path=ACTION):
    """(rule, severity, kind) of each OBAAF-GHA-025 and 026 finding, and the check's errors."""
    with TempDir() as tmp:
        result = check(tmp, workflow_text, files={action_path: action_text})
    return (sorted((f.rule, f.severity, f.kind) for f in result.findings if f.rule in RULES),
            list(result.errors))


class AValueNeverStartsAnExpressionTest(unittest.TestCase):
    """The ways a value put in could join the text around it into `${{`, each read as GitHub reads it."""

    AGENT = "claude ${{ env.F }} -p hi"

    def test_the_oracle(self):
        # The line written out in the action, and the line with no comment before it.
        self.assertEqual(found(composite(f"claude {SKIP} -p hi"), caller("")), ([HIGH_026], []))
        self.assertEqual(found(composite(self.AGENT), caller("{a: $}")), ([HIGH_026], []))

    def test_the_issues_case(self):
        # #401's case: the base gave no OBAAF-GHA-026 finding.
        self.assertEqual(found(composite(f"# ${{{{ inputs.a }}}}{{{{ x\n{self.AGENT}"), caller("{a: $}")),
                         ([HIGH_026], []))

    def test_each_way_to_join(self):
        for name, first_line, with_ in (
                ("a value ending in `${` before `{`", "# ${{ inputs.a }}{ x", "{a: '${'}"),
                ("text ending in `$` before a value starting `{{`", "# $${{ inputs.a }} x", "{a: '{{'}"),
                ("a value `{` between `$` and `{`", "# $${{ inputs.a }}{ x", "{a: '{'}"),
                ("two values, `$` and `{{`", "# ${{ inputs.a }}${{ inputs.b }} x", "{a: $, b: '{{'}"),
                ("an empty value between `$` and `{{`", "# $${{ inputs.a }}{{ x", "{a: ''}"),
                ("an input no caller gives", "# $${{ inputs.zz }}{{ x", "{a: x}"),
                ("in any letter case", "# ${{ INPUTS.A }}{{ x", "{a: $}"),
                ("by index", "# ${{ inputs['a'] }}{{ x", "{a: $}")):
            with self.subTest(name):
                self.assertEqual(found(composite(f"{first_line}\n{self.AGENT}"), caller(with_)),
                                 ([HIGH_026], []))

    def test_a_default(self):
        action_text = composite(f"# ${{{{ inputs.d }}}}{{{{ x\n{self.AGENT}", inputs="d: {default: $}")
        self.assertEqual(found(action_text, caller("")), ([HIGH_026], []))

    def test_the_actions_folder(self):
        # `uses: ./a$` puts `./a$` in for `${{ github.action_path }}`, and its `$` joins the `{{` after it.
        action_text = composite(f"# ${{{{ github.action_path }}}}{{{{ x\n{self.AGENT}")
        self.assertEqual(found(action_text, caller("", path="./a$"), action_path="a$/action.yml"),
                         ([HIGH_026], []))

    def test_a_join_hides_an_install_too(self):
        # OBAAF-GHA-025 reads the second pass's text as well: the install was inside the joined expression.
        script = "claude -p hi\n# ${{ inputs.a }}{{ x\nnpm install -g @anthropic-ai/claude-code\necho ${{ github.sha }}"
        plain = script.replace("# ${{ inputs.a }}{{ x\n", "")
        expected = found(composite(plain), caller("{a: $}", env="F: x"))
        self.assertIn("OBAAF-GHA-025", [rule for rule, _, _ in expected[0]])
        self.assertEqual(found(composite(script), caller("{a: $}", env="F: x")), expected)

    def test_what_github_runs_as_text_stays_text(self):
        # GitHub runs `claude ${{ env.F }} -p hi` as text, which bash stops at (a bad substitution): not high, and
        # read as written, "cannot tell" (2d.19f's case).
        self.assertEqual(found(composite("claude ${{ inputs.a }}{{ env.F }} -p hi"), caller("{a: $}")),
                         ([("OBAAF-GHA-026", "medium", "command-computed")], []))

    def test_no_join_is_read_as_before(self):
        # A value that joins nothing is put in as text, as before.
        self.assertEqual(found(composite("claude ${{ inputs.a }} -p hi"), caller(f"{{a: {SKIP}}}")),
                         ([HIGH_026], []))
        self.assertEqual(found(composite("# ${{ inputs.a }}{{ x\nclaude -p hi"), caller("{a: y}", env="F: x")),
                         ([], []))


# ------------------------------------------------------------------------------------------- the text itself
_EXPR_FORMS = ("inputs.a", "inputs.b", "INPUTS['b']", "github.action_path", "env.F", "github.sha")


def _github_reading(text, inputs, folder):
    """What GitHub's runner makes of `text`, a line of a composite action: each `${{ }}` worked out once, with an
    input's value, the action's folder, or a mark `\\x00<body>\\x00` for any other expression; None where an
    expression does not end or is not one of `_EXPR_FORMS` (the joined characters can make one GitHub refuses)."""
    parts = checker_mod._expression_parts(text)
    if parts is None:
        return None
    out = []
    for kind, body in parts:
        if kind == "text":
            out.append(body)
            continue
        if body.strip() not in _EXPR_FORMS:
            return None
        toks = expr_mod.tokens(body)
        words = [t for _, t in toks]
        if len(toks) == 3 and words[0].lower() == "inputs" and words[1] == ".":
            out.append(inputs.get(words[2].lower(), ""))
        elif len(toks) == 4 and words[0].lower() == "inputs" and words[1] == "[":
            out.append(inputs.get(words[2].lower(), ""))
        elif "".join(words).lower() == "github.action_path":
            out.append(f"./{folder}")
        else:
            out.append("\x00" + "".join(words) + "\x00")
    return "".join(out)


def _second_pass_reading(text):
    """The same of a text the second pass made: an expression that is one string literal gives its text, and any
    other is the same mark, by its tokens; None where a reader of the text would find an expression end otherwise
    than `env_expr.spans` does."""
    parts = checker_mod._expression_parts(text)
    if parts is None:
        return None
    if [(s, e) for s, e, _ in env_expr.spans(text)] != _spans_of(parts):
        return None
    out = []
    for kind, body in parts:
        if kind == "text":
            out.append(body)
            continue
        toks = expr_mod.tokens(body)
        if len(toks) == 1 and toks[0][0] == "str":
            out.append(toks[0][1])
        else:
            out.append("\x00" + "".join(t for _, t in toks).strip("()") + "\x00")
    return "".join(out)


def _spans_of(parts):
    out, at = [], 0
    for kind, body in parts:
        length = len(body) if kind == "text" else len(body) + 5
        if kind == "expr":
            out.append((at, at + length))
        at += length
    return out


class TheSecondPassTextIsWhatGitHubRunsTest(unittest.TestCase):
    """A property: for texts made of the characters that join (`$`, `{`, `}`, `'`) around inputs, the action's
    folder and other expressions, the second pass's text reads, expression by expression, as GitHub runs it."""

    def test_random_texts(self):
        rng = random.Random(401)
        alphabet = ["$", "{", "}", "'", "x", " ", "\n", "{{", "}}", "$$"]
        tried = 0
        for _ in range(3000):
            pieces = []
            for _ in range(rng.randint(1, 6)):
                if rng.random() < 0.45:
                    pieces.append("${{ " + rng.choice(_EXPR_FORMS) + " }}")
                else:
                    pieces.append("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 3))))
            text = "".join(pieces)
            inputs = {name: "".join(rng.choice(["$", "{", "}", "'", "x", ""]) for _ in range(rng.randint(0, 3)))
                      for name in ("a", "b")}
            # A caller cannot hand a value holding `${{` (GitHub reads it as an expression in the caller).
            if any(expr_mod.OPEN in value for value in inputs.values()):
                continue
            folder = rng.choice(["a", "a$", "a${", "{a", "a'"])
            expected = _github_reading(text, inputs, folder)
            if expected is None:
                continue
            tried += 1
            with self.subTest(text=text, inputs=inputs, folder=folder):
                made = checker_mod._inputs_put_in(text, inputs, folder, [], {})
                self.assertEqual(_second_pass_reading(made), expected)
                given = checker_mod._given_text(text, inputs, folder, {"check": {}})
                if given is not None:
                    self.assertEqual(_second_pass_reading(given), expected)
        self.assertGreater(tried, 1500)

    def test_an_ordinary_text_is_unchanged(self):
        # Texts with no join are made as before: values as text, other expressions as written.
        for text, inputs, made in (
                ("claude ${{ inputs.a }} -p hi", {"a": "--x"}, "claude --x -p hi"),
                ("cd ${{ github.action_path }} && ${{ env.F }}", {}, "cd ./f && ${{ env.F }}"),
                ("echo ${{inputs.a}}${{ github.sha }}", {"a": "$"}, "echo $${{ github.sha }}"),
                ("echo ${{ inputs.a }}{x}", {"a": "$"}, "echo ${x}"),
                ("echo ${{ format('{0}', inputs.a) }}", {"a": "y"}, "echo ${{ format('{0}','y') }}")):
            with self.subTest(text):
                self.assertEqual(checker_mod._inputs_put_in(text, inputs, "f", [], {}), made)

    def test_a_join_is_an_expression_that_gives_the_value(self):
        self.assertEqual(checker_mod._inputs_put_in("# ${{ inputs.a }}{{ x", {"a": "$"}, "f", [], {}),
                         "# ${{ '$' }}{{ x")
        self.assertEqual(checker_mod._inputs_put_in("# ${{ inputs.a }}{{ x", {"a": "it's $"}, "f", [], {}),
                         "# ${{ 'it''s $' }}{{ x")
        # Only the values in a join; the others stay text.
        self.assertEqual(checker_mod._inputs_put_in("${{ inputs.b }} ${{ inputs.a }}{{", {"a": "$", "b": "y"},
                                                    "f", [], {}), "y ${{ '$' }}{{")


if __name__ == "__main__":
    unittest.main()
