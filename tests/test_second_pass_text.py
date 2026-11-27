"""Flagship slice 2d.20a (#401): a value put into a local action's text never joins the text around it into an
expression.

The second pass (slice 2d.4b2) reads a local composite action's steps as the job's own, with the caller's `with:` put
into the action's text (`_inputs_put_in`). GitHub works the action's template out once, so a value put in is text and
never starts an expression: in `# ${{ inputs.a }}{{ x` given `$`, the `{{` the action writes stays text, and bash
runs the lines after it. The second pass's text was `# ${{ x`, which every reader of the text after it takes for an
expression, up to the next `}}`: a `claude ${{ env.F }} -p hi` or `npm install -g @anthropic-ai/claude-code` on the
next line was inside it, so OBAAF-GHA-026 and OBAAF-GHA-025 said nothing where GitHub runs both. Slice 2d.19f
refused such a line for its own reading (`_given_text`) and fell back to the second pass's text.

Now the characters of a value that would join the text around it into `${{` (a `$` before `{{`, `${` before `{`, a
`$` and a `{{` from two values or from the action's folder) are written as an expression that gives them,
`${{ '$' }}`, in the second pass's text and in 2d.19f's lines, and the rest of the value stays text, so no reader
finds an expression GitHub does not and every rule reads the value as GitHub runs it; a text the checker cannot build
so is an error of the check.
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

    def test_the_rest_of_a_joined_value_is_read(self):
        # The first review: the whole value written as an expression hid what it holds. Only the `$` is.
        option = composite("claude ${{ inputs.a }}{{ x")
        self.assertEqual(found(option, caller(f"{{a: '{SKIP} #$'}}", env="F: x")), ([HIGH_026], []))
        install = "${{ inputs.a }}{{ x\nclaude -p hi"
        for name, script, with_ in (
                ("a value ending in `$`", install, "{a: 'npm install -g @anthropic-ai/claude-code #$'}"),
                ("a value ending in `${`", install.replace("}}{{ x", "}}{ x"),
                 "{a: 'npm install -g @anthropic-ai/claude-code #${'}"),
                ("a value starting `{{`", "echo '$${{ inputs.a }}\nclaude -p hi",
                 '{a: "{{ x\'; npm install -g @anthropic-ai/claude-code #"}')):
            with self.subTest(name):
                self.assertIn(("OBAAF-GHA-025", "high", "agent-cli"),
                              found(composite(script), caller(with_, env="F: x"))[0])

    def test_a_joined_value_handed_on_to_a_further_local_action(self):
        # The second review: the outer action hands `${{ inputs.a }}{{ x` on to a further local action; the second
        # pass's `with:` value `... #${{ '$' }}{{ x` was read there as `format()`, which hid what the value holds.
        outer = ("inputs: {a: {required: false}}\nruns:\n  using: composite\n  steps:\n"
                 "    - uses: ./.github/actions/y\n      with:\n        b: \"${{ inputs.a }}{{ x\"\n")
        for name, inner_run, value, expected in (
                ("an option", "claude ${{ inputs.b }} -p hi", f"{SKIP} #$", HIGH_026),
                ("an install", "${{ inputs.b }}\n        claude -p hi", "npm install -g @anthropic-ai/claude-code #$",
                 ("OBAAF-GHA-025", "high", "agent-cli"))):
            inner = ("inputs: {b: {required: false}}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n"
                     f"      run: |\n        {inner_run}\n")
            with self.subTest(name), TempDir() as tmp:
                result = check(tmp, caller(f"{{a: '{value}'}}", env="F: x"),
                               files={ACTION: outer, ".github/actions/y/action.yml": inner})
                self.assertIn(expected, [(f.rule, f.severity, f.kind) for f in result.findings])
                self.assertEqual(list(result.errors), [])

    def test_a_string_handed_as_an_expression_is_its_text(self):
        # What the second review's fix also reads: a caller's `${{ '...' }}` is the text it gives, as GitHub hands it.
        self.assertEqual(found(composite("claude ${{ inputs.a }} -p hi"), caller(f"{{a: \"${{{{ '{SKIP}' }}}}\"}}")),
                         ([HIGH_026], []))

    def test_a_string_handed_as_an_expression_beside_an_env_expression(self):
        # The third review: 2d.19f's own reading of the line (`_caller_inputs`) took such a value for one it does not
        # work out, so a line that also reads `env` stayed "cannot tell".
        action_text = composite("claude ${{ inputs.a }} ${{ env.F }} -p hi")
        self.assertEqual(found(action_text, caller(f"{{a: \"${{{{ '{SKIP}' }}}}\"}}", env="F: --verbose")),
                         ([HIGH_026], []))
        self.assertEqual(found(action_text, caller("{a: \"${{ '--model sonnet' }}\"}", env="F: --verbose")),
                         ([], []))

    def test_a_reusable_workflows_inputs_are_read_as_before(self):
        # The third review: what a calling job hands a reusable workflow makes the words a baseline entry matches, so
        # a string written as an expression stays the expression it was there.
        self.assertEqual(checker_mod._caller_value_tokens("${{ '--x' }}"), [("op", "("), ("str", "--x"), ("op", ")")])
        self.assertEqual(checker_mod._value_tokens("${{ '--x' }}", literals=True), [("str", "--x")])

    def test_a_joined_value_holding_a_close_reads_no_quote_wrongly(self):
        # The first review: `}}$` written whole as `${{ '}}$' }}` was ended at its `}}` by the readers that do not
        # know strings, which then read an unclosed quote (an extra medium). Only the `$` is an expression now.
        action_text = composite(f"echo '${{{{ inputs.a }}}}{{{{ x'\nclaude {SKIP} -p hi")
        self.assertEqual(found(action_text, caller("{a: '}}$'}", env="F: x")), ([HIGH_026], []))

    def test_a_join_no_longer_makes_an_expression_github_never_works_out(self):
        # The other way: on the base the joined text read `# ${{ github.event.issue.title }}`, an outsider's text put
        # into the script (OBAAF-GHA-010, high), where GitHub runs the comment as text.
        action_text = composite("# ${{ inputs.a }}{{ github.event.issue.title }}\necho hi")
        workflow_text = ("on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n"
                         "      - uses: ./.github/actions/x\n        with: {a: $}\n")
        with TempDir() as tmp:
            result = check(tmp, workflow_text, files={ACTION: action_text})
        self.assertEqual([f for f in result.findings if f.rule == "OBAAF-GHA-010"], [])
        self.assertEqual(list(result.errors), [])

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


_NAIVE_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)


def _second_pass_reading(text):
    """The same of a text the second pass made: an expression that is one string literal gives its text, and any
    other is the same mark, by its tokens; None where a reader of the text would find an expression end otherwise
    than `env_expr.spans` does, whether it knows strings or not (`rules._EXPRESSION_RE`), or where a literal holds
    anything but `$` and `{`, the characters of a `${{` (the rest of a value must stay text, for the rules to read)."""
    parts = checker_mod._expression_parts(text)
    if parts is None:
        return None
    spans = _spans_of(parts)
    if [(s, e) for s, e, _ in env_expr.spans(text)] != spans or [m.span() for m in _NAIVE_RE.finditer(text)] != spans:
        return None
    out = []
    for kind, body in parts:
        if kind == "text":
            out.append(body)
            continue
        toks = expr_mod.tokens(body)
        if len(toks) == 1 and toks[0][0] == "str" and body.strip().startswith("'"):
            if set(toks[0][1]) - set("${"):
                return None
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

    def test_texts_made_to_join(self):
        # The first review found that the random texts above join in about one case in seventy: these are built so
        # that most do, with empty values, values on both sides of a `${{` and the action's folder among them.
        rng = random.Random(2020)
        ends, heads = ["", "$", "${", "x$", "$$", "'$"], ["", "{", "{{", "{ x", "{{ x }}", "}"]
        values = ["$", "${", "{", "{{", "", "a$", "{b", "$$", "}}$", "'$", "--yolo #$", "{{$", "{{${", "{$"]
        joins = 0
        for _ in range(3000):
            text = rng.choice(ends)
            for _ in range(rng.randint(1, 4)):
                text += "${{ " + rng.choice(("inputs.a", "inputs.b", "github.action_path", "env.F")) + " }}"
                text += rng.choice(heads) + rng.choice(["", "\n", " "]) + rng.choice(ends)
            inputs = {"a": rng.choice(values), "b": rng.choice(values)}
            folder = rng.choice(["a", "a$", "a${"])
            expected = _github_reading(text, inputs, folder)
            if expected is None:
                continue
            made = checker_mod._inputs_put_in(text, inputs, folder, [], {})
            joins += "${{ '" in made
            with self.subTest(text=text, inputs=inputs, folder=folder):
                self.assertEqual(_second_pass_reading(made), expected)
                given = checker_mod._given_text(text, inputs, folder, {"check": {}})
                self.assertIsNotNone(given)
                self.assertEqual(_second_pass_reading(given), expected)
        self.assertGreater(joins, 1000)

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
        # Only the characters in the `${{`; the rest of the value, and the other values, stay text.
        self.assertEqual(checker_mod._inputs_put_in("# ${{ inputs.a }}{{ x", {"a": "it's $"}, "f", [], {}),
                         "# it's ${{ '$' }}{{ x")
        self.assertEqual(checker_mod._inputs_put_in("${{ inputs.b }} ${{ inputs.a }}{{", {"a": "$", "b": "y"},
                                                    "f", [], {}), "y ${{ '$' }}{{")
        self.assertEqual(checker_mod._inputs_put_in("# $${{ inputs.a }} x", {"a": "{{ y"}, "f", [], {}),
                         "# $${{ '{{' }} y x")
        self.assertEqual(checker_mod._inputs_put_in("# $${{ inputs.a }}{{ x", {"a": ""}, "f", [], {}),
                         "# $${{ '' }}{{ x")
        self.assertEqual(checker_mod._inputs_put_in("${{ github.action_path }}{{", {}, "a$", [], {}),
                         "./a${{ '$' }}{{")


if __name__ == "__main__":
    unittest.main()
