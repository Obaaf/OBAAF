"""Flagship slice 2d.20b (#401, item 2): a warned option after an unclosed quote is "cannot tell", not a match.

Bash reads a script a command at a time and refuses the command whose quote never closes: it runs neither that
command nor any after it. OBAAF-GHA-026 read `claude '--dangerously-skip-permissions -p hi` as a run of claude with
the warned option (its second reading takes the quotes out), where bash stops at the quote and claude never starts;
the first reading already said "cannot tell" (an unclosed quote). A value a local action puts in can leave such a
quote (`claude ${{ inputs.a }}${{ env.F }} -p hi` given `'`), and so can a typing slip in a workflow's own step.

Now a warned option found only from the command that holds the unclosed quote on is "cannot tell". The commands
before it are read again on their own and keep their matches. A text that holds a `${{ }}` expression is read as
before: GitHub puts the expression's text in before bash reads the script, and it may hold the quote that closes
this one. So is a text with a command or process substitution or backticks (or `${` beside `$'`), whose reader may
take a closed quote for an unclosed one.
"""

import unittest

from helpers import TempDir
from test_local_composite_actions import check

from obaaf.catalog import load
from obaaf import agent_tools
from obaaf.checker import agent_flags

SKIP = "--dangerously-skip-permissions"
HIGH = ("high", "command-option")
CANNOT_TELL = ("medium", "command-computed")


def step_findings(script, env="", files=None, using=None):
    """(severity, kind) of each OBAAF-GHA-026 finding of a job that runs `script` in a bash step (or `using`)."""
    run = "".join(f"          {line}\n" for line in script.split("\n"))
    text = ("on: workflow_dispatch\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    permissions: {contents: read}\n"
            "    env:\n      ANTHROPIC_API_KEY: ${{ secrets.K }}\n" + (f"      {env}\n" if env else "") + "    steps:\n"
            + (using if using is not None else f"      - shell: bash\n        run: |\n{run}"))
    with TempDir() as tmp:
        result = check(tmp, text, files=files)
    return (sorted((f.severity, f.kind) for f in result.findings if f.rule == "OBAAF-GHA-026"),
            list(result.errors))


class AnUnclosedQuoteTest(unittest.TestCase):

    def test_the_oracle(self):
        self.assertEqual(step_findings(f"claude {SKIP} -p hi"), ([HIGH], []))

    def test_the_issues_case(self):
        # #401: GitHub runs `claude '--dangerously-skip-permissions -p hi`, which bash refuses. The base gave high.
        action = ("inputs: {a: {required: false}}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n"
                  "      run: claude ${{ inputs.a }}${{ env.F }} -p hi\n")
        using = "      - uses: ./.github/actions/x\n        with: {a: \"'\"}\n"
        self.assertEqual(step_findings("", env=f"F: {SKIP}", files={".github/actions/x/action.yml": action},
                                       using=using), ([CANNOT_TELL], []))

    def test_each_quote(self):
        for script in (f"claude '{SKIP} -p hi", f'claude "{SKIP} -p hi', f"claude $'{SKIP} -p hi",
                       f'claude $"{SKIP} -p hi', f"claude {SKIP} -p 'unclosed", f"echo 'oops\nclaude {SKIP} -p hi",
                       f"echo x | claude {SKIP} 'oops", f"echo 'oops; claude {SKIP} -p hi"):
            with self.subTest(script):
                self.assertEqual(step_findings(script), ([CANNOT_TELL], []))

    def test_what_runs_before_it_is_kept(self):
        for script in (f"claude {SKIP} -p hi\necho 'oops", f"claude {SKIP} -p hi; echo 'oops",
                       f"claude {SKIP} -p hi\necho ok\necho \"oops"):
            with self.subTest(script):
                self.assertEqual(step_findings(script), ([HIGH, CANNOT_TELL], []))

    def test_a_quote_that_is_not_one(self):
        # In a comment, a heredoc's text, a closed pair, or escaped: no unclosed quote, so the match stands.
        for script in (f"# it's\nclaude {SKIP} -p hi", f"cat <<EOF\n'\nEOF\nclaude {SKIP} -p hi",
                       f"echo 'a'\nclaude {SKIP} -p hi", f"echo it\\'s\nclaude {SKIP} -p hi",
                       f"echo \"it's\"\nclaude {SKIP} -p hi"):
            with self.subTest(script):
                self.assertEqual(step_findings(script), ([HIGH], []))

    def test_a_quote_the_reader_of_substitutions_may_misread(self):
        # The review: `_balanced` reads `$( )`, `${ }` and `<( )` without skipping a comment or reading `$'..\\'..'`
        # as bash does, so it may take a closed quote for an unclosed one. Bash runs the warned option in each; the
        # match stays (with the medium the lexer's misreading already gave on the base).
        line = f"claude {SKIP} -p hi"
        for script in (f'OUT="$(\n  # run claude, it\'s fine\n  {line}\n)"',
                       f'V="$(\n  # don\'t use the cache\n  echo 1.2.3\n)"\n{line}',
                       f'MODEL="${{MODEL:-$(\n  # pick the model that\'s cheapest\n  echo sonnet\n)}}"\n{line}',
                       f'V="$(\n  echo 1 # (one\n)"\n{line}',
                       f"X=$(\n  # step 1) don't cache\n  echo hi\n)\n{line}",
                       f'V="$(echo $\'it\\\'s\')"\n{line}',
                       f"V=`echo x`\necho 'oops\n{line}",
                       f"A=${{B:-$'it\\'s'}}\necho 'oops\n{line}"):
            with self.subTest(script):
                self.assertIn(HIGH, step_findings(script)[0])

    def test_an_expression_may_close_the_quote(self):
        # GitHub puts the expression's text in before bash reads the script: `'` there closes the quote, and claude runs.
        for script in ("echo '${{ github.event.issue.title }}\n" + f"claude {SKIP} -p hi",
                       "echo ${{ github.event.issue.title }}\necho 'oops\n" + f"claude {SKIP} -p hi"):
            with self.subTest(script):
                self.assertIn(HIGH, step_findings(script)[0])


class TheReaderTest(unittest.TestCase):
    """`agent_flags.read_script` itself: hits and "cannot tell" for the option."""

    @classmethod
    def setUpClass(cls):
        for tid, _name, flags, programs, packages, _args in agent_tools.flag_readers(load().detection):
            if tid == "claude-code":
                cls.flags, cls.programs, cls.packages = flags, programs, packages

    def read(self, text):
        reading = agent_flags.read_script(text, self.programs, self.packages, self.flags)
        return sorted(reading.hits), sorted(reading.unknown)

    def test_a_match_after_the_quote_is_cannot_tell(self):
        hits, unknown = self.read(f"claude '{SKIP} -p hi")
        self.assertEqual(hits, [])
        self.assertIn("skip-permissions", unknown)

    def test_the_command_before_it_stays_a_match(self):
        self.assertEqual(self.read(f"claude {SKIP} -p hi\necho 'x")[0], ["skip-permissions"])

    def test_one_list_is_cut_at_its_last_separator(self):
        # Bash refuses the whole list `claude ... && echo 'x`; the checker keeps the match before `&&` (stated).
        self.assertEqual(self.read(f"claude {SKIP} -p hi && echo 'x")[0], ["skip-permissions"])


if __name__ == "__main__":
    unittest.main()
