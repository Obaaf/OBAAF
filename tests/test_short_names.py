"""Flagship slice 2d.23 (#388): a tool is named where its name stands as a name, not where its letters do.

OBAAF-GHA-026 says "cannot tell" for what the checker cannot read in a step only where the step names the agent
tool. In code that is not read as bash (PowerShell, cmd, interpreters, github-script) the readers were told the
tool was named wherever its letters stood in any word (`appears`, a test for a substring), so a short name was
named almost everywhere: Continue's program is `cn`, found in `'acne'`, `$cnt = 1`, `-cne` and `example.cn`, and
Cline's program and package are `cline`, found in `decline`. A PowerShell step with one of them and a bracket left
open at a line's end (`$x = (`) was a medium OBAAF-GHA-026 for Continue, and a medium gate failed.

Now a "cannot tell" that turns on the tool being named asks `mentions` or `names`: the program's name, or a plain
package's, must stand as a name of its own, not inside another word and not as one label of a dotted name
(`edu.cn`, `cn.archive.ubuntu.com`), unless a suffix Windows runs follows it (`cn.exe`). `names` also takes a part
of a variable's name (`$CLAUDE_BIN`, `$env:CN_BIN`) and `${CMD:-claude}`, as the substring test did; a backslash is
read as a folder's separator as well as an escape (`C:\\tools\\cn.exe`). Where the tool is named, what the checker
cannot read stays "cannot tell": a bracket left open, `& $exe`, `%C%`, an unclosed string, `IFS=`.
"""

import random
import unittest

from helpers import TempDir
from test_local_composite_actions import check

from obaaf.checker import agent_flags

CN = (["cn"], ["@continuedev/cli"])
CLINE = (["cline"], ["cline"])
CLAUDE = (["claude"], ["@anthropic-ai/claude-code"])
CANNOT_TELL = ("medium", "command-computed")
SKIP = "--dangerously-skip-permissions"


def findings(script, shell="bash", env=None):
    """(severity, kind, program) of each OBAAF-GHA-026 finding of a job whose one step runs `script` in `shell`
    (`github-script` for an `actions/github-script` step)."""
    if shell == "github-script":
        body = "".join(f"            {line}\n" for line in script.split("\n"))
        step = ("      - uses: actions/github-script@" + "a" * 40 + "\n        with:\n          script: |\n" + body)
    else:
        body = "".join(f"          {line}\n" for line in script.split("\n"))
        step = f"      - shell: {shell}\n        run: |\n{body}"
    if env:
        step += "        env:\n" + "".join(f"          {k}: '{v}'\n" for k, v in env.items())
    text = ("on: workflow_dispatch\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n" + step)
    with TempDir() as tmp:
        result = check(tmp, text)
    return (sorted((f.severity, f.kind, f.facts.get("program")) for f in result.findings
                   if f.rule == "OBAAF-GHA-026"), list(result.errors))


class TheIssuesCaseTest(unittest.TestCase):

    OPEN = "$x = (\n1\n)"

    def test_the_issues_reproduction(self):
        # #388: on `84280c9`, one medium OBAAF-GHA-026 for Continue.
        self.assertEqual(findings("'acne'\n" + self.OPEN, "pwsh"), ([], []))

    def test_each_form_the_issue_names(self):
        for line in ("'acne'", "$cnt = 1", "Resolve-DnsName example.cn", "if ('a' -cne 'b') { 1 }"):
            with self.subTest(line):
                self.assertEqual(findings(line + "\n" + self.OPEN, "pwsh"), ([], []))

    def test_the_other_short_names(self):
        # Cline's program and package (`decline`), Kilo Code's `kilo` (`kilobyte`).
        for line in ("'decline'", "'incline'", "Write-Host 'kilobyte'"):
            with self.subTest(line):
                self.assertEqual(findings(line + "\n" + self.OPEN, "pwsh"), ([], []))

    def test_cmd_and_other_languages(self):
        cases = [
            ("cmd", "echo acne\n%X% --foo"),
            ("cmd", "echo pypi.tuna.tsinghua.edu.cn\n%X% --foo"),
            ("pwsh", "'acne'\nWrite-Host \"a string that does not end"),
            ("python", "print('acne')\nx = 'a string that does not end"),
            ("github-script", "core.info('acne'); const x = `a string that does not end"),
        ]
        for shell, script in cases:
            with self.subTest(shell=shell, script=script):
                self.assertEqual(findings(script, shell), ([], []))

    def test_bash_too(self):
        # The same class in bash: a word of a dotted name, a variable's name with the letters inside it, an alias
        # whose value holds them, `IFS=` beside them.
        for script in ("pip install -i https://pypi.tuna.tsinghua.edu.cn/simple x\n$CMD y",
                       "sed -i 's/archive.ubuntu.com/cn.archive.ubuntu.com/' /etc/apt/sources.list\n$CMD y",
                       "echo example.cn\n$X --foo", '"$CNT" x', '"$ACNE" x', "alias x='echo acne'\nx $f",
                       "echo acne\nIFS=,", 'echo "decline the change"\n$X --foo'):
            with self.subTest(script):
                self.assertEqual(findings(script), ([], []))


class WhereTheToolIsNamedTest(unittest.TestCase):
    """What the checker cannot read stays "cannot tell" where the step names the tool."""

    def assert_cannot_tell(self, script, shell="bash", program="continue", env=None):
        got, errors = findings(script, shell, env)
        self.assertEqual(errors, [])
        self.assertIn(CANNOT_TELL + (program,), got)

    def test_powershell(self):
        for script in ("cn -p hi\n$x = (\n1\n)", "$x = (\n1\n)\ncn -p x", "# run cn\n$x = (\n1\n)",
                       "cn $flags -p x", "cn -p hi\n& $exe -x", "& $env:CN_BIN $flags",
                       "$p = 'C:\\tools\\cn.exe'\n$q = $p\n& $q --auto", "$p = \"C:\\tools\\cn.exe\"\n$q = $p\n& $q --auto",
                       "& \"$dir\\cn.exe\" $flags", "& $dir\\cn.exe $flags", "& ((Get-Command cn).Source) --auto",
                       "$q = Get-Command cn\n& $q --auto", "cn -p hi\nWrite-Host \"a string that does not end"):
            with self.subTest(script):
                self.assert_cannot_tell(script, "pwsh")

    def test_cmd(self):
        for script in ("cn -p hi\n%X% --foo", "%TOOLS%\\bin\\cn.exe %F%"):
            with self.subTest(script):
                self.assert_cannot_tell(script, "cmd")

    def test_bash(self):
        for script, program in (('"$CLAUDE_BIN" $flags', "claude-code"), ('"$CN_BIN" $flags', "continue"),
                                ("A=cl; B=aude\nIFS=,\n$A$B -p x", "claude-code"),
                                ("A=cl; B=aude\n$A$B $FLAGS -p x", "claude-code"), ("cn -p hi\n$X --foo", "continue"),
                                ('"${CMD:-claude}" $flags', "claude-code"), ("alias c='cl''aude'\nc $f", "claude-code")):
            with self.subTest(script):
                self.assert_cannot_tell(script, program=program)

    def test_a_name_in_the_steps_env(self):
        self.assert_cannot_tell("IFS=,\n$T -p x", env={"T": "claude"}, program="claude-code")

    def test_a_warned_option_is_still_a_match(self):
        for shell, script in (("pwsh", f"& 'C:\\tools\\claude.exe' {SKIP} -p x"), ("cmd", "cn.exe --auto -p x"),
                              ("pwsh", "'acne'\ncn --auto -p x"), ("bash", "echo edu.cn\ncn --auto -p x")):
            with self.subTest(shell=shell, script=script):
                got, errors = findings(script, shell)
                self.assertEqual(errors, [])
                self.assertTrue(any(kind == "command-option" for _sev, kind, _p in got), got)


class TheTestsThemselvesTest(unittest.TestCase):
    """`mentions` and `names` on their own."""

    def test_not_inside_a_word(self):
        for text in ("'acne'", "$cnt = 1", "-cne", "picnic", "cnx", "xcn", "cn-wrapper"):
            with self.subTest(text):
                self.assertFalse(agent_flags.mentions(text, *CN))
                self.assertFalse(agent_flags.names(text, *CN))
        for text in ("decline", "incline", "clines", "cline-x"):
            with self.subTest(text):
                self.assertFalse(agent_flags.mentions(text, *CLINE))
                self.assertFalse(agent_flags.names(text, *CLINE))

    def test_not_a_label_of_a_dotted_name(self):
        for text in ("example.cn", "pypi.tuna.tsinghua.edu.cn/simple", "cn.archive.ubuntu.com", "x.cn.exe",
                     "https://mirrors.example.cn"):
            with self.subTest(text):
                self.assertFalse(agent_flags.mentions(text, *CN))
                self.assertFalse(agent_flags.names(text, *CN))
        for text in ("~/.claude.json", "claude.ai", "settings.claude"):
            with self.subTest(text):
                self.assertFalse(agent_flags.mentions(text, *CLAUDE))

    def test_named(self):
        for text in ("cn", "cn -p x", "'cn'", "cn.exe", "CN.EXE", "cn.cmd", "cn.ps1", "cn.", "./cn", ".\\cn",
                     "C:\\tools\\cn.exe", "$dir\\cn.exe", "(Get-Command cn).Source", "/usr/local/bin/cn",
                     "npx @continuedev/cli", "x@continuedev/cliy", "c''n", "c\\n", "$'\\x63n'", "$(cn)", "&cn",
                     "${dir}cn", "cn@1"):
            with self.subTest(text):
                self.assertTrue(agent_flags.mentions(text, *CN))
                self.assertTrue(agent_flags.names(text, *CN))
        for text in ("npm i -g cline@1.2", "npx cline", "node_modules/cline/bin"):
            with self.subTest(text):
                self.assertTrue(agent_flags.mentions(text, *CLINE))

    def test_a_part_of_a_name(self):
        # A `-` before it is an edge for `names` (`${CMD:-claude}`), so `my-cn` is a part of a name there.
        for text, tool in (("$CLAUDE_BIN", CLAUDE), ("$env:CN_BIN", CN), ("${CMD:-claude}", CLAUDE),
                           ("MY_CLAUDE", CLAUDE), ("cn_path", CN), ("my-cn", CN)):
            with self.subTest(text):
                self.assertFalse(agent_flags.mentions(text, *tool))
                self.assertTrue(agent_flags.names(text, *tool))

    def test_names_takes_all_that_mentions_takes(self):
        # A property: on random texts made of the name, letters, digits and the characters around names.
        rng = random.Random(388)
        pieces = ["cn", "claude", "cline", "a", "Z", "9", "_", "-", "@", ".", "/", "\\", "'", '"', " ", "$", "{",
                  "}", ":", "exe", "e", "$'\\x63'", "(", ")", "=", "\n"]
        for _ in range(3000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
            for tool in (CN, CLAUDE, CLINE):
                if agent_flags.mentions(text, *tool):
                    self.assertTrue(agent_flags.names(text, *tool), (text, tool))
                if agent_flags.names(text, *tool):
                    self.assertTrue(agent_flags.appears(text, *tool) or "\\" in text, (text, tool))


if __name__ == "__main__":
    unittest.main()
