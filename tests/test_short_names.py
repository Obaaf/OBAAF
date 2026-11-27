"""Flagship slice 2d.23 (#388): a tool is named where its name stands as a name, not where its letters do.

OBAAF-GHA-026 says "cannot tell" for what the checker cannot read in a step only where the step names the agent
tool. In code that is not read as bash (PowerShell, cmd, interpreters, github-script) the readers were told the
tool was named wherever its letters stood in any word (`appears`, a test for a substring), so a short name was
named almost everywhere: Continue's program is `cn`, found in `'acne'`, `$cnt = 1`, `-cne` and `example.cn`, and
Cline's program and package are `cline`, found in `decline`. A PowerShell step with one of them and a bracket left
open at a line's end (`$x = (`) was a medium OBAAF-GHA-026 for Continue, and a medium gate failed.

Now a "cannot tell" that turns on the step naming the tool asks `mentions` or `names`. In `mentions` the program's
name, or a plain package's, must stand as a word, as before; a name of two letters, a country's domain as well,
is not one label of a dotted name (`edu.cn`, `cn.archive.ubuntu.com`) unless a suffix Windows or node runs follows
(`cn.exe`, `cn.mjs`), and GitHub's expressions and a variable's properties are not dotted names
(`${{ steps.cn.outputs.bin }}`). `names` also takes a part of a variable's name (`$CN_BIN`, `$cnPath`,
`${CMD:-cn}`), and a name of six letters or more anywhere, as the substring test did. A backslash is read as a
folder's separator as well as an escape (`C:\\tools\\cn.exe`). The command word the checker cannot name is still
tested for the letters anywhere (`"$CLAUDEBIN"`, `& $claudeExe`). Where the tool is named, what the checker
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
        # The same class in bash: a label of a dotted name (two letters are a country's domain), an alias whose
        # value holds the letters, `IFS=` beside them, a locale or an AWS region.
        for script in ("pip install -i https://pypi.tuna.tsinghua.edu.cn/simple x\n$CMD y",
                       "sed -i 's/archive.ubuntu.com/cn.archive.ubuntu.com/' /etc/apt/sources.list\n$CMD y",
                       "echo example.cn\n$X --foo", "alias x='echo acne'\nx $f", "echo acne\nIFS=,",
                       'echo "decline the change"\n$X --foo', "export LANG=zh_CN.UTF-8\nIFS=,",
                       "aws s3 ls --region cn-north-1\n$X y", "echo zh-CN\n$X y"):
            with self.subTest(script):
                self.assertEqual(findings(script), ([], []))

    def test_the_word_of_a_command_the_checker_cannot_name(self):
        # There the letters in the word itself still decide, as before (the review): a variable named for the tool
        # may hold it. So `"$CNT" x`, a command named by `$CNT`, stays "cannot tell" for Continue.
        for script in ('"$CNT" x', '"$ACNE" x'):
            with self.subTest(script):
                self.assertEqual(findings(script), ([CANNOT_TELL + ("continue",)], []))


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
                       "$q = Get-Command cn\n& $q --auto", "cn -p hi\nWrite-Host \"a string that does not end",
                       "$cnPath = $env:INPUT_PATH\n& $cnPath --auto", "& $tools.cn $flags"):
            with self.subTest(script):
                self.assert_cannot_tell(script, "pwsh")
        for script in ("$claudeExe = Join-Path $env:RUNNER_TOOL_CACHE 'agent\\bin\\agent.exe'\n& $claudeExe -p x",
                       "& ('xclaude'.Substring(1)) -p x", "& ('claudeX' -replace 'X','') -p x",
                       "& $node \"$env:APPDATA\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js\" $flags"):
            with self.subTest(script):
                self.assert_cannot_tell(script, "pwsh", "claude-code")

    def test_cmd(self):
        for script in ("cn -p hi\n%X% --foo", "%TOOLS%\\bin\\cn.exe %F%"):
            with self.subTest(script):
                self.assert_cannot_tell(script, "cmd")
        self.assert_cannot_tell("%CLAUDEEXE% -p x", "cmd", "claude-code")
        self.assert_cannot_tell("set C=xclaude\n%C:~1% -p x", "cmd", "claude-code")

    def test_a_long_name_built_from_pieces(self):
        # A name of six letters or more counts anywhere, as before: the review's pieces glued to other letters.
        self.assert_cannot_tell("$t = 'xclaude'.Substring(1)\n& $t -p x", "pwsh", "claude-code")
        self.assert_cannot_tell("X=$(npm root -g)\nnode \"$X/cn.mjs\" --auto")

    def test_bash(self):
        for script, program in (('"$CLAUDE_BIN" $flags', "claude-code"), ('"$CN_BIN" $flags', "continue"),
                                ("A=cl; B=aude\nIFS=,\n$A$B -p x", "claude-code"),
                                ("A=cl; B=aude\n$A$B $FLAGS -p x", "claude-code"), ("cn -p hi\n$X --foo", "continue"),
                                ('"${CMD:-claude}" $flags', "claude-code"), ("alias c='cl''aude'\nc $f", "claude-code"),
                                ('"$claudeBin" -p x', "claude-code"), ("$CLAUDEBIN -p x", "claude-code"),
                                ("$CLAUDE2 -p x", "claude-code"), ("$(echo claudeX | tr -d X) -p x", "claude-code"),
                                ("$(echo xcn | cut -c2-) --auto", "continue"),
                                ("IFS=,\nset -- $claudeCmdline\n\"$@\"", "claude-code"),
                                ("curl -fsSL https://claude.ai/install.sh | bash\n\"$HOME/.local/bin/$AGENT\" -p x",
                                 "claude-code")):
            with self.subTest(script):
                self.assert_cannot_tell(script, program=program)

    def test_github_expressions(self):
        # The review's first way past: `steps.claude.outputs` and `${{ inputs.cn }}` read as dotted names.
        for script, program in (("${{ steps.claude.outputs.bin }} -p x", "claude-code"),
                                ("${{ needs.claude.outputs.bin }} $FLAGS", "claude-code"),
                                ("${{ inputs.cn }} $FLAGS", "continue"), ("${{ steps.cn.outputs.bin }} $FLAGS", "continue"),
                                ("alias c='${{ steps.claude.outputs.bin }}'\nc $f", "claude-code")):
            with self.subTest(script):
                self.assert_cannot_tell(script, program=program)
        self.assert_cannot_tell("& \"${{ steps.cn.outputs.bin }}\" $flags", "pwsh")
        self.assert_cannot_tell("IFS=,\nset -- $AGENT_CMD\n\"$@\"", program="claude-code",
                                env={"CLAUDE_CODE_OAUTH_TOKEN": "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}"})

    def test_a_name_in_the_steps_env(self):
        self.assert_cannot_tell("IFS=,\n$T -p x", env={"T": "claude"}, program="claude-code")
        # The review's second way past: another shell reads the step's `env` too, once its script is read.
        self.assert_cannot_tell("$claudeOpts = @('-p')\n& $env:AGENT @claudeOpts -x", "pwsh", "claude-code",
                                env={"AGENT": "claude"})
        self.assert_cannot_tell("# picnic\n& $env:AGENT --auto", "pwsh", env={"AGENT": "cn"})

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
        for text in ("decline", "incline", "clines"):
            with self.subTest(text):
                self.assertFalse(agent_flags.mentions(text, *CLINE))
                self.assertFalse(agent_flags.names(text, *CLINE))
        for text in ("zh-CN", "zh_CN", "my-cn", "arn:aws-cn:s3:::b", "cn-north-1", "cn2"):
            with self.subTest(text):
                self.assertFalse(agent_flags.names(text, *CN))

    def test_not_a_label_of_a_dotted_name(self):
        for text in ("example.cn", "pypi.tuna.tsinghua.edu.cn/simple", "cn.archive.ubuntu.com", "x.cn.exe",
                     "https://mirrors.example.cn"):
            with self.subTest(text):
                self.assertFalse(agent_flags.mentions(text, *CN))
                self.assertFalse(agent_flags.names(text, *CN))
        # Only a name of two letters, a country's domain as well: a longer one stays named in a dotted name, as before
        # (the review: `steps.claude.outputs`, `https://claude.ai/install.sh`, `nixpkgs.opencode`).
        for text in ("~/.claude.json", "claude.ai", "settings.claude", "steps.claude.outputs"):
            with self.subTest(text):
                self.assertTrue(agent_flags.mentions(text, *CLAUDE))
        # A GitHub expression's or a variable's property is not a dotted name.
        for text in ("${{ inputs.cn }}", "${{ steps.cn.outputs.bin }}", "$tools.cn", "${{ matrix.cn }}"):
            with self.subTest(text):
                self.assertTrue(agent_flags.mentions(text, *CN))
                self.assertTrue(agent_flags.names(text, *CN))

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
        self.assertTrue(agent_flags.mentions("%APPDATA%\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js",
                                             *CLAUDE))

    def test_a_part_of_a_name(self):
        for text, tool in (("$CLAUDE_BIN", CLAUDE), ("$env:CN_BIN", CN), ("${CMD:-claude}", CLAUDE),
                           ("cn_path", CN), ("$claudeBin", CLAUDE), ("$cnPath", CN), ("$CLAUDEBin", CLAUDE),
                           ("$CLAUDE2", CLAUDE), ("${claude-bin}", CLAUDE),
                           ("${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}", CLAUDE)):
            with self.subTest(text):
                self.assertFalse(agent_flags.mentions(text, *tool))
                self.assertTrue(agent_flags.names(text, *tool))

    def test_names_takes_all_that_mentions_takes(self):
        # A property: on random texts made of the name, letters, digits and the characters around names.
        rng = random.Random(388)
        pieces = ["cn", "claude", "cline", "CN", "Claude", "a", "Z", "B", "9", "_", "-", "@", ".", "/", "\\", "'",
                  '"', " ", "$", "{", "}", "${{ ", " }}", ":", "exe", "e", "$'\\x63'", "(", ")", "=", "\n", "steps."]
        for _ in range(3000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
            for tool in (CN, CLAUDE, CLINE):
                if agent_flags.mentions(text, *tool):
                    self.assertTrue(agent_flags.names(text, *tool), (text, tool))
                if agent_flags.names(text, *tool):
                    self.assertTrue(agent_flags.appears(text, *tool) or "\\" in text, (text, tool))


if __name__ == "__main__":
    unittest.main()
