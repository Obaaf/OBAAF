"""Flagship slice 2d.5c2c: OBAAF-GHA-026 reads options built in code in another language.

The plan's entry for 2d.5c2c asks that code given to an interpreter (`python3 -c`, a heredoc fed to `node`,
`perl -e`, `ruby -e`, awk), a github-script script and another shell (pwsh, cmd) be read well enough that
an argument array held in a variable (`exec.exec('claude', flags)`), a shell string joined with a variable
(`os.system("claude " + os.environ["F"])`, `#{ENV["F"]}`, `$ENV{F}`) and an option built from pieces
(`"--" + "dangerously-skip-permissions"`, `"-" + "y"`) are "cannot tell", while a literal argument list
(`subprocess.run(["claude", "--version"])`) and a single variable in a prompt's place stay quiet. The code
here is written for these tests; none is copied from another project.

`hit` is a `command-option` finding (the option is found), `cannot` a `command-computed` one with no option
found, `none` nothing.
"""

import time
import unittest

from test_agent_tool_flags import check, kinds, run_step

from obaaf.checker import agent_code

DSP = "--dangerously-skip-permissions"
PIN = "b" * 40


def script_step(js):
    body = "\n".join("            " + line for line in js.split("\n"))
    return ("on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: actions/github-script@{PIN}\n        with:\n          script: |\n{body}\n")


def shell_step(shell, text, runner="ubuntu-latest"):
    body = "\n".join("          " + line for line in text.split("\n"))
    return ("on: push\npermissions: {contents: read}\njobs:\n  a:\n"
            f"    runs-on: {runner}\n    steps:\n      - shell: {shell}\n        run: |\n{body}\n")


def heredoc(interpreter, code):
    return f"{interpreter} <<'EOF'\n{code}\nEOF"


class Case(unittest.TestCase):
    def expect(self, cases, make=run_step):
        for text, want in cases:
            with self.subTest(text=text):
                got = kinds(check(make(text)))
                if want == "hit":
                    self.assertIn("command-option", got, text)
                elif want == "cannot":
                    self.assertEqual(got, ["command-computed"], text)
                else:
                    self.assertEqual(got, [], text)


class TheEntrysCasesTest(Case):
    """The cases the plan's entry names, each in every language it names."""

    def test_an_argument_array_held_in_a_variable(self):
        self.expect([
            ("await exec.exec('claude', flags)", "cannot"),
            ("await exec.getExecOutput('claude', args, {silent: true})", "cannot"),
            ("require('child_process').spawnSync('claude', process.argv.slice(2))", "cannot"),
            ("await exec.exec('claude', ['-p', prompt, ...extra])", "cannot"),
            ("await exec.exec('claude', ['-p', prompt].concat(extra))", "cannot"),
        ], make=script_step)
        self.expect([
            (heredoc("python3", "import subprocess, sys\nsubprocess.run(['claude', *sys.argv[1:]])"), "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude'] + flags)"), "cannot"),
            (heredoc("python3", "import os\nos.execvp('claude', args)"), "cannot"),
            (heredoc("python3", "import subprocess\ncmd = ['claude', '-p', p]\ncmd.extend(flags)\nsubprocess.run(cmd)"),
             "cannot"),
            (heredoc("python3", "import subprocess\ncmd = ['claude', '-p', p]\ncmd += flags\nsubprocess.run(cmd)"),
             "cannot"),
            (heredoc("node", "const {spawn} = require('child_process');\nspawn('claude', args, {stdio: 'inherit'});"),
             "cannot"),
            ("ruby -e 'system(\"claude\", *ARGV)'", "cannot"),
            ("ruby -e 'system \"claude\", *flags'", "cannot"),
            ("perl -e 'system(\"claude\", @ARGV)'", "cannot"),
            ("perl -e 'my @c = (\"claude\", \"-p\", \"x\"); push @c, @f; system @c'", "cannot"),
            ("php -r 'pcntl_exec(\"claude\", $argv);'", "cannot"),
            ("php -r 'proc_open([\"claude\", ...$flags], [], $pipes);'", "cannot"),
        ])

    def test_a_shell_string_joined_with_a_variable(self):
        self.expect([
            ("python3 -c 'import os; os.system(\"claude \" + os.environ[\"F\"])'", "cannot"),
            ("python3 -c 'import os; os.system(f\"claude {os.environ[\\\"F\\\"]}\")'", "cannot"),
            (heredoc("python3", "import os\nos.system('claude %s' % flags)"), "cannot"),
            (heredoc("python3", "import os\nos.system('claude {}'.format(flags))"), "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run('claude -p x ' + extra, shell=True)"), "cannot"),
            (heredoc("python3", "import os\ncmd = 'claude -p x'\nos.system(cmd + ' ' + extra)"), "cannot"),
            ("ruby -e 'system(\"claude #{ENV[\"F\"]}\")'", "cannot"),
            ("ruby -e 'puts `claude #{ENV[\"F\"]}`'", "cannot"),
            ("ruby -e 'puts %x(claude #{f})'", "cannot"),
            ("perl -e 'system(\"claude $ENV{F}\")'", "cannot"),
            ("perl -e 'print `claude $f`'", "cannot"),
            ("perl -e 'system(\"claude \" . $f)'", "cannot"),
            ("php -r 'shell_exec(\"claude \" . getenv(\"F\"));'", "cannot"),
            ("php -r 'system(\"claude $f\");'", "cannot"),
            ("awk 'BEGIN { system(\"claude \" ENVIRON[\"F\"]) }'", "cannot"),
            (heredoc("node", "require('child_process').execSync(`claude ${process.env.F}`)"), "cannot"),
            (heredoc("node", "require('child_process').execSync('claude ' + process.env.F)"), "cannot"),
        ])
        self.expect([
            ("await exec.exec(`claude ${process.env.F}`)", "cannot"),
            ("await exec.exec('claude ' + flags)", "cannot"),
        ], make=script_step)

    def test_an_option_built_from_pieces(self):
        self.expect([
            (heredoc("python3", "import subprocess\nf = '--' + 'dangerously-skip-permissions'\n"
                                "subprocess.run(['claude', '-p', 'x', f])"), "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '--' + 'dangerously-skip-permissions'])"),
             "hit"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '--dangerously-' + mode])"), "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', f'--{mode}', '-p', 'x'])"), "cannot"),
            ("ruby -e 'f = \"--\" + \"dangerously-skip-permissions\"; system(\"claude\", \"-p\", \"x\", f)'", "cannot"),
            ("perl -e 'my $f = \"--\" . \"dangerously-skip-permissions\"; system(\"claude\", \"-p\", \"x\", $f)'",
             "cannot"),
        ])
        # Gemini CLI's `-y`.
        self.expect([
            (heredoc("python3", "import subprocess\ny = '-' + 'y'\nsubprocess.run(['gemini', '-p', 'x', y])"), "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['gemini', '-' + 'y', '-p', 'x'])"), "hit"),
        ])
        self.expect([
            ("await exec.exec('claude', ['-p', 'x', '--' + 'dangerously-skip-permissions'])", "hit"),
            ("const f = '--' + 'dangerously-skip-permissions'\nawait exec.exec('claude', ['-p', 'x', f])", "cannot"),
        ], make=script_step)

    def test_a_literal_argument_list_and_one_value_in_a_prompts_place_stay_quiet(self):
        self.expect([
            ("python3 -c 'import subprocess; subprocess.run([\"claude\", \"--version\"])'", "none"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '-p', prompt, '--output-format', 'json'],"
                                " check=True, env=env)"), "none"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '-p', prompt.strip()])"), "none"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '-p', f'Review {pr}'])"), "none"),
            ("ruby -e 'system(\"claude\", \"-p\", ENV[\"PROMPT\"])'", "none"),
            ("perl -e 'system(\"claude\", \"-p\", $ENV{PROMPT})'", "none"),
            (heredoc("node", "require('child_process').execFileSync('claude', ['-p', prompt], {encoding: 'utf8'})"),
             "none"),
            (heredoc("python3", f"import subprocess\nsubprocess.run(['claude', '{DSP}'])"), "hit"),
        ])
        self.expect([
            ("await exec.exec('claude', ['-p', prompt])", "none"),
            ("await exec.exec('claude', ['-p', `Review ${context.payload.pull_request.number}`])", "none"),
            ("core.info(`Running claude with ${args.length} arguments`)", "none"),
            ("console.log('claude', version)", "none"),
            (f"await exec.exec('claude', ['-p', 'x', '{DSP}'])", "hit"),
        ], make=script_step)

    def test_a_value_after_a_warned_option_that_takes_one_is_cannot_tell(self):
        self.expect([
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '--permission-mode', mode, '-p', 'x'])"),
             "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '--permission-mode', 'plan', '-p', 'x'])"),
             "none"),
        ])


class OtherShellsTest(Case):
    def test_pwsh(self):
        win = lambda text: shell_step("pwsh", text, "windows-latest")
        self.expect([
            ("claude -p x @flags", "cannot"),
            ("& claude -p x @flags", "cannot"),
            ("& 'claude' $flags", "cannot"),
            ("Start-Process claude -ArgumentList $args", "cannot"),
            ("Invoke-Expression \"claude $env:F\"", "cannot"),
            ("iex (\"claude \" + $f)", "cannot"),
            ("claude -p \"$env:PROMPT\"", "none"),
            ("claude --version", "none"),
            ("Write-Host \"claude finished: $result\"", "none"),
            (f"claude -p x {DSP}", "hit"),
            ("claude -p x ('--' + 'dangerously-skip-permissions')", "cannot"),
        ], make=win)

    def test_cmd(self):
        win = lambda text: shell_step("cmd", text, "windows-latest")
        self.expect([
            ("claude -p x %FLAGS%", "cannot"),
            ("claude -p x !FLAGS!", "cannot"),
            ("call claude %*", "cannot"),
            ("claude -p x %1", "cannot"),
            ("claude --version", "none"),
            (f"claude -p x {DSP}", "hit"),
        ], make=win)

    def test_python_as_the_steps_shell(self):
        py = lambda text: shell_step("python", text)
        self.expect([
            ("import subprocess\nsubprocess.run(['claude', *flags])", "cannot"),
            ("import subprocess\nsubprocess.run(['claude', '--version'])", "none"),
            (f"import subprocess\nsubprocess.run(['claude', '{DSP}'])", "hit"),
        ], make=py)


class ReadingTest(unittest.TestCase):
    def test_a_name_given_the_program_is_followed(self):
        cases = [
            (heredoc("python3", f"import subprocess\np = 'claude'\nsubprocess.run([p, '{DSP}'])"), "hit"),
            (heredoc("python3", "import subprocess\np = 'claude'\nsubprocess.run([p, *flags])"), "cannot"),
            (heredoc("python3", f"import os\np = 'claude'\nos.system(f'{{p}} {DSP}')"), "hit"),
            (heredoc("python3", "import os\np = 'claude'\nos.system(p + ' ' + flags)"), "cannot"),
        ]
        Case.expect(self, cases)

    def test_escapes_are_read(self):
        Case.expect(self, [
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '\\x2d\\x2ddangerously-skip-permissions'])"),
             "hit"),
            (heredoc("node", "require('child_process').execFileSync('claude', ['\\u002d-dangerously-skip-permissions'])"),
             "hit"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '\\N{HYPHEN-MINUS}-dangerously-skip-permissions'])"),
             "hit"),
        ])

    def test_an_unclosed_string_is_cannot_tell(self):
        Case.expect(self, [(heredoc("python3", "import subprocess\nsubprocess.run(['claude', '-p, 'x'])"), "cannot")])

    def test_tokens(self):
        toks, problem = agent_code.tokens("x = f'claude {a} --y' + \"b\"", "python")
        self.assertEqual(problem, "")
        strings = [t for t in toks if t.kind == "str"]
        self.assertEqual(strings[0].parts, [(False, "claude "), (True, "a"), (False, " --y")])
        toks, _ = agent_code.tokens("my @c = qw(claude --yolo);", "perl")
        self.assertEqual([t.text for t in toks if t.kind == "str"], ["claude", "--yolo"])
        toks, _ = agent_code.tokens("x = `claude ${a}`", "js")
        self.assertEqual(toks[-1].parts, [(False, "claude "), (True, "a")])
        toks, _ = agent_code.tokens('system("claude #{ENV["F"]}")', "ruby")
        self.assertEqual([t.parts for t in toks if t.kind == "str"], [[(False, "claude "), (True, 'ENV["F"]')]])

    def test_family(self):
        self.assertEqual(agent_code.family_of("python3.12"), "python")
        self.assertEqual(agent_code.family_of("/usr/bin/node"), "js")
        self.assertEqual(agent_code.family_of("pwsh.exe"), "pwsh")
        self.assertEqual(agent_code.family_of("github-script"), "js")
        self.assertEqual(agent_code.family_of("fish"), "other")


class CostTest(unittest.TestCase):
    def test_large_code_is_read_in_linear_time(self):
        for code in ("import subprocess\n" + "subprocess.run(['claude', '-p', x])\n" * 3000,
                     "x = " + "a." * 20000 + "b\nsubprocess.run(['claude'])\n",
                     "x = " + "[" * 5000 + "'claude'" + "]" * 5000 + "\n",
                     "x = ['claude', " + "'a', " * 50000 + "]\n"):
            start = time.monotonic()
            check(run_step(heredoc("python3", code)))
            self.assertLess(time.monotonic() - start, 20, code[:60])


if __name__ == "__main__":
    unittest.main()
