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
            # A name given literal pieces is that text where it is used (one step of data flow).
            (heredoc("python3", "import subprocess\nf = '--' + 'dangerously-skip-permissions'\n"
                                "subprocess.run(['claude', '-p', 'x', f])"), "hit"),
            (heredoc("python3", "import subprocess\nf = '--' + mode\nsubprocess.run(['claude', '-p', 'x', f])"),
             "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '--' + 'dangerously-skip-permissions'])"),
             "hit"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '--dangerously-' + mode])"), "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', f'--{mode}', '-p', 'x'])"), "cannot"),
            ("ruby -e 'f = \"--\" + \"dangerously-skip-permissions\"; system(\"claude\", \"-p\", \"x\", f)'", "hit"),
            ("perl -e 'my $f = \"--\" . \"dangerously-skip-permissions\"; system(\"claude\", \"-p\", \"x\", $f)'",
             "hit"),
        ])
        # Gemini CLI's `-y`.
        self.expect([
            (heredoc("python3", "import subprocess\ny = '-' + 'y'\nsubprocess.run(['gemini', '-p', 'x', y])"), "hit"),
            (heredoc("python3", "import subprocess\ny = '-' + v\nsubprocess.run(['gemini', '-p', 'x', y])"), "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['gemini', '-' + 'y', '-p', 'x'])"), "hit"),
        ])
        self.expect([
            ("await exec.exec('claude', ['-p', 'x', '--' + 'dangerously-skip-permissions'])", "hit"),
            ("const f = '--' + 'dangerously-skip-permissions'\nawait exec.exec('claude', ['-p', 'x', f])", "hit"),
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


def maker(name):
    makers = {
        "bash": run_step, "gs": script_step,
        "py": lambda c: run_step(heredoc("python3", c)), "node": lambda c: run_step(heredoc("node", c)),
        "rb": lambda c: run_step(heredoc("ruby", c)), "pl": lambda c: run_step(heredoc("perl", c)),
        "php": lambda c: run_step(heredoc("php", c)),
        "pwsh": lambda c: shell_step("pwsh", c, "windows-latest"), "cmd": lambda c: shell_step("cmd", c, "windows-latest"),
        "pyshell": lambda c: shell_step("python", c),
    }
    if name.startswith("shell:"):
        return lambda c: shell_step(name[6:], c)
    return makers[name]


class FirstReviewCasesTest(unittest.TestCase):
    """Every probe of the first review, with what is reported now (`agent_code_review_cases.py`)."""

    def test_each_case(self):
        from agent_code_review_cases import CASES, CASES_2
        for cid, how, code, want, why in CASES + CASES_2:
            with self.subTest(case=cid, why=why):
                got = kinds(check(maker(how)(code)))
                got = "hit" if "command-option" in got else ("cannot" if got == ["command-computed"] else (
                    "none" if not got else ",".join(got)))
                if want == "hit/cannot":
                    self.assertIn(got, ("hit", "cannot"), code)
                else:
                    self.assertEqual(got, want, code)

    def test_a_string_that_names_the_marker_does_not_end_the_check(self):
        # The first version raised IndexError, and the whole check ended with a traceback.
        text = run_step("python3 -c 'import os; os.system(\"claude ${__OBAAF_HOLE_1}\")'\nclaude " + DSP)
        self.assertIn("command-option", kinds(check(text)))

    def test_a_value_pasted_in_before_the_code_runs(self):
        self.assertEqual(kinds(check(script_step("await exec.exec('claude', ['-p', 'x', ${{ inputs.flags }}])"))),
                         ["command-computed"])
        self.assertEqual(kinds(check(run_step(heredoc("python3", "import subprocess\nsubprocess.run(['claude', '-p', "
                                                                 "'x', '${{ inputs.flags }}'])")))), ["command-computed"])
        unquoted = "python3 <<EOF\nimport subprocess\nsubprocess.run(['claude', '-p', 'x', '$FLAGS'])\nEOF"
        self.assertEqual(kinds(check(run_step(unquoted))), ["command-computed"])
        self.assertEqual(kinds(check(run_step(unquoted.replace("<<EOF", "<<'EOF'")))), [])

    def test_interpreter_options_are_read_by_language(self):
        Case.expect(self, [
            ("python3 -I -c 'import subprocess,sys; subprocess.run([\"claude\", *sys.argv[1:]])'", "cannot"),
            ("perl -Mautodie -e 'system(\"claude\", @ARGV)'", "cannot"),
            ("ruby -rtime -e 'system(\"claude\", *ARGV)'", "cannot"),
            ("awk -v f=\"$F\" 'BEGIN { system(\"claude \" f) }'", "cannot"),
            ("perl -le 'system(\"claude\", @ARGV)'", "cannot"),
            ("echo 'import subprocess,sys; subprocess.run([\"claude\", *sys.argv[1:]])' | python3", "cannot"),
        ])


class SecondReviewTest(unittest.TestCase):
    """Conditions the second review's mutations showed no test covered, and its crash."""

    def test_conditions(self):
        Case.expect(self, [
            (heredoc("python3", "import os\np = 'claude'\np += ' ' + F\nos.system(p)"), "cannot"),
            ("echo 'import subprocess; subprocess.run([\"claude\",\"--version\"])' | python3", "none"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['gemini', x + 'y', '-p', 'q'])"), "cannot"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', x + 'ion'])"), "none"),
            (heredoc("python3", "import subprocess\nsubprocess.run(['claude', '--yolo-is-not' + x])"), "none"),
            (heredoc("python3", "import os\nos.system('claude '\n          '" + DSP + "')"), "hit"),
            (heredoc("python3", "import os\nos.system('claude ' +\n          os.environ['F'])"), "cannot"),
            (heredoc("python3", "import subprocess\ncmd = ['claude', '-p', prompt]\nif model:\n    cmd += ['--model', model]\n"
                                "subprocess.run(cmd)"), "none"),
            (heredoc("python3", "import subprocess\ncmd = ['claude', '-p', 'x']\nfor a in extra:\n    cmd.append(a)\n"
                                "subprocess.run(cmd)"), "cannot"),
        ])
        Case.expect(self, [
            ("core.group('claude', async () => { await exec.exec('npm', ['test']) })", "none"),
            ("const args = ['-p', prompt];\nif (model) args.push('--model', model);\nawait exec.exec('claude', args);", "none"),
            ("const args = ['-p', prompt];\nargs.push(process.env.F, process.env.G);\nawait exec.exec('claude', args);",
             "none"),
            ("require('child_process').spawnSync('claude', ['-p', prompt], {shell: true})", "cannot"),
            ("await exec.exec('claude -p x', flags)", "cannot"),
            ("await exec.exec('bash', ['-c', `claude ${flags}`])", "cannot"),
        ], make=script_step)

    def test_the_third_pass(self):
        # An unclosed `${{` in a PowerShell step looped for ever; a held list's changes were read one by one.
        start = time.monotonic()
        self.assertEqual(kinds(check(shell_step("pwsh", "claude -p ${{ github.event.issue.title", "windows-latest"))),
                         ["command-computed"])
        self.assertLess(time.monotonic() - start, 10)
        Case.expect(self, [
            (heredoc("python3", "import subprocess\ncmd = ['claude', '-p', p]\ncmd.append('--permission-mode')\n"
                                "cmd.append('bypassPermissions')\nsubprocess.run(cmd)"), "hit"),
            (heredoc("python3", "import subprocess\ncmd = ['claude', '--permission-mode']\ncmd.append(mode)\n"
                                "subprocess.run(cmd)"), "cannot"),
            (heredoc("python3", "import subprocess\ncmd = ['claude', '-p', p]\nfor i in range(len(extra)):\n"
                                "    cmd.append(extra[i])\nsubprocess.run(cmd)"), "cannot"),
        ])
        Case.expect(self, [("cmd /c " * 2000 + "claude %F%", "cannot")],
                    make=lambda text: shell_step("cmd", text, "windows-latest"))
        Case.expect(self, [
            ("const args = ['-p', p];\nextra.forEach(f => args.push(f));\nawait exec.exec('claude', args)", "cannot"),
            ("const args = ['-p', p];\nfor (let i = 0; i < extra.length; i++) { args.push(extra[i]) }\n"
             "await exec.exec('claude', args)", "cannot"),
            ("const r = /" + "a" * 1001 + "'/;\nawait exec.exec('claude', flags) // '", "cannot"),
        ], make=script_step)

    def test_the_fourth_pass(self):
        # A list built afresh on each turn of a loop, with a literal added, is read as it is (it was "cannot
        # tell" at a2defae); the indentation walk skips strings and is worked out once.
        tq = "'" * 3
        Case.expect(self, [
            (heredoc("python3", "import subprocess\nfor p in prompts:\n    cmd = ['claude', '-p', p]\n    if v:\n"
                                "        cmd.append('--verbose')\n    subprocess.run(cmd)"), "none"),
            (heredoc("python3", "import subprocess\ndef main():\n    prompt = " + tq + "\nfor each file, review it\n    "
                                + tq + "\n    cmd = ['claude', '-p', prompt]\n    if verbose:\n"
                                "        cmd.append('--verbose')\n    subprocess.run(cmd)"), "none"),
            (heredoc("python3", "import subprocess\nfor p in prompts:\n    cmd = ['claude', '-p', p]\n"
                                "    cmd.append('" + DSP + "')\n    subprocess.run(cmd)"), "hit"),
            (heredoc("ruby", "c = ['claude']\nc.push('-v')\nsystem(*c)"), "none"),
            (heredoc("ruby", "args = ['claude', '-p', 'x']\nargs << '--verbose' if v\nsystem(*args)"), "none"),
            (heredoc("ruby", "args = ['claude', '-p', 'x']\nextra.each { |f| args << f }\nsystem(*args)"), "cannot"),
            (heredoc("ruby", "args = ['claude', '-p', 'x']\nextra.each do |f|\n  args << f\nend\nsystem(*args)"), "cannot"),
            (heredoc("python3", "import subprocess\ncmd = ['claude', '-p', 'x']\nfor f in extra:\n    cmd += [f]\n"
                                "subprocess.run(cmd)"), "cannot"),
            (heredoc("python3", "import subprocess\ncmd = ['claude', '-p', 'x']\nfor i in range(n):\n    cmd += [extra[i]]\n"
                                "subprocess.run(cmd)"), "cannot"),
        ])
        Case.expect(self, [
            ("for (const pr of prs) {\n  const args = ['-p', prompt(pr)];\n  if (v) args.push('--verbose');\n"
             "  await exec.exec('claude', args);\n}", "none"),
            ("await Promise.all(prs.map(async pr => { const args = ['-p', pr]; args.push('--output-format', 'json');"
             " await exec.exec('claude', args) }))", "none"),
        ], make=script_step)
        start = time.monotonic()
        check(run_step(heredoc("python3", "import subprocess\ncmd = ['claude', '-p', p]\n" + "cmd.append('-v')\n" * 12000
                                          + "subprocess.run(cmd)")))
        self.assertLess(time.monotonic() - start, 10)

    def test_a_long_chain_of_unary_operators_does_not_end_the_check(self):
        text = script_step("const x = " + "!" * 3000 + "y\nawait exec.exec('claude', flags)")
        self.assertEqual(kinds(check(text)), ["command-computed"])

    def test_the_site_limit(self):
        text = script_step("await exec.exec('claude', ['-p', p])\n" * 205)
        self.assertEqual(kinds(check(text)), ["command-computed"])
        text = script_step("core.info('claude step')\n" * 205 + "await exec.exec('claude', ['-p', p])")
        self.assertEqual(kinds(check(text)), [])


class CostTest(unittest.TestCase):
    def test_the_second_reviews_slow_inputs(self):
        # Each took 7 to 26 s before the second review's fixes.
        cases = [
            run_step(heredoc("python3", "x = ['claude', " + "a, " * 4000 + "]\na = ['y']")),
            script_step("await exec.exec('claude',['-p',p])\nconst r = 1" + "/[" * 16000),
            run_step(heredoc("python3", "p = 'claude " + "x " * 4000 + "'\nimport os\nos.system(f'" + "{p}" * 800 + "{f}')")),
            run_step(heredoc("python3", "c = 'claude ' + f\n" + "y = c\n" * 6000 + "import os\nos.system(y)")),
            run_step(heredoc("python3", "import subprocess\n" + "p = 'claude'\n" * 4000 + "f(p)\n" * 4000)),
        ]
        for text in cases:
            start = time.monotonic()
            check(text)
            self.assertLess(time.monotonic() - start, 10, text[:80])

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
