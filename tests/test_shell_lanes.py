"""Flagship slice 2d.27a (#420): the lanes take the program a PowerShell or cmd command runs from OBAAF-GHA-026's reader.

OBAAF-GHA-026 reads a PowerShell or cmd script with a reader of those shells (`agent_code.read_shell_lines`): quotes,
curly ones included, a program's folder and its `.exe`, cmd's carets, `Start-Process` and its parameters, and a name
the script gives the program's name. The lanes read the same scripts with bash's word splitting, so before this slice

    - shell: pwsh
      run: 'C:\\tools\\claude.exe --dangerously-skip-permissions -p x'

got OBAAF-GHA-026 high and was in no agent lane, so it got no OBAAF-GHA-003, 005 or 020. Now every command that reader
names the program of is put before the lanes as that program's command line (`agent_code.program_lines`), and the
catalogue's agent patterns are matched against it.

What the reader cannot name (a group `& (claude)`, a subexpression, a method's result, a splat, a loop's variable, a
typed copy) is "cannot tell" for OBAAF-GHA-026 and still in no agent lane; #420 keeps it for a later slice. The
workflows are written here and read through the command line; nothing in them is run.
"""

import json
import random
import time
import unittest

from helpers import TempDir
from test_env_shell import checked

from obaaf.checker import agent_code
from obaaf.checker.workflow import _agent_program_names

F = "--dangerously-skip-permissions"

# (name, family, script, env): each is an agent job, with OBAAF-GHA-026 high.
AGENT_FORMS = [
    ("pwsh-curly-double", "pwsh", "& \u201cclaude\u201d " + F + " -p x", {}),
    ("pwsh-curly-single", "pwsh", "& \u2018claude\u2019 " + F + " -p x", {}),
    ("pwsh-exe", "pwsh", "claude.exe " + F + " -p x", {}),
    ("pwsh-exe-other-case", "pwsh", "Claude.EXE " + F + " -p x", {}),
    ("pwsh-backslash-path", "pwsh", "C:\\tools\\claude.exe " + F + " -p x", {}),
    ("pwsh-quoted-path-with-a-space", "pwsh", "& 'C:\\Program Files\\claude\\claude.exe' " + F + " -p x", {}),
    ("pwsh-start-process-working-directory", "pwsh",
     "Start-Process -WorkingDirectory C:\\w claude -ArgumentList '" + F + "','-p','x'", {}),
    ("pwsh-start-process-file-path-exe", "pwsh",
     "Start-Process -Wait -WorkingDirectory C:\\w -FilePath claude.exe -ArgumentList '" + F + "','-p','x'", {}),
    ("pwsh-copied-into-a-variable", "pwsh", "$a = 'claude'; & $a " + F + " -p x", {}),
    ("pwsh-copied-exe-next-line", "pwsh", "$a = \"claude.exe\"\n& $a " + F + " -p x", {}),
    ("pwsh-exe-from-env", "pwsh", "& \"$env:AGENT.exe\" " + F + " -p x", {"AGENT": "claude"}),
    ("cmd-exe", "cmd", "claude.exe " + F + " -p x", {}),
    ("cmd-leading-caret", "cmd", "^claude " + F + " -p x", {}),
    ("cmd-caret-inside", "cmd", "c^laude " + F + " -p x", {}),
    ("cmd-backslash-path", "cmd", "C:\\tools\\claude.cmd " + F + " -p x", {}),
    ("cmd-set-then-run", "cmd", "set BIN=claude\n%BIN% " + F + " -p x", {}),
    ("cmd-quoted-set-then-call", "cmd", "set \"BIN=claude.exe\"\ncall %BIN% " + F + " -p x", {}),
    ("cmd-exe-from-env", "cmd", "%AGENT%.exe " + F + " -p x", {"AGENT": "claude"}),
    # From the review: wrappers and launchers the reader did not enter, the arguments `Start-Process` was not given,
    # a redirection that holds its target, an inline comment, and a separator inside one argument.
    ("cmd-options-before-c", "cmd", "cmd /d /s /c \"claude.exe " + F + " -p x\"", {}),
    ("pwsh-cmd-e-on", "pwsh", "cmd /e:on /c claude.exe " + F + " -p x", {}),
    ("pwsh-pwsh-command", "pwsh", "pwsh -NoProfile -ExecutionPolicy Bypass -Command \"claude.exe " + F + " -p x\"", {}),
    ("cmd-powershell-c", "cmd", "powershell -c \"& C:\\t\\claude.exe " + F + " -p x\"", {}),
    ("pwsh-iex-literal", "pwsh", "iex 'claude.exe " + F + " -p x'", {}),
    ("cmd-start-d", "cmd", "start /d C:\\w claude.exe " + F + " -p x", {}),
    ("cmd-if-if", "cmd", "if a==a if b==b claude.exe " + F + " -p x", {}),
    ("pwsh-start-process-spaced-commas", "pwsh", "Start-Process claude.exe -ArgumentList '" + F + "' , '-p' , 'x'", {}),
    ("pwsh-start-process-trailing-comma", "pwsh", "Start-Process claude.exe -ArgumentList '" + F + "',\n  '-p','x'", {}),
    ("pwsh-start-process-path-alias", "pwsh", "Start-Process -Path claude.exe -ArgumentList '" + F + " -p x'", {}),
    ("pwsh-start-process-short-names", "pwsh", "Start-Process -F claude.exe -A '" + F + " -p x'", {}),
    ("pwsh-redirection-with-its-target", "pwsh", "claude.exe " + F + " 2>&1 -p x", {}),
    ("cmd-redirection-with-its-target", "cmd", "claude.exe " + F + " >nul 2>&1 -p x", {}),
    ("pwsh-inline-comment", "pwsh", "claude.exe " + F + " <# note #> -p x", {}),
    # From the second review: a comment that ends with `,` or `|` carries nothing on; a bracket in a command's text
    # does not hold the next command; `^^` is an escaped caret, so the `&` after it is an operator.
    ("pwsh-comment-ending-with-a-comma", "pwsh", "# First install it,\nC:\\tools\\claude.exe " + F + " -p x", {}),
    ("pwsh-code-then-comment-with-a-pipe", "pwsh", "$a = 'claude' # the cli |\n& $a " + F + " -p x", {}),
    ("cmd-text-bracket-then-ampersand", "cmd", "echo :-( & claude.exe " + F + " -p x", {}),
    ("cmd-at-block", "cmd", "@(claude.exe " + F + " -p x) > log.txt", {}),
    ("cmd-escaped-caret-then-ampersand", "cmd", "echo a ^^& claude.exe " + F + " -p x", {}),
    ("pwsh-separator-in-an-argument", "pwsh",
     "claude.exe " + F + " --allowedTools \"Bash(npm test)|Read\" --append-system-prompt \"a; b\" -p x", {}),
]

# (name, family, script, env): in no agent lane, with no agent finding.
ORDINARY_FORMS = [
    ("pwsh-curly-other-program", "pwsh", "& \u201cnotepad\u201d -p x", {}),
    ("pwsh-other-exe", "pwsh", "notepad.exe -p x", {}),
    ("pwsh-other-program-in-a-claude-folder", "pwsh", "C:\\claude\\notepad.exe -p x", {}),
    ("pwsh-program-name-as-an-argument", "pwsh", "Write-Output claude.exe -p x", {}),
    ("pwsh-start-process-claude-folder", "pwsh",
     "Start-Process -WorkingDirectory C:\\claude notepad -ArgumentList '-p','x'", {}),
    ("pwsh-other-variable", "pwsh", "$a = 'claude'; & $b -p x", {}),
    ("pwsh-longer-name", "pwsh", "claudette.exe -p x", {}),
    ("cmd-echo", "cmd", "echo claude.exe -p x", {}),
    ("cmd-other-variable", "cmd", "set BIN=claude\n%OTHER% -p x", {}),
    ("cmd-other-exe", "cmd", "notepad.exe -p x", {}),
    ("cmd-remark", "cmd", "rem claude.exe -p x", {}),
    # From the review: text the base kept out of the lanes that the first head put in.
    ("cmd-echo-bracket", "cmd", "echo Run (claude.exe -p \"review\") locally", {}),
    ("cmd-for-set", "cmd", "for %%a in (claude.exe -p x) do echo %%a", {}),
    ("cmd-escaped-ampersand", "cmd", "echo a ^& claude.exe -p x", {}),
    ("cmd-remark-and-ampersand", "cmd", "rem see docs & claude.exe -p x", {}),
    ("cmd-label-and-ampersand", "cmd", ":: usage & claude.exe -p x", {}),
    ("pwsh-alias-as-a-value", "pwsh", "$x = $env:TOOL; $y = $x + ' -p x'", {"TOOL": "claude"}),
]

AGENT_RULES = ("OBAAF-GHA-003", "OBAAF-GHA-005", "OBAAF-GHA-020", "OBAAF-GHA-025", "OBAAF-GHA-026")


def workflow(cases) -> str:
    jobs = ""
    for name, family, run, env in cases:
        shell = "pwsh" if family == "pwsh" else "cmd"
        env_line = f"        env: {json.dumps(env)}\n" if env else ""
        jobs += (f"  {name}:\n    runs-on: windows-latest\n    steps:\n      - run: {json.dumps(run)}\n"
                 f"        shell: {shell}\n{env_line}")
    return "on: workflow_dispatch\npermissions: {}\njobs:\n" + jobs


def results(cases):
    """(lanes by job, OBAAF-GHA-026's (severity, kind) by job, agent rules by job, errors)."""
    with TempDir() as tmp:
        (tmp / ".github" / "workflows").mkdir(parents=True)
        (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
        (tmp / ".github" / "workflows" / "a.yml").write_text(workflow(cases), encoding="utf-8")
        _code, lanes, report = checked(tmp)
    gha026: dict = {}
    rules: dict = {}
    for f in report["findings"]:
        if f["rule"] == "OBAAF-GHA-026":
            gha026.setdefault(f["job"], []).append((f["severity"], f["kind"]))
        if f["rule"] in AGENT_RULES:
            rules.setdefault(f["job"], set()).add(f["rule"])
    return lanes, gha026, rules, report["errors"]


class TheFormsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lanes, cls.gha026, cls.rules, cls.errors = results(AGENT_FORMS + ORDINARY_FORMS)

    def test_no_errors(self):
        self.assertEqual(self.errors, [])

    def test_each_agent_form_is_an_agent_job(self):
        for name, _family, run, _env in AGENT_FORMS:
            with self.subTest(job=name, run=run):
                self.assertEqual(self.lanes.get(name), "agent")
                self.assertEqual(self.gha026.get(name), [("high", "command-option")])
                self.assertIn("OBAAF-GHA-020", self.rules.get(name, set()))

    def test_each_ordinary_form_is_in_no_agent_lane(self):
        # OBAAF-GHA-026 may say "cannot tell" where the script names the tool and runs a command it cannot name
        # (`$a = 'claude'; & $b`); it names no program there, and the job gets no other agent rule.
        for name, _family, run, _env in ORDINARY_FORMS:
            with self.subTest(job=name, run=run):
                self.assertEqual(self.lanes.get(name), "trusted")
                self.assertEqual(self.rules.get(name, set()) - {"OBAAF-GHA-026"}, set())
                self.assertTrue(all(kind == "command-computed" for _severity, kind in self.gha026.get(name, [])))


def generated(rng, count: int) -> list:
    """Commands that run claude with a prompt and a warned option, in the spellings PowerShell and cmd give a program:
    the call operators and launchers, quotes, a folder, a suffix, a letter case, carets, and a name the script gives
    the program's name. Seeded, so CI runs the same cases every time."""
    out = []
    for n in range(count):
        family = rng.choice(["pwsh", "cmd"])
        name = rng.choice(["claude", "Claude", "CLAUDE"]) + rng.choice(["", ".exe", ".EXE", ".cmd", ".bat"])
        folder = rng.choice(["", "C:\\tools\\", "D:/x/", ".\\", "C:\\Program Files\\Anthropic\\"])
        program = folder + name
        args = rng.choice([F + " -p x", "-p x " + F, "--print 'x' " + F])
        if family == "pwsh":
            quote = rng.choice(["", "'", '"', "\u201c\u201d", "\u2018\u2019"])
            if " " in program and not quote:
                quote = "'"
            written = (quote[0] + program + quote[-1]) if quote else program
            form = rng.randrange(6)
            if form == 4:
                inner = (("& " + written) if quote else program) + " " + args.replace("'", "")
                run = rng.choice([f'pwsh -NoProfile -Command "{inner}"', f'cmd /d /s /c "{inner}"',
                                  f"iex '{inner}'" if "'" not in inner else f'iex "{inner}"'])
                if run.startswith("cmd") and quote:
                    run = f'cmd /d /s /c "{program} {args.replace(chr(39), "")}"'
            elif form == 5:
                run = (f"Start-Process -WorkingDirectory C:\\w {written} -ArgumentList "
                       + " , ".join(f"'{a}'" for a in args.replace("'", "").split()) + " 2>&1")
            elif form == 0:
                run = rng.choice(["& ", ". ", "$out = & ", ""]) + (written if quote else program) + " " + args
                if quote and run.startswith(written):
                    run = "& " + run
            elif form == 1:
                parameters = rng.choice(["", "-Wait ", "-WorkingDirectory C:\\w ", "-NoNewWindow -WorkingDirectory C:\\w "])
                run = (f"Start-Process {parameters}-FilePath {written} -ArgumentList "
                       + ",".join(f"'{a}'" for a in args.replace("'", "").split()))
            elif form == 2:
                run = f"$exe = {written if quote else repr(program)}\n& $exe {args}"
            else:
                run = f"Write-Host start; & {written if quote else program} {args}"
        else:
            if " " in program:
                program = '"' + program + '"'
            form = rng.randrange(6)
            if form == 4:
                run = rng.choice(["cmd /d /s /c ", "cmd /e:on /c ", "if a==a if 1==1 ", "start /d C:\\w "]) + (
                    program + " " + args.replace("'", ""))
            elif form == 5:
                run = program + " " + args.replace("'", "").replace(" -p", " 2>&1 -p").replace(" --print", " >nul --print")
            elif form == 0:
                run = rng.choice(["", "@", "call "]) + program + " " + args.replace("'", "")
            elif form == 1:
                run = "^" + program + " " + args.replace("'", "")
            elif form == 2:
                run = f"set BIN={program.strip(chr(34))}\n%BIN% {args.replace(chr(39), '')}"
            else:
                run = f"echo start & {program} {args.replace(chr(39), '')}"
        out.append((f"gen-{n}", family, run, {}))
    return out


class TheReadersAgreeTest(unittest.TestCase):
    """Wherever OBAAF-GHA-026's reader names the program a PowerShell or cmd command runs (its finding is
    `command-option`, not "cannot tell"), and the command is one the catalogue's pattern counts (here, with a prompt
    flag), the job is an agent job."""

    def test_generated_commands(self):
        cases = generated(random.Random(20261128), 240)
        lanes, gha026, _rules, errors = results(cases)
        self.assertEqual(errors, [])
        named = 0
        for name, _family, run, _env in cases:
            if any(kind == "command-option" for _severity, kind in gha026.get(name, [])):
                named += 1
                with self.subTest(job=name, run=run):
                    self.assertEqual(lanes.get(name), "agent")
        # The generator is not idle: most of its commands are ones the reader names.
        self.assertGreater(named, 180)


class TheProgramLinesTest(unittest.TestCase):

    def test_lines(self):
        programs, packages = _agent_program_names()
        self.assertEqual(agent_code.program_lines("C:\\t\\Claude.EXE -p x >out.txt", "pwsh", programs, packages),
                         ["claude -p x"])
        self.assertEqual(agent_code.program_lines("set C=claude\n%C% -p \"%X%\"", "cmd", programs, packages),
                         ["claude -p %X%"])
        self.assertEqual(agent_code.program_lines("npx @anthropic-ai/claude-code -p x", "pwsh", programs, packages),
                         ["@anthropic-ai/claude-code -p x"])
        self.assertEqual(agent_code.program_lines("notepad.exe -p x", "pwsh", programs, packages), [])
        self.assertEqual(agent_code.program_lines("claude -p x", "bash", programs, packages), [])

    def test_linear(self):
        # Four times the script costs at most about four times as much (a ratio, not a fixed bound, so that a small
        # quadratic term is seen), for each shape the review timed.
        programs, packages = _agent_program_names()
        shapes = {
            "pwsh-aliases": ("pwsh", lambda n: "\n".join(["$a = 'claude'", *(f"& $a -p x{i}" for i in range(n))])),
            "pwsh-here-strings": ("pwsh", lambda n: "\n".join(f"$b{i} = @\"\nclaude -p {i}\n\"@" for i in range(n))),
            "pwsh-unclosed-here-strings": ("pwsh", lambda n: "\n".join("@'" for _ in range(n)) + "\nclaude -p x"),
            "cmd-sets": ("cmd", lambda n: "\n".join([*(f"set B{i}=claude" for i in range(n)), "%B1% -p x"])),
            "cmd-brackets": ("cmd", lambda n: "echo " + "(" * n + " claude -p x"),
        }
        for name, (family, make) in shapes.items():
            with self.subTest(shape=name):
                took = []
                for n in (1500, 6000):
                    script = make(n)
                    started = time.monotonic()
                    agent_code.program_lines(script, family, programs, packages)
                    took.append(time.monotonic() - started)
                self.assertLess(took[1], 8 * max(took[0], 0.01), took)


if __name__ == "__main__":
    unittest.main()
