"""Flagship slice 2d.25 (#411): an agent named only through `env` in a PowerShell or cmd step.

GitHub hands a `run` step's script to its shell with the `env` the step runs with (its own over its job's over its
workflow's) as the process's environment. PowerShell reads a variable as `$env:NAME` or `${env:NAME}`, cmd as
`%NAME%`. Before this slice the lanes (`Step.env_put_in`) put in only bash's `$NAME` and `${NAME}`, and OBAAF-GHA-026
read a script that is not bash only where the tool's letters stood in the script's own text, so

    - shell: pwsh
      run: '& $env:AGENT --dangerously-skip-permissions -p x'
      env: {AGENT: claude}

made no agent job and got no agent rule at all, where the same step in bash (`$AGENT ...`) got OBAAF-GHA-026 high and
the agent lane. Now both readers put those references in, as each shell expands them, with the bounds of D-137 and
D-138, and compare names as the runner does.

The workflows are static fixtures under `tests/fixtures/env-shell`, read through the command line; nothing in them is
run.
"""

import json
import shutil
import time
import unittest
from unittest import mock

from helpers import FIXTURES, TempDir, run_cli

from obaaf.checker import agent_flags, shell_env
from obaaf.checker.workflow import ENV_PUT_IN_UNREAD

FIXTURE = FIXTURES / "env-shell"

# Each job of the agents fixture: (its lane, OBAAF-GHA-026's severity and kind).
AGENT_JOBS = {
    "pwsh-step-env": ("agent", "high", "command-option"),
    "pwsh-windows-job-env-other-case": ("agent", "high", "command-option"),
    "pwsh-workflow-env-job-defaults": ("agent", "high", "command-option"),
    "pwsh-option-from-env": ("agent", "high", "command-option"),
    "pwsh-double-quoted": ("agent", "high", "command-option"),
    "pwsh-start-process": ("agent", "high", "command-option"),
    "pwsh-continue": ("agent", "medium", "command-option"),
    "cmd-step-env": ("agent", "high", "command-option"),
    "cmd-other-case-and-caret": ("agent", "high", "command-option"),
    # Set by the script, read from an `env` an earlier step's `GITHUB_ENV` may change, or in another letter case on a
    # runner that may compare names either way: the lanes read the widest way, OBAAF-GHA-026 cannot tell.
    "pwsh-set-by-the-script": ("agent", "medium", "command-computed"),
    "cmd-set-by-the-script": ("agent", "medium", "command-computed"),
    "pwsh-self-hosted-other-case": ("agent", "medium", "command-computed"),
    "pwsh-after-github-env": ("agent", "medium", "command-computed"),
    # From the second review: a value copied into a variable and run on the next line, `-FilePath:`, `call :label`.
    # The lanes follow neither a value copied into a script's variable nor the script's own assignments, for a
    # program written out as for one put in (`$a = 'claude'; & $a`; D-153's stated limits): those jobs are in no
    # agent lane, and OBAAF-GHA-026 reads them.
    "pwsh-copied-into-a-variable": ("trusted", "high", "command-option"),
    "pwsh-copied-after-github-env": ("trusted", "medium", "command-computed"),
    "pwsh-file-path-after-a-colon": ("agent", "high", "command-option"),
    "cmd-copied-into-a-variable": ("trusted", "high", "command-option"),
    "cmd-call-label-sets-it": ("trusted", "high", "command-option"),
    # From the third review: a value left out (after `GITHUB_ENV`) run where the reader reads it, and setters the
    # checker does not list. The copies and the script's own assignments are stated limits of the lanes.
    "pwsh-typed-copy-after-github-env": ("trusted", "medium", "command-computed"),
    "pwsh-foreach-after-github-env": ("trusted", "medium", "command-computed"),
    "cmd-if-exist-after-github-env": ("agent", "medium", "command-computed"),
    "pwsh-set-by-an-unlisted-setter": ("trusted", "medium", "command-computed"),
    "cmd-set-p-without-a-space": ("trusted", "medium", "command-computed"),
}
# The jobs above where the lanes and OBAAF-GHA-026 disagree, each for a reason D-153 states.
STATED_DISAGREEMENTS = {"pwsh-copied-into-a-variable", "cmd-copied-into-a-variable", "cmd-call-label-sets-it",
                        "pwsh-copied-after-github-env",
                        "pwsh-typed-copy-after-github-env", "pwsh-foreach-after-github-env",
                        "pwsh-set-by-an-unlisted-setter", "cmd-set-p-without-a-space"}
ORDINARY_JOBS = ["pwsh-region", "pwsh-tool-from-env", "cmd-greeting", "pwsh-linux-other-case",
                 "pwsh-single-quoted-and-escaped", "bash-reads-no-pwsh-reference", "pwsh-tool-named-in-prose",
                 "cmd-tool-named-in-prose", "cmd-ampersand-runs-another-program",
                 "pwsh-call-operator-on-another-program", "pwsh-assigned-prose", "cmd-assigned-prose"]


def checked(source=FIXTURE, *args):
    """(exit status, lanes by job, JSON report) of `obaaf check` on a copy of `source`."""
    with TempDir() as tmp:
        target = tmp / "repo"
        shutil.copytree(source, target)
        _code, lanes_out, _err = run_cli("check", target, "--lanes", *args)
        code, out, err = run_cli("check", target, "--format", "json", *args)
    lanes = {}
    for line in lanes_out.splitlines():
        where, _, rest = line.partition(": ")
        if "#" in where:
            lanes[where.split("#", 1)[1]] = rest.split(" ", 1)[0]
    return code, lanes, json.loads(out) if out.strip() else {"errors": [err], "findings": []}


class TheFixtureTest(unittest.TestCase):
    """Every case through the command line: the lane each job is in, and what OBAAF-GHA-026 gives it."""

    @classmethod
    def setUpClass(cls):
        cls.code, cls.lanes, cls.report = checked()

    def gha026(self, job):
        return [(f["severity"], f["kind"]) for f in self.report["findings"]
                if f["rule"] == "OBAAF-GHA-026" and f["job"] == job]

    def test_the_fixture_is_read_without_errors(self):
        self.assertEqual(self.report["errors"], [])

    def test_each_agent_job(self):
        for job, (lane, severity, kind) in AGENT_JOBS.items():
            with self.subTest(job=job):
                self.assertEqual(self.lanes.get(job), lane)
                self.assertEqual(self.gha026(job), [(severity, kind)])

    def test_each_ordinary_job_is_in_no_agent_lane_and_gets_no_agent_finding(self):
        for job in ORDINARY_JOBS:
            with self.subTest(job=job):
                self.assertEqual(self.lanes.get(job), "trusted")
                self.assertEqual(self.gha026(job), [])
                agent_rules = {f["rule"] for f in self.report["findings"] if f["job"] == job and f["rule"] in (
                    "OBAAF-GHA-003", "OBAAF-GHA-005", "OBAAF-GHA-020", "OBAAF-GHA-025", "OBAAF-GHA-026")}
                self.assertEqual(agent_rules, set())

    def test_the_lanes_and_gha026_agree(self):
        # Every job OBAAF-GHA-026 reads an agent in is an agent job, and the reverse (the lead's order on #411).
        for job, lane in self.lanes.items():
            with self.subTest(job=job):
                self.assertEqual(lane == "agent" or job in STATED_DISAGREEMENTS, bool(self.gha026(job)))

    def test_the_agent_rules_apply_to_an_agent_job(self):
        rules = {f["rule"] for f in self.report["findings"] if f["job"] == "pwsh-step-env"}
        self.assertIn("OBAAF-GHA-020", rules)


class TheBoundsTest(unittest.TestCase):
    """D-137: a step's values are put in eight times each, and 100,000 characters more; past that the step is an
    error of its file, as a bash step's is."""

    def test_a_pwsh_step_past_its_bound_is_an_error_of_its_file(self):
        prompt = "a" * 20_000
        refs = " ".join(["$env:P"] * 20)
        text = ("on: workflow_dispatch\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                f"      - shell: pwsh\n        run: 'Write-Host {refs}'\n        env:\n          P: {prompt}\n")
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
            (tmp / ".github" / "workflows" / "a.yml").write_text(text, encoding="utf-8")
            code, _lanes, report = checked(tmp)
        self.assertEqual(code, 1)          # a file the checker could not read fails the check
        self.assertTrue(any(ENV_PUT_IN_UNREAD in e for e in report["errors"]), report["errors"])

    def test_the_same_in_cmd(self):
        prompt = "a" * 20_000
        refs = " ".join(["%P%"] * 20)
        text = ("on: workflow_dispatch\npermissions: {}\njobs:\n  a:\n    runs-on: windows-latest\n    steps:\n"
                f"      - shell: cmd\n        run: 'echo {refs}'\n        env:\n          P: {prompt}\n")
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
            (tmp / ".github" / "workflows" / "a.yml").write_text(text, encoding="utf-8")
            code, _lanes, report = checked(tmp)
        self.assertEqual(code, 1)          # a file the checker could not read fails the check
        self.assertTrue(any(ENV_PUT_IN_UNREAD in e for e in report["errors"]), report["errors"])


class TheCostTest(unittest.TestCase):
    """A PowerShell or cmd step whose `env` names no agent is not read as code for one (#411: kept cheap, and kept
    from the false findings #388 removed)."""

    def test_no_agent_in_env_no_reading(self):
        calls = []
        original = agent_flags.read_script

        def counting(text, *args, **kwargs):
            if kwargs.get("bash") is False:
                calls.append(text)
            return original(text, *args, **kwargs)
        with mock.patch.object(agent_flags, "read_script", counting):
            code, lanes, report = checked()
        self.assertEqual(report["errors"], [])
        for text in calls:
            self.assertNotIn("aws s3 ls", text)
            self.assertNotIn("$env:TOOL build", text)

    def test_many_pwsh_steps_stay_cheap(self):
        steps = "".join(f"      - shell: pwsh\n        run: 'Write-Host $env:V{n % 50} $env:W'\n" for n in range(1500))
        env = "".join(f"      V{n}: value{n}\n" for n in range(50))
        text = ("on: workflow_dispatch\npermissions: {}\njobs:\n  a:\n    runs-on: windows-latest\n    env:\n"
                f"{env}      W: cn-north-1\n    steps:\n{steps}")
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
            (tmp / ".github" / "workflows" / "a.yml").write_text(text, encoding="utf-8")
            started = time.monotonic()
            code, lanes, report = checked(tmp)
            spent = time.monotonic() - started
        self.assertEqual(report["errors"], [])
        self.assertEqual(lanes.get("a"), "trusted")
        self.assertLess(spent, 30)


class TheReferencesTest(unittest.TestCase):
    """What each shell expands, as `shell_env.references` finds it."""

    def names(self, text, family):
        return [(name, in_string, plain) for _s, _e, name, in_string, plain in shell_env.references(text, family)]

    def test_pwsh(self):
        text = ("& $env:A --x; Write-Host '$env:B' \"$env:C\" `$env:D ${env:E} $ENV:F $env:G.Length $env:H[0] # $env:I\n"
                "@'\n$env:J\n'@\n@\"\n$env:K\n\"@\n<# $env:L #> $env:M \"`$env:N\" \"a\"\"$env:O\"")
        self.assertEqual(self.names(text, "pwsh"), [
            ("A", False, True), ("C", True, True), ("E", False, True), ("F", False, True), ("G", False, False),
            ("H", False, False), ("K", True, True), ("M", False, True), ("O", True, True)])

    def test_cmd(self):
        self.assertEqual(self.names("%%A%% %1 %~dp0 %B% %C:~1% %* %D", "cmd"),
                         [("B", False, True), ("C", False, False)])

    def test_a_reference_at_the_end_of_an_unclosed_string_is_read(self):
        self.assertEqual(self.names('Write-Host "$env:A', "pwsh"), [("A", True, True)])

    def test_linear(self):
        text = "'" * 20_000 + '"$env:A' * 20_000 + "@'\n" * 5_000
        started = time.monotonic()
        shell_env.references(text, "pwsh")
        shell_env.references("%" * 100_000 + "%A%" * 20_000, "cmd")
        self.assertLess(time.monotonic() - started, 5)


class TheLookupTest(unittest.TestCase):
    """Names compared as the runner compares them, the nearest scope winning (D-139, #387)."""

    def test_nearest_scope_and_case(self):
        lookup = shell_env.Lookup([{"AGENT": "claude"}, {"agent": "echo"}])
        self.assertEqual(lookup.get("AGENT", "exact"), "claude")
        self.assertEqual(lookup.get("agent", "exact"), "echo")
        self.assertEqual(lookup.get("agent", "folded"), "claude")
        self.assertIsNone(lookup.get("agent", "both"))
        self.assertEqual(lookup.get("AGENT", "both"), "claude")

    def test_two_names_of_one_scope_that_fold_together(self):
        lookup = shell_env.Lookup([{"AGENT": "claude", "agent": "echo"}])
        self.assertIsNone(lookup.get("Agent", "folded"))
        self.assertEqual(lookup.get("agent", "exact"), "echo")

    def test_a_nearer_value_that_is_not_text(self):
        lookup = shell_env.Lookup([{"AGENT": 5}, {"AGENT": "claude"}])
        self.assertIsNone(lookup.get("AGENT", "exact"))
        self.assertEqual(shell_env.Lookup([{"AGENT": 5}], numbers=True).get("AGENT", "exact"), "5")

    def test_untrusted_and_not_plain(self):
        lookup = shell_env.Lookup([{"A": "x"}, {"B": "y"}, {"C": "a'b"}], [True, False, True],
                                  shell_env.PLAIN_VALUE_RE)
        self.assertEqual(lookup.get("A", "exact"), "x")
        self.assertIsNone(lookup.get("B", "exact"))
        self.assertIsNone(lookup.get("C", "exact"))


class ThePutInTest(unittest.TestCase):
    """What OBAAF-GHA-026 reads: a value as one word in PowerShell code, as text in a string, and as text in cmd."""

    def test_pwsh(self):
        values = {"A": "claude", "F": "--x --y"}
        put, _size, names = shell_env.put_in("& $env:A $env:F \"$env:A\" '$env:A'", "pwsh", values.get)
        self.assertEqual(put, "& 'claude' '--x --y' \"claude\" '$env:A'")
        self.assertEqual(names, {"A", "F"})

    def test_cmd(self):
        put, _size, _names = shell_env.put_in("%A% %%A%% %F%", "cmd", {"A": "claude", "F": "--x --y"}.get)
        self.assertEqual(put, "claude %%A%% --x --y")

    def test_a_value_its_place_cannot_hold_is_left(self):
        self.assertEqual(shell_env.put_in("& $env:A", "pwsh", {"A": "it's"}.get)[0], "& $env:A")
        self.assertEqual(shell_env.put_in('"$env:A"', "pwsh", {"A": "a$b"}.get)[0], '"$env:A"')
        self.assertEqual(shell_env.put_in("%A%", "cmd", {"A": "a&b"}.get)[0], "%A%")


class TheScriptSetsTest(unittest.TestCase):
    """A name standing anywhere in the script other than as a reference the shell expands may be set by it (from the
    review: a list of setters was got past)."""

    def sets(self, text, family, name="AGENT", at=None):
        return shell_env.script_sets(text, family).may_set(name, len(text) if at is None else at)

    def test_pwsh(self):
        for text in ("& $env:AGENT --x; $env:PATH.Split(';')", "$agent = $env:AGENT", "Write-Host 'AGENT ready'",
                     "git rm -q old.txt", "function Run($Agent) { & $Agent }"):
            with self.subTest(text=text):
                self.assertFalse(self.sets(text, "pwsh"))
        for text in ("$env:Agent = 'x'", "$env:AGENT, $b = 'claude', 1", "Set-Content -Path ('en'+'v:AGENT') x",
                     "Set-Item env:X x", "[Environment]::SetEnvironmentVariable('A','x')",
                     "(New-Object -ComObject WScript.Shell).Environment('Process')", "rm x",
                     "$t = [Environment]; $t::$m('A'+'GENT', 'x')", "iex $c", ". ./setup.ps1", "& ./setup.ps1",
                     "Import-Module x", "Get-ChildItem Env:", "Copy-Item a b", "$ExecutionContext.SessionState"):
            with self.subTest(text=text):
                self.assertTrue(self.sets(text, "pwsh"))

    def test_cmd_counts_only_earlier_lines(self):
        text = "%AGENT% --x\nset AGENT=echo\n%AGENT% --y"
        self.assertFalse(self.sets(text, "cmd", at=0))
        self.assertTrue(self.sets(text, "cmd"))
        for text in ("se^t AGENT=claude\n%AGENT%", "set,AGENT=claude\n%AGENT%", "set;AGENT=claude\n%AGENT%",
                     'set "Agent=x"\n%AGENT%', "call setup.cmd\n%AGENT%", "set %N%=x\n%AGENT%",
                     "set !N!=x\n%AGENT%", ":a\n%AGENT%\nset AGENT=x\ngoto a"):
            with self.subTest(text=text):
                self.assertTrue(self.sets(text, "cmd", at=text.index("%AGENT%")))
        self.assertFalse(self.sets("call %AGENT% --x", "cmd", at=5))
        self.assertFalse(self.sets("call :sub\n%AGENT%", "cmd"))
        self.assertFalse(self.sets("echo Using AGENT\nset BIN=%AGENT%\n%BIN% -p x", "cmd"))
        # `call :label` runs lines out of their order, as `goto` does (the second review).
        text = "call :setup\n%AGENT% --x\nexit /b\n:setup\nset AGENT=claude\nexit /b"
        self.assertTrue(self.sets(text, "cmd", at=text.index("%AGENT%")))

    def test_linear(self):
        started = time.monotonic()
        shell_env.script_sets("set " * 60_000, "cmd")
        shell_env.script_sets("set a=b " * 60_000 + "\n%a%" * 20_000, "cmd").may_set("a", 10)
        shell_env.script_sets("$env:A " * 60_000, "pwsh")
        self.assertLess(time.monotonic() - started, 5)


class TheLaunchersTest(unittest.TestCase):

    def test_forms(self):
        cases = [
            ("Start-Process -FilePath claude -ArgumentList --x, -p, y", "pwsh", ["claude --x -p y"]),
            ("saps -Wait claude", "pwsh", ["claude"]),
            ("iex -Command claude -p y", "pwsh", ["claude -p y"]),
            ("& claude -p y", "pwsh", ["claude -p y"]),
            ("call claude -p y", "cmd", ["claude -p y"]),
            ("call :label", "cmd", []),
            ("start /wait title claude", "cmd", ["title claude", "claude"]),
            ("@claude -p y", "cmd", ["claude -p y"]),
            ("cmd /c claude", "cmd", ["claude"]),
            ("claude -p y", "pwsh", []),
            ("call claude", None, []),
        ]
        for segment, family, want in cases:
            with self.subTest(segment=segment):
                self.assertEqual(shell_env.command_forms(segment, family), want)


class TheShellTest(unittest.TestCase):
    """`run_shell` and `run_language` are the one reading of a step's shell for both readers."""

    def test_shells(self):
        self.assertEqual(shell_env.run_shell({}, ({}, {}), ["windows-latest"]), "pwsh")
        self.assertEqual(shell_env.run_shell({}, ({}, {}), ["ubuntu-latest"]), "bash")
        self.assertEqual(shell_env.run_shell({}, ({"defaults": {"run": {"shell": "cmd"}}}, {}), []), "cmd")
        self.assertEqual(shell_env.run_shell({"shell": "/usr/bin/pwsh -command {0}"}, (), []), "pwsh")
        self.assertEqual(shell_env.family(shell_env.run_language({"shell": "env pwsh {0}"}, "env")), "pwsh")
        self.assertEqual(shell_env.family("powershell.exe"), "pwsh")
        self.assertEqual(shell_env.family("C:\\Windows\\System32\\cmd.exe"), "cmd")
        self.assertIsNone(shell_env.family("bash"))



# The same command with the program (and, where it stands as a word of its own, the option) written out and named
# through `env` (from the review of 2d.25): what the lanes and OBAAF-GHA-026 give must be the same.
F = "--dangerously-skip-permissions"
PWSH_TEMPLATES = [
    "& {P} {F} -p x",
    "& \"{P}\" {F} -p x",
    "$out = & {P} {F} -p x",
    "Start-Process -FilePath {P} -ArgumentList '" + F + "', '-p', 'x'",
    "Start-Process {P} -ArgumentList '" + F + "','-p','x'",
    "Start-Process -ArgumentList '" + F + "', '-p', 'x' -FilePath {P}",
    "saps {P} '" + F + " -p x'",
    "if ($true) {{ & {P} {F} -p x }}",
    "Write-Host hi; & {P} {F} -p x",
    "'x' | & {P} {F} -p",
    "Write-Host 'nothing runs'; Write-Host {P}",
]
CMD_TEMPLATES = [
    "{P} {F} -p x",
    "@{P} {F} -p x",
    "call {P} {F} -p x",
    "start /wait {P} {F} -p x",
    "cmd /d /c {P} {F} -p x",
    "if 1==1 {P} {F} -p x",
    "for %%i in (1) do {P} {F} -p x",
    "{P} {F} -p x & echo done",
    "echo {P} is installed",
]


class TheLiteralFormTest(unittest.TestCase):
    """A command whose program or option comes from a plain `env` value gives what the same command written out
    gives: the same lane and the same OBAAF-GHA-026."""

    def results(self, cases):
        jobs = ""
        for name, runs_on, shell, run, env in cases:
            shell_line = f"        shell: {shell}\n" if shell else ""
            jobs += (f"  {name}:\n    runs-on: {runs_on}\n    steps:\n      - run: {json.dumps(run)}\n{shell_line}"
                     f"        env: {json.dumps(env)}\n")
        text = "on: workflow_dispatch\npermissions: {}\njobs:\n" + jobs
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
            (tmp / ".github" / "workflows" / "a.yml").write_text(text, encoding="utf-8")
            _code, lanes, report = checked(tmp)
        self.assertEqual(report["errors"], [])
        found = {}
        for f in report["findings"]:
            if f["rule"] == "OBAAF-GHA-026":
                found.setdefault(f["job"], []).append((f["severity"], f["kind"]))
        return {job: (lanes.get(job), sorted(found.get(job, []))) for job in lanes}

    def test_env_and_literal_agree(self):
        cases, pairs = [], []
        for family, templates, runners in (("pwsh", PWSH_TEMPLATES, [("windows-latest", None),
                                                                    ("ubuntu-latest", "pwsh")]),
                                           ("cmd", CMD_TEMPLATES, [("windows-latest", "cmd")])):
            ref = (lambda n: f"$env:{n}") if family == "pwsh" else (lambda n: f"%{n}%")
            for t, template in enumerate(templates):
                for r, (runs_on, shell) in enumerate(runners):
                    for option in (False, True):
                        if option and "{F}" not in template:
                            continue
                        base = f"{family}-{t}-{r}-{int(option)}"
                        literal = template.format(P="claude", F=F)
                        named = template.format(P=ref("AGENT"), F=ref("FLAGS") if option else F)
                        env = {"AGENT": "claude", "FLAGS": F}
                        cases.append((base + "-lit", runs_on, shell, literal, env))
                        cases.append((base + "-env", runs_on, shell, named, env))
                        pairs.append((base, literal, named))
        got = self.results(cases)
        for base, literal, named in pairs:
            with self.subTest(literal=literal, named=named):
                self.assertEqual(got[base + "-env"], got[base + "-lit"])


if __name__ == "__main__":
    unittest.main()
