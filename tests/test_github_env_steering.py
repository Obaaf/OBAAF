"""Slice 2d.13 (F-278): what an earlier step sets for the steps after it that changes what a check runs.

OBAAF-GHA-016 (and the other rules that count a command only where its failure stops the job: OBAAF-GHA-021's
checks and OBAAF-GHA-017's provenance commands) did not vouch for a check after an earlier step whose text named `BASH_ENV`, `BASH_FUNC` or
`GITHUB_PATH`. It did vouch for one after `echo "PATH=$PWD/fake:$PATH" >> "$GITHUB_ENV"`: the runner
gives every later step what a step writes to that file (actions/runner v2.338.2, `SetEnvFileCommand` in
src/Runner.Worker/FileCommandManager.cs refuses only `NODE_OPTIONS`), so the `obaaf` the check names is
then whatever the job put first on the PATH. `SHELLOPTS=noexec` written the same way makes bash read
the check's step without running any of it, and the step succeeds. Each such input here is inert: the
workflows are only read. Each has a harmless neighbour that must stay as it was.
"""

import unittest

from helpers import TempDir

from test_release_effect_bypasses import SHA, UPLOAD, VERIFY, check, kinds, of, release, run

CANNOT_TELL = [("high", "cannot-tell")]


def before_check(script, name="Prepare", extra=""):
    """A release job: a step with `script`, then the check, then the upload."""
    return release(run(script, name, extra) + run(VERIFY, "Verify") + UPLOAD)


class ProgramChangedThroughGitHubEnvTest(unittest.TestCase):
    """A name written to GITHUB_ENV that changes what a later bash step runs."""

    STEERING = {
        "PATH, the case F-278 found": 'echo "PATH=$RUNNER_TEMP/fake:$PATH" >> "$GITHUB_ENV"',
        "PATH unquoted": "echo PATH=/tmp/fake:/usr/bin >> $GITHUB_ENV",
        "PATH in braces": 'echo "PATH=/tmp/fake" >> "${GITHUB_ENV}"',
        "PATH in other letters": "echo path=/tmp/fake >> $GITHUB_ENV",
        "PATH split by quotes": 'echo P"A"TH=/tmp/fake >> "$GITHUB_ENV"',
        "PATH as the second write of a line": 'echo A=1 >> "$GITHUB_ENV" && echo PATH=/x >> "$GITHUB_ENV"',
        "PATH inside an if": 'if true; then echo PATH=/x >> "$GITHUB_ENV"; fi',
        "SHELLOPTS (noexec skips the check)": 'echo "SHELLOPTS=noexec" >> "$GITHUB_ENV"',
        "BASHOPTS": 'echo "BASHOPTS=xpg_echo" >> "$GITHUB_ENV"',
        "BASH_COMPAT": 'echo "BASH_COMPAT=31" >> "$GITHUB_ENV"',
        "ENV": 'echo "ENV=/tmp/x.sh" >> "$GITHUB_ENV"',
        "PS4": "echo 'PS4=$(id)' >> \"$GITHUB_ENV\"",
        "EXECIGNORE": 'echo "EXECIGNORE=/usr/*" >> "$GITHUB_ENV"',
        "LD_PRELOAD": 'echo "LD_PRELOAD=/tmp/x.so" >> "$GITHUB_ENV"',
        "LD_AUDIT": 'echo "LD_AUDIT=/tmp/x.so" >> "$GITHUB_ENV"',
        "GCONV_PATH": 'echo "GCONV_PATH=/tmp/gconv" >> "$GITHUB_ENV"',
        "PYTHONPATH": 'echo "PYTHONPATH=/tmp/py" >> "$GITHUB_ENV"',
        "PYTHONWARNINGS (imports a module)": 'echo "PYTHONWARNINGS=ignore::x.W" >> "$GITHUB_ENV"',
        "HOME (Python's user site)": 'echo "HOME=/tmp/home" >> "$GITHUB_ENV"',
        "ACTIONS_ALLOW_UNSECURE_COMMANDS": 'echo "ACTIONS_ALLOW_UNSECURE_COMMANDS=true" >> "$GITHUB_ENV"',
        "a heredoc-style write of PATH": 'echo "PATH<<EOF" >> "$GITHUB_ENV"\necho /x >> "$GITHUB_ENV"\necho EOF >> "$GITHUB_ENV"',
    }

    def test_a_steering_name_written_to_github_env_before_the_check_makes_it_cannot_tell(self):
        with TempDir() as tmp:
            for label, script in self.STEERING.items():
                with self.subTest(label):
                    self.assertEqual(kinds(check(tmp, before_check(script)), "OBAAF-GHA-016"), CANNOT_TELL)

    def test_the_check_is_named_among_those_the_checker_cannot_vouch_for(self):
        with TempDir() as tmp:
            found = of(check(tmp, before_check(self.STEERING["PATH, the case F-278 found"])), "OBAAF-GHA-016")
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].facts["checks"], ["r: Verify"])

    HARMLESS = {
        "a literal version": 'echo "VERSION=1.2.3" >> "$GITHUB_ENV"',
        "a version from the tag": 'echo "VERSION=${GITHUB_REF_NAME#v}" >> "$GITHUB_ENV"',
        "a command's output as the value": "echo TAG=$(git describe --tags) >> $GITHUB_ENV",
        "the agent-apply template's form": 'bundle="$RUNNER_TEMP/b/attestation.json"\necho "AGENT_RUN_BUNDLE=$bundle" >> "$GITHUB_ENV"',
        "two words on one line": 'echo "A=1" "B=2" >> "${GITHUB_ENV}"',
        "a test before it": '[ -n "$X" ] && echo "X_SET=1" >> "$GITHUB_ENV"',
        "inside an if": 'if true; then echo "RELEASE=1" >> "$GITHUB_ENV"; fi',
        "a comment that names PATH": '# PATH is not changed here\necho "VERSION=1" >> "$GITHUB_ENV"',
        "a name that only starts like PATH": 'echo "PATHNAME=x" >> "$GITHUB_ENV"\necho "ENVIRONMENT=prod" >> "$GITHUB_ENV"',
        "PYTHONUNBUFFERED": 'echo "PYTHONUNBUFFERED=1" >> "$GITHUB_ENV"',
        "a continued line": 'echo "VERSION=1" \\\n  >> "$GITHUB_ENV"',
    }

    def test_a_harmless_name_written_to_github_env_keeps_the_check(self):
        with TempDir() as tmp:
            for label, script in self.HARMLESS.items():
                with self.subTest(label):
                    self.assertEqual(of(check(tmp, before_check(script)), "OBAAF-GHA-016"), [])

    def test_a_write_after_the_check_does_not_change_it(self):
        with TempDir() as tmp:
            after = release(run(VERIFY, "Verify") + run('echo "PATH=/tmp/fake" >> "$GITHUB_ENV"', "Later") + UPLOAD)
            self.assertEqual(of(check(tmp, after), "OBAAF-GHA-016"), [])

    def test_a_write_in_another_job_does_not_change_the_check(self):
        with TempDir() as tmp:
            text = ("on: push\npermissions: {}\njobs:\n  prep:\n    runs-on: ubuntu-latest\n    steps:\n"
                    + run('echo "PATH=/tmp/fake" >> "$GITHUB_ENV"', "Prepare")
                    + "  r:\n    needs: prep\n    runs-on: ubuntu-latest\n    environment: release\n"
                      "    cache-mode: none\n    env:\n      OBAAF_LANE: release\n    steps:\n"
                    + run(VERIFY, "Verify") + UPLOAD)
            self.assertEqual(of(check(tmp, text), "OBAAF-GHA-016"), [])


class WriteTheCheckerCannotReadTest(unittest.TestCase):
    """A write to GITHUB_ENV whose name the checker cannot read may set any name, PATH among them."""

    UNREAD = {
        "a computed name": 'echo "$NAME=x" >> "$GITHUB_ENV"',
        "a computed name in braces": 'echo "${NAME}=x" >> "$GITHUB_ENV"',
        "a name from an expression": 'echo "${{ inputs.name }}=x" >> "$GITHUB_ENV"',
        "a name from a glob": "echo P*=1 >> $GITHUB_ENV",
        "a name from a brace expansion": "echo {A,PATH}=1 >> $GITHUB_ENV",
        "a file's lines": 'cat env.txt >> "$GITHUB_ENV"',
        "a heredoc": 'cat >> "$GITHUB_ENV" <<EOF\nVERSION=1\nEOF',
        "printf": "printf 'VERSION=%s\\n' \"$V\" >> \"$GITHUB_ENV\"",
        "tee": 'tee -a "$GITHUB_ENV" < env.txt',
        "a group": '{ echo "A=1"; echo "B=2"; } >> "$GITHUB_ENV"',
        "a subshell": '( echo "A=1" ) >> "$GITHUB_ENV"',
        "the file's path in a variable": 'f="$GITHUB_ENV"\necho "A=1" >> "$f"',
        "a descriptor opened on it": 'exec 3>>"$GITHUB_ENV"\necho "A=1" >&3',
        "echo -e with a line break": 'echo -e "A=1\\nPATH=/x" >> "$GITHUB_ENV"',
        "a backslash sh's echo reads as a line break": "echo 'A=1\\nPATH=/x' >> \"$GITHUB_ENV\"",
        "a quoted line break": 'echo "A=1\nPATH=/x" >> "$GITHUB_ENV"',
        "an ANSI-C line break": "echo $'A=1\\nPATH=/x' >> \"$GITHUB_ENV\"",
        "a first word that is computed": 'echo $PREFIX A=1 >> "$GITHUB_ENV"',
        "an empty first word": 'echo "" A=1 >> "$GITHUB_ENV"',
        "a line with no name": 'echo "just text" >> "$GITHUB_ENV"',
        "a command substitution that writes": 'echo "A=$(echo PATH=/x >> "$GITHUB_ENV")"',
        "echo replaced by a function": "echo() { printf 'PATH=/x\\n'; }\necho A=1 >> \"$GITHUB_ENV\"",
        "echo replaced by a loaded builtin": 'enable -f ./x.so echo\necho A=1 >> "$GITHUB_ENV"',
        "a nested shell": 'bash -c \'echo A=1 >> "$GITHUB_ENV"\'',
        "a program given the path": 'python3 write.py "$GITHUB_ENV"',
        "an unclosed quote": 'echo "A=1 >> "$GITHUB_ENV',
        "the runner's context for the file": 'echo "VERSION=1" >> "${{ github.env }}"',
        "the runner's context, upper case": 'echo "VERSION=1" >> "${{ GITHUB.ENV }}"',
        "the runner's context as JSON": "echo '${{ toJSON(github) }}' > ctx.json\npython3 w.py ctx.json",
        "the PATH file through the context": 'echo /tmp/fake >> "${{ github.path }}"',
    }

    def test_an_unread_write_before_the_check_makes_it_cannot_tell(self):
        with TempDir() as tmp:
            for label, script in self.UNREAD.items():
                with self.subTest(label):
                    self.assertEqual(kinds(check(tmp, before_check(script)), "OBAAF-GHA-016"), CANNOT_TELL)

    def test_other_shells_and_actions_that_write_it_make_it_cannot_tell(self):
        with TempDir() as tmp:
            steps = {
                "pwsh": run('"VERSION=1" >> $env:GITHUB_ENV', "Prepare", "        shell: pwsh\n"),
                "python": run("import os\nopen(os.environ['GITHUB_ENV'], 'a').write('A=1\\n')", "Prepare",
                              "        shell: python\n"),
                "github-script exportVariable": (f"      - uses: actions/github-script@{SHA}\n        with:\n"
                                                 "          script: core.exportVariable('PATH', '/x')\n"),
                "github-script addPath": (f"      - uses: actions/github-script@{SHA}\n        with:\n"
                                          "          script: core.addPath('/x')\n"),
                "an action's input": (f"      - uses: nick-fields/retry@{SHA}\n        with:\n          command: "
                                      "echo VERSION=1 >> $GITHUB_ENV\n"),
                "a step's env holding the write": run('eval "$CMD"', "Prepare", "        env:\n          CMD: "
                                                      "echo VERSION=1 >> $GITHUB_ENV\n"),
                "set-env": run('echo "::set-env name=PATH::/x"', "Prepare"),
                "add-path": run('echo "::add-path::/x"', "Prepare"),
                "the runner's folder for file commands": run('echo A=1 >> "$RUNNER_TEMP"/_runner_file_commands/f',
                                                             "Prepare"),
            }
            for label, step in steps.items():
                with self.subTest(label):
                    text = release(step + run(VERIFY, "Verify") + UPLOAD)
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-016"), CANNOT_TELL)


class ProgramChangedThroughEnvTest(unittest.TestCase):
    """An `env` of the check's step, its job or its workflow that changes what the check runs. Before
    this slice only `BASH_ENV`, `ENV` and `BASH_FUNC...` there made the check not count."""

    STEERING = ["PATH", "SHELLOPTS", "BASHOPTS", "PS4", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH",
                "PYTHONHOME", "HOME", "GCONV_PATH", "EXECIGNORE", "ACTIONS_ALLOW_UNSECURE_COMMANDS",
                " path ", "${{ inputs.name }}"]
    HARMLESS = ["PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PYTHONIOENCODING", "VERSION", "GH_TOKEN",
                "NODE_OPTIONS", "PATHS"]

    def scopes(self, key):
        entry = f"'{key}': /tmp/x"
        step_env = run(VERIFY, "Verify", f"        env:\n          {entry}\n")
        yield "step", release(step_env + UPLOAD)
        yield "job", release(run(VERIFY, "Verify") + UPLOAD,
                             job_extra=f"    environment: release\n    cache-mode: none\n    defaults:\n"
                                       f"      run:\n        shell: bash -e {{0}}\n").replace(
            "    env:\n      OBAAF_LANE: release\n", f"    env:\n      OBAAF_LANE: release\n      {entry}\n")
        yield "workflow", release(run(VERIFY, "Verify") + UPLOAD).replace(
            "permissions: {}\n", f"permissions: {{}}\nenv:\n  {entry}\n", 1)

    def test_a_steering_name_in_any_env_makes_the_check_cannot_tell(self):
        with TempDir() as tmp:
            for key in self.STEERING:
                for scope, text in self.scopes(key):
                    with self.subTest(key=key, scope=scope):
                        self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-016"), CANNOT_TELL)

    def test_a_harmless_name_in_any_env_keeps_the_check(self):
        with TempDir() as tmp:
            for key in self.HARMLESS:
                for scope, text in self.scopes(key):
                    with self.subTest(key=key, scope=scope):
                        self.assertEqual(of(check(tmp, text), "OBAAF-GHA-016"), [])


class RecordChecksTest(unittest.TestCase):
    """OBAAF-GHA-021 counts `obaaf verify agent-run` and `obaaf proposal check` with the same reader. Any
    `run` step before them already counts as one that may apply, so only the `env` part changes it."""

    def effect(self, steps, env=""):
        return ("on:\n  workflow_run:\n    workflows: [p]\n    types: [completed]\npermissions: {}\njobs:\n"
                "  apply:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n"
                f"    environment: apply\n    env:\n      OBAAF_LANE: effect\n{env}    steps:\n" + steps)

    CHECKS = run("obaaf verify agent-run --policy p --proposal x --snapshot s --bundle b", "Record") + \
        run("obaaf proposal check x --repo .", "Proposal")
    APPLY = run("git apply x/patch.diff && git push", "Apply")

    def test_a_path_in_the_jobs_env_means_the_checks_do_not_count(self):
        with TempDir() as tmp:
            steered = self.effect(self.CHECKS + self.APPLY, "      PATH: /tmp/fake:/usr/bin\n")
            self.assertEqual(kinds(check(tmp, steered), "OBAAF-GHA-021"), [("high", "unchecked")])
            harmless = self.effect(self.CHECKS + self.APPLY, "      PYTHONUNBUFFERED: '1'\n")
            self.assertEqual(of(check(tmp, harmless), "OBAAF-GHA-021"), [])



class ProvenanceCommandTest(unittest.TestCase):
    """OBAAF-GHA-017 counts `cosign attest` in a `run` step as signing provenance with the same reader."""

    def workflow(self, attest_steps):
        return ("on: push\npermissions: {}\njobs:\n  attest:\n    runs-on: ubuntu-latest\n"
                "    permissions:\n      id-token: write\n      attestations: write\n"
                f"    steps:\n{attest_steps}"
                "  r:\n    runs-on: ubuntu-latest\n    environment: release\n    cache-mode: none\n"
                f"    env:\n      OBAAF_LANE: release\n    steps:\n{UPLOAD}")

    SIGN = run("cosign attest-blob --predicate p.json --type slsaprovenance dist/x", "Sign")

    def test_a_path_written_before_the_signing_command_means_it_does_not_count(self):
        with TempDir() as tmp:
            self.assertEqual(of(check(tmp, self.workflow(self.SIGN)), "OBAAF-GHA-017"), [])
            steered = run('echo "PATH=/tmp/fake:$PATH" >> "$GITHUB_ENV"', "Prepare") + self.SIGN
            self.assertEqual(len(of(check(tmp, self.workflow(steered)), "OBAAF-GHA-017")), 1)
            harmless = run('echo "DIGEST=$(sha256sum dist/x)" >> "$GITHUB_ENV"', "Prepare") + self.SIGN
            self.assertEqual(of(check(tmp, self.workflow(harmless)), "OBAAF-GHA-017"), [])

if __name__ == "__main__":
    unittest.main()
