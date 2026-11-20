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
        "a steering name printed by a command substitution": 'echo "V=$(echo; echo PATH=/tmp/x)" >> "$GITHUB_ENV"',
        "PATH through printf": "printf 'PATH=%s\\n' \"$P\" >> \"$GITHUB_ENV\"",
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
        "printf with %s": "printf 'VERSION=%s\\n' \"$V\" >> \"$GITHUB_ENV\"",
        "stderr to /dev/null": 'echo "SUMMARY=ok" >> "$GITHUB_ENV" 2>/dev/null',
        "a command's output that sets nothing": 'echo "DIGEST=$(sha256sum dist/x | cut -c1-64)" >> "$GITHUB_ENV"',
        "an output written plainly": 'echo "v=1" >> "$GITHUB_OUTPUT"\necho "## done" >> "${GITHUB_STEP_SUMMARY}"',
        "an output through tee": 'echo "v=1" | tee -a "$GITHUB_OUTPUT"',
        "an array's keys": 'a=(x y)\nfor i in "${!a[@]}"; do echo "$i"; done',
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
        "a continued line inside the variable's name": 'echo "PATH=/tmp/x:$PATH" >> "$GITHUB_\\\nENV"',
        "the name split by quotes for printenv": 'echo "PATH=/x" >> "$(printenv GITHUB_E""NV)"',
        "the output file's path changed into the env file's": 'echo "PATH=/x" >> "${GITHUB_OUTPUT/set_output_/set_env_}"',
        "the state file's path changed": 'echo "PATH=/x" >> "${GITHUB_STATE/save_state_/set_env_}"',
        "an indirect expansion": 'for v in ${!GITHUB_E*}; do echo "PATH=/x" >> "${!v}"; done',
        "the folder of the output file": 'echo "PATH=/x" >> "$(dirname "$GITHUB_OUTPUT")"/set_env_*',
        "the output file's path copied": 'o="$GITHUB_OUTPUT"\necho "PATH=/x" >> "${o%output*}env${o#*output}"',
        "the output context's folder": 'echo "PATH=/x" >> "$(dirname "${{ github.output }}")"/set_env_*',
        "printf with another conversion": "printf 'A=%b\\n' \"$V\" >> \"$GITHUB_ENV\"",
        "printf with a second line": "printf 'A=1\\nPATH=/x\\n' >> \"$GITHUB_ENV\"",
        "printf with a computed name": "printf '%s=1\\n' PATH >> \"$GITHUB_ENV\"",
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
                "python reaching it from the output file": run(
                    "import os\nd = os.path.dirname(os.environ['GITHUB_OUTPUT'])", "Prepare", "        shell: python\n"),
                "a custom shell that writes it": run("echo ignored", "Prepare", "        shell: bash -c \"echo "
                                                     "PATH=/tmp/x:$PATH >> $GITHUB_ENV\" {0}\n"),
            }
            for label, step in steps.items():
                with self.subTest(label):
                    text = release(step + run(VERIFY, "Verify") + UPLOAD)
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-016"), CANNOT_TELL)


class OtherFileCommandsTest(unittest.TestCase):
    """The runner names a step's file-command files side by side with one suffix, so the path of any of them
    leads to GITHUB_ENV's (the reviews of slice 2d.13). In bash, writing an output, the summary or the state
    through a plain redirection keeps the check; their path anywhere else does not. Code in another
    language is not read as bash, so naming any of them there does not either."""

    REACHED = {
        "set --": 'set -- "$GITHUB_OUTPUT"\necho "PATH=/x" >> "${1/set_output_/set_env_}"',
        "for": 'for o in "$GITHUB_OUTPUT"; do echo "PATH=/x" >> "${o/set_output_/set_env_}"; done',
        "read": 'read -r o <<< "$GITHUB_OUTPUT"\necho "PATH=/x" >> "${o/set_output_/set_env_}"',
        "printf -v": 'printf -v o %s "$GITHUB_OUTPUT"\necho "PATH=/x" >> "${o/set_output_/set_env_}"',
        "a name reference": 'declare -n o=GITHUB_OUTPUT\necho "PATH=/x" >> "${o/set_output_/set_env_}"',
        "a function's argument": 'f() { echo "PATH=/x" >> "${1/set_output_/set_env_}"; }\nf "$GITHUB_OUTPUT"',
        "a substitution": 'o=$(echo "$GITHUB_OUTPUT")\necho "PATH=/x" >> "${o/set_output_/set_env_}"',
        "a prefix taken off": 'o=x$GITHUB_OUTPUT\no=${o#x}\necho "PATH=/x" >> "${o/set_output_/set_env_}"',
        "sed": 'e=$(echo "$GITHUB_OUTPUT" | sed s/set_output_/set_env_/)\necho "PATH=/x" >> "$e"',
        "python in a bash step": "python3 -c \"import os; open(os.environ['GITHUB_OUTPUT'].replace('output', 'env'), 'a')\"",
        "the summary through sed": 'e=$(echo "$GITHUB_STEP_SUMMARY" | sed s/step_summary_/set_env_/)\necho SHELLOPTS=noexec >> "$e"',
        "a name in ANSI-C quotes": "f=$(printenv $'GITHUB_\\x45NV')\necho \"PATH=/x\" >> \"$f\"",
        "a name in octal": "f=$(printenv $'\\107ITHUB_ENV')\necho \"PATH=/x\" >> \"$f\"",
        "a name reference in ANSI-C quotes": "declare -n f=$'GITHUB_\\x45NV'\necho \"PATH=/x\" >> \"$f\"",
        "a tool given the output's path": 'tool --github-output="$GITHUB_OUTPUT"',
        "a nested substitution": 'echo "V=${X:-$(echo; echo PATH=/tmp/x:$PATH)}" >> "$GITHUB_ENV"',
        "a nested substitution with +": 'echo "V=${HOME:+$(echo; echo SHELLOPTS=noexec)}" >> "$GITHUB_ENV"',
        "a substitution with a quote-split name": 'echo "V=$(echo; echo P""ATH=/tmp/x)" >> "$GITHUB_ENV"',
    }

    def test_another_file_commands_path_used_otherwise_makes_it_cannot_tell(self):
        with TempDir() as tmp:
            for label, script in self.REACHED.items():
                with self.subTest(label):
                    self.assertEqual(kinds(check(tmp, before_check(script)), "OBAAF-GHA-016"), CANNOT_TELL)

    PLAIN = {
        "a version from the ref": 'echo "version=$(basename "$GITHUB_REF")" >> "$GITHUB_OUTPUT"',
        "a listing to the summary": 'ls -la dist >> "$GITHUB_STEP_SUMMARY"\ncd dist && ls >> "$GITHUB_STEP_SUMMARY"',
        "a default for running outside Actions": 'echo "v=1" >> "${GITHUB_OUTPUT:-/dev/stdout}"',
        "tee to the summary": 'echo "## built" | tee -a "$GITHUB_STEP_SUMMARY"',
        "a check that secrets are set": 'for v in NPM_TOKEN TWINE_PASSWORD; do [ -z "${!v}" ] && exit 1; done',
        "an option in a substitution": 'echo "V=$(tool --home=/tmp/t)" >> "$GITHUB_ENV"',
        "a query in a substitution": "echo \"C=$(gh api 'repos/o/r/contents?path=x')\" >> \"$GITHUB_ENV\"",
        "names listed with another prefix": 'echo "${!CI_@}"',
    }

    def test_a_plain_write_to_another_file_command_keeps_the_check(self):
        with TempDir() as tmp:
            for label, script in self.PLAIN.items():
                with self.subTest(label):
                    self.assertEqual(of(check(tmp, before_check(script)), "OBAAF-GHA-016"), [])

    def test_code_in_another_language_that_names_one_makes_it_cannot_tell(self):
        with TempDir() as tmp:
            step = run("import os\nwith open(os.environ['GITHUB_OUTPUT'], 'a') as f:\n    f.write('v=1\\n')",
                       "Prepare", "        shell: python\n")
            self.assertEqual(kinds(check(tmp, release(step + run(VERIFY, "Verify") + UPLOAD)), "OBAAF-GHA-016"),
                             CANNOT_TELL)
            plain = run("print('Publishing...')", "Prepare", "        shell: python\n")
            self.assertEqual(of(check(tmp, release(plain + run(VERIFY, "Verify") + UPLOAD)), "OBAAF-GHA-016"), [])


class TheThirdReviewTest(unittest.TestCase):
    """Ways past the third version: `tee`'s own output sent to GITHUB_ENV, `$'...'` in an sh step (dash does
    not read it and its `echo` reads the backslash), a read-write redirection that writes over an earlier
    line, a descriptor left open on an output, and a container's `env` and `options`."""

    WAYS = {
        "tee's output to the env file": 'echo "PATH=/tmp/x:$PATH" | tee -a "$GITHUB_OUTPUT" >> "$GITHUB_ENV"',
        "tee from a here-string": 'tee "$GITHUB_STEP_SUMMARY" >> "$GITHUB_ENV" <<< "SHELLOPTS=noexec"',
        "tee with 1>>": 'echo "PATH=/x" | tee -a "$GITHUB_STATE" 1>>"$GITHUB_ENV"',
        "ANSI-C quotes": "echo V=$'\\0012'PATH=/tmp/x:/usr/bin:/bin >> \"$GITHUB_ENV\"",
        "ANSI-C quotes between strings": 'echo "V=1"$\'\\0012\'"PATH=/tmp/x" >> "$GITHUB_ENV"',
        "a read-write redirection": 'echo "VVVVPATH=/tmp/x:/usr/bin:/bin" >> "$GITHUB_ENV"\necho "V=1" 1<> "$GITHUB_ENV"',
        "printf with a read-write redirection": "printf 'V=%s\\n' 1 1<>\"$GITHUB_ENV\"",
        "a descriptor left open on an output": 'exec 3>>"$GITHUB_OUTPUT"\nf=$(readlink /proc/self/fd/3)',
        "a continued line inside <>": 'echo "VVVVPATH=/tmp/x:/usr/bin" >> "$GITHUB_ENV"\necho "V=1" 1<\\\n>"$GITHUB_ENV"',
        "a continued line inside <> with no descriptor": 'echo "VVVVPATH=/x" >> "$GITHUB_ENV"\necho "V=1" <\\\n>"$GITHUB_ENV"',
    }

    def test_each_way_past_is_cannot_tell(self):
        with TempDir() as tmp:
            for label, script in self.WAYS.items():
                with self.subTest(label):
                    self.assertEqual(kinds(check(tmp, before_check(script)), "OBAAF-GHA-016"), CANNOT_TELL)
            sh = before_check("echo V=$'\\0012'PATH=/x >> \"$GITHUB_ENV\"", extra="        shell: sh\n")
            self.assertEqual(kinds(check(tmp, sh), "OBAAF-GHA-016"), CANNOT_TELL)

    def test_a_containers_env_or_options_can_change_what_the_check_runs(self):
        with TempDir() as tmp:
            for container in ("    container:\n      image: ubuntu:24.04\n      env:\n        PATH: /tmp/evil:/usr/bin\n",
                              "    container:\n      image: ubuntu:24.04\n      options: -e LD_PRELOAD=/tmp/x.so\n",
                              "    container:\n      image: ubuntu:24.04\n      options: --env-file x.env\n",
                              "    container:\n      image: ubuntu:24.04\n      env: ${{ fromJSON(vars.E) }}\n"):
                with self.subTest(container):
                    text = release(run(VERIFY, "Verify") + UPLOAD,
                                   job_extra="    environment: release\n    cache-mode: none\n" + container)
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-016"), CANNOT_TELL)
            plain = release(run(VERIFY, "Verify") + UPLOAD, job_extra="    environment: release\n    cache-mode: none\n"
                            "    container:\n      image: ubuntu:24.04\n      env:\n        VERSION: '1'\n"
                            "      options: --cpus 2\n")
            self.assertEqual(of(check(tmp, plain), "OBAAF-GHA-016"), [])

    def test_tee_and_plain_redirections_that_stay_harmless(self):
        with TempDir() as tmp:
            for script in ('echo "## notes" | tee -a "$GITHUB_STEP_SUMMARY" > /dev/null',
                           'echo "V=1" > "$GITHUB_ENV"', 'echo "V=1" &>> "$GITHUB_ENV"'):
                with self.subTest(script):
                    self.assertEqual(of(check(tmp, before_check(script)), "OBAAF-GHA-016"), [])


class TheJobsTextTest(unittest.TestCase):
    """A write held in the workflow's or the job's `env`, `defaults` or `strategy` can be run by any step."""

    def test_a_write_in_the_jobs_text_makes_the_check_cannot_tell(self):
        with TempDir() as tmp:
            write = "echo PATH=/tmp/x:$PATH >> $GITHUB_ENV"
            job_env = release(run('eval "$CMD"', "Prepare") + run(VERIFY, "Verify") + UPLOAD).replace(
                "      OBAAF_LANE: release\n", f"      OBAAF_LANE: release\n      CMD: '{write}'\n")
            workflow_env = release(run('bash -c "$CMD"', "Prepare") + run(VERIFY, "Verify") + UPLOAD).replace(
                "permissions: {}\n", "permissions: {}\nenv:\n  CMD: 'echo SHELLOPTS=noexec >> $GITHUB_ENV'\n", 1)
            expression = release(run("${{ env.CMD }}", "Prepare") + run(VERIFY, "Verify") + UPLOAD).replace(
                "      OBAAF_LANE: release\n", f"      OBAAF_LANE: release\n      CMD: '{write}'\n")
            matrix = release(run("${{ matrix.cmd }}", "Prepare") + run(VERIFY, "Verify") + UPLOAD,
                             job_extra="    environment: release\n    cache-mode: none\n    strategy:\n"
                                       f"      matrix:\n        cmd: ['{write}']\n")
            continued = release(run('eval "$CMD"', "Prepare", "        env:\n          CMD: |\n"
                                    "            echo PATH=/tmp/x:$PATH >> $GITHUB_\\\n            ENV\n")
                                + run(VERIFY, "Verify") + UPLOAD)
            for label, text in (("job env", job_env), ("workflow env", workflow_env), ("expression", expression),
                                ("matrix", matrix), ("a continued line in a step's env", continued)):
                with self.subTest(label):
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-016"), CANNOT_TELL)

    def test_a_long_word_is_read_quickly(self):
        import time
        with TempDir() as tmp:
            for script in ("echo " + "a" * 40_000, 'echo "V=$(echo ' + "b" * 40_000 + ')" >> "$GITHUB_ENV"',
                           "ls " * 16_000 + ">> $GITHUB_OUTPUT"):
                with self.subTest(len(script)):
                    started = time.monotonic()
                    check(tmp, before_check(script))
                    self.assertLess(time.monotonic() - started, 2.0)


class MacLoaderTest(unittest.TestCase):
    """The rule counts a check on a macOS runner, where the loader's variables are `DYLD_...`, and the runner
    keeps `DYLD_INSERT_LIBRARIES` for each step's process (Handlers/ScriptHandler.cs, v2.338.2)."""

    def test_dyld_names_make_the_check_cannot_tell(self):
        with TempDir() as tmp:
            for name in ("DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
                with self.subTest(name):
                    text = before_check(f'echo "{name}=/tmp/x.dylib" >> "$GITHUB_ENV"').replace(
                        "ubuntu-latest", "macos-14")
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-016"), CANNOT_TELL)
                    in_env = release(run(VERIFY, "Verify", f"        env:\n          {name}: /tmp/x.dylib\n")
                                     + UPLOAD).replace("ubuntu-latest", "macos-14")
                    self.assertEqual(kinds(check(tmp, in_env), "OBAAF-GHA-016"), CANNOT_TELL)
            plain = before_check('echo "VERSION=1" >> "$GITHUB_ENV"').replace("ubuntu-latest", "macos-14")
            self.assertEqual(of(check(tmp, plain), "OBAAF-GHA-016"), [])


class ProgramChangedThroughEnvTest(unittest.TestCase):
    """An `env` of the check's step, its job or its workflow that changes what the check runs. Before
    this slice only `BASH_ENV`, `ENV` and `BASH_FUNC...` there made the check not count."""

    STEERING = ["PATH", "SHELLOPTS", "BASHOPTS", "PS4", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH",
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
