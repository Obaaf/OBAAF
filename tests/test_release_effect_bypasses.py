"""Slice 2d.2e: release and effect jobs.

Two reviewers that did not write them tried to get past the seven rules about release and effect jobs:
OBAAF-GHA-006 (a release job reads a shared cache), 007 (an outsider's run writes the cache), 014 (a
release job with no protected environment), 016 (an upload without a check that stops it), 017 (no
provenance), 021 (agent output applied unchecked) and 022 (agent output applied with no approval).
Every way past that the checker did not already report is a test here; the record of every attempt,
including the ones that held, is docs/bypass-attempts.md.
"""

import json
import unittest

from helpers import TempDir

from obaaf import checker

SHA = "1111111111111111111111111111111111111111"


def check(tmp, text, name="wf.yml"):
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    for old in (root / ".github" / "workflows").iterdir():
        old.unlink()
    (root / ".github" / "workflows" / name).write_text(text, encoding="utf-8")
    return checker.check(root)


def of(result, rule):
    return [f for f in result.findings if f.rule == rule]


def kinds(result, rule):
    return sorted((f.severity, f.kind) for f in of(result, rule))


def release(steps, job_extra="    environment: release\n    cache-mode: none\n", on="push"):
    """A release job (declared) that publishes in its last step."""
    return (f"on: {on}\npermissions: {{}}\njobs:\n  r:\n    runs-on: ubuntu-latest\n{job_extra}"
            f"    env:\n      OBAAF_LANE: release\n    steps:\n{steps}")


def run(script, name="s", extra=""):
    body = "".join(f"          {line}\n" for line in script.splitlines())
    return f"      - name: {name}\n{extra}        run: |\n{body}"


UPLOAD = run("npm publish", "Upload", "        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n")
VERIFY = "obaaf verify release --policy p.yaml --artifacts dist"


class BindingReaderTest(unittest.TestCase):
    """OBAAF-GHA-016 and 021 counted a check wherever its text appeared in a step. A check now counts
    only where its failure stops the job: a command of its own at the top level of a POSIX shell
    script that stops on failure."""

    IGNORED = {
        "comment": f"# {VERIFY}",
        "echo": f"echo {VERIFY}",
        "heredoc": f"cat <<EOF\n{VERIFY}\nEOF",
        "after exit 0": f"exit 0\n{VERIFY}",
        "in a function never called": f"f() {{\n  {VERIFY}\n}}",
        "colon": f": {VERIFY}",
        "after true ||": f"true || {VERIFY}",
        "and list, not last": f"{VERIFY} && echo ok\necho next",
        "and at the end of a line": f"{VERIFY} &&\necho ok",
        "test and": f"[ -z \"$SKIP\" ] && {VERIFY}",
        "if condition": f"if {VERIFY}; then echo ok; fi",
        "until condition": f"until {VERIFY}; do sleep 1; done",
        "negated": f"! {VERIFY}",
        "substitution": f"echo \"$({VERIFY})\"",
        "local substitution": f"x=$({VERIFY})",
        "nested shell": f"sh -c \"true; {VERIFY}; true\"",
        "pipe without pipefail": f"{VERIFY} | tee log",
        "or true on the next line": f"{VERIFY} \\\n  || true",
        "background": f"{VERIFY} &\nwait",
        "set +o errexit": f"set +o errexit\n{VERIFY}",
        "set +eu": f"set +eu\n{VERIFY}",
        "set +e in an if": f"if true; then set +e; fi\n{VERIFY}",
        "false or set +e": f"false || set +e\n{VERIFY}",
        "shopt": f"shopt -uo errexit\n{VERIFY}",
        "trap": f"trap 'exit 0' ERR\n{VERIFY}",
        "shadowing function": f"obaaf() {{ :; }}\n{VERIFY}",
        "help": "obaaf verify release --help",
        "quoted separator": f"echo \";\" {VERIFY}",
        # The review of slice 2d.2e.
        "exit inside an if": f"if [ \"${{GITHUB_REF:-}}\" != refs/tags/v1 ]; then exit 0; fi\n{VERIFY}",
        "exit in a case": f"case x in\n  *) exit 0 ;;\nesac\n{VERIFY}",
        "exit in a group": f"{{ exit 0; }}\n{VERIFY}",
        "exit in a loop": f"while true; do exit 0; done\n{VERIFY}",
        "a function that exits": f"skip() {{ exit 0; }}\nskip\n{VERIFY}",
        "inside an if that never runs": f"if false; then\n  {VERIFY}\nfi",
        "after a quoted fi": f"if false; then\n\"fi\"\n{VERIFY}\nfi",
        "after an escaped fi": f"if false; then\n\\fi\n{VERIFY}\nfi",
        "case hiding the check": f"case x in never) echo esac\n{VERIFY}\n;; esac",
        "ansi-c quoting": f"echo $'\\''\n{VERIFY}\n'",
        "partly quoted here-document": f"cat <<E\"O\"F\nE\n{VERIFY}\nEOF",
        "exit 256": f"{VERIFY} || exit 256",
        "exit 00": f"{VERIFY} || exit 00",
        "exit -0": f"{VERIFY} || exit -0",
        "false or true": f"{VERIFY} || false || true",
        "exit piped": f"{VERIFY} || exit 1 | cat",
        "exit in the background": f"{VERIFY} || exit 1 &",
        "group in the background": f"{VERIFY} || {{ exit 1 & }}",
        "group with a list": f"{VERIFY} || {{ true || exit 1; }}",
        "group with a pipe": f"{VERIFY} || {{ exit 1 | cat; }}",
        "false redefined": f"false() {{ true; }}\n{VERIFY} || false",
        "exec first": f"exec true\n{VERIFY}",
        "builtin exit": f"builtin exit 0\n{VERIFY}",
        "eval exit": f"eval exit 0\n{VERIFY}",
        "source": f"source /dev/stdin <<< 'exit 0'\n{VERIFY}",
        "builtin set": f"builtin set +e\n{VERIFY}\necho after",
        "eval set": f"eval 'set +e'\n{VERIFY}\necho after",
        "set from a variable": f"E=e; set +$E\n{VERIFY}\necho after",
        "set from a whole variable": f"F=+e; set $F\n{VERIFY}\necho after",
        "dot of a substitution": f". <(echo 'set +e')\n{VERIFY}\necho after",
        "eval of a function": f"eval 'obaaf() {{ :; }}'\n{VERIFY}",
        "hash": f"hash -p /bin/true obaaf\n{VERIFY}",
        "path": f'PATH="$PWD/f:$PATH"\n{VERIFY}',
        "env --version": f"env --version {VERIFY}",
        "timeout --help": f"timeout --help {VERIFY}",
        "expression with shell syntax after": VERIFY + " ${{ '|| true' }}",
        "expression with shell syntax before": "${{ 'exit 0' }}\n" + VERIFY,
        "expression the checker cannot read": "${{ inputs.prepare }}\n" + VERIFY,
        # The second pass of the review.
        "quotes inside exit": f'e"x"it 0\n{VERIFY}',
        "backslash inside exit": f"e\\xit 0\n{VERIFY}",
        "empty quotes inside exit": f"ex''it 0\n{VERIFY}",
        "empty quotes inside eval": f"ev''al 'set +e'\n{VERIFY}\necho after",
        "exit continued over two lines": f"ex\\\nit 0\n{VERIFY}",
        "if continued over two lines": f"i\\\nf false; then\n{VERIFY}\nfi",
        "a comment ending in a backslash": f"# note \\\nexit 0\n{VERIFY}",
        "an escaped space before a hash": f"echo a\\ #; exit 0\n{VERIFY}",
        "time if": f"time if false; then\n{VERIFY}\nfi",
        "a command named fi": f"if false; then\nX=1 fi\n{VERIFY}\nfi",
        "a parenthesis in an expansion": "if false; then\necho ${x:-)}\n" + VERIFY + "\nfi",
        "a parenthesis after a comment sign": f"if false; then\n(true)#)\n{VERIFY}\nfi",
        "or at the end of the line before": f"true ||\n{VERIFY}",
        "and at the end of the line before": f"false &&\n{VERIFY}\necho done",
        "path from a loop": f'for PATH in "$PWD/f:$PATH"; do :; done\n{VERIFY}',
        "path from read": f'read -r PATH <<< "$PWD/f"\n{VERIFY}',
        "path from printf": f'printf -v PATH %s "$PWD/f"\n{VERIFY}',
        "path as a prefix": f'PATH="$PWD/f:$PATH" {VERIFY}',
        "mapfile callback": f"mapfile -t -C 'exit 0 #' -c 1 a <<< x\n{VERIFY}",
        # The third pass of the review.
        "bash's command table": f"BASH_CMDS[obaaf]=/bin/true\n{VERIFY}",
        "the command table in a quoted expansion": ': "${BASH_CMDS[obaaf]:=/bin/true}"\n' + VERIFY,
        "path in a quoted arithmetic expansion": ': "$((PATH=5))"\n' + VERIFY,
        "path through PS4": f"PS4='$((PATH=5))'\nset -x\n{VERIFY}",
        "an interpreter variable exported": f"export PYTHONPATH=dir\n{VERIFY}",
        "an interpreter variable as a prefix": f"PYTHONPATH=dir {VERIFY}",
        "a preload library": f"LD_PRELOAD=x.so {VERIFY}",
        # The fourth pass: arithmetic carried by a variable's value (x holds `PATH=5`).
        "an array subscript assignment": f'a=PA; b=TH; x="$a$b=5"\ny[x]=1\n{VERIFY}',
        "an array subscript read": 'a=PA; b=TH; x="$a$b=5"\necho "${y[x]}"\n' + VERIFY,
        "a substring offset": 'a=PA; b=TH; x="$a$b=5"\necho "${s:x}"\n' + VERIFY,
        "double brackets": f'a=PA; b=TH; x="$a$b=5"\n[[ x -eq 5 ]]\n{VERIFY}',
        "an indirect expansion": 'x="y[PATH=5]"\necho "${!x}"\n' + VERIFY,
    }

    BREAKS = {"carriage return": "\r", "vertical tab": "\v", "form feed": "\f", "file separator": "\x1c",
              "next line": "\x85", "line separator": "\u2028"}

    def test_a_line_break_bash_does_not_see_hides_nothing(self):
        with TempDir() as tmp:
            for label, char in self.BREAKS.items():
                with self.subTest(label):
                    script = "echo skip" + char + VERIFY
                    step = "      - name: Verify\n        run: " + json.dumps(script) + "\n"
                    self.assertEqual(kinds(check(tmp, release(step + UPLOAD)), "OBAAF-GHA-016"), [("high", "cannot-tell")])

    def test_a_check_whose_failure_does_not_stop_the_job_does_not_count(self):
        with TempDir() as tmp:
            for label, script in self.IGNORED.items():
                with self.subTest(label):
                    result = check(tmp, release(run(script, "Verify") + UPLOAD))
                    self.assertEqual(kinds(result, "OBAAF-GHA-016"), [("high", "cannot-tell")])

    BINDING = {
        "plain": VERIFY,
        "or exit 1": f"{VERIFY} || exit 1",
        "or a group that exits": f"{VERIFY} || {{ echo failed; exit 1; }}",
        "or in a comment": f"{VERIFY}  # a || b",
        "set +e after it": f"{VERIFY}\nset +e",
        "after a loop": f"for n in a b; do\n  echo $n\ndone\n{VERIFY}",
        "env prefix": f"GH_TOKEN=x {VERIFY}",
        "an expression whose value cannot hold shell syntax": VERIFY + " --source-revision ${{ github.sha }}",
        "group after a plain loop": f"for n in a b; do\n  echo $n\ndone\n{VERIFY} || {{ echo failed; exit 1; }}",
        "a quoted assignment before it": f'B="$RUNNER_TEMP/x"\nGH_TOKEN="$T" {VERIFY}',
        "redirections": f"{VERIFY} > log 2>&1",
    }

    def test_a_check_that_stops_the_job_counts(self):
        with TempDir() as tmp:
            for label, script in self.BINDING.items():
                with self.subTest(label):
                    self.assertEqual(of(check(tmp, release(run(script, "Verify") + UPLOAD)), "OBAAF-GHA-016"), [])

    def test_a_pipe_counts_only_under_pipefail(self):
        with TempDir() as tmp:
            piped = run(f"{VERIFY} | tee log", "Verify", "        shell: bash\n")
            self.assertEqual(of(check(tmp, release(piped + UPLOAD)), "OBAAF-GHA-016"), [])
            set_pipefail = run(f"set -o pipefail\n{VERIFY} | tee log", "Verify")
            self.assertEqual(of(check(tmp, release(set_pipefail + UPLOAD)), "OBAAF-GHA-016"), [])

    def test_the_shell_is_read(self):
        with TempDir() as tmp:
            for shell in ("bash {0}", "cmd", "python", "pwsh", "powershell", "${{ inputs.shell }}", "bash -e +e {0}",
                          "bash -eo pipefail +o errexit {0}", "bash -el {0}", "bash -e --login {0}", "bash -ie {0}",
                          "bash -en {0}", "sh -en {0}", "bash -et {0}", "bash -eD {0}"):
                with self.subTest(shell):
                    step = run(VERIFY, "Verify", f"        shell: {shell}\n")
                    self.assertEqual(kinds(check(tmp, release(step + UPLOAD)), "OBAAF-GHA-016"),
                                     [("high", "cannot-tell")])
            defaults = release(run(VERIFY, "Verify") + UPLOAD,
                               job_extra="    environment: release\n    cache-mode: none\n"
                                         "    defaults:\n      run:\n        shell: bash {0}\n")
            self.assertEqual(kinds(check(tmp, defaults), "OBAAF-GHA-016"), [("high", "cannot-tell")])
            for runner in ("windows-latest", "self-hosted", "[self-hosted, build]", "{group: g}", "${{ inputs.runner }}"):
                with self.subTest(runner):
                    text = release(run(VERIFY, "Verify") + UPLOAD).replace("ubuntu-latest", runner)
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-016"), [("high", "cannot-tell")])
            linux = release(run(VERIFY, "Verify") + UPLOAD).replace("ubuntu-latest", "[self-hosted, linux]")
            self.assertEqual(of(check(tmp, linux), "OBAAF-GHA-016"), [])
            for shell in ("bash -e {0}", "sh -e {0}", "bash --noprofile --norc -eo pipefail {0}", "sh"):
                with self.subTest(shell):
                    step = run(VERIFY, "Verify", f"        shell: {shell}\n")
                    self.assertEqual(of(check(tmp, release(step + UPLOAD)), "OBAAF-GHA-016"), [])
            set_e = run(f"set -e\n{VERIFY}", "Verify", "        shell: bash {0}\n")
            self.assertEqual(of(check(tmp, release(set_e + UPLOAD)), "OBAAF-GHA-016"), [])

    def test_bash_env_anywhere_before_the_check_makes_it_not_count(self):
        with TempDir() as tmp:
            in_env = run(VERIFY, "Verify", "        env:\n          BASH_ENV: /tmp/x\n")
            self.assertEqual(kinds(check(tmp, release(in_env + UPLOAD)), "OBAAF-GHA-016"), [("high", "cannot-tell")])
            for script in ('echo "BASH_ENV=/tmp/x" >> "$GITHUB_ENV"', 'echo "$PWD/fake" >> "$GITHUB_PATH"',
                           "echo 'BASH_FUNC_obaaf%%=() { :; }' >> \"$GITHUB_ENV\""):
                with self.subTest(script):
                    written = run(script, "Prepare") + run(VERIFY, "Verify")
                    self.assertEqual(kinds(check(tmp, release(written + UPLOAD)), "OBAAF-GHA-016"), [("high", "cannot-tell")])
            as_expression = run(VERIFY, "Verify", "        env: ${{ fromJSON(vars.E) }}\n")
            self.assertEqual(kinds(check(tmp, release(as_expression + UPLOAD)), "OBAAF-GHA-016"), [("high", "cannot-tell")])

    def test_a_github_script_check_does_not_count(self):
        with TempDir() as tmp:
            script = (f"      - name: Verify\n        uses: actions/github-script@{SHA}\n        with:\n"
                      f"          script: |\n            // {VERIFY}\n")
            self.assertEqual(kinds(check(tmp, release(script + UPLOAD)), "OBAAF-GHA-016"), [("high", "cannot-tell")])

    def test_the_conditions_github_reads_as_success_count(self):
        with TempDir() as tmp:
            for cond in ("${{success()}}", "true", "${{ true }}"):
                with self.subTest(cond):
                    step = run(VERIFY, "Verify", f"        if: {cond}\n")
                    self.assertEqual(of(check(tmp, release(step + UPLOAD)), "OBAAF-GHA-016"), [])

    def test_pre_approval_skips_the_approvals_so_it_is_a_provenance_check(self):
        with TempDir() as tmp:
            step = run(VERIFY + " --pre-approval", "Verify")
            self.assertEqual(kinds(check(tmp, release(step + UPLOAD)), "OBAAF-GHA-016"),
                             [("medium", "provenance-only")])

    def test_the_reader_reports_what_it_could_not_read(self):
        from obaaf.checker.workflow import binding_commands
        for script in ("echo 'unclosed", "cat <<EOF\nnever closed", "trap '' ERR\nobaaf verify release",
                       "echo $'x'\nobaaf verify release"):
            with self.subTest(script):
                found, complete = binding_commands(script, True, False)
                self.assertFalse(complete)
                self.assertNotIn("obaaf", [words[0] for words in found])


class EveryUploadTest(unittest.TestCase):
    """Only the first upload step was looked at. Every one is now: a later upload that runs after a
    failure is unchecked."""

    def test_a_later_upload_that_runs_after_a_failure_is_unchecked(self):
        with TempDir() as tmp:
            for cond in ("always()", "${{ !cancelled() }}"):
                with self.subTest(cond):
                    steps = (run(VERIFY, "Verify") + run("gh release upload v1 notes.txt", "Upload notes")
                             + run("npm publish", "Upload binaries", f"        if: {cond}\n"))
                    found = of(check(tmp, release(steps)), "OBAAF-GHA-016")
                    self.assertEqual([(f.kind, f.step) for f in found], [("unchecked", "Upload binaries")])
                    self.assertEqual(found[0].facts["steps"], ["Upload binaries (npm publish)"])


class NeededJobTest(unittest.TestCase):
    """A needed job with `continue-on-error` is no gate: its failure does not stop the jobs that need
    it. The jobs it needs still are."""

    def workflow(self, coe, approve_env=False):
        env = "    environment: approve\n" if approve_env else ""
        return ("on: push\npermissions: {}\njobs:\n  verify:\n    runs-on: ubuntu-latest\n"
                f"    continue-on-error: {coe}\n{env}    steps:\n{run(VERIFY, 'Verify')}"
                "  r:\n    needs: verify\n    runs-on: ubuntu-latest\n    environment: release\n    cache-mode: none\n"
                f"    env:\n      OBAAF_LANE: release\n    steps:\n{UPLOAD}")

    def test_continue_on_error_on_the_needed_job(self):
        with TempDir() as tmp:
            for coe in ("true", "${{ true }}", "'true'"):
                with self.subTest(coe):
                    self.assertEqual(kinds(check(tmp, self.workflow(coe)), "OBAAF-GHA-016"), [("high", "unchecked")])
            self.assertEqual(of(check(tmp, self.workflow("false")), "OBAAF-GHA-016"), [])

    def test_a_gate_further_up_still_counts(self):
        with TempDir() as tmp:
            text = ("on: push\npermissions: {}\njobs:\n  verify:\n    runs-on: ubuntu-latest\n"
                    f"    steps:\n{run(VERIFY, 'Verify')}"
                    "  middle:\n    needs: verify\n    runs-on: ubuntu-latest\n    continue-on-error: true\n"
                    f"    steps:\n{run('echo hi')}"
                    "  r:\n    needs: middle\n    runs-on: ubuntu-latest\n    environment: release\n"
                    f"    cache-mode: none\n    env:\n      OBAAF_LANE: release\n    steps:\n{UPLOAD}")
            self.assertEqual(of(check(tmp, text), "OBAAF-GHA-016"), [])


class AcceptanceIdentityTest(unittest.TestCase):
    """An acceptance written for a harmless upload, cache step or effect job covered a risky one with
    the same step name, or a second upload. The steps, the restoring action and what the job may write
    are now facts."""

    def assertDiffers(self, first, second, rule):
        with TempDir() as tmp:
            a = [f for f in of(check(tmp, first), rule)]
            b = [f for f in of(check(tmp, second), rule)]
            self.assertTrue(a and b)
            self.assertNotEqual([(f.kind, f.facts) for f in a], [(f.kind, f.facts) for f in b])

    def test_a_different_upload_in_a_step_of_the_same_name_is_another_finding(self):
        staging = release(run("aws s3 cp dist s3://staging/", "Upload"))
        npm = release(UPLOAD)
        self.assertDiffers(staging, npm, "OBAAF-GHA-016")
        self.assertDiffers(staging.replace("    environment: release\n", ""),
                           npm.replace("    environment: release\n", ""), "OBAAF-GHA-014")

    def test_a_second_upload_is_part_of_the_finding(self):
        one = release(run("aws s3 cp dist s3://staging/", "Upload"))
        two = release(run("aws s3 cp dist s3://staging/", "Upload") + run("npm publish", "More"))
        self.assertDiffers(one, two, "OBAAF-GHA-016")

    def test_the_restoring_action_is_part_of_a_cache_finding(self):
        lookup = release(f"      - name: deps\n        uses: actions/cache@{SHA}\n        with:\n"
                         "          path: x\n          key: k\n          lookup-only: ${{ inputs.l }}\n",
                         job_extra="    environment: release\n")
        restore = lookup.replace("actions/cache@", "actions/cache/restore@")
        self.assertDiffers(lookup, restore, "OBAAF-GHA-006")

    def test_what_an_effect_job_may_write_is_part_of_its_findings(self):
        def effect(scope):
            return ("on:\n  workflow_run:\n    workflows: [p]\n    types: [completed]\njobs:\n  apply:\n"
                    f"    runs-on: ubuntu-latest\n    permissions:\n      {scope}: write\n"
                    f"    env:\n      OBAAF_LANE: effect\n    steps:\n{run('git push origin HEAD:main')}")
        self.assertDiffers(effect("pull-requests"), effect("contents"), "OBAAF-GHA-021")
        self.assertDiffers(effect("pull-requests"), effect("contents"), "OBAAF-GHA-022")


class EffectOrderTest(unittest.TestCase):
    """OBAAF-GHA-021 counted a check anywhere in the job, after the step that applies included, and
    had no idea of a step that applies after a failure."""

    def effect(self, steps, job_extra="    environment: apply\n"):
        return ("on:\n  workflow_run:\n    workflows: [p]\n    types: [completed]\npermissions: {}\njobs:\n"
                f"  apply:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n{job_extra}"
                f"    env:\n      OBAAF_LANE: effect\n    steps:\n{steps}")

    CHECKS = run("obaaf verify agent-run --policy p --proposal x --snapshot s --bundle b", "Record") + \
        run("obaaf proposal check x --repo .", "Proposal")
    APPLY = run("git apply x/patch.diff && git push", "Apply")

    def test_checks_after_the_apply_step_do_not_count(self):
        with TempDir() as tmp:
            self.assertEqual(kinds(check(tmp, self.effect(self.APPLY + self.CHECKS)), "OBAAF-GHA-021"),
                             [("high", "unchecked")])
            self.assertEqual(of(check(tmp, self.effect(self.CHECKS + self.APPLY)), "OBAAF-GHA-021"), [])

    def test_an_apply_step_that_runs_after_a_failure_is_unchecked(self):
        with TempDir() as tmp:
            late = run("git push", "Apply", "        if: always()\n")
            self.assertEqual(kinds(check(tmp, self.effect(self.CHECKS + late)), "OBAAF-GHA-021"),
                             [("high", "unchecked")])

    def test_preparing_steps_before_the_checks_are_fine(self):
        with TempDir() as tmp:
            prepare = (f"      - uses: actions/checkout@{SHA}\n      - uses: actions/download-artifact@{SHA}\n"
                       f"      - uses: actions/setup-python@{SHA}\n")
            self.assertEqual(of(check(tmp, self.effect(prepare + self.CHECKS + self.APPLY)), "OBAAF-GHA-021"), [])

    def test_a_step_that_applies_before_its_checks_is_unchecked(self):
        with TempDir() as tmp:
            one = run("git apply d/patch\ngit push origin HEAD\nobaaf verify agent-run --policy p\n"
                      "obaaf proposal check d --repo .", "All in one")
            self.assertEqual(kinds(check(tmp, self.effect(one)), "OBAAF-GHA-021"), [("high", "unchecked")])

    def test_a_substitution_in_a_check_step_may_apply(self):
        with TempDir() as tmp:
            for prepare in ('echo "$(git apply d/patch && git push origin HEAD)"', "echo `git push origin HEAD`"):
                with self.subTest(prepare):
                    steps = run(prepare + "\nobaaf verify agent-run --policy p\nobaaf proposal check d --repo .", "Check")
                    self.assertEqual(kinds(check(tmp, self.effect(steps + self.APPLY)), "OBAAF-GHA-021"),
                                     [("high", "unchecked")])

    def test_a_local_setup_obaaf_is_not_taken_for_obaafs(self):
        with TempDir() as tmp:
            local = "      - uses: ./actions/setup-obaaf\n"
            self.assertEqual(kinds(check(tmp, self.effect(local + self.CHECKS + self.APPLY)), "OBAAF-GHA-021"),
                             [("high", "unchecked")])

    def test_only_a_setup_obaaf_from_a_repository_named_obaaf_prepares(self):
        with TempDir() as tmp:
            other = f"      - uses: attacker/anything/actions/setup-obaaf@{SHA}\n"
            self.assertEqual(kinds(check(tmp, self.effect(other + self.CHECKS + self.APPLY)), "OBAAF-GHA-021"),
                             [("high", "unchecked")])
            ours = f"      - uses: Obaaf/obaaf/actions/setup-obaaf@{SHA}\n"
            self.assertEqual(of(check(tmp, self.effect(ours + self.CHECKS + self.APPLY)), "OBAAF-GHA-021"), [])

    def test_gh_attestation_verify_is_not_a_record_check(self):
        with TempDir() as tmp:
            steps = (run("obaaf proposal check x --repo .", "Proposal") +
                     run("gh attestation verify b.json --repo o/r", "Record") + self.APPLY)
            self.assertEqual(kinds(check(tmp, self.effect(steps)), "OBAAF-GHA-021"), [("medium", "no-record")])

    def test_an_environment_that_may_be_blank_is_no_gate(self):
        with TempDir() as tmp:
            for env in ("' '", "{name: '  '}", "${{ github.ref == 'refs/heads/main' && 'apply' || '' }}",
                        "${{ vars.UNSET }}", "${{ '' }}", "1", "${{ null }}"):
                with self.subTest(env):
                    text = self.effect(self.CHECKS + self.APPLY, job_extra=f"    environment: {env}\n")
                    self.assertEqual(len(of(check(tmp, text), "OBAAF-GHA-022")), 1)


class EnvironmentPresenceTest(unittest.TestCase):
    """OBAAF-GHA-014 took any value that was not empty for an environment."""

    def test_a_value_that_may_be_no_environment_is_cannot_tell(self):
        cases = {"' '": "blank", "{name: ' '}": "blank", "${{ inputs.env }}": "open",
                 "${{ github.ref == 'refs/heads/main' && 'release' || '' }}": "open", "${{ '' }}": "open",
                 "1": "unreadable", "true": "unreadable"}
        with TempDir() as tmp:
            for env, kind in cases.items():
                with self.subTest(env):
                    text = release(run(VERIFY, "Verify") + UPLOAD, job_extra=f"    environment: {env}\n    cache-mode: none\n")
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-014"), [("medium", kind)])

    def test_a_matrix_of_named_environments_is_set(self):
        with TempDir() as tmp:
            text = release(run(VERIFY, "Verify") + UPLOAD,
                           job_extra="    strategy:\n      matrix:\n        env: [staging, release]\n"
                                     "    environment: ${{ matrix.env }}\n    cache-mode: none\n")
            self.assertEqual(of(check(tmp, text), "OBAAF-GHA-014"), [])

    def test_a_release_job_that_holds_publishing_credentials_needs_an_environment(self):
        with TempDir() as tmp:
            text = release(run("./scripts/ship.sh", "Ship", "        env:\n          TOKEN: ${{ secrets.NPM_TOKEN }}\n"),
                           job_extra="    cache-mode: none\n")
            self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-014"), [("medium", "capability")])
            harmless = release(run("echo build"), job_extra="    cache-mode: none\n")
            self.assertEqual(of(check(tmp, harmless), "OBAAF-GHA-014"), [])


class PublishingTheListsMissedTest(unittest.TestCase):
    """Common ways to publish that the lists did not name: the job was no release job, or no upload
    was seen in it."""

    COMMANDS = ["mvn -B deploy", "./gradlew publish", "sbt +publishSigned", "helm push chart.tgz oci://r",
                "oras push r/x:1 f", "podman push img", "crane push img r/x", "gh -R o/r release upload v1 f",
                "npx semantic-release", "npx changeset publish", "bun publish", "maturin publish", "pdm publish",
                "pod trunk push", "goreleaser release --clean", "aws s3api put-object --bucket b --key k",
"curl --data-binary @f https://uploads.github.com/repos/o/r/x"]

    def test_each_is_an_upload(self):
        with TempDir() as tmp:
            for command in self.COMMANDS:
                with self.subTest(command):
                    text = f"on: push\npermissions: {{}}\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n{run(command)}"
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-014"), [("medium", "")])

    NOT_PUBLISHING = ["./gradlew build publishToMavenLocal", "goreleaser release --snapshot --clean",
                      "npx semantic-release --dry-run", "npm publish --dry-run", "cargo publish --dry-run",
                      "rclone copy :http,url=https://example.com/:fixtures ./fixtures",
                      "skopeo copy docker://docker.io/library/alpine oci-archive:alpine.tar",
                      "mvn -B deploy -DaltDeploymentRepository=local::file:./target/staging-deploy",
                      "helm push chart.tgz oci://localhost:5000/charts"]

    STILL_PUBLISHING = ["npm publish # was --dry-run", "npm publish --dry-run=false", "npm publish; echo --dry-run",
                        "npm publish --dry-run false", "uv publish --dry-run false",
                        "npm publish --dry-run --dry-run=false", "npm publish --dry-run --no-dry-run",
                        "npx semantic-release --dry-run --no-dry-run",
                        "cargo publish --token t # --dry-run on PRs", "goreleaser release --clean # not --snapshot",
                        "helm push c.tgz oci://ghcr.io/o/charts && curl -fsS localhost:8080/health",
                        "npx semantic-release && test -d dist",
                        "mvn -B deploy -DaltSnapshotDeploymentRepository=snap::default::file:./snap"]

    def test_a_dry_run_flag_counts_only_on_the_same_command(self):
        with TempDir() as tmp:
            for command in self.STILL_PUBLISHING:
                with self.subTest(command):
                    text = f"on: push\npermissions: {{}}\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n{run(command)}"
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-014"), [("medium", "")])

    def test_dry_runs_and_local_targets_are_not_uploads(self):
        with TempDir() as tmp:
            for command in self.NOT_PUBLISHING:
                with self.subTest(command):
                    text = (f"on: [push, pull_request]\npermissions: {{}}\njobs:\n  ci:\n    runs-on: ubuntu-latest\n"
                            f"    steps:\n{run(command)}")
                    found = [f.rule for f in check(tmp, text).findings if f.rule in (
                        "OBAAF-GHA-006", "OBAAF-GHA-014", "OBAAF-GHA-015", "OBAAF-GHA-016", "OBAAF-GHA-017")]
                    self.assertEqual(found, [])

    def test_an_image_build_that_pushes_is_an_upload(self):
        with TempDir() as tmp:
            for push in ("true", "${{ github.event_name == 'push' }}"):
                with self.subTest(push):
                    text = (f"on: push\npermissions: {{}}\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n"
                            f"      - uses: docker/build-push-action@{SHA}\n        with:\n          push: {push}\n")
                    self.assertEqual(kinds(check(tmp, text), "OBAAF-GHA-014"), [("medium", "")])
            text = (f"on: push\npermissions: {{}}\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n"
                    f"      - uses: docker/build-push-action@{SHA}\n        with:\n          push: false\n")
            self.assertEqual(of(check(tmp, text), "OBAAF-GHA-014"), [])


class CacheRestoreTest(unittest.TestCase):
    """OBAAF-GHA-006 knew a closed list of cache steps with inputs read as text. Inputs written as
    expressions, more actions and a local action now count as restoring."""

    def job(self, step, mode=""):
        extra = "    environment: release\n" + (f"    cache-mode: {mode}\n" if mode else "")
        return release(step + run(VERIFY, "Verify") + UPLOAD, job_extra=extra)

    STEPS = {
        "path with ..": f"      - uses: actions/cache/save/../restore@{SHA}\n        with:\n          path: x\n          key: k\n",
        "local action": "      - uses: ./.github/actions/toolchain\n",
        "rust toolchain": f"      - uses: actions-rust-lang/setup-rust-toolchain@{SHA}\n",
        "dotnet expression": f"      - uses: actions/setup-dotnet@{SHA}\n        with:\n          cache: ${{{{ true }}}}\n",
        "ruby expression": f"      - uses: ruby/setup-ruby@{SHA}\n        with:\n          bundler-cache: ${{{{ true }}}}\n",
        "inputs as one expression": f"      - uses: actions/setup-python@{SHA}\n        with: ${{{{ fromJSON(vars.PY) }}}}\n",
        "bun": f"      - uses: oven-sh/setup-bun@{SHA}\n",
        "pnpm": f"      - uses: pnpm/action-setup@{SHA}\n        with:\n          cache: true\n",
        "ccache": f"      - uses: hendrikmuhs/ccache-action@{SHA}\n",
        "sccache": f"      - uses: mozilla-actions/sccache-action@{SHA}\n",
        "bake": f"      - uses: docker/bake-action@{SHA}\n        with:\n          set: '*.cache-from=type=gha'\n",
        "cache-from expression": f"      - uses: docker/build-push-action@{SHA}\n        with:\n          cache-from: ${{{{ env.CF }}}}\n",
        "runtime then buildx": f"      - uses: crazy-max/ghaction-github-runtime@{SHA}\n",
        "buildx in run": run("docker buildx build --cache-from type=gha ."),
        "github-script toolkit": f"      - uses: actions/github-script@{SHA}\n        with:\n          script: |\n            const cache = require('@actions/cache'); await cache.restoreCache(['x'], 'k')\n",
        "mise": f"      - uses: jdx/mise-action@{SHA}\n",
        "zig": f"      - uses: mlugg/setup-zig@{SHA}\n",
        "magic nix": f"      - uses: DeterminateSystems/magic-nix-cache-action@{SHA}\n",
    }

    def test_each_restores(self):
        with TempDir() as tmp:
            for label, step in self.STEPS.items():
                with self.subTest(label):
                    self.assertIn(("high", "restores"), kinds(check(tmp, self.job(step)), "OBAAF-GHA-006"))

    def test_lookup_only_restores_nothing(self):
        with TempDir() as tmp:
            step = f"      - uses: actions/cache@{SHA}\n        with:\n          path: x\n          key: k\n          lookup-only: true\n"
            self.assertEqual(kinds(check(tmp, self.job(step)), "OBAAF-GHA-006"), [("low", "no-cache-mode")])

    def test_write_only_needs_no_low_finding(self):
        with TempDir() as tmp:
            self.assertEqual(of(check(tmp, self.job("", mode="write-only")), "OBAAF-GHA-006"), [])

    def test_a_needed_job_that_restores_and_hands_over_artifacts(self):
        with TempDir() as tmp:
            text = ("on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                    f"      - uses: actions/setup-node@{SHA}\n        with:\n          cache: npm\n"
                    f"      - uses: actions/upload-artifact@{SHA}\n"
                    "  r:\n    needs: build\n    runs-on: ubuntu-latest\n    environment: release\n    cache-mode: none\n"
                    f"    env:\n      OBAAF_LANE: release\n    steps:\n      - uses: actions/download-artifact@{SHA}\n"
                    + run(VERIFY, "Verify") + UPLOAD)
            found = of(check(tmp, text), "OBAAF-GHA-006")
            self.assertEqual([(f.kind, f.facts["jobs"]) for f in found], [("needed-job-restores", ["build"])])
            fixed = text.replace("  build:\n    runs-on: ubuntu-latest\n", "  build:\n    runs-on: ubuntu-latest\n    cache-mode: none\n")
            self.assertEqual(of(check(tmp, fixed), "OBAAF-GHA-006"), [])


class CacheModeSpellingTest(unittest.TestCase):
    """OBAAF-GHA-007 compared the value with `write` and `write-only` exactly. A value it cannot read
    is now reported, a null at the job no longer hides the workflow's value, and a key in another
    spelling is read."""

    def job(self, job_mode=None, workflow_mode=None, key="cache-mode"):
        wf = f"{key}: {workflow_mode}\n" if workflow_mode is not None else ""
        jm = f"    {key}: {job_mode}\n" if job_mode is not None else ""
        return (f"on: pull_request_target\npermissions: {{}}\n{wf}jobs:\n  j:\n    runs-on: ubuntu-latest\n{jm}"
                f"    steps:\n{run('echo hi')}")

    def test_values_it_cannot_read(self):
        with TempDir() as tmp:
            for value in ("Write", "' write'", "${{ 'write' }}", "true", "1", "|\n      write"):
                with self.subTest(value):
                    self.assertEqual(kinds(check(tmp, self.job(value)), "OBAAF-GHA-007"), [("high", "unreadable")])

    def test_a_null_at_the_job_does_not_hide_the_workflow(self):
        with TempDir() as tmp:
            for null in ("", "~", "null"):
                with self.subTest(null):
                    self.assertEqual(kinds(check(tmp, self.job(null, "write")), "OBAAF-GHA-007"), [("high", "")])

    def test_a_key_in_another_spelling(self):
        with TempDir() as tmp:
            self.assertEqual(kinds(check(tmp, self.job("write", key="Cache-Mode")), "OBAAF-GHA-007"),
                             [("high", "unreadable")])

    def test_read_and_none_hold(self):
        with TempDir() as tmp:
            for value in ("read", "none"):
                with self.subTest(value):
                    self.assertEqual(of(check(tmp, self.job(value, "write")), "OBAAF-GHA-007"), [])


class ProvenanceTest(unittest.TestCase):
    """OBAAF-GHA-017 was cleared by a provenance step that never ran, by its text in a comment or an
    echo, by an SBOM attestation, and by verify text anywhere in the publishing job."""

    def workflow(self, attest_steps, publish_extra="", attest_job_extra=""):
        return ("on: push\npermissions: {}\njobs:\n  attest:\n    runs-on: ubuntu-latest\n"
                f"    permissions:\n      id-token: write\n      attestations: write\n{attest_job_extra}"
                f"    steps:\n{attest_steps}"
                "  r:\n    runs-on: ubuntu-latest\n    environment: release\n    cache-mode: none\n"
                f"    env:\n      OBAAF_LANE: release\n    steps:\n{publish_extra}{UPLOAD}")

    def test_provenance_that_is_not_signed_does_not_count(self):
        attest = f"      - uses: actions/attest-build-provenance@{SHA}\n        with:\n          subject-path: dist/*\n"
        cases = {
            "step if false": attest.replace("      - uses:", "      - if: false\n        uses:"),
            "continue on error": attest + "        continue-on-error: true\n",
            "comment": run("# cosign attest --predicate p dist"),
            "echo": run("echo obaaf attest build-record --artifact dist"),
            "sbom only": f"      - uses: actions/attest@{SHA}\n        with:\n          subject-path: dist/*\n          sbom-path: sbom.json\n",
            "cosign sbom": run("cosign attest --type spdxjson --predicate sbom.json img"),
        }
        with TempDir() as tmp:
            for label, steps in cases.items():
                with self.subTest(label):
                    self.assertEqual(len(of(check(tmp, self.workflow(steps)), "OBAAF-GHA-017")), 1)
            for extra in ("    if: false\n", "    continue-on-error: true\n"):
                with self.subTest(extra):
                    self.assertEqual(len(of(check(tmp, self.workflow(attest, attest_job_extra=extra)),
                                            "OBAAF-GHA-017")), 1)
            self.assertEqual(of(check(tmp, self.workflow(attest)), "OBAAF-GHA-017"), [])

    def test_verifying_elsewhere_counts_only_before_the_upload(self):
        with TempDir() as tmp:
            nothing = run("echo build")
            after = ("on: push\npermissions: {}\njobs:\n  r:\n    runs-on: ubuntu-latest\n    environment: release\n"
                     f"    cache-mode: none\n    env:\n      OBAAF_LANE: release\n    steps:\n{UPLOAD}"
                     + run("gh attestation verify dist/x --repo o/r", "Verify"))
            self.assertEqual(len(of(check(tmp, after), "OBAAF-GHA-017")), 1)
            echo = self.workflow(nothing, publish_extra=run("echo gh attestation verify x", "Verify"))
            self.assertEqual(len(of(check(tmp, echo), "OBAAF-GHA-017")), 1)
            self.assertEqual(kinds(check(tmp, echo), "OBAAF-GHA-016"), [("high", "cannot-tell")])


class TemplatesStayCleanTest(unittest.TestCase):
    def test_this_repository_and_the_templates_have_no_finding_of_these_rules_at_medium_or_above(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        rules = {"OBAAF-GHA-006", "OBAAF-GHA-007", "OBAAF-GHA-014", "OBAAF-GHA-016", "OBAAF-GHA-017",
                 "OBAAF-GHA-021", "OBAAF-GHA-022"}
        for target in (root, root / "templates" / "github-actions" / "workflows"):
            found = [(f.rule, f.path) for f in checker.check(target).findings
                     if f.rule in rules and f.severity in ("high", "medium")]
            self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
