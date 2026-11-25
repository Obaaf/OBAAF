"""Flagship slice 2d.15 (#148, #245): a runner label or an action reference written so that the checker
reads less than GitHub may run.

#148. Two checks of OBAAF's egress action (the runner it was tested on, for OBAAF-GHA-020 and for
OBAAF-GHA-005's `key-out-of-reach`), the runner's default shell (whether a check stops the job) and the
runner of `npm publish --provenance` compared a job's labels after `strip()`. So `"ubuntu-24.04\\n"` or
`" ubuntu-latest"` was taken for the GitHub-hosted runner it names, where OBAAF-GHA-013's hosted list,
which has never trimmed a label, says it cannot name it (the native firewall's half was fixed in slice
2d.9). Whether GitHub trims a label is not established: if it does not, the job never starts; if it
does, the label is the runner. Either way the checker no longer reads such a label more generously
than OBAAF-GHA-013 does.

#245. A remote `uses:` was split on `/` as written, so `openai//codex-action@...`,
`/openai/codex-action@...` and `openai\\codex-action@...` were not matched to the agent action, and the
job got no agent rule at all. Whether GitHub refuses such a value or runs the action without the extra
characters (the runner may split on `/` and `\\` and drop empty parts) is not established, so the
checker cannot tell which action such a step runs: it is now an error of the file, as a `uses:` that
is not text is (slice 2d.2f), in a workflow's steps, a job's call and a local composite action's steps.
"""

import unittest

from helpers import TempDir, run_cli

from obaaf import checker
from obaaf.checker import workflow as wf_mod
from obaaf.checker.rules import CANNOT_TELL, VERIFIED

from test_egress_recognised import (CHECKOUT, REVIEWED_PIN, action, egress, key_control, keyed, run_check,
                                    verdict, workflow)
from test_npm_provenance import found as provenance_findings
from test_npm_provenance import workflow as provenance_workflow
from test_release_effect_bypasses import UPLOAD, VERIFY, kinds, release, run
from test_release_effect_bypasses import check as release_check

SHA = "1" * 40
# Labels written with space or a line break round them, as a double-quoted YAML value keeps them.
PADDED = ('"ubuntu-24.04\\n"', '" ubuntu-24.04"', '"ubuntu-24.04 "', '"\\tubuntu-24.04"')


class RunnerLabelTest(unittest.TestCase):
    """#148: the egress action's tested runner, the default shell and npm's provenance runner."""

    def test_the_egress_action_on_a_padded_label_is_cannot_tell(self):
        plain = egress(run_check(workflow(CHECKOUT + "\n" + action(ref=REVIEWED_PIN)), cat=checker.load()))
        self.assertEqual(verdict(plain), VERIFIED)     # the neighbour that must stay verified
        for runs_on in PADDED:
            with self.subTest(runs_on=runs_on):
                result = run_check(workflow(CHECKOUT + "\n" + action(ref=REVIEWED_PIN), runs_on=runs_on),
                                   cat=checker.load())
                f = egress(result)
                self.assertEqual(verdict(f), CANNOT_TELL)
                self.assertIn("tested only on GitHub-hosted ubuntu-24.04 runners", f.controls[0].detail)
                # OBAAF-GHA-013 reads the same label as one it cannot name, as before.
                self.assertIn("OBAAF-GHA-013", {x.rule for x in result.findings})

    def test_key_out_of_reach_on_a_padded_label_is_cannot_tell(self):
        plain = key_control(run_check(workflow(CHECKOUT + "\n" + keyed(ref=REVIEWED_PIN)), cat=checker.load()))
        self.assertEqual(plain.verdict, VERIFIED)
        for runs_on in PADDED:
            with self.subTest(runs_on=runs_on):
                control = key_control(run_check(workflow(CHECKOUT + "\n" + keyed(ref=REVIEWED_PIN), runs_on=runs_on),
                                                cat=checker.load()))
                self.assertEqual(control.verdict, CANNOT_TELL)
                self.assertIn("tested only on GitHub-hosted ubuntu-24.04 runners", control.detail)

    def test_a_padded_hosted_label_gives_no_default_shell(self):
        """The default shell is bash with `-e` only on a runner the checker can show is Linux or macOS:
        on Windows it is PowerShell, where a failing check does not stop the step."""
        with TempDir() as tmp:
            plain = release(run(VERIFY, "Verify") + UPLOAD)
            self.assertEqual(kinds(release_check(tmp, plain), "OBAAF-GHA-016"), [])
            for label in ('" ubuntu-latest"', '"ubuntu-latest\\n"', '[self-hosted, " linux"]'):
                with self.subTest(label=label):
                    text = plain.replace("runs-on: ubuntu-latest", f"runs-on: {label}")
                    self.assertEqual(kinds(release_check(tmp, text), "OBAAF-GHA-016"), [("high", "cannot-tell")])

    def test_npm_provenance_on_a_padded_label_is_not_credited(self):
        self.assertEqual(provenance_findings(provenance_workflow()), [])
        for runs_on in ('" ubuntu-latest"', '"ubuntu-latest "', '"ubuntu-latest\\n"'):
            with self.subTest(runs_on=runs_on):
                self.assertEqual(len(provenance_findings(provenance_workflow(runs_on=runs_on))), 1)

    def test_the_label_in_another_letter_case_is_still_the_runner(self):
        """Only the trimming goes: GitHub's labels are read in any letter case, as OBAAF-GHA-013 reads them."""
        f = egress(run_check(workflow(CHECKOUT + "\n" + action(ref=REVIEWED_PIN), runs_on="Ubuntu-24.04"),
                             cat=checker.load()))
        self.assertEqual(verdict(f), VERIFIED)
        self.assertEqual(provenance_findings(provenance_workflow(runs_on="Ubuntu-Latest")), [])

    def test_space_round_the_expression_is_space_round_the_label(self):
        """Found by the third review pass: `runs-on: " ${{ matrix.os }}"` is `" ubuntu-24.04"` once GitHub fills
        it in, and the expression readers trimmed the value first."""
        matrix = "\n    strategy:\n      matrix:\n        os: [ubuntu-24.04]"
        for runs_on in ('" ${{ matrix.os }}"', '"${{ matrix.os }} "', '"${{ matrix.os }}\\n"'):
            with self.subTest(runs_on=runs_on):
                result = run_check(workflow(CHECKOUT + "\n" + keyed(ref=REVIEWED_PIN), runs_on=runs_on + matrix),
                                   cat=checker.load())
                self.assertEqual(verdict(egress(result)), CANNOT_TELL)
                self.assertEqual(key_control(result).verdict, CANNOT_TELL)
                self.assertIn("OBAAF-GHA-013", {f.rule for f in result.findings})
        plain = run_check(workflow(CHECKOUT + "\n" + keyed(ref=REVIEWED_PIN), runs_on='"${{ matrix.os }}"' + matrix),
                          cat=checker.load())
        self.assertEqual(verdict(egress(plain)), VERIFIED)
        text = provenance_workflow(runs_on='" ${{ matrix.os }}"').replace(
            "    steps:\n", "    strategy:\n      matrix:\n        os: [ubuntu-latest]\n    steps:\n", 1)
        self.assertEqual(len(provenance_findings(text)), 1)

    def test_space_round_an_expression_for_a_self_hosted_runner_keeps_it_self_hosted(self):
        """Found by the fourth review pass: the third pass's fix left such labels unresolved, so a matrix of
        `self-hosted` behind `" ${{ matrix.r }}"` became an unknown runner, medium where it was high."""
        for values in ("[self-hosted]", "[[self-hosted, linux]]"):
            for runs_on in ('" ${{ matrix.r }}"', '"${{ matrix.r }}"'):
                with self.subTest(values=values, runs_on=runs_on):
                    text = ("on: pull_request\npermissions: {contents: read}\njobs:\n  build:\n"
                            f"    runs-on: {runs_on}\n    strategy:\n      matrix:\n        r: {values}\n"
                            "    steps:\n      - run: make\n")
                    (found,) = [f for f in check_files({".github/workflows/b.yml": text}).findings
                                if f.rule == "OBAAF-GHA-013"]
                    self.assertEqual(found.severity, "high")

    def test_the_settings_audit_reads_a_padded_self_hosted_label_as_self_hosted(self):
        """Found by the fifth review pass: the audit's own reading of a job's runner compared `self-hosted`
        exactly, so a label resolved from `" ${{ matrix.r }}"`, or written `" self-hosted"`, was an unknown
        runner there, and its fork-pull-request finding "cannot tell" where it was high."""
        from obaaf.audit import workflows as audit_workflows
        for runs_on, values in (('" ${{ matrix.r }}"', "[self-hosted]"), ('" ${{ matrix.r }}"', "[[self-hosted, linux]]"),
                                ('" self-hosted"', None), ("self-hosted", None), ("{group: pool}", None)):
            with self.subTest(runs_on=runs_on, values=values):
                matrix = f"\n    strategy:\n      matrix:\n        r: {values}" if values else ""
                text = (f"on: pull_request\njobs:\n  build:\n    runs-on: {runs_on}{matrix}\n"
                        "    steps:\n      - run: make\n")
                job = wf_mod.parse("b.yml", text).jobs["build"]
                expected = "unknown" if "group" in runs_on else "self-hosted"
                self.assertEqual(audit_workflows._runner(job), expected)


def check_files(files):
    with TempDir() as tmp:
        for name, body in files.items():
            path = tmp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
        return checker.check(tmp)


def step_workflow(uses, extra=""):
    return ("on: pull_request\npermissions: {contents: read}\njobs:\n  review:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - uses: {uses}\n{extra}")


RESPELLED = {
    "two slashes": f"openai//codex-action@{SHA}",
    "a leading slash": f"/openai/codex-action@{SHA}",
    "a backslash": f"openai\\codex-action@{SHA}",
    "a slash at the end of the name": f"openai/codex-action/@{SHA}",
    "space at the start": f'" openai/codex-action@{SHA}"',
    "a space in the name": f'"openai/ codex-action@{SHA}"',
    "a tab before the @": f'"openai/codex-action\\t@{SHA}"',
}


class ActionReferenceTest(unittest.TestCase):
    """#245: a `uses:` the checker would not match to the action it may name is an error of its file."""

    def test_the_plain_form_is_an_agent_job_with_no_error(self):
        result = check_files({".github/workflows/r.yml": step_workflow(f"openai/codex-action@{SHA}")})
        self.assertEqual(result.errors, [])
        self.assertIn("OBAAF-GHA-020", {f.rule for f in result.findings})     # an agent job

    def test_each_respelling_of_an_agent_action_is_an_error(self):
        for label, uses in RESPELLED.items():
            with self.subTest(label):
                result = check_files({".github/workflows/r.yml": step_workflow(uses)})
                self.assertEqual(len(result.errors), 1, result.errors)
                error = result.errors[0]
                self.assertIn(".github/workflows/r.yml: job 'review', step 1 has uses written as", error)
                self.assertIn("cannot tell which action it runs", error)
                self.assertIn("openai/codex-action", error)

    def test_a_line_break_after_the_reference_is_read_past(self):
        """Found by the parity test in CI on the first head: zizmor's own test data has a step written as a
        block scalar, `actions/checkout@...` with a line break after it (`unpinned-uses/issue-1543-repro.yml`).
        Space after another repository's reference leaves the name the checker matches unchanged, so it is
        read as before and is not an error; after a local path it is."""
        for uses in (f'"openai/codex-action@{SHA}\\n"', f'"openai/codex-action@{SHA} "', f"|\n          openai/codex-action@{SHA}"):
            with self.subTest(uses=uses):
                result = check_files({".github/workflows/r.yml": step_workflow(uses)})
                self.assertEqual(result.errors, [])
                self.assertIn("OBAAF-GHA-020", {f.rule for f in result.findings})
        files = {".github/workflows/r.yml": step_workflow('"./local-action "'),
                 "local-action/action.yml": "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"}
        self.assertEqual(len([e for e in check_files(files).errors if "uses written as" in e]), 1)

    def test_a_respelled_checkout_is_an_error_too(self):
        """The issue asks for the same on an action that is not an agent's: the check of what a job
        checks out reads `actions/checkout` by its name."""
        for uses in (f"actions//checkout@{SHA}", f"actions\\checkout@{SHA}", f"/actions/checkout@{SHA}"):
            with self.subTest(uses=uses):
                result = check_files({".github/workflows/r.yml": step_workflow(uses)})
                self.assertEqual(len(result.errors), 1, result.errors)
                self.assertIn("actions/checkout", result.errors[0])

    def test_the_error_fails_the_command(self):
        with TempDir() as tmp:
            target = tmp / ".github" / "workflows"
            target.mkdir(parents=True)
            (target / "r.yml").write_text(step_workflow(f"openai//codex-action@{SHA}"), encoding="utf-8")
            code, out, err = run_cli("check", str(tmp))
        self.assertNotEqual(code, 0, out + err)
        self.assertIn("cannot tell which action it runs", out + err)

    def test_forms_that_are_read_as_before_are_not_errors(self):
        for uses in (f"actions/checkout@{SHA}", f"Actions/Checkout@{SHA}", f"actions/cache/save@{SHA}",
                     "docker://alpine:3.20", "./local-action", "$/local-action", f"actions/checkout@{SHA[:7]}",
                     f"actions/cache/save/../restore@{SHA}", "actions/checkout"):
            with self.subTest(uses=uses):
                files = {".github/workflows/r.yml": step_workflow(uses)}
                if "local-action" in uses:
                    files["local-action/action.yml"] = "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"
                result = check_files(files)
                self.assertEqual([e for e in result.errors if "has uses written as" in e], [])

    def test_steps_in_a_parallel_group_are_read(self):
        text = ("on: pull_request\npermissions: {contents: read}\njobs:\n  review:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n      - parallel:\n          - uses: openai//codex-action@{SHA}\n          - run: echo\n")
        result = check_files({".github/workflows/r.yml": text})
        self.assertEqual(len([e for e in result.errors if "has uses written as" in e]), 1, result.errors)

    def test_a_respelled_call_of_a_reusable_workflow_is_an_error(self):
        for uses in (f"openai//codex-action/.github/workflows/x.yml@{SHA}",
                     f"openai\\codex-action/.github/workflows/x.yml@{SHA}",
                     f'" openai/codex-action/.github/workflows/x.yml@{SHA}"'):
            with self.subTest(uses=uses):
                text = (f"on: pull_request\npermissions: {{contents: read}}\njobs:\n  call:\n    uses: {uses}\n")
                result = check_files({".github/workflows/r.yml": text})
                self.assertEqual(len(result.errors), 1, result.errors)
                self.assertIn("job 'call' has uses written as", result.errors[0])
                self.assertIn("cannot tell which workflow it calls", result.errors[0])

    def test_a_respelled_step_in_a_local_composite_action_is_an_error(self):
        action_file = ("runs:\n  using: composite\n  steps:\n"
                       f"    - uses: openai//codex-action@{SHA}\n")
        text = ("on: pull_request\npermissions: {contents: read}\njobs:\n  review:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n      - uses: actions/checkout@{SHA}\n        with: {{persist-credentials: false}}\n"
                "      - uses: ./.github/actions/review\n")
        result = check_files({".github/workflows/r.yml": text, ".github/actions/review/action.yml": action_file})
        errors = [e for e in result.errors if "has uses written as" in e]
        self.assertEqual(len(errors), 1, result.errors)
        self.assertIn(".github/actions/review/action.yml", errors[0])
        self.assertIn("openai/codex-action", errors[0])

    def test_the_reason_is_named(self):
        cases = {
            f"openai//codex-action@{SHA}": "two / together",
            f"/openai/codex-action@{SHA}": "a / at its start",
            f"openai\\codex-action@{SHA}": "a backslash",
            f"openai/codex-action/@{SHA}": "a / at its end",
            f" openai/codex-action@{SHA}": "space or a line break at its start",
            "./local-action ": "space or a line break at its end, which a folder's name may hold",
            "$/x\n": "space or a line break at its end",
            f"openai/ codex-action@{SHA}": "a character in its owner or repository name",
            f"openai/codex-action/ sub@{SHA}": "space at the start or end of a part of its path",
            f"openai/codex-action/s\u200bub@{SHA}": "control or format character in its path",
            f"openai/codex-action/x\u2028y@{SHA}": "a line break, control or format character in its path",
            f"OpenAI./codex-action@{SHA}": "a character in its owner or repository name",
            f"openai/codex-action.@{SHA}": "a character in its owner or repository name",
            f"openai/codex-action.git@{SHA}": "'.git' at the end of its repository name",
        }
        for uses, why in cases.items():
            with self.subTest(uses=uses):
                self.assertIn(why, wf_mod.respelled_reference(uses))
        for uses in (f"openai/codex-action@{SHA}", "./x", "$/x", "docker://a//b", ".\\x", None, 5,
                     f"openai/codex-action@{SHA} ", f"openai/codex-action@{SHA}\n", "docker://alpine:3 ",
                     f"octo/repo/my action@{SHA}", f"octo/repo.js/.github/workflows/my workflow.yml@{SHA}",
                     f"Octo-Org/repo_name.v2@{SHA}", "openai/codex-action", "", f"user_emu/repo@{SHA}",
                     f"org/.github/.github/workflows/ci.yml@{SHA}", f"../repo/x@{SHA}", f"openai/./codex-action@{SHA}"):
            with self.subTest(uses=uses):
                self.assertIsNone(wf_mod.respelled_reference(uses))


class RunnerSelectorTest(unittest.TestCase):
    """Found by the review of 2d.15: OBAAF-GHA-013's runtime selector (`head.repo.full_name ==
    github.repository && <self-hosted> || '<hosted>'`) took space out of the whole expression before it
    read the hosted label, so `'ubuntu-latest '` was GitHub's ubuntu-latest and the finding informational."""

    SELECTOR = ("on: pull_request\npermissions: {contents: read}\njobs:\n  build:\n"
                "    runs-on: \"${{ github.event.pull_request.head.repo.full_name == github.repository && "
                "'self-hosted' || %s }}\"\n    steps:\n      - run: make\n")

    def severity(self, label):
        result = check_files({".github/workflows/b.yml": self.SELECTOR % label})
        (found,) = [f for f in result.findings if f.rule == "OBAAF-GHA-013"]
        return found.severity

    def test_the_plain_selector_is_still_informational(self):
        self.assertEqual(self.severity("'ubuntu-latest'"), "info")
        self.assertEqual(self.severity("'Ubuntu-Latest'"), "info")

    def test_a_padded_label_in_the_selector_is_not_the_hosted_runner(self):
        for label in ("'ubuntu-latest '", "' ubuntu-latest'", "'ubuntu-latest\\t'", "'ubuntu- latest'"):
            with self.subTest(label=label):
                self.assertNotEqual(self.severity(label), "info")

    def test_the_selector_is_read_from_its_tokens(self):
        """Found by the second review pass: `"` was read as `'` before quotes were paired, so a `"` inside a
        string before the hosted label hid the label's space; and a quoted value with space in the other
        branch (`fromJSON('["self-hosted", "linux"]')`) made a sound selector medium."""
        self.assertNotEqual(self.severity("'ubuntu-latest\\u200b'"), "info")     # a format character, not space
        tricky = ("on: pull_request\npermissions: {contents: read}\njobs:\n  build:\n"
                  "    runs-on: ${{ github.event.pull_request.head.repo.full_name == github.repository && 'a\"'||'ubuntu-latest ' }}\n"
                  "    steps:\n      - run: make\n")
        (found,) = [f for f in check_files({".github/workflows/b.yml": tricky}).findings if f.rule == "OBAAF-GHA-013"]
        self.assertEqual(found.severity, "medium")
        text = self.SELECTOR.replace("'self-hosted' || %s", "fromJSON('[\\\"self-hosted\\\", \\\"linux\\\"]') || 'ubuntu-latest'")
        (found,) = [f for f in check_files({".github/workflows/b.yml": text}).findings if f.rule == "OBAAF-GHA-013"]
        self.assertEqual(found.severity, "info", text)
        for odd in ('\\"ubuntu-latest\\"', "'ubuntu-latest"):     # a double-quoted or an unclosed string
            with self.subTest(odd=odd):
                self.assertNotEqual(self.severity(odd), "info")
        for form in ("github.repository != github.event.pull_request.head.repo.full_name && 'Ubuntu-Latest' || 'self-hosted'",
                     "github.event.pull_request.head.repo.full_name == github.repository && inputs.runner || 'ubuntu-24.04'",
                     "GITHUB.EVENT.PULL_REQUEST.HEAD.REPO.FULL_NAME==GITHUB.REPOSITORY&&'it''s'||'ubuntu-latest'"):
            with self.subTest(form=form):
                text = self.SELECTOR.replace("github.event.pull_request.head.repo.full_name == github.repository && "
                                             "'self-hosted' || %s", form)
                (found,) = [f for f in check_files({".github/workflows/b.yml": text}).findings if f.rule == "OBAAF-GHA-013"]
                self.assertEqual(found.severity, "info", form)

    def test_space_round_the_selector_is_not_the_form(self):
        for pad in (" %s", "%s ", "%s\\n"):
            with self.subTest(pad=pad):
                text = self.SELECTOR.replace('"${{', '"' + pad.split("%s")[0] + "${{").replace(
                    '}}"', "}}" + pad.split("%s")[1] + '"')
                (found,) = [f for f in check_files({".github/workflows/b.yml": text % "'ubuntu-latest'"}).findings
                            if f.rule == "OBAAF-GHA-013"]
                self.assertNotEqual(found.severity, "info")


class ReviewFindingsTest(unittest.TestCase):
    """The rest of what the review of 2d.15 found."""

    def errors(self, files):
        return [e for e in check_files(files).errors if "uses written as" in e or "'parallel'" in e]

    def test_names_github_does_not_have_are_errors(self):
        for uses in (f"openai/codex%2Daction@{SHA}", f"openai%2Fcodex-action@{SHA}",
                     f"openai/codex-actio\u0301n@{SHA}", f"opena\u0131/codex-action@{SHA}",
                     f"openai/codex-action?@{SHA}", f"'openai/codex-action#@{SHA}'", f"openai/codex-action.git@{SHA}",
                     f"openai/codex-action.GIT@{SHA}"):
            with self.subTest(uses=uses):
                errors = self.errors({".github/workflows/r.yml": step_workflow(uses)})
                self.assertEqual(len(errors), 1, errors)

    def test_space_inside_a_part_of_the_path_is_read_as_written(self):
        self.assertEqual(self.errors({".github/workflows/r.yml": step_workflow(f"octo/repo/my action@{SHA}")}), [])
        text = ("on: push\npermissions: {}\njobs:\n  call:\n"
                f"    uses: octo/repo/.github/workflows/my workflow.yml@{SHA}\n")
        self.assertEqual(self.errors({".github/workflows/r.yml": text}), [])

    def test_a_step_with_parallel_and_uses_is_an_error(self):
        text = ("on: pull_request\npermissions: {contents: read}\njobs:\n  review:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n      - uses: openai/codex-action@{SHA}\n        parallel:\n          - run: echo\n")
        errors = self.errors({".github/workflows/r.yml": text})
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("has 'parallel' and also 'run' or 'uses'", errors[0])

    def test_a_parallel_group_inside_another_is_an_error(self):
        text = ("on: pull_request\npermissions: {contents: read}\njobs:\n  review:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - parallel:\n          - parallel:\n"
                f"              - uses: openai/codex-action@{SHA}\n          - run: echo\n")
        errors = self.errors({".github/workflows/r.yml": text})
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("a 'parallel' group inside a 'parallel' group", errors[0])

    def test_parallel_entries_are_reported_once_and_strings_are_errors(self):
        text = ("on: pull_request\npermissions: {contents: read}\njobs:\n  review:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - parallel:\n          - parallel: [{run: echo}]\n          - parallel: [{run: echo}]\n"
                f"          - openai/codex-action@{SHA}\n")
        errors = self.errors({".github/workflows/r.yml": text})
        self.assertEqual(len(errors), 2, errors)
        self.assertEqual(len(set(errors)), 2, errors)
        self.assertTrue(any("not a mapping" in e for e in errors), errors)

    def test_an_empty_uses_is_not_this_error(self):
        self.assertEqual(self.errors({".github/workflows/r.yml": step_workflow("''")}), [])

    def composite(self, action_file):
        text = ("on: pull_request\npermissions: {contents: read}\njobs:\n  review:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n      - uses: actions/checkout@{SHA}\n        with: {{persist-credentials: false}}\n"
                "      - uses: ./.github/actions/review\n")
        return check_files({".github/workflows/r.yml": text, ".github/actions/review/action.yml": action_file}).errors

    def test_the_composite_error_is_whole(self):
        errors = self.composite(f"runs:\n  using: composite\n  steps:\n    - uses: openai//codex-action@{SHA}\n")
        error = next(e for e in errors if "uses written as" in e)
        self.assertNotIn("characters)", error)          # not cut short
        self.assertIn(f"read it as 'openai/codex-action@{SHA}'", error)
        self.assertEqual(error.count("so the checker cannot tell"), 1, error)

    def test_a_composite_step_whose_uses_is_not_text_is_an_error(self):
        errors = self.composite("runs:\n  using: composite\n  steps:\n    - uses: [1, 2]\n")
        self.assertTrue(any("which is not text" in e for e in errors), errors)

    def test_a_node_action_with_stray_steps_is_not_read_for_them(self):
        errors = self.composite(f"runs:\n  using: node20\n  main: index.js\n  steps:\n    - uses: ' openai/codex-action@{SHA}'\n")
        self.assertEqual([e for e in errors if "uses written as" in e], [])

    def test_an_image_is_shown_as_written(self):
        problem = wf_mod.respelled_problem(" docker://alpine@sha256:" + "a" * 64, "action it runs")
        self.assertIn("read it as 'docker://alpine@sha256:", problem)


if __name__ == "__main__":
    unittest.main()
