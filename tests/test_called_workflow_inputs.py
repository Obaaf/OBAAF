"""Flagship slice 2d.4b3a: what a called local workflow is given.

Since slice 2d.4b1 a workflow that a job of the same repository calls (`uses:
./.github/workflows/x.yml`) is read with the events that can start the calling job. Two things the
caller gives it were still not read:

- the caller's `with:`, which is what the called workflow's `inputs` hold. A checkout of `${{
  inputs.ref }}` that a `pull_request_target` caller hands the pull request's head was "cannot tell"
  at medium, not OBAAF-GHA-002 high, and an outsider's text handed to an input and expanded in a
  script was no OBAAF-GHA-010 at all;
- the caller's token. A called job that declares no permissions holds what the calling job grants, and
  OBAAF-GHA-003 and 004 said so in general (kind `inherited`) without naming what the callers of the
  repository grant, so an acceptance written while every caller granted read only still covered a
  caller that grants `contents: write`.

Now each reference to `inputs` in the called workflow (outside `on`) is read as `format()` of the
reference as written (for a caller the checker cannot see) and each value a caller of the repository
gives it, and the `inherited` findings name, as a fact, what each caller grants.
"""

import time
import unittest

from helpers import TempDir

from obaaf import checker
from obaaf.checker import baseline as baseline_mod

SHA = "1111111111111111111111111111111111111111"
CALLED = ".github/workflows/called.yml"
CALLER = ".github/workflows/caller.yml"


def build(tmp, files):
    root = tmp / "repo"
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def check(tmp, files, **kwargs):
    return checker.check(build(tmp, files), **kwargs)


def caller(on="pull_request_target", given="", job="call", perms="permissions: {}\n", job_perms="",
           uses="./.github/workflows/called.yml"):
    with_ = "    with:\n" + "".join(f"      {line}\n" for line in given.splitlines()) if given else ""
    return f"on: {on}\n{perms}jobs:\n  {job}:\n{job_perms}    uses: {uses}\n{with_}"


def called(steps, inputs="ref", extra_job="", perms="permissions:\n  contents: read\n", job="work"):
    declared = "".join(f"      {name}:\n        type: string\n" for name in inputs.split()) if inputs else ""
    on = f"on:\n  workflow_call:\n    inputs:\n{declared}" if declared else "on: workflow_call\n"
    return f"{on}{perms}jobs:\n  {job}:\n    runs-on: ubuntu-latest\n{extra_job}    steps:\n{steps}"


def checkout(ref):
    return (f"      - uses: actions/checkout@{SHA}\n        with:\n          ref: {ref}\n"
            "          persist-credentials: false\n")


def found(result, rule, path=CALLED):
    return [f for f in result.findings if f.rule == rule and f.path == path]


HEAD = "${{ github.event.pull_request.head.sha }}"


class ACallersInputIsReadInItsPlaceTest(unittest.TestCase):

    def test_the_head_handed_to_an_input_is_checked_out(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(given=f"ref: {HEAD}"),
                                 CALLED: called(checkout("${{ inputs.ref }}"))})
        (finding,) = found(result, "OBAAF-GHA-002")
        self.assertEqual((finding.severity, finding.kind), ("high", "checkout"))
        self.assertIn("github.event.pull_request.head.sha", finding.facts["reads"])

    def test_without_a_caller_in_the_repository_it_is_as_before(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLED: called(checkout("${{ inputs.ref }}"))})
        self.assertEqual(found(result, "OBAAF-GHA-002"), [])

    def test_a_caller_that_hands_the_base_leaves_cannot_tell_for_a_caller_not_seen(self):
        # The reference as written stays among the values: another repository may call the workflow.
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(given="ref: ${{ github.sha }}"),
                                 CALLED: called(checkout("${{ inputs.ref }}"))})
        (finding,) = found(result, "OBAAF-GHA-002")
        self.assertEqual((finding.severity, finding.kind), ("medium", "checkout-unresolved"))

    def test_the_spellings_of_a_reference(self):
        for ref in ["${{ inputs['ref'] }}", "${{ INPUTS.REF }}", "${{ Inputs.Ref }}", "x-${{ inputs.ref }}",
                    "${{ format('{0}', inputs.ref) }}", "${{inputs.ref}}"]:
            with self.subTest(ref=ref), TempDir() as tmp:
                result = check(tmp, {CALLER: caller(given=f"ref: {HEAD}"), CALLED: called(checkout(repr(ref)))})
                self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])

    def test_the_spellings_of_the_name_a_caller_gives(self):
        for key in ["REF", "Ref", " ref "]:
            with self.subTest(key=key), TempDir() as tmp:
                result = check(tmp, {CALLER: caller(given=f"{key!r}: {HEAD}"),
                                     CALLED: called(checkout("${{ inputs.ref }}"))})
                self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])

    def test_one_of_two_callers_hands_the_head(self):
        other = ".github/workflows/other.yml"
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(given="ref: ${{ github.sha }}"),
                                 other: caller(given=f"ref: {HEAD}"),
                                 CALLED: called(checkout("${{ inputs.ref }}"))})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])

    def test_a_default_is_read_for_a_caller_that_gives_nothing(self):
        text = called(checkout("${{ inputs.ref }}"), inputs="").replace(
            "on: workflow_call\n",
            "on:\n  workflow_call:\n    inputs:\n      ref:\n        type: string\n"
            "        default: ${{ github.event.pull_request.head.sha }}\n")
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(), CALLED: text})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])

    def test_a_name_the_workflow_does_not_declare_is_put_in_too(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(given=f"ref: {HEAD}"),
                                 CALLED: called(checkout("${{ inputs.ref }}"), inputs="")})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])

    def test_an_outsiders_text_handed_to_an_input_is_expanded_in_a_script(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(on="issue_comment", given="body: ${{ github.event.comment.body }}"),
                                 CALLED: called('      - run: echo "${{ inputs.body }}"\n', inputs="body")})
        (finding,) = found(result, "OBAAF-GHA-010")
        self.assertEqual(finding.severity, "high")

    def test_a_chain_carries_the_first_callers_value(self):
        middle = ".github/workflows/middle.yml"
        middle_text = ("on:\n  workflow_call:\n    inputs:\n      ref:\n        type: string\npermissions: {}\n"
                       "jobs:\n  pass:\n    uses: ./.github/workflows/called.yml\n    with:\n"
                       "      ref: ${{ inputs.ref }}\n")
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(given=f"ref: {HEAD}", uses="./.github/workflows/middle.yml"),
                                 middle: middle_text, CALLED: called(checkout("${{ inputs.ref }}"))})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])

    def test_a_job_condition_without_braces_is_read_with_the_value(self):
        extra = "    if: inputs.ref != ''\n"
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(given=f"ref: {HEAD}"),
                                 CALLED: called(checkout("${{ inputs.ref }}"), extra_job=extra)})
        (finding,) = found(result, "OBAAF-GHA-002")
        self.assertIn("github.event.pull_request.head.sha", " ".join(finding.facts["condition"]))

    def test_the_on_block_is_not_changed(self):
        # A default is in the called workflow's own terms, and `on` is not put in.
        text = called(checkout("${{ inputs.ref }}"), inputs="").replace(
            "on: workflow_call\n",
            "on:\n  workflow_call:\n    inputs:\n      ref:\n        type: string\n        default: ${{ inputs.ref }}\n")
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(), CALLED: text})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["medium"])
        self.assertEqual(result.errors, [])


class TheCallersOwnContextsTest(unittest.TestCase):

    def test_the_callers_matrix_is_not_read_as_the_called_jobs(self):
        # The called job's matrix holds an outsider's text; the caller's does not. The caller's
        # `matrix.t` must not be read as the called job's.
        extra = "    strategy:\n      matrix:\n        t: ['${{ github.event.issue.title }}']\n"
        text = (f"on: issues\npermissions: {{}}\njobs:\n  call:\n    strategy:\n      matrix:\n        t: [a, b]\n"
                "    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ matrix.t }}\n")
        with TempDir() as tmp:
            result = check(tmp, {CALLER: text,
                                 CALLED: called('      - run: echo "${{ inputs.t }}"\n', inputs="t", extra_job=extra)})
        self.assertEqual(found(result, "OBAAF-GHA-010"), [])

    def test_a_callers_job_output_is_cannot_tell(self):
        text = (f"on: pull_request_target\npermissions: {{}}\njobs:\n  find:\n    runs-on: ubuntu-latest\n"
                "    outputs:\n      sha: ${{ steps.s.outputs.sha }}\n    steps:\n      - id: s\n        run: echo\n"
                "  call:\n    needs: find\n    uses: ./.github/workflows/called.yml\n    with:\n"
                "      ref: ${{ needs.find.outputs.sha }}\n")
        with TempDir() as tmp:
            result = check(tmp, {CALLER: text, CALLED: called(checkout("${{ inputs.ref }}"))})
        (finding,) = found(result, "OBAAF-GHA-002")
        self.assertEqual((finding.severity, finding.kind), ("medium", "checkout-unresolved"))
        self.assertIn("caller.needs.find.outputs.sha", finding.facts["reads"])


class WhatIsNotWorkedOutIsSaidTest(unittest.TestCase):

    def test_a_reference_to_every_input_gets_every_value(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(on="issue_comment", given="body: ${{ github.event.comment.body }}"),
                                 CALLED: called("      - run: echo '${{ toJSON(inputs) }}'\n", inputs="body")})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-010")], ["high"])
        self.assertTrue(any("does not work out" in note for note in result.notes), result.notes)

    def test_a_with_that_is_not_a_mapping_gives_every_input(self):
        text = caller() + "    with: ${{ github.event.pull_request.head.sha }}\n"
        with TempDir() as tmp:
            result = check(tmp, {CALLER: text, CALLED: called(checkout("${{ inputs.ref }}"))})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])
        self.assertTrue(any("not a mapping" in note for note in result.notes), result.notes)

    def test_a_key_that_is_not_text_gives_every_input(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(given=f"null: {HEAD}"), CALLED: called(checkout("${{ inputs.ref }}"))})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])
        self.assertTrue(any("not text" in note for note in result.notes), result.notes)


class BoundsTest(unittest.TestCase):

    def test_a_text_past_the_bound_is_an_error_and_is_read_as_written(self):
        files = {CALLED: called(checkout("${{ inputs.ref }}"))}
        for n in range(30):
            files[f".github/workflows/c{n:02d}.yml"] = caller(given=f"ref: {HEAD}-{n}-" + "x" * 5000)
        with TempDir() as tmp:
            result = check(tmp, files)
        self.assertTrue(any(CALLED in e and "inputs are read as written" in e for e in result.errors), result.errors)
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["medium"])

    def test_values_that_double_at_each_level_end_in_an_error_quickly(self):
        # Each level hands its own input on twice in one value, so the text doubles at each level.
        files = {}
        count = 40
        for level in range(count):
            name = f".github/workflows/w{level:03d}.yml"
            if level == count - 1:
                files[name] = called(checkout("${{ inputs.ref }}"))
            else:
                target = "called" if level == count - 2 else f"w{level + 1:03d}"
                on = ("pull_request_target" if level == 0 else
                      "\n  workflow_call:\n    inputs:\n      ref:\n        type: string")
                files[name] = (f"on: {on}\npermissions: {{}}\njobs:\n  call:\n    uses: ./.github/workflows/{target}.yml\n"
                               "    with:\n      ref: ${{ inputs.ref }}-${{ inputs.ref }}\n")
        files[".github/workflows/w000.yml"] = files[".github/workflows/w000.yml"].replace(
            "${{ inputs.ref }}-${{ inputs.ref }}", HEAD)
        files[CALLED] = files.pop(f".github/workflows/w{count - 1:03d}.yml")
        with TempDir() as tmp:
            start = time.monotonic()
            result = check(tmp, files)
            spent = time.monotonic() - start
        self.assertLess(spent, 20)
        self.assertTrue(any("inputs are read as written" in e for e in result.errors), result.errors)

    def test_many_callers_with_the_same_value_are_one_value(self):
        files = {CALLED: called(checkout("${{ inputs.ref }}") * 50)}
        for n in range(500):
            files[f".github/workflows/c{n:03d}.yml"] = caller(given=f"ref: {HEAD}")
        with TempDir() as tmp:
            start = time.monotonic()
            result = check(tmp, files)
            spent = time.monotonic() - start
        self.assertLess(spent, 30)
        self.assertEqual([e for e in result.errors if "inputs" in e], [])


class FromTheFirstReviewTest(unittest.TestCase):

    def test_aliases_of_a_long_value_given_many_times_end_quickly(self):
        # 100 jobs each giving 100 aliases of a 100 KB value took 128 s before each value was read once.
        keys = "".join(f"        k{n}: *v\n" for n in range(1, 100))
        jobs = "".join(f"  c{n}:\n    uses: ./.github/workflows/called.yml\n    with: *w\n" for n in range(1, 100))
        text = ("on: issue_comment\npermissions: {}\njobs:\n  c0:\n    uses: ./.github/workflows/called.yml\n"
                "    with: &w\n        k0: &v \"${{ github.event.comment.body || '" + "a" * 100_000 + "' }}\"\n"
                + keys + jobs)
        with TempDir() as tmp:
            start = time.monotonic()
            result = check(tmp, {CALLER: text, CALLED: called('      - run: echo "${{ inputs.k0 }}"\n', inputs="k0")})
            spent = time.monotonic() - start
        self.assertLess(spent, 20)
        self.assertTrue(any("inputs are read as written" in e for e in result.errors), result.errors)

    def test_many_inputs_sharing_a_long_default_end_quickly(self):
        # 10,000 inputs sharing a 200 KB default took 1.9 GB before.
        specs = "".join(f"      i{n}: *spec\n" for n in range(1, 10_000))
        text = ("on:\n  workflow_call:\n    inputs:\n      i0: &spec {type: string, default: '" + "a" * 200_000 + "'}\n"
                + specs + "permissions: {}\njobs:\n  work:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: echo \"${{ inputs.i0 }}\"\n")
        with TempDir() as tmp:
            start = time.monotonic()
            result = check(tmp, {CALLER: caller(), CALLED: text})
            spent = time.monotonic() - start
        self.assertLess(spent, 20)
        self.assertTrue(any("inputs are read as written" in e for e in result.errors), result.errors)

    def test_a_workflow_that_reads_no_input_is_not_worked_on(self):
        specs = "".join(f"      i{n}: *spec\n" for n in range(1, 10_000))
        text = ("on:\n  workflow_call:\n    inputs:\n      i0: &spec {type: string, default: '" + "a" * 200_000 + "'}\n"
                + specs + "permissions: {}\njobs:\n  work:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n")
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(), CALLED: text})
        self.assertEqual([e for e in result.errors if "inputs" in e], [])

    def test_an_outsiders_text_in_the_callers_matrix_is_followed(self):
        text = ("on: issue_comment\npermissions: {}\njobs:\n  call:\n    strategy:\n      matrix:\n"
                "        b: ['${{ github.event.comment.body }}']\n    uses: ./.github/workflows/called.yml\n"
                "    with:\n      x: ${{ matrix.b }}\n")
        for form in ("matrix.b", "matrix['b']", "MATRIX.B", "toJSON(matrix)"):
            with self.subTest(form=form), TempDir() as tmp:
                result = check(tmp, {CALLER: text.replace("matrix.b }}", form + " }}"),
                                     CALLED: called('      - run: echo "${{ inputs.x }}"\n', inputs="x")})
                self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-010")], ["high"])

    def test_an_outsiders_text_in_the_callers_matrix_include_is_followed(self):
        text = ("on: issue_comment\npermissions: {}\njobs:\n  call:\n    strategy:\n      matrix:\n"
                "        include:\n          - b: '${{ github.event.comment.body }}'\n"
                "    uses: ./.github/workflows/called.yml\n    with:\n      x: ${{ matrix.b }}\n")
        with TempDir() as tmp:
            result = check(tmp, {CALLER: text, CALLED: called('      - run: echo "${{ inputs.x }}"\n', inputs="x")})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-010")], ["high"])

    def test_a_needed_jobs_output_is_followed_one_level(self):
        text = ("on: pull_request_target\npermissions: {}\njobs:\n  pre:\n    runs-on: ubuntu-latest\n"
                "    outputs:\n      sha: ${{ github.event.pull_request.head.sha }}\n    steps:\n      - run: echo\n"
                "  call:\n    needs: pre\n    uses: ./.github/workflows/called.yml\n    with:\n"
                "      ref: ${{ needs.pre.outputs.sha }}\n")
        with TempDir() as tmp:
            result = check(tmp, {CALLER: text, CALLED: called(checkout("${{ inputs.ref }}"))})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-002")], ["high"])

    def test_a_name_with_a_letter_outside_ascii_gives_every_input(self):
        with TempDir() as tmp:
            result = check(tmp, {CALLER: caller(on="issue_comment", given="\u017f: ${{ github.event.comment.body }}"),
                                 CALLED: called('      - run: echo "${{ inputs.s }}"\n', inputs="s")})
        self.assertEqual([f.severity for f in found(result, "OBAAF-GHA-010")], ["high"])
        self.assertTrue(any("outside ASCII" in note for note in result.notes), result.notes)

    def test_a_value_at_the_top_of_the_workflow_is_put_in(self):
        from obaaf.checker import workflow as wf_mod
        called_wf = wf_mod.parse(CALLED, "on: workflow_call\nrun-name: ${{ inputs.x }}\nconcurrency: ${{ inputs.x }}\n"
                                         "jobs:\n  work:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n")
        caller_wf = wf_mod.parse(CALLER, caller(given="x: ${{ github.event.pull_request.head.sha }}"))
        checker._give_callers([(CALLER, caller_wf), (CALLED, called_wf)])
        for key in ("run-name", "concurrency"):
            self.assertIn("github.event.pull_request.head.sha", called_wf.raw[key])


class TheCallersGrantTest(unittest.TestCase):

    AGENT = "      - run: claude -p 'review'\n"

    def agent_findings(self, files):
        with TempDir() as tmp:
            result = check(tmp, files)
        return {f.rule: f for f in result.findings if f.rule in ("OBAAF-GHA-003", "OBAAF-GHA-004")
                and f.path == CALLED}

    def test_what_the_caller_grants_is_part_of_the_finding(self):
        grant = "    permissions:\n      contents: write\n      id-token: write\n"
        found_ = self.agent_findings({CALLER: caller(on="push", job_perms=grant),
                                      CALLED: called(self.AGENT, inputs="", perms="")})
        self.assertEqual(found_["OBAAF-GHA-003"].kind, "inherited")
        self.assertEqual(found_["OBAAF-GHA-003"].facts["granted"],
                         [".github/workflows/caller.yml job 'call' grants contents: write"])
        self.assertEqual(found_["OBAAF-GHA-004"].facts["granted"],
                         [".github/workflows/caller.yml job 'call' grants id-token: write"])

    def test_the_finding_changes_when_a_caller_grants_more(self):
        before = self.agent_findings({CALLER: caller(on="push", job_perms="    permissions:\n      contents: read\n"),
                                      CALLED: called(self.AGENT, inputs="", perms="")})
        after = self.agent_findings({CALLER: caller(on="push", job_perms="    permissions:\n      contents: write\n"),
                                     CALLED: called(self.AGENT, inputs="", perms="")})
        self.assertNotEqual(baseline_mod.key(before["OBAAF-GHA-003"]), baseline_mod.key(after["OBAAF-GHA-003"]))

    def test_without_a_caller_the_finding_is_as_before(self):
        found_ = self.agent_findings({CALLED: called(self.AGENT, inputs="", perms="")})
        self.assertNotIn("granted", found_["OBAAF-GHA-003"].facts)
        self.assertNotIn("granted", found_["OBAAF-GHA-004"].facts)

    def test_a_caller_that_declares_nothing_grants_the_default(self):
        found_ = self.agent_findings({CALLER: caller(on="push", perms=""), CALLED: called(self.AGENT, inputs="", perms="")})
        (entry,) = found_["OBAAF-GHA-003"].facts["granted"]
        self.assertIn("repository's default", entry)

    def test_the_workflows_grant_counts_for_its_calling_job(self):
        found_ = self.agent_findings({CALLER: caller(on="push", perms="permissions: write-all\n"),
                                      CALLED: called(self.AGENT, inputs="", perms="")})
        self.assertEqual(found_["OBAAF-GHA-003"].facts["granted"],
                         [".github/workflows/caller.yml job 'call' grants write-all"])

    def test_a_chain_is_followed_to_the_first_caller_that_declares(self):
        middle = ".github/workflows/middle.yml"
        middle_text = "on: workflow_call\njobs:\n  pass:\n    uses: ./.github/workflows/called.yml\n"
        found_ = self.agent_findings({CALLER: caller(on="push", job_perms="    permissions:\n      packages: write\n",
                                                     uses="./.github/workflows/middle.yml"),
                                      middle: middle_text, CALLED: called(self.AGENT, inputs="", perms="")})
        self.assertEqual(found_["OBAAF-GHA-003"].facts["granted"],
                         [".github/workflows/caller.yml job 'call' grants packages: write"])

    def test_a_job_that_declares_permissions_is_not_given_the_callers(self):
        found_ = self.agent_findings({CALLER: caller(on="push", job_perms="    permissions:\n      contents: write\n"),
                                      CALLED: called(self.AGENT, inputs="")})
        self.assertNotIn("OBAAF-GHA-003", found_)

    def test_a_caller_only_another_repository_calls_grants_what_that_caller_grants(self):
        middle = ".github/workflows/middle.yml"
        middle_text = "on: workflow_call\njobs:\n  pass:\n    uses: ./.github/workflows/called.yml\n"
        found_ = self.agent_findings({middle: middle_text, CALLED: called(self.AGENT, inputs="", perms="")})
        (entry,) = found_["OBAAF-GHA-003"].facts["granted"]
        self.assertIn("not in this repository", entry)

    def test_a_workflow_that_can_also_start_on_its_own_says_so(self):
        text = called(self.AGENT, inputs="", perms="").replace("on: workflow_call", "on: [workflow_call, push]")
        found_ = self.agent_findings({CALLER: caller(on="push", job_perms="    permissions:\n      contents: read\n"),
                                      CALLED: text})
        self.assertTrue(any("can also start on push" in e for e in found_["OBAAF-GHA-003"].facts["granted"]))

    def test_many_agent_jobs_and_callers_are_quick(self):
        # The review found it quadratic: 1,000 agent jobs and 2,000 callers took 22 s.
        jobs = "".join(f"  a{n}:\n    runs-on: ubuntu-latest\n    steps:\n      - run: claude -p x\n" for n in range(1000))
        calls = "".join(f"  c{n}:\n    permissions:\n      contents: write\n    uses: ./.github/workflows/called.yml\n"
                        for n in range(2000))
        with TempDir() as tmp:
            start = time.monotonic()
            check(tmp, {CALLER: f"on: push\npermissions: {{}}\njobs:\n{calls}",
                        CALLED: f"on: workflow_call\njobs:\n{jobs}"})
            spent = time.monotonic() - start
        self.assertLess(spent, 30)


if __name__ == "__main__":
    unittest.main()
