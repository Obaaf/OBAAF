"""OBAAF-SET-011 read from GitHub's page on reusing workflows (flagship slice 2b.9, issue #212 item 1).

The page (https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows, read on 2026-11-26)
says: "The job that calls the reusable workflow can't use the `environment` keyword"; "To use an environment
secret in a reusable workflow, set `environment` on the job in the reusable workflow. The caller workflow must
still pass the secret. Use `secrets: inherit` or pass the secret by name"; "You can pass a secret by name even
if it only exists in the environment"; "The job that sets `environment` receives the environment secret's
value"; "If the caller workflow doesn't pass an environment secret, the secret resolves to an empty string in
the reusable workflow. The workflow run doesn't show an error."

Before this slice the rule weighed only a caller that passed something, reported a secret passed by name
"whatever the called workflow declares", and told the caller to stop passing it. The first adopter's incident
(Expectrail `ad3e0775`, 2026-11-10: "a called workflow does not see the main-only environment's secrets") was a
caller that passed nothing to a called job that declared the environment, and the rule did not apply to it.

The recording `admin-token` holds: environment `main-only` with HELDOUT_TOKEN and MODEL_API_KEY, environment
`release` with PACKAGE_INDEX_TOKEN, and MODEL_API_KEY also as a repository secret.
"""

import unittest

from test_settings_rules import ADMIN, assess_files, job, of, status, workflow

from obaaf.audit import rules

CALL = "./.github/workflows/w.yml"


def caller(passes: str = "", uses: str = CALL, name: str = "case") -> str:
    return workflow("  workflow_dispatch:\n", f"  {name}:\n    uses: {uses}\n{passes}")


def called(reads: str, environment: str = "", job_id: str = "propose") -> str:
    """A called workflow whose one job reads ``reads`` (an expression body) in a step's env."""
    return workflow("  workflow_call:\n", job(job_id, environment, "      - run: ./propose\n        env:\n"
                                                                    f"          K: ${{{{ {reads} }}}}\n"))


def results(files: dict) -> list[tuple]:
    found = assess_files(ADMIN, files)
    return [(r["state"], r.get("severity"), r["subject"]) for r in of(found, "OBAAF-SET-011")]


def one(files: dict) -> dict:
    result, = of(assess_files(ADMIN, files), "OBAAF-SET-011")
    return result


class TheIncidentTest(unittest.TestCase):
    """Expectrail `ad3e0775`: jit-bench.yml called jit.yml with no `secrets:`, and jit.yml's propose job declared
    `environment: main-only` and read the model key. Every propose job ran with no key."""

    FILES = {"bench.yml": caller(), "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")}

    def test_a_caller_that_passes_nothing_to_a_job_that_declares_the_environment_is_a_finding(self):
        result = one(self.FILES)
        self.assertEqual((result["state"], result["severity"], result["subject"]),
                         ("finding", "medium", "job .github/workflows/bench.yml#case"))
        self.assertIn('without passing "HELDOUT_TOKEN"', result["message"])
        self.assertIn('Its job "propose" declares an environment that holds "HELDOUT_TOKEN", but the caller must still '
                      'pass a secret for the job to get it.', result["message"])
        self.assertIn('"HELDOUT_TOKEN" is empty in the called workflow, and the run shows no error',
                      result["message"])

    def test_one_finding_for_the_call_with_every_secret_and_job_it_concerns(self):
        # jit.yml's propose and revise jobs each read MODEL_API_KEY and HELDOUT_TOKEN: one finding, not four.
        steps = ("      - run: ./x\n        env:\n          A: ${{ secrets.MODEL_API_KEY }}\n"
                 "          B: ${{ secrets.HELDOUT_TOKEN }}\n")
        two = workflow("  workflow_call:\n", job("propose", "    environment: main-only\n", steps)
                       + job("revise", "    environment: main-only\n", steps))
        result = one({"bench.yml": caller(), "w.yml": two})
        self.assertIn('without passing "HELDOUT_TOKEN", "MODEL_API_KEY", which its jobs "propose", "revise" read',
                      result["message"])

    def test_the_same_when_the_secret_is_also_stored_for_every_job(self):
        # MODEL_API_KEY is also a repository secret, which a called workflow does not get unless it is passed.
        files = {"bench.yml": caller(), "w.yml": called("secrets.MODEL_API_KEY", "    environment: main-only\n")}
        self.assertEqual(results(files), [("finding", "medium", "job .github/workflows/bench.yml#case")])

    def test_and_when_the_called_job_names_its_environment_with_an_expression(self):
        # Not passed is empty whichever environment the job gets.
        files = {"bench.yml": caller(), "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: ${{ inputs.e }}\n")}
        self.assertEqual(results(files)[0][:2], ("finding", "medium"))

    def test_passing_it_by_name_or_with_inherit_clears_it(self):
        for passes in ("    secrets:\n      HELDOUT_TOKEN: ${{ secrets.HELDOUT_TOKEN }}\n",
                       "    secrets:\n      heldout_token: ${{ secrets['HELDOUT_TOKEN'] }}\n",
                       "    secrets: inherit\n"):
            files = {"bench.yml": caller(passes), "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")}
            found = assess_files(ADMIN, files)
            self.assertEqual(status(found, "OBAAF-SET-011"), "no-finding", passes)
        # The environment's name in another letter case is the same environment.
        files = {"bench.yml": caller("    secrets: inherit\n"),
                 "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: Main-Only\n")}
        self.assertEqual(status(assess_files(ADMIN, files), "OBAAF-SET-011"), "no-finding")

    def test_a_secret_kept_outside_every_environment_and_not_passed_is_not_this_rules(self):
        files = {"bench.yml": caller(), "w.yml": called("secrets.NOT_STORED_ANYWHERE")}
        self.assertEqual(status(assess_files(ADMIN, files), "OBAAF-SET-011"), "no-finding")

    def test_a_call_to_a_workflow_that_reads_no_secret_and_is_passed_none_does_not_apply(self):
        files = {"bench.yml": caller(), "w.yml": workflow("  workflow_call:\n", job("plan"))}
        self.assertEqual(status(assess_files(ADMIN, files), "OBAAF-SET-011"), "not-applicable")

    def test_a_workflow_that_was_not_read_and_is_passed_nothing_is_cannot_tell(self):
        # The review of slice 2b.9: a job there may read a secret an environment holds, which it would get empty.
        for uses in ("octo-org/shared/.github/workflows/p.yml@" + "a" * 40, "./.github/workflows/W.yml"):
            files = {"bench.yml": caller(uses=uses), "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")}
            result = one(files)
            self.assertEqual(result["state"], "cannot-tell", uses)
            self.assertIn("which was not read", result["message"], uses)

    def test_a_caller_that_passes_other_secrets_but_not_the_one_read_is_a_finding(self):
        # The shape test_a_secret_stored_for_every_job_is_passed_whole had before slice 2b.9.
        files = {"bench.yml": caller("    secrets:\n      key: ${{ secrets.MODEL_API_KEY }}\n"),
                 "w.yml": called("secrets.PACKAGE_INDEX_TOKEN")}
        result = one(files)
        self.assertEqual(result["state"], "finding")
        self.assertIn('without passing "PACKAGE_INDEX_TOKEN"', result["message"])

    def test_the_message_names_only_the_secrets_each_job_s_environment_holds(self):
        two = workflow("  workflow_call:\n",
                       job("j1", "    environment: main-only\n",
                           "      - run: ./x\n        env:\n          A: ${{ secrets.HELDOUT_TOKEN }}\n")
                       + job("j2", "", "      - run: ./x\n        env:\n          B: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n"))
        message = one({"bench.yml": caller(), "w.yml": two})["message"]
        self.assertIn('Its job "j1" declares an environment that holds "HELDOUT_TOKEN",', message)
        self.assertNotIn('"j2" declares', message)

    def test_a_secret_marked_required_makes_the_run_fail_rather_than_be_empty(self):
        declared = workflow("  workflow_call:\n    secrets:\n      HELDOUT_TOKEN:\n        required: true\n",
                            job("propose", "    environment: main-only\n",
                                "      - run: ./x\n        env:\n          A: ${{ secrets.HELDOUT_TOKEN }}\n"))
        message = one({"bench.yml": caller(), "w.yml": declared})["message"]
        self.assertIn('GitHub fails the run at its start for "HELDOUT_TOKEN", which the called workflow marks required',
                      message)
        self.assertNotIn("empty in the called workflow", message)

    def test_a_named_secret_is_weighed_beside_every_secret(self):
        # The review of slice 2b.9: `toJSON(secrets)` beside a named secret hid the named one.
        both = workflow("  workflow_call:\n", job("propose", "    environment: main-only\n",
                                                  "      - run: ./x\n        env:\n          A: ${{ secrets.HELDOUT_TOKEN }}\n"
                                                  "          B: ${{ toJSON(secrets) }}\n"))
        states = sorted(r[0] for r in results({"bench.yml": caller(), "w.yml": both}))
        self.assertEqual(states, ["cannot-tell", "finding"])
        alone = {"bench.yml": caller(), "w.yml": called("toJSON(secrets)", "    environment: main-only\n")}
        self.assertEqual([r[0] for r in results(alone)], ["cannot-tell"])


class PassedByNameTest(unittest.TestCase):

    def test_a_secret_kept_only_in_an_environment_reaches_a_called_job_that_declares_it(self):
        files = {"r.yml": caller("    secrets:\n      PACKAGE_INDEX_TOKEN: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n"),
                 "w.yml": called("secrets.PACKAGE_INDEX_TOKEN", "    environment: release\n")}
        self.assertEqual(status(assess_files(ADMIN, files), "OBAAF-SET-011"), "no-finding")

    def test_one_that_does_not_declare_it_gets_an_empty_value(self):
        files = {"r.yml": caller("    secrets:\n      PACKAGE_INDEX_TOKEN: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n"),
                 "w.yml": called("secrets.PACKAGE_INDEX_TOKEN")}
        result = one(files)
        self.assertEqual((result["state"], result["severity"]), ("finding", "medium"))
        self.assertIn('"PACKAGE_INDEX_TOKEN" is stored only in the environment "release"', result["message"])
        # A job that declares another environment, which does not hold it, is the same.
        files["w.yml"] = called("secrets.PACKAGE_INDEX_TOKEN", "    environment: main-only\n")
        self.assertEqual(results(files)[0][:2], ("finding", "medium"))

    def test_under_another_name_to_a_job_whose_environment_holds_the_secret_is_cannot_tell(self):
        # The review of slice 2b.9: the page says a secret may be passed by name "even if it only exists in the
        # environment", and documents only NAME: ${{ secrets.NAME }}; what T gets here is not documented.
        files = {"r.yml": caller("    secrets:\n      T: ${{ secrets.HELDOUT_TOKEN }}\n"),
                 "w.yml": called("secrets.T", "    environment: main-only\n")}
        result = one(files)
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("not documented", result["message"])

    def test_under_another_name_to_a_job_with_no_such_environment_is_a_finding(self):
        # release holds neither T nor HELDOUT_TOKEN: T is what the caller passed, which it could not read.
        files = {"r.yml": caller("    secrets:\n      T: ${{ secrets.HELDOUT_TOKEN }}\n"),
                 "w.yml": called("secrets.T", "    environment: release\n")}
        result = one(files)
        self.assertEqual(result["state"], "finding")
        self.assertIn('as "T"', result["message"])

    def test_two_keys_in_two_letter_cases_are_cannot_tell_in_either_order(self):
        for first, second in (("TOKEN", "token"), ("token", "TOKEN")):
            files = {"r.yml": caller(f"    secrets:\n      {first}: ${{{{ secrets.MODEL_API_KEY }}}}\n"
                                     f"      {second}: ${{{{ secrets.HELDOUT_TOKEN }}}}\n"),
                     "w.yml": called("secrets.TOKEN")}
            self.assertEqual(one(files)["state"], "cannot-tell", first)

    def test_secrets_written_as_other_text_than_inherit_is_cannot_tell(self):
        for text in ("Inherit", "inheritt", "' inherit '"):
            files = {"r.yml": caller(f"    secrets: {text}\n"),
                     "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")}
            self.assertEqual(one(files)["state"], "cannot-tell", text)

    def test_an_environment_not_written_as_a_plain_name_is_cannot_tell(self):
        for environment in ("    environment: ' main-only '\n", "    environment:\n      url: https://example.com\n",
                            "    environment: ${{ inputs.e }}\n"):
            files = {"r.yml": caller("    secrets: inherit\n"), "w.yml": called("secrets.HELDOUT_TOKEN", environment)}
            result = one(files)
            self.assertEqual(result["state"], "cannot-tell", environment)
            self.assertNotIn("with an expression", result["message"], environment)

    def test_a_file_github_may_read_otherwise_is_cannot_tell(self):
        # A YAML merge key that gives the called job its environment: the audit merges it, GitHub may not.
        merged = ("name: W\non:\n  workflow_call:\npermissions:\n  contents: read\n"
                  "x-env: &env\n  environment: main-only\njobs:\n  propose:\n    <<: *env\n    runs-on: ubuntu-latest\n"
                  "    steps:\n      - run: ./x\n        env:\n          A: ${{ secrets.HELDOUT_TOKEN }}\n")
        files = {"r.yml": caller("    secrets: inherit\n"), "w.yml": merged}
        result = one(files)
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("GitHub may read the files otherwise", result["message"])

    def test_under_its_own_name_with_another_value_is_cannot_tell(self):
        # The page documents what a job that declares the environment gets only for NAME: ${{ secrets.NAME }}.
        for value in ("${{ secrets.MODEL_API_KEY }}", "${{ secrets.HELDOUT_TOKEN || 'none' }}", "plain text"):
            files = {"r.yml": caller(f"    secrets:\n      HELDOUT_TOKEN: {value}\n"),
                     "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")}
            result = one(files)
            self.assertEqual(result["state"], "cannot-tell", value)
            self.assertIn("not documented", result["message"], value)

    def test_a_value_that_reads_an_environment_secret_among_other_things_is_cannot_tell(self):
        files = {"r.yml": caller("    secrets:\n      T: ${{ secrets.HELDOUT_TOKEN || secrets.MODEL_API_KEY }}\n"),
                 "w.yml": called("secrets.T")}
        self.assertEqual(one(files)["state"], "cannot-tell")

    def test_a_value_from_secrets_every_job_can_read_is_no_finding(self):
        files = {"r.yml": caller("    secrets:\n      T: ${{ secrets.MODEL_API_KEY }}\n"), "w.yml": called("secrets.T")}
        self.assertEqual(status(assess_files(ADMIN, files), "OBAAF-SET-011"), "no-finding")

    def test_a_workflow_in_another_repository_is_cannot_tell_where_it_was_a_finding(self):
        remote = "octo-org/shared/.github/workflows/p.yml@" + "a" * 40
        files = {"r.yml": caller("    secrets:\n      PACKAGE_INDEX_TOKEN: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n", remote)}
        result = one(files)
        self.assertEqual(result["state"], "cannot-tell")
        self.assertIn("only if it declares an environment that holds it", result["message"])
        self.assertNotIn("is empty", result["message"])

    def test_a_key_this_reader_does_not_take_as_a_name_is_cannot_tell(self):
        files = {"r.yml": caller("    secrets:\n      ~: ${{ secrets.MODEL_API_KEY }}\n"),
                 "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")}
        self.assertEqual(one(files)["state"], "cannot-tell")

    def test_handed_over_as_an_input_it_is_empty_whatever_the_called_job_declares(self):
        reads_input = workflow("  workflow_call:\n    inputs:\n      token:\n        type: string\n",
                               job("u", "    environment: release\n", "      - run: ./u ${{ inputs.token }}\n"))
        files = {"r.yml": caller("    with:\n      token: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n"), "w.yml": reads_input}
        result = one(files)
        self.assertEqual(result["state"], "finding")
        self.assertIn("as an input", result["message"])


class SecondReviewTest(unittest.TestCase):
    """What the second review of slice 2b.9 found: messages that said more than was known."""

    def test_a_cycle_or_a_chain_deeper_than_github_allows_is_cannot_tell(self):
        reads = ("      - run: ./x\n        env:\n          A: ${{ secrets.HELDOUT_TOKEN }}\n")
        itself = workflow("  workflow_call:\n  workflow_dispatch:\n",
                          "  again:\n    uses: ./.github/workflows/w.yml\n" + job("propose", "    environment: main-only\n", reads))
        self.assertEqual({r[0] for r in results({"w.yml": itself})}, {"cannot-tell"})
        chain = {"a.yml": caller(uses="./.github/workflows/b.yml")}
        for here, there in (("b", "c"), ("c", "d"), ("d", "e")):
            chain[f"{here}.yml"] = workflow("  workflow_call:\n", f"  next:\n    uses: ./.github/workflows/{there}.yml\n"
                                            + job("propose", "    environment: main-only\n", reads))
        chain["e.yml"] = workflow("  workflow_call:\n", job("propose", "    environment: main-only\n", reads))
        found = results(chain)
        self.assertTrue(found)
        self.assertEqual({r[0] for r in found}, {"cannot-tell"})

    def test_a_call_written_with_dollar_slash_says_the_finding_rests_on_it(self):
        files = {"bench.yml": caller(uses="$/.github/workflows/w.yml"),
                 "w.yml": called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")}
        result = one(files)
        self.assertEqual(result["state"], "finding")
        self.assertIn("This holds if GitHub runs a call written with $/", result["message"])

    def test_a_declaration_that_was_not_read_whole_does_not_say_no_error(self):
        body = job("propose", "    environment: main-only\n",
                   "      - run: ./x\n        env:\n          A: ${{ secrets.HELDOUT_TOKEN }}\n")
        for declared in ("    secrets: [HELDOUT_TOKEN]\n", "    secrets:\n      ' HELDOUT_TOKEN ':\n        required: true\n",
                         "    secrets:\n      HELDOUT_TOKEN:\n        required: 'yes'\n"):
            files = {"bench.yml": caller(), "w.yml": workflow(f"  workflow_call:\n{declared}", body)}
            message = one(files)["message"]
            self.assertIn("the run either fails at its start or gets an empty value", message, declared)
            self.assertNotIn("shows no error", message, declared)
            self.assertNotIn("GitHub fails the run at its start for", message, declared)

    def test_a_call_that_passes_a_secret_the_called_workflow_does_not_declare_does_not_say_no_error(self):
        declares = workflow("  workflow_call:\n    secrets:\n      HELDOUT_TOKEN:\n",
                            job("propose", "    environment: main-only\n",
                                "      - run: ./x\n        env:\n          A: ${{ secrets.HELDOUT_TOKEN }}\n"))
        files = {"bench.yml": caller("    secrets:\n      key: ${{ secrets.MODEL_API_KEY }}\n"), "w.yml": declares}
        message = one(files)["message"]
        self.assertIn("the call also passes a secret the called workflow does not declare", message)
        self.assertNotIn("shows no error", message)

    def test_either_value_non_empty_is_no_finding(self):
        # release holds PACKAGE_INDEX_TOKEN; MODEL_API_KEY is a repository secret release does not hold.
        files = {"r.yml": caller("    secrets:\n      PACKAGE_INDEX_TOKEN: ${{ secrets.MODEL_API_KEY }}\n"),
                 "w.yml": called("secrets.PACKAGE_INDEX_TOKEN", "    environment: release\n")}
        self.assertEqual(status(assess_files(ADMIN, files), "OBAAF-SET-011"), "no-finding")

    def test_an_odd_key_to_a_workflow_not_read_does_not_say_every_secret(self):
        remote = "octo-org/shared/.github/workflows/p.yml@" + "a" * 40
        message = one({"r.yml": caller("    secrets:\n      ~: x\n", remote)})["message"]
        self.assertNotIn("passes every secret", message)


class ThirdReviewTest(unittest.TestCase):
    """What the third review of slice 2b.9 found."""

    READS = "      - run: ./x\n        env:\n          A: ${{ secrets.HELDOUT_TOKEN }}\n"

    def test_a_cyclic_file_elsewhere_does_not_silence_another_caller_of_a_shared_workflow(self):
        lib = workflow("  workflow_call:\n", job("propose", "    environment: main-only\n", self.READS))
        bad = workflow("  workflow_call:\n  workflow_dispatch:\n", "  again:\n    uses: ./.github/workflows/bad.yml\n"
                       "  shared:\n    uses: ./.github/workflows/lib.yml\n")
        found = assess_files(ADMIN, {"q.yml": caller(uses="./.github/workflows/lib.yml"), "lib.yml": lib, "bad.yml": bad})
        mine = [r for r in of(found, "OBAAF-SET-011") if r["subject"] == "job .github/workflows/q.yml#case"]
        self.assertEqual([r["state"] for r in mine], ["finding"])
        theirs = {r["state"] for r in of(found, "OBAAF-SET-011") if "bad.yml" in r["subject"]}
        self.assertEqual(theirs, {"cannot-tell"})

    def test_a_deep_chain_elsewhere_does_not_silence_another_caller(self):
        lib = workflow("  workflow_call:\n", job("propose", "    environment: main-only\n", self.READS))
        files = {"q.yml": caller(uses="./.github/workflows/lib.yml"), "lib.yml": lib,
                 "a.yml": caller(uses="./.github/workflows/b.yml", name="start")}
        for here, there in (("b", "c"), ("c", "d"), ("d", "lib")):
            files[f"{here}.yml"] = workflow("  workflow_call:\n", f"  next:\n    uses: ./.github/workflows/{there}.yml\n")
        found = assess_files(ADMIN, files)
        mine = [r["state"] for r in of(found, "OBAAF-SET-011") if r["subject"] == "job .github/workflows/q.yml#case"]
        self.assertEqual(mine, ["finding"])

    def test_two_spellings_of_a_declared_name_are_either_whatever_required_says(self):
        declared = ("  workflow_call:\n    secrets:\n      HELDOUT_TOKEN:\n        required: true\n"
                    "      heldout_token:\n        required: false\n")
        files = {"bench.yml": caller(),
                 "w.yml": workflow(declared, job("propose", "    environment: main-only\n", self.READS))}
        message = one(files)["message"]
        self.assertIn("the run either fails at its start or gets an empty value", message)
        self.assertNotIn("GitHub fails the run at its start for", message)

    def test_the_dollar_slash_clause_reaches_a_call_to_a_file_that_was_not_read(self):
        files = {"r.yml": caller("    with:\n      token: ${{ secrets.PACKAGE_INDEX_TOKEN }}\n", "$/.github/workflows/gone.yml")}
        finding, = of(assess_files(ADMIN, files), "OBAAF-SET-011", "finding")
        self.assertIn("This holds if GitHub runs a call written with $/", finding["message"])


class SecondCallTest(unittest.TestCase):

    def test_a_called_job_that_passes_every_secret_on_from_a_caller_that_passed_none_is_cannot_tell(self):
        # The review of slice 2b.9: it gave no finding.
        middle = workflow("  workflow_call:\n", "  relay:\n    uses: ./.github/workflows/last.yml\n    secrets: inherit\n")
        last = called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")
        found = results({"r.yml": caller(), "w.yml": middle, "last.yml": last})
        self.assertIn(("cannot-tell", None, "job .github/workflows/r.yml#case"), found)

    def test_a_called_job_that_passes_it_on_is_followed_as_a_caller_of_its_own(self):
        middle = workflow("  workflow_call:\n", "  relay:\n    uses: ./.github/workflows/last.yml\n    secrets:\n"
                                                "      HELDOUT_TOKEN: ${{ secrets.HELDOUT_TOKEN }}\n")
        last = called("secrets.HELDOUT_TOKEN", "    environment: main-only\n")
        # The first caller passes it by name: nothing to say at either call.
        files = {"r.yml": caller("    secrets:\n      HELDOUT_TOKEN: ${{ secrets.HELDOUT_TOKEN }}\n"),
                 "w.yml": middle, "last.yml": last}
        self.assertEqual(status(assess_files(ADMIN, files), "OBAAF-SET-011"), "no-finding")
        # It does not: what reaches the last job the page does not say, so the first call is "cannot tell".
        files["r.yml"] = caller()
        self.assertEqual(results(files), [("cannot-tell", None, "job .github/workflows/r.yml#case")])

    def test_inherit_into_a_job_that_reads_every_secret_stays_cannot_tell(self):
        every = workflow("  workflow_call:\n", job("u", "", "      - run: ./u\n        env:\n          A: ${{ toJSON(secrets) }}\n"))
        files = {"r.yml": caller("    secrets: inherit\n"), "w.yml": every}
        self.assertEqual(one(files)["state"], "cannot-tell")


class WordingTest(unittest.TestCase):

    def test_the_fix_no_longer_says_to_stop_passing_the_secret(self):
        rule = rules.RULE_BY_ID["OBAAF-SET-011"]
        self.assertNotIn("stop passing", rule.fix)
        self.assertIn("by name", rule.fix)
        self.assertIn("required", rule.fix)
        self.assertIn("the caller still passes the secret", rule.description)
        self.assertEqual(rule.title, "A reusable workflow gets an empty value for a secret kept in an environment")


if __name__ == "__main__":
    unittest.main()
