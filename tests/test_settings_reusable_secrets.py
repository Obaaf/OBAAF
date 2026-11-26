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
        self.assertIn('Its job "propose" declares an environment that holds it, but the caller must still pass the '
                      'secret', result["message"])
        self.assertIn("empty value", result["message"])

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
        remote = {"bench.yml": caller(uses="octo-org/shared/.github/workflows/p.yml@" + "a" * 40)}
        self.assertEqual(status(assess_files(ADMIN, remote), "OBAAF-SET-011"), "not-applicable")


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

    def test_under_another_name_the_environment_must_hold_that_name(self):
        # T is what the called job reads; main-only holds HELDOUT_TOKEN, not T, so T is what the caller passed:
        # empty, because the caller cannot read HELDOUT_TOKEN.
        files = {"r.yml": caller("    secrets:\n      T: ${{ secrets.HELDOUT_TOKEN }}\n"),
                 "w.yml": called("secrets.T", "    environment: main-only\n")}
        result = one(files)
        self.assertEqual(result["state"], "finding")
        self.assertIn('as "T"', result["message"])

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
        self.assertIn("only if it declares that environment itself", result["message"])

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


class SecondCallTest(unittest.TestCase):

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
