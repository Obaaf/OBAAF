"""The checker reads `${{ }}` expressions from their tokens and fails closed.

Each test class below starts from a spelling that got past a rule when expressions were matched as
text: the rule saw nothing, and the workflow would still have used the secret or expanded the
outsider's text. The fix is the reader in obaaf.checker.expr, so the tests cover the reader and
then each rule that depends on it.

None of these workflows has been run on GitHub. The reader takes the wider reading wherever the
platform's behaviour is in doubt, so being wrong about the platform costs a false positive, not a
miss.
"""

import random
import unittest

from helpers import TempDir, run_cli

from obaaf import checker
from obaaf.checker import expr
from obaaf.checker import workflow as wf_mod

HEAD = "on: {trigger}\npermissions:\n  contents: read\n"
STEP = "      - run: echo hi\n"


def _check(tmp, workflow, config=None):
    (tmp / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (tmp / ".github" / "workflows" / "ci.yml").write_text(workflow, encoding="utf-8")
    if config:
        (tmp / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")
    return checker.check(tmp)


def _rules(workflow, config=None):
    with TempDir() as tmp:
        result = _check(tmp, workflow, config)
        return [(f.rule, f.job, f.message) for f in result.findings], result.errors


def _job(env_value, trigger="issue_comment", extra=""):
    return (HEAD.format(trigger=trigger) + "jobs:\n  work:\n    runs-on: ubuntu-latest\n" + extra +
            "    steps:\n      - run: echo hi\n        env:\n          VALUE: " + env_value + "\n")


def _script(script, trigger="issues", env=""):
    return (HEAD.format(trigger=trigger) + "jobs:\n  work:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: " + script + "\n" + env)


class BodiesTest(unittest.TestCase):
    def test_plain_expressions(self):
        self.assertEqual(expr.bodies("a ${{ x }} b ${{ y }}"), [" x ", " y "])

    def test_closing_braces_inside_a_string_do_not_end_the_expression(self):
        found = expr.bodies("${{ format('}}{0}', secrets.KEY) }}")
        self.assertIn(" format('}}{0}', secrets.KEY) ", found)
        # The shorter reading is kept too, so either way of ending the expression is covered.
        self.assertIn(" format('", found)

    def test_doubled_quote_is_an_escaped_quote(self):
        self.assertEqual(expr.bodies("${{ format('it''s }}', secrets.KEY) }}")[0], " format('it''s }}', secrets.KEY) ")

    def test_expression_without_an_end_is_read_to_the_end(self):
        self.assertEqual(expr.bodies("x ${{ secrets.KEY"), [" secrets.KEY"])

    def test_expression_started_inside_a_string_is_still_read(self):
        found = expr.bodies("${{ format('}} ${{ secrets.A }}') }}")
        self.assertTrue(any("secrets.A" in body and "format" not in body for body in found), found)

    def test_pathological_text_is_refused_not_read_slowly(self):
        with self.assertRaises(expr.TooComplex):
            expr.bodies("${{'}}'" * 50000)

    def test_many_ordinary_expressions_are_fine(self):
        self.assertEqual(len(expr.bodies("${{ a }} " * 20000)), 20000)


class SecretRefsTest(unittest.TestCase):
    ONE = {
        "secrets.KEY": "KEY",
        "SECRETS.KEY": "KEY",
        "secrets . KEY": "KEY",
        "secrets['KEY']": "KEY",
        "secrets [ 'KEY' ]": "KEY",
        "format('{0}', secrets.KEY)": "KEY",
        "format('it''s', secrets.KEY)": "KEY",
        "secrets.KEY != ''": "KEY",
        "secrets.my-key": "my-key",
    }
    EVERY = [
        "toJSON(secrets)",
        "tojson( SECRETS )",
        "join(secrets.*, ',')",
        "secrets.*",
        "secrets[format('{0}', 'KEY')]",
        "secrets[matrix.name]",
        "secrets[matrix.name].x",
        "fromJSON(toJSON(secrets)).KEY",
        "contains(secrets, 'x')",
        "format('{0}', secrets)",
        'secrets["KEY"]',
        "secrets['']",
        "secrets[ ]",
        "secrets",
    ]
    NONE = [
        "needs.build.outputs.secrets",
        "github.secrets.KEY",
        "format('secrets.KEY')",
        "inputs.secrets_file",
        "vars.KEY",
        "fromJSON(inputs.x).secrets",
    ]

    def test_a_literal_name_is_that_secret(self):
        for text, name in self.ONE.items():
            self.assertEqual(expr.secret_refs(text), {name}, text)

    def test_anything_else_on_the_secrets_context_is_every_secret(self):
        for text in self.EVERY:
            self.assertIn(expr.ALL, expr.secret_refs(text), text)

    def test_other_things_called_secrets_are_not_the_context(self):
        for text in self.NONE:
            self.assertEqual(expr.secret_refs(text), set(), text)

    def test_index_expression_is_read_for_its_own_references(self):
        self.assertEqual(expr.secret_refs("vars[secrets.KEY]"), {"KEY"})
        self.assertEqual(expr.secret_refs("secrets[secrets.NAME]"), {expr.ALL, "NAME"})

    def test_equivalent_spellings_never_lose_the_reference(self):
        """Property: changing letter case, adding spaces around operators or wrapping the reference
        in a function never makes a reference to a secret disappear."""
        rng = random.Random(20261111)
        wrappers = ["{}", "format('{{0}}', {})", "toJSON({})", "({})", "{} || ''", "join({}.*)",
                    "fromJSON(format('[{{0}}]', {}))[0]", "contains({}, 'a')", "format('}}}}', {})"]
        for _ in range(2000):
            context = "".join(rng.choice((c.upper(), c.lower())) for c in "secrets")
            pad = lambda: " " * rng.randrange(3)  # noqa: E731
            access = rng.choice([f"{pad()}.{pad()}KEY", f"{pad()}[{pad()}'KEY'{pad()}]", f"{pad()}.{pad()}*",
                                 f"{pad()}[{pad()}matrix.k{pad()}]", ""])
            text = "${{" + pad() + rng.choice(wrappers).format(context + access) + pad() + "}}"
            names = wf_mod.secret_names(text)
            self.assertTrue(names & {"KEY", expr.ALL}, f"{text!r} read as {names}")


class PathsTest(unittest.TestCase):
    def _dotted(self, text):
        return [expr.dotted(p) for p in expr.paths(text)]

    def test_index_and_case_spellings_give_the_same_path(self):
        for text in ("github.event.issue.title", "GITHUB.Event.ISSUE.Title", "github['event']['issue'].title",
                     "github . event . issue . title"):
            self.assertEqual(self._dotted(text), ["github.event.issue.title"], text)

    def test_wildcards_and_computed_indexes_are_kept_as_such(self):
        self.assertEqual(self._dotted("github.event.*.title"), ["github.event.*.title"])
        self.assertEqual(self._dotted("github.event[inputs.kind].body"), ["inputs.kind", "github.event.[...].body"])
        self.assertEqual(self._dotted("github.event.commits[0].message"), ["github.event.commits.[...].message"])

    def test_function_names_and_strings_are_not_paths(self):
        self.assertEqual(self._dotted("format('github.event.issue.title', 1)"), [])
        self.assertEqual(self._dotted("contains(github.actor, 'bot')"), ["github.actor"])


class SecretRulesTest(unittest.TestCase):
    """OBAAF-GHA-001, 005 and 024 on spellings that used to read as 'no secret here'."""

    CONFIG = "lanes:\n  \".github/workflows/ci.yml#work\": agent\nprotected_secrets:\n  \"*_API_KEY\": main-only\n"

    def _fired(self, workflow, config=None):
        findings, errors = _rules(workflow, config)
        self.assertEqual(errors, [])
        return {rule for rule, _, _ in findings}, findings

    def test_wildcard_over_the_secrets_context(self):
        rules, findings = self._fired(_job("${{ join(secrets.*, ' ') }}"), self.CONFIG)
        self.assertLessEqual({"OBAAF-GHA-001", "OBAAF-GHA-005", "OBAAF-GHA-024"}, rules)
        self.assertTrue(any("all secrets" in m for r, _, m in findings if r == "OBAAF-GHA-005"), findings)

    def test_secret_after_closing_braces_in_a_string(self):
        rules, findings = self._fired(_job("${{ format('}}{0}', secrets.MODEL_API_KEY) }}"), self.CONFIG)
        self.assertLessEqual({"OBAAF-GHA-001", "OBAAF-GHA-005", "OBAAF-GHA-024"}, rules)
        self.assertTrue(any("MODEL_API_KEY" in m for r, _, m in findings if r == "OBAAF-GHA-024"), findings)

    def test_secret_in_job_outputs(self):
        workflow = (HEAD.format(trigger="issue_comment") + "jobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    outputs:\n      key: ${{ secrets.MODEL_API_KEY }}\n    steps:\n" + STEP)
        rules, _ = self._fired(workflow, self.CONFIG)
        self.assertLessEqual({"OBAAF-GHA-001", "OBAAF-GHA-005", "OBAAF-GHA-024"}, rules)

    def test_secrets_context_passed_to_a_function(self):
        rules, _ = self._fired(_job("${{ contains(secrets, 'x') }}"), self.CONFIG)
        self.assertLessEqual({"OBAAF-GHA-001", "OBAAF-GHA-005", "OBAAF-GHA-024"}, rules)

    def test_any_string_for_secrets_on_a_reusable_call_counts_as_inherit(self):
        workflow = (HEAD.format(trigger="issue_comment") + "jobs:\n  work:\n"
                    "    uses: ./.github/workflows/other.yml\n    secrets: INHERIT\n")
        _, findings = self._fired(workflow)
        self.assertTrue(any(r == "OBAAF-GHA-001" and "secrets: inherit" in m for r, _, m in findings), findings)

    def test_a_job_with_no_secret_still_has_no_secret_finding(self):
        rules, _ = self._fired(_job("${{ needs.build.outputs.secrets }} ${{ format('secrets.KEY') }} ${{ vars.KEY }}"))
        self.assertFalse(rules & {"OBAAF-GHA-001", "OBAAF-GHA-005", "OBAAF-GHA-024"}, rules)

    def test_the_job_token_is_still_not_a_stored_secret(self):
        rules, _ = self._fired(_job("${{ secrets.GITHUB_TOKEN }}"))
        self.assertNotIn("OBAAF-GHA-001", rules)


class ScriptInjectionTest(unittest.TestCase):
    """OBAAF-GHA-010 on spellings that used to read as 'nothing an outsider wrote'."""

    def _gha010(self, workflow):
        findings, errors = _rules(workflow)
        self.assertEqual(errors, [])
        return [m for rule, _, m in findings if rule == "OBAAF-GHA-010"]

    def test_wildcard_in_place_of_the_object(self):
        self.assertEqual(len(self._gha010(_script("echo \"${{ join(github.event.*.title, ' ') }}\""))), 1)

    def test_wildcard_over_the_object_fields(self):
        self.assertEqual(len(self._gha010(_script("echo \"${{ join(github.event.issue.*, ' ') }}\""))), 1)

    def test_computed_index(self):
        self.assertEqual(len(self._gha010(_script("echo \"${{ github.event[inputs.kind].body }}\""))), 1)
        self.assertEqual(len(self._gha010(_script("echo \"${{ github[format('ev{0}', 'ent')].issue.title }}\""))), 1)

    def test_field_after_closing_braces_in_a_string(self):
        found = self._gha010(_script("echo \"${{ format('}}{0}', github.event.issue.title) }}\""))
        self.assertEqual(len(found), 1)
        self.assertIn("github.event.issue.title", found[0])

    def test_field_reached_through_env_in_the_step_the_job_or_the_workflow(self):
        step = "        env:\n          TITLE: ${{ github.event.issue.title }}\n"
        found = self._gha010(_script("echo \"${{ env.TITLE }}\"", env=step))
        self.assertEqual(len(found), 1)
        self.assertIn("env.title, which holds github.event.issue.title", found[0])
        job = (HEAD.format(trigger="issues") + "jobs:\n  work:\n    runs-on: ubuntu-latest\n    env:\n"
               "      TITLE: ${{ github.event.issue.title }}\n    steps:\n      - run: echo \"${{ env.title }}\"\n")
        self.assertEqual(len(self._gha010(job)), 1)
        workflow = ("on: issues\npermissions:\n  contents: read\nenv:\n  TITLE: ${{ github.event.issue.title }}\n"
                    "jobs:\n  work:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ env['TITLE'] }}\"\n")
        self.assertEqual(len(self._gha010(workflow)), 1)
        every = _script("echo \"${{ join(env.*, ' ') }}\"", env=step)
        self.assertEqual(len(self._gha010(every)), 1)

    def test_the_documented_fix_is_not_reported(self):
        step = "        env:\n          TITLE: ${{ github.event.issue.title }}\n"
        self.assertEqual(self._gha010(_script("echo \"$TITLE\"", env=step)), [])

    def test_env_values_that_hold_nothing_untrusted_are_not_reported(self):
        step = "        env:\n          SHA: ${{ github.sha }}\n"
        self.assertEqual(self._gha010(_script("echo \"${{ env.SHA }}\"", env=step)), [])

    def test_fields_outsiders_do_not_write_are_not_reported(self):
        for safe in ("${{ github.event.pull_request.number }}",
                     "${{ join(github.event.pull_request.labels.*.name, ',') }}",
                     "${{ github.event.pull_request.head.sha }}",
                     "${{ github.event.commits.*.id }}",
                     "${{ matrix.*.title }}",
                     "${{ needs.*.result }}",
                     "${{ github.event.inputs.title }}"):
            self.assertEqual(self._gha010(_script(f"echo \"{safe}\"")), [], safe)


class UnreadableTextTest(unittest.TestCase):
    def test_text_the_reader_refuses_is_an_error_and_fails_the_check(self):
        with TempDir() as tmp:
            result = _check(tmp, _script("echo \"" + "${{'}}'" * 50000 + "\""))
            self.assertEqual(len(result.errors), 1, result.errors)
            self.assertIn("cannot tell", result.errors[0])
            code, _, _ = run_cli("check", tmp, "--fail-on", "never")
            self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
