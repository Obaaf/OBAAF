"""The checker reads `${{ }}` expressions from their tokens and fails closed.

Each test class below starts from a spelling that got past a rule when expressions were matched as
text: the rule saw nothing, and the workflow would still have used the secret or expanded the
outsider's text. The fix is the reader in obaaf.checker.expr, so the tests cover the reader and
then each rule that depends on it.

None of these workflows has been run on GitHub. Where the platform's behaviour was known to be in
doubt, the reader takes the wider reading. An independent review of the first version of this
change found more spellings (groups, function results, a second hop through env, the matrix) and
inputs that crashed or stalled the reader; those are the later classes in this file.
"""

import random
import time
import unittest

from helpers import TempDir, run_cli

from obaaf import checker
from obaaf.checker import expr
from obaaf.checker import workflow as wf_mod
from obaaf.checker.rules import WorkflowRules

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


class GroupsAndFunctionResultsTest(unittest.TestCase):
    """A property or index applied to a group or to a function's result reads the same field."""

    REPORTED = [
        "(github.event.issue).title",
        "(github).event.issue.title",
        "(github.event.issue)['title']",
        "((github.event).issue).title",
        "(github).head_ref",
        "(github.event.issue || github.event.pull_request).title",
        "toJSON(github.event.issue || 1)",
        "toJSON((github.event))",
        "fromJSON(toJSON(github.event.issue || 1)).title",
        "case(true, github.event.issue, 1).title",
        "format('{0}', github.event.issue)",
        "github.*",
        "join(github.event.*)",
        "toJSON(github.event.commits.*)",
        "github.event.commits[0].message",
        "github.event.commits['0'].message",
        "github.event.pull_request.*.ref",
    ]
    NOT_REPORTED = [
        "(github.event.issue || github.event.pull_request).number",
        "github.event.*.number",
        "github.event[github.event_name].number",
        "github.event.pull_request.*.sha",
        "github.event.commits.*.id",
        "github.event.issue && 'yes' || 'no'",
        "join(github.event.pull_request.labels.*.name, ',')",
        "format('{0}', github.event.pull_request.number)",
        "hashFiles('**/package-lock.json')",
    ]

    def test_reported(self):
        for text in self.REPORTED:
            self.assertTrue(WorkflowRules._untrusted_text(text), text)

    def test_near_misses_are_not_reported(self):
        for text in self.NOT_REPORTED:
            self.assertIsNone(WorkflowRules._untrusted_text(text), text)

    def test_through_the_checker(self):
        for text in ("(github.event.issue).title", "(github.event.issue || github.event.pull_request).title",
                     "toJSON(github.event.issue || 1)"):
            findings, errors = _rules(_script("echo '${{ " + text + " }}'"))
            self.assertEqual(errors, [])
            self.assertEqual([r for r, _, _ in findings].count("OBAAF-GHA-010"), 1, text)

    def test_secrets_through_groups_and_function_results(self):
        self.assertEqual(expr.secret_refs("(secrets).KEY"), {"KEY"})
        self.assertEqual(expr.secret_refs("(secrets || 1)['KEY']"), {"KEY"})
        for text in ("toJSON((secrets))", "case(true, secrets, 1).KEY", "(secrets).*", "(secrets)[matrix.k]",
                     "secrets['*']", "secrets['*inherit']", "secrets['not a name']"):
            self.assertEqual(expr.secret_refs(text), {expr.ALL}, text)
        for text in ("!secrets.KEY", "secrets.KEY&&1", "1||secrets.KEY", "''==secrets.KEY", "0<secrets.KEY"):
            self.assertEqual(expr.secret_refs(text), {"KEY"}, text)

    def test_expression_in_a_mapping_key_is_read(self):
        workflow = (HEAD.format(trigger="issue_comment") + "jobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    steps:\n      - run: echo hi\n        env:\n          ${{ secrets.DEPLOY_KEY }}: x\n")
        findings, _ = _rules(workflow)
        self.assertTrue(any(r == "OBAAF-GHA-001" and "DEPLOY_KEY" in m for r, _, m in findings), findings)


class IndirectionTest(unittest.TestCase):
    """Outsider-written text that reaches a script through env (in two hops) or the matrix."""

    def _gha010(self, workflow):
        findings, errors = _rules(workflow)
        self.assertEqual(errors, [])
        return [m for rule, _, m in findings if rule == "OBAAF-GHA-010"]

    def _chain(self, where, value="${{ env.A }}"):
        top = "env:\n  A: ${{ github.event.issue.title }}\n" if where == "workflow" else ""
        job = "    env:\n      A: ${{ github.event.issue.title }}\n" if where == "job" else ""
        return ("on: issues\npermissions:\n  contents: read\n" + top + "jobs:\n  work:\n    runs-on: ubuntu-latest\n"
                + job + "    steps:\n      - run: echo \"${{ env.B }}\"\n        env:\n          B: " + value + "\n")

    def test_step_env_that_reads_job_or_workflow_env(self):
        for where in ("job", "workflow"):
            found = self._gha010(self._chain(where))
            self.assertEqual(len(found), 1, where)
            self.assertIn("github.event.issue.title", found[0])
        self.assertEqual(len(self._gha010(self._chain("job", "${{ format('{0}', env.A) }}"))), 1)
        self.assertEqual(len(self._gha010(self._chain("job", "${{ toJSON(env) }}"))), 1)

    def test_env_value_written_with_a_group(self):
        step = "        env:\n          TITLE: ${{ (github.event.issue).title }}\n"
        self.assertEqual(len(self._gha010(_script("echo \"${{ env.TITLE }}\"", env=step))), 1)

    def test_step_value_that_replaces_the_job_value_is_not_reported(self):
        workflow = ("on: issues\npermissions:\n  contents: read\njobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    env:\n      TITLE: ${{ github.event.issue.title }}\n    steps:\n"
                    "      - run: echo \"${{ env.TITLE }}\"\n        env:\n          TITLE: fixed\n")
        self.assertEqual(self._gha010(workflow), [])

    def test_matrix_value_set_from_event_text(self):
        workflow = ("on: issues\npermissions:\n  contents: read\njobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    strategy:\n      matrix:\n        t: [\"${{ github.event.issue.title }}\"]\n"
                    "    steps:\n      - run: echo \"${{ matrix.t }}\"\n")
        found = self._gha010(workflow)
        self.assertEqual(len(found), 1)
        self.assertIn("matrix", found[0])

    def test_ordinary_matrix_is_not_reported(self):
        workflow = ("on: issues\npermissions:\n  contents: read\njobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n"
                    "    steps:\n      - run: echo \"${{ matrix.os }}\"\n")
        self.assertEqual(self._gha010(workflow), [])


class HardInputTest(unittest.TestCase):
    """Crafted files must end in an error or a result within seconds, never a crash or a stall.
    Before the review fixes the first crashed the whole run and the others took 8 to 115 seconds."""

    def _timed(self, workflow, limit=10.0):
        started = time.monotonic()
        with TempDir() as tmp:
            result = _check(tmp, workflow)
        self.assertLess(time.monotonic() - started, limit)
        return result

    def test_deep_nesting_is_an_error_for_that_file_only(self):
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "ok.yml").write_text(_job("${{ secrets.DEPLOY_KEY }}"), encoding="utf-8")
            result = _check(tmp, _job("${{ " + "a[" * 1100 + "0" + "]" * 1100 + " }}"))
            self.assertEqual(len(result.errors), 1, result.errors)
            self.assertIn("nested too deeply", result.errors[0])
            self.assertTrue(any(f.rule == "OBAAF-GHA-001" and f.path.endswith("ok.yml") for f in result.findings))
        for text in ("a[" * 5000, "(" * 5000, "f(" * 5000, "a[" * 60 + "(" * 60):
            with self.assertRaises(expr.TooComplex):
                expr.refs(text)

    def test_nesting_within_the_limit_is_read(self):
        text = "(" * 40 + "secrets.KEY" + ")" * 40
        self.assertEqual(expr.secret_refs(text), {"KEY"})

    def test_long_expression_in_workflow_env_with_several_jobs(self):
        jobs = "".join(f"  j{n}:\n    runs-on: ubuntu-latest\n    steps:\n{STEP}" for n in range(6))
        workflow = ("on: push\npermissions:\n  contents: read\nenv:\n  V: ${{ " + "a[" * 50 + "1," * 20000
                    + " }}\njobs:\n" + jobs)
        self._timed(workflow)

    def test_many_env_entries_and_many_expressions(self):
        env = "".join(f"  V{n}: v\n" for n in range(2000))
        script = " ".join("${{ env[0] }}" for _ in range(2000))
        workflow = ("on: issues\npermissions:\n  contents: read\nenv:\n" + env + "jobs:\n  work:\n"
                    "    runs-on: ubuntu-latest\n    steps:\n      - run: echo " + script + "\n")
        self._timed(workflow)

    def test_nested_aliases_are_read_once(self):
        levels = "      a0: &a0 [\"${{ secrets.DEPLOY_KEY }}\"]\n" + "".join(
            f"      a{n}: &a{n} [{', '.join([f'*a{n - 1}'] * 10)}]\n" for n in range(1, 9))
        workflow = (HEAD.format(trigger="issue_comment") + "jobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    strategy:\n      matrix:\n" + levels + "    steps:\n" + STEP)
        result = self._timed(workflow)
        self.assertTrue(any(f.rule == "OBAAF-GHA-001" for f in result.findings))

    def test_long_run_of_spaces_in_an_expression(self):
        self._timed(_script("echo \"${{ github.sha" + " " * 60000 + "}}\""))


class UnreadableYamlTest(unittest.TestCase):
    """Values the checker would have skipped without a word are errors instead."""

    def _errors(self, workflow):
        return _rules(workflow)[1]

    def test_steps_given_as_tagged_pairs(self):
        workflow = (HEAD.format(trigger="issues") + "jobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    steps: !!pairs\n      - run: echo \"${{ github.event.issue.title }}\"\n")
        self.assertTrue(any("does not read" in e for e in self._errors(workflow)))

    def test_env_given_as_a_tagged_set(self):
        workflow = (HEAD.format(trigger="issues") + "jobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    env: !!set\n      ? ${{ secrets.DEPLOY_KEY }}\n    steps:\n" + STEP)
        self.assertTrue(any("does not read" in e for e in self._errors(workflow)))

    def test_binary_value(self):
        self.assertTrue(any("does not read" in e for e in self._errors(_job("!!binary JHt7IHNlY3JldHMuWCB9fQ=="))))

    def test_step_that_is_not_a_mapping(self):
        workflow = (HEAD.format(trigger="issues") + "jobs:\n  work:\n    runs-on: ubuntu-latest\n"
                    "    steps:\n      - echo hi\n")
        self.assertTrue(any("not a mapping" in e for e in self._errors(workflow)))

    def test_line_breaks_yaml_readers_disagree_about(self):
        for char in ("\u0085", "\u2028", "\u2029"):
            errors = self._errors(_job("x" + char + "# ${{ secrets.DEPLOY_KEY }}"))
            self.assertTrue(any("line break" in e for e in errors), repr(char))

    def test_dates_and_numbers_are_still_ordinary_values(self):
        workflow = (HEAD.format(trigger="push") + "env:\n  RELEASED: 2026-11-11\n  COUNT: 3\n  RATIO: 0.5\n"
                    "  EMPTY:\n  ON: true\njobs:\n  work:\n    runs-on: ubuntu-latest\n    steps:\n" + STEP)
        self.assertEqual(self._errors(workflow), [])


if __name__ == "__main__":
    unittest.main()
