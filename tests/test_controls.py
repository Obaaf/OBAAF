"""Controls that clear a finding (flagship slice 2a.2).

OBAAF-GHA-005 (a secret in an agent job) and OBAAF-GHA-020 (no egress restriction) name the controls
that would clear them, and say of each whether the checker verified it, found it missing, or could
not tell. A control is verified only from something the checker read. Which events can start a job
is read from the tokens of its `if:`, never by searching its text.
"""

import itertools
import json
import unittest

from helpers import RISKY, TEMPLATES, TempDir, run_cli

from obaaf import checker
from obaaf.checker import report
from obaaf.checker import workflow as wf_mod
from obaaf.checker.rules import CANNOT_TELL, NOT_MET, VERIFIED

SHA = "a" * 40
CONFIG = {"lanes": {".github/workflows/agent.yml#agent": "agent"},
          "protected_secrets": {"*_API_KEY": "main-only", "HELDOUT_TOKEN": "main-only"}}


def agent_workflow(on="workflow_dispatch", cond=None, environment="main-only", secrets=("MODEL_API_KEY",),
                   steps=None, job_extra="", top=""):
    lines = [f"on: {on}", "permissions: {}", top, "jobs:", "  agent:", "    runs-on: ubuntu-24.04",
             "    permissions: {contents: read}"]
    if cond is not None:
        lines.append(f"    if: {json.dumps(cond)}")      # a JSON string is a YAML double-quoted scalar
    if environment:
        lines.append(f"    environment: {environment}")
    if job_extra:
        lines.append(job_extra)
    lines.append("    steps:")
    lines.append(steps if steps is not None else f"      - uses: actions/checkout@{SHA}\n        with: {{persist-credentials: false}}")
    env = ", ".join(f"{name}: '${{{{ secrets.{name} }}}}'" for name in secrets)
    lines.append(f"      - run: python -m agents.fix\n        env: {{{env}}}")
    return "\n".join(line for line in lines if line) + "\n"


def check(text, config=CONFIG):
    with TempDir() as tmp:
        target = tmp / ".github" / "workflows"
        target.mkdir(parents=True)
        (target / "agent.yml").write_text(text, encoding="utf-8")
        (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
        return checker.check(tmp, config=checker.Config.from_data(config, "obaaf.yml"))


def one(result, rule):
    found = [f for f in result.findings if f.rule == rule]
    assert len(found) == 1, [(f.rule, f.kind, f.message) for f in result.findings]
    return found[0]


def verdicts(finding):
    return {c.id: c.verdict for c in finding.controls}


def control(finding, ident):
    return next(c for c in finding.controls if c.id == ident)


class SecretInAgentJobTest(unittest.TestCase):
    """OBAAF-GHA-005 carries four controls, and all four are needed to clear it."""

    def test_the_first_adopters_shape_is_two_verified_one_setting_and_no_egress(self):
        f = one(check(agent_workflow()), "OBAAF-GHA-005")
        self.assertEqual(verdicts(f), {"secrets-protected": VERIFIED, "environment-restricted": CANNOT_TELL,
                                       "no-outsider-input": VERIFIED, "egress-enforced": NOT_MET})
        self.assertEqual(f.state, "new")       # one control is known to be missing
        self.assertIn("MODEL_API_KEY in environment 'main-only'", control(f, "secrets-protected").detail)
        self.assertIn("started only by workflow_dispatch", control(f, "no-outsider-input").detail)

    def test_no_workflow_can_clear_it_yet(self):
        """The environment's settings are not read by `obaaf check`, and no egress control is
        recognised as verified, so whatever the workflow says the finding is never `fixed`."""
        monitor = (f"      - uses: step-security/harden-runner@{SHA}\n"
                   "        with: {egress-policy: block, disable-sudo: true, allowed-endpoints: 'api.example.com:443'}\n"
                   f"      - uses: actions/checkout@{SHA}")
        for on, steps, env in itertools.product(("workflow_dispatch", "schedule", "[push]"), (None, monitor),
                                                ("main-only", "production")):
            f = one(check(agent_workflow(on=on, steps=steps, environment=env)), "OBAAF-GHA-005")
            with self.subTest(on=on, monitor=steps is not None, environment=env):
                self.assertNotEqual(f.state, "fixed")
                self.assertNotEqual(control(f, "environment-restricted").verdict, VERIFIED)
                self.assertNotEqual(control(f, "egress-enforced").verdict, VERIFIED)

    def test_with_a_monitor_and_everything_else_in_place_it_is_cannot_tell(self):
        steps = (f"      - uses: step-security/harden-runner@{SHA}\n        with: {{egress-policy: block}}\n"
                 f"      - uses: actions/checkout@{SHA}")
        result = check(agent_workflow(steps=steps))
        f = one(result, "OBAAF-GHA-005")
        self.assertEqual(f.state, "cannot-tell")
        self.assertIn(f, result.gating("high", checker.load()))    # it still fails a gate
        text = report.to_text(result)
        self.assertIn("Cannot tell: no control that would clear this finding is known to be missing", text)
        self.assertIn("(it is cleared when all 4 are verified):", text)
        self.assertIn("          cannot tell  the secrets are stored only in that environment", text)

    def test_a_secret_that_is_not_protected_is_not_met(self):
        f = one(check(agent_workflow(secrets=("MODEL_API_KEY", "DEPLOY_TOKEN"))), "OBAAF-GHA-005")
        made = control(f, "secrets-protected")
        self.assertEqual((made.verdict, made.detail), (NOT_MET, "not listed in protected_secrets: DEPLOY_TOKEN"))

    def test_no_protected_secrets_at_all_is_not_met(self):
        f = one(check(agent_workflow(), config={"lanes": CONFIG["lanes"]}), "OBAAF-GHA-005")
        self.assertEqual(control(f, "secrets-protected").verdict, NOT_MET)

    def test_every_secret_is_not_met(self):
        for spelling in ("${{ toJSON(secrets) }}", "${{ secrets[inputs.name] }}", "${{ secrets.* }}"):
            steps = f"      - run: python -m agents.fix\n        env: {{ALL: '{spelling}'}}"
            f = one(check(agent_workflow(steps=steps)), "OBAAF-GHA-005")
            with self.subTest(spelling=spelling):
                self.assertEqual(control(f, "secrets-protected").verdict, NOT_MET)
                self.assertIn("every secret", control(f, "secrets-protected").detail)

    def test_no_environment_or_another_one_is_not_met(self):
        f = one(check(agent_workflow(environment=None)), "OBAAF-GHA-005")
        self.assertEqual((control(f, "secrets-protected").verdict, control(f, "secrets-protected").detail),
                         (NOT_MET, "the job declares no environment"))
        f = one(check(agent_workflow(environment="staging")), "OBAAF-GHA-005")
        self.assertEqual(control(f, "secrets-protected").verdict, NOT_MET)
        self.assertIn("'main-only'", control(f, "secrets-protected").detail)

    def test_an_environment_named_by_an_expression_is_cannot_tell(self):
        f = one(check(agent_workflow(environment="${{ inputs.environment }}")), "OBAAF-GHA-005")
        self.assertEqual(control(f, "secrets-protected").verdict, CANNOT_TELL)

    def test_the_first_control_agrees_with_gha_024(self):
        """It is verified exactly when every secret is listed and OBAAF-GHA-024 has nothing to say."""
        cases = itertools.product((("MODEL_API_KEY",), ("MODEL_API_KEY", "HELDOUT_TOKEN"), ("OTHER",), ("OTHER", "X_API_KEY")),
                                  (None, "main-only", "Main-Only", "staging", "${{ inputs.e }}"))
        for secrets, environment in cases:
            result = check(agent_workflow(secrets=secrets, environment=environment))
            verdict = control(one(result, "OBAAF-GHA-005"), "secrets-protected").verdict
            listed = all(name.endswith("_API_KEY") or name == "HELDOUT_TOKEN" for name in secrets)
            reported = any(f.rule == "OBAAF-GHA-024" for f in result.findings)
            with self.subTest(secrets=secrets, environment=environment):
                self.assertEqual(verdict == VERIFIED, listed and not reported)

    def test_an_entry_that_names_no_environment_takes_the_jobs_own(self):
        config = {"lanes": CONFIG["lanes"], "protected_secrets": ["MODEL_API_KEY"]}
        f = one(check(agent_workflow(environment="anything"), config=config), "OBAAF-GHA-005")
        self.assertEqual(control(f, "secrets-protected").verdict, VERIFIED)
        self.assertIn("environment 'anything'", control(f, "environment-restricted").detail)

    def test_a_job_with_an_environment_and_no_secret_has_no_controls(self):
        steps = "      - run: python -m agents.fix"
        text = agent_workflow(steps=steps).replace("      - run: python -m agents.fix\n        env: "
                                                   "{MODEL_API_KEY: '${{ secrets.MODEL_API_KEY }}'}\n", "")
        f = one(check(text), "OBAAF-GHA-005")
        self.assertEqual((f.kind, f.controls, f.state), ("environment", [], "new"))


class OutsiderInputTest(unittest.TestCase):
    """The third control: what a pull request, an issue or a comment controls."""

    def verdict(self, **changes):
        return control(one(check(agent_workflow(**changes)), "OBAAF-GHA-005"), "no-outsider-input")

    def test_events_only_someone_with_write_access_causes_are_verified(self):
        for on in ("workflow_dispatch", "schedule", "push", "release", "[push, workflow_dispatch]",
                   "{schedule: [{cron: '0 4 * * *'}]}"):
            with self.subTest(on=on):
                self.assertEqual(self.verdict(on=on).verdict, VERIFIED)

    def test_an_outsiders_event_is_not_met(self):
        for on in ("pull_request", "pull_request_target", "issues", "issue_comment", "workflow_run",
                   "[workflow_dispatch, pull_request]", "discussion_comment"):
            made = self.verdict(on=on)
            with self.subTest(on=on):
                self.assertEqual(made.verdict, NOT_MET)
                self.assertIn("it can be started by", made.detail)

    def test_an_event_the_checker_knows_nothing_about_is_cannot_tell(self):
        for on in ("workflow_call", "repository_dispatch", "merge_group", "deployment", "label", "'${{ inputs.on }}'"):
            with self.subTest(on=on):
                self.assertEqual(self.verdict(on=on).verdict, CANNOT_TELL)

    def test_a_run_that_follows_a_trusted_run_is_cannot_tell(self):
        made = self.verdict(on="workflow_run", cond="github.event.workflow_run.event == 'push'")
        self.assertEqual(made.verdict, CANNOT_TELL)

    def test_an_event_test_in_the_jobs_if_narrows_it(self):
        both = "[pull_request, workflow_dispatch]"
        for cond in ("${{ github.event_name == 'workflow_dispatch' }}",
                     "github.event_name == 'workflow_dispatch' && inputs.mode != 'rehearsal'",
                     "${{ !cancelled() && github.event_name == 'workflow_dispatch' && needs.plan.result == 'success' }}",
                     "${{ github.event_name != 'pull_request' }}"):
            with self.subTest(cond=cond):
                self.assertEqual(self.verdict(on=both, cond=cond).verdict, VERIFIED)

    def test_text_that_only_looks_like_an_event_test_does_not(self):
        """Each of these runs on a pull request. Before this slice the first four were read as
        `workflow_dispatch` only, by every rule that asks what can start a job."""
        both = "[pull_request, workflow_dispatch]"
        for cond in ("""${{ 'github.event_name == "workflow_dispatch"' != '' }}""",
                     "${{ github.event_name == 'workflow_dispatch' == false }}",
                     "${{ github.event_name == 'workflow_dispatch' }} && ${{ true }}",
                     """format('{0}', 'github.event_name == "workflow_dispatch"')""",
                     "${{ github.event_name == 'workflow_dispatch' || true }}",
                     "${{ !(github.event_name == 'pull_request') || true }}",
                     "${{ contains(github.event_name, 'workflow_dispatch') }}"):
            with self.subTest(cond=cond):
                self.assertEqual(self.verdict(on=both, cond=cond).verdict, NOT_MET)

    def test_a_block_scalar_that_adds_a_line_break_is_a_string_to_github(self):
        text = agent_workflow(on="[pull_request, workflow_dispatch]").replace(
            "    environment:", "    if: |\n      ${{ github.event_name == 'workflow_dispatch' }}\n    environment:")
        f = one(check(text), "OBAAF-GHA-005")
        self.assertEqual(control(f, "no-outsider-input").verdict, NOT_MET)

    def test_a_pull_requests_code_is_not_met_whatever_starts_the_job(self):
        for steps in (f"      - uses: actions/checkout@{SHA}\n        with: {{ref: 'refs/pull/7/head'}}",
                      f"      - uses: actions/checkout@{SHA}\n        with: {{ref: '${{{{ github.event.pull_request.head.sha }}}}'}}",
                      "      - run: gh pr checkout 7",
                      "      - run: git fetch origin pull/7/head"):
            with self.subTest(steps=steps):
                self.assertEqual(self.verdict(steps=steps).verdict, NOT_MET)

    def test_a_checkout_the_checker_cannot_place_is_cannot_tell(self):
        for inputs in ("{ref: '${{ inputs.ref }}'}", "{repository: example/other}", "'${{ fromJSON(inputs.with) }}'"):
            steps = f"      - uses: actions/checkout@{SHA}\n        with: {inputs}"
            with self.subTest(inputs=inputs):
                self.assertEqual(self.verdict(steps=steps).verdict, CANNOT_TELL)

    def test_a_fixed_ref_is_verified(self):
        steps = f"      - uses: actions/checkout@{SHA}\n        with: {{ref: {'c' * 40}}}"
        self.assertEqual(self.verdict(steps=steps).verdict, VERIFIED)

    def test_text_an_outsider_writes_is_not_met(self):
        made = self.verdict(on="push", job_extra="    env: {MESSAGE: '${{ github.event.head_commit.message }}'}")
        self.assertEqual(made.verdict, NOT_MET)
        self.assertIn("github.event.head_commit.message", made.detail)
        made = self.verdict(on="push", top="env: {EVENT: '${{ toJSON(github.event) }}'}")
        self.assertEqual(made.verdict, NOT_MET)

    def test_a_job_that_calls_a_reusable_workflow_is_cannot_tell(self):
        text = ("on: workflow_dispatch\npermissions: {}\njobs:\n  agent:\n    permissions: {contents: read}\n"
                f"    uses: example/workflows/.github/workflows/agent.yml@{SHA}\n"
                "    secrets: {MODEL_API_KEY: '${{ secrets.MODEL_API_KEY }}'}\n")
        f = one(check(text), "OBAAF-GHA-005")
        self.assertEqual(control(f, "no-outsider-input").verdict, CANNOT_TELL)
        self.assertEqual(control(f, "secrets-protected").verdict, NOT_MET)   # a caller cannot declare an environment


class EgressTest(unittest.TestCase):
    """OBAAF-GHA-020 is reported for every agent job, with the one control that clears it."""

    def egress(self, steps=None, job_extra=""):
        return one(check(agent_workflow(steps=steps, job_extra=job_extra)), "OBAAF-GHA-020")

    def test_nothing_or_a_declaration_is_not_met(self):
        f = self.egress()
        self.assertEqual((f.kind, f.state, verdicts(f)), ("none", "new", {"egress-enforced": NOT_MET}))
        f = self.egress(job_extra="    env: {OBAAF_EGRESS: model endpoint only}")
        self.assertEqual((f.kind, f.state, verdicts(f)), ("declared", "new", {"egress-enforced": NOT_MET}))

    def test_a_monitor_behind_a_condition_is_not_met(self):
        steps = (f"      - uses: step-security/harden-runner@{SHA}\n        if: vars.MONITOR == 'on'\n"
                 "        with: {egress-policy: block}")
        f = self.egress(steps=steps)
        self.assertEqual((f.kind, f.state, verdicts(f)), ("conditional", "new", {"egress-enforced": NOT_MET}))

    def test_a_monitor_that_always_runs_is_cannot_tell_wherever_it_is(self):
        monitor = f"      - uses: step-security/harden-runner@{SHA}\n        with: {{egress-policy: block}}"
        agent = f"      - uses: actions/checkout@{SHA}"
        for steps in (monitor + "\n" + agent, agent + "\n" + monitor):
            f = self.egress(steps=steps)
            with self.subTest(first=steps.startswith(monitor)):
                self.assertEqual((f.kind, f.state, verdicts(f)),
                                 ("unverified-monitor", "cannot-tell", {"egress-enforced": CANNOT_TELL}))
                self.assertIn("step-security/harden-runner", f.message)

    def test_audit_mode_is_not_a_blocking_monitor(self):
        steps = f"      - uses: step-security/harden-runner@{SHA}\n        with: {{egress-policy: audit}}"
        self.assertEqual(self.egress(steps=steps).kind, "none")

    def test_messages_and_identity_of_the_three_old_cases_are_unchanged(self):
        """A baseline entry written before this slice still names the same finding."""
        f = self.egress()
        self.assertEqual(f.message, "Agent job 'agent' shows no egress restriction (no OBAAF_EGRESS declaration "
                                    "and no blocking egress monitor).")
        self.assertEqual(f.facts, {})
        f = self.egress(job_extra="    env: {OBAAF_EGRESS: model endpoint only}")
        self.assertEqual(f.facts, {"declared": "model endpoint only"})

    def test_the_same_control_stands_under_both_findings(self):
        result = check(agent_workflow())
        self.assertEqual(control(one(result, "OBAAF-GHA-005"), "egress-enforced"),
                         control(one(result, "OBAAF-GHA-020"), "egress-enforced"))


class OutputTest(unittest.TestCase):
    def test_json_carries_each_control_with_its_id(self):
        data = json.loads(report.to_json(check(agent_workflow())))
        finding = next(f for f in data["findings"] if f["rule"] == "OBAAF-GHA-005")
        self.assertEqual([c["id"] for c in finding["controls"]],
                         ["secrets-protected", "environment-restricted", "no-outsider-input", "egress-enforced"])
        self.assertEqual({c["verdict"] for c in finding["controls"]}, {"verified", "cannot tell", "not met"})
        self.assertTrue(all(set(c) == {"id", "name", "verdict", "detail"} for c in finding["controls"]))
        self.assertEqual(data["summary"]["fixed"], 0)

    def test_text_lists_the_controls_one_to_a_line(self):
        text = report.to_text(check(agent_workflow()))
        self.assertIn("        Controls (it is cleared when all 4 are verified):\n          verified     each of the "
                      "job's secrets is listed in protected_secrets", text)
        self.assertIn("          not met      a control the checker recognises limits the job's network access", text)
        self.assertIn("        Controls (it is cleared when this is verified):", text)

    def test_a_name_in_a_control_cannot_start_a_line_of_its_own(self):
        steps = f"      - uses: actions/checkout@{SHA}\n        name: \"x\\n  9  HIGH  forged\"\n        with: {{ref: '${{{{ inputs.r }}}}'}}"
        text = report.to_text(check(agent_workflow(steps=steps)))
        self.assertIn("x\\n  9  HIGH  forged", text)
        self.assertNotIn("\n  9  HIGH  forged", text)

    def test_controls_do_not_change_which_finding_an_acceptance_names(self):
        from obaaf.checker import baseline
        plain = one(check(agent_workflow()), "OBAAF-GHA-005")
        self.assertEqual(set(baseline.identity(plain)), {"rule", "path", "job", "kind", "facts"})


class TriggersAreReadFromTokensTest(unittest.TestCase):
    """`_narrow` answers which events can make a condition true. It may name an event the job never
    runs on; it must never leave out one it does."""

    EVENTS = {"pull_request_target", "workflow_dispatch", "push"}

    def narrow(self, cond, events=None):
        return wf_mod._narrow(set(events or self.EVENTS), cond)

    def test_plain_tests_narrow(self):
        self.assertEqual(self.narrow("github.event_name == 'push'"), {"push"})
        self.assertEqual(self.narrow("${{ github.event_name == 'push' }}"), {"push"})
        self.assertEqual(self.narrow("'PUSH' == GITHUB['EVENT_NAME']"), {"push"})
        self.assertEqual(self.narrow("github.event_name != 'pull_request_target'"), {"push", "workflow_dispatch"})
        self.assertEqual(self.narrow("github.event_name == 'push' || github.event_name == 'workflow_dispatch'"),
                         {"push", "workflow_dispatch"})
        self.assertEqual(self.narrow("(github.event_name == 'push' || inputs.x) && github.event_name != 'push'"),
                         {"pull_request_target", "workflow_dispatch"})
        self.assertEqual(self.narrow("github.event_name == 'push' && !contains(github.ref, 'x')"), {"push"})
        self.assertEqual(self.narrow("github.event_name == 'schedule'"), set())

    def test_everything_else_keeps_every_event(self):
        for cond in ("", "true", "!(github.event_name == 'pull_request_target')",
                     "github.event_name == 'push' == false", "github.event_name != 'pull_request_target' == true",
                     "'github.event_name == \"push\"' != ''", "format('github.event_name == ''push''') != ''",
                     "contains(github.event_name, 'push')", "github.event_name == 'push' || always()",
                     "${{ github.event_name == 'push' }} ", " ${{ github.event_name == 'push' }}",
                     "${{ github.event_name == 'push' }}\n", "${{ github.event_name == 'push' }} && ${{ true }}",
                     "x ${{ github.event_name == 'push' }}", "github.event_name == 'puſh'",
                     "github.event_name == format('push')", "github.event_name == 'push' && (", "((((", "github.event_name == 'push') && (true", "github.event_name == 'push' && x[(])",
                     "github.event_name < 'push'", "github.event_name == 1", "steps.github.event_name == 'push' || x.y"):
            with self.subTest(cond=cond):
                self.assertEqual(self.narrow(cond), self.EVENTS)

    def test_a_run_after_a_trusted_run(self):
        events = {"workflow_run", "pull_request_target"}
        trusted = wf_mod.TRUSTED_WORKFLOW_RUN
        self.assertEqual(self.narrow("github.event.workflow_run.event == 'push'", events), {trusted, "pull_request_target"})
        self.assertEqual(self.narrow("github.event.workflow_run.event == 'pull_request'", events), events)
        self.assertEqual(self.narrow("github.event.workflow_run.event == 'push' || "
                                     "github.event.workflow_run.event == 'pull_request'", events), events)
        self.assertEqual(self.narrow("github.event_name == 'workflow_run' && github.event.workflow_run.event == 'push'",
                                     events), {trusted})
        self.assertEqual(self.narrow("'github.event.workflow_run.event == \"push\"' != ''", events), events)

    def test_it_never_leaves_out_an_event_the_condition_is_true_for(self):
        """Every condition below is built from parts whose truth on each event is known, so the
        events it is really true for can be worked out and compared."""
        parts = [("github.event_name == 'push'", {"push"}), ("github.event_name != 'push'", self.EVENTS - {"push"}),
                 ("'workflow_dispatch' == github.event_name", {"workflow_dispatch"}), ("true", self.EVENTS),
                 ("false", set()), ("!(github.event_name == 'push')", self.EVENTS - {"push"}),
                 ("(github.event_name == 'push') == false", self.EVENTS - {"push"}),
                 ("'github.event_name == \"push\"' != ''", self.EVENTS),
                 ("contains(github.event_name, 'pull')", {"pull_request_target"})]
        checked = 0
        for (a, ta), (b, tb), (c, tc) in itertools.product(parts, repeat=3):
            for text, truth in ((f"{a} && {b} || {c}", (ta & tb) | tc), (f"{a} || {b} && {c}", ta | (tb & tc)),
                                (f"({a} || {b}) && {c}", (ta | tb) & tc), (f"{a} && ({b} || {c})", ta & (tb | tc))):
                for cond in (text, "${{ " + text + " }}"):
                    checked += 1
                    self.assertTrue(truth <= self.narrow(cond), cond)
        self.assertEqual(checked, 9 ** 3 * 8)

    def test_a_job_behind_a_gate_it_can_outrun_is_not_narrowed_by_the_gate(self):
        """`agent` needs `gate`, which runs only when dispatched. Any status function other than a
        plain `success() &&` lets `agent` run when `gate` was skipped, so on a pull request too."""
        for cond, narrowed in (("github.ref == 'refs/heads/main'", True), ("success() && inputs.x", True),
                               ("success() == false", False), ("!(success())", False), ("success() != true", False),
                               ("format('{0}', success()) == 'false'", False), ("always()", False),
                               ("!cancelled()", False), ("success() || true", False)):
            text = ("on: [pull_request_target, workflow_dispatch]\njobs:\n  gate:\n    runs-on: ubuntu-24.04\n"
                    "    if: github.event_name == 'workflow_dispatch'\n    steps: [{run: 'true'}]\n"
                    f"  agent:\n    needs: gate\n    runs-on: ubuntu-24.04\n    if: {json.dumps(cond)}\n    steps: [{{run: 'true'}}]\n")
            workflow = wf_mod.parse("w.yml", text)
            with self.subTest(cond=cond):
                self.assertIsNone(workflow.error)
                self.assertEqual(workflow.jobs["agent"].triggers() == {"workflow_dispatch"}, narrowed)

    def test_a_word_in_a_string_is_not_a_status_function(self):
        self.assertFalse(wf_mod.runs_after_failure("contains(github.ref, 'always()')"))
        self.assertTrue(wf_mod.runs_after_failure("${{ success() }} "))
        self.assertFalse(wf_mod.runs_after_failure("(success() && inputs.x)"))

    def test_other_rules_see_the_events_too(self):
        """OBAAF-GHA-001: the secret reaches a job a pull request can start."""
        text = ("on: [pull_request_target, workflow_dispatch]\npermissions: {}\njobs:\n  build:\n"
                "    runs-on: ubuntu-24.04\n    if: \"${{ github.event_name == 'workflow_dispatch' == false }}\"\n"
                "    steps:\n      - run: make\n        env: {TOKEN: '${{ secrets.DEPLOY }}'}\n")
        found = [f for f in check(text, config={}).findings if f.rule == "OBAAF-GHA-001"]
        self.assertEqual([(f.severity, f.kind) for f in found], [("high", "privileged")])


class NothingElseChangedTest(unittest.TestCase):
    def test_the_published_test_set_and_the_templates_never_report_fixed(self):
        for path in sorted(RISKY.glob("*.yml")) + sorted((TEMPLATES / "workflows").glob("*.yml")):
            with self.subTest(path=path.name):
                self.assertEqual(checker.check(path).cleared(), [])

    def test_the_command_line_shows_the_controls(self):
        with TempDir() as tmp:
            target = tmp / ".github" / "workflows"
            target.mkdir(parents=True)
            (target / "agent.yml").write_text(agent_workflow(), encoding="utf-8")
            (tmp / ".github" / "obaaf.yml").write_text(
                "lanes: {'.github/workflows/agent.yml#agent': agent}\nprotected_secrets: {'*_API_KEY': main-only}\n",
                encoding="utf-8")
            code, out, _ = run_cli("check", tmp, "--fail-on", "low")
            self.assertEqual(code, 1)
            self.assertIn("Controls (it is cleared when all 4 are verified):", out)
            code, out, _ = run_cli("check", tmp, "--fail-on", "never", "--format", "json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["summary"]["new"], 3)


if __name__ == "__main__":
    unittest.main()
