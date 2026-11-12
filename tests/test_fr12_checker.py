"""FR12: flag risky pipeline settings.

Acceptance criterion: the checker finds every case in the test set,
such as secrets exposed to untrusted triggers, write tokens in agent jobs,
caches shared between lanes, and unpinned third-party actions, and names the
requirement and fix for each.
"""

import json
import re
import unittest
from datetime import date

from helpers import RISKY, ROOT, TempDir, install_templates, run_cli, unexpected_findings

from obaaf import checker, render
from obaaf.catalog import load
from obaaf.checker import report


class PublishedTestSetTest(unittest.TestCase):
    def test_set_covers_the_four_classes_named_in_fr12(self):
        cases = render.read_test_set(RISKY)
        expected = {rule for case in cases for rule in case["expect"]}
        self.assertIn("OBAAF-GHA-001", expected)  # secrets exposed to untrusted triggers
        self.assertIn("OBAAF-GHA-003", expected)  # write tokens in agent jobs
        self.assertTrue({"OBAAF-GHA-006", "OBAAF-GHA-007"} <= expected)  # caches shared between lanes
        self.assertIn("OBAAF-GHA-008", expected)  # unpinned third-party actions

    def test_checker_finds_every_expected_rule(self):
        cases = render.read_test_set(RISKY)
        self.assertGreaterEqual(len(cases), 12)
        for case in cases:
            path = ROOT / case["file"]
            config = checker.Config.from_data(case["config"], path) if case["config"] else None
            found = {f.rule for f in checker.check(path, config=config).findings}
            with self.subTest(case=path.name):
                self.assertTrue(set(case["expect"]) <= found, f"missing {set(case['expect']) - found}")

    def test_every_workflow_rule_is_exercised_by_the_test_set(self):
        cases = render.read_test_set(RISKY)
        exercised = {rule for case in cases for rule in case["expect"]}
        workflow_rules = {rid for rid in load().rules if rid.startswith("OBAAF-GHA-")}
        self.assertEqual(workflow_rules - exercised, set())

    def test_test_set_is_published_in_the_rules_document(self):
        text = (ROOT / "spec" / "checker-rules.md").read_text()
        for case in render.read_test_set(RISKY):
            self.assertIn(case["file"], text)


class FindingsNameRequirementAndFixTest(unittest.TestCase):
    def test_every_finding_names_a_requirement_and_a_fix(self):
        catalog = load()
        for path in sorted(RISKY.glob("*.yml")):
            for f in checker.check(path).findings:
                rule = catalog.rules[f.rule]
                with self.subTest(rule=f.rule, file=path.name):
                    if f.rule != "OBAAF-GHA-023":
                        self.assertTrue(rule["requirements"] or rule.get("agent_controls"))
                    self.assertGreater(len(rule["fix"].split()), 5)
                    self.assertTrue(f.message)

    def test_text_output_shows_requirement_and_fix(self):
        out = report.to_text(checker.check(RISKY / "pwn-request.yml"))
        self.assertIn("Requirement: G3.4, G8.1, G9.1", out)
        self.assertIn("Fix: ", out)

    def test_sarif_output_is_well_formed(self):
        sarif = json.loads(report.to_sarif(checker.check(RISKY / "promptpwnd-issue-agent.yml")))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        for result in run["results"]:
            self.assertEqual(ids[result["ruleIndex"]], result["ruleId"])
            self.assertIn(result["level"], ("error", "warning", "note"))
            self.assertGreaterEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        for rule in run["tool"]["driver"]["rules"]:
            self.assertRegex(rule["properties"]["security-severity"], r"^\d+\.\d$")

    def test_json_output_lists_requirements(self):
        data = json.loads(report.to_json(checker.check(RISKY / "nx-title-injection.yml")))
        self.assertTrue(all(f["requirements"] and f["fix"] for f in data["findings"]))


class TemplatesAreCleanTest(unittest.TestCase):
    def test_installed_templates_have_no_findings(self):
        with TempDir() as tmp:
            install_templates(tmp)
            result = checker.check(tmp)
            self.assertEqual(unexpected_findings(result.findings), [])
            self.assertEqual(result.errors, [])
            self.assertEqual(len(result.files), 6)

    def test_uninstalled_templates_are_flagged_for_placeholders(self):
        from helpers import TEMPLATES

        rules = {f.rule for f in checker.check(TEMPLATES / "workflows" / "obaaf-release.yml").findings}
        self.assertEqual(rules, {"OBAAF-GHA-023"})

    def test_this_repositorys_own_workflows_pass(self):
        result = checker.check(ROOT)
        self.assertEqual([(f.rule, f.path) for f in result.active() if f.severity in ("high", "medium")], [])


SHA = "1" * 40


def findings_for(tmp, text, name="wf.yml", config=None):
    path = tmp / name
    path.write_text(text, encoding="utf-8")
    return checker.check(path, config=config).findings


def rules_of(findings):
    return {f.rule: f.severity for f in findings}


class CheckerBypassesTest(unittest.TestCase):
    """Workflows that earlier versions of the checker misread (independent security review, 2026-10)."""

    def test_a_negated_event_test_does_not_narrow_the_triggers(self):
        wf = ("on: [issue_comment, push]\npermissions: {}\njobs:\n  build:\n"
              "    if: ${{ !(github.event_name == 'push') }}\n    runs-on: ubuntu-latest\n"
              "    permissions: {contents: read}\n    steps:\n"
              "      - run: echo \"${{ github.event.comment.body }}\"\n")
        with TempDir() as tmp:
            self.assertEqual(rules_of(findings_for(tmp, wf)).get("OBAAF-GHA-010"), "high")

    def test_a_negated_status_function_still_lets_an_event_test_narrow(self):
        base = ("on: [pull_request, workflow_dispatch]\npermissions: {{contents: read}}\njobs:\n  run:\n"
                "    if: ${{{{ {cond} }}}}\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: echo \"${{{{ secrets.KEY }}}}\" | wc -c\n")
        with TempDir() as tmp:
            narrowed = base.format(cond="!cancelled() && github.event_name == 'workflow_dispatch'")
            self.assertNotIn("OBAAF-GHA-001", rules_of(findings_for(tmp, narrowed)))
            # A negation that can invert the event test still stops narrowing.
            inverted = base.format(cond="!cancelled() && !(github.event_name == 'workflow_dispatch')")
            self.assertIn("OBAAF-GHA-001", rules_of(findings_for(tmp, inverted)))
            # And an alternative without an event test still reaches pull requests.
            either = base.format(cond="!cancelled() && github.event_name == 'workflow_dispatch' || always()")
            self.assertIn("OBAAF-GHA-001", rules_of(findings_for(tmp, either)))

    def test_a_job_that_runs_an_agent_cannot_declare_itself_out_of_the_agent_lane(self):
        wf = ("on: issue_comment\npermissions: {}\njobs:\n  triage:\n    runs-on: ubuntu-latest\n"
              "    permissions: {contents: write}\n    env: {OBAAF_LANE: trusted}\n    steps:\n"
              f"      - uses: anthropics/claude-code-action@{SHA}\n")
        with TempDir() as tmp:
            self.assertIn("OBAAF-GHA-003", rules_of(findings_for(tmp, wf)))
            config = checker.Config(lanes={"wf.yml#triage": "trusted"})
            self.assertIn("OBAAF-GHA-003", rules_of(findings_for(tmp, wf, config=config)))

    def test_an_ignore_entry_cannot_match_everything(self):
        with TempDir() as tmp:
            (tmp / ".github").mkdir()
            for pattern in ("'*'", "'**'", "'**/*'", "'*/*'"):
                (tmp / ".github" / "obaaf.yml").write_text(
                    f"ignore:\n  - rule: OBAAF-GHA-013\n    path: {pattern}\n    reason: x\n    until: 2027-01-31\n")
                with self.subTest(pattern=pattern), self.assertRaises(checker.ConfigError):
                    checker.Config.load(tmp)

    def test_runners_that_are_not_standard_hosted_labels_are_reported(self):
        base = ("on: pull_request\npermissions: {}\njobs:\n  build:\n    runs-on: RUNNER\n{strategy}"
                "    permissions: {contents: read}\n    steps: [{run: make}]\n")
        cases = {
            "[linux, gpu]": ("", "medium"),
            "'${{ matrix.os }}'": ("    strategy: {matrix: {os: [ubuntu-latest, studio-mac]}}\n", "medium"),
            "'${{ inputs.runner }}'": ("", "medium"),
            "[self-hosted, linux]": ("", "high"),
        }
        with TempDir() as tmp:
            for runner, (strategy, severity) in cases.items():
                with self.subTest(runner=runner):
                    wf = base.replace("RUNNER", runner).replace("{strategy}", strategy)
                    self.assertEqual(rules_of(findings_for(tmp, wf)).get("OBAAF-GHA-013"), severity)
            hosted = base.replace("RUNNER", "'${{ matrix.os }}'").replace(
                "{strategy}", "    strategy: {matrix: {os: [ubuntu-latest, windows-latest, macos-15]}}\n")
            self.assertNotIn("OBAAF-GHA-013", rules_of(findings_for(tmp, hosted)))

    def test_injection_through_index_syntax_case_or_tojson_is_found(self):
        with TempDir() as tmp:
            for expr in ("github.event['issue']['title']", "GitHub.Event.Issue.Title",
                         "github.event[\"comment\"].body", "toJSON(github.event)", "toJson(github.event.issue)"):
                with self.subTest(expr=expr):
                    wf = ("on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                          f"    permissions: {{contents: read}}\n    steps:\n      - run: echo '${{{{ {expr} }}}}'\n")
                    self.assertEqual(rules_of(findings_for(tmp, wf)).get("OBAAF-GHA-010"), "high")

    def test_github_script_artifact_downloads_make_an_effect_job(self):
        wf = ("on:\n  workflow_run: {workflows: [CI], types: [completed]}\npermissions: {}\njobs:\n  comment:\n"
              "    runs-on: ubuntu-latest\n    permissions: {pull-requests: write, actions: read}\n    steps:\n"
              f"      - uses: actions/github-script@{SHA}\n        with:\n          script: |\n"
              "            const all = await github.rest.actions.listWorkflowRunArtifacts({owner: context.repo.owner,\n"
              "              repo: context.repo.repo, run_id: context.payload.workflow_run.id});\n")
        with TempDir() as tmp:
            self.assertTrue({"OBAAF-GHA-021", "OBAAF-GHA-022"} <= set(rules_of(findings_for(tmp, wf))))

    def release_workflow(self, verify_step, upload_if=""):
        return ("on: {push: {tags: ['v*']}}\npermissions: {}\njobs:\n  publish:\n    runs-on: ubuntu-latest\n"
                "    environment: release\n    cache-mode: none\n"
                "    permissions: {contents: read, id-token: write, attestations: write}\n    steps:\n"
                f"      - uses: actions/attest-build-provenance@{SHA}\n        with: {{subject-path: 'dist/*'}}\n"
                f"{verify_step}"
                f"      - run: gh release upload v1 dist/*\n{upload_if}")

    def test_a_verification_whose_failure_is_ignored_does_not_gate_the_upload(self):
        good = "      - run: obaaf verify release --policy p.yaml --artifacts dist\n"
        ignored = [
            "      - run: obaaf verify release --policy p.yaml --artifacts dist || true\n",
            "      - run: obaaf verify release --policy p.yaml --artifacts dist\n        continue-on-error: true\n",
            "      - run: |\n          set +e\n          obaaf verify release --policy p.yaml --artifacts dist\n",
            "      - run: obaaf verify release --policy p.yaml --artifacts dist\n        if: github.ref == 'x'\n",
        ]
        with TempDir() as tmp:
            self.assertNotIn("OBAAF-GHA-016", rules_of(findings_for(tmp, self.release_workflow(good))))
            for step in ignored:
                with self.subTest(step=step):
                    self.assertEqual(rules_of(findings_for(tmp, self.release_workflow(step))).get("OBAAF-GHA-016"),
                                     "high")
            bypass = self.release_workflow(good, upload_if="        if: always()\n")
            self.assertEqual(rules_of(findings_for(tmp, bypass)).get("OBAAF-GHA-016"), "high")

    def test_a_provenance_only_check_is_reported_at_medium(self):
        step = "      - run: gh attestation verify dist/game.zip --repo studio/game\n"
        with TempDir() as tmp:
            self.assertEqual(rules_of(findings_for(tmp, self.release_workflow(step))).get("OBAAF-GHA-016"), "medium")

    def test_a_declared_egress_policy_is_not_enforcement(self):
        wf = ("on: issues\npermissions: {}\njobs:\n  agent:\n    runs-on: ubuntu-latest\n    cache-mode: none\n"
              "    permissions: {contents: read}\n    env: {OBAAF_EGRESS: model endpoint only}\n    steps:\n"
              f"      - uses: anthropics/claude-code-action@{SHA}\n")
        with TempDir() as tmp:
            found = [f for f in findings_for(tmp, wf) if f.rule == "OBAAF-GHA-020"]
            self.assertEqual(len(found), 1)
            self.assertIn("nothing in the job enforces it", found[0].message)
            enforced = wf.replace("    steps:\n", "    steps:\n"
                                  f"      - uses: step-security/harden-runner@{SHA}\n"
                                  "        with: {egress-policy: block, allowed-endpoints: 'proxy.example:443'}\n")
            # A blocking monitor that always runs is no longer a pass: the checker does not read what
            # makes it hold (its version, its place before the agent, whether the job can undo it),
            # so the finding stays and says "cannot tell".
            found = [f for f in findings_for(tmp, enforced) if f.rule == "OBAAF-GHA-020"]
            self.assertEqual([(f.kind, f.state) for f in found], [("unverified-monitor", "cannot-tell")])

    def test_an_effect_job_gated_by_a_needed_job_counts_only_without_always(self):
        wf = ("on:\n  workflow_run: {workflows: [Agent], types: [completed]}\npermissions: {}\njobs:\n"
              "  gate:\n    runs-on: ubuntu-latest\n    environment: approve\n    permissions: {actions: read}\n"
              "    steps: [{run: obaaf verify agent-run --policy p --proposal b --snapshot s --bundle x}, "
              "{run: obaaf proposal check bundle}]\n"
              "  apply:\n    needs: gate\nIF    runs-on: ubuntu-latest\n    permissions: {contents: write, actions: read}\n"
              "    steps:\n"
              f"      - uses: actions/download-artifact@{SHA}\n"
              "        with: {name: p, run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}'}\n"
              "      - run: git apply p/patch.diff\n")
        with TempDir() as tmp:
            gated = rules_of(findings_for(tmp, wf.replace("IF", "")))
            self.assertFalse({"OBAAF-GHA-021", "OBAAF-GHA-022"} & set(gated), gated)
            ungated = rules_of(findings_for(tmp, wf.replace("IF", "    if: always()\n")))
            self.assertTrue({"OBAAF-GHA-021", "OBAAF-GHA-022"} <= set(ungated), ungated)
            # success() in an || also lets the job run after the gate failed.
            ungated = rules_of(findings_for(tmp, wf.replace("IF", "    if: success() || github.event_name == 'workflow_run'\n")))
            self.assertTrue({"OBAAF-GHA-021", "OBAAF-GHA-022"} <= set(ungated), ungated)

    def test_an_effect_job_needs_both_the_record_check_and_the_proposal_check(self):
        wf = ("on:\n  workflow_run: {workflows: [Agent], types: [completed]}\npermissions: {}\njobs:\n"
              "  apply:\n    runs-on: ubuntu-latest\n    environment: approve\n"
              "    permissions: {contents: write, actions: read}\n    steps:\n"
              f"      - uses: actions/download-artifact@{SHA}\n"
              "        with: {name: p, run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}'}\n"
              "      - run: CHECK\n      - run: git apply p/patch.diff\n")
        with TempDir() as tmp:
            only_proposal = rules_of(findings_for(tmp, wf.replace("CHECK", "obaaf proposal check p")))
            self.assertEqual(only_proposal.get("OBAAF-GHA-021"), "medium")
            both = wf.replace("CHECK", "obaaf verify agent-run --policy x --proposal p --snapshot s --bundle b\n"
                                       "        obaaf proposal check p --repo .").replace("- run: obaaf", "- run: |\n        obaaf")
            self.assertNotIn("OBAAF-GHA-021", rules_of(findings_for(tmp, both)))

    def test_a_needed_gate_does_not_narrow_triggers_when_success_is_ored(self):
        # A job with `success() || <event>` runs on that event even when its gate was skipped.
        wf = ("on: [push, pull_request_target]\npermissions: {}\njobs:\n"
              "  gate:\n    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n"
              "    permissions: {contents: read}\n    steps: [{run: echo ok}]\n"
              "  build:\n    needs: gate\n    if: success() || github.event_name == 'pull_request_target'\n"
              "    runs-on: ubuntu-latest\n    permissions: {contents: read}\n    steps:\n"
              f"      - uses: actions/checkout@{SHA}\n"
              "        with: {ref: '${{ github.event.pull_request.head.sha }}', persist-credentials: false}\n"
              "      - run: ./build.sh\n        env: {TOKEN: '${{ secrets.DEPLOY_TOKEN }}'}\n")
        with TempDir() as tmp:
            found = rules_of(findings_for(tmp, wf))
            self.assertTrue({"OBAAF-GHA-001", "OBAAF-GHA-002"} <= set(found), found)

    def test_steps_inside_parallel_groups_are_checked(self):
        wf = ("on: issue_comment\npermissions: {}\njobs:\n  triage:\n    runs-on: ubuntu-latest\n"
              "    permissions: {contents: write, id-token: write}\n    steps:\n      - parallel:\n"
              f"          - uses: anthropics/claude-code-action@{SHA}\n"
              "          - run: echo \"${{ github.event.comment.body }}\"\n")
        with TempDir() as tmp:
            found = rules_of(findings_for(tmp, wf))
            self.assertTrue({"OBAAF-GHA-003", "OBAAF-GHA-004", "OBAAF-GHA-010"} <= set(found), found)

    def test_a_background_verification_does_not_gate_an_upload(self):
        step = ("      - run: obaaf verify release --policy p.yaml --artifacts dist\n        background: true\n")
        with TempDir() as tmp:
            found = rules_of(findings_for(tmp, self.release_workflow(step)))
            self.assertEqual(found.get("OBAAF-GHA-016"), "high")
            grouped = ("      - parallel:\n          - run: obaaf verify release --policy p.yaml --artifacts dist\n"
                       "          - run: echo building notes\n")
            self.assertNotIn("OBAAF-GHA-016", rules_of(findings_for(tmp, self.release_workflow(grouped))))

    def test_unknown_step_forms_are_errors(self):
        wf = ("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
              "      - future-group: [{run: make}]\n")
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(wf)
            result = checker.check(path)
            self.assertTrue(any("cannot check what the step does" in e for e in result.errors), result.errors)


class ConfigurationTest(unittest.TestCase):
    def test_ignore_entries_need_a_reason_and_expire(self):
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "ci.yml").write_text((RISKY / "pytorch-self-hosted.yml").read_text())
            (tmp / ".github" / "CODEOWNERS").write_text("/.github/ @studio/build\n")
            config = tmp / ".github" / "obaaf.yml"
            config.write_text("ignore:\n  - rule: OBAAF-GHA-013\n    path: .github/workflows/ci.yml\n"
                              "    owner: '@studio/build'\n"
                              "    reason: Ephemeral runners, see issue 9\n    until: 2027-01-31\n")
            before = checker.check(tmp, today=date(2026, 12, 1))
            suppressed = [f for f in before.findings if f.rule == "OBAAF-GHA-013"]
            self.assertTrue(suppressed and all(f.suppressed for f in suppressed))
            after = checker.check(tmp, today=date(2027, 2, 1))
            active = [f for f in after.active() if f.rule == "OBAAF-GHA-013"]
            self.assertTrue(active and "expired" in active[0].message)
            config.write_text("ignore:\n  - rule: OBAAF-GHA-013\n    path: .github/workflows/ci.yml\n")
            with self.assertRaises(checker.ConfigError):
                checker.Config.load(tmp)

    def test_lane_overrides_and_explicit_lanes(self):
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env: {OBAAF_LANE: agent}\n"
                            "    steps: [{run: echo}]\n")
            lanes = checker.lanes(path)
            self.assertEqual(lanes[0][2:], ("agent", "set by OBAAF_LANE"))

    def test_cli_fail_threshold(self):
        code, _, _ = run_cli("check", RISKY / "claude-action-toctou.yml", "--fail-on", "high")
        self.assertEqual(code, 1)
        code, _, _ = run_cli("check", RISKY / "claude-action-toctou.yml", "--fail-on", "never")
        self.assertEqual(code, 0)

    def test_unparseable_workflows_are_errors(self):
        with TempDir() as tmp:
            path = tmp / "bad.yml"
            path.write_text("on: [push\njobs: {")
            code, out, _ = run_cli("check", path, "--fail-on", "never")
            self.assertEqual(code, 1)
            self.assertIn("cannot parse", out)

    def test_duplicate_keys_are_errors(self):
        with TempDir() as tmp:
            path = tmp / "dup.yml"
            path.write_text("on: push\njobs:\n  a: {runs-on: x, steps: [{run: a}]}\n  a: {runs-on: y, steps: []}\n")
            self.assertTrue(checker.check(path).errors)


class InjectionDetectionTest(unittest.TestCase):
    def test_fields_outsiders_control_are_flagged_and_safe_ones_are_not(self):
        cases = {
            "${{ github.event.issue.title }}": True,
            "${{ github.event.pull_request.head.ref }}": True,
            "${{ github.head_ref }}": True,
            "${{ github.event.comment.body }}": True,
            "${{ github.event.head_commit.message }}": True,
            "${{ github.event.issue.number }}": False,
            "${{ github.sha }}": False,
            "${{ github.event.pull_request.head.sha }}": False,
        }
        for expr, flagged in cases.items():
            text = ("on: issue_comment\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                    f"    steps:\n      - run: echo \"{expr}\"\n")
            with TempDir() as tmp, self.subTest(expr=expr):
                path = tmp / "wf.yml"
                path.write_text(text)
                found = any(f.rule == "OBAAF-GHA-010" for f in checker.check(path).findings)
                self.assertEqual(found, flagged)



class ProtectedSecretsTest(unittest.TestCase):
    """GHA-024: a secret listed in protected_secrets is used only by jobs that declare its environment."""

    JOB = """\
name: wf
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  bench:
    runs-on: ubuntu-24.04
{extra}    steps:
      - run: echo "${{{{ secrets.{secret} }}}}" | wc -c
"""

    def run_case(self, protected, extra="", secret="PRIVATE_SET_TOKEN"):
        with TempDir() as tmp:
            config = checker.Config.from_data({"protected_secrets": protected}, "test")
            text = self.JOB.format(extra=extra, secret=secret)
            return [f for f in findings_for(tmp, text, config=config) if f.rule == "OBAAF-GHA-024"]

    def test_job_without_environment_is_high(self):
        found = self.run_case(["PRIVATE_SET_TOKEN"])
        self.assertEqual([f.severity for f in found], ["high"])
        self.assertIn("without declaring an environment", found[0].message)

    def test_job_in_the_named_environment_passes(self):
        self.assertEqual(self.run_case({"PRIVATE_SET_TOKEN": "private-set"}, "    environment: private-set\n"), [])
        self.assertEqual(self.run_case({"PRIVATE_SET_TOKEN": "private-set"},
                                       "    environment:\n      name: private-set\n"), [])

    def test_any_environment_satisfies_a_list_entry(self):
        self.assertEqual(self.run_case(["PRIVATE_SET_TOKEN"], "    environment: anything\n"), [])

    def test_wrong_environment_is_high(self):
        found = self.run_case({"PRIVATE_SET_TOKEN": "private-set"}, "    environment: unity\n")
        self.assertEqual([f.severity for f in found], ["high"])
        self.assertIn("not environment 'private-set'", found[0].message)

    def test_expression_environment_is_medium(self):
        found = self.run_case({"PRIVATE_SET_TOKEN": "private-set"}, "    environment: ${{ inputs.env }}\n")
        self.assertEqual([f.severity for f in found], ["medium"])

    def test_names_are_case_insensitive_and_globs_match(self):
        self.assertEqual(len(self.run_case(["private_set_token"])), 1)
        self.assertEqual(len(self.run_case(["PRIVATE_*"])), 1)
        self.assertEqual(self.run_case(["OTHER_TOKEN"]), [])

    def test_taking_every_secret_counts(self):
        with TempDir() as tmp:
            config = checker.Config.from_data({"protected_secrets": ["PRIVATE_SET_TOKEN"]}, "test")
            text = self.JOB.format(extra="", secret="X").replace(
                'echo "${{ secrets.X }}" | wc -c', 'echo "${{ toJSON(secrets) }}" | wc -c')
            found = [f for f in findings_for(tmp, text, config=config) if f.rule == "OBAAF-GHA-024"]
            self.assertEqual(len(found), 1)
            self.assertIn("can take every secret", found[0].message)
            for index in ("format('{0}_TOKEN', 'PRIVATE_SET')", "matrix.k"):
                text = self.JOB.format(extra="", secret="X").replace("secrets.X", f"secrets[{index}]")
                found = [f for f in findings_for(tmp, text, config=config) if f.rule == "OBAAF-GHA-024"]
                self.assertEqual(len(found), 1, index)

    def test_context_name_case_does_not_matter(self):
        with TempDir() as tmp:
            config = checker.Config.from_data({"protected_secrets": ["PRIVATE_SET_TOKEN"]}, "test")
            text = self.JOB.format(extra="", secret="X").replace("secrets.X", "SECRETS.private_set_token")
            self.assertEqual(len([f for f in findings_for(tmp, text, config=config) if f.rule == "OBAAF-GHA-024"]), 1)

    def test_environment_names_are_case_insensitive(self):
        self.assertEqual(self.run_case({"PRIVATE_SET_TOKEN": "private-set"}, "    environment: Private-Set\n"), [])

    def test_a_looser_pattern_cannot_relax_a_stricter_one(self):
        found = self.run_case({"PRIVATE_SET_TOKEN": "private-set", "*_TOKEN": None}, "    environment: other\n")
        self.assertEqual(len(found), 1)
        self.assertIn("not environment 'private-set'", found[0].message)

    def test_reusable_workflow_callers(self):
        with TempDir() as tmp:
            config = checker.Config.from_data({"protected_secrets": {"PRIVATE_SET_TOKEN": "private-set"}}, "test")
            head = ("name: wf\non: [push]\npermissions:\n  contents: read\njobs:\n  call:\n"
                    "    uses: example/repo/.github/workflows/x.yml@" + SHA + "\n")
            # inherit passes repository and organization secrets only, never an environment's.
            inherit = head + "    secrets: inherit\n"
            self.assertEqual([f for f in findings_for(tmp, inherit, name="c.yml", config=config)
                              if f.rule == "OBAAF-GHA-024"], [])
            mapped = head + "    secrets:\n      token: ${{ secrets.PRIVATE_SET_TOKEN }}\n"
            found = [f for f in findings_for(tmp, mapped, name="c.yml", config=config) if f.rule == "OBAAF-GHA-024"]
            self.assertEqual([f.severity for f in found], ["high"])
            self.assertIn("in the called workflow's job", found[0].message)

    def test_no_config_means_no_findings(self):
        with TempDir() as tmp:
            text = self.JOB.format(extra="", secret="PRIVATE_SET_TOKEN")
            self.assertEqual([f for f in findings_for(tmp, text) if f.rule == "OBAAF-GHA-024"], [])

    def test_config_is_validated(self):
        for bad in ("TOKEN", [""], ["*"], ["*_*"], ["A?_*"], ["NAME WITH SPACE"], ["GITHUB_TOKEN"], {"ABC": ""},
                    {"ABC": "${{ x }}"}, {"ABC": 3}):
            with self.subTest(bad=bad), self.assertRaises(checker.ConfigError):
                checker.Config.from_data({"protected_secrets": bad}, "test")

    def test_unknown_settings_are_refused(self):
        with self.assertRaises(checker.ConfigError) as ctx:
            checker.Config.from_data({"protected-secrets": ["PRIVATE_SET_TOKEN"]}, "test")
        self.assertIn("protected-secrets", str(ctx.exception))

    def test_config_file_is_read(self):
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "obaaf.yml").write_text("protected_secrets:\n  PRIVATE_SET_TOKEN: private-set\n")
            (tmp / ".github" / "workflows" / "wf.yml").write_text(self.JOB.format(extra="", secret="PRIVATE_SET_TOKEN"))
            rules = {f.rule for f in checker.check(tmp).findings}
            self.assertIn("OBAAF-GHA-024", rules)

if __name__ == "__main__":
    unittest.main()
