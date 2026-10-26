"""Regression tests for the issue #19 severity changes (PR #28).

PR #28 lowered OBAAF-GHA-008 (unpinned action) to low for ordinary, explicitly
read-only jobs, and made OBAAF-GHA-013 informational for runtime selectors that
name both hosted and self-hosted runners. Both changes lower a severity, so these
tests pin down where they must not apply: a job with write or OIDC authority,
secrets, a privileged outside trigger, undeclared permissions, or an agent role
keeps its severity, and known self-hosted matrices stay high.
"""

import json
import unittest

from helpers import TempDir

from obaaf import checker
from obaaf.catalog import load
from obaaf.checker import report

SHA = "1" * 40
UNPINNED = "      - uses: actions/checkout@v4\n"
PINNED = f"      - uses: actions/checkout@{SHA}\n"


def _check(tmp, workflow):
    (tmp / ".github" / "workflows").mkdir(parents=True)
    (tmp / ".github" / "workflows" / "ci.yml").write_text(workflow, encoding="utf-8")
    return checker.check(tmp)


def _severities(result, rule):
    return [f.severity for f in result.findings if f.rule == rule]


def _job(trigger, workflow_permissions=None, job_permissions=None, extra_steps="", step=UNPINNED,
         runs_on="ubuntu-latest", strategy=""):
    wf = f"on: {trigger}\n"
    if workflow_permissions is not None:
        wf += f"permissions: {workflow_permissions}\n"
    wf += f"jobs:\n  build:\n{strategy}    runs-on: {runs_on}\n"
    if job_permissions is not None:
        wf += f"    permissions: {job_permissions}\n"
    return wf + "    steps:\n" + step + extra_steps


class PinningSeverityTest(unittest.TestCase):
    """OBAAF-GHA-008 is low only for ordinary jobs with explicitly limited authority."""

    def _gha008(self, workflow):
        with TempDir() as tmp:
            return _severities(_check(tmp, workflow), "OBAAF-GHA-008")

    def test_read_only_ordinary_job_is_low(self):
        self.assertEqual(self._gha008(_job("push", workflow_permissions="{contents: read}")), ["low"])

    def test_empty_permissions_is_low(self):
        self.assertEqual(self._gha008(_job("push", workflow_permissions="{}")), ["low"])

    def test_job_level_read_overrides_workflow_write_all(self):
        wf = _job("push", workflow_permissions="write-all", job_permissions="{contents: read}")
        self.assertEqual(self._gha008(wf), ["low"])

    def test_undeclared_permissions_stay_medium(self):
        self.assertEqual(self._gha008(_job("push")), ["medium"])

    def test_write_scope_stays_medium(self):
        self.assertEqual(self._gha008(_job("push", "{}", "{contents: write}")), ["medium"])

    def test_oidc_stays_medium(self):
        self.assertEqual(self._gha008(_job("push", "{}", "{id-token: write}")), ["medium"])

    def test_secret_stays_medium(self):
        step = "      - run: echo hi\n        env:\n          T: ${{ secrets.TOKEN }}\n"
        self.assertEqual(self._gha008(_job("push", "{contents: read}", extra_steps=step)), ["medium"])

    def test_privileged_outside_trigger_stays_medium(self):
        self.assertEqual(self._gha008(_job("pull_request_target", "{contents: read}")), ["medium"])

    def test_agent_job_stays_high(self):
        wf = _job("issue_comment", "{}", "{contents: read}", step="      - uses: anthropics/claude-code-action@v1\n")
        self.assertEqual(self._gha008(wf), ["high"])

    def test_low_pinning_passes_a_medium_gate_but_not_a_low_gate(self):
        with TempDir() as tmp:
            result = _check(tmp, _job("push", workflow_permissions="{contents: read}"))
            catalog = load()
            self.assertNotIn("OBAAF-GHA-008", {f.rule for f in result.gating("medium", catalog)})
            self.assertIn("OBAAF-GHA-008", {f.rule for f in result.gating("low", catalog)})


class RunnerSelectorTest(unittest.TestCase):
    """OBAAF-GHA-013 is informational only for a mixed hosted/self-hosted runtime selector."""

    MIXED = "${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}"

    def _gha013(self, workflow):
        with TempDir() as tmp:
            return _severities(_check(tmp, workflow), "OBAAF-GHA-013")

    def test_mixed_selector_on_untrusted_trigger_is_info(self):
        self.assertEqual(self._gha013(_job("pull_request", "{}", step=PINNED, runs_on=self.MIXED)), ["info"])

    def test_info_is_never_gated(self):
        with TempDir() as tmp:
            result = _check(tmp, _job("pull_request", "{}", step=PINNED, runs_on=self.MIXED))
            self.assertNotIn("OBAAF-GHA-013", {f.rule for f in result.gating("low", load())})

    def test_known_self_hosted_matrix_stays_high(self):
        strategy = "    strategy:\n      matrix:\n        os: [ubuntu-latest, self-hosted]\n"
        wf = _job("pull_request", "{}", step=PINNED, runs_on="${{ matrix.os }}", strategy=strategy)
        self.assertEqual(self._gha013(wf), ["high"])

    def test_unknown_runner_input_stays_medium(self):
        self.assertEqual(self._gha013(_job("pull_request", "{}", step=PINNED, runs_on="${{ vars.RUNNER }}")),
                         ["medium"])

    def test_mixed_selector_on_trusted_trigger_reports_nothing(self):
        self.assertEqual(self._gha013(_job("push", "{}", step=PINNED, runs_on=self.MIXED)), [])

    def test_sarif_reports_info_as_note(self):
        with TempDir() as tmp:
            result = _check(tmp, _job("pull_request", "{}", step=PINNED, runs_on=self.MIXED))
            sarif = json.loads(report.to_sarif(result))
            levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
            self.assertEqual(levels["OBAAF-GHA-013"], "note")

    def test_text_report_lists_info_outside_the_gate(self):
        with TempDir() as tmp:
            out = report.to_text(_check(tmp, _job("pull_request", "{}", step=PINNED, runs_on=self.MIXED)))
            self.assertIn("Informational findings (not gated)", out)


if __name__ == "__main__":
    unittest.main()
