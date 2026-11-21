"""Public verdicts for artifact handoffs. The checker only reads these workflow fixtures."""

import unittest

from obaaf.checker.rules import CANNOT_TELL, NOT_MET, VERIFIED
from test_egress_recognised import CHECKOUT, FIREWALL, SHA, egress, keyed, run_check, verdict, workflow


UPLOAD = (f"      - uses: actions/upload-artifact@{SHA}\n"
          "        with: {name: report, path: report.txt}")
DOWNLOADS = {
    "action": f"      - uses: actions/download-artifact@{SHA}\n        with: {{name: report}}",
    "cli": "      - run: gh run download 123 --name report",
    "api": "      - run: gh api repos/example/project/actions/artifacts/123/zip",
}
ROUTES = {
    "action": ("ubuntu-24.04", CHECKOUT + "\n" + keyed()),
    "firewall": ("ubuntu-24.04-firewall", "      - run: python -m agents.fix\n"
                 "        env: {KEY: '${{ secrets.MODEL_API_KEY }}'}"),
}


def check_handoff(route, *, upload=True, same_workflow=None, downstream=None, upstream="Reports",
                  same_job=None, files=None, single=False):
    runner, steps = ROUTES[route]
    if upload:
        steps += "\n" + UPLOAD
    if same_job:
        steps += "\n" + same_job
    producer = workflow(steps, runs_on=runner, top="name: Reports")
    files = dict(files or {})
    if same_workflow:
        producer += ("  read_report:\n    needs: agent\n    runs-on: ubuntu-24.04\n    steps:\n"
                     + same_workflow + "\n")
    if downstream:
        files[".github/workflows/read-report.yml"] = (
            "name: Read report\non:\n  workflow_run:\n"
            f"    workflows: ['{upstream}']\n    types: [completed]\n"
            "jobs:\n  read_report:\n    runs-on: ubuntu-24.04\n    steps:\n" + downstream + "\n"
        )
    return run_check(producer, files=files, policy=FIREWALL, single=single)


class ArtifactHandoffTest(unittest.TestCase):
    def test_consumer_prevents_verified_egress(self):
        for route in ROUTES:
            for location in ("same_workflow", "downstream"):
                for method, step in DOWNLOADS.items():
                    with self.subTest(route=route, location=location, method=method):
                        result = check_handoff(route, **{location: step})
                        self.assertEqual(verdict(egress(result)), CANNOT_TELL)
                        finding, = [f for f in result.findings if f.rule == "OBAAF-GHA-005"]
                        controls = {c.id: c.verdict for c in finding.controls}
                        self.assertEqual(controls["egress-enforced"], CANNOT_TELL)
                        expected_key = CANNOT_TELL if route == "action" else NOT_MET
                        self.assertEqual(controls["key-out-of-reach"], expected_key)
                        self.assertNotEqual(finding.state, "fixed")

    def test_verified_when_there_is_no_handoff(self):
        cases = {
            "producer does not upload": {"upload": False, "same_workflow": DOWNLOADS["action"]},
            "linked workflow does not download": {"downstream": "      - run: echo completed"},
            "consumer follows a different workflow": {"downstream": DOWNLOADS["action"], "upstream": "Other"},
        }
        for route in ROUTES:
            for name, options in cases.items():
                with self.subTest(route=route, case=name):
                    self.assertEqual(verdict(egress(check_handoff(route, **options))), VERIFIED)

    def test_upload_with_incomplete_workflow_inventory(self):
        cases = {
            "single workflow": {"single": True},
            "malformed sibling": {"files": {".github/workflows/incomplete.yml": "jobs: [\n"}},
        }
        for route in ROUTES:
            for name, options in cases.items():
                with self.subTest(route=route, case=name):
                    self.assertEqual(verdict(egress(check_handoff(route, **options))), CANNOT_TELL)

    def test_firewall_job_downloads_its_own_upload(self):
        result = check_handoff("firewall", same_job=DOWNLOADS["action"])
        self.assertEqual(verdict(egress(result)), CANNOT_TELL)
