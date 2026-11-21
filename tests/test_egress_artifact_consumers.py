"""Public verdicts for artifact handoffs. The checker only reads these workflow fixtures."""

import unittest

from obaaf.checker.rules import CANNOT_TELL, VERIFIED
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
    "firewall": ("ubuntu-24.04-firewall", "      - run: python -m agents.fix"),
}


def check_handoff(route, *, upload=True, same_workflow=None, downstream=None, upstream="Reports"):
    runner, steps = ROUTES[route]
    if upload:
        steps += "\n" + UPLOAD
    producer = workflow(steps, runs_on=runner, top="name: Reports")
    files = {}
    if same_workflow:
        producer += ("  read_report:\n    needs: agent\n    runs-on: ubuntu-24.04\n    steps:\n"
                     + same_workflow + "\n")
    if downstream:
        files[".github/workflows/read-report.yml"] = (
            "name: Read report\non:\n  workflow_run:\n"
            f"    workflows: ['{upstream}']\n    types: [completed]\n"
            "jobs:\n  read_report:\n    runs-on: ubuntu-24.04\n    steps:\n" + downstream + "\n"
        )
    return run_check(producer, files=files, policy=FIREWALL)


class ArtifactHandoffTest(unittest.TestCase):
    def test_consumer_prevents_verified_egress(self):
        for route in ROUTES:
            for location in ("same_workflow", "downstream"):
                for method, step in DOWNLOADS.items():
                    with self.subTest(route=route, location=location, method=method):
                        result = check_handoff(route, **{location: step})
                        self.assertEqual(verdict(egress(result)), CANNOT_TELL)
                        if route == "action":
                            finding, = [f for f in result.findings if f.rule == "OBAAF-GHA-005"]
                            controls = {c.id: c.verdict for c in finding.controls}
                            self.assertEqual(controls["egress-enforced"], CANNOT_TELL)
                            self.assertNotEqual(controls["key-out-of-reach"], VERIFIED)
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
