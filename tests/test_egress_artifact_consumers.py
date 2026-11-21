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


def other_workflow(steps, on="workflow_dispatch"):
    """A workflow that `workflow_run` does not start for the producer, with a job that runs what it fetched."""
    return (f"name: Deploy\non: {on}\npermissions: {{actions: read, contents: read}}\njobs:\n  deploy:\n"
            "    runs-on: ubuntu-24.04\n    steps:\n" + steps + "\n      - run: make test\n"
            "        env: {KEY: '${{ secrets.MODEL_API_KEY }}'}\n")


class DownloadsFromAnyRunTest(unittest.TestCase):
    """From the review of #357 (run gannet): a workflow the producer does not start can still download the
    producer's artifact by naming its run, so the subscriber test alone left these verified."""

    CONSUMERS = {
        "dawidd6 in a dispatched workflow": {".github/workflows/deploy.yml": other_workflow(
            f"      - uses: dawidd6/action-download-artifact@{SHA}\n        with: {{workflow: agent.yml, name: report}}")},
        "download-artifact with a run id on a schedule": {".github/workflows/deploy.yml": other_workflow(
            f"      - uses: actions/download-artifact@{SHA}\n"
            "        with: {name: report, run-id: '${{ inputs.run }}', github-token: '${{ github.token }}'}",
            on="schedule")},
        "gh run download on push": {".github/workflows/deploy.yml": other_workflow(
            "      - run: gh run download \"$RUN\" -n report", on="push")},
        "a called workflow of this repository downloads": {
            ".github/workflows/deploy.yml": ("name: Deploy\non: workflow_dispatch\njobs:\n  deploy:\n"
                                             "    uses: ./.github/workflows/build.yml\n    secrets: inherit\n"),
            ".github/workflows/build.yml": other_workflow(
                f"      - uses: dawidd6/action-download-artifact@{SHA}\n        with: {{workflow: agent.yml}}",
                on="workflow_call")},
        "a call of another repository's workflow": {".github/workflows/deploy.yml": (
            "name: Deploy\non: workflow_dispatch\njobs:\n  deploy:\n"
            f"    uses: example/shared/.github/workflows/build.yml@{SHA}\n    secrets: inherit\n")},
        "a local action in another workflow": {".github/workflows/deploy.yml": other_workflow(
            "      - uses: ./.github/actions/fetch")},
    }

    def test_a_download_from_another_run_anywhere_in_the_repository(self):
        for route in ROUTES:
            for name, files in self.CONSUMERS.items():
                with self.subTest(route=route, case=name):
                    result = check_handoff(route, files=files)
                    self.assertEqual(verdict(egress(result)), CANNOT_TELL)
                    finding, = [f for f in result.findings if f.rule == "OBAAF-GHA-005"]
                    self.assertNotEqual(finding.state, "fixed")

    def test_a_download_from_its_own_run_in_another_workflow_is_not_a_consumer(self):
        files = {".github/workflows/deploy.yml": other_workflow(
            f"      - uses: actions/download-artifact@{SHA}\n        with: {{name: report}}")}
        for route in ROUTES:
            with self.subTest(route=route):
                self.assertEqual(verdict(egress(check_handoff(route, files=files))), VERIFIED)

    def test_an_upload_by_an_action_named_like_one(self):
        # The firewall route confines the whole job, so the upload can be any step after the agent's.
        pages = f"      - uses: actions/upload-pages-artifact@{SHA}\n        with: {{path: site}}"
        consumer = f"      - uses: actions/download-artifact@{SHA}\n        with: {{name: github-pages}}"
        self.assertEqual(verdict(egress(check_handoff("firewall", upload=False, same_job=pages,
                                                      same_workflow=consumer))), CANNOT_TELL)
        self.assertEqual(verdict(egress(check_handoff("firewall", upload=False, same_job=pages))), VERIFIED)
