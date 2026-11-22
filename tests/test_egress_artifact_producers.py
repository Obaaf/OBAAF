"""Static checker fixtures for artifacts uploaded by the agent job."""

import unittest

from obaaf.checker.rules import CANNOT_TELL, NOT_MET, VERIFIED
from test_egress_recognised import (
    CHECKOUT, FIREWALL, SHA, egress, keyed, run_check, secret_finding, verdict, workflow,
)


def upload(action_name="upload-artifact"):
    return (f"      - uses: actions/{action_name}@{SHA}\n"
            "        with: {name: report, path: report.txt}")


ROUTES = {
    "action": ("ubuntu-24.04", CHECKOUT + "\n" + keyed(), VERIFIED),
    "firewall": ("ubuntu-24.04-firewall", "      - run: claude -p review\n"
                 "        env: {KEY: '${{ secrets.MODEL_API_KEY }}'}", NOT_MET),
}


class ArtifactProducerTest(unittest.TestCase):
    def test_upload_changes_producer_verdict_without_a_visible_consumer(self):
        for route, (runner, steps, baseline_key) in ROUTES.items():
            for action_name in (None, "upload-artifact", "upload-pages-artifact"):
                with self.subTest(route=route, upload=action_name):
                    body = steps if action_name is None else steps + "\n" + upload(action_name)
                    result = run_check(workflow(body, runs_on=runner), policy=FIREWALL)
                    expected = VERIFIED if action_name is None else CANNOT_TELL
                    self.assertEqual(verdict(egress(result)), expected)
                    finding = secret_finding(result)
                    controls = {control.id: control.verdict for control in finding.controls}
                    self.assertEqual(controls["egress-enforced"], expected)
                    key = CANNOT_TELL if action_name and route == "action" else baseline_key
                    self.assertEqual(controls["key-out-of-reach"], key)
                    if action_name:
                        self.assertNotEqual(finding.state, "fixed")

    def test_a_sibling_jobs_upload_does_not_change_producer_egress(self):
        for route, (runner, steps, _) in ROUTES.items():
            with self.subTest(route=route):
                body = workflow(steps, runs_on=runner)
                body += ("  report:\n    runs-on: ubuntu-24.04\n    steps:\n" + upload() + "\n")
                self.assertEqual(verdict(egress(run_check(body, policy=FIREWALL))), VERIFIED)

    def test_an_upload_preserves_a_known_key_exposure(self):
        steps = keyed(model_keys=None, env_input="ANTHROPIC_API_KEY") + "\n" + upload()
        result = run_check(workflow(steps))
        controls = {control.id: control.verdict for control in secret_finding(result).controls}
        self.assertEqual(controls["key-out-of-reach"], NOT_MET)

    def test_an_upload_preserves_a_missing_egress_control(self):
        _, agent, _ = ROUTES["firewall"]
        result = run_check(workflow(agent + "\n" + upload()))
        self.assertEqual(verdict(egress(result)), NOT_MET)

    def test_opaque_steps_limit_what_the_checker_can_verify(self):
        unknown = (
            "      - uses: ./.github/actions/report",
            f"      - uses: example/report@{SHA}",
            "      - uses: docker://example/report:1",
            "      - run: ./scripts/report.sh",
        )
        for route, (runner, steps, _) in ROUTES.items():
            for step in unknown:
                with self.subTest(route=route, step=step):
                    body = workflow(steps + "\n" + step, runs_on=runner)
                    result = run_check(body, policy=FIREWALL)
                    self.assertEqual(verdict(egress(result)), CANNOT_TELL)
