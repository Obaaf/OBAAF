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
                    egress_state = next(f.state for f in result.findings if f.rule == "OBAAF-GHA-020")
                    self.assertEqual(egress_state, "fixed" if action_name is None else "cannot-tell")

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

    def test_an_upload_preserves_a_route_condition_that_is_not_met(self):
        """Review of #357 (run `ouzel`): "not met" for a reason inside a route is not improved by an upload."""
        firewall_log = run_check(workflow(ROUTES["firewall"][1] + "\n" + upload(), runs_on="ubuntu-24.04-firewall"),
                                 policy="mode: log\nallow:\n  - api.example.com\n")
        self.assertEqual(verdict(egress(firewall_log)), NOT_MET)
        wide = run_check(workflow(CHECKOUT + "\n" + keyed(allow="github.io") + "\n" + upload()))
        self.assertEqual(verdict(egress(wide)), NOT_MET)

    def test_a_variable_that_makes_a_step_run_unread_code_withholds_credit(self):
        """Review of #357 (run `ouzel`): `NODE_OPTIONS`, the loader's variables, bash's, git's config variables or
        a job container can make an action the list trusts, `echo` or the agent's CLI run code the checker did
        not read; in an action that code holds the token that uploads artifacts."""
        firewall_agent = "      - run: claude -p review"
        cases = {
            "workflow NODE_OPTIONS, checkout": ("action", CHECKOUT + "\n" + keyed(), "", "env: {NODE_OPTIONS: --require ./x.js}"),
            "job LD_PRELOAD, checkout": ("action", CHECKOUT + "\n" + keyed(), "    env: {LD_PRELOAD: ./x.so}", ""),
            "step NODE_OPTIONS on checkout": ("action", f"      - uses: actions/checkout@{SHA}\n"
                                              "        env: {NODE_OPTIONS: --require ./x.js}\n" + keyed(), "", ""),
            "job GIT_CONFIG_COUNT, checkout": ("action", CHECKOUT + "\n" + keyed(), "    env: {GIT_CONFIG_COUNT: '1'}", ""),
            "BASH_ENV on an echo before": ("action", CHECKOUT + "\n      - run: echo prep\n        env: {BASH_ENV: ./bg.sh}\n"
                                           + keyed(), "", ""),
            "BASH_ENV on the agent's step": ("firewall", firewall_agent + "\n        env: {BASH_ENV: ./x.sh}", "", ""),
            "workflow ENV, echo after": ("firewall", firewall_agent + "\n      - run: echo done", "", "env: {ENV: ./x.sh}"),
            "NODE_OPTIONS on the agent's step": ("firewall", firewall_agent + "\n        env: {NODE_OPTIONS: --require ./x.js}",
                                                 "", ""),
        }
        for name, (route, steps, job_extra, top) in cases.items():
            with self.subTest(name):
                runner = ROUTES[route][0]
                result = run_check(workflow(steps, runs_on=runner, job_extra=job_extra, top=top), policy=FIREWALL)
                self.assertEqual(verdict(egress(result)), CANNOT_TELL)
                self.assertIn("can make it run code the checker did not read", egress(result).controls[0].detail)
        plain = {
            "identity names": ("action", CHECKOUT + "\n" + keyed(), "    env: {GIT_AUTHOR_NAME: bot, GIT_COMMITTER_EMAIL: b@x}", ""),
            "NODE_ENV": ("firewall", firewall_agent + "\n        env: {NODE_ENV: production}", "", ""),
        }
        for name, (route, steps, job_extra, top) in plain.items():
            with self.subTest(name):
                runner = ROUTES[route][0]
                result = run_check(workflow(steps, runs_on=runner, job_extra=job_extra, top=top), policy=FIREWALL)
                self.assertEqual(verdict(egress(result)), VERIFIED)

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
                    body = workflow(step + "\n" + steps, runs_on=runner)
                    result = run_check(body, policy=FIREWALL)
                    self.assertEqual(verdict(egress(result)), CANNOT_TELL)
                    self.assertIn("artifact", egress(result).controls[0].detail)
