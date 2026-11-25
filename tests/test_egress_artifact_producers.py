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
    def test_visible_upload_preserves_producer_egress_without_a_consumer(self):
        for route, (runner, steps, baseline_key) in ROUTES.items():
            for action_name in (None, "upload-artifact", "upload-pages-artifact"):
                with self.subTest(route=route, upload=action_name):
                    body = steps if action_name is None else steps + "\n" + upload(action_name)
                    result = run_check(workflow(body, runs_on=runner), policy=FIREWALL)
                    expected = VERIFIED
                    self.assertEqual(verdict(egress(result)), expected)
                    finding = secret_finding(result)
                    controls = {control.id: control.verdict for control in finding.controls}
                    self.assertEqual(controls["egress-enforced"], expected)
                    key = CANNOT_TELL if action_name and route == "action" else baseline_key
                    self.assertEqual(controls["key-out-of-reach"], key)
                    egress_state = next(f.state for f in result.findings if f.rule == "OBAAF-GHA-020")
                    self.assertEqual(egress_state, "fixed")

    def test_only_the_job_that_could_run_downloaded_code_gets_the_finding(self):
        _, steps, _ = ROUTES["action"]
        producer = workflow(steps + "\n" + upload())
        for command, reported in (("cat result/report.txt", False), ("echo ./result/report.txt", False),
                                  ("sh result/report.txt", True), ("sh result/unrelated.sh", False),
                                  ("./elsewhere/report.txt", False)):
            with self.subTest(command=command):
                consumer = ("  read:\n    needs: agent\n    runs-on: ubuntu-24.04\n    steps:\n"
                            f"      - uses: actions/download-artifact@{SHA}\n"
                            "        with: {name: report, path: result}\n"
                            f"      - name: inspect\n        run: {command}\n")
                result = run_check(producer + consumer)
                found = [f for f in result.findings if f.rule == "OBAAF-GHA-027"]
                self.assertEqual([(f.job, f.step) for f in found], [("read", "inspect")] if reported else [])
                self.assertEqual(verdict(egress(result)), VERIFIED)
                self.assertIn("other repositories", egress(result).controls[0].detail)
                unrelated = run_check(producer + consumer.replace("name: report", "name: another"))
                self.assertFalse(any(f.rule == "OBAAF-GHA-027" for f in unrelated.findings))

    def test_build_target_in_downloaded_workspace_is_reported_on_build(self):
        for route, (runner, steps, _) in ROUTES.items():
            with self.subTest(route=route):
                archive = upload().replace("report.txt", "'${{ steps.agent.outputs.workspace }}'")
                producer = workflow(steps + "\n" + archive, runs_on=runner)
                consumer = ("  build:\n    needs: agent\n    runs-on: ubuntu-24.04\n    steps:\n"
                            f"      - uses: actions/download-artifact@{SHA}\n"
                            "        with: {name: report}\n      - run: make test\n")
                checked = run_check(producer + consumer, policy=FIREWALL)
                self.assertEqual(verdict(egress(checked)), VERIFIED)
                found = [f for f in checked.findings if f.rule == "OBAAF-GHA-027"]
                self.assertEqual([(f.job, f.facts["path"]) for f in found], [("build", "Makefile")])

    def test_triggering_run_is_matched_to_its_named_workflow(self):
        _, steps, _ = ROUTES["action"]
        producer = "name: Producer\n" + workflow(steps + "\n" + upload())
        consumer = ("on:\n  workflow_run:\n    workflows: [Producer]\n    types: [completed]\n"
                    "jobs:\n  read:\n    runs-on: ubuntu-24.04\n    steps:\n"
                    f"      - uses: actions/download-artifact@{SHA}\n"
                    "        with:\n          name: report\n          path: result\n"
                    "          run-id: '${{ github.event.workflow_run.id }}'\n"
                    "          github-token: '${{ github.token }}'\n"
                    "      - run: sh result/report.txt\n")
        for subscribed, count in (("Producer", 1), ("Elsewhere", 0)):
            with self.subTest(subscribed=subscribed):
                result = run_check(producer, files={".github/workflows/read.yml": consumer.replace("Producer", subscribed)})
                self.assertEqual(sum(f.rule == "OBAAF-GHA-027" for f in result.findings), count)

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
        """Reviews of #357 (run `ouzel`): `NODE_OPTIONS`, the loader's variables, bash's, git's config variables,
        `TAR_OPTIONS`, a job container or an earlier step can make an action the list trusts, `echo` or the agent's
        CLI run code the checker did not read; in an action that code holds the token that uploads artifacts."""
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
        # The second review of #357: a job container, an earlier step that names GITHUB_PATH before an install, and
        # the `actions/setup-` actions, which start tools that read the repository and variables the checker does not.
        b = "b" * 40
        more = {
            "a job container, action route": ("action", CHECKOUT + "\n" + keyed(), "    container: node:20", "",
                                              "runs in a container, whose image the checker does not read"),
            "a job container, firewall": ("firewall", keyed(), "    container: node:20", "",
                                          "runs in a container, whose image the checker does not read"),
            "an install after a step naming GITHUB_PATH": (
                "action", CHECKOUT + "\n      - run: echo GITHUB_PATH\n      - run: npm install -g @anthropic-ai/claude-code\n"
                + keyed(), "", "", "can make it run code the checker did not read"),
            "setup-go": ("action", CHECKOUT + f"\n      - uses: actions/setup-go@{b}\n" + keyed(), "", "",
                         "uses an action whose implementation may upload an artifact"),
            "setup-node": ("action", CHECKOUT + f"\n      - uses: actions/setup-node@{b}\n" + keyed(), "", "",
                           "uses an action whose implementation may upload an artifact"),
            "XDG_CONFIG_HOME": ("action", CHECKOUT + "\n" + keyed(), "    env: {XDG_CONFIG_HOME: ./cfg}", "",
                                "can make it run code the checker did not read"),
            "TAR_OPTIONS on a cache step": ("action", CHECKOUT + f"\n      - uses: actions/cache@{b}\n"
                                            "        with: {path: deps, key: k}\n        env: {TAR_OPTIONS: --x}\n"
                                            + keyed(), "", "", "can make it run code the checker did not read"),
        }
        for name, (route, steps, job_extra, top, reason) in more.items():
            with self.subTest(name):
                result = run_check(workflow(steps, runs_on=ROUTES[route][0], job_extra=job_extra, top=top), policy=FIREWALL)
                self.assertEqual(verdict(egress(result)), CANNOT_TELL)
                self.assertIn(reason, egress(result).controls[0].detail)
        # The action route's key-out-of-reach too (the commit message of the first review said so).
        steered = workflow(f"      - uses: actions/checkout@{SHA}\n        env: {{NODE_OPTIONS: --require ./x.js}}\n" + keyed())
        controls = {c.id: c.verdict for c in secret_finding(run_check(steered)).controls}
        self.assertEqual((controls["egress-enforced"], controls["key-out-of-reach"]), (CANNOT_TELL, CANNOT_TELL))
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
