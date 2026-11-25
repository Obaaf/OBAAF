"""Slice 2d.2f: pins, egress and declarations.

Two reviewers that did not write them tried to get past the five rules no earlier tranche took:
OBAAF-GHA-008 (an action, reusable workflow or image not pinned), 009 (token permissions not
declared), 020 (an agent job without an egress restriction), 023 (a template placeholder left in) and
OBAAF-CFG-001 (a lane declaration that does nothing). Every way past that the checker did not already
report is a test here; the record of every attempt, including the ones that held, is
docs/bypass-attempts.md.
"""

import json
import unittest

from helpers import TempDir, run_cli
from test_egress_recognised import CHECKOUT, RELEASED, action, catalog, run_check, workflow

from obaaf import checker

SHA = "1111111111111111111111111111111111111111"
DIGEST = "sha256:" + "a" * 64


def check(tmp, text, name="wf.yml", files=None):
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    for old in (root / ".github" / "workflows").iterdir():
        old.unlink()
    (root / ".github" / "workflows" / name).write_text(text, encoding="utf-8")
    for rel, body in (files or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return checker.check(root)


def of(result, rule):
    return [f for f in result.findings if f.rule == rule]


def kinds(result, rule):
    return sorted((f.severity, f.kind) for f in of(result, rule))


def job(steps="      - run: echo hi\n", extra="", on="push", top="permissions: {}\n"):
    return f"on: {on}\n{top}jobs:\n  build:\n    runs-on: ubuntu-latest\n{extra}    steps:\n{steps}"


class PinnedTest(unittest.TestCase):
    """OBAAF-GHA-008: what counts as a pin."""

    def test_only_forty_lower_case_hex_digits_pin_an_action(self):
        # github.com has no SHA-256 repositories, so a 64-digit ref is a tag or a branch that can move.
        cases = {"a" * 64: True, "a" * 40: False, "a" * 40 + "\n": True, "A" * 40: True, "a" * 39: True}
        for ref, reported in cases.items():
            with self.subTest(ref=ref), TempDir() as tmp:
                result = check(tmp, job(f"      - uses: {json.dumps('some/action@' + ref)}\n"))
                self.assertEqual(bool(of(result, "OBAAF-GHA-008")), reported)

    def test_a_64_digit_ref_on_a_reusable_workflow_is_reported(self):
        with TempDir() as tmp:
            result = check(tmp, "on: push\npermissions: {}\njobs:\n  call:\n"
                                f"    uses: some/repo/.github/workflows/x.yml@{'b' * 64}\n")
        self.assertEqual(kinds(result, "OBAAF-GHA-008"), [("low", "reusable-workflow")])

    def test_a_self_repository_reference_has_nothing_to_pin(self):
        # `$/path` is the workflow's own repository at the running commit (GitHub, 2026-07-30).
        with TempDir() as tmp:
            steps = check(tmp, job("      - uses: $/.github/actions/build\n"))
            called = check(tmp, "on: push\npermissions: {}\njobs:\n  call:\n    uses: $/.github/workflows/x.yml\n")
        self.assertEqual(of(steps, "OBAAF-GHA-008"), [])
        self.assertEqual(of(called, "OBAAF-GHA-008"), [])

    def test_a_docker_reference_is_pinned_only_by_a_full_sha256_digest_at_its_end(self):
        cases = {f"docker://alpine@{DIGEST}": False, "docker://alpine@sha256:abc": True,
                 f"docker://alpine@{DIGEST}x": True, f"Docker://alpine@{DIGEST}": False,
                 "Docker://alpine:3": True}
        for uses, reported in cases.items():
            with self.subTest(uses=uses), TempDir() as tmp:
                result = check(tmp, job(f"      - uses: {uses}\n"))
                self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-008")], ["container"] if reported else [])


class ImageTest(unittest.TestCase):
    """OBAAF-GHA-008: every image the job runs is read, and one the checker cannot read is said so."""

    def test_an_image_computed_when_the_job_runs_is_cannot_tell(self):
        for image in ("${{ vars.IMAGE }}", "node:${{ matrix.v }}", "ghcr.io/x/y:latest${{ '' }}",
                      "${{ matrix.image || 'node:20' }}"):
            for form in (f"    container: {json.dumps(image)}\n",
                         f"    container:\n      image: {json.dumps(image)}\n",
                         f"    services:\n      db:\n        image: {json.dumps(image)}\n"):
                with self.subTest(image=image, form=form), TempDir() as tmp:
                    result = check(tmp, job(extra=form + "    strategy:\n      matrix:\n        v: ['20']\n"))
                    self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-008")], ["image-expression"])

    def test_a_matrix_written_out_in_the_file_is_read_value_by_value(self):
        matrix = f"    strategy:\n      matrix:\n        image: ['node@{DIGEST}', 'node:20']\n"
        with TempDir() as tmp:
            result = check(tmp, job(extra=matrix + "    container: ${{ matrix.image }}\n"))
            pinned = check(tmp, job(extra=f"    strategy:\n      matrix:\n        image: ['node@{DIGEST}']\n"
                                          "    container: ${{ matrix.image }}\n"))
        self.assertEqual([(f.kind, f.facts["image"]) for f in of(result, "OBAAF-GHA-008")], [("image", "node:20")])
        self.assertEqual(of(pinned, "OBAAF-GHA-008"), [])

    def test_forms_the_checker_does_not_read_are_not_taken_for_no_image(self):
        forms = {
            "a service written as text": ("    services:\n      db: postgres:16\n", "image"),
            "services as a list": ("    services:\n      - postgres:16\n", "image-unreadable"),
            "Image in another case": ("    container:\n      Image: node:20\n", "image-unreadable"),
            "Container in another case": ("    Container: node:20\n", "image-unreadable"),
            "Services in another case": ("    Services:\n      db:\n        image: postgres\n", "image-unreadable"),
            "a number": ("    container: 18\n", "image-unreadable"),
            "a huge number": ("    container: 0x" + "f" * 4000 + "\n", "image-unreadable"),
        }
        for name, (extra, kind) in forms.items():
            with self.subTest(name), TempDir() as tmp:
                result = check(tmp, job(extra=extra))
                self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-008")], [kind])

    def test_an_empty_image_is_no_container(self):
        matrix = (f"    strategy:\n      matrix:\n        include: [{{container: ''}}, {{container: 'fedora@{DIGEST}'}}]\n"
                  "    container: ${{ matrix.container }}\n")
        with TempDir() as tmp:
            result = check(tmp, job(extra=matrix))
            literal = check(tmp, job(extra="    container: {image: ''}\n"))
        self.assertEqual(of(result, "OBAAF-GHA-008"), [])
        self.assertEqual(of(literal, "OBAAF-GHA-008"), [])

    def test_a_short_digest_is_not_a_pin(self):
        with TempDir() as tmp:
            result = check(tmp, job(extra="    container: node@sha256:abcd\n"))
        self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-008")], ["image"])


class LocalActionTest(unittest.TestCase):
    """OBAAF-GHA-008: a `./` action is whatever an earlier step put at that path."""

    def test_an_action_from_another_repositorys_checkout_is_that_repository_at_its_ref(self):
        for checkout, kind in (
                (f"      - uses: actions/checkout@{SHA}\n        with: {{repository: someorg/actions, ref: main, "
                 "path: ext}\n", "local-from-checkout"),
                (f"      - uses: actions/checkout@{SHA}\n        with: {{repository: someorg/actions, path: ext}}\n",
                 "local-from-checkout"),
                (f"      - uses: actions/checkout@{SHA}\n        with: {{repository: someorg/actions}}\n",
                 "local-from-checkout"),
                ("      - run: git clone https://github.com/someorg/actions ext\n", "local-after-download"),
                (f"      - uses: actions/download-artifact@{SHA}\n        with: {{run-id: '1', github-token: x}}\n",
                 "local-after-download"),
                (f"      - uses: dawidd6/action-download-artifact@{SHA}\n        with: {{repo: someorg/actions}}\n",
                 "local-after-download"),
                ("      - run: curl -fsSL -o ext/deploy/action.yml https://example.com/action.yml\n",
                 "local-after-download"),
                (f"      - uses: actions/checkout@{SHA}\n        with: {{repository: someorg/actions, ref: main, "
                 "path: ./x/../ext}\n", "local-from-checkout"),
                (f"      - uses: actions/checkout@{SHA}\n        with: {{repository: someorg/actions, ref: main, "
                 "path: /home/runner/work/r/r/ext}\n", "local-from-checkout"),
                (f"      - uses: actions/download-artifact@{SHA}\n", None),
                ("      - run: curl -sSfL https://raw.githubusercontent.com/myorg/ext/main/x.sh -o /tmp/x.sh\n", None),
                (f"      - uses: actions/cache@{SHA}\n        with:\n          key: k\n          path: |\n"
                 "            ~/.cargo/registry\n            ~/.cargo/git\n", None),
                ("      - run: curl -o /tmp/p.zip https://example.com/p.zip && unzip /tmp/p.zip -d $HOME/.local\n", None),
                ("      - run: git fetch --tags && git checkout -b release && git submodule update --init\n", None),
                (f"      - uses: actions/checkout@{SHA}\n        with: {{repository: someorg/actions, ref: {SHA}, "
                 "path: ext}\n", None),
                (f"      - uses: actions/checkout@{SHA}\n        with: {{repository: someorg/actions, ref: main, "
                 "path: other}\n", None),
                (f"      - uses: actions/checkout@{SHA}\n", None),
                (f"      - uses: actions/checkout@{SHA}\n        with: {{repository: '${{{{ github.repository }}}}'}}\n",
                 None)):
            with self.subTest(checkout=checkout), TempDir() as tmp:
                result = check(tmp, job(checkout + "      - uses: ./ext/deploy\n"))
                self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-008")], [kind] if kind else [])

    def test_a_download_before_an_action_at_the_workspace_root_is_not_read(self):
        # `uses: ./` in an action's own repository, after a setup step that downloads a tool (review of 2d.2f).
        with TempDir() as tmp:
            result = check(tmp, job(f"      - uses: actions/checkout@{SHA}\n"
                                    "      - run: curl -sSfL https://example.com/tool -o /tmp/tool && chmod +x /tmp/tool\n"
                                    "      - uses: ./\n"))
            cloned = [check(tmp, job(f"      - run: {clone}\n      - uses: ./ext/deploy\n"))
                      for clone in ("git clone https://github.com/someorg/ext", "git clone --depth 1 https://x.org/o/ext",
                                    "git clone -b main https://github.com/someorg/ext.git", "gh repo clone someorg/ext")]
            lint = check(tmp, job("      - run: curl -sSfL https://x.org/install.sh | sh -s -- -b /usr/local/bin && "
                                  "golangci-lint run --config .github/golangci.yml\n      - uses: ./.github/actions/report\n"))
        self.assertEqual(of(result, "OBAAF-GHA-008"), [])
        self.assertEqual([[f.kind for f in of(r, "OBAAF-GHA-008")] for r in cloned], [["local-after-download"]] * 4)
        self.assertEqual(of(lint, "OBAAF-GHA-008"), [])

    def test_a_path_with_dots_in_the_action_is_resolved(self):
        steps = (f"      - uses: actions/checkout@{SHA}\n      - uses: actions/checkout@{SHA}\n"
                 "        with: {repository: someorg/actions, ref: main, path: ext}\n"
                 "      - uses: ./.github/../ext/deploy\n")
        with TempDir() as tmp:
            result = check(tmp, job(steps))
        self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-008")], ["local-from-checkout"])

    def test_the_facts_name_the_repository_and_the_ref(self):
        with TempDir() as tmp:
            result = check(tmp, job(f"      - uses: actions/checkout@{SHA}\n        with: {{repository: someorg/actions, "
                                    "ref: main, path: ext}\n      - uses: ./ext/deploy\n"))
        facts = of(result, "OBAAF-GHA-008")[0].facts
        self.assertEqual((facts["repository"], facts["ref"]), ("someorg/actions", "main"))


class SeverityTest(unittest.TestCase):
    def test_a_called_workflow_is_never_low(self):
        # Its triggers are its callers', which the file does not show (a caller on pull_request_target
        # made the called job low before).
        with TempDir() as tmp:
            result = check(tmp, job("      - uses: some/action@v1\n", on="workflow_call",
                                    top="permissions: {contents: read}\n"))
            plain = check(tmp, job("      - uses: some/action@v1\n", top="permissions: {contents: read}\n"))
        self.assertEqual(kinds(result, "OBAAF-GHA-008"), [("medium", "action")])
        self.assertEqual(kinds(plain, "OBAAF-GHA-008"), [("low", "action")])


class FileFormTest(unittest.TestCase):
    """Shared by every rule: what is found and how it is read."""

    def test_job_ids_that_this_reader_takes_for_other_values_are_both_checked_and_an_error(self):
        for first, second in (("null", "None"), ("true", "'True'"), ("1", "'1'")):
            text = (f"on: push\npermissions: {{}}\njobs:\n  {first}:\n    runs-on: ubuntu-latest\n    steps:\n"
                    f"      - uses: some/action@v1\n  {second}:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - uses: other/action@v2\n")
            with self.subTest(first=first), TempDir() as tmp:
                result = check(tmp, text)
                self.assertEqual(sorted(f.facts["uses"] for f in of(result, "OBAAF-GHA-008")),
                                 ["other/action@v2", "some/action@v1"])
                self.assertTrue(any("job id written as" in e for e in result.errors), result.errors)

    def test_a_merge_key_is_an_error(self):
        with TempDir() as tmp:
            result = check(tmp, "<<:\n  permissions: {}\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                                "    steps:\n      - run: echo hi\n")
        self.assertTrue(any("merge key" in e for e in result.errors), result.errors)

    def test_workflow_files_are_found_in_any_letter_case_and_with_no_name_before_the_extension(self):
        for name in ("wf.YML", "wf.Yaml", ".yml", ".yaml"):
            with self.subTest(name=name), TempDir() as tmp:
                result = check(tmp, job("      - uses: some/action@v1\n"), name=name)
                self.assertEqual(len(of(result, "OBAAF-GHA-008")), 1)

    def test_a_uses_that_is_not_text_is_an_error_not_a_traceback(self):
        for uses in ("18", "0x" + "f" * 4000, "[a, b]"):
            with self.subTest(uses=uses[:10]), TempDir() as tmp:
                steps = check(tmp, job(f"      - uses: {uses}\n"))
                called = check(tmp, f"on: push\npermissions: {{}}\njobs:\n  call:\n    uses: {uses}\n")
                self.assertTrue(any("uses written as" in e for e in steps.errors), steps.errors)
                self.assertTrue(any("uses written as" in e for e in called.errors), called.errors)


class PlaceholderTest(unittest.TestCase):
    """OBAAF-GHA-023 reads values as YAML gives them, one finding for each placeholder."""

    def test_an_escaped_placeholder_is_the_placeholder_it_spells(self):
        zeros = "0" * 40
        for uses in ('"OBAAF\\x5FOWNER/obaaf/actions/setup-obaaf@v1"', '"OBAAF\\u005FOWNER/obaaf/a@v1"',
                     '"OBAAF_\\\n  OWNER/obaaf/a@v1"', f'"x/y@\\x30{zeros[1:]}"', f'"x/y\\x40{zeros}"',
                     "obaaf_owner/obaaf/a@v1", f'"x/y@{zeros[:20]}\\\n  {zeros[20:]}"'):
            with self.subTest(uses=uses), TempDir() as tmp:
                result = check(tmp, job(f"      - uses: {uses}\n"))
                self.assertEqual(len(of(result, "OBAAF-GHA-023")), 1)

    def test_a_comment_and_a_longer_run_of_zeros_are_not_placeholders(self):
        with TempDir() as tmp:
            comment = check(tmp, job(f"      - uses: some/action@{SHA} # replace OBAAF_OWNER\n"))
            longer = check(tmp, job(f"      - uses: some/action@{'0' * 41}\n"))
        self.assertEqual(of(comment, "OBAAF-GHA-023"), [])
        self.assertEqual(of(longer, "OBAAF-GHA-023"), [])

    def test_a_placeholder_in_a_key_and_its_value_is_one_finding(self):
        with TempDir() as tmp:
            result = check(tmp, job("      - uses: some/a@v1\n        with: {OBAAF_OWNER: OBAAF_OWNER}\n"))
        self.assertEqual(len(of(result, "OBAAF-GHA-023")), 1)

    def test_each_placeholder_is_its_own_finding_named_by_where_it_is(self):
        zeros = "0" * 40
        with TempDir() as tmp:
            result = check(tmp, job(f"      - run: echo OBAAF_OWNER\n      - uses: OBAAF_OWNER/obaaf/a@{zeros}\n"))
        found = sorted((f.facts["where"], f.facts["placeholder"], f.step) for f in of(result, "OBAAF-GHA-023"))
        self.assertEqual(found, [("steps[0].run", "OBAAF_OWNER", "step 1"),
                                 ("steps[1].uses", zeros, f"OBAAF_OWNER/obaaf/a@{zeros}"),
                                 ("steps[1].uses", "OBAAF_OWNER", f"OBAAF_OWNER/obaaf/a@{zeros}")])

    def test_an_acceptance_of_one_placeholder_does_not_cover_another(self):
        harmless = job("      - run: echo OBAAF_OWNER\n")
        risky = job("      - run: echo OBAAF_OWNER\n      - name: setup\n        uses: OBAAF_OWNER/obaaf/a@v1\n")
        with TempDir() as tmp:
            check(tmp, harmless)
            root = tmp / "repo"
            code, _, err = run_cli("check", root, "--write-baseline", root / "b.json", "--owner", "@example",
                                   "--reason", "template kept for the docs", "--expires", "2026-12-31")
            # 1: the fixture has no CODEOWNERS, a medium finding no entry can accept (slice 3.2b).
            self.assertEqual(code, 1, err)
            self.assertIn("not written: medium OBAAF-REPO-001", err)
            check(tmp, risky)
            code, out, _ = run_cli("check", root, "--baseline", root / "b.json", "--format", "json")
        states = sorted((f["facts"]["where"], f["state"]) for f in json.loads(out)["findings"]
                        if f["rule"] == "OBAAF-GHA-023")
        self.assertEqual(states, [("steps[0].run", "accepted"), ("steps[1].uses", "new")])


class FirewallPolicyTest(unittest.TestCase):
    """OBAAF-GHA-020 under GitHub's native firewall."""

    def firewall(self, policy, runs_on="ubuntu-24.04-firewall"):
        # No action in the job: since the review of #357 a script beside an action is "cannot tell" on this route
        # (`test_an_action_beside_a_script_is_cannot_tell`), which would hide what these tests are about.
        return run_check(workflow("      - run: claude -p 'review'", runs_on=runs_on), policy=policy)

    @staticmethod
    def verdict(result):
        f = [f for f in result.findings if f.rule == "OBAAF-GHA-020"][0]
        return [c for c in f.controls if c.name == "egress"][0].verdict if any(
            c.name == "egress" for c in f.controls) else f.controls[-1].verdict

    def test_a_key_the_readme_does_not_describe_is_cannot_tell(self):
        for policy in ("mode: enforce\nMODE: log\nallow: [api.example.com]\n",
                       "mode: enforce\nallow: [api.example.com]\nAllow: [example.org]\n",
                       "mode: enforce\nallow: [api.example.com]\nallow-ips: [0.0.0.0/0]\n",
                       "mode: enforce\nallow: [api.example.com]\noverrides: {}\n"):
            with self.subTest(policy=policy):
                result = self.firewall(policy)
                f = [f for f in result.findings if f.rule == "OBAAF-GHA-020"][0]
                self.assertEqual(f.state, "cannot-tell")

    def test_the_label_written_twice_is_the_firewall(self):
        result = self.firewall("mode: enforce\nallow: [api.example.com]\n",
                               runs_on="[ubuntu-24.04-firewall, ubuntu-24.04-firewall]")
        f = [f for f in result.findings if f.rule == "OBAAF-GHA-020"][0]
        self.assertEqual(f.state, "fixed")

    def test_the_external_firewall_covers_actions_beside_agent_scripts(self):
        policy = "mode: enforce\nallow: [api.example.com]\n"
        b = "b" * 40
        agent = "      - run: claude -p 'review'"
        download = f"      - uses: actions/download-artifact@{b}"
        cache = f"      - uses: actions/cache/restore@{b}\n        with: {{path: x, key: k}}"
        for steps in (CHECKOUT + "\n" + agent, agent + "\n" + CHECKOUT, agent + "\n" + download,
                      download + "\n" + agent, cache + "\n" + agent, CHECKOUT + "\n      - run: echo hello\n" + agent):
            with self.subTest(steps=steps):
                result = run_check(workflow(steps, runs_on="ubuntu-24.04-firewall"), policy=policy)
                finding = next(f for f in result.findings if f.rule == "OBAAF-GHA-020")
                self.assertEqual(finding.state, "fixed")
                self.assertIn("producing job", finding.controls[-1].detail)

    def test_a_cleared_finding_names_the_defaults_and_that_the_label_is_taken_at_its_word(self):
        result = self.firewall("mode: enforce\nallow: [api.example.com]\n")
        f = [f for f in result.findings if f.rule == "OBAAF-GHA-020"][0]
        detail = " ".join(c.detail for c in f.controls)
        self.assertIn("github.com, codeload.github.com", detail)
        self.assertIn("taken at its label", detail)


class AgentFoundTest(unittest.TestCase):
    """An agent command anywhere a step runs one puts the job in the agent lane (OBAAF-GHA-020 and the
    other agent rules apply)."""

    def test_an_agent_given_to_any_action_or_spelt_with_quotes_is_an_agent(self):
        steps = {
            "a fork of the egress action": "      - uses: someone/obaaf/actions/egress@" + RELEASED +
                                           "\n        with: {allow: api.example.com, run: claude -p hi}\n",
            "another action's input": f"      - uses: some/run-action@{SHA}\n        with: {{command: claude -p hi}}\n",
            "docker args": f"      - uses: docker://node@{'sha256:' + 'a' * 64}\n        with: {{args: claude -p hi}}\n",
            "quoted": "      - run: cl''aude -p hi\n",
            "backslash": "      - run: cl\\aude -p hi\n",
        }
        for name, body in steps.items():
            with self.subTest(name), TempDir() as tmp:
                result = check(tmp, job(body))
                self.assertEqual([f.rule for f in result.findings if f.rule == "OBAAF-GHA-020"], ["OBAAF-GHA-020"])


    def test_free_text_in_an_input_is_not_an_agent(self):
        steps = {
            "a French comment": f"      - uses: peter-evans/create-or-update-comment@{SHA}\n"
                                "        with: {body: 'Merci ! Un mainteneur va vous aider bientôt.'}\n",
            "release notes": f"      - uses: softprops/action-gh-release@{SHA}\n"
                             "        with: {body: 'Use with cline or aider out of the box'}\n",
        }
        for name, body in steps.items():
            with self.subTest(name), TempDir() as tmp:
                result = check(tmp, job(body))
                self.assertEqual(of(result, "OBAAF-GHA-020"), [])

    def test_an_agent_behind_a_shell_or_a_wrapper_with_options(self):
        cases = {
            "bash -c": f"      - uses: some/run-action@{SHA}\n        with: {{command: 'bash -c \"claude -p triage\"'}}\n",
            "sh -lc in docker": (f"      - uses: docker://node@sha256:{'a' * 64}\n"
                                 "        with: {entrypoint: /bin/sh, args: '-lc \"npx -y @anthropic-ai/claude-code -p t\"'}\n"),
            "env value with bash -c": "      - run: $AGENT\n        env: {AGENT: \"bash -c 'claude -p triage'\"}\n",
            "sudo -u": f"      - uses: some/run-action@{SHA}\n        with: {{command: sudo -u runner claude -p triage}}\n",
            "nice -n": f"      - uses: some/run-action@{SHA}\n        with: {{command: nice -n 10 claude -p triage}}\n",
            "timeout -s": f"      - uses: some/run-action@{SHA}\n        with: {{command: timeout -s KILL 5m claude -p t}}\n",
            "the command in env, its options in run": "      - run: $AGENT -p triage\n        env: {AGENT: claude}\n",
        }
        for name, body in cases.items():
            with self.subTest(name), TempDir() as tmp:
                result = check(tmp, job(body))
                self.assertEqual(len(of(result, "OBAAF-GHA-020")), 1)

    def test_prose_in_an_env_value_is_not_an_agent(self):
        for body in ('      - run: echo "$MESSAGE"\n        env: {MESSAGE: "Merci de nous aider à tester cette version."}\n',
                     '      - run: gh release create v1 --notes "$NOTES"\n        env: {NOTES: "Now works with aider and cline."}\n'):
            with self.subTest(body=body), TempDir() as tmp:
                result = check(tmp, job(body))
                self.assertEqual(of(result, "OBAAF-GHA-020"), [])

    def test_an_agent_as_the_shell_or_in_an_env_value(self):
        cases = {
            "shell": ("      - run: review\n        shell: claude -p {0}\n", ""),
            "default shell": ("      - run: review\n", "    defaults:\n      run:\n        shell: npx -y @anthropic-ai/claude-code -p {0}\n"),
            "env value": ("      - run: $AGENT triage\n        env: {AGENT: claude -p}\n", ""),
        }
        for name, (body, extra) in cases.items():
            with self.subTest(name), TempDir() as tmp:
                result = check(tmp, job(body, extra=extra))
                self.assertEqual(len(of(result, "OBAAF-GHA-020")), 1)


class EgressActionTest(unittest.TestCase):
    """OBAAF-GHA-020 under OBAAF's egress action: what may run after it, and what it cannot see."""

    def state(self, steps, job_extra="", top=""):
        result = run_check(workflow(steps, job_extra=job_extra, top=top))
        return [f for f in result.findings if f.rule == "OBAAF-GHA-020"][0].state

    def test_the_plain_form_clears(self):
        self.assertEqual(self.state(CHECKOUT + "\n" + action()), "fixed")

    def test_uploads_after_confinement_preserve_credit_and_invalid_paths_stay_untrusted(self):
        for uses in ("actions/upload-artifact//x@v4", "actions/upload-artifact/./x@v4"):
            with self.subTest(uses=uses):
                after = f"\n      - uses: {uses}\n        with: {{name: out, path: out}}"
                self.assertEqual(self.state(CHECKOUT + "\n" + action() + after), "cannot-tell")
        # Flagship slice 2d.11 (from its review): a path that climbs out of upload-artifact's repository can
        # reach any action the runner downloaded for the job, so it is an agent outside the confined command.
        after = "\n      - uses: actions/upload-artifact/../../../evil/act/v1@v4\n        with: {name: out, path: out}"
        self.assertEqual(self.state(CHECKOUT + "\n" + action() + after), "new")
        after = "\n      - uses: actions/upload-artifact@v4\n        with: {name: out, path: out}"
        self.assertEqual(self.state(CHECKOUT + "\n" + action() + after), "fixed")

    def test_a_cache_or_earlier_step_that_may_reach_the_scratch_directory_by_a_pattern(self):
        for path in ("/t[m]p/obaaf-e*", "/t?p/*", "/*/obaaf*", "$(dirname $(mktemp -u))/obaaf-e*", "//tmp/x"):
            with self.subTest(path=path):
                cache = f"      - uses: actions/cache@{RELEASED}\n        with: {{path: {json.dumps(path)}, key: k}}\n"
                self.assertEqual(self.state(CHECKOUT + "\n" + cache + action()), "new")

    def test_a_process_left_running_by_an_earlier_step(self):
        for script in ("pm2 start relay.js", "ssh -fN -L 9000:x:443 host", "sudo -b ./relay",
                       "python3 -c 'import os; os.fork()'", "systemctl start relay", "dockerd"):
            with self.subTest(script=script):
                before = f"      - run: {json.dumps(script)}\n"
                self.assertEqual(self.state(CHECKOUT + "\n" + before + action()), "cannot-tell")

    def test_a_credential_by_a_route_that_is_not_a_secret(self):
        for given in ("${{ vars.ANTHROPIC_API_KEY }}", "${{ needs.k.outputs.token }}", "${{ toJSON(vars) }}"):
            with self.subTest(given=given):
                before = f"      - run: curl https://api.anthropic.com\n        env: {{K: {json.dumps(given)}}}\n"
                self.assertEqual(self.state(CHECKOUT + "\n" + before + action()), "cannot-tell")

    def test_an_agent_before_it_in_a_docker_step(self):
        before = (f"      - uses: docker://node@sha256:{'a' * 64}\n"
                  "        with: {entrypoint: npx, args: --yes @anthropic-ai/claude-code -p triage}\n")
        self.assertEqual(self.state(CHECKOUT + "\n" + before + action()), "new")

    def test_an_agent_before_it_spelt_with_a_backslash(self):
        before = "      - run: cl\\aude -p triage\n"
        self.assertEqual(self.state(CHECKOUT + "\n" + before + action()), "new")


class DeclarationTest(unittest.TestCase):
    """OBAAF-CFG-001: the lane variable in any spelling, anywhere it is not read."""

    def idle(self, result):
        return sorted((f.kind, f.severity) for f in of(result, "OBAAF-CFG-001"))

    def test_other_spellings_of_the_variable(self):
        for name in ("OBAAF​_LANE", "ОBAAF_LANE", "OBAAFLANE", "OBAAF.LANE", "OBAAF_LANES", "OBAAF_LANE_",
                     "obaaf lane", "0BAAF_LANE"):
            with self.subTest(name=name), TempDir() as tmp:
                result = check(tmp, job(extra=f"    env:\n      {json.dumps(name)}: agent\n"))
                self.assertEqual(self.idle(result), [("job-misnamed", "high")])
        for name in ("MY_OBAAF_LANE", "LANE", "OBAAF_STEP", "OBAAF_EGRESS"):
            with self.subTest(name=name), TempDir() as tmp:
                result = check(tmp, job(extra=f"    env:\n      {name}: agent\n"))
                self.assertEqual(self.idle(result), [])

    def test_declarations_where_they_are_not_read(self):
        cases = {
            "another spelling in a step's env": "      - run: echo\n        env: {obaaf_lane: agent}\n",
            "a step's with": f"      - uses: some/a@{SHA}\n        with: {{OBAAF_LANE: agent}}\n",
            "a script writes it to GITHUB_ENV": "      - run: echo OBAAF_LANE=agent >> \"$GITHUB_ENV\"\n",
        }
        for name, steps in cases.items():
            with self.subTest(name), TempDir() as tmp:
                result = check(tmp, job(steps))
                self.assertEqual(self.idle(result), [("elsewhere", "high")])
        for name, extra in {"the matrix": "    strategy:\n      matrix:\n        OBAAF_LANE: [agent]\n",
                            "an env written as one expression": "    env: ${{ fromJSON('{\"OBAAF_LANE\":\"agent\"}') }}\n"}.items():
            with self.subTest(name), TempDir() as tmp:
                result = check(tmp, job(extra=extra))
                self.assertEqual(self.idle(result), [("elsewhere", "high")])

    def test_an_input_definition_named_like_it_is_not_a_declaration(self):
        text = ("on:\n  workflow_dispatch:\n    inputs:\n      OBAAF_LANE: {type: string}\npermissions: {}\n"
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        with TempDir() as tmp:
            self.assertEqual(self.idle(check(tmp, text)), [])

    def test_two_configurations_or_one_where_the_checker_does_not_look_is_an_error(self):
        for files in ({".github/obaaf.yml": "lanes: {}\n", "obaaf.yml": "lanes: {}\n"},
                      {".github/obaaf.yml": "lanes: {}\n", ".github/obaaf.yaml": "lanes: {}\n"},
                      {".obaaf.yml": "lanes: {}\n"}, {"OBAAF.yml": "lanes: {}\n"}):
            with self.subTest(files=sorted(files)), TempDir() as tmp:
                with self.assertRaises(checker.ConfigError):
                    check(tmp, job(), files=files)

    def test_jenkins_spellings_and_a_scripted_assignment(self):
        jenkinsfile = ("pipeline {\n  agent any\n  environment { obaaf_lane = 'agent' }\n  stages {\n"
                       "    stage('Fix') {\n      steps {\n        script { env.OBAAF_LANE = 'agent' }\n"
                       "        withEnv(['OBAAF-LANE=agent']) { sh 'make' }\n      }\n    }\n  }\n}\n")
        with TempDir() as tmp:
            (tmp / "Jenkinsfile").write_text(jenkinsfile, encoding="utf-8")
            result = checker.check(tmp)
        self.assertEqual(self.idle(result), [("jenkins-misnamed", "high"), ("jenkins-misnamed", "high"),
                                             ("jenkins-scripted", "high")])


if __name__ == "__main__":
    unittest.main()
