"""Slice 2d.2b: what a job can reach.

Two reviewers that did not write the rules tried to get past the six that depend on which secrets
and which token permissions a job gets: OBAAF-GHA-001, 003, 004, 005, 018 and 024. Every way past
them that the checker did not already report is a test here; the record of every attempt, including
the ones that held, is docs/bypass-attempts.md.
"""

import unittest

from helpers import TempDir

from obaaf import checker

SHA = "1111111111111111111111111111111111111111"
AGENT = "      - uses: anthropics/claude-code-action@" + SHA + "\n"


def check(tmp, text, name="wf.yml", config=None, extra=None):
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows" / name).write_text(text, encoding="utf-8")
    for other, body in (extra or {}).items():
        (root / ".github" / "workflows" / other).write_text(body, encoding="utf-8")
    return checker.check(root, config=config)


def of(result, rule, path=None):
    return [f for f in result.findings if f.rule == rule and (path is None or f.path.endswith(path))]


def agent_workflow(top="", job="", on="issues"):
    return (f"on: {on}\n{top}jobs:\n  a:\n    runs-on: ubuntu-latest\n{job}    steps:\n" + AGENT)


class PermissionsAreReadTheWideWayTest(unittest.TestCase):
    """A permissions value written in a form GitHub does not document was read as no permissions at
    all, with no word: `Write-All`, `write`, `contents: WRITE`, `contents: " write"`, `ID-TOKEN: write`,
    an expression. Now it is a problem of the file, which fails the check, and the rules read it as
    the widest grant it could be."""

    def test_undocumented_spellings_fail_the_check_and_count_as_write(self):
        cases = {
            "permissions: Write-All\n": ("write-all", True),
            "permissions: write\n": ("write-all", True),
            "permissions: \"${{ fromJSON('\\\"write-all\\\"') }}\"\n": ("write-all", True),
            "permissions:\n  contents: WRITE\n": ("contents", False),
            "permissions:\n  contents: ' write'\n": ("contents", False),
            "permissions:\n  Contents: write\n": ("Contents", False),
            "permissions:\n  id-token: Write\n": (None, True),
            "permissions:\n  ID-TOKEN: write\n": (None, True),
            "permissions: 7\n": ("write-all", True),
            "permissions:\n  contents: 0x" + "f" * 4000 + "\n": ("write-all", True),
        }
        with TempDir() as tmp:
            for top, (scope, oidc) in cases.items():
                with self.subTest(top=top[:40]):
                    result = check(tmp, agent_workflow(top=top))
                    self.assertTrue(result.errors, "an undocumented permissions value must fail the check")
                    self.assertIn("permission", result.errors[0])
                    write = of(result, "OBAAF-GHA-003")
                    if scope is None:
                        self.assertEqual(write, [])
                    else:
                        self.assertEqual([(f.kind, scope in f.facts["scopes"]) for f in write], [("write", True)])
                    self.assertEqual(bool(of(result, "OBAAF-GHA-004")), oidc)

    def test_documented_spellings_are_no_problem(self):
        with TempDir() as tmp:
            for top in ("permissions: read-all\n", "permissions: {}\n", "permissions:\n  contents: read\n"
                        "  id-token: none\n  pull-requests: write\n  copilot-requests: write\n"):
                with self.subTest(top=top):
                    self.assertEqual(check(tmp, agent_workflow(top=top)).errors, [])

    def test_a_job_permissions_key_with_no_value_does_not_hide_the_workflows(self):
        with TempDir() as tmp:
            result = check(tmp, agent_workflow(top="permissions: write-all\n", job="    permissions:\n"))
            self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-003")], ["write"])
            self.assertEqual(len(of(result, "OBAAF-GHA-004")), 1)
            result = check(tmp, agent_workflow(top="permissions:\n"))
            self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-003")], ["undeclared"])
            self.assertEqual(len(of(result, "OBAAF-GHA-009")), 1)


class CalledWorkflowsHoldWhatTheCallerGrantsTest(unittest.TestCase):
    """A workflow another can call (`workflow_call`) and that declares nothing holds the calling
    job's token. OBAAF-GHA-003 said only "may inherit write access", as for any undeclared job, and
    OBAAF-GHA-004 said nothing, though the caller can grant `id-token: write`."""

    CALLED = "on: workflow_call\njobs:\n  agent:\n    runs-on: ubuntu-latest\n    steps:\n" + AGENT
    CALLER = ("on: issues\npermissions: {}\njobs:\n  call:\n    permissions:\n      contents: write\n"
              "      id-token: write\n    uses: ./.github/workflows/agent.yml\n")

    def test_an_undeclared_called_agent_job_is_reported_as_inheriting(self):
        with TempDir() as tmp:
            result = check(tmp, self.CALLED, name="agent.yml", extra={"caller.yml": self.CALLER})
            self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-003", "agent.yml")], ["inherited"])
            self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-004", "agent.yml")], ["inherited"])
            self.assertIn("calling job", of(result, "OBAAF-GHA-009", "agent.yml")[0].message)

    def test_a_called_workflow_that_declares_its_permissions_is_read_as_declared(self):
        with TempDir() as tmp:
            text = self.CALLED.replace("jobs:", "permissions:\n  contents: read\njobs:")
            result = check(tmp, text, name="agent.yml")
            self.assertEqual(of(result, "OBAAF-GHA-003"), [])
            self.assertEqual(of(result, "OBAAF-GHA-004"), [])

    def test_a_workflow_nothing_can_call_is_as_before(self):
        with TempDir() as tmp:
            result = check(tmp, agent_workflow())
            self.assertEqual([f.kind for f in of(result, "OBAAF-GHA-003")], ["undeclared"])
            self.assertEqual(of(result, "OBAAF-GHA-004"), [])


class AnEnvironmentLowersGha001OnlyWhenNamedTest(unittest.TestCase):
    """Any `environment:` made OBAAF-GHA-001 medium on pull_request_target, including a name built
    from an expression, which GitHub creates on first use with no protection rules, or one the
    pull request's author picks (`github.event.pull_request.head.ref`)."""

    def wf(self, environment):
        return ("on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                f"    environment: {environment}\n    steps:\n      - run: echo ${{{{ secrets.TOKEN }}}}\n")

    def test_only_a_name_written_as_text_lowers_it(self):
        with TempDir() as tmp:
            for environment, severity in (("review", "medium"), ("{name: review}", "medium"),
                                          ("tmp-${{ github.run_id }}", "high"),
                                          ("${{ github.event.pull_request.head.ref }}", "high"),
                                          ("\"${{ '' }}\"", "high"), ("\" \"", "high"), ("8", "high")):
                with self.subTest(environment=environment):
                    found = of(check(tmp, self.wf(environment)), "OBAAF-GHA-001")
                    self.assertEqual([f.severity for f in found], [severity])


class ProtectedSecretsTest(unittest.TestCase):
    HEAD = "on: push\npermissions: {}\njobs:\n  pub:\n    runs-on: ubuntu-latest\n"
    STEPS = "    steps:\n      - run: twine upload dist/*\n        env:\n          T: ${{ secrets.PYPI_TOKEN }}\n"

    def run_case(self, protected, job):
        config = checker.Config.from_data({"protected_secrets": protected}, "test")
        with TempDir() as tmp:
            return of(check(tmp, self.HEAD + job + self.STEPS, config=config), "OBAAF-GHA-024")

    def test_names_equal_only_under_unicode_case_folding_are_not_taken_for_the_same(self):
        for environment, wanted in (("\u212aube-prod", "kube-prod"), ("stra\u00dfe", "strasse"),
                                    ("relea\u017fe", "release")):
            with self.subTest(environment=environment):
                found = self.run_case({"PYPI_TOKEN": wanted}, f"    environment: {environment}\n")
                self.assertEqual([(f.kind, f.severity) for f in found], [("environment-unsure", "medium")])

    def test_ascii_case_still_matches(self):
        self.assertEqual(self.run_case({"PYPI_TOKEN": "release"}, "    environment: {name: Release}\n"), [])

    def test_a_name_that_is_not_text_or_is_blank_is_not_taken_for_an_environment(self):
        for protected, job in (({"PYPI_TOKEN": "8"}, "    environment: 010\n"),
                               (["PYPI_TOKEN"], "    environment: ' '\n"),
                               (["PYPI_TOKEN"], "    environment: {name: [release]}\n")):
            with self.subTest(job=job):
                found = self.run_case(protected, job)
                self.assertEqual([(f.kind, f.severity) for f in found], [("environment-unsure", "medium")])

    def test_two_entries_for_one_secret_name_are_a_configuration_error(self):
        with self.assertRaises(checker.ConfigError):
            checker.Config.from_data({"protected_secrets": {"PYPI_TOKEN": "release", "pypi_token": "staging"}},
                                     "test")


class SigningKeysTest(unittest.TestCase):
    def job(self, body, extra=""):
        return ("on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n" + extra +
                "    steps:\n" + body)

    def test_a_job_that_can_read_every_secret_can_read_the_signing_key(self):
        bodies = {
            "computed": "      - run: echo \"$K\" | base64 -d > k.p12\n        env:\n"
                        "          K: ${{ secrets[format('{0}_KEY', 'SIGNING')] }}\n",
            "tojson": "      - run: echo \"$S\" | jq -r .SIGNING_KEY > k\n        env:\n          S: ${{ toJSON(secrets) }}\n",
        }
        with TempDir() as tmp:
            for name, body in bodies.items():
                with self.subTest(name=name):
                    found = of(check(tmp, self.job(body)), "OBAAF-GHA-018")
                    self.assertEqual([f.kind for f in found], ["any-secret"])
            inherit = ("on: push\npermissions: {}\njobs:\n  sign:\n    uses: org/rel/.github/workflows/sign.yml@" + SHA +
                       "\n    secrets: inherit\n")
            found = of(check(tmp, inherit), "OBAAF-GHA-018")
            self.assertEqual([(f.kind, f.facts["how"]) for f in found], [("any-secret", ["*inherit"])])

    def test_commands_and_actions_the_patterns_missed(self):
        steps = ["      - run: |\n          cosign sign \\\n            --key env://K img\n",
                 "      - run: /usr/bin/gpg --import k.asc\n", "      - run: gpg2 --import k.asc\n",
                 "      - run: gpg --batch --yes --import k.asc\n",
                 "      - run: gpg --pinentry-mode loopback --import k.asc\n",
                 "      - run: security import cert.P12 -k build.keychain\n",
                 "      - shell: pwsh\n        run: Import-PfxCertificate -FilePath c.pfx\n",
                 "      - uses: crazy-max/ghaction-import-gpg@" + SHA + "\n",
                 "      - uses: apple-actions/import-codesign-certs@" + SHA + "\n"]
        with TempDir() as tmp:
            for body in steps:
                with self.subTest(body=body.strip()[:40]):
                    self.assertEqual(len(of(check(tmp, self.job(body)), "OBAAF-GHA-018")), 1)
            self.assertEqual(of(check(tmp, self.job("      - run: gpg --list-keys\n")), "OBAAF-GHA-018"), [])

    def test_common_signing_secret_names(self):
        with TempDir() as tmp:
            for name in ("CSC_LINK", "MACOS_CERTIFICATE", "WINDOWS_CERTIFICATE", "APPLE_CERTIFICATE", "KEY_STORE"):
                with self.subTest(name=name):
                    body = f"      - run: make sign\n        env:\n          K: ${{{{ secrets.{name} }}}}\n"
                    self.assertEqual([f.kind for f in of(check(tmp, self.job(body)), "OBAAF-GHA-018")], ["secrets"])


class TheEnvironmentIsPartOfASecretsFindingTest(unittest.TestCase):
    """An environment's secret takes precedence over a repository secret of the same name, so the
    same reference in another environment reads another secret. An acceptance written for the job
    in `sandbox` covered it in `production`."""

    def test_the_environment_is_a_fact_of_gha_005_and_gha_018(self):
        body = ("on: push\npermissions: {}\njobs:\n  agent:\n    runs-on: ubuntu-latest\nENV    steps:\n"
                + AGENT + "        env:\n          SIGNING_KEY: ${{ secrets.SIGNING_KEY }}\n")
        with TempDir() as tmp:
            facts = {}
            for env in ("", "    environment: sandbox\n", "    environment: production\n"):
                result = check(tmp, body.replace("ENV", env))
                facts[env] = [f.facts for f in result.findings if f.rule in ("OBAAF-GHA-005", "OBAAF-GHA-018")]
            self.assertEqual(len({repr(v) for v in facts.values()}), 3)
            self.assertEqual([len(v) for v in facts.values()], [2, 2, 2])
            self.assertNotIn("environment", facts[""][0])
            self.assertEqual(facts["    environment: sandbox\n"][0]["environment"], "'sandbox'")


class TriggersTest(unittest.TestCase):
    def test_an_event_not_written_as_github_writes_them_fails_the_check(self):
        with TempDir() as tmp:
            for on in ("Pull_Request_Target", "[push, Pull_Request_Target]", "[{pull_request_target: {}}]",
                       "{Pull_Request_Target: {}}", "[pull_request_target, 0x" + "f" * 4000 + "]"):
                with self.subTest(on=on[:40]):
                    text = ("on: " + on + "\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                            "      - run: echo ${{ secrets.TOKEN }}\n")
                    result = check(tmp, text)
                    self.assertTrue(any("trigger under 'on'" in e for e in result.errors), result.errors)


if __name__ == "__main__":
    unittest.main()
