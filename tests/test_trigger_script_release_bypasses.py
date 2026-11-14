"""Slice 2d.2d: triggers, scripts and release jobs.

Two reviewers that did not write them tried to get past the three rules that depend on what started a
run and what a job runs: OBAAF-GHA-010 (outsider text expanded in a script), OBAAF-GHA-013 (a
self-hosted runner for untrusted work) and OBAAF-GHA-015 (a release job that untrusted input can
start). Every way past that the checker did not already report is a test here; the record of every
attempt, including the ones that held, is docs/bypass-attempts.md.
"""

import time
import unittest

from helpers import TempDir

from obaaf import checker
from obaaf.checker import baseline
from obaaf.checker.workflow import release_environment

SHA = "1111111111111111111111111111111111111111"


def check(tmp, text, name="wf.yml"):
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    for old in (root / ".github" / "workflows").iterdir():
        old.unlink()
    (root / ".github" / "workflows" / name).write_text(text, encoding="utf-8")
    return checker.check(root)


def of(result, rule):
    return [f for f in result.findings if f.rule == rule]


def run_step(expression_line, on="issues", job_extra="", step_extra="", workflow_extra=""):
    """A workflow with one job and one step whose script holds `expression_line`."""
    return (f"on: {on}\npermissions: {{}}\n{workflow_extra}jobs:\n  j:\n    runs-on: ubuntu-latest\n{job_extra}"
            f"    steps:\n      - name: s\n{step_extra}        run: |\n          {expression_line}\n")


def uses_step(uses, with_lines, on="issues"):
    body = "".join(f"          {line}\n" for line in with_lines)
    return (f"on: {on}\npermissions: {{}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - name: s\n        uses: {uses}\n        with:\n{body}")


class OutsiderFieldsTest(unittest.TestCase):
    """OBAAF-GHA-010's list of outsider-written fields missed fields a person without write access
    writes. Each is now reported, high on the event that carries it."""

    CASES = {
        "issues": ["github.event.changes.title.from", "github.event.changes.body.from",
                   "github.event.changes.new_issue.title"],
        "pull_request_review_comment": ["github.event.comment.path", "github.event.comment.diff_hunk"],
        "workflow_run": ["github.event.workflow_run.head_commit.committer.name",
                         "github.event.workflow_run.head_commit.committer.email",
                         "github.event.workflow_run.head_repository.description",
                         "github.event.workflow_run.pull_requests[0].head.ref",
                         "github.event.workflow_run.path"],
        "push": ["github.event.head_commit.added[0]", "github.event.commits[0].modified[1]",
                 "toJSON(github.event.head_commit.removed)"],
        "gollum": ["github.event.pages[0].title", "github.event.pages[0].summary"],
        "discussion": ["github.event.answer.body", "github.event.changes.new_discussion.title"],
        "merge_group": ["github.event.merge_group.head_commit.message",
                        "github.event.merge_group.head_commit.author.name"],
        "fork": ["github.event.forkee.description"],
        "check_suite": ["github.event.check_suite.head_branch", "github.event.check_suite.head_commit.message"],
        "status": ["github.event.commit.commit.message", "github.event.branches[0].name"],
        "commit_comment": ["github.event.comment.body"],
    }

    def test_each_field_is_reported_high(self):
        with TempDir() as tmp:
            for event, fields in self.CASES.items():
                for field in fields:
                    with self.subTest(event=event, field=field):
                        found = of(check(tmp, run_step(f'echo "${{{{ {field} }}}}"', on=event)), "OBAAF-GHA-010")
                        self.assertEqual([f.severity for f in found], ["high"])


class ScriptsOtherThanRunTest(unittest.TestCase):
    """What a step runs that is not its `run`: a `docker://` step's arguments, the command OBAAF's
    egress action runs (also under spellings of its path that do not make it the control), the inputs
    of actions that run them as scripts (in any letter case: GitHub folds input names), and the `shell`
    the runner starts."""

    FIELD = "${{ github.event.issue.title }}"

    def test_each_is_read(self):
        cases = {
            "docker args": uses_step("docker://alpine:3", [f'args: sh -c "echo {self.FIELD}"']),
            "egress run": uses_step(f"Obaaf/OBAAF/actions/egress@{SHA}", [f'run: echo "{self.FIELD}"',
                                                                         "allow: api.example.com"]),
            "egress trailing slash": uses_step(f"Obaaf/OBAAF/actions/egress/@{SHA}", [f'run: echo "{self.FIELD}"']),
            "egress double slash": uses_step(f"Obaaf/OBAAF//actions/egress@{SHA}", [f'run: echo "{self.FIELD}"']),
            "egress dot segment": uses_step(f"Obaaf/OBAAF/actions/./egress@{SHA}", [f'run: echo "{self.FIELD}"']),
            "azure/cli": uses_step(f"azure/cli@{SHA}", [f'inlineScript: echo "{self.FIELD}"']),
            "azure/cli lower case": uses_step(f"azure/cli@{SHA}", [f'inlinescript: echo "{self.FIELD}"']),
            "azure/powershell": uses_step(f"azure/powershell@{SHA}", [f'inlineScript: echo "{self.FIELD}"']),
            "retry": uses_step(f"nick-fields/retry@{SHA}", [f'command: echo "{self.FIELD}"']),
            "step shell": run_step("echo hi", step_extra=f"        shell: bash -c \"{self.FIELD}\" {{0}}\n"),
            "job default shell": run_step("echo hi", job_extra=f"    defaults:\n      run:\n        shell: "
                                                               f"bash -c \"{self.FIELD}\" {{0}}\n"),
        }
        with TempDir() as tmp:
            for name, text in cases.items():
                with self.subTest(case=name):
                    self.assertEqual([f.severity for f in of(check(tmp, text), "OBAAF-GHA-010")], ["high"])


class SeverityTest(unittest.TestCase):
    """The severity followed the trigger only through UNTRUSTED_TRIGGERS, so a called workflow and a
    commit's text on push were medium, and a whole object or computed path on push was medium where the
    plain field was high."""

    def test_a_called_workflow_is_high(self):
        with TempDir() as tmp:
            text = run_step('echo "${{ github.event.pull_request.title }}"', on="workflow_call")
            self.assertEqual([f.severity for f in of(check(tmp, text), "OBAAF-GHA-010")], ["high"])

    def test_a_commits_text_on_push_is_high_in_every_spelling(self):
        spellings = ["github.event.head_commit.message", "github.event.head_commit.author.name",
                     "toJSON(github.event)", "toJSON(github)", "toJSON(github.event.head_commit)",
                     "toJSON(github.event.commits)", "github.event[format('head_commit')].message"]
        with TempDir() as tmp:
            for on in ("push", "merge_group"):
                for spelling in spellings:
                    with self.subTest(on=on, spelling=spelling):
                        text = run_step(f'echo "${{{{ {spelling} }}}}"', on=on)
                        self.assertEqual([f.severity for f in of(check(tmp, text), "OBAAF-GHA-010")], ["high"])

    def test_a_run_after_a_push_is_high_for_the_commits_text(self):
        text = ("on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\npermissions: {}\njobs:\n  j:\n"
                "    if: github.event.workflow_run.event == 'push'\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: echo \"${{ toJSON(github.event.workflow_run) }}\"\n")
        with TempDir() as tmp:
            self.assertEqual([f.severity for f in of(check(tmp, text), "OBAAF-GHA-010")], ["high"])

    def test_a_field_an_ordinary_dispatch_carries_nothing_of_stays_medium(self):
        with TempDir() as tmp:
            text = run_step('echo "${{ github.event.issue.title }}"', on="workflow_dispatch")
            self.assertEqual([f.severity for f in of(check(tmp, text), "OBAAF-GHA-010")], ["medium"])


class EveryFieldIsAFactTest(unittest.TestCase):
    """Only the first field a step expanded was a fact, so an accepted step could expand another one and
    keep its acceptance; an env value, a matrix or an output holding two fields showed one."""

    def facts(self, text):
        with TempDir() as tmp:
            found = of(check(tmp, text), "OBAAF-GHA-010")
            self.assertEqual(len(found), 1)
            return found[0].facts

    def test_two_fields_in_one_step(self):
        facts = self.facts(run_step('echo "${{ github.event.issue.title }}" "${{ github.event.issue.body }}"'))
        self.assertEqual(facts["fields"], ["github.event.issue.body", "github.event.issue.title"])

    def test_an_env_value_that_holds_two(self):
        env = "        env:\n          T: ${{ github.event.issue.title }} ${{ github.event.issue.body }}\n"
        facts = self.facts(run_step('echo "${{ env.T }}"', step_extra=env))
        self.assertEqual(facts["fields"], ["github.event.issue.body", "github.event.issue.title"])

    def test_a_matrix_that_holds_two(self):
        job = ("    strategy:\n      matrix:\n        t: ['${{ github.event.issue.title }}', "
               "'${{ github.event.issue.body }}']\n")
        facts = self.facts(run_step('echo "${{ matrix.t }}"', job_extra=job))
        self.assertEqual(facts["fields"], ["github.event.issue.body", "github.event.issue.title"])

    def test_an_added_field_or_trigger_or_expression_is_a_new_finding(self):
        def key(text):
            with TempDir() as tmp:
                return baseline.key(of(check(tmp, text), "OBAAF-GHA-010")[0])
        one = key(run_step('echo "${{ github.event.issue.title }}"'))
        self.assertNotEqual(one, key(run_step('echo "${{ github.event.issue.title }} ${{ github.event.issue.body }}"')))
        self.assertNotEqual(one, key(run_step('echo "${{ github.event.issue.title }}"', on="[issues, issue_comment]")))
        # An accepted test that gives only true or false does not cover the field itself.
        harmless = key(run_step("echo \"${{ contains(github.event.issue.title, 'bug') }}\""))
        self.assertNotEqual(harmless, one)


class ValuesBetweenJobsTest(unittest.TestCase):
    """A job's outputs written in the file, read in another job's script as `needs.<job>.outputs.<name>`,
    and an `env:` written as one expression that reads the matrix, were not followed."""

    def test_a_static_output_is_followed(self):
        text = ("on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n"
                "      t: ${{ github.event.issue.title }}\n    steps:\n      - run: 'true'\n"
                "  b:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: echo \"${{ needs.a.outputs.t }}\"\n")
        with TempDir() as tmp:
            found = of(check(tmp, text), "OBAAF-GHA-010")
            self.assertEqual([(f.job, f.severity) for f in found], [("b", "high")])
            self.assertEqual(found[0].facts["fields"], ["github.event.issue.title"])

    def test_an_output_through_another_output_and_an_env_value(self):
        text = ("on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n"
                "      t: ${{ github.event.issue.title }}\n    steps:\n      - run: 'true'\n"
                "  b:\n    needs: a\n    runs-on: ubuntu-latest\n    outputs:\n      u: ${{ needs.a.outputs.t }}\n"
                "    steps:\n      - run: 'true'\n"
                "  c:\n    needs: b\n    runs-on: ubuntu-latest\n    env:\n      U: ${{ needs.b.outputs.u }}\n"
                "    steps:\n      - run: echo \"${{ env.U }}\"\n")
        with TempDir() as tmp:
            self.assertEqual([f.job for f in of(check(tmp, text), "OBAAF-GHA-010")], ["c"])

    def test_an_output_that_is_only_a_result_is_not(self):
        text = ("on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n"
                "      t: ${{ github.event.issue.title }}\n    steps:\n      - run: 'true'\n"
                "  b:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ needs.a.result }}\"\n")
        with TempDir() as tmp:
            self.assertEqual(of(check(tmp, text), "OBAAF-GHA-010"), [])

    def test_an_env_written_as_one_expression_that_reads_the_matrix(self):
        job = ("    strategy:\n      matrix:\n        e: ['${{ github.event.issue.title }}']\n"
               "    env: ${{ fromJSON(format('{{\"T\":\"{0}\"}}', matrix.e)) }}\n")
        with TempDir() as tmp:
            found = of(check(tmp, run_step('echo "${{ env.T }}"', job_extra=job)), "OBAAF-GHA-010")
            self.assertEqual([f.severity for f in found], ["high"])


class HostedLabelsTest(unittest.TestCase):
    """OBAAF-GHA-013 took any `ubuntu-*`, `windows-*` or `macos-*` label for GitHub-hosted, matched
    `self-hosted` only exactly, and reported a job that calls a reusable workflow as running on no labels."""

    def severities(self, runs_on, on="pull_request", job_extra=""):
        text = (f"on: {on}\npermissions: {{}}\njobs:\n  j:\n    runs-on: {runs_on}\n{job_extra}    steps:\n"
                "      - run: make\n")
        with TempDir() as tmp:
            return [f.severity for f in of(check(tmp, text), "OBAAF-GHA-013")]

    def test_a_label_shaped_like_a_hosted_one_is_not_taken_for_one(self):
        for label in ("ubuntu-gpu", "windows-builder", "macos-mini-farm", "ubuntu-20.04"):
            with self.subTest(label=label):
                self.assertEqual(self.severities(label), ["medium"])
        for label in ("ubuntu-latest", "ubuntu-24.04-arm", "windows-11-arm", "macos-15-xlarge", "UBUNTU-LATEST"):
            with self.subTest(label=label):
                self.assertEqual(self.severities(label), [])

    def test_self_hosted_with_spaces_case_or_commas(self):
        for runs_on in ("'Self-Hosted '", "[' self-hosted', linux]", "'linux, self-hosted'", "'self-hosted linux'"):
            with self.subTest(runs_on=runs_on):
                self.assertEqual(self.severities(runs_on), ["high"])

    def test_a_calling_job_is_not_reported(self):
        text = ("on: pull_request\npermissions: {}\njobs:\n  call:\n    uses: ./.github/workflows/other.yml\n")
        with TempDir() as tmp:
            self.assertEqual(of(check(tmp, text), "OBAAF-GHA-013"), [])

    def test_matrix_pools_are_facts(self):
        def key(pool):
            text = ("on: pull_request\npermissions: {}\njobs:\n  j:\n    runs-on: ${{ matrix.pool }}\n"
                    f"    strategy:\n      matrix:\n        pool: [[self-hosted, {pool}]]\n    steps:\n      - run: make\n")
            with TempDir() as tmp:
                return baseline.key(of(check(tmp, text), "OBAAF-GHA-013")[0])
        self.assertNotEqual(key("ephemeral-firecracker"), key("persistent-build-box"))


class RuntimeSelectorTest(unittest.TestCase):
    """Any selector that named a hosted label and `self-hosted` was informational, whatever it chose."""

    FULL_NAME = ("${{ github.event.pull_request.head.repo.full_name == github.repository && 'self-hosted' "
                 "|| 'ubuntu-latest' }}")

    def finding(self, runs_on, on="pull_request", step="      - run: make\n"):
        text = f"on: {on}\npermissions: {{}}\njobs:\n  j:\n    runs-on: \"{runs_on}\"\n    steps:\n{step}"
        with TempDir() as tmp:
            return [(f.severity, f.kind) for f in of(check(tmp, text), "OBAAF-GHA-013")]

    def test_a_selector_that_always_picks_self_hosted_is_medium(self):
        for runs_on in ("${{ false && 'ubuntu-latest' || 'self-hosted' }}",
                        "${{ 'self-hosted' || 'ubuntu-latest' }}",
                        "${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || 'self-hosted' }}"):
            with self.subTest(runs_on=runs_on):
                self.assertEqual(self.finding(runs_on), [("medium", "other-labels")])

    def test_the_recognised_form_is_informational_only_on_pull_request_events_without_an_agent(self):
        self.assertEqual(self.finding(self.FULL_NAME), [("info", "runtime-choice")])
        self.assertEqual(self.finding(self.FULL_NAME, on="issue_comment"), [("medium", "other-labels")])
        agent = f"      - uses: anthropics/claude-code-action@{SHA}\n"
        self.assertEqual([s for s, _ in self.finding(self.FULL_NAME, step=agent)], ["medium"])

    def test_the_selector_is_a_fact(self):
        with TempDir() as tmp:
            text = (f"on: pull_request\npermissions: {{}}\njobs:\n  j:\n    runs-on: \"{self.FULL_NAME}\"\n"
                    "    steps:\n      - run: make\n")
            found = of(check(tmp, text), "OBAAF-GHA-013")[0]
            self.assertIn("selector", found.facts)


def release_job(steps, on="pull_request_target", job_extra=""):
    return (f"on: {on}\npermissions: {{}}\njobs:\n  rel:\n    runs-on: ubuntu-latest\n{job_extra}    steps:\n{steps}")


class ReleaseRecognisedTest(unittest.TestCase):
    """OBAAF-GHA-015 recognised a release job by lists that missed many ways of publishing."""

    def severities(self, text):
        with TempDir() as tmp:
            return [(f.severity, f.kind) for f in of(check(tmp, text), "OBAAF-GHA-015")]

    def test_publishing_commands_the_lists_missed(self):
        scripts = ["gh release edit v1 --draft=false", "gh api -X POST repos/o/r/releases -f tag_name=v1",
                   "git push origin --tags", "aws --region us-east-1 s3 cp dist s3://b/ --recursive",
                   "aws \\\n            s3 cp dist s3://b/", "pnpm -r publish", "cargo +stable publish",
                   "\"npm\" publish", "./scripts/release.sh", "docker buildx build --push -t x .",
                   "firebase deploy", "npx vercel --prod", "curl -T dist.zip https://repo.example/up/"]
        for script in scripts:
            with self.subTest(script=script):
                step = f"      - run: |\n          {script}\n"
                self.assertEqual(self.severities(release_job(step)), [("high", "")])

    def test_publishing_by_an_action_or_a_container(self):
        steps = {
            "pypi action": f"      - uses: pypa/gh-action-pypi-publish@{SHA}\n",
            "github-script": (f"      - uses: actions/github-script@{SHA}\n        with:\n"
                              "          script: |\n            await github.rest.repos.createRelease({owner: 'o'})\n"),
            "docker://": "      - uses: docker://node:20\n        with:\n          entrypoint: npm\n          args: publish\n",
        }
        for name, step in steps.items():
            with self.subTest(case=name):
                self.assertEqual(self.severities(release_job(step)), [("high", "")])

    def test_environment_names_read_word_by_word(self):
        for name in ("live", "prd", "pypi", "npm", "crates", "gh-pages", "github-pages", "AppProd", "awsprod", "switch",
                     "nintendo-switch"):
            with self.subTest(name=name):
                self.assertTrue(release_environment(name))
        for name in ("kitchen", "restore-drill", "reproducibility", "product-docs-preview", "staging", "preprod", "ci"):
            with self.subTest(name=name):
                self.assertFalse(release_environment(name))

    def test_an_environment_named_by_a_matrix_or_a_function(self):
        matrix = ("    strategy:\n      matrix:\n        env: [staging, production]\n"
                  "    environment: ${{ matrix.env }}\n")
        self.assertEqual(self.severities(release_job("      - run: make\n", job_extra=matrix)), [("high", "")])
        built = "    environment: ${{ format('{0}{1}', 'pr', 'oduction') }}\n"
        self.assertEqual(self.severities(release_job("      - run: make\n", job_extra=built)),
                         [("medium", "capability")])


class ReleaseSeverityAndFactsTest(unittest.TestCase):
    """OBAAF-GHA-015 was high on pull_request, where OBAAF-GHA-001 is low because a fork's run gets no
    secrets, and its facts were only the triggers: an acceptance of a job that pushes to a registry
    inside the job covered the same job once it published to npm."""

    PUBLISH = "      - run: npm publish\n"

    def findings(self, text):
        with TempDir() as tmp:
            return of(check(tmp, text), "OBAAF-GHA-015")

    def test_severity_follows_the_event_and_the_environment(self):
        self.assertEqual([(f.severity, f.kind) for f in self.findings(release_job(self.PUBLISH))], [("high", "")])
        self.assertEqual([(f.severity, f.kind) for f in self.findings(release_job(self.PUBLISH, on="pull_request"))],
                         [("medium", "pull-request")])
        self.assertEqual([(f.severity, f.kind) for f in self.findings(
            release_job(self.PUBLISH, on="pull_request_review"))], [("medium", "pull-request")])
        with_env = release_job(self.PUBLISH, job_extra="    environment: production\n")
        self.assertEqual([(f.severity, f.kind) for f in self.findings(with_env)], [("medium", "environment")])

    def test_the_release_steps_and_environment_are_facts(self):
        local = self.findings(release_job("      - run: docker push localhost:5000/x\n"))[0]
        npm = self.findings(release_job("      - run: docker push localhost:5000/x\n" + self.PUBLISH))[0]
        self.assertNotEqual(baseline.key(local), baseline.key(npm))
        staging = self.findings(release_job(self.PUBLISH, job_extra="    environment: production\n"))[0]
        other = self.findings(release_job(self.PUBLISH, job_extra="    environment: production-eu\n"))[0]
        self.assertNotEqual(baseline.key(staging), baseline.key(other))


class ReleaseCapabilityTest(unittest.TestCase):
    """A job nothing marks a release job but that holds what publishing needs, and that an outside event
    can start, is reported as one that may release."""

    def finding(self, steps="      - run: make\n", on="pull_request_target", job_extra=""):
        with TempDir() as tmp:
            text = release_job(steps, on=on, job_extra=job_extra)
            return [(f.severity, f.kind) for f in of(check(tmp, text), "OBAAF-GHA-015")]

    def test_each_capability(self):
        cases = {
            "packages": dict(job_extra="    permissions: {packages: write}\n"),
            "npm secret": dict(steps="      - run: make\n        env:\n          T: ${{ secrets.NPM_TOKEN }}\n"),
            "docker hub secret": dict(steps="      - run: make\n        env:\n"
                                            "          T: ${{ secrets.DOCKER_HUB_ACCESS_TOKEN }}\n"),
            "build-push": dict(steps=f"      - uses: docker/build-push-action@{SHA}\n"),
            "unreadable environment": dict(job_extra="    environment: ${{ inputs.target }}\n"),
        }
        for name, kwargs in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self.finding(**kwargs), [("medium", "capability")])

    def test_low_on_pull_request_events_only(self):
        self.assertEqual(self.finding(on="pull_request", job_extra="    permissions: {packages: write}\n"),
                         [("low", "capability")])

    def test_what_is_not_a_capability(self):
        cases = {
            "id-token alone": dict(job_extra="    permissions: {id-token: write}\n"),
            "deploy key": dict(steps="      - run: make\n        env:\n          K: ${{ secrets.SUBMODULE_DEPLOY_KEY }}\n"),
            "install token": dict(steps="      - run: npm ci\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.GH_READ }}\n"),
        }
        for name, kwargs in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self.finding(**kwargs), [])

    def test_a_trusted_trigger_is_not_reported(self):
        self.assertEqual(self.finding(on="push", job_extra="    permissions: {packages: write}\n"), [])


class ReviewOfTheSliceTest(unittest.TestCase):
    """What the review of slice 2d.2d found in its first version."""

    def test_a_step_name_with_braces_is_reported_and_keeps_its_old_message(self):
        for name in ("Say {0}", "Say {hello}", "Say }", "Greet on ${{ matrix.os }}"):
            with self.subTest(name=name), TempDir() as tmp:
                text = run_step('echo "${{ github.event.issue.title }}"').replace("name: s", f"name: '{name}'")
                found = of(check(tmp, text), "OBAAF-GHA-010")
                self.assertEqual([f.step for f in found], [name])
                self.assertEqual(found[0].legacy, "")       # the message is the one 0.3.0 wrote

    def test_the_old_message_names_the_first_field_as_written(self):
        env = "        env:\n          T: ${{ github.event.issue.title }} ${{ github.event.issue.body }}\n"
        with TempDir() as tmp:
            found = of(check(tmp, run_step('echo "${{ env.T }}"', step_extra=env)), "OBAAF-GHA-010")[0]
            self.assertIn("which holds", found.message)
            self.assertEqual(found.legacy or found.message,
                             "Step 's' expands env.t, which holds github.event.issue.title, inside its script.")

    def test_outputs_are_followed_in_any_order_of_jobs(self):
        # The consumer is listed first, and an earlier harmless `needs` reference starts the reading.
        text = ("on: issues\npermissions: {}\njobs:\n"
                "  c:\n    needs: [a, b]\n    runs-on: ubuntu-latest\n    outputs:\n      z: ${{ env.X }}\n"
                "    env:\n      X: ${{ needs.b.outputs.y }}\n    steps:\n      - run: echo \"${{ needs.a.result }} ${{ env.X }}\"\n"
                "  b:\n    needs: a\n    runs-on: ubuntu-latest\n    outputs:\n      y: ${{ needs.a.outputs.t }}\n"
                "    steps:\n      - run: 'true'\n"
                "  a:\n    runs-on: ubuntu-latest\n    outputs:\n      t: ${{ github.event.issue.title }}\n"
                "    steps:\n      - run: 'true'\n")
        with TempDir() as tmp:
            self.assertEqual([f.job for f in of(check(tmp, text), "OBAAF-GHA-010")], ["c"])

    def test_a_long_chain_of_outputs_is_read_quickly(self):
        jobs = []
        for i in range(150):
            refs = " ".join(f"${{{{ needs.j{i + 1}.outputs.o }}}}" for _ in range(20))
            jobs.append(f"  j{i}:\n    needs: j{i + 1}\n    runs-on: ubuntu-latest\n    outputs:\n      o: {refs}\n"
                        "    steps:\n      - run: 'true'\n")
        jobs.append("  j150:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ github.event.issue.title }}\n"
                    "    steps:\n      - run: 'true'\n")
        jobs.append("  z:\n    needs: j0\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ needs.j0.outputs.o }}\"\n")
        text = "on: issues\npermissions: {}\njobs:\n" + "".join(jobs)
        with TempDir() as tmp:
            started = time.monotonic()
            found = of(check(tmp, text), "OBAAF-GHA-010")
            self.assertLess(time.monotonic() - started, 10)
            self.assertEqual([f.job for f in found], ["z"])

    def test_names_of_production_still_say_release(self):
        for name in ("euproduction", "awsproduction", "prodeu", "PRODEU", "prodcluster", "prodv2", "appdeployment",
                     "appstoreconnect", "myappreleases", "deployer", "publisher"):
            with self.subTest(name=name):
                self.assertTrue(release_environment(name))
        for name in ("keystore", "datastore", "firestore"):
            with self.subTest(name=name):
                self.assertFalse(release_environment(name))

    def test_a_runs_display_title_after_a_push_is_high(self):
        text = ("on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\npermissions: {}\njobs:\n  j:\n"
                "    if: github.event.workflow_run.event == 'push'\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: echo \"${{ github.event.workflow_run.display_title }}\"\n")
        with TempDir() as tmp:
            self.assertEqual([f.severity for f in of(check(tmp, text), "OBAAF-GHA-010")], ["high"])

    def test_a_new_pin_of_the_publishing_action_is_the_same_finding(self):
        def key(ref):
            with TempDir() as tmp:
                step = f"      - name: Publish\n        uses: pypa/gh-action-pypi-publish@{ref}\n"
                return baseline.key(of(check(tmp, release_job(step)), "OBAAF-GHA-015")[0])
        self.assertEqual(key(SHA), key("2" * 40))

    def test_a_new_pin_of_an_unnamed_publishing_step_is_the_same_finding(self):
        def key(ref):
            with TempDir() as tmp:
                step = f"      - uses: pypa/gh-action-pypi-publish@{ref}\n"
                return baseline.key(of(check(tmp, release_job(step)), "OBAAF-GHA-015")[0])
        self.assertEqual(key(SHA), key("2" * 40))

    def test_a_job_that_calls_a_workflow_with_a_publishing_grant(self):
        text = ("on: pull_request_target\npermissions: {}\njobs:\n  call:\n    permissions: {packages: write}\n"
                "    uses: example/shared/.github/workflows/build.yml@" + SHA + "\n")
        with TempDir() as tmp:
            self.assertEqual([(f.severity, f.kind) for f in of(check(tmp, text), "OBAAF-GHA-015")],
                             [("medium", "capability")])


if __name__ == "__main__":
    unittest.main()
