"""Slice 2d.2c: triggers and checkouts, the checkout half.

A reviewer that did not write them tried to get past the four rules about what a run checks out:
OBAAF-GHA-002 (a pull request's code in a privileged workflow), OBAAF-GHA-011 (the token kept on
disk), OBAAF-GHA-012 (an agent reading instructions from the change under review) and OBAAF-GHA-019
(the unsafe checkout allowed). Every way past that the checker did not already report is a test
here; the record of every attempt, including the ones that held, is docs/bypass-attempts.md.
"""

import unittest

from helpers import TempDir

from obaaf import checker
from obaaf.checker import baseline
from obaaf.checker.workflow import pr_code

SHA = "1111111111111111111111111111111111111111"
CHECKOUT = "actions/checkout@" + SHA
AGENT = "      - uses: anthropics/claude-code-action@" + SHA + "\n"


def check(tmp, text, name="wf.yml"):
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    for old in (root / ".github" / "workflows").iterdir():
        old.unlink()
    (root / ".github" / "workflows" / name).write_text(text, encoding="utf-8")
    return checker.check(root)


def of(result, rule):
    return [f for f in result.findings if f.rule == rule]


def checkout_job(with_lines, on="pull_request_target", job_extra="", after=""):
    body = "".join(f"          {line}\n" for line in with_lines)
    return (f"on: {on}\npermissions: {{contents: read}}\njobs:\n  build:\n    runs-on: ubuntu-latest\n{job_extra}"
            f"    steps:\n      - uses: {CHECKOUT}\n        with:\n          persist-credentials: false\n{body}{after}")


def script_job(script, on="pull_request_target", env="", uses=None):
    lines = "".join(f"          {line}\n" for line in script.splitlines())
    step = (f"      - name: Get the code\n{env}        run: |\n{lines}" if uses is None else
            f"      - name: Get the code\n        uses: {uses}\n{env}")
    return (f"on: {on}\npermissions: {{contents: read}}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: false\n{step}")


class CheckoutRefIsReadAsAnExpressionTest(unittest.TestCase):
    """OBAAF-GHA-002 matched the text of `ref` and `repository` against a pattern of plain spellings.
    Index syntax, letter case, `format`, `join`, `fromJSON(toJSON(...))`, a value given through `env`
    and the head repository with no ref all checked out the pull request's code with no finding. The
    two inputs are now read with the expression reader, and `env` is followed to where it is set."""

    def test_every_spelling_of_the_head_is_reported_high(self):
        cases = {
            "ref: ${{ github.event.pull_request.head['sha'] }}": "pull_request_target",
            "ref: ${{ GitHub.Event.Pull_Request.Head.SHA }}": "pull_request_target",
            "ref: ${{ format('refs/{0}/{1}/merge', 'pull', github.event.number) }}": "pull_request_target",
            "ref: ${{ format('refs/{0}/{1}/head', 'pull', github.event.issue.number) }}": "issue_comment",
            "ref: ${{ join(fromJSON(format('[\"refs\",\"pull\",\"{0}\",\"head\"]', github.event.number)), '/') }}":
                "pull_request_target",
            "ref: ${{ fromJSON(toJSON(github.event.pull_request.head)).sha }}": "pull_request_target",
            "repository: ${{ github.event.pull_request.head.repo.full_name }}": "pull_request_target",
            "repository: ${{ github.event.pull_request.head.repo.owner.login }}/x": "pull_request_target",
            "ref: ${{ github.event.workflow_run.pull_requests[0].head.sha }}": "workflow_run",
            "ref: ${{ github.event.pull_request.head.sha || github.event.pull_request.base.sha }}":
                "pull_request_target",
        }
        with TempDir() as tmp:
            for line, on in cases.items():
                with self.subTest(line=line):
                    found = of(check(tmp, checkout_job([line], on=on)), "OBAAF-GHA-002")
                    self.assertEqual([(f.severity, f.kind) for f in found], [("high", "checkout")])

    def test_a_value_given_through_env_is_followed_at_every_level(self):
        with TempDir() as tmp:
            for job_extra, top in (("    env:\n      PR_SHA: ${{ github.event.pull_request.head.sha }}\n", ""),
                                   ("", "env:\n  PR_SHA: ${{ github.event.pull_request.head.sha }}\n")):
                with self.subTest(job=bool(job_extra)):
                    text = checkout_job(["ref: ${{ env.pr_sha }}"], job_extra=job_extra)
                    result = check(tmp, top + text)
                    found = of(result, "OBAAF-GHA-002")
                    self.assertEqual([(f.severity, f.kind) for f in found], [("high", "checkout")])
                    self.assertIn("github.event.pull_request.head.sha", found[0].facts["reads"])

    def test_a_value_computed_while_the_job_runs_is_cannot_tell_at_medium(self):
        """The issue_comment pattern: a step asks the API for the head commit and the checkout takes
        its output. What the output holds is not in the file, so the finding says the checker cannot
        tell, at medium; a step's output named `base` is reported the same way."""
        cases = ["ref: ${{ steps.pr.outputs.sha }}", "ref: ${{ needs.resolve.outputs.sha }}",
                 "ref: ${{ env.NOT_SET_IN_THE_FILE }}", "ref: ${{ inputs.ref }}"]
        with TempDir() as tmp:
            for line in cases:
                with self.subTest(line=line):
                    found = of(check(tmp, checkout_job([line], on="issue_comment")), "OBAAF-GHA-002")
                    self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "checkout-unresolved")])

    def test_inputs_written_as_one_expression_are_cannot_tell(self):
        text = (f"on: pull_request_target\npermissions: {{}}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
                f"      - uses: {CHECKOUT}\n        with: ${{{{ fromJSON(vars.CHECKOUT) }}}}\n")
        with TempDir() as tmp:
            found = of(check(tmp, text), "OBAAF-GHA-002")
        self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "checkout-unresolved")])

    def test_the_base_repositorys_own_code_is_no_finding(self):
        cases = ["ref: ${{ github.sha }}", "ref: ${{ github.event.pull_request.base.sha }}", "ref: main",
                 "ref: ${{ github.event.repository.default_branch }}", "repository: octo-org/tools",
                 "repository: ${{ github.repository }}"]
        with TempDir() as tmp:
            for line in cases:
                with self.subTest(line=line):
                    self.assertEqual(of(check(tmp, checkout_job([line])), "OBAAF-GHA-002"), [])


class FetchCommandsAreReadByWhatTheyDoTest(unittest.TestCase):
    """OBAAF-GHA-002 knew one spelling of each command (`git fetch ... pull/`, `gh pr checkout`,
    `git checkout ${{ ...head`). A global option, a path or quotes before the command, another
    subcommand (`pull`, `clone`, `reset`), a line continuation, a SHA from an env value, a docker
    step's arguments, a github-script or Python script, `gh pr diff | git apply`, a patch or archive
    fetched with curl or `gh api` all brought the pull request's code in with no finding. Now a line
    that runs a command that brings code in, and names the pull request's code (directly, through
    env, through a variable set earlier in the step, or by its number on that line), is reported."""

    SCRIPTS = [
        'git fetch origin ${{ github.event.pull_request.head.sha }}\ngit checkout FETCH_HEAD',
        'git -c advice.detachedHead=false checkout ${{ github.event.pull_request.head.sha }}',
        'git -C . fetch origin pull/${{ github.event.number }}/head',
        'git pull origin pull/${{ github.event.number }}/head',
        'git clone --branch "$HEAD_REF" "$CLONE_URL" pr',
        'git fetch \\\n  origin refs/pull/${{ github.event.number }}/head',
        'gh pr diff ${{ github.event.number }} | git apply',
        'curl -sL "${{ github.event.pull_request.patch_url }}" | git apply',
        '/usr/bin/gh pr checkout ${{ github.event.number }}',
        '"gh" pr checkout ${{ github.event.number }}',
        'gh pr --repo ${{ github.repository }} checkout ${{ github.event.number }}',
        'gh api repos/$FORK/tarball/${{ github.event.pull_request.head.sha }} | tar xz',
        'git fetch origin ${{ github.event.pull_request.head.sha }}\ngit reset --hard ${{ github.event.pull_request.head.sha }}',
        'SHA=$(gh pr view "$N" --json headRefOid -q .headRefOid)\ngit fetch origin "$SHA"',
        'SHA=$(jq -r .pull_request.head.sha "$GITHUB_EVENT_PATH")\ngit checkout "$SHA"',
    ]
    ENV = ("        env:\n          HEAD_REF: ${{ github.event.pull_request.head.ref }}\n"
           "          CLONE_URL: ${{ github.event.pull_request.head.repo.clone_url }}\n"
           "          FORK: ${{ github.event.pull_request.head.repo.full_name }}\n"
           "          N: ${{ github.event.number }}\n")

    def test_every_spelling_is_reported_high(self):
        with TempDir() as tmp:
            for script in self.SCRIPTS:
                with self.subTest(script=script[:60]):
                    found = of(check(tmp, script_job(script, env=self.ENV)), "OBAAF-GHA-002")
                    self.assertEqual([(f.severity, f.kind) for f in found], [("high", "fetch")])

    def test_other_ways_to_run_a_command(self):
        github_script = (f"actions/github-script@{SHA}\n        with:\n          script: |\n"
                         "            await exec.exec('git', ['fetch', 'origin', `refs/pull/${context.issue.number}/head`])\n")
        docker = ("docker://alpine/git@sha256:" + "a" * 64 + "\n        with:\n          entrypoint: /bin/sh\n"
                  "          args: -c \"git fetch origin refs/pull/${{ github.event.number }}/head && git checkout FETCH_HEAD\"\n")
        python = ("shell: python\n        run: |\n          import subprocess\n"
                  "          subprocess.run(['git', 'fetch', 'origin', 'refs/pull/${{ github.event.number }}/head'])\n")
        with TempDir() as tmp:
            for name, text in (("github-script", script_job("", uses=github_script)),
                               ("docker", script_job("", uses=docker)),
                               ("python", script_job("x").replace("run: |\n          x\n", python))):
                with self.subTest(name=name):
                    found = of(check(tmp, text), "OBAAF-GHA-002")
                    self.assertEqual([(f.severity, f.kind) for f in found], [("high", "fetch")])

    def test_a_command_with_a_value_computed_while_the_job_runs_is_cannot_tell(self):
        with TempDir() as tmp:
            for script in ('git fetch origin ${{ steps.pr.outputs.sha }}',
                           'git checkout "$SHA"'):
                with self.subTest(script=script):
                    env = "        env:\n          SHA: ${{ needs.resolve.outputs.sha }}\n"
                    found = of(check(tmp, script_job(script, on="issue_comment", env=env)), "OBAAF-GHA-002")
                    self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "fetch-unresolved")])

    def test_what_brings_no_code_in_is_no_finding(self):
        """The pull request's diff kept as data, a comment on the pull request, a branch created at
        the current commit, and the head named on a line that runs no such command."""
        scripts = ['gh pr diff "$N" > "$RUNNER_TEMP/pr.diff"',
                   'gh pr comment "$N" --body "Thanks"',
                   'gh api repos/${{ github.repository }}/issues/${{ github.event.number }}/comments -f body=x',
                   'git switch -c "obaaf/${{ steps.x.outputs.digest }}"',
                   'echo "${{ github.event.pull_request.head.ref }}"\ngit fetch origin main']
        with TempDir() as tmp:
            for script in scripts:
                with self.subTest(script=script):
                    self.assertEqual(of(check(tmp, script_job(script, env=self.ENV)), "OBAAF-GHA-002"), [])


class UnsafeCheckoutOptInTest(unittest.TestCase):
    """OBAAF-GHA-019 tested the text of `allow-unsafe-pr-checkout` for `true`, so an expression
    that evaluates to true (`${{ true }}`, `${{ 'true' }}`, a comparison, an env value) opted in with
    no finding. Now anything but a plainly false value counts."""

    def test_an_expression_opts_in(self):
        with TempDir() as tmp:
            for value in ("${{ true }}", "${{ 'true' }}", "${{ github.event_name == 'pull_request_target' }}",
                          "${{ env.UNSAFE }}", "${{ format('{0}', true) }}", "yes"):
                with self.subTest(value=value):
                    text = checkout_job([f"allow-unsafe-pr-checkout: \"{value}\"", "ref: main"])
                    self.assertEqual(len(of(check(tmp, text), "OBAAF-GHA-019")), 1)

    def test_a_false_value_does_not(self):
        with TempDir() as tmp:
            for value in ("false", "False", "${{ false }}", "${{ 'false' }}"):
                with self.subTest(value=value):
                    text = checkout_job([f"allow-unsafe-pr-checkout: \"{value}\"", "ref: main"])
                    self.assertEqual(of(check(tmp, text), "OBAAF-GHA-019"), [])


class TokenKeptOnDiskTest(unittest.TestCase):
    """OBAAF-GHA-011 applied to a job in the untrusted lane, which needs every trigger to be a pull
    request's, so `on: [pull_request, workflow_dispatch]` kept the token with no finding. Now any job
    an outsider's event can start is covered. Its facts now hold the triggers, whether it is an agent
    job and what the token can write, so an acceptance for a read-only pull_request job does not cover
    a pull_request_target job that can write."""

    def wf(self, on, permissions="{contents: read}", value=None):
        given = f"        with:\n          persist-credentials: {value}\n" if value is not None else ""
        return (f"on: {on}\npermissions: {permissions}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
                f"      - uses: {CHECKOUT}\n{given}")

    def test_a_job_a_pull_request_can_start_is_covered_whatever_else_starts_it(self):
        with TempDir() as tmp:
            for on in ("[pull_request, workflow_dispatch]", "[pull_request, schedule]", "pull_request"):
                with self.subTest(on=on):
                    self.assertEqual(len(of(check(tmp, self.wf(on)), "OBAAF-GHA-011")), 1)

    def test_values_actions_checkout_reads_as_false(self):
        with TempDir() as tmp:
            for value in ("false", "'${{ false }}'", "\"${{ 'false' }}\"", "off", "no", "0"):
                with self.subTest(value=value):
                    self.assertEqual(of(check(tmp, self.wf("pull_request", value=value)), "OBAAF-GHA-011"), [])
            for value in ("true", "TRUE", "", "${{ vars.KEEP }}"):
                with self.subTest(value=value):
                    self.assertEqual(len(of(check(tmp, self.wf("pull_request", value=f"'{value}'")),
                                            "OBAAF-GHA-011")), 1)

    def test_the_triggers_and_the_token_are_part_of_the_finding(self):
        with TempDir() as tmp:
            low = of(check(tmp, self.wf("pull_request")), "OBAAF-GHA-011")[0]
            high = of(check(tmp, self.wf("pull_request_target", "{contents: write}")), "OBAAF-GHA-011")[0]
        self.assertNotEqual(baseline.key(low), baseline.key(high))
        self.assertEqual(high.facts["scopes"], ["contents"])
        self.assertEqual(high.facts["triggers"], ["pull_request_target"])

    def test_an_agent_run_by_its_path_makes_an_agent_job(self):
        text = (f"on: workflow_dispatch\npermissions: {{contents: write}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n      - uses: {CHECKOUT}\n      - run: $HOME/.local/bin/claude -p \"Fix the tests\"\n")
        with TempDir() as tmp:
            found = of(check(tmp, text), "OBAAF-GHA-011")
        self.assertEqual(len(found), 1)
        self.assertIs(found[0].facts["agent"], True)


class AgentInstructionsFromTheChangeTest(unittest.TestCase):
    """OBAAF-GHA-012 skipped any `ref` whose text held the word `base`, took the merge commit only
    for `pull_request` with no `ref`, never looked at `repository`, and knew the fetch commands
    OBAAF-GHA-002 knew. `head.sha || base.sha`, `github.sha` or `github.ref` on a pull request, the
    review events' default checkout, the head repository, `git show HEAD:CLAUDE.md` and the contents
    API all gave the agent the pull request's instruction files with no finding."""

    def agent_wf(self, on, step):
        return (f"on: {on}\npermissions: {{contents: read}}\njobs:\n  review:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n{step}" + AGENT)

    def checkout(self, *lines):
        body = "".join(f"          {line}\n" for line in lines)
        return f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: false\n{body}"

    def test_the_head_however_it_is_named(self):
        cases = [("pull_request", self.checkout("ref: ${{ github.event.pull_request.head.sha || github.event.pull_request.base.sha }}")),
                 ("pull_request", self.checkout("ref: ${{ GITHUB.EVENT.PULL_REQUEST.HEAD['SHA'] }}")),
                 ("pull_request_target", self.checkout("repository: ${{ github.event.pull_request.head.repo.full_name }}"))]
        with TempDir() as tmp:
            for on, step in cases:
                with self.subTest(step=step[-60:]):
                    found = of(check(tmp, self.agent_wf(on, step)), "OBAAF-GHA-012")
                    self.assertEqual([f.kind for f in found], ["head"])

    def test_the_merge_commit_on_every_event_whose_ref_it_is(self):
        cases = [("pull_request", self.checkout("ref: ${{ github.sha }}")),
                 ("pull_request", self.checkout("ref: ${{ github.ref }}")),
                 ("pull_request_review", f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: false\n"),
                 ("pull_request_review_comment", f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: false\n")]
        with TempDir() as tmp:
            for on, step in cases:
                with self.subTest(on=on, step=step[-40:]):
                    found = of(check(tmp, self.agent_wf(on, step)), "OBAAF-GHA-012")
                    self.assertEqual([f.kind for f in found], ["merge-commit"])
                    self.assertEqual(found[0].facts["triggers"], [on])

    def test_instruction_files_fetched_by_a_script(self):
        env = "        env:\n          GH_TOKEN: ${{ github.token }}\n"
        scripts = ["git fetch origin ${{ github.event.pull_request.head.sha }}\ngit checkout FETCH_HEAD",
                   "git show ${{ github.event.pull_request.head.sha }}:CLAUDE.md > CLAUDE.md",
                   "gh api \"repos/${{ github.repository }}/contents/CLAUDE.md?ref=${{ github.event.pull_request.head.sha }}\" > CLAUDE.md"]
        with TempDir() as tmp:
            for script in scripts:
                with self.subTest(script=script[:50]):
                    lines = "".join(f"          {line}\n" for line in script.splitlines())
                    step = self.checkout() + f"      - name: Fetch\n{env}        run: |\n{lines}"
                    found = of(check(tmp, self.agent_wf("pull_request_target", step)), "OBAAF-GHA-012")
                    self.assertEqual([f.kind for f in found], ["fetch"])

    def test_a_ref_computed_while_the_job_runs_is_cannot_tell(self):
        step = self.checkout("ref: ${{ steps.pr.outputs.sha }}")
        with TempDir() as tmp:
            found = of(check(tmp, self.agent_wf("issue_comment", step)), "OBAAF-GHA-012")
            self.assertEqual([(f.severity, f.kind) for f in found], [("medium", "unresolved")])
            # On a push, which only people with write access cause, it is not reported.
            self.assertEqual(of(check(tmp, self.agent_wf("push", step)), "OBAAF-GHA-012"), [])

    def test_the_triggers_are_part_of_the_finding(self):
        step = self.checkout("ref: ${{ github.event.pull_request.head.sha }}")
        with TempDir() as tmp:
            a = of(check(tmp, self.agent_wf("pull_request", step)), "OBAAF-GHA-012")[0]
            b = of(check(tmp, self.agent_wf("pull_request_target", step)), "OBAAF-GHA-012")[0]
        self.assertNotEqual(baseline.key(a), baseline.key(b))


class GuardIsPartOfTheFindingTest(unittest.TestCase):
    """An acceptance of a checkout guarded to pull requests from the same repository covered the
    same checkout without the guard: the finding's facts were only its triggers. The job's and the
    step's `if:` are now part of it, and so is what was checked out."""

    def test_an_acceptance_of_the_guarded_step_does_not_cover_the_unguarded_one(self):
        guard = "    if: github.event.pull_request.head.repo.full_name == github.repository\n"
        line = ["ref: ${{ github.event.pull_request.head.sha }}"]
        with TempDir() as tmp:
            guarded = of(check(tmp, checkout_job(line, job_extra=guard)), "OBAAF-GHA-002")[0]
            plain = of(check(tmp, checkout_job(line)), "OBAAF-GHA-002")[0]
        self.assertNotEqual(baseline.key(guarded), baseline.key(plain))
        self.assertEqual(plain.facts["condition"], [])
        self.assertTrue(guarded.facts["condition"][0].startswith("job: "))


class ReleasedBaselinesStillNameTheirFindingsTest(unittest.TestCase):
    """The messages of OBAAF-GHA-002, 011, 012 and 019 now say more. A v0.1 baseline (0.3.0)
    identifies a finding by its message, so each finding carries the message 0.3.0 wrote for it, and
    `obaaf baseline migrate` still carries such an entry over."""

    def test_the_old_message_is_kept_for_the_old_fingerprint(self):
        with TempDir() as tmp:
            found = of(check(tmp, checkout_job(["ref: ${{ github.event.pull_request.head.sha }}"])), "OBAAF-GHA-002")[0]
        self.assertEqual(found.legacy, "Step 'actions/checkout@" + SHA + "' checks out pull-request code in a "
                                       "workflow started by pull_request_target.")
        self.assertNotEqual(found.message, found.legacy)
        self.assertEqual(baseline._identity_v1(found)[-1], found.legacy)


class ReaderUnitTest(unittest.TestCase):
    def test_pr_code_states(self):
        self.assertEqual(pr_code("${{ github.event.pull_request.head.sha }}").state, "head")
        self.assertEqual(pr_code("refs/pull/7/merge").state, "head")
        self.assertEqual(pr_code("${{ steps.x.outputs.y }}").state, "unresolved")
        self.assertEqual(pr_code("${{ github.sha }}").state, "base")
        self.assertEqual(pr_code("").state, "base")
        # Flags of the head repository name no code.
        self.assertEqual(pr_code("${{ github.event.pull_request.head.repo.fork }}").state, "unresolved")


if __name__ == "__main__":
    unittest.main()
