"""OBAAF-GHA-027 read the fail-closed way (review of #366, run `rosefinch`).

An independent attacker got past the first reading 56 times in 89 attempts: it looked at the first word of
each line for a short list of commands, and at the upload's layout to rule files out. Now every later step
that names the download's folder, or every later step when the folder is the workspace or cannot be read,
is reported unless it is plainly read-only; each case below was a way past, a false positive or a cost.
"""

import time
import unittest

from obaaf.checker.rules import CANNOT_TELL, VERIFIED
from test_egress_artifact_producers import ROUTES
from test_egress_recognised import CHECKOUT, FIREWALL, SHA, egress, keyed, run_check, secret_finding, verdict, workflow

AGENT_LANE = {".github/workflows/agent.yml#agent": "agent"}


def producer(upload_with="{name: report, path: out/}", action="upload-artifact", route="action"):
    runner, steps, _ = ROUTES[route]
    return workflow(steps + f"\n      - uses: actions/{action}@{SHA}\n        with: {upload_with}", runs_on=runner)


def consumer(*steps, download_with="{name: report, path: result}", job="use"):
    body = "".join(steps)
    return (f"  {job}:\n    needs: agent\n    runs-on: ubuntu-24.04\n    steps:\n"
            f"      - uses: actions/download-artifact@{SHA}\n        with: {download_with}\n" + body)


def run(cmd, extra=""):
    return f"      - name: consume\n        run: {cmd}\n{extra}"


def found(result, rule="OBAAF-GHA-027"):
    return [f for f in result.findings if f.rule == rule]


class ExecutionFormsTest(unittest.TestCase):
    def test_every_step_that_names_the_download_and_is_not_read_only_is_reported(self):
        reported = {
            "a path run directly": run("result/run.sh"),
            "chmod then run": run("chmod +x result/run.sh && ./result/run.sh"),
            "an interpreter option": run("bash -e result/run.sh"),
            "source": run("source result/env.sh"),
            "dot": run(". result/env.sh"),
            "npm ci in the folder": run("npm ci", "        working-directory: result\n"),
            "npm install in the folder": run("npm install", "        working-directory: ./result\n"),
            "pip install": run("pip install ./result"),
            "pytest in the folder": run("pytest", "        working-directory: result\n"),
            "python -m pytest": run("python -m pytest result"),
            "make -C": run("make -C result"),
            "make -j4 in the folder": run("make -j4", "        working-directory: result\n"),
            "cd then a semicolon": run("'cd result; ./run.sh'"),
            "perl": run("perl result/x.pl"),
            "an assignment first": run("FOO=1 ./result/run.sh"),
            "sudo": run("sudo ./result/run.sh"),
            "exec": run("exec ./result/run.sh"),
            "echo then run": run("echo go && ./result/run.sh"),
            "npx": run("npx ./result"),
            "if": run("'if [ -f result/x ]; then ./result/run.sh; fi'"),
            "a pipe into bash": run("cat result/x | bash"),
            "docker build": run("docker build result"),
            "the workspace variable": run("bash \"$GITHUB_WORKSPACE/result/run.sh\""),
            "an env value": run("bash \"$DIR/run.sh\"", "        env: {DIR: result}\n"),
            "a local action from the download": "      - name: consume\n        uses: ./result/action\n",
            "the download itself as an action": "      - name: consume\n        uses: ./result\n",
            "a line continued": "      - name: consume\n        run: |\n          bash \\\n            result/run.sh\n",
            "pushd then a second line": "      - name: consume\n        run: |\n          pushd result\n          ./run.sh\n",
        }
        base = producer()
        for name, step in reported.items():
            with self.subTest(name):
                result = run_check(base + consumer(step))
                self.assertEqual([(f.job, f.step) for f in found(result)], [("use", "consume")], name)
                self.assertEqual(verdict(egress(result)), VERIFIED)

    def test_read_only_steps_and_steps_that_do_not_name_the_download_are_not(self):
        quiet = {
            "cat": run("cat result/report.txt"),
            "echo": run("echo ./result/report.txt"),
            "ls": run("ls -la result"),
            "the step summary": run("jq . result/r.json >> \"$GITHUB_STEP_SUMMARY\""),
            "a pipe of readers": run("grep -r TODO result | head -5"),
            "checksums": run("sha256sum result/a result/b"),
            "a test": run("'[ -s result/report.txt ] && echo present'"),
            "another folder's script": run("./scripts/test.sh"),
            "a build of the checkout": run("npm test"),
            "a folder with the download's name as a prefix": run("bash results/run.sh"),
            "an upload of the download": f"      - name: consume\n        uses: actions/upload-artifact@{SHA}\n"
                                         "        with: {name: copy, path: result}\n",
        }
        base = producer()
        for name, step in quiet.items():
            with self.subTest(name):
                self.assertEqual(found(run_check(base + consumer(step))), [], name)

    def test_writing_the_download_where_later_steps_read_settings_is_not_read_only(self):
        for cmd in ("cat result/env >> \"$GITHUB_ENV\"", "cat result/p >> $GITHUB_PATH", "cat result/x > run.sh",
                    "cat result/x 2>&1 | tee out", "cat <<EOF result/x"):
            with self.subTest(cmd):
                self.assertEqual(len(found(run_check(producer() + consumer(run(f"'{cmd}'"))))), 1)


class LayoutsTest(unittest.TestCase):
    def test_upload_paths_do_not_rule_files_out(self):
        several = "\n          name: report\n          path: |\n            a/x.sh\n            b/y.sh"
        for upload in [f"{{name: report, path: {path}}}" for path in
                       ("out", "out/*.sh", "'out.d'", ".agent-out", "build-1.2", "report.txt")] + [several]:
            with self.subTest(upload=upload):
                result = run_check(producer(upload) + consumer(run("./result/build.sh")))
                self.assertEqual(len(found(result)), 1)

    def test_a_download_into_the_workspace_reaches_every_step_that_is_not_read_only(self):
        for download in ("{name: report}", "{name: report, path: .}", "{name: report, path: ./}",
                         "{name: report, path: '${{ github.workspace }}'}"):
            with self.subTest(download=download):
                result = run_check(producer() + consumer(run("cat README.md"), run("npm test"),
                                                         download_with=download))
                self.assertEqual([f.facts["path"] for f in found(result)], ["package.json"])

    def test_a_computed_folder_is_any_folder(self):
        result = run_check(producer() + consumer(run("./scripts/test.sh"),
                                                 download_with="{name: report, path: '${{ env.D }}'}"))
        self.assertEqual([f.facts["path"] for f in found(result)], ["scripts/test.sh"])

    def test_absolute_and_home_folders(self):
        for path, cmd in (("/tmp/art", "bash /tmp/art/x.sh"), ("~/art", "bash \"$HOME/art/x.sh\""),
                          ("~/art", "bash ~/art/x.sh"), ("/tmp/art", "./x.sh\n        working-directory: /tmp/art")):
            with self.subTest(path=path, cmd=cmd):
                result = run_check(producer() + consumer(run(cmd), download_with=f"{{name: report, path: '{path}'}}"))
                self.assertEqual(len(found(result)), 1)

    def test_a_download_of_every_artifact_writes_each_into_a_folder_of_its_name(self):
        base = producer()
        for cmd, count in (("bash dl/report/x.sh", 1), ("bash dl/other/x.sh", 0)):
            with self.subTest(cmd=cmd):
                result = run_check(base + consumer(run(cmd), download_with="{path: dl}"))
                self.assertEqual(len(found(result)), count)
        merged = run_check(base + consumer(run("bash dl/x.sh"), download_with="{path: dl, merge-multiple: true}"))
        self.assertEqual(len(found(merged)), 1)
        patterned = run_check(base + consumer(run("bash dl/report/x.sh"), download_with="{path: dl, pattern: rep*}"))
        self.assertEqual(len(found(patterned)), 1)
        other = run_check(base + consumer(run("bash dl/report/x.sh"), download_with="{path: dl, pattern: zzz*}"))
        self.assertEqual(found(other), [])

    def test_names_the_first_reading_refused(self):
        for upload, download in (("{name: 5, path: out/}", "{name: 5, path: result}"),
                                 ("{name: patch+tests, path: out/}", "{name: patch+tests, path: result}"),
                                 ("{name: Report, path: out/}", "{name: report, path: result}"),
                                 ("{name: '${{ github.sha }}', path: out/}", "{name: report, path: result}"),
                                 ("{path: out/}", "{name: artifact, path: result}")):
            with self.subTest(upload=upload):
                result = run_check(producer(upload) + consumer(run("./result/x.sh"), download_with=download))
                self.assertEqual(len(found(result)), 1)

    def test_merged_and_pages_uploads_are_followed(self):
        for action, upload, name in (("upload-artifact/merge", "{name: all}", "all"),
                                     ("upload-artifact/merge", "{pattern: '*'}", "merged-artifacts"),
                                     ("upload-pages-artifact", "{path: out/}", "github-pages")):
            with self.subTest(action=action, upload=upload):
                result = run_check(producer(upload, action=action)
                                   + consumer(run("./result/x.sh"), download_with=f"{{name: {name}, path: result}}"))
                self.assertEqual(len(found(result)), 1)


class RunsTest(unittest.TestCase):
    CALLED = ("on: workflow_call\npermissions: {}\njobs:\n  agent:\n    runs-on: ubuntu-24.04\n"
              "    permissions: {contents: read}\n    steps:\n      - run: claude -p review\n"
              f"      - uses: actions/upload-artifact@{SHA}\n        with: {{name: report, path: out/}}\n")
    LANES = {"lanes": {".github/workflows/called.yml#agent": "agent"}}

    def test_a_called_workflow_is_part_of_the_callers_run(self):
        caller = ("on: workflow_dispatch\npermissions: {}\njobs:\n  produce:\n    uses: ./.github/workflows/called.yml\n"
                  + consumer(run("./result/run.sh")).replace("needs: agent", "needs: produce"))
        result = run_check(caller, files={".github/workflows/called.yml": self.CALLED}, config=self.LANES)
        self.assertEqual([(f.path, f.job) for f in found(result)], [(".github/workflows/agent.yml", "use")])

    def test_a_consumer_in_a_called_workflow(self):
        called = ("on: workflow_call\npermissions: {}\njobs:\n" + consumer(run("./result/run.sh")).replace(
            "    needs: agent\n", ""))
        caller = producer() + "  use:\n    needs: agent\n    uses: ./.github/workflows/called.yml\n"
        result = run_check(caller, files={".github/workflows/called.yml": called})
        self.assertEqual([(f.path, f.job) for f in found(result)], [(".github/workflows/called.yml", "use")])

    def test_workflow_run_from_a_caller_of_the_agent_and_from_an_unnamed_producer(self):
        subscriber = ("on:\n  workflow_run:\n    workflows: [{name}]\n    types: [completed]\npermissions: {{}}\n"
                      "jobs:\n  read:\n    runs-on: ubuntu-24.04\n    steps:\n"
                      f"      - uses: actions/download-artifact@{SHA}\n"
                      "        with:\n          name: report\n          path: result\n"
                      "          run-id: '${{{{ github.event.workflow_run.id }}}}'\n"
                      "          github-token: '${{{{ github.token }}}}'\n"
                      "      - run: sh result/report.sh\n")
        caller = "name: Caller\non: push\npermissions: {}\njobs:\n  produce:\n    uses: ./.github/workflows/called.yml\n"
        for name, count in (("Caller", 1), ("Elsewhere", 0)):
            with self.subTest(name=name):
                result = run_check(caller, config=self.LANES, files={
                    ".github/workflows/called.yml": self.CALLED,
                    ".github/workflows/read.yml": subscriber.format(name=name)})
                self.assertEqual(len(found(result)), count)
        unnamed = run_check(producer(), files={
            ".github/workflows/read.yml": subscriber.format(name=".github/workflows/agent.yml")})
        self.assertEqual(len(found(unnamed)), 1)

    def test_a_run_id_without_a_token_is_the_current_run(self):
        download = "{name: report, path: result, run-id: '123'}"
        self.assertEqual(len(found(run_check(producer() + consumer(run("./result/x.sh"), download_with=download)))), 1)


    def test_the_current_run_by_its_id_and_workflow_names_in_any_case(self):
        download = "{name: report, path: result, run-id: '${{ github.run_id }}', github-token: '${{ github.token }}'}"
        self.assertEqual(len(found(run_check(producer() + consumer(run("./result/x.sh"), download_with=download)))), 1)
        subscriber = ("on:\n  workflow_run:\n    workflows: [producer]\n    types: [completed]\npermissions: {}\n"
                      "jobs:\n  read:\n    runs-on: ubuntu-24.04\n    steps:\n"
                      f"      - uses: actions/download-artifact@{SHA}\n"
                      "        with: {name: report, path: result, run-id: '${{ github.event.workflow_run.id }}', "
                      "github-token: '${{ github.token }}'}\n      - run: sh result/report.sh\n")
        result = run_check("name: Producer\n" + producer(), files={".github/workflows/read.yml": subscriber})
        self.assertEqual(len(found(result)), 1)

    def test_an_upload_in_a_local_composite_action_and_a_merge_in_another_job(self):
        composite = ("runs:\n  using: composite\n  steps:\n"
                     f"    - uses: actions/upload-artifact@{SHA}\n      with: {{name: report, path: out/}}\n")
        _, steps, _ = ROUTES["action"]
        text = workflow(steps + "\n      - uses: ./.github/actions/up") + consumer(run("./result/x.sh"))
        result = run_check(text, files={".github/actions/up/action.yml": composite})
        self.assertEqual(len(found(result)), 1)
        merge = (f"  merge:\n    needs: agent\n    runs-on: ubuntu-24.04\n    steps:\n"
                 f"      - uses: actions/upload-artifact/merge@{SHA}\n        with: {{name: all, pattern: rep*}}\n")
        merged = run_check(producer() + merge + consumer(run("./result/x.sh"), download_with="{name: all, path: result}"))
        self.assertEqual(len(found(merged)), 1)
        unrelated = merge.replace("rep*", "zzz*")
        self.assertEqual(found(run_check(producer() + unrelated + consumer(run("./result/x.sh"),
                                                                           download_with="{name: all, path: result}"))), [])


class FalsePositivesTest(unittest.TestCase):
    def test_a_group_written_to_the_step_summary_is_read_only(self):
        step = ("      - name: consume\n        run: |\n          {\n            echo '## Report'\n"
                "            cat result/summary.md\n          } >> \"$GITHUB_STEP_SUMMARY\"\n")
        self.assertEqual(found(run_check(producer() + consumer(step))), [])
        worse = step.replace("cat result/summary.md", "./result/run.sh")
        self.assertEqual(len(found(run_check(producer() + consumer(worse)))), 1)

    def test_a_download_into_another_folder_leaves_unrelated_steps_alone(self):
        result = run_check(producer() + consumer(run("cat result/report.txt"), run("./scripts/test.sh"),
                                                 run("make test")))
        self.assertEqual(found(result), [])


class OpenSslTest(unittest.TestCase):
    def test_openssl_names_steer_the_steps_outside_the_sandbox(self):
        """Node.js loads the configuration `OPENSSL_CONF` names, and the libraries it names, when it starts
        (reproduced with Node.js 22 by the review's attacker); every action after the confined step is Node.js."""
        _, steps, _ = ROUTES["action"]
        after = workflow(steps + f"\n      - uses: actions/upload-artifact@{SHA}\n"
                                 "        env: {OPENSSL_CONF: ./openssl.cnf}\n        with: {name: r, path: out/}")
        self.assertEqual(verdict(egress(run_check(after))), CANNOT_TELL)
        top = workflow(steps + f"\n      - uses: actions/upload-artifact@{SHA}\n        with: {{name: r, path: out/}}",
                       top="env: {openssl_modules: ./m}")
        self.assertEqual(verdict(egress(run_check(top))), CANNOT_TELL)
        before = workflow(f"      - uses: actions/checkout@{SHA}\n        with: {{persist-credentials: false}}\n"
                          "        env: {OPENSSL_CONF: ./openssl.cnf}\n" + keyed())
        checked = run_check(before)
        self.assertEqual(verdict(egress(checked)), CANNOT_TELL)
        controls = {c.id: c.verdict for c in secret_finding(checked).controls}
        self.assertEqual(controls["key-out-of-reach"], CANNOT_TELL)


class CostTest(unittest.TestCase):
    def test_findings_and_time_grow_with_the_steps_not_their_product(self):
        n = 120
        uploads = "".join(f"\n      - uses: actions/upload-artifact@{SHA}\n        with: {{name: a{i}, path: out{i}/}}"
                          for i in range(n))
        downloads = "".join(f"      - uses: actions/download-artifact@{SHA}\n        with: {{name: a{i}, path: result}}\n"
                            for i in range(n))
        runs = "".join(f"      - run: sh result/run{i}.sh\n" for i in range(n))
        _, steps, _ = ROUTES["action"]
        text = workflow(steps + uploads) + "  use:\n    needs: agent\n    runs-on: ubuntu-24.04\n    steps:\n" + downloads + runs
        started = time.monotonic()
        result = run_check(text)
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(len(found(result)), n)
        quiet = text.replace("path: result}", "path: elsewhere}")
        started = time.monotonic()
        self.assertEqual(found(run_check(quiet)), [])
        self.assertLess(time.monotonic() - started, 20)


if __name__ == "__main__":
    unittest.main()
