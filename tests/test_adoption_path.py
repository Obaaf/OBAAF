"""The two paths the documents describe, run in the order they are written.

`docs/from-report-to-gate.md` takes a team from reading the report to a check that fails a build, and
`docs/upgrading.md` takes a repository from release 0.3.0 to the code after it. Each gives a command
and the exit status it ends with. These tests run the commands in the pages' order on the small
repository in `tests/fixtures/adoption`, whose baseline was written by the real 0.3.0, and check the
status of each. They do not run 0.3.0, and they do not check every sentence of the pages: an
independent review found seven untrue ones while this file passed.
"""

import json
import re
import shlex
import shutil
import unittest
from datetime import date, timedelta

from helpers import FIXTURES, ROOT, TempDir, run_cli

from obaaf import cli

ADOPTION = FIXTURES / "adoption"
BASELINE = ".github/obaaf-baseline.json"
OWNER = "@my-org/build"
DOCS = (ROOT / "docs" / "from-report-to-gate.md", ROOT / "docs" / "upgrading.md")


TODAY = date.today()        # read once, so a run that crosses midnight compares like with like


def day(ahead: int) -> str:
    return (TODAY + timedelta(days=ahead)).isoformat()


def repository(tmp, baseline: bool):
    """A copy of the fixture: two workflows, one job declared `OBAAF_LANE: agnet`, and, with
    `baseline`, the baseline release 0.3.0 wrote for it."""
    shutil.copytree(ADOPTION, tmp, dirs_exist_ok=True)
    if not baseline:
        (tmp / BASELINE).unlink()
    return tmp


def edit(tmp, name: str, old: str, new: str) -> None:
    path = tmp / ".github" / "workflows" / name
    text = path.read_text(encoding="utf-8")
    assert old in text, (name, old)
    path.write_text(text.replace(old, new), encoding="utf-8")


def accept(tmp, reason: str, expires: str):
    return run_cli("check", tmp, "--write-baseline", tmp / BASELINE, "--owner", OWNER, "--reason", reason,
                   "--expires", expires)


class FromAReportToAGateTest(unittest.TestCase):
    def test_the_path_as_the_page_gives_it(self):
        with TempDir() as tmp:
            repository(tmp, baseline=False)
            gate = ("check", tmp, "--baseline", tmp / BASELINE, "--fail-on", "medium")

            # 1. Read the report, and fail nothing. An unreadable file still fails.
            code, out, _ = run_cli("check", tmp, "--fail-on", "never")
            self.assertEqual(code, 0)
            self.assertTrue(out.startswith("Accepted risk: none."), out[:80])
            broken = tmp / ".github" / "workflows" / "broken.yml"
            broken.write_text("on: [push\njobs: {", encoding="utf-8")
            self.assertEqual(run_cli("check", tmp, "--fail-on", "never")[0], 1)
            broken.unlink()
            self.assertEqual(run_cli("check", tmp)[0], 1)       # the default gate, before anything is accepted

            # 2. Which jobs run an agent: the declaration that does nothing is a note here, and a finding.
            code, out, err = run_cli("check", tmp, "--lanes")
            self.assertEqual(code, 0)
            self.assertIn(".github/workflows/triage.yml#triage: trusted (default)", out)
            self.assertIn("note: Lane declaration ignored: .github/workflows/triage.yml, line 12:", err)
            self.assertIn("OBAAF-CFG-001", err)
            edit(tmp, "triage.yml", "OBAAF_LANE: agnet", "OBAAF_LANE: agent")
            code, out, err = run_cli("check", tmp, "--lanes")
            self.assertIn(".github/workflows/triage.yml#triage: agent (set by OBAAF_LANE)", out)
            self.assertEqual(err, "")

            # 3. Fix what is cheap.
            edit(tmp, "ci.yml", "      - uses: actions/checkout@v4\n",
                 "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n"
                 "        with:\n          persist-credentials: false\n")

            # 4. Accept what is left, in somebody's name and until a date; without them nothing is written.
            code, _, err = run_cli("check", tmp, "--write-baseline", tmp / BASELINE)
            self.assertEqual(code, 2)
            self.assertFalse((tmp / BASELINE).exists())
            code, _, err = accept(tmp, "Inherited on adoption; tracked in issue 12", day(120))
            self.assertEqual(code, 0, err)
            self.assertIn(f"newly accepted by {OWNER} until {day(120)}", err)

            # 5. Fail on anything new.
            self.assertEqual(run_cli(*gate)[0], 0)
            edit(tmp, "ci.yml", "      - run: make test\n",
                 "      - uses: some-org/coverage-action@v1\n      - run: make test\n")
            code, out, _ = run_cli(*gate)
            self.assertEqual(code, 1)                           # a new finding at medium
            self.assertIn("OBAAF-GHA-008", out)
            edit(tmp, "ci.yml", "      - uses: some-org/coverage-action@v1\n", "")
            self.assertEqual(run_cli(*gate)[0], 0)

            # A finding that was fixed fails the gate once, until its entry is dropped.
            edit(tmp, "triage.yml", "      issues: write\n", "      issues: read\n")
            code, out, _ = run_cli(*gate)
            self.assertEqual(code, 1)
            self.assertIn("no longer found: OBAAF-GHA-003", out)
            code, _, err = accept(tmp, "unused", day(30))
            self.assertEqual(code, 0, err)
            self.assertIn("0 finding(s) newly accepted", err)   # the valid entries keep what they had
            entries = json.loads((tmp / BASELINE).read_text(encoding="utf-8"))["findings"]
            self.assertEqual({entry["expires"] for entry in entries}, {day(120)})
            self.assertEqual(run_cli(*gate)[0], 0)
            # And the same finding coming back is new.
            edit(tmp, "triage.yml", "      issues: read\n", "      issues: write\n")
            self.assertEqual(run_cli(*gate)[0], 1)

            # Code scanning is not the gate: the SARIF run reports and fails nothing.
            code, _, _ = run_cli("check", tmp, "--format", "sarif", "--output", tmp / "obaaf.sarif", "--fail-on", "never")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads((tmp / "obaaf.sarif").read_text(encoding="utf-8"))["version"], "2.1.0")

    def test_a_baseline_written_before_the_lanes_are_right_accepts_the_wrong_declaration(self):
        # Step 2 comes before step 4 for this reason: the declaration that does nothing is a
        # finding like any other, so a baseline written while it is there accepts it, and the
        # agent findings it hides are never seen.
        with TempDir() as tmp:
            repository(tmp, baseline=False)
            self.assertEqual(accept(tmp, "Inherited on adoption; tracked in issue 12", day(120))[0], 0)
            entries = json.loads((tmp / BASELINE).read_text(encoding="utf-8"))["findings"]
            code, out, _ = run_cli("check", tmp, "--baseline", tmp / BASELINE, "--fail-on", "medium")
        self.assertEqual([entry["kind"] for entry in entries if entry["rule"] == "OBAAF-CFG-001"], ["job-not-a-lane"])
        self.assertEqual(code, 0)
        self.assertNotIn("OBAAF-GHA-003", out)

    def test_lanes_fails_on_a_workflow_it_could_not_read_as_the_check_does(self):
        # Slice 3.2a: until then --lanes ended with 0 and said nothing of the file.
        with TempDir() as tmp:
            repository(tmp, baseline=False)
            (tmp / ".github" / "workflows" / "broken.yml").write_text("on: [push\njobs: {", encoding="utf-8")
            code, out, err = run_cli("check", tmp, "--lanes")
            report = run_cli("check", tmp, "--fail-on", "never")[0]
        self.assertEqual(code, 1)
        self.assertNotIn("broken.yml", out)
        self.assertIn("error: .github/workflows/broken.yml: cannot parse YAML", err)
        self.assertEqual(report, 1)

    def test_a_finding_left_out_of_the_baseline_because_its_ignore_entry_does_not_count(self):
        with TempDir() as tmp:
            repository(tmp, baseline=False)
            edit(tmp, "triage.yml", "OBAAF_LANE: agnet", "OBAAF_LANE: trusted")
            (tmp / ".github" / "obaaf.yml").write_text(
                f"ignore:\n  - rule: OBAAF-GHA-008\n    path: .github/workflows/ci.yml\n"
                f"    reason: The vendor publishes no commit SHAs\n    until: {day(90)}\n", encoding="utf-8")
            code, _, err = accept(tmp, "Inherited on adoption; tracked in issue 12", day(120))
            gate = run_cli("check", tmp, "--baseline", tmp / BASELINE, "--fail-on", "medium")[0]
        self.assertEqual(code, 0)
        self.assertIn("warning: 1 finding(s) whose ignore entry has expired or does not count were not written", err)
        self.assertEqual(gate, 1)

    def test_pinning_the_action_of_an_unnamed_step_makes_its_accepted_finding_new(self):
        with TempDir() as tmp:
            repository(tmp, baseline=False)
            edit(tmp, "triage.yml", "OBAAF_LANE: agnet", "OBAAF_LANE: trusted")
            self.assertEqual(accept(tmp, "Inherited on adoption; tracked in issue 12", day(120))[0], 0)
            edit(tmp, "ci.yml", "actions/checkout@v4", "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
            code, out, _ = run_cli("check", tmp, "--baseline", tmp / BASELINE, "--fail-on", "medium", "--format", "json")
            data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual([f["rule"] for f in data["findings"] if f["state"] == "new"], ["OBAAF-GHA-011"])
        self.assertEqual(sorted(entry["rule"] for entry in data["baseline"]["stale"]), ["OBAAF-GHA-008", "OBAAF-GHA-011"])

    def test_an_acceptance_that_has_run_out_counts_again_and_is_announced_before(self):
        with TempDir() as tmp:
            repository(tmp, baseline=False)
            edit(tmp, "triage.yml", "OBAAF_LANE: agnet", "OBAAF_LANE: trusted")
            self.assertEqual(accept(tmp, "Inherited on adoption; tracked in issue 12", day(10))[0], 0)
            code, out, _ = run_cli("check", tmp, "--baseline", tmp / BASELINE, "--fail-on", "medium")
            self.assertEqual(code, 0)
            self.assertIn("Expiring soon:", out)
            data = json.loads((tmp / BASELINE).read_text(encoding="utf-8"))
            for entry in data["findings"]:
                entry["expires"] = day(-1)
            (tmp / BASELINE).write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(run_cli("check", tmp, "--baseline", tmp / BASELINE, "--fail-on", "medium")[0], 1)


class UpgradingFromRelease030Test(unittest.TestCase):
    def test_one_upgrade_start_to_finish(self):
        with TempDir() as tmp:
            repository(tmp, baseline=True)
            old = json.loads((tmp / BASELINE).read_text(encoding="utf-8"))
            self.assertEqual((old["format"], old["tool"], len(old["findings"])), ("obaaf-baseline/v0.1", "obaaf 0.3.0", 4))
            gate = ("check", tmp, "--baseline", tmp / BASELINE, "--fail-on", "low")

            # The gate that passed with 0.3.0 ("4 accepted, 0 new", and a note) fails, and says how to go on.
            code, out, _ = run_cli(*gate)
            self.assertEqual(code, 1)
            self.assertIn("Baseline: 0 finding(s) accepted by the baseline, 5 new.", out)
            self.assertIn("The baseline is in the old format (obaaf-baseline/v0.1).", out)
            self.assertIn("obaaf baseline migrate", out)

            code, out, err = run_cli("baseline", "migrate", tmp / BASELINE, tmp, "--owner", OWNER,
                                     "--reason", "Inherited on adoption; tracked in issue 12", "--expires", day(120))
            self.assertEqual(code, 0, err)
            said = out + err
            self.assertIn("4 finding(s) carried over", said)
            self.assertIn("1 finding(s) were not in the old baseline and are not accepted by the new one", said)

            # One finding is left: the declaration that 0.3.0 listed in a note.
            code, out, _ = run_cli(*gate)
            self.assertEqual(code, 1)
            self.assertIn("Baseline: 4 finding(s) accepted by the baseline, 1 new.", out)
            self.assertIn("    12  HIGH   OBAAF-CFG-001  Lane declaration that does nothing  [job triage]", out)

            # Correcting it brings three findings nobody had seen.
            edit(tmp, "triage.yml", "OBAAF_LANE: agnet", "OBAAF_LANE: agent")
            code, out, _ = run_cli(*gate, "--format", "json")
            self.assertEqual(code, 1)
            self.assertEqual(sorted(f["rule"] for f in json.loads(out)["findings"] if f["state"] == "new"),
                             ["OBAAF-GHA-003", "OBAAF-GHA-005", "OBAAF-GHA-020"])

            code, _, err = accept(tmp, "Agent job needs an egress control; issue 31", day(80))
            self.assertEqual(code, 0, err)
            self.assertIn(f"3 finding(s) newly accepted by {OWNER} until {day(80)}, 4 kept with the owner, reason and "
                          "expiry date they had.", err)
            code, out, _ = run_cli(*gate)
            self.assertEqual(code, 0)
            self.assertTrue(out.startswith("Accepted risk: 7 finding(s) are accepted and do not fail the check "
                                           "(3 high, 2 medium, 2 low)."), out[:120])

    def test_what_the_table_says_of_ignore_entries(self):
        entry = ("ignore:\n  - rule: OBAAF-GHA-008\n    path: .github/workflows/ci.yml\n"
                 "    reason: %s\n    until: %s\n%s")
        cases = {
            "no owner": (entry % ("The vendor publishes no commit SHAs", day(90), ""), 1, "because it names no owner"),
            "a short reason": (entry % ("ok", day(90), f"    owner: '{OWNER}'\n"), 1,
                               "because its reason says too little (fewer than 4 letters or digits)"),
            "a date too far ahead": (entry % ("The vendor publishes no commit SHAs", day(400), f"    owner: '{OWNER}'\n"),
                                     1, "more than 366 days ahead"),
            "a time of day": (entry % ("The vendor publishes no commit SHAs", "2027-01-31T10:00:00Z",
                                       f"    owner: '{OWNER}'\n"), 2, "must be a date"),
            "a date in another spelling": (entry % ("The vendor publishes no commit SHAs", "20270131",
                                                    f"    owner: '{OWNER}'\n"), 2, "must be a date"),
            "the lane rule": (f"ignore:\n  - rule: OBAAF-CFG-001\n    path: .github/workflows/triage.yml\n"
                              f"    reason: The job is not an agent\n    until: {day(90)}\n    owner: '{OWNER}'\n",
                              2, "an ignore entry cannot accept OBAAF-CFG-001"),
            "complete": (entry % ("The vendor publishes no commit SHAs", day(90), f"    owner: '{OWNER}'\n"), 0, "ignored: "),
        }
        for name, (config, expected, text) in cases.items():
            with self.subTest(case=name), TempDir() as tmp:
                repository(tmp, baseline=False)
                (tmp / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")
                # Only this one rule is gated on, so the status is the entry's doing.
                code, out, err = run_cli("check", tmp, "--fail-on", "hygiene")
                self.assertEqual(code, expected, out + err)
                self.assertIn(text, out + err)


class TheCommandsOnThePagesExistTest(unittest.TestCase):
    def commands(self):
        for path in DOCS:
            text = path.read_text(encoding="utf-8")
            for block in re.findall(r"```bash\n(.*?)```", text, re.S):
                for command in block.replace("\\\n", " ").splitlines():
                    if command.strip().startswith("obaaf "):
                        yield path.name, command.strip()

    def test_every_command_in_a_code_block_is_one_the_command_line_accepts(self):
        found = list(self.commands())
        self.assertGreaterEqual(len(found), 7, found)
        parser = cli.build_parser()
        for name, command in found:
            with self.subTest(page=name, command=command):
                try:
                    parser.parse_args(shlex.split(command)[1:])
                except SystemExit as exc:      # argparse exits on an option it does not know
                    self.fail(f"{name}: `{command}` is not a command the tool accepts ({exc.code})")

    def test_the_pages_say_what_the_tests_above_establish(self):
        gate, upgrading = (path.read_text(encoding="utf-8") for path in DOCS)
        for text in ("tests/test_adoption_path.py", "| 0 |", "| 1 |", "| 2 |", "`never` included",
                     "Without `--owner`, `--reason` and `--expires` the status is 2", "no longer found",
                     "`--lanes` lists and judges nothing", "the status is 1; a path with nothing to list is status 2", "is not written to the baseline",
                     "A step with no `name` or `id` is known by the action it uses"):
            with self.subTest(page="from-report-to-gate.md", text=text):
                self.assertIn(text, gate)
        for text in ("4 finding(s) carried over", "1 finding(s) were not in the old baseline",
                     "Baseline: 0 finding(s) accepted by the baseline, 5 new.",
                     "    12  HIGH   OBAAF-CFG-001  Lane declaration that does nothing  [job triage]",
                     "3 finding(s) newly accepted by @my-org/build until",
                     "4 kept with the owner, reason and expiry date they had.",
                     "Accepted risk: 7 finding(s) are accepted and do not fail the check (3 high, 2 medium, 2 low)",
                     "tests/test_adoption_path.py"):
            with self.subTest(page="upgrading.md", text=text):
                self.assertIn(text, upgrading)


if __name__ == "__main__":
    unittest.main()
