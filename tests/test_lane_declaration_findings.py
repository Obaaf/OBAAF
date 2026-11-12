"""A lane declaration that does nothing is a finding (OBAAF-CFG-001).

A job is an agent job to the checker when the checker recognises its agent or when the repository
declares it one. Until 0.3.0 a declaration that did nothing (`OBAAF_LANE: agnet`, a `lanes:` entry
for a job that was renamed) was a note, which changes no exit code: the gate stayed green on a job
nobody was checking. These tests hold the finding to what the flagship plan asks of it (slice 2a.4):
it fails a gate at its severity, it is fixed by correcting the declaration, and it can be accepted
with an owner, a reason and an expiry date like any other finding.
"""

import json
import unittest
from datetime import date, timedelta

from helpers import RISKY, TempDir, install_templates, run_cli

from obaaf import checker, render
from obaaf.catalog import load
from obaaf.checker import baseline, report
from obaaf.checker import workflow as wf_mod

CFG = "OBAAF-CFG-001"
SHA = "1" * 40
OWNER, REASON = "@studio/build", "Tracked in issue 12 until the job is renamed"
AGENT_RULES = {"OBAAF-GHA-003", "OBAAF-GHA-005", "OBAAF-GHA-020"}
JENKINSFILE = """pipeline {
  agent any
  stages {
    stage('Build') {
      %s
      steps {
        sh './build.sh'
      }
    }
  }
}
"""


def day(ahead: int) -> str:
    return (date.today() + timedelta(days=ahead)).isoformat()


def job(env="", steps="      - run: ./work.sh\n", extra="", name="work"):
    env_line = f"    env: {{{env}}}\n" if env else ""
    return (f"on: push\npermissions: {{}}\njobs:\n  {name}:\n    runs-on: ubuntu-latest\n"
            f"    permissions: {{contents: read}}\n{env_line}{extra}    steps:\n{steps}")


def repo(tmp, workflow, config=None, name="wf.yml", jenkinsfile=None):
    (tmp / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (tmp / ".github" / "workflows" / name).write_text(workflow, encoding="utf-8")
    # Owners for everything, so the only findings are the ones a test is about.
    (tmp / ".github" / "CODEOWNERS").write_text("* @studio/build\n", encoding="utf-8")
    if config is not None:
        (tmp / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")
    if jenkinsfile is not None:
        (tmp / "Jenkinsfile").write_text(jenkinsfile, encoding="utf-8")
    return tmp


def idle(result):
    return [f for f in result.findings if f.rule == CFG]


def seen(result):
    return sorted((f.path, f.line, f.kind, f.severity, f.job, f.step) for f in idle(result))


class EveryCaseIsAFindingWhereItIsWrittenTest(unittest.TestCase):
    def test_in_a_workflow(self):
        wf = ("on: push\npermissions: {}\nenv:\n  OBAAF_LANE: relaese\njobs:\n  work:\n    runs-on: ubuntu-latest\n"
              "    env:\n      OBAAF_LANE: agnet\n"
              "    container:\n      image: node:22\n      env:\n        OBAAF_LANE: agent\n"
              "    services:\n      db:\n        image: postgres:17\n        env:\n          OBAAF_LANE: agent\n"
              "    steps:\n      - name: Run it\n        run: ./work.sh\n        env:\n          OBAAF_LANE: agent\n")
        with TempDir() as tmp:
            result = checker.check(repo(tmp, wf))
        path = ".github/workflows/wf.yml"
        self.assertEqual(seen(result), [
            (path, 4, "workflow-not-a-lane", "high", None, None),
            (path, 9, "job-not-a-lane", "high", "work", None),
            (path, 13, "container-env", "high", "work", None),
            (path, 18, "service-env", "high", "work", None),
            (path, 23, "step-env", "high", "work", "Run it"),
        ])
        by_kind = {f.kind: f for f in idle(result)}
        self.assertEqual(by_kind["job-not-a-lane"].message,
                         "Job 'work' sets OBAAF_LANE to 'agnet', which is not a lane (untrusted, agent, effect, "
                         "release, trusted), so the declaration changes nothing.")
        self.assertEqual(by_kind["workflow-not-a-lane"].message,
                         "The workflow's env sets OBAAF_LANE to 'relaese', which is not a lane (untrusted, agent, "
                         "effect, release, trusted), so the declaration changes nothing.")
        self.assertEqual(by_kind["service-env"].message,
                         "Job 'work' sets OBAAF_LANE to 'agent' in services.db.env, where it is not read (it is read "
                         "in the job's env and in the workflow's env), so the declaration changes nothing.")
        self.assertEqual(by_kind["service-env"].facts, {"value": "'agent'", "service": "db"})
        self.assertEqual(by_kind["step-env"].facts, {"value": "'agent'"})
        # No note says the same thing a second time.
        self.assertEqual([note for note in result.notes if "declaration" in note], [])

    def test_in_the_checker_configuration(self):
        config = ("# the lanes of this repository\nlanes:\n"
                  "  .github/workflows/wf.yml#work: probe\n"          # line 3: not a lane
                  "  .github/workflows/wf.yml#wrok: agent\n"          # line 4: no such job
                  "  .github/workflows/gone.yml#work: release\n"      # line 5: no such file
                  "  Jenkinsfile#Nope: agent\n"                       # line 6: no such stage
                  "  .github/workflows/wf.yml#nope: agnet\n")         # line 7: both
        with TempDir() as tmp:
            result = checker.check(repo(tmp, job(), config, jenkinsfile=JENKINSFILE % ""))
        path = ".github/obaaf.yml"
        self.assertEqual(seen(result), [
            (path, 3, "entry-not-a-lane", "high", None, None),
            (path, 4, "entry-no-job", "high", None, None),
            (path, 5, "entry-no-file", "high", None, None),
            (path, 6, "entry-no-stage", "high", None, None),
            (path, 7, "entry-no-job", "high", None, None),
            (path, 7, "entry-not-a-lane", "high", None, None),
        ])
        messages = {(f.line, f.kind): f.message for f in idle(result)}
        self.assertEqual(messages[(4, "entry-no-job")],
                         "lanes: '.github/workflows/wf.yml#wrok' (set to 'agent') names a job that "
                         ".github/workflows/wf.yml does not have, so the declaration changes nothing.")
        self.assertEqual(messages[(5, "entry-no-file")],
                         "lanes: '.github/workflows/gone.yml#work' (set to 'release') names a file the checker did "
                         "not read, so the declaration changes nothing.")
        self.assertEqual(messages[(6, "entry-no-stage")],
                         "lanes: 'Jenkinsfile#Nope' (set to 'agent') names a stage that Jenkinsfile does not have, "
                         "so the declaration changes nothing.")
        # The configuration is a file with findings, and is not counted as a workflow that was checked.
        self.assertEqual(result.files, [".github/workflows/wf.yml", "Jenkinsfile"])

    def test_in_a_jenkinsfile(self):
        for declared, kind, text in (
                ("environment { OBAAF_LANE = 'relaese' }", "jenkins-not-a-lane",
                 "OBAAF_LANE is set to 'relaese', which is not a lane"),
                ('environment { OBAAF_LANE = "${params.LANE}" }', "jenkins-computed",
                 "OBAAF_LANE is set to a value computed when the build runs, which the checker cannot read as a lane")):
            with self.subTest(kind=kind), TempDir() as tmp:
                result = checker.check(repo(tmp, job(), jenkinsfile=JENKINSFILE % declared))
                self.assertEqual(seen(result), [("Jenkinsfile", 5, kind, "high", None, None)])
                self.assertIn(text, idle(result)[0].message)

    def test_a_declaration_that_works_is_no_finding(self):
        config = "lanes:\n  .github/workflows/wf.yml#work: agent\n  .github/workflows/wf.yml: release\n  Jenkinsfile#Build: Agent\n"
        with TempDir() as tmp:
            result = checker.check(repo(tmp, job(env="OBAAF_LANE: ' Effect '"), config,
                                        jenkinsfile=JENKINSFILE % "environment { OBAAF_LANE = 'release' }"))
        self.assertEqual(idle(result), [])

    def test_every_case_the_notes_listed_is_a_finding_and_lanes_prints_each_once(self):
        # `--lanes` reports no findings, so it still prints these declarations as notes: one a finding.
        config = "lanes:\n  .github/workflows/wf.yml#wrok: agnet\n  nowhere.yml: agent\n"
        wf = job(env="OBAAF_LANE: agnet", steps="      - run: ./work.sh\n        env: {OBAAF_LANE: trusted}\n")
        with TempDir() as tmp:
            repo(tmp, wf, config)
            result = checker.check(tmp)
            code, out, err = run_cli("check", tmp, "--lanes")
        notes = [line for line in err.splitlines() if line.startswith("note: Lane declaration ignored: ")]
        self.assertEqual(code, 0)
        self.assertEqual(out, ".github/workflows/wf.yml#work: trusted (default)\n")
        self.assertEqual(len(idle(result)), 5)
        self.assertEqual(len(notes), 5, err)
        for f in idle(result):
            with self.subTest(kind=f.kind):
                self.assertEqual(notes.count(f"note: Lane declaration ignored: {f.path}, line {f.line}: {f.message} "
                                             f"(`obaaf check` reports it as {CFG}, {f.severity}.)"), 1, err)


class ItFailsAGateAtItsSeverityTest(unittest.TestCase):
    MISSPELT = (RISKY / "agent-lane-misspelled.yml").read_text(encoding="utf-8")

    def test_the_misspelling_that_passed_now_fails_and_correcting_it_brings_the_agent_rules(self):
        with TempDir() as tmp:
            repo(tmp, self.MISSPELT)
            misspelt = checker.check(tmp)
            # Whatever else is wrong with the job, this is what the misspelling alone does to a gate.
            gating = [f.rule for f in misspelt.gating("high", load()) if f.rule == CFG]
            repo(tmp, self.MISSPELT.replace("OBAAF_LANE: agnet", "OBAAF_LANE: agent"))
            corrected = checker.check(tmp)
        self.assertEqual(gating, [CFG])
        self.assertEqual({f.rule for f in misspelt.findings} & AGENT_RULES, set())
        self.assertEqual(idle(corrected), [])
        self.assertEqual({f.rule for f in corrected.findings} & AGENT_RULES, AGENT_RULES)

    def test_exit_codes(self):
        with TempDir() as tmp:
            repo(tmp, job(env="OBAAF_LANE: agnet"))
            codes = {gate: run_cli("check", tmp, "--fail-on", gate)[0]
                     for gate in ("never", "low", "medium", "high", "authority:high", "hygiene")}
            default = run_cli("check", tmp)[0]
            fixed = {}
            for name, env in (("corrected", "OBAAF_LANE: trusted"), ("deleted", "")):
                repo(tmp, job(env=env))
                fixed[name] = run_cli("check", tmp, "--fail-on", "low")[0]
        self.assertEqual(codes, {"never": 0, "low": 1, "medium": 1, "high": 1, "authority:high": 1, "hygiene": 0})
        self.assertEqual(default, 1)
        self.assertEqual(fixed, {"corrected": 0, "deleted": 0})

    def test_low_where_nothing_can_be_missing(self):
        cases = {
            # `trusted` adds no rule even where it is read.
            "a step declares trusted": job(steps="      - run: ./work.sh\n        env: {OBAAF_LANE: trusted}\n"),
            # The job is an agent job anyway: the checker recognises the action.
            "a step repeats a lane the job is in": job(
                steps=f"      - uses: anthropics/claude-code-action@{SHA}\n        env: {{OBAAF_LANE: agent}}\n"),
            "a step repeats the job's own declaration": job(
                env="OBAAF_LANE: Release", steps="      - run: ./work.sh\n        env: {OBAAF_LANE: release}\n"),
        }
        for name, wf in cases.items():
            with self.subTest(case=name), TempDir() as tmp:
                repo(tmp, wf)
                result = checker.check(tmp)
                self.assertEqual([(f.kind, f.severity) for f in idle(result)], [("step-env", "low")])
                self.assertEqual([f.rule for f in result.gating("medium", load()) if f.rule == CFG], [])
                self.assertEqual([f.rule for f in result.gating("low", load()) if f.rule == CFG], [CFG])
        with TempDir() as tmp:
            result = checker.check(repo(tmp, job(), "lanes:\n  .github/workflows/wf.yml#gone: trusted\n"
                                                    "  .github/workflows/gone.yml: Trusted\n"))
        self.assertEqual([(f.kind, f.severity) for f in idle(result)],
                         [("entry-no-job", "low"), ("entry-no-file", "low")])

    def test_high_where_something_can(self):
        cases = {
            "a step names a lane the job is not in": job(steps="      - run: ./work.sh\n        env: {OBAAF_LANE: agent}\n"),
            "a step names another lane than the job's": job(
                env="OBAAF_LANE: release", steps="      - run: ./work.sh\n        env: {OBAAF_LANE: agent}\n"),
            "a step's value is not a lane": job(steps="      - run: ./work.sh\n        env: {OBAAF_LANE: agnet}\n"),
        }
        for name, wf in cases.items():
            with self.subTest(case=name), TempDir() as tmp:
                self.assertEqual([(f.kind, f.severity) for f in idle(checker.check(repo(tmp, wf)))],
                                 [("step-env", "high")])

    def test_an_agent_found_through_a_script_counts_as_the_lane_the_job_is_in(self):
        wf = job(steps="      - run: bash scripts/review.sh\n        env: {OBAAF_LANE: agent}\n")
        with TempDir() as tmp:
            repo(tmp, wf)
            (tmp / "scripts").mkdir()
            (tmp / "scripts" / "review.sh").write_text("#!/bin/bash\nclaude -p 'review this'\n", encoding="utf-8")
            result = checker.check(tmp)
        self.assertIn("OBAAF-GHA-020", {f.rule for f in result.findings})
        self.assertEqual([(f.kind, f.severity) for f in idle(result)], [("step-env", "low")])


class ItCanBeAcceptedLikeAnyOtherFindingTest(unittest.TestCase):
    CONFIG = "lanes:\n  .github/workflows/byo-smoke.yml#byo-smoke: probe\n"

    def adopter(self, tmp, config=None):
        return repo(tmp, job(name="byo-smoke"), self.CONFIG if config is None else config, name="byo-smoke.yml")

    def test_by_an_ignore_entry_with_an_owner_a_reason_and_a_date(self):
        entry = (f"ignore:\n  - rule: {CFG}\n    path: .github/obaaf.yml\n"
                 f"    reason: probe is this project's own label for the job\n    until: {day(90)}\n")
        with TempDir() as tmp:
            self.adopter(tmp, self.CONFIG + entry)
            without_owner = checker.check(tmp)
            code_without, text, _ = run_cli("check", tmp, "--fail-on", "low")
            self.adopter(tmp, self.CONFIG + entry + f"    owner: '{OWNER}'\n")
            accepted = checker.check(tmp)
            code_accepted, lead, _ = run_cli("check", tmp, "--fail-on", "low")
        self.assertEqual([f.state for f in idle(without_owner)], ["new"])
        self.assertEqual(code_without, 1)
        self.assertIn("because it names no owner", text)
        self.assertEqual([f.state for f in idle(accepted)], ["accepted"])
        self.assertEqual(code_accepted, 0)
        self.assertTrue(lead.startswith("Accepted risk: 1 finding(s) are accepted and do not fail the check (1 high)"),
                        lead)

    def test_by_a_baseline_entry_that_names_the_key_and_the_value(self):
        with TempDir() as tmp:
            self.adopter(tmp)
            path = tmp / "baseline.json"
            refused = run_cli("check", tmp, "--write-baseline", path)
            written = run_cli("check", tmp, "--write-baseline", path, "--owner", OWNER, "--reason", REASON,
                              "--expires", day(90))
            entries = json.loads(path.read_text(encoding="utf-8"))["findings"]
            accepted = run_cli("check", tmp, "--baseline", path, "--fail-on", "low")
            # Another value is another finding: the reason given for `probe` says nothing about `agnet`.
            self.adopter(tmp, self.CONFIG.replace("probe", "agnet"))
            changed = run_cli("check", tmp, "--baseline", path, "--fail-on", "low", "--format", "json")
            # Corrected: the entry is left over, which fails the check until the baseline is written again.
            self.adopter(tmp, self.CONFIG.replace("probe", "trusted"))
            corrected = run_cli("check", tmp, "--baseline", path, "--fail-on", "low", "--format", "json")
        self.assertEqual(refused[0], 2, refused[2])
        self.assertEqual(written[0], 0, written[2])
        self.assertEqual(entries, [{
            "rule": CFG, "severity": "high", "path": ".github/obaaf.yml", "kind": "entry-not-a-lane",
            "facts": {"entry": ".github/workflows/byo-smoke.yml#byo-smoke", "value": "'probe'"},
            "owner": OWNER, "reason": REASON, "expires": day(90)}])
        self.assertEqual(accepted[0], 0, accepted[1])
        self.assertIn("Accepted risk: 1 finding(s) are accepted", accepted[1])
        data = json.loads(changed[1])
        self.assertEqual(changed[0], 1)
        self.assertEqual([(f["rule"], f["state"], f["facts"]["value"]) for f in data["findings"]],
                         [(CFG, "new", "'agnet'")])
        self.assertEqual(len(data["baseline"]["stale"]), 1)
        data = json.loads(corrected[1])
        self.assertEqual(corrected[0], 1)
        self.assertEqual(data["findings"], [])
        self.assertEqual(len(data["baseline"]["stale"]), 1)

    def test_an_acceptance_at_low_does_not_cover_the_finding_once_it_is_high(self):
        stray = "        env: {OBAAF_LANE: agent}\n"
        recognised = job(steps=f"      - name: Review\n        uses: anthropics/claude-code-action@{SHA}\n{stray}")
        unrecognised = job(steps=f"      - name: Review\n        run: ./review.sh\n{stray}")
        with TempDir() as tmp:
            repo(tmp, recognised)
            path = tmp / "baseline.json"
            code, _, err = run_cli("check", tmp, "--write-baseline", path, "--owner", OWNER, "--reason", REASON,
                                   "--expires", day(90))
            self.assertEqual(code, 0, err)
            before = checker.check(tmp)
            baseline.apply(before, baseline.load(path))
            repo(tmp, unrecognised)     # the job is no longer an agent job to the checker
            after = checker.check(tmp)
            baseline.apply(after, baseline.load(path))
        self.assertEqual([(f.severity, f.state) for f in idle(before)], [("low", "accepted")])
        self.assertEqual([(f.severity, f.state) for f in idle(after)], [("high", "new")])
        self.assertIn("it accepts the finding at low severity and the finding is now high",
                      idle(after)[0].acceptance.problems[0])

    def test_two_declarations_that_differ_only_in_their_line_need_two_entries(self):
        steps = ("      - name: Run\n        run: ./a.sh\n        env: {OBAAF_LANE: agent}\n"
                 "      - name: Run\n        run: ./b.sh\n        env: {OBAAF_LANE: agent}\n")
        with TempDir() as tmp:
            result = checker.check(repo(tmp, job(steps=steps)))
            found = idle(result)
            one = baseline.Baseline(baseline.FORMAT, [baseline.entry_for(found[0], OWNER, REASON, day(30))])
            baseline.apply(result, one)
        self.assertEqual(len(found), 2)
        self.assertEqual(baseline.key(found[0]), baseline.key(found[1]))
        self.assertEqual(sorted(f.state for f in found), ["accepted", "new"])


class WhatIdentifiesItTest(unittest.TestCase):
    def test_a_value_is_text_whatever_yaml_made_of_it_and_never_mistaken_for_a_list(self):
        same = [("true", True), ("5", 5), ("", None)]
        for text, parsed in same:
            with self.subTest(value=parsed):
                self.assertEqual(wf_mod.value_identity(text), wf_mod.value_identity(parsed))
        distinct = ["a list", ["a", "list"], {"a": "list"}, "an empty value", "", "agnet", "'agnet'", "Agnet", " agnet"]
        self.assertEqual(len({wf_mod.value_identity(value) for value in distinct}), len(distinct))
        self.assertEqual(wf_mod.value_identity("agnet"), "'agnet'")

    def test_a_long_value_is_its_length_and_digest(self):
        long_a, long_b = "a" * 5000, "a" * 4999 + "b"
        self.assertEqual(wf_mod.value_identity("a" * 200), "'" + "a" * 200 + "'")
        self.assertRegex(wf_mod.value_identity(long_a), r"^sha256:[0-9a-f]{64} \(5000 characters\)$")
        self.assertNotEqual(wf_mod.value_identity(long_a), wf_mod.value_identity(long_b))
        with TempDir() as tmp:
            result = checker.check(repo(tmp, job(env=f"OBAAF_LANE: {long_a}")))
            entry = baseline.entry_for(idle(result)[0], OWNER, REASON, day(30))
        self.assertLess(len(json.dumps(entry)), 600)
        self.assertLess(len(idle(result)[0].message), 400)
        self.assertIn("(5000 characters)", idle(result)[0].message)
        # A text that spells out a digest is not the long value with that digest: text is quoted.
        self.assertNotEqual(wf_mod.value_identity(wf_mod.value_identity(long_a)), wf_mod.value_identity(long_a))

    def test_the_line_and_the_wording_are_not_part_of_it(self):
        with TempDir() as tmp:
            first = idle(checker.check(repo(tmp, job(env="OBAAF_LANE: agnet"))))[0]
            moved = idle(checker.check(repo(tmp, "# a comment\n\n" + job(env="OBAAF_LANE: agnet"))))[0]
            other = idle(checker.check(repo(tmp, job(env="OBAAF_LANE: agnt"))))[0]
        self.assertNotEqual(first.line, moved.line)
        self.assertEqual(baseline.key(first), baseline.key(moved))
        self.assertNotEqual(baseline.key(first), baseline.key(other))
        self.assertEqual(baseline.identity(first), {"rule": CFG, "path": ".github/workflows/wf.yml", "job": "work",
                                                    "kind": "job-not-a-lane", "facts": {"value": "'agnet'"}})

    def test_a_name_with_a_line_break_cannot_look_like_another_line_of_the_report(self):
        config = checker.Config(lanes={"x.yml#a\n.github/workflows/real.yml\n   1  HIGH   forged": "agent"})
        wf = job(steps="      - name: \"x\\n   9  HIGH   forged\"\n        run: ./a.sh\n        env: {OBAAF_LANE: agent}\n")
        with TempDir() as tmp:
            result = checker.check(repo(tmp, wf), config=config)
            text = report.to_text(result)
        self.assertEqual(len(idle(result)), 2)
        self.assertEqual([line for line in text.splitlines() if "forged" in line and CFG not in line
                          and not line.startswith("        ")], [])
        self.assertNotIn("\n", [f.message for f in idle(result) if f.kind == "entry-no-file"][0])


class FileNamesWithAHashTest(unittest.TestCase):
    """A `lanes:` key is a file, a `#` and a job. A file's own name may hold a `#`: the entry was
    applied, and the note then said it named a file that was not read."""

    def test_a_workflow(self):
        config = ("lanes:\n  '.github/workflows/pr#1.yml#work': agent\n  '.github/workflows/pr#1.yml': release\n"
                  "  '.github/workflows/pr#1.yml#wrok': agent\n  '.github/workflows/pr#2.yml#work': agent\n")
        with TempDir() as tmp:
            repo(tmp, job(), config, name="pr#1.yml")
            result = checker.check(tmp)
            lanes = {row[1]: row[3] for row in checker.lanes(tmp)}
        self.assertIn("set in the checker configuration", lanes["work"])
        self.assertEqual([(f.line, f.kind) for f in idle(result)], [(4, "entry-no-job"), (5, "entry-no-file")])

    def test_a_jenkinsfile(self):
        config = ("jenkins:\n  files: ['ci#1/Jenkinsfile']\n"
                  "lanes:\n  'ci#1/Jenkinsfile#Build': agent\n  'ci#1/Jenkinsfile#Nope': agent\n")
        with TempDir() as tmp:
            repo(tmp, job(), config)
            (tmp / "ci#1").mkdir()
            (tmp / "ci#1" / "Jenkinsfile").write_text(JENKINSFILE % "", encoding="utf-8")
            result = checker.check(tmp)
        self.assertIn("ci#1/Jenkinsfile", result.jenkins_files)
        self.assertEqual([(f.line, f.kind) for f in idle(result)], [(5, "entry-no-stage")])


class WhereTheConfigurationIsNamedFromTest(unittest.TestCase):
    CONFIG = "lanes:\n  .github/workflows/wf.yml#wrok: agent\n"

    def test_from_the_repository_root_and_beside_one_workflow_checked_on_its_own(self):
        with TempDir() as tmp:
            repo(tmp, job(), self.CONFIG)
            (tmp / "elsewhere.yml").write_text(self.CONFIG, encoding="utf-8")
            whole = checker.check(tmp)
            given = checker.check(tmp, config=checker.Config.load(tmp, str(tmp / "elsewhere.yml")))
            alone = checker.check(tmp / ".github" / "workflows" / "wf.yml", config=checker.Config.load(tmp))
            built = checker.check(tmp, config=checker.Config(lanes={".github/workflows/wf.yml#wrok": "agent"}))
        self.assertEqual([f.path for f in idle(whole)], [".github/obaaf.yml"])
        self.assertEqual([f.path for f in idle(given)], ["elsewhere.yml"])
        self.assertEqual([f.path for f in idle(alone)], ["../obaaf.yml"])
        # A configuration that was not read from a file is named as the file it would be written in.
        self.assertEqual([(f.path, f.line) for f in idle(built)], [(".github/obaaf.yml", 1)])


class TheReportsCarryItTest(unittest.TestCase):
    def test_text_json_and_sarif(self):
        with TempDir() as tmp:
            repo(tmp, job(env="OBAAF_LANE: agnet"), "lanes:\n  .github/workflows/wf.yml#wrok: agent\n")
            text = run_cli("check", tmp)[1]
            data = json.loads(run_cli("check", tmp, "--format", "json")[1])
            sarif = json.loads(run_cli("check", tmp, "--format", "sarif")[1])
        self.assertIn("     2  HIGH   OBAAF-CFG-001  Lane declaration that does nothing\n", text)
        self.assertIn("     7  HIGH   OBAAF-CFG-001  Lane declaration that does nothing  [job work]\n", text)
        self.assertNotIn("Notes (advisory", text)
        self.assertEqual(data["notes"], [])
        self.assertEqual([(f["rule"], f["path"], f["line"], f["severity"], f["category"], f["state"], f["kind"])
                          for f in data["findings"]],
                         [(CFG, ".github/obaaf.yml", 2, "high", "authority", "new", "entry-no-job"),
                          (CFG, ".github/workflows/wf.yml", 7, "high", "authority", "new", "job-not-a-lane")])
        run = sarif["runs"][0]
        self.assertEqual([rule["id"] for rule in run["tool"]["driver"]["rules"]], [CFG])
        self.assertEqual([(r["ruleId"], r["level"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                           r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in run["results"]],
                         [(CFG, "error", ".github/obaaf.yml", 2), (CFG, "error", ".github/workflows/wf.yml", 7)])
        notes = [n for n in run["invocations"][0]["toolExecutionNotifications"] if n["descriptor"]["id"] == "note"]
        self.assertEqual(notes, [])


class TheRuleIsInTheCatalogueTest(unittest.TestCase):
    def test_the_rule_and_its_test_case_are_published(self):
        rule = load().rules[CFG]
        self.assertEqual((rule["severity"], rule["category"], rule["supports"]), ("high", "authority", ["FR12"]))
        self.assertEqual(load().problems(), [])
        cases = [case for case in render.read_test_set(RISKY) if CFG in case["expect"]]
        self.assertEqual([case["file"] for case in cases], ["tests/fixtures/workflows/risky/agent-lane-misspelled.yml"])
        spec = render.checker_rules_md()
        self.assertIn(f"## {CFG}", spec)
        self.assertIn("| [OBAAF-CFG-001](#obaaf-cfg-001) | high | authority | Lane declaration that does nothing | - |",
                      spec)

    def test_every_case_has_one_template(self):
        from obaaf.checker import _IDLE_TEMPLATES, rules
        kinds = {"job-not-a-lane", "workflow-not-a-lane", "jenkins-not-a-lane", "jenkins-computed", "step-env",
                 "container-env", "service-env", "entry-not-a-lane", "entry-no-job", "entry-no-stage", "entry-no-file"}
        self.assertEqual(set(_IDLE_TEMPLATES), kinds)
        self.assertEqual([pair for pair in rules.CONFLICTS if pair[0] == CFG], [])


class TheExampleConfigurationDeclaresNothingTest(unittest.TestCase):
    def test_the_installed_templates_have_no_declaration_that_does_nothing(self):
        # `obaaf templates install` writes the example as .github/obaaf.yml. In 0.3.0 it gave a lane
        # to a job in a file the templates do not install.
        with TempDir() as tmp:
            install_templates(tmp)
            config = checker.Config.load(tmp)
            result = checker.check(tmp)
        self.assertEqual((config.lanes, config.ignore), ({}, []))
        self.assertEqual(idle(result), [])

    def test_the_example_as_0_3_0_shipped_it_is_a_finding(self):
        with TempDir() as tmp:
            install_templates(tmp)
            (tmp / ".github" / "obaaf.yml").write_text("lanes:\n  .github/workflows/nightly.yml#package: release\n",
                                                       encoding="utf-8")
            result = checker.check(tmp)
        self.assertEqual([(f.path, f.line, f.kind, f.severity) for f in idle(result)],
                         [(".github/obaaf.yml", 2, "entry-no-file", "high")])


if __name__ == "__main__":
    unittest.main()
