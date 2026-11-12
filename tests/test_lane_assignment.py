"""A job gets the rules of every lane it belongs to.

Before this, a job had exactly one lane, chosen in a fixed order. A job that did two things got the
rules for one of them, and a declaration that did not match what the checker inferred was dropped.
An independent reviewer found the first two cases below on 2026-11-11; the rest are the same class.
"""

import unittest

from helpers import TempDir, run_cli

from obaaf import checker

SHA = "1" * 40
AGENT = f"      - uses: anthropics/claude-code-action@{SHA}\n"
UPLOAD = f"      - uses: softprops/action-gh-release@{SHA}\n"
CHECKOUT = f"      - uses: actions/checkout@{SHA}\n"

AGENT_RULES = {"OBAAF-GHA-003", "OBAAF-GHA-005", "OBAAF-GHA-020"}
RELEASE_RULES = {"OBAAF-GHA-014", "OBAAF-GHA-016"}
EFFECT_RULES = {"OBAAF-GHA-021", "OBAAF-GHA-022"}


def check(tmp, text, config=None, name="wf.yml"):
    path = tmp / name
    path.write_text(text, encoding="utf-8")
    return checker.check(path, config=config)


def rules(result, job=None):
    return {f.rule for f in result.findings if job is None or f.job == job}


def job(steps, env="", on="push", permissions="{contents: write}", extra=""):
    env_line = f"    env: {{{env}}}\n" if env else ""
    return (f"on: {on}\npermissions: {{}}\njobs:\n  work:\n    runs-on: ubuntu-latest\n"
            f"    permissions: {permissions}\n{env_line}{extra}    steps:\n{steps}")


class AJobInTwoLanesGetsBothSetsOfRulesTest(unittest.TestCase):
    def test_a_declared_agent_job_that_publishes(self):
        # The reviewer's first case: the upload made it a release job, and the declaration was dropped.
        wf = job(UPLOAD + "      - run: ./agent.sh\n", env="OBAAF_LANE: agent, KEY: '${{ secrets.MODEL_API_KEY }}'")
        with TempDir() as tmp:
            found = rules(check(tmp, wf))
        self.assertLessEqual(AGENT_RULES, found)
        self.assertLessEqual(RELEASE_RULES, found)

    def test_a_named_agent_that_publishes(self):
        # The reviewer's second case: the agent action made it an agent job, and the release rules never ran.
        wf = job(AGENT + UPLOAD, env="KEY: '${{ secrets.MODEL_API_KEY }}'")
        with TempDir() as tmp:
            found = rules(check(tmp, wf))
        self.assertLessEqual(AGENT_RULES, found)
        self.assertLessEqual(RELEASE_RULES | {"OBAAF-GHA-006"}, found)

    def test_an_agent_that_applies_another_runs_output(self):
        steps = (f"      - uses: actions/download-artifact@{SHA}\n"
                 "        with: {run-id: '${{ github.event.workflow_run.id }}'}\n" + AGENT)
        wf = job(steps, on="workflow_run")
        with TempDir() as tmp:
            found = rules(check(tmp, wf))
        self.assertLessEqual(EFFECT_RULES, found)
        self.assertLessEqual({"OBAAF-GHA-003", "OBAAF-GHA-020"}, found)

    def test_an_effect_job_that_publishes(self):
        steps = (f"      - uses: actions/download-artifact@{SHA}\n"
                 "        with: {run-id: '${{ github.event.workflow_run.id }}'}\n" + UPLOAD)
        wf = job(steps, on="workflow_run")
        with TempDir() as tmp:
            found = rules(check(tmp, wf))
        self.assertLessEqual(EFFECT_RULES, found)
        self.assertLessEqual(RELEASE_RULES, found)

    def test_an_agent_started_from_a_script_in_a_job_that_publishes(self):
        # Script detection used to look only at jobs left in the trusted lane.
        wf = job("      - run: bash scripts/run-agent.sh\n" + UPLOAD)
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / "scripts").mkdir()
            (tmp / "scripts" / "run-agent.sh").write_text("claude -p 'triage this'\n")
            (tmp / ".github" / "workflows" / "wf.yml").write_text(wf)
            found = rules(checker.check(tmp))
        self.assertLessEqual({"OBAAF-GHA-003", "OBAAF-GHA-020"}, found)
        self.assertLessEqual(RELEASE_RULES, found)

    def test_an_agent_started_from_a_script_in_a_pull_request_job(self):
        wf = job("      - run: bash scripts/run-agent.sh\n", on="pull_request")
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / "scripts").mkdir()
            (tmp / "scripts" / "run-agent.sh").write_text("claude -p 'review this'\n")
            (tmp / ".github" / "workflows" / "wf.yml").write_text(wf)
            found = rules(checker.check(tmp))
        self.assertLessEqual({"OBAAF-GHA-003", "OBAAF-GHA-020"}, found)


class ADeclarationOnlyAddsRulesTest(unittest.TestCase):
    """No declaration, by either route, may take a finding away."""

    BASES = {
        "pull request build": job(CHECKOUT + "      - run: make\n", on="pull_request"),
        "named agent": job(CHECKOUT + AGENT, on="issue_comment"),
        "publisher": job(CHECKOUT + UPLOAD),
        "publisher on pull requests": job(CHECKOUT + UPLOAD, on="pull_request"),
        "agent that publishes": job(AGENT + UPLOAD),
        "plain": job("      - run: make\n"),
    }

    def test_no_lane_declared_in_the_workflow_removes_a_finding(self):
        for name, base in self.BASES.items():
            with TempDir() as tmp:
                before = rules(check(tmp, base))
                for lane in checker.wf_mod.LANES:
                    declared = base.replace("    steps:\n", f"    env: {{OBAAF_LANE: {lane}}}\n    steps:\n", 1)
                    with self.subTest(base=name, declared=lane):
                        self.assertLessEqual(before, rules(check(tmp, declared)))

    def test_no_lane_declared_in_the_configuration_removes_a_finding(self):
        for name, base in self.BASES.items():
            with TempDir() as tmp:
                before = rules(check(tmp, base))
                for lane in checker.wf_mod.LANES:
                    for key in ("wf.yml#work", "wf.yml"):
                        config = checker.Config(lanes={key: lane})
                        with self.subTest(base=name, declared=lane, key=key):
                            self.assertLessEqual(before, rules(check(tmp, base, config=config)))

    def test_a_pull_request_job_keeps_its_findings_when_it_starts_to_publish(self):
        # Adding an upload step used to move the job out of the untrusted lane and drop OBAAF-GHA-011.
        with TempDir() as tmp:
            before = rules(check(tmp, self.BASES["pull request build"]))
            after = rules(check(tmp, self.BASES["publisher on pull requests"]))
        self.assertIn("OBAAF-GHA-011", before)
        self.assertLessEqual(before, after)

    def test_two_declarations_both_count(self):
        wf = job("      - run: ./work.sh\n", env="OBAAF_LANE: agent")
        with TempDir() as tmp:
            for key in ("wf.yml#work", "wf.yml"):
                found = rules(check(tmp, wf, config=checker.Config(lanes={key: "release"})))
                with self.subTest(key=key):
                    self.assertIn("OBAAF-GHA-003", found)     # agent, from OBAAF_LANE
                    self.assertIn("OBAAF-GHA-006", found)     # release, from the configuration

    def test_a_workflow_level_and_a_job_level_declaration_both_count(self):
        wf = ("on: push\npermissions: {}\nenv: {OBAAF_LANE: release}\njobs:\n  work:\n    runs-on: ubuntu-latest\n"
              "    permissions: {contents: write}\n    env: {OBAAF_LANE: agent}\n    steps:\n      - run: ./work.sh\n")
        with TempDir() as tmp:
            found = rules(check(tmp, wf))
            both = checker.Config(lanes={"wf.yml#work": "effect", "wf.yml": "release"})
            plain = job("      - run: ./work.sh\n")
            from_config = rules(check(tmp, plain, config=both))
        self.assertIn("OBAAF-GHA-003", found)
        self.assertIn("OBAAF-GHA-006", found)
        self.assertLessEqual(EFFECT_RULES, from_config)
        self.assertIn("OBAAF-GHA-006", from_config)


class DeclarationsAreReadForgivinglyAndNeverSilentlyDroppedTest(unittest.TestCase):
    def test_case_and_surrounding_space_do_not_matter(self):
        for spelling in ("Agent", "AGENT", "' agent '"):
            wf = job("      - run: ./work.sh\n", env=f"OBAAF_LANE: {spelling}")
            with TempDir() as tmp:
                with self.subTest(spelling=spelling):
                    self.assertIn("OBAAF-GHA-003", rules(check(tmp, wf)))
        with TempDir() as tmp:
            config = checker.Config(lanes={"wf.yml#work": "Agent "})
            self.assertIn("OBAAF-GHA-003", rules(check(tmp, job("      - run: ./work.sh\n"), config=config)))

    def test_a_value_that_is_not_a_lane_is_reported(self):
        wf = job("      - run: ./work.sh\n", env="OBAAF_LANE: agnet")
        with TempDir() as tmp:
            result = check(tmp, wf)
        self.assertNotIn("OBAAF-GHA-003", rules(result))
        self.assertTrue(any("agnet" in note and "wf.yml" in note for note in result.notes), result.notes)

    def test_a_value_that_is_not_a_lane_in_the_configuration_is_reported(self):
        with TempDir() as tmp:
            result = check(tmp, job("      - run: ./work.sh\n"), config=checker.Config(lanes={"wf.yml#work": "probe"}))
        self.assertTrue(any("probe" in note and "wf.yml#work" in note for note in result.notes), result.notes)

    def test_an_expression_is_not_a_lane_and_is_reported(self):
        wf = job("      - run: ./work.sh\n", env="OBAAF_LANE: '${{ vars.LANE }}'")
        with TempDir() as tmp:
            result = check(tmp, wf)
        self.assertTrue(any("vars.LANE" in note for note in result.notes), result.notes)

    def test_a_configured_lane_for_a_job_that_does_not_exist_is_reported(self):
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "wf.yml").write_text(job("      - run: ./work.sh\n"))
            config = checker.Config(lanes={".github/workflows/wf.yml#wrok": "agent",
                                           ".github/workflows/gone.yml#work": "agent",
                                           ".github/workflows/wf.yml#work": "agent"})
            result = checker.check(tmp, config=config)
        self.assertIn("OBAAF-GHA-003", rules(result))
        notes = " ".join(result.notes)
        self.assertIn("wf.yml#wrok", notes)
        self.assertIn("gone.yml#work", notes)
        self.assertNotIn("wf.yml#work'", notes)

    def test_declaring_trusted_changes_nothing_and_says_so(self):
        wf = job(AGENT, env="OBAAF_LANE: trusted", on="issue_comment")
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(wf)
            self.assertIn("OBAAF-GHA-003", rules(checker.check(path)))
            lane, reason = checker.lanes(path)[0][2:]
        self.assertEqual(lane, "agent")
        self.assertIn("declared trusted, which cannot override what the job does", reason)


class WhatIsShownTest(unittest.TestCase):
    def test_lanes_names_every_lane_a_job_is_in(self):
        wf = job(AGENT + UPLOAD)
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(wf)
            lane, reason = checker.lanes(path)[0][2:]
            code, out, _ = run_cli("check", path, "--lanes")
        self.assertEqual(lane, "agent")
        self.assertIn("also release: uploads or publishes artifacts", reason)
        self.assertEqual(code, 0)
        self.assertIn("wf.yml#work: agent (", out)
        self.assertIn("also release", out)

    def test_a_job_in_one_lane_is_shown_as_before(self):
        cases = {
            job("      - run: ./work.sh\n", env="OBAAF_LANE: agent"): ("agent", "set by OBAAF_LANE"),
            job(UPLOAD): ("release", "uploads or publishes artifacts"),
            job("      - run: make\n", on="pull_request"): ("untrusted", "builds pull requests"),
            job("      - run: make\n"): ("trusted", "default"),
        }
        for wf, expected in cases.items():
            with TempDir() as tmp:
                path = tmp / "wf.yml"
                path.write_text(wf)
                with self.subTest(expected=expected):
                    self.assertEqual(checker.lanes(path)[0][2:], expected)

    def test_messages_for_a_job_in_one_lane_are_unchanged(self):
        # Baselines key on the message, so these must not move.
        wf = job("      - run: ./work.sh\n", env="OBAAF_LANE: agent")
        with TempDir() as tmp:
            messages = {f.message for f in check(tmp, wf).findings}
            config = checker.Config(lanes={"wf.yml#work": "agent"})
            configured = {f.message for f in check(tmp, job(AGENT), config=config).findings}
        self.assertIn("Agent job 'work' (set by OBAAF_LANE) holds write permissions: contents.", messages)
        self.assertIn("Agent job 'work' (set in the checker configuration) holds write permissions: contents.",
                      configured)

    def test_an_agent_finding_gives_the_reason_the_job_is_an_agent_job(self):
        # In a job that is in two lanes, the agent findings must not quote the release lane's reason.
        wf = job(UPLOAD + "      - run: ./agent.sh\n", env="OBAAF_LANE: agent")
        with TempDir() as tmp:
            messages = {f.message for f in check(tmp, wf).findings if f.rule == "OBAAF-GHA-003"}
        self.assertEqual(messages, {"Agent job 'work' (set by OBAAF_LANE) holds write permissions: contents."})


# The cases below come from the second review of this change (2026-11-12): a reviewer who did not
# write it generated 9,240 workflows and compared the old and the new checker on each.

JENKINSFILE = """pipeline {
  agent { label 'linux' }
  stages {
    stage('Build') {
      steps {
        sh './build.sh'
      }
    }
  }
}
"""


def repo(tmp, workflow, config=None, name="wf.yml", jenkinsfile=None):
    (tmp / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    path = tmp / ".github" / "workflows" / name
    path.write_text(workflow, encoding="utf-8")
    if config is not None:
        (tmp / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")
    if jenkinsfile is not None:
        (tmp / "Jenkinsfile").write_text(jenkinsfile, encoding="utf-8")
    return path


def ignored(result_or_notes):
    notes = getattr(result_or_notes, "notes", result_or_notes)
    return [note for note in notes if note.startswith("Lane declaration ignored")]


class AcceptedFindingsStayWhereTheBaselineHasThemTest(unittest.TestCase):
    TWO_PUBLISHERS = (f"on: push\njobs:\n"
                      f"  bot:\n    runs-on: ubuntu-latest\n    permissions: {{contents: read}}\n    steps:\n"
                      f"      - uses: openai/codex-action@{SHA}\n      - run: npm publish\n"
                      f"  ship:\n    runs-on: ubuntu-latest\n    permissions: {{contents: read}}\n    steps:\n"
                      f"      - run: npm publish\n")

    def test_the_provenance_finding_stays_on_the_job_that_only_publishes(self):
        # One OBAAF-GHA-017 per workflow. `bot` is now a release job as well as an agent job, and
        # comes first, but the finding an adopter accepted is the one on `ship`.
        with TempDir() as tmp:
            found = [f for f in check(tmp, self.TWO_PUBLISHERS).findings if f.rule == "OBAAF-GHA-017"]
        self.assertEqual([(f.job, f.message) for f in found], [
            ("ship", "Job 'ship' publishes artifacts, but no job in this workflow signs provenance for them.")])

    def test_the_provenance_finding_is_reported_when_only_an_agent_job_publishes(self):
        only_bot = self.TWO_PUBLISHERS[:self.TWO_PUBLISHERS.index("  ship:")]
        with TempDir() as tmp:
            found = [f.job for f in check(tmp, only_bot).findings if f.rule == "OBAAF-GHA-017"]
        self.assertEqual(found, ["bot"])

    def test_a_workflow_wide_trusted_under_a_declared_agent_job_adds_nothing_to_the_message(self):
        # Nothing was inferred here, so there is nothing that `trusted` failed to override.
        wf = ("on: push\nenv: {OBAAF_LANE: trusted}\njobs:\n  bot:\n    runs-on: ubuntu-latest\n"
              "    permissions: {contents: write}\n    env: {OBAAF_LANE: agent}\n    steps:\n      - run: ./bot\n")
        expected = "Agent job 'bot' (set by OBAAF_LANE) holds write permissions: contents."
        with TempDir() as tmp:
            self.assertIn(expected, {f.message for f in check(tmp, wf).findings})
            config = checker.Config(lanes={"wf.yml": "trusted", "wf.yml#bot": "agent"})
            plain = wf.replace("env: {OBAAF_LANE: trusted}\n", "").replace("    env: {OBAAF_LANE: agent}\n", "")
            self.assertIn("Agent job 'bot' (set in the checker configuration) holds write permissions: contents.",
                          {f.message for f in check(tmp, plain, config=config).findings})

    def test_trusted_beside_another_declared_lane_is_not_called_an_override(self):
        # The note is for a job that was declared trusted and nothing else.
        wf = job(AGENT, env="OBAAF_LANE: agent").replace("permissions: {}\n", "permissions: {}\nenv: {OBAAF_LANE: trusted}\n")
        with TempDir() as tmp:
            messages = {f.message for f in check(tmp, wf).findings if f.rule == "OBAAF-GHA-003"}
        self.assertEqual(messages, {"Agent job 'work' (set by OBAAF_LANE) holds write permissions: contents."})

    def test_a_declaration_in_another_case_reads_like_the_exact_one(self):
        # `Agent` was ignored before and is read now, so the job's messages quote the declaration,
        # exactly as they do for `agent`. This is the one message change an upgrade can bring to a
        # job whose lanes did not change, and the changelog says so.
        with TempDir() as tmp:
            exact = {f.message for f in check(tmp, job(AGENT, env="OBAAF_LANE: agent")).findings}
            other = {f.message for f in check(tmp, job(AGENT, env="OBAAF_LANE: Agent")).findings}
        self.assertEqual(exact, other)


class AReleaseEnvironmentMakesAReleaseJobWhateverStartsItTest(unittest.TestCase):
    def lanes_and_rules(self, on):
        wf = job("      - run: ./deploy.sh\n", on=on, extra="    environment: production\n")
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(wf)
            return checker.lanes(path)[0][2:], rules(checker.check(path))

    def test_a_job_that_pull_requests_can_start(self):
        (lane, reason), found = self.lanes_and_rules("[push, pull_request]")
        self.assertEqual(lane, "release")
        self.assertIn("uses the 'production' environment", reason)
        self.assertIn("also untrusted: builds pull requests", reason)
        self.assertIn("OBAAF-GHA-015", found)

    def test_a_job_that_a_privileged_trigger_can_start(self):
        for on in ("pull_request_target", "issue_comment", "[push, workflow_run]"):
            with self.subTest(on=on):
                (lane, _), found = self.lanes_and_rules(on)
                self.assertEqual(lane, "release")
                self.assertIn("OBAAF-GHA-015", found)

    def test_a_job_started_by_a_push_is_as_before(self):
        (lane, reason), found = self.lanes_and_rules("push")
        self.assertEqual((lane, reason), ("release", "uses the 'production' environment"))
        self.assertNotIn("OBAAF-GHA-015", found)

    def test_declaring_the_lane_and_inferring_it_give_the_same_rules(self):
        inferred = self.lanes_and_rules("pull_request_target")[1]
        wf = job("      - run: ./deploy.sh\n", on="pull_request_target", env="OBAAF_LANE: release",
                 extra="    environment: live\n")
        with TempDir() as tmp:
            declared = rules(check(tmp, wf))
        self.assertEqual(inferred, declared)


class NoDeclarationIsDroppedWithoutAWordTest(unittest.TestCase):
    PLAIN = job("      - run: ./work.sh\n")

    def test_configured_keys_that_match_nothing(self):
        keys = ["wf#work", ".github/workflows/wf.yml #work", ".github/workflows/wf.YML#work", "work",
                ".github/workflows/wf.yml#"]
        config = "lanes:\n" + "".join(f"  '{key}': agent\n" for key in keys)
        with TempDir() as tmp:
            repo(tmp, self.PLAIN, config)
            notes = ignored(checker.check(tmp))
        for key in keys:
            with self.subTest(key=key):
                self.assertEqual(len([note for note in notes if f"'{key}'" in note]), 1, notes)

    def test_an_empty_value(self):
        for env in ("OBAAF_LANE: ''", "OBAAF_LANE: null"):
            with self.subTest(env=env), TempDir() as tmp:
                notes = ignored(check(tmp, job("      - run: ./work.sh\n", env=env)))
                self.assertEqual(len(notes), 1, notes)
                self.assertIn("an empty value", notes[0])
        with TempDir() as tmp:
            repo(tmp, self.PLAIN, "lanes:\n  .github/workflows/wf.yml#work:\n")
            notes = ignored(checker.check(tmp))
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("an empty value", notes[0])

    def test_obaaf_lane_on_a_step(self):
        wf = job("      - run: ./work.sh\n        env: {OBAAF_LANE: agent}\n")
        with TempDir() as tmp:
            result = check(tmp, wf)
        self.assertNotIn("OBAAF-GHA-003", rules(result))
        notes = ignored(result)
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("job 'work' sets OBAAF_LANE in step 1, where it is not read", notes[0])

    def test_obaaf_lane_in_an_env_that_is_not_read(self):
        # The step is named by its place in the file, the number an error about it would use.
        wf = ("on: push\njobs:\n  work:\n    runs-on: ubuntu-latest\n"
              "    container: {image: 'node:22', env: {OBAAF_LANE: agent}}\n"
              "    steps:\n      - not-a-step\n      - run: make\n        env: &shared {OBAAF_LANE: agent}\n"
              "      - run: make test\n        env: *shared\n")
        with TempDir() as tmp:
            notes = ignored(check(tmp, wf))
        self.assertEqual(len(notes), 3, notes)
        for where in ("container.env", "step 2", "step 3"):
            with self.subTest(where=where):
                self.assertTrue(any(f"job 'work' sets OBAAF_LANE in {where}," in note for note in notes), notes)

    def test_no_note_for_obaaf_lane_that_is_read_or_is_not_a_declaration(self):
        # An env shared through an anchor is the job's env; an input of that name is not an env.
        wf = ("on:\n  workflow_call:\n    inputs:\n      OBAAF_LANE: {type: string}\n"
              "jobs:\n  first:\n    runs-on: ubuntu-latest\n    env: &lane {OBAAF_LANE: agent}\n"
              "    steps:\n      - run: ./a.sh\n"
              "  second:\n    runs-on: ubuntu-latest\n    env: *lane\n    steps:\n"
              f"      - uses: some/action@{SHA}\n        with: {{OBAAF_LANE: agent}}\n")
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(wf)
            shown = {row[1]: row[2] for row in checker.lanes(path)}
            notes = ignored(checker.check(path))
        self.assertEqual(shown, {"first": "agent", "second": "agent"})
        self.assertEqual(notes, [])

    def test_one_workflow_checked_with_the_repository_configuration(self):
        # The configuration names files from the repository root; a file checked on its own must
        # not lose its declared lane because the checker calls it by a shorter path.
        config = ("lanes:\n  .github/workflows/wf.yml#work: agent\n  .github/workflows/wf.yml#wrok: agent\n"
                  "  .github/workflows/other.yml#work: agnet\n")
        with TempDir() as tmp:
            path = repo(tmp, self.PLAIN, config)
            result = checker.check(path, config=checker.Config.load(tmp))
            lane = checker.lanes(path, config=checker.Config.load(tmp))[0][2]
            code, out, err = run_cli("check", path, "--config", tmp / ".github" / "obaaf.yml", "--lanes")
        self.assertIn("OBAAF-GHA-003", rules(result))
        self.assertEqual(lane, "agent")
        notes = ignored(result)
        self.assertEqual(len(notes), 1, notes)        # the job this file does not have, and no other file's entry
        self.assertIn("wf.yml#wrok", notes[0])
        self.assertIn("wf.yml#work: agent (set in the checker configuration)", out)
        self.assertIn("wf.yml#wrok", err)

    def test_jenkins_stages(self):
        config = "lanes:\n  Jenkinsfile#Nope: agent\n  Jenkinsfile#Build: agnet\n"
        with TempDir() as tmp:
            repo(tmp, self.PLAIN, config, jenkinsfile=JENKINSFILE)
            notes = ignored(checker.check(tmp))
            (tmp / ".github" / "obaaf.yml").write_text("lanes:\n  Jenkinsfile#Build: agent\n")
            fine = ignored(checker.check(tmp))
        self.assertEqual(len(notes), 2, notes)
        self.assertTrue(any("'Jenkinsfile#Nope'" in n and "names a stage that Jenkinsfile does not have" in n
                            for n in notes), notes)
        self.assertTrue(any("'Jenkinsfile#Build'" in n and "'agnet', which is not a lane" in n for n in notes), notes)
        self.assertEqual(fine, [])

    def test_a_list_of_files_gives_each_file_one_path(self):
        # Two files with the same name: the repository form of the key belongs to neither.
        with TempDir() as tmp:
            paths = []
            for side in ("a", "b"):
                (tmp / side / ".github" / "workflows").mkdir(parents=True)
                paths.append(tmp / side / ".github" / "workflows" / "ci.yml")
                paths[-1].write_text(self.PLAIN)
            config = checker.Config(lanes={".github/workflows/ci.yml#work": "agent",
                                           "a/.github/workflows/ci.yml#work": "agent"})
            result = checker.check(tmp, files=paths, config=config)
        self.assertEqual({f.path for f in result.findings if f.rule == "OBAAF-GHA-003"}, {"a/.github/workflows/ci.yml"})
        self.assertEqual(ignored(result), [])

    def test_a_jenkins_stage_lane_is_read_like_a_workflow_lane(self):
        from obaaf.checker import jenkins
        from obaaf.catalog import load
        declared = JENKINSFILE.replace("steps {", "environment { OBAAF_LANE = 'agent' }\n      steps {")
        for overrides, text in (({"Jenkinsfile#Build": " Agent"}, JENKINSFILE),
                                ({"Jenkinsfile#Build": "agnet"}, declared)):
            with self.subTest(overrides=overrides):
                result = jenkins.analyze("Jenkinsfile", text.encode(), load(), None, lane_overrides=overrides)
                self.assertEqual([lane for _, lane, _ in result.lanes], ["agent"])

    def test_no_note_about_files_the_run_did_not_look_for(self):
        config = "lanes:\n  .github/workflows/wf.yml#work: agent\n  Jenkinsfile#Build: agent\n"
        with TempDir() as tmp:
            repo(tmp, self.PLAIN, config, jenkinsfile=JENKINSFILE)
            for platform in ("auto", "github", "jenkins"):
                with self.subTest(platform=platform):
                    self.assertEqual(ignored(checker.check(tmp, platform=platform)), [])

    def test_no_note_about_a_jenkinsfile_when_only_the_workflows_directory_is_checked(self):
        # But an entry for a file that does not exist is a mistake whatever was checked.
        config = "lanes:\n  Jenkinsfile#Build: agent\n  wf#work: agent\n"
        with TempDir() as tmp:
            repo(tmp, self.PLAIN, config, jenkinsfile=JENKINSFILE)
            result = checker.check(tmp / ".github" / "workflows")
            github_only = ignored(checker.check(tmp, platform="github"))
        self.assertEqual(result.jenkins_files, [])
        for notes in (ignored(result), github_only):
            self.assertEqual(len(notes), 1, notes)
            self.assertIn("'wf#work'", notes[0])

    def test_no_second_report_for_a_job_already_reported_as_an_error(self):
        wf = "on: push\njobs:\n  build: hello\n  work:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
        with TempDir() as tmp:
            repo(tmp, wf, "lanes:\n  .github/workflows/wf.yml#build: agent\n")
            result = checker.check(tmp)
        self.assertTrue(any("job 'build' is not a mapping" in error for error in result.errors), result.errors)
        self.assertEqual(ignored(result), [])

    def test_lanes_prints_the_notes(self):
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(job("      - run: ./work.sh\n", env="OBAAF_LANE: agnet"))
            code, out, err = run_cli("check", path, "--lanes")
        self.assertEqual(code, 0)
        self.assertEqual(out, "wf.yml#work: trusted (default)\n")
        self.assertIn("note: Lane declaration ignored: wf.yml: job 'work' sets OBAAF_LANE to 'agnet'", err)

    def test_declaring_another_lane_does_not_silence_the_note_about_an_agent_like_name(self):
        wf = job("      - run: ./review.sh\n", env="OBAAF_LANE: untrusted").replace("  work:", "  claude-review:")
        with TempDir() as tmp:
            notes = check(tmp, wf).notes
        self.assertTrue(any("suggests agent work but are not in the agent lane" in n and "claude-review" in n
                            for n in notes), notes)


SHIP = """pipeline {
  agent any
  %s
  stages {
    stage('Ship') {
      %s
      steps {
        sh './ship.sh'
      }
    }
  }
}
"""
NESTED = """pipeline {
  agent any
  stages {
    stage('Deploy') {
      parallel {
        stage('East') { steps { sh './ship.sh east' } }
        stage('West') { steps { sh './ship.sh west' } }
      }
    }
  }
}
"""


def jenkins_rules(text, lanes=None):
    from obaaf.catalog import load
    from obaaf.checker import jenkins
    result = jenkins.analyze("Jenkinsfile", text.encode(), load(), None, lane_overrides=lanes or {})
    return {f.rule for f in result.findings}, result


class AJenkinsStageDeclarationOnlyAddsRulesTest(unittest.TestCase):
    RELEASE = "environment { OBAAF_LANE = 'release' }"
    AGENT = "environment { OBAAF_LANE = 'agent' }"

    def test_a_configured_lane_does_not_hide_the_stages_own(self):
        # The second review's case: `lanes: {Jenkinsfile#Ship: trusted}` removed a high finding.
        for own in (self.RELEASE, self.AGENT):
            alone, _ = jenkins_rules(SHIP % ("", own))
            self.assertTrue(alone, "the declared stage must have findings for this test to mean anything")
            for configured in ("trusted", "untrusted", "agent", "release", "effect", "agnet"):
                with self.subTest(own=own, configured=configured):
                    found, _ = jenkins_rules(SHIP % ("", own), {"Jenkinsfile#Ship": configured})
                    self.assertLessEqual(alone, found)

    def test_a_stages_own_lane_does_not_hide_the_pipelines(self):
        alone, _ = jenkins_rules(SHIP % (self.RELEASE, ""))
        self.assertTrue(alone)
        for inner in ("environment { OBAAF_LANE = 'trusted' }", self.AGENT):
            with self.subTest(inner=inner):
                found, _ = jenkins_rules(SHIP % (self.RELEASE, inner))
                self.assertLessEqual(alone, found)

    def test_both_declarations_count(self):
        release, _ = jenkins_rules(SHIP % ("", self.RELEASE))
        agent, _ = jenkins_rules(SHIP % ("", self.AGENT))
        both, _ = jenkins_rules(SHIP % ("", self.RELEASE), {"Jenkinsfile#Ship": "agent"})
        self.assertLessEqual(release | agent, both)

    def test_a_key_for_the_file_or_for_an_outer_stage_reaches_the_stages_inside(self):
        declared, _ = jenkins_rules(NESTED, {"Jenkinsfile#East": "release", "Jenkinsfile#West": "release"})
        plain, _ = jenkins_rules(NESTED)
        self.assertLess(plain, declared)
        for key in ("Jenkinsfile", "Jenkinsfile#Deploy"):
            with self.subTest(key=key):
                found, result = jenkins_rules(NESTED, {key: "release"})
                self.assertEqual(found, declared)
                self.assertIn("Deploy", result.stage_keys)

    def test_the_step_nothing_checks_is_reported_at_its_own_severity(self):
        # The third review's case. OBAAF-JEN-012 is reported once for a file. A stage declared
        # `release` behind a provenance check came first and took the finding at medium, and the
        # `npm publish` that nothing checks lost it.
        text = """pipeline {
  agent any
  stages {
    stage('Verify') {
      when { branch 'main' }
      steps { sh 'gh attestation verify app.tgz --owner acme' }
    }
    stage('Pack') {
      when { branch 'main' }
      environment { OBAAF_LANE = 'release' }
      steps { sh 'tar czf app.tgz build' }
    }
    stage('Ship') { steps { sh 'npm publish' } }
  }
}
"""
        from obaaf.catalog import load
        from obaaf.checker import jenkins
        for lanes in ({}, {"Jenkinsfile#Pack": "agent"}, {"Jenkinsfile#Pack": "trusted"}, {"Jenkinsfile": "release"}):
            with self.subTest(lanes=lanes):
                result = jenkins.analyze("Jenkinsfile", text.encode(), load(), None, lane_overrides=lanes)
                found = [(f.severity, f.job) for f in result.findings if f.rule == "OBAAF-JEN-012"]
                self.assertEqual([severity for severity, _ in found], ["high"], found)

    def test_a_declared_stage_whose_steps_are_not_shell_steps(self):
        # The step's code is not in the file; the declaration says what it is.
        for lane, step, expected in (("agent", "reviewWithAssistant(prompt: 'review this')", "agent"),
                                     ("release", "uploadToStore(file: 'app.tgz')", "release")):
            with self.subTest(lane=lane):
                text = JENKINSFILE.replace("sh './build.sh'", step)
                _, plain = jenkins_rules(text)
                _, declared = jenkins_rules(text, {"Jenkinsfile#Build": lane})
                self.assertNotEqual([row[1] for row in plain.lanes], [expected])
                self.assertEqual([row[1] for row in declared.lanes], [expected])

    def test_a_value_computed_when_the_build_runs_is_reported_as_that(self):
        with TempDir() as tmp:
            repo(tmp, job("      - run: make\n"), jenkinsfile=SHIP % ("", "environment { OBAAF_LANE = \"${params.LANE}\" }"))
            notes = ignored(checker.check(tmp))
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("Jenkinsfile, line 6, sets OBAAF_LANE to a value computed when the build runs", notes[0])

    def test_a_value_in_the_file_that_is_not_a_lane_is_reported(self):
        with TempDir() as tmp:
            repo(tmp, job("      - run: make\n"), jenkinsfile=SHIP % ("", "environment { OBAAF_LANE = 'relaese' }"))
            notes = ignored(checker.check(tmp))
            (tmp / ".github" / "obaaf.yml").write_text("lanes:\n  Jenkinsfile#Deploy: release\n  Jenkinsfile: release\n")
            (tmp / "Jenkinsfile").write_text(NESTED)
            nested = ignored(checker.check(tmp))
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("Jenkinsfile, line 6, sets OBAAF_LANE to 'relaese', which is not a lane", notes[0])
        self.assertEqual(nested, [])


class AnEnvironmentNamedForReleasesTest(unittest.TestCase):
    def lane(self, environment):
        wf = job("      - run: ./go.sh\n", extra=f"    environment: {environment}\n")
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(wf)
            return checker.lanes(path)[0][2]

    def test_names_that_say_release(self):
        # Anywhere in the name, in any case, as before this change.
        for name in ("prod", "production", "aws-prod", "Prod_EU", "AppProd", "awsprod", "K8sProd", "GameItch",
                     "release", "itch", "itch.io", "appstore", "steam", "deploy-preview", "publish",
                     "preprod-release", "{name: WebProd}"):
            with self.subTest(name=name):
                self.assertEqual(self.lane(name), "release")

    def test_a_name_that_says_it_is_not_production(self):
        for name in ("nonprod", "non-prod", "NonProd", "preprod", "pre-production", "PreProduction", "pre_prod"):
            with self.subTest(name=name):
                self.assertEqual(self.lane(name), "trusted")

    def test_names_that_say_nothing(self):
        for name in ("staging", "ci", "review"):
            with self.subTest(name=name):
                self.assertEqual(self.lane(name), "trusted")


class WhatIsPrintedCannotBeForgedOrFloodedTest(unittest.TestCase):
    FORGING = ("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    permissions: {contents: write}\n    steps:\n"
               "      - name: \"x'; also release: uploads or publishes artifacts)\\nfake.yml#other: trusted (default\"\n"
               "        run: claude -p hello\n")

    def test_a_step_name_with_a_line_break_stays_on_its_line(self):
        with TempDir() as tmp:
            path = tmp / "wf.yml"
            path.write_text(self.FORGING)
            _, lanes_out, _ = run_cli("check", path, "--lanes")
            _, report, _ = run_cli("check", path, "--fail-on", "never")
            _, as_json, _ = run_cli("check", path, "--fail-on", "never", "--format", "json")
        self.assertEqual(len(lanes_out.splitlines()), 1, lanes_out)
        self.assertTrue(lanes_out.startswith("wf.yml#b: agent (runs an agent CLI in 'x'; also release"), lanes_out)
        self.assertIn("\\nfake.yml#other", lanes_out)
        self.assertFalse([line for line in report.splitlines() if line.startswith("fake.yml")], report)
        # The structured form carries the name as it is; a baseline keys on that.
        self.assertIn("\\nfake.yml#other", as_json)

    def test_a_configuration_key_with_a_line_break(self):
        with TempDir() as tmp:
            repo(tmp, job("      - run: make\n"))
            config = checker.Config(lanes={"x.yml#a\nLane declaration ignored: nothing to see": "agent"})
            notes = ignored(checker.check(tmp, config=config))
        self.assertEqual(len(notes), 1, notes)
        self.assertNotIn("\n", notes[0])

    def test_a_very_long_value_is_cut(self):
        with TempDir() as tmp:
            notes = ignored(check(tmp, job("      - run: make\n"), config=checker.Config(lanes={"wf.yml#work": "a" * 200_000})))
        self.assertEqual(len(notes), 1, notes)
        self.assertLess(len(notes[0]), 400)
        self.assertIn("(200000 characters)", notes[0])

    def test_values_are_shown_as_they_were_written(self):
        shown = {False: "'false'", True: "'true'", 5: "'5'", "": "an empty value", None: "an empty value",
                 ("agent", "release"): "a list", "\u0430gent": "'\\u0430gent'"}
        for value, text in shown.items():
            value = list(value) if isinstance(value, tuple) else value
            with self.subTest(value=value), TempDir() as tmp:
                notes = ignored(check(tmp, job("      - run: make\n"), config=checker.Config(lanes={"wf.yml#work": value})))
                self.assertEqual(len(notes), 1, notes)
                self.assertIn(f"to {text}, which is not a lane", notes[0])


class AConfigurationThatCannotBeReadIsAnErrorTest(unittest.TestCase):
    def test_lanes_that_is_not_a_mapping(self):
        for value in ("5", "true", "[a, b]", "[[wf.yml, agent]]", "agent"):
            with self.subTest(value=value), TempDir() as tmp:
                repo(tmp, job("      - run: make\n"), f"lanes: {value}\n")
                with self.assertRaises(checker.ConfigError):
                    checker.Config.load(tmp)
                code, out, err = run_cli("check", tmp)
                self.assertEqual(code, 2)
                self.assertIn("lanes must be a mapping", err)
                self.assertNotIn("Traceback", out + err)

    def test_lanes_left_empty_is_no_declaration(self):
        # As before this change: an empty value of any kind declares nothing.
        for value in ("", "{}", "[]", "''", "false", "0"):
            with self.subTest(value=value), TempDir() as tmp:
                repo(tmp, job("      - run: make\n"), f"lanes: {value}\n")
                self.assertEqual(checker.Config.load(tmp).lanes, {})


if __name__ == "__main__":
    unittest.main()
