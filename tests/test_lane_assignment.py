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


if __name__ == "__main__":
    unittest.main()
