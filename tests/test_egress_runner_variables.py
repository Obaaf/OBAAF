"""The runner-variables escape test agrees with its own data (slice 2c.12a, issue #198).

What GitHub-hosted runners do with each name is measured by the runner-variables jobs of
.github/workflows/egress-escape-tests.yml and judged by tests/egress/runner-variables.py against
tests/egress/runner-variables.json. These tests need no runner: they pin that the jobs set exactly the
names and values the judge expects, that the plain probe and the composite probe run the same code,
and that the record covers every name, channel and probe.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("obaaf_runner_variables", ROOT / "tests" / "egress" / "runner-variables.py")
rv = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rv)
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "egress-escape-tests.yml").read_text(encoding="utf-8"))
PROBE = yaml.safe_load((ROOT / "tests" / "egress" / "runner-variables-probe" / "action.yml").read_text(encoding="utf-8"))
OUTCOMES = {rv.WORKFLOW, rv.RUNNER, rv.UNSET, rv.NOT_SET_HERE, rv.NOT_MEASURED}


def _step(job: str, label: str) -> dict:
    found = [s for s in WORKFLOW["jobs"][job]["steps"] if (s.get("env") or {}).get("OBAAF_RV_LABEL") == label]
    assert len(found) == 1, (job, label, len(found))
    return found[0]


class Data(unittest.TestCase):
    def setUp(self):
        self.data = rv.load()

    def test_every_name_says_why_it_is_a_candidate(self):
        for name, why in self.data["names"].items():
            with self.subTest(name=name):
                self.assertTrue(why.strip())
        self.assertLessEqual(set(self.data["network_names"]), set(self.data["names"]))

    def test_every_value_names_its_channel_and_differs_between_channels(self):
        for name in self.data["names"]:
            values = {rv.marker(c, name) for c in rv.CHANNELS}
            self.assertEqual(len(values), 3, name)

    def test_the_record_covers_every_name_channel_and_probe(self):
        expected = self.data["expected"]
        self.assertIsNotNone(expected, "record what the runner showed in runner-variables.json's expected")
        self.assertEqual(set(expected), {f"{c}-{p}" for c in rv.CHANNELS for p in rv.PROBES})
        for label, outcomes in expected.items():
            with self.subTest(label=label):
                self.assertEqual(set(outcomes), set(self.data["names"]))
                self.assertLessEqual(set(outcomes.values()), OUTCOMES)
                self.assertNotIn(rv.NOT_MEASURED, outcomes.values())


class Workflow(unittest.TestCase):
    def setUp(self):
        self.data = rv.load()
        self.names = " ".join(self.data["names"])

    def test_the_job_env_sets_what_the_judge_expects(self):
        env = WORKFLOW["jobs"]["runner-variables-job-env"]["env"]
        want = {"OBAAF_RV_NAMES": self.names, **{n: rv.marker("job", n) for n in rv.set_in(self.data, "job")}}
        self.assertEqual(env, want)

    def test_each_step_env_probe_sets_what_the_judge_expects(self):
        self.assertEqual(WORKFLOW["jobs"]["runner-variables"]["env"], {"OBAAF_RV_NAMES": self.names})
        for label in ("step-plain", "step-composite"):
            with self.subTest(label=label):
                env = _step("runner-variables", label)["env"]
                want = {"OBAAF_RV_LABEL": label, **{n: rv.marker("step", n) for n in rv.set_in(self.data, "step")}}
                self.assertEqual(env, want)
        for label in ("genv-plain", "genv-composite"):
            with self.subTest(label=label):
                self.assertEqual(_step("runner-variables", label)["env"], {"OBAAF_RV_LABEL": label})

    def test_every_probe_runs_the_same_code_as_the_action_runs_its_steps(self):
        composite = PROBE["runs"]["steps"]
        self.assertEqual(PROBE["runs"]["using"], "composite")
        self.assertEqual(len(composite), 1)
        code = composite[0]["run"]
        self.assertEqual(composite[0]["shell"], "/usr/bin/python3 -I -S {0}")
        action = yaml.safe_load((ROOT / "actions" / "egress" / "action.yml").read_text(encoding="utf-8"))
        # The action's steps that run code use this shell; its last step names a program that does not
        # exist, so that it fails when it runs at all (slice 2c.9).
        shells = {s["shell"] for s in action["runs"]["steps"] if s["shell"].startswith("/usr/")}
        self.assertEqual(shells, {"/usr/bin/python3 -I -S {0}"})
        for job, label in (("runner-variables-job-env", "job-plain"), ("runner-variables", "step-plain"),
                           ("runner-variables", "genv-plain")):
            with self.subTest(label=label):
                step = _step(job, label)
                self.assertEqual(step["shell"], "/usr/bin/python3 -I -S {0}")
                self.assertEqual(step["run"], code)
        for job, label in (("runner-variables-job-env", "job-composite"), ("runner-variables", "step-composite"),
                           ("runner-variables", "genv-composite")):
            with self.subTest(label=label):
                self.assertEqual(_step(job, label)["uses"], "./tests/egress/runner-variables-probe")

    def test_the_names_the_action_empties_are_the_ones_the_guide_names(self):
        # docs/egress-control.md (item 13) says which of the candidates the action's three code steps
        # empty in their own env, which outranks the job's, a step's and GITHUB_ENV; a change to the
        # action's env makes this test say the guide is out of date.
        action = yaml.safe_load((ROOT / "actions" / "egress" / "action.yml").read_text(encoding="utf-8"))
        code_steps = [s for s in action["runs"]["steps"] if s["shell"] == "/usr/bin/python3 -I -S {0}"]
        self.assertEqual(len(code_steps), 3)
        for step in code_steps:
            with self.subTest(step=step["name"]):
                emptied = {n for n, v in (step.get("env") or {}).items() if n in self.data["names"] and v == ""}
                self.assertEqual(emptied, {"TMPDIR", "LOCPATH", "TZDIR", "HOSTALIASES", "RES_OPTIONS", "LOCALDOMAIN"})
                others = {n for n in (step.get("env") or {}) if n in self.data["names"]} - emptied
                self.assertEqual(others, set())

    def test_github_env_lines_are_the_judges_values(self):
        lines = [f"{n}={rv.marker('genv', n)}" for n in rv.set_in(self.data, "genv")]
        self.assertEqual(len(lines), len(self.data["names"]))
        for line in lines:
            self.assertNotIn("\n", line)


class Judge(unittest.TestCase):
    """The judge on made-up readings: what the first review found the tests did not pin."""

    def setUp(self):
        self.data = rv.load()

    def _seen(self, channel):
        """A reading in which every name the channel set came back with the test's value."""
        return {name: rv.marker(channel, name) for name in rv.set_in(self.data, channel)}

    def test_a_reading_is_sorted_by_what_came_back(self):
        seen = self._seen("step")
        seen["RUNNER_TEMP"] = "/home/runner/work/_temp"     # the runner's own
        seen["CI"] = None                                    # not in the step's environment
        del seen["HOME"]                                     # the probe did not report it
        got = rv.classify(self.data, "step", seen)
        self.assertEqual(got["RUNNER_TEMP"], rv.RUNNER)
        self.assertEqual(got["CI"], rv.UNSET)
        self.assertEqual(got["HOME"], rv.NOT_MEASURED)
        self.assertEqual(got["TEMP"], rv.WORKFLOW)
        # Another channel's value is not this channel's: it reads as the runner's, never as set.
        seen["TMP"] = rv.marker("job", "TMP")
        self.assertEqual(rv.classify(self.data, "step", seen)["TMP"], rv.RUNNER)

    def test_a_missing_reading_is_not_measured_for_every_name(self):
        self.assertEqual(set(rv.classify(self.data, "genv", None).values()), {rv.NOT_MEASURED})

    def test_the_judge_fails_without_the_readings_and_on_the_wrong_outcome_of_the_node_options_write(self):
        import contextlib
        import io
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(rv.judge(Path(tmp), rv.NODE_OPTIONS_WRITE), 1)      # no readings at all
            self.assertIn("not measured", out.getvalue())
            # Readings that give back the record, name for name.
            how = {rv.WORKFLOW: lambda c, n: rv.marker(c, n), rv.RUNNER: lambda c, n: "the runner's own",
                   rv.UNSET: lambda c, n: None}
            for label, outcomes in self.data["expected"].items():
                channel = label.split("-")[0]
                seen = {}
                for name, outcome in outcomes.items():
                    twin = self.data["case_twins"].get(name)
                    if outcome == rv.NOT_SET_HERE:
                        continue
                    seen[name] = how[outcome](channel, twin if name not in rv.set_in(self.data, channel) and twin else name)
                (Path(tmp) / f"{label}.json").write_text(json.dumps(seen))
            for outcome, status in ((rv.NODE_OPTIONS_WRITE, 0), (None, 0), ("failure", 1), ("skipped", 1), ("", 1)):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(rv.judge(Path(tmp), outcome), status, (outcome, out.getvalue()[-400:]))
            self.assertEqual(rv.NODE_OPTIONS_WRITE, "success")
            # One name that came back another way than the record says fails the judge, and it says which:
            # the runner taking the NODE_OPTIONS line after all, and the runner giving up RUNNER_TEMP.
            for label, name, value in (("genv-plain", "NODE_OPTIONS", rv.marker("genv", "NODE_OPTIONS")),
                                       ("step-composite", "RUNNER_TEMP", rv.marker("step", "RUNNER_TEMP")),
                                       ("job-plain", "HOME", None)):
                path = Path(tmp) / f"{label}.json"
                kept = path.read_text()
                seen = json.loads(kept)
                self.assertNotEqual(seen.get(name, "absent"), value)
                seen[name] = value
                path.write_text(json.dumps(seen))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(rv.judge(Path(tmp), rv.NODE_OPTIONS_WRITE), 1, (label, name))
                self.assertIn(f"FAILED: {label} {name}:", out.getvalue())
                path.write_text(kept)
            # The command line needs the outcome: without it the check would be skipped silently.
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(rv.main(["--judge", tmp]), 2)
                self.assertEqual(rv.main(["--judge", tmp, rv.NODE_OPTIONS_WRITE]), 0)
                self.assertEqual(rv.main(["--judge", tmp, "failure"]), 1)

    def test_the_job_gives_the_judge_the_outcome_of_the_step_that_wrote_node_options(self):
        steps = WORKFLOW["jobs"]["runner-variables"]["steps"]
        wrote = [s for s in steps if s.get("id") == "genv_node_options"]
        self.assertEqual(len(wrote), 1)
        self.assertIn("grep '^NODE_OPTIONS='", wrote[0]["run"])
        judged = [s for s in steps if "OBAAF_RV_JUDGE" in (s.get("env") or {})]
        self.assertEqual(len(judged), 1)
        self.assertEqual(judged[0]["env"]["NODE_OPTIONS_WRITE"], "${{ steps.genv_node_options.outcome }}")
        self.assertIn('os.environ["NODE_OPTIONS_WRITE"]]', judged[0]["run"])


if __name__ == "__main__":
    unittest.main()
