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

    def test_github_env_lines_are_the_judges_values(self):
        lines = [f"{n}={rv.marker('genv', n)}" for n in rv.set_in(self.data, "genv")]
        self.assertEqual(len(lines), len(self.data["names"]))
        for line in lines:
            self.assertNotIn("\n", line)


if __name__ == "__main__":
    unittest.main()
