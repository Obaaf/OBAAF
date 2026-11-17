"""The watch behind the escape tests' own-steps-environment job (slice 2c.12, issue #198).

The job runs on a GitHub-hosted runner; these tests pin the parts that can be checked without one:
that the three steps under test are given exactly the variables tests/egress/environment-watch.py
plants for, and that its judge passes only when the control and the action at the floor before the
slice used what was planted and the action now used none of it.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import re
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("obaaf_environment_watch", ROOT / "tests" / "egress" / "environment-watch.py")
watch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(watch)
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "egress-escape-tests.yml").read_text(encoding="utf-8"))
JOB = WORKFLOW["jobs"]["own-steps-environment"]
PLANTED_DIR = "/opt/obaaf-env/planted"
USED = ("locale/LC_CTYPE", "zone", "ca.pem", "proxy")


def judged(control, floor, now, ran=None) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        logs = Path(tmp) / "logs"
        logs.mkdir()
        for phase, lines in (("control", control), ("floor", floor), ("now", now)):
            if lines is not None:
                (logs / f"seen-{phase}").write_text("".join(line + "\n" for line in lines))
        if ran is not None:
            (Path(tmp) / "planted").mkdir()
            (Path(tmp) / "planted" / "ran").write_text(ran)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = watch.judge(logs)
        return status, out.getvalue()


class TheJob(unittest.TestCase):
    def setUp(self):
        self.given = [step for step in JOB["steps"] if "env" in step and "LC_ALL" in step["env"]]

    def test_three_steps_are_given_the_variables_and_all_the_same(self):
        self.assertEqual(len(self.given), 3)
        expected = watch.values(PLANTED_DIR)
        for step in self.given:
            self.assertEqual({name: str(value) for name, value in step["env"].items()}, expected, step["name"])

    def test_they_are_a_plain_step_the_action_before_the_slice_and_the_action_now(self):
        control, floor, now = self.given
        self.assertEqual(control["shell"], "/usr/bin/python3 -I -S {0}")
        self.assertRegex(floor["uses"], r"^Obaaf/OBAAF/actions/egress@[0-9a-f]{40}$")
        self.assertEqual(floor["uses"].rsplit("@", 1)[1], "cc2ba59d4dfb70b6dcdcd660ca700c6dbe20d13e")
        self.assertEqual(now["uses"], "./actions/egress")
        self.assertTrue(floor["continue-on-error"] and now["continue-on-error"])

    def test_no_step_is_given_a_key_and_the_job_sets_nothing_for_every_step(self):
        self.assertNotIn("env", JOB)
        text = yaml.safe_dump(JOB)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("model-keys", text)

    def test_the_variables_cover_what_the_slice_settles(self):
        names = set(watch.values(PLANTED_DIR))
        self.assertTrue({"LC_ALL", "LANG", "LANGUAGE", "TZ", "HTTPS_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "HOME",
                         "TEMP", "TMP", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "SUDO_ASKPASS",
                         "XDG_RUNTIME_DIR", "CI", "NODE_OPTIONS"} <= names)
        # A workflow's env keys are case-insensitive, so no two differ only in case.
        self.assertEqual(len({name.upper() for name in names}), len(names))


class Planting(unittest.TestCase):
    def test_plant_makes_what_each_variable_names_and_prints_the_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "planted"
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(watch.plant(directory), 0)
            lines = dict(line.split("=", 1) for line in out.getvalue().splitlines())
            self.assertEqual(lines, watch.values(str(directory)))
            for relative, kind, _ in watch.PLANTED.values():
                path = directory / relative
                self.assertTrue(path.is_dir() if kind == "dir" else path.is_file(), relative)
            for relative in watch.INSIDE:
                self.assertTrue((directory / relative).is_file(), relative)
            for path in directory.rglob("*"):
                if path.is_file():
                    self.assertNotRegex(path.read_text(), re.compile("key|token|secret", re.I), str(path))
            self.assertFalse((directory / "ran").exists())


class Judging(unittest.TestCase):
    def test_passes_when_the_control_and_the_floor_used_it_and_the_action_now_did_not(self):
        status, text = judged(USED, USED, [])
        self.assertEqual(status, 0, text)
        self.assertNotIn("FAILED", text)

    def test_fails_when_the_control_did_not_use_one_of_them(self):
        for missing in USED:
            status, text = judged([line for line in USED if line != missing], USED, [])
            self.assertEqual(status, 1, missing)
            self.assertIn("FAILED: control", text)

    def test_fails_when_the_floor_did_not_use_one_of_them(self):
        for missing in USED:
            status, text = judged(USED, [line for line in USED if line != missing], [])
            self.assertEqual(status, 1, missing)
            self.assertIn("the record of what this slice fixes is wrong", text)

    def test_fails_when_the_action_now_used_anything(self):
        for line in (*USED, "home/.docker/config.json", "docker-config", "temp", "xdg", "language/LC_MESSAGES/libc.mo"):
            status, text = judged(USED, USED, [line])
            self.assertEqual(status, 1, line)
            self.assertIn("FAILED: the action now used", text)

    def test_fails_when_a_log_is_missing_or_a_planted_program_ran(self):
        self.assertEqual(judged(None, USED, [])[0], 1)
        self.assertEqual(judged(USED, None, [])[0], 1)
        status, text = judged(USED, USED, [], ran="ran askpass\n")
        self.assertEqual(status, 1)
        self.assertIn("a planted program ran", text)


if __name__ == "__main__":
    unittest.main()
