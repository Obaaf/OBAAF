"""Slice 3.2a: the first run says what it did not read.

`obaaf check --lanes` reports a file it could not read and a path with nothing to list, with the
statuses `obaaf check` uses, where it used to end 0 in silence; the text report names the version
that wrote it; and a run with no configuration file says what that leaves out.
"""
import json
import unittest

from helpers import TempDir, run_cli
from obaaf import __version__
from obaaf.checker import report

AGENT = """on: workflow_dispatch
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@1111111111111111111111111111111111111111
"""
PLAIN = """on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
TWICE = """on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          ref: main
          REF: other
"""


def repository(tmp, files: dict, config: str | None = None):
    workflows = tmp / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for name, text in files.items():
        (workflows / name).write_text(text, encoding="utf-8")
    (tmp / ".github" / "CODEOWNERS").write_text("* @example/build\n", encoding="utf-8")
    if config is not None:
        (tmp / ".github" / "obaaf.yml").write_text(config, encoding="utf-8")


class LanesSaysWhatItDidNotReadTest(unittest.TestCase):
    def test_a_workflow_it_could_not_read_is_an_error_and_the_others_are_still_listed(self):
        with TempDir() as tmp:
            repository(tmp, {"agent.yml": AGENT, "broken.yml": "on: [push\njobs: {"})
            code, out, err = run_cli("check", tmp, "--lanes")
        self.assertEqual(code, 1, err)
        self.assertIn(".github/workflows/agent.yml#review: agent", out)
        self.assertNotIn("broken.yml", out)
        self.assertIn("error: .github/workflows/broken.yml: cannot parse YAML", err)
        self.assertIn("error: 1 problem(s) in the files above", err)

    def test_an_input_given_twice_fails_the_listing_as_it_fails_the_check(self):
        with TempDir() as tmp:
            repository(tmp, {"twice.yml": TWICE})
            code, out, err = run_cli("check", tmp, "--lanes")
            check = run_cli("check", tmp, "--fail-on", "never")
        self.assertEqual(code, 1, err)
        self.assertIn(".github/workflows/twice.yml#build:", out)
        self.assertIn("error: .github/workflows/twice.yml:", err)
        self.assertEqual(check[0], 1, check[1] + check[2])

    def test_nothing_to_list_and_a_path_that_is_not_there_end_with_two(self):
        with TempDir() as tmp:
            code, out, err = run_cli("check", tmp, "--lanes")
            self.assertEqual((code, out), (2, ""))
            self.assertIn("nothing was checked", err)
            code, out, err = run_cli("check", tmp / "missing", "--lanes")
            self.assertEqual((code, out), (2, ""))
            self.assertIn("not found", err)

    def test_a_listing_with_every_file_read_still_ends_with_zero(self):
        with TempDir() as tmp:
            repository(tmp, {"agent.yml": AGENT, "plain.yml": PLAIN})
            code, out, err = run_cli("check", tmp, "--lanes")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        self.assertEqual(len(out.splitlines()), 2, out)


class TheTextReportTest(unittest.TestCase):
    def test_it_ends_with_the_version_that_wrote_it(self):
        with TempDir() as tmp:
            repository(tmp, {"plain.yml": PLAIN}, config="{}\n")
            code, out, err = run_cli("check", tmp, "--fail-on", "never")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.splitlines()[-1], f"Checked by obaaf {__version__}.")

    def test_with_no_configuration_file_it_says_what_that_leaves_out(self):
        with TempDir() as tmp:
            repository(tmp, {"plain.yml": PLAIN})
            out = run_cli("check", tmp, "--fail-on", "never")[1]
        lines = out.splitlines()
        self.assertEqual(lines[-3:], [report.FIRST_RUN_CONFIG, report.FIRST_RUN_OTHER_TOOLS,
                                      f"Checked by obaaf {__version__}."])
        for name in ("--lanes", ".github/obaaf.yml", "zizmor", "actionlint", "poutine", "code scanning"):
            self.assertIn(name, out)

    def test_with_a_configuration_file_it_does_not(self):
        for config in ("{}\n", "lanes:\n  .github/workflows/plain.yml#build: trusted\n"):
            with self.subTest(config=config), TempDir() as tmp:
                repository(tmp, {"plain.yml": PLAIN}, config=config)
                out = run_cli("check", tmp, "--fail-on", "never")[1]
            self.assertNotIn(report.FIRST_RUN_CONFIG, out)
            self.assertNotIn(report.FIRST_RUN_OTHER_TOOLS, out)

    def test_json_and_sarif_are_unchanged_by_it(self):
        with TempDir() as tmp:
            repository(tmp, {"plain.yml": PLAIN})
            data = run_cli("check", tmp, "--fail-on", "never", "--format", "json")[1]
            sarif = run_cli("check", tmp, "--fail-on", "never", "--format", "sarif")[1]
        for text in (data, sarif):
            self.assertNotIn("No configuration file was read", text)
            self.assertNotIn("Checked by obaaf", text)
        self.assertEqual(json.loads(data)["tool"], f"obaaf {__version__}")


if __name__ == "__main__":
    unittest.main()
