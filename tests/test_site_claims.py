"""Sentences on the website about the development version, checked against the code (flagship slice 4.7).

The site describes release 0.3.0 and, where a sentence says so, the development version: the code the
site is built from. Until slice 4.7 nothing kept those sentences in step with the code, and after 4.4
some went out of date. Each test here runs what a page describes and fails when the page and the code
disagree, so that the page is changed with the code. What the pages say of release 0.3.0 is a record
of runs of that release; these tests cannot run it, and do not try.
"""

import html
import json
import os
import re
import unittest

import yaml

from helpers import ROOT, TempDir, run_cli

from obaaf import __version__

SITE = ROOT / "site"
PRE_RE = re.compile(r"<pre><code>(.*?)</code></pre>", re.S)


def page(name: str) -> str:
    return (SITE / name).read_text(encoding="utf-8")


def blocks(name: str) -> list[str]:
    """The text of every `<pre><code>` block on a page, as a browser shows it."""
    return [html.unescape(match) for match in PRE_RE.findall(page(name))]


def text(name: str) -> str:
    """A page's words without tags, entities decoded, white space collapsed."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", page(name))))


def example_files(name: str) -> tuple[str, str]:
    """The two one-job workflow files a page shows, unpinned first."""
    files = [block for block in blocks(name) if block.startswith("name: pin\n")]
    if len(files) != 2:
        raise AssertionError(f"{name} shows {len(files)} example workflow files, not 2")
    return files[0], files[1]


def check_in(directory, *args: str) -> tuple[int, str, str]:
    """Run `obaaf check` from a directory, as the page's reader would."""
    before = os.getcwd()
    os.chdir(directory)
    try:
        return run_cli("check", *args)
    finally:
        os.chdir(before)


class TheTwoExampleFiles(unittest.TestCase):
    """The home page and the quickstart show the same two files and the same 0.3.0 report, and say
    which lines the development version's report adds. The development version must print the 0.3.0
    report's lines and the added kinds, and nothing else."""

    # The kinds of line the pages say the development report adds, by how each begins. These are
    # tripwires: a change to how the checker words or indents one of these lines fails here even where
    # the pages, which describe the lines without quoting them, are still true. Then update this map.
    ADDED = {
        "Accepted risk: ": "\"Accepted risk: none\"",
        "Other findings: ": "a count of other findings",
        "        Why: ": "a \"Why:\" line under the finding",
        "No configuration file was read": "what a check with no configuration file leaves out",
        "Other tools find workflow mistakes OBAAF does not look for": "the tools to run beside OBAAF",
        "Checked by obaaf ": "the version that checked",
    }

    def test_both_pages_show_the_same_files_and_report(self):
        self.assertEqual(example_files("index.html"), example_files("quickstart.html"))
        report = [block for block in blocks("index.html") if block.startswith("unpinned.yml\n")]
        self.assertEqual(report, [block for block in blocks("quickstart.html") if block.startswith("unpinned.yml\n")])
        self.assertEqual(len(report), 1)

    def test_the_pages_name_every_added_kind(self):
        for name in ("index.html", "quickstart.html"):
            words = text(name)
            for description in self.ADDED.values():
                self.assertIn(description, words, f"{name} no longer says the development report adds {description}")

    def _development_reports(self) -> dict:
        unpinned, pinned = example_files("index.html")
        with TempDir() as tmp:
            (tmp / "unpinned.yml").write_text(unpinned + "\n", encoding="utf-8")
            (tmp / "pinned.yml").write_text(pinned + "\n", encoding="utf-8")
            return {name: check_in(tmp, f"{name}.yml", "--fail-on", "low") for name in ("unpinned", "pinned")}

    def _without_added(self, out: str) -> tuple[list[str], set]:
        kept, seen = [], set()
        for line in out.splitlines():
            start = next((prefix for prefix in self.ADDED if line.startswith(prefix)), None)
            if start is not None:
                seen.add(start)
            elif line.strip():
                kept.append(line)
        return kept, seen

    def test_the_development_report_is_the_release_report_and_the_added_lines(self):
        reports = self._development_reports()
        self.assertEqual(reports["unpinned"][0], 1, "the pages say the unpinned file exits 1")
        self.assertEqual(reports["pinned"][0], 0, "the pages say the pinned file exits 0")
        before = next(block for block in blocks("index.html") if block.startswith("unpinned.yml\n"))
        after = next(block for block in blocks("index.html") if block.startswith("1 workflow file(s) checked.\n"))
        for name, shown in (("unpinned", before), ("pinned", after)):
            kept, seen = self._without_added(reports[name][1])
            self.assertEqual(kept, [line for line in shown.splitlines() if line.strip()],
                             f"the development report of {name}.yml has lines the pages do not account for")
            expected = set(self.ADDED) if name == "unpinned" else set(self.ADDED) - {"        Why: "}
            self.assertEqual(seen, expected, f"the development report of {name}.yml lacks a kind the pages name")

    def test_the_added_lines_are_where_the_pages_say(self):
        """At the top "Accepted risk: none" and the count; the "Why:" line under the finding, before its
        requirement; at the end the three closing lines, the last naming the version the banner names."""
        lines = self._development_reports()["unpinned"][1].splitlines()

        def where(start: str) -> int:
            found = [i for i, line in enumerate(lines) if line.startswith(start)]
            self.assertEqual(len(found), 1, f"{start!r} in {lines}")
            return found[0]

        first_file = where("unpinned.yml")
        self.assertTrue(lines[where("Accepted risk: ")].startswith("Accepted risk: none."))
        self.assertLess(where("Accepted risk: "), first_file)
        self.assertLess(where("Other findings: "), first_file)
        finding = where("     9  LOW    OBAAF-GHA-008")
        self.assertLess(finding, where("        Why: "))
        self.assertLess(where("        Why: "), where("        Requirement: "))
        last_count = where("Hygiene findings: ")
        for start in ("No configuration file was read", "Other tools find workflow mistakes", "Checked by obaaf "):
            self.assertGreater(where(start), last_count, start)
        self.assertEqual(lines[-1], f"Checked by obaaf {__version__}.")
        self.assertIn(f"numbered {__version__}", text("index.html"), "the banner names another development version")
        self.assertIn(f"checked with obaaf {__version__} on", text("index.html"))
        for name in ("index.html", "quickstart.html"):
            words = text(name)
            for placed in ("a count of other findings at the top",
                           "a \"Why:\" line under the finding, saying why it matters",
                           "and, at the end, what a check with no configuration file leaves out"):
                self.assertIn(placed, words, f"{name} no longer says where the added lines are")


class TheEgressAction(unittest.TestCase):
    def test_pages_name_the_reviewed_pin_and_conditional_credit(self):
        reviewed = "80db1e68769165c9ecf24e553254fa35d6e168d5"
        data = yaml.safe_load((ROOT / "src" / "obaaf" / "data" / "detection.yaml").read_text(encoding="utf-8"))
        self.assertEqual(data["egress_action_releases"], [reviewed])
        for name in ("index.html", "rules.html", "comparison.html", "case-study.html"):
            words = text(name)
            self.assertIn(f"pins Obaaf/OBAAF/actions/egress@{reviewed}", words, name)
            self.assertIn("can clear OBAAF-GHA-020 when the job meets the egress conditions", words, name)


AGENT_JOB = """\
name: agent
on: {on}
permissions:
  {permissions}
jobs:
  triage:
    runs-on: {runs_on}
{strategy}    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567 # v1
        with:
          prompt: Triage this issue.
"""

POLICY = "mode: enforce\nallow:\n  - api.anthropic.com\n"


class TheFirewallConditions(unittest.TestCase):
    """The rules page lists when the development checker clears OBAAF-GHA-020 for GitHub's native
    egress firewall. The case that meets every condition is cleared, and breaking any one of the
    conditions below (or, in the next test, calling a reusable workflow) is not."""

    def _gha020(self, workflow: dict | None = None, policy: str | None = POLICY, policy_name="egress-firewall.yaml",
                single_file=False) -> str:
        values = {"on": "issues", "permissions": "contents: read", "runs_on": "ubuntu-24.04-firewall", "strategy": ""}
        values.update(workflow or {})
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "agent.yml").write_text(AGENT_JOB.format(**values), encoding="utf-8")
            if policy is not None:
                (tmp / ".github" / policy_name).write_text(policy, encoding="utf-8")
            target = tmp / ".github" / "workflows" / "agent.yml" if single_file else tmp
            code, out, err = run_cli("check", target, "--format", "json")
        self.assertIn(code, (0, 1), err)
        report = json.loads(out)
        # A finding cleared by verified controls is listed under "fixed", not under "findings".
        found = [("fixed" if where == "fixed" else f["state"]) for where in ("findings", "fixed")
                 for f in report.get(where, []) if f["rule"] == "OBAAF-GHA-020"]
        self.assertEqual(len(found), 1, out)
        return found[0]

    def test_the_page_lists_the_conditions_tested_here(self):
        words = text("rules.html")
        for condition in ("run on the repository, not on a single file", "matrix runs included",
                          "as its only runner label", "named exactly .github/egress-firewall.yaml",
                          "is YAML the checker can read", "no key but mode, allow and no-default-urls",
                          "sets mode: enforce",
                          "allows only plain host names, none of which is a public suffix or has one under it",
                          "the job's token has contents permission", "the job calls no reusable workflow",
                          "no other workflow can call this one"):
            self.assertIn(condition, words)

    def test_a_job_that_calls_a_reusable_workflow_is_not_cleared(self):
        """The page's "the job calls no reusable workflow": a job declared an agent job that only calls
        another workflow is not cleared by the firewall. Such a job has no `runs-on`, so the runner
        condition already rules it out; this keeps the page's sentence tied to a run, and would not
        notice the separate check for a reusable call being removed."""
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "agent.yml").write_text(
                AGENT_JOB.format(on="[issues, workflow_call]", permissions="contents: read",
                                 runs_on="ubuntu-24.04-firewall", strategy=""), encoding="utf-8")
            (tmp / ".github" / "workflows" / "caller.yml").write_text(
                "name: caller\non: issues\npermissions:\n  contents: read\njobs:\n  call:\n"
                "    uses: ./.github/workflows/agent.yml\n", encoding="utf-8")
            (tmp / ".github" / "obaaf.yml").write_text("lanes:\n  .github/workflows/caller.yml#call: agent\n",
                                                       encoding="utf-8")
            (tmp / ".github" / "egress-firewall.yaml").write_text(POLICY, encoding="utf-8")
            code, out, err = run_cli("check", tmp, "--format", "json")
        self.assertIn(code, (0, 1), err)
        report = json.loads(out)
        called = [f for f in report["findings"] + report.get("fixed", []) if f["rule"] == "OBAAF-GHA-020"
                  and f.get("job") == "call"]
        self.assertEqual(len(called), 1, out)
        self.assertNotIn(called[0], report.get("fixed", []))

    def test_every_condition_met_clears_it(self):
        self.assertEqual(self._gha020(), "fixed")

    def test_breaking_any_one_condition_does_not(self):
        cases = {
            "a single file": dict(single_file=True),
            "another runner on one matrix run": dict(workflow={
                "runs_on": "${{ matrix.os }}",
                "strategy": "    strategy:\n      matrix:\n        os: [ubuntu-24.04-firewall, ubuntu-24.04]\n"}),
            "a second label": dict(workflow={"runs_on": "[ubuntu-24.04-firewall, gpu]"}),
            "no policy file": dict(policy=None),
            "the policy under another name": dict(policy_name="egress-firewall.yml"),
            "a key the README does not describe": dict(policy=POLICY + "extra: true\n"),
            "YAML the checker cannot read": dict(policy="mode: enforce\nallow: [api.anthropic.com\n"),
            "mode: log": dict(policy=POLICY.replace("enforce", "log")),
            "a wildcard": dict(policy="mode: enforce\nallow:\n  - '*.anthropic.com'\n"),
            "a public suffix": dict(policy="mode: enforce\nallow:\n  - github.io\n"),
            "no contents permission": dict(workflow={"permissions": "issues: read"}),
            "callable by another workflow": dict(workflow={"on": "[issues, workflow_call]"}),
        }
        for case, arguments in cases.items():
            with self.subTest(case):
                self.assertNotEqual(self._gha020(**arguments), "fixed")


SECRET_JOBS = """\
name: agent
on: push
permissions:
  contents: read
jobs:
  named:
    runs-on: ubuntu-latest
    environment: main-only
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567 # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
  environment-only:
    runs-on: ubuntu-latest
    environment: main-only
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567 # v1
"""


class OBAAFGHA005(unittest.TestCase):
    def test_five_controls_one_a_setting_check_does_not_read(self):
        """The rules page: with named secrets the finding lists five controls and clears only when all
        five are verified; one is a setting `obaaf check` does not read, so it is never cleared; a job
        that only declares an environment gets the finding with no controls."""
        words = text("rules.html")
        self.assertIn("lists five controls on the finding and clears it only when it has verified all five", words)
        self.assertIn("A job that only declares an environment gets the finding with no controls listed", words)
        with TempDir() as tmp:
            (tmp / "agent.yml").write_text(SECRET_JOBS, encoding="utf-8")
            code, out, err = run_cli("check", tmp / "agent.yml", "--format", "json")
        self.assertEqual(code, 1, err)
        found = {f["job"]: f for f in json.loads(out)["findings"] if f["rule"] == "OBAAF-GHA-005"}
        self.assertEqual(len(found["named"]["controls"]), 5)
        setting = [c for c in found["named"]["controls"] if c["id"] == "environment-restricted"]
        self.assertEqual([c["verdict"] for c in setting], ["cannot tell"])
        self.assertEqual(found["environment-only"].get("controls", []), [])
        self.assertNotEqual(found["named"]["state"], "fixed")


if __name__ == "__main__":
    unittest.main()
