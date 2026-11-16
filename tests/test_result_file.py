"""Slice 3.8: the result file someone sends back after trying OBAAF.

`python -m obaaf.result` runs `obaaf check` and writes counts only. The tests below put a marker word in
every place a repository's author can write text (file and directory names, workflow, job and step
names, scripts, `env` names and values, secret and environment names, actions, runner labels, the
configuration, an ignore entry, a baseline, CODEOWNERS, an instruction file, a Jenkinsfile, a file that
does not parse) and in every string of a settings audit report, and check that the word is nowhere in
the result file, that the file still counts what the reports found, and that a file holding a string
outside OBAAF's vocabulary is never written.
"""
import contextlib
import datetime
import io
import json
import re
import shlex
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from helpers import ROOT, TempDir, run_cli
from obaaf import result as result_mod

MARK = "zqxmark"
TOKEN_LIKE = "ghp_" + "Z" * 36

AGENT_WORKFLOW = f"""name: {MARK} workflow
on:
  push:
    branches: [{MARK}-branch]
  issue_comment:
    types: [created]
permissions:
  contents: write
  pull-requests: write
jobs:
  {MARK}_agent:
    name: {MARK} agent job
    runs-on: ubuntu-latest
    environment: {MARK}-env
    env:
      {MARK.upper()}_VALUE: {TOKEN_LIKE}
    steps:
      - name: {MARK} checkout
        uses: actions/checkout@v4
      - name: {MARK} agent step
        uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{{{ secrets.{MARK.upper()}_API_KEY }}}}
          prompt: "${{{{ github.event.comment.body }}}} {MARK}"
      - name: {MARK} script
        run: |
          echo "${{{{ github.event.issue.title }}}} {MARK}"
          curl -fsSL https://{MARK}.example.com/install.sh | bash
  {MARK}_declared:
    runs-on: [self-hosted, {MARK}-runner]
    environment: {MARK}-prod
    steps:
      - uses: {MARK}org/{MARK}-action@main
      - run: ./{MARK}-cli --token ${{{{ secrets.{MARK.upper()}_PUBLISH }}}}
"""

BROKEN_WORKFLOW = f"""name: {MARK} broken
on: [push
jobs: {MARK}: {{
"""

CONFIG = f"""lanes:
  ".github/workflows/{MARK}-agent.yml#{MARK}_declared": agent
  ".github/workflows/{MARK}-agent.yml#{MARK}_missing": {MARK}
protected_secrets:
  {MARK.upper()}_API_KEY: {MARK}-env
agents:
  commands: [{MARK}-cli]
ignore:
  - rule: OBAAF-GHA-008
    path: .github/workflows/{MARK}-agent.yml
    job: {MARK}_agent
    owner: "@{MARK}-owner"
    reason: {MARK} reviewed this pin and accepts it for now
    until: {(datetime.date.today() + datetime.timedelta(days=200)).isoformat()}
"""

JENKINSFILE = f"""pipeline {{
  agent {{ label '{MARK}-agent' }}
  stages {{
    stage('{MARK} build') {{
      steps {{ sh './{MARK}.sh' }}
    }}
    stage('{MARK} publish') {{
      steps {{ withCredentials([string(credentialsId: '{MARK}-cred', variable: 'TOKEN')]) {{ sh 'curl -T x https://{MARK}.example.com' }} }}
    }}
  }}
}}
"""


def marked_repository(tmp: Path) -> Path:
    repo = tmp / f"{MARK}-repo"
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / f"{MARK}-agent.yml").write_text(AGENT_WORKFLOW, encoding="utf-8")
    (workflows / f"{MARK}-broken.yml").write_text(BROKEN_WORKFLOW, encoding="utf-8")
    (repo / ".github" / "obaaf.yml").write_text(CONFIG, encoding="utf-8")
    (repo / ".github" / "CODEOWNERS").write_text(f"* @{MARK}/team\n", encoding="utf-8")
    (repo / "AGENTS.md").write_text(f"# {MARK}\nAgents may run {MARK}-cli.\n", encoding="utf-8")
    (repo / "Jenkinsfile").write_text(JENKINSFILE, encoding="utf-8")
    return repo


def run_result(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = result_mod.main([str(a) for a in args])
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def all_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from all_strings(item)


def mark_every_string(value, keep=()):
    """Every string value in a report with the marker added, except under the keys in `keep`."""
    if isinstance(value, dict):
        return {k: (v if k in keep and isinstance(v, str) else mark_every_string(v, keep)) for k, v in value.items()}
    if isinstance(value, list):
        return [mark_every_string(v, keep) for v in value]
    if isinstance(value, str):
        return f"{value} {MARK}"
    return value


class NothingFromTheRepositoryTest(unittest.TestCase):
    def assert_nothing_leaks(self, text: str) -> None:
        self.assertNotIn(MARK, text.lower())
        self.assertNotIn(TOKEN_LIKE[:8].lower(), text.lower())
        self.assertNotIn(".github", text)
        self.assertNotIn("@", text)

    def test_a_repository_marked_everywhere_leaves_no_mark_in_the_file(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            out = tmp / "result.json"
            code, _, err = run_result(repo, "--output", out)
            self.assertEqual(code, 0, err)
            text = out.read_text(encoding="ascii")
            self.assert_nothing_leaks(text)
            data = json.loads(text)
            result_mod.check_sendable(data)
            check = data["check"]
            # The file is not empty of what matters: the run found things, and says so as counts.
            self.assertEqual(check["exit"], 1)
            self.assertEqual(check["files"]["notRead"], 1)
            self.assertTrue(check["configuration"])
            rules = {row["rule"] for row in check["findings"]}
            self.assertIn("OBAAF-GHA-005", rules)
            self.assertIn("OBAAF-CFG-001", rules)
            self.assertTrue(any(row["state"] == "accepted" for row in check["findings"]), check["findings"])
            self.assertEqual(check["acceptedRisk"]["owners"], 1)
            self.assertGreater(check["jobs"]["withConfiguration"]["workflowJobs"]["agent"],
                               check["jobs"]["withoutConfiguration"]["workflowJobs"]["agent"])
            self.assertGreater(sum(check["jobs"]["withConfiguration"]["jenkinsStages"].values()), 0)
            self.assertIn("secrets-protected", {row["control"] for row in check["controls"]})

    def test_a_baseline_written_with_a_marked_owner_and_reason_leaves_no_mark(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            (repo / ".github" / "workflows" / f"{MARK}-broken.yml").unlink()
            baseline = tmp / f"{MARK}-baseline.json"
            code, _, err = run_cli("check", repo, "--write-baseline", baseline, "--owner", f"@{MARK}-owner",
                                   "--reason", f"{MARK} accepted while we look", "--expires", "2027-06-30",
                                   "--fail-on", "never")
            self.assertEqual(code, 0, err)
            self.assertIn(MARK, baseline.read_text(encoding="utf-8"))
            out = tmp / "result.json"
            code, _, err = run_result(repo, "--baseline", baseline, "--fail-on", "low", "--output", out)
            self.assertEqual(code, 0, err)
            text = out.read_text(encoding="ascii")
            self.assert_nothing_leaks(text)
            data = json.loads(text)
            self.assertTrue(data["check"]["baseline"]["used"])
            self.assertGreater(data["check"]["summary"]["accepted"], 1)

    def test_every_string_of_a_check_report_marked_leaves_only_counts(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            report = tmp / "check.json"
            run_cli("check", repo, "--format", "json", "--output", report)
            doc = json.loads(report.read_text(encoding="utf-8"))
            honest = result_mod.summarize_check(doc, result_mod._rule_ids())
            marked = mark_every_string(doc, keep=("format",))
            summary = result_mod.summarize_check(marked, result_mod._rule_ids())
            result_mod.check_sendable(summary)
            self.assertNotIn(MARK, json.dumps(summary))
            # A rule id, severity, state, control or verdict that is not OBAAF's own is counted as `other`.
            self.assertEqual({row["rule"] for row in summary["findings"]}, {"other"})
            self.assertEqual(sum(r["count"] for r in summary["findings"]),
                             sum(r["count"] for r in honest["findings"]))

    def test_every_string_of_an_audit_report_marked_leaves_only_counts(self):
        with TempDir() as tmp:
            audit = tmp / "audit.json"
            code, _, err = run_cli("audit", ROOT, "--from-snapshot", ROOT / ".github" / "obaaf-settings.json",
                                   "--format", "json", "--output", audit)
            self.assertIn(code, (0, 1), err)
            doc = json.loads(audit.read_text(encoding="utf-8"))
            marked = mark_every_string(doc, keep=("format",))
            marked["snapshot"]["settings"][f"{MARK}_setting"] = {"status": MARK}
            path = tmp / "marked.json"
            path.write_text(json.dumps(marked), encoding="utf-8")
            repo = tmp / "repo"
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / ".github" / "workflows" / "ci.yml").write_text(
                "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: make\n", encoding="utf-8")
            out = tmp / "result.json"
            code, _, err = run_result(repo, "--audit", path, "--output", out)
            self.assertEqual(code, 0, err)
            text = out.read_text(encoding="ascii")
            self.assertNotIn(MARK, text)
            self.assertNotIn("Obaaf/OBAAF", text)
            data = json.loads(text)["audit"]
            self.assertEqual({row["rule"] for row in data["rules"]}, {"other"})
            self.assertEqual({row["status"] for row in data["settings"]} - {None}, {"other"})
            self.assertEqual(data["tool"], "other")

    def test_the_honest_audit_report_is_counted_by_setting_and_rule(self):
        with TempDir() as tmp:
            audit = tmp / "audit.json"
            run_cli("audit", ROOT, "--from-snapshot", ROOT / ".github" / "obaaf-settings.json",
                    "--format", "json", "--output", audit)
            doc = json.loads(audit.read_text(encoding="utf-8"))
            data = result_mod.summarize_audit(doc, result_mod._rule_ids())
            result_mod.check_sendable(data)
            self.assertNotIn("Obaaf", json.dumps(data))
            self.assertEqual(len(data["rules"]), 15)
            settings = {row["setting"]: row for row in data["settings"]}
            self.assertEqual(settings["branch_protection"], {"setting": "branch_protection", "status": "unread",
                                                             "reason": "forbidden"})
            self.assertEqual(settings["rulesets"]["status"], "read")
            self.assertEqual(data["summary"]["cannotTell"], doc["summary"]["cannot_tell"])
            self.assertTrue(data["token"]["used"])
            self.assertFalse(any(data["token"]["roles"].values()))
            self.assertEqual(data["visibility"], "public")


class NothingOutsideTheVocabularyIsWrittenTest(unittest.TestCase):
    def test_a_key_or_a_string_that_is_not_obaafs_own_is_refused(self):
        for bad in ({"format": result_mod.FORMAT, "path": 1},
                    {"tool": ".github/workflows/release.yml"},
                    {"tool": "obaaf 1.2.3 and more"},
                    {"check": {"findings": [{"rule": "OBAAF-GHA-001", "count": 1, "job": "build"}]}},
                    {"check": {"seconds": float("nan")}},
                    {"check": {"files": b"bytes"}},
                    {"audit": {"rules": [{"rule": "OBAAF-SET-001", "status": "secret value"}]}},
                    {"date": "2026-11-16 build"}):
            with self.subTest(bad=bad):
                with self.assertRaises(result_mod.NotSendable):
                    result_mod.check_sendable(bad)

    def test_the_vocabulary_holds_every_rule_and_no_free_text(self):
        words = result_mod.vocabulary()
        self.assertIn("OBAAF-GHA-005", words)
        self.assertIn("OBAAF-SET-015", words)
        self.assertIn("branch_protection", words)
        for word in words:
            if word == result_mod.ABOUT:
                continue
            with self.subTest(word=word):
                self.assertRegex(word, r"\A[A-Za-z0-9_:./ -]{2,40}\Z")

    def test_a_result_that_would_leak_is_not_written_and_ends_with_2(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            out = tmp / "result.json"
            real = result_mod.summarize_check

            def leaking(doc, rule_ids):
                summary = real(doc, rule_ids)
                summary["notes"] = doc["files"][0]
                return summary

            with mock.patch.object(result_mod, "summarize_check", leaking):
                code, _, err = run_result(repo, "--output", out)
            self.assertEqual(code, 2)
            self.assertIn("was not written", err)
            self.assertFalse(out.exists())

    def test_every_control_and_lane_the_checker_gives_is_in_the_vocabulary(self):
        # If the checker gains a control or a lane, the result file would count it as `other`; this test
        # says so first.
        from obaaf.checker import workflow as wf_mod
        source = (ROOT / "src" / "obaaf" / "checker" / "rules.py").read_text(encoding="utf-8")
        idents = set(re.findall(r'(?:_ID|ident)\s*=\s*"([a-z-]+)"', source))
        idents |= set(re.findall(r'Control\([^)]*"([a-z]+(?:-[a-z]+)+)"\)', source))
        self.assertTrue(idents)
        self.assertLessEqual(idents, set(result_mod.CONTROL_IDS))
        self.assertLessEqual(set(wf_mod.LANES), set(result_mod.LANES))


class WhatTheFileCountsTest(unittest.TestCase):
    def test_its_counts_and_exit_status_are_those_of_obaaf_check_with_the_same_options(self):
        risky = ROOT / "tests" / "fixtures" / "workflows" / "risky"
        with TempDir() as tmp:
            repo = tmp / "repo"
            (repo / ".github" / "workflows").mkdir(parents=True)
            for name in ("pwn-request.yml", "promptpwnd-issue-agent.yml", "clinejection-release.yml"):
                (repo / ".github" / "workflows" / name).write_bytes((risky / name).read_bytes())
            # A category alone means that category at low and above, and is written so.
            for fail_on, written in (("medium", "medium"), ("never", "never"), ("authority:high", "authority:high"),
                                     ("hygiene", "hygiene:low")):
                with self.subTest(fail_on=fail_on):
                    report = tmp / "check.json"
                    status, _, _ = run_cli("check", repo, "--format", "json", "--fail-on", fail_on,
                                           "--output", report)
                    doc = json.loads(report.read_text(encoding="utf-8"))
                    out = tmp / "result.json"
                    code, _, err = run_result(repo, "--fail-on", fail_on, "--output", out)
                    self.assertEqual(code, 0, err)
                    check = json.loads(out.read_text(encoding="ascii"))["check"]
                    self.assertEqual(check["exit"], status)
                    self.assertEqual(check["failOn"], written)
                    self.assertEqual(check["summary"], doc["summary"])
                    self.assertEqual(sum(r["count"] for r in check["findings"]), len(doc["findings"]))
                    self.assertFalse(check["configuration"])
                    self.assertEqual(check["baseline"], {"used": False})

    def test_what_it_says_about_the_machine_and_the_version(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            out = tmp / "result.json"
            run_result(repo, "--output", out)
            data = json.loads(out.read_text(encoding="ascii"))
            from obaaf import __version__
            self.assertEqual(data["format"], "obaaf-result/v0.1")
            self.assertEqual(data["tool"], f"obaaf {__version__}")
            self.assertRegex(data["python"], r"\A3\.\d+\Z")
            self.assertIn(data["system"], ("linux", "darwin", "windows", "other"))
            self.assertIsNone(data["audit"])
            self.assertIsInstance(data["check"]["seconds"], float)

    def test_a_check_that_cannot_run_writes_no_file_and_ends_with_2(self):
        with TempDir() as tmp:
            out = tmp / "result.json"
            for args in ((tmp / "missing",), (tmp, "--fail-on", "sometimes"), (tmp,)):
                with self.subTest(args=args):
                    code, _, err = run_result(*args, "--output", out)
                    self.assertEqual(code, 2, err)
                    self.assertFalse(out.exists())

    def test_an_audit_file_that_is_not_an_audit_report_writes_no_file_and_ends_with_2(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            out = tmp / "result.json"
            not_json = tmp / "a.json"
            not_json.write_text("not json", encoding="utf-8")
            other = tmp / "b.json"
            other.write_text(json.dumps({"format": "obaaf-check/v0.1"}), encoding="utf-8")
            for path in (not_json, other, tmp / "missing.json"):
                with self.subTest(path=path.name):
                    code, _, err = run_result(repo, "--audit", path, "--output", out)
                    self.assertEqual(code, 2, err)
                    self.assertFalse(out.exists())

    def test_it_runs_as_a_module(self):
        with TempDir() as tmp:
            repo = tmp / "repo"
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / ".github" / "workflows" / "ci.yml").write_text(
                "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: make\n", encoding="utf-8")
            out = tmp / "result.json"
            import os
            import sys
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
            done = subprocess.run([sys.executable, "-m", "obaaf.result", str(repo), "--output", str(out)],
                                  capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("Read it before you send it.", done.stderr)
            self.assertEqual(json.loads(out.read_text(encoding="ascii"))["format"], "obaaf-result/v0.1")



PAGE = ROOT / "docs" / "send-us-the-result.md"
FORMS = ROOT / ".github" / "ISSUE_TEMPLATE"


def page_blocks() -> list[str]:
    import importlib.util
    spec = importlib.util.spec_from_file_location("page_blocks", ROOT / "scripts" / "page_blocks.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.blocks(PAGE.read_text(encoding="utf-8"))


class ThePageTest(unittest.TestCase):
    def test_its_blocks_are_the_steps_ci_runs_in_order(self):
        blocks = page_blocks()
        # .github/workflows/ci.yml runs block 1, then 2 to 5, then 6, by number.
        self.assertEqual(len(blocks), 6)
        self.assertIn("pip install --quiet --require-hashes --only-binary=:all:", blocks[0])
        self.assertIn("obaaf check .", blocks[1])
        self.assertIn("obaaf audit . --format json --output", blocks[2])
        self.assertTrue(blocks[3].startswith("python -m obaaf.result . --audit "))
        self.assertTrue(blocks[4].startswith("cat "))
        self.assertIn('rm -rf "$HOME/obaaf-try"', blocks[5])
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('page_blocks.py "$PAGE" --count)" = 6', workflow)
        self.assertIn("PAGE: docs/send-us-the-result.md", workflow)

    def test_every_command_on_the_page_is_one_the_tools_accept(self):
        from obaaf import cli
        found = 0
        for block in page_blocks():
            for line in block.replace("\\\n", " ").splitlines():
                line = line.strip()
                if line.startswith("obaaf "):
                    parser, words = cli.build_parser(), shlex.split(line)[1:]
                elif line.startswith("python -m obaaf.result"):
                    parser, words = result_mod.build_parser(), shlex.split(line)[3:]
                else:
                    continue
                found += 1
                with self.subTest(line=line):
                    try:
                        parser.parse_args(words)
                    except SystemExit as exc:
                        self.fail(f"`{line}` is not a command the tool accepts ({exc.code})")
        self.assertEqual(found, 4)

    def test_the_pinned_commit_holds_this_result_module(self):
        import os
        text = PAGE.read_text(encoding="utf-8")
        pins = set(re.findall(r"\b[0-9a-f]{40}\b", text))
        self.assertEqual(len(pins), 1, pins)
        pin = pins.pop()
        self.assertIn(f"checkout --quiet --detach {pin}", page_blocks()[0])
        try:
            done = subprocess.run(["git", "-C", str(ROOT), "show", f"{pin}:src/obaaf/result.py"],
                                  capture_output=True, timeout=60)
        except OSError as exc:
            done = None
            why = str(exc)
        if done is None or done.returncode != 0:
            why = why if done is None else done.stderr.decode(errors="replace").strip()
            if os.environ.get("CI"):
                self.fail(f"the commit the page pins is not in this clone ({why}); CI fetches the full history")
            self.skipTest(f"the commit the page pins is not in this clone's history ({why})")
        here = (ROOT / "src" / "obaaf" / "result.py").read_bytes()
        self.assertEqual(done.stdout, here, "the page pins a commit whose result module differs from this one; "
                                            "pin the commit that last changed src/obaaf/result.py")

    def test_the_page_says_what_the_file_holds_as_the_code_does(self):
        text = " ".join(PAGE.read_text(encoding="utf-8").split())
        for words in ("Nothing leaves your machine unless you send it", "status 0 when the file is written and 2 "
                      "when it is not", "counted as `other`", "tests/test_result_file.py", "development version",
                      "not a release", "--no-token", "--repo OWNER/REPO"):
            self.assertIn(words, text)
        self.assertIn("docs/send-us-the-result.md", result_mod.ABOUT)

    def test_the_issue_forms_are_forms_and_the_page_links_them(self):
        import yaml
        text = PAGE.read_text(encoding="utf-8")
        for name in ("obaaf-result.yml", "finding-changed-what-we-shipped.yml"):
            with self.subTest(form=name):
                form = yaml.safe_load((FORMS / name).read_text(encoding="utf-8"))
                self.assertTrue(form["name"] and form["description"])
                self.assertIn("public", form["description"])
                ids = [item["id"] for item in form["body"] if "id" in item]
                self.assertEqual(len(ids), len(set(ids)))
                for item in form["body"]:
                    self.assertIn(item["type"], ("markdown", "textarea", "input", "dropdown", "checkboxes"))
                    self.assertTrue(item["attributes"].get("label") or item["type"] == "markdown")
                self.assertIn(f"issues/new?template={name}", text)

    def test_the_docs_index_lists_the_page(self):
        index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
        self.assertIn("(send-us-the-result.md)", index)


class WhatTheReviewFoundTest(unittest.TestCase):
    """Faults the first review of slice 3.8 found, each shown before it was fixed."""

    def test_digits_of_other_scripts_and_large_numbers_are_refused(self):
        for bad in ({"tool": "obaaf \u0661.\u0662.\u0663"}, {"date": "\u0662\u0660\u0662\u0666-11-16"},
                    {"python": "3.\u0669"}, {"check": {"exit": int.from_bytes(b"ghp_token", "big")}},
                    {"check": {"seconds": 1e12}}, {"check": {"notes": -10**7}}):
            with self.subTest(bad=bad):
                with self.assertRaises(result_mod.NotSendable):
                    result_mod.check_sendable(bad)
        result_mod.check_sendable({"check": {"exit": 1, "seconds": 0.4, "notes": 999_999}})

    def test_an_audit_report_with_a_huge_count_writes_no_file(self):
        with TempDir() as tmp:
            audit = tmp / "audit.json"
            run_cli("audit", ROOT, "--from-snapshot", ROOT / ".github" / "obaaf-settings.json",
                    "--format", "json", "--output", audit)
            doc = json.loads(audit.read_text(encoding="utf-8"))
            doc["summary"]["findings"] = int.from_bytes(TOKEN_LIKE.encode(), "big")
            audit.write_text(json.dumps(doc), encoding="utf-8")
            repo = marked_repository(tmp)
            out = tmp / "result.json"
            code, _, err = run_result(repo, "--audit", audit, "--output", out)
            self.assertEqual(code, 2, err)
            self.assertFalse(out.exists())

    def test_a_deeply_nested_audit_file_ends_with_2_not_a_traceback(self):
        with TempDir() as tmp:
            deep = tmp / "deep.json"
            deep.write_text("[" * 200_000, encoding="utf-8")
            out = tmp / "result.json"
            code, _, err = run_result(marked_repository(tmp), "--audit", deep, "--output", out)
            self.assertEqual(code, 2, err)
            self.assertIn("nested too deeply", err)
            self.assertFalse(out.exists())

    def test_a_workflow_job_named_like_a_stage_is_a_workflow_job(self):
        with TempDir() as tmp:
            repo = tmp / "repo"
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / ".github" / "workflows" / "ci.yml").write_text(
                "on: push\npermissions:\n  contents: read\njobs:\n  'stage deploy':\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: make\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n",
                encoding="utf-8")
            out = tmp / "result.json"
            code, _, err = run_result(repo, "--fail-on", "never", "--output", out)
            self.assertEqual(code, 0, err)
            jobs = json.loads(out.read_text(encoding="ascii"))["check"]["jobs"]["withConfiguration"]
            self.assertEqual(sum(jobs["workflowJobs"].values()), 2)
            self.assertEqual(sum(jobs["jenkinsStages"].values()), 0)

    def test_an_option_value_that_begins_with_a_hyphen_is_passed_as_a_value(self):
        with TempDir() as tmp:
            repo = tmp / "repo"
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / ".github" / "workflows" / "ci.yml").write_text(
                "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: make\n", encoding="utf-8")
            (repo / "-cfg.yml").write_text("lanes: {}\n", encoding="utf-8")
            out = tmp / "result.json"
            import os
            here = os.getcwd()
            os.chdir(repo)
            try:
                code, _, err = run_result(".", "--config=-cfg.yml", "--output", out)
            finally:
                os.chdir(here)
            self.assertEqual(code, 0, err)
            self.assertTrue(json.loads(out.read_text(encoding="ascii"))["check"]["configuration"])

    def test_a_failed_run_leaves_no_earlier_result_behind(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            (repo / ".github" / "obaaf.yml").write_text("lanes: [not, a, mapping\n", encoding="utf-8")
            out = tmp / "result.json"
            out.write_text('{"format": "obaaf-result/v0.1", "an": "earlier run"}', encoding="utf-8")
            code, _, err = run_result(repo, "--output", out)
            self.assertEqual(code, 2, err)
            self.assertFalse(out.exists())

    def test_a_mistake_in_the_command_removes_nothing_and_says_the_old_file_is_not_this_runs(self):
        with TempDir() as tmp:
            out = tmp / "result.json"
            out.write_text('{"format": "obaaf-result/v0.1", "an": "earlier run"}', encoding="utf-8")
            for args in ((tmp / "missing",), (tmp, "--fail-on", "sometimes")):
                with self.subTest(args=args):
                    code, _, err = run_result(*args, "--output", out)
                    self.assertEqual(code, 2, err)
                    self.assertTrue(out.exists())
                    self.assertIn("not this run's result, so do not send it", err)

    def test_the_output_may_not_be_a_file_given_to_read_or_inside_what_is_checked(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            config = repo / ".github" / "obaaf.yml"
            workflow = repo / ".github" / "workflows" / f"{MARK}-agent.yml"
            audit = tmp / "audit.json"
            audit.write_text("{}", encoding="utf-8")
            files = {p: p.read_bytes() for p in (config, workflow, audit)}
            for args in ((repo, "--config", config, "--output", config), (repo, "--output", config),
                         (workflow, "--output", workflow), (repo, "--output", repo / "result.json"),
                         (repo, "--audit", audit, "--output", audit)):
                with self.subTest(args=[str(a).replace(str(tmp), "") for a in args]):
                    code, _, err = run_result(*args)
                    self.assertEqual(code, 2, err)
                    for path, before in files.items():
                        self.assertEqual(path.read_bytes(), before)
                    self.assertFalse((repo / "result.json").exists())

    def test_an_option_the_check_refuses_removes_nothing(self):
        with TempDir() as tmp:
            keep = tmp / "keep.txt"
            keep.write_text("mine", encoding="utf-8")
            code, _, err = run_result(marked_repository(tmp), "--fail-on", "sometimes", "--output", keep)
            self.assertEqual(code, 2, err)
            self.assertEqual(keep.read_text(encoding="utf-8"), "mine")

    def test_a_device_or_a_pipe_given_as_the_output_is_written_to_and_not_removed(self):
        import os
        with TempDir() as tmp:
            repo = tmp / "repo"
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / ".github" / "workflows" / "ci.yml").write_text(
                "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: make\n", encoding="utf-8")
            if not hasattr(os, "mkfifo") or not os.path.exists(os.devnull) or os.devnull != "/dev/null":
                self.skipTest("no /dev/null or named pipes here")
            code, _, err = run_result(repo, "--output", os.devnull)
            self.assertEqual(code, 0, err)
            self.assertFalse(Path(os.devnull).is_file())
            fifo = tmp / "fifo"
            os.mkfifo(fifo)
            import threading
            got = []
            reader = threading.Thread(target=lambda: got.append(fifo.read_bytes()))
            reader.start()
            code, _, err = run_result(repo, "--output", fifo)
            reader.join(timeout=60)
            self.assertEqual(code, 0, err)
            self.assertTrue(fifo.is_fifo())
            self.assertEqual(json.loads(got[0])["format"], "obaaf-result/v0.1")

    def test_an_audit_rule_listed_many_times_gives_one_row(self):
        with TempDir() as tmp:
            audit = tmp / "audit.json"
            run_cli("audit", ROOT, "--from-snapshot", ROOT / ".github" / "obaaf-settings.json",
                    "--format", "json", "--output", audit)
            doc = json.loads(audit.read_text(encoding="utf-8"))
            first = dict(doc["rules"][0], findings=3)
            doc["rules"] = doc["rules"] + [first] * 40 + [dict(first, id="OBAAF-SET-999")] * 40
            data = result_mod.summarize_audit(doc, result_mod._rule_ids())
            self.assertEqual(len(data["rules"]), 16)
            row = next(r for r in data["rules"] if r["rule"] == first["id"])
            self.assertEqual(row["findings"], doc["rules"][0]["findings"] + 120)
            other = next(r for r in data["rules"] if r["rule"] == "other")
            self.assertEqual(other["findings"], 120)

    def test_every_count_is_the_reports_counted_independently(self):
        with TempDir() as tmp:
            repo = marked_repository(tmp)
            (repo / ".github" / "workflows" / f"{MARK}-broken.yml").unlink()
            report = tmp / "check.json"
            run_cli("check", repo, "--format", "json", "--output", report)
            doc = json.loads(report.read_text(encoding="utf-8"))
            out = tmp / "result.json"
            code, _, err = run_result(repo, "--output", out)
            self.assertEqual(code, 0, err)
            check = json.loads(out.read_text(encoding="ascii"))["check"]
            from collections import Counter
            self.assertEqual(check["files"], {"checked": len(doc["files"]),
                                              "jenkinsfiles": len(doc.get("jenkins", {}).get("files", [])),
                                              "notRead": len(doc["errors"])})
            self.assertEqual(check["notes"], len(doc["notes"]))
            findings = Counter((f["rule"], f["severity"], f["state"]) for f in doc["findings"])
            self.assertEqual({(r["rule"], r["severity"], r["state"]): r["count"] for r in check["findings"]},
                             dict(findings))
            controls = Counter((f["rule"], c["id"], c["verdict"]) for f in doc["findings"]
                               for c in f.get("controls", []))
            self.assertTrue(controls)
            self.assertEqual({(r["rule"], r["control"], r["verdict"]): r["count"] for r in check["controls"]},
                             dict(controls))
            risk = doc["acceptedRisk"]
            self.assertEqual(check["acceptedRisk"], {
                "total": risk["total"], "bySeverity": risk["bySeverity"], "bySource": risk["bySource"],
                "owners": len(risk["owners"]), "daysToNearestExpiry": risk["daysToNearestExpiry"],
                "expiringSoon": risk["expiringSoon"]["total"]})
            self.assertGreater(check["acceptedRisk"]["total"], 0)
            # The lanes, against what `obaaf check --lanes` prints for each job and stage.
            _, listing, _ = run_cli("check", repo, "--lanes")
            lanes = Counter()
            for line in listing.splitlines():
                # `FILE#JOB: LANE (REASON)`; the reason may hold ": " itself.
                where, lane = re.match(r"(.*?#.*?): ([a-z]+) \(", line).groups()
                lanes[("jenkinsStages" if "#stage " in where else "workflowJobs", lane)] += 1
            counted = Counter({(kind, lane): n for kind in ("workflowJobs", "jenkinsStages")
                               for lane, n in check["jobs"]["withConfiguration"][kind].items() if n})
            self.assertEqual(counted, lanes)


if __name__ == "__main__":
    unittest.main()
