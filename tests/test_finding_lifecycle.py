"""The lifecycle of a finding (flagship slice 2a.1).

A finding is new, accepted, fixed, or one the checker cannot tell about. Only a valid acceptance (an
owner, a reason and an expiry date that has not passed and is at most a year ahead) or controls the
checker verified keep it from failing the check. What a finding is does not depend on how its
message is worded, so an acceptance survives a change of wording and never covers another finding.
"""

import itertools
import json
import random
import re
import shutil
import unittest
from datetime import date, datetime, timedelta

from helpers import FIXTURES, RISKY, TEMPLATES, TempDir, run_cli

from obaaf import checker
from obaaf.checker import acceptance, baseline, report, rules
from obaaf.checker.rules import CANNOT_TELL, NOT_MET, VERIFIED, Control, Finding

TODAY = date.today()
SOON = (TODAY + timedelta(days=90)).isoformat()
OWNER, REASON = "@example/maintainers", "Reviewed; tracked in issue 7"
ACCEPT = ("--owner", OWNER, "--reason", REASON, "--expires", SOON)
REPO = FIXTURES / "baselines" / "repo"
V1 = FIXTURES / "baselines" / "v0.1.json"      # written by `obaaf check --write-baseline` of OBAAF 0.3.0


def fixture_repo(tmp):
    """A copy of the fixture repository and of the old-format baseline 0.3.0 wrote for it."""
    shutil.copytree(REPO, tmp / "repo", dirs_exist_ok=True)
    shutil.copy(V1, tmp / "baseline.json")
    return tmp / "repo", tmp / "baseline.json"


def finding(**changes):
    values = dict(rule="OBAAF-GHA-005", severity="high", path=".github/workflows/agent.yml", line=9,
                  message="Agent job 'triage' receives MODEL_KEY.", job="triage", kind="secrets",
                  facts={"secrets": ["MODEL_KEY"]})
    values.update(changes)
    return Finding(**values)


def result_of(*findings):
    return checker.CheckResult(findings=list(findings), files=["x"], errors=[], config=checker.Config())


def entry(f=None, **changes):
    made = baseline.entry_for(f or finding(), OWNER, REASON, SOON)
    for name, value in changes.items():
        if value is None:
            made.pop(name, None)
        else:
            made[name] = value
    return made


def applied(entries, *findings, today=TODAY):
    result = result_of(*findings)
    baseline.apply(result, baseline.Baseline(baseline.FORMAT, list(entries)), today)
    return result


class AcceptanceTest(unittest.TestCase):
    """Every way an acceptance can fail to count."""

    def problems(self, owner=OWNER, reason=REASON, expires=SOON):
        return acceptance.problems(owner, reason, expires, TODAY)

    def test_owner_reason_and_a_date_within_a_year_is_valid(self):
        self.assertEqual(self.problems(), [])
        for owner in ("@octocat", "@example/maintainers", "@a", "@0", "@a-b", "@org/team.name", "security@example.com",
                      "first.last+ci@mail.example.co", " @octocat "):
            self.assertEqual(self.problems(owner=owner), [], owner)
        for day in (TODAY, TODAY + timedelta(days=acceptance.MAX_DAYS)):
            self.assertEqual(self.problems(expires=day.isoformat()), [], day)
            self.assertEqual(self.problems(expires=day), [], day)

    def test_no_owner(self):
        for owner in (None, "", "   ", [], ["@octocat"], 7, True):
            self.assertEqual(self.problems(owner=owner), ["it names no owner"], repr(owner))

    def test_an_owner_that_names_nobody(self):
        for owner in ("Sean", "the team", "@", "@a b", "@-x", "@org/", "@org/team/extra", "x@y", "tbd", "@org//team",
                      "a@b@c.d", "@" + "a" * 40, "@a-", "@a--b", "@org/-team", "@org/team-", ".@-.-", "%@-.-", "-@-.-",
                      "+@0.0", "a@-.com", "a@b.-", "a@b..c", "@NAME" + "x" * 100_000, "a" * 70 + "@example.com",
                      "<@user or @org/team>", "OWNER"):
            found = self.problems(owner=owner)
            self.assertEqual(len(found), 1, owner)
            self.assertIn("is not a user (@name), a team (@org/team) or an e-mail address", found[0])

    def test_no_reason(self):
        for reason in (None, "", "  \n ", [], 0):
            self.assertEqual(self.problems(reason=reason), ["it gives no reason"], repr(reason))

    def test_a_reason_that_says_too_little(self):
        for reason in (".", "?", "...", "tbd", "n/a", "ok", "REASON", "reviewed", "\u200b", "\u2060\ufeff\u00ad",
                       "\u3164" * 20, "- - - - - - - - - - - -", "x" * 9):
            found = self.problems(reason=reason)
            self.assertEqual(len(found), 1, repr(reason))
            self.assertIn("says too little", found[0])
        for reason in ("x" * 10, "Tracked in issue 12", "レビュー済み、課題12で追跡します"):
            self.assertEqual(self.problems(reason=reason), [], reason)

    def test_no_expiry_date(self):
        for expires in (None, "", "  "):
            self.assertEqual(self.problems(expires=expires), ["it has no expiry date"], repr(expires))

    def test_an_expiry_that_is_not_a_date(self):
        ahead = (TODAY + timedelta(days=30)).isoformat()
        other_digits = ahead.translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))      # Arabic-Indic digits
        for expires in ("soon", "never", "2027-13-01", "2027-02-30", "20270101", "2027-1-1", "01/02/2027", 20270101,
                        True, ["2027-01-01"], datetime(2027, 1, 1, 12, 0), "2027-01-01T00:00:00", other_digits):
            found = self.problems(expires=expires)
            self.assertEqual(len(found), 1, repr(expires))
            self.assertIn("is not a date (YYYY-MM-DD)", found[0])

    def test_an_expiry_date_that_has_passed(self):
        yesterday = TODAY - timedelta(days=1)
        self.assertEqual(self.problems(expires=yesterday.isoformat()), [f"it expired on {yesterday.isoformat()}"])

    def test_an_expiry_date_more_than_a_year_ahead(self):
        for day in (TODAY + timedelta(days=acceptance.MAX_DAYS + 1), date(2999, 1, 1)):
            found = self.problems(expires=day.isoformat())
            self.assertEqual(len(found), 1)
            self.assertIn(f"more than {acceptance.MAX_DAYS} days ahead", found[0])

    def test_every_problem_is_listed(self):
        self.assertEqual(len(acceptance.problems(None, None, None, TODAY)), 3)
        self.assertEqual(len(acceptance.problems("nobody", "", "2000-01-01", TODAY)), 3)
        self.assertEqual(len(acceptance.problems("OWNER", "REASON", "YYYY-MM-DD", TODAY)), 3)   # the hint, pasted


class StateTest(unittest.TestCase):
    """new, accepted, fixed, cannot tell: what each is, and which of them fail the check."""

    def gates(self, *findings):
        return bool(result_of(*findings).gating("low", checker.load()))

    def test_a_finding_with_nothing_said_about_it_is_new_and_fails(self):
        f = finding()
        self.assertEqual(f.state, "new")
        self.assertTrue(self.gates(f))

    def test_a_valid_acceptance_makes_it_accepted_and_it_passes(self):
        result = applied([entry()], finding())
        f = result.findings[0]
        self.assertEqual((f.state, f.baselined, f.acceptance.valid), ("accepted", True, True))
        self.assertEqual((f.acceptance.owner, f.acceptance.reason, f.acceptance.expires), (OWNER, REASON, SOON))
        self.assertFalse(result.gating("low", checker.load()))

    def test_an_ignored_finding_is_accepted(self):
        f = finding(suppressed="reviewed (until 2027-01-01)")
        self.assertEqual(f.state, "accepted")
        self.assertFalse(self.gates(f))

    def test_every_control_verified_makes_it_fixed_and_it_passes(self):
        f = finding(controls=[Control("the key is in an environment", VERIFIED, "environment main-only"),
                              Control("egress is enforced", VERIFIED)])
        self.assertEqual(f.state, "fixed")
        self.assertFalse(self.gates(f))
        result = result_of(f)
        self.assertEqual((result.active(), result.cleared()), ([], [f]))

    def test_a_control_that_is_not_met_leaves_it_new(self):
        f = finding(controls=[Control("the key is in an environment", VERIFIED),
                              Control("egress is enforced", NOT_MET), Control("no pull request code", CANNOT_TELL)])
        self.assertEqual(f.state, "new")
        self.assertTrue(self.gates(f))

    def test_a_control_that_could_not_be_verified_is_cannot_tell_and_fails(self):
        f = finding(controls=[Control("the key is in an environment", VERIFIED),
                              Control("the environment is limited to main", CANNOT_TELL, "settings were not read")])
        self.assertEqual(f.state, "cannot-tell")
        self.assertTrue(self.gates(f))

    def test_cannot_tell_is_never_a_pass_but_can_be_accepted(self):
        f = finding(controls=[Control("the environment is limited to main", CANNOT_TELL)])
        result = applied([entry()], f)
        self.assertEqual(f.state, "accepted")
        self.assertFalse(result.gating("low", checker.load()))

    def test_a_control_has_no_fourth_verdict(self):
        for verdict in ("pass", "assumed", "", "Verified", None):
            with self.assertRaises(ValueError):
                Control("x", verdict)

    def test_a_fixed_finding_makes_its_acceptance_stale(self):
        f = finding(controls=[Control("egress is enforced", VERIFIED)])
        result = applied([entry()], f)
        self.assertEqual(f.state, "fixed")
        self.assertIsNone(f.acceptance)
        self.assertEqual(len(result.baseline_stale), 1)
        self.assertTrue(result.stale_gating("low", checker.load()))

    def test_the_report_shows_each_state(self):
        fixed = finding(job="a", controls=[Control("egress is enforced", VERIFIED, "awf, pinned")])
        undecided = finding(job="b", controls=[Control("the environment is limited to main", CANNOT_TELL,
                                                       "settings were not read")])
        accepted, new = finding(job="c"), finding(job="d")
        result = applied([entry(accepted)], fixed, undecided, accepted, new)
        text = report.to_text(result)
        self.assertIn("Baseline: 1 finding(s) accepted by the baseline, 2 new.", text)
        self.assertIn(f"Accepted by {OWNER} until {SOON}: {REASON}", text)
        self.assertIn("Cannot tell: no control that would clear this finding is known to be missing", text)
        self.assertIn("the environment is limited to main: cannot tell (settings were not read)", text)
        self.assertIn("Cannot tell: for 1 finding(s)", text)
        self.assertIn("Fixed: 1 finding(s) are cleared by controls the checker verified", text)
        self.assertIn("fixed: OBAAF-GHA-005 .github/workflows/agent.yml:9 [job a] - egress is enforced: verified "
                      "(awf, pinned)", text)
        data = json.loads(report.to_json(result))
        self.assertEqual(data["summary"], {"new": 1, "accepted": 1, "cannotTell": 1, "fixed": 1, "notAccepted": 0})
        self.assertEqual(sorted(f["state"] for f in data["findings"]), ["accepted", "cannot-tell", "new"])
        self.assertEqual([f["job"] for f in data["fixed"]], ["a"])
        sarif = json.loads(report.to_sarif(result))["runs"][0]["results"]
        self.assertEqual(sorted(r["properties"]["obaaf-state"] for r in sarif), ["accepted", "cannot-tell", "new"])


class BaselineEntryTest(unittest.TestCase):
    """What a v0.2 entry accepts, and what it does not."""

    def refused(self, changed, expected):
        result = applied([changed], finding())
        f = result.findings[0]
        self.assertFalse(f.baselined)
        self.assertEqual(f.state, "new")
        self.assertFalse(f.acceptance.valid)
        self.assertIn(expected, "; ".join(f.acceptance.problems))
        self.assertTrue(result.gating("low", checker.load()))
        self.assertEqual(result.baseline_stale, [])     # the entry names the finding; it just does not count
        self.assertEqual(result.not_accepted(), [f])
        self.assertIn("Not accepted: the baseline entry that names this finding does not count, because",
                      report.to_text(result))

    def test_an_entry_without_an_owner_a_reason_or_an_expiry_date_accepts_nothing(self):
        self.refused(entry(owner=None), "it names no owner")
        self.refused(entry(owner=""), "it names no owner")
        self.refused(entry(owner="somebody"), "is not a user")
        self.refused(entry(reason=None), "it gives no reason")
        self.refused(entry(reason="  "), "it gives no reason")
        self.refused(entry(expires=None), "it has no expiry date")
        self.refused(entry(expires="later"), "is not a date")
        self.refused(entry(expires="2001-02-03"), "it expired on 2001-02-03")
        self.refused(entry(expires="2999-01-01"), "days ahead")

    def test_an_entry_expires_the_day_after_its_date(self):
        made = entry(expires=SOON)
        day = date.fromisoformat(SOON)
        self.assertTrue(applied([made], finding(), today=day).findings[0].baselined)
        self.assertFalse(applied([made], finding(), today=day + timedelta(days=1)).findings[0].baselined)

    def test_an_entry_does_not_cover_a_finding_that_became_more_severe(self):
        result = applied([entry(severity="low")], finding())
        f = result.findings[0]
        self.assertFalse(f.baselined)
        self.assertIn("it accepts the finding at low severity and the finding is now high",
                      f.acceptance.problems)
        self.assertTrue(applied([entry(severity="high")], finding(severity="medium")).findings[0].baselined)

    def test_an_entry_covers_only_the_finding_its_fields_describe(self):
        for change in (dict(job="other"), dict(path=".github/workflows/other.yml"), dict(rule="OBAAF-GHA-003"),
                       dict(kind="environment"), dict(facts={"secrets": ["MODEL_KEY", "DEPLOY_KEY"]}),
                       dict(facts={"secrets": ["*"]}), dict(step="run"), dict(scope="stage")):
            result = applied([entry()], finding(**change))
            self.assertFalse(result.findings[0].baselined, change)
            self.assertIsNone(result.findings[0].acceptance, change)
            self.assertEqual(len(result.baseline_stale), 1, change)

    def test_the_wording_of_a_message_and_the_line_are_not_part_of_what_a_finding_is(self):
        reworded = finding(message="The agent job triage is given the secret MODEL_KEY.", line=400)
        self.assertEqual(baseline.key(reworded), baseline.key(finding()))
        self.assertTrue(applied([entry()], reworded).findings[0].baselined)

    def test_a_finding_without_facts_is_identified_by_its_message(self):
        jenkins = dict(rule="OBAAF-JEN-007", path="Jenkinsfile", job="Triage", scope="stage", kind="", facts=None,
                       severity="low", message="Nothing in the Jenkinsfile limits the network access of the agent.")
        made = entry(finding(**jenkins))
        self.assertEqual(made["message"], jenkins["message"])
        self.assertNotIn("facts", made)
        self.assertTrue(applied([made], finding(**jenkins)).findings[0].baselined)
        self.assertFalse(applied([made], finding(**{**jenkins, "message": "Another message."})).findings[0].baselined)

    def test_a_valid_entry_is_used_before_one_that_does_not_count(self):
        result = applied([entry(expires="2001-02-03"), entry()], finding())
        self.assertTrue(result.findings[0].baselined)
        self.assertEqual([e["expires"] for e in result.baseline_stale], ["2001-02-03"])

    def test_two_findings_need_two_entries(self):
        result = applied([entry()], finding(line=1), finding(line=2))
        self.assertEqual(sorted(f.baselined for f in result.findings), [False, True])

    def test_an_entry_that_gives_a_key_twice_is_refused(self):
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            path = tmp / "b.json"
            text = json.dumps({"format": baseline.FORMAT, "findings": [entry(expires="2001-02-03")]})
            path.write_text(text.replace('"expires": "2001-02-03"', f'"expires": "2001-02-03", "expires": "{SOON}"'))
            code, _, err = run_cli("check", repo, "--baseline", path, "--fail-on", "low")
            self.assertEqual(code, 2)
            self.assertIn("appears twice", err)

    def test_a_file_the_checker_cannot_read_as_a_baseline_is_refused(self):
        good = entry()
        bad = [{**good, "expiry": SOON}, {**good, "fingerprint": "sha256:00"}, {**good, "facts": {"secrets": [1]}},
               {**good, "facts": {}}, {**good, "facts": {"n": 1.5}}, {**good, "facts": ["MODEL_KEY"]},
               {**good, "message": "x"}, {**good, "severity": "critical"}, {**good, "job": ""}, {**good, "job": 7},
               {**good, "severity": ["high"]}, {**good, "severity": {"high": 1}}, {**good, "rule": ["OBAAF-GHA-005"]},
               {k: v for k, v in good.items() if k != "rule"}, {k: v for k, v in good.items() if k != "path"},
               {k: v for k, v in good.items() if k != "severity"}, "text", ["x"], None]
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            path = tmp / "b.json"
            for number, item in enumerate(bad):
                path.write_text(json.dumps({"format": baseline.FORMAT, "findings": [good, item]}))
                code, out, err = run_cli("check", repo, "--baseline", path, "--fail-on", "low")
                self.assertEqual(code, 2, f"{number}: {item!r}")
                self.assertIn("entry 2", err)
                self.assertNotIn("Traceback", err)


class IgnoreEntryTest(unittest.TestCase):
    """An ignore entry in the configuration is an acceptance like any other."""

    def run_with(self, tmp, lines, today=TODAY):
        repo, _ = fixture_repo(tmp)
        (repo / ".github" / "obaaf.yml").write_text(
            "ignore:\n  - rule: OBAAF-GHA-001\n    path: .github/workflows/ci.yml\n" + lines)
        result = checker.check(repo, today=today)
        return result, next(f for f in result.findings if f.rule == "OBAAF-GHA-001" and f.path.endswith("ci.yml"))

    def test_an_entry_with_owner_reason_and_date_ignores_the_finding(self):
        with TempDir() as tmp:
            result, f = self.run_with(tmp, f"    owner: '@octocat'\n    reason: {REASON}\n    until: {SOON}\n")
            self.assertEqual(f.suppressed, f"{REASON} (until {SOON})")
            self.assertEqual((f.state, f.acceptance.source, f.acceptance.owner), ("accepted", "ignore", "@octocat"))
            self.assertEqual(result.not_accepted(), [])

    def test_an_entry_without_an_owner_ignores_nothing(self):
        with TempDir() as tmp:
            result, f = self.run_with(tmp, f"    reason: {REASON}\n    until: {SOON}\n")
            self.assertIsNone(f.suppressed)
            self.assertEqual(f.state, "new")
            self.assertEqual(f.acceptance.problems, ["it names no owner"])
            self.assertIn(f, result.gating("low", checker.load()))
            text = report.to_text(result)
            self.assertIn("Not accepted: the ignore entry that names this finding does not count, because it names "
                          "no owner.", text)
            self.assertIn("Not accepted: 1 finding(s) are named by an ignore or baseline entry", text)

    def test_an_entry_dated_more_than_a_year_ahead_ignores_nothing(self):
        with TempDir() as tmp:
            _, f = self.run_with(tmp, f"    owner: '@octocat'\n    reason: {REASON}\n    until: 2999-01-01\n")
            self.assertIsNone(f.suppressed)
            self.assertIn("days ahead", f.acceptance.problems[0])

    def test_an_expired_entry_ignores_nothing_and_says_when_it_expired(self):
        with TempDir() as tmp:
            _, f = self.run_with(tmp, f"    owner: '@octocat'\n    reason: {REASON}\n    until: 2001-02-03\n")
            self.assertIsNone(f.suppressed)
            self.assertEqual(f.acceptance.problems, ["it expired on 2001-02-03"])
            self.assertIn("(An ignore entry for this finding expired on 2001-02-03.)", f.message)

    def test_a_second_entry_that_is_valid_still_ignores_the_finding(self):
        with TempDir() as tmp:
            _, f = self.run_with(tmp, f"    reason: {REASON}\n    until: 2001-02-03\n"
                                      "  - rule: OBAAF-GHA-001\n    path: .github/workflows/ci.yml\n"
                                      f"    owner: '@octocat'\n    reason: Looked at again in May\n    until: {SOON}\n")
            self.assertEqual(f.suppressed, f"Looked at again in May (until {SOON})")
            self.assertTrue(f.acceptance.valid)

    def test_until_is_a_date_and_nothing_else(self):
        for until in ("2027-01-31T10:00:00Z", "2027-01-31 10:00:00", "next year", "20270131"):
            with TempDir() as tmp, self.subTest(until=until):
                with self.assertRaises(checker.ConfigError) as raised:
                    self.run_with(tmp, f"    owner: '@octocat'\n    reason: {REASON}\n    until: {until}\n")
                self.assertIn("must be a date (YYYY-MM-DD)", str(raised.exception))

    def test_a_finding_waiting_on_an_ignore_entry_is_not_written_into_a_baseline(self):
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            (repo / ".github" / "obaaf.yml").write_text(
                "ignore:\n  - rule: OBAAF-GHA-001\n    path: .github/workflows/ci.yml\n"
                f"    reason: {REASON}\n    until: {SOON}\n")
            out = tmp / "new.json"
            code, _, err = run_cli("check", repo, "--write-baseline", out, *ACCEPT)
            self.assertEqual(code, 0, err)
            self.assertIn("1 finding(s) whose ignore entry has expired or does not count were not written", err)
            written = json.loads(out.read_text())["findings"]
            self.assertEqual(len(written), 15)
            self.assertFalse([e for e in written if e["path"].endswith("ci.yml")])


class OldFormatTest(unittest.TestCase):
    """A baseline written by 0.2.0 or 0.3.0 is still read, and accepts nothing until it is converted."""

    def test_the_file_0_3_0_wrote_is_read_and_every_entry_still_names_its_finding(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            self.assertEqual(json.loads(old.read_text())["tool"], "obaaf 0.3.0")
            code, out, err = run_cli("check", repo, "--baseline", old, "--fail-on", "low", "--format", "json")
            self.assertEqual(code, 1, err)
            data = json.loads(out)
            self.assertEqual(len(data["findings"]), 16)
            self.assertEqual(data["baseline"], {"stale": [], "format": baseline.FORMAT_V1})
            self.assertEqual(data["summary"], {"new": 16, "accepted": 0, "cannotTell": 0, "fixed": 0,
                                               "notAccepted": 16})
            for f in data["findings"]:
                self.assertEqual((f["state"], f["baselined"], f["acceptance"]["valid"]), ("new", False, False))

    def test_the_report_says_how_to_convert_it(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            code, out, _ = run_cli("check", repo, "--baseline", old, "--fail-on", "low", "--no-fixes")
            self.assertEqual(code, 1)
            self.assertIn("Baseline: 0 finding(s) accepted by the baseline, 16 new.", out)
            self.assertIn("The baseline is in the old format (obaaf-baseline/v0.1).", out)
            self.assertIn(f"obaaf baseline migrate {old} {repo} --owner OWNER --reason REASON --expires YYYY-MM-DD", out)
            self.assertIn("because it is an old-format entry, which names no owner, reason or expiry date.", out)

    def test_reporting_mode_still_exits_zero(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            code, _, _ = run_cli("check", repo, "--baseline", old, "--fail-on", "never")
            self.assertEqual(code, 0)

    def test_an_entry_whose_text_does_not_match_its_fingerprint_is_refused(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            data = json.loads(old.read_text())
            data["findings"][0]["message"] = "something harmless"
            old.write_text(json.dumps(data))
            code, _, err = run_cli("check", repo, "--baseline", old, "--fail-on", "low")
            self.assertEqual(code, 2)
            self.assertIn("does not match", err)
            code, _, err = run_cli("baseline", "migrate", old, repo, *ACCEPT)
            self.assertEqual(code, 2)

    def test_an_old_file_with_values_of_the_wrong_kind_is_an_error_or_is_read_never_a_traceback(self):
        # From the review of this slice: a list for a rule or a severity ended in a traceback (in
        # 0.3.0 too), and so did an old entry carrying `facts` when the report listed it as stale.
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            data = json.loads(old.read_text())
            for change in ({"rule": ["OBAAF-GHA-005"]}, {"severity": ["high"]}, {"job": {"a": 1}}, {"message": 5}):
                broken = json.loads(json.dumps(data))
                broken["findings"][0].update(change)
                old.write_text(json.dumps(broken))
                code, _, err = run_cli("check", repo, "--baseline", old, "--fail-on", "low")
                self.assertEqual(code, 2, change)
                self.assertNotIn("Traceback", err)
            stray = {"rule": "OBAAF-GHA-009", "severity": "medium", "path": "p", "facts": "x"}
            stray["fingerprint"] = baseline._digest(baseline._entry_identity_v1(stray))
            old.write_text(json.dumps({"format": baseline.FORMAT_V1, "findings": [stray]}))
            code, out, err = run_cli("check", repo, "--baseline", old, "--fail-on", "low")
            self.assertEqual(code, 1, err)
            self.assertIn("no longer found: OBAAF-GHA-009 p - the finding it names", out)

    def test_a_name_that_is_not_valid_unicode_does_not_stop_the_reader(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            data = json.loads(old.read_text())
            data["findings"][0]["job"] = "a\udc00b"
            old.write_text(json.dumps(data))
            code, _, err = run_cli("check", repo, "--baseline", old, "--fail-on", "low")
            self.assertEqual(code, 2)       # the fingerprint no longer matches; an error, not a traceback
            self.assertNotIn("Traceback", err)


class MigrateTest(unittest.TestCase):
    """`obaaf baseline migrate`: from the old format to the new, with somebody's name on it."""

    def test_it_carries_over_what_the_old_file_covered_and_the_check_passes_again(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            code, _, err = run_cli("baseline", "migrate", old, repo, *ACCEPT)
            self.assertEqual(code, 0, err)
            self.assertIn(f"16 finding(s) carried over, accepted by {OWNER} until {SOON}.", err)
            data = json.loads(old.read_text())
            self.assertEqual(data["format"], baseline.FORMAT)
            self.assertEqual(len(data["findings"]), 16)
            for item in data["findings"]:
                self.assertEqual((item["owner"], item["reason"], item["expires"]), (OWNER, REASON, SOON))
                self.assertNotIn("fingerprint", item)
                self.assertNotIn("message", item)
            code, out, _ = run_cli("check", repo, "--baseline", old, "--fail-on", "low", "--no-fixes")
            self.assertEqual(code, 0, out)
            self.assertIn("Baseline: 16 finding(s) accepted by the baseline, 0 new.", out)
            self.assertNotIn("Not accepted", out)

    def test_it_needs_an_owner_a_reason_and_a_date_that_count(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            before = old.read_text()
            for args in (("--owner", "nobody", "--reason", REASON, "--expires", SOON),
                         ("--owner", OWNER, "--reason", " ", "--expires", SOON),
                         ("--owner", OWNER, "--reason", REASON, "--expires", "2999-01-01"),
                         ("--owner", OWNER, "--reason", REASON, "--expires", "2001-01-01"),
                         ("--owner", OWNER, "--reason", REASON)):
                code, _, err = run_cli("baseline", "migrate", old, repo, *args)
                self.assertEqual(code, 2, args)
                self.assertEqual(old.read_text(), before)

    def test_it_accepts_nothing_the_old_file_did_not_cover(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            workflow = repo / ".github" / "workflows" / "ci.yml"
            workflow.write_text(workflow.read_text().replace("secrets.CODECOV_TOKEN", "secrets.OTHER_TOKEN"))
            new = tmp / "new.json"
            code, _, err = run_cli("baseline", "migrate", old, repo, *ACCEPT, "--output", new)
            self.assertEqual(code, 0, err)
            self.assertIn("15 finding(s) carried over", err)
            self.assertIn("1 old entry matches no finding any more and was dropped:", err)
            self.assertIn("Job 'test' receives CODECOV_TOKEN", err)
            self.assertIn("1 finding(s) were not in the old baseline and are not accepted by the new one", err)
            self.assertEqual(json.loads(old.read_text())["format"], baseline.FORMAT_V1)     # --output leaves it
            code, out, _ = run_cli("check", repo, "--baseline", new, "--fail-on", "low", "--no-fixes")
            self.assertEqual(code, 1)
            self.assertIn("Baseline: 15 finding(s) accepted by the baseline, 1 new.", out)

    def test_it_writes_nothing_when_no_entry_matches(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            before = old.read_text()
            (tmp / "empty" / ".github" / "workflows").mkdir(parents=True)
            (tmp / "empty" / ".github" / "workflows" / "ci.yml").write_text(
                "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n")
            (tmp / "empty" / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n")
            code, _, err = run_cli("baseline", "migrate", old, tmp / "empty", *ACCEPT)
            self.assertEqual(code, 1)
            self.assertIn("none of the 16 entries", err)
            self.assertEqual(old.read_text(), before)

    def test_a_file_already_converted_is_left_alone(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            run_cli("baseline", "migrate", old, repo, *ACCEPT)
            before = old.read_text()
            code, _, err = run_cli("baseline", "migrate", old, repo, "--owner", "@someone-else", "--reason", "x",
                                   "--expires", SOON)
            self.assertEqual(code, 0)
            self.assertIn("nothing to do", err)
            self.assertEqual(old.read_text(), before)

    def test_it_refuses_a_path_with_nothing_to_check(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            before = old.read_text()
            (tmp / "nothing").mkdir()
            code, _, err = run_cli("baseline", "migrate", old, tmp / "nothing", *ACCEPT)
            self.assertEqual(code, 2)
            self.assertIn("nothing was checked", err)
            self.assertEqual(old.read_text(), before)

    def test_it_does_not_convert_while_a_file_cannot_be_read(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            before = old.read_text()
            (repo / ".github" / "workflows" / "broken.yml").write_text("jobs: [unclosed\n")
            code, _, err = run_cli("baseline", "migrate", old, repo, *ACCEPT)
            self.assertEqual(code, 1)
            self.assertEqual(old.read_text(), before)


class WriteBaselineTest(unittest.TestCase):
    """`--write-baseline` accepts findings in somebody's name, and never renews an acceptance by itself."""

    def test_new_acceptances_need_an_owner_a_reason_and_a_date(self):
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            out = tmp / "new.json"
            for args in ((), ("--owner", OWNER), ("--owner", OWNER, "--reason", REASON),
                         ("--owner", OWNER, "--reason", REASON, "--expires", "2999-01-01"),
                         ("--owner", "nobody", "--reason", REASON, "--expires", SOON)):
                code, _, err = run_cli("check", repo, "--write-baseline", out, *args)
                self.assertEqual(code, 2, args)
                self.assertIn("would accept 16 finding(s)", err)
                self.assertIn("Nothing was written.", err)
                self.assertFalse(out.exists())

    def test_the_options_do_nothing_without_write_baseline(self):
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            code, _, err = run_cli("check", repo, "--owner", OWNER)
            self.assertEqual(code, 2)
            self.assertIn("--write-baseline", err)

    def test_valid_entries_keep_their_owner_reason_and_date_and_only_new_findings_get_the_new_ones(self):
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            out = tmp / "new.json"
            self.assertEqual(run_cli("check", repo, "--write-baseline", out, *ACCEPT)[0], 0)
            workflow = repo / ".github" / "workflows" / "ci.yml"
            workflow.write_text(workflow.read_text().replace("secrets.CODECOV_TOKEN", "secrets.OTHER_TOKEN"))
            later = (TODAY + timedelta(days=200)).isoformat()
            code, _, err = run_cli("check", repo, "--write-baseline", out, "--owner", "@octocat", "--reason",
                                   "The new token is read-only", "--expires", later)
            self.assertEqual(code, 0, err)
            self.assertIn(f"1 finding(s) newly accepted by @octocat until {later}, 15 kept", err)
            entries = json.loads(out.read_text())["findings"]
            self.assertEqual(len(entries), 16)
            new = [e for e in entries if e["owner"] == "@octocat"]
            self.assertEqual([(e["rule"], e["facts"], e["expires"]) for e in new],
                             [("OBAAF-GHA-001", {"secrets": ["OTHER_TOKEN"]}, later)])
            self.assertTrue(all((e["owner"], e["reason"], e["expires"]) == (OWNER, REASON, SOON)
                                for e in entries if e not in new))

    def test_an_expired_entry_is_renewed_only_in_somebodys_name(self):
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            out = tmp / "new.json"
            run_cli("check", repo, "--write-baseline", out, *ACCEPT)
            data = json.loads(out.read_text())
            data["findings"][0]["expires"] = "2001-02-03"
            out.write_text(json.dumps(data))
            code, _, err = run_cli("check", repo, "--write-baseline", out)
            self.assertEqual(code, 2)
            self.assertIn("would accept 1 finding(s)", err)
            self.assertEqual(json.loads(out.read_text()), data)
            code, _, err = run_cli("check", repo, "--write-baseline", out, "--owner", "@octocat", "--reason",
                                   "Looked at again", "--expires", SOON)
            self.assertEqual(code, 0, err)
            renewed = [e for e in json.loads(out.read_text())["findings"] if e["owner"] == "@octocat"]
            self.assertEqual(len(renewed), 1)

    def test_a_valid_entry_is_kept_when_an_ignore_entry_that_does_not_count_names_its_finding(self):
        # From the review of this slice: rewriting the baseline dropped the valid entry.
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            out = tmp / "new.json"
            self.assertEqual(run_cli("check", repo, "--write-baseline", out, *ACCEPT)[0], 0)
            (repo / ".github" / "obaaf.yml").write_text(
                "ignore:\n  - rule: OBAAF-GHA-001\n    path: .github/workflows/ci.yml\n"
                f"    reason: {REASON}\n    until: {SOON}\n")
            before = json.loads(out.read_text())
            code, _, err = run_cli("check", repo, "--write-baseline", out)
            self.assertEqual(code, 0, err)
            self.assertIn("0 finding(s) newly accepted, 16 kept", err)
            self.assertEqual(json.loads(out.read_text())["findings"], before["findings"])
            self.assertEqual(run_cli("check", repo, "--baseline", out, "--fail-on", "low")[0], 0)

    def test_it_writes_only_where_a_baseline_can_go(self):
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            code, _, err = run_cli("check", repo, "--write-baseline", tmp / "no-such-directory" / "b.json", *ACCEPT)
            self.assertEqual(code, 2)
            self.assertIn("cannot write the baseline", err)
            notes = tmp / "notes.txt"
            notes.write_text("not a baseline\n")
            code, _, err = run_cli("check", repo, "--write-baseline", notes, *ACCEPT)
            self.assertEqual(code, 2)
            self.assertIn("does not write over a file that is not one", err)
            self.assertEqual(notes.read_text(), "not a baseline\n")

    def test_it_does_not_write_over_an_old_format_baseline(self):
        with TempDir() as tmp:
            repo, old = fixture_repo(tmp)
            before = old.read_text()
            code, _, err = run_cli("check", repo, "--write-baseline", old, *ACCEPT)
            self.assertEqual(code, 2)
            self.assertIn("obaaf baseline migrate", err)
            self.assertEqual(old.read_text(), before)

    def test_a_job_name_that_is_not_valid_unicode_is_written_and_read_back(self):
        # Found in slice 2d.2a: --write-baseline ended in a traceback for a job id with a lone surrogate.
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "ci.yml").write_text(
                'on: [pull_request]\npermissions:\n  contents: read\njobs:\n  "a\\uDC00b":\n'
                '    runs-on: ubuntu-24.04\n    steps:\n      - run: echo "${{ secrets.TOKEN_A }}" | wc -c\n')
            (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n")
            out = tmp / "b.json"
            code, _, err = run_cli("check", tmp, "--write-baseline", out, *ACCEPT)
            self.assertEqual(code, 0, err)
            text = out.read_bytes().decode("utf-8")                 # valid UTF-8
            self.assertIn('"job": "a\\udc00b"', text)
            self.assertEqual(json.loads(text)["findings"][0]["job"], "a\udc00b")
            code, shown, err = run_cli("check", tmp, "--baseline", out, "--fail-on", "low")
            self.assertEqual(code, 0, shown + err)
            self.assertIn("1 finding(s) accepted by the baseline, 0 new", shown)


class IdentityTest(unittest.TestCase):
    """A finding's facts hold everything its message says about it."""

    def test_every_workflow_and_repository_finding_has_facts(self):
        seen = set()
        targets = sorted(RISKY.glob("*.yml")) + [REPO]
        with TempDir() as tmp:
            for number, target in enumerate(targets):
                found = checker.check(target).findings
                for f in found:
                    if not f.rule.startswith("OBAAF-JEN-"):
                        self.assertIsNotNone(f.facts, f"{f.rule} in {target.name}")
                        seen.add(f.rule)
        self.assertGreaterEqual(len(seen), 22, sorted(seen))

    def test_which_agent_holds_write_access_is_part_of_the_finding(self):
        # An acceptance of one agent holding write access does not cover another put in its place
        # (found by the review of this slice: with the reason left out, 0.3.0 failed here and this passed).
        keys, messages = [], []
        for extra, step in (("", "      - uses: anthropics/claude-code-action@" + "1" * 40 + "\n"),
                            ("", "      - name: Agent\n        run: claude --dangerously-skip-permissions -p x\n"),
                            ("    env:\n      OBAAF_LANE: agent\n", "      - run: python -m agents.triage\n")):
            with TempDir() as tmp:
                (tmp / ".github" / "workflows").mkdir(parents=True)
                (tmp / ".github" / "workflows" / "a.yml").write_text(
                    "on: push\npermissions:\n  contents: write\njobs:\n  triage:\n    runs-on: ubuntu-24.04\n"
                    + extra + "    steps:\n" + step)
                f = next(f for f in checker.check(tmp).findings if f.rule == "OBAAF-GHA-003")
                keys.append(baseline.key(f))
                messages.append(f.message)
        self.assertEqual(len(set(messages)), 3)
        self.assertEqual(len(set(keys)), 3)

    def test_a_field_expanded_through_env_is_the_reference_and_the_field_not_a_clause(self):
        # From the review of this slice: the fact was a piece of the sentence, comma included.
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "a.yml").write_text(
                "on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n"
                "      - name: say\n        run: echo \"${{ env.TITLE }}\"\n        env:\n"
                "          TITLE: ${{ github.event.issue.title }}\n")
            f = next(f for f in checker.check(tmp).findings if f.rule == "OBAAF-GHA-010")
            self.assertEqual(f.message, "Step 'say' expands env.title, which holds github.event.issue.title, inside "
                                        "its script.")
            self.assertEqual((f.kind, f.facts), ("through-env", {"reference": "env.title",
                                                                "field": "github.event.issue.title"}))

    def test_a_hidden_character_that_moves_is_the_same_finding_and_another_one_is_not(self):
        def key_for(text):
            with TempDir() as tmp:
                (tmp / ".github" / "workflows").mkdir(parents=True)
                (tmp / ".github" / "workflows" / "a.yml").write_text(
                    "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n")
                (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n")
                (tmp / "AGENTS.md").write_text(text, encoding="utf-8")
                found = [f for f in checker.check(tmp).findings if f.rule == "OBAAF-INS-001"]
                self.assertEqual(len(found), 1)
                return baseline.key(found[0])
        one = key_for("Read this.\u200b\n")
        # The line moved down, and other lines changed: the same finding.
        self.assertEqual(one, key_for("# Title\n\nMore words.\nRead this.\u200b\n"))
        # The character is on other text, at another place in its line, twice, or another character:
        # another finding. (Found by the review of this slice, with a direction override that moved
        # from a quoted sample into an instruction.)
        self.assertNotEqual(one, key_for("Read all of this.\u200b\n"))
        self.assertNotEqual(one, key_for("Read\u200b this.\n"))
        self.assertNotEqual(one, key_for("Read this.\u200b\u200b\n"))
        self.assertNotEqual(one, key_for("Read this.\u202e\n"))
        self.assertNotEqual(key_for('A sample: "\u202eabc"\nNever push to main.\n'),
                            key_for('A sample: "abc"\nNever \u202epush to main.\n'))

    def test_generated_workflows_never_give_one_identity_two_messages(self):
        """Over a few hundred generated workflows with the same file and job names: two findings that
        are the same to an acceptance, at one severity, always carry the same message. If a rule
        printed something that its facts left out, an acceptance of one finding would cover the
        other, and this is where it would show."""
        knobs = {
            "on": ["pull_request", "pull_request_target", "issue_comment", "push", "workflow_run",
                   "[pull_request, issue_comment]", "[push, pull_request_target]"],
            "permissions": [None, "contents: read", "contents: write", "id-token: write",
                            "contents: write\n      issues: write"],
            "secrets": [(), ("TOKEN_A",), ("TOKEN_B",), ("TOKEN_A", "TOKEN_B"), ("SIGNING_KEY",), ("*",)],
            "environment": [None, "production", "staging", "${{ inputs.env }}"],
            "lane": [None, "agent", "release", "effect"],
            "runs_on": ["ubuntu-24.04", "self-hosted", "[self-hosted, linux]", "big-box",
                        "${{ matrix.os == 'x' && 'ubuntu-24.04' || 'self-hosted' }}"],
            "cache_mode": [None, "none", "write", "read"],
            "egress": [None, "api.example.com", "other.example.com"],
            "steps": [
                "      - run: make test\n",
                "      - uses: actions/checkout@v7\n",
                "      - uses: actions/checkout@v7\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
                "      - uses: actions/checkout@" + "1" * 40 + "\n        with:\n          persist-credentials: false\n"
                "          allow-unsafe-pr-checkout: true\n",
                "      - uses: openai/codex-action@v1\n",
                "      - uses: actions/cache@v5\n        with:\n          path: x\n          key: y\n"
                "      - run: gh release upload v1 dist/*\n",
                "      - run: gh release upload v1 dist/*\n",
                "      - run: echo \"${{ github.event.issue.title }}\"\n",
                "      - run: echo \"${{ github.event.comment.body }}\"\n",
                "      - run: echo \"${{ env.T }}\"\n        env:\n          T: ${{ github.event.issue.title }}\n",
                "      - run: echo \"${{ env.T }}\"\n        env:\n          T: ${{ github.event.issue.body }}\n",
                "      - run: echo \"${{ env.U }}\"\n        env:\n          U: ${{ github.event.issue.title }}\n",
                "      - uses: docker://alpine:3\n      - run: gh pr checkout 5\n",
                "      - uses: step-security/harden-runner@v2\n        if: github.actor != 'x'\n        with:\n"
                "          egress-policy: block\n      - run: claude -p hello\n",
            ],
            "container": [None, "node:22", "node:24"],
        }
        generator = random.Random(20261112)
        names = list(knobs)
        combos = {tuple(generator.randrange(len(knobs[n])) for n in names) for _ in range(700)}
        messages: dict[str, set] = {}
        rules_seen = set()
        with TempDir() as tmp:
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n")
            path = tmp / ".github" / "workflows" / "w.yml"
            (tmp / ".github" / "obaaf.yml").write_text("protected_secrets:\n  TOKEN_A: production\n  SIGNING_KEY:\n")
            for combo in sorted(combos):
                c = {n: knobs[n][i] for n, i in zip(names, combo)}
                text = f"on: {c['on']}\n"
                if c["cache_mode"]:
                    text += f"cache-mode: {c['cache_mode']}\n"
                text += "jobs:\n  job:\n    runs-on: " + c["runs_on"] + "\n"
                if c["permissions"]:
                    text += "    permissions:\n      " + c["permissions"] + "\n"
                if c["environment"]:
                    text += f"    environment: {c['environment']}\n"
                if c["container"]:
                    text += f"    container: {c['container']}\n"
                env = [f"      S{i}: ${{{{ secrets.{s} }}}}" if s != "*" else "      ALL: ${{ toJSON(secrets) }}"
                       for i, s in enumerate(c["secrets"])]
                if c["lane"]:
                    env.append(f"      OBAAF_LANE: {c['lane']}")
                if c["egress"]:
                    env.append(f"      OBAAF_EGRESS: {c['egress']}")
                if env:
                    text += "    env:\n" + "\n".join(env) + "\n"
                text += "    steps:\n" + c["steps"]
                path.write_text(text)
                result = checker.check(tmp)
                self.assertEqual(result.errors, [], text)
                for f in result.findings:
                    self.assertIsNotNone(f.facts)
                    rules_seen.add((f.rule, f.kind))
                    messages.setdefault(baseline.key(f) + "|" + f.severity, set()).add(f.message)
        clashes = {k: v for k, v in messages.items() if len(v) > 1}
        self.assertEqual(clashes, {})
        # The generator has to reach most of what the rules can say, or the test above shows little.
        self.assertGreaterEqual(len(rules_seen), 40, sorted(rules_seen))
        self.assertGreaterEqual(len({rule for rule, _ in rules_seen}), 21, sorted(rules_seen))

    def test_no_two_cases_of_a_rule_share_a_kind(self):
        # `compose` records every (rule, kind) it is used with and the template that came with it.
        # After the fixtures have run (and whatever other tests ran in this process), no pair has
        # been seen with two templates: each case of a rule has a kind of its own.
        for target in itertools.chain(sorted(RISKY.glob("*.yml")), [REPO, TEMPLATES]):
            checker.check(target)
        self.assertEqual(rules.CONFLICTS, [])
        self.assertGreaterEqual(len(rules.TEMPLATES), 30)

    def test_json_output_keeps_what_it_had_and_adds_the_state(self):
        with TempDir() as tmp:
            repo, _ = fixture_repo(tmp)
            _, out, _ = run_cli("check", repo, "--format", "json", "--fail-on", "never")
            data = json.loads(out)
            self.assertEqual(data["format"], "obaaf-check/v0.1")
            for name in ("tool", "files", "errors", "findings", "notes"):
                self.assertIn(name, data)
            for f in data["findings"]:
                for name in ("rule", "title", "severity", "category", "remediation", "path", "line", "job", "step",
                             "message", "requirements", "agentControls", "fix", "suppressed"):
                    self.assertIn(name, f)
                self.assertEqual(f["state"], "new")
                self.assertNotIn("acceptance", f)
            one = next(f for f in data["findings"] if f["rule"] == "OBAAF-GHA-005" and f["job"] == "triage")
            self.assertEqual((one["kind"], one["facts"]), ("secrets", {"secrets": ["ANTHROPIC_API_KEY", "TRIAGE_TOKEN"]}))
            self.assertNotIn("fixed", data)


if __name__ == "__main__":
    unittest.main()
