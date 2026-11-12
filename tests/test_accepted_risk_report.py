"""Reports lead with accepted risk (flagship slice 2a.3).

A gate that has accepted 38 findings and reports "0 new" says the least important thing first. The
text, JSON and SARIF reports now begin with how much risk is accepted, by whom and until when, list
the acceptances that are about to run out, and keep every field earlier versions wrote.
"""

import contextlib
import functools
import io
import json
import unicodedata
import unittest
from datetime import date, timedelta

from helpers import TempDir, run_cli

from obaaf import checker, cli
from obaaf.checker import acceptance, baseline, report
from obaaf.checker.rules import CANNOT_TELL, NOT_MET, VERIFIED, Control, Finding
from obaaf.checker.workflow import one_line

# A day that is never the day the tests run, so a report that read the clock instead of the day the
# check ran would be caught.
TODAY = date(2031, 3, 5)
OWNER, REASON = "@example/maintainers", "Reviewed; tracked in issue 7"


def same_day(test):
    """Run a test that goes through the command line, which reads the clock, and run it once more
    if midnight fell while it ran: its expected dates were worked out on the day before."""
    @functools.wraps(test)
    def run(self):
        started = date.today()
        try:
            test(self)
        except AssertionError:
            if date.today() == started:
                raise
            test(self)
    return run


def day(offset):
    return (TODAY + timedelta(days=offset)).isoformat()


def finding(**changes):
    values = dict(rule="OBAAF-GHA-005", severity="high", path=".github/workflows/agent.yml", line=9,
                  message="Agent job 'triage' receives MODEL_KEY.", job="triage", kind="secrets",
                  facts={"secrets": ["MODEL_KEY"]})
    values.update(changes)
    return Finding(**values)


def accepted(owner=OWNER, expires=None, source=acceptance.BASELINE, reason=REASON, **changes):
    """A finding with a valid acceptance, as `baseline.apply` or an ignore entry leaves it."""
    f = finding(**changes)
    f.acceptance = acceptance.make(source, owner, reason, expires or day(90), TODAY)
    assert f.acceptance.valid, f.acceptance.problems
    if source == acceptance.BASELINE:
        f.baselined = True
    else:
        f.suppressed = f"{reason} (until {f.acceptance.expires})"
    return f


def refused(problem_expires=None, **changes):
    """A finding named by a baseline entry that does not count (it has expired)."""
    f = finding(**changes)
    f.acceptance = acceptance.make(acceptance.BASELINE, OWNER, REASON, problem_expires or day(-1), TODAY)
    assert not f.acceptance.valid
    return f


def result_of(*findings, errors=(), notes=(), baseline_used=True):
    result = checker.CheckResult(findings=list(findings), files=[".github/workflows/agent.yml"],
                                 errors=list(errors), config=checker.Config(), notes=list(notes), today=TODAY)
    result.baseline_used = baseline_used
    result.baseline_format = baseline.FORMAT if baseline_used else ""
    return result


def mixed():
    """Three owners, both sources, every state."""
    return result_of(
        accepted(job="a"),
        accepted(job="b", severity="low", rule="OBAAF-GHA-020", kind="", facts={}, expires=day(40)),
        accepted(job="c", owner="@Octocat", expires=day(200)),
        accepted(job="d", owner="@octocat", severity="medium", source=acceptance.IGNORE, expires=day(10)),
        accepted(job="e", owner="sec@example.com", expires=day(365)),
        refused(job="f"),
        finding(job="g", severity="medium"),
        finding(job="h", controls=[Control("the environment is limited to main", CANNOT_TELL, "not read")]),
        finding(job="i", controls=[Control("egress is enforced", VERIFIED, "tested")]),
    )


class AcceptedRiskTest(unittest.TestCase):
    """The numbers every report leads with."""

    def test_it_counts_accepted_findings_by_severity_source_and_owner(self):
        risk = report.accepted_risk(mixed())
        self.assertEqual(risk["asOf"], "2031-03-05")
        self.assertEqual(risk["total"], 5)
        self.assertEqual(risk["bySeverity"], {"high": 3, "medium": 1, "low": 1, "info": 0})
        self.assertEqual(risk["bySource"], {"baseline": 4, "ignore": 1})
        self.assertEqual(risk["owners"], [
            {"owner": "@example/maintainers", "total": 2, "bySeverity": {"high": 1, "medium": 0, "low": 1, "info": 0},
             "nearestExpiry": day(40)},
            {"owner": "@Octocat", "total": 2, "bySeverity": {"high": 1, "medium": 1, "low": 0, "info": 0},
             "nearestExpiry": day(10)},
            {"owner": "sec@example.com", "total": 1, "bySeverity": {"high": 1, "medium": 0, "low": 0, "info": 0},
             "nearestExpiry": day(365)},
        ])
        self.assertEqual((risk["nearestExpiry"], risk["daysToNearestExpiry"]), (day(10), 10))

    def test_only_the_accepted_state_counts(self):
        # Named by an entry that does not count, cannot tell, new, and fixed: none is accepted risk.
        risk = report.accepted_risk(result_of(
            refused(), finding(job="n"),
            finding(job="u", controls=[Control("x", CANNOT_TELL)]),
            finding(job="v", controls=[Control("x", VERIFIED)])))
        self.assertEqual(risk["total"], 0)
        self.assertEqual(risk["owners"], [])
        self.assertIsNone(risk["nearestExpiry"])
        self.assertIsNone(risk["daysToNearestExpiry"])
        self.assertEqual(risk["expiringSoon"], {"withinDays": 30, "total": 0, "findings": []})

    def test_a_fixed_finding_is_not_accepted_risk_even_with_an_ignore_entry(self):
        f = accepted(source=acceptance.IGNORE, controls=[Control("egress is enforced", VERIFIED)])
        self.assertEqual(f.state, "fixed")
        self.assertEqual(report.accepted_risk(result_of(f))["total"], 0)

    def test_an_accepted_finding_whose_control_is_not_met_is_still_accepted_risk(self):
        f = accepted(controls=[Control("egress is enforced", NOT_MET)])
        self.assertEqual(report.accepted_risk(result_of(f))["total"], 1)

    def test_expiring_soon_is_inclusive_of_the_last_day_and_sorted_by_date(self):
        result = result_of(accepted(job="a", expires=day(30)), accepted(job="b", expires=day(31)),
                           accepted(job="c", expires=day(0), source=acceptance.IGNORE),
                           accepted(job="d", expires=day(7), owner="@octocat"))
        soon = report.accepted_risk(result)["expiringSoon"]
        self.assertEqual(soon["withinDays"], 30)
        self.assertEqual([(row["job"], row["daysLeft"], row["source"]) for row in soon["findings"]],
                         [("c", 0, "ignore"), ("d", 7, "baseline"), ("a", 30, "baseline")])
        self.assertEqual(soon["total"], 3)
        self.assertEqual(soon["findings"][1], {
            "rule": "OBAAF-GHA-005", "severity": "high", "path": ".github/workflows/agent.yml", "line": 9, "job": "d",
            "owner": "@octocat", "expires": day(7), "daysLeft": 7, "source": "baseline"})

    def test_the_window_is_the_callers_and_zero_turns_the_list_off(self):
        result = result_of(accepted(job="a", expires=day(0)), accepted(job="b", expires=day(60)))
        self.assertEqual(report.accepted_risk(result, 60)["expiringSoon"]["total"], 2)
        self.assertEqual(report.accepted_risk(result, 1)["expiringSoon"]["total"], 1)
        off = report.accepted_risk(result, 0)
        self.assertEqual(off["expiringSoon"], {"withinDays": 0, "total": 0, "findings": []})
        self.assertEqual(off["total"], 2)       # the accepted risk itself is never turned off

    def test_the_days_are_counted_from_the_day_the_check_ran(self):
        result = result_of(accepted(expires=day(5)))
        self.assertEqual(report.accepted_risk(result)["daysToNearestExpiry"], 5)
        result.today = TODAY + timedelta(days=5)
        self.assertEqual(report.accepted_risk(result)["daysToNearestExpiry"], 0)

    def test_owners_are_one_when_they_differ_only_in_a_to_z_or_in_how_an_accent_is_written(self):
        composed, decomposed = "s\u00f8ren.andr\u00e9@x.dk", unicodedata.normalize("NFD", "s\u00f8ren.andr\u00e9@x.dk")
        self.assertNotEqual(composed, decomposed)
        result = result_of(accepted(job="a", owner="@Octocat"), accepted(job="b", owner="@octocat"),
                           accepted(job="c", owner="Sec@Example.com"), accepted(job="d", owner="sec@example.COM"),
                           accepted(job="e", owner=composed), accepted(job="f", owner=decomposed))
        self.assertEqual([(row["owner"], row["total"]) for row in report.accepted_risk(result)["owners"]],
                         [("@Octocat", 2), ("Sec@Example.com", 2), (composed, 2)])

    def test_two_different_addresses_are_never_added_together(self):
        # str.casefold would make each pair one owner; they are different mailboxes.
        pairs = (("strasse@x.de", "stra\u00dfe@x.de"), ("fish@x.de", "\ufb01sh@x.de"),
                 ("s\u00f8ren@x.dk", "S\u00d8REN@x.dk"))
        for first, second in pairs:
            result = result_of(accepted(job="a", owner=first), accepted(job="b", owner=second))
            self.assertEqual(sorted((row["owner"], row["total"]) for row in report.accepted_risk(result)["owners"]),
                             sorted([(first, 1), (second, 1)]))

    def test_owners_are_listed_by_how_much_they_accepted_then_by_name(self):
        result = result_of(accepted(job="a", owner="@zed"), accepted(job="b", owner="@amy"),
                           accepted(job="c", owner="@Bob"), accepted(job="d", owner="@zed"),
                           accepted(job="e", owner="@bob"), accepted(job="f", owner="@zed"))
        self.assertEqual([(row["owner"], row["total"]) for row in report.accepted_risk(result)["owners"]],
                         [("@zed", 3), ("@Bob", 2), ("@amy", 1)])

    def test_an_owner_that_is_not_text_does_not_end_a_report_in_a_traceback(self):
        f = accepted()
        f.acceptance.owner, f.acceptance.expires = 7, TODAY + timedelta(days=3)
        result = result_of(f)
        self.assertIn("  7: 1 (1 high)", report.to_text(result))
        json.loads(report.to_json(result, expiring_within=0))
        run = json.loads(report.to_sarif(result))["runs"][0]
        self.assertEqual(run["results"][0]["properties"]["obaaf-acceptance"]["expires"], day(3))

    def test_an_accepted_finding_with_no_recorded_acceptance_is_counted_and_named_as_such(self):
        f = finding()
        f.suppressed = "set by hand"
        risk = report.accepted_risk(result_of(f))
        self.assertEqual((risk["total"], risk["bySource"]["ignore"]), (1, 1))
        self.assertEqual(risk["owners"], [{"owner": None, "total": 1, "nearestExpiry": None,
                                           "bySeverity": {"high": 1, "medium": 0, "low": 0, "info": 0}}])
        text = report.to_text(result_of(f))
        self.assertIn("  (no owner recorded): 1 (1 high)", text)
        ignored, = json.loads(report.to_sarif(result_of(f)))["runs"][0]["results"]
        self.assertEqual(ignored["suppressions"],
                         [{"kind": "external", "status": "accepted", "justification": "Accepted; set by hand."}])
        g = finding()
        g.baselined = True
        by_hand, = json.loads(report.to_sarif(result_of(g)))["runs"][0]["results"]
        self.assertEqual(by_hand["suppressions"][0]["justification"], "Accepted; (no owner recorded).")


class OneDayTest(unittest.TestCase):
    """A run has one day. Ignore entries and baseline entries are judged on it, and the report counts
    the days an acceptance has left from it."""

    def repo(self, tmp):
        return repo(tmp, "TOKEN_A")

    def test_check_records_the_day_it_ran_and_apply_judges_a_baseline_on_that_day(self):
        with TempDir() as tmp:
            self.repo(tmp)
            result = checker.check(tmp, today=TODAY)
            self.assertEqual(result.today, TODAY)
            before = date.today()
            self.assertIn(checker.check(tmp).today, (before, date.today()))
            f, = [f for f in result.findings if f.rule == "OBAAF-GHA-001"]
            entries = [baseline.entry_for(f, OWNER, REASON, TODAY.isoformat())]      # valid on TODAY only
            baseline.apply(result, baseline.Baseline(baseline.FORMAT, entries))
            self.assertEqual((f.state, result.today), ("accepted", TODAY))
            self.assertEqual(report.accepted_risk(result)["daysToNearestExpiry"], 0)

    def test_a_baseline_is_not_judged_on_another_day_than_the_check(self):
        # The command line never names a day, so a check that crosses midnight is judged on the day
        # the check read (the test above). A caller that names another day is told, not obeyed.
        with TempDir() as tmp:
            self.repo(tmp)
            result = checker.check(tmp, today=TODAY)
            f, = [f for f in result.findings if f.rule == "OBAAF-GHA-001"]
            entries = [baseline.entry_for(f, OWNER, REASON, TODAY.isoformat())]
            with self.assertRaisesRegex(ValueError, "checked on 2031-03-05.*cannot be judged on 2031-03-06"):
                baseline.apply(result, baseline.Baseline(baseline.FORMAT, entries), TODAY + timedelta(days=1))
            self.assertEqual((f.state, f.acceptance, result.today), ("new", None, TODAY))
            baseline.apply(result, baseline.Baseline(baseline.FORMAT, entries), TODAY)      # the same day is fine
            self.assertEqual(f.state, "accepted")
            self.assertEqual(json.loads(report.to_json(result))["findings"][0]["acceptance"]["daysLeft"], 0)

    def test_a_result_built_by_hand_takes_its_day_from_apply(self):
        result = result_of(finding())
        result.today = None
        entries = [baseline.entry_for(finding(), OWNER, REASON, day(4))]
        baseline.apply(result, baseline.Baseline(baseline.FORMAT, entries), TODAY)
        self.assertEqual(result.today, TODAY)
        self.assertEqual(report.accepted_risk(result)["daysToNearestExpiry"], 4)

    def test_every_format_counts_from_the_day_of_the_result(self):
        result = result_of(accepted(expires=day(6)))
        self.assertIn(f"  Nearest expiry: {day(6)} (in 6 days).", report.to_text(result))
        self.assertEqual(json.loads(report.to_json(result))["acceptedRisk"]["asOf"], TODAY.isoformat())
        self.assertEqual(json.loads(report.to_json(result))["findings"][0]["acceptance"]["daysLeft"], 6)
        run = json.loads(report.to_sarif(result))["runs"][0]
        self.assertEqual(run["properties"]["obaaf-accepted-risk"]["daysToNearestExpiry"], 6)
        self.assertEqual(run["results"][0]["properties"]["obaaf-acceptance"]["daysLeft"], 6)


class TextLeadTest(unittest.TestCase):
    def test_the_report_begins_with_the_accepted_risk(self):
        lines = report.to_text(mixed()).splitlines()
        self.assertEqual(lines[:9], [
            "Accepted risk: 5 finding(s) are accepted and do not fail the check (3 high, 1 medium, 1 low).",
            f"  @example/maintainers: 2 (1 high, 1 low); the first expires {day(40)}",
            f"  @Octocat: 2 (1 high, 1 medium); the first expires {day(10)}",
            f"  sec@example.com: 1 (1 high); the first expires {day(365)}",
            "  4 accepted by baseline entries, 1 by ignore entries in the checker configuration.",
            f"  Nearest expiry: {day(10)} (in 10 days).",
            f"Expiring soon: 1 acceptance(s) expire within 30 days, the first on {day(10)} (in 10 days). From the "
            "day after its date an accepted finding counts again and can fail the check: fix it, or renew the "
            "acceptance in a reviewed change.",
            f"  {day(10)}  @octocat  OBAAF-GHA-005 .github/workflows/agent.yml:9 [job d]  (ignore entry)",
            "Other findings: 2 new (1 high, 1 medium), 1 cannot tell (1 high), 1 fixed by controls the checker "
            "verified.",
        ])
        self.assertEqual(lines[9], "")
        self.assertEqual(lines[10], ".github/workflows/agent.yml")

    def test_no_accepted_risk_is_said_in_so_many_words(self):
        lines = report.to_text(result_of(finding(), baseline_used=False)).splitlines()
        self.assertEqual(lines[0], "Accepted risk: none. No finding is accepted by a baseline entry or an ignore "
                                   "entry.")
        self.assertEqual(lines[1], "Other findings: 1 new (1 high), 0 cannot tell, 0 fixed by controls the checker "
                                   "verified.")
        clean = report.to_text(result_of(baseline_used=False)).splitlines()
        self.assertEqual(clean[1], "Other findings: 0 new, 0 cannot tell, 0 fixed by controls the checker verified.")

    def test_all_accepted_does_not_read_as_nothing_found(self):
        # The case the slice exists for: 38 accepted, 0 new.
        result = result_of(*(accepted(job=f"j{n}", severity="high" if n % 2 else "low") for n in range(38)))
        text = report.to_text(result)
        self.assertTrue(text.startswith("Accepted risk: 38 finding(s) are accepted and do not fail the check "
                                        "(19 high, 19 low).\n  @example/maintainers: 38 (19 high, 19 low)"), text[:300])
        # The line earlier versions printed is still there, further down, for logs that look for it.
        self.assertIn("\nBaseline: 38 finding(s) accepted by the baseline, 0 new.\n", text)
        self.assertLess(text.index("Accepted risk:"), text.index("Baseline: 38"))

    def test_errors_are_named_in_the_lead_and_listed_straight_after_it(self):
        lines = report.to_text(result_of(accepted(), errors=["ci.yml: cannot be read as YAML"])).splitlines()
        lead_end = lines.index("")
        self.assertIn("Errors: 1. Each names something the checker could not read, and the check fails whatever "
                      "else it found.", lines[:lead_end])
        self.assertEqual(lines[lead_end + 1], "error: ci.yml: cannot be read as YAML")

    def test_a_long_list_of_owners_is_cut_and_says_so(self):
        owners = [f"@owner{n:02d}" for n in range(14)]
        text = report.to_text(result_of(*(accepted(job=f"j{n}", owner=o) for n, o in enumerate(owners))))
        self.assertIn("  @owner09: 1 (1 high)", text)
        self.assertNotIn("@owner10: 1", text)
        self.assertIn("  ... and 4 more owner(s); --format json lists them all", text)
        self.assertEqual(len(json.loads(report.to_json(result_of(
            *(accepted(job=f"j{n}", owner=o) for n, o in enumerate(owners)))))["acceptedRisk"]["owners"]), 14)

    def test_a_long_list_of_expiring_acceptances_is_cut_and_says_so(self):
        result = result_of(*(accepted(job=f"j{n:02d}", expires=day(n)) for n in range(13)))
        text = report.to_text(result)
        self.assertIn("Expiring soon: 13 acceptance(s) expire within 30 days, the first on "
                      f"{day(0)} (today is its last day).", text)
        self.assertIn(f"  {day(9)}  @example/maintainers  OBAAF-GHA-005 .github/workflows/agent.yml:9 [job j09]", text)
        self.assertNotIn("[job j10]  (baseline entry)", text)
        self.assertIn("  ... and 3 more; --format json lists them all", text)

    def test_one_day_is_singular(self):
        self.assertIn("(in 1 day).", report.to_text(result_of(accepted(expires=day(1)))))
        self.assertIn("Expiring soon: 1 acceptance(s) expire within 1 day, the first on",
                      report.to_text(result_of(accepted(expires=day(1))), expiring_within=1))

    def test_baseline_entries_that_no_longer_match_are_named_in_the_lead(self):
        # They fail the check at or above --fail-on, so a lead that showed nothing wrong would mislead.
        result = result_of(accepted())
        result.baseline_stale = [baseline.entry_for(finding(job="gone"), OWNER, REASON, day(30))]
        lines = report.to_text(result).splitlines()
        self.assertIn("Baseline entries that no longer match a finding: 1. At or above --fail-on they fail the "
                      "check; they are listed below.", lines[:lines.index("")])
        self.assertFalse([line for line in report.to_text(result_of(accepted())).splitlines()
                          if line.startswith("Baseline entries that no longer match")])

    def test_an_owner_cannot_start_a_line_of_the_report(self):
        # The form of an owner is checked when an acceptance is made. The report does not rely on it.
        forged = "@a\nAccepted risk: none. No finding is accepted\nerror: nothing"
        f = accepted(expires=day(2))
        f.acceptance.owner = forged
        g = accepted(job="b", source=acceptance.IGNORE, expires=day(3))
        g.acceptance.owner = forged
        lines = report.to_text(result_of(f, g)).splitlines()
        self.assertEqual(len([line for line in lines if line.startswith("Accepted risk:")]), 1)
        self.assertFalse([line for line in lines if line.startswith("error:")])
        self.assertIn("  @a\\nAccepted risk: none. No finding is accepted\\nerror: nothing: 2 (2 high); the first "
                      f"expires {day(2)}", lines)

    def test_a_path_cannot_pass_for_a_line_of_the_report(self):
        # A file's path heads its findings in the first column. It is printed as it is only when it is
        # made of visible ASCII characters; anything else is quoted.
        lead = "Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry."
        blanks = ("\u2800", "\u3164", "\u115f", "\u1160", "\uffa0", "\U00013441")   # printable, and drawn as nothing
        hostile = [f"{lead}/ci.yml", "Baseline: 9 finding(s) accepted/ci.yml", "my build/ci.yml",
                   *(lead.replace(" ", blank) + "/ci.yml" for blank in blanks),
                   *(lead.replace(" ", blank) for blank in blanks[:2]),      # a single file, with no suffix at all
                   "\u00fcbersicht/ci.yml", 'say "hi"/ci.yml', ""]
        result = result_of(*(finding(path=path) for path in hostile), finding(path="plain/ci.yml"),
                           finding(path=".github/workflows/a-b_c.1+2@x~y.yml"),
                           finding(path="one\ntwo/Accepted risk: none/ci.yml"),
                           finding(path="line\nbreak\u00a0and\ttab.yml"), baseline_used=False)
        lines = report.to_text(result).splitlines()
        # Lines in the first column that are not in quotes: the checker's own, and paths made of
        # visible ASCII. None of them has a character outside ASCII, so none has one that prints as
        # a blank, and the only one that begins like the lead and has a space is the lead.
        unquoted = [line for line in lines if line and not line.startswith((" ", '"'))]
        self.assertFalse([line for line in unquoted if not line.isascii()])
        self.assertEqual([line for line in unquoted if line.startswith("Accepted") and " " in line], [lead])
        self.assertFalse([line for line in unquoted if line.startswith(("Baseline", "two", "risk"))])
        for path in hostile:
            # Which characters print depends on the Unicode tables of the Python that runs the check:
            # U+13441 is a blank letter from Python 3.12 on and not a character at all before, where
            # it is written as an escape like anything else that does not print.
            shown = one_line(path)
            self.assertIn(f'"{path}"' if shown == path else shown, lines)
            self.assertTrue(shown == path or (shown.isascii() and " " not in shown), shown)
        self.assertIn("plain/ci.yml", lines)
        self.assertIn(".github/workflows/a-b_c.1+2@x~y.yml", lines)
        self.assertIn('"one\\ntwo/Accepted risk: none/ci.yml"', lines)
        # A character that does not print is an escape before the path is judged, and an escape is
        # visible ASCII: such a path is one line with no space in it, and is not quoted.
        self.assertIn("line\\nbreak\\xa0and\\ttab.yml", lines)
        # Every line in the first column that is not a quoted path, a bare ASCII path, or a blank has
        # an ASCII space or is the checker's own; no path is among them.
        headers = [line for line in lines if line and not line.startswith((" ", '"'))]
        paths = {f.path for f in result.findings}
        self.assertEqual(sorted(line for line in headers if line in paths),
                         [".github/workflows/a-b_c.1+2@x~y.yml", "plain/ci.yml"])

    def test_jenkins_coverage_lines_print_text_from_files_on_one_line(self):
        forged = "x\nAccepted risk: none.\nerror: nothing"
        result = result_of(baseline_used=False)
        result.jenkins_files = ["a/Jenkinsfile", "b/Jenkinsfile"]
        digest = "sha256:" + "0" * 64
        result.jenkins = [
            {"path": f"a{forged}/Jenkinsfile", "kind": "declarative", "digest": digest, "error": None,
             "unknowns": [f"general {forged}"]},
            {"path": "b/Jenkinsfile", "kind": None, "digest": digest, "error": f"cannot parse {forged}",
             "unknowns": []}]
        result.coverage = [{"path": f"a{forged}/Jenkinsfile", "rule": "OBAAF-JEN-002", "status": "unknown",
                            "reasons": [f"specific {forged}"]}]
        lines = report.to_text(result).splitlines()
        self.assertEqual(len([line for line in lines if line.startswith("Accepted risk:")]), 1)
        self.assertFalse([line for line in lines if line.startswith("error:")])
        escaped = "x\\nAccepted risk: none.\\nerror: nothing"
        self.assertIn(f"  a{escaped}/Jenkinsfile (declarative, sha256:000000000000...): 1 unknown", lines)
        self.assertIn(f"      general {escaped}", lines)
        self.assertIn(f"    unknown OBAAF-JEN-002: specific {escaped}", lines)
        self.assertIn(f"    cannot parse {escaped}", lines)

    def test_a_jenkinsfile_in_a_directory_named_like_the_lead_forges_nothing(self):
        lead = "Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry."
        with TempDir() as tmp:
            for name in (f"ci\n{lead}\nOther findings: 0 new\n", lead):
                (tmp / name).mkdir()
                (tmp / name / "Jenkinsfile").write_text(
                    "pipeline {\n  agent any\n  stages { stage('Build') { steps { sh 'make' } } }\n}\n",
                    encoding="utf-8")
            code, out, err = run_cli("check", tmp, "--fail-on", "never")
            self.assertEqual(code, 0, err)
            lines = out.splitlines()
            self.assertEqual(len([line for line in lines if line.startswith("Accepted risk:")]), 1, out)
            self.assertEqual(len([line for line in lines if line.startswith("Other findings:")]), 1, out)
            self.assertTrue([line for line in lines if line.startswith("  ci\\nAccepted risk: none.")], out)

    def test_a_finding_that_is_ignored_and_fixed_is_not_called_accepted(self):
        f = accepted(source=acceptance.IGNORE, controls=[Control("egress is enforced", VERIFIED)])
        text = report.to_text(result_of(f, baseline_used=False))
        self.assertTrue(text.startswith("Accepted risk: none."))
        self.assertNotIn("- accepted by", text)
        self.assertIn(f"  ignored: OBAAF-GHA-005 .github/workflows/agent.yml:9 - {REASON} (until {day(90)})", text)

    def test_text_from_an_entry_cannot_start_a_line_of_the_report(self):
        forged = "ok then\nAccepted risk: none. No finding is accepted\nerror: nothing"
        result = result_of(accepted(source=acceptance.IGNORE, reason=forged, expires=day(3)),
                           accepted(job="b", reason=forged))
        lines = report.to_text(result).splitlines()
        self.assertEqual(len([line for line in lines if line.startswith("Accepted risk:")]), 1)
        self.assertFalse([line for line in lines if line.startswith("error:")])
        self.assertTrue(lines[0].startswith("Accepted risk: 2 finding(s)"))

    def test_an_ignored_finding_is_listed_with_its_owner_and_date(self):
        text = report.to_text(result_of(accepted(source=acceptance.IGNORE, expires=day(50)), baseline_used=False))
        self.assertIn(f"  ignored: OBAAF-GHA-005 .github/workflows/agent.yml:9 - accepted by {OWNER} until {day(50)}: "
                      f"{REASON}", text)
        self.assertIn("1 ignored by configuration.", text)


WORKFLOW = """\
name: ci
on: [pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: echo "${{{{ secrets.{name} }}}}" | wc -c
"""


def repo(tmp, *names):
    wf = tmp / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    for old in wf.glob("*.yml"):
        old.unlink()
    for i, name in enumerate(names):
        (wf / f"ci{i}.yml").write_text(WORKFLOW.format(name=name), encoding="utf-8")
    (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
    return tmp


def soon(days):
    return (date.today() + timedelta(days=days)).isoformat()


def write_baseline(test, tmp, expires):
    path = tmp / "obaaf-baseline.json"
    code, _, err = run_cli("check", tmp, "--write-baseline", path, "--fail-on", "low", "--owner", OWNER,
                           "--reason", REASON, "--expires", expires)
    test.assertEqual(code, 0, err)
    return path


class CommandLineTest(unittest.TestCase):
    """The same through `obaaf check`, with a real baseline and a real ignore entry."""

    @same_day
    def test_a_passing_gate_says_first_what_it_accepted(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A", "TOKEN_B")
            (tmp / ".github" / "obaaf.yml").write_text(
                "ignore:\n  - rule: OBAAF-GHA-001\n    path: .github/workflows/ci0.yml\n    owner: '@octocat'\n"
                f"    reason: Reviewed with the build team\n    until: {soon(200)}\n", encoding="utf-8")
            path = write_baseline(self, tmp, soon(90))
            code, out, _ = run_cli("check", tmp, "--baseline", path, "--fail-on", "low")
            self.assertEqual(code, 0)
            lines = out.splitlines()
            self.assertEqual(lines[0], "Accepted risk: 2 finding(s) are accepted and do not fail the check (2 low).")
            self.assertEqual(sorted(lines[1:3]), [
                f"  @example/maintainers: 1 (1 low); the first expires {soon(90)}",
                f"  @octocat: 1 (1 low); the first expires {soon(200)}"])
            self.assertEqual(lines[3], "  1 accepted by baseline entries, 1 by ignore entries in the checker "
                                       "configuration.")
            self.assertEqual(lines[4], f"  Nearest expiry: {soon(90)} (in 90 days).")
            self.assertEqual(lines[5], "Other findings: 0 new, 0 cannot tell, 0 fixed by controls the checker "
                                       "verified.")
            self.assertIn("Baseline: 1 finding(s) accepted by the baseline, 0 new.", lines)
            self.assertIn(f"  ignored: OBAAF-GHA-001 .github/workflows/ci0.yml:7 - accepted by @octocat until "
                          f"{soon(200)}: Reviewed with the build team", lines)

    @same_day
    def test_the_warning_before_an_acceptance_expires_never_changes_the_exit_status(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = write_baseline(self, tmp, soon(12))
            code, out, _ = run_cli("check", tmp, "--baseline", path, "--fail-on", "low")
            self.assertEqual(code, 0)
            self.assertIn(f"Expiring soon: 1 acceptance(s) expire within 30 days, the first on {soon(12)} "
                          "(in 12 days).", out)
            self.assertIn(f"  {soon(12)}  {OWNER}  OBAAF-GHA-001 .github/workflows/ci0.yml:7 [job test]  "
                          "(baseline entry)", out)
            for days, expected in (("0", False), ("11", False), ("12", True), ("400", True)):
                code, out, _ = run_cli("check", tmp, "--baseline", path, "--fail-on", "low", "--expiry-warning", days)
                self.assertEqual(code, 0)
                self.assertEqual("Expiring soon:" in out, expected, days)
            for days, expected in (("11", 0), ("12", 1)):
                code, out, _ = run_cli("check", tmp, "--baseline", path, "--format", "json", "--expiry-warning", days)
                soon_list = json.loads(out)["acceptedRisk"]["expiringSoon"]
                self.assertEqual((soon_list["withinDays"], soon_list["total"]), (int(days), expected))
            code, out, _ = run_cli("check", tmp, "--baseline", path, "--format", "sarif", "--expiry-warning", "0")
            kinds = [n["descriptor"]["id"] for n in
                     json.loads(out)["runs"][0]["invocations"][0]["toolExecutionNotifications"]]
            self.assertNotIn("acceptance-expiring", kinds)

    def test_the_window_must_be_a_number_of_days(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            code, _, err = run_cli("check", tmp, "--expiry-warning", "-1")
            self.assertEqual(code, 2)
            self.assertIn("--expiry-warning is a number of days, 0 or more", err)
            code, _, err = run_cli("check", tmp, "--expiry-warning", "soon")
            self.assertEqual(code, 2)
            code, _, err = run_cli("check", tmp, "--lanes", "--expiry-warning", "-1")
            self.assertEqual(code, 2)
        default = cli.build_parser().parse_args(["check", "."]).expiry_warning
        self.assertEqual(default, report.EXPIRY_WARNING_DAYS)

    def test_the_migrate_hint_repeats_the_options_the_check_was_given(self):
        from test_finding_lifecycle import fixture_repo
        with TempDir() as tmp:
            target, old = fixture_repo(tmp)
            config = tmp / "my config.yml"
            config.write_text("lanes: {}\n", encoding="utf-8")
            _, out, _ = run_cli("check", target, "--baseline", old, "--platform", "github", "--config", config)
            hint = [line for line in out.splitlines() if "obaaf baseline migrate" in line]
            self.assertEqual(len(hint), 1)
            self.assertTrue(hint[0].endswith(f"--owner OWNER --reason REASON --expires YYYY-MM-DD "
                                             f"'--config={config}' --platform=github"), hint[0])
            self.assertNotIn("if any", out)
            # The command as printed is one the command line accepts, also for a file whose name
            # begins with a hyphen.
            import shlex
            words = shlex.split(hint[0])
            self.assertEqual(words[:3], ["obaaf", "baseline", "migrate"])
            parsed = cli.build_parser().parse_args(words[1:])
            self.assertEqual((parsed.config, parsed.platform), (str(config), "github"))
            result = result_of(finding())
            result.baseline_format, result.baseline_path = baseline.FORMAT_V1, "old.json"
            result.options = ["--config=-cfg.yml", "--platform=jenkins"]
            hint, = [line for line in report.to_text(result).splitlines() if "obaaf baseline migrate" in line]
            parsed = cli.build_parser().parse_args(shlex.split(hint)[1:])
            self.assertEqual((parsed.file, parsed.config, parsed.platform), ("old.json", "-cfg.yml", "jenkins"))
            _, out, _ = run_cli("check", target, "--baseline", old)
            hint = [line for line in out.splitlines() if "obaaf baseline migrate" in line]
            self.assertTrue(hint[0].endswith("--expires YYYY-MM-DD"), hint[0])


# The fields of a finding and of the report that 0.3.0 wrote. Expectrail's audit script reads
# findings[].suppressed, category, severity, job, path, line, rule and title, and files, tool and
# errors (agents/assurance/audit.py at 16edb91).
REPORT_FIELDS_0_3_0 = ("format", "tool", "files", "errors", "findings", "notes")
FINDING_FIELDS_0_3_0 = ("rule", "title", "severity", "category", "remediation", "path", "line", "job", "step",
                        "message", "requirements", "agentControls", "fix", "suppressed")


class JsonTest(unittest.TestCase):
    def test_the_accepted_risk_and_the_summary_come_before_the_findings(self):
        data = json.loads(report.to_json(mixed()))
        self.assertEqual(list(data)[:4], ["format", "tool", "acceptedRisk", "summary"])
        self.assertEqual(data["acceptedRisk"], report.accepted_risk(mixed()))
        self.assertEqual(data["summary"], {"new": 2, "accepted": 5, "cannotTell": 1, "fixed": 1, "notAccepted": 1})
        self.assertEqual(data["format"], "obaaf-check/v0.1")

    def test_every_field_an_earlier_version_wrote_is_still_there(self):
        data = json.loads(report.to_json(mixed()))
        for name in REPORT_FIELDS_0_3_0:
            self.assertIn(name, data)
        self.assertEqual(len(data["findings"]), 8)      # the fixed one is under "fixed"
        for f in data["findings"]:
            for name in FINDING_FIELDS_0_3_0:
                self.assertIn(name, f, name)
            self.assertIn("baselined", f)
        ignored = [f for f in data["findings"] if f["suppressed"]]
        self.assertEqual([f["suppressed"] for f in ignored], [f"{REASON} (until {day(10)})"])
        self.assertEqual(data["baseline"], {"stale": [], "format": baseline.FORMAT})

    def test_a_valid_acceptance_says_how_many_days_it_has_left(self):
        data = json.loads(report.to_json(result_of(accepted(expires=day(17)), refused(job="f"))))
        first, second = data["findings"]
        self.assertEqual(first["acceptance"], {"source": "baseline", "owner": OWNER, "reason": REASON,
                                               "expires": day(17), "valid": True, "problems": [], "daysLeft": 17})
        self.assertFalse(second["acceptance"]["valid"])
        self.assertNotIn("daysLeft", second["acceptance"])

    @same_day
    def test_through_the_command_line(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A", "TOKEN_B")
            path = write_baseline(self, tmp, soon(45))
            repo(tmp, "TOKEN_A", "TOKEN_C")
            (tmp / ".github" / "obaaf.yml").write_text("lanes:\n  .github/workflows/ci0.yml#nobody: agent\n",
                                                       encoding="utf-8")
            (tmp / ".github" / "workflows" / "broken.yml").write_text("on: [push\njobs: {", encoding="utf-8")
            code, out, _ = run_cli("check", tmp, "--baseline", path, "--format", "json", "--fail-on", "low")
            self.assertEqual(code, 1)
            data = json.loads(out)
            # The values, not only the names, of what an earlier version wrote.
            from obaaf import __version__
            self.assertEqual(data["tool"], f"obaaf {__version__}")
            self.assertEqual(data["files"], [".github/workflows/broken.yml", ".github/workflows/ci0.yml",
                                             ".github/workflows/ci1.yml"])
            self.assertEqual(len(data["errors"]), 1)
            self.assertTrue(data["errors"][0].startswith(".github/workflows/broken.yml: "))
            self.assertEqual(len(data["notes"]), 1)
            self.assertTrue(data["notes"][0].startswith("Lane declaration ignored: lanes: "
                                                        "'.github/workflows/ci0.yml#nobody'"))
            self.assertEqual([(f["rule"], f["title"], f["severity"], f["category"], f["path"], f["line"], f["job"],
                               f["suppressed"], f["baselined"], f["state"]) for f in data["findings"]],
                             [("OBAAF-GHA-001", "Secret available to a workflow started by untrusted input", "low",
                               "authority", f".github/workflows/ci{n}.yml", 7, "test", None, n == 0,
                               "accepted" if n == 0 else "new") for n in (0, 1)])
            self.assertEqual(data["summary"], {"new": 1, "accepted": 1, "cannotTell": 0, "fixed": 0, "notAccepted": 0})
            self.assertEqual(json.loads(run_cli("check", tmp, "--baseline", path, "--format", "json")[1])
                             ["acceptedRisk"]["expiringSoon"], {"withinDays": 30, "total": 0, "findings": []})
            self.assertEqual(json.loads(run_cli("check", tmp, "--baseline", path, "--format", "json",
                                                "--expiry-warning", "60")[1])["acceptedRisk"]["expiringSoon"]["total"], 1)
            risk = data["acceptedRisk"]
            self.assertEqual((risk["total"], risk["bySource"], risk["nearestExpiry"], risk["daysToNearestExpiry"]),
                             (1, {"baseline": 1, "ignore": 0}, soon(45), 45))
            self.assertEqual(risk["asOf"], date.today().isoformat())
            self.assertEqual(risk["owners"][0]["owner"], OWNER)
            self.assertEqual(len(data["baseline"]["stale"]), 1)


class SarifTest(unittest.TestCase):
    def run_of(self, result, **options):
        return json.loads(report.to_sarif(result, **options))["runs"][0]

    def test_the_run_leads_with_the_accepted_risk(self):
        run = self.run_of(mixed())
        self.assertEqual(run["properties"]["obaaf-accepted-risk"], report.accepted_risk(mixed()))
        self.assertEqual(run["properties"]["obaaf-summary"], report.summary(mixed()))
        invocation, = run["invocations"]
        self.assertIs(invocation["executionSuccessful"], True)
        first = invocation["toolExecutionNotifications"][0]
        self.assertEqual((first["descriptor"]["id"], first["level"]), ("accepted-risk", "note"))
        self.assertEqual(first["message"]["text"],
                         "Accepted risk: 5 finding(s) are accepted and do not fail the check (3 high, 1 medium, "
                         f"1 low). By owner: @example/maintainers: 2, first expiry {day(40)}; @Octocat: 2, first "
                         f"expiry {day(10)}; sec@example.com: 1, first expiry {day(365)}.")
        second = invocation["toolExecutionNotifications"][1]
        self.assertEqual((second["descriptor"]["id"], second["level"]), ("acceptance-expiring", "warning"))
        self.assertIn(f"the first on {day(10)} (in 10 days)", second["message"]["text"])

    def test_no_accepted_risk_is_a_notification_too(self):
        run = self.run_of(result_of(finding(), baseline_used=False))
        notes = run["invocations"][0]["toolExecutionNotifications"]
        self.assertEqual([n["message"]["text"] for n in notes],
                         ["Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry."])
        self.assertEqual(run["properties"]["obaaf-accepted-risk"]["total"], 0)

    def test_an_accepted_finding_is_a_suppressed_result_that_says_who_accepted_it(self):
        run = self.run_of(result_of(accepted(job="a", expires=day(40)),
                                    accepted(job="b", source=acceptance.IGNORE, owner="@octocat", expires=day(9)),
                                    refused(job="c"), finding(job="d")))
        by_baseline, by_ignore, not_accepted, new = run["results"]
        said = f"Accepted by {OWNER} until {day(40)}: {REASON}."
        self.assertEqual(by_baseline["suppressions"], [{"kind": "external", "status": "accepted",
                                                        "justification": said}])
        self.assertEqual(by_baseline["message"]["text"], f"Agent job 'triage' receives MODEL_KEY. {said}")
        self.assertEqual(by_baseline["properties"]["obaaf-acceptance"],
                         {"source": "baseline", "owner": OWNER, "reason": REASON, "expires": day(40), "daysLeft": 40})
        self.assertEqual(by_baseline["baselineState"], "unchanged")
        self.assertEqual(by_ignore["suppressions"][0]["justification"],
                         f"Accepted by @octocat until {day(9)}: {REASON}.")
        self.assertEqual(by_ignore["properties"]["obaaf-acceptance"]["source"], "ignore")
        self.assertNotIn("baselineState", by_ignore)
        # An entry that does not count suppresses nothing, and the result says why in words. An empty
        # list is how SARIF says "not suppressed"; a missing one would say nobody knows.
        self.assertEqual(not_accepted["suppressions"], [])
        self.assertNotIn("obaaf-acceptance", not_accepted["properties"])
        self.assertEqual(not_accepted["message"]["text"],
                         "Agent job 'triage' receives MODEL_KEY. Not accepted: the baseline entry that names this "
                         f"finding does not count, because it expired on {day(-1)}.")
        self.assertEqual(not_accepted["properties"]["obaaf-state"], "new")
        self.assertEqual(new["suppressions"], [])
        self.assertEqual(new["message"]["text"], "Agent job 'triage' receives MODEL_KEY.")

    def test_values_that_are_not_text_do_not_end_a_report_in_a_traceback(self):
        f = finding(message=None)
        result = result_of(f, errors=[ValueError("ci.yml: unreadable")], notes=[("a", "note")], baseline_used=True)
        result.baseline_format, result.baseline_path, result.options = baseline.FORMAT_V1, "old.json", [7, "--x=y"]
        run = self.run_of(result)
        self.assertEqual(run["results"][0]["message"]["text"], "")
        g = finding(message="", controls=[Control("egress is enforced", NOT_MET)])
        self.assertEqual(self.run_of(result_of(g))["results"][0]["message"]["text"],
                         "Controls: egress is enforced: not met.")
        texts = [n["message"]["text"] for n in run["invocations"][0]["toolExecutionNotifications"]]
        self.assertIn("ci.yml: unreadable", texts)
        self.assertIn("('a', 'note')", texts)
        hint, = [line for line in report.to_text(result).splitlines() if "obaaf baseline migrate" in line]
        self.assertTrue(hint.endswith("--expires YYYY-MM-DD 7 --x=y"), hint)

    def test_a_result_carries_its_controls_as_data_and_in_words(self):
        controls = [Control("the key is in an environment", VERIFIED, "main-only", id="secrets-protected"),
                    Control("egress is enforced", NOT_MET, id="egress-enforced")]
        result, = self.run_of(result_of(finding(controls=controls), baseline_used=False))["results"]
        self.assertEqual(result["properties"]["obaaf-controls"], [
            {"id": "secrets-protected", "name": "the key is in an environment", "verdict": "verified",
             "detail": "main-only"},
            {"id": "egress-enforced", "name": "egress is enforced", "verdict": "not met", "detail": ""}])
        self.assertEqual(result["message"]["text"],
                         "Agent job 'triage' receives MODEL_KEY. Controls: the key is in an environment: verified "
                         "(main-only); egress is enforced: not met.")

    def test_errors_and_notes_are_in_the_run(self):
        run = self.run_of(result_of(accepted(), errors=["ci.yml: cannot be read as YAML: line 3"],
                                    notes=["Lane declaration ignored: wf.yml: job 'work' sets OBAAF_LANE to 'agnet'."]))
        invocation, = run["invocations"]
        self.assertIs(invocation["executionSuccessful"], False)
        seen = [(n["descriptor"]["id"], n["level"], n["message"]["text"])
                for n in invocation["toolExecutionNotifications"]]
        self.assertEqual(seen[0][0], "accepted-risk")
        self.assertIn(("not-read", "error", "ci.yml: cannot be read as YAML: line 3"), seen)
        self.assertIn(("note", "note", "Lane declaration ignored: wf.yml: job 'work' sets OBAAF_LANE to 'agnet'."),
                      seen)

    def test_baseline_entries_that_no_longer_match_and_an_old_baseline_are_in_the_run(self):
        result = result_of(finding())
        result.baseline_stale = [baseline.entry_for(finding(job="gone"), OWNER, REASON, day(30))]
        texts = [(n["descriptor"]["id"], n["level"], n["message"]["text"])
                 for n in self.run_of(result)["invocations"][0]["toolExecutionNotifications"]]
        stale = [text for kind, level, text in texts if (kind, level) == ("baseline", "warning")]
        self.assertEqual(len(stale), 1)
        self.assertTrue(stale[0].startswith("A baseline entry no longer matches a finding: OBAAF-GHA-005 "
                                            ".github/workflows/agent.yml [job gone] - secrets; secrets: MODEL_KEY."))
        old = result_of(finding())
        old.baseline_format = baseline.FORMAT_V1
        texts = [n["message"]["text"] for n in self.run_of(old)["invocations"][0]["toolExecutionNotifications"]]
        self.assertTrue(any("old format (obaaf-baseline/v0.1)" in text for text in texts))

    def test_the_run_is_well_formed(self):
        """What SARIF 2.1.0 requires of the objects this slice added (sections 3.20, 3.58 and 3.35 of
        the standard): an invocation says whether execution succeeded, a notification has a message
        and one of four levels, a descriptor reference points at a descriptor of the tool, and a
        suppression has a kind and, when it has a status, one of three."""
        result = mixed()
        result.errors, result.notes = ["x.yml: unreadable"], ["a note"]
        run = self.run_of(result)
        descriptors = run["tool"]["driver"]["notifications"]
        self.assertEqual([d["id"] for d in descriptors], list(report.NOTIFICATIONS))
        for descriptor in descriptors:
            self.assertTrue(descriptor["shortDescription"]["text"])
        invocation, = run["invocations"]
        self.assertIsInstance(invocation["executionSuccessful"], bool)
        for note in invocation["toolExecutionNotifications"]:
            self.assertTrue(note["message"]["text"])
            self.assertIn(note["level"], ("none", "note", "warning", "error"))
            self.assertEqual(descriptors[note["descriptor"]["index"]]["id"], note["descriptor"]["id"])
        rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
        for res in run["results"]:
            self.assertEqual(rules[res["ruleIndex"]], res["ruleId"])
            self.assertTrue(res["message"]["text"])
            for suppression in res.get("suppressions", []):
                self.assertIn(suppression["kind"], ("inSource", "external"))
                self.assertIn(suppression["status"], ("accepted", "underReview", "rejected"))
        # A fixed finding is not a result, as before.
        self.assertEqual(len(run["results"]), 8)

    @same_day
    def test_through_the_command_line(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            path = write_baseline(self, tmp, soon(100))
            (tmp / ".github" / "workflows" / "broken.yml").write_text("on: [push\njobs: {", encoding="utf-8")
            code, out, _ = run_cli("check", tmp, "--baseline", path, "--format", "sarif", "--fail-on", "never")
            self.assertEqual(code, 1)       # a file that could not be read fails the check whatever --fail-on says
            run = json.loads(out)["runs"][0]
            self.assertIs(run["invocations"][0]["executionSuccessful"], False)
            errors = [n for n in run["invocations"][0]["toolExecutionNotifications"] if n["level"] == "error"]
            self.assertEqual(len(errors), 1)
            self.assertIn(".github/workflows/broken.yml", errors[0]["message"]["text"])
            result, = run["results"]
            self.assertEqual(result["suppressions"][0]["status"], "accepted")
            self.assertIn(f"Accepted by {OWNER} until {soon(100)}: {REASON}.", result["message"]["text"])
            self.assertEqual(run["properties"]["obaaf-accepted-risk"]["total"], 1)


class OutputThatCannotShowALetterTest(unittest.TestCase):
    """An owner, a job or a path can be written in any script. Where standard output is ASCII the
    report shows such a letter as an escape; it used to end in a traceback."""

    @same_day
    def test_an_owner_outside_ascii_on_ascii_output(self):
        with TempDir() as tmp:
            repo(tmp, "TOKEN_A")
            (tmp / ".github" / "obaaf.yml").write_text(
                "ignore:\n  - rule: OBAAF-GHA-001\n    path: .github/workflows/ci0.yml\n"
                f"    owner: s\u00f8ren@example.dk\n    reason: Reviewed with the build team\n    until: {soon(50)}\n",
                encoding="utf-8")
            raw = io.BytesIO()
            stream = io.TextIOWrapper(raw, encoding="ascii")
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(["check", str(tmp), "--fail-on", "low"])
                stream.flush()
            self.assertEqual(code, 0)
            out = raw.getvalue().decode("ascii")
            self.assertIn("  s\\xf8ren@example.dk: 1 (1 low); the first expires " + soon(50), out.splitlines())
            self.assertIn("accepted by s\\xf8ren@example.dk until", out)

    def test_an_error_message_outside_ascii_on_ascii_error_output(self):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="ascii")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stream):
            code = cli.main(["check", "no-such-directory-s\u00f8ren"])
            stream.flush()
        self.assertEqual(code, 2)
        self.assertEqual(raw.getvalue().decode("ascii"), "error: no-such-directory-s\\xf8ren not found\n")

    def test_a_stream_that_cannot_be_changed_is_left_alone(self):
        class Fixed(io.StringIO):
            def reconfigure(self, **options):
                raise ValueError("closed")
        out = Fixed()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["check", "no-such-directory"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
