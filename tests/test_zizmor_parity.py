"""Slice 2d.3b: the parity test against zizmor (decision F-19).

scripts/zizmor_parity.py compares OBAAF's findings with what a pinned zizmor reports, through the
mapping in tests/parity/zizmor.yaml. CI's advisory job `zizmor-parity` runs zizmor itself. These
tests need no zizmor:

* the comparison's logic, on zizmor output written here in the shape zizmor 1.32.0's json-v1 format
  has (crates/zizmor/src/output/json/v1.rs and finding/location.rs at v1.32.0);
* the mapping, the pin and the CI job agree with each other;
* OBAAF answers every recorded case of the sets whose files are in this repository, or the mapping
  says why it does not, so a change that makes OBAAF silent where zizmor reports fails here.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

_SPEC = importlib.util.spec_from_file_location("zizmor_parity", ROOT / "scripts" / "zizmor_parity.py")
zp = importlib.util.module_from_spec(_SPEC)
sys.modules["zizmor_parity"] = zp
_SPEC.loader.exec_module(zp)


def location(path: str, route: list, kind: str = "Primary", row: int = 4) -> dict:
    parts = [{"Key": p} if isinstance(p, str) else {"Index": p} for p in route]
    return {
        "symbolic": {"key": {"Local": {"prefix": None, "given_path": path, "verbatim_path": path}},
                     "annotation": "here", "route": {"route": parts}, "feature_kind": "Normal", "kind": kind},
        "concrete": {"location": {"start_point": {"row": row, "column": 6}, "end_point": {"row": row, "column": 20},
                                  "offset_span": {"start": 1, "end": 2}},
                     "feature": "x", "comments": []},
    }


def finding(ident: str, locations: list, severity: str = "High", confidence: str = "High",
            ignored: bool = False) -> dict:
    return {"ident": ident, "desc": "d", "url": "https://docs.zizmor.sh/audits/",
            "determinations": {"confidence": confidence, "severity": severity, "persona": "Regular"},
            "locations": locations, "ignored": ignored, "fixes": []}


AUDITS = {"template-injection": ["OBAAF-GHA-010"], "artipacked": ["OBAAF-GHA-011"],
          "excessive-permissions": ["OBAAF-GHA-009"]}


def mapping(silent=(), recorded=(), root: str = "w") -> "zp.Mapping":
    return zp.Mapping("1.32.0", ["--offline"], AUDITS, {"s": zp.FileSet("s", root, ["*.yml"])},
                      list(silent), list(recorded))


class ZizmorOutput(unittest.TestCase):
    def test_a_finding_on_a_step_is_a_case_of_its_job_and_that_step(self):
        cases = zp.cases_from_zizmor([finding("template-injection", [
            location("a.yml", ["jobs", "build", "steps", 0, "run"], kind="Related", row=9),
            location("a.yml", ["jobs", "build", "steps", 1, "run"], row=12)])], AUDITS)
        self.assertEqual([("a.yml", "build", "template-injection", "high", "high", (13,), ((1,),), False)],
                         [(c.file, c.job, c.audit, c.severity, c.confidence, c.lines, c.steps, c.job_level)
                          for c in cases])

    def test_a_workflow_level_finding_names_no_job(self):
        cases = zp.cases_from_zizmor([finding("excessive-permissions", [location("./b.yml", ["permissions"])])],
                                     AUDITS)
        self.assertEqual([("b.yml", None, (), True)], [(c.file, c.job, c.steps, c.job_level) for c in cases])

    def test_findings_of_one_job_and_audit_are_one_case_with_the_highest_determinations(self):
        cases = zp.cases_from_zizmor([
            finding("template-injection", [location("a.yml", ["jobs", "j", "steps", 0])], "Low", "Medium"),
            finding("template-injection", [location("a.yml", ["jobs", "j", "steps", 3])], "Informational", "High"),
            finding("template-injection", [location("a.yml", ["jobs", "j", "permissions"], row=2)], "Low", "Low"),
        ], AUDITS)
        self.assertEqual(1, len(cases))
        c = cases[0]
        self.assertEqual(("low", "high", (3, 5), ((0,), (3,)), True), (c.severity, c.confidence, c.lines, c.steps,
                                                                 c.job_level))

    def test_unmapped_and_ignored_findings_are_not_cases(self):
        cases = zp.cases_from_zizmor([
            finding("dangerous-triggers", [location("a.yml", ["on"])]),
            finding("artipacked", [location("a.yml", ["jobs", "j"])], ignored=True),
        ], AUDITS)
        self.assertEqual([], cases)

    def test_output_it_cannot_read_is_an_error_not_a_looser_case(self):
        good = finding("artipacked", [location("a.yml", ["jobs", "j"])])

        def with_location(**changes):
            loc = location("a.yml", ["jobs", "j"])
            for key, value in changes.items():
                if key == "symbolic" or key == "concrete":
                    loc[key] = value
                else:
                    loc["symbolic"][key] = value
            return [dict(good, locations=[loc])]

        bad = {
            "not a list": "not a list",
            "no ident": [{"no": "ident"}],
            "no locations": [finding("artipacked", [])],
            "hidden only": [finding("artipacked", [location("a.yml", ["jobs", "j"], kind="Hidden")])],
            "unknown severity": [finding("artipacked", [location("a.yml", ["jobs", "j"])], severity="Severe")],
            "no determinations": [dict(good, determinations=None)],
            "ignored not a boolean": [dict(good, ignored="yes")],
            "remote key": with_location(key={"Remote": {}}),
            "two keys": with_location(key={"Local": {"verbatim_path": "a.yml"}, "Stdin": {}}),
            "no path": with_location(key={"Local": {}}),
            "job as an index": with_location(route={"route": [{"Key": "jobs"}, {"Index": 1}]}),
            "route part not read": with_location(route={"route": [{"Key": 1}]}),
            "negative index": with_location(route={"route": [{"Key": "jobs"}, {"Key": "j"}, {"Index": -1}]}),
            "route as text": with_location(route="jobs.j"),
            "symbolic null": with_location(symbolic=None),
            "concrete null": with_location(concrete=None),
            "no row": with_location(concrete={"location": {"start_point": {}}}),
        }
        for name, output in bad.items():
            with self.subTest(name=name):
                with self.assertRaises(zp.ParityError):
                    zp.cases_from_zizmor(output, AUDITS)

    def test_cases_and_digests_round_trip_through_the_recorded_file(self):
        cases = zp.cases_from_zizmor([finding("artipacked", [location("a.yml", ["jobs", "j", "steps", 0])])],
                                     AUDITS)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cases.json"
            path.write_text(zp.dump_cases("1.32.0", {"s": cases}, {"s": {"a.yml": "0" * 64}}), encoding="utf-8")
            self.assertEqual({"zizmor": "1.32.0", "sets": {"s": cases}, "digests": {"s": {"a.yml": "0" * 64}}},
                             zp.load_cases(path))


WORKFLOW = """\
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo one
      - run: echo two
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo three
"""


S1, S2 = (6, "step 1"), (7, "step 2")


class Comparison(unittest.TestCase):
    """The comparison, with OBAAF's findings given by hand. Steps of WORKFLOW's job `build` are at lines 6
    and 7 (OBAAF's reader puts a step at the line of its first key)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        for name in ("a.yml", "b.yml"):
            (self.base / name).write_text(WORKFLOW, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def run_compare(self, cases, hits, silent=(), recorded=(), errors=None):
        def findings(path):
            return zp.FileResult(hits.get(path.name, []), (errors or {}).get(path.name, []),
                                 {"build": {(0,): {S1}, (1,): {S2}}, "deploy": {(0,): {(11, "step 1")}}})
        return zp.compare(mapping(silent, recorded), "s", cases, self.base, findings=findings)

    @staticmethod
    def case(job="build", audit="template-injection", file="a.yml", steps=(), job_level=True):
        return zp.Case(file, job, audit, "high", "high", (3,), tuple(steps), job_level)

    def test_answered_by_the_mapped_rule_on_the_same_job(self):
        result = self.run_compare([self.case()], {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new", S1)]})
        self.assertEqual(["answered"], [o.status for o in result.outcomes])
        self.assertEqual(0, result.failures)

    def test_another_job_another_rule_or_a_fixed_finding_does_not_answer(self):
        for hit in (zp.Hit("OBAAF-GHA-010", "deploy", "new"), zp.Hit("OBAAF-GHA-001", "build", "new"),
                    zp.Hit("OBAAF-GHA-010", "build", "fixed"), zp.Hit("OBAAF-GHA-010", None, "new")):
            with self.subTest(hit=hit):
                result = self.run_compare([self.case()], {"a.yml": [hit]})
                self.assertEqual(["unexplained"], [o.status for o in result.outcomes])
                self.assertEqual(1, result.failures)

    def test_each_step_zizmor_names_needs_a_finding_on_that_step(self):
        case = self.case(steps=((1,),), job_level=False)
        on_other_step = {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new", S1)]}
        result = self.run_compare([case], on_other_step)
        self.assertEqual(["unexplained"], [o.status for o in result.outcomes])
        self.assertEqual(["step 2 (line 7)"], result.outcomes[0].unmet)
        self.assertEqual(0, self.run_compare([case], {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new", S2)]}).failures)
        # A finding on the job as a whole answers no step (OBAAF-GHA-006's `no-cache-mode` is one).
        self.assertEqual(1, self.run_compare([case], {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new", None)]}).failures)
        both = self.case(steps=((0,), (1,)), job_level=False)
        self.assertEqual(1, self.run_compare([both], on_other_step).failures)

    def test_a_finding_on_the_job_answers_the_job_zizmor_names_but_no_step(self):
        case = self.case(steps=((1,),), job_level=True)
        result = self.run_compare([case], {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new", None)]})
        self.assertEqual(["step 2 (line 7)"], result.outcomes[0].unmet)
        self.assertEqual(0, self.run_compare([self.case(job_level=True)],
                                             {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new", None)]}).failures)

    def test_a_restores_finding_answers_the_steps_it_covers(self):
        case = self.case(audit="excessive-permissions", steps=((0,), (1,)), job_level=False)
        one = zp.Hit("OBAAF-GHA-009", "build", "new", S1, frozenset({S1}))
        self.assertEqual(1, self.run_compare([case], {"a.yml": [one]}).failures)
        both = zp.Hit("OBAAF-GHA-009", "build", "new", S1, frozenset({S1, S2}))
        self.assertEqual(0, self.run_compare([case], {"a.yml": [both]}).failures)

    def test_a_reason_for_a_case_obaaf_partly_answers_must_be_judged_again(self):
        entry = zp.Silent("s", "a.yml", "build", "template-injection", "OBAAF reads only outsiders' text here.",
                          "narrower")
        case = self.case(steps=((0,), (1,)), job_level=False)
        result = self.run_compare([case], {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new", None)]},
                                  silent=[entry])
        self.assertEqual(["silent"], [o.status for o in result.outcomes])
        self.assertEqual(1, result.failures)
        self.assertIn("judge the reason again", result.stale[0][1])

    def test_an_entry_may_name_the_steps_it_explains_in_a_case_obaaf_answers_in_part(self):
        case = self.case(steps=((0,), (1,)), job_level=False)
        on_first = {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new", S1)]}

        def entry(steps):
            item = zp.Silent("s", "a.yml", "build", "template-injection",
                             "OBAAF does not count the second step's text as an outsider's.", "narrower")
            item.steps = steps
            return item

        result = self.run_compare([case], on_first, silent=[entry(((1,),))])
        self.assertEqual((["silent"], 0), ([o.status for o in result.outcomes], result.failures))
        for wrong in ((), ((0,),), ((0,), (1,))):
            with self.subTest(steps=wrong):
                self.assertEqual(1, self.run_compare([case], on_first, silent=[entry(wrong)]).failures)
        # Steps named while OBAAF reports nothing on the job: the entry should name none.
        result = self.run_compare([case], {}, silent=[entry(((1,),))])
        self.assertEqual(1, result.failures)
        self.assertIn("remove its `steps`", result.stale[0][1])

    def test_a_step_or_job_obaaf_s_reader_does_not_have_is_an_error(self):
        for case in (self.case(steps=((5,),), job_level=False), self.case(job="nope", steps=((0,),), job_level=False)):
            with self.subTest(case=case), self.assertRaises(zp.ParityError):
                self.run_compare([case], {"a.yml": [zp.Hit("OBAAF-GHA-010", case.job, "new", None)]})

    def test_accepted_and_cannot_tell_findings_answer(self):
        for state in ("accepted", "cannot-tell"):
            result = self.run_compare([self.case()], {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", state)]})
            self.assertEqual(0, result.failures, state)

    def test_a_case_without_a_job_is_answered_anywhere_in_the_file(self):
        result = self.run_compare([self.case(job=None, audit="excessive-permissions")],
                                  {"a.yml": [zp.Hit("OBAAF-GHA-009", "anything", "new")]})
        self.assertEqual(0, result.failures)

    def test_a_file_obaaf_could_not_read_fails_even_where_a_reason_is_recorded(self):
        entry = zp.Silent("s", "a.yml", "build", "template-injection", "OBAAF reads only outsiders' text here.",
                          "narrower")
        result = self.run_compare([self.case()], {}, silent=[entry], errors={"a.yml": ["cannot parse YAML"]})
        self.assertEqual(["silent"], [o.status for o in result.outcomes])
        self.assertEqual(1, result.failures)
        self.assertIn("[obaaf could not read] a.yml: cannot parse YAML", zp.render(result))

    def test_a_recorded_reason_makes_a_silent_case_pass(self):
        entry = zp.Silent("s", "a.yml", "build", "template-injection", "OBAAF reads only outsiders' text here.",
                          "narrower")
        result = self.run_compare([self.case()], {}, silent=[entry])
        self.assertEqual(["silent"], [o.status for o in result.outcomes])
        self.assertEqual(0, result.failures)

    def test_a_reason_for_a_case_zizmor_does_not_report_or_obaaf_answers_fails(self):
        entry = zp.Silent("s", "a.yml", "build", "template-injection", "OBAAF reads only outsiders' text here.",
                          "narrower")
        result = self.run_compare([], {}, silent=[entry])
        self.assertEqual(1, result.failures)
        self.assertIn("zizmor reports no such case", result.stale[0][1])
        result = self.run_compare([self.case()], {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new")]},
                                  silent=[entry])
        self.assertEqual(1, result.failures)
        self.assertIn("OBAAF now answers", result.stale[0][1])

    def test_a_reason_for_a_file_outside_the_set_is_an_error(self):
        entry = zp.Silent("s", "gone.yml", "build", "template-injection", "OBAAF reads only outsiders' text here.",
                          "narrower")
        with self.assertRaises(zp.ParityError):
            self.run_compare([], {}, silent=[entry])

    def test_unmapped_audits_are_not_compared(self):
        result = self.run_compare([self.case(audit="dangerous-triggers")], {})
        self.assertEqual([], result.outcomes)

    def test_a_file_zizmor_names_outside_the_set_is_an_error(self):
        with self.assertRaises(zp.ParityError):
            self.run_compare([self.case(file="elsewhere.yml")], {})

    def test_recorded_results_of_other_tools(self):
        item = zp.Recorded("poutine 1.1.6", "untrusted_checkout_exec", "s", "b.yml", ["OBAAF-GHA-002"])
        self.assertEqual(1, self.run_compare([], {}, recorded=[item]).failures)
        self.assertEqual(1, self.run_compare([], {"b.yml": [zp.Hit("OBAAF-GHA-002", "j", "fixed")]},
                                             recorded=[item]).failures)
        self.assertEqual(0, self.run_compare([], {"b.yml": [zp.Hit("OBAAF-GHA-002", "j", "new")]},
                                             recorded=[item]).failures)

    def test_the_report_names_each_case_and_its_status(self):
        entry = zp.Silent("s", "b.yml", None, "artipacked", "OBAAF covers agent jobs and untrusted triggers.",
                          "gap", "#1")
        result = self.run_compare(
            [self.case(), self.case(job=None, audit="artipacked", file="b.yml"), self.case(job="x")],
            {"a.yml": [zp.Hit("OBAAF-GHA-010", "build", "new")]}, silent=[entry])
        text = zp.render(result)
        self.assertIn("3 cases of the mapped audits: 1 answered by OBAAF, 1 silent with a recorded reason, "
                      "1 silent without one", text)
        self.assertIn("[unexplained] a.yml#x template-injection", text)
        self.assertIn("[silent] b.yml (file) artipacked", text)
        self.assertIn("gap (#1): OBAAF covers agent jobs", text)


class StepPlaces(unittest.TestCase):
    def test_obaaf_findings_gives_each_place_s_step_and_the_step_a_finding_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "w.yml"
            path.write_text(WORKFLOW.replace("echo two", "echo ${{ github.event.pull_request.title }}"),
                            encoding="utf-8")
            result = zp.obaaf_findings(path)
        self.assertEqual({"build": {(0,): {S1}, (1,): {S2}}, "deploy": {(0,): {(11, "step 1")}}}, result.steps)
        self.assertIn(zp.Hit("OBAAF-GHA-010", "build", "new", S2), result.hits)
        self.assertEqual([], result.errors)

    def test_parallel_groups_and_steps_on_one_line_keep_their_places(self):
        text = ("on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - parallel:\n          - run: echo ${{ github.event.pull_request.title }}\n"
                "          - run: echo two\n"
                "      - run: echo ${{ github.event.discussion.labels[0].name }}\n"
                "  k:\n    runs-on: ubuntu-latest\n"
                "    steps: [{run: 'echo ${{ github.event.pull_request.body }}'}, {run: echo two}]\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "w.yml"
            path.write_text(text, encoding="utf-8")
            result = zp.obaaf_findings(path)
        self.assertEqual({(0, 0), (0, 1), (1,)}, set(result.steps["j"]))
        self.assertEqual(3, len({k for keys in result.steps["j"].values() for k in keys}))
        self.assertEqual(2, len({k for keys in result.steps["k"].values() for k in keys}))
        case_on = {
            ("j", (1,)): 1,      # the labels step: OBAAF reports nothing there
            ("j", (0, 0)): 0,    # the first step of the group
            ("k", (1,)): 1,      # the second step on the one line: nothing there
            ("k", (0,)): 0,
        }
        for (job, place), failures in case_on.items():
            with self.subTest(job=job, place=place):
                case = zp.Case("w.yml", job, "template-injection", "high", "high", (1,), (place,), False)
                found, unmet, _ = zp.answer(case, ["OBAAF-GHA-010"], result)
                self.assertEqual(failures, len(unmet), (found, unmet))

    def test_obaaf_gha_006_against_a_case_on_several_cache_steps(self):
        """The review's probes: OBAAF-GHA-006 reports one `restores` finding at the first cache step, and a
        low `no-cache-mode` finding on the job when it sees no cache step."""
        uv = "        uses: astral-sh/setup-uv@" + "1" * 40 + "\n"
        restoring = ("on: release\njobs:\n  p:\n    runs-on: ubuntu-latest\n    environment: pypi\n    steps:\n"
                     "      - name: a\n" + uv + "      - name: b\n" + uv + "        with: {enable-cache: true}\n"
                     "      - run: uv publish\n")
        unknown = restoring.replace("astral-sh/setup-uv", "example/not-a-cache-action")
        for text, unmet in ((restoring, 0), (unknown, 2)):
            with self.subTest(unmet=unmet), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "w.yml"
                path.write_text(text, encoding="utf-8")
                result = zp.obaaf_findings(path)
                self.assertTrue([h for h in result.hits if h.rule == "OBAAF-GHA-006"], result.hits)
                case = zp.Case("w.yml", "p", "cache-poisoning", "high", "low", (8, 10), ((0,), (1,)), False)
                found, missing, _ = zp.answer(case, ["OBAAF-GHA-006", "OBAAF-GHA-007"], result)
                self.assertEqual(unmet, len(missing), (found, missing))
                self.assertTrue(found)

    def test_zizmor_s_route_into_a_parallel_group(self):
        cases = zp.cases_from_zizmor([finding("template-injection", [
            location("a.yml", ["jobs", "j", "steps", 2, "parallel", 1, "run"])])], AUDITS)
        self.assertEqual(((2, 1),), cases[0].steps)
        with self.assertRaises(zp.ParityError):
            zp.cases_from_zizmor([finding("template-injection", [
                location("a.yml", ["jobs", "j", "steps", 2, "parallel"])])], AUDITS)


class Commands(unittest.TestCase):
    """`ci` and `compare` end to end, with a copy of the mapping and cases in a temporary folder."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.saved = (zp.CASES, zp.MAPPING)
        self.addCleanup(self.restore)
        zp.CASES = self.dir / "cases.json"
        zp.CASES.write_text(self.saved[0].read_text(encoding="utf-8"), encoding="utf-8")

    def restore(self):
        zp.CASES, zp.MAPPING = self.saved

    def run_main(self, *argv) -> tuple[int, str]:
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = zp.main(list(argv))
        return code, out.getvalue()

    def test_compare_passes_on_the_recorded_cases_and_skips_a_set_it_has_no_files_for(self):
        code, text = self.run_main("compare")
        self.assertEqual(0, code, text)
        self.assertIn("set zizmor-tests: skipped", text)

    def test_compare_refuses_a_named_set_it_has_no_files_for(self):
        code, text = self.run_main("compare", "--set", "zizmor-tests")
        self.assertEqual(2, code, text)

    def test_compare_fails_when_a_file_is_not_the_one_the_cases_were_read_from(self):
        data = json.loads(zp.CASES.read_text(encoding="utf-8"))
        name = sorted(data["digests"]["risky"])[0]
        data["digests"]["risky"][name] = "0" * 64
        zp.CASES.write_text(json.dumps(data), encoding="utf-8")
        code, text = self.run_main("compare", "--set", "risky")
        self.assertEqual(1, code, text)
        self.assertIn(f"not the ones zizmor's recorded cases were read from: {name}", text)

    def test_ci_fails_and_prints_the_cases_when_zizmor_reports_otherwise(self):
        recorded = zp.load_cases()
        zizmor_out = {name: self.dir / f"{name}.json" for name in recorded["sets"]}
        # zizmor reports nothing on either set: every recorded case is gone, and every silent entry stale.
        for path in zizmor_out.values():
            path.write_text("[]", encoding="utf-8")
        base = self.dir / "zizmor-tests"
        for rel in recorded["digests"]["zizmor-tests"]:
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_text("on: push\njobs: {}\n", encoding="utf-8")
        code, text = self.run_main("ci", *[f"--zizmor={n}={p}" for n, p in zizmor_out.items()],
                                   f"--root=zizmor-tests={base}")
        self.assertEqual(1, code, text)
        self.assertIn("cases.json is not what zizmor", text)
        line = next(line for line in text.splitlines() if line.startswith("CASES "))
        printed = json.loads(line[6:])
        self.assertEqual({"risky": [], "zizmor-tests": []}, printed["sets"])
        self.assertEqual(recorded["digests"]["risky"], printed["digests"]["risky"])
        self.assertIn("[stale] silent entry", text)
        self.assertIn("parity: FAILED", text)


class FileSets(unittest.TestCase):
    def test_include_exclude_and_double_star(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for rel in ("t.yml", "t/a.yml", "t/deep/b.yml", "t/action.yml", "t/configs/c.yml", "u.yml", "t/x.txt"):
                (base / rel).parent.mkdir(parents=True, exist_ok=True)
                (base / rel).write_text("x", encoding="utf-8")
            (base / "t" / "link.yml").symlink_to(base / "u.yml")
            fs = zp.FileSet("t", ".", ["t.yml", "t/**/*.yml"], ["**/action.yml", "t/configs/**"])
            self.assertEqual(["t.yml", "t/a.yml", "t/deep/b.yml"], fs.files(base))


class MappingFile(unittest.TestCase):
    def setUp(self):
        self.mapping = zp.load_mapping()

    def write(self, text: str) -> Path:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
        tmp.write(text)
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return Path(tmp.name)

    def test_the_mapping_pairs_the_five_audits_f19_names_and_gha_007(self):
        self.assertEqual({"template-injection": ["OBAAF-GHA-010"], "unpinned-uses": ["OBAAF-GHA-008"],
                          "excessive-permissions": ["OBAAF-GHA-009"], "artipacked": ["OBAAF-GHA-011"],
                          "cache-poisoning": ["OBAAF-GHA-006", "OBAAF-GHA-007"]}, self.mapping.audits)

    def test_a_set_written_by_others_is_compared(self):
        others = [s for s in self.mapping.sets.values() if s.repository]
        self.assertTrue(others)

    def test_the_pin_the_cases_and_the_mapping_name_one_version(self):
        lock = (ROOT / "tests" / "parity" / "zizmor-requirements.txt").read_text(encoding="utf-8")
        self.assertEqual(self.mapping.version, zp.lock_version(lock))
        self.assertEqual(zp.lock_text(self.mapping.version, __import__("re").findall(r"sha256:([0-9a-f]{64})", lock)),
                         lock)
        self.assertEqual(self.mapping.version, zp.load_cases()["zizmor"])

    def test_ci_runs_the_mapping_s_commit_and_root(self):
        import yaml

        ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
        job = ci["jobs"]["zizmor-parity"]
        self.assertIs(True, job.get("continue-on-error"))
        text = json.dumps(job)
        for fileset in self.mapping.sets.values():
            if fileset.repository:
                checkout = [s for s in job["steps"] if s.get("with", {}).get("repository") == fileset.repository]
                self.assertEqual(1, len(checkout), fileset.name)
                self.assertEqual(fileset.commit, checkout[0]["with"]["ref"])
                self.assertIn(f"{fileset.name}=third-party/zizmor/{fileset.root}", text)
                self.assertEqual(fileset.root, checkout[0]["with"]["sparse-checkout"])
        install = next(s["run"] for s in job["steps"] if "pip install" in s.get("run", "") and "zizmor" in s["run"])
        for option in ("--require-hashes", "--only-binary=:all:", "--no-deps", "tests/parity/zizmor-requirements.txt"):
            self.assertIn(option, install)
        later = [s for s in job["steps"] if "zizmor_parity.py run" in s.get("run", "")
                 or "zizmor_parity.py ci" in s.get("run", "")]
        self.assertEqual(2, len(later))
        for fileset in self.mapping.sets.values():
            if fileset.repository:
                for step in later:
                    self.assertIn(f"{fileset.name}=third-party/zizmor/{fileset.root}", step["run"])

    def test_mistakes_in_the_mapping_are_errors(self):
        good = (ROOT / "tests" / "parity" / "zizmor.yaml").read_text(encoding="utf-8")
        self.assertEqual(1, good.count("\nsilent:\n"))
        entry = ("  - set: risky\n    file: a.yml\n    job: j\n    audit: artipacked\n"
                 "    kind: {kind}\n    reason: {reason}\n")
        narrower = "OBAAF is narrower than zizmor in this case"

        def with_entry(text: str) -> str:
            return good.replace("\nsilent:\n", "\nsilent:\n" + text, 1)

        broken = {
            "unknown key": good.replace("format:", "colour: red\nformat:", 1),
            "short reason": with_entry(entry.format(kind="narrower", reason="covered")),
            "unmapped audit": with_entry(entry.format(kind="narrower", reason=narrower).replace(
                "artipacked", "dangerous-triggers")),
            "unknown kind": with_entry(entry.format(kind="fine", reason=narrower)),
            "no kind": with_entry(entry.format(kind="narrower", reason=narrower).replace("    kind: narrower\n", "")),
            "gap without issue": with_entry(entry.format(kind="gap", reason="OBAAF should report this and does not")),
            "gap with a loose issue": with_entry(entry.format(kind="gap", reason="OBAAF should report this and does "
                                                              "not") + "    issue: '279'\n"),
            "narrower with issue": with_entry(entry.format(kind="narrower", reason=narrower) + "    issue: '#5'\n"),
            "no set": with_entry(entry.format(kind="narrower", reason=narrower).replace("set: risky", "set: other")),
            "no commit": good.replace("    commit: 21bd300700d43d9ba04b0c1fce72a89391ac80b4\n", ""),
            "loose version": good.replace("version: 1.32.0", "version: '1.32'"),
            "rule of another platform": good.replace("[OBAAF-GHA-010]", "[OBAAF-JEN-010]"),
            "duplicate": with_entry(entry.format(kind="narrower", reason=narrower) * 2),
            "steps numbered from 1 as text": with_entry(entry.format(kind="narrower", reason=narrower)
                                                        + "    steps: ['2']\n"),
            "a negative step": with_entry(entry.format(kind="narrower", reason=narrower) + "    steps: [[-1]]\n"),
            "steps without a job": with_entry(entry.format(kind="narrower", reason=narrower).replace(
                "    job: j\n", "") + "    steps: [[1]]\n"),
        }
        for name, text in broken.items():
            with self.subTest(name=name):
                self.assertNotEqual(good, text)
                with self.assertRaises(zp.ParityError):
                    zp.load_mapping(self.write(text))
        # The same entry, well formed, loads.
        zp.load_mapping(self.write(with_entry(entry.format(kind="gap", reason="OBAAF should report this and does "
                                                           "not") + "    issue: '#279'\n")))


class ActionsThatRunTheirInputs(unittest.TestCase):
    """The two actions the parity test found OBAAF did not read (detection.yaml, script_inputs)."""

    def test_an_outsider_s_text_in_their_code_input_is_reported(self):
        from obaaf import checker

        steps = {
            "mikefarah/yq": "cmd", "MikeFarah/YQ": "cmd",
            "Amadevus/pwsh-script": "script", "amadevus/PWSH-SCRIPT": "script",
        }
        for action, name in steps.items():
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "w.yml"
                path.write_text(
                    "on: pull_request_target\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                    f"    steps:\n      - uses: {action}@{'1' * 40}\n        with:\n"
                    f"          {name}: echo ${{{{ github.event.pull_request.title }}}}\n"
                    f"          other: echo ${{{{ github.event.pull_request.body }}}}\n", encoding="utf-8")
                result = checker.check(path, config=checker.Config.load(path.parent, None), platform="github")
                found = [f for f in result.findings if f.rule == "OBAAF-GHA-010"]
                self.assertEqual(1, len(found), [f.message for f in result.findings])
                self.assertIn("github.event.pull_request.title", found[0].message)
                self.assertNotIn("body", found[0].message)


class RecordedCases(unittest.TestCase):
    """OBAAF against what zizmor 1.32.0 reported, as CI recorded it, for the sets in this repository."""

    def test_obaaf_answers_or_the_mapping_explains_every_recorded_case(self):
        mapping = zp.load_mapping()
        recorded = zp.load_cases()
        compared = 0
        for name, fileset in mapping.sets.items():
            if fileset.repository:
                continue
            self.assertEqual(recorded["digests"][name], zp.digests(fileset, ROOT / fileset.root),
                             f"set {name}: a file changed since zizmor's cases were recorded; record them again "
                             "from CI's zizmor-parity job")
            result = zp.compare(mapping, name, recorded["sets"].get(name, []), ROOT / fileset.root)
            self.assertEqual(0, result.failures, zp.render(result))
            compared += len(result.outcomes)
        self.assertGreater(compared, 0)

    def test_every_recorded_case_is_of_a_mapped_audit_and_a_file_of_its_set(self):
        mapping = zp.load_mapping()
        for name, cases in zp.load_cases()["sets"].items():
            self.assertIn(name, mapping.sets)
            files = None if mapping.sets[name].repository else set(mapping.sets[name].files(ROOT / mapping.sets[name].root))
            for case in cases:
                self.assertIn(case.audit, mapping.audits)
                if files is not None:
                    self.assertIn(case.file, files)


if __name__ == "__main__":
    unittest.main()
