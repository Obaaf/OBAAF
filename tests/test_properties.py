"""Slice 2d.3: properties of the workflow and expression readers, tried on many inputs.

Earlier slices had reviewers write one-off generators to get past a rule. These tests keep the
idea: each states a property and tries it on every workflow of a corpus, many times, with seeded
random choices, so a run is repeatable and CI runs the same cases every time.

The properties:

* The same YAML written another way gives the same findings. Block or flow collections, quoted,
  literal or folded text, keys in another order, anchors and aliases, comments, indentation and
  line width change nothing GitHub reads, and the generator checks that the checker's loader reads
  the same data from both texts.
* An expression respelled the ways obaaf.checker.expr documents as reading the same (letter case
  in names, `.name` and `['name']`, spaces, parentheses) never removes a finding, lowers its
  severity or moves it nearer to cleared.
* A workflow in another form GitHub documents as meaning the same (one label, job or event as a
  list of one, an event as an empty mapping, the workflow's `env` written into each job) never
  removes a finding either.
* Corrupted text never makes the checker raise, and never takes it more than a few seconds.

The corpus is OBAAF's published test set (tests/fixtures/workflows/risky, with the configuration
each file names), the templates, and this repository's own workflows. Set OBAAF_PROPERTY_ROUNDS to
try more rounds than CI does, and OBAAF_PROPERTY_CORPUS to a folder of further workflow files (for
example a copy of another project's .github/workflows) to try them too.

None of the respellings has been run on GitHub. The tests claim what the checker does with them.
"""

from __future__ import annotations

import collections
import os
import random
import time
import unittest
from pathlib import Path

import property_spellings as spell
from helpers import RISKY, ROOT, TEMPLATES, TempDir

from obaaf import checker, render
from obaaf.checker import expr
from obaaf.checker import workflow as wf_mod

ROUNDS = int(os.environ.get("OBAAF_PROPERTY_ROUNDS") or "12")
SEED = 20261119
SEVERITY = {"low": 0, "medium": 1, "high": 2}
# How near a finding is to not failing the check: a respelling may only keep a finding where it was
# or move it away from cleared.
NEARNESS = {"new": 0, "cannot-tell": 1, "accepted": 2, "fixed": 3}


def corpus() -> list[tuple[str, str, dict | None]]:
    """(name, text, configuration data) for every workflow the properties are tried on."""
    out = []
    for case in render.read_test_set(RISKY):
        path = ROOT / case["file"]
        out.append((path.name, path.read_text(encoding="utf-8"), case["config"]))
    for folder in (TEMPLATES / "workflows", ROOT / ".github" / "workflows"):
        for path in sorted(folder.glob("*.yml")):
            out.append((path.name, path.read_text(encoding="utf-8"), None))
    extra = os.environ.get("OBAAF_PROPERTY_CORPUS")
    if extra:
        for path in sorted(Path(extra).glob("*.y*ml")):
            out.append((path.name, path.read_text(encoding="utf-8"), None))
    return out


def run(tmp: Path, name: str, text: str, config: dict | None):
    path = tmp / name
    path.write_text(text, encoding="utf-8")
    loaded = checker.Config.from_data(config, path) if config else None
    return checker.check(path, config=loaded)


def identity(finding) -> tuple:
    """What a finding is, apart from where its text sits in the file and how its message words
    what it found. A step with no name is named by its `uses`, which a respelling may write in
    another letter case, so the step's name is compared without regard to case."""
    return (finding.rule, finding.job, (finding.step or "").lower(), finding.kind)


def summary(result) -> collections.Counter:
    return collections.Counter((identity(f), f.severity, f.state) for f in result.findings)


def lost(before, after) -> list[str]:
    """Findings of `before` that `after` does not have at the same or a higher severity and at the
    same distance from cleared or further."""
    available = collections.Counter((identity(f), f.severity, f.state) for f in after.findings)
    out = []
    for f in sorted(before.findings, key=lambda f: f.sort_key()):
        match = next((key for key in available if key[0] == identity(f) and available[key] > 0
                      and SEVERITY[key[1]] >= SEVERITY[f.severity]
                      and NEARNESS[key[2]] <= NEARNESS[f.state]), None)
        if match is None:
            out.append(f"{f.rule} {f.severity} {f.state} job={f.job} step={f.step} kind={f.kind}: {f.message[:120]}")
        else:
            available[match] -= 1
    return out


class YamlRespellingTest(unittest.TestCase):
    """The same data in other YAML gives the same findings and the same errors."""

    def test_the_generator_keeps_the_data(self):
        rng = random.Random(SEED)
        for name, text, _ in corpus():
            for _ in range(ROUNDS):
                respelled = spell.respell_yaml(text, rng)
                with self.subTest(file=name):
                    self.assertEqual(spell.yaml_data(respelled), spell.yaml_data(text), respelled)

    def test_other_yaml_gives_the_same_findings(self):
        rng = random.Random(SEED + 1)
        with TempDir() as tmp:
            for name, text, config in corpus():
                before = run(tmp, name, text, config)
                for round_ in range(ROUNDS):
                    respelled = spell.respell_yaml(text, rng)
                    if spell.yaml_data(respelled) != spell.yaml_data(text):
                        self.fail(f"{name}: the generator changed the data in round {round_}")
                    after = run(tmp, name, respelled, config)
                    with self.subTest(file=name, round=round_):
                        self.assertEqual(summary(after), summary(before), respelled)
                        self.assertEqual(len(after.errors), len(before.errors), respelled)


class ExpressionRespellingTest(unittest.TestCase):
    """Expressions respelled as the reader documents never lose a finding."""

    def test_the_reader_reads_at_least_the_same_references(self):
        """Every field the original expression reads, the respelled one reads too (the same path, or
        a wider one: inside a function's arguments `(needs).plan.outputs.x` is read as all of
        `needs`), and it reads every secret the original names, or all of them."""
        rng = random.Random(SEED + 2)
        seen = 0
        for name, text, _ in corpus():
            for value in _strings(spell.yaml_data(text)):
                for begin, end in spell.spans(value):
                    body = value[begin:end]
                    try:
                        want = expr.refs(body)
                    except expr.TooComplex:
                        continue
                    for _ in range(ROUNDS):
                        respelled = spell.respell_body(body, rng)
                        seen += 1
                        got = expr.refs(respelled)
                        with self.subTest(file=name, body=body):
                            for ref in want:
                                if any(s.kind != expr.NAME for s in ref.path):
                                    continue
                                pattern = tuple({s.value.lower()} for s in ref.path)
                                self.assertTrue(any(expr.reaches(r.path, pattern, r.extracted) for r in got),
                                                f"{respelled!r} does not read {expr.dotted(ref.path)}")
                            names, other = _secret_names(body), _secret_names(respelled)
                            self.assertTrue(expr.ALL in other or names <= other, respelled)
        self.assertGreater(seen, 100)

    def test_respelled_expressions_lose_no_finding(self):
        rng = random.Random(SEED + 3)
        with TempDir() as tmp:
            for name, text, config in corpus():
                if "${{" not in text:
                    continue
                before = run(tmp, name, text, config)
                for round_ in range(ROUNDS):
                    respelled = spell.respell_expressions(text, rng)
                    after = run(tmp, name, respelled, config)
                    with self.subTest(file=name, round=round_):
                        self.assertEqual(lost(before, after), [], respelled)


class WorkflowFormsTest(unittest.TestCase):
    """Forms GitHub documents as meaning the same never lose a finding."""

    def test_other_forms_lose_no_finding(self):
        rng = random.Random(SEED + 4)
        tried = 0
        with TempDir() as tmp:
            for name, text, config in corpus():
                before = run(tmp, name, text, config)
                for round_ in range(ROUNDS):
                    respelled = spell.respell_forms(text, rng)
                    if respelled is None:
                        continue
                    tried += 1
                    after = run(tmp, name, respelled, config)
                    with self.subTest(file=name, round=round_):
                        self.assertEqual(lost(before, after), [], respelled)
        self.assertGreater(tried, 20)

    def test_the_forms_are_read_as_the_same_triggers_labels_and_needs(self):
        rng = random.Random(SEED + 5)
        for name, text, _ in corpus():
            original = wf_mod.parse(name, text)
            if original.error:
                continue
            for _ in range(ROUNDS):
                respelled = spell.respell_forms(text, rng)
                if respelled is None:
                    continue
                other = wf_mod.parse(name, respelled)
                with self.subTest(file=name):
                    self.assertIsNone(other.error)
                    self.assertEqual(sorted(other.triggers), sorted(original.triggers))
                    for job_id, job in original.jobs.items():
                        self.assertEqual(sorted(other.jobs[job_id].needs), sorted(job.needs))
                        self.assertEqual(other.jobs[job_id].runs_on, job.runs_on)


class CorruptionTest(unittest.TestCase):
    """Whatever the text, the checker answers: findings, or an error for the file. It never raises
    and never stalls."""

    LIMIT = 5.0

    def test_corrupted_workflows(self):
        rng = random.Random(SEED + 6)
        with TempDir() as tmp:
            for name, text, config in corpus():
                for round_ in range(ROUNDS * 4):
                    broken = spell.corrupt(text, rng)
                    started = time.monotonic()
                    try:
                        result = run(tmp, name, broken, config)
                    except Exception as exc:  # noqa: BLE001 - the property is that nothing is raised
                        self.fail(f"{name}, round {round_}: {type(exc).__name__}: {exc}\n---\n{broken}")
                    took = time.monotonic() - started
                    with self.subTest(file=name, round=round_):
                        self.assertLess(took, self.LIMIT, broken)
                        self.assertIsInstance(result.findings, list)

    def test_corrupted_expressions(self):
        rng = random.Random(SEED + 7)
        bodies = [value[b:e] for _, text, _ in corpus() for value in _strings(spell.yaml_data(text))
                  for b, e in spell.spans(value)]
        self.assertGreater(len(bodies), 50)
        for _ in range(ROUNDS * 200):
            text = "${{" + spell.corrupt(rng.choice(bodies), rng) + rng.choice(["}}", "", "}"])
            started = time.monotonic()
            try:
                expr.bodies(text)
                for body in expr.bodies(text):
                    expr.refs(body)
                    expr.secret_refs(body)
                wf_mod.secret_names(text)
            except expr.TooComplex:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"{type(exc).__name__}: {exc} on {text!r}")
            self.assertLess(time.monotonic() - started, 1.0, text)


class FoundByThePropertiesTest(unittest.TestCase):
    """What the properties found on the corpus when they were first run, each as a test of its own."""

    EFFECT = ("on:\n  workflow_run:\n    workflows: [Agent]\n    types: [completed]\npermissions:\n"
              "  contents: write\njobs:\n  apply:\n    runs-on: ubuntu-latest\n{env}    steps:\n"
              "      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c\n"
              "        with:\n{given}"
              "      - run: git apply patch.diff && git push origin HEAD:agent-fix\n")

    def _effect(self, given, env=""):
        with TempDir() as tmp:
            result = run(tmp, "apply.yml", self.EFFECT.format(given=given, env=env), None)
        return sorted({f.rule for f in result.findings} & {"OBAAF-GHA-021", "OBAAF-GHA-022"})

    def test_a_download_from_another_run_is_found_in_any_spelling(self):
        """The effect lane read `workflow_run` in the download's inputs as written, so another letter
        case, a run id passed through `env`, or a repository took the job out of the lane, and
        OBAAF-GHA-021 and 022 with it."""
        both = ["OBAAF-GHA-021", "OBAAF-GHA-022"]
        for given, env in (
                ("          run-id: ${{ github.event.workflow_run.id }}\n", ""),
                ("          run-id: ${{ GITHUB.EVENT.WORKFLOW_RUN.ID }}\n", ""),
                ("          run-id: ${{ Github.Event.Workflow_Run.Id }}\n", ""),
                ("          run-id: ${{ env.RUN }}\n", "    env:\n      RUN: ${{ github.event.workflow_run.id }}\n"),
                ("          run-id: ${{ fromJSON(env.RUN) }}\n", "    env:\n      RUN: '1'\n"),
                ("          repository: other/repo\n          github-token: ${{ secrets.T }}\n", ""),
                ("          RUN-ID: ${{ inputs.id }}\n", "")):
            with self.subTest(given=given.strip()):
                self.assertEqual(self._effect(given, env), both)

    def test_this_runs_own_artifact_is_not_another_runs(self):
        for given in ("          name: patch\n", "          run-id: ${{ github.run_id }}\n",
                      "          run-id: ${{ GITHUB.RUN_ID }}\n"):
            with self.subTest(given=given.strip()):
                self.assertEqual(self._effect(given), [])

    def test_inputs_the_checker_cannot_read_count_as_another_run(self):
        text = self.EFFECT.format(given="", env="").replace("        with:\n",
                                                             "        with: ${{ fromJSON(vars.DOWNLOAD) }}\n")
        with TempDir() as tmp:
            rules = {f.rule for f in run(tmp, "apply.yml", text, None).findings}
        self.assertTrue({"OBAAF-GHA-021", "OBAAF-GHA-022"} <= rules)

    PLACEHOLDER = ("on: push\npermissions:\n  contents: read\njobs:\n  one:\n    runs-on: ubuntu-latest\n"
                   "    steps:\n      - &setup\n        name: Set up OBAAF\n"
                   "        uses: OBAAF_OWNER/obaaf/actions/setup-obaaf@0000000000000000000000000000000000000000\n"
                   "{same}"
                   "  two:\n    runs-on: ubuntu-latest\n    steps:\n      - *setup\n")

    def _placeholders(self, text):
        with TempDir() as tmp:
            result = run(tmp, "wf.yml", text, None)
        self.assertEqual(result.errors, [])
        return sorted((f.job, f.step, f.facts["placeholder"]) for f in result.findings if f.rule == "OBAAF-GHA-023")

    def test_a_step_shared_through_an_alias_is_reported_in_each_job(self):
        """A step written once under an anchor and used by a second job through an alias was
        reported for the first job only: the reader walked each value once."""
        zeros = "0" * 40
        self.assertEqual(self._placeholders(self.PLACEHOLDER.format(same="")),
                         [("one", "Set up OBAAF", zeros), ("one", "Set up OBAAF", "OBAAF_OWNER"),
                          ("two", "Set up OBAAF", zeros), ("two", "Set up OBAAF", "OBAAF_OWNER")])

    def test_a_step_used_twice_in_one_job_is_two_steps(self):
        found = self._placeholders(self.PLACEHOLDER.format(same="      - *setup\n"))
        self.assertEqual(len(found), 6, found)

    def test_placeholders_outside_steps_are_reported_where_they_are(self):
        """From the review of the first fix: a memo keyed by the identity of short-lived values gave
        one key's results to the next, so placeholders at workflow and job level were lost or put on
        the wrong job."""
        zeros = "0" * 40
        call = ("on: push\npermissions:\n  contents: read\njobs:\n  call:\n"
                f"    uses: OBAAF_OWNER/obaaf/.github/workflows/x.yml@{zeros}\n")
        self.assertEqual(self._placeholders(call), [("call", None, zeros), ("call", None, "OBAAF_OWNER")])
        levels = ("env:\n  A: OBAAF_OWNER\non: push\nrun-name: OBAAF_OWNER\npermissions:\n  contents: read\n"
                  "jobs:\n  one:\n    runs-on: OBAAF_OWNER\n    container: OBAAF_OWNER/image\n"
                  "    env:\n      B: OBAAF_OWNER\n    steps:\n      - run: echo\n")
        with TempDir() as tmp:
            found = sorted((f.job or "", f.facts["where"]) for f in run(tmp, "wf.yml", levels, None).findings
                           if f.rule == "OBAAF-GHA-023")
        self.assertEqual(found, [("", "env.A"), ("", "run-name"), ("one", "container"), ("one", "env.B"),
                                 ("one", "runs-on")])

    def test_an_alias_bomb_costs_little_and_is_reported_once_per_place(self):
        """From the review of the first fix: giving what a shared value holds again at every path that
        reaches it made ten nested lists of ten aliases a million findings and minutes of work."""
        lines = ["on: push", "permissions:", "  contents: read", "jobs:", "  one:", "    runs-on: ubuntu-latest",
                 "    steps:", "      - run: echo", "        env:", '          L0: &l0 ["OBAAF_OWNER"]']
        for depth in range(1, 10):
            lines.append(f"          L{depth}: &l{depth} [" + ", ".join([f"*l{depth - 1}"] * 10) + "]")
        started = time.monotonic()
        found = self._placeholders("\n".join(lines) + "\n")
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(found, [("one", "step 1", "OBAAF_OWNER")])

    def test_the_effect_lanes_download_is_read_as_the_shell_reads_it(self):
        """From the review: the artifacts API and `gh run download` were matched in the text as
        written, so a line continued with a backslash, a quoted word or `-R` before `run` hid them."""
        both = ["OBAAF-GHA-021", "OBAAF-GHA-022"]
        head = ("on:\n  workflow_run:\n    workflows: [Agent]\n    types: [completed]\npermissions:\n"
                "  contents: write\njobs:\n  apply:\n    runs-on: ubuntu-latest\n    steps:\n")
        tail = "      - run: git apply patch.diff && git push origin HEAD:agent-fix\n"
        for step in ("      - run: |\n          gh run \\\n            download ${{ github.event.workflow_run.id }}\n",
                     "      - run: gh 'run' download 1 -n patch\n",
                     "      - run: gh -R $GITHUB_REPOSITORY run download 1 -n patch\n",
                     "      - run: gh --repo=$GITHUB_REPOSITORY run download 1 -n patch\n",
                     "      - run: curl -sL \"$(gh api repos/$R/actions/artifacts --jq '.artifacts[0].archive_download_url')\"\n",
                     "      - run: curl -s ${{ github.event.workflow_run.artifacts_url }}\n",
                     "      - uses: Legit-Labs/action-download-artifact@1111111111111111111111111111111111111111\n",
                     "      - uses: actions/github-script@1111111111111111111111111111111111111111\n"
                     "        with:\n          script: |\n            github.rest.actions.listArtifactsForRepo({owner: 'o', repo: 'r'})\n"):
            with self.subTest(step=step.strip()[:60]), TempDir() as tmp:
                rules = sorted({f.rule for f in run(tmp, "apply.yml", head + step + tail, None).findings}
                               & set(both))
                self.assertEqual(rules, both)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _secret_names(body: str) -> set:
    return {n if n == expr.ALL else n.upper() for n in expr.secret_refs(body)}


if __name__ == "__main__":
    unittest.main()
