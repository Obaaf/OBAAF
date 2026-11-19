"""Flagship slice 2d.5c1: OBAAF-GHA-026, an agent action given a setting its own documentation warns about.

The plan (decisions F-22 and F-24, part 2 of 2d.5) asks for rules that report the settings an agent
tool's own documentation warns about, each citing its sentence, and nothing that only another scanner's
data calls dangerous. The settings are data under each tool's entry in `detection.yaml`; this slice
fills them for `openai/codex-action` and `anthropics/claude-code-action` (and its base action) from their
own files at the commits the entries name. The workflows here are written for these tests from that
documentation; none is copied from another project.
"""

import datetime
import re
import unittest

from helpers import TempDir

from obaaf import agent_tools, checker
from obaaf.catalog import load

CODEOWNERS = "* @example/maintainers\n"
RULE = "OBAAF-GHA-026"
CODEX = "openai/codex-action@4aac6da4b686168e147798ca841cf64ff0f027b8"
CLAUDE = "anthropics/claude-code-action@5a856893345e332afa621934082d8c660c26d689"
CLAUDE_BASE = "anthropics/claude-code-base-action@78702a3c36b5baa51f6fa2e298a962cae8bb55d8"


def check(workflow_text, files=None):
    with TempDir() as tmp:
        root = tmp / "repo"
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / ".github" / "workflows" / "wf.yml").write_text(workflow_text, encoding="utf-8")
        (root / ".github" / "CODEOWNERS").write_text(CODEOWNERS, encoding="utf-8")
        for rel, body in (files or {}).items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return checker.check(root)


def one_step(uses, inputs):
    """A workflow with one job whose one step uses `uses` with `inputs` (YAML lines, already indented)."""
    return ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - uses: {uses}\n        with:\n          prompt: review this\n{inputs}")


def found(result, kind=None):
    return [f for f in result.findings if f.rule == RULE and (kind is None or f.kind == kind)]


class DocumentedValuesTest(unittest.TestCase):
    """Each value the two actions' documentation warns about is reported, with its words and source."""

    CASES = [
        (CODEX, "safety-strategy: unsafe", "codex/safety-unsafe", "high"),
        (CODEX, "safety-strategy: read-only", "codex/safety-read-only", "medium"),
        (CODEX, 'allow-users: "*"', "codex/anyone", "high"),
        (CLAUDE, 'allowed_non_write_users: "*"', "claude-code/non-write-users-anyone", "high"),
        (CLAUDE, "allowed_non_write_users: alice,bob", "claude-code/non-write-users", "medium"),
        (CLAUDE, "allowed_bots: '*'", "claude-code/any-bot", "medium"),
        (CLAUDE, "show_full_output: true", "claude-code/full-output", "medium"),
        (CLAUDE_BASE, 'show_full_output: "true"', "claude-code/base-full-output", "medium"),
    ]

    def test_each_documented_value_is_reported_once_with_its_words(self):
        catalog = {f"{tool}/{s['id']}": s for tool, _name, s in agent_tools.settings(load().detection)}
        for uses, line, setting, severity in self.CASES:
            with self.subTest(setting=setting):
                hits = found(check(one_step(uses, f"          {line}\n")))
                self.assertEqual(len(hits), 1, [h.message for h in hits])
                hit = hits[0]
                self.assertEqual((hit.kind, hit.severity, hit.facts["setting"]), ("setting", severity, setting))
                self.assertEqual(hit.job, "a")
                self.assertIn(" ".join(catalog[setting]["says"].split()), hit.message)
                self.assertIn(catalog[setting]["source"], hit.message)
                self.assertEqual(hit.facts["action"], uses.split("@")[0])

    def test_the_value_is_read_trimmed_and_in_any_case_and_the_input_name_in_any_case(self):
        for line in ('Safety-Strategy: " UNSAFE "', "SAFETY-STRATEGY: Unsafe", "safety-strategy: |\n            unsafe"):
            with self.subTest(line=line):
                hits = found(check(one_step(CODEX, f"          {line}\n")))
                self.assertEqual([h.facts["setting"] for h in hits], ["codex/safety-unsafe"])
        hits = found(check(one_step(CLAUDE, "          SHOW_FULL_OUTPUT: True\n")))
        self.assertEqual([h.facts["setting"] for h in hits], ["claude-code/full-output"])

    def test_an_action_at_a_path_under_one_is_read_as_it(self):
        uses = "anthropics/claude-code-action/base-action@5a856893345e332afa621934082d8c660c26d689"
        hits = found(check(one_step(uses, "          show_full_output: true\n")))
        self.assertEqual([h.facts["setting"] for h in hits], ["claude-code/full-output"])

    def test_the_first_setting_for_an_input_is_the_one_reported(self):
        # `*` matches both of allowed_non_write_users's settings; only the first, high, is reported.
        hits = found(check(one_step(CLAUDE, '          allowed_non_write_users: "*"\n')))
        self.assertEqual([(h.facts["setting"], h.severity) for h in hits],
                         [("claude-code/non-write-users-anyone", "high")])


class SafeValuesTest(unittest.TestCase):
    """What the documentation recommends, the defaults, and values the actions do not read as warned."""

    CASES = [
        (CODEX, "safety-strategy: drop-sudo"),
        (CODEX, "safety-strategy: unprivileged-user"),
        (CODEX, "allow-users: alice,bob"),
        # The action takes `*` as everyone only when it is the whole value; in a list it is a user's name.
        (CODEX, 'allow-users: "alice,*"'),
        (CODEX, 'allow-users: ""'),
        (CLAUDE, 'allowed_non_write_users: ""'),
        (CLAUDE, 'allowed_non_write_users: "   "'),
        (CLAUDE, "allowed_non_write_users:"),
        (CLAUDE, "allowed_bots: dependabot[bot],renovate[bot]"),
        (CLAUDE, "show_full_output: false"),
        (CLAUDE, 'show_full_output: "no"'),
        (CLAUDE_BASE, "show_full_output: false"),
    ]

    def test_none_is_reported(self):
        for uses, line in self.CASES:
            with self.subTest(uses=uses, line=line):
                self.assertEqual(found(check(one_step(uses, f"          {line}\n"))), [])

    def test_no_input_is_no_finding(self):
        self.assertEqual(found(check(one_step(CODEX, ""))), [])
        self.assertEqual(found(check(one_step(CLAUDE, ""))), [])

    def test_another_action_with_the_same_input_name_is_not_read(self):
        for uses in ("example/codex-action@v1", "openai/codex-action-fork@v1", "anthropics/claude-code@v1"):
            with self.subTest(uses=uses):
                result = check(one_step(uses, "          safety-strategy: unsafe\n          show_full_output: true\n"))
                self.assertEqual(found(result), [])

    def test_a_setting_written_in_run_is_not_read_by_this_slice(self):
        # Command-line options are slice 2d.5c2's; a `run` script naming the input is not an input.
        text = ("on: workflow_dispatch\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: echo 'safety-strategy: unsafe'\n")
        self.assertEqual(found(check(text)), [])


class CannotTellTest(unittest.TestCase):
    """A value the checker cannot read is "cannot tell", never a pass."""

    def test_an_expression_is_computed_at_most_medium(self):
        for line in ("safety-strategy: ${{ inputs.mode }}", "safety-strategy: un${{ vars.X }}",
                     "safety-strategy: ${{ 'unsafe' }}"):
            with self.subTest(line=line):
                hits = found(check(one_step(CODEX, f"          {line}\n")))
                self.assertEqual([(h.kind, h.severity) for h in hits], [("computed", "medium")])
                self.assertEqual(hits[0].facts["settings"], ["codex/safety-read-only", "codex/safety-unsafe"])

    def test_a_medium_setting_stays_medium_and_a_list_or_mapping_cannot_be_read(self):
        hits = found(check(one_step(CLAUDE, "          show_full_output: ${{ env.DEBUG }}\n")))
        self.assertEqual([(h.kind, h.severity) for h in hits], [("computed", "medium")])
        for line in ("allow-users: [alice, '*']", "allow-users: {a: b}"):
            with self.subTest(line=line):
                hits = found(check(one_step(CODEX, f"          {line}\n")))
                self.assertEqual([h.kind for h in hits], ["computed"])


    def test_inputs_written_as_one_expression_are_cannot_tell(self):
        # Found by 2d.5c1's review: GitHub evaluates `with:` into the inputs, which the checker cannot read.
        for uses, settings in ((CODEX, ["codex/anyone", "codex/safety-read-only", "codex/safety-unsafe"]),
                               (CLAUDE, ["claude-code/any-bot", "claude-code/full-output",
                                         "claude-code/non-write-users", "claude-code/non-write-users-anyone"])):
            for written in ("${{ fromJSON(vars.CFG) }}", "${{ matrix.w }}"):
                with self.subTest(uses=uses, written=written):
                    text = ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n"
                            "    runs-on: ubuntu-latest\n    steps:\n      - uses: " + uses + "\n"
                            "        with: " + written + "\n")
                    hits = found(check(text))
                    self.assertEqual([(h.kind, h.severity, h.facts["input"]) for h in hits],
                                     [("computed", "medium", "with")])
                    self.assertEqual(hits[0].facts["settings"], settings)

    def test_a_character_an_action_may_read_otherwise_is_cannot_tell(self):
        # JavaScript's trim takes off U+FEFF, which Python's strip does not; a NUL ends an environment
        # variable; a no-break space or a zero-width space inside a value may be read otherwise.
        for line, setting in (('allow-users: "\\ufeff*"', "codex/anyone"),
                              ('allow-users: "*\\ufeff"', "codex/anyone")):
            with self.subTest(line=line):
                hits = found(check(one_step(CODEX, f"          {line}\n")))
                self.assertEqual([(h.kind, h.facts.get("setting")) for h in hits], [("setting", setting)])
        hits = found(check(one_step(CLAUDE, '          allowed_non_write_users: "\\ufeff*"\n')))
        self.assertEqual([(h.facts["setting"], h.severity) for h in hits],
                         [("claude-code/non-write-users-anyone", "high")])
        for line in ('safety-strategy: "unsafe\\0"', 'safety-strategy: "un\\u200bsafe"',
                     'safety-strategy: "un\\u00a0safe"', 'allow-users: "*\\0x"'):
            with self.subTest(line=line):
                hits = found(check(one_step(CODEX, f"          {line}\n")))
                self.assertEqual([(h.kind, h.severity) for h in hits], [("computed", "medium")])


    def test_a_list_on_several_lines_is_named_users_not_cannot_tell(self):
        for uses, name in ((CLAUDE, "allowed_bots"), (CODEX, "allow-users"), (CLAUDE, "allowed_non_write_users")):
            with self.subTest(input=name):
                hits = found(check(one_step(uses, f"          {name}: |\n            alice,\n            bob\n")))
                self.assertEqual([h.kind for h in hits], ["setting"] if name == "allowed_non_write_users" else [])

    def test_the_whole_value_is_the_fact_so_an_acceptance_stops_matching_when_it_changes(self):
        # Found by 2d.5c1's second review: a fact cut to 60 characters let `drop-sudo` become `unsafe`.
        def fact(mode):
            text = ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                    "    steps:\n      - uses: " + CODEX + "\n        with: ${{ fromJSON('{\"prompt\":"
                    "\"review the change please\",\"safety-strategy\":\"" + mode + "\"}') }}\n")
            hits = found(check(text))
            self.assertEqual([h.kind for h in hits], ["computed"])
            return hits[0].facts["value"]
        self.assertNotEqual(fact("drop-sudo"), fact("read-only"))
        self.assertIn("read-only", fact("read-only"))
        hits = found(check(one_step(CODEX, "          allow-users: [alice, '*']\n")))
        self.assertEqual(hits[0].facts["value"], '["alice", "*"]')

    def test_a_value_json_cannot_sort_or_print_is_still_a_finding_not_a_traceback(self):
        # Found by 2d.5c1's third review: mixed keys and an integer of thousands of digits raised.
        big = "0x" + "f" * 5000
        for written in ("[{1: a, b: c}]", "[{~: a, b: c}]", "[{true: a, b: c}]", f"[{big}]"):
            with self.subTest(written=written[:20]):
                text = ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                        "    steps:\n      - uses: " + CODEX + "\n        with: " + written + "\n")
                self.assertEqual([h.kind for h in found(check(text))], ["computed"])
        for written in ("{1: a, b: c}", "{~: a, b: c}", "[" * 70 + "x" + "]" * 70):
            with self.subTest(written=written[:20]):
                hits = found(check(one_step(CODEX, f"          allow-users: {written}\n")))
                self.assertEqual([h.kind for h in hits], ["computed"])


class WhereStepsAreReadTest(unittest.TestCase):

    def test_yaml_anchors_and_aliases_are_read(self):
        text = ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: " + CODEX + "\n        with: &w\n          safety-strategy: unsafe\n"
                "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + CODEX + "\n        with: *w\n")
        hits = found(check(text))
        self.assertEqual(sorted(h.job for h in hits), ["a", "b"])

    def test_a_local_composite_action_s_steps_are_read(self):
        action = ("runs:\n  using: composite\n  steps:\n    - uses: " + CODEX + "\n      with:\n"
                  "        safety-strategy: unsafe\n")
        text = ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/checkout@0000000000000000000000000000000000000001\n"
                "      - uses: ./.github/actions/review\n")
        hits = found(check(text, {".github/actions/review/action.yml": action}))
        self.assertEqual([h.facts["setting"] for h in hits], ["codex/safety-unsafe"])
        self.assertEqual(hits[0].job, "a")

    def test_an_input_the_local_action_passes_on_is_read_with_the_using_step_s_value(self):
        action = ("inputs:\n  mode: {default: drop-sudo}\nruns:\n  using: composite\n  steps:\n"
                  "    - uses: " + CODEX + "\n      with:\n        safety-strategy: ${{ inputs.mode }}\n")
        text = ("on: issue_comment\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: ./.github/actions/review\n        with:\n          mode: unsafe\n")
        hits = found(check(text, {".github/actions/review/action.yml": action}))
        self.assertEqual([(h.kind, h.facts["setting"]) for h in hits], [("setting", "codex/safety-unsafe")])


class DataTest(unittest.TestCase):
    """The settings are data the catalogue checks."""

    def entries(self):
        from obaaf import yamlutil
        from obaaf.catalog import data_text
        return yamlutil.load(data_text("detection.yaml"))

    def problems_with(self, change):
        data = self.entries()
        codex = next(e for e in data["agent_tools"] if e["id"] == "codex")
        change(codex["settings"][0], codex)
        return agent_tools.problems(data)

    def test_the_shipped_settings_have_no_problem(self):
        self.assertEqual(agent_tools.problems(self.entries()), [])

    def test_every_shipped_setting_cites_a_file_at_a_commit_and_was_read(self):
        shipped = agent_tools.settings(load().detection)
        self.assertEqual(len(shipped), 8)
        for tool, _name, setting in shipped:
            with self.subTest(setting=f"{tool}/{setting['id']}"):
                self.assertRegex(setting["source"], r"/blob/[0-9a-f]{40}/.+#L\d+")
                self.assertIsInstance(setting["read"], datetime.date)
                self.assertGreater(len(setting["says"].split()), 5)

    def test_faults_are_named(self):
        cases = [
            (lambda s, e: s.pop("says"), "missing says"),
            (lambda s, e: s.update(source="https://github.com/openai/codex-action/blob/main/action.yml"),
             "source must be a file at a commit"),
            (lambda s, e: s.update(action="openai/other-action"), "is not one of the entry's actions"),
            (lambda s, e: s.update(set=True), "either equals"),
            (lambda s, e: (s.pop("equals"), s.update(set="yes")), "set must be true"),
            (lambda s, e: s.update(equals="unsafe"), "equals must be a list"),
            (lambda s, e: s.update(severity="critical"), "severity must be one of"),
            (lambda s, e: s.update(read="yesterday"), "read must be a date"),
            (lambda s, e: s.update(colour="red"), "unknown key 'colour'"),
            (lambda s, e: e["settings"].append(dict(s)), "id is given twice"),
            (lambda s, e: s.update(input=" safety-strategy"), "input must be an input's name"),
        ]
        for change, message in cases:
            with self.subTest(message=message):
                self.assertTrue(any(message in p for p in self.problems_with(change)),
                                self.problems_with(change))

    def test_the_rule_cites_each_setting_it_names(self):
        rule = load().rules[RULE]
        for tool, _name, setting in agent_tools.settings(load().detection):
            with self.subTest(setting=f"{tool}/{setting['id']}"):
                self.assertIn(f"`{setting['input']}", rule["description"])
        self.assertTrue(re.search(r"2d\.5c2", rule["description"]))


if __name__ == "__main__":
    unittest.main()
