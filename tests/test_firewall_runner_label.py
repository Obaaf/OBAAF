"""GitHub's native egress firewall runner is a GitHub-hosted label (flagship slice 2d.9, issue #172).

OBAAF-GHA-020 clears for a job on `ubuntu-24.04-firewall` with an enforcing policy (decision D-050),
which reads the label as GitHub's own runner. OBAAF-GHA-013 used to report the same label at medium
as one it could not name, so a job on the firewall still failed a medium gate. Both rules now read the
label the same way: any letter case, no space trimmed, and only as the job's one label.
"""

import unittest

from helpers import TempDir, run_cli

from obaaf import checker
from obaaf.checker import egress as egress_mod
from obaaf.checker import workflow as workflow_mod

POLICY = "mode: enforce\nallow:\n  - api.anthropic.com\n"


def write_repository(tmp, runs_on, on="push", policy=POLICY):
    workflows = tmp / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "agent.yml").write_text(
        f"name: agent\non: {on}\npermissions:\n  contents: read\njobs:\n  agent:\n"
        f"    runs-on: {runs_on}\n    env:\n      OBAAF_LANE: agent\n    steps:\n      - run: echo hi\n",
        encoding="utf-8")
    (tmp / ".github" / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
    if policy is not None:
        (tmp / ".github" / "egress-firewall.yaml").write_text(policy, encoding="utf-8")


def findings(runs_on, **kw):
    with TempDir() as tmp:
        write_repository(tmp, runs_on, **kw)
        result = checker.check(tmp)
    return {f.rule: f for f in result.findings if f.rule in ("OBAAF-GHA-013", "OBAAF-GHA-020")}


class FirewallRunnerLabelTest(unittest.TestCase):

    def test_the_two_rules_name_the_same_label(self):
        self.assertIn(egress_mod.FIREWALL_LABEL, workflow_mod.HOSTED_LABELS)
        self.assertTrue(workflow_mod.is_hosted_label("ubuntu-24.04-firewall"))
        self.assertTrue(workflow_mod.is_hosted_label("Ubuntu-24.04-Firewall"))

    def test_the_issue_172_repository_passes_a_medium_gate(self):
        """The repository from #172, with a CODEOWNERS file: before this slice it exited 1 on a medium
        OBAAF-GHA-013 while OBAAF-GHA-020 was cleared."""
        with TempDir() as tmp:
            write_repository(tmp, "ubuntu-24.04-firewall")
            code, out, err = run_cli("check", str(tmp), "--fail-on", "medium")
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("OBAAF-GHA-013", out)
        self.assertIn("fixed: OBAAF-GHA-020", out)

    def test_no_finding_for_the_firewall_label_in_any_letter_case(self):
        for runs_on in ("ubuntu-24.04-firewall", "Ubuntu-24.04-Firewall", "[ubuntu-24.04-firewall]"):
            with self.subTest(runs_on=runs_on):
                found = findings(runs_on)
                self.assertNotIn("OBAAF-GHA-013", found)
                self.assertEqual(found["OBAAF-GHA-020"].state, "fixed")

    def test_an_outsiders_event_on_the_firewall_runner_is_not_a_self_hosted_finding(self):
        found = findings("ubuntu-24.04-firewall", on="pull_request_target")
        self.assertNotIn("OBAAF-GHA-013", found)

    def test_a_label_with_spaces_round_it_is_one_neither_rule_names(self):
        """GitHub's handling of a label written with spaces round it was not read. OBAAF-GHA-013's
        hosted list has never trimmed a label; OBAAF-GHA-020 used to, and so cleared on a label
        OBAAF-GHA-013 reported. Now both fail closed: a medium OBAAF-GHA-013, and, where the policy
        enforces, OBAAF-GHA-020 "cannot tell"."""
        found = findings('" ubuntu-24.04-firewall "')
        self.assertEqual(found["OBAAF-GHA-013"].severity, "medium")
        self.assertNotEqual(found["OBAAF-GHA-020"].state, "fixed")
        self.assertEqual(found["OBAAF-GHA-020"].controls[0].verdict, "cannot tell")

    def test_the_label_beside_another_is_not_the_firewall_runner(self):
        found = findings("[ubuntu-24.04-firewall, gpu]")
        self.assertEqual(found["OBAAF-GHA-013"].severity, "medium")
        self.assertNotEqual(found["OBAAF-GHA-020"].state, "fixed")

    def test_a_self_hosted_runner_with_the_label_is_still_high(self):
        found = findings("[self-hosted, ubuntu-24.04-firewall]")
        self.assertEqual(found["OBAAF-GHA-013"].severity, "high")
        self.assertNotEqual(found["OBAAF-GHA-020"].state, "fixed")

    def test_a_runner_group_with_the_label_is_still_high(self):
        found = findings("{group: agents, labels: [ubuntu-24.04-firewall]}")
        self.assertEqual(found["OBAAF-GHA-013"].severity, "high")
        self.assertNotEqual(found["OBAAF-GHA-020"].state, "fixed")

    def test_a_runner_group_with_a_value_that_looks_false_is_still_a_group(self):
        """`group: 0`, `false`, `''` or null: the key names a runner group whatever its value. Before,
        a value that Python reads as false was dropped, and the job was taken for GitHub-hosted (or,
        before this slice, for an unknown label at medium) while OBAAF-GHA-020 cleared."""
        for group in ("0", "false", "''", "~", "0.0"):
            with self.subTest(group=group):
                found = findings(f"{{group: {group}, labels: [ubuntu-24.04-firewall]}}")
                self.assertEqual(found["OBAAF-GHA-013"].severity, "high")
                self.assertNotEqual(found["OBAAF-GHA-020"].state, "fixed")
        for group, shown in (("~", "group:null"), ("false", "group:false"), ("''", "group:''"), ("0", "group:0")):
            with self.subTest(group=group, shown=shown):
                self.assertIn(f"({shown}, ubuntu-24.04-firewall)",
                              findings(f"{{group: {group}, labels: [ubuntu-24.04-firewall]}}")["OBAAF-GHA-013"].message)
        for group in ("{1: a, b: c}", "[{1: a, b: c}]", "[pool]"):     # no traceback on keys of mixed types
            with self.subTest(group=group):
                self.assertEqual(findings(f"{{group: {group}, labels: [ubuntu-24.04-firewall]}}")["OBAAF-GHA-013"].severity,
                                 "high")
        for group in ("0", "false"):
            with self.subTest(group=group, label="ubuntu-latest"):
                self.assertEqual(findings(f"{{group: {group}, labels: [ubuntu-latest]}}")["OBAAF-GHA-013"].severity,
                                 "high")

    def test_a_matrix_of_the_firewall_and_a_hosted_label_names_no_unknown_runner(self):
        found = findings("${{ matrix.os }}\n    strategy:\n      matrix:\n"
                         "        os: [ubuntu-24.04-firewall, ubuntu-24.04]")
        self.assertNotIn("OBAAF-GHA-013", found)
        self.assertNotEqual(found["OBAAF-GHA-020"].state, "fixed")     # one leg runs without it


class TheSameLabelWrittenTwiceTest(unittest.TestCase):
    """One GitHub-hosted label written twice, or twice in two letter cases, is one requirement, as
    OBAAF-GHA-020's firewall reading has read it since slice 2d.2f. OBAAF-GHA-013 reported it at
    medium, as labels it could not name (flagship slice 2d.10, issue #216)."""

    def test_the_firewall_label_written_twice_is_the_firewall_runner(self):
        for runs_on in ("[ubuntu-24.04-firewall, ubuntu-24.04-firewall]", "[ubuntu-24.04-firewall, Ubuntu-24.04-Firewall]"):
            with self.subTest(runs_on=runs_on):
                found = findings(runs_on, on="issues")
                self.assertNotIn("OBAAF-GHA-013", found)
                self.assertEqual(found["OBAAF-GHA-020"].state, "fixed")

    def test_a_hosted_label_written_twice_is_github_hosted(self):
        for runs_on in ("[ubuntu-latest, ubuntu-latest]", "[ubuntu-latest, UBUNTU-LATEST]",
                        "[ubuntu-latest, ubuntu-latest, ubuntu-latest]"):
            with self.subTest(runs_on=runs_on):
                with TempDir() as tmp:
                    write_repository(tmp, runs_on, on="pull_request_target", policy=None)
                    result = checker.check(tmp)
                self.assertNotIn("OBAAF-GHA-013", {f.rule for f in result.findings})

    def test_two_different_labels_are_still_not_one(self):
        for runs_on in ("[ubuntu-latest, ubuntu-24.04]", "[ubuntu-latest, 'ubuntu-latest ']", "[ubuntu-latest, gpu]"):
            with self.subTest(runs_on=runs_on):
                with TempDir() as tmp:
                    write_repository(tmp, runs_on, on="pull_request_target", policy=None)
                    result = checker.check(tmp)
                found = [f for f in result.findings if f.rule == "OBAAF-GHA-013"]
                self.assertEqual([f.severity for f in found], ["medium"])


if __name__ == "__main__":
    unittest.main()
