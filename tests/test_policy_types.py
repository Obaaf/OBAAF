"""The release policy is read field by field, with each field's YAML type checked (#395, slice 2d.21).

Before this slice `Policy.load` converted values with `int()`, `bool()`, `str()` and `list()` without
looking at their type. That ended `obaaf verify release` in a traceback (`min_approvals: null`) and it
also let a release through that the policy's author meant to stop:

* `source_refs: "refs/tags/v*"`, written as text instead of a list, became one pattern per character,
  and the pattern `*` allowed provenance from any ref;
* `allow_self_hosted_runners: "false"` or `no` (text under YAML 1.2) was read as true;
* `min_approvals: 0.5`, `false` or `-1` turned the approvals check off;
* `approvers: alice` let the one-letter logins `a`, `l`, `i`, `c` and `e` approve;
* a misspelt key (`min_aprovals: 2`) was ignored, so the default of 1 applied.

Now a value of the wrong type, a key the policy does not read, and YAML that cannot be read are each a
`PolicyError` naming the field (and its line), which the command prints as `error: ...` with status 2.
"""

import random
import unittest

from helpers import TempDir, run_cli

from obaaf import yamlutil
from obaaf.verify.policy import FORMAT, KEY_ROLES, Policy, PolicyError

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# A valid policy that names every field the policy reads, with a value of the right type.
FULL = """\
format: obaaf-policy/v0.1
repository: studio/game
signing: sigstore
provenance:
  signer_workflow: studio/game/.github/workflows/obaaf-release.yml
  source_refs: ["refs/tags/v*"]
  runner_environments: [github-hosted]
  issuer: https://token.actions.githubusercontent.com
keys:
  provenance: [keys/p.pem]
  build_record: [keys/b.pem]
  agent_run: [keys/a.pem]
  approval: [keys/r.pem]
build_record:
  allowed_tiers: [A, B]
  require_sdks: true
release:
  branch: main
  environments: [release]
  min_approvals: 2
  approver_not_actor: true
  approvers: [carol, dave]
  jenkins_project: releases/game-tags
agents:
  check: true
  since: "0123456789abcdef0123456789abcdef01234567"
  records_dir: .obaaf/records
  propose_workflow: studio/game/.github/workflows/obaaf-agent-propose.yml
  apply_workflow: studio/game/.github/workflows/obaaf-agent-apply.yml
  source_ref: refs/heads/main
  effect_identities: [obaaf-effect-lane]
  require_exact_diff: true
  allow_self_hosted_runners: false
"""

# What each field is, as the policy reads it: (section, key, kind). `section` None is the top level.
TEXT, FLAG, COUNT, NAMES, NONEMPTY_NAMES, TIERS, SECTION, SHA = (
    "text", "flag", "count", "names", "nonempty-names", "tiers", "section", "sha")
FIELDS = [
    (None, "format", TEXT), (None, "repository", TEXT), (None, "signing", TEXT),
    (None, "provenance", SECTION), (None, "keys", SECTION), (None, "build_record", SECTION),
    (None, "release", SECTION), (None, "agents", SECTION),
    ("provenance", "signer_workflow", TEXT), ("provenance", "source_refs", NAMES),
    ("provenance", "runner_environments", NAMES), ("provenance", "issuer", TEXT),
    ("keys", "provenance", NAMES), ("keys", "build_record", NAMES), ("keys", "agent_run", NAMES),
    ("keys", "approval", NAMES),
    ("build_record", "allowed_tiers", TIERS), ("build_record", "require_sdks", FLAG),
    ("release", "branch", TEXT), ("release", "environments", NONEMPTY_NAMES),
    ("release", "min_approvals", COUNT), ("release", "approver_not_actor", FLAG),
    ("release", "approvers", NAMES), ("release", "jenkins_project", TEXT),
    ("agents", "check", FLAG), ("agents", "since", SHA), ("agents", "records_dir", TEXT),
    ("agents", "propose_workflow", TEXT), ("agents", "apply_workflow", TEXT), ("agents", "source_ref", TEXT),
    ("agents", "effect_identities", NONEMPTY_NAMES), ("agents", "require_exact_diff", FLAG),
    ("agents", "allow_self_hosted_runners", FLAG),
]

# YAML values of every kind the loader can give, written as flow YAML on one line.
SAMPLES = {
    "null": "null", "empty": "", "true": "true", "false": "false", "zero": "0", "one": "1", "minus": "-1",
    "float": "1.5", "whole float": "1.0", "inf": ".inf", "nan": ".nan", "text": "abc", "quoted false": '"false"',
    "no": "no", "off": "off", "quoted one": '"1"', "empty text": "''", "list": "[a]", "empty list": "[]",
    "list of int": "[1]", "list of null": "[null]", "list of list": "[[a]]", "list of empty": "['']",
    "list of map": "[{a: b}]", "map": "{a: b}", "empty map": "{}", "date": "2026-11-27",
    "binary": "!!binary aGk=", "set": "!!set {a}", "pairs": "!!pairs [a: b]",
}

# Which samples each kind accepts (all others must be refused).
ACCEPTS = {
    TEXT: {"text", "quoted false", "no", "off", "quoted one", "empty text"},
    FLAG: {"true", "false"},
    COUNT: {"zero", "one"},
    NAMES: {"list", "empty list"},
    NONEMPTY_NAMES: {"list"},
    TIERS: set(),               # every sample is wrong: a tier is A or B
    SECTION: {"null", "empty", "empty map"},
    SHA: {"empty text"},        # since is a full commit ID written as text; '' means "not set", as before
}


def set_field(text: str, section, key: str, value: str) -> str:
    """FULL with one field's value replaced (the key is kept, so the field is present)."""
    lines = text.splitlines()
    if section is None:
        start = next(i for i, line in enumerate(lines) if line.startswith(f"{key}:"))
        end = start + 1
        while end < len(lines) and lines[end].startswith("  "):
            end += 1
        return "\n".join(lines[:start] + [f"{key}: {value}"] + lines[end:]) + "\n"
    head = next(i for i, line in enumerate(lines) if line == f"{section}:")
    i = head + 1
    while not lines[i].startswith(f"  {key}:"):
        i += 1
    lines[i] = f"  {key}: {value}"
    return "\n".join(lines) + "\n"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.ctx = TempDir()
        self.tmp = self.ctx.__enter__()
        self.path = self.tmp / "policy.yaml"

    def tearDown(self):
        self.ctx.__exit__(None, None, None)

    def load(self, text: str) -> Policy:
        self.path.write_text(text, encoding="utf-8")
        return Policy.load(self.path)

    def refused(self, text: str, *needles: str) -> str:
        self.path.write_text(text, encoding="utf-8")
        with self.assertRaises(PolicyError) as ctx:
            Policy.load(self.path)
        message = str(ctx.exception)
        for needle in needles:
            self.assertIn(needle, message)
        return message


class FullPolicyTest(Fixture):
    def test_the_full_policy_loads_every_field_as_written(self):
        p = self.load(FULL)
        self.assertEqual((p.repository, p.signing), ("studio/game", "sigstore"))
        self.assertEqual(p.provenance_workflow, "studio/game/.github/workflows/obaaf-release.yml")
        self.assertEqual(p.source_refs, ["refs/tags/v*"])
        self.assertEqual(p.runner_environments, ["github-hosted"])
        self.assertEqual(p.keys, {"provenance": ["keys/p.pem"], "build_record": ["keys/b.pem"],
                                  "agent_run": ["keys/a.pem"], "approval": ["keys/r.pem"]})
        self.assertEqual((p.allowed_tiers, p.require_sdks), (["A", "B"], True))
        self.assertEqual((p.release_branch, p.release_environments, p.min_approvals), ("main", ["release"], 2))
        self.assertEqual((p.approver_not_actor, p.approvers, p.jenkins_project),
                         (True, ["carol", "dave"], "releases/game-tags"))
        self.assertEqual((p.agents_check, p.agents_since), (True, "0123456789abcdef0123456789abcdef01234567"))
        self.assertEqual((p.records_dir, p.agent_source_ref, p.effect_identities), (
            ".obaaf/records", "refs/heads/main", ["obaaf-effect-lane"]))
        self.assertEqual((p.require_exact_diff, p.allow_self_hosted_agents), (True, False))
        for value in (p.repository, p.provenance_workflow, *p.source_refs, *p.approvers, p.release_branch):
            self.assertIs(type(value), str)
        self.assertIs(type(p.min_approvals), int)

    def test_the_shipped_policies_still_load(self):
        texts = {
            ".github/obaaf-policy.yaml": (ROOT / ".github" / "obaaf-policy.yaml").read_text(encoding="utf-8"),
        }
        for name in ("github-actions", "jenkins"):
            text = (ROOT / "templates" / name / "obaaf-policy.example.yaml").read_text(encoding="utf-8")
            texts[name] = text.replace("OWNER/REPO", "studio/game")
        for name, text in texts.items():
            with self.subTest(policy=name):
                p = self.load(text)
                self.assertGreaterEqual(p.min_approvals, 1)
                self.assertTrue(p.approver_not_actor)
                self.assertFalse(p.allow_self_hosted_agents)
                self.assertTrue(p.agents_check)

    def test_the_defaults_when_a_section_is_absent_or_empty(self):
        minimal = "format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: sigstore\n" \
                  "provenance: {source_refs: ['refs/tags/v*']}\n"
        for extra in ("", "release:\nagents:\nbuild_record:\nkeys:\n", "release: {}\nagents: {}\n"):
            with self.subTest(extra=extra):
                p = self.load(minimal + extra)
                self.assertEqual((p.min_approvals, p.release_branch, p.release_environments), (1, "main", ["release"]))
                self.assertEqual((p.allowed_tiers, p.require_sdks), (["A", "B"], True))
                self.assertEqual((p.agents_check, p.allow_self_hosted_agents, p.require_exact_diff), (True, False, True))
                self.assertEqual(p.effect_identities, ["obaaf-effect-lane"])

    def test_an_empty_text_keeps_its_old_meaning(self):
        # `branch: ""` turns the protected-branch check off (documented); the others give their defaults.
        p = self.load(set_field(set_field(FULL, "release", "branch", "''"), "agents", "records_dir", "''"))
        self.assertEqual((p.release_branch, p.records_dir), ("", ".obaaf/records"))
        p = self.load(set_field(FULL, "agents", "since", "''"))
        self.assertIsNone(p.agents_since)

    def test_the_singular_environment_is_still_read(self):
        text = FULL.replace("  environments: [release]\n", "")
        text = text.replace("  min_approvals: 2", "  environment: pypi\n  min_approvals: 2")
        self.assertEqual(self.load(text).release_environments, ["pypi"])


class EveryFieldTest(Fixture):
    """For every field and every kind of YAML value: the field's own kind loads, any other is refused."""

    def test_each_field_refuses_every_value_of_another_type(self):
        for section, key, kind in FIELDS:
            name = key if section is None else f"{section}.{key}"
            for sample, yaml_text in SAMPLES.items():
                if section is None and key in ("format", "repository", "signing"):
                    continue        # covered by their own tests below
                with self.subTest(field=name, value=sample):
                    text = set_field(FULL, section, key, yaml_text)
                    if name in ("provenance", "provenance.source_refs") and sample in ACCEPTS[kind] \
                            and yaml_text in ("null", "", "{}", "[]"):
                        # Right type, but a Sigstore policy must name its source refs (FR4), as before.
                        self.refused(text, "provenance.source_refs is required")
                    elif sample in ACCEPTS[kind]:
                        self.load(text)
                    else:
                        message = self.refused(text, name)
                        self.assertIn("line", message)

    def test_the_command_says_error_and_exits_2(self):
        for section, key, kind in FIELDS:
            if section is None:
                continue
            name = f"{section}.{key}"
            for sample in ("null", "float", "map", "list of int", "date", "binary"):
                if sample in ACCEPTS[kind]:
                    continue
                with self.subTest(field=name, value=sample):
                    self.path.write_text(set_field(FULL, section, key, SAMPLES[sample]), encoding="utf-8")
                    # `--gh` names no program, so a policy that loaded by mistake fails here and calls nothing.
                    for command in (["verify", "release", "--policy", self.path, "--artifacts", self.path,
                                     "--gh", self.tmp / "no-gh"],
                                    ["verify", "agent-run", "--policy", self.path, "--proposal", self.tmp,
                                     "--snapshot", self.tmp, "--bundle", self.path, "--gh", self.tmp / "no-gh"]):
                        code, out, err = run_cli(*command)
                        self.assertEqual(code, 2, err)
                        self.assertTrue(err.startswith("error: "), err)
                        self.assertIn(name, err)
                        self.assertNotIn("Traceback", err)
                        self.assertEqual(out, "")

    def test_the_issue_example_min_approvals_null(self):
        # The command ended in a TypeError traceback before this slice.
        self.path.write_text(set_field(FULL, "release", "min_approvals", "null"), encoding="utf-8")
        code, out, err = run_cli("verify", "release", "--policy", self.path, "--artifacts", self.path,
                                 "--gh", self.tmp / "no-gh")
        self.assertEqual(code, 2)
        self.assertIn("release.min_approvals", err)
        self.assertIn("nothing", err)


class FailOpenTest(Fixture):
    """The readings that let a release through which the policy's author meant to stop."""

    def test_source_refs_written_as_text(self):
        message = self.refused(set_field(FULL, "provenance", "source_refs", '"refs/tags/v*"'),
                               "provenance.source_refs", "a list")
        self.assertIn("refs/tags/v*", message)

    def test_self_hosted_agents_written_as_text(self):
        for value in ('"false"', "no", "off", "'0'", "0"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "agents", "allow_self_hosted_runners", value),
                             "agents.allow_self_hosted_runners", "true or false")

    def test_min_approvals_that_turned_the_check_off(self):
        for value in ("0.5", "false", "-1", "true", "1.9", "'2'", ".inf", ".nan", "-.inf", "1.0"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "release", "min_approvals", value), "release.min_approvals",
                             "whole number")

    def test_min_approvals_zero_is_still_allowed(self):
        self.assertEqual(self.load(set_field(FULL, "release", "min_approvals", "0")).min_approvals, 0)

    def test_approvers_written_as_text(self):
        self.refused(set_field(FULL, "release", "approvers", "alice"), "release.approvers", "a list")

    def test_other_lists_written_as_text(self):
        for section, key, kind in FIELDS:
            if kind in (NAMES, NONEMPTY_NAMES, TIERS):
                with self.subTest(field=f"{section}.{key}"):
                    self.refused(set_field(FULL, section, key, "AB"), f"{section}.{key}", "a list")

    def test_a_list_item_that_is_not_text(self):
        message = self.refused(set_field(FULL, "release", "approvers", "[carol, 7, dave]"),
                               "release.approvers[2]")
        self.assertIn("a whole number", message)

    def test_an_empty_list_the_verifier_needs_an_entry_of(self):
        # Before this slice an empty list was replaced by the default without a word.
        for section, key in (("build_record", "allowed_tiers"), ("release", "environments"),
                             ("agents", "effect_identities")):
            with self.subTest(field=f"{section}.{key}"):
                self.refused(set_field(FULL, section, key, "[]"), f"{section}.{key}", "at least one")

    def test_an_empty_text_in_a_list(self):
        for section, key, kind in FIELDS:
            if kind in (NAMES, NONEMPTY_NAMES):
                with self.subTest(field=f"{section}.{key}"):
                    self.refused(set_field(FULL, section, key, "[a, '']"), f"{section}.{key}[2]", "empty")

    def test_a_tier_other_than_a_or_b(self):
        for value in ("[C]", "[a]", "[A, ' B']", "[1]"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "build_record", "allowed_tiers", value), "build_record.allowed_tiers")

    def test_both_environment_and_environments(self):
        text = FULL.replace("  min_approvals: 2", "  environment: pypi\n  min_approvals: 2")
        self.refused(text, "release.environment", "release.environments")

    def test_since_unquoted_digits_or_not_a_full_commit(self):
        for value in ("1234567890123456789012345678901234567890", "abc", "'0123'", "[a]"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "agents", "since", value), "agents.since")


class KeysAndValuesTest(Fixture):
    def test_unknown_keys_at_each_level(self):
        cases = {
            "top": (FULL + "relase: {min_approvals: 2}\n", "'relase'"),
            "release": (FULL.replace("  min_approvals: 2", "  min_approvals: 2\n  min_aprovals: 3"),
                        "'min_aprovals' in release"),
            "agents": (FULL.replace("  check: true", "  check: true\n  allow_self_hosted_runner: false"),
                       "'allow_self_hosted_runner' in agents"),
            "provenance": (FULL.replace("  issuer:", "  source_ref: x\n  issuer:"), "'source_ref' in provenance"),
            "build_record": (FULL.replace("  require_sdks: true", "  require_sdks: true\n  tiers: [A]"),
                             "'tiers' in build_record"),
            "keys": (FULL.replace("  approval: [keys/r.pem]", "  approval: [keys/r.pem]\n  agent-run: [x]"),
                     "'agent-run' in keys"),
            "number key": (FULL + "1: x\n", "1"),
        }
        for name, (text, needle) in cases.items():
            with self.subTest(level=name):
                message = self.refused(text, needle, "unknown key")
                self.assertIn("line", message)

    def test_the_known_keys_are_named(self):
        message = self.refused(FULL.replace("  min_approvals: 2", "  min_approvals: 2\n  min_aprovals: 3"))
        self.assertIn("min_approvals", message.split("min_aprovals", 1)[1])

    def test_key_roles(self):
        self.assertEqual(KEY_ROLES, ("provenance", "build_record", "agent_run", "approval"))

    def test_format_repository_and_signing(self):
        for value in ("null", "[obaaf-policy/v0.1]", "1", "obaaf-policy/v0.2"):
            with self.subTest(format=value):
                self.refused(set_field(FULL, None, "format", value), FORMAT)
        for value in ("null", "[studio/game]", "{studio: game/x}", "studio", "''", "1"):
            with self.subTest(repository=value):
                self.refused(set_field(FULL, None, "repository", value), "repository")
        for value in ("null", "[keys]", "true", "gpg", "''"):
            with self.subTest(signing=value):
                self.refused(set_field(FULL, None, "signing", value), "signing")

    def test_a_section_of_another_type(self):
        for section in ("provenance", "keys", "build_record", "release", "agents"):
            for value in ("[1]", "true", "x", "0", "''"):
                with self.subTest(section=section, value=value):
                    self.refused(set_field(FULL, None, section, value), section, "a mapping")

    def test_the_value_in_a_message_is_quoted_and_short(self):
        message = self.refused(set_field(FULL, "release", "branch", "[" + "x" * 500 + "]"))
        self.assertLess(len(message), 400)
        message = self.refused(set_field(FULL, "release", "min_approvals", '"\\u202e1\\x1b[31m"'))
        self.assertNotIn("‮", message)
        self.assertNotIn("\x1b", message)


class UnreadableYamlTest(Fixture):
    def test_yaml_the_loader_refuses_is_a_policy_error(self):
        cases = {
            "syntax": FULL + "  bad: [\n",
            "duplicate key": FULL + "agents: {}\n",
            "two documents": FULL + "---\nformat: x\n",
            "tab indent": FULL.replace("  check: true", "\tcheck: true"),
            "null tag with text": FULL.replace("branch: main", "branch: !!null main"),
            "unknown tag": FULL.replace("branch: main", "branch: !!python/name:os.system ''"),
            "deep nesting": FULL.replace("  approvers: [carol, dave]", "  approvers: " + "[" * 5000 + "]" * 5000),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.refused(text, str(self.path))
                code, out, err = run_cli("verify", "release", "--policy", self.path, "--artifacts", self.path,
                                         "--gh", self.tmp / "no-gh")
                self.assertEqual(code, 2, err)
                self.assertTrue(err.startswith("error: "), err)

    def test_text_that_is_not_utf8(self):
        self.path.write_bytes(FULL.encode("utf-8") + b"# \xff\n")
        with self.assertRaises(PolicyError):
            Policy.load(self.path)

    def test_a_missing_file_is_still_an_os_error(self):
        with self.assertRaises(OSError):
            Policy.load(self.tmp / "missing.yaml")


class RandomValuesTest(Fixture):
    """Any one field given any value: either a PolicyError, or the field holds exactly what was written."""

    def test_random_values_are_refused_or_kept_exactly(self):
        rng = random.Random(395)
        atoms = list(SAMPLES.values()) + ["'refs/tags/v*'", "A", "B", "[A]", "[B, A]", "[x, y]", "2", "40",
                                          "'0123456789abcdef0123456789abcdef01234567'", "*a", "&a [x]"]
        attribute = {("release", "min_approvals"): "min_approvals", ("agents", "allow_self_hosted_runners"):
                     "allow_self_hosted_agents", ("provenance", "source_refs"): "source_refs",
                     ("release", "approvers"): "approvers", ("build_record", "require_sdks"): "require_sdks",
                     ("release", "approver_not_actor"): "approver_not_actor", ("agents", "check"): "agents_check",
                     ("agents", "require_exact_diff"): "require_exact_diff",
                     ("provenance", "runner_environments"): "runner_environments",
                     ("build_record", "allowed_tiers"): "allowed_tiers"}
        for _ in range(1500):
            section, key, kind = rng.choice([f for f in FIELDS if f[0] is not None])
            value = rng.choice(atoms)
            if rng.random() < 0.3:
                value = "[" + ", ".join(rng.choice(atoms[:20] + ["a", "b"]) for _ in range(rng.randint(0, 3))) + "]"
            text = set_field(FULL, section, key, value)
            self.path.write_text(text, encoding="utf-8")
            try:
                parsed = yamlutil.load(text)
            except Exception:
                with self.assertRaises(PolicyError, msg=(section, key, value)):
                    Policy.load(self.path)
                continue
            written = (parsed.get(section) or {}).get(key) if isinstance(parsed.get(section), dict) else None
            try:
                policy = Policy.load(self.path)
            except PolicyError as exc:
                self.assertIn(f"{section}.{key}", str(exc), (value, str(exc)))
                continue
            name = attribute.get((section, key))
            if name is None:
                continue
            got = getattr(policy, name)
            self.assertEqual(type(got), type(written) if not isinstance(written, list) else list, (section, key, value))
            self.assertEqual(got, written, (section, key, value))


if __name__ == "__main__":
    unittest.main()
