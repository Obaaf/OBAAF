"""The release policy is read field by field, with each field's YAML type checked (#395, slice 2d.21).

Before this slice `Policy.load` converted values with `int()`, `bool()`, `str()` and `list()` without
looking at their type. That ended `obaaf verify release` in a traceback (`min_approvals: null`) and it
also let a release through that the policy's author meant to stop:

* `source_refs: "refs/tags/v*"`, written as text instead of a list, became one pattern per character,
  and the pattern `*` allowed provenance from any ref;
* `allow_self_hosted_runners: "false"` or `no` (text under YAML 1.2) was read as true;
* `min_approvals: 0.5`, `false` or `-1` turned the approvals check off;
* `approvers: alice` let the one-letter logins `a`, `l`, `i`, `c` and `e` approve;
* a misspelt key (`min_aprovals: 2`) was ignored, so the default of 1 applied;
* `provenance.source_refs` under `signing: keys` loaded, and no ref was checked.

Now a value of the wrong type, a key the policy does not define or does not read with its `signing`, and
YAML that cannot be read are each a `PolicyError` naming the file (and the field and line where it can),
which the command prints as `error: ...` with status 2.
"""

import random
import unittest
from pathlib import Path

from helpers import TempDir, run_cli

from obaaf.verify import policy as policy_module
from obaaf.verify.policy import FORMAT, KEY_ROLES, Policy, PolicyError

ROOT = Path(__file__).resolve().parents[1]
SHA = "0123456789abcdef0123456789abcdef01234567"

# A valid Sigstore policy that names every field it reads, each with a value other than its default, so
# that a field the loader ignored would show.
FULL = f"""\
format: obaaf-policy/v0.1
repository: studio/game
signing: sigstore
provenance:
  signer_workflow: studio/game/.github/workflows/sign.yml
  source_refs: ["refs/tags/v*", "refs/tags/release-*"]
  runner_environments: [github-hosted]
  issuer: https://issuer.example
build_record:
  allowed_tiers: [A]
  require_sdks: false
release:
  branch: release
  environments: [release-check, release]
  min_approvals: 2
  approver_not_actor: false
  approvers: [carol, dave]
  jenkins_project: /releases/game-tags/
agents:
  check: false
  since: "{SHA}"
  records_dir: records/agents
  propose_workflow: studio/game/.github/workflows/propose.yml
  apply_workflow: studio/game/.github/workflows/apply.yml
  source_ref: refs/heads/trunk
  effect_identities: [obaaf-effect-lane, release-bot]
  require_exact_diff: false
  allow_self_hosted_runners: true
"""
FULL_VALUES = {
    "repository": "studio/game", "signing": "sigstore",
    "provenance_workflow": "studio/game/.github/workflows/sign.yml",
    "source_refs": ["refs/tags/v*", "refs/tags/release-*"], "runner_environments": ["github-hosted"],
    "issuer": "https://issuer.example", "keys": {}, "allowed_tiers": ["A"], "require_sdks": False,
    "release_environments": ["release-check", "release"], "min_approvals": 2, "approver_not_actor": False,
    "release_branch": "release", "agents_check": False, "agents_since": SHA, "records_dir": "records/agents",
    "propose_workflow": "studio/game/.github/workflows/propose.yml",
    "apply_workflow": "studio/game/.github/workflows/apply.yml", "agent_source_ref": "refs/heads/trunk",
    "effect_identities": ["obaaf-effect-lane", "release-bot"], "require_exact_diff": False,
    "allow_self_hosted_agents": True, "approvers": ["carol", "dave"], "jenkins_project": "releases/game-tags",
}

# A valid policy for signing with keys: the `keys` section, and none of the fields only Sigstore reads.
KEYS_FULL = """\
format: obaaf-policy/v0.1
repository: studio/game
signing: keys
keys:
  provenance: [keys/p.pem]
  build_record: [keys/b.pem, keys/b2.pem]
  agent_run: [keys/a.pem]
  approval: [keys/r.pem]
build_record:
  allowed_tiers: [A, B]
release:
  min_approvals: 1
agents:
  check: true
"""

# What each field is, as the policy reads it: (section, key, kind). `section` None is the top level.
TEXT, FLAG, COUNT, NAMES, TIERS, SECTION, SINCE = "text", "flag", "count", "names", "tiers", "section", "since"
FIELDS = [
    (None, "provenance", SECTION), (None, "keys", SECTION), (None, "build_record", SECTION),
    (None, "release", SECTION), (None, "agents", SECTION),
    ("provenance", "signer_workflow", TEXT), ("provenance", "source_refs", NAMES),
    ("provenance", "runner_environments", NAMES), ("provenance", "issuer", TEXT),
    ("keys", "provenance", NAMES), ("keys", "build_record", NAMES), ("keys", "agent_run", NAMES),
    ("keys", "approval", NAMES),
    ("build_record", "allowed_tiers", TIERS), ("build_record", "require_sdks", FLAG),
    ("release", "branch", TEXT), ("release", "environments", NAMES),
    ("release", "min_approvals", COUNT), ("release", "approver_not_actor", FLAG),
    ("release", "approvers", NAMES), ("release", "jenkins_project", TEXT),
    ("agents", "check", FLAG), ("agents", "since", SINCE), ("agents", "records_dir", TEXT),
    ("agents", "propose_workflow", TEXT), ("agents", "apply_workflow", TEXT), ("agents", "source_ref", TEXT),
    ("agents", "effect_identities", NAMES), ("agents", "require_exact_diff", FLAG),
    ("agents", "allow_self_hosted_runners", FLAG),
]


def base_for(section, key) -> str:
    """The policy a field is tried in: the `keys` section only with signing: keys."""
    return KEYS_FULL if section == "keys" or (section is None and key == "keys") else FULL


# YAML values of every kind the loader can give, written as flow YAML on one line.
SAMPLES = {
    "null": "null", "empty": "", "true": "true", "false": "false", "zero": "0", "one": "1", "minus": "-1",
    "float": "1.5", "whole float": "1.0", "inf": ".inf", "nan": ".nan", "text": "abc", "quoted false": '"false"',
    "no": "no", "off": "off", "quoted one": '"1"', "empty text": "''", "list": "[a]", "empty list": "[]",
    "list of int": "[1]", "list of null": "[null]", "list of list": "[[a]]", "list of empty": "['']",
    "list of map": "[{a: b}]", "map": "{a: b}", "empty map": "{}", "date": "2026-11-27",
    "time": "2026-11-27 10:00:00", "binary": "!!binary aGk=", "set": "!!set {a}", "pairs": "!!pairs [a: b]",
    "omap": "!!omap [a: b]", "str tag": "!!str 5", "int tag": '!!int "3"', "float tag": "!!float 1",
    "octal": "010", "hex": "0x10", "sexagesimal": "1:30", "underscore": "1_0", "bool tag yes": "!!bool yes",
}
# Refused by the loader itself, before any field is read: the message names the file and line, not the field.
YAML_REFUSED = {"octal", "hex", "sexagesimal", "underscore", "bool tag yes"}

# Which samples each kind accepts (all others must be refused).
ACCEPTS = {
    TEXT: {"text", "quoted false", "no", "off", "quoted one", "empty text", "str tag"},
    FLAG: {"true", "false"},
    COUNT: {"zero", "one", "int tag"},
    NAMES: {"list"},
    TIERS: set(),               # every sample is wrong: a tier is A or B
    SECTION: {"null", "empty", "empty map"},
    SINCE: {"empty text"},      # a full commit ID written as text; '' means "not set", as before
}
# A value of the right type that still fails, because of another rule (with what the error says).
RIGHT_TYPE_BUT = {
    (None, "provenance"): "provenance.source_refs is required",     # a Sigstore policy names its refs (FR4)
    (None, "keys"): "signing: keys needs keys.provenance",
}


def set_field(text: str, section, key: str, value: str) -> str:
    """`text` with one field's value replaced (the key is kept, so the field is present)."""
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


def values(policy: Policy) -> dict:
    out = dict(vars(policy))
    out.pop("base_dir")
    return out


class Fixture(unittest.TestCase):
    def setUp(self):
        self.ctx = TempDir()
        self.tmp = self.ctx.__enter__()
        self.path = self.tmp / "policy.yaml"
        self.no_gh = self.tmp / "no-gh"     # names no program: a policy that loaded by mistake calls nothing

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
        self.assertTrue(message.startswith(str(self.path)), message)
        for needle in needles:
            self.assertIn(needle, message)
        return message

    def commands(self):
        return (["verify", "release", "--policy", self.path, "--artifacts", self.path, "--gh", self.no_gh],
                ["verify", "agent-run", "--policy", self.path, "--proposal", self.tmp, "--snapshot", self.tmp,
                 "--bundle", self.path, "--gh", self.no_gh])

    def assert_cli_refuses(self, *needles: str) -> None:
        for command in self.commands():
            code, out, err = run_cli(*command)
            self.assertEqual(code, 2, err)
            self.assertTrue(err.startswith("error: "), err)
            self.assertNotIn("Traceback", err)
            self.assertEqual(out, "")
            for needle in needles:
                self.assertIn(needle, err)


class FullPolicyTest(Fixture):
    def test_every_field_of_a_sigstore_policy_is_read_as_written(self):
        p = self.load(FULL)
        self.assertEqual(values(p), FULL_VALUES)
        self.assertEqual(p.base_dir, self.tmp)
        for name, value in FULL_VALUES.items():
            with self.subTest(field=name):
                self.assertIs(type(getattr(p, name)), type(value))
                if isinstance(value, list):
                    self.assertTrue(all(type(item) is str for item in getattr(p, name)))

    def test_every_field_of_a_keys_policy_is_read_as_written(self):
        p = self.load(KEYS_FULL)
        self.assertEqual(p.keys, {"provenance": ["keys/p.pem"], "build_record": ["keys/b.pem", "keys/b2.pem"],
                                  "agent_run": ["keys/a.pem"], "approval": ["keys/r.pem"]})
        self.assertEqual(p.key_paths("build_record"), [self.tmp / "keys/b.pem", self.tmp / "keys/b2.pem"])
        self.assertEqual((p.signing, p.allowed_tiers, p.min_approvals), ("keys", ["A", "B"], 1))

    def test_the_shipped_policies_load_with_the_values_they_had(self):
        # The values the loader before this slice gave for each (checked by running it on `1676ecd`).
        own = {
            "repository": "Obaaf/OBAAF", "signing": "sigstore",
            "provenance_workflow": "Obaaf/OBAAF/.github/workflows/release-pypi.yml",
            "source_refs": ["refs/tags/v*"], "runner_environments": ["github-hosted"],
            "issuer": "https://token.actions.githubusercontent.com", "keys": {}, "allowed_tiers": ["A", "B"],
            "require_sdks": False, "release_environments": ["pypi"], "min_approvals": 1,
            "approver_not_actor": True, "release_branch": "main", "agents_check": True,
            "agents_since": "5162a177955b4f18ba190d048862e66246b4af05", "records_dir": ".obaaf/records",
            "propose_workflow": "Obaaf/OBAAF/.github/workflows/obaaf-agent-propose.yml",
            "apply_workflow": "Obaaf/OBAAF/.github/workflows/obaaf-agent-apply.yml",
            "agent_source_ref": "refs/heads/main", "effect_identities": ["obaaf-effect-lane"],
            "require_exact_diff": True, "allow_self_hosted_agents": False, "approvers": [], "jenkins_project": "",
        }
        github = dict(own, repository="studio/game",
                      provenance_workflow="studio/game/.github/workflows/obaaf-release.yml", runner_environments=[],
                      require_sdks=True, release_environments=["release"], agents_since=None,
                      propose_workflow="studio/game/.github/workflows/obaaf-agent-propose.yml",
                      apply_workflow="studio/game/.github/workflows/obaaf-agent-apply.yml")
        jenkins = dict(github, signing="keys", source_refs=[],
                       keys={"provenance": ["keys/release.pub.pem"], "build_record": ["keys/release.pub.pem"]},
                       approvers=["release-manager-1", "release-manager-2"], jenkins_project="releases/game-tags")
        cases = {
            ".github/obaaf-policy.yaml": (ROOT / ".github" / "obaaf-policy.yaml", own),
            "github-actions example": (ROOT / "templates" / "github-actions" / "obaaf-policy.example.yaml", github),
            "jenkins example": (ROOT / "templates" / "jenkins" / "obaaf-policy.example.yaml", jenkins),
        }
        for name, (path, expected) in cases.items():
            with self.subTest(policy=name):
                text = path.read_text(encoding="utf-8").replace("OWNER/REPO", "studio/game")
                self.assertEqual(values(self.load(text)), expected)

    def test_the_defaults_when_a_section_is_absent_or_empty(self):
        minimal = "format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: sigstore\n" \
                  "provenance: {source_refs: ['refs/tags/v*']}\n"
        for extra in ("", "release:\nagents:\nbuild_record:\n", "release: {}\nagents: {}\nbuild_record: {}\n",
                      "release:\n  # min_approvals: 2\n"):
            with self.subTest(extra=extra):
                p = self.load(minimal + extra)
                self.assertEqual((p.min_approvals, p.release_branch, p.release_environments), (1, "main", ["release"]))
                self.assertEqual((p.allowed_tiers, p.require_sdks, p.approvers), (["A", "B"], True, []))
                self.assertEqual((p.agents_check, p.allow_self_hosted_agents, p.require_exact_diff), (True, False, True))
                self.assertEqual(p.effect_identities, ["obaaf-effect-lane"])

    def test_an_empty_text_keeps_its_old_meaning(self):
        # `branch: ""` turns the protected-branch check off (documented); `since: ""` means not set; the
        # other text fields with a default give it.
        text = FULL
        for section, key in (("release", "branch"), ("agents", "since"), ("provenance", "signer_workflow"),
                             ("provenance", "issuer"), ("agents", "records_dir"), ("agents", "propose_workflow"),
                             ("agents", "apply_workflow"), ("agents", "source_ref"), ("release", "jenkins_project")):
            text = set_field(text, section, key, "''")
        p = self.load(text)
        self.assertEqual((p.release_branch, p.agents_since, p.jenkins_project), ("", None, ""))
        self.assertEqual((p.provenance_workflow, p.issuer, p.records_dir), (
            "studio/game/.github/workflows/obaaf-release.yml", "https://token.actions.githubusercontent.com",
            ".obaaf/records"))
        self.assertEqual((p.propose_workflow, p.apply_workflow, p.agent_source_ref), (
            "studio/game/.github/workflows/obaaf-agent-propose.yml",
            "studio/game/.github/workflows/obaaf-agent-apply.yml", "refs/heads/main"))

    def test_the_singular_environment_is_still_read(self):
        text = FULL.replace("  environments: [release-check, release]\n", "  environment: pypi\n")
        self.assertEqual(self.load(text).release_environments, ["pypi"])
        text = FULL.replace("  environments: [release-check, release]\n", "  environment: ''\n")
        self.assertEqual(self.load(text).release_environments, ["release"])

    def test_anchors_and_merge_keys_are_read_as_yaml_reads_them(self):
        text = FULL.replace("  approvers: [carol, dave]", "  approvers: &people [carol, dave]")
        text = text.replace("  effect_identities: [obaaf-effect-lane, release-bot]", "  effect_identities: *people")
        self.assertEqual(self.load(text).effect_identities, ["carol", "dave"])
        # A key merged in and also written is a duplicate, as OBAAF's reader has it for workflows too.
        self.refused(FULL.replace("release:\n", "release:\n  <<: {min_approvals: 3}\n"),
                     "duplicate key 'min_approvals'")
        # A mapping kept at the top level only to be merged is a key the policy does not read.
        self.refused(FULL + "defaults: &d {min_approvals: 3}\n", "unknown key 'defaults'")
        text = FULL.replace("release:\n  branch: release\n", "release:\n  <<: {branch: release}\n")
        self.assertEqual(self.load(text).release_branch, "release")
        self.refused(FULL.replace("release:\n", "release:\n  <<: {min_aprovals: 3}\n"), "'min_aprovals' in release")


class EveryFieldTest(Fixture):
    """For every field and every kind of YAML value: the field's own kind loads, any other is refused."""

    def test_each_field_refuses_every_value_of_another_type(self):
        for section, key, kind in FIELDS:
            name = key if section is None else f"{section}.{key}"
            for sample, yaml_text in SAMPLES.items():
                with self.subTest(field=name, value=sample):
                    text = set_field(base_for(section, key), section, key, yaml_text)
                    if sample in YAML_REFUSED:
                        self.refused(text, "cannot be read as YAML", "line")
                    elif sample in ACCEPTS[kind] and (section, key) in RIGHT_TYPE_BUT:
                        self.refused(text, RIGHT_TYPE_BUT[(section, key)])
                    elif sample in ACCEPTS[kind]:
                        self.load(text)
                    else:
                        self.refused(text, name, "line")

    def test_the_commands_say_error_and_exit_2(self):
        for section, key, kind in FIELDS:
            if section is None:
                continue
            name = f"{section}.{key}"
            for sample in ("null", "float", "map", "list of int", "date", "binary", "empty list"):
                if sample in ACCEPTS[kind]:
                    continue
                with self.subTest(field=name, value=sample):
                    self.path.write_text(set_field(base_for(section, key), section, key, SAMPLES[sample]),
                                         encoding="utf-8")
                    self.assert_cli_refuses(name)

    def test_the_issue_example_min_approvals_null(self):
        # The command ended in a TypeError traceback before this slice.
        self.path.write_text(set_field(FULL, "release", "min_approvals", "null"), encoding="utf-8")
        self.assert_cli_refuses("release.min_approvals", "nothing (null)")


class FailOpenTest(Fixture):
    """The readings that let a release through which the policy's author meant to stop."""

    def test_source_refs_written_as_text(self):
        # Before: the patterns r, e, f, ..., *, and the pattern * allowed every ref.
        message = self.refused(set_field(FULL, "provenance", "source_refs", '"refs/tags/v*"'),
                               "provenance.source_refs", "a list")
        self.assertIn("refs/tags/v*", message)

    def test_self_hosted_agents_written_as_text(self):
        # Before: bool("false") and bool("no") are true.
        for value in ('"false"', "no", "off", "'0'", "0"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "agents", "allow_self_hosted_runners", value),
                             "agents.allow_self_hosted_runners", "true or false")

    def test_min_approvals_that_turned_the_check_off(self):
        # Before: int(0.5) and int(False) are 0, and 0 or less skips the approvals check.
        for value in ("0.5", "false", "-1"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "release", "min_approvals", value), "release.min_approvals",
                             "whole number, 0 or more")

    def test_min_approvals_of_another_type(self):
        for value in ("true", "1.9", "'2'", ".inf", ".nan", "-.inf", "1.0", "[2]"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "release", "min_approvals", value), "release.min_approvals")

    def test_min_approvals_not_in_plain_decimal(self):
        # PyYAML reads YAML 1.1's forms: 010 is 8, 0x10 is 16, 1:30 is 90, 1_0 is 10.
        for value in ("010", "0x10", "1:30", "1_0", "0b11", "!!int 010"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "release", "min_approvals", value), "plain decimal", "line 15")
        self.assertEqual(self.load(set_field(FULL, "release", "min_approvals", "0")).min_approvals, 0)
        self.assertEqual(self.load(set_field(FULL, "release", "min_approvals", "+3")).min_approvals, 3)

    def test_approvers_written_as_text(self):
        # Before: the logins a, l, i, c and e.
        self.refused(set_field(FULL, "release", "approvers", "alice"), "release.approvers", "a list")

    def test_an_empty_allow_list(self):
        # Before: [] was no restriction, the same as leaving the key out; the entries commented out of a
        # flow list give [] too.
        for section, key in (("release", "approvers"), ("provenance", "runner_environments")):
            with self.subTest(field=f"{section}.{key}"):
                self.refused(set_field(FULL, section, key, "[]"), f"{section}.{key}", "at least one",
                             "no restriction")
        self.refused(set_field(FULL, "release", "approvers", "[\n    # carol,\n  ]"), "release.approvers")

    def test_an_empty_list_the_verifier_needs_an_entry_of(self):
        # Before: an empty list was replaced by the default without a word.
        for section, key in (("build_record", "allowed_tiers"), ("release", "environments"),
                             ("agents", "effect_identities")):
            with self.subTest(field=f"{section}.{key}"):
                self.refused(set_field(FULL, section, key, "[]"), f"{section}.{key}", "at least one", "the default")
        # A list the policy needs an entry of: no hint to remove the key.
        for section, key, text in (("provenance", "source_refs", FULL), ("keys", "agent_run", KEYS_FULL),
                                   ("keys", "provenance", KEYS_FULL)):
            with self.subTest(field=f"{section}.{key}"):
                message = self.refused(set_field(text, section, key, "[]"), f"{section}.{key} must name at least "
                                       "one entry")
                self.assertNotIn("remove the key", message)

    def test_other_lists_written_as_text(self):
        for section, key, kind in FIELDS:
            if kind in (NAMES, TIERS):
                with self.subTest(field=f"{section}.{key}"):
                    self.refused(set_field(base_for(section, key), section, key, "AB"), f"{section}.{key}",
                                 "a list")

    def test_a_list_item_that_is_not_text(self):
        message = self.refused(set_field(FULL, "release", "approvers", "[carol, 7, dave]"),
                               "release.approvers[2]")
        self.assertIn("a whole number", message)

    def test_an_empty_text_in_a_list(self):
        for section, key, kind in FIELDS:
            if kind == NAMES:
                with self.subTest(field=f"{section}.{key}"):
                    self.refused(set_field(base_for(section, key), section, key, "[a, '']"), f"{section}.{key}[2]",
                                 "empty")

    def test_a_tier_other_than_a_or_b(self):
        for value in ("[C]", "[a]", "[A, ' B']", "[1]"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "build_record", "allowed_tiers", value), "build_record.allowed_tiers")

    def test_both_environment_and_environments(self):
        text = FULL.replace("  min_approvals: 2", "  environment: pypi\n  min_approvals: 2")
        self.refused(text, "write release.environments or release.environment, not both")

    def test_since_unquoted_digits_or_not_a_full_commit(self):
        for value in ("1234567890123456789012345678901234567890", "abc", "'0123'", "[a]"):
            with self.subTest(value=value):
                self.refused(set_field(FULL, "agents", "since", value), "agents.since")

    def test_a_key_the_chosen_signing_does_not_read(self):
        # Before: these loaded, and the verifier did not check them: with signing: keys it checks each
        # record's key only, so `source_refs` there looked like a check of the ref that was never made.
        for section, key, value in (("provenance", "source_refs", "['refs/tags/v*']"),
                                    ("provenance", "runner_environments", "[github-hosted]"),
                                    ("provenance", "issuer", "https://issuer.example"),
                                    ("provenance", "signer_workflow", "a/b/.github/workflows/x.yml"),
                                    ("agents", "propose_workflow", "a/b/.github/workflows/p.yml"),
                                    ("agents", "apply_workflow", "a/b/.github/workflows/a.yml"),
                                    ("agents", "source_ref", "refs/heads/main")):
            with self.subTest(field=f"{section}.{key}"):
                text = KEYS_FULL if section != "provenance" else KEYS_FULL + "provenance:\n"
                text = text.replace(f"{section}:\n", f"{section}:\n  {key}: {value}\n", 1)
                self.refused(text, f"{section}.{key} is not read with signing: keys", "line")
        message = self.refused(FULL + "keys:\n  provenance: [k.pem]\n", "keys is not read with signing: sigstore")
        self.assertIn(f"line {len(FULL.splitlines()) + 1}", message)
        # An empty `keys:` is read as absent, as any section with nothing under it.
        for empty in ("keys:\n", "keys: {}\n", "keys: null\n"):
            with self.subTest(keys=empty):
                self.assertEqual(self.load(FULL + empty).keys, {})
        # An empty provenance section is still allowed with signing: keys.
        self.assertEqual(self.load(KEYS_FULL + "provenance:\n").source_refs, [])


class KeysAndValuesTest(Fixture):
    def test_unknown_keys_at_each_level(self):
        cases = {
            "top": (FULL + "relase: {min_approvals: 2}\n", "'relase'"),
            "release": (FULL.replace("  min_approvals: 2", "  min_approvals: 2\n  min_aprovals: 3"),
                        "'min_aprovals' in release"),
            "agents": (FULL.replace("  check: false", "  check: false\n  allow_self_hosted_runner: false"),
                       "'allow_self_hosted_runner' in agents"),
            "provenance": (FULL.replace("  issuer:", "  source_ref: x\n  issuer:"), "'source_ref' in provenance"),
            "build_record": (FULL.replace("  require_sdks: false", "  require_sdks: false\n  tiers: [A]"),
                             "'tiers' in build_record"),
            "keys": (KEYS_FULL.replace("  approval: [keys/r.pem]", "  approval: [keys/r.pem]\n  agent-run: [x]"),
                     "'agent-run' in keys"),
            "number key": (FULL + "1: x\n", "unknown key 1;"),
            "null key": (FULL + "~: x\n", "unknown key null;"),
            "true key": (FULL + "true: x\n", "unknown key true;"),
            "look-alike": (FULL.replace("  branch: release", "  brаnch: release"), "'brаnch' in release"),
            "case": (FULL.replace("  branch: release", "  Branch: release"), "'Branch' in release"),
        }
        for name, (text, needle) in cases.items():
            with self.subTest(level=name):
                self.refused(text, needle, "unknown key", "line")

    def test_a_huge_number_as_a_key(self):
        # repr() of an int over 4,300 digits raises ValueError; the message gives no number.
        self.refused(FULL + "? " + "9" * 4200 + "\n: 1\n", "unknown key (a whole number too long to print);")
        self.refused(FULL + "? " + "9" * 4400 + "\n: 1\n", "cannot be read as YAML")

    def test_the_known_keys_are_named(self):
        message = self.refused(FULL.replace("  min_approvals: 2", "  min_approvals: 2\n  min_aprovals: 3"))
        self.assertIn("min_approvals", message.split("min_aprovals", 1)[1])

    def test_key_roles(self):
        self.assertEqual(KEY_ROLES, ("provenance", "build_record", "agent_run", "approval"))

    def test_format_repository_and_signing(self):
        for value in ("null", "[obaaf-policy/v0.1]", "1", "obaaf-policy/v0.2"):
            with self.subTest(format=value):
                self.refused(set_field(FULL, None, "format", value), FORMAT, "line 1")
        for value in ("null", "[studio/game]", "{studio: game/x}", "studio", "''", "1"):
            with self.subTest(repository=value):
                self.refused(set_field(FULL, None, "repository", value), "'repository' must be OWNER/REPO",
                             "line 2")
        for value in ("null", "[keys]", "true", "gpg", "''"):
            with self.subTest(signing=value):
                self.refused(set_field(FULL, None, "signing", value), "'signing' must be sigstore or keys", "line 3")

    def test_a_section_of_another_type(self):
        for section in ("provenance", "keys", "build_record", "release", "agents"):
            for value in ("[1]", "true", "x", "0", "''"):
                with self.subTest(section=section, value=value):
                    self.refused(set_field(base_for(None, section), None, section, value), section, "a mapping")

    def test_an_absent_section_names_no_line(self):
        message = self.refused("format: obaaf-policy/v0.1\nrepository: studio/game\n",
                               "provenance.source_refs is required")
        self.assertNotIn(", line", message)
        message = self.refused("format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: keys\n",
                               "signing: keys needs keys.provenance")
        self.assertNotIn(", line", message)

    def test_the_value_in_a_message_is_quoted_and_short(self):
        message = self.refused(set_field(FULL, "release", "min_approvals", "'" + "x" * 500 + "'"))
        self.assertIn("x" * 60 + "...", message)
        self.assertLess(len(message), len(str(self.path)) + 200)
        message = self.refused(set_field(FULL, "release", "min_approvals", '"\\u202e1\\x1b[31m"'))
        self.assertNotIn("‮", message)
        self.assertNotIn("\x1b", message)
        self.assertIn("\\u202e", message)


class UnreadableYamlTest(Fixture):
    def test_yaml_the_loader_refuses_is_a_policy_error(self):
        cases = {
            "syntax": FULL + "  bad: [\n",
            "duplicate key": FULL + "agents: {}\n",
            "two documents": FULL + "---\nformat: x\n",
            "tab indent": FULL.replace("  check: false", "\tcheck: false"),
            "null tag with text": FULL.replace("branch: release", "branch: !!null main"),
            "unknown tag": FULL.replace("branch: release", "branch: !!python/name:os.system ''"),
            "deep nesting": FULL.replace("  approvers: [carol, dave]", "  approvers: " + "[" * 5000 + "]" * 5000),
            "undefined alias": FULL.replace("  approvers: [carol, dave]", "  approvers: *nobody"),
            "int tag on text": FULL.replace("  min_approvals: 2", "  min_approvals: !!int ''"),
            "bool tag on text": FULL.replace("  check: false", "  check: !!bool maybe"),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.refused(text, "cannot be read as YAML")
                self.assert_cli_refuses(str(self.path))

    def test_the_yaml_error_is_printed_on_one_line_with_escapes(self):
        message = self.refused(FULL + "bad: [‮\n")
        self.assertNotIn("‮", message)
        self.assertNotIn("\n", message)

    def test_text_that_is_not_utf8(self):
        self.path.write_bytes(FULL.encode("utf-8") + b"# \xff\n")
        with self.assertRaises(PolicyError) as ctx:
            Policy.load(self.path)
        self.assertIn("is not UTF-8 text", str(ctx.exception))
        self.assert_cli_refuses("UTF-8")

    def test_an_empty_or_comment_only_file(self):
        for text in ("", "# a policy\n", "﻿# a policy\n", "---\n"):
            with self.subTest(text=text):
                self.refused(text, f"expected 'format: {FORMAT}'")

    def test_a_missing_file_is_still_an_os_error(self):
        with self.assertRaises(OSError):
            Policy.load(self.tmp / "missing.yaml")


class RandomValuesTest(Fixture):
    """Any one field given any value: either a PolicyError, or the field holds exactly what was written."""

    def test_random_values_are_refused_or_kept_exactly(self):
        rng = random.Random(395)
        atoms = list(SAMPLES.values()) + ["'refs/tags/v*'", "A", "B", "[A]", "[B, A]", "[x, y]", "2", "40",
                                          f"'{SHA}'", "*a", "&a [x]"]
        attribute = {("release", "min_approvals"): "min_approvals", ("agents", "allow_self_hosted_runners"):
                     "allow_self_hosted_agents", ("provenance", "source_refs"): "source_refs",
                     ("release", "approvers"): "approvers", ("build_record", "require_sdks"): "require_sdks",
                     ("release", "approver_not_actor"): "approver_not_actor", ("agents", "check"): "agents_check",
                     ("agents", "require_exact_diff"): "require_exact_diff",
                     ("provenance", "runner_environments"): "runner_environments",
                     ("build_record", "allowed_tiers"): "allowed_tiers", ("release", "branch"): "release_branch",
                     ("agents", "effect_identities"): "effect_identities"}
        loaded = 0
        for _ in range(1500):
            section, key, kind = rng.choice([f for f in FIELDS if f[0] is not None])
            value = rng.choice(atoms)
            if rng.random() < 0.3:
                value = "[" + ", ".join(rng.choice(atoms[:20] + ["a", "b"]) for _ in range(rng.randint(0, 3))) + "]"
            text = set_field(base_for(section, key), section, key, value)
            self.path.write_text(text, encoding="utf-8")
            try:
                parsed = policy_module._read(self.path)
            except PolicyError:
                continue        # the loader refused the YAML itself
            written = parsed[section][key]
            try:
                policy = Policy.load(self.path)
            except PolicyError as exc:
                self.assertIn(f"{section}.{key}", str(exc), (value, str(exc)))
                continue
            loaded += 1
            name = attribute.get((section, key))
            if name is None:
                continue
            got = getattr(policy, name)
            self.assertEqual(type(got), list if isinstance(written, list) else type(written), (section, key, value))
            self.assertEqual(got, written, (section, key, value))
        self.assertGreater(loaded, 100)


if __name__ == "__main__":
    unittest.main()
