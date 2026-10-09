"""FR5: record how every release was built.

Acceptance criterion: each release artifact carries signed provenance naming
its source revision, asset revision, manifest digest, SDK versions, build
workflow and builder; verification fails for a modified artifact.
"""

import json
import unittest

from helpers import TEMPLATES, TempDir, make_key, run_cli, sign, write_json

from obaaf.attest import manifest, records
from obaaf.attest.common import sha256_file, statement, validate_predicate
from obaaf.predicates import BUILD_RECORD, SLSA_PROVENANCE_V1
from obaaf.verify import release
from obaaf.verify.policy import Policy

SOURCES = """
components:
  - id: engine
    name: Example engine
    version: "5.4.1"
    source: Vendor portal
    kind: engine
    paths: ["Engine/**"]
  - id: analytics
    name: Example analytics SDK
    version: "2.0.0"
    source: Vendor archive
    kind: sdk
    paths: ["ThirdParty/Analytics/**"]
"""


def make_project(root):
    (root / "Engine").mkdir(parents=True)
    (root / "Engine" / "engine.dll").write_bytes(b"engine-binary")
    (root / "ThirdParty" / "Analytics").mkdir(parents=True)
    (root / "ThirdParty" / "Analytics" / "analytics.dll").write_bytes(b"sdk-binary")
    (root / "obaaf-sources.yaml").write_text(SOURCES, encoding="utf-8")
    data = manifest.create(root, root / "obaaf-sources.yaml")
    manifest.write(data, root / "obaaf-manifest.json")
    (root / "dist").mkdir()
    (root / "dist" / "Game-win64.zip").write_bytes(b"release build, windows")
    (root / "dist" / "Game-linux.tar.gz").write_bytes(b"release build, linux")
    return root


def build_record(root):
    return records.build_record_predicate(
        [root / "dist"], source_revision="a" * 40, source_ref="refs/tags/v1.0.0", repository="studio/game",
        asset_revision="a" * 40, asset_system="git", manifest_path=root / "obaaf-manifest.json",
        builder_id="https://github.com/studio/game/.github/workflows/obaaf-release.yml",
        workflow_file=TEMPLATES / "workflows" / "obaaf-release.yml", build_job="build", trigger_actor="releaser")


class BuildRecordTest(unittest.TestCase):
    def test_record_names_everything_fr5_requires(self):
        with TempDir() as tmp:
            root = make_project(tmp)
            subjects, pred = build_record(root)
            self.assertEqual(validate_predicate(BUILD_RECORD, pred), [])
            self.assertEqual(pred["source"]["revision"], "a" * 40)
            self.assertEqual(pred["assets"]["revision"], "a" * 40)
            self.assertEqual(pred["manifest"]["digest"]["sha256"], sha256_file(root / "obaaf-manifest.json"))
            self.assertEqual({(s["name"], s["version"]) for s in pred["sdks"]},
                             {("Example engine", "5.4.1"), ("Example analytics SDK", "2.0.0")})
            self.assertIn("obaaf-release.yml", pred["builder"]["id"])
            self.assertEqual(pred["isolation"]["tier"], "A")
            self.assertEqual({s["name"] for s in subjects}, {"Game-win64.zip", "Game-linux.tar.gz"})

    def test_cli_writes_a_schema_valid_record(self):
        with TempDir() as tmp:
            root = make_project(tmp)
            out = tmp / "record.json"
            code, stdout, err = run_cli(
                "attest", "build-record", "--artifact", root / "dist", "--source-revision", "b" * 40,
                "--asset-revision", "CL-12345", "--asset-system", "perforce", "--manifest", root / "obaaf-manifest.json",
                "--builder-id", "https://example.invalid/builder", "--workflow-file",
                TEMPLATES / "workflows" / "obaaf-release.yml", "--out", out, "--statement-out", tmp / "stmt.json")
            self.assertEqual(code, 0, err)
            pred = json.loads(out.read_text())
            self.assertEqual(pred["assets"], {"revision": "CL-12345", "system": "perforce", "reportedBy": "build job"})
            stmt = json.loads((tmp / "stmt.json").read_text())
            self.assertEqual(stmt["predicateType"], BUILD_RECORD)

    def test_invalid_records_fail_the_schema(self):
        with TempDir() as tmp:
            root = make_project(tmp)
            _, pred = build_record(root)
            del pred["manifest"]
            self.assertTrue(validate_predicate(BUILD_RECORD, pred))


class ManifestTest(unittest.TestCase):
    def test_manifest_check_catches_changed_new_and_missing_files(self):
        with TempDir() as tmp:
            root = make_project(tmp)
            data = manifest.load(root / "obaaf-manifest.json")
            self.assertEqual(manifest.check(root, data), [])
            (root / "Engine" / "engine.dll").write_bytes(b"engine-binary-tampered")
            (root / "ThirdParty" / "Analytics" / "extra.dll").write_bytes(b"new")
            (root / "ThirdParty" / "Analytics" / "analytics.dll").unlink()
            problems = manifest.check(root, data)
            kinds = sorted(p.split(":")[0] for p in problems)
            self.assertEqual(kinds, ["changed", "missing", "unrecorded"])
            code, out, _ = run_cli("manifest", "check", "--manifest", root / "obaaf-manifest.json", "--root", root)
            self.assertEqual(code, 1)
            self.assertIn("FAILED", out)


    def test_manifest_check_catches_symbolic_links(self):
        import os

        with TempDir() as tmp:
            root = make_project(tmp)
            data = manifest.load(root / "obaaf-manifest.json")
            # A file replaced by a link to somewhere else, and a new link, are both changes.
            (root / "Engine" / "engine.dll").unlink()
            os.symlink("/tmp/elsewhere.dll", root / "Engine" / "engine.dll")
            os.symlink("analytics.dll", root / "ThirdParty" / "Analytics" / "alias.dll")
            problems = manifest.check(root, data)
            self.assertIn("changed: Engine/engine.dll is now a symbolic link", problems)
            self.assertTrue(any(p.startswith("unrecorded: ThirdParty/Analytics/alias.dll") for p in problems))
            # Links recorded in the manifest are checked by target.
            relinked = manifest.create(root, root / "obaaf-sources.yaml")
            entry = next(e for e in relinked["entries"] if e["path"] == "Engine/engine.dll")
            self.assertEqual(entry["symlink"], "/tmp/elsewhere.dll")
            (root / "Engine" / "engine.dll").unlink()
            os.symlink("/tmp/other.dll", root / "Engine" / "engine.dll")
            self.assertTrue(any("now links to '/tmp/other.dll'" in p for p in manifest.check(root, relinked)))


class ModifiedArtifactFailsVerificationTest(unittest.TestCase):
    def test_signed_provenance_does_not_cover_a_modified_artifact(self):
        with TempDir() as tmp:
            root = make_project(tmp)
            key, pub = make_key(tmp, "release")
            subjects, pred = build_record(root)
            slsa = records.slsa_provenance_predicate(builder_id="https://example.invalid/builder",
                                                     repository_uri="https://github.com/studio/game",
                                                     source_revision="a" * 40)
            envs = [sign(statement(subjects, SLSA_PROVENANCE_V1, slsa), key),
                    sign(statement(subjects, BUILD_RECORD, pred), key)]
            write_json(tmp / "attestations.json", envs)
            policy_path = tmp / "policy.yaml"
            policy_path.write_text(
                "format: obaaf-policy/v0.1\nrepository: studio/game\nsigning: keys\n"
                f"keys: {{provenance: [{pub.name}], build_record: [{pub.name}]}}\n"
                "release: {min_approvals: 0, branch: ''}\nagents: {check: false}\n", encoding="utf-8")
            policy = Policy.load(policy_path)
            ok = release.verify_release(policy, [root / "dist"], dsse_files=[tmp / "attestations.json"])
            self.assertTrue(ok.ok, ok.blocks)
            (root / "dist" / "Game-win64.zip").write_bytes(b"release build, windows, with a backdoor")
            bad = release.verify_release(policy, [root / "dist"], dsse_files=[tmp / "attestations.json"])
            self.assertFalse(bad.ok)
            self.assertTrue(any("Game-win64.zip: no verified SLSA provenance" in b for b in bad.blocks))


if __name__ == "__main__":
    unittest.main()
