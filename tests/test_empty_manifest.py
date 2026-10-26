"""Empty / no-vendored-binaries manifests (G2.1) and require_sdks policy gating."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from helpers import TEMPLATES, TempDir, make_key, run_cli, sign, write_json

from obaaf.attest import manifest, records
from obaaf.attest.common import RecordError, sha256_file, statement, validate_predicate
from obaaf.predicates import BUILD_RECORD, SLSA_PROVENANCE_V1
from obaaf.verify import release
from obaaf.verify.policy import Policy

FIXED_NOW = "2026-01-01T00:00:00Z"
NONE_SOURCES = "vendored_binaries: none\n"


def write_none_sources(root, name="obaaf-sources.yaml"):
    path = root / name
    path.write_text(NONE_SOURCES, encoding="utf-8")
    return path


def create_none_manifest(root, sources=None):
    sources = sources or write_none_sources(root)
    with mock.patch("obaaf.attest.manifest.now", return_value=FIXED_NOW):
        data = manifest.create(root, sources)
    manifest.write(data, root / "obaaf-manifest.json")
    return data


def populated_dist(root):
    (root / "dist").mkdir(exist_ok=True)
    (root / "dist" / "pkg.whl").write_bytes(b"release wheel")
    return root / "dist"


class EmptyManifestCreateTest(unittest.TestCase):
    def test_create_writes_none_claim_and_empty_lists(self):
        with TempDir() as tmp:
            data = create_none_manifest(tmp)
            self.assertEqual(data["format"], manifest.FORMAT)
            self.assertEqual(data["vendoredBinaries"], "none")
            self.assertEqual(data["components"], [])
            self.assertEqual(data["entries"], [])
            self.assertEqual(data["createdAt"], FIXED_NOW)
            loaded = manifest.load(tmp / "obaaf-manifest.json")
            self.assertEqual(loaded["vendoredBinaries"], "none")

    def test_create_succeeds_when_tree_has_untracked_binaries(self):
        with TempDir() as tmp:
            (tmp / "ThirdParty").mkdir()
            (tmp / "ThirdParty" / "sneaky.dll").write_bytes(b"not tracked")
            data = create_none_manifest(tmp)
            self.assertEqual(data["entries"], [])

    def test_cli_create_and_check_none(self):
        with TempDir() as tmp:
            write_none_sources(tmp)
            out = tmp / "obaaf-manifest.json"
            with mock.patch("obaaf.attest.manifest.now", return_value=FIXED_NOW):
                code, stdout, err = run_cli(
                    "manifest", "create", "--components", tmp / "obaaf-sources.yaml",
                    "--root", tmp, "--out", out)
            self.assertEqual(code, 0, err)
            self.assertIn("vendoredBinaries: none", stdout)
            self.assertIn("0 file(s) in 0 component(s)", stdout)
            code, stdout, err = run_cli("manifest", "check", "--manifest", out, "--root", tmp)
            self.assertEqual(code, 0, err)
            self.assertIn("vendoredBinaries: none", stdout)


class EmptyManifestFailClosedTest(unittest.TestCase):
    def test_empty_components_without_declaration_fails(self):
        with TempDir() as tmp:
            (tmp / "sources.yaml").write_text("components: []\n", encoding="utf-8")
            with self.assertRaises(RecordError) as ctx:
                manifest.create(tmp, tmp / "sources.yaml")
            self.assertIn("declare components or set vendored_binaries: none", str(ctx.exception))

    def test_missing_components_without_declaration_fails(self):
        with TempDir() as tmp:
            (tmp / "sources.yaml").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(RecordError) as ctx:
                manifest.create(tmp, tmp / "sources.yaml")
            self.assertIn("declare components or set vendored_binaries: none", str(ctx.exception))

    def test_none_plus_components_fails(self):
        with TempDir() as tmp:
            (tmp / "sources.yaml").write_text(
                "vendored_binaries: none\n"
                "components:\n"
                "  - id: x\n    name: X\n    version: '1'\n    source: s\n    kind: sdk\n"
                "    paths: ['X/**']\n",
                encoding="utf-8")
            with self.assertRaises(RecordError) as ctx:
                manifest.create(tmp, tmp / "sources.yaml")
            self.assertIn("cannot be combined with components", str(ctx.exception))

    def test_invalid_vendored_values_fail(self):
        cases = [
            "vendored_binaries: true\n",
            "vendored_binaries: false\n",
            "vendored_binaries: no\n",
            "vendored_binaries: ''\n",
            "vendored_binaries: absent\n",
            "vendored_binaries: null\n",
        ]
        for text in cases:
            with self.subTest(text=text.strip()):
                with TempDir() as tmp:
                    (tmp / "sources.yaml").write_text(text, encoding="utf-8")
                    with self.assertRaises(RecordError):
                        manifest.create(tmp, tmp / "sources.yaml")

    def test_load_rejects_empty_without_claim(self):
        with TempDir() as tmp:
            path = tmp / "obaaf-manifest.json"
            write_json(path, {"format": manifest.FORMAT, "createdAt": FIXED_NOW,
                              "components": [], "entries": []})
            with self.assertRaises(RecordError) as ctx:
                manifest.load(path)
            self.assertIn("vendoredBinaries", str(ctx.exception))

    def test_load_rejects_none_claim_with_entries(self):
        with TempDir() as tmp:
            path = tmp / "obaaf-manifest.json"
            write_json(path, {
                "format": manifest.FORMAT, "createdAt": FIXED_NOW, "vendoredBinaries": "none",
                "components": [], "entries": [{"path": "x", "sha256": "a" * 64, "size": 1, "component": "x"}],
            })
            with self.assertRaises(RecordError) as ctx:
                manifest.load(path)
            self.assertIn("empty components and entries", str(ctx.exception))

    def test_load_rejects_none_claim_with_components(self):
        with TempDir() as tmp:
            path = tmp / "obaaf-manifest.json"
            write_json(path, {
                "format": manifest.FORMAT, "createdAt": FIXED_NOW, "vendoredBinaries": "none",
                "components": [{"id": "x", "name": "X", "version": "1", "source": "s",
                                "kind": "sdk", "paths": ["X/**"]}],
                "entries": [],
            })
            with self.assertRaises(RecordError) as ctx:
                manifest.load(path)
            self.assertIn("empty components and entries", str(ctx.exception))

    def test_load_rejects_entries_without_components(self):
        with TempDir() as tmp:
            path = tmp / "obaaf-manifest.json"
            write_json(path, {
                "format": manifest.FORMAT, "createdAt": FIXED_NOW,
                "components": [],
                "entries": [{"path": "x", "sha256": "a" * 64, "size": 1, "component": "x"}],
            })
            with self.assertRaises(RecordError) as ctx:
                manifest.load(path)
            self.assertIn("entries without components", str(ctx.exception))

    def test_load_rejects_unknown_vendored_field(self):
        with TempDir() as tmp:
            path = tmp / "obaaf-manifest.json"
            write_json(path, {
                "format": manifest.FORMAT, "createdAt": FIXED_NOW, "vendoredBinaries": "maybe",
                "components": [{"id": "x", "name": "X", "version": "1", "source": "s",
                                "kind": "sdk", "paths": ["X/**"]}],
                "entries": [{"path": "X/a", "sha256": "a" * 64, "size": 1, "component": "x"}],
            })
            with self.assertRaises(RecordError) as ctx:
                manifest.load(path)
            self.assertIn("unknown vendoredBinaries", str(ctx.exception))

    def test_sources_drift_does_not_fail_disk_check_but_fails_sources_match(self):
        # Disk check ignores sources; --sources / sources_match catches declaration drift.
        with TempDir() as tmp:
            create_none_manifest(tmp)
            (tmp / "obaaf-sources.yaml").write_text(
                "components:\n"
                "  - id: later\n    name: Later\n    version: '1'\n    source: s\n    kind: sdk\n"
                "    paths: ['Later/**']\n",
                encoding="utf-8")
            (tmp / "Later").mkdir()
            (tmp / "Later" / "x.dll").write_bytes(b"x")
            data = manifest.load(tmp / "obaaf-manifest.json")
            self.assertEqual(manifest.check(tmp, data), [])
            drift = manifest.sources_match(tmp / "obaaf-sources.yaml", data)
            self.assertTrue(any("vendoredBinaries: none" in p for p in drift))
            code, out, err = run_cli(
                "manifest", "check", "--manifest", tmp / "obaaf-manifest.json",
                "--root", tmp, "--sources", tmp / "obaaf-sources.yaml")
            self.assertEqual(code, 1)
            self.assertIn("vendoredBinaries: none", out + err)

    def test_cli_rejects_empty_sources_without_declaration(self):
        with TempDir() as tmp:
            (tmp / "sources.yaml").write_text("components: []\n", encoding="utf-8")
            code, _, err = run_cli(
                "manifest", "create", "--components", tmp / "sources.yaml",
                "--root", tmp, "--out", tmp / "out.json")
            self.assertEqual(code, 1)
            self.assertIn("declare components or set vendored_binaries: none", err)

    def test_none_with_empty_components_list_creates(self):
        with TempDir() as tmp:
            (tmp / "sources.yaml").write_text("vendored_binaries: none\ncomponents: []\n", encoding="utf-8")
            with mock.patch("obaaf.attest.manifest.now", return_value=FIXED_NOW):
                data = manifest.create(tmp, tmp / "sources.yaml")
            self.assertEqual(data["vendoredBinaries"], "none")
            self.assertEqual(data["components"], [])


class EmptyBuildRecordTest(unittest.TestCase):
    def test_build_record_with_empty_manifest(self):
        with TempDir() as tmp:
            create_none_manifest(tmp)
            populated_dist(tmp)
            subjects, pred = records.build_record_predicate(
                [tmp / "dist"], source_revision="a" * 40, source_ref="refs/tags/v1.0.0",
                repository="studio/tools", asset_revision="a" * 40, asset_system="git",
                manifest_path=tmp / "obaaf-manifest.json",
                builder_id="https://github.com/studio/tools/.github/workflows/obaaf-release.yml",
                workflow_file=TEMPLATES / "workflows" / "obaaf-release.yml", build_job="build")
            self.assertEqual(validate_predicate(BUILD_RECORD, pred), [])
            self.assertEqual(pred["manifest"]["entries"], 0)
            self.assertEqual(pred["manifest"]["components"], 0)
            self.assertEqual(pred["sdks"], [])
            self.assertEqual(pred["manifest"]["digest"]["sha256"],
                             sha256_file(tmp / "obaaf-manifest.json"))
            self.assertEqual({s["name"] for s in subjects}, {"pkg.whl"})

    def test_cli_attest_build_record_empty(self):
        with TempDir() as tmp:
            create_none_manifest(tmp)
            populated_dist(tmp)
            out = tmp / "record.json"
            code, _, err = run_cli(
                "attest", "build-record", "--artifact", tmp / "dist",
                "--source-revision", "b" * 40, "--asset-revision", "b" * 40,
                "--manifest", tmp / "obaaf-manifest.json",
                "--builder-id", "https://example.invalid/builder",
                "--workflow-file", TEMPLATES / "workflows" / "obaaf-release.yml",
                "--out", out)
            self.assertEqual(code, 0, err)
            pred = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(pred["sdks"], [])
            self.assertEqual(pred["manifest"]["entries"], 0)

    def test_extra_sdk_with_empty_manifest(self):
        with TempDir() as tmp:
            create_none_manifest(tmp)
            populated_dist(tmp)
            _, pred = records.build_record_predicate(
                [tmp / "dist"], source_revision="a" * 40, asset_revision="a" * 40,
                manifest_path=tmp / "obaaf-manifest.json",
                builder_id="https://example.invalid/builder",
                workflow_file=TEMPLATES / "workflows" / "obaaf-release.yml",
                extra_sdks=[("Toolchain", "1.0")])
            self.assertEqual(pred["sdks"],
                             [{"name": "Toolchain", "version": "1.0", "reportedBy": "build job"}])


class RequireSdksPolicyTest(unittest.TestCase):
    def _signed_empty_release(self, tmp, *, extra_sdks=None):
        create_none_manifest(tmp)
        populated_dist(tmp)
        key, pub = make_key(tmp, "release")
        subjects, pred = records.build_record_predicate(
            [tmp / "dist"], source_revision="a" * 40, asset_revision="a" * 40,
            repository="studio/tools", manifest_path=tmp / "obaaf-manifest.json",
            builder_id="https://example.invalid/builder",
            workflow_file=TEMPLATES / "workflows" / "obaaf-release.yml",
            extra_sdks=extra_sdks)
        slsa = records.slsa_provenance_predicate(
            builder_id="https://example.invalid/builder",
            repository_uri="https://github.com/studio/tools", source_revision="a" * 40)
        envs = [sign(statement(subjects, SLSA_PROVENANCE_V1, slsa), key),
                sign(statement(subjects, BUILD_RECORD, pred), key)]
        write_json(tmp / "attestations.json", envs)
        return pub

    def _policy(self, tmp, pub, *, require_sdks: bool) -> Policy:
        path = tmp / "policy.yaml"
        path.write_text(
            "format: obaaf-policy/v0.1\nrepository: studio/tools\nsigning: keys\n"
            f"keys: {{provenance: [{pub.name}], build_record: [{pub.name}]}}\n"
            f"build_record: {{require_sdks: {str(require_sdks).lower()}}}\n"
            "release: {min_approvals: 0, branch: ''}\nagents: {check: false}\n",
            encoding="utf-8")
        return Policy.load(path)

    def test_require_sdks_true_blocks_empty_sdks(self):
        with TempDir() as tmp:
            pub = self._signed_empty_release(tmp)
            decision = release.verify_release(
                self._policy(tmp, pub, require_sdks=True), [tmp / "dist"],
                dsse_files=[tmp / "attestations.json"])
            self.assertFalse(decision.ok)
            self.assertTrue(any("lists no SDK versions" in b for b in decision.blocks))

    def test_require_sdks_false_allows_empty_sdks(self):
        with TempDir() as tmp:
            pub = self._signed_empty_release(tmp)
            decision = release.verify_release(
                self._policy(tmp, pub, require_sdks=False), [tmp / "dist"],
                dsse_files=[tmp / "attestations.json"])
            self.assertTrue(decision.ok, decision.blocks)

    def test_require_sdks_true_allows_extra_sdk(self):
        with TempDir() as tmp:
            pub = self._signed_empty_release(tmp, extra_sdks=[("Toolchain", "1.0")])
            decision = release.verify_release(
                self._policy(tmp, pub, require_sdks=True), [tmp / "dist"],
                dsse_files=[tmp / "attestations.json"])
            self.assertTrue(decision.ok, decision.blocks)

    def test_policy_default_require_sdks_is_true(self):
        with TempDir() as tmp:
            path = tmp / "policy.yaml"
            path.write_text(
                "format: obaaf-policy/v0.1\nrepository: studio/tools\nsigning: keys\n"
                "keys: {provenance: [a.pem], build_record: [a.pem]}\n"
                "provenance: {source_refs: ['refs/tags/v*']}\n"
                "release: {min_approvals: 0, branch: ''}\nagents: {check: false}\n",
                encoding="utf-8")
            # Policy.load requires key files to exist for signing: keys — write stubs.
            (tmp / "a.pem").write_text("x", encoding="utf-8")
            # Re-write without keys mode issue: use sigstore-shaped policy without loading keys.
            path.write_text(
                "format: obaaf-policy/v0.1\nrepository: studio/tools\nsigning: sigstore\n"
                "provenance: {signer_workflow: studio/tools/.github/workflows/r.yml, "
                "source_refs: ['refs/tags/v*']}\n"
                "release: {min_approvals: 0, branch: ''}\nagents: {check: false}\n",
                encoding="utf-8")
            self.assertTrue(Policy.load(path).require_sdks)


class CommittedEmptyManifestTest(unittest.TestCase):
    def test_repo_dogfood_manifest_matches_frozen_create(self):
        import subprocess
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        sources = root / "obaaf-sources.yaml"
        committed = root / "obaaf-manifest.json"
        for rel in ("obaaf-sources.yaml", "obaaf-manifest.json", "tests/test_empty_manifest.py"):
            tracked = subprocess.run(
                ["git", "-C", str(root), "ls-files", "--error-unmatch", rel],
                capture_output=True, check=False)
            self.assertEqual(tracked.returncode, 0, f"{rel} must be tracked in git for dogfood/CI")
        self.assertEqual(sources.read_text(encoding="utf-8").strip(), "vendored_binaries: none")
        expected = {
            "format": manifest.FORMAT,
            "createdAt": FIXED_NOW,
            "vendoredBinaries": "none",
            "components": [],
            "entries": [],
        }
        with mock.patch("obaaf.attest.manifest.now", return_value=FIXED_NOW):
            created = manifest.create(root, sources)
        self.assertEqual(created, expected)
        self.assertEqual(manifest.load(committed), expected)
        self.assertEqual(manifest.check(root, manifest.load(committed)), [])
        self.assertEqual(manifest.sources_match(sources, manifest.load(committed)), [])


if __name__ == "__main__":
    unittest.main()
