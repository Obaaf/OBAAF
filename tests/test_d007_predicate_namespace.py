"""D-007: OBAAF's type URIs live under the project's domain and resolve to published pages.

Every predicate type and the generic build type use https://www.obaaf.com/, the
templates sign with exactly those types, each schema's $id matches the URL the site
serves it at, and the site build publishes a page behind every type URI.
"""

import json
import re
import subprocess
import sys
import unittest

from helpers import ROOT, TempDir

from obaaf import predicates
from obaaf.attest import records
from obaaf.catalog import data_text

LIVE_DIRS = ("src", "templates", "actions", "site")


class NamespaceTest(unittest.TestCase):
    def test_every_obaaf_type_is_under_the_project_domain(self):
        for uri in [*predicates.OBAAF_TYPES.values(), predicates.GENERIC_BUILD_TYPE, *predicates.SCHEMA_ID.values()]:
            with self.subTest(uri=uri):
                self.assertTrue(uri.startswith("https://www.obaaf.com/"), uri)

    def test_build_record_module_uses_the_shared_build_type(self):
        self.assertEqual(records.GENERIC_BUILD_TYPE, predicates.GENERIC_BUILD_TYPE)

    def test_no_placeholder_domain_in_live_code_or_templates(self):
        offenders = []
        for folder in LIVE_DIRS:
            for path in (ROOT / folder).rglob("*"):
                if not path.is_file() or "_site" in path.parts or path.suffix in (".png", ".svg", ".pyc"):
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
                for line in text.splitlines():
                    # The predicates docstring records the 0.1 history; that is the one allowed mention.
                    if "obaaf.example" in line and path.name != "predicates.py":
                        offenders.append(f"{path.relative_to(ROOT)}: {line.strip()}")
        self.assertEqual(offenders, [])

    def test_templates_sign_with_the_current_types(self):
        found = set()
        for path in (ROOT / "templates").rglob("*.yml"):
            found.update(re.findall(r"predicate-type:\s*(\S+)", path.read_text(encoding="utf-8")))
        obaaf_types = {t for t in found if "obaaf" in t}
        self.assertTrue(obaaf_types)
        self.assertLessEqual(obaaf_types, set(predicates.OBAAF_TYPES.values()))

    def test_schema_ids_match_their_published_urls(self):
        for uri, rel in predicates.SCHEMA_FOR_TYPE.items():
            with self.subTest(uri=uri):
                self.assertEqual(json.loads(data_text(rel))["$id"], predicates.SCHEMA_ID[uri])


class PublishedPagesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TempDir()
        cls.out = cls.tmp.__enter__() / "site"
        subprocess.run([sys.executable, str(ROOT / "site" / "build.py"), "--output", str(cls.out)],
                       check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.__exit__(None, None, None)

    def _local(self, uri):
        return self.out / uri.removeprefix(predicates.NAMESPACE + "/")

    def test_every_type_uri_has_a_page_that_names_it(self):
        for uri in [*predicates.OBAAF_TYPES.values(), predicates.GENERIC_BUILD_TYPE]:
            with self.subTest(uri=uri):
                page = self._local(uri) / "index.html"
                self.assertTrue(page.is_file(), page)
                text = page.read_text(encoding="utf-8")
                self.assertIn(uri, text)
                self.assertIn(f'<link rel="canonical" href="{uri}">', text)

    def test_every_schema_is_served_at_its_id(self):
        for uri, rel in predicates.SCHEMA_FOR_TYPE.items():
            with self.subTest(uri=uri):
                served = self._local(predicates.SCHEMA_ID[uri])
                self.assertTrue(served.is_file(), served)
                self.assertEqual(json.loads(served.read_text(encoding="utf-8")), json.loads(data_text(rel)))

    def test_every_shipped_schema_with_an_id_here_is_served_at_it(self):
        """Not only the predicate types' schemas: the settings snapshot's too (flagship slice 4.6, #176)."""
        from importlib import resources
        names = []
        for entry in resources.files("obaaf.data").joinpath("schemas").iterdir():
            if not entry.name.endswith(".json"):
                continue
            schema = json.loads(entry.read_text(encoding="utf-8"))
            names.append(entry.name)
            with self.subTest(schema=entry.name):
                self.assertTrue(schema["$id"].startswith(predicates.NAMESPACE + "/schemas/"))
                served = self._local(schema["$id"])
                self.assertTrue(served.is_file(), served)
                self.assertEqual(json.loads(served.read_text(encoding="utf-8")), schema)
        self.assertIn("settings-snapshot.schema.json", names)

    def test_the_questionnaire_names_its_canonical_address_and_says_it_needs_javascript(self):
        text = (self.out / "assessment.html").read_text(encoding="utf-8")
        self.assertEqual(text.count('<link rel="canonical" href="https://www.obaaf.com/assessment.html">'), 1)
        self.assertIn('</noscript><div id="tiers"></div>', text)
        self.assertIn("obaaf assess init", text)
        self.assertIn("Back to the OBAAF field guide", text)

    def test_format_pages_use_no_dashes(self):
        for uri in [*predicates.OBAAF_TYPES.values(), predicates.GENERIC_BUILD_TYPE]:
            with self.subTest(uri=uri):
                text = (self._local(uri) / "index.html").read_text(encoding="utf-8")
                self.assertNotIn("—", text)
                self.assertNotIn("–", text)


class SchemaPublishingRefusesTest(unittest.TestCase):
    """`write_schemas` in site/build.py stops the build on a schema it cannot publish safely (flagship
    slice 4.6): run against a folder of made-up schemas in place of OBAAF's own."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("obaaf_site_build", ROOT / "site" / "build.py")
        cls.build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.build)

    def publish(self, files):
        build = self.build
        with TempDir() as tmp:
            (tmp / "data" / "schemas").mkdir(parents=True)
            for name, text in files.items():
                (tmp / "data" / "schemas" / name).write_text(text, encoding="utf-8")
            real = build.resources.files
            build.resources.files = lambda package: tmp / "data"
            try:
                out = tmp / "site"
                out.mkdir()
                names = build.write_schemas(out)
                return names, sorted(p.relative_to(out).as_posix() for p in out.rglob("*.json"))
            finally:
                build.resources.files = real

    def test_a_schema_is_published_at_its_id_and_other_files_are_skipped(self):
        names, served = self.publish({"a.json": json.dumps({"$id": predicates.NAMESPACE + "/schemas/a/v1.json"}),
                                      "notes.txt": "not a schema"})
        self.assertEqual((names, served), (["a.json"], ["schemas/a/v1.json"]))

    def test_what_stops_the_build(self):
        ns = predicates.NAMESPACE
        cases = {
            "dot-dot": {"a.json": json.dumps({"$id": ns + "/schemas/../assessment.json"})},
            "another host": {"a.json": json.dumps({"$id": "https://example.com/schemas/a/v1.json"})},
            "not json": {"a.json": "{not json"},
            "an array": {"a.json": "[1, 2]"},
            "no id": {"a.json": "{}"},
            "not a .json file": {"a.json": json.dumps({"$id": ns + "/schemas/a/v1.html"})},
            "a duplicate": {"a.json": json.dumps({"$id": ns + "/schemas/a/v1.json"}),
                            "b.json": json.dumps({"$id": ns + "/schemas/a/v1.json"})},
        }
        for case, files in cases.items():
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    self.publish(files)


if __name__ == "__main__":
    unittest.main()
