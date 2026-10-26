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

    def test_format_pages_use_no_dashes(self):
        for uri in [*predicates.OBAAF_TYPES.values(), predicates.GENERIC_BUILD_TYPE]:
            with self.subTest(uri=uri):
                text = (self._local(uri) / "index.html").read_text(encoding="utf-8")
                self.assertNotIn("—", text)
                self.assertNotIn("–", text)


if __name__ == "__main__":
    unittest.main()
