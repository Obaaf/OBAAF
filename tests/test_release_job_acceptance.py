"""The project's own baseline accepts one verification finding in its release job."""

from datetime import date
from pathlib import Path
import shutil
import unittest

from helpers import ROOT, TempDir
from obaaf.checker import baseline, check


class ReleaseJobAcceptanceTest(unittest.TestCase):
    def test_another_upload_in_publish_requires_a_new_decision(self):
        release = Path(".github/workflows/release-pypi.yml")
        entry_path = Path(".github/obaaf-baseline.json")
        with TempDir() as root:
            for path in (release, entry_path, Path(".github/obaaf.yml"), Path(".github/CODEOWNERS")):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, root / path)
            shutil.copytree(ROOT / "actions/setup-obaaf", root / "actions/setup-obaaf")
            accepted = baseline.load(root / entry_path)
            self.assertEqual(len(accepted.entries), 1)
            entry = accepted.entries[0]
            self.assertEqual((entry["rule"], entry["path"], entry["job"]),
                             ("OBAAF-GHA-016", release.as_posix(), "publish"))

            def publish_verdicts():
                result = check(root, today=date(2026, 11, 19), gate_files=[root / entry_path])
                baseline.apply(result, accepted)
                findings = [f for f in result.findings if f.rule == entry["rule"] and f.job == entry["job"]]
                return [(f.baselined, bool(f.suppressed)) for f in findings]

            self.assertEqual(publish_verdicts(), [(True, False)])
            # Add a second upload to a private copy. The checker groups the two uploads in one
            # finding. Its changed facts must fail the gate even though its rule and job match.
            with (root / release).open("a", encoding="utf-8") as workflow:
                workflow.write("\n      - name: Publish another distribution\n"
                               "        run: python -m twine upload extra-dist/*\n")
            self.assertEqual(publish_verdicts(), [(False, False)])
