"""The project's own baseline accepts one verification finding in its release job."""

from datetime import date
from pathlib import Path
import re
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

    def test_the_entry_is_the_one_sean_approved(self):
        # Sean's choice of 2026-11-18 (#238, plan item 64): this one finding, in his name, for this
        # reason, until this date. A rewritten entry that still matches must fail here.
        entries = baseline.load(ROOT / ".github/obaaf-baseline.json").entries
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual({k: entry[k] for k in ("rule", "severity", "path", "job", "kind", "facts", "owner",
                                                 "reason", "expires")}, {
            "rule": "OBAAF-GHA-016", "severity": "high", "path": ".github/workflows/release-pypi.yml",
            "job": "publish", "kind": "cannot-tell",
            "facts": {"steps": ["pypa/gh-action-pypi-publish"],
                      "checks": ["publish: Verify the release before uploading (FR6)"]},
            "owner": "@seanudeke",
            "reason": "The PATH entry before the verify step is the one this repository's own setup-obaaf "
                      "writes, from hash-locked wheels; see plan item 64",
            "expires": "2027-02-18"})

    def test_the_path_write_is_the_only_reason_the_checker_cannot_tell(self):
        # The entry accepts "cannot tell" whatever causes it. Without setup-obaaf's one GITHUB_PATH
        # write, the publish job must have no OBAAF-GHA-016 at all, so a verify step that no longer
        # stops the upload (`|| true`, `if: false`, another PATH write) fails here (review of #256).
        release = Path(".github/workflows/release-pypi.yml")
        action = Path("actions/setup-obaaf/action.yml")
        line = 'echo "$bin" >> "$GITHUB_PATH"'
        with TempDir() as root:
            for path in (release, Path(".github/obaaf.yml"), Path(".github/CODEOWNERS")):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, root / path)
            shutil.copytree(ROOT / "actions/setup-obaaf", root / "actions/setup-obaaf")
            text = (root / action).read_text(encoding="utf-8")
            self.assertEqual(text.count(line), 1)
            self.assertEqual(text.count("GITHUB_PATH"), 1)
            # What the line puts on the PATH is the virtual environment the action has just made.
            assignments = [w.strip() for w in text.split("\n") if re.search(r"\b(bin|venv)=", w)]
            self.assertEqual(assignments, [
                'venv="$RUNNER_TEMP/obaaf-venv"',
                'if [ -d "$venv/Scripts" ]; then bin="$venv/Scripts"; else bin="$venv/bin"; fi'])

            def publish_016():
                result = check(root, today=date(2026, 11, 19))
                return [f.kind for f in result.findings if f.rule == "OBAAF-GHA-016" and f.job == "publish"]

            self.assertEqual(publish_016(), ["cannot-tell"])
            (root / action).write_text(text.replace(line, "true"), encoding="utf-8")
            self.assertEqual(publish_016(), [])
