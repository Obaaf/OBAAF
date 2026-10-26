"""Discovery and empty coverage (Jenkins design, section 2 and JT 01).

`obaaf check .github/workflows` used to check zero files and pass, because discovery
expected a repository root. A check that finds nothing must say so and fail.
"""

import unittest

from helpers import ROOT, TempDir, run_cli

from obaaf import checker
from obaaf.checker import workflow as wf_mod

WORKFLOW = ("on: push\npermissions: {contents: read}\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo hi\n")


def _repo(tmp):
    (tmp / ".github" / "workflows").mkdir(parents=True)
    (tmp / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW, encoding="utf-8")
    return tmp


class LocateTest(unittest.TestCase):
    def test_repository_root(self):
        with TempDir() as tmp:
            root, files = wf_mod.locate(_repo(tmp))
            self.assertEqual(root, tmp.resolve())
            self.assertEqual([p.name for p in files], ["ci.yml"])

    def test_workflows_directory_resolves_to_the_repository(self):
        with TempDir() as tmp:
            root, files = wf_mod.locate(_repo(tmp) / ".github" / "workflows")
            self.assertEqual(root, tmp.resolve())
            self.assertEqual([p.name for p in files], ["ci.yml"])

    def test_github_directory_resolves_to_the_repository(self):
        with TempDir() as tmp:
            root, files = wf_mod.locate(_repo(tmp) / ".github")
            self.assertEqual(root, tmp.resolve())
            self.assertEqual(len(files), 1)

    def test_paths_keep_the_repository_form(self):
        with TempDir() as tmp:
            result = checker.check(_repo(tmp) / ".github" / "workflows")
            self.assertEqual(result.files, [".github/workflows/ci.yml"])

    def test_this_repository_from_its_workflows_directory(self):
        # The root also finds Jenkinsfiles (templates/jenkins); the workflows directory finds workflows only.
        by_root = checker.check(ROOT).workflow_files
        by_dir = checker.check(ROOT / ".github" / "workflows").files
        self.assertTrue(by_root)
        self.assertEqual(by_root, by_dir)


class EmptyCoverageTest(unittest.TestCase):
    def test_empty_directory_is_a_usage_error_not_a_pass(self):
        with TempDir() as tmp:
            code, out, err = run_cli("check", tmp)
            self.assertEqual(code, 2)
            self.assertIn("nothing was checked", err)

    def test_workflows_directory_is_checked(self):
        with TempDir() as tmp:
            code, out, _ = run_cli("check", _repo(tmp) / ".github" / "workflows", "--fail-on", "never")
            self.assertEqual(code, 0)
            self.assertIn("1 workflow file(s) checked", out)


if __name__ == "__main__":
    unittest.main()
