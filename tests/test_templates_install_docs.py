"""The pages that tell a reader to run `obaaf templates install` give a command that works with the
package from PyPI (flagship slice 3.9, issue #142).

The package does not include the templates, so the command needs `--source`, the templates directory
of a clone of OBAAF. Before this slice the README and the adoption guide printed a command without it,
which exits 2 after `pip install obaaf`. Each page's command is run here as printed, with the clone's
directory standing for this checkout's templates and the placeholders filled in. Run from this
checkout, a command without `--source` would work too, so the first test is what holds a page to it.
"""

import re
import shlex
import unittest

from helpers import ROOT, TEST_SHA, TempDir, run_cli

PAGES = ("README.md", "docs/adoption-guide.md", "templates/github-actions/README.md", "docs/live-acceptance-tests.md")
CLONE_TEMPLATES = "obaaf-src/templates/github-actions"


def commands(page: str) -> list[str]:
    """Each `obaaf templates install` command on a page, its continuation lines joined."""
    text = (ROOT / page).read_text(encoding="utf-8").replace("\\\n", " ")
    found = re.findall(r"obaaf templates install[^`\n]*", text)
    return [" ".join(command.split()) for command in found]


class TemplatesInstallAsDocumented(unittest.TestCase):
    def test_every_page_gives_the_templates_from_a_clone(self):
        for page in PAGES:
            found = commands(page)
            self.assertTrue(found, f"{page} no longer shows `obaaf templates install`")
            for command in found:
                self.assertIn(f"--source {CLONE_TEMPLATES}", command, f"{page}: {command}")
            words = (ROOT / page).read_text(encoding="utf-8")
            for step in ("git clone https://github.com/Obaaf/OBAAF.git obaaf-src", "git -C obaaf-src checkout"):
                self.assertIn(step, words, f"{page} no longer says how to get the clone")

    def test_each_command_runs_as_printed(self):
        for page in PAGES:
            for command in commands(page):
                with self.subTest(page=page), TempDir() as tmp:
                    filled = (command.replace("<full commit SHA of the OBAAF release>", TEST_SHA)
                              .replace("<commit>", TEST_SHA))
                    args = shlex.split(filled)[1:]   # drop "obaaf"
                    args = [str(ROOT / "templates" / "github-actions") if a == CLONE_TEMPLATES else a for a in args]
                    dest = args.index("--dest") + 1
                    args[dest] = str(tmp / "repo")
                    (tmp / "repo").mkdir()
                    code, out, err = run_cli(*args)
                    self.assertEqual(code, 0, f"{page}: {command}\n{err}")
                    self.assertTrue((tmp / "repo" / ".github" / "workflows" / "obaaf-pipeline-check.yml").is_file())
                    text = (tmp / "repo" / ".github" / "workflows" / "obaaf-pipeline-check.yml").read_text()
                    self.assertIn(f"/actions/setup-obaaf@{TEST_SHA}", text)


if __name__ == "__main__":
    unittest.main()
