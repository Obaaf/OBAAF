"""The pages that tell a reader to run `obaaf templates install` give a command that works with the
package from PyPI (flagship slice 3.9, issue #142).

The package does not include the templates, so the command needs `--source`, the templates directory
of a clone of OBAAF. Before this slice the README and the adoption guide printed a command without it,
which exits 2 after `pip install obaaf`. For each page this reads the clone it tells the reader to make,
the commit it checks out and the install command, holds them to each other, and runs the command as
printed, with this checkout's templates standing for the clone's and the placeholders filled in. Run
from this checkout, a command without `--source` would work too, so the first test is what holds a page
to it. What the pages say in prose is not tested.
"""

import re
import shlex
import unittest

from helpers import ROOT, TEST_SHA, TempDir, run_cli

PAGES = ("README.md", "docs/adoption-guide.md", "templates/github-actions/README.md", "docs/live-acceptance-tests.md")
CLONE_RE = re.compile(r"git clone https://github\.com/Obaaf/OBAAF\.git ([^\s`]+)")


def page_text(page: str) -> str:
    # Lines a shell joins with a backslash are one command; the long placeholder is read as the short one.
    text = (ROOT / page).read_text(encoding="utf-8").replace("\\\n", " ")
    return text.replace("<full commit SHA of the OBAAF release>", "<commit>")


def read_page(page: str) -> tuple[str, str, list[list[str]]]:
    """The clone's directory, the commit checked out in it, and each install command's arguments."""
    text = page_text(page)
    clones = set(CLONE_RE.findall(text))
    if len(clones) != 1:
        raise AssertionError(f"{page} names {len(clones)} clones of OBAAF: {sorted(clones)}")
    clone = clones.pop()
    checkouts = set(re.findall(rf"git -C {re.escape(clone)} checkout ([^\s`]+)", text))
    if len(checkouts) != 1:
        raise AssertionError(f"{page} checks out {sorted(checkouts)} in {clone}")
    commit = checkouts.pop()
    installs = []
    for match in re.findall(r"obaaf templates install [^`\n]*", text):
        if "--obaaf-sha" not in match:
            continue    # a mention of the command, not a command to run
        installs.append(shlex.split(match)[1:])
    if not installs:
        raise AssertionError(f"{page} no longer shows `obaaf templates install` with --obaaf-sha")
    return clone, commit, installs


def option(args: list[str], name: str, default: str | None = None) -> str | None:
    for i, arg in enumerate(args):
        if arg == name and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return default


class TemplatesInstallAsDocumented(unittest.TestCase):
    def test_every_command_takes_the_templates_from_the_clone_at_the_pinned_commit(self):
        for page in PAGES:
            with self.subTest(page=page):
                clone, commit, installs = read_page(page)
                for args in installs:
                    self.assertEqual(option(args, "--source"), f"{clone}/templates/github-actions", f"{page}: {args}")
                    self.assertEqual(option(args, "--obaaf-sha"), commit,
                                     f"{page}: the clone is checked out at {commit}, the workflows pin another")

    def test_each_command_runs_as_printed(self):
        for page in PAGES:
            clone, _, installs = read_page(page)
            for args in installs:
                with self.subTest(page=page), TempDir() as tmp:
                    filled = [arg.replace("<commit>", TEST_SHA) for arg in args]
                    filled = [str(ROOT / "templates" / "github-actions") if a == f"{clone}/templates/github-actions"
                              else a for a in filled]
                    dest = tmp / "repo"
                    dest.mkdir()
                    if "--dest" in filled:
                        filled[filled.index("--dest") + 1] = str(dest)
                    else:
                        filled += ["--dest", str(dest)]
                    code, out, err = run_cli(*filled)
                    self.assertEqual(code, 0, f"{page}: {args}\n{err}")
                    text = (dest / ".github" / "workflows" / "obaaf-pipeline-check.yml").read_text(encoding="utf-8")
                    self.assertIn(f"/actions/setup-obaaf@{TEST_SHA}", text)


if __name__ == "__main__":
    unittest.main()
