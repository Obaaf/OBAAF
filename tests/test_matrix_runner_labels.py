"""Runner labels from a matrix value with a written default (flagship slice 2d.7, issue #141).

`runs-on: ${{ matrix.os || 'ubuntu-latest' }}` is read from the expression's tokens and resolved
against a matrix written out in the file. The labels it can take include the default wherever a row
may lack the value, so a job is taken for GitHub-hosted only when every label it can get is a
standard hosted one. Anything the checker cannot resolve stays "unknown", as before, and OBAAF-GHA-013
reports it for a job an outsider can start.
"""

import unittest

from helpers import TempDir

from obaaf import checker

SHA = "1" * 40

# The shape of pallets/flask's tests.yaml at 49943b5: a matrix of `include` entries only, a few of
# which name an `os`.
FLASK = """    strategy:
      fail-fast: false
      matrix:
        include:
          - {python: '3.14'}
          - {name: Windows, python: '3.14', os: windows-latest}
          - {name: Mac, python: '3.14', os: macos-latest}
          - {python: '3.13'}
"""


def workflow(runs_on, strategy=FLASK, on="pull_request"):
    return (f"on: {on}\npermissions: {{}}\njobs:\n  tests:\n{strategy}    runs-on: {runs_on}\n"
            f"    steps:\n      - uses: actions/checkout@{SHA}\n        with: {{persist-credentials: false}}\n"
            "      - run: tox\n")


def gha013(text):
    with TempDir() as tmp:
        (tmp / ".github" / "workflows").mkdir(parents=True)
        (tmp / ".github" / "workflows" / "ci.yml").write_text(text, encoding="utf-8")
        result = checker.check(tmp)
    return [(f.severity, f.kind) for f in result.findings if f.rule == "OBAAF-GHA-013"]


class MatrixDefaultTest(unittest.TestCase):
    def test_flasks_shape_runs_on_hosted_runners_only(self):
        self.assertEqual(gha013(workflow("${{ matrix.os || 'ubuntu-latest' }}")), [])

    def test_spacing_and_a_key_matrix_with_include(self):
        strategy = ("    strategy:\n      matrix:\n        os: [ubuntu-24.04, windows-latest]\n"
                    "        include:\n          - {os: macos-latest, extra: 1}\n")
        for runs_on in ("${{matrix.os||'ubuntu-latest'}}", "${{ matrix.os || 'ubuntu-latest' }}"):
            with self.subTest(runs_on=runs_on):
                self.assertEqual(gha013(workflow(runs_on, strategy)), [])

    def test_a_default_or_a_value_that_is_not_hosted_is_still_reported(self):
        cases = {
            "the default": workflow("${{ matrix.os || 'my-runner' }}"),
            "a value": workflow("${{ matrix.os || 'ubuntu-latest' }}",
                                FLASK + "          - {os: self-hosted}\n"),
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertTrue(gha013(text))
        self.assertEqual(gha013(workflow("${{ matrix.os || 'ubuntu-latest' }}", FLASK + "          - {os: self-hosted}\n")),
                         [("high", "self-hosted")])

    def test_the_default_counts_where_a_row_may_lack_the_value(self):
        """Every row has `os` from the key's list, but an `include` entry without `os` that cannot be
        added to any combination makes a row of its own, which the default then names."""
        strategy = ("    strategy:\n      matrix:\n        os: [ubuntu-latest]\n        python: ['3.12']\n"
                    "        include:\n          - {python: '3.11'}\n")
        self.assertTrue(gha013(workflow("${{ matrix.os || 'my-runner' }}", strategy)))
        # When every include entry sets it, the default is never used.
        strategy = ("    strategy:\n      matrix:\n        os: [ubuntu-latest]\n"
                    "        include:\n          - {os: windows-latest, python: '3.11'}\n")
        self.assertEqual(gha013(workflow("${{ matrix.os || 'my-runner' }}", strategy)), [])

    def test_an_empty_value_takes_the_default(self):
        strategy = "    strategy:\n      matrix:\n        os: ['', windows-latest]\n"
        self.assertEqual(gha013(workflow("${{ matrix.os || 'ubuntu-latest' }}", strategy)), [])
        self.assertTrue(gha013(workflow("${{ matrix.os || 'my-runner' }}", strategy)))

    def test_what_cannot_be_resolved_stays_unknown(self):
        cases = {
            "a key computed when the job runs, with include": (
                "${{ matrix.os || 'ubuntu-latest' }}",
                "    strategy:\n      matrix:\n        os: ${{ fromJSON(vars.OSES) }}\n"
                "        include:\n          - {os: ubuntu-latest}\n"),
            "include computed": ("${{ matrix.os || 'ubuntu-latest' }}",
                                 "    strategy:\n      matrix:\n        os: [ubuntu-latest]\n"
                                 "        include: ${{ fromJSON(vars.MORE) }}\n"),
            "an include entry computed": ("${{ matrix.os || 'ubuntu-latest' }}",
                                          FLASK + "          - ${{ fromJSON(vars.ROW) }}\n"),
            "the whole matrix computed": ("${{ matrix.os || 'ubuntu-latest' }}",
                                          "    strategy:\n      matrix: ${{ fromJSON(vars.M) }}\n"),
            "a key in another case": ("${{ matrix.OS || 'ubuntu-latest' }}", FLASK),
            "the same key in two cases": ("${{ matrix.os || 'ubuntu-latest' }}",
                                          FLASK + "          - {OS: self-hosted}\n"),
            "another operator": ("${{ matrix.os && 'ubuntu-latest' }}", FLASK),
            "a function": ("${{ format('{0}', matrix.os) }}", FLASK),
            "two defaults": ("${{ matrix.os || 'ubuntu-latest' || 'windows-latest' }}", FLASK),
            "a context default": ("${{ matrix.os || vars.RUNNER }}", FLASK),
            "text outside the expression": ("x-${{ matrix.os || 'ubuntu-latest' }}", FLASK),
            "two expressions": ("${{ matrix.os }}${{ matrix.arch }}", FLASK),
            "an index": ("${{ matrix['os'] || 'ubuntu-latest' }}", FLASK),
            "an unclosed default": ("${{ matrix.os || 'ubuntu-latest }}", FLASK),
        }
        for name, (runs_on, strategy) in cases.items():
            with self.subTest(name):
                self.assertEqual(gha013(workflow(runs_on, strategy)), [("medium", "other-labels")])

    def test_a_plain_matrix_value_is_read_as_before(self):
        strategy = "    strategy:\n      matrix:\n        os: [ubuntu-latest, self-hosted]\n"
        self.assertEqual(gha013(workflow("${{ matrix.os }}", strategy)), [("high", "self-hosted")])
        strategy = "    strategy:\n      matrix:\n        os: [ubuntu-latest, windows-latest]\n"
        self.assertEqual(gha013(workflow("${{ matrix.os }}", strategy)), [])
        # A trusted trigger is not reported whatever the labels.
        self.assertEqual(gha013(workflow("${{ matrix.os || 'my-runner' }}", on="push")), [])


if __name__ == "__main__":
    unittest.main()
