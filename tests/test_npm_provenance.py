"""Flagship slice 2d.12 (#201): OBAAF-GHA-017 and the provenance `npm publish --provenance` signs.

Before this slice a release job whose only publish was `npm publish --provenance` got OBAAF-GHA-017,
"Release builds without provenance", although npm signs a provenance statement through Sigstore and
publishes it with the package. npm's own documentation asks for `id-token: write`, a GitHub-hosted
runner and the `--provenance` flag (npm/documentation at 507a73e,
content/packages-and-modules/securing-your-code/generating-provenance-statements.mdx, lines 51 to 70),
and npm's CLI throws before it publishes when it cannot sign (npm/cli at 787f152,
workspaces/libnpmpublish/lib/publish.js, lines 160 to 162 and 195 to 219). So such a step publishes
nothing without provenance, and the checker now credits it, in the one form it reads; every other form
keeps the finding, as before.

The workflows here are written for these tests from npm's documented example; none is copied from
another project.
"""

import unittest

from helpers import TempDir

from obaaf import checker

PIN = "0" * 40
RULE = "OBAAF-GHA-017"


def workflow(publish="      - run: npm publish --provenance --access public\n", permissions="      contents: read\n      id-token: write\n",
             runs_on="ubuntu-latest", top="", extra_steps=""):
    perms = f"    permissions:\n{permissions}" if permissions is not None else ""
    return ("name: Publish Package to npmjs\non:\n  release:\n    types: [published]\n" + top + "jobs:\n  build:\n"
            f"    runs-on: {runs_on}\n" + perms + "    steps:\n"
            f"      - uses: actions/checkout@{PIN}\n"
            f"      - uses: actions/setup-node@{PIN}\n        with:\n          node-version: '24.x'\n"
            "          registry-url: 'https://registry.npmjs.org'\n"
            "      - run: npm ci\n" + extra_steps + publish)


def found(text, files=None):
    with TempDir() as tmp:
        target = tmp / ".github" / "workflows"
        target.mkdir(parents=True)
        (target / "wf.yml").write_text(text, encoding="utf-8")
        for rel, body in (files or {}).items():
            path = tmp / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return [f for f in checker.check(tmp).findings if f.rule == RULE]


class CreditedTest(unittest.TestCase):
    """The documented form, and the spellings of it the checker reads."""

    def test_npms_own_example_has_no_finding(self):
        self.assertEqual(found(workflow()), [])

    def test_the_spellings_that_are_read(self):
        for line in ("npm publish --provenance", "npm publish --provenance=true --access public",
                     "npm publish --access public --tag next --provenance",
                     "npm publish --no-provenance --provenance",
                     "npm publish --provenance  # signed by Sigstore",
                     "npm publish \\\n          --provenance --access public"):
            with self.subTest(line=line):
                publish = "      - run: |\n          " + line + "\n"
                self.assertEqual(found(workflow(publish)), [])

    def test_the_workflows_permissions_count_when_the_job_has_none(self):
        top = "permissions:\n  contents: read\n  id-token: write\n"
        self.assertEqual(found(workflow(permissions=None, top=top)), [])
        self.assertEqual(found(workflow(permissions=None, top="permissions: write-all\n")), [])

    def test_a_hosted_matrix_is_read(self):
        text = workflow(runs_on="${{ matrix.os }}").replace(
            "    steps:\n", "    strategy:\n      matrix:\n        os: [ubuntu-latest, ubuntu-24.04]\n    steps:\n", 1)
        self.assertEqual(found(text), [])


class StillReportedTest(unittest.TestCase):
    """Every other form keeps OBAAF-GHA-017: the checker cannot show that npm signs."""

    def test_without_id_token_write(self):
        for permissions in ("      contents: read\n", "      contents: read\n      id-token: read\n",
                            "      contents: read\n      id-token: none\n", None):
            with self.subTest(permissions=permissions):
                self.assertEqual(len(found(workflow(permissions=permissions))), 1)

    def test_a_runner_that_may_not_be_github_hosted(self):
        for runs_on in ("self-hosted", "[self-hosted, linux]", "ubuntu-gpu", "${{ inputs.runner }}",
                        "[ubuntu-latest, self-hosted]"):
            with self.subTest(runs_on=runs_on):
                self.assertEqual(len(found(workflow(runs_on=runs_on))), 1)

    def test_provenance_turned_off_or_not_read(self):
        for line in ("npm publish", "npm publish --access public", "npm publish --provenance --no-provenance",
                     "npm publish --provenance --provenance=false", "npm publish --provenance=no",
                     "npm publish --provenance-file prov.sigstore", "npm publish --provenance $FLAGS",
                     "npm publish --provenance ${{ inputs.flags }}", "npm publish \"$@\" --provenance",
                     "npm publish --provenance `echo --no-provenance`", "npm publish --provenance || exit 1",
                     "npx npm publish --provenance",
                     "pnpm publish --provenance", "yarn npm publish --provenance",
                     "npm publish --provenance && gh release upload v1 dist/x.tgz",
                     "npm publish --provenance; npm publish ./other"):
            with self.subTest(line=line):
                self.assertEqual(len(found(workflow("      - run: |\n          " + line + "\n"))), 1)

    def test_two_commands_in_the_step(self):
        publish = "      - run: |\n          npm run build\n          npm publish --provenance\n"
        self.assertEqual(len(found(workflow(publish))), 1)

    def test_npm_config_provenance_is_not_read(self):
        # npm reads it (the documentation's lines 108 to 123), but an earlier step can write another value
        # into GITHUB_ENV, and the checker does not weigh that yet: the finding stays.
        publish = "      - run: npm publish\n        env:\n          NPM_CONFIG_PROVENANCE: true\n"
        self.assertEqual(len(found(workflow(publish))), 1)

    def test_another_upload_beside_it(self):
        extra = "      - run: gh release upload v1 dist/app.tgz\n"
        self.assertEqual(len(found(workflow(extra_steps=extra))), 1)
        other_job = workflow() + ("  docker:\n    runs-on: ubuntu-latest\n    permissions: {contents: read}\n"
                                  "    steps:\n      - run: docker push ghcr.io/example/app:1\n")
        self.assertEqual(len(found(other_job)), 1)

    def test_a_shell_the_checker_does_not_read_or_one_changed_before(self):
        pwsh = "      - run: npm publish --provenance\n        shell: pwsh\n"
        self.assertEqual(len(found(workflow(pwsh))), 1)
        path = "      - run: echo \"$RUNNER_TEMP/bin\" >> \"$GITHUB_PATH\"\n"
        self.assertEqual(len(found(workflow(extra_steps=path))), 1)
        bash_env = "      - run: npm publish --provenance\n        env:\n          BASH_ENV: ./x.sh\n"
        self.assertEqual(len(found(workflow(bash_env))), 1)


if __name__ == "__main__":
    unittest.main()
