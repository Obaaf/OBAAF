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
        result = checker.check(tmp)
        # A file the checker could not read reports nothing, which would pass a test that expects nothing.
        assert not result.errors, result.errors
        assert any(f.rule == "OBAAF-GHA-016" or f.rule == RULE for f in result.findings), "no release job read"
        return [f for f in result.findings if f.rule == RULE]


class CreditedTest(unittest.TestCase):
    """The documented form, and the spellings of it the checker reads."""

    def test_npms_own_example_has_no_finding(self):
        self.assertEqual(found(workflow()), [])

    def test_the_spellings_that_are_read(self):
        for line in ("npm publish --provenance", "npm publish --provenance=true --access public",
                     "npm publish --access public --tag next --provenance",
                     "npm publish --provenance --tag=next --access=public --provenance",
                     "npm publish --provenance  # signed by Sigstore",
                     "npm publish \\\n          --provenance --access public"):
            with self.subTest(line=line):
                publish = "      - run: |\n          " + line + "\n"
                self.assertEqual(found(workflow(publish)), [])

    def test_the_workflows_permissions_count_when_the_job_has_none(self):
        top = "permissions:\n  contents: read\n  id-token: write\n"
        self.assertEqual(found(workflow(permissions=None, top=top)), [])
        self.assertEqual(found(workflow(permissions=None, top="permissions: write-all\n")), [])

    def test_the_node_versions_and_earlier_steps_that_are_read(self):
        for version in ("20", "'20.11.1'", "'22.x'", "24", "lts/*", "latest", "node", "current", "v20"):
            with self.subTest(version=version):
                self.assertEqual(found(workflow().replace("node-version: '24.x'", f"node-version: {version}")), [])
        extra = "      - run: npm run build\n      - run: |\n          npm test\n          npm run lint:ci\n"
        self.assertEqual(found(workflow(extra_steps=extra)), [])

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

    def test_what_npms_option_reader_does_with_the_words(self):
        # Found by the review of slice 2d.12: nopt takes `false` after a boolean option as its value, reads
        # `no-` in any case after any number of dashes, and gives an option that takes a value the next
        # word, `--provenance` too; a positional is a folder or a package to publish; `--` ends options.
        for line in ("npm publish --provenance false", "npm publish --access public --provenance\tfalse",
                     "npm publish --provenance true", "npm publish --provenance --NO-provenance",
                     "npm publish --provenance --No-provenance", "npm publish --provenance -no-provenance",
                     "npm publish --provenance ---no-provenance", "npm publish --cache --provenance",
                     "npm publish -C --provenance", "npm publish --otp --provenance",
                     "npm publish --access --provenance", "npm publish --access restricted --provenance",
                     "npm publish some-pkg@1.0.0 --provenance", "npm publish ./other --provenance",
                     "npm publish --no-provenance -- --provenance", "npm publish --provenance --tag",
                     "npm publish --provenance --tag -x", "npm publish --provenance --registry=https://registry.npmjs.org"):
            with self.subTest(line=line):
                self.assertEqual(len(found(workflow("      - run: |\n          " + line + "\n"))), 1)

    def test_an_npm_that_may_not_sign(self):
        # npm 9.5.0 or later is needed (npm's documentation, line 37); Node.js before 20 may ship npm 8.
        for version in ("16.x", "14", "'18.x'", "lts/hydrogen", "${{ matrix.node }}", "'>=20'"):
            with self.subTest(version=version):
                self.assertEqual(len(found(workflow().replace("node-version: '24.x'", f"node-version: {version}"))), 1)
        no_version = workflow().replace("          node-version: '24.x'\n", "")
        self.assertEqual(len(found(no_version)), 1)
        from_file = workflow().replace("node-version: '24.x'", "node-version-file: .nvmrc")
        self.assertEqual(len(found(from_file)), 1)
        no_setup = workflow().replace(f"      - uses: actions/setup-node@{PIN}\n        with:\n          node-version: '24.x'\n"
                                      "          registry-url: 'https://registry.npmjs.org'\n", "")
        self.assertEqual(len(found(no_setup)), 1)
        for extra in ("      - run: npm install -g npm@8.19.4\n", "      - run: sudo ln -sf /bin/true /usr/local/bin/npm\n",
                      f"      - uses: example/setup-tools@{PIN}\n", "      - run: npm ci && npm run build\n",
                      f"      - uses: actions/cache@{PIN}\n        with: {{path: ~/.npm, key: k}}\n",
                      "      - run: npm ci\n        shell: bash -e {0}\n",
                      "      - run: npm ci\n        env:\n          NODE_OPTIONS: --require ./x.js\n",
                      # Found by the second review: an action runs in its own Node.js, which an `env` can
                      # change; bash runs `SHELLOPTS` and expands `PS4` when it starts.
                      f"      - uses: actions/checkout@{PIN}\n        env:\n          NODE_OPTIONS: --require ./evil.js\n",
                      "      - run: npm ci\n        env:\n          SHELLOPTS: xtrace\n          PS4: '$(npm i -g npm@8)'\n",
                      "      - run: npm ci\n        env:\n          CI: true\n",
                      "      - run: npm ci\n        if: github.event_name == 'release'\n"):
            with self.subTest(extra=extra):
                self.assertEqual(len(found(workflow(extra_steps=extra))), 1)

    def test_what_npm_runs_may_have_been_changed(self):
        for env in ("PATH: /tmp/fake:/usr/bin:/bin", "NODE_OPTIONS: --require ./x.js", "NODE_PATH: ./x",
                    "LD_PRELOAD: ./x.so", "path: /tmp/fake"):
            publish = "      - run: npm publish --provenance --access public\n        env:\n          " + env + "\n"
            with self.subTest(env=env, where="step"):
                self.assertEqual(len(found(workflow(publish))), 1)
            with self.subTest(env=env, where="workflow"):
                self.assertEqual(len(found(workflow(top="env:\n  " + env + "\n"))), 1)
        job_env = workflow().replace("    steps:\n", "    env:\n      PATH: /tmp/fake\n    steps:\n", 1)
        self.assertEqual(len(found(job_env)), 1)
        container = workflow().replace("    steps:\n", "    container: node:16\n    steps:\n", 1)
        self.assertEqual(len(found(container)), 1)
        # Found by the third review: a service is another image, running as root for the whole job.
        service = workflow().replace("    steps:\n", "    services:\n      helper:\n        image: example/helper:1\n"
                                     "        volumes: ['/opt/hostedtoolcache:/t']\n    steps:\n", 1)
        self.assertEqual(len(found(service)), 1)
        working = workflow().replace("    steps:\n", "    defaults:\n      run:\n        working-directory: .\n    steps:\n", 1)
        self.assertEqual(found(working), [])
        expression_env = workflow().replace("    steps:\n", "    env: ${{ fromJSON(vars.ENV) }}\n    steps:\n", 1)
        self.assertEqual(len(found(expression_env)), 1)
        for env in ("SHELLOPTS: xtrace", "BASHOPTS: extglob", "PS4: x", "EXECIGNORE: x", "BASH_XTRACEFD: 3",
                    "NPM_CONFIG_REGISTRY: https://relay.example", "npm_config_registry: https://relay.example",
                    "NODE_TLS_REJECT_UNAUTHORIZED: 0", "NODE_EXTRA_CA_CERTS: ./ca.pem"):
            with self.subTest(env=env):
                self.assertEqual(len(found(workflow(top="env:\n  " + env + "\n"))), 1)
        token = "      - run: npm publish --provenance --access public\n        env:\n          NODE_AUTH_TOKEN: x\n"
        self.assertEqual(found(workflow(token)), [])

    def test_a_default_shell_another_registry_or_a_setup_node_that_may_be_skipped(self):
        shell = "defaults:\n  run:\n    shell: 'bash -c \"npm i -g npm@8 && bash -e {0}\"'\n"
        self.assertEqual(len(found(workflow(top=shell))), 1)
        job_shell = workflow().replace("    steps:\n", "    defaults:\n      run:\n        shell: bash\n    steps:\n", 1)
        self.assertEqual(len(found(job_shell)), 1)
        relay = workflow().replace("registry-url: 'https://registry.npmjs.org'", "registry-url: 'https://relay.example'")
        self.assertEqual(len(found(relay)), 1)
        skipped = workflow().replace(f"      - uses: actions/setup-node@{PIN}\n", f"      - uses: actions/setup-node@{PIN}\n        if: false\n")
        self.assertEqual(len(found(skipped)), 1)
        for version in ("20.10", "true", "'２０'", "[20]"):
            with self.subTest(version=version):
                self.assertEqual(len(found(workflow().replace("node-version: '24.x'", f"node-version: {version}"))), 1)
        parallel = workflow().replace("      - run: npm ci\n", "      - run: npm ci\n        background: true\n")
        self.assertEqual(len(found(parallel)), 1)

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

    def test_the_finding_moves_to_the_job_whose_upload_has_no_provenance(self):
        # Found by the review of slice 2d.12: an acceptance names the job, so it no longer matches
        # (docs/upgrading.md says so).
        text = workflow() + ("  docker:\n    runs-on: ubuntu-latest\n    permissions: {contents: read}\n"
                             "    steps:\n      - run: docker push ghcr.io/example/app:1\n")
        (finding,) = found(text)
        self.assertEqual(finding.job, "docker")

    def test_a_shell_the_checker_does_not_read_or_one_changed_before(self):
        pwsh = "      - run: npm publish --provenance\n        shell: pwsh\n"
        self.assertEqual(len(found(workflow(pwsh))), 1)
        path = "      - run: echo \"$RUNNER_TEMP/bin\" >> \"$GITHUB_PATH\"\n"
        self.assertEqual(len(found(workflow(extra_steps=path))), 1)
        bash_env = "      - run: npm publish --provenance\n        env:\n          BASH_ENV: ./x.sh\n"
        self.assertEqual(len(found(workflow(bash_env))), 1)


if __name__ == "__main__":
    unittest.main()
