"""Command-line behavior: help, version, usage errors and template installation."""

import unittest

from helpers import ROOT, TEST_SHA, TempDir, run_cli

from obaaf import __version__


class CliTest(unittest.TestCase):
    def test_version_and_help(self):
        code, out, _ = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)
        code, out, _ = run_cli("--help")
        self.assertEqual(code, 0)
        for command in ("assess", "check", "snapshot", "manifest", "proposal", "attest", "record", "verify",
                        "templates", "docs", "catalog"):
            self.assertIn(command, out)

    def test_unknown_command_is_a_usage_error(self):
        self.assertEqual(run_cli("frobnicate")[0], 2)

    def test_templates_install_refuses_placeholder_or_short_shas(self):
        with TempDir() as tmp:
            for sha in ("0" * 40, "abc123"):
                code, _, err = run_cli("templates", "install", "--dest", tmp, "--obaaf-repo", "studio/obaaf",
                                       "--obaaf-sha", sha)
                self.assertEqual(code, 2)
                self.assertIn("40-character", err)

    def test_templates_install_writes_pinned_workflows_and_support_files(self):
        with TempDir() as tmp:
            code, out, err = run_cli("templates", "install", "--dest", tmp, "--obaaf-repo", "studio/obaaf",
                                     "--obaaf-sha", TEST_SHA, "--repository", "studio/game")
            self.assertEqual(code, 0, err)
            workflows = sorted(p.name for p in (tmp / ".github" / "workflows").glob("*.yml"))
            self.assertEqual(workflows, ["obaaf-agent-apply.yml", "obaaf-agent-propose.yml", "obaaf-pipeline-check.yml",
                                         "obaaf-publish.yml", "obaaf-release.yml", "obaaf-untrusted-ci.yml"])
            for name in workflows:
                text = (tmp / ".github" / "workflows" / name).read_text()
                self.assertNotIn("OBAAF_OWNER", text)
                self.assertNotIn("0" * 40, text)
                self.assertIn(f"studio/obaaf/actions/setup-obaaf@{TEST_SHA}", text)
            policy = (tmp / ".github" / "obaaf-policy.yaml").read_text()
            self.assertIn("repository: studio/game", policy)
            self.assertTrue((tmp / ".github" / "obaaf" / "agent.sh").stat().st_mode & 0o111)
            self.assertTrue((tmp / "obaaf-sources.yaml").is_file())
            # A second install does not overwrite without --force.
            code, out, _ = run_cli("templates", "install", "--dest", tmp, "--obaaf-repo", "studio/obaaf",
                                   "--obaaf-sha", TEST_SHA)
            self.assertIn("skip", out)

    def test_composite_action_installs_from_its_own_source(self):
        action = (ROOT / "actions" / "setup-obaaf" / "action.yml").read_text()
        self.assertIn('"$GITHUB_ACTION_PATH/../.."', action)
        # Dependencies come from the hash-pinned list generated from constraints.txt (D-011).
        self.assertIn("requirements.txt", action)
        self.assertIn("--require-hashes", action)
        # No isolated build environment, which would fetch whatever setuptools is newest.
        self.assertIn("--no-build-isolation", action)
        self.assertIn("pip check", action)
        constraints = (ROOT / "actions" / "setup-obaaf" / "constraints.txt").read_text()
        pinned = {}
        for line in constraints.splitlines():
            if line and not line.startswith("#"):
                self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[0-9][0-9A-Za-z.]*$")
                name, version = line.split("==")
                pinned[name.lower()] = version
        for name in ("setuptools", "pyyaml", "jsonschema", "cryptography", "cffi", "pycparser"):
            self.assertIn(name, pinned)


if __name__ == "__main__":
    unittest.main()
