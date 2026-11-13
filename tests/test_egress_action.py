"""The egress control's own logic (actions/egress/egress.py), offline.

What the control blocks on a real runner is established by the escape tests in
.github/workflows/egress-escape-tests.yml, not here. These tests pin the parts
that need no runner: what the action accepts as an allow-list and as variable
names, and that the AWF command line it builds holds nothing from the workflow
but host names.
"""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("obaaf_egress_action", ROOT / "actions" / "egress" / "egress.py")
egress = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(egress)


class AllowList(unittest.TestCase):
    def test_plain_names_any_separator_lowercased_and_deduplicated(self):
        self.assertEqual(
            egress.parse_allow_list("api.anthropic.com, API.github.com\nstatsig.anthropic.com api.github.com"),
            ["api.anthropic.com", "api.github.com", "statsig.anthropic.com"],
        )

    def test_refused(self):
        for bad in (
            "", "   ", "*.github.com", "github.*", "*", "localhost", "com",
            "1.1.1.1", "10.0.0.1", "[2606:4700::1111]", "2606:4700::1111",
            "https://api.github.com", "api.github.com:443", "api.github.com/path",
            "api.github.com.", ".github.com", "-bad.example.com", "bad-.example.com",
            "exa mple.com\x00", "under_score.example.com", "a" * 64 + ".com",
            "example.123",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(egress.UsageError):
                    egress.parse_allow_list(bad)

    def test_long_but_valid_name(self):
        name = ".".join(["a" * 63] * 3) + ".com"
        self.assertEqual(egress.parse_allow_list(name), [name])

    def test_covered_is_the_name_or_under_it(self):
        allow = ["github.com"]
        self.assertTrue(egress.covered("github.com", allow))
        self.assertTrue(egress.covered("api.github.com", allow))
        self.assertFalse(egress.covered("evilgithub.com", allow))
        self.assertFalse(egress.covered("github.com.evil.net", allow))

    def test_probe_host_is_never_covered(self):
        self.assertEqual(egress.probe_host(["api.github.com"]), "example.com")
        self.assertEqual(egress.probe_host(["example.com"]), "example.net")
        self.assertEqual(egress.probe_host(["example.com", "example.net"]), "example.org")
        with self.assertRaises(egress.UsageError):
            egress.probe_host(["example.com", "example.net", "example.org"])


class EnvNames(unittest.TestCase):
    def test_named_variables_only(self):
        env = {"A_KEY": "one", "OTHER": "two"}
        self.assertEqual(egress.parse_env_names("A_KEY", env), {"A_KEY": "one"})
        self.assertEqual(egress.parse_env_names("", env), {})

    def test_refused(self):
        env = {name: "x" for name in ("PATH", "HTTPS_PROXY", "no_proxy", "LD_PRELOAD", "GITHUB_ENV",
                                       "AWF_ANYTHING", "ACTIONS_RUNTIME_TOKEN", "BASH_ENV", "GIT_SSH_COMMAND")}
        env.update({"MULTI": "a\nb", "NUL": "a\0b"})
        for bad in list(env) + ["1BAD", "BAD-NAME", "MISSING"]:
            with self.subTest(bad=bad):
                with self.assertRaises(egress.UsageError):
                    egress.parse_env_names(bad, env)


class CommandLine(unittest.TestCase):
    def test_fixed_options_and_pinned_images(self):
        argv = egress.awf_argv("/x/awf", ["api.github.com", "example.org"], "/p/c.json", "/p/e.env",
                               "/tmp/obaaf-egress.abc/workspace", "/p/work", "/p/logs", "/tmp/obaaf-egress.abc/i.sh")
        self.assertEqual(argv[0], "/x/awf")
        self.assertEqual(argv[argv.index("--allow-domains") + 1], "api.github.com,example.org")
        self.assertEqual(argv[-3:], ["--", "/bin/bash", "/tmp/obaaf-egress.abc/i.sh"])
        options = [a for a in argv[: argv.index("--")] if a.startswith("--")]
        self.assertEqual(options, ["--allow-domains", "--config", "--env-file", "--container-workdir",
                                   "--work-dir", "--proxy-logs-dir", "--image-tag", "--log-level"])
        for unsafe in ("--enable-dind", "--env-all", "--legacy-security", "--enable-host-access",
                       "--ssl-bump", "--upstream-proxy", "--dns-over-https", "--allow-host-ports"):
            self.assertNotIn(unsafe, argv)
        tag = argv[argv.index("--image-tag") + 1]
        self.assertTrue(tag.startswith(egress.AWF_VERSION.lstrip("v") + ","))
        for name in ("squid", "agent", "api-proxy"):
            self.assertRegex(tag, rf"(^|,){re.escape(name)}=sha256:[0-9a-f]{{64}}(,|$)")

    def test_pins_have_the_right_shape(self):
        self.assertRegex(egress.AWF_VERSION, r"^v\d+\.\d+\.\d+$")
        self.assertRegex(egress.AWF_SHA256, r"^[0-9a-f]{64}$")
        for digest in egress.AWF_IMAGE_DIGESTS.values():
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")


class InnerScript(unittest.TestCase):
    def test_probe_runs_before_the_command_and_fails_closed(self):
        script = egress.inner_script("/tmp/obaaf-egress.abc", "/tmp/obaaf-egress.abc/workspace",
                                     "/tmp/obaaf-egress.abc/command.sh", "/tmp/obaaf-egress.abc/.m",
                                     "n" * 32, "example.com")
        probe = script.index("attempt \"direct IPv4")
        marker = script.index("> '/tmp/obaaf-egress.abc/.m'")
        command = script.index("exec /bin/bash -e '/tmp/obaaf-egress.abc/command.sh'")
        self.assertLess(probe, marker)
        self.assertLess(marker, command)
        self.assertIn(f"exit {egress.EXIT_NOT_CONFINED}", script[:marker])
        for what in ("direct IPv6", "unlisted host example.com", "sudo", "Docker socket"):
            self.assertIn(what, script)


class ActionFile(unittest.TestCase):
    def test_no_input_reaches_a_shell_line(self):
        text = (ROOT / "actions" / "egress" / "action.yml").read_text()
        for line in text.splitlines():
            if "${{ inputs." in line:
                # Inputs go to the environment of a step, never into a run line.
                self.assertRegex(line.strip(), r"^INPUT_[A-Z]+: \$\{\{ inputs\.[a-z]+ \}\}$")

    def test_python_runs_isolated(self):
        text = (ROOT / "actions" / "egress" / "action.yml").read_text()
        calls = re.findall(r"python3[^\n]*OBAAF_EGRESS_SCRIPT", text)
        self.assertTrue(calls)
        for call in calls:
            self.assertIn("python3 -I", call)


if __name__ == "__main__":
    unittest.main()
