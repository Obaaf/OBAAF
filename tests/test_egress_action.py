"""The egress control's own logic (actions/egress/egress.py), offline.

What the control blocks on a real runner is established by the escape tests in
.github/workflows/egress-escape-tests.yml, not here. These tests pin the parts
that need no runner: what the action accepts as an allow-list and as variable
names, and that the AWF command line it builds holds nothing from the workflow
but host names.
"""

from __future__ import annotations

import importlib.util
import os
import re
import tempfile
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
                                       "AWF_ANYTHING", "ACTIONS_RUNTIME_TOKEN", "BASH_ENV", "GIT_SSH_COMMAND",
                                       "OTEL_EXPORTER_OTLP_ENDPOINT", "ANTHROPIC_API_TARGET", "OPENAI_BASE_URL",
                                       "OPENAI_ENDPOINT_OVERRIDE", "FOUNDRY_ENDPOINT",
                                       "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "GH_TOKEN")}
        env.update({"MULTI": "a\nb", "NUL": "a\0b"})
        for bad in list(env) + ["1BAD", "BAD-NAME", "MISSING"]:
            with self.subTest(bad=bad):
                with self.assertRaises(egress.UsageError):
                    egress.parse_env_names(bad, env)


class CommandLine(unittest.TestCase):
    def test_fixed_options_and_pinned_images(self):
        argv = egress.awf_argv("/x/awf", ["api.github.com", "example.org"], "/p/c.json", "/p/e.env",
                               "/tmp/obaaf-egress.abc/workspace", "/p/work", "/p/logs", "/tmp/obaaf-egress.abc/i.sh",
                               "172.17.0.1")
        self.assertEqual(argv[0], "/x/awf")
        self.assertEqual(argv[argv.index("--allow-domains") + 1], "api.github.com,example.org")
        self.assertEqual(argv[-3:], ["--", "/bin/bash", "/tmp/obaaf-egress.abc/i.sh"])
        options = [a for a in argv[: argv.index("--")] if a.startswith("--")]
        self.assertEqual(argv[argv.index("--dns-servers") + 1], "172.17.0.1")
        self.assertEqual(options, ["--allow-domains", "--dns-servers", "--config", "--env-file", "--container-workdir",
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


class ModelKeys(unittest.TestCase):
    def test_the_two_tested_keys_with_their_values(self):
        env = {"ANTHROPIC_API_KEY": "sk-ant-x", "OPENAI_API_KEY": "sk-y", "OTHER": "z"}
        self.assertEqual(egress.parse_model_keys("ANTHROPIC_API_KEY, OPENAI_API_KEY", env),
                         {"ANTHROPIC_API_KEY": "sk-ant-x", "OPENAI_API_KEY": "sk-y"})
        self.assertEqual(egress.parse_model_keys("", env), {})

    def test_refused(self):
        env = {"GEMINI_API_KEY": "g", "GITHUB_TOKEN": "t", "OTHER": "o", "ANTHROPIC_API_KEY": "",
               "OPENAI_API_KEY": "a\nb"}
        for bad in ("GEMINI_API_KEY", "GITHUB_TOKEN", "OTHER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                    "1BAD", "BAD-NAME"):
            with self.subTest(bad=bad):
                with self.assertRaises(egress.UsageError):
                    egress.parse_model_keys(bad, env)
        with self.assertRaises(egress.UsageError):
            egress.parse_model_keys("ANTHROPIC_API_KEY", {})

    def test_env_points_a_model_key_at_model_keys(self):
        with self.assertRaisesRegex(egress.UsageError, "model-keys"):
            egress.parse_env_names("ANTHROPIC_API_KEY", {"ANTHROPIC_API_KEY": "k"})

    def test_the_resolver_answers_the_provider_host_only_when_its_key_is_given(self):
        self.assertEqual(egress.resolver_names(["api.github.com"], {}), ["api.github.com"])
        self.assertEqual(egress.resolver_names(["api.github.com"], {"ANTHROPIC_API_KEY": "k"}),
                         ["api.github.com", "=api.anthropic.com"])
        self.assertEqual(egress.resolver_names(["api.openai.com"], {"OPENAI_API_KEY": "k"}), ["api.openai.com"])
        self.assertEqual(egress.resolver_names(["openai.com"], {"OPENAI_API_KEY": "k"}), ["openai.com"])
        self.assertEqual(egress.read_resolver_names("api.github.com\n=api.anthropic.com\n"),
                         (["api.github.com"], ["api.anthropic.com"]))
        with self.assertRaises(egress.UsageError):
            egress.read_resolver_names("api.github.com\n=*.anthropic.com\n")

    def test_hosted_web_tools_are_refused_in_awf_config(self):
        config = egress.awf_config("/tmp/obaaf-egress.abc")
        self.assertEqual(config["filesystem"], {"allowWrite": ["/tmp/obaaf-egress.abc"]})
        self.assertEqual(config["apiProxy"]["hostedWeb"], {"claude": {"enabled": False}, "codex": {"enabled": False}})


def _question(message: bytes):
    return egress.dns_question(message)


class Resolver(unittest.TestCase):
    """The resolver given to AWF's proxy: what it passes on and what it refuses."""

    def test_reads_a_plain_query(self):
        query = egress.dns_query("API.GitHub.com", 0x1234, qtype=28)
        self.assertEqual(_question(query), ("api.github.com", 28, len(query)))

    def test_not_a_standard_one_question_query(self):
        query = bytearray(egress.dns_query("api.github.com", 1))
        response = bytearray(query)
        response[2] |= 0x80
        two = bytearray(query)
        two[5] = 2
        notify = bytearray(query)
        notify[2] |= 0x20  # opcode 4
        chaos = bytearray(query)
        chaos[-1] = 3      # class CH
        pointer = bytes(query[:12]) + b"\xc0\x0c" + bytes(query[-4:])
        for bad in (b"", b"\x00" * 11, bytes(response), bytes(two), bytes(notify), bytes(chaos), pointer,
                    bytes(query[:-2])):
            with self.subTest(bad=bad):
                self.assertIsNone(_question(bad))

    def test_a_label_that_could_hide_another_name_is_not_read_as_one(self):
        # One label "x.api.github" under "com": a name under com, not under api.github.com.
        dotted = bytes(12) + b"\x0cx.api.github\x03com\x00" + b"\x00\x01\x00\x01"
        dotted = b"\x00\x01\x01\x00\x00\x01" + dotted[6:]
        self.assertEqual(_question(dotted)[0], None)
        for label in (b"a b", b"a\x00", b"\xc3\xa9", b"a\\b"):
            with self.subTest(label=label):
                message = b"\x00\x01\x01\x00\x00\x01" + bytes(6) + bytes([len(label)]) + label + b"\x03com\x00\x00\x01\x00\x01"
                self.assertEqual(_question(message)[0], None)

    def test_a_label_ending_in_a_newline_is_not_a_plain_label(self):
        message = b"\x00\x01\x01\x00\x00\x01" + bytes(6) + b"\x02x\n\x03api\x06github\x03com\x00\x00\x01\x00\x01"
        self.assertIsNone(_question(message)[0])
        import io
        outgoing, reply = egress.DnsFilter(["api.github.com"], "127.0.0.1", io.StringIO()).decide(message)
        self.assertIsNone(outgoing)
        self.assertEqual(reply[3] & 0xF, egress.DNS_RCODE_REFUSED)

    def test_only_the_id_recursion_flag_and_question_are_forwarded(self):
        import io
        query = bytearray(egress.dns_query("api.github.com", 0x0102))
        query[2:4] = (0x0100 | 0x0010 | 0x0020).to_bytes(2, "big")  # RD, CD and the reserved Z bit
        query[10:12] = (1).to_bytes(2, "big")                            # one additional record
        opt = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0b\x00\x08\x00\x07\x00\x01\x18\x00leak"
        message = bytes(query) + opt + b"trailing-data"
        outgoing, reply = egress.DnsFilter(["api.github.com"], "127.0.0.1", io.StringIO()).decide(message)
        self.assertIsNone(reply)
        self.assertEqual(outgoing, egress.dns_query("api.github.com", 0x0102))
        self.assertNotIn(b"leak", outgoing)

    def test_refusal_keeps_id_question_and_recursion_flag(self):
        query = egress.dns_query("leak.example.com", 0xBEEF)
        name, qtype, end = _question(query)
        reply = egress.dns_refusal(query, end)
        self.assertEqual(reply[:2], b"\xbe\xef")
        flags = int.from_bytes(reply[2:4], "big")
        self.assertTrue(flags & 0x8000)
        self.assertEqual(flags & 0xF, egress.DNS_RCODE_REFUSED)
        self.assertTrue(flags & 0x0100)
        self.assertEqual(reply[4:12], b"\x00\x01" + bytes(6))
        self.assertEqual(reply[12:], query[12:end])
        self.assertIsNone(egress.dns_refusal(b"\x00", 0))

    def test_decide_forwards_only_covered_names(self):
        import io
        log = io.StringIO()
        deciding = egress.DnsFilter(["api.github.com"], "127.0.0.1", log, exact=["api.anthropic.com"])
        for name in ("api.github.com", "x.api.github.com", "api.anthropic.com"):
            outgoing, reply = deciding.decide(egress.dns_query(name, 7))
            self.assertIsNotNone(outgoing, name)
            self.assertIsNone(reply)
        for name in ("github.com", "evilapi.github.com", "api.github.com.evil.net", "leak-1234.example.com",
                     "leak.api.anthropic.com", "anthropic.com"):
            outgoing, reply = deciding.decide(egress.dns_query(name, 7))
            self.assertIsNone(outgoing, name)
            self.assertEqual(reply[3] & 0xF, egress.DNS_RCODE_REFUSED)
        outgoing, reply = deciding.decide(b"\x00\x09" + bytes(10))
        self.assertIsNone(outgoing)
        self.assertEqual(reply[3] & 0xF, egress.DNS_RCODE_FORMERR)
        self.assertIn("refused 1 leak-1234.example.com", log.getvalue())
        self.assertIn("allowed 1 api.github.com", log.getvalue())

    def test_forwards_to_the_upstream_and_returns_its_answer(self):
        import io
        import socket
        import threading
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        port = upstream.getsockname()[1]

        def answer():
            data, peer = upstream.recvfrom(512)
            upstream.sendto(data[:2] + b"\x81\x80" + data[4:], peer)

        thread = threading.Thread(target=answer, daemon=True)
        thread.start()
        deciding = egress.DnsFilter(["api.github.com"], "127.0.0.1", io.StringIO(), upstream_port=port)
        query = egress.dns_query("api.github.com", 0x4242)
        reply = deciding.forward_udp(query)
        thread.join(5)
        upstream.close()
        self.assertEqual(reply[:4], b"\x42\x42\x81\x80")

    def test_refused_names_in_the_summary_are_plain_text(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "dns.log"
            log.write_text("listening on ...\nrefused 1 leak.example.com\nrefused 28 leak.example.com\n"
                           "allowed 1 api.github.com\nrefused unreadable a`b\\032c\nrefused 1 x::warning::y\n")
            self.assertEqual(egress._dns_refused(log),
                             ["leak.example.com", "a?b\\032c", "x??warning??y"])

    def test_runner_resolver_is_the_first_ipv4_nameserver(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "resolv.conf"
            conf.write_text("# x\nsearch a\nnameserver ::1\nnameserver 127.0.0.53\nnameserver 8.8.8.8\n")
            self.assertEqual(egress.runner_resolver(str(conf)), "127.0.0.53")
            conf.write_text("search a\n")
            self.assertIsNone(egress.runner_resolver(str(conf)))
        self.assertIsNone(egress.runner_resolver("/nonexistent/resolv.conf"))


class InnerScript(unittest.TestCase):
    def test_probe_runs_before_the_command_and_fails_closed(self):
        script = egress.inner_script("/tmp/obaaf-egress.abc", "/tmp/obaaf-egress.abc/workspace",
                                     "/tmp/obaaf-egress.abc/command.sh", "/tmp/obaaf-egress.abc/.m",
                                     "n" * 32, "example.com")
        probe = script.index("attempt \"direct IPv4")
        marker = script.index("> '/tmp/obaaf-egress.abc/.m'")
        command = script.index("exec /bin/bash -e '/tmp/obaaf-egress.abc/command.sh'")
        cd = script.index("cd '/tmp/obaaf-egress.abc/workspace'")
        self.assertLess(probe, cd)
        self.assertLess(cd, marker)
        self.assertLess(marker, command)
        self.assertIn(f"exit {egress.EXIT_NOT_CONFINED}", script[:marker])
        for what in ("direct IPv6", "unlisted host example.com", "sudo", "Docker socket"):
            self.assertIn(what, script)

    def test_a_writable_socket_or_pipe_outside_the_scratch_directory_stops_the_command(self):
        script = egress.inner_script("/tmp/obaaf-egress.abc", "/tmp/obaaf-egress.abc/workspace",
                                     "/tmp/obaaf-egress.abc/command.sh", "/tmp/obaaf-egress.abc/.m",
                                     "n" * 32, "example.com")
        endpoints = script.index("endpoints=\"$(find /tmp /run /var /home /etc ")
        self.assertLess(endpoints, script.index("if [ \"$failed\" -ne 0 ]"))
        self.assertIn("-path '/tmp/obaaf-egress.abc'", script)
        self.assertIn("\\( -type s -o -type p \\) -writable -print", script)
        self.assertIn("sockets or pipes it could write ($endpoints) GOT OUT\"\n  failed=1", script)


class AfterTheRun(unittest.TestCase):
    """What the action reads back from the scratch directory and the proxy's
    log, which the command wrote or chose (slice 2c.6)."""

    def test_the_marker_is_read_only_from_a_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "m"
            marker.write_text("nonce\n")
            self.assertEqual(egress.read_marker(marker), "nonce\n")
            target = Path(tmp) / "elsewhere"
            target.write_text("nonce\n")
            link = Path(tmp) / "link"
            link.symlink_to(target)
            self.assertIsNone(egress.read_marker(link))
            fifo = Path(tmp) / "fifo"
            os.mkfifo(fifo)
            self.assertIsNone(egress.read_marker(fifo))  # and does not block
            self.assertIsNone(egress.read_marker(Path(tmp) / "absent"))

    def test_removed_entries_are_relative_and_plain_text(self):
        root = Path("/tmp/obaaf-egress.abc")
        data = b"/tmp/obaaf-egress.abc/workspace/a-1.txt\0/tmp/obaaf-egress.abc/home/b c\n$(x)`y`![z](w)\0"
        self.assertEqual(egress.split_null_list(data, root), ["workspace/a-1.txt", "home/b?c???x??y???z??w?"])

    def test_refused_hosts_come_from_the_request_and_are_plain_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "access.log"
            log.write_text(
                # A Host header the command chose, on a request for example.net.
                '1.0 172.30.0.20:1 $(curl$IFS@evil) 0.0.0.0:0 1.1 GET 403 TCP_DENIED:HIER_NONE http://example.net/x "c"\n'
                # A CONNECT to example.org sent with Host: api.github.com.
                '1.0 172.30.0.20:2 api.github.com:443 0.0.0.0:0 1.1 CONNECT 403 TCP_DENIED:HIER_NONE example.org:443 "c"\n'
                '1.0 172.30.0.20:3 x 0.0.0.0:0 1.1 CONNECT 403 TCP_DENIED:HIER_NONE $(id)`x`:443 "c"\n'
                '1.0 172.30.0.20:4 api.github.com:443 1.2.3.4:443 1.1 CONNECT 200 TCP_TUNNEL:HIER_DIRECT api.github.com:443 "c"\n')
            self.assertEqual(egress._denied_hosts(Path(tmp)), ["example.net", "example.org", "??id??x?"])


class GitCredentials(unittest.TestCase):
    """The action refuses a workspace where a checkout kept its token (slice 2c.6)."""

    def tree(self, files: dict[str, str]) -> Path:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        for name, text in files.items():
            path = tmp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return tmp

    def test_no_kept_token(self):
        root = self.tree({".git/config": "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/o/r\n",
                          "src/config": "extraheader = not a git configuration\n"})
        self.assertIsNone(egress.git_credentials(root))

    def test_a_token_in_the_configuration_before_checkout_v6(self):
        root = self.tree({".git/config": '[http "https://github.com/"]\n\textraheader = AUTHORIZATION: basic x\n'})
        self.assertIn("extraheader", egress.git_credentials(root))

    def test_an_included_file_as_checkout_v6_and_later_write(self):
        root = self.tree({".git/config": '[core]\n[includeIf "gitdir:/home/runner/work/r/r/.git"]\n\tpath = /home/runner/work/_temp/x.config\n'})
        self.assertIn("includes another file", egress.git_credentials(root))
        root = self.tree({".git/config": "[Include]\n\tpath = x\n"})
        self.assertIn("includes another file", egress.git_credentials(root))

    def test_a_token_in_a_remote_url_or_a_worktree_configuration(self):
        root = self.tree({".git/config": '[remote "origin"]\n\turl = https://x-access-token:ghs_abc@github.com/o/r\n'})
        self.assertIn("remote URL", egress.git_credentials(root))
        root = self.tree({".git/config": "[core]\n", ".git/worktrees/w/config.worktree": "[http]\n\textraheader = x\n"})
        self.assertIn("config.worktree", egress.git_credentials(root))
        root = self.tree({".git/config": '[remote "origin"]\n\turl = git@github.com:o/r.git\n'})
        self.assertIsNone(egress.git_credentials(root))

    def test_the_refusal_says_why(self):
        error = egress.UsageError("x", reason="credential")
        self.assertEqual(error.reason, "credential")
        self.assertEqual(egress.UsageError("x").reason, "input")

    def test_a_second_checkout_or_a_submodule(self):
        for name in ("other/.git/config", ".git/modules/sub/config"):
            root = self.tree({".git/config": "[core]\n", name: '[http]\n\textraHeader = x\n'})
            self.assertIn(name, egress.git_credentials(root))


class ActionFile(unittest.TestCase):
    def test_no_input_reaches_a_shell_line(self):
        text = (ROOT / "actions" / "egress" / "action.yml").read_text()
        for line in text.splitlines():
            if "${{ inputs." in line:
                # Inputs go to the environment of a step, never into a run line.
                self.assertRegex(line.strip(), r"^INPUT_[A-Z_]+: \$\{\{ inputs\.[a-z][a-z-]* \}\}$")

    def test_the_removed_output_is_declared(self):
        text = (ROOT / "actions" / "egress" / "action.yml").read_text()
        self.assertIn("value: ${{ steps.run.outputs.removed }}", text)

    def test_python_runs_isolated(self):
        text = (ROOT / "actions" / "egress" / "action.yml").read_text()
        calls = re.findall(r"python3[^\n]*OBAAF_EGRESS_SCRIPT", text)
        self.assertTrue(calls)
        for call in calls:
            self.assertIn("python3 -I", call)


if __name__ == "__main__":
    unittest.main()
