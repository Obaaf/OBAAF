#!/usr/bin/env python3
"""Judge of the egress escape tests (slice 2c.2).

Two modes:

  judge.py snapshot OUT.json
      Record the files a confined command must not be able to change.

  judge.py judge --outside-pcap F --inside-pcap F --resolved F.json
                 --outside-prefix P --inside-prefix P --record-prefix P
                 --outside-results F --inside-results F --snapshot F.json
                 --action-exit N [--summary F] [--json-out F]

The verdict on every network attempt comes from packet captures taken on the
runner's external interface, outside the sandbox: one while the attempts ran
outside it (each must be seen leaving: the control), one while they ran
inside it (none may be seen). The confined command's own exit statuses are
printed for the record and decide nothing, except for the one thing that must
still work: a request to the listed host.

An attempt whose control was not seen leaving is reported as "not testable
here", never as blocked. It fails the job for IPv4 attempts (the runner has
IPv4, so a failed control means the test is broken) and is only recorded for
IPv6 (a runner may have no IPv6 route at all).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Must match attempts.sh. Each entry: addresses the attempt connects to,
# host names whose addresses (resolved outside, before the attempts) it
# connects to, and label suffixes it puts in DNS queries or payloads.
ATTEMPTS: dict[str, dict] = {
    "https-unlisted": {"hosts": ["example.org"]},
    "http-unlisted": {"hosts": ["example.net"]},
    "noproxy-unlisted": {"hosts": ["example.org"]},
    "proxy-override": {"ips": ["208.67.220.123"]},
    "ip-443-direct": {"ips": ["1.1.1.1"]},
    "ip-443-via-proxy": {"ips": ["1.0.0.1"]},
    "ip-other-port": {"ips": ["208.67.220.220"]},
    "dns-udp-other": {"ips": ["9.9.9.9"], "labels": ["dnsudp"]},
    "dns-tcp-other": {"ips": ["149.112.112.112"], "labels": ["dnstcp"]},
    "doh-name": {"hosts": ["cloudflare-dns.com"]},
    "doh-address": {"ips": ["1.1.1.3"]},
    "dns-two-in-one": {"ips": ["149.112.112.10"], "labels": ["two1", "two2"]},
    "ipv6-direct": {"ips": ["2606:4700:4700::1111"], "ipv6": True},
    "ipv6-dns": {"ips": ["2620:fe::fe"], "labels": ["dns6"], "ipv6": True},
    "sendto": {"ips": ["1.1.1.2"], "labels": ["sendto"]},
    "sendmsg": {"ips": ["1.0.0.2"], "labels": ["sendmsg"]},
    "tls-no-sni": {"ips": ["149.112.112.11"]},
    "child-process": {"ips": ["9.9.9.11"]},
    "background": {"ips": ["1.0.0.3"]},
    "sudo-net": {"ips": ["9.9.9.10"]},
    # Outside, this is `sudo -n iptables -S`; its control is that command's
    # success. Inside, it flushes the rules and connects to 9.9.9.10.
    "sudo-iptables": {"ips": ["9.9.9.10"], "control_by_result": True},
    "docker-socket": {"ips": ["208.67.222.222"]},
    # Slice 2c.4: a name asked of the proxy (over HTTPS and HTTP, the proxy
    # named explicitly) and a name the command looks up itself must not leave
    # the runner in a DNS query. Outside, the same names are looked up by the
    # runner's resolver and leave. The command's own lookups never reached the
    # action's resolver (AWF gives the command's container Docker's resolver):
    # they are regression tests, not tests of the resolver.
    "dns-via-proxy": {"labels": ["viaproxy"]},
    "dns-via-proxy-http": {"labels": ["plainproxy"]},
    "dns-default-getent": {"labels": ["getent"]},
    "dns-default-dig": {"labels": ["digdefault"]},
}

# Slice 2c.6: counts the attempts script reports as "RESULT <id> <bad> <total>",
# where <bad> must be 0 inside the sandbox; outside, a non-zero <bad> is the
# control. A runner where nothing listens outside makes the attempt "not
# testable here", recorded and not failed: whether the hosted runner's .NET
# programs listen in /tmp is what the attempt finds out.
ENDPOINT_ATTEMPTS = {
    "tmp-socket-connect": "sockets in the runner's /tmp accepted a connection",
    "tmp-pipe-writable": "named pipes in the runner's /tmp were writable",
    "dotnet-diagnostics": ".NET diagnostic sockets answered a request",
}

# Entries the attempts script makes inside the scratch directory, which the
# action must delete after the run and list in its removed output (relative
# to the scratch directory).
SPECIAL_PLANTED = [
    "workspace/escape-link-environ",
    "workspace/escape-link-runner-temp",
    "workspace/escape-link-relative",
    "workspace/escape-dir/escape-link-root",
    "workspace/escape-fifo",
    "workspace/escape-socket",
    "home/.cache/escape-link-home",
    "workspace/escape-locked/escape-link-hidden",
]

# Files a confined command must not be able to create or change.
PLANTED = [
    "~/.local/bin/git",
    "~/.config/git/config",
    "~/.gitconfig",
    "/tmp/obaaf-planted",
    "$RUNNER_TEMP/obaaf-planted",
    "$GITHUB_WORKSPACE/obaaf-planted",
    "$GITHUB_WORKSPACE/.git/hooks/post-checkout",
]


def _expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path)))


def _digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def snapshot(out: Path) -> int:
    data = {str(_expand(p)): _digest(_expand(p)) for p in PLANTED}
    out.write_text(json.dumps(data, indent=1) + "\n")
    print(json.dumps(data, indent=1))
    return 0


def _tcpdump(pcap: Path, ascii_payload: bool) -> str:
    argv = ["tcpdump", "-nn", "-r", str(pcap)]
    if ascii_payload:
        argv.insert(2, "-A")
    done = subprocess.run(argv, capture_output=True, text=True, errors="replace", check=False)
    if done.returncode != 0 and not done.stdout:
        raise SystemExit(f"tcpdump could not read {pcap}: {done.stderr.strip()}")
    return done.stdout


def _addresses_seen(headers: str) -> set[str]:
    """Every IPv4 and IPv6 address that appears as a source or destination."""
    seen: set[str] = set()
    for line in headers.splitlines():
        # "IP src.port > dst.port: ..." or "IP6 src.port > dst.port: ..."; an IPv6
        # address holds colons, but never a colon followed by a space.
        match = re.search(r"\bIP6? (\S+) > (\S+):\s", line)
        if not match:
            continue
        for end in match.groups():
            # tcpdump writes address.port for both families.
            address = end.rsplit(".", 1)[0] if end.count(".") in (1, 4) or ":" in end else end
            seen.add(address)
    return seen


def _answers(headers: str, hosts: list[str]) -> dict[str, set[str]]:
    """Addresses that DNS answers in a capture gave for each host.

    tcpdump prints a query as "id+ A? name. (n)" and its answer as
    "id n/n/n A addr, A addr (n)" without the name, so answers are matched to
    queries by DNS id. Used so that a host whose addresses changed after they
    were resolved at the start is still recognised.
    """
    names: dict[str, str] = {}
    found: dict[str, set[str]] = {host: set() for host in hosts}
    for line in headers.splitlines():
        # The id may carry flag characters (+ recursion desired, $ AD, * AA, | TC, % CD, -).
        query = re.search(r": (\d+)[+*|$%-]* .*?\b(?:A|AAAA)\? ([A-Za-z0-9.-]+)\. ", line)
        if query:
            names[query.group(1)] = query.group(2).lower()
            continue
        answer = re.search(r": (\d+)[+*|$%-]* (?:[A-Za-z]+ )?\d+/\d+/\d+ (.*)$", line)
        if answer and answer.group(1) in names:
            name = names[answer.group(1)]
            for host in hosts:
                if name == host or name.endswith("." + host):
                    found[host].update([a.rstrip(",.") if a.count(".") != 3 else a.rstrip(",") for a in re.findall(r"\b(?:AAAA|A) ([0-9A-Fa-f:.]+)", answer.group(2))])
    return found


def _results(path: Path) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    plants: list[str] = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return results
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "RESULT":
            if parts[1] == "plant":
                plants.append(" ".join(parts[2:]))
            else:
                results[parts[1]] = parts[2:]
    results["__plants__"] = plants
    return results


def judge(args: argparse.Namespace) -> int:
    resolved: dict[str, list[str]] = json.loads(Path(args.resolved).read_text())
    out_headers = _tcpdump(Path(args.outside_pcap), False)
    out_ascii = _tcpdump(Path(args.outside_pcap), True)
    in_headers = _tcpdump(Path(args.inside_pcap), False)
    in_ascii = _tcpdump(Path(args.inside_pcap), True)
    out_seen = _addresses_seen(out_headers)
    in_seen = _addresses_seen(in_headers)
    out_results = _results(Path(args.outside_results))
    in_results = _results(Path(args.inside_results))

    failures: list[str] = []
    rows: list[tuple[str, str, str, str]] = []
    forbidden: set[str] = set()

    hosts = sorted({h for spec in ATTEMPTS.values() for h in spec.get("hosts", [])})
    learned = _answers(out_headers, hosts)
    for host, addresses in _answers(in_headers, hosts).items():
        learned[host].update(addresses)
    for attempt, spec in ATTEMPTS.items():
        ips = list(spec.get("ips", []))
        for host in spec.get("hosts", []):
            ips.extend(resolved.get(host, []))
            ips.extend(sorted(learned.get(host, set())))
        forbidden.update(ips)
        labels = spec.get("labels", [])

        # Control: outside, it must be seen leaving.
        if spec.get("control_by_result"):
            control = out_results.get(attempt, ["?"])[0] == "0"
        else:
            control = any(ip in out_seen for ip in ips) or any(
                f"{args.outside_prefix}-{label}" in out_ascii for label in labels)
        # Inside: nothing of it may be seen.
        escaped_ips = sorted(ip for ip in ips if ip in in_seen)
        escaped_labels = sorted(label for label in labels if f"{args.inside_prefix}-{label}" in in_ascii)
        inside_status = " ".join(in_results.get(attempt, ["not run"]))

        if escaped_ips or escaped_labels:
            verdict = "GOT OUT: " + ", ".join(escaped_ips + escaped_labels)
            failures.append(f"{attempt} got out ({', '.join(escaped_ips + escaped_labels)})")
        elif attempt not in in_results:
            # Nothing was tried inside, so nothing was blocked.
            verdict = "not attempted inside (the confined command did not run it)"
            failures.append(f"{attempt} was not attempted inside the sandbox")
        elif not control:
            verdict = "not testable here (the control did not get out)"
            if not spec.get("ipv6"):
                failures.append(f"{attempt}: the control outside the sandbox did not get out, so the test proves nothing")
        else:
            verdict = "blocked"
        rows.append((attempt, "got out" if control else "did not get out", verdict, inside_status))

    # Programs on the runner that listen in /tmp (slice 2c.6).
    def _counts(results: dict[str, list[str]], key: str) -> tuple[int, int] | None:
        value = results.get(key, [])
        try:
            return int(value[0]), int(value[1])
        except (IndexError, ValueError):
            return None

    for attempt, what in ENDPOINT_ATTEMPTS.items():
        inside, outside = _counts(in_results, attempt), _counts(out_results, attempt)
        control = f"{outside[0]} of {outside[1]}" if outside else "not run"
        status = f"{inside[0]} of {inside[1]}" if inside else " ".join(in_results.get(attempt, ["not run"]))
        if inside is None:
            verdict = "not attempted inside (the confined command did not run it)"
            failures.append(f"{attempt} was not attempted inside the sandbox")
        elif inside[0] > 0:
            verdict = f"GOT OUT: {inside[0]} of {inside[1]}"
            failures.append(f"{attempt}: {inside[0]} of {inside[1]} {what} from inside the sandbox")
        elif not outside or outside[0] == 0:
            verdict = "not testable here (none outside)"
        else:
            verdict = "blocked"
        rows.append((attempt, control, verdict, status))

    # The capture must have seen the run at all: the listed host was reached
    # from inside (asserted below), so traffic to it, or a lookup of it, must
    # be in the inside capture. Without it, an empty capture would judge every
    # attempt blocked.
    api_addresses = set(resolved.get("api.github.com", []))
    api_addresses |= _answers(in_headers, ["api.github.com"])["api.github.com"]
    api_addresses |= _answers(out_headers, ["api.github.com"])["api.github.com"]
    if not (api_addresses & in_seen) and not re.search(r"\? api\.github\.com\. ", in_headers):
        failures.append("the capture taken while the attempts ran inside shows no traffic to the listed host "
                        "api.github.com and no lookup of it, so it may have captured nothing")

    # Links, pipes, sockets and device files in the scratch directory (slice 2c.6).
    special_left: list[str] = []
    if args.scratch:
        found = subprocess.run(["sudo", "-n", "find", args.scratch, "!", "-type", "f", "!", "-type", "d", "-print0"],
                               capture_output=True, check=False)
        prefix = args.scratch.rstrip("/") + "/"
        special_left = [p.decode(errors="replace").removeprefix(prefix) for p in found.stdout.split(b"\0") if p]
        if found.returncode != 0:
            failures.append(f"the judge could not list the scratch directory (find status {found.returncode})")
        if special_left:
            failures.append("links, pipes or sockets are left in the scratch directory after the run: "
                            + ", ".join(special_left[:10]))
        removed = set((args.removed or "").split(","))
        missing = [name for name in SPECIAL_PLANTED if name not in removed]
        if missing:
            failures.append("the action's removed output does not list " + ", ".join(missing))
        planted = in_results.get("plant-special", ["0"])[0]
        if planted != str(len(SPECIAL_PLANTED)):
            failures.append(f"the attempts made {planted} of the {len(SPECIAL_PLANTED)} links, pipes and sockets, "
                            "so the test does not show them all removed")
    else:
        failures.append("the judge was not given the scratch directory, so it could not check what is left in it")

    # Anything else to a forbidden address, whichever attempt sent it.
    stray = sorted(ip for ip in forbidden if ip in in_seen)
    if stray:
        failures.append(f"packets to forbidden addresses while the attempts ran inside: {', '.join(stray)}")
    if args.inside_prefix in in_ascii:
        failures.append(f"the inside label {args.inside_prefix} appears in the capture of the external interface")

    # Must still work. curl checks the server's certificate against the
    # runner's own trust store (AWF adds no authority of its own without
    # --ssl-bump, which the action never passes), so status 0 with any HTTP
    # code means the listed host's own server answered. Its code is not
    # asserted: api.github.com answers 403 to an address that has used up
    # GitHub's limit for requests without a token, outside the sandbox too.
    allowed = in_results.get("allowed-https", [])
    if len(allowed) < 2 or allowed[0] != "0" or not re.fullmatch(r"[1-5][0-9][0-9]", allowed[1]):
        failures.append(f"the listed host did not answer inside the sandbox (curl status and HTTP code: {' '.join(allowed) or 'none'})")

    # The action itself must have run the command and returned its status.
    if str(args.action_exit) != "0":
        failures.append(f"the action's exit-code output is {args.action_exit!r}, expected 0 (the attempts script always exits 0)")
    if str(args.action_confined) != "true":
        failures.append(f"the action's confined output is {args.action_confined!r}: it failed the step itself (probe, runner files or cleanup)")

    # Left behind.
    before = json.loads(Path(args.snapshot).read_text())
    left: list[str] = []
    for path, digest in before.items():
        now = _digest(Path(path))
        if now != digest:
            left.append(path)
    if left:
        failures.append(f"files changed or created outside the scratch directory: {', '.join(left)}")
    planted_ok = [p for p in in_results.get("__plants__", []) if p.endswith(" 0")]
    runner_files = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")) / "_runner_file_commands"
    leaked_cmds = []
    if runner_files.is_dir():
        for f in runner_files.iterdir():
            try:
                if "OBAAF_PLANTED" in f.read_text(errors="replace"):
                    leaked_cmds.append(f.name)
            except OSError:
                pass
    if leaked_cmds:
        failures.append(f"the runner's file commands hold a line written from inside: {', '.join(leaked_cmds)}")
    if os.environ.get("OBAAF_PLANTED_ENV") or os.environ.get("OBAAF_PLANTED"):
        failures.append("a variable set from inside the sandbox reached a later step")
    if "/tmp/obaaf-planted-path" in os.environ.get("PATH", ""):
        failures.append("a PATH entry added from inside the sandbox reached a later step")

    # No unlisted name the attempts or the action's probe used may leave the
    # runner in a DNS query (slice 2c.4: before it, the proxy's resolver sent
    # every name it was asked for).
    queried = sorted({m.group(1) for m in re.finditer(r"\? ([A-Za-z0-9.-]+)\. ", in_headers)
                      if any(m.group(1) == h or m.group(1).endswith("." + h)
                             for h in ("example.org", "example.net", "example.com", "cloudflare-dns.com"))})
    if queried:
        failures.append("unlisted names left the runner in DNS queries while the attempts ran inside: "
                        + ", ".join(q.replace(args.record_prefix, "<label>").replace(args.inside_prefix, "<label>") for q in queried))
    # The names asked of the proxy must have reached the action's resolver and
    # been refused there; otherwise the two attempts did not test it.
    refused_names = set((args.dns_refused or "").split(","))
    for label in ("viaproxy", "plainproxy"):
        if f"{args.inside_prefix}-{label}.example.com" not in refused_names:
            failures.append(f"the name {args.inside_prefix}-{label}.example.com is not among the names the action's "
                            "resolver refused, so the proxy did not ask it and the attempt did not test the resolver")

    # Recorded, not asserted.
    recorded = {
        "names the action's resolver refused (its dns-refused output)":
            (args.dns_refused or "none").replace(args.inside_prefix, "<label>"),
        "Host header that differs from the allowed name (curl status, HTTP code)":
            " ".join(in_results.get("host-mismatch", ["not run"])),
        "files the confined command reported writing outside the scratch directory (the judge checks the runner's copies above)":
            ", ".join(planted_ok) or "none",
        "entries the action deleted from the scratch directory (its removed output)":
            args.removed or "none",
    }

    facts = []
    try:
        facts = [line for line in Path(args.inside_results).read_text(errors="replace").splitlines() if line.startswith("FACT ")]
    except OSError:
        pass

    lines = ["## Egress escape tests\n\n",
             "Judge: packet captures on the runner's external interface, outside the sandbox. "
             "A control is the same attempt made outside the sandbox first.\n\n",
             "| Attempt | Control (outside) | Inside the sandbox | Command's own status inside |\n",
             "| --- | --- | --- | --- |\n"]
    for attempt, control, verdict, status in rows:
        lines.append(f"| `{attempt}` | {control} | {verdict} | {status} |\n")
    allowed_out = out_results.get("allowed-https", [])
    lines.append(f"\nMust still work, the listed host: curl status and HTTP code `{' '.join(allowed) or 'none'}` "
                 f"(outside the sandbox: `{' '.join(allowed_out) or 'none'}`)\n\n")
    lines.append("No unlisted name left the runner in a DNS query.\n\n" if not queried else
                 "**Unlisted names left the runner in DNS queries** (see Failed, below).\n\n")
    lines.append("Recorded, not asserted:\n\n")
    for key, value in recorded.items():
        lines.append(f"- {key}: `{value}`\n")
    lines.append("\nFiles outside the scratch directory, before and after: "
                 + ("unchanged\n" if not left else "**changed: " + ", ".join(left) + "**\n"))
    lines.append("\nFacts about the sandbox, reported from inside it:\n\n```\n" + "\n".join(facts) + "\n```\n")
    if failures:
        lines.append("\n**Failed:**\n\n" + "".join(f"- {f}\n" for f in failures))
    else:
        lines.append("\n**Every asserted attempt was blocked, and the listed host worked.**\n")
    text = "".join(lines)
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "rows": rows, "failures": failures, "recorded": recorded, "facts": facts}, indent=1) + "\n")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("out")
    j = sub.add_parser("judge")
    for name in ("outside-pcap", "inside-pcap", "resolved", "outside-prefix", "inside-prefix",
                 "record-prefix", "outside-results", "inside-results", "snapshot", "action-exit",
                 "action-confined"):
        j.add_argument(f"--{name}", required=True)
    j.add_argument("--summary")
    j.add_argument("--json-out")
    j.add_argument("--dns-refused", default="")
    j.add_argument("--scratch", default="")
    j.add_argument("--removed", default="")
    args = parser.parse_args()
    if args.mode == "snapshot":
        return snapshot(Path(args.out))
    return judge(args)


if __name__ == "__main__":
    sys.exit(main())
