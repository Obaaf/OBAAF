"""Which variables a workflow can set for the egress action's own steps (slice 2c.12a, issue #198).

The escape tests' runner-variables jobs set every name in runner-variables.json three ways: in the
job's `env` (channel `job`), in the step's `env` (channel `step`), and with a line written to
GITHUB_ENV by an earlier step (channel `genv`). For each way, a plain step and a step of a composite
action, both run as the egress action's own steps are (`/usr/bin/python3 -I -S`), record what they
see (tests/egress/runner-variables-probe). This script gives the values to set and judges what was
seen against the file's `expected`. Every value is a made-up path or word; none is a secret.

  python3 -I runner-variables.py --github-env CHANNEL     lines for GITHUB_ENV
  python3 -I runner-variables.py --judge DIR              read DIR/<channel>-<plain|composite>.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DATA = Path(__file__).with_name("runner-variables.json")
CHANNELS = ("job", "step", "genv")
PROBES = ("plain", "composite")
# What a name the workflow set can come back as.
WORKFLOW, RUNNER, UNSET, NOT_SET_HERE, NOT_MEASURED = (
    "workflow's value", "runner's value", "unset", "not set by this test", "not measured")

_PROXIES = {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"}
_HOSTS = {"NO_PROXY", "no_proxy", "LOCALDOMAIN"}
_URLS = {"GITHUB_API_URL", "GITHUB_SERVER_URL"}
_WORDS = {"GITHUB_ACTIONS", "CI"}
_RES_OPTIONS = {"job": "timeout:1", "step": "timeout:2", "genv": "timeout:3"}


def load() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def marker(channel: str, name: str) -> str:
    """The value the test sets for `name` through `channel`. Each names its channel, so a value seen
    can be told from the runner's own and from another channel's."""
    if channel not in CHANNELS:
        raise ValueError(channel)
    if name in _PROXIES:
        return f"http://obaaf-rv-{channel}.invalid:9"
    if name in _HOSTS:
        return f"obaaf-rv-{channel}.invalid"
    if name in _URLS:
        return f"https://obaaf-rv-{channel}.invalid"
    if name in _WORDS:
        return f"obaaf-rv-{channel}"
    if name == "RES_OPTIONS":
        return _RES_OPTIONS[channel]
    if name == "NODE_OPTIONS":
        return f"--title=obaaf-rv-{channel}"
    return f"/tmp/obaaf-rv-{channel}/{name}"


def set_in(data: dict, channel: str) -> list[str]:
    """The names the test sets through `channel`. A workflow's env keys are case-insensitive, so the
    lower-case twins are set only through GITHUB_ENV. The job's env leaves out the names that would
    cut the job off from GitHub (its checkout, its upload), which the other two channels cover."""
    names = list(data["names"])
    if channel != "genv":
        names = [n for n in names if n not in data["case_twins"]]
    if channel == "job":
        names = [n for n in names if n not in data["network_names"]]
    return names


def classify(data: dict, channel: str, seen: dict | None) -> dict[str, str]:
    """How each name came back. A lower-case twin the channel did not set is judged by its upper-case
    twin's value, which is the same text, so the record shows whether setting one sets the other."""
    out = {}
    wanted = set(set_in(data, channel))
    for name in data["names"]:
        twin = data["case_twins"].get(name)
        if seen is None:
            out[name] = NOT_MEASURED
        elif name not in wanted and not (twin and twin in wanted):
            out[name] = NOT_SET_HERE
        elif name not in seen:
            out[name] = NOT_MEASURED
        elif seen[name] is None:
            out[name] = UNSET
        elif seen[name] == marker(channel, name):
            out[name] = WORKFLOW
        else:
            out[name] = RUNNER
    return out


def judge(directory: Path) -> int:
    data = load()
    observed: dict[str, dict[str, str]] = {}
    shown: dict[str, dict] = {}
    for channel in CHANNELS:
        for probe in PROBES:
            label = f"{channel}-{probe}"
            path = directory / f"{label}.json"
            seen = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
            shown[label] = seen or {}
            observed[label] = classify(data, channel, seen)
    labels = list(observed)
    width = max(len(n) for n in data["names"])
    print("name".ljust(width) + "  " + "  ".join(labels))
    for name in data["names"]:
        print(name.ljust(width) + "  " + "  ".join(observed[l][name].ljust(len(l)) for l in labels))
    print()
    # The runner's own value, where it kept one, so the record says what a step sees instead.
    for label in labels:
        for name, how in observed[label].items():
            if how == RUNNER:
                print(f"{label}: {name} kept the runner's value {shown[label].get(name)!r}")
    expected = data.get("expected")
    if expected is None:
        print("\nexpected is not recorded yet; this is what to record:")
        print(json.dumps(observed, indent=1, sort_keys=True))
        return 1
    fail = 0
    for label in labels:
        for name in data["names"]:
            want = expected.get(label, {}).get(name)
            got = observed[label][name]
            if want != got:
                print(f"FAILED: {label} {name}: expected {want!r}, saw {got!r}")
                fail = 1
    if not fail:
        print("ok: every name came back as recorded for every channel and probe")
    return fail


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--github-env":
        data = load()
        for name in set_in(data, argv[1]):
            print(f"{name}={marker(argv[1], name)}")
        return 0
    if len(argv) == 2 and argv[0] == "--judge":
        return judge(Path(argv[1]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
