"""What the egress action's own steps read of the variables a workflow sets for them (slice 2c.12, issue #198).

Slice 2c.12a measured which variables a workflow can set for the action's steps. This script is the
other half: it plants a file or a directory for each of those variables to name, watches them, and
judges what was opened. The escape tests' own-steps-environment job sets the variables in the env of
one step at a time (a plain step, the action at the floor before this slice, the action now), so
whatever is opened while that step runs was opened by that step's processes.

  python3 -I environment-watch.py plant DIR      make the files and directories, and print the env lines
  python3 -I environment-watch.py plant-locale   as root: make the locale directory LC_ALL and LANG name
  python3 -I environment-watch.py watch DIR LOG  watch them and the proxy port until killed (run in the background)
  python3 -I environment-watch.py judge LOGDIR   read LOGDIR/seen-control, seen-floor and seen-now

glibc looks for a locale only under /usr/lib/locale (LOCPATH, which would move that, is among the
loader's variables the action empties), so a workflow's LC_ALL or LANG can only name a locale the
runner has. To see that it is read, plant-locale makes one there, which needs root; the escape tests
run it with sudo. Everything else is planted in DIR, as a workflow without sudo could.

The watch uses inotify through ctypes (the standard library has no binding) and reports opens and
reads, never contents. The proxy is a listener on 127.0.0.1 that records that something connected and
closes the connection. Every planted file holds made-up bytes; none is a secret, and nothing here is
given a key.
"""
from __future__ import annotations

import ctypes
import os
import select
import socket
import struct
import sys
import threading
from pathlib import Path

PROXY_PORT = 18473
IN_ACCESS, IN_OPEN = 0x1, 0x20
LOCALE_NAME = "obaaf-planted"
LOCALE_DIR = Path("/usr/lib/locale") / LOCALE_NAME
LOCALE = "locale"                      # what the watch calls LOCALE_DIR

# name -> (what is planted, relative to DIR; "file" or "dir"), and the value the variable is given.
# LC_ALL, LANG and TZ are read by glibc and Python while Python starts; the rest when first needed.
# LANGUAGE names a directory of message catalogues, relative to /usr/share/locale, and glibc lets it
# hold "../" in a program that is not setuid; it is read only in a locale other than "C".
PLANTED = {
    "LANGUAGE": ("language", "dir", "../../../..{dir}/language"),
    "TZ": ("zone", "file", ":{dir}/zone"),
    "SSL_CERT_FILE": ("ca.pem", "file", "{dir}/ca.pem"),
    "SSL_CERT_DIR": ("ca-dir", "dir", "{dir}/ca-dir"),
    "HOME": ("home", "dir", "{dir}/home"),
    "TEMP": ("temp", "dir", "{dir}/temp"),
    "TMP": ("temp", "dir", "{dir}/temp"),
    "DOCKER_CONFIG": ("docker-config", "dir", "{dir}/docker-config"),
    "XDG_RUNTIME_DIR": ("xdg", "dir", "{dir}/xdg"),
    "SUDO_ASKPASS": ("askpass", "file", "{dir}/askpass"),
}
# Set as well, with nothing planted in DIR: the locale plant-locale makes, a proxy that is this
# script's listener (in upper case: a workflow's env keys are case-insensitive, and urllib.request
# reads either case), a docker endpoint that does not exist (a docker command given it fails, and the
# action with it), and two flags.
UNWATCHED = {
    "LC_ALL": LOCALE_NAME,
    "LANG": LOCALE_NAME,
    "HTTPS_PROXY": f"http://127.0.0.1:{PROXY_PORT}",
    "DOCKER_HOST": "unix://{dir}/no-such-docker.sock",
    "DOCKER_CONTEXT": "obaaf-no-such-context",
    "CI": "obaaf-planted",
    "NODE_OPTIONS": "--title=obaaf-planted",
}
# Inside the planted directories, the files a reader would look for.
INSIDE = ("language/LC_MESSAGES/libc.mo", "home/.docker/config.json", "home/.docker/cli-plugins/docker-compose", "docker-config/config.json",
          "ca-dir/00000000.0")
STARTUP = (LOCALE, "zone")             # read before a step's first line
LATER = ("ca.pem", "proxy")            # read by the install step's one download
PROXY = "proxy"


def values(directory: str) -> dict[str, str]:
    out = {name: value.format(dir=directory) for name, (_, _, value) in PLANTED.items()}
    out.update({name: value.format(dir=directory) for name, value in UNWATCHED.items()})
    return out


def plant(directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    for relative, kind, _ in PLANTED.values():
        path = directory / relative
        if kind == "dir":
            path.mkdir(parents=True, exist_ok=True)
        elif not path.exists():
            path.write_bytes(b"obaaf planted file, not a real one\n")
    for relative in INSIDE:
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"obaaf planted file, not a real one\n")
    for relative in ("askpass", "home/.docker/cli-plugins/docker-compose"):
        script = directory / relative
        script.write_text(f"#!/bin/sh\necho 'ran {relative}' >> '{directory}/ran'\n")
        script.chmod(0o755)
    for name, value in sorted(values(str(directory)).items()):
        print(f"{name}={value}")
    return 0


def plant_locale() -> int:
    try:
        LOCALE_DIR.mkdir(parents=True, exist_ok=True)
        (LOCALE_DIR / "LC_CTYPE").write_bytes(b"obaaf planted file, not a real one\n")
    except OSError as error:
        print(f"cannot make {LOCALE_DIR} (this needs root): {error}", file=sys.stderr)
        return 1
    return 0


def _watched(directory: Path) -> dict[Path, str]:
    """Every planted directory (each reports the opens of the files in it) and every planted file,
    with the name the log gives it."""
    paths = {directory / relative for relative, _, _ in PLANTED.values()}
    paths |= {(directory / relative).parent for relative in INSIDE}
    named = {path: str(path.relative_to(directory)) for path in sorted(paths)}
    named[LOCALE_DIR] = LOCALE
    return named


def watch(directory: Path, log: Path) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(0)
    if fd < 0:
        print("inotify is not available", file=sys.stderr)
        return 1
    names = {}
    for path, name in _watched(directory).items():
        wd = libc.inotify_add_watch(fd, os.fsencode(path), IN_OPEN | IN_ACCESS)
        if wd < 0:
            print(f"cannot watch {path}", file=sys.stderr)
            return 1
        names[wd] = name
    lock = threading.Lock()

    def note(what: str) -> None:
        with lock, open(log, "a", encoding="utf-8") as out:
            out.write(what + "\n")

    def proxy() -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", PROXY_PORT))
        server.listen(8)
        (log.parent / "watch-ready").write_text("ready\n")
        while True:
            connection, _ = server.accept()
            note(PROXY)
            connection.close()

    threading.Thread(target=proxy, daemon=True).start()
    while True:
        select.select([fd], [], [])
        data = os.read(fd, 65536)
        offset = 0
        while offset + 16 <= len(data):
            wd, _mask, _cookie, length = struct.unpack_from("iIII", data, offset)
            inside = data[offset + 16:offset + 16 + length].split(b"\0", 1)[0].decode("utf-8", "replace")
            offset += 16 + length
            base = names.get(wd, "?")
            note(base + ("/" + inside if inside else ""))


def _seen(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def _groups(seen: set[str]) -> set[str]:
    """What was seen, by what was planted for it: 'locale/LC_CTYPE' is the planted 'locale'."""
    return {line.split("/", 1)[0] for line in seen}


def judge(logs: Path) -> int:
    fail = 0

    def ok(text: str) -> None:
        print("ok: " + text)

    def bad(text: str) -> None:
        nonlocal fail
        print("FAILED: " + text)
        fail = 1

    seen = {phase: _seen(logs / f"seen-{phase}") for phase in ("control", "floor", "now")}
    for phase, lines in seen.items():
        print(f"--- seen-{phase}: " + (", ".join(sorted(lines)) or "(nothing)"))
    control, floor, now = (_groups(seen[phase]) for phase in ("control", "floor", "now"))
    # The control shows the watch works on this runner: a plain step run as the action's steps are,
    # with the same variables, opens the locale and the zone as it starts and, for one download, the
    # CA file and the proxy.
    for what in STARTUP + LATER:
        if what in control:
            ok(f"control: a plain step with these variables used the planted {what}")
        else:
            bad(f"control: the planted {what} was not used, so the watch shows nothing about it on this runner")
    # The action before this slice: what a workflow set reached its key-holding steps.
    for what in STARTUP:
        if what in floor:
            ok(f"the action at the floor before this slice opened the planted {what} as its steps started")
        else:
            bad(f"the action at the floor did not open the planted {what}; the record of what this slice fixes is wrong")
    for what in LATER:
        if what in floor:
            ok(f"the action at the floor used the planted {what} for its download")
        else:
            bad(f"the action at the floor did not use the planted {what}; the record of what this slice fixes is wrong")
    # The action now: nothing.
    if now:
        bad("the action now used what the workflow set for its steps: " + ", ".join(sorted(seen["now"])))
    else:
        ok("the action now opened none of the planted files and directories and did not use the proxy")
    ran = logs.parent / "planted" / "ran"
    if ran.exists():
        bad("a planted program ran: " + ran.read_text(encoding="utf-8").replace("\n", "; "))
    else:
        ok("no planted program (the askpass, the docker plug-in) ran")
    return fail


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "plant":
        return plant(Path(argv[1]))
    if argv == ["plant-locale"]:
        return plant_locale()
    if len(argv) == 3 and argv[0] == "watch":
        return watch(Path(argv[1]), Path(argv[2]))
    if len(argv) == 2 and argv[0] == "judge":
        return judge(Path(argv[1]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
