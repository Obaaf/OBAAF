"""Compare the egress action's LOADER_VARIABLES with the runner's own dynamic loader (slice 2c.9).

    python3 -I loader-names.py <egress.py> [<ld.so>]

The loader keeps, as one run of NUL-separated names, the variables it removes
from the environment of a setuid program (glibc's UNSECURE_ENVVARS). The
action empties each of them in its steps' env. This prints the runner's list
and exits 1 if it has a name the action does not empty, or if no such list is
found.
"""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("obaaf_egress_action", sys.argv[1])
egress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(egress)
data = Path(sys.argv[2] if len(sys.argv) > 2 else "/lib64/ld-linux-x86-64.so.2").read_bytes()
found = None
at = data.find(b"GCONV_PATH\0")
while at != -1:
    names = data[at:at + 4096].split(b"\0\0", 1)[0].split(b"\0")
    if b"LD_PRELOAD" in names and b"LD_AUDIT" in names:
        found = [name.decode("ascii", "replace") for name in names]
        break
    at = data.find(b"GCONV_PATH\0", at + 1)
if found is None:
    print("loader-names: no list of unsecure variables found in the loader")
    sys.exit(1)
print(f"loader-names: the runner's loader removes {len(found)} variables for setuid programs: {' '.join(found)}")
missing = sorted(set(found) - set(egress.LOADER_VARIABLES))
extra = sorted(set(egress.LOADER_VARIABLES) - set(found))
if extra:
    print(f"loader-names: the action also empties {' '.join(extra)}")
if missing:
    print(f"loader-names: the action does not empty {' '.join(missing)}")
    sys.exit(1)
print("loader-names: the action empties every one")
