#!/bin/bash
# Hooks a job's environment can set for its later steps (slice 2c.9, issues #139 and #145).
#
#   plant.sh <dir>
#
# Run by the own-steps job of the escape tests. Writes, under <dir>:
#   bash-env.sh   a file for BASH_ENV (the job sets BASH_ENV to it);
#   bin/          programs named like ones a step finds through the PATH, each of
#                 which runs the real one from /usr/bin, /usr/sbin, /bin or /sbin;
#   preload.so    a library for LD_PRELOAD (the job sets LD_PRELOAD to it);
#   audit.so      a library for LD_AUDIT;
#   py/sitecustomize.py  for PYTHONPATH.
# Each appends a line to <dir>/markers, and only in a process whose environment
# holds OBAAF_EGRESS_SCRIPT, as each of the egress action's own steps does, so
# the test's other steps leave no line. Then it sets LD_AUDIT, PYTHONPATH,
# SHELLOPTS (xtrace) and a PS4 that marks when bash expands it, through
# GITHUB_ENV, and puts bin/ first on the PATH through GITHUB_PATH.
set -euo pipefail
dir="$1"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$dir/bin" "$dir/py"
markers="$dir/markers"

cat > "$dir/bash-env.sh" <<HOOK
if [ -n "\${OBAAF_EGRESS_SCRIPT:-}" ]; then echo "BASH_ENV sourced by bash" >> '$markers'; fi
HOOK

for name in bash sh uname python3 sudo docker ip find rm chmod git curl env cat cp mkdir tar id; do
  real="$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v "$name" || true)"
  case "$real" in
    /*) ;;
    *)
      case "$name" in bash|uname|python3) echo "plant: no $name on the runner" >&2; exit 1 ;; esac
      echo "plant: no $name on the runner; not planted"
      continue
      ;;
  esac
  cat > "$dir/bin/$name" <<HOOK
#!/bin/sh
if [ -n "\${OBAAF_EGRESS_SCRIPT:-}" ]; then echo "PATH: $name found through the PATH" >> '$markers'; fi
exec '$real' "\$@"
HOOK
  chmod 755 "$dir/bin/$name"
done

gcc -shared -fPIC -O2 -Wall -o "$dir/preload.so" -DMARKERS="\"$markers\"" "$here/hooks.c"
gcc -shared -fPIC -O2 -Wall -o "$dir/audit.so" -DAUDIT -DMARKERS="\"$markers\"" "$here/hooks.c"

cat > "$dir/py/sitecustomize.py" <<HOOK
import os
if os.environ.get("OBAAF_EGRESS_SCRIPT"):
    with open("$markers", "a") as handle:
        handle.write("PYTHONPATH sitecustomize imported\\n")
HOOK

{
  echo "LD_AUDIT=$dir/audit.so"
  echo "PYTHONPATH=$dir/py"
  echo "SHELLOPTS=xtrace"
  echo "PS4=+\$(if [ -n \"\${OBAAF_EGRESS_SCRIPT:-}\" ]; then echo 'PS4 expanded by bash' >> '$markers'; fi) "
} >> "$GITHUB_ENV"
echo "$dir/bin" >> "$GITHUB_PATH"
echo "plant: hooks written under $dir"
ls -l "$dir" "$dir/bin"
