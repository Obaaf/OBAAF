#!/usr/bin/env bash
set -euo pipefail
umask 077
unset PYTHONPATH PYTHONHOME
pin=4c228e0072c1c755e3ed4b11b8830120817be0fe
[[ "$pin" =~ ^[0-9a-f]{40}$ && "$pin" != 0000000000000000000000000000000000000000 ]]
test -n "$NODE_NAME"
test "$NODE_NAME" != built-in
root=$(mktemp -d "$PROBE_ROOT/install.XXXXXX")
test "$(stat -c '%a' "$root")" = 700
fixture=$(cat "$PROBE_ROOT/fixture-path")
case "$root/" in "$WORKSPACE/"*|"$fixture/"*) exit 1 ;; esac
export TMPDIR="$root/tmp"
mkdir "$TMPDIR"
if git -C "$TMPDIR" rev-parse --git-dir >/dev/null 2>&1; then exit 1; fi
git init -q "$root/src"
git -C "$root/src" fetch -q --depth=1 https://github.com/Obaaf/OBAAF.git "$pin"
git -C "$root/src" checkout -q --detach FETCH_HEAD
test "$(git -C "$root/src" rev-parse HEAD)" = "$pin"
python3 -m venv "$root/venv"
python="$root/venv/bin/python"
"$python" -m pip install --require-hashes --only-binary=:all: -r "$root/src/actions/setup-obaaf/requirements.txt"
"$python" -m pip install --no-build-isolation --no-deps "$root/src"
"$python" -m pip check
verify=("$root/venv/bin/obaaf" verify release --format json --policy "$fixture/policy.yaml" --artifacts "$fixture/dist" --release-run "$fixture/release-run.json" --repo-dir "$fixture/game" --source-revision "$(cat "$fixture/revision")" --dsse "$fixture/attestations/slsa.dsse.json" --dsse "$fixture/attestations/build-record.dsse.json")
if [[ "$1" == before ]]; then
    printf '%s\n' "$root" > "$PROBE_ROOT/first-install"
    "${verify[@]}" --pre-approval > "$root/pre.json"
    "$python" -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["preApproval"] and d["checksPassed"] and not d["allowed"]' "$root/pre.json"
    echo 'OBAAF pre-approval checks passed with upload withheld'
else
    test "$1" = after
    test "$root" != "$(cat "$PROBE_ROOT/first-install")"
    status=0
    "${verify[@]}" > "$root/missing.json" || status=$?
    test "$status" = 1
    "$python" -c 'import json,sys; d=json.load(open(sys.argv[1])); assert not d["preApproval"] and not d["checksPassed"] and not d["allowed"] and not d["approvals"]' "$root/missing.json"
    "${verify[@]}" --approvals "$fixture/publish-run.json" > "$root/approved.json"
    "$python" -c 'import json,sys; d=json.load(open(sys.argv[1])); assert not d["preApproval"] and d["checksPassed"] and d["allowed"] and d["approvals"] == ["carol"]' "$root/approved.json"
    echo 'OBAAF distinct second installation withheld upload without approval and allowed the named fixture approval'
fi
