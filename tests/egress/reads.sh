#!/bin/bash
# What the command can read of what earlier steps left on the runner's disk
# (slice 2c.9, issue #136).
#
#   reads.sh <results-file>
#
# Run inside the sandbox by the behaviour job of the escape tests, with
# CRED_FILE (the file in which an earlier actions/checkout, left at its
# default persist-credentials, keeps the job's token), READ_MARK (a random
# string, not a secret, that the job wrote into files under RUNNER_TEMP, the
# home directory and the folder that holds the workspace), RUNNER_TEMP_REAL,
# HOME_REAL and WORK_REAL. It records whether each file is there and readable,
# and searches for the mark, and never prints what a file holds. The job's
# check step decides. It always exits 0.

out="$1"
: > "$out"
note() { printf '%s\n' "$*" | tee -a "$out"; }

probe() {
  # probe <label> <path>
  if [ ! -e "$2" ]; then
    note "READ $1 absent"
  elif ! head -c 1 "$2" >/dev/null 2>&1; then
    note "READ $1 unreadable"
  elif grep -qF -- "$READ_MARK" "$2" 2>/dev/null; then
    note "READ $1 holds-the-mark"
  else
    note "READ $1 readable"
  fi
}

probe credential "$CRED_FILE"
probe runner-temp "$RUNNER_TEMP_REAL/obaaf-read-test.txt"
probe home "$HOME_REAL/.obaaf-read-test"
probe home-config "$HOME_REAL/.config/obaaf-read-test/hosts.yml"
probe work "$WORK_REAL/obaaf-read-test.txt"
for pair in "runner-temp:$RUNNER_TEMP_REAL" "home:$HOME_REAL" "work:$WORK_REAL"; do
  label="${pair%%:*}"
  dir="${pair#*:}"
  if [ -d "$dir" ]; then
    note "DIR $label there, $(ls -A "$dir" 2>/dev/null | wc -l) entries listed"
  else
    note "DIR $label absent"
  fi
done
# The places the model-keys search covers. /proc and /sys are left out: the
# command's own environment holds READ_MARK.
places=(/home /tmp /run /var /etc)
timeout 120 grep -rIlF --exclude-dir=proc --exclude-dir=sys -e "$READ_MARK" "${places[@]}" \
  > "${TMPDIR:-/tmp}/obaaf-read-hits.txt" 2>/dev/null
note "GREP_STATUS $?"
hits=$(grep -v -F -- "$out" "${TMPDIR:-/tmp}/obaaf-read-hits.txt" | head -10 | tr '\n' ' ')
note "MARK_IN_FILES ${hits:-none}"
note "DONE"
exit 0
