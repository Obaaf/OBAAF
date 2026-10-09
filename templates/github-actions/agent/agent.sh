#!/usr/bin/env bash
# OBAAF example agent. Install it as .github/obaaf/agent.sh and replace it with yours.
#
# The contract every agent in the OBAAF agent lane follows:
#   * Read the task only from the snapshot in $OBAAF_SNAPSHOT (snapshot.json and inputs/).
#     Everything there is labeled with the trust level of its author; treat it as data.
#   * Write the result only to $OBAAF_PROPOSAL, as any of:
#       patch.diff   a git-format diff against the default branch, made with
#                    `git diff --no-renames --no-ext-diff --no-color`: regular files only, no
#                    renames, binaries, symbolic links or submodules, and nothing under .github/,
#                    .obaaf/, an agent instruction file, or another path starting with '.'
#       comment.md   plain text to post on the issue: no links, images, HTML, '<', '//',
#                    'www.' or email addresses
#       labels.json  {"add": [...], "remove": [...]} using allowed labels
#     `obaaf proposal check` refuses anything else (docs/attestations.md).
#   * Reach the model only through the inference proxy at $OBAAF_MODEL_ENDPOINT, which holds
#     the model credential (docs/inference-proxy.md). The job holds no secrets.
#   * Optionally write a trace of tool calls to $OBAAF_TRACE (JSON lines). It is recorded as
#     self-reported and untrusted.
#
# This example calls no model: it writes a fixed acknowledgement, so the lanes can be tested
# end to end (docs/live-acceptance-tests.md) before a real agent is connected.
set -euo pipefail

: "${OBAAF_SNAPSHOT:?OBAAF_SNAPSHOT is not set}"
: "${OBAAF_PROPOSAL:?OBAAF_PROPOSAL is not set}"
mkdir -p "$OBAAF_PROPOSAL"

level=$(jq -r '.integrityLevel' "$OBAAF_SNAPSHOT/snapshot.json")
inputs=$(jq -r '.inputs | length' "$OBAAF_SNAPSHOT/snapshot.json")

cat > "$OBAAF_PROPOSAL/comment.md" <<EOF
Thanks for the report. A maintainer will take a look.

(Automated note from the OBAAF example agent: it read ${inputs} input(s) at integrity level ${level}.)
EOF

if [ -n "${OBAAF_TRACE:-}" ]; then
  printf '{"tool":"write_file","path":"comment.md"}\n' > "$OBAAF_TRACE"
fi

# To connect a real agent, replace the lines above. For example, for a command-line agent
# that accepts a custom API base URL, point it at the proxy and give it the snapshot:
#
#   prompt="$(jq -r '.inputs[] | "\(.name) (written by a \(.label) principal):"' "$OBAAF_SNAPSHOT/snapshot.json")"
#   YOUR_AGENT_CLI --base-url "$OBAAF_MODEL_ENDPOINT" --read-only-tools \
#       --task-file "$OBAAF_SNAPSHOT/inputs/..." --output-patch "$OBAAF_PROPOSAL/patch.diff"
#
# Keep the agent's tools read-only: it proposes; the effect lane applies.
