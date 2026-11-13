#!/bin/bash
# Model keys through AWF's API proxy (slice 2c.4).
#
#   model-keys.sh <results-file>
#
# Run inside the sandbox by the behaviour job of the escape tests, with two
# made-up keys given to the action's model-keys input and KEY_MARK (a string
# both keys contain, which is not a key itself) given to the command. It
# records what the command sees and what each provider answered; the job's
# check step decides. The script never stops on a failure and always exits 0.

out="$1"
: > "$out"
note() { printf '%s\n' "$*" | tee -a "$out"; }

note "ENV_NAMES $(env | cut -d= -f1 | sort | tr '\n' ' ')"
for v in ANTHROPIC_API_KEY OPENAI_API_KEY ANTHROPIC_AUTH_TOKEN CODEX_API_KEY ANTHROPIC_BASE_URL OPENAI_BASE_URL \
    CLAUDE_CODE_API_KEY_HELPER; do
  if [ -n "${!v+x}" ]; then
    case "${!v}" in
      *"$KEY_MARK"*) note "VAR $v holds-the-key" ;;
      *) note "VAR $v = ${!v}" ;;
    esac
  else
    note "VAR $v unset"
  fi
done
note "MARK_IN_ENV $(env | grep -v '^KEY_MARK=' | grep -c -- "$KEY_MARK")"
# Places the command can read. The proc and sys trees are left out (the
# command's own environment holds KEY_MARK); the results file holds no key.
places=("$HOME" "${TMPDIR:-/tmp}" "$PWD" /tmp /home /run /etc /var)
searched=$(timeout 120 find "${places[@]}" -path /proc -prune -o -path /sys -prune -o -type f -readable -print 2>/dev/null | wc -l)
hits=$(timeout 120 grep -rIl --exclude-dir=proc --exclude-dir=sys -e "$KEY_MARK" "${places[@]}" 2>/dev/null | grep -v -- "$out" | head -5 | tr '\n' ' ')
note "FILES_SEARCHED $searched"
note "MARK_IN_FILES ${hits:-none}"

body() { head -c 400 "$1" 2>/dev/null | tr '\n\r' '  '; }

# An ordinary request through the API proxy, as an agent would send it: the
# placeholder the command was given, which the proxy replaces with the key.
code=$(curl -sS --max-time 40 -o anthropic.json -w '%{http_code}' "$ANTHROPIC_BASE_URL/v1/messages" \
  -H "x-api-key: ${ANTHROPIC_AUTH_TOKEN:-none}" -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}' 2>/dev/null)
note "ANTHROPIC $? $code $(body anthropic.json)"

code=$(curl -sS --max-time 40 -o openai.json -w '%{http_code}' "$OPENAI_BASE_URL/models" \
  -H "Authorization: Bearer ${OPENAI_API_KEY:-none}" 2>/dev/null)
note "OPENAI $? $code $(body openai.json)"

# A request that asks the provider to fetch the web for the agent. The action
# sets AWF's hosted-web policy to enabled: false, so the proxy must refuse it
# before it reaches the provider.
code=$(curl -sS --max-time 40 -o hosted.json -w '%{http_code}' "$ANTHROPIC_BASE_URL/v1/messages" \
  -H "x-api-key: ${ANTHROPIC_AUTH_TOKEN:-none}" -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}' 2>/dev/null)
note "ANTHROPIC_HOSTED_WEB $? $code $(body hosted.json)"

# The provider directly, through the proxy, which does not list it.
curl -sS --max-time 15 -o /dev/null https://api.anthropic.com/v1/messages >/dev/null 2>&1
note "DIRECT_ANTHROPIC $?"

note "DONE"
exit 0
