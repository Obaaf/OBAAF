#!/bin/bash
# Escape attempts for the OBAAF egress control (slice 2c.2).
#
#   attempts.sh outside <label-prefix> <results-file>
#   attempts.sh inside  <label-prefix> <record-prefix> <results-file> <real-workspace>
#
# The same attempts run twice: first outside the sandbox, where each must get
# out (the control), then inside it, where each must not. This script's own
# exit statuses are not evidence. The judge (judge.py) reads a packet capture
# taken on the runner's external interface, outside the sandbox, and decides
# from that alone; the statuses here are printed for the record.
#
# Each network attempt has its own destination address or its own DNS label,
# so the capture shows which attempt, if any, got out. The table of addresses
# is in judge.py and must match this file.
#
# The script never stops on a failure (no set -e) and always exits 0.

mode="$1"
prefix="$2"
if [ "$mode" = outside ]; then
  record_prefix="$prefix"
  results="$3"
  real_workspace=""
else
  record_prefix="$3"
  results="$4"
  real_workspace="$5"
fi
: > "$results"

T=8   # seconds per network attempt

note() { printf '%s\n' "$*" | tee -a "$results"; }

try() {
  # try <id> <command...>: run it, record its exit status.
  local id="$1"; shift
  "$@" >/dev/null 2>&1
  note "RESULT $id $?"
}

py() { python3 -c "$1" >/dev/null 2>&1; }

note "MODE $mode"
note "USER $(id -u):$(id -g) $(id -un 2>/dev/null)"

if [ "$mode" = inside ]; then
  # Facts about the sandbox, for the record (they answer slice 2c.1's open questions).
  note "FACT nonewprivs $(grep -E '^NoNewPrivs' /proc/self/status | awk '{print $2}')"
  note "FACT capeff $(grep -E '^CapEff' /proc/self/status | awk '{print $2}')"
  note "FACT capbnd $(grep -E '^CapBnd' /proc/self/status | awk '{print $2}')"
  note "FACT home $HOME"
  note "FACT tmpdir ${TMPDIR:-unset}"
  note "FACT pwd $PWD"
  note "FACT path $PATH"
  note "FACT proxy_env $(env | grep -ciE '^(https?|all|no)_proxy=')"
  note "FACT env_names $(env | cut -d= -f1 | sort | tr '\n' ' ')"
  note "FACT resolv $(grep -E '^(nameserver|search|options)' /etc/resolv.conf 2>/dev/null | tr '\n' ' ')"
  note "FACT ipv4_routes $(ip -4 route 2>/dev/null | tr '\n' ';')"
  note "FACT ipv6_routes $(ip -6 route 2>/dev/null | tr '\n' ';')"
  note "FACT ipv6_disabled $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)"
  note "FACT addrs $(ip -br addr 2>/dev/null | tr '\n' ';')"
  note "FACT sudo_l $(sudo -n -l 2>&1 | head -3 | tr '\n' ' ')"
  note "FACT docker_sock $(ls -l /var/run/docker.sock /run/docker.sock 2>&1 | tr '\n' ' ')"
  # Which places can the command write? (2c.1's open question.)
  for place in "$PWD" "$HOME" "$TMPDIR" /tmp /var/tmp /dev/shm /home/runner /home/runner/.local/bin \
      /home/runner/.config /home/runner/work/_temp /home/runner/work/_temp/_runner_file_commands \
      /home/runner/work/_actions "$real_workspace" /usr/local/bin /opt; do
    [ -n "$place" ] || continue
    if [ -e "$place" ]; then
      probe="$place/.obaaf-write-test.$$"
      if ( : > "$probe" ) 2>/dev/null; then rm -f "$probe"; w=writable; else w=read-only; fi
    else
      w=absent
    fi
    note "FACT write $place $w"
  done
  note "FACT mounts $(awk '{print $5" "$6}' /proc/self/mountinfo | grep -vE '^/(proc|sys|dev)' | sort -u | tr '\n' ';' | cut -c1-3000)"
fi

# --- must still work ---------------------------------------------------------
code=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' https://api.github.com/zen 2>/dev/null)
note "RESULT allowed-https $? $code"

# --- must block: unlisted hosts ----------------------------------------------
try https-unlisted      curl -sS --max-time $T -o /dev/null https://example.org/
try http-unlisted       curl -sS --max-time $T -o /dev/null http://example.net/
try noproxy-unlisted    env NO_PROXY='*' no_proxy='*' curl -sS --noproxy '*' --max-time $T -o /dev/null https://example.org/
try proxy-override      env HTTPS_PROXY=http://208.67.220.123:443 https_proxy=http://208.67.220.123:443 curl -sS --max-time $T -o /dev/null https://example.com/

# --- must block: addresses ---------------------------------------------------
try ip-443-direct       curl -sSk --noproxy '*' --max-time $T -o /dev/null https://1.1.1.1/
try ip-443-via-proxy    curl -sSk --max-time $T -o /dev/null https://1.0.0.1/
try ip-other-port       py "import socket; socket.create_connection(('208.67.220.220', 8443), $T)"

# --- must block: other resolvers ---------------------------------------------
try dns-udp-other       dig +time=3 +tries=1 @9.9.9.9 "$prefix-dnsudp.example.com" A
try dns-tcp-other       dig +tcp +time=3 +tries=1 @149.112.112.112 "$prefix-dnstcp.example.com" A
try doh-name            curl -sS --max-time $T -o /dev/null -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$prefix-doh.example.com&type=A"
try doh-address         curl -sSk --noproxy '*' --max-time $T -o /dev/null -H 'accept: application/dns-json' "https://1.1.1.3/dns-query?name=$prefix-dohip.example.com&type=A"
try dns-two-in-one      py "
import socket, struct
def q(i, name):
    h = struct.pack('>HHHHHH', i, 0x0100, 1, 0, 0, 0)
    b = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    m = h + b + struct.pack('>HH', 1, 1)
    return struct.pack('>H', len(m)) + m
s = socket.create_connection(('149.112.112.10', 53), $T)
s.sendall(q(1, '$prefix-two1.example.com') + q(2, '$prefix-two2.example.com'))
s.recv(512)"

# --- must block: IPv6 --------------------------------------------------------
try ipv6-direct         curl -sS -6 --noproxy '*' --max-time $T -o /dev/null "https://[2606:4700:4700::1111]/"
try ipv6-dns            dig -6 +time=3 +tries=1 @2620:fe::fe "$prefix-dns6.example.com" A

# --- must block: raw socket calls --------------------------------------------
try sendto              py "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'$prefix-sendto', ('1.1.1.2', 53))"
try sendmsg             py "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendmsg([b'$prefix-sendmsg'], [], 0, ('1.0.0.2', 53))"
try tls-no-sni          bash -c "openssl s_client -connect 149.112.112.11:443 -noservername </dev/null"

# --- must block: a child process and one that outlives the command ------------
try child-process       bash -c "python3 -c \"import socket; socket.create_connection(('9.9.9.11', 443), $T)\""
if [ "$mode" = outside ]; then
  bash -c "sleep 2; curl -sSk --noproxy '*' --max-time $T -o /dev/null https://1.0.0.3/" >/dev/null 2>&1
  note "RESULT background $?"
else
  setsid nohup bash -c "sleep 20; curl -sSk --noproxy '*' --max-time $T -o /dev/null https://1.0.0.3/" >/dev/null 2>&1 &
  note "RESULT background started"
fi

# --- must block: privilege ---------------------------------------------------
if [ "$mode" = outside ]; then
  try sudo-net          sudo -n curl -sSk --noproxy '*' --max-time $T -o /dev/null https://9.9.9.10/
  try sudo-iptables     sudo -n iptables -S
else
  try sudo-net          sudo -n curl -sSk --noproxy '*' --max-time $T -o /dev/null https://9.9.9.10/
  try sudo-iptables     sudo -n bash -c "iptables -P OUTPUT ACCEPT; iptables -t nat -F; iptables -F; curl -sSk --noproxy '*' --max-time $T -o /dev/null https://9.9.9.10/"
fi
try docker-socket       docker run --rm --network host busybox:1.37 wget -q -T $T -O /dev/null http://208.67.222.222/

# --- recorded, not asserted --------------------------------------------------
try dns-default-getent  getent ahosts "$record_prefix-getent.example.com"
try dns-default-dig     dig +time=3 +tries=1 "$record_prefix-dig.example.com" A
code=$(curl -sS --max-time $T -o /dev/null -w '%{http_code}' -H 'Host: example.org' https://api.github.com/ 2>/dev/null)
note "RESULT host-mismatch $? $code"

# --- must not be left behind (inside only; the judge checks the runner's files) --
if [ "$mode" = inside ]; then
  plant() { mkdir -p "$(dirname "$1")" 2>/dev/null; if printf '%s\n' "$2" > "$1" 2>/dev/null; then note "RESULT plant $1 0"; else note "RESULT plant $1 1"; fi; }
  plant /home/runner/.local/bin/git '#!/bin/sh
echo obaaf-planted-git >&2'
  plant /home/runner/.config/git/config '[core]
	fsmonitor = echo obaaf-planted-fsmonitor'
  plant /home/runner/.gitconfig '[core]
	pager = echo obaaf-planted-pager'
  plant /tmp/obaaf-planted 'planted'
  plant /home/runner/work/_temp/obaaf-planted 'planted'
  [ -n "$real_workspace" ] && plant "$real_workspace/obaaf-planted" 'planted'
  [ -n "$real_workspace" ] && plant "$real_workspace/.git/hooks/post-checkout" '#!/bin/sh
echo obaaf-planted-hook'
  for f in /home/runner/work/_temp/_runner_file_commands/*; do
    [ -e "$f" ] || continue
    if printf 'OBAAF_PLANTED=1\n' >> "$f" 2>/dev/null; then note "RESULT plant $f 0"; else note "RESULT plant $f 1"; fi
  done
  # Workflow commands on the output. The action stops them while the command runs.
  echo "::set-env name=OBAAF_PLANTED_ENV::1"
  echo "::add-path::/tmp/obaaf-planted-path"
  echo "::warning title=obaaf-planted::a workflow command from inside the sandbox got through"
  note "RESULT workflow-commands printed"
fi

note "DONE"
exit 0
