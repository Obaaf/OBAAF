#!/bin/bash
# Plant an OpenSSL module and the configuration that loads it (slice 2c.11, issue #195).
#
#   plant-openssl.sh <dir>
#
# Run by the openssl-modules job of the escape tests. Writes, under <dir>:
#   module.so     a shared object whose constructor appends a line to <dir>/markers
#                 when libcrypto loads it, and only in a process that holds
#                 OBAAF_EGRESS_SCRIPT (so the test's other steps leave no line);
#   modules/fips.so  the same object, named for the FIPS route (OPENSSL_MODULES);
#   evil.cnf      an OpenSSL configuration that loads module.so as a provider;
#   fipsswitch    a file holding "1", for OPENSSL_FIPS_MODE_SWITCH_PATH.
# The job sets OPENSSL_CONF, OPENSSL_MODULES, OPENSSL_FORCE_FIPS_MODE and
# OPENSSL_FIPS_MODE_SWITCH_PATH; this script only lays down the files.
set -euo pipefail
dir="$1"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$dir/modules"
markers="$dir/markers"

gcc -shared -fPIC -O2 -Wall -o "$dir/module.so" -DMARKERS="\"$markers\"" "$here/openssl-module.c"
cp "$dir/module.so" "$dir/modules/fips.so"

cat > "$dir/evil.cnf" <<CONF
openssl_conf = obaaf_init
[obaaf_init]
providers = obaaf_providers
[obaaf_providers]
obaaf = obaaf_provider
[obaaf_provider]
module = $dir/module.so
activate = 1
CONF

printf '1\n' > "$dir/fipsswitch"
echo "plant-openssl: module and configuration written under $dir"
ls -l "$dir" "$dir/modules"
