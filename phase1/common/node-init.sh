#!/bin/sh
set -e
# ROUTES="cidr=gateway cidr=gateway ..."  (space separated)
if [ -n "$ROUTES" ]; then
  for r in $ROUTES; do
    net="${r%=*}"; gw="${r#*=}"
    echo "node-init: ip route replace $net via $gw"
    ip route replace "$net" via "$gw"
  done
fi
exec "$@"