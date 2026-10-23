#!/bin/sh
# Each server signs its own zone and publishes its DS up to the parent.
set -eu
if [ -n "${ROUTES:-}" ]; then for r in $ROUTES; do ip route replace "${r%=*}" via "${r#*=}"; done; fi
KD=/signed/keys; DSD=/signed/ds; W=/work; ALG=ECDSAP256SHA256
mkdir -p "$KD" "$DSD" "$W"

if [ -n "${SIGN_ZONE:-}" ] && [ ! -f "$SIGN_OUT" ]; then
    ZONE="$SIGN_ZONE"
    cp "$SIGN_SRC" "$W/zone"
    [ -n "$(tail -c1 "$W/zone")" ] && printf '
' >> "$W/zone"
    # wait for the child's DS, then fold it in (NODS=1 skips it for com)
    SKIP=0; [ "$ZONE" = "com" ] && [ "${NODS:-0}" = "1" ] && SKIP=1
    if [ -n "${SIGN_CHILD:-}" ] && [ "$SKIP" = "0" ]; then
        echo "dnssec-init: $ZONE waiting for $SIGN_CHILD DS..."
        while [ ! -f "$DSD/$SIGN_CHILD.ds" ]; do sleep 1; done
        cat "$DSD/$SIGN_CHILD.ds" >> "$W/zone"
    fi
    KSK=$(dnssec-keygen -q -a $ALG -f KSK -n ZONE -K "$KD" "$ZONE")
    dnssec-keygen -q -a $ALG -n ZONE -K "$KD" "$ZONE" >/dev/null
    EXTRA=""; [ "$ZONE" = "example.com" ] && [ "${NSEC3:-0}" = "1" ] && EXTRA="-3 DEADBEEF"
    dnssec-signzone -S $EXTRA -K "$KD" -o "$ZONE" -f "$SIGN_OUT" "$W/zone" >/dev/null
    if [ "$ZONE" = "." ]; then
        L=$(grep DNSKEY "$KD/$KSK.key" | grep -v '^;' | head -1 | sed 's/.*DNSKEY[[:space:]]*//')
        set -- $L; F=$1; P=$2; A=$3; shift 3; K=$(echo "$*" | tr -d ' ')
        printf 'trust-anchors {
    "." static-key %s %s %s "%s";
};
' "$F" "$P" "$A" "$K" > /signed/root-anchor.conf
    else
        dnssec-dsfromkey -2 "$KD/$KSK.key" > "$DSD/$ZONE.ds"
    fi
    chmod -R a+r /signed
    echo "dnssec-init: $ZONE signed by itself; DS/anchor published"
fi

if [ "${WAIT_ANCHOR:-0}" = "1" ]; then
    echo "dnssec-init: waiting for root trust anchor..."
    while [ ! -f /signed/root-anchor.conf ]; do sleep 1; done
fi
exec "$@"
