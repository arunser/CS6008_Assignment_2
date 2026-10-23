#!/bin/sh
# Private CA + resolver cert (SAN resolver.cs6008.local, no IP). Also a rogue
# self-signed cert for the same name. Output to /pki, nothing committed.
set -eu
D=/pki; cd "$D"
CN=resolver.cs6008.local
# idempotent: generate once per deployment (a down -v clears the volume and forces regen)
if [ -f "$D/ca.pem" ]; then echo "pki: CA/certs already present, keeping them"; exit 0; fi

# private CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=CS6008 Test CA" -out ca.pem

# resolver certificate, signed by our CA, DNS SAN only
openssl ecparam -name prime256v1 -genkey -noout -out resolver.key
openssl req -new -key resolver.key -subj "/CN=$CN" -out resolver.csr
printf "subjectAltName=DNS:%s\n" "$CN" > ext.cnf
openssl x509 -req -in resolver.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 825 -sha256 -extfile ext.cnf -out resolver.crt

# rogue cert for the same name, NOT signed by our CA (attack ii)
openssl ecparam -name prime256v1 -genkey -noout -out rogue.key
openssl req -x509 -new -key rogue.key -sha256 -days 825 -subj "/CN=$CN" \
        -addext "subjectAltName=DNS:$CN" -out rogue.crt

chmod -R a+r "$D"
echo "pki: CA + resolver cert (SAN DNS:$CN, no IP) + rogue cert ready"
ls -1 "$D"
