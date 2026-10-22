#!/usr/bin/env bash
# Regenerates the TLS verification test fixtures (requires OpenSSL >= 3.4).
# Private keys here are TEST-ONLY and must never be trusted outside the test suite.
set -euo pipefail
cd "$(dirname "$0")"
PASS=changeit
FAR_START=20260101000000Z
FAR_END=21251231235959Z

ext() { printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$1"; }

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -subj "/CN=Echalote Test Root CA" \
  -not_before "$FAR_START" -not_after "$FAR_END" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
openssl x509 -in ca.pem -outform DER -out ca.der

leaf() { # name san notBefore notAfter
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -subj "/CN=$1" -out "$1.csr"
  ext "$2" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -set_serial "0x$(openssl rand -hex 8)" \
    -not_before "$3" -not_after "$4" -extfile "$1.ext" -out "$1.pem"
  openssl x509 -in "$1.pem" -outform DER -out "$1.der"
  openssl pkcs12 -export -inkey "$1.key" -in "$1.pem" -certfile ca.pem -name server -passout "pass:$PASS" -out "$1.p12"
  rm -f "$1.csr" "$1.ext" "$1.key"
}

leaf valid "DNS:echalote.test,DNS:*.wild.echalote.test,IP:127.0.0.1" "$FAR_START" "$FAR_END"
leaf wronghost "DNS:other.test" "$FAR_START" "$FAR_END"
leaf expired "DNS:echalote.test" 20200101000000Z 20210101000000Z

openssl req -x509 -newkey rsa:2048 -nodes -keyout selfsigned.key -subj "/CN=echalote.test" \
  -not_before "$FAR_START" -not_after "$FAR_END" -addext "subjectAltName=DNS:echalote.test" -out selfsigned.pem
openssl x509 -in selfsigned.pem -outform DER -out selfsigned.der
openssl pkcs12 -export -inkey selfsigned.key -in selfsigned.pem -name server -passout "pass:$PASS" -out selfsigned.p12
rm -f selfsigned.key ca.key *.pem
