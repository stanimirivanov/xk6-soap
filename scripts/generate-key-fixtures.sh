#!/bin/sh
# Deliberately public synthetic test identities. Run from repository root.
set -eu
case "$(openssl version)" in 'OpenSSL 3.'*) ;; *) exit 1 ;; esac
out=internal/keys/testdata
openssl pkcs12 -export -inkey internal/wssec/testdata/signing-key.pem \
    -in internal/wssec/testdata/signing-cert.pem -name synthetic-only \
    -passout pass:synthetic-only -out "$out/openssl3.p12"
# A second private-key bag makes the container ambiguous even with one public key.
rm -f "$out/ambiguous.p12"
for alias in first second; do
    keytool -importkeystore -noprompt -srckeystore "$out/openssl3.p12" \
        -srcstoretype PKCS12 -srcstorepass synthetic-only -srcalias synthetic-only \
        -destkeystore "$out/ambiguous.p12" -deststoretype PKCS12 \
        -deststorepass synthetic-only -destalias "$alias"
done
