#!/bin/sh
set -eu
# Synthetic fixture identities only. Never load these keys in production.
destination=${1:?expected a fresh destination directory}
mkdir "$destination"
keytool -genkeypair -alias fixture-server -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
    -dname 'CN=xk6-soap-test-only,OU=Synthetic Fixture' -validity 3650 \
    -storetype PKCS12 -keystore "$destination/server.p12" \
    -storepass fixture-only -keypass fixture-only -noprompt
keytool -exportcert -rfc -alias fixture-server -keystore "$destination/server.p12" \
    -storepass fixture-only -file "$destination/server.pem"
keytool -list -alias fixture-server -keystore "$destination/server.p12" \
    -storepass fixture-only > "$destination/identity.txt"
for bits in 256 384 521; do
    keytool -genkeypair -alias "fixture-server-ec$bits" -keyalg EC -groupname "secp${bits}r1" \
        -dname "CN=xk6-soap-server-ec$bits,OU=Synthetic Fixture" -validity 3650 \
        -storetype PKCS12 -keystore "$destination/server.p12" -storepass fixture-only -noprompt
    keytool -genkeypair -alias "fixture-client-ec$bits" -keyalg EC -groupname "secp${bits}r1" \
        -dname "CN=xk6-soap-client-ec$bits,OU=Synthetic Fixture" -validity 3650 \
        -storetype PKCS12 -keystore "$destination/client-ec$bits.p12" -storepass fixture-only -noprompt
    keytool -exportcert -rfc -alias "fixture-server-ec$bits" -keystore "$destination/server.p12" \
        -storepass fixture-only -file "$destination/server-ec$bits.pem"
    keytool -exportcert -rfc -alias "fixture-client-ec$bits" -keystore "$destination/client-ec$bits.p12" \
        -storepass fixture-only -file "$destination/client-ec$bits.pem"
    keytool -importcert -noprompt -alias "fixture-client-ec$bits" -file "$destination/client-ec$bits.pem" \
        -keystore "$destination/server.p12" -storepass fixture-only
done
chmod 444 "$destination"/*
