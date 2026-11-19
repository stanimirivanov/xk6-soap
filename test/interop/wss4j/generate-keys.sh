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
chmod 444 "$destination"/*
