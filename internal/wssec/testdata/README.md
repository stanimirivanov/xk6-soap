# Public synthetic signature fixtures

`signing-key.pem` is an intentionally committed, publicly known RSA test key.
`signing-cert.pem` is its self-signed synthetic certificate (serial 21,
CN=xk6-soap-synthetic-signature-test). Never use either as deployment credentials
or production trust. The private key is not copied into the Apache image.

The fixed key, IDs and timestamp make the XML/canonical-byte artifacts stable.
See ADR-0002 for artifact meanings and the explicit review-only refresh command.
No captured production traffic or real credentials are stored here.
