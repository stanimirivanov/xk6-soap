# Sign then encrypt SOAP requests

Configure a signing identity and an RSA recipient certificate at init. The
recipient certificate must be valid for key encipherment when it declares
KeyUsage. The trust pin below is used separately to authenticate signed replies.

```js
import { Client } from 'k6/x/soap';
import http from 'k6/http';

const client = new Client({
  url: 'https://example.test/service',
  keys: {
    signing: {cert: open('./client-cert.pem', 'b'), key: open('./client-key.pem', 'b')},
    recipient: {cert: open('./server-encryption-cert.pem', 'b')},
    trust: [open('./server-signing-cert.pem', 'b')],
  },
  security: {
    sign: {},
    encrypt: {algorithm: 'aes-256-gcm', target: 'content'},
    order: 'sign-then-encrypt',
  },
});

export default function () {
  const request = client.build('Echo', '<Echo>example</Echo>', {soapAction: 'urn:echo'});
  const response = http.post(request.url, request.body, {headers: request.headers});
  const result = client.parse(response); // Signed, unencrypted response.
}
```

`content` encrypts all child nodes of the SOAP Body. `body` encrypts the
operation element and retains any surrounding whitespace and comments. Both
leave the SOAP Body element and its signing ID in the envelope. Security
headers remain visible, including any UsernameToken. The signature covers
the plaintext Body and the configured signed headers. The receiver decrypts
the Body region before checking that signature.

The default profile uses AES-256-GCM and `content`. AES-128-GCM is also
available. Each build generates a fresh session key and a fresh 96-bit GCM
IV. The key is wrapped with XML Encryption 1.1 RSA-OAEP using SHA-256 for
the digest and MGF1. The EncryptedKey names the recipient by issuer and
serial number. Send the generated body unchanged.

The public API currently supports this order for outgoing requests with
signing enabled. Encrypted response parsing, encrypt-then-sign, and header
encryption require separate profiles and remain gated.

The local and native interop tests cover both targets and AES sizes. The
WSS4J exchange runs with SOAP 1.1 and 1.2. A local test unwraps two requests
and checks key and IV sample uniqueness as a sanity check. Injected failures
in session-key randomness return `SOAP_RANDOM_FAILED` and no wire message.
