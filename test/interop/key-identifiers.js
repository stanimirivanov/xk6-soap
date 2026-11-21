import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

const cert = open('../../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../../internal/wssec/testdata/signing-key.pem', 'b');
const server = open(__ENV.SOAP_INTEROP_SIGNATURE_TRUST, 'b');
const matrix = JSON.parse(open('./matrix.json'));
const rows = matrix.identifiers.flatMap(row => row.soapVersions.map(soapVersion => ({...row,soapVersion})));
const cases = rows.map(({mode, keyId, marker, soapVersion}) => {
  const url = __ENV.SOAP_INTEROP_URL + '/' + mode + soapVersion.replace('.', '');
  const client = new Client({url, soapVersion, debug:true, keys:{signing:{cert,key},trust:[server]}, security:{sign:{keyId}}});
  const untrusted = new Client({url, soapVersion, keys:{trust:[cert]}, security:{verify:{signature:true}}});
  return {client, untrusted, keyId, marker};
});

export const options = {vus:1, iterations:1, thresholds:{checks:['rate==1']}};

export default function () {
  for (const {client, untrusted, keyId, marker} of cases) {
    const payload = '<m:echo xmlns:m="urn:xk6-soap:fixture"><value>KEY_IDENTIFIER_PRIVATE_SENTINEL</value></m:echo>';
    const request = client.build('echo', payload, {soapAction:'urn:echo'});
    const response = http.post(request.url, request.body, {headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
    check(response, {
      [keyId + ' independently accepted and emitted by Apache']: r => r.status === 200 && request.body.includes(marker) && r.body.includes(marker),
    });
    check(client.parse(response), {
      [keyId + ' Apache response authenticated']: p => p.ok && p.sigVerified && p.timestampValid,
    });
    check(untrusted.parse(response), {
      [keyId + ' untrusted response withheld']: p => !p.ok && p.body === null && p.error.code === 'SIGNATURE_INVALID',
    });
    if (keyId === 'direct') {
      const substitute = certificateBase64(cert);
      const body = response.body.replace(/(<[^<> ]+:BinarySecurityToken\b[^>]*>)[^<]+/, (_, start) => start + substitute);
      check(untrusted.parse({status:200,body}), {
        'substituted BST matches the wrong pin but fails signature verification': p =>
          body !== response.body && !p.ok && p.body === null && p.error.code === 'SIGNATURE_INVALID',
      });
    }
  }
}

function certificateBase64(buffer) {
  // The fixture PEM is ASCII. Strip the armor to get its DER Base64.
  const pem = String.fromCharCode(...new Uint8Array(buffer));
  return pem.replace(/-----[^-]+-----|\s/g, '');
}
