import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

const cert = open('../../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../../internal/wssec/testdata/signing-key.pem', 'b');
const server = open(__ENV.SOAP_INTEROP_SIGNATURE_TRUST, 'b');
const cases = [];
for (const soapVersion of ['1.1', '1.2']) {
  for (const bits of [128, 256]) {
    for (const [mode, order] of [['ste','sign-then-encrypt'],['ets','encrypt-then-sign']]) {
      const url = __ENV.SOAP_INTEROP_URL + '/' + mode + bits + soapVersion.replace('.', '');
      for (const target of ['content', 'body']) {
        const client = new Client({
          url, soapVersion, debug:true,
          keys:{signing:{cert,key},recipient:{cert:server},trust:[server]},
          security:{sign:{},encrypt:{algorithm:'aes-' + bits + '-gcm',target},order},
        });
        cases.push({client, target, order});
      }
    }
  }
}
export const options = {vus:1, iterations:1, thresholds:{checks:['rate==1']}};

function post(req, body) {
  return http.post(req.url, body, {headers:req.headers,timeout:'5s',redirects:0,responseType:'text'});
}

export default function () {
  for (const {client, target, order} of cases) {
    const payload = '<m:echo xmlns:m="urn:xk6-soap:fixture"><value>REQUEST_PRIVATE_SENTINEL</value></m:echo>';
    const req = client.build('echo', payload, {soapAction:'urn:echo'});
    const type = target === 'content' ? 'Content' : 'Element';
    check(req, {
      'real Body contains encrypted target and no plaintext': r =>
        /<s:Body\b[^>]*><[^<> ]+:EncryptedData\b/.test(r.body) &&
        r.body.includes('Type="http://www.w3.org/2001/04/xmlenc#' + type + '"') &&
        !r.body.includes('REQUEST_PRIVATE_SENTINEL'),
    });
    check(post(req, req.body), {
      [order + ' ' + target + ' accepted by WSS4J']: r => r.status === 200,
    });

    // Keep encryption unchanged and invalidate the signature on the recovered Body.
    const tampered = req.body.replace(/(<[^<> ]+:SignatureValue\b[^>]*>)([A-Za-z0-9+/])/, (_, tag, ch) =>
      tag + (ch === 'A' ? 'B' : 'A'));
    check(post(req, tampered), {
      'Apache rejects an invalid signature on an encrypted message': r =>
        tampered !== req.body && r.status === 500 && r.body.includes('Fault'),
    });
  }
}
