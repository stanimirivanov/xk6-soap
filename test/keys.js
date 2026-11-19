import { Client } from 'k6/x/soap';
import { check } from 'k6';

// Deliberately public synthetic identities; actual k6 open(..., 'b') inputs.
const cert = open('../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../internal/wssec/testdata/signing-key.pem', 'b');
const pkcs12 = open('../internal/keys/testdata/openssl3.p12', 'b');
function rejectsPassword() {
  try {
    new Client({url:'https://example.test', keys:{signing:{pkcs12, password:'wrong-synthetic'}}});
  } catch (error) {
    return error.code === 'SOAP_KEY_INVALID' && error.stage === 'keys';
  }
  return false;
}
if (!rejectsPassword()) throw new Error('wrong password accepted before cache load');
const client = new Client({url:'https://example.test', keys:{
  signing:{cert, key},
  recipient:{cert}, trust:[cert],
}});
const pfxClient = new Client({url:'https://example.test', keys:{signing:{pkcs12, password:'synthetic-only'}}});
if (!rejectsPassword()) throw new Error('wrong password accepted after cache load');
new Uint8Array(cert).fill(0);
new Uint8Array(key).fill(0);
new Uint8Array(pkcs12).fill(0);

export const options = { vus:8, iterations:16, thresholds:{checks:['rate==1']} };
export default function () {
  const request = client.build('Echo', '<Echo>synthetic</Echo>');
  const parsed = client.parse({status:200, body:request.body});
  const pfxRequest = pfxClient.build('Echo', '<Echo>synthetic</Echo>');
  check(parsed, {
    'copied keys remain valid across VUs': value => value.ok && value.body.includes('synthetic') && pfxRequest.body.includes('synthetic'),
    'key material stays private': () => client.keys === undefined && !request.body.includes('PRIVATE KEY'),
  });
}
