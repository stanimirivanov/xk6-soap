import { Client } from 'k6/x/soap';
import { check } from 'k6';

const cert = open('../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../internal/wssec/testdata/signing-key.pem', 'b');
const keys = {signing:{cert,key}, recipient:{cert}, trust:[cert]};
function rejects(security, code, material=keys) {
  try { new Client({url:'https://example.test', keys:material, security, debug:true}); }
  catch (error) { return error.code===code && error.stage==='security' && !String(error).includes('POLICY_PRIVATE_SENTINEL'); }
  return false;
}
const constructorChecks = [
  rejects({sign:{}}, 'SOAP_FEATURE_UNAVAILABLE'),
  rejects({encrypt:{}}, 'SOAP_FEATURE_UNAVAILABLE'),
  rejects({verify:{signature:true}}, 'SOAP_FEATURE_UNAVAILABLE'),
  rejects({sign:{algorithm:'rsa-sha1'}}, 'SOAP_POLICY_INVALID'),
  rejects({sign:undefined}, 'SOAP_POLICY_INVALID'),
  rejects({verify:{signature:true}}, 'SOAP_POLICY_KEY', {}),
];
if (!constructorChecks.every(Boolean)) throw new Error('security constructor gate failed');
const tokenClient = new Client({url:'https://example.test',security:{usernameToken:{user:'POLICY_PRIVATE_SENTINEL',password:'POLICY_PRIVATE_SENTINEL',passwordType:'PasswordText'}},debug:true});
const timestampClient = new Client({url:'https://example.test',security:{timestamp:{}},debug:true});
const client = new Client({url:'https://example.test', security:{verify:{signature:false}}, debug:true});
export const options = {vus:2, iterations:4, thresholds:{checks:['rate==1']}};
export default function () {
  tokenClient.build('Echo','<Echo/>');timestampClient.build('Echo','<Echo/>');
  const request = client.build('Echo', '<Echo>POLICY_PRIVATE_SENTINEL</Echo>');
  const result = client.parse({status:200,body:request.body});
  check(result, {
    'plain policy stays explicitly unverified': p => p.ok && p.sigVerified===null && p.timestampValid===null,
    'unavailable security never becomes a silent no-op': () => constructorChecks.every(Boolean),
  });
}
