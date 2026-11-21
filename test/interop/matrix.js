import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

const cert = open('../../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../../internal/wssec/testdata/signing-key.pem', 'b');
const server = open(__ENV.SOAP_INTEROP_SIGNATURE_TRUST, 'b');
const trace = {namespace: 'urn:trace', localName: 'Trace'};
const rows = JSON.parse(open('./matrix.json')).core.map(row => {
  const headers = row.target === 'headers';
  const client = new Client({
    url: __ENV.SOAP_INTEROP_URL + '/' + row.endpoint,
    soapVersion: row.soapVersion,
    keys: {signing: {cert,key}, recipient: {cert:server}, decryption: {cert,key}, trust: [server]},
    security: {
      sign: {},
      encrypt: {algorithm: 'aes-' + row.bits + '-gcm', target: row.target, ...(headers ? {headers: ['trace']} : {})},
      order: row.order,
      verify: {order: row.order, requireEncryption: !headers, ...(headers ? {signedHeaders: [trace], encryptedHeaders: [trace]} : {})},
    },
  });
  return {row,client};
});

export const options = {vus:1, iterations:1, thresholds:{checks:['rate==1']}};
const sentinel = 'MATRIX_PRIVATE_SENTINEL';
const faultReason = 'Synthetic service fault';

function wireMatches(body, row) {
  const type = row.target === 'content' ? 'Content' : 'Element';
  return body.includes('EncryptedData') &&
    body.includes('http://www.w3.org/2009/xmlenc11#aes' + row.bits + '-gcm') &&
    body.includes('Type="http://www.w3.org/2001/04/xmlenc#' + type + '"') &&
    body.includes('EncryptedHeader') === (row.target === 'headers');
}

export default function () {
  for (const {row,client} of rows) {
    for (const outcome of row.outcomes) {
      const fault = outcome === 'fault';
      const value = fault ? 'fault' : sentinel;
      const headers = row.target === 'headers';
      const label = row.endpoint + ' ' + outcome;
      const request = client.build('echo', '<m:echo xmlns:m="urn:xk6-soap:fixture"><value>' + value + '</value></m:echo>', {
        soapAction: 'urn:echo',
        ...(headers ? {headers: [
          {name:'trace', xml:'<h:Trace xmlns:h="urn:trace">MATRIX_PRIVATE_HEADER</h:Trace>'},
          {name:'other', xml:'<h:Other xmlns:h="urn:trace">clear-header</h:Other>'},
        ]} : {}),
      });
      check(request, {
        [label + ' request matches target and AES']: r =>
          wireMatches(r.body,row) && (headers
            ? r.body.includes('clear-header') && !r.body.includes('MATRIX_PRIVATE_HEADER') && r.body.includes('<value>' + value + '</value>')
            : !r.body.includes('<value>' + value + '</value>')),
      });
      const response = http.post(request.url, request.body, {headers:request.headers, responseType:'text', timeout:'5s', redirects:0});
      check(response, {
        [label + ' independent response matches target and AES']: r =>
          r.status === (fault ? 500 : 200) && wireMatches(r.body,row) &&
          (headers ? r.body.includes('response-clear-header') && !r.body.includes('response-original')
            : !r.body.includes(fault ? faultReason : sentinel)),
      });
      const parsed = client.parse(response);
      check(parsed, {
        [label + ' content released after authentication']: p =>
          p.sigVerified === true && p.timestampValid === true && (fault
            ? !p.ok && p.error?.code === 'SOAP_FAULT' && p.fault?.reason === faultReason
            : p.ok && p.xpath('string(.//*[local-name()="return"])').value === sentinel),
      });
      const changed = response.body.replace(/(<[^<> ]+:SignatureValue\b[^>]*>\s*)([A-Za-z0-9+/])/, (_,tag,ch) =>
        tag + (ch === 'A' ? 'B' : 'A'));
      const invalid = client.parse({status:response.status,body:changed});
      check(invalid, {
        [label + ' invalid signature withholds Body and Fault']: p =>
          changed !== response.body && p.body === null && p.fault === null &&
          p.error?.code === 'SIGNATURE_INVALID' && p.xpath('string(.)').error?.code === 'CONTENT_UNAVAILABLE',
      });
    }
  }
}
