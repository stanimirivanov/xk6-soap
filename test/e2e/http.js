import http from 'k6/http';
import { check } from 'k6';
import { Client } from 'k6/x/soap';

export const options = { vus: 1, iterations: 1, thresholds: { checks: ['rate==1'] } };
// Prove this is the custom binary; SOAP construction is a later feature task.
const client = new Client();
const base = __ENV.SOAP_FIXTURE_URL;
const versions = [
  ['http://schemas.xmlsoap.org/soap/envelope/', 'text/xml; charset=utf-8'],
  ['http://www.w3.org/2003/05/soap-envelope', 'application/soap+xml; charset=utf-8'],
];
export default function () {
  check(client, { 'custom extension loaded': (c) => typeof c.build === 'function' && typeof c.parse === 'function' });
  for (const [namespace, contentType] of versions) {
    const body = `<s:Envelope xmlns:s="${namespace}"><s:Body><m:Echo xmlns:m="urn:fixture">synthetic</m:Echo></s:Body></s:Envelope>`;
    const response = http.post(`${base}/echo`, body, {
      headers: { 'Content-Type': contentType, 'X-Synthetic': 'soap-e2e' },
      timeout: '2s', redirects: 0,
    });
    check(response, { 'SOAP echo is byte exact': (r) => r.status === 200 && r.body === body });
  }
  for (const version of ['11', '12']) {
    const response = http.post(`${base}/fault${version}`, '<synthetic/>', { timeout: '2s' });
    check(response, { 'SOAP fault shape': (r) => r.status === 500 && r.body.includes('Synthetic fault') && r.body.includes(version === '11' ? 'faultcode' : 's:Code') });
  }
  const empty = http.post(`${base}/empty`, null, { timeout: '2s' });
  check(empty, { 'empty response': (r) => r.status === 204 && (r.body === '' || r.body === null) });
  const binary = http.post(`${base}/binary`, null, { responseType: 'binary', timeout: '2s' });
  check(binary, { 'binary response bytes': (r) => {
    const bytes = new Uint8Array(r.body);
    return r.status === 200 && bytes.length === 3 && bytes[0] === 0 && bytes[1] === 128 && bytes[2] === 255;
  } });
  const delayed = http.post(`${base}/delay`, '<synthetic/>', { timeout: '50ms' });
  check(delayed, { 'delay produces status zero': (r) => r.status === 0 });
  const disconnected = http.post(`${base}/disconnect`, '<synthetic/>', { timeout: '2s' });
  check(disconnected, { 'disconnect produces status zero': (r) => r.status === 0 });
  check(null, { 'threshold negative control': () => __ENV.SOAP_E2E_FAIL !== '1' });
}
