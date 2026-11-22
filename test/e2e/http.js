import http from 'k6/http';
import { check } from 'k6';
import { Client } from 'k6/x/soap';

export const options = { vus: 1, iterations: 1, thresholds: { checks: ['rate==1'] } };
// Retain the raw HTTP fixture probes alongside the public SOAP API scenarios.
const client = new Client({url:__ENV.SOAP_FIXTURE_URL});
const soapClients = ['1.1','1.2'].map(soapVersion => new Client({url:__ENV.SOAP_FIXTURE_URL+'/echo',soapVersion}));
const base = __ENV.SOAP_FIXTURE_URL;
const versions = [
  ['http://schemas.xmlsoap.org/soap/envelope/', 'text/xml; charset=utf-8'],
  ['http://www.w3.org/2003/05/soap-envelope', 'application/soap+xml; charset=utf-8'],
];
export default function () {
  check(client, { 'custom extension loaded': (c) => typeof c.build === 'function' && typeof c.parse === 'function' });
  for (let index=0;index<versions.length;index++) {
    const [namespace, contentType] = versions[index];
    const request = soapClients[index].build('Echo','<m:Echo xmlns:m="urn:fixture">synthetic</m:Echo>',{soapAction:'urn:echo'});
    const response = http.post(request.url, request.body, {
      headers: {...request.headers, 'X-Synthetic':'soap-e2e'},
      responseType: index===0 ? 'text':'binary', timeout:'2s', redirects:0,
    });
    const parsed = soapClients[index].parse(response);
    check(parsed, {
      'build/post/parse succeeds': p => p.ok && p.status===200 && p.error===null && p.sigVerified===null,
      'namespace XPath result': p => p.xpath('//m:Echo',{m:'urn:fixture'}).value[0]==='synthetic',
      'context step yields a boolean': p => {
        const result = p.xpath('. and true()');
        return result.error === null && result.value === true;
      },
      'parent step yields a boolean': p => {
        const result = p.xpath('.. or true()');
        return result.error === null && result.value === true;
      },
      'context and parent steps work in predicates': p => {
        const result = p.xpath('./m:Echo[. and true()][.. and true()]', {m:'urn:fixture'});
        return result.error === null && result.value.length === 1 && result.value[0] === 'synthetic';
      },
      'HTTP headers follow SOAP version': () => request.headers['Content-Type'].startsWith(contentType) && request.body.includes(namespace),
    });
  }
  for (let index=0;index<2;index++) {
    const version = ['11','12'][index];
    const response = http.post(`${base}/fault${version}`, '<synthetic/>', {timeout:'2s'});
    const parsed = soapClients[index].parse(response);
    check(parsed, {'parsed SOAP fault': p => !p.ok && p.error.code==='SOAP_FAULT' && p.fault.reason==='Synthetic fault'});
  }
  const discarded=http.post(`${base}/echo`,'<Echo/>',{responseType:'none',timeout:'2s'});
  check(client.parse(discarded),{'discarded body unavailable': p => !p.ok && p.error.code==='BODY_UNAVAILABLE'});
  const empty = http.post(`${base}/empty`, null, { timeout: '2s' });
  check(client.parse(empty),{'empty SOAP unavailable': p=>p.error.code==='BODY_UNAVAILABLE'});
  check(empty, { 'empty response': (r) => r.status === 204 && (r.body === '' || r.body === null) });
  const binary = http.post(`${base}/binary`, null, { responseType: 'binary', timeout: '2s' });
  check(binary, { 'binary response bytes': (r) => {
    const bytes = new Uint8Array(r.body);
    return r.status === 200 && bytes.length === 3 && bytes[0] === 0 && bytes[1] === 128 && bytes[2] === 255;
  } });
  const delayed = http.post(`${base}/delay`, '<synthetic/>', { timeout: '50ms' });
  check(client.parse(delayed),{'timeout SOAP result': p=>p.error.code==='TRANSPORT_ERROR'});
  check(delayed, { 'delay produces status zero': (r) => r.status === 0 });
  const disconnected = http.post(`${base}/disconnect`, '<synthetic/>', { timeout: '2s' });
  check(client.parse(disconnected),{'disconnect SOAP result': p=>p.error.code==='TRANSPORT_ERROR'});
  check(disconnected, { 'disconnect produces status zero': (r) => r.status === 0 });
  check(null, { 'threshold negative control': () => __ENV.SOAP_E2E_FAIL !== '1' });
}
