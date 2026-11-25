import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { Client } from 'k6/x/soap';

export const options = {
  vus: 1, iterations: 1, thresholds: { checks: ['rate==1'], https_scenarios_completed: ['count==1'] },
};
const completed = new Counter('https_scenarios_completed');
const client = new Client({url:__ENV.SOAP_TLS_URL, soapVersion:'1.2'});
const marker = 'tls-auth-echo';

export default function () {
  // An interrupted iteration must still contribute a sample to the threshold.
  completed.add(0);
  if (__ENV.SOAP_HTTPS_INTERRUPT === 'before-checks') throw new Error('HTTPS control: before-checks');
  const request = client.build('Echo', `<m:Echo xmlns:m="urn:fixture">${marker}</m:Echo>`);
  const params = {headers:request.headers, redirects:0, timeout:'2s'};
  const authenticated = http.post(request.url, request.body, {
    ...params, headers:{...request.headers, Authorization:`Basic ${__ENV.SOAP_BASIC_AUTH}`},
  });
  check(client.parse(authenticated), {
    'authenticated HTTPS reply echoes the SOAP Body marker': p =>
      p.status === 200 && p.ok && p.xpath('string(./m:Echo)', {m:'urn:fixture'}).value === marker,
  });
  if (__ENV.SOAP_HTTPS_INTERRUPT === 'after-authenticated') throw new Error('HTTPS control: after-authenticated');
  const unauthenticated = http.post(request.url, request.body, params);
  check(unauthenticated, {'HTTPS without Basic Auth returns 401': r => r.status === 401});
  completed.add(1);
}
