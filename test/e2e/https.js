import http from 'k6/http';
import { check } from 'k6';
import { Client } from 'k6/x/soap';

export const options = { vus: 1, iterations: 1, thresholds: { checks: ['rate==1'] } };
const client = new Client({url:__ENV.SOAP_TLS_URL, soapVersion:'1.2'});
const marker = 'tls-auth-echo';

export default function () {
  const request = client.build('Echo', `<m:Echo xmlns:m="urn:fixture">${marker}</m:Echo>`);
  const params = {headers:request.headers, redirects:0, timeout:'2s'};
  const authenticated = http.post(request.url, request.body, {
    ...params, headers:{...request.headers, Authorization:`Basic ${__ENV.SOAP_BASIC_AUTH}`},
  });
  check(client.parse(authenticated), {
    'authenticated HTTPS reply echoes the SOAP Body marker': p =>
      p.status === 200 && p.ok && p.xpath('string(./m:Echo)', {m:'urn:fixture'}).value === marker,
  });
  const unauthenticated = http.post(request.url, request.body, params);
  check(unauthenticated, {'HTTPS without Basic Auth returns 401': r => r.status === 401});
}
