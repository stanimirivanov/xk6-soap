import { check } from 'k6';
import http from 'k6/http';
import { Client } from 'k6/x/soap';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: { soap_req_failed: ['rate==0'], checks: ['rate==1'] },
};

const client = new Client({ url: __ENV.SOAP_URL, soapVersion: '1.2' });

export default function () {
  const request = client.build('Echo', '<Echo xmlns="urn:example">hello</Echo>', {
    soapAction: 'urn:echo',
  });
  const response = http.post(request.url, request.body, {
    headers: request.headers,
    responseType: 'text',
    redirects: 0,
    timeout: '5s',
  });
  const parsed = client.parse(response);
  check(parsed, { 'SOAP accepted': (result) => result.ok });
}
