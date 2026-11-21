import { check } from 'k6';
import http from 'k6/http';
import { Client } from 'k6/x/soap';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: { soap_req_failed: ['rate==0'], checks: ['rate==1'] },
};

const client = new Client({
  url: __ENV.SOAP_URL,
  soapVersion: '1.2',
  namespace: 'urn:example',
});

export default function () {
  const request = client.build('Echo', {
    '@id': 'synthetic',
    item: ['first', 'second'],
  }, { soapAction: 'urn:echo' });
  const response = http.post(request.url, request.body, {
    headers: request.headers,
    responseType: 'text',
    redirects: 0,
    timeout: '5s',
  });
  const parsed = client.parse(response);
  check(parsed, {
    'SOAP accepted': (result) => result.ok,
    'echo preserved item order': (result) => {
      const items = result.xpath('//m:item', { m: 'urn:example' });
      return items.error === null && items.value.join(',') === 'first,second';
    },
  });
}
