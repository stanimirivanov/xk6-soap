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
  keys: {
    signing: {
      cert: open(__ENV.SOAP_SIGN_CERT, 'b'),
      key: open(__ENV.SOAP_SIGN_KEY, 'b'),
    },
    trust: [open(__ENV.SOAP_TRUST_CERT, 'b')],
  },
  security: { sign: {}, verify: { signature: true, timestamp: true } },
});

export default function () {
  const request = client.build('echo',
    '<m:echo xmlns:m="urn:xk6-soap:fixture"><value>synthetic</value></m:echo>',
    { soapAction: 'urn:echo' });
  const response = http.post(request.url, request.body, {
    headers: request.headers,
    responseType: 'text',
    redirects: 0,
    timeout: '5s',
  });
  const parsed = client.parse(response);
  check(parsed, {
    'SOAP accepted': (result) => result.ok,
    'signature and Timestamp verified': (result) =>
      result.sigVerified === true && result.timestampValid === true,
  });
}
