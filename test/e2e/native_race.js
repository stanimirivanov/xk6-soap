import { Counter } from 'k6/metrics';
import exec from 'k6/execution';
import http from 'k6/http';
import { Client } from 'k6/x/soap';

const cert = open('../../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../../internal/wssec/testdata/signing-key.pem', 'b');
const client = new Client({
  url: __ENV.SOAP_RACE_URL,
  soapVersion: '1.2',
  keys: { signing: { cert, key }, trust: [cert] },
  security: { sign: {}, verify: { signature: true, timestamp: true } },
});
const vus = Number(__ENV.SOAP_RACE_VUS);
const iterations = Number(__ENV.SOAP_RACE_ITERATIONS);
const expected = vus * iterations;
const verifiedReplies = new Counter('race_verified_replies');
const matchingReplies = new Counter('race_matching_replies');

export const options = {
  scenarios: {
    signedEcho: { executor:'per-vu-iterations', vus, iterations, maxDuration:'20s', gracefulStop:'0s' },
  },
  thresholds: {
    race_verified_replies: [`count==${expected}`],
    race_matching_replies: [`count==${expected}`],
  },
};

export default function () {
  const marker = `${exec.vu.idInTest}-${exec.vu.iterationInScenario}`;
  const request = client.build('Echo', `<m:Echo xmlns:m="urn:fixture:race">${marker}</m:Echo>`);
  const response = http.post(request.url, request.body, {headers:request.headers, timeout:'2s', redirects:0});
  const reply = client.parse(response);
  const verified = reply.ok && reply.sigVerified === true && reply.timestampValid === true;
  const markerResult = reply.xpath('string(./m:Echo)', {m:'urn:fixture:race'});
  verifiedReplies.add(verified ? 1 : 0);
  matchingReplies.add(verified && markerResult.error === null && markerResult.value === marker ? 1 : 0);
}

export function handleSummary({metrics}) {
  const verified = metrics.race_verified_replies?.values.count ?? 0;
  const matching = metrics.race_matching_replies?.values.count ?? 0;
  return {stdout:`RACE_REPLIES verified=${verified} matching=${matching}\n`};
}
