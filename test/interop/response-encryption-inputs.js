import { Client } from 'k6/x/soap';
import { check } from 'k6';

export const operations = {
  success: open('./testdata/response-encryption/echo-success.xml'),
  fault: open('./testdata/matrix/echo-fault.xml'),
};
export const soapVersions = ['1.1', '1.2'];
const plainClients = Object.fromEntries(soapVersions.map(soapVersion => [
  soapVersion, new Client({url: 'http://127.0.0.1:1', soapVersion}),
]));

export const options = {vus: 1, iterations: 1, thresholds: {checks: ['rate==1']}};

export function buildEcho(client, operation) {
  return client.build('echo', operation, {soapAction: 'urn:echo'});
}

function matchesPlainBody(request, operation) {
  // The plain SOAP serializer writes fixed Body wrappers.
  const body = request.body.match(/<s:Body>([\s\S]*)<\/s:Body>/)?.[1];
  return body === operation;
}

export default function checkPlainBuilds() {
  for (const soapVersion of soapVersions) {
    for (const [outcome, operation] of Object.entries(operations)) {
      const request = buildEcho(plainClients[soapVersion], operation);
      check(request, {
        ['SOAP ' + soapVersion + ' ' + outcome + ' retains Body operation bytes']: r => matchesPlainBody(r, operation),
      });
    }
  }

  const original = operations.success;
  const changed = original.replace('xmlns:m="urn:xk6-soap:fixture"', "xmlns:m='urn:xk6-soap:fixture'");
  const request = buildEcho(plainClients['1.2'], changed);
  check(request, {
    'SOAP 1.2 quote change keeps Echo value and length': () =>
      changed.includes('<value>RESPONSE_PRIVATE_SENTINEL</value>') && changed.length === original.length,
    'SOAP 1.2 retains changed Body operation bytes': r => matchesPlainBody(r, changed),
    'SOAP 1.2 changed Body fails the original byte comparison': r => !matchesPlainBody(r, original),
  });
}
