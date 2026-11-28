import { Client } from 'k6/x/soap';
import { check } from 'k6';

const operation = open('./testdata/header-encryption/echo.xml');
const headerBlocks = [
  {name: 'trace', xml: open('./testdata/header-encryption/header-trace.xml')},
  {name: 'other', xml: open('./testdata/matrix/header-other.xml')},
];
const soapVersions = ['1.1', '1.2'];
const plainClients = Object.fromEntries(soapVersions.map(soapVersion => [
  soapVersion, new Client({url: 'http://127.0.0.1:1', soapVersion}),
]));

export const options = {vus: 1, iterations: 1, thresholds: {checks: ['rate==1']}};

export function buildEcho(client, headers = headerBlocks) {
  return client.build('echo', operation, {soapAction: 'urn:echo', headers});
}

function rawPlainBodyOperation(request) {
  // The plain SOAP serializer writes fixed Header and Body wrappers.
  return request.body.match(/<s:Body>([\s\S]*)<\/s:Body>/)?.[1];
}

function matchesPlainHeader(request, blocks) {
  const rawHeader = request.body.match(/<s:Header>([\s\S]*?)<\/s:Header><s:Body>/)?.[1];
  return rawHeader === blocks.map(block => block.xml).join('');
}

export default function checkPlainBuilds() {
  for (const soapVersion of soapVersions) {
    const request = buildEcho(plainClients[soapVersion]);
    check(request, {
      ['SOAP ' + soapVersion + ' retains Body operation bytes']: r => rawPlainBodyOperation(r) === operation,
      ['SOAP ' + soapVersion + ' retains ordered Header bytes']: r => matchesPlainHeader(r, headerBlocks),
    });
  }

  const [traceBlock, otherBlock] = headerBlocks;
  const changedTrace = traceBlock.xml.replace('xmlns:h="urn:trace"', "xmlns:h='urn:trace'");
  const changedBlocks = [{...traceBlock, xml: changedTrace}, otherBlock];
  const request = buildEcho(plainClients['1.2'], changedBlocks);
  check(request, {
    'SOAP 1.2 quote change keeps Trace length': () => changedTrace.length === traceBlock.xml.length,
    'SOAP 1.2 quote change keeps Body operation bytes': r => rawPlainBodyOperation(r) === operation,
    'SOAP 1.2 retains the changed Trace and unchanged Other bytes in order': r => matchesPlainHeader(r, changedBlocks),
    'SOAP 1.2 changed Trace fails the original Header byte comparison': r => !matchesPlainHeader(r, headerBlocks),
  });
}
