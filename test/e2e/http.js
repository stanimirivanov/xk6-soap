import http from 'k6/http';
import { check } from 'k6';
import { Client } from 'k6/x/soap';

export const options = { vus: 1, iterations: 1, thresholds: { checks: ['rate==1'] } };
// Retain the raw HTTP fixture probes alongside the public SOAP API scenarios.
const base = __ENV.SOAP_FIXTURE_URL;
const client = new Client({url:base});
const soap11 = {
  version:'11', namespace:'http://schemas.xmlsoap.org/soap/envelope/', code:'Server', responseType:'text', mediaType:'text/xml',
  soap:new Client({url:base+'/echo', soapVersion:'1.1'}),
};
const soap12 = {
  version:'12', namespace:'http://www.w3.org/2003/05/soap-envelope', code:'Receiver', responseType:'binary', mediaType:'application/soap+xml',
  soap:new Client({url:base+'/echo', soapVersion:'1.2', namespace:'urn:fixture'}),
};
const echoNamespaces = {m:'urn:fixture'};
const echoPayload = marker => `<m:Echo xmlns:m="urn:fixture">${marker}</m:Echo>`;

function rejectsArgument(call, stage) {
  try {
    call();
  } catch (error) {
    return error instanceof TypeError && error.code === 'INVALID_ARGUMENT' && error.stage === stage;
  }
  return false;
}

function checkEcho({version, namespace, responseType, mediaType, soap}) {
  const explicit = `soap${version}-explicit`;
  const omitted = `soap${version}-omitted`;
  const request = soap.build('Echo', echoPayload(explicit), {soapAction:'urn:echo'});
  const params = {
    responseType, timeout:'2s', redirects:0,
  };
  const response = http.post(request.url, request.body, {...params, headers:{...request.headers, 'X-Synthetic':'soap-e2e'}});
  const parsed = soap.parse(response);
  check(parsed, {
    'build/post/parse succeeds': p => p.ok && p.status===200 && p.error===null && p.sigVerified===null,
    'namespace XPath result': p => p.xpath('string(//m:Echo)', echoNamespaces).value === explicit,
    'context step yields a boolean': p => {
      const result = p.xpath('. and true()');
      return result.error === null && result.value === true;
    },
    'parent step yields a boolean': p => {
      const result = p.xpath('.. or true()');
      return result.error === null && result.value === true;
    },
    'context and parent steps work in predicates': p => {
      const result = p.xpath('./m:Echo[. and true()][.. and true()]', echoNamespaces);
      return result.error === null && result.value.length === 1 && result.value[0] === explicit;
    },
  });
  const requestWithoutAction = soap.build('Echo', echoPayload(omitted));
  const omittedReply = http.post(requestWithoutAction.url, requestWithoutAction.body, {
    ...params, headers:{...requestWithoutAction.headers, 'X-Synthetic':'soap-e2e'},
  });
  check(soap.parse(omittedReply), {
    'omitted action echoes its own marker': p => p.ok && p.xpath('string(//m:Echo)', echoNamespaces).value === omitted,
  });
  const declarationMarker = `soap${version}-declared`;
  const declarationRequest = soap.build('Echo', echoPayload(declarationMarker));
  const undeclared = soap.parse({status:200, body:declarationRequest.body});
  const declared = http.post(declarationRequest.url, '<?xml version="1.0" encoding="UTF-8"?>\n' + declarationRequest.body,
    {...params, headers:declarationRequest.headers});
  check([response, omittedReply, declared], {
    [`SOAP ${version} echo replies have the expected media type`]: replies => replies.every(reply =>
      reply.status === 200 && reply.headers['Content-Type']?.split(';', 1)[0].trim().toLowerCase() === mediaType),
  });
  check(soap.parse(declared), {
    'XML declaration preserves accepted response content': p =>
      p.ok && p.status === undeclared.status && p.body === undeclared.body &&
      p.xpath('string(//m:Echo)', echoNamespaces).value === declarationMarker,
  });
  const httpError = soap.parse({status:503, body:request.body});
  check(httpError, {
    'HTTP errors retain accepted Body and XPath': p =>
      !p.ok && p.error?.code === 'HTTP_STATUS' && p.body === parsed.body &&
      p.xpath('string(//m:Echo)', echoNamespaces).value === explicit,
  });
  const encrypted = `<s:Envelope xmlns:s="${namespace}"><s:Body><x:EncryptedData xmlns:x="http://www.w3.org/2001/04/xmlenc#"/></s:Body></s:Envelope>`;
  check(soap.parse({status:503, body:encrypted}), {
    'plain client withholds encrypted Body before HTTP outcome': p =>
      !p.ok && p.error?.code === 'POLICY_VIOLATION' && p.body === null && p.fault === null &&
      p.xpath('.').error?.code === 'CONTENT_UNAVAILABLE',
  });
}

function checkFault({version, namespace, code, soap}) {
  const response = http.post(`${base}/fault${version}`, '<synthetic/>', {timeout:'2s'});
  check(soap.parse(response), {
    [`SOAP ${version} Fault code and reason`]: p => p.status === 500 && !p.ok && p.error?.code === 'SOAP_FAULT' &&
      p.fault?.code?.namespace === namespace && p.fault.code.localName === code && p.fault.reason === 'Synthetic fault',
    [`SOAP ${version} Fault detail XML`]: p => {
      if (typeof p.fault?.detail !== 'string') return false;
      const detail = soap.parse({status:200, body:`<s:Envelope xmlns:s="${namespace}"><s:Body>${p.fault.detail}</s:Body></s:Envelope>`});
      return detail.ok && detail.xpath('count(./*)').value === 1 && detail.xpath('count(./fixture)').value === 1;
    },
  });
}

function checkVersionMismatchFault({namespace, soap}) {
  const response = http.post(`${base}/w3c-t30`, null, {timeout:'2s'});
  check(soap.parse(response), {
    'W3C T30 SOAP 1.1 VersionMismatch Fault projects its qualified code': p =>
      p.status === 500 && !p.ok && p.error?.code === 'SOAP_FAULT' &&
      p.fault?.code?.namespace === namespace && p.fault.code.localName === 'VersionMismatch',
  });
}

const withholdsMandatoryHeader = p => withholdsHeaderBody(p, 'POLICY_VIOLATION');

function withholdsHeaderBody(p, code) {
  const query = p.xpath('string(./m:Echo)', echoNamespaces);
  return p.status === 200 && !p.ok && p.error?.code === code && p.error.stage === 'parse' &&
    p.body === null && p.fault === null && query.value === null && query.error?.code === 'CONTENT_UNAVAILABLE';
}

function acceptsHeaderReplyBody(p) {
  const query = p.xpath('string(./m:Echo)', echoNamespaces);
  return p.status === 200 && p.ok && p.error === null && p.fault === null &&
    query.error === null && query.value === 'w3c-role-marker';
}

function checkMandatoryHeaderRoles(soap) {
  const targeted = http.post(`${base}/w3c-t12`, null, {timeout:'2s'});
  check(soap.parse(targeted), {
    'W3C T12 targeted unknown mandatory header withholds content': withholdsMandatoryHeader,
  });
  const otherRole = http.post(`${base}/w3c-t15`, null, {timeout:'2s'});
  check(soap.parse(otherRole), {
    'W3C T15 unknown mandatory header for a different role allows Body': acceptsHeaderReplyBody,
  });
  for (const role of ['next', 'none']) {
    const response = http.post(`${base}/w3c-standard-role/${role}`, null, {timeout:'2s'});
    check(soap.parse(response), {
      [`SOAP 1.2 role=${role} with mustUnderstand=1`]: role === 'next' ? withholdsMandatoryHeader : acceptsHeaderReplyBody,
    });
  }
  for (const mustUnderstand of ['1', 'true', '0', 'false']) {
    const response = http.post(`${base}/w3c-default-role/${mustUnderstand}`, null, {timeout:'2s'});
    check(soap.parse(response), {
      [`SOAP 1.2 omitted role with mustUnderstand=${mustUnderstand}`]:
        ['1', 'true'].includes(mustUnderstand) ? withholdsMandatoryHeader : acceptsHeaderReplyBody,
    });
  }
}

function checkForeignMustUnderstand(soap) {
  const cases = [
    ['foreign-only', acceptsHeaderReplyBody],
    ['mandatory-native-first', withholdsMandatoryHeader],
    ['mandatory-foreign-first', withholdsMandatoryHeader],
    ['optional-native-first', acceptsHeaderReplyBody],
    ['optional-foreign-first', acceptsHeaderReplyBody],
    ['foreign-actor', p => withholdsHeaderBody(p, 'XML_INVALID')],
  ];
  for (const [name, outcome] of cases) {
    const response = http.post(`${base}/w3c-t34/${name}`, null, {timeout:'2s'});
    check(soap.parse(response), { [`W3C T34 ${name}`]: outcome });
  }
}

export default function () {
  check(client, { 'custom extension loaded': (c) => typeof c.build === 'function' && typeof c.parse === 'function' });
  checkEcho(soap11);
  checkEcho(soap12);
  checkFault(soap11);
  checkFault(soap12);
  checkVersionMismatchFault(soap11);
  check(soap12.soap, {
    'nested null rejects at the payload boundary': soap => rejectsArgument(() => soap.build('Echo', {value:null}), 'payload'),
    'typed array view rejects at the response body boundary': soap => rejectsArgument(() => soap.parse({status:200, body:new Uint8Array([65])}), 'body'),
  });
  checkMandatoryHeaderRoles(soap12.soap);
  checkForeignMustUnderstand(soap12.soap);
  const malformedFault = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>' +
    '<s:Code><s:Value>s:Sender</s:Value><s:Value>s:Receiver</s:Value></s:Code>' +
    '<s:Reason><s:Text xml:lang="en">Synthetic fault</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>';
  const malformed = http.post(base + '/echo', malformedFault, {timeout:'2s'});
  check(soap12.soap.parse(malformed), {
    'malformed SOAP 1.2 Fault withholds content': p => {
      const query = p.xpath('.');
      return p.status === 200 && !p.ok && p.error?.code === 'XML_INVALID' &&
        p.body === null && p.fault === null && query.value === null && query.error?.code === 'CONTENT_UNAVAILABLE';
    },
  });
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
