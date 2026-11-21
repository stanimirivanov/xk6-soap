import { Client } from 'k6/x/soap';
import http from 'k6/http';
import encoding from 'k6/encoding';
import { check } from 'k6';

const cert = open('../../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../../internal/wssec/testdata/signing-key.pem', 'b');
const rsaTrust = __ENV.SOAP_INTEROP_SIGNATURE_TRUST;
const rsaPin = open(rsaTrust, 'b');
const fixtureDir = rsaTrust.slice(0, rsaTrust.lastIndexOf('/'));
const rows = [
  ['sigrsa384', 'rsa-sha384', 'sha512', 0, '1.1'],
  ['sigrsa512', 'rsa-sha512', 'sha384', 0, '1.2'],
  ['sigec256', 'ecdsa-sha256', 'sha256', 256, '1.1'],
  ['sigec384', 'ecdsa-sha384', 'sha384', 384, '1.2'],
  ['sigec521', 'ecdsa-sha512', 'sha512', 521, '1.2'],
];
const cases = rows.map(([mode, algorithm, digest, bits, soapVersion]) => {
  const url = __ENV.SOAP_INTEROP_URL + '/' + mode + soapVersion.replace('.', '');
  const signing = bits
    ? {pkcs12: open(fixtureDir + '/client-ec' + bits + '.p12', 'b'), password: 'fixture-only'}
    : {cert, key};
  const trust = [open(bits ? fixtureDir + '/server-ec' + bits + '.pem' : rsaTrust, 'b')];
  const verify = {signature:true, signatureAlgorithms:[algorithm], digestAlgorithms:[digest]};
  const client = new Client({url, soapVersion, keys:{signing, trust}, security:{sign:{algorithm,digest}, verify}});
  const receive = overrides => new Client({url, soapVersion, keys:{trust:bits ? [...trust,rsaPin] : trust}, security:{verify:{...verify,...overrides}}});
  const deniedAlgorithm = receive({signatureAlgorithms:['rsa-sha256']});
  const deniedDigest = receive({digestAlgorithms:[digest === 'sha256' ? 'sha384' : 'sha256']});
  if (bits) {
    const wrong = algorithm === 'ecdsa-sha256' ? 'ecdsa-sha384' : 'ecdsa-sha256';
    try {
      new Client({url, soapVersion, keys:{signing}, security:{sign:{algorithm:wrong},verify:{signature:false}}});
      throw new Error('constructor accepted incompatible EC curve');
    } catch (err) {
      if (err.code !== 'SOAP_POLICY_KEY') throw err;
    }
  }
  return {client, deniedAlgorithm, deniedDigest, bits, algorithm};
});

const wrongCurveURL = __ENV.SOAP_INTEROP_URL + "/sigecwrongcurve11";
const wrongCurveClient = new Client({
  url:wrongCurveURL,
  keys:{signing:{cert,key}, trust:[256,384].map(bits => open(fixtureDir + '/server-ec' + bits + '.pem', 'b'))},
  security:{sign:{}, verify:{signatureAlgorithms:['ecdsa-sha256']}},
});

export const options = {vus:1, iterations:1, thresholds:{checks:['rate==1']}};

function signatureWidth(xml) {
  const field = xml.match(/<(?:[\w.-]+:)?SignatureValue(?:\s[^>]*)?>([\s\S]*?)<\/(?:[\w.-]+:)?SignatureValue>/);
  return field ? encoding.b64decode(field[1].replace(/\s/g, '')).byteLength : 0;
}

const payload = '<m:echo xmlns:m="urn:xk6-soap:fixture"><value>ALGORITHM_PRIVATE_SENTINEL</value></m:echo>';

export default function () {
  for (const {client, deniedAlgorithm, deniedDigest, bits, algorithm} of cases) {
    const request = client.build('echo', payload, {soapAction:'urn:echo'});
    const response = http.post(request.url, request.body, {headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
    check(response, {
      [algorithm + ' accepted independently by Apache']: r => r.status === 200,
    });
    check(client.parse(response), {
      [algorithm + ' Apache response verified and fresh']: p => p.ok && p.sigVerified && p.timestampValid,
    });
    for (const denied of [deniedAlgorithm, deniedDigest]) {
      check(denied.parse(response), {
        'unlisted wire algorithm or digest withholds content': p => !p.ok && p.body === null && p.error.code === 'POLICY_VIOLATION',
      });
    }
    if (bits) {
      const width = 2 * Math.ceil(bits / 8);
      check(response, {
        [algorithm + ' fixed-width r||s in both directions']: r => signatureWidth(request.body) === width && signatureWidth(r.body) === width,
      });
    }
  }
  const request = wrongCurveClient.build('echo', payload, {soapAction:'urn:echo'});
  const response = http.post(request.url, request.body, {headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
  const result = wrongCurveClient.parse(response);
  check(result, {
    'allow-listed ECDSA method with pinned wrong curve rejected': p =>
      response.status === 200 && signatureWidth(response.body) === 96 &&
      !p.ok && p.body === null && p.error.code === 'POLICY_VIOLATION',
  });
}
