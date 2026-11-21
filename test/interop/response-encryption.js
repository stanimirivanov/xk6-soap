import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

const cert = open('../../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../../internal/wssec/testdata/signing-key.pem', 'b');
const server = open(__ENV.SOAP_INTEROP_SIGNATURE_TRUST, 'b');
const cases = [];
for (const soapVersion of ['1.1', '1.2']) {
  for (const bits of [128, 256]) {
    const url = __ENV.SOAP_INTEROP_URL + '/stefault' + bits + soapVersion.replace('.', '');
    const client = new Client({
      url, soapVersion, debug:true,
      keys:{signing:{cert,key},recipient:{cert:server},decryption:{cert,key},trust:[server]},
      security:{
        sign:{}, encrypt:{algorithm:'aes-' + bits + '-gcm'},
        verify:{order:'sign-then-encrypt',requireEncryption:true},
      },
    });
    cases.push({client,soapVersion,bits});
  }
}
export const options = {vus:1,iterations:1,thresholds:{checks:['rate==1']}};
const sentinel = 'RESPONSE_PRIVATE_SENTINEL';

function flip(xml, start) {
  const pattern = new RegExp('(' + start + '\\b[^>]*>\\s*)([A-Za-z0-9+/])');
  return xml.replace(pattern, (_, tag, ch) => tag + (ch === 'A' ? 'B' : 'A'));
}

export default function () {
  for (const {client,soapVersion,bits} of cases) {
    for (const value of [sentinel, 'fault']) {
      const req = client.build('echo', '<m:echo xmlns:m="urn:xk6-soap:fixture"><value>' + value + '</value></m:echo>', {soapAction:'urn:echo'});
      const res = http.post(req.url,req.body,{headers:req.headers,timeout:'5s',redirects:0,responseType:'text'});
      const isFault = value === 'fault';
      const label = soapVersion + ' AES-' + bits + (isFault ? ' fault' : ' success');
      check(res,{
        [label + ' was encrypted by WSS4J']: r =>
          r.status === (isFault ? 500 : 200) && r.body.includes('EncryptedData') &&
          !r.body.includes(sentinel) && !r.body.includes('Synthetic service fault'),
      });
      const result = client.parse(res);
      check(result,{
        [label + ' authenticated and projected']: p =>
          p.sigVerified === true && p.timestampValid === true &&
          (isFault
            ? !p.ok && p.error.code === 'SOAP_FAULT' && p.fault.reason === 'Synthetic service fault'
            : p.ok && p.xpath('string(.//*[local-name()="return"])').value === sentinel),
      });
      const badSignature = flip(res.body,'<[^<> ]+:SignatureValue');
      const badCipher = flip(res.body,'<[^<> ]+:CipherValue');
      const hidden = (wire,code) => {
        const p = client.parse({status:res.status, body:wire});
        return wire !== res.body && !p.ok && p.body === null && p.fault === null &&
          p.error.code === code && p.xpath('string(.)').error.code === 'CONTENT_UNAVAILABLE';
      };
      check(result,{
        'mutated wrapped key withholds output': () => hidden(badCipher,'DECRYPTION_FAILED'),
        'decryption alone does not expose the result': () => hidden(badSignature,'SIGNATURE_INVALID'),
      });
    }
  }
}
