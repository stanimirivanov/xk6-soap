import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

const cert = open('../../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../../internal/wssec/testdata/signing-key.pem', 'b');
const server = open(__ENV.SOAP_INTEROP_SIGNATURE_TRUST, 'b');
const cases = [];
const trace = {namespace:'urn:trace',localName:'Trace'};
for (const soapVersion of ['1.1','1.2']) {
  for (const [mode,order] of [['stehdr','sign-then-encrypt'],['etshdr','encrypt-then-sign']]) {
    const url = __ENV.SOAP_INTEROP_URL + '/' + mode + soapVersion.replace('.', '');
    const config = {
      url, soapVersion, debug:true,
      keys:{signing:{cert,key},recipient:{cert:server},decryption:{cert,key},trust:[server]},
      security:{
        sign:{},encrypt:{target:'headers',headers:['trace']},order,
        verify:{order,encryptedHeaders:[trace],signedHeaders:[trace]},
      },
    };
    const client = new Client(config);
    const bodyRequired = new Client({
      ...config,
      security:{...config.security,verify:{...config.security.verify,requireEncryption:true}},
    });
    cases.push({client,bodyRequired,order,soapVersion});
  }
}
export const options = {vus:1,iterations:1,thresholds:{checks:['rate==1']}};

export default function () {
  for (const {client,bodyRequired,order,soapVersion} of cases) {
    const req = client.build('echo','<m:echo xmlns:m="urn:xk6-soap:fixture"><value>visible-body</value></m:echo>',{
      soapAction:'urn:echo',
      headers:[
        {name:'trace',xml:'<h:Trace xmlns:h="urn:trace">HEADER_ENCRYPTION_PRIVATE_SENTINEL</h:Trace>'},
        {name:'other',xml:'<h:Other xmlns:h="urn:trace">clear-header</h:Other>'},
      ],
    });
    const label = order + ' SOAP ' + soapVersion;
    check(req,{
      [label + ' encrypts only the selected request header']: r =>
        r.body.includes('EncryptedHeader') && !r.body.includes('HEADER_ENCRYPTION_PRIVATE_SENTINEL') &&
        r.body.includes('clear-header') && r.body.includes('visible-body'),
    });
    const res = http.post(req.url,req.body,{headers:req.headers,timeout:'5s',redirects:0,responseType:'text'});
    check(res,{
      [label + ' WSS4J returned encrypted Trace and clear siblings']: r =>
        r.status === 200 && r.body.includes('EncryptedHeader') && r.body.includes('response-clear-header') &&
        r.body.includes('visible-body') && !r.body.includes('response-original'),
    });
    check(client.parse(res),{
      [label + ' accepts independently recovered and signed header']: p =>
        p.ok && p.sigVerified && p.timestampValid && p.xpath('string(.//*[local-name()="return"])').value === 'visible-body',
    });
    check(bodyRequired.parse(res),{
      [label + ' header protection cannot satisfy Body policy']: p =>
        !p.ok && p.error.code === 'POLICY_VIOLATION' && p.body === null,
    });
  }
}
