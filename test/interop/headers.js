import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

const cert=open('../../internal/wssec/testdata/signing-cert.pem','b');
const key=open('../../internal/wssec/testdata/signing-key.pem','b');
const trust=open(__ENV.SOAP_INTEROP_SIGNATURE_TRUST,'b');
const cases=[];
for(const version of ['1.1','1.2']) {
  for(const weak of [false,true]) {
    const url=__ENV.SOAP_INTEROP_URL+'/'+(weak?'sighdrweak':'sighdr')+version.replace('.','');
    const client=new Client({url,soapVersion:version,debug:true,keys:{signing:{cert,key},trust:[trust]},security:{sign:{headers:['trace']},verify:{signedHeaders:[{namespace:'urn:trace',localName:'Trace'}]}}});
    cases.push({client,url,weak});
  }
}
export const options={vus:1,iterations:1,thresholds:{checks:['rate==1']}};
export default function() {
  for(const {client,url,weak} of cases) {
    const request=client.build('echo','<m:echo xmlns:m="urn:xk6-soap:fixture"><value>HEADER_PRIVATE_SENTINEL</value></m:echo>',{
      headers:[{name:'trace',xml:'<h:Trace xmlns:h="urn:trace">selected-original</h:Trace>'}],
      addressing:{action:'urn:echo',to:url,messageId:'urn:uuid:header-test',replyTo:'http://www.w3.org/2005/08/addressing/anonymous'}
    });
    const response=http.post(url,request.body,{headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
    check(response,{'Apache accepts signed custom and addressing headers':r=>r.status===200});
    const parsed=client.parse(response);
    check(parsed,{'Apache response coverage enforced':p=>weak?!p.ok&&p.body===null&&p.sigVerified===false:p.ok&&p.sigVerified===true&&p.timestampValid===true});
    if(!weak){
      const tampered=client.parse({status:200,body:response.body.replace('response-original','response-tampered')});
      check(tampered,{'tampered selected response header withheld':p=>!p.ok&&p.body===null&&p.fault===null&&p.xpath('//*').error.code==='CONTENT_UNAVAILABLE'});
    }
    const rejected=http.post(url,request.body.replace('selected-original','selected-tampered'),{headers:request.headers,timeout:'5s',redirects:0});
    check(rejected,{'Apache rejects tampered selected request header':r=>r.status===500&&r.body.includes('Fault')});
    const badAddress=http.post(url,request.body.replace('urn:uuid:header-test','urn:uuid:tampered'),{headers:request.headers,timeout:'5s',redirects:0});
    check(badAddress,{'Apache rejects tampered addressing header':r=>r.status===500&&r.body.includes('Fault')});
  }
}
