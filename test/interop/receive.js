import {Client} from 'k6/x/soap';
import http from 'k6/http';
import {check} from 'k6';
const cert=open('../../internal/wssec/testdata/signing-cert.pem','b');
const key=open('../../internal/wssec/testdata/signing-key.pem','b');
const server=open(__ENV.SOAP_INTEROP_SIGNATURE_TRUST,'b');
const cases=['1.1','1.2'].map(soapVersion=>{
 const url=__ENV.SOAP_INTEROP_URL+'/sig'+soapVersion.replace('.','');
 const create=(trust,verify)=>new Client({url,soapVersion,debug:true,keys:{signing:{cert,key},trust},security:{sign:{},...(verify?{verify}:{})}});
 return {client:create([server]),wrong:create([cert]),skip:create([],{signature:false})};
});
export const options={vus:1,iterations:1,thresholds:{checks:['rate==1']}};
function hidden(p){return !p.ok&&p.body===null&&p.fault===null&&p.sigVerified===false&&p.xpath('string(.)').error.code==='CONTENT_UNAVAILABLE';}
export default function(){
 for(const {client,wrong,skip} of cases){
  for(const value of ['synthetic','fault']){
   const request=client.build('echo','<m:echo xmlns:m="urn:xk6-soap:fixture"><value>'+value+'</value></m:echo>',{soapAction:'urn:echo'});
   const response=http.post(request.url,request.body,{headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
   const p=client.parse(response);
   check(p,{
    'independently signed response or signed fault accepted':r=>value==='fault'?response.status===500&&r.error!==null&&r.error.code==='SOAP_FAULT'&&r.fault!==null:response.status===200&&r.ok&&r.body.includes('synthetic'),
    'both required checks are true':r=>r.sigVerified===true&&r.timestampValid===true,
    'accepted XPath is isolated from security headers':r=>r.xpath('count(//ds:Signature)',{ds:'http://www.w3.org/2000/09/xmldsig#'}).value===0,
   });
   const declared={status:response.status,body:'<?xml version="1.0" encoding="UTF-8"?>\n'+response.body};
   check(client.parse(declared),{'XML declaration preserves signed response acceptance':r=>
    r.sigVerified===true&&r.timestampValid===true&&r.ok===p.ok&&r.body!==null&&
    r.error?.code===p.error?.code&&r.fault?.reason===p.fault?.reason&&
    r.xpath('string(.)').value===p.xpath('string(.)').value});
   check(wrong.parse(response),{'wrong leaf pin withholds response and fault':hidden});
   const original=value==='fault'?'Synthetic service fault':'synthetic';
   const changed=response.body.replace(original,'RECEIVE_PRIVATE_SENTINEL');
   if(changed===response.body)throw new Error('missing tamper target');
   const altered={status:response.status,body:changed};
   check(client.parse(altered),{'modified consumed content never escapes':hidden});
   check(skip.parse(altered),{'explicitly skipped signature grants no authenticity':r=>r.body!==null&&r.sigVerified===null&&r.timestampValid===null});
  }
 }
}
