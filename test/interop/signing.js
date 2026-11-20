import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

// Public synthetic fixture identities only. k6 owns file inputs and HTTP.
const cert=open('../../internal/wssec/testdata/signing-cert.pem','b');
const key=open('../../internal/wssec/testdata/signing-key.pem','b');
const cases=[];
for(const version of ['1.1','1.2']) {
  const create=(token,mode)=>new Client({url:__ENV.SOAP_INTEROP_URL+'/'+mode+version.replace('.',''),soapVersion:version,debug:true,keys:{signing:{cert,key}},security:{sign:{},verify:{signature:false},...(token?{usernameToken:{user:'fixture-user',password:'fixture-password',passwordType:token}}:{})}});
  cases.push({client:create(null,'sig'),token:false});
  for(const type of ['PasswordDigest','PasswordText'])cases.push({client:create(type,'sigut'),bodyOnly:create(null,'sigut'),token:true});
}
export const options={vus:1,iterations:1,thresholds:{checks:['rate==1']}};
const payload='<m:echo xmlns:m="urn:xk6-soap:fixture"><value>SIGN_PRIVATE_SENTINEL</value></m:echo>';
function send(request,body,wantFault) {
  const response=http.post(request.url,body,{headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
  check(response,{'Apache validates exact signed wire or returns SOAP fault':r=>wantFault?r.status===500&&r.body.includes('Fault'):r.status===200&&r.body.includes('SIGN_PRIVATE_SENTINEL')});
}
export default function() {
  for(const {client,bodyOnly,token} of cases) {
    const request=client.build('echo',payload,{soapAction:'urn:echo'});
    send(request,request.body,false);
    send(request,request.body.replace('SIGN_PRIVATE_SENTINEL','tampered'),true);
    send(request,request.body.replace(/(<wsu:Created[^>]*>)([^<]+)/,(_,prefix,created)=>prefix+new Date(Date.parse(created)+1000).toISOString()),true);
    if(token) {
      send(request,request.body.replace('fixture-user','tampered-user'),true);
      // A valid two-reference signature plus a valid but unsigned UsernameToken
      // must fail the independent coverage policy, even with correct credentials.
      const uncovered=bodyOnly.build('echo',payload,{soapAction:'urn:echo'});
      const freshToken=client.build('echo',payload,{soapAction:'urn:echo'});
      const match=freshToken.body.match(/<wsse:UsernameToken\b[^>]*>[\s\S]*?<\/wsse:UsernameToken>/);
      if(!match)throw new Error('missing token for coverage control');
      send(uncovered,uncovered.body.replace('<wsse:BinarySecurityToken',match[0]+'<wsse:BinarySecurityToken'),true);
    }
  }
}
