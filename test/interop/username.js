import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

const cases=[];
for(const version of ['1.1','1.2']) {
  for(const passwordType of ['PasswordDigest','PasswordText']) {
    const url=__ENV.SOAP_INTEROP_URL+'/ut'+version.replace('.','');
    const create=password=>new Client({url,soapVersion:version,security:{usernameToken:{user:'fixture-user',password,passwordType}}});
    cases.push({good:create('fixture-password'),bad:create('wrong-password')});
  }
}
const stamps=['1.1','1.2'].map(version=>new Client({url:__ENV.SOAP_INTEROP_URL+'/ts'+version.replace('.',''),soapVersion:version,security:{timestamp:{ttlSeconds:300}}}));
export const options={vus:1,iterations:1,thresholds:{checks:['rate==1']}};
const payload='<m:echo xmlns:m="urn:xk6-soap:fixture"><value>synthetic</value></m:echo>';
function send(client,request,wantFault) {
  const response=http.post(request.url,request.body,{headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
  const result=client.parse(response);
  check(result,{
    'independent Apache acceptance or parsed fault':p=>wantFault ? !p.ok&&p.status===500&&p.fault!==null&&p.error.code==='SOAP_FAULT' : p.ok&&p.status===200&&p.body.includes('synthetic'),
    'UsernameToken does not authenticate responses':p=>p.sigVerified===null&&p.timestampValid===null,
  });
}
export default function(){
  for(const {good,bad} of cases){
    const request=good.build('echo',payload,{soapAction:'urn:echo'});
    send(good,request,false);send(good,request,true);
    send(good,good.build('echo',payload,{soapAction:'urn:echo',credentials:{user:'fixture-user',password:'wrong-password'}}),true);
    send(good,good.build('echo',payload,{soapAction:'urn:echo'}),false);
    send(bad,bad.build('echo',payload,{soapAction:'urn:echo',credentials:{user:'fixture-user',password:'fixture-password'}}),false);
    send(bad,bad.build('echo',payload,{soapAction:'urn:echo'}),true);
  }
  for(const client of stamps)send(client,client.build('echo',payload,{soapAction:'urn:echo'}),false);
}
