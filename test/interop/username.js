import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';
import checkPlainBuilds, {buildEcho, expectedValue, operation, soapVersions} from './username-inputs.js';

export { options } from './username-inputs.js';

const cases=[];
for(const version of soapVersions) {
  for(const passwordType of ['PasswordDigest','PasswordText']) {
    const url=__ENV.SOAP_INTEROP_URL+'/ut'+version.replace('.','');
    const create=password=>new Client({url,soapVersion:version,security:{usernameToken:{user:'fixture-user',password,passwordType}}});
    cases.push({good:create('fixture-password'),bad:create('wrong-password')});
  }
}
const stamps=soapVersions.map(version=>new Client({url:__ENV.SOAP_INTEROP_URL+'/ts'+version.replace('.',''),soapVersion:version,security:{timestamp:{ttlSeconds:300}}}));
function send(client,request,wantFault) {
  const response=http.post(request.url,request.body,{headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
  const result=client.parse(response);
  check(result,{
    'independent Apache acceptance or parsed fault':p=>wantFault ? !p.ok&&p.status===500&&p.fault!==null&&p.error.code==='SOAP_FAULT' : p.ok&&p.status===200&&p.body.includes(expectedValue),
    'UsernameToken does not authenticate responses':p=>p.sigVerified===null&&p.timestampValid===null,
  });
}
export default function(){
  checkPlainBuilds();
  for(const {good,bad} of cases){
    const request=buildEcho(good,operation);
    send(good,request,false);send(good,request,true);
    send(good,good.build('echo',operation,{soapAction:'urn:echo',credentials:{user:'fixture-user',password:'wrong-password'}}),true);
    send(good,buildEcho(good,operation),false);
    send(bad,bad.build('echo',operation,{soapAction:'urn:echo',credentials:{user:'fixture-user',password:'fixture-password'}}),false);
    send(bad,buildEcho(bad,operation),true);
  }
  for(const client of stamps)send(client,buildEcho(client,operation),false);
}
