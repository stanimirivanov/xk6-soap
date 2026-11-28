import {Client} from 'k6/x/soap';
import http from 'k6/http';
import {check} from 'k6';
import checkPlainBuilds, {buildEcho, operations, soapVersions} from './timestamp-inputs.js';

export { options } from './timestamp-inputs.js';

const cert=open('../../internal/wssec/testdata/signing-cert.pem','b');
const key=open('../../internal/wssec/testdata/signing-key.pem','b');
const server=open(__ENV.SOAP_INTEROP_SIGNATURE_TRUST,'b');
const cases=[];
for(const soapVersion of soapVersions){
 for(const mode of ['sig','sigstale','sigfuture']){
  const create=verify=>new Client({url:__ENV.SOAP_INTEROP_URL+'/'+mode+soapVersion.replace('.',''),soapVersion,debug:true,keys:{signing:{cert,key},trust:[server]},security:{sign:{},...(verify?{verify}:{})}});
  cases.push({mode,required:create(),skip:create({signature:true,timestamp:false}),relaxed:create({signature:true,clockSkewSeconds:180}),short:create({signature:true,maxAgeSeconds:1})});
 }
}
function accepted(p,fault){return fault?p.error!==null&&p.error.code==='SOAP_FAULT'&&p.fault!==null:p.ok&&p.body.includes('TIMESTAMP_PRIVATE_SENTINEL');}
function stale(p){return !p.ok&&p.body===null&&p.fault===null&&p.error.code==='TIMESTAMP_INVALID'&&p.sigVerified===true&&p.timestampValid===false&&p.xpath('string(.)').error.code==='CONTENT_UNAVAILABLE';}
export default function(){
 checkPlainBuilds();
 for(const {mode,required,skip,relaxed,short} of cases){
  for(const [outcome,operation] of Object.entries(operations)){
   const fault=outcome==='fault';
   const request=buildEcho(required,operation);
   const response=http.post(request.url,request.body,{headers:request.headers,timeout:'5s',redirects:0,responseType:'text'});
   const p=required.parse(response);
   check(p,{'required freshness accepts fresh Apache and withholds stale/future content':r=>mode==='sig'?accepted(r,fault)&&r.sigVerified===true&&r.timestampValid===true:stale(r)});
   check(skip.parse(response),{'freshness skip authenticates signature without checking time':r=>accepted(r,fault)&&r.sigVerified===true&&r.timestampValid===null});
   if(mode==='sigfuture')check(relaxed.parse(response),{'configured receive skew accepts independently future-dated Timestamp':r=>accepted(r,fault)&&r.sigVerified===true&&r.timestampValid===true});
   if(mode==='sig'){
    check(short.parse(response),{'configured max age bounds signed lifetime':stale});
    check(required.parse(response),{'freshness alone is not replay detection':r=>accepted(r,fault)&&r.timestampValid===true});
   }
  }
 }
}
