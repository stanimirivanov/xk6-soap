import {Client} from 'k6/x/soap';
import http from 'k6/http';
import {check} from 'k6';
const client=new Client({url:__ENV.SOAP_METRICS_URL});
// Init-context misuse must not emit samples or wait for an output consumer.
for(const call of [()=>client.build('Echo','<Echo/>'),()=>client.parse({status:0})]){
 try{call();throw new Error('init call accepted');}catch(e){if(e.code!=='SOAP_EXECUTION_ONLY')throw e;}
}
export const options={vus:1,iterations:1,summaryTrendStats:['count','min','max'],tags:{user_tag:'provided'},thresholds:{
 checks:['rate==1'],
 soap_build_duration:['min>=0'],soap_parse_duration:['min>=0'],soap_reqs:['count==6'],
 'soap_reqs{soap_version:1.1,security_mode:plain}':['count==6'],
 soap_req_failed:[__ENV.SOAP_METRICS_FAIL==='1'?'rate==0':'rate<0.7'],
 http_req_failed:['rate==0'],
}};
export default function(){
 const request=client.build('Echo','<Echo>METRIC_PRIVATE_SENTINEL</Echo>');
 try{client.build('Echo','invalid')}catch(e){}
 client.build('Echo','<Echo>build-only</Echo>');
 client.parse({status:200,body:request.body});client.parse({status:200,body:request.body});
 const response=http.get(__ENV.SOAP_METRICS_URL,{timeout:'2s'});
 const fault=client.parse(response);
 check(fault,{'HTTP 200 SOAP fault retains SOAP failure':p=>response.status===200&&!p.ok&&p.error.code==='SOAP_FAULT'});
 client.parse({status:0});try{client.parse()}catch(e){}
 const unavailable=client.parse({status:204,body:''});unavailable.xpath('string(.)');
}
export function handleSummary(data){
 const result={};
 for(const name of ['soap_build_duration','soap_parse_duration','soap_reqs','soap_req_failed','http_req_failed'])result[name]=data.metrics[name];
 return {stdout:'SOAP_METRICS_SUMMARY='+JSON.stringify(result)+'\n'};
}
