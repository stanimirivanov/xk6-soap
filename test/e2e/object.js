import {Client} from 'k6/x/soap';
import http from 'k6/http';
import {check} from 'k6';
const clients=['1.1','1.2'].map(soapVersion=>new Client({url:__ENV.SOAP_FIXTURE_URL+'/echo',soapVersion,namespace:'urn:object',debug:true}));
export const options={vus:1,iterations:1,thresholds:{checks:['rate==1'],soap_req_failed:['rate==0']}};
export default function(){
 for(const client of clients){
  const request=client.build('Echo',{'@id':'a&"',z:'OBJECT_PRIVATE_SENTINEL',a:['one','two'],item:{'@flag':true,'#text':'<&😀'},empty:{},none:[]});
  check(request,{'ordered object mapping reaches native k6':r=>r.body.includes('<Echo xmlns="urn:object" id="a&amp;&#34;"><z>OBJECT_PRIVATE_SENTINEL</z><a>one</a><a>two</a>')});
  const response=http.post(request.url,request.body,{headers:request.headers,timeout:'2s',redirects:0});
  const parsed=client.parse(response);
  check(parsed,{
   'HTTP echo accepts object envelope':p=>p.ok&&response.body===request.body,
   'children inherit namespace and attributes stay unqualified':p=>p.xpath('string(//m:item/@flag)',{m:'urn:object'}).value==='true'&&p.xpath('string(//m:Echo/@id)',{m:'urn:object'}).value==='a&"',
   'text and array order survive XML escaping':p=>p.xpath('string(//m:item)',{m:'urn:object'}).value==='<&😀'&&p.xpath('//m:a',{m:'urn:object'}).value.join(',')==='one,two',
  });
 }
}
