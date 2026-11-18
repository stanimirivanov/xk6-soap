import { Client } from 'k6/x/soap';
import { check } from 'k6';

export const options = { vus: 2, iterations: 2, thresholds: { checks: ['rate==1'] } };
const client = new Client();
function rejects(fn, code) {
  try { fn(); } catch (error) { return String(error).includes(code); }
  return false;
}
export default function () {
  check(client, {
    'build explicitly unavailable': (c) => rejects(() => c.build(), 'SOAP_NOT_IMPLEMENTED'),
    'parse explicitly unavailable': (c) => rejects(() => c.parse(), 'SOAP_NOT_IMPLEMENTED'),
    'constructor is init-only': () => rejects(() => new Client(), 'SOAP_INIT_ONLY'),
    'negative control': () => __ENV.SOAP_SMOKE_FORCE_FAILURE !== '1',
  });
}
