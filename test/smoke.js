import { Client } from 'k6/x/soap';
import { check } from 'k6';

export const options = { vus: 2, iterations: 2, thresholds: { checks: ['rate==1'] } };
const client = new Client({url:'http://example.test'});
function rejects(fn, code) {
  try { fn(); } catch (error) { return String(error).includes(code); }
  return false;
}
export default function () {
  check(client, {
    'build requires valid arguments': (c) => rejects(() => c.build(), 'INVALID_ARGUMENT'),
    'parse requires a response': (c) => rejects(() => c.parse(), 'INVALID_ARGUMENT'),
    'constructor is init-only': () => rejects(() => new Client(), 'SOAP_INIT_ONLY'),
    'negative control': () => __ENV.SOAP_SMOKE_FORCE_FAILURE !== '1',
  });
}
