import { Client } from 'k6/x/soap';
import exec from 'k6/execution';
import { Counter } from 'k6/metrics';

const workload = JSON.parse(open("./workload.json"));
const mode = __ENV.PERF_MODE;
const profile = __ENV.PERF_PROFILE;
const arrival = profile === 'arrival';
const fixed = profile === 'fixed';
if (!(arrival || fixed) || !workload.modes.includes(mode)) {
  throw new Error('unsupported performance profile or mode');
}

const cert = open('../../internal/wssec/testdata/signing-cert.pem', 'b');
const key = open('../../internal/wssec/testdata/signing-key.pem', 'b');
const encrypted = mode === 'ste' || mode === 'ets';
const order = mode === 'ets' ? 'encrypt-then-sign' : 'sign-then-encrypt';
const client = new Client({
  url: 'https://example.invalid/soap',
  ...(mode === 'plain' ? {} : {
    keys: {signing:{cert,key}, trust:[cert], ...(encrypted ? {decryption:{cert,key},recipient:{cert}} : {})},
    security: {sign:{}, ...(encrypted ? {encrypt:{}, order, verify:{order, requireEncryption:true}} : {})},
  }),
});
const payload = '<Echo>' + 'x'.repeat(workload.payload_bytes - '<Echo></Echo>'.length) + '</Echo>';
const measured = new Counter('perf_measured');
const buildMetric = 'soap_build_duration{phase:measured}';
const parseMetric = 'soap_parse_duration{phase:measured}';
const rate = workload.arrival.iterations_per_second;
const fixedConfig = workload.fixed;
const arrivalConfig = workload.arrival;
const fixedMeasured = fixedConfig.vus * fixedConfig.measured_iterations_per_vu;

export const options = {
  scenarios: {
    workload: arrival
      ? {executor:'constant-arrival-rate', rate, timeUnit:'1s', duration:(arrivalConfig.warmup_seconds + arrivalConfig.measured_seconds) + 's', preAllocatedVUs:arrivalConfig.vus, maxVUs:arrivalConfig.vus, gracefulStop:arrivalConfig.graceful_stop_seconds + 's'}
      : {executor:'per-vu-iterations', vus:fixedConfig.vus, iterations:fixedConfig.warmup_iterations_per_vu + fixedConfig.measured_iterations_per_vu, maxDuration:fixedConfig.max_duration_seconds + 's', gracefulStop:'0s'},
  },
  summaryTrendStats: ['p(95)', 'count'],
  systemTags: ['scenario'],
  thresholds: {
    [buildMetric]: ['p(95)>=0'],
    [parseMetric]: ['p(95)>=0'],
    perf_measured: [arrival ? 'count>=' + (rate * arrivalConfig.measured_seconds - 5) : 'count==' + fixedMeasured],
    soap_req_failed: ['rate==0'],
    ...(arrival ? {dropped_iterations:['count==0']} : {}),
  },
};

export default function () {
  const warming = arrival ? Date.now() - exec.scenario.startTime < arrivalConfig.warmup_seconds * 1000 : exec.vu.iterationInScenario < fixedConfig.warmup_iterations_per_vu;
  exec.vu.metrics.tags.phase = warming ? 'warmup' : 'measured';
  const request = client.build('Echo', payload);
  const response = client.parse({status:200,body:request.body});
  if (!response.ok) exec.test.abort('performance fixture failed SOAP acceptance');
  if (!warming) measured.add(1);
}

export function handleSummary(data) {
  const metrics = data.metrics;
  return {
    stdout: JSON.stringify({
      measured: metrics.perf_measured.values.count,
      iterations: metrics.iterations.values.count,
      duration_ms: data.state.testRunDurationMs,
      build_p95_ms: metrics[buildMetric].values['p(95)'],
      parse_p95_ms: metrics[parseMetric].values['p(95)'],
      build_samples: metrics[buildMetric].values.count,
      parse_samples: metrics[parseMetric].values.count,
      drops: metrics.dropped_iterations?.values.count ?? 0,
    }) + '\n',
  };
}
