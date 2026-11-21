# Performance and retention gate

`make bench` builds native k6, verifies the runner profile in
[runner.json](runner.json), and compares three independent measurement passes
against [baseline.json](baseline.json). The normal quality gate runs
`make perf-budget-test` on any runner to check the comparison logic without
requiring this hardware.

The runner profile is the i7-12800H reference host with four pinned physical
performance cores and `GOMAXPROCS=4`. It pins the OS, kernel, governor, Go and
k6 versions, provider versions and synthetic leaf certificate. Run on AC power
with the selected cores and their siblings otherwise idle. The profiles
measure the generator, its metrics and SOAP processing in process. They do
not measure HTTP transport or peer performance.

[workload.json](workload.json) freezes the 2 KiB ASCII payload and the following
measurement windows. The four modes are plain SOAP, RSA-2048 signing, and
AES-256-GCM Body-content encryption in each protection order.

| Measurement | Warmup | Recorded window |
| --- | --- | --- |
| Native fixed VUs | First 5 iterations of each of 500 VUs | Next 100 iterations per VU, 50,000 measured |
| Native arrival rate | First 2 seconds | Next 10 seconds at 250 iterations/s and 100 preallocated VUs |
| Go operation benchmarks | Construct and exercise the fixture outside the timer | 300 ms calibrated window per operation, with allocation reporting |
| Go retained memory and goroutines | 250 build/parse pairs, then two forced collections | Five windows of 500 pairs with two collections after each window |

The native p95 values are the extension's own measured build and parse
samples. Throughput counts measured iterations per full scenario wall
second, including warmup. Generator CPU is user plus system time for the
k6 process, also reported per 1,000 measured iterations. The arrival-rate
profile requires zero drops on every run. A SOAP failure, incomplete sample
count, or interrupted run fails before comparison.

Go benchmarks measure build and parse independently, with the parse input
prepared outside the timer. Cold PEM initialization creates a fresh cache
and signing material for each operation. Retention holds the key material
and policy live while discarding the per-request results. It measures live
Go heap bytes and the process goroutine count, rather than RSS. Each trial
starts at its post-warmup sample and computes peak growth and the largest
growth across three consecutive increases. The gate compares the worst of
three retention trials. Latency, allocation, throughput and CPU comparisons
use the median of three fresh trials. The baseline stores all samples for
review alongside the numeric budgets.

## First baseline

Collected on 2026-11-21 on the pinned runner profile. The table shows medians
from three runs. CPU is process CPU seconds per 1,000 measured iterations.

| Mode / profile | Build p95 (ms) | Parse p95 (ms) | Measured iter/s | CPU s / 1,000 | Drops |
| --- | ---: | ---: | ---: | ---: | ---: |
| plain/fixed | 0.087 | 0.219 | 14413.4 | 0.280 | 0 |
| plain/arrival | 0.198 | 0.509 | 208.3 | 1.284 | 0 |
| signed/fixed | 132.075 | 38.393 | 1812.6 | 2.202 | 0 |
| signed/arrival | 2.387 | 1.166 | 208.4 | 3.812 | 0 |
| ste/fixed | 486.615 | 549.420 | 810.2 | 4.655 | 0 |
| ste/arrival | 1.722 | 2.485 | 208.3 | 4.986 | 0 |
| ets/fixed | 757.220 | 749.662 | 659.9 | 5.830 | 0 |
| ets/arrival | 2.549 | 3.428 | 208.3 | 5.734 | 0 |

Fixed-VU timing includes scheduler contention on four cores. In particular,
the signed parse p95 ranged from 1.12 to 57.0 ms, while the corresponding
arrival-rate values were 1.12 to 1.17 ms. The fixed-VU guard uses the observed
run envelope to tolerate that variance. These budgets are regression
checks for this workload and host.

For time, allocation and CPU ceilings, the budget is 120% of the highest
baseline trial, rounded up. Throughput floors are 80% of the lowest trial,
rounded down. Drops must stay at zero. Retention limits allow 16 KiB for
peak heap growth and growth across three consecutive increases. The largest
observed heap increases were 9,208 bytes peak and 7,320 bytes across three
increases. All modes showed zero goroutine growth, which is the limit.

The cold PEM init median was 109.2 µs, 28,712 B and 227 allocations per operation.
The baseline includes the full time and allocation samples for Go build and parse.

The nightly workflow runs trusted `main` only on a dedicated self-hosted
runner labeled `xk6-perf-i7-12800h`. It remains dormant until a matching
runner is registered and repository variable `XK6_PERF_RUNNER_ENABLED` is
set to `true`. A general hosted runner does not provide comparable CPU
measurements.

For an intentional rebaseline, collect a new candidate into a separate
file on the pinned runner:

```sh
make build-k6
PYTHONDONTWRITEBYTECODE=1 python3 test/perf/run.py --record /tmp/xk6-perf-candidate.json
```

Review the sample spread, confirm workload or runner changes, and update the
committed baseline and budgets in a dedicated change. Recording cannot
overwrite a file. The nightly comparison never records or refreshes its
own limits.
