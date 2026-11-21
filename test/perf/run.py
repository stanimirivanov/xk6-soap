"""Measure and compare the fixed, synthetic xk6-soap performance workloads."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODES = ("plain", "signed", "ste", "ets")
PROFILES = ("fixed", "arrival")
NATIVE_CASES = {f"{mode}/{profile}" for mode in MODES for profile in PROFILES}
NATIVE_BUDGETS = {
    "build_p95_ms": "max", "parse_p95_ms": "max", "cpu_seconds_per_1000_iterations": "max",
    "measured_per_second": "min", "drops": "max",
}
GO_BUDGETS = {metric: "max" for metric in ("ns_per_op", "bytes_per_op", "allocs_per_op")}
RETENTION_BUDGETS = {
    f"{metric}_{growth}_growth": "max"
    for metric in ("heap_bytes", "goroutines") for growth in ("peak", "monotonic")
}
REPEATS = 3
BENCHMARKS = {"ColdPEMKeyInit"} | {
    f"SOAP/{mode}/{phase}" for mode in MODES for phase in ("build", "parse")
}
BENCH_LINE = re.compile(
    r"^Benchmark(\S+)-4\s+\d+\s+([\d.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op$"
)


def finite_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def compare(observations, limits):
    failures = []
    for metric, bounds in limits.items():
        value = observations.get(metric)
        if not finite_number(value):
            failures.append(f"{metric}: missing or nonfinite measurement")
            continue
        if not isinstance(bounds, dict) or not bounds or any(
            bound not in {"min", "max"} or not finite_number(limit) or limit < 0
            for bound, limit in bounds.items()
        ):
            failures.append(f"{metric}: invalid budget bounds")
            continue
        for bound, limit in bounds.items():
            if (bound == "max" and value > limit) or (bound == "min" and value < limit):
                failures.append(f"{metric}: {value:.6g} exceeds {bound} budget {limit:.6g}")
    return failures


def check_budget_schema(budgets):
    shapes = {
        "go": (BENCHMARKS, GO_BUDGETS),
        "native": (NATIVE_CASES, NATIVE_BUDGETS),
        "retention": (set(MODES), RETENTION_BUDGETS),
    }
    if budgets.keys() != shapes.keys():
        raise ValueError("missing or unexpected performance budget section")
    for section, (cases, required) in shapes.items():
        if budgets[section].keys() != cases:
            raise ValueError(f"missing or unexpected {section} budget case")
        for case, limits in budgets[section].items():
            if limits.keys() != required.keys() or any(
                not isinstance(bounds, dict) or set(bounds) != {required[metric]}
                for metric, bounds in limits.items()
            ):
                raise ValueError(f"incomplete or unexpected {section}/{case} budget")


def retention_growth(values):
    """Largest growth over three consecutive increases, ignoring isolated jitter."""
    return max(
        (d - a for a, b, c, d in zip(values, values[1:], values[2:], values[3:]) if a < b < c < d),
        default=0,
    )


def command(args, timeout, **extra_env):
    env = {key: value for key, value in os.environ.items() if not key.startswith("K6_")}
    env.update(extra_env)
    output = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout)
    if output.returncode:
        raise ValueError(f"{args[0]} exited {output.returncode}\n{output.stdout[-4000:]}{output.stderr[-4000:]}")
    return output.stdout


def runner():
    expected = json.loads((HERE / "runner.json").read_text())
    cpu_model = next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name"))
    actual = {
        "architecture": platform.machine(),
        "cpu_model": cpu_model,
        "os": platform.freedesktop_os_release()["PRETTY_NAME"],
        "kernel": platform.release(),
    }
    for field, value in actual.items():
        if value != expected[field]:
            raise ValueError(f"{field}: expected {expected[field]!r}, found {value!r}")
    cpus = set(expected["cpus"])
    if not cpus <= os.sched_getaffinity(0):
        raise ValueError("configured performance CPUs are unavailable")
    for cpu in cpus:
        governor = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor").read_text().strip()
        if governor != expected["governor"]:
            raise ValueError(f"CPU {cpu}: unexpected governor {governor!r}")
    os.sched_setaffinity(0, cpus)
    os.environ["GOMAXPROCS"] = str(len(cpus))
    os.environ["GOGC"] = str(expected["go_gc_percent"])
    os.environ["GOMEMLIMIT"] = expected["go_memory_limit"]
    os.environ["GOFLAGS"] = "-mod=readonly"
    if command(["go", "version"], 15).split()[2] != f'go{expected["go"]}':
        raise ValueError("Go toolchain does not match runner profile")
    binary = str(ROOT / "bin/k6")
    version = command([binary, "version"], 15).splitlines()[0]
    if not version.startswith(f'k6 {expected["k6"]} (go{expected["go"]}, '):
        raise ValueError("k6 binary does not match runner profile")
    certificate = ROOT / "internal/wssec/testdata/signing-cert.pem"
    if hashlib.sha256(certificate.read_bytes()).hexdigest() != expected["fixture_cert_sha256"]:
        raise ValueError("benchmark fixture certificate changed")
    for module, version in expected["dependencies"].items():
        if command(["go", "list", "-m", "-f", "{{.Version}}", module], 15).strip() != version:
            raise ValueError(f"unexpected version for {module}")
    return expected


def go_measurements(workload):
    print("Measuring Go operations and cold PEM key initialization", flush=True)
    output = command(["go", "test", "./test/perf", "-run", "^$", "-bench", ".", "-benchmem",
                      f'-benchtime={workload["go_benchmark_window_ms"]}ms', f"-count={REPEATS}", "-cpu=4", "-timeout=3m"], 200)
    benchmarks = {}
    for line in output.splitlines():
        match = BENCH_LINE.fullmatch(line.rstrip())
        if match:
            name, elapsed, allocated, allocations = match.groups()
            benchmarks.setdefault(name, []).append({
                "ns_per_op": float(elapsed), "bytes_per_op": int(allocated), "allocs_per_op": int(allocations),
            })
    if benchmarks.keys() != BENCHMARKS or any(len(rows) != REPEATS for rows in benchmarks.values()):
        raise ValueError("incomplete Go benchmark output")
    print("Measuring post-GC retention windows", flush=True)
    output = command(["go", "test", "./test/perf", "-run", "^TestRetention$", "-v",
                      f"-count={REPEATS}", "-cpu=4", "-timeout=3m"], 200, XK6_PERF_RETENTION="1")
    retained = {}
    for line in output.splitlines():
        if line.startswith("RETENTION "):
            _, mode, samples = line.split(" ", 2)
            snapshot = json.loads(samples)
            if len(snapshot) != workload["retention"]["windows"] + 1:
                raise ValueError("incomplete retention series")
            retained.setdefault(mode, []).append(snapshot)
    if retained.keys() != set(MODES) or any(len(rows) != REPEATS for rows in retained.values()):
        raise ValueError("incomplete retention output")
    return benchmarks, retained


def native_measurements(workload):
    reports = {f"{mode}/{profile}": [] for mode in MODES for profile in PROFILES}
    fixed = workload["fixed"]
    arrival = workload["arrival"]
    with tempfile.TemporaryDirectory() as scratch:
        cpu_file = Path(scratch) / "cpu"
        for repeat in range(REPEATS):
            for mode in MODES:
                for profile in PROFILES:
                    print(f"Measuring k6 {mode}/{profile}, repeat {repeat + 1}/{REPEATS}", flush=True)
                    output = command(
                        ["/usr/bin/time", "-f", "%U %S", "-o", str(cpu_file),
                         str(ROOT / "bin/k6"), "run", "--quiet", "--no-usage-report", str(HERE / "profile.js")],
                        270, PERF_MODE=mode, PERF_PROFILE=profile,
                    )
                    row = json.loads(output)
                    if not all(finite_number(row.get(metric)) for metric in (
                        "measured", "iterations", "build_samples", "parse_samples",
                        "duration_ms", "build_p95_ms", "parse_p95_ms", "drops",
                    )):
                        raise ValueError("incomplete or nonfinite k6 measurements")
                    if not (0 < row["measured"] == row["build_samples"] == row["parse_samples"]) or row["drops"] != 0:
                        raise ValueError("incomplete k6 measurements or dropped iterations")
                    if profile == "fixed":
                        if row["measured"] != fixed["vus"] * fixed["measured_iterations_per_vu"]:
                            raise ValueError("unexpected fixed-VU sample count")
                        planned = fixed["vus"] * (fixed["warmup_iterations_per_vu"] + fixed["measured_iterations_per_vu"])
                        if row["iterations"] != planned:
                            raise ValueError("unexpected fixed-VU iteration count")
                    else:
                        planned = arrival["iterations_per_second"] * (arrival["warmup_seconds"] + arrival["measured_seconds"])
                        if abs(row["iterations"] - planned) > 1:
                            raise ValueError("unexpected arrival-rate iteration count")
                    if row["duration_ms"] <= 0:
                        raise ValueError("nonpositive k6 duration")
                    seconds = row["duration_ms"] / 1000
                    cpu_seconds = sum(map(float, cpu_file.read_text().split()))
                    row["process_cpu_seconds"] = cpu_seconds
                    row["cpu_seconds_per_1000_iterations"] = cpu_seconds / row["measured"] * 1000
                    row["measured_per_second"] = row["measured"] / seconds
                    reports[f"{mode}/{profile}"].append(row)
    return reports


def summarize(raw):
    summary = {}
    for section in ("go", "native"):
        summary[section] = {
            name: {metric: statistics.median(row[metric] for row in rows) for metric in rows[0]}
            for name, rows in raw[section].items()
        }
    summary["retention"] = {}
    for mode, runs in raw["retention"].items():
        group = {}
        for metric in ("heap_bytes", "goroutines"):
            values = [[sample[metric] for sample in window] for window in runs]
            group[f"{metric}_peak_growth"] = max(max(series) - series[0] for series in values)
            group[f"{metric}_monotonic_growth"] = max(retention_growth(series) for series in values)
        summary["retention"][mode] = group
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, help="write a new measurement artifact, never overwrite a baseline")
    args = parser.parse_args()
    if args.record and args.record.exists():
        parser.error("recording output already exists")
    try:
        rig = runner()
        workload = json.loads((HERE / "workload.json").read_text())
        baseline = None if args.record else json.loads((HERE / "baseline.json").read_text())
        if baseline and (baseline["runner"] != rig or baseline["workload"] != workload):
            raise ValueError("baseline runner or workload differs from the configured profile")
        if baseline is not None:
            check_budget_schema(baseline["budgets"])
        if workload["modes"] != list(MODES) or workload["repeats"] != REPEATS:
            raise ValueError("unexpected workload modes or repeat count")
        benchmarks, retained = go_measurements(workload)
        raw = {"runner": rig, "workload": workload, "go": benchmarks, "retention": retained, "native": native_measurements(workload)}
        data = summarize(raw)
        if args.record:
            with args.record.open("x") as target:
                json.dump({**raw, "summary": data}, target, indent=2, allow_nan=False)
                target.write("\n")
            return 0
        failures = []
        for section, cases in baseline["budgets"].items():
            for case, limits in cases.items():
                failures.extend(f"{section}/{case}/{failure}" for failure in compare(data[section].get(case, {}), limits))
        print(json.dumps(data, indent=2, allow_nan=False))
        if failures:
            raise ValueError("\n".join(failures))
        print("Performance and retention budgets passed.")
        return 0
    except (KeyError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(exc, file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
