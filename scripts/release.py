"""Verify custom k6 build identity and assemble a local release rehearsal."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
K6 = "go.k6.io/k6/v2"
EXTENSION = "github.com/stanimirivanov/xk6-soap"
PLATFORM = {"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "-trimpath": "true"}
NOTICE_NAME = re.compile(r"^(?:LICENSE|LICENCE|COPYRIGHT|NOTICE|COPYING|PATENTS)(?:$|[._-])", re.I)
VERSION = "v0.1.0"
PROMETHEUS = "buf.build/gen/go/prometheus/prometheus/protocolbuffers/go"
PROMETHEUS_VERSION = "v1.36.12-20261001224011-d7f6cfecf2b8.2"
PROMETHEUS_NOTICE = (
    "Prometheus generated Protocol Buffers code\n"
    "Copyright 2013, 2016, 2017 and 2024 Prometheus Team\n"
    "Licensed under the Apache License, Version 2.0. See LICENSE.\n"
)


def go_output(*args, cwd=ROOT):
    return subprocess.check_output(["go", *args], cwd=cwd, text=True)


def runtime_module(info, path):
    matches = [module for module in info["Deps"] if module["Path"] == path]
    if len(matches) != 1:
        raise ValueError(f"expected one linked module for {path}")
    return matches[0]


def check_build(info, expected_go, expected_k6, source, build_dir=ROOT):
    if info["GoVersion"] != expected_go:
        raise ValueError(f"expected {expected_go}, built with {info['GoVersion']}")
    entry = runtime_module(info, K6)
    effective = entry.get("Replace") or entry
    if (effective["Path"], effective.get("Version")) != (K6, expected_k6):
        raise ValueError(f"expected {K6}@{expected_k6}, found {effective}")
    replacement = runtime_module(info, EXTENSION).get("Replace", {})
    local = replacement.get("Path")
    if not local or (build_dir / local).resolve() != source or replacement.get("Version") not in (None, "(devel)"):
        raise ValueError("binary does not link the checkout of xk6-soap")


def write_archive(path, members):
    with path.open("xb") as target, gzip.GzipFile(filename="", mode="wb", fileobj=target, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, (data, mode) in sorted(members.items()):
                entry = tarfile.TarInfo(name)
                entry.mode = mode
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))


def verify_archive(path, members):
    with tarfile.open(path, mode="r:gz") as archive:
        if archive.getnames() != sorted(members):
            raise ValueError("release archive members do not match the manifest")
        for entry in archive:
            data, mode = members[entry.name]
            if not entry.isfile() or entry.mode != mode or archive.extractfile(entry).read() != data:
                raise ValueError(f"release archive member mismatch: {entry.name}")


def decode_downloads(output):
    decoder = json.JSONDecoder()
    remaining = output.strip()
    while remaining:
        module, end = decoder.raw_decode(remaining)
        if module.get("Error"):
            raise ValueError(f"module download failed: {module['Path']}: {module['Error']}")
        yield module
        remaining = remaining[end:].lstrip()


def linked_modules(info):
    modules = []
    for entry in info["Deps"]:
        if entry["Path"] == EXTENSION:
            continue
        module = entry.get("Replace") or entry
        modules.append({key: module[key] for key in ("Path", "Version", "Sum")})
    return sorted(modules, key=lambda module: module["Path"])


def dependency_notices(modules, downloads):
    sources = {(module["Path"], module["Version"]): module for module in downloads}
    files = {}
    for module in modules:
        path = module["Path"]
        downloaded = sources[path, module["Version"]]
        if downloaded.get("Sum") != module["Sum"]:
            raise ValueError(f"source checksum differs from binary build info for {path}")
        notices = sorted(
            file for file in Path(downloaded["Dir"]).iterdir()
            if file.is_file() and NOTICE_NAME.match(file.name)
        )
        prefix = f"licenses/{path}/"
        notice_files = {file.name: file.read_bytes() for file in notices}
        if not notice_files and (path, module["Version"]) == (PROMETHEUS, PROMETHEUS_VERSION):
            notice_files = {
                "LICENSE": (ROOT / "LICENSE").read_bytes(),
                "NOTICE": PROMETHEUS_NOTICE.encode(),
            }
        if not notice_files:
            raise ValueError(f"review missing root notices for {path}@{module['Version']}")
        module["notices"] = [prefix + name for name in sorted(notice_files)]
        files.update((prefix + name, (data, 0o644)) for name, data in notice_files.items())
    goroot = Path(go_output("env", "GOROOT").strip())
    for name in ("LICENSE", "PATENTS"):
        files[f"licenses/go/{name}"] = ((goroot / name).read_bytes(), 0o644)
    return modules, files


def portable_go_mod(text):
    directives = re.findall(r"^\s*replace[ \t].*$", text, re.M)
    expected = f"replace {EXTENSION} => "
    if len(directives) != 1 or not directives[0].lstrip().startswith(expected):
        raise ValueError("expected xk6's single extension replacement")
    return text.replace(directives[0].lstrip(), expected + "../extension", 1)


def source_members(commit, driver, downloads):
    snapshot = subprocess.check_output(["git", "archive", commit], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(snapshot)) as archive:
        members = {}
        for entry in archive:
            if entry.isdir():
                continue
            if not entry.isfile():
                raise ValueError(f"unexpected non-file in Git source: {entry.name}")
            members[f"extension/{entry.name}"] = (archive.extractfile(entry).read(), entry.mode)

    for file in sorted(driver.glob("*.go")) + [driver / "go.mod", driver / "go.sum"]:
        data = file.read_bytes()
        if file.name == "go.mod":
            data = portable_go_mod(data.decode()).encode()
        members[f"build/{file.name}"] = (data, 0o644)

    cache = Path(go_output("env", "GOMODCACHE").strip()) / "cache" / "download"
    for module in downloads:
        for key in ("Info", "GoMod", "Zip"):
            file = Path(module[key])
            relative = file.relative_to(cache)
            members[f"proxy/{relative.as_posix()}"] = (file.read_bytes(), 0o644)
    members["rebuild.sh"] = ((ROOT / "scripts/release-rebuild.sh").read_bytes(), 0o755)
    return members


def rebuild(archive_path, destination, binary):
    destination.mkdir()
    with tarfile.open(archive_path, mode="r:gz") as archive:
        archive.extractall(destination, filter="data")
    go_bin = Path(go_output("env", "GOROOT").strip()) / "bin"
    env = {**os.environ, "PATH": f"{go_bin}{os.pathsep}{os.environ['PATH']}"}
    subprocess.run(["sh", str(destination / "rebuild.sh"), str(binary)], env=env, check=True)
    return json.loads(go_output("version", "-m", "-json", str(binary)))


def file_sha256(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def assemble(output, driver, info, expected_go, expected_k6, xk6, govulncheck):
    settings = {item["Key"]: item["Value"] for item in info["Settings"]}
    if any(settings.get(key) != value for key, value in PLATFORM.items()):
        raise ValueError(f"expected fixed release platform and build settings: {PLATFORM}")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True):
        raise ValueError("source must remain clean throughout the rehearsal")
    downloads = list(decode_downloads(go_output("mod", "download", "-json", cwd=driver)))
    original_modules = linked_modules(info)
    modules, members = dependency_notices(original_modules, downloads)

    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        source_archive = work / f"xk6-soap-{VERSION}.source.dry-run.tar.gz"
        source = source_members(commit, driver, downloads)
        write_archive(source_archive, source)
        verify_archive(source_archive, source)
        del source

        binary = work / "k6"
        kit = work / "source"
        built = rebuild(source_archive, kit, binary)
        check_build(built, expected_go, expected_k6, kit / "extension", kit / "build")
        if linked_modules(built) != linked_modules(info) or built["Settings"] != info["Settings"]:
            raise ValueError("source archive rebuild changed the xk6 dependency graph or build settings")
        repeated = work / "k6-repeat"
        rebuild(source_archive, work / "repeat", repeated)
        data = binary.read_bytes()
        if data != repeated.read_bytes():
            raise ValueError("source archive rebuild did not produce identical bytes")
        subprocess.run([str(govulncheck), "-mode=binary", str(binary)], cwd=ROOT, check=True)
        output.mkdir()
        source_digest = file_sha256(source_archive)
        shutil.copyfile(source_archive, output / source_archive.name)

    members["k6"] = (data, 0o755)
    members["LICENSE"] = members[f"licenses/{K6}/LICENSE.md"]
    members["LICENSE.xk6-soap"] = ((ROOT / "LICENSE").read_bytes(), 0o644)
    for name in ("THIRD_PARTY_NOTICES.md", "RELEASE_NOTES.md"):
        members[name] = ((ROOT / name).read_bytes(), 0o644)
    metadata = {
        "release": VERSION,
        "dry_run": True,
        "source_commit": commit,
        "source_dirty": False,
        "source_archive": source_archive.name,
        "source_sha256": source_digest,
        "offline_source_verified": True,
        "go": expected_go,
        "k6": expected_k6,
        "xk6": xk6,
        "platform": PLATFORM,
        "binary_sha256": hashlib.sha256(data).hexdigest(),
        "repeated_binary_match": True,
        "modules": modules,
    }
    manifest = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode()
    members["metadata.json"] = (manifest, 0o644)
    output.mkdir()
    archive = output / f"xk6-soap-{VERSION}-linux-amd64.dry-run.tar.gz"
    write_archive(archive, members)
    verify_archive(archive, members)
    (output / "metadata.json").write_bytes(manifest)
    (output / "SHA256SUMS").write_text(
        f"{file_sha256(archive)}  {archive.name}\n{source_digest}  {source_archive.name}\n"
    )
    print(f"Verified dry-run archive: {archive}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("go")
    parser.add_argument("k6")
    parser.add_argument("--driver", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--xk6")
    parser.add_argument("--govulncheck", type=Path)
    args = parser.parse_args()
    package_args = (args.driver, args.output, args.xk6, args.govulncheck)
    if any(package_args) and not all(package_args):
        parser.error("--driver, --output, --xk6 and --govulncheck are required together")
    try:
        info = json.loads(go_output("version", "-m", "-json", str(args.binary.resolve())))
        check_build(info, args.go, args.k6, ROOT)
        if args.driver:
            assemble(args.output, args.driver, info, args.go, args.k6, args.xk6, args.govulncheck)
        else:
            print(f"Verified {args.go} / k6 {args.k6} and the checkout extension")
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        parser.exit(1, f"release check failed: {exc}\n")


if __name__ == "__main__":
    main()
