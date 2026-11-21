"""Verify custom k6 build identity and assemble a local release rehearsal."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent.parent
K6 = "go.k6.io/k6/v2"
EXTENSION = "github.com/stanimirivanov/xk6-soap"
PLATFORM = {"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "-trimpath": "true"}
NOTICE_NAME = re.compile(r"^(?:LICENSE|LICENCE|COPYRIGHT|NOTICE|COPYING|PATENTS)(?:$|[._-])", re.I)
VERSION = "v0.1.0"


def go_output(*args):
    return subprocess.check_output(["go", *args], cwd=ROOT, text=True)


def runtime_module(info, path):
    matches = [module for module in info["Deps"] if module["Path"] == path]
    if len(matches) != 1:
        raise ValueError(f"expected one linked module for {path}")
    return matches[0]


def check_build(info, expected_go, expected_k6, source):
    if info["GoVersion"] != expected_go:
        raise ValueError(f"expected {expected_go}, built with {info['GoVersion']}")
    entry = runtime_module(info, K6)
    effective = entry.get("Replace") or entry
    if (effective["Path"], effective.get("Version")) != (K6, expected_k6):
        raise ValueError(f"expected {K6}@{expected_k6}, found {effective}")
    replacement = runtime_module(info, EXTENSION).get("Replace", {})
    local = replacement.get("Path")
    if not local or Path(local).resolve() != source or replacement.get("Version") not in (None, "(devel)"):
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


def dependency_notices(info):
    modules = []
    for entry in info["Deps"]:
        if entry["Path"] == EXTENSION:
            continue
        module = entry.get("Replace") or entry
        modules.append({key: module[key] for key in ("Path", "Version", "Sum")})
    modules.sort(key=lambda module: module["Path"])
    downloads = go_output("mod", "download", "-json", *(
        f"{module['Path']}@{module['Version']}" for module in modules
    )).strip()
    decoder = json.JSONDecoder()
    sources = {}
    while downloads:
        downloaded, end = decoder.raw_decode(downloads)
        sources[downloaded["Path"], downloaded["Version"]] = downloaded
        downloads = downloads[end:].lstrip()
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
        module["notices"] = [f"licenses/{path}/{file.name}" for file in notices]
        files.update((name, (file.read_bytes(), 0o644)) for name, file in zip(module["notices"], notices))
    goroot = Path(go_output("env", "GOROOT").strip())
    for name in ("LICENSE", "PATENTS"):
        files[f"licenses/go/{name}"] = ((goroot / name).read_bytes(), 0o644)
    return modules, files


def assemble(binary, repeat, output, info, expected_k6, xk6):
    settings = {item["Key"]: item["Value"] for item in info["Settings"]}
    if any(settings.get(key) != value for key, value in PLATFORM.items()):
        raise ValueError(f"expected fixed release platform and build settings: {PLATFORM}")
    if info != json.loads(go_output("version", "-m", "-json", str(repeat))):
        raise ValueError("repeat build has different Go build information")
    data = binary.read_bytes()
    if data != repeat.read_bytes():
        raise ValueError("repeat build did not produce identical bytes")
    modules, members = dependency_notices(info)
    members["k6"] = (data, 0o755)
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md", "RELEASE_NOTES.md"):
        members[name] = ((ROOT / name).read_bytes(), 0o644)
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    metadata = {
        "release": VERSION,
        "dry_run": True,
        "source_commit": source_commit,
        "source_dirty": bool(source_status),
        "go": info["GoVersion"],
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
    with archive.open("rb") as built:
        checksum = hashlib.file_digest(built, "sha256").hexdigest()
    (output / "SHA256SUMS").write_text(f"{checksum}  {archive.name}\n")
    print(f"Verified dry-run archive: {archive}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("go")
    parser.add_argument("k6")
    parser.add_argument("--repeat", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--xk6")
    args = parser.parse_args()
    if any((args.repeat, args.output, args.xk6)) and not all((args.repeat, args.output, args.xk6)):
        parser.error("--repeat, --output and --xk6 are required together")
    try:
        info = json.loads(go_output("version", "-m", "-json", str(args.binary.resolve())))
        check_build(info, args.go, args.k6, ROOT)
        if args.repeat:
            assemble(args.binary, args.repeat, args.output, info, args.k6, args.xk6)
        else:
            print(f"Verified {args.go} / k6 {args.k6} and the checkout extension")
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        parser.exit(1, f"release check failed: {exc}\n")


if __name__ == "__main__":
    main()
