#!/usr/bin/env python3
"""Prove that a fresh consumer downloaded the real kernel action's outputs."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def records(path):
    decoder = json.JSONDecoder()
    content = path.read_text()
    offset = 0
    while offset < len(content):
        while offset < len(content) and content[offset].isspace():
            offset += 1
        if offset == len(content):
            return
        entry, offset = decoder.raw_decode(content, offset)
        yield entry


def kernel_record(directory):
    entries = [entry for entry in records(directory / "execution.json")
               if entry.get("mnemonic") == "SonicKernelBuild"]
    require(len(entries) == 1, "expected exactly one kernel action in " + str(directory))
    entry = entries[0]
    require(entry.get("exitCode") == 0 and entry.get("status") in ("", "SUCCESS"),
            "kernel action did not succeed")
    require(entry.get("cacheable") is True and entry.get("remoteCacheable") is True,
            "kernel action does not permit remote caching")
    return entry


def outputs(directory):
    found = {}
    for line in (directory / "output-paths.txt").read_text().splitlines():
        relative = PurePosixPath(line).relative_to("/work")
        require(".." not in relative.parts, "output escaped the build directory")
        path = (directory / str(relative)).resolve()
        path.relative_to(directory.resolve())
        require(path.is_file() and path.name not in found, "missing or duplicate kernel output")
        found[path.name] = path
    require(len(found) == 5 and "kernel-packages.json" in found, "expected four DEBs and their manifest")
    manifest = json.loads(found["kernel-packages.json"].read_text())
    require(len(manifest["packages"]) == 4, "manifest must describe four packages")
    for package in manifest["packages"]:
        path = found[package["name"]]
        require(sha256(path) == package["sha256"] and path.stat().st_size == package["size"],
                "kernel package bytes differ from manifest")
    return found


def verify(cold, hit, destination):
    require(cold.resolve() != hit.resolve(), "cache proof requires distinct Bazel output directories")
    first, second = kernel_record(cold), kernel_record(hit)
    require(first.get("cacheHit") is False, "producer did not execute kernel compilation")
    require(second.get("cacheHit") is True and second.get("runner") == "remote cache hit",
            "consumer did not get the kernel action from the remote cache")
    for field in ("commandArgs", "environmentVariables", "platform", "inputs", "listedOutputs"):
        require(first.get(field) == second.get(field), "producer and consumer kernel actions differ: " + field)
    for directory in (cold, hit):
        invocation = json.loads((directory / "invocation.json").read_text())
        require(invocation.get("disk_cache") is None, "cache proof must disable the disk cache")
    first_outputs, second_outputs = outputs(cold), outputs(hit)
    hashes = {name: sha256(path) for name, path in first_outputs.items()}
    require(hashes == {name: sha256(path) for name, path in second_outputs.items()},
            "cached packages differ from freshly compiled packages")
    destination.mkdir(parents=True, exist_ok=True)
    for name, path in second_outputs.items():
        shutil.copyfile(path, destination / name)
    receipt = {"schema": 1, "result": "passed", "cold_compiled": True,
               "consumer_kernel_runner": second["runner"], "consumer_kernel_cache_hit": True,
               "kernel_compilation_skipped": True, "outputs_sha256": hashes,
               "cold_metrics": first.get("metrics"), "hit_metrics": second.get("metrics")}
    (destination / "cache-proof.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cold", required=True, type=Path)
    parser.add_argument("--hit", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.cold, args.hit, args.artifacts), indent=2))


if __name__ == "__main__":
    main()
