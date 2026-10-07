#!/usr/bin/env python3
"""Build the original kernel packages offline in a verified shared worker."""

import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import stat
import tempfile

SOURCE_DATE_EPOCH = 1754969284  # Debian linux 6.12.41-1 changelog timestamp.
PACKAGE_NAMES = {
    "linux-headers-6.12.41+deb13-common-sonic_6.12.41-1_all.deb",
    "linux-headers-6.12.41+deb13-sonic-amd64_6.12.41-1_amd64.deb",
    "linux-image-6.12.41+deb13-sonic-amd64-unsigned_6.12.41-1_amd64.deb",
    "linux-kbuild-6.12.41+deb13_6.12.41-1_amd64.deb",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_identity(runtime):
    marker = json.loads((runtime / "kernel-runtime.json").read_text())
    require(marker.get("schema_version") == 1 and marker.get("kind") == "debian-build-tools",
            "unsupported declared build-tools runtime")
    require(marker.get("architecture") == "amd64", "kernel tools must execute on AMD64")
    inputs = marker.get("input_sha256")
    require(isinstance(inputs, list) and inputs
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in inputs)
            and inputs == sorted(inputs)
            and isinstance(marker.get("packages"), dict) and marker["packages"]
            and all(isinstance(name, str) and isinstance(version, str) and name and version
                    for name, version in marker["packages"].items()),
            "missing build-tools provenance")
    expected = hashlib.sha256(json.dumps({"architecture": "amd64", "inputs": inputs},
                                         sort_keys=True).encode()).hexdigest()
    require(marker.get("identity_sha256") == expected, "build-tools identity digest differs from its inputs")
    return marker


def in_chroot(root, command, **kwargs):
    def enter():
        os.chroot(root)
        os.chdir("/build/source")
    return subprocess.run(command, preexec_fn=enter, **kwargs)


def source_inventory(sources, destination=None):
    inventory = []
    seen = set()
    for source in sorted(sources, key=lambda entry: entry["name"]):
        name = source["name"]
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts and name not in seen,
                "unsafe or duplicate kernel input path: " + name)
        seen.add(name)
        path = Path(source["path"])
        require(path.is_file(), "missing kernel input: " + str(path))
        # Bazel materializes source inputs as symlinks in the sandbox. Copy their
        # contents and executable bit, never a link to the original checkout.
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        inventory.append({"name": name, "mode": mode, "sha256": sha256(path)})
        if destination is not None:
            output = destination / name
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, output)
            output.chmod(mode)
            os.utime(output, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))
    return inventory


def source_tree_sha256(inventory):
    return hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()


def checkout_source_identity(checkout):
    files = [checkout / name for name in ("Makefile", "manage-config")]
    for directory in ("config.local", "patches-debian", "patches-sonic"):
        files.extend(path for path in (checkout / directory).rglob("*") if path.is_file())
    return source_tree_sha256(source_inventory([
        {"name": str(path.relative_to(checkout)), "path": str(path)} for path in files
    ]))


def package_record(path, root, *, exported=True):
    require(path.is_file() and not path.is_symlink(), "kernel package must be a regular file: " + str(path))
    relative = path.resolve().relative_to(root.resolve())
    metadata = in_chroot(
        root, ["/usr/bin/dpkg-deb", "-f", "/" + str(relative),
               "Package", "Version", "Architecture"], check=True, capture_output=True, text=True,
    ).stdout
    values = dict(line.split(": ", 1) for line in metadata.splitlines())
    expected_arch = "all" if "common-sonic" in path.name else "amd64"
    require(values["Version"] == "6.12.41-1" and values["Architecture"] in ("all", "amd64")
            and (not exported or values["Architecture"] == expected_arch),
            "kernel package version or architecture differs from target: " + path.name)
    require(path.name == f'{values["Package"]}_{values["Version"]}_{values["Architecture"]}.deb',
            "kernel package filename differs from its control metadata")
    return {"name": path.name, "sha256": sha256(path), "size": path.stat().st_size,
            "package": values["Package"], "version": values["Version"],
            "architecture": values["Architecture"]}


def created_package_records(root, source, destination):
    """Record every DEB left by dpkg-buildpackage before private scratch cleanup."""
    records = {}
    # The existing Make recipe builds DEBs in its source directory and moves
    # the four exported files to DEST. Both directories start empty here.
    for directory in (source, destination):
        for path in sorted(directory.glob("*.deb")):
            record = package_record(path, root, exported=path.name in PACKAGE_NAMES)
            record["exported"] = path.name in PACKAGE_NAMES
            if path.name in records:
                require(records[path.name] == record, "duplicate kernel package bytes differ: " + path.name)
            records[path.name] = record
    require(PACKAGE_NAMES <= records.keys(), "kernel build omitted required packages from its created inventory")
    return [records[name] for name in sorted(records)]


def validate_outputs(config):
    outputs = config.get("outputs")
    require(isinstance(outputs, list) and len(outputs) == len(PACKAGE_NAMES)
            and all(isinstance(name, str) and name for name in outputs)
            and {Path(name).name for name in outputs} == PACKAGE_NAMES,
            "kernel action must declare exactly the four supported packages")
    require(isinstance(config.get("manifest"), str)
            and Path(config["manifest"]).name == "kernel-packages.json",
            "kernel action must declare kernel-packages.json")


def build(config):
    require(config.get("schema") == 1, "unsupported kernel action schema")
    validate_outputs(config)
    require(os.geteuid() == 0, "kernel action requires root in its disposable worker for chroot")
    runtime = Path(config["build_tools"])
    marker = runtime_identity(runtime)
    # The tool tree is a declared input. Copy it before building so no action
    # mutates the shared runtime. Chroot makes Kbuild's /build path independent
    # of the Bazel output base, checkout path, and host tool installation.
    with tempfile.TemporaryDirectory(prefix="kernel-action-", dir=Path.cwd()) as temporary:
        root = Path(temporary) / "root"
        shutil.copytree(runtime, root, symlinks=True)
        source = root / "build/source"
        source.mkdir(parents=True)
        archives = root / "build/archives"
        archives.mkdir()
        dest = root / "build/packages"
        dest.mkdir()
        (root / "build/home").mkdir()
        (root / "build/tmp").mkdir()
        (root / "dev").mkdir(exist_ok=True)
        for name, minor in (("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)):
            os.mknod(root / "dev" / name, stat.S_IFCHR | 0o666, os.makedev(1, minor))
        inventory = source_inventory(config["sources"], source)
        archive_records = []
        for archive in config["archives"]:
            require(Path(archive["name"]).name == archive["name"], "unsafe archive filename")
            require(sha256(archive["path"]) == archive["sha256"], "kernel archive checksum mismatch")
            shutil.copyfile(archive["path"], archives / archive["name"])
            archive_records.append({"name": archive["name"], "sha256": archive["sha256"]})
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/build/home", "TMPDIR": "/build/tmp",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH), "PYTHONHASHSEED": "0",
            "KBUILD_BUILD_USER": "sonic", "KBUILD_BUILD_HOST": "kernel-builder",
            "KBUILD_BUILD_TIMESTAMP": "@" + str(SOURCE_DATE_EPOCH),
            "KBUILD_BUILD_VERSION": "1", "DEB_BUILD_OPTIONS": "parallel=4",
            "INCLUDE_EXTERNAL_PATCHES": "n",
        }
        print("SONIC_KERNEL_COMPILATION_STARTED", flush=True)
        in_chroot(root, [
            "/usr/bin/make", "-f", "Makefile", "DEST=/build/packages",
            "KERNEL_SOURCE_DIR=/build/archives", "NON_UP_DIR=/build/non-upstream",
            "CONFIGURED_ARCH=amd64", "CONFIGURED_PLATFORM=vs", "CROSS_BUILD_ENVIRON=n",
            "KERNEL_VERSION=6.12.41", "KERNEL_ABISUFFIX=+deb13", "KERNEL_SUBVERSION=1",
            "KERNEL_FEATURESET=sonic", "KVERSION=6.12.41+deb13-sonic-amd64",
            "SECURE_UPGRADE_MODE=no_sign", "SECURE_UPGRADE_KERNEL_CAFILE=",
            "SONIC_CONFIG_MAKE_JOBS=4", "ADDITIONAL_BUILD_PROFILES=",
        ], env=environment, check=True)
        print("SONIC_KERNEL_PACKAGE_INVENTORY_STARTED", flush=True)
        created_packages = created_package_records(root, source, dest)
        print("SONIC_KERNEL_CREATED_PACKAGES " + json.dumps(created_packages, sort_keys=True), flush=True)
        created_by_name = {record["name"]: record for record in created_packages}
        packages = []
        for name in config["outputs"]:
            output = Path(name)
            package = dest / output.name
            require(package.is_file(), "kernel build omitted required package: " + package.name)
            record = dict(created_by_name[output.name])
            record.pop("exported")
            packages.append(record)
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(package, output)
        manifest = {
            "schema": 1, "architecture": "amd64", "platform": "vs",
            "kernel_version": "6.12.41", "kernel_abi": "6.12.41+deb13-sonic-amd64",
            "package_version": "6.12.41-1", "signing": "unsigned",
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "source_archives": sorted(archive_records, key=lambda entry: entry["name"]),
            "source_tree_sha256": source_tree_sha256(inventory),
            "source_files": inventory,
            "build_tools": marker,
            "created_packages": created_packages,
            "packages": sorted(packages, key=lambda entry: entry["name"]),
        }
        Path(config["manifest"]).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print("SONIC_KERNEL_COMPILATION_COMPLETED", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--source-tree-sha256":
        print(checkout_source_identity(Path(sys.argv[2])))
    else:
        build(json.loads(Path(sys.argv[1]).read_text()))
