#!/usr/bin/env python3
"""Build the original kernel packages offline in a verified shared worker."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import stat
import tempfile

SOURCE_DATE_EPOCH = 1754969284  # Debian linux 6.12.41-1 changelog timestamp.


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
    require(len(marker.get("identity_sha256", "")) == 64 and marker.get("packages"),
            "missing build-tools provenance")
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


def package_record(path, root):
    metadata = in_chroot(
        root, ["/usr/bin/dpkg-deb", "-f", "/build/packages/" + path.name,
               "Package", "Version", "Architecture"], check=True, capture_output=True, text=True,
    ).stdout
    values = dict(line.split(": ", 1) for line in metadata.splitlines())
    expected_arch = "all" if "common-sonic" in path.name else "amd64"
    require(values["Version"] == "6.12.41-1" and values["Architecture"] == expected_arch,
            "kernel package version or architecture differs from target: " + path.name)
    require(path.name == f'{values["Package"]}_{values["Version"]}_{values["Architecture"]}.deb',
            "kernel package filename differs from its control metadata")
    return {"name": path.name, "sha256": sha256(path), "size": path.stat().st_size,
            "package": values["Package"], "version": values["Version"],
            "architecture": values["Architecture"]}


def build(config):
    require(config.get("schema") == 1, "unsupported kernel action schema")
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
        packages = []
        for name in config["outputs"]:
            output = Path(name)
            package = dest / output.name
            require(package.is_file(), "kernel build omitted required package: " + package.name)
            packages.append(package_record(package, root))
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
            "packages": sorted(packages, key=lambda entry: entry["name"]),
        }
        Path(config["manifest"]).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print("SONIC_KERNEL_COMPILATION_COMPLETED", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--source-tree-sha256":
        print(checkout_source_identity(Path(sys.argv[2])))
    else:
        build(json.loads(Path(sys.argv[1]).read_text()))
