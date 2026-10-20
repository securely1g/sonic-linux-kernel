#!/usr/bin/env python3
"""Stage Debian's compiled kernel outputs as installed runtime/debug TARs.

Debian build_image already separates signed stripped modules from their original
unsigned debug ELFs. Preserve those bytes: changing a signed module to add a GNU
debuglink would invalidate its signature. GDB can instead resolve detached
symbols through the matching GNU build IDs and conventional debug paths.
"""

import hashlib
import json
import lzma
import os
from pathlib import Path
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile

ABI = "6.12.41+deb13-sonic-amd64"
ABINAME = "6.12.41+deb13"
EPOCH = 1754969284
COMMON_HEADERS = "linux-headers-" + ABINAME + "-common-sonic"
ARCH_HEADERS = "linux-headers-" + ABI
KBUILD = "linux-kbuild-" + ABINAME


def require(condition, message):
    if not condition:
        raise ValueError(message)


def copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        destination.symlink_to(os.readlink(source))
    elif source.is_dir():
        shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)
    else:
        shutil.copy2(source, destination)


def link(target, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.symlink_to(target)


def elf_info(path):
    result = subprocess.run(["/usr/bin/readelf", "-h", "-n", "-SW", str(path)],
                            capture_output=True, text=True, check=True).stdout
    match = re.search(r"Build ID: ([0-9a-f]+)", result)
    require(match is not None, "ELF lacks a GNU build ID: " + str(path))
    require("ELF64" in result and "Advanced Micro Devices X86-64" in result,
            "ELF is not an AMD64 kernel artifact: " + str(path))
    return match[1], ".debug_info" in result


def build_id_link(debug_root, debug_file, build_id):
    destination = debug_root / "usr/lib/debug/.build-id" / build_id[:2] / (build_id[2:] + ".debug")
    if destination.is_symlink():
        require(destination.resolve().read_bytes() == debug_file.read_bytes(),
                "different debug files share a build ID")
    else:
        link(os.path.relpath(debug_file, destination.parent), destination)


def validate_debug_pairs(source, runtime, debug):
    kernel = debug / ("usr/lib/debug/boot/vmlinux-" + ABI)
    kernel_id, has_debug = elf_info(kernel)
    require(has_debug, "kernel vmlinux is missing DWARF debug information")
    with tempfile.TemporaryDirectory(prefix="kernel-debug-check-") as temporary:
        temporary = Path(temporary)
        embedded = temporary / "vmlinux"
        with embedded.open("wb") as out:
            subprocess.run(["/bin/sh", str(source / "scripts/extract-vmlinux"),
                            str(runtime / ("boot/vmlinuz-" + ABI))], stdout=out, check=True)
        require(elf_info(embedded)[0] == kernel_id, "boot image and debug vmlinux build IDs differ")
        build_id_link(debug, kernel, kernel_id)
        modules = runtime / "usr/lib/modules" / ABI
        debug_modules = debug / "usr/lib/debug/lib/modules" / ABI
        runtime_modules = sorted(list(modules.rglob("*.ko")) + list(modules.rglob("*.ko.xz")))
        require(runtime_modules, "runtime contains no kernel modules")
        pairs = []
        for deployed in runtime_modules:
            relative = deployed.relative_to(modules)
            if deployed.suffix == ".xz":
                module = temporary / "module.ko"
                with lzma.open(deployed, "rb") as src, module.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                relative = relative.with_suffix("")
            else:
                module = deployed
            detached = debug_modules / relative
            require(detached.is_file(), "runtime module has no matching debug module: " + str(relative))
            runtime_id, runtime_debug = elf_info(module)
            debug_id, has_debug = elf_info(detached)
            require(runtime_id == debug_id and has_debug and not runtime_debug,
                    "runtime/debug module build ID or DWARF mismatch: " + str(relative))
            require(b"~Module signature appended~" in module.read_bytes(),
                    "runtime kernel module lost its Debian-generated signature: " + str(relative))
            require(b"~Module signature appended~" not in detached.read_bytes(),
                    "debug module unexpectedly contains a signature")
            build_id_link(debug, detached, debug_id)
            pairs.append({"module": str(relative), "build_id": debug_id})
        require(len(list(debug_modules.rglob("*.ko"))) == len(pairs),
                "runtime and debug module inventories differ")
    return {"kernel_build_id": kernel_id, "module_count": len(pairs),
            "module_build_ids_sha256": hashlib.sha256(json.dumps(pairs, sort_keys=True).encode()).hexdigest()}


def stage_headers(source, build, development):
    """Preserve the header layout documented in Debian rules.real.

    Copying these installation inputs is independent of Debian's binary_headers
    targets, which would also assemble packages. Kbuild tools are installed by
    stage-kernel.mk using Debian's own install recipes.
    """
    common = development / "usr/src" / COMMON_HEADERS
    arch = development / "usr/src" / ARCH_HEADERS
    copy(source / "Makefile", common / "Makefile")
    copy(source / "include", common / "include")
    # Debian's common-headers contract includes shared headers for every arch.
    for arch_source in sorted((source / "arch").iterdir()):
        if not arch_source.is_dir():
            continue
        selected = set(arch_source.glob("Makefile*"))
        selected.update(p for p in arch_source.rglob("*") if p.name in ("Kbuild.platforms", "Platform"))
        directories = [p for p in arch_source.rglob("*") if p.is_dir() and p.name in ("include", "scripts")]
        for path in directories + sorted(selected):
            copy(path, common / path.relative_to(source))
    for name in (".config", "Module.symvers", "include"):
        copy(build / name, arch / name)
    for path in build.glob(".kernel*"):
        copy(path, arch / path.name)
    copy(build / "arch/x86/include", arch / "arch/x86/include")
    (arch / "arch/x86/kernel").mkdir(parents=True, exist_ok=True)
    copy(build / "scripts/module.lds", arch / "arch/x86/module.lds")
    for path in arch.rglob("*.cmd"):
        path.unlink()
    subprocess.run(["/usr/bin/objcopy", "-j", ".BTF", "-j", ".BTF_ids",
                    str(build / "vmlinux"), str(arch / "vmlinux")], check=True)
    (arch / "vmlinux").chmod(0o644)
    (arch / "Makefile").write_text("include /usr/src/" + COMMON_HEADERS + "/Makefile\n")
    for directory in (common, arch):
        for name in ("scripts", "tools"):
            link(os.path.relpath(development / "usr/lib" / KBUILD / name, directory), directory / name)
    link("../lib/" + KBUILD, development / "usr/src" / KBUILD)
    for name, target in (("build", ARCH_HEADERS), ("source", COMMON_HEADERS)):
        destination = development / "usr/lib/modules" / ABI / name
        link(os.path.relpath(development / "usr/src" / target, destination.parent), destination)
    require((development / "usr/lib" / KBUILD / "scripts/mod/modpost").is_file(),
            "development TAR omitted the installed kbuild module tools")


def write_tar(root, output):
    """Use the declared GNU tar with canonical installed-file metadata."""
    names = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        require(path.is_file() or path.is_dir() or path.is_symlink(), "unsupported staged file type")
        if path.is_symlink():
            target = os.readlink(path)
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
            require(not target.startswith("/") and not resolved.startswith("../") and resolved != "..",
                    "TAR link escapes installation root or names a build-tree path")
        else:
            path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
        names.append(relative)
    subprocess.run([
        "/usr/bin/tar", "--create", "--file=" + str(output.resolve()), "--format=posix",
        "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
        "--mtime=@" + str(EPOCH), "--owner=0", "--group=0", "--numeric-owner",
        "--hard-dereference", "--no-recursion", "--null", "--files-from=-",
    ], cwd=root, input=("\0".join(names) + "\0").encode(), check=True)


def stage(source, staging, artifacts):
    build = source / "debian/build/build_amd64_sonic_amd64"
    patched = source / "debian/build/source_sonic"
    runtime, debug, development = (staging / name for name in ("runtime", "debug", "development"))
    for path in (runtime, debug, development, artifacts):
        path.mkdir(parents=True, exist_ok=True)
    image, symbols = build / "output/image", build / "output/image-dbg"
    copy(image / "boot", runtime / "boot")
    copy(image / "lib/modules", runtime / "usr/lib/modules")
    # Preserve the real map, and match Debian's config filtering of ephemeral keys.
    copy(build / "System.map", runtime / ("boot/System.map-" + ABI))
    config = (build / ".config").read_text().splitlines(keepends=True)
    (runtime / ("boot/config-" + ABI)).write_text("".join(line for line in config if not re.search(
        r"CONFIG_(MODULE_SIG_(ALL|KEY)|SYSTEM_TRUSTED_KEYS|BUILD_SALT)[ =]", line)))
    copy(symbols / "boot", debug / "usr/lib/debug/boot")
    copy(symbols / "lib/modules", debug / "usr/lib/debug/lib/modules")
    if (symbols / "usr/lib/debug").exists():
        copy(symbols / "usr/lib/debug", debug / "usr/lib/debug")
    link("boot/vmlinux-" + ABI, debug / ("usr/lib/debug/vmlinux-" + ABI))
    link("../../../boot/vmlinux-" + ABI, debug / "usr/lib/debug/lib/modules" / ABI / "vmlinux")
    for tree in (runtime / "usr/lib/modules" / ABI, debug / "usr/lib/debug/lib/modules" / ABI):
        require(not (tree / "build").exists() and not (tree / "build").is_symlink()
                and not (tree / "source").exists() and not (tree / "source").is_symlink(),
                "runtime/debug contains an unintended header or build-tree link")
    stage_headers(patched, build, development)
    # DWARF paths retain Debian's relative build layout after debug-prefix-map.
    # Ship the actual patched source and generated headers so source/line lookup
    # also works when the disposable compiler tree has been removed.
    debug_source = debug / "usr/src/debug" / ("linux-" + ABI)
    shutil.copytree(patched, debug_source / "debian/build/source_sonic",
                    symlinks=True, ignore=shutil.ignore_patterns(".pc"))
    for name in ("include", "arch/x86/include", ".config"):
        copy(build / name, debug_source / "debian/build/build_amd64_sonic_amd64" / name)
    for tree, packages in ((runtime, ["linux-image-" + ABI + "-unsigned"]),
                           (debug, ["linux-image-" + ABI + "-dbg"]),
                           (development, [COMMON_HEADERS, ARCH_HEADERS, KBUILD])):
        for package in packages:
            for name in ("copyright", "changelog"):
                copy(source / "debian" / name, tree / "usr/share/doc" / package / name)
    receipt = validate_debug_pairs(source, runtime, debug)
    (artifacts / "debug-validation.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    for name, tree in (("runtime", runtime), ("debug", debug), ("development", development)):
        write_tar(tree, artifacts / ("kernel-" + name + ".tar"))
    print("SONIC_KERNEL_DEBUG_VERIFIED " + json.dumps(receipt, sort_keys=True), flush=True)


if __name__ == "__main__":
    stage(*(Path(value) for value in sys.argv[1:]))
