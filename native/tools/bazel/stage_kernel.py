#!/usr/bin/env python3
"""Add matched build-ID links to Debian's debug package.

Debian build_image already separates signed stripped modules from their original
unsigned debug ELFs. Preserve those bytes: changing a signed module to add a GNU
debuglink would invalidate its signature. GDB can instead resolve detached
symbols through the matching GNU build IDs and conventional debug paths.
"""

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import tarfile

from kernel_arch import ARCHITECTURES, build_directory, kernel_abi, materialize_kernel_elf


def require(condition, message):
    if not condition:
        raise ValueError(message)


def link(target, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.symlink_to(target)


def elf_interpreter(path):
    """Read PT_INTERP without loading a build output or touching signed modules."""
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) < 64 or header[:6] != b"\x7fELF\x02\x01":
            return None
        if struct.unpack_from("<H", header, 16)[0] not in (2, 3):
            return None
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        for index in range(count):
            stream.seek(offset + index * size)
            program = stream.read(size)
            require(len(program) >= 56, "truncated ELF program header: " + str(path))
            if struct.unpack_from("<I", program)[0] == 3:
                stream.seek(struct.unpack_from("<Q", program, 8)[0])
                length = struct.unpack_from("<Q", program, 32)[0]
                return stream.read(length).rstrip(b"\0").decode()
    return None


def normalize_tools(package, architecture, runtime, patchelf):
    """Remove the private build runtime before Debian strips/packages tools.

    Kbuild's HOSTCC executables need the declared loader while building. The
    installed kbuild tools need the ordinary Debian loader and dependencies.
    Signed kernel modules have no PT_INTERP and are never modified here.
    """
    loader = {"amd64": "/lib64/ld-linux-x86-64.so.2", "arm64": "/lib/ld-linux-aarch64.so.1"}[architecture]
    prefixes = tuple(str(path) + "/" for path in {runtime.absolute(), runtime.resolve()})
    normalized = 0
    for path in sorted(package.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        interpreter = elf_interpreter(path)
        if interpreter is None or not interpreter.startswith(prefixes):
            continue
        old_rpath = subprocess.check_output([str(patchelf), "--print-rpath", str(path)], text=True).strip()
        kept = [entry for entry in old_rpath.split(":") if entry and not entry.startswith(prefixes)]
        rpath_args = ["--set-rpath", ":".join(kept)] if kept else ["--remove-rpath"]
        subprocess.run([str(patchelf), "--set-interpreter", loader, *rpath_args, str(path)], check=True)
        require(elf_interpreter(path) == loader, "installed tool retained its build-time interpreter")
        normalized += 1
    print("SONIC_KERNEL_TOOLS_NORMALIZED " + str(normalized), flush=True)
    return normalized


def elf_info(path, architecture="amd64"):
    """Read GNU notes and section names without starting an execution tool."""
    path = Path(path)
    expected_class, expected_machine = {
        "amd64": (2, 62), "arm64": (2, 183), "armhf": (1, 40),
    }[architecture]
    with path.open("rb") as stream:
        file_size = os.fstat(stream.fileno()).st_size

        def read_at(offset, size):
            require(0 <= offset <= file_size and 0 <= size <= file_size - offset,
                    "ELF range exceeds artifact: " + str(path))
            stream.seek(offset)
            data = stream.read(size)
            require(len(data) == size, "truncated ELF artifact: " + str(path))
            return data

        identification = read_at(0, 16)
        require(identification[:4] == b"\x7fELF" and identification[5] in (1, 2),
                "invalid ELF artifact: " + str(path))
        elf_class = identification[4]
        require(elf_class == expected_class,
                "ELF is not an " + architecture.upper() + " kernel artifact: " + str(path))
        endian = "<" if identification[5] == 1 else ">"
        header_format = endian + ("HHIQQQIHHHHHH" if elf_class == 2 else "HHIIIIIHHHHHH")
        header = struct.unpack(header_format, read_at(16, struct.calcsize(header_format)))
        require(header[1] == expected_machine,
                "ELF is not an " + architecture.upper() + " kernel artifact: " + str(path))
        program_offset, section_offset = header[4:6]
        program_size, program_count, section_size, section_count, names_index = header[8:13]
        section_format = endian + ("IIQQQQIIQQ" if elf_class == 2 else "IIIIIIIIII")
        section_header_size = struct.calcsize(section_format)
        sections = []
        if section_offset:
            require(section_size >= section_header_size, "invalid ELF section header size: " + str(path))
            first = struct.unpack(section_format, read_at(section_offset, section_header_size))
            if section_count == 0:
                section_count = first[5]
            if names_index == 0xffff:
                names_index = first[6]
            if program_count == 0xffff:
                program_count = first[7]
            headers = read_at(section_offset, section_size * section_count)
            sections = [struct.unpack_from(section_format, headers, index * section_size)
                        for index in range(section_count)]
        names = b""
        if names_index:
            require(names_index < len(sections), "invalid ELF section names index: " + str(path))
            names = read_at(sections[names_index][4], sections[names_index][5])
        has_debug = False
        note_ranges = []
        for section in sections:
            name_offset = section[0]
            require(not names or name_offset < len(names), "invalid ELF section name: " + str(path))
            name = names[name_offset:].split(b"\0", 1)[0]
            has_debug = has_debug or name == b".debug_info"
            if section[1] == 7:  # SHT_NOTE also covers relocatable .ko files.
                note_ranges.append((section[4], section[5]))
        if not note_ranges and program_count:
            program_format = endian + ("IIQQQQQQ" if elf_class == 2 else "IIIIIIII")
            require(program_size >= struct.calcsize(program_format),
                    "invalid ELF program header size: " + str(path))
            headers = read_at(program_offset, program_size * program_count)
            for index in range(program_count):
                program = struct.unpack_from(program_format, headers, index * program_size)
                if program[0] == 4:  # PT_NOTE survives stripping of section headers.
                    offset = program[2] if elf_class == 2 else program[1]
                    size = program[5] if elf_class == 2 else program[4]
                    note_ranges.append((offset, size))
        for offset, size in note_ranges:
            notes = read_at(offset, size)
            position = 0
            while position + 12 <= len(notes):
                name_size, description_size, kind = struct.unpack_from(endian + "III", notes, position)
                position += 12
                name_end = position + name_size
                description_start = position + ((name_size + 3) & ~3)
                description_end = description_start + description_size
                require(description_end <= len(notes), "truncated ELF note: " + str(path))
                if kind == 3 and notes[position:name_end].rstrip(b"\0") == b"GNU":
                    return notes[description_start:description_end].hex(), has_debug
                position = description_start + ((description_size + 3) & ~3)
    raise ValueError("ELF lacks a GNU build ID: " + str(path))


def build_id_link(debug_root, debug_file, build_id):
    destination = debug_root / "usr/lib/debug/.build-id" / build_id[:2] / (build_id[2:] + ".debug")
    if destination.is_symlink():
        require(destination.resolve().read_bytes() == debug_file.read_bytes(),
                "different debug files share a build ID")
    else:
        link(os.path.relpath(debug_file, destination.parent), destination)


def validate_debug_pairs(source, runtime, debug, architecture="amd64", raw_vmlinux=None):
    abi = kernel_abi(architecture)
    kernel = debug / ("usr/lib/debug/boot/vmlinux-" + abi)
    kernel_id, has_debug = elf_info(kernel, architecture)
    require(has_debug, "kernel vmlinux is missing DWARF debug information")
    with tempfile.TemporaryDirectory(prefix="kernel-debug-check-") as temporary:
        temporary = Path(temporary)
        embedded = temporary / "vmlinux"
        if raw_vmlinux is None:
            materialize_kernel_elf(architecture, source, runtime / ("boot/vmlinuz-" + abi), kernel, embedded)
        else:
            embedded = Path(raw_vmlinux)
        require(elf_info(embedded, architecture)[0] == kernel_id, "compiled kernel and debug vmlinux build IDs differ")
        build_id_link(debug, kernel, kernel_id)
        modules = runtime / "lib/modules" / abi
        if not modules.exists():
            modules = runtime / "usr/lib/modules" / abi
        debug_modules = debug / "usr/lib/debug/lib/modules" / abi
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
            runtime_id, runtime_debug = elf_info(module, architecture)
            debug_id, has_debug = elf_info(detached, architecture)
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


def stage(source, debug, artifacts, architecture="amd64"):
    """Validate detached symbols and add their conventional build-ID links."""
    spec = install_config(required=False)
    if spec:
        return  # The install action validates directly after materializing debug files.
    build = source / "debian/build" / build_directory(architecture)
    receipt = validate_debug_pairs(source, build / "output/image", debug, architecture)
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "debug-validation.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print("SONIC_KERNEL_DEBUG_VERIFIED " + json.dumps(receipt, sort_keys=True), flush=True)


def install_config(required=True):
    path = os.environ.get("SONIC_KERNEL_INSTALL_CONFIG")
    if path:
        return json.loads(Path(path).read_text())
    require(not required, "SONIC_KERNEL_INSTALL_CONFIG is required")


def stage_install(package, architecture):
    """Materialize declared compile outputs into their final installation layout."""
    spec = install_config()
    role = spec["role"]
    require(role in ("runtime", "debug"), "only runtime/debug have compile trees")
    root = Path(spec[role + "_tree"])
    destination = package if role == "runtime" else package / "usr/lib/debug"
    entries = json.loads(Path(spec["receipt"]).read_text())["core_trees"][role]
    directories = []
    for entry in entries:
        relative = Path(entry["path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "invalid compile tree path")
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        kind = entry["type"]
        if kind == "directory":
            output.mkdir(exist_ok=True)
            directories.append((output, int(entry["mode"], 8)))
        elif kind == "symlink":
            output.symlink_to(entry["target"])
        else:
            require(kind == "file", "invalid compile tree entry type")
            shutil.copyfile(root / relative, output)
            output.chmod(int(entry["mode"], 8))
    for output, mode in reversed(directories):
        output.chmod(mode)
    boot = destination / "boot"
    boot.mkdir(parents=True, exist_ok=True)
    names = {"image": "vmlinuz"} if role == "runtime" else {"vmlinux": "vmlinux", "System.map": "System.map"}
    for key, basename in names.items():
        output = boot / (basename + "-" + kernel_abi(architecture))
        shutil.copyfile(spec["raw_files"][key], output)
        output.chmod(0o644)
    if role == "debug":
        receipt = validate_debug_pairs(None, Path(spec["runtime_tree"]), package, architecture,
                                       raw_vmlinux=spec["raw_files"]["vmlinux"])
        output = Path(spec["install_outputs"]["debug_validation"])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


def export_boot(package, outputs, architecture):
    release = kernel_abi(architecture)
    boot = Path(outputs["boot"]) / "boot"
    boot.mkdir(parents=True, exist_ok=True)
    records = {}
    for kind in ("vmlinuz", "config", "System.map"):
        name = kind + "-" + release
        source = package / "boot" / name
        shutil.move(source, boot / name)
        records[kind] = {"path": "boot/" + name,
                         "sha256": hashlib.sha256((boot / name).read_bytes()).hexdigest()}
    module_directories = [directory for directory in ("lib/modules/", "usr/lib/modules/")
                          if (package / directory / release).is_dir()]
    require(len(module_directories) == 1, "ambiguous runtime module directory")
    Path(outputs["metadata"]).write_text(json.dumps({
        "schema": 1, "architecture": architecture, "kernel_release": release,
        "module_directory": module_directories[0] + release, "boot": records,
    }, sort_keys=True) + "\n")


def export_install(package, architecture):
    """Export finalized Debian installation metadata and uncompressed payload."""
    spec = install_config()
    outputs = spec["install_outputs"]
    epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    for name, output in outputs.items():
        paths = output.values() if name == "control_files" else [output]
        for path in paths:
            Path(path).parent.mkdir(parents=True, exist_ok=True)

    def normalize(member):
        member.uid = member.gid = 0
        member.uname = member.gname = "root"
        member.mtime = epoch
        return member

    with tarfile.open(outputs["data"], "w") as stream:
        for path in sorted(package.iterdir()):
            if path.name != "DEBIAN":
                stream.add(path, arcname="./" + path.name, filter=normalize)
    control = package / "DEBIAN"
    with tarfile.open(outputs["control_tar"], "w") as stream:
        stream.add(control, arcname=".", filter=normalize)
    shutil.copyfile(control / "control", outputs["control"])
    for member, output in outputs["control_files"].items():
        shutil.move(control / member, output)
    if spec["role"] == "runtime":
        export_boot(package, outputs, architecture)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("debug", type=Path, nargs="?")
    parser.add_argument("artifacts", type=Path, nargs="?")
    parser.add_argument("--stage-install", type=Path)
    parser.add_argument("--export-install", type=Path)
    parser.add_argument("--normalize-tools", type=Path)
    parser.add_argument("--architecture", choices=ARCHITECTURES, default="amd64")
    args = parser.parse_args()
    if args.stage_install is not None:
        stage_install(args.stage_install, args.architecture)
    elif args.export_install is not None:
        export_install(args.export_install, args.architecture)
    elif args.normalize_tools is not None:
        normalize_tools(args.normalize_tools, args.architecture,
                        Path(os.environ["SONIC_KERNEL_TOOLS"]).parent,
                        Path(os.environ["SONIC_KERNEL_PATCHELF"]))
    elif all(path is not None for path in (args.source, args.debug, args.artifacts)):
        stage(args.source, args.debug, args.artifacts, args.architecture)
    else:
        parser.error("source, debug and artifacts are required for debug staging")
