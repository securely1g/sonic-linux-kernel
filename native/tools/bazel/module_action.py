"""Build external modules against declared kernel sources and generated data."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile


ARCHITECTURES = {
    'amd64': ('x86', 'x86_64-linux-gnu', 62, 'ld-linux-x86-64.so.2'),
    'arm64': ('arm64', 'aarch64-linux-gnu', 183, 'ld-linux-aarch64.so.1'),
}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def elf_identity(path):
    """Return the machine and PT_INTERP presence without running target files."""
    with path.open('rb') as stream:
        header = stream.read(64)
        if header[:4] != b'\x7fELF':
            return None, False
        endian = '<' if header[5] == 1 else '>'
        machine = struct.unpack_from(endian + 'H', header, 18)[0]
        if header[4] == 2:
            offset = struct.unpack_from(endian + 'Q', header, 32)[0]
            size, count = struct.unpack_from(endian + 'HH', header, 54)
        else:
            offset = struct.unpack_from(endian + 'I', header, 28)[0]
            size, count = struct.unpack_from(endian + 'HH', header, 42)
        for index in range(count):
            stream.seek(offset + size * index)
            if struct.unpack(endian + 'I', stream.read(4))[0] == 3:
                return machine, True
        return machine, False


def runtime_libraries(runtime, machine):
    directories = set()
    for path in runtime.rglob('*.so*'):
        if path.is_file() and elf_identity(path)[0] == machine:
            directories.add(str(path.parent))
    if not directories:
        raise ValueError('Declared execution runtime contains no native libraries')
    return ':'.join(sorted(directories))


def prepare_build_tree(artifacts, build, source, runtime, patchelf, host_arch):
    shutil.copytree(artifacts / 'build', build)
    paths = json.loads((artifacts / 'build-paths.json').read_text())
    replacements = {paths['source']: str(source), paths['build']: str(build)}
    for path in build.rglob('*'):
        path.chmod(path.stat().st_mode | 0o200 | (0o100 if path.is_dir() else 0))
        if path.is_file() and (path.name.endswith('.cmd') or path.name in ('.config', '.kernelvariables')):
            text = path.read_text()
            for previous, current in replacements.items():
                text = text.replace(previous, current)
            path.write_text(text)
    build.chmod(0o755)
    # Kbuild creates these forwarding entries itself for this O= directory.
    for name in ('Makefile', 'source'):
        (build / name).unlink(missing_ok=True)
    # Recompute Kconfig dependencies against the new declared source path.
    (build / 'include/config/auto.conf.cmd').unlink(missing_ok=True)
    _, host_triple, host_machine, loader_name = ARCHITECTURES[host_arch]
    loader = next((path for path in (
        runtime / 'usr/lib' / host_triple / loader_name,
        runtime / 'lib' / host_triple / loader_name,
        runtime / 'usr/lib64' / loader_name,
        runtime / 'lib64' / loader_name,
    ) if path.is_file()), None)
    if loader is None:
        raise ValueError('Declared execution runtime loader is missing')
    libraries = runtime_libraries(runtime, host_machine)
    for path in build.rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        machine, dynamic = elf_identity(path)
        if machine == host_machine and dynamic:
            subprocess.run([str(patchelf), '--set-interpreter', str(loader),
                            '--set-rpath', libraries, str(path)], check=True)


def build(config):
    runtime = Path(config['runtime']).resolve(strict=True)
    source = Path(config['source_root']).resolve(strict=True)
    artifacts = Path(config['kernel']).resolve(strict=True)
    host_arch = config['host_arch']
    marker = json.loads((runtime / 'kernel-runtime.json').read_text())
    if marker['architecture'] != host_arch:
        raise ValueError('Declared kernel tools do not match the execution architecture')
    karch, triple, _, _ = ARCHITECTURES[config['arch']]
    host_triple = ARCHITECTURES[host_arch][1]
    with tempfile.TemporaryDirectory(dir=Path.cwd(), prefix='kernel-module-') as temporary:
        work = Path(temporary).resolve()
        kernel = work / 'build'
        module = work / 'module'
        prepare_build_tree(artifacts, kernel, source, runtime,
                           Path(config['patchelf']).resolve(strict=True), host_arch)
        module.mkdir()
        for filename, relative in config['sources'].items():
            relative = Path(relative)
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('External module input escapes its declared root')
            destination = module / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(filename, destination)
        directory = module / config['directory']
        directory.resolve().relative_to(module)
        symbols = [str(Path(path).resolve(strict=True)) for path in config['symbols']]
        environment = {
            'PATH': str(runtime / 'bin'), 'HOME': str(work), 'TMPDIR': str(work),
            'SHELL': str(runtime / 'bin/bash'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'TZ': 'UTC', 'SOURCE_DATE_EPOCH': '1754969284',
        }
        command = [str(runtime / 'bin/make'), '-C', str(source), 'O=' + str(kernel),
                   '-j' + str(len(os.sched_getaffinity(0))), 'ARCH=' + karch,
                   'SHELL=' + str(runtime / 'bin/bash'),
                   'CONFIG_SHELL=' + str(runtime / 'bin/bash'),
                   'CC=' + str(runtime / 'bin' / (triple + '-gcc-14')),
                   'CROSS_COMPILE=' + str(runtime / 'bin' / (triple + '-')),
                   'HOSTCC=' + str(runtime / 'bin/host-gcc'),
                   'HOSTCXX=' + str(runtime / 'bin/host-g++'),
                   'HOSTLD=' + str(runtime / 'bin' / (host_triple + '-ld')),
                   'HOSTAR=' + str(runtime / 'bin' / (host_triple + '-ar'))]
        for name in ('ld', 'ar', 'as', 'nm', 'objcopy', 'objdump', 'strip', 'readelf'):
            command.append(name.upper() + '=' + str(runtime / 'bin' / (triple + '-' + name)))
        if config['arch'] == 'arm64':
            prefix = 'arm-linux-gnueabihf-'
            command.extend(['CROSS_COMPILE_COMPAT=' + prefix, 'CROSS32_COMPILE=' + prefix])
        original_symvers = digest(kernel / 'Module.symvers')
        subprocess.run(command + ['modules_prepare'], env=environment, check=True)
        release = Path(config['release']).read_text().strip()
        utsrelease = (kernel / 'include/generated/utsrelease.h').read_text()
        if not re.search(r'^#define UTS_RELEASE "' + re.escape(release) + r'"$', utsrelease, re.M):
            raise ValueError('External module preparation changed the kernel release')
        if digest(kernel / 'Module.symvers') != original_symvers:
            raise ValueError('External module preparation changed kernel Module.symvers')
        arguments = ['M=' + str(directory), 'KBUILD_EXTRA_SYMBOLS=' + ' '.join(symbols)]
        arguments.extend(key + '=' + value for key, value in config['make_vars'].items())
        subprocess.run(command + arguments + ['modules'], env=environment, check=True)
        output = Path(config['modules'])
        output.mkdir(parents=True, exist_ok=True)
        for compiled in sorted(directory.rglob('*.ko')):
            destination = output / compiled.relative_to(directory)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(compiled, destination)
        for name, destination in config['metadata'].items():
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text((directory / name).read_text().replace(str(directory) + '/', ''))


if __name__ == '__main__':
    build(json.loads(Path(sys.argv[1]).read_text()))
