#!/usr/bin/env python3
"""Build prepared Linux sources with independent execution and target tools."""

from contextlib import contextmanager
import time
import io
import stat
import tarfile
import shlex
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile

from kernel_arch import (ARCHITECTURES, HOST_ARCHITECTURES, build_directory, kernel_abi, kernel_architecture,
                         kernel_flavour, validate_architecture, validate_build_pair)

SOURCE_DATE_EPOCH = 1754969284  # Debian linux 6.12.41-1 changelog timestamp.
BUILD_JOBS = len(os.sched_getaffinity(0))
MANIFEST = "kernel-packages.json"
PACKAGE_VERSION = "6.12.41-1"
EXTRA_SOURCES = ("tools/bazel/kernel_arch.py", "tools/bazel/stage_kernel.py")

def package_kinds(architecture="amd64"):
    abi = kernel_abi(architecture)
    suffix = "_" + PACKAGE_VERSION + "_" + architecture + ".deb"
    return {
        "linux-image-" + abi + ("" if architecture == "armhf" else "-unsigned") + suffix: "runtime",
        "linux-image-" + abi + "-dbg" + suffix: "debug",
        "linux-headers-" + abi + suffix: "headers",
        "linux-headers-6.12.41+deb13-common-sonic_" + PACKAGE_VERSION + "_all.deb": "headers_common",
        "linux-kbuild-6.12.41+deb13" + suffix: "kbuild",
    }


def package_names(architecture="amd64"):
    return set(package_kinds(architecture))


PACKAGE_NAMES = package_names()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_identity(runtime, architecture=None, target_architecture=None):
    marker = json.loads((runtime / "kernel-runtime.json").read_text())
    return validate_runtime_identity(marker, architecture, target_architecture)


def validate_runtime_identity(marker, architecture=None, target_architecture=None):
    require(isinstance(marker, dict), "missing declared build-tools provenance")
    require(marker.get("schema_version") == 1 and marker.get("kind") == "debian-build-tools",
            "unsupported declared build-tools runtime")
    if architecture is None:
        architecture = marker.get("architecture")
    require(architecture in HOST_ARCHITECTURES, "unsupported kernel execution architecture")
    require(marker.get("architecture") == architecture, "kernel tools must execute on " + architecture.upper())
    cross_architectures = marker.get("cross_architectures", [])
    require(isinstance(cross_architectures, list)
            and all(isinstance(target, str) for target in cross_architectures)
            and cross_architectures == sorted(set(cross_architectures)),
            "invalid build-tools cross architectures")
    require(architecture not in cross_architectures,
            "cross architectures must exclude the execution architecture")
    if target_architecture is not None:
        validate_build_pair(architecture, target_architecture)
        require(target_architecture == architecture or target_architecture in cross_architectures,
                "kernel tools do not support the target architecture")
    require(marker.get("execution") == "relocatable", "kernel tools must support unprivileged direct execution")
    inputs = marker.get("input_sha256")
    require(isinstance(inputs, list) and inputs
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in inputs)
            and inputs == sorted(inputs)
            and isinstance(marker.get("packages"), dict) and marker["packages"]
            and all(isinstance(name, str) and isinstance(version, str) and name and version
                    for name, version in marker["packages"].items()),
            "missing build-tools provenance")
    expected = hashlib.sha256(json.dumps({"architecture": architecture, "inputs": inputs},
                                         sort_keys=True).encode()).hexdigest()
    require(marker.get("identity_sha256") == expected, "build-tools identity digest differs from its inputs")
    return marker


def packaging_database(runtime, destination):
    """Let dpkg resolve declared libraries without modifying the shared input.

    dpkg-shlibdeps looks up the resolved library filename in dpkg's file lists.
    The libraries live beneath the declared runtime, so its private database
    needs those same paths instead of paths on the build host.
    """
    runtime = runtime.resolve(strict=True)
    shutil.copytree(runtime / "var/lib/dpkg", destination, copy_function=shutil.copyfile)
    for listing in sorted((destination / "info").glob("*.list")):
        paths = listing.read_text().splitlines()
        listing.write_text("\n".join(
            str(runtime / path.lstrip("/")) if path.startswith("/") else path
            for path in paths
        ) + "\n")


def source_inventory(sources):
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
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        inventory.append({"name": name, "mode": mode, "sha256": sha256(path)})
    return inventory


def source_tree_sha256(inventory):
    return hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()


def checkout_source_identity(checkout):
    files = [checkout / name for name in ("Makefile", "manage-config", *EXTRA_SOURCES)]
    for directory in ("config.local", "patches-debian", "patches-sonic"):
        files.extend(path for path in (checkout / directory).rglob("*") if path.is_file())
    return source_tree_sha256(source_inventory([
        {"name": str(path.relative_to(checkout)), "path": str(path)} for path in files
    ]))


def validate_configuration(kernel_config, architecture, host_architecture):
    """Check the normalized producer contract before invoking build tools."""
    validate_build_pair(host_architecture, architecture)
    expected = {
        "CONFIGURED_ARCH": architecture, "CONFIGURED_PLATFORM": "vs", "BLDENV": "trixie",
        "CROSS_BUILD_ENVIRON": "y" if host_architecture != architecture else "n",
        "MULTIARCH_QEMU_ENVIRON": "n", "KERNEL_VERSION": "6.12.41", "KERNEL_ABISUFFIX": "+deb13",
        "KERNEL_SUBVERSION": "1", "KERNEL_FEATURESET": "sonic", "KVERSION": kernel_abi(architecture),
        "ADDITIONAL_BUILD_PROFILES": "", "SECURE_UPGRADE_MODE": "no_sign", "INCLUDE_EXTERNAL_PATCHES": "n",
    }
    inactive = {"SECURE_UPGRADE_KERNEL_CAFILE", "EXTERNAL_KERNEL_PATCH_URL", "EXTERNAL_KERNEL_PATCH_LOC"}
    require(isinstance(kernel_config, dict) and set(kernel_config) == set(expected) | inactive
            and all(isinstance(value, str) for value in kernel_config.values()),
            "kernel configuration must contain all normalized Make variables")
    for name, value in expected.items():
        require(kernel_config[name] == value, "unsupported kernel configuration: " + name)


def build_profiles(kernel_config, cross):
    profiles = ["cross", "nocheck", "nodoc"] if cross else ["nodoc"]
    return profiles + list(filter(None, kernel_config["ADDITIONAL_BUILD_PROFILES"].split(",")))


def debian_architecture(runtime, architecture, host_architecture, environment):
    """Resolve the complete Debian build/host tuple before generating controls."""
    validate_build_pair(host_architecture, architecture)
    result = subprocess.run([str(runtime / "bin/dpkg-architecture"), "-a" + architecture, "-l"],
                            env=environment, text=True, capture_output=True, check=True)
    values = {}
    for line in result.stdout.splitlines():
        name, separator, value = line.partition("=")
        require(separator and re.fullmatch(r"DEB_(BUILD|HOST|TARGET)_[A-Z_]+", name)
                and value and not any(c.isspace() for c in value),
                "invalid declared dpkg architecture output")
        require(name not in values, "duplicate declared dpkg architecture output")
        values[name] = value
    require(values.get("DEB_BUILD_ARCH") == host_architecture
            and values.get("DEB_HOST_ARCH") == architecture
            and values.get("DEB_HOST_GNU_TYPE"), "declared Debian build/host architecture differs")
    return values


def package_record(path, architecture="amd64", environment=None):
    command = ["dpkg-deb", "--show", "--showformat=${Package}\t${Version}\t${Architecture}", str(path)]
    result = subprocess.run(command, check=True, text=True, capture_output=True, env=environment)
    package, version, binary_arch = result.stdout.split("\t")
    require(version == PACKAGE_VERSION and binary_arch in (architecture, "all"),
            "unexpected Debian kernel package version or architecture")
    require(path.name == f"{package}_{version}_{binary_arch}.deb", "Debian filename differs from control metadata")
    return {"name": path.name, "kind": package_kinds(architecture).get(path.name, "other"),
            "package": package, "version": version, "architecture": binary_arch,
            "sha256": sha256(path), "size": path.stat().st_size}


def run(command, cwd, environment, **kwargs):
    print('KERNEL_COMMAND ' + shlex.join(str(value) for value in command), flush=True)
    subprocess.run([str(value) for value in command], cwd=cwd, env=environment, check=True, **kwargs)


@contextmanager
def phase(name, timings):
    started = time.monotonic()
    print('KERNEL_PHASE_STARTED ' + name, flush=True)
    try:
        yield
    finally:
        timings[name] = round(time.monotonic() - started, 3)
        print('KERNEL_PHASE_SECONDS ' + name + ' ' + str(timings[name]), flush=True)


def metadata_source(debian, prepared, recipe, kernel, architecture, environment, setup=True):
    """Merge declared config fragments and run only Linux's Kconfig machinery."""
    from package_metadata import kernel_configuration_metadata
    kernel.mkdir()
    work = kernel / 'build'
    work.mkdir()
    if not setup:
        return work
    metadata = kernel_configuration_metadata({
        'architecture': architecture, 'debian_source': str(debian),
        'recipe_source': str(recipe), 'kernel_config': environment,
    })
    runtime = Path(environment['SONIC_KERNEL_TOOLS']).parent
    command = [str(runtime / 'bin/python3'), str(debian / 'debian/bin/kconfig.py'), str(work / '.config'),
               *metadata['kconfig'], *metadata['kconfig_options'],
               '-o', 'MODULE_SIG_KEY="output/signing_key.pem"']
    run(command, kernel, environment)
    target = {'amd64': 'x86_64-linux-gnu', 'arm64': 'aarch64-linux-gnu'}[architecture] + '-'
    variables = [
        'override ARCH = ' + kernel_architecture(architecture),
        'override KERNELRELEASE = ' + kernel_abi(architecture),
        'CCACHE = ccache',
        'CC = $(if $(DEBIAN_KERNEL_USE_CCACHE),$(CCACHE)) $(CROSS_COMPILE)' + metadata['compiler'],
        'DEB_BUILD_ARCH ?= $(shell dpkg --print-architecture)',
        'override CROSS_COMPILE = ' + target,
        'DEBIAN_KERNEL_NO_CC_VERSION_CHECK = y',
    ]
    if metadata.get('compat_gnutype'):
        variables += ['override CROSS_COMPILE_COMPAT = ' + metadata['compat_gnutype'] + '-',
                      'override CROSS32_COMPILE = ' + metadata['compat_gnutype'] + '-',
                      'export CROSS_COMPILE_COMPAT CROSS32_COMPILE']
    (work / '.kernelvariables').write_text('\n'.join(variables) + '\n')
    run(['make', '-C', prepared, 'O=' + str(work),
         *kbuild_tools(runtime, architecture, environment.get('SONIC_KERNEL_HOST_ARCHITECTURE', architecture)),
         'olddefconfig'], kernel, environment)
    if metadata.get('enable_signed'):
        text = (work / '.config').read_text()
        require('CONFIG_EFI_STUB=y\n' in text, 'Secure Boot: CONFIG_EFI_STUB has wrong value')
        require('CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"' not in text,
                'Secure Boot: CONFIG_MODULE_SIG_KEY has default value')
    return work


def kbuild_tools(runtime, architecture, host_architecture):
    triplets = {'amd64': 'x86_64-linux-gnu', 'arm64': 'aarch64-linux-gnu'}
    target = triplets[architecture] + '-'
    host = triplets[host_architecture] + '-'
    tools = runtime / 'bin'
    arguments = [
        'ARCH=' + kernel_architecture(architecture),
        'SHELL=' + str(tools / 'bash'), 'CONFIG_SHELL=' + str(tools / 'bash'),
        'CC=' + str(tools / (target + 'gcc-14')),
        'HOSTCC=' + str(tools / 'host-gcc'), 'HOSTCXX=' + str(tools / 'host-g++'),
        'HOSTLD=' + str(tools / (host + 'ld')), 'HOSTAR=' + str(tools / (host + 'ar')),
        'CROSS_COMPILE=' + str(tools / target),
    ]
    for name in ('ld', 'ar', 'as', 'nm', 'objcopy', 'objdump', 'strip', 'readelf'):
        arguments.append(name.upper() + '=' + str(tools / (target + name)))
    if architecture == 'arm64':
        arguments += ['CROSS_COMPILE_COMPAT=arm-linux-gnueabihf-',
                      'CROSS32_COMPILE=arm-linux-gnueabihf-']
    return arguments


def compile_kernel(prepared, kernel, work, runtime, architecture, host_architecture, environment):
    """Run one explicit Kbuild and one runtime modules_install pass."""
    output = work / 'output'
    output.mkdir()
    environment['KBUILD_SIGN_PIN'] = os.urandom(16).hex()
    run(['openssl', 'req', '-new', '-utf8', '-sha256', '-days', '36500', '-batch', '-x509',
         '-passout', 'env:KBUILD_SIGN_PIN',
         '-config', prepared / 'certs/default_x509.genkey', '-outform', 'PEM',
         '-out', output / 'signing_key.pem', '-keyout', output / 'signing_key.pem',
         '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:secp384r1'], kernel, environment)
    abi = kernel_abi(architecture)
    debug_root = '/usr/src/debug/linux-' + abi
    flags = ['-fdebug-prefix-map=' + str(prepared) + '=' + debug_root + '/debian/build/source_sonic',
             '-fdebug-prefix-map=' + str(work) + '=' + debug_root + '/debian/build/' + build_directory(architecture)]
    assembler_flags = flags + [
        '-Wa,--debug-prefix-map=' + str(prepared) + '=' + debug_root + '/debian/build/source_sonic',
        '-Wa,--debug-prefix-map=' + str(work) + '=' + debug_root + '/debian/build/' + build_directory(architecture)]
    make = ['make', '-C', prepared, 'O=' + str(work), '-j' + str(BUILD_JOBS),
            *kbuild_tools(runtime, architecture, host_architecture),
            'KCFLAGS=' + ' '.join(flags), 'KAFLAGS=' + ' '.join(assembler_flags),
            'PAHOLE_FLAGS=$(filter-out -j,$(pahole-flags-y)) -j1',
            'cmd_mkmap=TOPDIR=' + shlex.quote(os.path.relpath(prepared, work))
            + ' SPKDIR=' + shlex.quote(os.path.relpath(prepared / 'drivers/accessibility/speakup', work))
            + ' $(obj)/makemapdata > $@']
    image = 'bzImage' if architecture == 'amd64' else 'Image'
    run(make + [image, 'modules'] + (['dtbs'] if architecture == 'arm64' else []), kernel, environment)
    runtime_tree, debug_tree = output / 'image', output / 'image-dbg'
    runtime_tree.mkdir(parents=True)
    debug_tree.mkdir(parents=True)
    no_depmod = 'DEPMOD=' + str(kernel / 'debian/bin/no-depmod')
    run(make + ['modules_install', no_depmod, 'INSTALL_MOD_PATH=' + str(runtime_tree),
                'INSTALL_MOD_STRIP=1'], kernel, environment)
    for line in (work / 'modules.order').read_text().splitlines():
        relative = Path(line)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Invalid modules.order entry')
        relative = relative.with_suffix('.ko')
        destination = debug_tree / 'lib/modules' / abi / 'kernel' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(work / relative, destination)
    for name in ('modules.order', 'modules.builtin', 'modules.builtin.modinfo'):
        source = runtime_tree / 'lib/modules' / abi / name
        if source.exists():
            destination = debug_tree / 'lib/modules' / abi / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    run(make + ['vdso_install', 'INSTALL_MOD_PATH=' + str(debug_tree)], kernel, environment)
    if architecture == 'arm64':
        run(make + ['dtbs_install', 'INSTALL_DTBS_PATH=' + str(runtime_tree / 'usr/lib' / ('linux-image-' + abi))], kernel, environment)
    for tree in (runtime_tree, debug_tree):
        for name in ('build', 'source'):
            (tree / 'lib/modules' / abi / name).unlink(missing_ok=True)
    (output / 'signing_key.pem').unlink()


def move_output(source, destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Bazel may precreate an empty TreeArtifact directory. Rename replaces
    # that empty directory rather than nesting the source directory inside it.
    Path(source).rename(destination)


def tree_manifest(tree):
    """Preserve installation metadata before Bazel normalizes output modes/links."""
    records = []
    for directory, directories, files in os.walk(tree, followlinks=False):
        for name in sorted(directories + files):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            record = {'path': path.relative_to(tree).as_posix(),
                      'mode': format(stat.S_IMODE(mode), '04o')}
            if stat.S_ISLNK(mode):
                record.update(type='symlink', target=os.readlink(path))
            elif stat.S_ISDIR(mode):
                record['type'] = 'directory'
            else:
                require(stat.S_ISREG(mode), 'Unsupported kernel installation file: ' + str(path))
                record['type'] = 'file'
            records.append(record)
    return sorted(records, key=lambda record: record['path'])


def export_build_data(prepared, work, config, architecture):
    export = Path(config['artifacts'])
    export.mkdir(parents=True, exist_ok=True)
    data = export / 'build'
    data.mkdir()
    paths = ['include', 'arch/' + kernel_architecture(architecture) + '/include',
             'scripts/module.lds', '.config', '.kernelvariables', 'Module.symvers',
             'scripts/basic/fixdep', 'scripts/mod/modpost', 'scripts/genksyms/genksyms',
             'scripts/sign-file', 'tools/objtool/objtool', 'tools/bpf/resolve_btfids/resolve_btfids']
    raw = config['raw_files']
    # These small files have both a raw interface and a build-data consumer.
    for name, source in [('config', work / '.config'), ('Module.symvers', work / 'Module.symvers')]:
        destination = Path(raw[name])
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    for name in paths:
        source = work / name
        if source.exists():
            move_output(source, data / name)
    image = 'bzImage' if architecture == 'amd64' else 'Image'
    for name, source in [('image', work / 'arch' / kernel_architecture(architecture) / 'boot' / image),
                         ('vmlinux', work / 'vmlinux'), ('System.map', work / 'System.map')]:
        move_output(source, raw[name])
    release = Path(raw['kernel.release'])
    release.parent.mkdir(parents=True, exist_ok=True)
    release.write_text(kernel_abi(architecture) + '\n')
    (export / 'build-paths.json').write_text(json.dumps({'source': str(prepared), 'build': str(work)}) + '\n')
    trees = {}
    for role, name in [('runtime', 'image'), ('debug', 'image-dbg')]:
        source = work / 'output' / name
        trees[role] = tree_manifest(source)
        move_output(source, config[role + '_tree'])
    return trees


def control_fields(text):
    fields = {}
    key = None
    for line in text.splitlines():
        if line.startswith((' ', '\t')):
            require(key is not None, 'Invalid Debian control continuation')
            fields[key] += '\n' + line
        elif line:
            key, separator, value = line.partition(':')
            require(separator and key not in fields, 'Invalid Debian control field')
            fields[key] = value.strip()
    return fields


def deb_control(path):
    """Read only ar's small control archive, without unpacking the payload."""
    with path.open('rb') as stream:
        require(stream.read(8) == b'!<arch>\n', 'Invalid Debian ar archive')
        while header := stream.read(60):
            require(len(header) == 60 and header[58:] == b'`\n', 'Invalid Debian ar member')
            name = header[:16].decode().strip().rstrip('/')
            size = int(header[48:58])
            if name.startswith('control.tar'):
                with tarfile.open(fileobj=io.BytesIO(stream.read(size)), mode='r:*') as archive:
                    member = next(member for member in archive if member.name.removeprefix('./') == 'control')
                    return control_fields(archive.extractfile(member).read().decode())
            stream.seek(size + size % 2, 1)
    raise ValueError('Debian archive contains no control archive')


def manifest_record(path, architecture):
    path = Path(path)
    if path.is_dir():
        debs = list(path.glob('*.deb'))
        require(len(debs) == 1, 'Expected one Debian package per output directory')
        return manifest_record(debs[0], architecture)
    fields = deb_control(path)
    payload = path
    package, version, binary_arch = (fields[key] for key in ('Package', 'Version', 'Architecture'))
    name = f'{package}_{version}_{binary_arch}.deb'
    require(version == PACKAGE_VERSION and binary_arch in (architecture, 'all'),
            'unexpected Debian kernel package version or architecture')
    require(name in package_names(architecture), 'Unexpected kernel package: ' + name)
    if path.is_file():
        require(path.name == name, 'Debian filename differs from control metadata')
    return {'name': name, 'kind': package_kinds(architecture)[name], 'package': package,
            'version': version, 'architecture': binary_arch, 'sha256': sha256(payload),
            'size': payload.stat().st_size}


def manifest_action(config):
    receipt = json.loads(Path(config['receipt']).read_text())
    architecture = receipt['architecture']
    packages = sorted((manifest_record(path, architecture) for path in config['packages']),
                      key=lambda record: record['name'])
    require(len(packages) == len(package_names(architecture))
            and {record['name'] for record in packages} == package_names(architecture),
            'Kernel manifest requires all five package kinds')
    manifest = {key: value for key, value in receipt.items()
                if key not in ('core_trees', 'compilation_completed')}
    manifest.update(packages=packages,
                    created_packages=[{**record, 'exported': True} for record in packages])
    if 'debug_validation' in config:
        manifest['debug'] = json.loads(Path(config['debug_validation']).read_text())
    Path(config['manifest']).write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')


def build(config):
    require(config.get("schema") == 6, "unsupported kernel action schema")
    mode = config.get('mode')
    require(mode in ('compile', 'manifest'), 'unsupported kernel action mode')
    if mode == 'manifest':
        manifest_action(config)
        return
    architecture = config['architecture']
    host_architecture = config['host_architecture']
    kernel_config = config['kernel_config']
    validate_configuration(kernel_config, architecture, host_architecture)
    runtime = Path(config['build_tools']).resolve(strict=True)
    marker = runtime_identity(runtime, target_architecture=architecture)
    require(host_architecture == marker['architecture'], 'declared kernel execution host differs from runtime')
    require(set(config['raw_files']) == {'image', 'vmlinux', 'System.map', 'config',
                                        'Module.symvers', 'kernel.release'},
            'Kernel compilation must declare all raw kernel interfaces')
    cross = host_architecture != architecture
    with tempfile.TemporaryDirectory(prefix="kernel-action-", dir=Path.cwd()) as temporary:
        root = Path(temporary).absolute()
        source = root / 'source'
        source.mkdir()
        (root / 'home').mkdir()
        (root / 'tmp').mkdir()
        recipe = Path(config['recipe_source']).resolve(strict=True)
        inventory = source_inventory(config['sources'])
        prepared_source = Path(config['prepared_source']).resolve(strict=True)
        debian_source = Path(config['debian_source']).resolve(strict=True)
        timings = {}
        environment = {
            "PATH": str(runtime / "bin"),
            "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
            "SHELL": str(runtime / "bin/bash"), "CONFIG_SHELL": str(runtime / "bin/bash"),
            "DPKG_ADMINDIR": str(root / "dpkg"),
            "DPKG_DATADIR": str(runtime / "usr/share/dpkg"),
            "DPKG_ORIGINS_DIR": str(runtime / "etc/dpkg/origins"),
            "DEB_RULES_REQUIRES_ROOT": "no",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH), "PYTHONHASHSEED": "0",
            "KBUILD_BUILD_USER": "sonic", "KBUILD_BUILD_HOST": "kernel-builder",
            "KBUILD_BUILD_TIMESTAMP": "@" + str(SOURCE_DATE_EPOCH),
            "KBUILD_BUILD_VERSION": "1", "DEB_BUILD_OPTIONS": "parallel=" + str(BUILD_JOBS),
            "DEB_BUILD_PROFILES": " ".join(build_profiles(kernel_config, cross)),
            "DPKG_DEB_THREADS_MAX": str(BUILD_JOBS),
            "PAHOLE": str(runtime / "bin/pahole"),
            **kernel_config,
            "SONIC_KERNEL_DEBUG_STAGE": str(recipe / "tools/bazel/stage_kernel.py"),
            "SONIC_KERNEL_TOOLS": str(runtime / "bin"),
            "SONIC_KERNEL_ARCHITECTURE": architecture,
            "SONIC_KERNEL_HOST_ARCHITECTURE": host_architecture,
            "SONIC_KERNEL_PATCHELF": str(Path(config["patchelf"]).absolute()),
        }
        environment.update(debian_architecture(runtime, architecture, host_architecture, environment))
        if cross:
            prefix = environment["DEB_HOST_GNU_TYPE"] + "-"
            for tool in ("gcc", "ld", "objcopy", "readelf", "strip", "pkg-config"):
                require((runtime / "bin" / (prefix + tool)).is_file(),
                        "declared runtime lacks cross tool: " + prefix + tool)
            environment["SONIC_KERNEL_CROSS_COMPILE"] = prefix
        kernel = source / ('linux-' + kernel_config['KERNEL_VERSION'])
        with phase('configuration', timings):
            work = metadata_source(debian_source, prepared_source, recipe, kernel, architecture,
                                   environment)
        archive_records = []
        for archive in config['archives']:
            require(Path(archive['name']).name == archive['name'], 'unsafe archive filename')
            require(sha256(archive['path']) == archive['sha256'], 'kernel archive checksum mismatch')
            archive_records.append({'name': archive['name'], 'sha256': archive['sha256']})
        print('SONIC_KERNEL_COMPILATION_STARTED', flush=True)
        with phase('kbuild', timings):
            compile_kernel(prepared_source, kernel, work, runtime, architecture, host_architecture, environment)
        with phase('export', timings):
            core_trees = export_build_data(prepared_source, work, config, architecture)
        receipt = {
            'schema': 4, 'architecture': architecture, 'host_architecture': host_architecture,
            'platform': kernel_config['CONFIGURED_PLATFORM'], 'kernel_config': kernel_config,
            'kernel_version': kernel_config['KERNEL_VERSION'], 'kernel_abi': kernel_config['KVERSION'],
            'package_version': PACKAGE_VERSION, 'signing': 'unsigned',
            'source_date_epoch': SOURCE_DATE_EPOCH,
            'source_archives': sorted(archive_records, key=lambda entry: entry['name']),
            'source_tree_sha256': source_tree_sha256(inventory), 'source_files': inventory,
            'build_tools': marker, 'core_trees': core_trees, 'compilation_completed': True,
        }
        Path(config['receipt']).write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        print('SONIC_KERNEL_COMPILATION_COMPLETED', flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--source-tree-sha256":
        print(checkout_source_identity(Path(sys.argv[2])))
    else:
        build(json.loads(Path(sys.argv[1]).read_text()))
