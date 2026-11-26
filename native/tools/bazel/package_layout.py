"""Kernel development-package layouts from Debian's effective installation rules.

The entries describe final ownership-independent installation metadata. File
bytes stay in the declared prepared source or build artifacts. Only the header
Makefile, BTF-only vmlinux and Perl shebang corrections produce new files.
"""

import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

# debian/rules.d/scripts/Makefile: DATA and SCRIPTS, with its wildcard semantics.
_KBUILD_DATA = (
    'Kbuild.include', 'Makefile.*', 'mkversion', 'module-common.c',
    'module-common.lds', 'subarch.include',
)
_KBUILD_SCRIPTS = (
    'checkincludes.pl', 'check-local-export', 'checkstack.pl', 'checkversion.pl',
    'depmod.sh', 'gcc-*.sh', 'gen_initramfs_list.sh', 'headers_install.sh',
    'kernel-doc', 'ld-version.sh', 'Lindent', 'makelst', 'mksysmap', 'mkuboot.sh',
    'modules-check.sh', 'namespace.pl', 'pahole-flags.sh', 'pahole-version.sh',
    'patch-kernel', 'recordmcount.pl', 'setlocalversion', 'ver_linux',
)
def _file(source, mode=None):
    source = Path(source)
    if not source.is_file():
        raise ValueError('missing installation source: ' + str(source))
    if mode is None:
        # dh_fixperms preserves executable input files while removing group/other
        # write bits and ensuring readability. The Bazel build tree is already
        # permission-normalized; retain that existing effective contract.
        mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
    return {'type': 'file', 'mode': mode, 'contents': str(source.absolute())}


def _directory(entries, name):
    name = str(PurePosixPath(name))
    if name == '.':
        return
    _directory(entries, str(PurePosixPath(name).parent))
    entries.setdefault(name, {'type': 'dir', 'mode': 0o755})


def _put(entries, name, entry):
    _directory(entries, str(PurePosixPath(name).parent))
    entries[str(PurePosixPath(name))] = entry


def _tree(entries, source, destination, exclude_commands=False):
    """cpio -pL / cp -aL semantics: directly reference dereferenced file bytes."""
    source = Path(source)
    if exclude_commands and source.name.endswith('.cmd'):
        return
    if source.is_dir():
        _directory(entries, destination)
        for child in sorted(source.iterdir()):
            _tree(entries, child, str(PurePosixPath(destination) / child.name), exclude_commands)
    else:
        _put(entries, destination, _file(source))


def _link(entries, name, target):
    # The caller performs merged-/usr mapping before reproducing dh_link's
    # relative target calculation. Source symlinks are never marked this way.
    _put(entries, name, {'type': 'link', 'mode': 0o777,
                         'link': target, 'normalized_link': True})


def _kbuild_links(entries, base, kbuild):
    for child in ('scripts', 'tools'):
        _link(entries, base + '/' + child, '/usr/lib/' + kbuild + '/' + child)


def _headers_common(config, entries, prepared, package, kbuild):
    base = 'usr/src/' + package
    _put(entries, base + '/Makefile', _file(prepared / 'Makefile'))
    if 'all_kernel_arches' not in config:
        raise ValueError('headers_common requires Config-derived all_kernel_arches')
    for architecture in config['all_kernel_arches']:
        root = prepared / 'arch' / architecture
        if not root.is_dir():
            raise ValueError('missing configured kernel architecture: ' + architecture)
        for path in sorted(root.glob('Makefile*')):
            _put(entries, base + '/' + path.relative_to(prepared).as_posix(), _file(path))
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(prepared).as_posix()
            if path.name in ('Kbuild.platforms', 'Platform') and path.is_file():
                _put(entries, base + '/' + relative, _file(path))
            elif path.name in ('include', 'scripts') and path.is_dir():
                _tree(entries, path, base + '/' + relative)
    _tree(entries, prepared / 'include', base + '/include')
    _kbuild_links(entries, base, kbuild)


def _headers(config, entries, build, generated, package, common, kbuild, kernel_arch, release):
    base = 'usr/src/' + package
    _directory(entries, base + '/arch/' + kernel_arch + '/kernel')
    # rules.real binary_headers copies .config,.kernel*,Module.symvers,include.
    for path in sorted(build.iterdir()):
        if path.name in ('.config', 'Module.symvers', 'include') or path.name.startswith('.kernel'):
            _tree(entries, path, base + '/' + path.name, exclude_commands=True)
    _tree(entries, build / 'arch' / kernel_arch / 'include',
          base + '/arch/' + kernel_arch + '/include', exclude_commands=True)
    vmlinux = generated / 'headers-vmlinux'
    vmlinux.parent.mkdir(parents=True, exist_ok=True)
    if 'objcopy' not in config:
        raise ValueError('headers require target objcopy from the declared binutils toolchain')
    subprocess.run([str(config['objcopy']), '-j', '.BTF', '-j', '.BTF_ids',
                    str(Path(config['raw_files']['vmlinux']).absolute()), str(vmlinux)], check=True)
    _put(entries, base + '/vmlinux', _file(vmlinux, 0o644))
    optional = build / 'arch' / kernel_arch / 'lib/crtsavres.o'
    if optional.is_file():
        _put(entries, base + '/arch/' + kernel_arch + '/lib/crtsavres.o', _file(optional))
    _put(entries, base + '/arch/' + kernel_arch + '/module.lds',
         _file(build / 'scripts/module.lds'))
    makefile = generated / 'headers-Makefile'
    makefile.write_text('include /usr/src/' + common + '/Makefile\n')
    _put(entries, base + '/Makefile', _file(makefile, 0o644))
    _kbuild_links(entries, base, kbuild)
    _link(entries, 'lib/modules/' + release + '/build', '/usr/src/' + package)
    _link(entries, 'lib/modules/' + release + '/source', '/usr/src/' + common)


def _kbuild(config, entries, prepared, generated, kbuild):
    base = 'usr/lib/' + kbuild
    scripts = prepared / 'scripts'
    for pattern in _KBUILD_DATA:
        for source in sorted(scripts.glob(pattern)):
            if source.is_file():
                _put(entries, base + '/scripts/' + source.name, _file(source, 0o644))
    for pattern in _KBUILD_SCRIPTS:
        for source in sorted(scripts.glob(pattern)):
            if not source.is_file():
                continue
            content = source.read_bytes()
            first, newline, rest = content.partition(b'\n')
            # debian/bin/fix-shebang changes exactly /usr/bin/env perl, and
            # deliberately leaves all other env invocations unchanged.
            match = re.fullmatch(rb'#!\s*/usr/bin/env\s+(.+)', first)
            if match and match[1] == b'perl':
                target = generated / 'kbuild-scripts' / source.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'#!/usr/bin/perl\n' + rest)
                source = target
            _put(entries, base + '/scripts/' + source.name, _file(source, 0o755))
    tools = config.get('kbuild_tools', {})
    if not tools:
        raise ValueError('kbuild requires its declared native tool outputs')
    for name, source in sorted(tools.items()):
        _put(entries, base + '/' + name, _file(source, 0o755))
    _link(entries, 'usr/src/' + kbuild, '/' + base)


def layout(config, role, generated):
    """Return original installation paths; the caller finalizes merged-/usr."""
    generated = Path(generated).absolute()
    generated.mkdir(parents=True, exist_ok=True)
    prepared = Path(config['prepared_source']).absolute()
    build = Path(config['artifacts']).absolute() / 'build'
    variables = config['kernel_config']
    abi = variables['KERNEL_VERSION'] + variables['KERNEL_ABISUFFIX']
    featureset = variables['KERNEL_FEATURESET']
    release = variables['KVERSION']
    common = 'linux-headers-' + abi + '-common-' + featureset
    package = 'linux-headers-' + release
    kbuild = 'linux-kbuild-' + abi
    kernel_arch = {'amd64': 'x86', 'arm64': 'arm64', 'armhf': 'arm'}[config['architecture']]
    entries = {}
    if role == 'headers_common':
        _headers_common(config, entries, prepared, common, kbuild)
    elif role == 'headers':
        _headers(config, entries, build, generated, package, common, kbuild, kernel_arch, release)
    elif role == 'kbuild':
        _kbuild(config, entries, prepared, generated, kbuild)
    else:
        raise ValueError('unsupported development package role: ' + role)
    return entries
