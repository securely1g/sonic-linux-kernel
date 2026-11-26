"""Declare kernel package layouts and metadata without Debian build orchestration."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile
import time

from kernel_arch import kernel_abi
from stage_kernel import elf_info
from package_layout import layout
from package_metadata import generate_metadata, compute_shlibs


def require(condition, message):
    if not condition:
        raise ValueError(message)


def escape(value):
    return ''.join(chr(b) if 33 <= b <= 126 and chr(b) not in '#=\\' else '\\%03o' % b
                   for b in str(value).encode())


def file_entry(path, mode=0o644):
    return {'type': 'file', 'contents': str(Path(path).absolute()), 'mode': mode}


def write_file(root, name, content, mode=0o644):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return file_entry(path, mode)


def tree_entries(config, role):
    tree = Path(config[role + '_tree'])
    receipt = json.loads(Path(config['receipt']).read_text())
    prefix = 'usr/lib/debug/' if role == 'debug' else ''
    entries = {}
    for record in receipt['core_trees'][role]:
        name = record['path']
        require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
                'unsafe kernel tree member')
        value = {'mode': int(record['mode'], 8)}
        if record['type'] == 'file':
            value.update(type='file', contents=str((tree / name).absolute()))
        elif record['type'] == 'symlink':
            value.update(type='link', link=record['target'])
        else:
            value['type'] = 'dir'
        # The original dh_fixperms policy makes shared libraries non-executable,
        # including native and compatibility VDSOs installed by Kbuild.
        if role == 'debug' and value['type'] == 'file':
            import re
            if re.search(r'\.so(?:\..*)?$', name):
                value['mode'] = 0o644
        entries[prefix + name] = value
    return entries


def debug_layout(config, generated):
    entries = {name: value for name, value in tree_entries(config, 'debug').items()
               if '/vdso/.build-id' not in name}
    arch = config['architecture']
    abi = kernel_abi(arch)
    debug_root = 'usr/lib/debug/'
    entries[debug_root + 'boot/vmlinux-' + abi] = file_entry(config['raw_files']['vmlinux'])
    entries[debug_root + 'boot/System.map-' + abi] = file_entry(config['raw_files']['System.map'])
    entries[debug_root + 'vmlinux-' + abi] = {'type': 'link', 'link': 'boot/vmlinux-' + abi, 'mode': 0o777}
    entries[debug_root + 'lib/modules/' + abi + '/vmlinux'] = {
        'type': 'link', 'link': '../../../boot/vmlinux-' + abi, 'mode': 0o777}
    pairs = []

    def build_link(name, build_id):
        require(build_id, 'missing debug build ID: ' + name)
        link = debug_root + '.build-id/' + build_id[:2] + '/' + build_id[2:] + '.debug'
        value = {'type': 'link', 'link': os.path.relpath(name, str(PurePosixPath(link).parent)), 'mode': 0o777}
        if link in entries:
            old = str(PurePosixPath(link).parent / entries[link]['link'])
            # Duplicate IDs are legal only for identical ELF content.
            old = os.path.normpath(old)
            require(Path(entries[old]['contents']).read_bytes() == Path(entries[name]['contents']).read_bytes(),
                    'different debug files share a build ID')
        entries[link] = value

    kernel_id, has_debug = elf_info(config['raw_files']['vmlinux'], arch)
    require(has_debug, 'kernel vmlinux is missing DWARF debug information')
    build_link(debug_root + 'boot/vmlinux-' + abi, kernel_id)
    runtime = Path(config['runtime_tree']) / 'lib/modules' / abi
    debug_modules = Path(config['debug_tree']) / 'lib/modules' / abi
    modules = sorted(list(runtime.rglob('*.ko')) + list(runtime.rglob('*.ko.xz')))
    require(modules, 'runtime contains no kernel modules')
    for deployed in modules:
        relative = deployed.relative_to(runtime)
        temporary = None
        module = deployed
        if deployed.suffix == '.xz':
            temporary = generated / 'module-check.ko'
            with lzma.open(deployed, 'rb') as src, temporary.open('wb') as dst:
                shutil.copyfileobj(src, dst)
            module = temporary
            relative = relative.with_suffix('')
        detached = debug_modules / relative
        require(detached.is_file(), 'missing detached debug module: ' + str(relative))
        runtime_id, runtime_debug = elf_info(module, arch)
        debug_id, debug_dwarf = elf_info(detached, arch)
        require(runtime_id == debug_id and debug_dwarf and not runtime_debug,
                'runtime/debug module build ID or DWARF mismatch: ' + str(relative))
        require(b'~Module signature appended~' in module.read_bytes(), 'runtime module lost its signature')
        require(b'~Module signature appended~' not in detached.read_bytes(), 'debug module contains a signature')
        build_link(debug_root + 'lib/modules/' + abi + '/' + relative.as_posix(), debug_id)
        pairs.append({'module': relative.as_posix(), 'build_id': debug_id})
        if temporary:
            temporary.unlink()
    require(len(list(debug_modules.rglob('*.ko'))) == len(pairs), 'runtime/debug inventories differ')
    # Debian also publishes build-ID links for compatibility VDSOs.
    for name, value in list(entries.items()):
        if value['type'] == 'file' and '/vdso/' in name:
            # Debian's VDSO contract includes both compat ELF32 and native
            # ELF64 (x32 even uses EM_X86_64 with ELFCLASS32). Read GNU notes
            # with the declared binutils rather than applying kernel ABI checks.
            import subprocess
            import re
            notes = subprocess.check_output([config['readelf'], '-n', value['contents']], text=True)
            match = re.search(r'Build ID: ([0-9a-f]+)', notes)
            require(match, 'VDSO has no build ID')
            build_link(name, match[1])
    Path(config['install_outputs']['debug_validation']).write_text(json.dumps({
        'kernel_build_id': kernel_id, 'module_count': len(pairs),
        'module_build_ids_sha256': hashlib.sha256(json.dumps(pairs, sort_keys=True).encode()).hexdigest()},
        indent=2, sort_keys=True) + '\n')
    return entries


def runtime_layout(config, generated):
    entries = tree_entries(config, 'runtime')
    entries = {name: value for name, value in entries.items()
               if name != 'lib/firmware' and not name.startswith('lib/firmware/')}
    abi = kernel_abi(config['architecture'])
    entries['boot/vmlinuz-' + abi] = file_entry(config['raw_files']['image'])
    lines = Path(config['raw_files']['config']).read_text().splitlines(keepends=True)
    import re
    config_text = ''.join(line for line in lines if not re.match(
        r'CONFIG_(MODULE_SIG_(ALL|KEY)|SYSTEM_TRUSTED_KEYS|BUILD_SALT)[ =]', line))
    entries['boot/config-' + abi] = write_file(generated, 'config', config_text)
    entries['boot/System.map-' + abi] = write_file(generated, 'System.map',
        'ffffffffffffffff B The real System.map is in the linux-image-<version>-dbg package\n')
    return entries


def finalize(entries):
    result = {'.': {'type': 'dir', 'mode': 0o755}}
    for name, value in entries.items():
        name = str(PurePosixPath(name))
        require(not name.startswith('/') and '..' not in PurePosixPath(name).parts, 'unsafe installation path')
        if name == 'lib' or name.startswith('lib/'):
            name = 'usr/' + name
        value = dict(value)
        if value.pop('link_relative', False) or value.pop('normalized_link', False):
            value['link'] = os.path.relpath(value['link'], '/' + str(PurePosixPath(name).parent))
        require(name not in result or result[name] == value, 'conflicting installation path: ' + name)
        result[name] = value
    for name in list(result):
        for parent in PurePosixPath(name).parents:
            result.setdefault(str(parent), {'type': 'dir', 'mode': 0o755})
    return result


def install(config):
    started = time.monotonic()
    role = config['role']
    outputs = config['install_outputs']
    for value in outputs.values():
        for path in (value.values() if isinstance(value, dict) else [value]):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    generated = Path(outputs['supplemental']).absolute()
    generated.mkdir(parents=True, exist_ok=True)
    receipt = json.loads(Path(config['receipt']).read_text())
    config['source_date_epoch'] = receipt['source_date_epoch']
    require(receipt.get('schema') == 4 and receipt.get('compilation_completed') is True
            and receipt['architecture'] == config['architecture']
            and receipt['host_architecture'] == config['host_architecture']
            and receipt['kernel_config'] == config['kernel_config'],
            'installation requires a matching successful compilation')
    metadata = generate_metadata(config, generated, {})
    config['all_kernel_arches'] = metadata['all_kernel_arches']
    entries = (runtime_layout(config, generated) if role == 'runtime' else
               debug_layout(config, generated) if role == 'debug' else layout(config, role, generated))
    for name, value in metadata['entries'].items():
        require(name not in entries, 'metadata overlaps installed payload: ' + name)
        entries[name] = value
    entries = finalize(entries)
    lines = ['#mtree']
    for name, value in sorted(entries.items()):
        line = escape('./' + name) + ' type=' + value['type'] + ' uid=0 gid=0 mode=%o time=%d' % (
            value['mode'], 0 if name == '.' else config['source_date_epoch'])
        for key in ('contents', 'link'):
            if key in value:
                val = os.path.relpath(value[key], Path.cwd()) if key == 'contents' else value[key]
                line += ' ' + key + '=' + escape(val)
        lines.append(line)
    Path(outputs['data']).write_text('\n'.join(lines) + '\n')
    fields = metadata['fields']
    if role == 'kbuild':
        with tempfile.TemporaryDirectory(prefix='shlibs-', dir=generated.parent) as temporary:
            shlibs = compute_shlibs(config, list(config['kbuild_tools'].values()), Path(temporary))
        for key, value in list(fields.items()):
            fields[key] = value.replace('${shlibs:Depends}', shlibs)
    require(not any('${' in str(value) for value in fields.values()), 'unresolved package substitution')
    sums = None
    if role == 'runtime':
        import importlib.util
        helper = importlib.util.spec_from_file_location('sonic_deb_mtree', config['mtree_helper'])
        module = importlib.util.module_from_spec(helper)
        helper.loader.exec_module(module)
        _, installed_size, sums = module.summarize_mtree(Path(outputs['data']), config['architecture'])
        fields['Installed-Size'] = str(installed_size)
    control_lines = []
    for key, value in fields.items():
        lines = str(value).splitlines()
        control_lines.append(key + ': ' + lines[0])
        control_lines += [line if line.startswith((' ', '\t')) else ' ' + (line or '.') for line in lines[1:]]
    control = '\n'.join(control_lines) + '\n'
    Path(outputs['control']).write_text(control)
    controls = {'control': (control.encode(), 0o644)}
    if sums is not None:
        controls['md5sums'] = (sums.encode(), 0o644)
    for member, destination in outputs['control_files'].items():
        source = Path(metadata['control_files'][member])
        Path(destination).write_bytes(source.read_bytes())
        controls[member] = (source.read_bytes(), 0o755)
    with tarfile.open(outputs['control_tar'], 'w', format=tarfile.GNU_FORMAT) as archive:
        for name, (content, mode) in controls.items():
            info = tarfile.TarInfo('./' + name)
            info.size, info.mode, info.mtime = len(content), mode, config['source_date_epoch']
            info.uid = info.gid = 0
            archive.addfile(info, io.BytesIO(content))
    if role == 'runtime':
        boot = Path(outputs['boot']) / 'boot'
        boot.mkdir(parents=True, exist_ok=True)
        records = {}
        for kind in ('vmlinuz', 'config', 'System.map'):
            name = kind + '-' + kernel_abi(config['architecture'])
            source = Path(entries['boot/' + name]['contents'])
            shutil.copyfile(source, boot / name)
            records[kind] = {'path': 'boot/' + name, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
        Path(outputs['metadata']).write_text(json.dumps({'schema': 1, 'architecture': config['architecture'],
            'kernel_release': kernel_abi(config['architecture']),
            'module_directory': 'usr/lib/modules/' + kernel_abi(config['architecture']), 'boot': records}, sort_keys=True) + '\n')
    print('KERNEL_PHASE_SECONDS native-install-' + role + ' ' + str(round(time.monotonic() - started, 3)), flush=True)


if __name__ == '__main__':
    install(json.loads(Path(sys.argv[1]).read_text()))
