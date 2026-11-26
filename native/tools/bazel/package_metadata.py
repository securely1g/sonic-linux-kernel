"""Kernel package identity, documentation and scripts from declared Debian sources.

The source generator's data API is reused, without executing or emitting its
Make/debhelper workflow. Large payload files remain owned by the layout action.
"""
from contextlib import contextmanager
import dataclasses
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _load_generator(debian):
    # Imported source/configuration files are immutable action inputs.
    sys.dont_write_bytecode = True
    library = str(debian / 'lib/python')
    if library not in sys.path:
        sys.path.insert(0, library)
    path = debian / 'bin/gencontrol.py'
    spec = importlib.util.spec_from_file_location('kernel_source_gencontrol', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _serialize_fields(package):
    result = {}
    for field in dataclasses.fields(package):
        schema = field.metadata.get('deb822')
        value = getattr(package, field.name, None)
        if schema and schema.dump and value:
            result[schema.key] = schema.dump(value).strip()
    return result


def _architecture_matches(architectures, architecture):
    if not architectures:
        return True
    def match(value):
        if value in ('any', 'linux-any'):
            return True
        if value.startswith('any-'):
            return value[4:] == architecture
        return value == architecture
    positive = [value for value in architectures if not value.startswith('!')]
    negative = [value[1:] for value in architectures if value.startswith('!')]
    return (not positive or any(map(match, positive))) and not any(map(match, negative))


def _relation(package, name, architecture, substitutions):
    groups = []
    for group in getattr(package, name):
        alternatives = []
        for entry in group:
            if not _architecture_matches(entry.arches, architecture):
                continue
            if entry.restrictions:
                raise ValueError('Unexpected binary relationship build profile: ' + str(entry))
            value = entry.name
            if entry.operator is not None:
                value += ' (' + str(entry.operator) + ' ' + str(entry.version) + ')'
            value = re.sub(r'\$\{([^}]+)\}',
                           lambda found: substitutions[found[1]], value)
            if value:
                alternatives.append(value)
        if alternatives:
            groups.append(' | '.join(alternatives))
    return ', '.join(groups)


def _changes_policy(runtime):
    # These values belong to the fixed packaging-tool input, not to a sample
    # output. Preserve its trim policy without invoking the helper itself.
    source = (runtime / 'usr/bin/dh_installchangelogs').read_text()
    cutoff = re.search(r'CUTOFF_DATE_STR\s*=>\s*"([\d-]+)"', source)
    minimum = re.search(r'MIN_NUM_ENTRIES\s*=>\s*(\d+)', source)
    if not cutoff or not minimum:
        raise ValueError('Declared changelog trimming policy is not recognized')
    return datetime.fromisoformat(cutoff[1]).replace(tzinfo=timezone.utc), int(minimum[1])


def _trim_changes(text, package, cutoff, minimum=0, news=False):
    entries, current, oldest = [], [], None
    lines = text.splitlines(keepends=True)
    trimmed = False
    for index, line in enumerate(lines):
        current.append(line)
        footer = re.match(r'\s*--\s+.*?\s+<[^>]*>\s+(.*)$', line)
        if not footer:
            continue
        try:
            timestamp = parsedate_to_datetime(footer[1])
        except (TypeError, ValueError):
            return text, None
        if timestamp < cutoff and (news or len(entries) >= minimum):
            trimmed = index + 1 < len(lines)
            break
        entries.append(''.join(current))
        current = []
        oldest = timestamp
    result = ''.join(entries)
    if trimmed and not news:
        result += ('\n# Older entries have been removed from this changelog.\n'
                   '# To read the complete changelog use `apt changelog ' + package + '`.\n')
    return result, oldest


def generate_metadata(config, output_directory, entries=None):
    """Return source-derived fields, maintainer scripts and mtree payload entries.

    kbuild's shlibs:Depends is supplied through config['shlibs_depends'] after
    the caller's declared ELF dependency analysis. If absent it stays a substvar
    for runtime_packages to finalize; no dependency versions are inferred here.
    """
    output = Path(output_directory).absolute()
    output.mkdir(parents=True, exist_ok=True)
    debian = Path(config['debian_source']).absolute() / 'debian'
    recipe = Path(config['recipe_source']).absolute()
    runtime = Path(config['build_tools']).absolute()
    architecture = config['architecture']
    role = config['role']
    kernel_config = config['kernel_config']
    feature = kernel_config['KERNEL_FEATURESET']
    config_dirs = [debian / 'config', recipe / 'config.local']
    module = _load_generator(debian)
    with tempfile.TemporaryDirectory(prefix='kernel-metadata-', dir=output.parent) as temporary:
        generated = Path(temporary)
        (generated / 'debian').mkdir()
        (generated / 'debian/changelog').symlink_to(debian / 'changelog')
        with working_directory(generated):
            generator = module.Gencontrol(config_dirs=config_dirs,
                                          template_dirs=[str(debian / 'templates')])
            generator.do_source()
            generator.do_main()
            generator.do_extra()
        arch_config = next(arch for kernel in generator.config.kernelarchs
                           for arch in kernel.debianarchs if arch.name == architecture)
        feature_config = next(item for item in arch_config.featuresets
                              if item.name_featureset == feature)
        flavour_config = next(item for item in feature_config.flavours
                              if item.name == ('armmp' if architecture == 'armhf' else architecture))
        abi = kernel_config['KVERSION']
        names = {
            'runtime': 'linux-image-' + abi + ('' if architecture == 'armhf' else '-unsigned'),
            'debug': 'linux-image-' + abi + '-dbg',
            'headers': 'linux-headers-' + abi,
            'headers_common': 'linux-headers-' + generator.abiname + '-common-' + feature,
            'kbuild': 'linux-kbuild-' + generator.abiname,
        }
        name = names[role]
        package = generator.bundle.packages[name]
        fields = _serialize_fields(package)
        fields.pop('Build-Profiles', None)
        fields['Source'] = generator.changelog[0].source
        fields['Version'] = generator.version.complete
        fields['Architecture'] = 'all' if role == 'headers_common' else architecture
        source_fields = _serialize_fields(generator.bundle.source)
        for field in ('Maintainer', 'Section', 'Priority', 'Homepage'):
            if field not in fields and field in source_fields:
                fields[field] = source_fields[field]
        substitutions = {'source:Version': generator.version.complete,
                         'binary:Version': generator.version.complete,
                         'misc:Depends': '',
                         'shlibs:Depends': config.get('shlibs_depends', '${shlibs:Depends}')}
        for field in ('Built-Using', 'Provides', 'Pre-Depends', 'Depends', 'Recommends',
                      'Suggests', 'Replaces', 'Breaks', 'Conflicts'):
            attr = field.lower().replace('-', '_')
            if not hasattr(package, attr):
                continue
            value = _relation(package, attr, architecture, substitutions)
            if value:
                fields[field] = value
            else:
                fields.pop(field, None)

        payload = {}
        def source_file(destination, source, mode=0o644):
            payload[destination] = {'type': 'file', 'mode': mode, 'contents': str(Path(source).absolute())}
        def generated_file(destination, content, mode=0o644, compress=False):
            path = output / destination
            path.parent.mkdir(parents=True, exist_ok=True)
            if compress:
                with path.open('wb') as stream:
                    subprocess.run([str(runtime / 'bin/gzip'), '-9nc'], input=content.encode(), stdout=stream, check=True)
            else:
                path.write_text(content)
            path.chmod(mode)
            source_file(destination, path, mode)
        doc = 'usr/share/doc/' + name
        source_file(doc + '/copyright', debian / 'copyright')
        cutoff, minimum = _changes_policy(runtime)
        changelog, oldest = _trim_changes((debian / 'changelog').read_text(), name, cutoff, minimum)
        generated_file(doc + '/changelog.Debian.gz', changelog, compress=True)
        if role == 'headers_common':
            source_file(doc + '/README.Debian', debian / 'README.Debian')
        generated_debian = generated / 'debian'
        news = generated_debian / (name + '.NEWS')
        if news.is_file():
            content, _ = _trim_changes(news.read_text(), name, oldest, news=True) if oldest else (news.read_text(), None)
            if content:
                generated_file(doc + '/NEWS.Debian.gz', content, compress=True)
        lintian = generated_debian / (name + '.lintian-overrides')
        if lintian.is_file():
            generated_file('usr/share/lintian/overrides/' + name, lintian.read_text())
        control_files = {}
        for member in ('preinst', 'postinst', 'prerm', 'postrm'):
            source = generated_debian / (name + '.' + member)
            if source.is_file():
                destination = output / 'DEBIAN' / member
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(source.read_bytes())
                destination.chmod(0o755)
                control_files[member] = str(destination)
        if role == 'runtime':
            bug = 'usr/share/bug/' + name
            for source in sorted((debian / 'templates/image.bug').iterdir()):
                if source.is_file():
                    source_file(bug + '/' + source.name, source,
                                0o755 if source.stat().st_mode & 0o111 else 0o644)
            generated_file(bug + '/info', "RELEASE='" + abi + "'\nDISTRIBUTOR='Debian'\nSOURCEVERSION='" + generator.version.complete + "'\nPACKAGE_NAME='" + name + "'\nPACKAGE_VERSION='" + generator.version.complete + "'")
        all_arches = sorted({kernel.name for kernel in generator.config.kernelarchs
                             for arch in kernel.debianarchs for item in arch.featuresets
                             if feature in item.name})
        return {'fields': fields, 'control_files': control_files,
                'entries': payload, 'all_kernel_arches': all_arches,
                'kconfig': [str(directory / fragment) for fragment in flavour_config.config
                            for directory in config_dirs if (directory / fragment).exists()],
                'compiler': flavour_config.build.compiler,
                'kernel_stem': flavour_config.build.kernel_stem,
                'enable_vdso': flavour_config.build.enable_vdso}


def kernel_configuration_metadata(config):
    """Read the authoritative flavour/configuration inputs without running Make."""
    debian = Path(config['debian_source']).absolute() / 'debian'
    recipe = Path(config['recipe_source']).absolute()
    values = config['kernel_config']
    architecture = config['architecture']
    feature = values['KERNEL_FEATURESET']
    flavour = 'armmp' if architecture == 'armhf' else architecture
    module = _load_generator(debian)
    directories = [debian / 'config', recipe / 'config.local']
    with tempfile.TemporaryDirectory(prefix='kernel-configuration-', dir=Path.cwd()) as temporary:
        root = Path(temporary)
        (root / 'debian').mkdir()
        (root / 'debian/changelog').symlink_to(debian / 'changelog')
        with working_directory(root):
            generator = module.Gencontrol(config_dirs=directories,
                                          template_dirs=[str(debian / 'templates')])
        arch = next(arch for kernel in generator.config.kernelarchs
                    for arch in kernel.debianarchs if arch.name == architecture)
        featureset = next(item for item in arch.featuresets if item.name_featureset == feature)
        configuration = next(item for item in featureset.flavours if item.name == flavour)
        localversion = ('' if feature == 'none' else '-' + feature) + '-' + flavour
        fragments = []
        for fragment in configuration.config:
            for directory in directories:
                path = directory / fragment
                if path.name == 'config.sonic-platform-specific':
                    platform = path.with_name('config.sonic-' + values['CONFIGURED_PLATFORM'])
                    if platform.is_file():
                        path = platform
                if path.is_file():
                    fragments.append(str(path))
        return {'kconfig': fragments, 'compiler': configuration.build.compiler,
                'abi': generator.abiname, 'localversion': localversion,
                'enable_vdso': configuration.build.enable_vdso,
                'enable_signed': configuration.build.enable_signed,
                'kernel_arch': configuration.name_kernelarch,
                'kernel_stem': configuration.build.kernel_stem,
                'kernel_file': configuration.build.kernel_file,
                'compat_gnutype': configuration.build.compiler_gnutype_compat,
                'kconfig_options': ['-o', 'BUILD_SALT="' + generator.abiname + localversion + '"',
                                    '-o', 'MODULE_SIG_KEY="output/signing_key.pem"']}


def compute_shlibs(config, tool_paths, generated):
    """Resolve actual installed tool ELF dependencies using the declared database."""
    from kernel_action import packaging_database
    runtime = Path(config['build_tools']).absolute()
    root = Path(generated).absolute() / 'shlibs-analysis'
    root.mkdir(parents=True, exist_ok=True)
    database = root / 'dpkg'
    packaging_database(runtime, database)
    debian = root / 'debian'
    debian.mkdir()
    (debian / 'control').write_text('Source: kernel-tools-analysis\nSection: kernel\n'
                                   'Priority: optional\nMaintainer: Kernel build\n\n'
                                   'Package: kernel-tools-analysis\nArchitecture: any\n'
                                   'Description: Kernel tool dependency analysis\n')
    binaries = []
    for source in tool_paths:
        source = Path(source).absolute()
        with source.open('rb') as stream:
            header = stream.read(20)
        if len(header) >= 20 and header.startswith(b'\x7fELF'):
            order = 'little' if header[5] == 1 else 'big'
            if int.from_bytes(header[16:18], order) in (2, 3):
                binaries.append(source)
    if not binaries:
        return ''
    environment = {'PATH': str(runtime / 'bin'), 'LC_ALL': 'C.UTF-8', 'LANG': 'C.UTF-8',
                   'DPKG_ADMINDIR': str(database), 'DPKG_DATADIR': str(runtime / 'usr/share/dpkg'),
                   'DPKG_ORIGINS_DIR': str(runtime / 'etc/dpkg/origins'),
                   'DEB_HOST_ARCH': config['architecture']}
    multiarch = subprocess.check_output([str(runtime / 'bin/dpkg-architecture'),
                                        '-a' + config['architecture'], '-qDEB_HOST_MULTIARCH'],
                                       env=environment, text=True).strip()
    libraries = [runtime / 'usr/lib' / multiarch, runtime / 'lib' / multiarch,
                 runtime / 'usr/lib', runtime / 'lib']
    command = [str(runtime / 'bin/dpkg-shlibdeps'), '-O', '--admindir=' + str(database)]
    command += ['-l' + str(path) for path in libraries if path.is_dir()]
    command += ['-e' + str(path) for path in binaries]
    result = subprocess.check_output(command, cwd=root, env=environment, text=True)
    values = dict(line.split('=', 1) for line in result.splitlines() if '=' in line)
    return values.get('shlibs:Depends', '')
