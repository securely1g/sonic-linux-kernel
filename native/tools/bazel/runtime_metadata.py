"""Publish source-package metadata from finalized kernel installation outputs."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def publish(spec):
    tree = Path(spec['tree'])
    root = tree / spec['package']
    controls = root / 'DEBIAN'
    controls.mkdir(parents=True, exist_ok=True)
    with tarfile.open(spec['control']) as archive:
        archive.extractall(controls, filter='data')
    fields = {}
    for line in (controls / 'control').read_text().splitlines():
        if line.startswith((' ', '\t')):
            fields[key] += '\n' + line
        elif line:
            key, value = line.split(':', 1)
            fields[key] = value.strip()
    if fields['Package'] != spec['package'] or fields['Architecture'] != spec['architecture']:
        raise ValueError('Finalized control identity differs from declared kernel package')
    payload_sha = sha(spec['runtime'])
    control_files = {
        path.name: {'path': str(path.relative_to(tree)), 'sha256': sha(path),
                    'mode': format(path.stat().st_mode & 0o7777, '04o')}
        for path in sorted(controls.iterdir()) if path.is_file()
    }
    record = {'runtime_target': spec['runtime_target'], 'control_fields': {key: value for key, value in fields.items()
                                 if key not in {'Installed-Size', 'Status', 'Conffiles', 'SHA256', 'MD5sum'}},
              'payload_sha256': payload_sha, 'control_files': control_files}
    Path(spec['output']).write_text(json.dumps({
        'schema': 1, 'module': 'sonic-linux-kernel', 'architecture': spec['architecture'],
        'packages': {spec['package']: record},
    }, sort_keys=True, indent=2) + '\n')
    (tree / 'manifest.json').write_text(json.dumps({
        'schema': 1, 'architecture': spec['architecture'],
        'packages': [{'root': spec['package'], 'kind': 'source',
                      'payload_sha256': payload_sha, 'control_sha256': sha(controls / 'control'),
                      'omitted_analysis_links': []}],
    }, sort_keys=True) + '\n')


if __name__ == '__main__':
    publish(json.loads(Path(sys.argv[1]).read_text()))
