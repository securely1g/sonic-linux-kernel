"""Small source transformations required by Debian's multi-ELF kbuild tools."""
import argparse
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('header', 'offsets', 'options'))
    parser.add_argument('output', type=Path)
    parser.add_argument('inputs', type=Path, nargs='+')
    args = parser.parse_args()
    if args.mode == 'header':
        # Debian's variant headers include the shared file through ../. Flatten
        # that include without replicating a directory tree of source inputs.
        body = '\n'.join(re.sub(r'^#include "\.\./(?:types|elfconfig)\.h"\n?', '', p.read_text(), flags=re.M)
                         for p in args.inputs)
    elif args.mode == 'offsets':
        lines = ['#define __DEVICEVTABLE_OFFSETS_H__']
        for line in args.inputs[0].read_text().splitlines():
            match = re.match(r'\s*\.ascii\s+"(->.*?)"', line)
            if match is None:
                continue
            record = match[1]
            if record.startswith('->#'):
                lines.append('/* ' + record[3:] + ' */')
            else:
                match = re.match(r'->(\S+)\s+[$#]*(\S+)\s+(.*)', record)
                if match:
                    lines.append('#define %s %s /* %s */' % match.groups())
        body = '\n'.join(lines)
    else:
        match = re.search(r'getopt\(argc, argv, "([\w:]*?)"\)', args.inputs[0].read_text())
        if match is None:
            raise ValueError('modpost getopt specification missing')
        options = match[1]
        body = '#define GETOPT_OPTIONS "%s"\n#define GETOPT_CASE %s' % (
            options, ' '.join("case '%s':" % c for c in options if c not in ':T'))
    args.output.write_text(body + '\n')


if __name__ == '__main__':
    main()
