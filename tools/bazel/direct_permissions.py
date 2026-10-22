#!/usr/bin/env python3
"""Check the kernel action's existing root, chroot and device permissions."""

import os
from pathlib import Path
import stat
import sys
import tempfile


def check(work):
    if os.geteuid() != 0:
        raise PermissionError("direct kernel execution requires root or noninteractive sudo")
    # Probe in a disposable directory owned by this invocation. No host device
    # or root filesystem is mounted, and no device is read or written.
    with tempfile.TemporaryDirectory(prefix=".kernel-permissions-", dir=work) as directory:
        for name, minor in (("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)):
            path = Path(directory) / name
            os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(1, minor))
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
            os.close(fd)
        child = os.fork()
        if child == 0:
            try:
                os.chroot(directory)
                os.chdir("/")
            except OSError as error:
                print("Direct kernel chroot permission check failed: " + str(error), file=sys.stderr, flush=True)
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(child, 0)
        if status != 0:
            raise PermissionError("direct kernel execution requires permission to chroot")


if __name__ == "__main__":
    try:
        check(Path(sys.argv[1]))
    except OSError as error:
        raise SystemExit("Direct kernel permissions unavailable (root, chroot and mknod required): " + str(error))
