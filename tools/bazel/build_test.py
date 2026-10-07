#!/usr/bin/env python3
"""Check the kernel launcher's bounded worker and resolution command."""

import argparse
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build


class KernelLauncherTest(unittest.TestCase):
    def test_worker_bounds_and_module_inspection_use_supported_options(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace, work, source = root / "consumer", root / "work", root / "source"
            for path in (workspace, work, source):
                path.mkdir()
            args = argparse.Namespace(
                workspace=workspace, work_dir=work, repository_cache=None, disk_cache=None,
                remote_cache="http://127.0.0.1:8080", remote_cache_read_only=True,
                java_trust_store=None, ca_bundle=None, distdir=None,
                module_override=[("sonic-linux-kernel", source)],
                bazel_arg=["--strategy=SonicKernelBuild=local"],
                target="@sonic_linux_kernel//:kernel_packages", worker_image=build.WORKER_IMAGE,
            )
            command = build.worker_command(args, root / "bazel", "kernel-test")
            self.assertIn("--cpus=4", command)
            self.assertIn("--memory=12g", command)
            self.assertIn("--memory-swap=12g", command)
            script = command[-1]
            subprocess.run(["bash", "-n", "-c", script], check=True)
            graph = next(line for line in script.splitlines() if " mod graph " in line)
            options = shlex.split(graph)
            self.assertIn("--override_module=sonic-linux-kernel=/module-overrides/sonic-linux-kernel", options)
            self.assertIn("--repository_cache=/repository-cache", options)
            self.assertIn("--lockfile_mode=off", options)
            self.assertFalse(any(option.startswith(("--strategy=", "--jobs=", "--platforms=", "--host_platform="))
                                 for option in options))
            self.assertIn("/work/module-graph.json", graph)
            self.assertIn("/work/module-graph.exit-code", script)


if __name__ == "__main__":
    unittest.main()
