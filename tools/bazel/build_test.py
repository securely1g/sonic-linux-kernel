#!/usr/bin/env python3
"""Check the kernel launcher's bounded worker and resolution command."""

import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import time
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build
import direct_permissions


class KernelLauncherTest(unittest.TestCase):
    def test_native_architecture_rejects_emulated_or_cross_configuration(self):
        for architecture, machine in (("amd64", "x86_64"), ("arm64", "aarch64")):
            with self.subTest(architecture=architecture), patch.object(
                    build.os, "uname", return_value=os.uname_result(("Linux", "runner", "", "", machine))):
                self.assertEqual(build.native_architecture(), architecture)
                self.assertEqual(build.native_architecture(architecture), architecture)
                other = "arm64" if architecture == "amd64" else "amd64"
                with self.assertRaisesRegex(ValueError, "must match"):
                    build.native_architecture(other)
        with patch.object(build.os, "uname", return_value=os.uname_result(("Linux", "runner", "", "", "riscv64"))):
            with self.assertRaisesRegex(ValueError, "native Linux"):
                build.native_architecture()

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
                target="@sonic_linux_kernel//:kernel_artifacts", worker_image=build.WORKER_IMAGE,
                architecture="amd64",
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
            for architecture, platform in (("amd64", "x86_64_trixie"), ("arm64", "aarch64_trixie")):
                args.architecture = architecture
                command = build.worker_command(args, root / "bazel", "kernel-test")
                self.assertIn("--platform=linux/" + architecture, command)
                for line in command[-1].splitlines():
                    if " build " in line or " cquery " in line:
                        self.assertIn("--host_platform=@sonic_build_infra//platforms:" + platform, shlex.split(line))
                        self.assertIn("--platforms=@sonic_build_infra//platforms:" + platform, shlex.split(line))
                self.assertIn(build.ARCHITECTURES[architecture]["machine"], command[-1])


class DirectLauncherTest(unittest.TestCase):
    def fixture(self, root):
        workspace, work = root / "consumer ' $literal", root / "work ' $literal"
        workspace.mkdir(); work.mkdir()
        (workspace / "MODULE.bazel").write_text('module(name="fixture")\n')
        shims = root / "shims"; shims.mkdir()
        chown = shims / "chown"
        chown.write_text("#!/usr/bin/python3\nimport json,os,sys\nwith open(os.environ['FIXTURE_CHOWN'], 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n")
        chown.chmod(0o755)
        probe = root / "permission-probe"
        probe.write_text("#!/usr/bin/python3\nimport os,sys\nsys.exit(int(os.environ.get('FIXTURE_PERMISSION_STATUS', '0')))\n")
        probe.chmod(0o755)
        bazel = root / "bazel ' $literal"
        bazel.write_text("""#!/usr/bin/python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['FIXTURE_BAZEL'], 'a') as f: f.write(json.dumps(args)+'\\n')
command=next(value for value in args if value in ('build','cquery','mod','shutdown'))
if command=='build':
    lock=Path.cwd() / 'MODULE.bazel.lock'
    lock.write_text('{}')
    lock.chmod(0o600)
    if os.environ.get('FIXTURE_BUILD_SLEEP'):
        import time
        time.sleep(30)
    if os.environ.get('FIXTURE_BUILD_STATUS'): sys.exit(int(os.environ['FIXTURE_BUILD_STATUS']))
    out=Path(next(value.split('=',1)[1] for value in args if value.startswith('--output_user_root='))) / 'private/execroot/_main/bazel-out'
    out.mkdir(parents=True)
    (out / 'kernel.deb').write_bytes(b'fixture kernel output')
    prefix=next(value.split('=',1)[1] for value in args if value.startswith('--symlink_prefix='))
    Path(prefix+'out').symlink_to(out)
elif command=='cquery': print('bazel-out/kernel.deb')
elif command=='mod': print('{}')
""")
        bazel.chmod(0o755)
        args = argparse.Namespace(workspace=workspace, work_dir=work,
            repository_cache=root / "shared root cache/repository", disk_cache=root / "shared root cache/disk",
            remote_cache=None, remote_cache_read_only=True, java_trust_store=root / "trust ' $literal/cacerts",
            ca_bundle=root / "trust ' $literal/ca.pem", distdir=root / "archives ' $literal",
            module_override=[("sonic-linux-kernel", root / "source ' $literal")], bazel_arg=[],
            target="@sonic_linux_kernel//:kernel_packages", worker_image=build.WORKER_IMAGE,
            architecture=build.native_architecture())
        env = dict(os.environ, PATH=str(shims) + os.pathsep + os.environ['PATH'],
                   FIXTURE_BAZEL=str(root / 'bazel-calls.jsonl'), FIXTURE_CHOWN=str(root / 'chown-calls.jsonl'))
        return args, bazel, probe, env

    def run_script(self, args, bazel, probe, env):
        with patch.object(build.os, "geteuid", return_value=0), patch.object(build.sys, "executable", str(probe)):
            command = build.direct_command(args, bazel)
        self.assertEqual(command[:2], ["/bin/bash", "-c"])
        subprocess.run(["bash", "-n", "-c", command[-1]], check=True)
        return subprocess.run(command, text=True, capture_output=True, env=env)

    def test_actual_paths_quoting_output_resolution_and_bounded_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            result=self.run_script(args,bazel,probe,env)
            self.assertEqual(result.returncode,0,result.stderr)
            output=Path((args.work_dir / 'output-paths.txt').read_text().strip())
            self.assertTrue(output.is_relative_to(args.work_dir / 'output'))
            self.assertEqual(output.read_bytes(),b'fixture kernel output')
            calls=[json.loads(line) for line in Path(env['FIXTURE_BAZEL']).read_text().splitlines()]
            self.assertEqual([next(x for x in a if x in ('build','cquery','mod','shutdown')) for a in calls],['build','cquery','mod','shutdown'])
            for invocation in calls:
                self.assertIn('--nosystem_rc',invocation); self.assertIn('--nohome_rc',invocation)
            for option in ('--repository_cache='+str(args.repository_cache), '--disk_cache='+str(args.disk_cache),
                           '--distdir='+str(args.distdir), '--override_module=sonic-linux-kernel='+str(args.module_override[0][1]),
                           '--repo_env=SSL_CERT_FILE='+str(args.ca_bundle)):
                self.assertIn(option,calls[0])
            ownership=[json.loads(line) for line in Path(env['FIXTURE_CHOWN']).read_text().splitlines()]
            self.assertEqual([row[-1] for row in ownership],[str(args.work_dir/'output'),str(args.workspace/'MODULE.bazel.lock'),str(args.work_dir)])
            self.assertEqual(ownership[-1][1],str(os.getuid())+':'+str(os.getgid()))

    def test_failed_build_preserves_error_and_shuts_down_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            env['FIXTURE_BUILD_STATUS']='23'
            result=self.run_script(args,bazel,probe,env)
            self.assertEqual(result.returncode,23,result.stderr)
            calls=Path(env['FIXTURE_BAZEL']).read_text()
            self.assertIn('"shutdown"',calls); self.assertNotIn('"cquery"',calls)
            self.assertFalse((args.work_dir/'output-paths.txt').exists())

    def test_permission_failure_prevents_bazel_and_returns_work_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            env['FIXTURE_PERMISSION_STATUS']='42'
            result=self.run_script(args,bazel,probe,env)
            self.assertEqual(result.returncode,42,result.stderr)
            self.assertFalse(Path(env['FIXTURE_BAZEL']).exists())
            ownership=[json.loads(line) for line in Path(env['FIXTURE_CHOWN']).read_text().splitlines()]
            self.assertEqual(ownership[-1][-1],str(args.work_dir))

    def test_redirected_output_directory_does_not_start_or_stop_another_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            outside=root/'outside'; outside.mkdir()
            (args.work_dir/'output').symlink_to(outside,target_is_directory=True)
            result=self.run_script(args,bazel,probe,env)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Invalid Bazel output directory',result.stderr)
            self.assertFalse(Path(env['FIXTURE_BAZEL']).exists())

    def test_private_generated_lock_is_returned_without_chowning_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            with patch.object(build.os,'geteuid',return_value=0), patch.object(build.sys,'executable',str(probe)):
                command=build.direct_command(args,bazel)
            result=subprocess.run(command,env=env,text=True,capture_output=True,umask=0o077)
            self.assertEqual(result.returncode,0,result.stderr)
            lock=args.workspace/'MODULE.bazel.lock'
            self.assertEqual(lock.stat().st_mode & 0o777,0o600)
            ownership=[json.loads(line) for line in Path(env['FIXTURE_CHOWN']).read_text().splitlines()]
            self.assertIn(['-h',str(os.getuid())+':'+str(os.getgid()),'--',str(lock)],ownership)
            self.assertNotIn(str(args.workspace),[row[-1] for row in ownership])

    def test_generated_lock_symlink_fails_before_bazel_or_external_chown(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            outside=root/'outside-lock'; outside.write_text('unchanged')
            (args.workspace/'MODULE.bazel.lock').symlink_to(outside)
            result=self.run_script(args,bazel,probe,env)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Invalid generated module lock',result.stderr)
            self.assertFalse(Path(env['FIXTURE_BAZEL']).exists())
            self.assertEqual(outside.read_text(),'unchanged')
            ownership=[json.loads(line) for line in Path(env['FIXTURE_CHOWN']).read_text().splitlines()]
            self.assertNotIn(str(outside),[row[-1] for row in ownership])

    def test_nonroot_uses_noninteractive_sudo_without_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            with patch.object(build.os,'geteuid',return_value=1000):
                command=build.direct_command(args,bazel)
            self.assertEqual(command[:2],['sudo','-n'])
            self.assertNotIn('docker',command)
            self.assertEqual(command[4:6],['/bin/bash','-c'])

    def test_cache_directories_are_created_only_after_elevation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            with patch.object(Path,'mkdir',side_effect=PermissionError('root-owned cache parent')):
                command=build.direct_command(args,bazel)
            self.assertIn('(umask 022; mkdir -p -- ',command[-1])
            result=self.run_script(args,bazel,probe,env)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(args.repository_cache.is_dir()); self.assertTrue(args.disk_cache.is_dir())

    def test_termination_shuts_down_the_private_server_and_restores_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            env['FIXTURE_BUILD_SLEEP']='1'
            with patch.object(build.os,'geteuid',return_value=0), patch.object(build.sys,'executable',str(probe)):
                command=build.direct_command(args,bazel)
            process=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
            try:
                deadline=time.monotonic()+5
                while not Path(env['FIXTURE_BAZEL']).exists() and time.monotonic()<deadline:
                    time.sleep(0.01)
                self.assertTrue(Path(env['FIXTURE_BAZEL']).exists())
                os.killpg(process.pid,signal.SIGTERM)
                _,stderr=process.communicate(timeout=10)
                self.assertEqual(process.returncode,143,stderr)
                calls=Path(env['FIXTURE_BAZEL']).read_text()
                self.assertIn('"shutdown"',calls)
                ownership=[json.loads(line) for line in Path(env['FIXTURE_CHOWN']).read_text().splitlines()]
                self.assertEqual(ownership[-1][-1],str(args.work_dir))
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL); process.wait()

    def test_direct_invocation_records_mode_without_a_worker_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); args,bazel,probe,env=self.fixture(root)
            argv=['build.py','--execution-mode','direct','--workspace',str(args.workspace),'--work-dir',str(args.work_dir),
                  '--repository-cache',str(args.repository_cache)]
            with patch.dict(os.environ,env), patch.object(build.sys,'argv',argv), patch.object(build.sys,'executable',str(probe)), \
                 patch.object(build.os,'geteuid',return_value=0), patch.object(build,'bazel_binary',return_value=bazel):
                self.assertEqual(build.main(),0)
            receipt=json.loads((args.work_dir/'invocation.json').read_text())
            self.assertEqual(receipt['execution_mode'],'direct'); self.assertIsNone(receipt['worker'])
            self.assertEqual(receipt['work_dir'],str(args.work_dir)); self.assertEqual(receipt['workspace'],str(args.workspace))
            self.assertEqual(receipt['repository_cache'],str(args.repository_cache))
            self.assertEqual(receipt['caller_uid'],os.getuid()); self.assertEqual(receipt['execution_uid'],0)

    def test_permission_probe_rejects_nonroot_before_touching_work(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(direct_permissions.os,'geteuid',return_value=1000):
            with self.assertRaisesRegex(PermissionError,'root or noninteractive sudo'):
                direct_permissions.check(Path(directory))
            self.assertEqual(list(Path(directory).iterdir()),[])


if __name__ == "__main__":
    unittest.main()
