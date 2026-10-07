#!/usr/bin/env python3
"""Exercise the public kernel artifact boundary with secret-bearing fixtures."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect_ci_artifacts as artifacts
import kernel_action

SENTINEL = "SENSITIVE_FIXTURE_DO_NOT_PUBLISH"
REVISION = "1" * 40


def digest(value):
    return hashlib.sha256(value).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fixture(root):
    private = root / "private"
    verified = private / "verified"
    verified.mkdir(parents=True)
    inventory = [{"name": "Makefile", "mode": 0o644, "sha256": digest(b"source")}]
    archives = sorted([
        {"name": name, "sha256": digest(name.encode())} for name in (
            "linux_6.12.41-1.dsc", "linux_6.12.41.orig.tar.xz", "linux_6.12.41-1.debian.tar.xz",
        )
    ], key=lambda item: item["name"])
    packages = []
    for index, name in enumerate(sorted(kernel_action.PACKAGE_NAMES)):
        # These bytes are deliberately not Debian packages. The test exercises
        # copying and hashing and never invokes a package creation tool.
        content = ("fake-package-bytes-" + str(index)).encode()
        (verified / name).write_bytes(content)
        package, version, architecture = name.removesuffix(".deb").rsplit("_", 2)
        packages.append({"name": name, "sha256": digest(content), "size": len(content),
                         "package": package, "version": version, "architecture": architecture})
    inputs = [digest(b"tool")]
    tools = {"schema_version": 1, "kind": "debian-build-tools", "architecture": "amd64",
             "input_sha256": inputs, "packages": {"python3": "3.13.5-1"},
             "identity_sha256": digest(json.dumps({"architecture": "amd64", "inputs": inputs}, sort_keys=True).encode())}
    manifest = {**artifacts.CONFIGURATION, "source_archives": archives, "source_files": inventory,
                "source_tree_sha256": kernel_action.source_tree_sha256(inventory), "build_tools": tools,
                "packages": packages, "created_packages": [dict(record, exported=True) for record in packages]}
    write_json(verified / artifacts.MANIFEST, manifest)
    proof = {"schema": 1, "result": "passed", "cold_compiled": True,
             "consumer_kernel_runner": "remote cache hit", "consumer_kernel_cache_hit": True,
             "kernel_compilation_skipped": True,
             "outputs_sha256": {path.name: digest(path.read_bytes()) for path in verified.iterdir()},
             "cold_metrics": {"totalTime": "12.3s", "executionWallTime": "12.1s", "inputFiles": "3",
                              "environment": {"TOKEN": SENTINEL}, "diagnostic": SENTINEL},
             "hit_metrics": {"totalTime": "0.8s", "fetchTime": SENTINEL, "inputBytes": "42"},
             "environmentVariables": [{"name": "TOKEN", "value": SENTINEL}]}
    write_json(verified / "cache-proof.json", proof)
    module = {"key": "rules_python@1.1.0", "name": "rules_python", "version": "1.1.0",
              "dependencies": [], "environment": {"TOKEN": SENTINEL}}
    kernel = {"key": "sonic-linux-kernel@_", "name": "sonic-linux-kernel", "version": "0.0.1",
              "dependencies": [module], "failureDetail": SENTINEL}
    graph = {"key": "<root>", "name": "sonic-kernel-cache-consumer", "version": "", "root": True,
             "dependencies": [kernel], "clientEnv": [SENTINEL]}
    prefix = "https://bcr.bazel.build/modules/rules_python/1.1.0/"
    lock = {"lockFileVersion": 24, "registryFileHashes": {
                prefix + "MODULE.bazel": digest(b"module"), prefix + "source.json": digest(b"source-json"),
                "https://example.test/" + SENTINEL: digest(b"unselected"),
            }, "moduleExtensions": {"private": {"envVariables": {"TOKEN": SENTINEL}}},
            "selectedYankedVersions": {"private": SENTINEL}}
    for run in ("cold", "hit"):
        write_json(private / (run + "-consumer") / "MODULE.bazel.lock", lock)
        write_json(private / run / "module-graph.json", graph)
        (private / run / "module-graph.exit-code").write_text("0\n")
        for name in ("build.log", "execution.json", "bep.json", "profile.json.gz", "invocation.json"):
            (private / run / name).write_text(SENTINEL)
    (private / "cache.log").write_text(SENTINEL)
    (private / "unselected-secret-file").write_text(SENTINEL)
    return private, (REVISION, inventory, archives)


class ArtifactTest(unittest.TestCase):
    def collect(self, private, expected, output, status="success"):
        with patch.object(artifacts, "checkout_inputs", return_value=expected):
            return artifacts.collect(private, private.parent / "source", output, status)

    def update_manifest(self, private, change):
        path = private / "verified" / artifacts.MANIFEST
        manifest = json.loads(path.read_text())
        change(manifest)
        write_json(path, manifest)
        proof_path = private / "verified/cache-proof.json"
        proof = json.loads(proof_path.read_text())
        proof["outputs_sha256"][artifacts.MANIFEST] = digest(path.read_bytes())
        write_json(proof_path, proof)

    def test_publishes_only_verified_outputs_and_allowlisted_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, expected = fixture(root)
            output = root / "public"
            result = self.collect(private, expected, output)
            self.assertEqual(result, {"result": "passed", "published_file_count": 7})
            self.assertEqual({path.name for path in output.iterdir()},
                             kernel_action.PACKAGE_NAMES | {artifacts.MANIFEST, "validation.json", "resolution.json"})
            for path in output.iterdir():
                self.assertNotIn(SENTINEL.encode(), path.read_bytes())
                self.assertFalse(path.is_symlink())
            for name in kernel_action.PACKAGE_NAMES | {artifacts.MANIFEST}:
                self.assertEqual((output / name).read_bytes(), (private / "verified" / name).read_bytes())
            validation = json.loads((output / "validation.json").read_text())
            self.assertEqual(validation["checkout_revision"], REVISION)
            self.assertEqual(validation["cache_proof"]["cold_metrics"],
                             {"totalTime": "12.3s", "executionWallTime": "12.1s", "inputFiles": 3})
            self.assertEqual(validation["cache_proof"]["hit_metrics"], {"totalTime": "0.8s", "inputBytes": 42})
            resolution = json.loads((output / "resolution.json").read_text())
            self.assertTrue(resolution["module_graph_complete"])
            self.assertTrue(resolution["module_extension_state_redacted"])
            self.assertEqual(len(resolution["modules"]), 3)
            self.assertEqual(resolution["cold"]["omitted_registry_entry_count"], 1)

    def test_rejects_unknown_manifest_fields_even_with_matching_hashes(self):
        changes = (
            lambda manifest: manifest.update(environment=SENTINEL),
            lambda manifest: manifest["build_tools"].update(environment=SENTINEL),
            lambda manifest: manifest["packages"][0].update(environment=SENTINEL),
            lambda manifest: manifest["source_files"][0].update(environment=SENTINEL),
        )
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private, expected = fixture(root)
                self.update_manifest(private, change)
                with self.assertRaises(artifacts.CollectionError):
                    self.collect(private, expected, root / "public")
                self.assertFalse((root / "public").exists())

    def test_rejects_duplicate_json_keys_before_copying_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, expected = fixture(root)
            path = private / "verified" / artifacts.MANIFEST
            path.write_text('{"schema": "' + SENTINEL + '",' + path.read_text()[1:])
            with self.assertRaises(artifacts.CollectionError):
                self.collect(private, expected, root / "public")
            self.assertFalse((root / "public").exists())

    def test_failed_job_publishes_only_fixed_status_without_parsing_raw_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, _expected = fixture(root)
            (private / "verified/cache-proof.json").write_text(SENTINEL)
            result = artifacts.collect(private, root / "absent-source", root / "public", "failure")
            self.assertEqual(result, {"result": "incomplete", "published_file_count": 1})
            content = (root / "public/validation.json").read_text()
            self.assertNotIn(SENTINEL, content)
            self.assertFalse(json.loads(content)["packages_published"])

    def test_rejects_symlink_inputs_and_existing_destinations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, expected = fixture(root)
            manifest = private / "verified" / artifacts.MANIFEST
            outside = root / "outside"
            shutil.copyfile(manifest, outside)
            manifest.unlink()
            manifest.symlink_to(outside)
            with self.assertRaises(artifacts.CollectionError):
                self.collect(private, expected, root / "public")
            self.assertFalse((root / "public").exists())
            output = root / "public"
            output.mkdir()
            (output / "existing").write_text(SENTINEL)
            with self.assertRaises(artifacts.CollectionError):
                self.collect(private, expected, output)
            self.assertEqual((output / "existing").read_text(), SENTINEL)

    def test_rejects_unmapped_modules_and_different_selected_resolution(self):
        for mutation in ("unmapped", "different"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private, expected = fixture(root)
                if mutation == "unmapped":
                    path = private / "hit/module-graph.json"
                    graph = json.loads(path.read_text())
                    node = graph["dependencies"][0]["dependencies"][0]
                    node.update(key="private_module@1.0.0", name="private_module", version="1.0.0")
                    write_json(path, graph)
                else:
                    path = private / "hit-consumer/MODULE.bazel.lock"
                    lock = json.loads(path.read_text())
                    lock["registryFileHashes"]["https://bcr.bazel.build/modules/rules_python/1.1.0/source.json"] = digest(b"different")
                    write_json(path, lock)
                with self.assertRaises(artifacts.CollectionError):
                    self.collect(private, expected, root / "public")
                self.assertFalse((root / "public").exists())

    def test_rejects_changed_package_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, expected = fixture(root)
            (private / "verified" / sorted(kernel_action.PACKAGE_NAMES)[0]).write_bytes(b"changed")
            with self.assertRaises(artifacts.CollectionError):
                self.collect(private, expected, root / "public")
            self.assertFalse((root / "public").exists())

    def test_cli_never_prints_untrusted_exception_details(self):
        output = io.StringIO()
        with patch.object(artifacts, "collect", side_effect=ValueError(SENTINEL)), \
                patch.object(sys, "argv", ["collect", "--private-root", "/tmp/private", "--source-root", "/tmp/source",
                                           "--output", "/tmp/public", "--job-status", "success"]), \
                contextlib.redirect_stderr(output):
            self.assertEqual(artifacts.main(), 1)
        self.assertNotIn(SENTINEL, output.getvalue())

    def test_workflow_uploads_only_the_collector_directory_after_success(self):
        workflow = (Path(__file__).parent.parent.parent / ".github/workflows/bazel.yml").read_text()
        steps = workflow.split("\n      - ")
        uploads = [step for step in steps if "uses: actions/upload-artifact@" in step]
        self.assertEqual(len(uploads), 1)
        self.assertIn("if: always() && steps.collect.outcome == 'success'", uploads[0])
        self.assertIn("path: ${{ runner.temp }}/kernel-artifacts", uploads[0])
        self.assertIn("if-no-files-found: error", uploads[0])
        self.assertNotIn("kernel-private", uploads[0])
        self.assertNotIn("path: |", uploads[0])
        builds = [step for step in steps if "python3 tools/bazel/build.py" in step]
        self.assertEqual(len(builds), 2)
        for run, step in zip(("cold", "hit"), builds):
            self.assertIn('--workspace "$RUNNER_TEMP/kernel-private/' + run + '-consumer"', step)
            self.assertIn("--target @sonic_linux_kernel//:kernel_packages", step)
            self.assertIn('> "$RUNNER_TEMP/kernel-private/' + run + '-launcher.log" 2>&1', step)


if __name__ == "__main__":
    unittest.main()
