#!/usr/bin/env python3
"""Exercise the public kernel artifact boundary with secret-bearing fixtures."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
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


def build_deb(path, members, *, control=None):
    """Build small, real DEBs using Debian's maintained packaging tool."""
    package, version, architecture = path.name.removesuffix(".deb").rsplit("_", 2)
    fields = {"Package": package, "Version": version, "Architecture": architecture,
              "Maintainer": "Kernel fixture <kernel@example.test>", "Description": "Kernel fixture"}
    fields.update(control or {})
    with tempfile.TemporaryDirectory(dir=path.parent.parent) as directory:
        root = Path(directory)
        (root / "DEBIAN").mkdir()
        (root / "DEBIAN/control").write_text("".join(key + ": " + value + "\n" for key, value in fields.items()))
        for name in members:
            payload = root / name
            payload.parent.mkdir(parents=True, exist_ok=True)
            payload.write_text("fixture-" + name)
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", "-Znone", str(root), str(path)],
                       check=True, capture_output=True)
    return {"name": path.name, "package": package, "version": version, "architecture": architecture,
            "size": path.stat().st_size, "sha256": digest(path.read_bytes())}


def validate_payload_file(path, kind, architecture="amd64"):
    with tarfile.open(path) as archive:
        return artifacts.validate_payload(archive, kind, architecture)


def fixture(root, architecture="amd64"):
    private = root / "private"
    verified = private / "verified"
    verified.mkdir(parents=True)
    inventory = [{"name": "Makefile", "mode": 0o644, "sha256": digest(b"source")}]
    archives = sorted([
        {"name": name, "sha256": digest(name.encode())} for name in (
            "linux_6.12.41-1.dsc", "linux_6.12.41.orig.tar.xz", "linux_6.12.41-1.debian.tar.xz",
        )
    ], key=lambda item: item["name"])
    records = []
    abi = artifacts.configuration(architecture)["kernel_abi"]
    members = {
        "runtime": ["boot/vmlinuz-" + abi, "boot/config-" + abi,
                    "usr/lib/modules/" + abi + "/kernel/example.ko.xz"],
        "debug": ["usr/lib/debug/boot/vmlinux-" + abi,
                  "usr/lib/debug/lib/modules/" + abi + "/kernel/example.ko",
                  "usr/src/debug/linux-" + abi + "/debian/build/source_sonic/init/main.c",
                  "usr/src/debug/linux-" + abi + "/debian/build/source_sonic/drivers/net/dummy.c"],
        "headers": ["usr/src/linux-headers-" + abi + "/" + name
                    for name in (".config", "Module.symvers", "Makefile")],
        "headers_common": ["usr/src/linux-headers-6.12.41+deb13-common-sonic/" + name
                           for name in ("Makefile", "include/linux/module.h")],
        "kbuild": ["usr/lib/linux-kbuild-6.12.41+deb13/scripts/mod/modpost"],
    }
    if architecture == "arm64":
        members["runtime"].append("usr/lib/linux-image-" + abi + "/marvell/armada-8040-db.dtb")
    for name, kind in sorted(kernel_action.package_kinds(architecture).items()):
        records.append({**build_deb(verified / name, members[kind]), "kind": kind})
    inputs = [digest(b"tool")]
    tools = {"schema_version": 1, "kind": "debian-build-tools", "architecture": architecture,
             "input_sha256": inputs, "packages": {"python3": "3.13.5-1"},
             "identity_sha256": digest(json.dumps({"architecture": architecture, "inputs": inputs}, sort_keys=True).encode())}
    manifest = {**artifacts.configuration(architecture), "source_archives": archives, "source_files": inventory,
                "source_tree_sha256": kernel_action.source_tree_sha256(inventory), "build_tools": tools,
                "packages": records, "created_packages": [{**record, "exported": True} for record in records], "debug": {"kernel_build_id": "12" * 20, "module_count": 1,
                    "module_build_ids_sha256": digest(b"module-build-ids")}}
    write_json(verified / artifacts.MANIFEST, manifest)
    proof = {"schema": 1, "architecture": architecture, "result": "passed", "cold_compiled": True,
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
    write_json(private / "debugger.json", {
        "schema": 1, "result": "passed", "architecture": architecture, "gdb": "GNU gdb (Debian 16.3-1) 16.3",
        "kernel": {"function": "start_kernel", "source": "debian/build/source_sonic/init/main.c",
                   "line": 900, "type_lookup": True},
        "module": {"function": "dummy_init", "source": "debian/build/source_sonic/drivers/net/dummy.c",
                   "line": 200, "type_lookup": False, "path": "kernel/example.ko"},
    })
    write_json(private / "installation.json", {
        "schema": 1, "result": "passed", "architecture": architecture,
        "installed_packages": sorted([
            {**{key: record[key] for key in ("package", "version", "architecture")}, "status": "install ok installed"}
            for record in records
        ], key=lambda item: item["package"]),
        "initramfs": True, "external_module": True, "module_vermagic": abi + " SMP preempt mod_unload modversions ",
    })
    (private / "cache.log").write_text(SENTINEL)
    (private / "unselected-secret-file").write_text(SENTINEL)
    return private, (REVISION, inventory, archives)


class ArtifactTest(unittest.TestCase):
    def test_checkout_inventory_matches_the_kernel_actions_declared_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            names = ["Makefile", "manage-config", "config.local/arm64/config",
                     "patches-debian/fix.patch", "patches-sonic/fix.patch", *kernel_action.EXTRA_SOURCES]
            for name in names:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("source fixture: " + name)
            declarations = {
                "dsc": "linux_6.12.41-1.dsc",
                "orig": "linux_6.12.41.orig.tar.xz",
                "debian": "linux_6.12.41-1.debian.tar.xz",
            }
            (source / "tools/bazel/sources.bzl").write_text("KERNEL_SOURCES = {\n" + "".join(
                repr(key) + ": struct(name=" + repr(name) + ", sha256=" + repr(digest(name.encode())) + "),\n"
                for key, name in declarations.items()) + "}\n")
            with patch.object(artifacts, "git", side_effect=[REVISION, "", "\n".join(names)]):
                revision, inventory, _archives = artifacts.checkout_inputs(source)
            self.assertEqual(revision, REVISION)
            self.assertEqual({item["name"] for item in inventory}, set(names))
            self.assertEqual(kernel_action.source_tree_sha256(inventory),
                             kernel_action.checkout_source_identity(source))

    def collect(self, private, expected, output, status="success", architecture="amd64"):
        with patch.object(artifacts, "checkout_inputs", return_value=expected):
            return artifacts.collect(private, private.parent / "source", output, status, architecture)

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
            self.assertEqual(result, {"result": "passed", "published_file_count": 8})
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

    def test_arm64_artifacts_match_the_requested_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, expected = fixture(root, "arm64")
            result = self.collect(private, expected, root / "public", architecture="arm64")
            self.assertEqual(result, {"result": "passed", "published_file_count": 8})
            validation = json.loads((root / "public/validation.json").read_text())
            self.assertEqual(validation["configuration"]["architecture"], "arm64")
            self.assertEqual(validation["configuration"]["kernel_abi"], kernel_action.kernel_abi("arm64"))
            self.assertEqual(validation["cache_proof"]["architecture"], "arm64")
            self.assertEqual(validation["debugger"]["architecture"], "arm64")
            self.assertEqual(validation["installation"]["architecture"], "arm64")
            self.assertTrue(validation["installation"]["initramfs"])

    def test_rejects_architecture_mismatches_in_tools_cache_and_debugger(self):
        for mismatch in ("requested", "tools", "proof", "debugger"):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private, expected = fixture(root, "arm64")
                if mismatch == "tools":
                    def change(manifest):
                        tools = manifest["build_tools"]
                        tools["architecture"] = "amd64"
                        tools["identity_sha256"] = digest(json.dumps(
                            {"architecture": "amd64", "inputs": tools["input_sha256"]}, sort_keys=True).encode())
                    self.update_manifest(private, change)
                elif mismatch in ("proof", "debugger"):
                    path = private / ("verified/cache-proof.json" if mismatch == "proof" else "debugger.json")
                    receipt = json.loads(path.read_text())
                    receipt["architecture"] = "amd64"
                    write_json(path, receipt)
                with self.assertRaises(artifacts.CollectionError):
                    self.collect(private, expected, root / "public",
                                 architecture="amd64" if mismatch == "requested" else "arm64")
                self.assertFalse((root / "public").exists())

    def test_rejects_deb_control_identity_mismatches(self):
        for field, value in (("Package", "linux-wrong"), ("Version", "6.12.41-2"), ("Architecture", "arm64")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / next(name for name, kind in kernel_action.package_kinds().items() if kind == "runtime")
                record = {**build_deb(path, [], control={field: value}), "kind": "runtime"}
                with self.assertRaisesRegex(artifacts.CollectionError, "control identity"):
                    artifacts.validate_deb(path, record)

    def test_rejects_another_architectures_payload_even_with_correct_control(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / next(name for name, kind in kernel_action.package_kinds("arm64").items() if kind == "runtime")
            wrong = kernel_action.kernel_abi("amd64")
            record = {**build_deb(path, ["boot/vmlinuz-" + wrong, "boot/config-" + wrong,
                                       "usr/lib/modules/" + wrong + "/kernel/example.ko.xz"]), "kind": "runtime"}
            with self.assertRaisesRegex(artifacts.CollectionError, "runtime package lacks kernel"):
                artifacts.validate_deb(path, record, "arm64")

    def test_arm64_runtime_requires_device_trees_for_its_abi(self):
        for wrong_abi in (None, kernel_action.kernel_abi("amd64")):
            with self.subTest(wrong_abi=wrong_abi), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "runtime.tar"
                abi = kernel_action.kernel_abi("arm64")
                names = ["boot/vmlinuz-" + abi, "boot/config-" + abi,
                         "usr/lib/modules/" + abi + "/kernel/example.ko.xz"]
                if wrong_abi:
                    names.append("usr/lib/linux-image-" + wrong_abi + "/vendor/board.dtb")
                with tarfile.open(path, "w") as archive:
                    for name in names:
                        member = tarfile.TarInfo(name)
                        member.size, member.mode = 1, 0o644
                        archive.addfile(member, io.BytesIO(b"x"))
                with self.assertRaisesRegex(artifacts.CollectionError, "device trees"):
                    validate_payload_file(path, "runtime", "arm64")

    def test_rejects_unknown_manifest_fields_even_with_matching_hashes(self):
        changes = (
            lambda manifest: manifest.update(environment=SENTINEL),
            lambda manifest: manifest["build_tools"].update(environment=SENTINEL),
            lambda manifest: manifest["packages"][0].update(environment=SENTINEL),
            lambda manifest: manifest["created_packages"][0].update(environment=SENTINEL),
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
            self.assertFalse(json.loads(content)["artifacts_published"])

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

    def test_rejects_changed_deb_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, expected = fixture(root)
            (private / "verified" / sorted(kernel_action.PACKAGE_NAMES)[0]).write_bytes(b"changed")
            with self.assertRaises(artifacts.CollectionError):
                self.collect(private, expected, root / "public")
            self.assertFalse((root / "public").exists())

    def test_rejects_wrong_package_kind_and_invalid_debug_inventory(self):
        changes = (
            lambda manifest: manifest["packages"][0].update(kind="other"),
            lambda manifest: manifest["debug"].update(module_count=0),
            lambda manifest: manifest["debug"].update(module_count=2),
            lambda manifest: manifest["debug"].update(kernel_build_id="not-a-build-id"),
            lambda manifest: manifest["debug"].update(environment=SENTINEL),
        )
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private, expected = fixture(root)
                self.update_manifest(private, change)
                with self.assertRaises(artifacts.CollectionError):
                    self.collect(private, expected, root / "public")
                self.assertFalse((root / "public").exists())

    def test_rejects_invalid_debs_unsafe_paths_and_devices(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.tar"
            invalid = Path(directory) / next(iter(kernel_action.PACKAGE_NAMES))
            invalid.write_bytes(b"not-a-deb")
            package, version, architecture = invalid.name.removesuffix(".deb").rsplit("_", 2)
            record = {"name": invalid.name, "package": package, "version": version, "architecture": architecture,
                      "kind": kernel_action.package_kinds()[invalid.name], "size": invalid.stat().st_size,
                      "sha256": digest(invalid.read_bytes())}
            with self.assertRaisesRegex(artifacts.CollectionError, "control identity"):
                artifacts.validate_deb(invalid, record)
            for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                               ("dev/device", tarfile.CHRTYPE)):
                with self.subTest(name=name):
                    with tarfile.open(path, "w") as archive:
                        member = tarfile.TarInfo(name)
                        member.type = kind
                        archive.addfile(member)
                    with self.assertRaises(artifacts.CollectionError):
                        validate_payload_file(path, "runtime")

    def test_rejects_duplicate_members_and_symlink_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.tar"
            for traversal in (False, True):
                with self.subTest(traversal=traversal):
                    with tarfile.open(path, "w") as archive:
                        first = tarfile.TarInfo("usr/include")
                        if traversal:
                            first.type, first.linkname = tarfile.SYMTYPE, "/tmp"
                        archive.addfile(first)
                        archive.addfile(tarfile.TarInfo("usr/include/file" if traversal else "./usr/include"))
                    with self.assertRaises(artifacts.CollectionError):
                        validate_payload_file(path, "runtime")

    def test_rejects_missing_or_invalid_debugger_receipt(self):
        for mutation in ("missing", "type", "path", "source", "absent-source", "absent-module", "unknown"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private, expected = fixture(root)
                path = private / "debugger.json"
                value = json.loads(path.read_text())
                if mutation == "missing":
                    path.unlink()
                else:
                    if mutation == "type":
                        value["kernel"]["type_lookup"] = 1
                    elif mutation == "path":
                        value["module"]["path"] = "kernel/../../outside.ko"
                    elif mutation == "source":
                        value["kernel"]["source"] = "/tmp/not-shipped.c"
                    elif mutation == "absent-source":
                        value["kernel"]["source"] = "missing.c"
                    elif mutation == "absent-module":
                        value["module"]["path"] = "kernel/not-shipped.ko"
                    else:
                        value["module"]["private"] = SENTINEL
                    write_json(path, value)
                with self.assertRaises(artifacts.CollectionError):
                    self.collect(private, expected, root / "public")
                self.assertFalse((root / "public").exists())

    def test_created_package_inventory_is_bounded_and_consistent(self):
        changes = (
            lambda manifest: manifest["created_packages"].append(manifest["created_packages"][0]),
            lambda manifest: manifest["created_packages"][0].update(exported=1),
            lambda manifest: manifest["created_packages"][0].update(exported=False),
            lambda manifest: manifest["created_packages"][0].update(version="6.12.41-2"),
            lambda manifest: manifest["created_packages"][0].update(sha256="0" * 64),
            lambda manifest: manifest["created_packages"][0].update(architecture="arm64"),
            lambda manifest: manifest["created_packages"].clear(),
        )
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private, expected = fixture(root)
                self.update_manifest(private, change)
                with self.assertRaises(artifacts.CollectionError):
                    self.collect(private, expected, root / "public")
                self.assertFalse((root / "public").exists())

    def test_records_but_does_not_export_other_created_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, expected = fixture(root)
            def change(manifest):
                manifest["created_packages"].append({
                    "name": "linux-libc-dev_6.12.41-1_all.deb", "package": "linux-libc-dev", "kind": "other",
                    "version": "6.12.41-1", "architecture": "all", "exported": False,
                    "size": 123, "sha256": digest(b"not-an-exported-package"),
                })
                manifest["created_packages"].sort(key=lambda item: item["name"])
            self.update_manifest(private, change)
            self.assertEqual(self.collect(private, expected, root / "public")["published_file_count"], 8)
            self.assertFalse((root / "public/linux-libc-dev_6.12.41-1_all.deb").exists())

    def test_installed_package_receipt_matches_actual_exported_identities(self):
        for mutation in ("missing", "version", "architecture", "status", "extra", "initramfs", "external_module", "vermagic", "unknown"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                private, expected = fixture(root)
                path = private / "installation.json"
                receipt = json.loads(path.read_text())
                if mutation == "missing":
                    path.unlink()
                else:
                    if mutation in ("version", "architecture", "status"):
                        receipt["installed_packages"][0][mutation] = "invalid"
                    elif mutation == "extra":
                        receipt["installed_packages"][0]["environment"] = SENTINEL
                    elif mutation in ("initramfs", "external_module"):
                        receipt[mutation] = 1
                    elif mutation == "vermagic":
                        receipt["module_vermagic"] = kernel_action.kernel_abi("arm64") + " SMP "
                    else:
                        receipt["environment"] = SENTINEL
                    write_json(path, receipt)
                with self.assertRaises(artifacts.CollectionError):
                    self.collect(private, expected, root / "public")
                self.assertFalse((root / "public").exists())

    def test_payload_accepts_safe_hardlinks_and_rejects_link_escapes(self):
        abi = kernel_action.kernel_abi()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload.tar"
            for target, linktype, valid in (("./boot/config-" + abi, tarfile.LNKTYPE, True),
                                            ("../outside", tarfile.LNKTYPE, False),
                                            ("/outside", tarfile.LNKTYPE, False),
                                            ("missing", tarfile.LNKTYPE, False),
                                            ("../../outside", tarfile.SYMTYPE, False)):
                with self.subTest(target=target, linktype=linktype):
                    with tarfile.open(path, "w") as archive:
                        for name in ("boot/vmlinuz-" + abi, "boot/config-" + abi,
                                     "usr/lib/modules/" + abi + "/kernel/example.ko.xz"):
                            member = tarfile.TarInfo(name)
                            member.size, member.mode = 1, 0o644
                            archive.addfile(member, io.BytesIO(b"x"))
                        link = tarfile.TarInfo("boot/config-link")
                        link.type, link.linkname = linktype, target
                        archive.addfile(link)
                    if valid:
                        self.assertEqual(len(validate_payload_file(path, "runtime")), 1)
                    else:
                        with self.assertRaises(artifacts.CollectionError):
                            validate_payload_file(path, "runtime")

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
