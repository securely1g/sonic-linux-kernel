#!/usr/bin/env python3
"""Check input identity and package handoff without compiling a sample kernel."""

import hashlib
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kernel_action as action


class KernelActionTest(unittest.TestCase):
    def test_source_identity_ignores_path_but_tracks_content_and_executable_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            first.write_text("same content")
            second.write_text("same content")
            inventory = lambda path: action.source_inventory([{"name": "manage-config", "path": str(path)}])
            self.assertEqual(action.source_tree_sha256(inventory(first)), action.source_tree_sha256(inventory(second)))
            second.chmod(0o755)
            self.assertNotEqual(action.source_tree_sha256(inventory(first)), action.source_tree_sha256(inventory(second)))
            second.chmod(0o644)
            second.write_text("changed configuration")
            self.assertNotEqual(action.source_tree_sha256(inventory(first)), action.source_tree_sha256(inventory(second)))

    def test_source_paths_cannot_escape_or_collide(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_text("source")
            for name in ("../escape", "/absolute"):
                with self.assertRaisesRegex(ValueError, "unsafe or duplicate"):
                    action.source_inventory([{"name": name, "path": str(path)}])
            with self.assertRaisesRegex(ValueError, "unsafe or duplicate"):
                action.source_inventory([{"name": "same", "path": str(path)}] * 2)

    def test_sandbox_links_are_copied_as_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_text("source")
            (root / "link").symlink_to(root / "input")
            action.source_inventory([{"name": "config.local/test", "path": str(root / "link")}], root / "out")
            output = root / "out/config.local/test"
            self.assertFalse(output.is_symlink())
            self.assertEqual(output.read_text(), "source")
            self.assertEqual(output.stat().st_mtime, action.SOURCE_DATE_EPOCH)

    def test_runtime_requires_declared_amd64_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = ["a" * 64, "b" * 64]
            identity = hashlib.sha256(json.dumps({"architecture": "amd64", "inputs": inputs},
                                                 sort_keys=True).encode()).hexdigest()
            marker = {"schema_version": 1, "kind": "debian-build-tools", "architecture": "arm64",
                      "identity_sha256": identity, "input_sha256": inputs, "packages": {"make": "4.4.1"}}
            (root / "kernel-runtime.json").write_text(json.dumps(marker))
            with self.assertRaisesRegex(ValueError, "AMD64"):
                action.runtime_identity(root)
            marker["architecture"] = "amd64"
            (root / "kernel-runtime.json").write_text(json.dumps(marker))
            self.assertEqual(action.runtime_identity(root), marker)
            marker["input_sha256"][0] = "c" * 64
            marker["input_sha256"].sort()
            (root / "kernel-runtime.json").write_text(json.dumps(marker))
            with self.assertRaisesRegex(ValueError, "identity digest"):
                action.runtime_identity(root)

    def test_action_rejects_missing_extra_and_duplicate_package_outputs(self):
        config = {"outputs": sorted(action.PACKAGE_NAMES), "manifest": "out/kernel-packages.json"}
        action.validate_outputs(config)
        for outputs in (config["outputs"][:-1], config["outputs"] + ["other.deb"],
                        [config["outputs"][0]] * 4):
            with self.subTest(outputs=outputs), self.assertRaisesRegex(ValueError, "four supported packages"):
                action.validate_outputs(dict(config, outputs=outputs))
        with self.assertRaisesRegex(ValueError, "kernel-packages.json"):
            action.validate_outputs(dict(config, manifest="out/other.json"))

    def test_package_metadata_must_match_filename_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "linux-kbuild-6.12.41+deb13_6.12.41-1_amd64.deb"
            path.write_bytes(b"only metadata is mocked; this is not a DEB")
            with patch.object(action, "in_chroot") as child:
                child.return_value.stdout = "Package: linux-kbuild-6.12.41+deb13\nVersion: 6.12.41-1\nArchitecture: amd64\n"
                self.assertEqual(action.package_record(path, root)["name"], path.name)
                child.return_value.stdout = "Package: linux-kbuild-6.12.41+deb13\nVersion: 6.12.41-2\nArchitecture: amd64\n"
                with self.assertRaisesRegex(ValueError, "version or architecture"):
                    action.package_record(path, root)


if __name__ == "__main__":
    unittest.main()
