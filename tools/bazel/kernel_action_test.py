#!/usr/bin/env python3
"""Check input identity and TAR handoff without compiling a sample kernel."""

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

    def test_runtime_requires_matching_architecture_and_input_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for architecture in action.ARCHITECTURES:
                with self.subTest(architecture=architecture):
                    inputs = ["a" * 64, "b" * 64]
                    identity = hashlib.sha256(json.dumps({"architecture": architecture, "inputs": inputs},
                                                         sort_keys=True).encode()).hexdigest()
                    marker = {"schema_version": 1, "kind": "debian-build-tools", "architecture": architecture,
                              "identity_sha256": identity, "input_sha256": inputs, "packages": {"make": "4.4.1"}}
                    (root / "kernel-runtime.json").write_text(json.dumps(marker))
                    self.assertEqual(action.runtime_identity(root, architecture), marker)
                    other = "arm64" if architecture == "amd64" else "amd64"
                    with self.assertRaisesRegex(ValueError, "must execute on " + other.upper()):
                        action.runtime_identity(root, other)
                    marker["input_sha256"][0] = "c" * 64
                    marker["input_sha256"].sort()
                    (root / "kernel-runtime.json").write_text(json.dumps(marker))
                    with self.assertRaisesRegex(ValueError, "identity digest"):
                        action.runtime_identity(root, architecture)

    def test_action_requires_runtime_debug_and_development_tars(self):
        config = {"outputs": sorted(action.ARTIFACT_NAMES), "manifest": "out/kernel-artifacts.json"}
        action.validate_outputs(config)
        for outputs in (config["outputs"][:-1], config["outputs"] + ["other.deb"],
                        [config["outputs"][0]] * 3):
            with self.subTest(outputs=outputs), self.assertRaisesRegex(ValueError, "exactly runtime, debug and development"):
                action.validate_outputs(dict(config, outputs=outputs))
        for architecture in action.ARCHITECTURES:
            action.validate_outputs(dict(config, architecture=architecture))
        with self.assertRaisesRegex(ValueError, "unsupported kernel architecture"):
            action.validate_outputs(dict(config, architecture="armhf"))
        with self.assertRaisesRegex(ValueError, "kernel-artifacts.json"):
            action.validate_outputs(dict(config, manifest="out/other.json"))

    def test_compile_recipe_selects_native_source_build_and_install_for_each_architecture(self):
        for architecture in action.ARCHITECTURES:
            with self.subTest(architecture=architecture):
                commands = action.compilation_commands(architecture)
                self.assertEqual(commands[0][0:2], ["/usr/bin/dpkg-source", "-x"])
                self.assertIn(f"manage-config {architecture} no_sign", commands[3][-1])
                self.assertIn(f"debian/config.local/{architecture}/config.sonic-vs", commands[3][-1])
                self.assertIn(f"build-arch_{architecture}_sonic_{architecture}_image", commands[4])
                self.assertIn(f"build-arch_{architecture}_kbuild", commands[4])
                self.assertIn("sonic-install-kbuild", commands[5])
                self.assertIn("ARCH=" + architecture, commands[5])
                self.assertIn("KERNEL_ARCH=" + ("x86" if architecture == "amd64" else "arm64"), commands[5])
                self.assertEqual(commands[-1][-2:], ["--architecture", architecture])
                for command in commands:
                    for forbidden in ("dpkg-buildpackage", "dpkg-deb", "dh_builddeb", "binary_", "binary-"):
                        self.assertNotIn(forbidden, " ".join(command))
        with self.assertRaisesRegex(ValueError, "unsupported kernel architecture"):
            action.compilation_commands("armhf")


if __name__ == "__main__":
    unittest.main()
