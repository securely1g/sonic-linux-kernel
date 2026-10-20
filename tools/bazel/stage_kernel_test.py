#!/usr/bin/env python3
"""Focused regressions for signed kernel runtime/debug payloads."""
import hashlib
import io
import lzma
from pathlib import Path
import tarfile
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_kernel as stage


class StageKernelTest(unittest.TestCase):
    def test_tar_preserves_installed_links_and_canonical_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / "tree"
            (tree / "usr/src/headers").mkdir(parents=True)
            (tree / "usr/src/headers/Makefile").write_text("header source")
            stage.link("../../../src/headers", tree / "usr/lib/modules/test/build")
            stage.write_tar(tree, root / "one.tar")
            (tree / "usr/src/headers/Makefile").touch()
            stage.write_tar(tree, root / "two.tar")
            self.assertEqual((root / "one.tar").read_bytes(), (root / "two.tar").read_bytes())
            with tarfile.open(root / "one.tar") as archive:
                self.assertEqual(archive.getmember("usr/lib/modules/test/build").linkname, "../../../src/headers")
                for item in archive.getmembers():
                    self.assertEqual((item.uid, item.gid, item.mtime), (0, 0, stage.EPOCH))
                    self.assertFalse(item.islnk())

    def test_tar_rejects_build_tree_and_parent_escape_links(self):
        for target in ("/build/source/tree", "../../../../escape"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tree = root / "tree"
                tree.mkdir()
                (tree / "link").symlink_to(target)
                with self.assertRaisesRegex(ValueError, "build-tree|escapes"):
                    stage.write_tar(tree, root / "output.tar")

    def test_signed_runtime_keeps_bytes_and_pairs_original_debug_by_build_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime, debug = root / "runtime", root / "debug"
            kernel = debug / ("usr/lib/debug/boot/vmlinux-" + stage.ABI)
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"kernel debug")
            runtime_file = runtime / "usr/lib/modules" / stage.ABI / "kernel/test.ko.xz"
            runtime_file.parent.mkdir(parents=True)
            signed = b"runtime ELF~Module signature appended~\n"
            runtime_file.write_bytes(lzma.compress(signed))
            original_hash = hashlib.sha256(runtime_file.read_bytes()).hexdigest()
            debug_file = debug / "usr/lib/debug/lib/modules" / stage.ABI / "kernel/test.ko"
            debug_file.parent.mkdir(parents=True)
            debug_file.write_bytes(b"debug ELF")
            def inspect(path):
                if path.name.startswith("vmlinux"):
                    return "a" * 40, path == kernel
                return "b" * 40, path == debug_file
            with patch.object(stage, "elf_info", side_effect=inspect), patch.object(stage.subprocess, "run"):
                result = stage.validate_debug_pairs(root / "source", runtime, debug)
                self.assertEqual(result["module_count"], 1)
                self.assertEqual(hashlib.sha256(runtime_file.read_bytes()).hexdigest(), original_hash)
                link = debug / "usr/lib/debug/.build-id/bb" / ("b" * 38 + ".debug")
                self.assertEqual(link.resolve(), debug_file)
            def mismatched(path):
                identity, has_debug = inspect(path)
                return ("c" * 40 if path == debug_file else identity), has_debug
            with patch.object(stage, "elf_info", side_effect=mismatched), patch.object(stage.subprocess, "run"):
                with self.assertRaisesRegex(ValueError, "build ID or DWARF mismatch"):
                    stage.validate_debug_pairs(root / "source", runtime, debug)


if __name__ == "__main__":
    unittest.main()
