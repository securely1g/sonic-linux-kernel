"""Installation contracts from rules.real and dh_movetousr, independent of staging."""
import json
from pathlib import Path
import tempfile
import unittest

from native_install import finalize, runtime_layout, tree_entries


class InstallationTest(unittest.TestCase):
    def test_merged_usr_preserves_paths_and_link_meaning(self):
        entries = {
            'lib': {'type': 'dir', 'mode': 0o755},
            'lib/modules/release/build': {'type': 'link', 'mode': 0o777,
                'link': '/usr/src/linux-headers-release', 'normalized_link': True},
            'usr/lib/debug/current': {'type': 'link', 'mode': 0o777, 'link': 'boot/vmlinux'},
            'usr/src/linux-headers-release/include.h': {'type': 'file', 'mode': 0o640, 'contents': '/declared/header'},
        }
        installed = finalize(entries)
        self.assertNotIn('lib', installed)
        self.assertEqual(installed['usr/lib/modules/release/build']['link'], '../../../src/linux-headers-release')
        self.assertEqual(installed['usr/lib/debug/current']['link'], 'boot/vmlinux')
        self.assertEqual(installed['usr/src/linux-headers-release/include.h']['mode'], 0o640)
        self.assertEqual(installed['usr/src/linux-headers-release/include.h']['contents'], '/declared/header')
        self.assertEqual(installed['usr/src']['type'], 'dir')

    def test_vdso_data_permissions_match_library_installation_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'vdsox32.so'
            source.write_bytes(b'compatibility VDSO')
            source.chmod(0o755)
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'core_trees': {'debug': [
                {'path': 'vdsox32.so', 'type': 'file', 'mode': '0755'}]}}))
            entries = tree_entries({'debug_tree': str(root), 'receipt': str(receipt)}, 'debug')
            value = entries['usr/lib/debug/vdsox32.so']
            self.assertEqual(value['mode'], 0o644)
            self.assertEqual(Path(value['contents']).read_bytes(), b'compatibility VDSO')
            self.assertEqual(source.stat().st_mode & 0o777, 0o755)

    def test_runtime_config_filter_and_declared_module_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / 'runtime'
            runtime.mkdir()
            module = runtime / 'module.ko'
            module.write_bytes(b'signed module payload')
            module.chmod(0o444)
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'core_trees': {'runtime': [
                {'path': 'module.ko', 'type': 'file', 'mode': '0644'},
                {'path': 'lib/firmware/unused', 'type': 'file', 'mode': '0644'}]}}))
            config = root / 'config'
            config.write_text('CONFIG_MODULE_SIG_ALL=y\nCONFIG_MODULE_SIG_KEY="private"\n'
                              'CONFIG_SYSTEM_TRUSTED_KEYS="private"\nCONFIG_BUILD_SALT="salt"\n'
                              'CONFIG_MODULE_SIG=y\nCONFIG_IPV6=y\n')
            image = root / 'image'
            image.write_bytes(b'kernel image')
            generated = root / 'generated'
            generated.mkdir()
            entries = runtime_layout({'runtime_tree': str(runtime), 'receipt': str(receipt),
                                      'architecture': 'amd64',
                                      'raw_files': {'config': str(config), 'image': str(image)}}, generated)
            self.assertEqual(Path(entries['module.ko']['contents']).read_bytes(), b'signed module payload')
            self.assertEqual(entries['module.ko']['mode'], 0o644)
            self.assertEqual(module.stat().st_mode & 0o777, 0o444)
            self.assertNotIn('lib/firmware/unused', entries)
            target = next(value for name, value in entries.items() if name.startswith('boot/config-'))
            self.assertEqual(Path(target['contents']).read_text(), 'CONFIG_MODULE_SIG=y\nCONFIG_IPV6=y\n')
            self.assertEqual(config.read_text().count('private'), 2)


if __name__ == '__main__':
    unittest.main()
