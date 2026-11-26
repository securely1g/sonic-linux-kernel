"""The generated kbuild headers must preserve ABI facts and getopt semantics."""
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest


class HeaderGenerationTest(unittest.TestCase):
    def generate(self, mode, sources):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = []
            for index, source in enumerate(sources):
                path = root / ('source%d' % index)
                path.write_text(source)
                inputs.append(str(path))
            out = root / 'output.h'
            subprocess.run([sys.executable, str(Path(__file__).with_name('kbuild_generate.py')),
                            mode, str(out), *inputs], check=True)
            return out.read_text()

    def test_variant_keeps_shared_definitions_and_overrides(self):
        text = self.generate('header', ['typedef unsigned int __u32;\n',
                                       '#include "../types.h"\ntypedef __u32 kernel_ulong_t;\n#define BITS_PER_LONG 32\n'])
        self.assertIn('typedef unsigned int __u32;', text)
        self.assertIn('typedef __u32 kernel_ulong_t;', text)
        self.assertIn('#define BITS_PER_LONG 32', text)
        self.assertNotIn('../types.h', text)

    def test_device_offsets_preserve_compiler_numeric_values(self):
        text = self.generate('offsets', ['  .ascii "->SIZE_usb_device_id $32 sizeof(struct usb_device_id)"\n'
                                         '  .ascii "->OFF_usb_device_id_idVendor $4 offsetof(struct usb_device_id, idVendor)"\n'])
        self.assertIn('#define SIZE_usb_device_id 32 /* sizeof(struct usb_device_id) */', text)
        self.assertIn('#define OFF_usb_device_id_idVendor 4 /* offsetof(struct usb_device_id, idVendor) */', text)

    def test_wrapper_options_keep_argument_colons_and_exclude_T_case(self):
        text = self.generate('options', ['while ((opt = getopt(argc, argv, "ab:T:")) != -1) {}'])
        self.assertIn('#define GETOPT_OPTIONS "ab:T:"', text)
        self.assertIn("#define GETOPT_CASE case 'a': case 'b':", text)
        self.assertNotIn("case 'T'", text)


if __name__ == '__main__':
    unittest.main()
