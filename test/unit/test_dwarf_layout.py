import itertools
import os
import struct
import subprocess
import tempfile

from scripts.test import shared
from . import utils


def uleb(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def decode(data, offset):
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
        shift += 7


def section(name, payload):
    name = name.encode()
    payload = uleb(len(name)) + name + payload
    return b'\x00' + uleb(len(payload)) + payload


def sections(wasm):
    result = {}
    offset = 8
    while offset < len(wasm):
        kind = wasm[offset]
        size, start = decode(wasm, offset + 1)
        offset = start + size
        if kind == 0:
            length, start = decode(wasm, start)
            name = wasm[start:start + length].decode()
            result[name] = wasm[start + length:offset]
    return result


class DWARFLayoutTest(utils.BinaryenTestCase):
    def fixture(self, version, form=0x15, target=127, expression=None, location=None):
        # A short function grows past 127 bytes when local reads are instrumented.
        # The following type starts exactly at a reference-width boundary. Thus
        # high_pc growth moves it, then ref_udata growth moves it once more.
        wasm = bytes.fromhex('0061736d01000000 01050160017f00 03020100 07050101660000')
        code = b'\x01\x3e\x00' + b'\x20\x00\x1a' * 20 + b'\x0b'
        wasm += b'\x0a' + uleb(len(code)) + code
        extra = b'\x02\x18' if expression is not None else b''  # location: exprloc
        abbrev = (bytes.fromhex('0111011101120f03080000 021600030849') +
                  bytes([form]) + extra + bytes.fromhex('0000 03240003080000') +
                  bytes.fromhex('041100030849100000 00'))
        header_size = 11 if version == 4 else 12
        ref = uleb(target) if form == 0x15 else target.to_bytes(1 if form == 0x11 else 4, 'little')
        block = b'' if expression is None else uleb(len(expression)) + expression
        alias = b'\x02alias\x00' + ref + block
        padding = target - header_size - 6 - len(alias)
        root = b'\x01' + struct.pack('<I', 1) + b'\x3f' + b'u' * (padding - 1) + b'\x00'

        def unit(body):
            length = header_size - 4 + len(body)
            if version == 4:
                return struct.pack('<IHIB', length, 4, 0, 4) + body
            return struct.pack('<IHBBI', length, 5, 1, 4, 0) + body

        first = unit(root + alias + b'\x03target\x00\x00')
        self.assertEqual(first.index(b'\x03target\x00'), target)
        peer = unit(b'\x04peer\x00' + struct.pack('<I', target))
        aranges = b''.join(struct.pack('<IHIBB', 20, 2, offset, 4, 0) + bytes(12)
                           for offset in (len(first), 0))
        if location is not None:
            locs = struct.pack('<IIH', 1, 64, len(location)) + location + bytes(8)
            wasm += section('.debug_loc', locs)
        return (wasm + section('.debug_abbrev', abbrev) +
                section('.debug_info', first + peer) +
                section('.debug_aranges', aranges))

    def optimize(self, wasm, temp_dir):
        source = os.path.join(temp_dir, 'input.wasm')
        output = os.path.join(temp_dir, 'output.wasm')
        with open(source, 'wb') as f:
            f.write(wasm)
        process = subprocess.run(shared.WASM_OPT + [source, '--instrument-locals',
                                                  '-g', '-o', output],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process, output

    def test_growth_relocates_references_and_aranges(self):
        # Nop, a literal byte equal to call4, and a nested entry-value expression
        # contain no DIE references and must survive relocation unchanged.
        expressions = (None, b'\x96', b'\x9e\x01\x99', b'\xa3\x01\x96')
        for version, form, expression in itertools.product((4, 5), (0x13, 0x15), expressions):
            with self.subTest(version=version, form=form, expression=expression), tempfile.TemporaryDirectory() as temp:
                process, output = self.optimize(self.fixture(version, form, expression=expression, location=expression), temp)
                self.assertEqual(process.returncode, 0, process.stderr.decode())
                with open(output, 'rb') as f:
                    emitted = sections(f.read())
                info = emitted['.debug_info']
                high, _ = decode(info, (11 if version == 4 else 12) + 5)
                self.assertGreater(high, 127)
                target = info.index(b'\x03target\x00')
                self.assertEqual(target, 129 if form == 0x15 else 128)
                ref_offset = info.index(b'\x02alias\x00') + 7
                reference = (decode(info, ref_offset)[0] if form == 0x15 else
                             struct.unpack_from('<I', info, ref_offset)[0])
                self.assertEqual(reference, target)
                peer = struct.unpack_from('<I', info)[0] + 4
                absolute = info.index(b'\x04peer\x00') + 6
                self.assertEqual(struct.unpack_from('<I', info, absolute)[0], target)
                self.assertEqual(len(emitted['.debug_aranges']), 48)
                self.assertEqual(struct.unpack_from('<I', emitted['.debug_aranges'], 6)[0], peer)
                self.assertEqual(struct.unpack_from('<I', emitted['.debug_aranges'], 30)[0], 0)
                self.assertEqual(peer + struct.unpack_from('<I', info, peer)[0] + 4, len(info))
                # Decode the output again: relocation must be idempotent.
                shared.run_process(shared.WASM_OPT + [output, '--roundtrip', '-g', '-o', output])
                with open(output, 'rb') as f:
                    self.assertEqual(sections(f.read())['.debug_info'], info)

    def test_unsupported_relocation_fails_closed(self):
        cases = [
            (self.fixture(4, form=0x11, target=255), b'fixed-width field'),
            (self.fixture(4, expression=b'\x99\x7f\x00\x00\x00'), b'expression references'),
            (self.fixture(4, expression=b'\xa3\x05\x99\x7f\x00\x00\x00'), b'expression references'),
            (self.fixture(4, expression=b'\xff'), b'unknown opcodes'),
            (self.fixture(4, location=b'\x99\x7f\x00\x00\x00'), b'expression references'),
            (self.fixture(4) + section('.debug_names', b''), b'does not support .debug_names'),
        ]
        wasm = self.fixture(4)
        aranges = sections(wasm)['.debug_aranges']
        cases.append((wasm.replace(section('.debug_aranges', aranges),
                                   section('.debug_aranges', aranges[:-8])),
                      b'cannot decode complete DWARF aranges'))
        for wasm, error in cases:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temp:
                process, _ = self.optimize(wasm, temp)
                self.assertNotEqual(process.returncode, 0)
                self.assertIn(error, process.stdout + process.stderr)
