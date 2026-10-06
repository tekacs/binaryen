import os
import re
import struct
import tempfile

from scripts.test import shared
from . import utils


def leb(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def section(kind, payload):
    return bytes([kind]) + leb(len(payload)) + payload


def custom(name, payload):
    name = name.encode()
    return section(0, leb(len(name)) + name + payload)


def fixture(discriminators, extension):
    # (func (export "f") (param i32) (result i32)
    #   local.get 0; repeated { i32.const 1; i32.add })
    body = b'\x00\x20\x00' + b'\x41\x01\x6a' * len(discriminators) + b'\x0b'
    wasm = bytes.fromhex('0061736d01000000')
    wasm += section(1, bytes.fromhex('0160017f017f'))
    wasm += section(3, bytes.fromhex('0100'))
    wasm += section(7, bytes.fromhex('0101660000'))
    wasm += section(10, b'\x01' + leb(len(body)) + body)
    end = 2 + len(body)

    # A CU with stmt_list, name, low_pc and fixed-width high_pc.
    abbrev = bytes.fromhex('0111001017030e11011206000000')
    info = struct.pack('<HIBBIIII', 4, 0, 4, 1, 0, 0, 3, end - 3)
    wasm += custom('.debug_abbrev', abbrev)
    wasm += custom('.debug_info', struct.pack('<I', len(info)) + info)
    wasm += custom('.debug_str', b'line.c\x00')

    # DWARF4 prologue, one file, standard opcode operand counts.
    prologue = bytes([1, 1, 1, 251, 14, 13])
    prologue += bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
    prologue += b'\x00line.c\x00\x00\x00\x00\x00'
    program = b'\x00\x05\x02' + struct.pack('<I', 5)
    if extension:
        # A multi-byte extended-op length must skip exactly its payload.
        payload = b'\x80' + b'\x00' * 128
        program += b'\x00' + leb(len(payload)) + payload
    for index, value in enumerate(discriminators):
        if index:
            program += b'\x02\x03\x03\x01'  # advance_pc 3, advance_line 1
        if value:
            payload = b'\x04' + leb(value)
            program += b'\x00' + leb(len(payload)) + payload
        if index % 3 != 2:
            program += b'\x07'  # set_basic_block, also resets per row
        program += b'\x01'  # copy
    program += b'\x02\x04\x00\x01\x01'  # function end, end_sequence
    line = struct.pack('<HI', 4, len(prologue)) + prologue + program
    wasm += custom('.debug_line', struct.pack('<I', len(line)) + line)
    return wasm


class DwarfLinesTest(utils.BinaryenTestCase):
    def test_discriminators(self):
        values = [1, 1, 0, 127, 128, 16384, 0xffffffff, 0]
        for extension in (False, True):
            with self.subTest(extension=extension), tempfile.TemporaryDirectory() as tmp:
                source = os.path.join(tmp, 'input.wasm')
                output = os.path.join(tmp, 'output.wasm')
                with open(source, 'wb') as f:
                    f.write(fixture(values, extension))
                result = shared.run_process(
                    shared.WASM_OPT + [source, '--roundtrip', '-g', '-o', output],
                    capture_output=True)
                if extension:
                    self.assertEqual(result.stderr.count('unknown subopcode 128'), 1)
                else:
                    self.assertEqual(result.stderr, '')
                dump = shared.run_process(
                    shared.WASM_OPT + [output, '--dwarfdump', '-o', os.devnull],
                    capture_output=True)
                self.assertEqual(dump.stderr, '')
                self.assertNotIn('warning:', dump.stdout)
                lines = dump.stdout.split('.debug_line contents:', 1)[1]
                rows = [line.split() for line in lines.splitlines()
                        if re.match(r'^\s+0x[0-9a-f]+\s+\d+\s', line)
                        and 'end_sequence' not in line]
                self.assertEqual([int(row[5]) for row in rows], values)
                self.assertEqual([int(row[1]) for row in rows], list(range(1, 9)))
                self.assertEqual(['basic_block' in row for row in rows],
                                 [index % 3 != 2 for index in range(8)])
