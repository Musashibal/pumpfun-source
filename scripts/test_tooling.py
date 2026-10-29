#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
from types import SimpleNamespace
import deep_section_analysis
import deep_disassembly
import analyze
from compare import compare
class ComparisonTests(unittest.TestCase):
    def test_equal(self): self.assertTrue(compare(b'abc\0\0',b'abc\0\0')['full_byte_equality'])
    def test_code_mutation(self): self.assertEqual(compare(b'abc\0\0',b'axc\0\0')['first_difference'],1)
    def test_padding_mutation(self): self.assertEqual(compare(b'abc\0\0',b'abc\0x')['first_difference'],4)
    def test_truncated_padding(self): self.assertFalse(compare(b'abc\0\0',b'abc\0')['full_byte_equality'])
    def test_extended_padding(self): self.assertFalse(compare(b'abc\0',b'abc\0\0')['full_byte_equality'])
    def test_empty(self): self.assertEqual(compare(b'a',b'')['first_difference'],0)


class EndianDecodeTests(unittest.TestCase):
    def test_conversion_direction_and_width(self):
        for opcode, direction in ((0xd4, 'le'), (0xdc, 'be')):
            for width in (16, 32, 64):
                with self.subTest(direction=direction, width=width):
                    blob = struct.pack('<BBhi', opcode, 5, 0, width)
                    record, size = deep_disassembly.decode_instruction(blob, 0, None)
                    self.assertEqual(record['mnemonic'], f'{direction}{width} r5')
                    self.assertEqual(record['imm'], width)
                    self.assertEqual(record['hex'], blob.hex())
                    self.assertEqual(size, 8)

    def test_other_alu_operand_forms_are_unchanged(self):
        for opcode, regs, immediate, mnemonic in (
            (0x04, 5, 16, 'add32 r5, 16'),
            (0x0c, 0x35, 0, 'add32 r5, r3'),
        ):
            with self.subTest(opcode=opcode):
                blob = struct.pack('<BBhi', opcode, regs, 0, immediate)
                record, _ = deep_disassembly.decode_instruction(blob, 0, None)
                self.assertEqual(record['mnemonic'], mnemonic)

    def test_captured_big_endian_conversions(self):
        for relative in ('original/mayhem', 'dependencies/spl_token_2022'):
            with self.subTest(capture=relative):
                elf = deep_disassembly.Elf(
                    analyze.ROOT / 'evidence' / relative / 'deployed.so')
                offset = elf.lo
                widths = []
                while offset < elf.hi:
                    record, size = deep_disassembly.decode_instruction(elf.b, offset, elf)
                    if elf.b[offset] == 0xdc:
                        widths.append(record['imm'])
                        self.assertEqual(record['mnemonic'],
                                         f"be{record['imm']} r{record['dst']}")
                    offset += size
                self.assertEqual(sorted(widths), [16] + [32] * 7)


class RelocationTargetTests(unittest.TestCase):
    def test_target_section_uses_address_not_file_offset(self):
        blob = bytearray(64)
        struct.pack_into('<QQ', blob, 0, 0x1000, 2)
        elf = SimpleNamespace(
            b=bytes(blob),
            symbols={},
            lo=0x2000,
            hi=0x3000,
            secs={
                '.rel.dyn': (0, 9, 0, 0, 0, 16, 0, 0, 1, 16),
                '.rodata': (0, 1, 2, 0x1000, 0x20, 0x100, 0, 0, 1, 0),
            },
        )
        report = deep_section_analysis.analyze_relocations(elf)
        self.assertEqual(report['entries'][0]['target_section'], '.rodata')


class InstructionLogNameTests(unittest.TestCase):
    def names(self, name):
        blob = (analyze.ROOT / 'evidence/original' / name / 'deployed.so').read_bytes()
        return set(analyze.instruction_log_names(blob, analyze.known_instruction_names(name)))

    def test_idl_names_do_not_absorb_adjacent_text(self):
        pump = self.names('pump')
        self.assertIn('Buy', pump)
        self.assertIn('UpdateBuybackConfig', pump)
        self.assertIn('IdlResizeAccount', pump)
        self.assertNotIn('BuyCreateV2Disabled', pump)
        self.assertNotIn('UpdateBuybackConfigAn', pump)
        self.assertNotIn('IdlResizeAccountdata', pump)

        amm = self.names('pump_amm')
        self.assertIn('ClaimCashback', amm)
        self.assertIn('IdlCreateAccount', amm)
        self.assertNotIn('ClaimCashbacksol', amm)
        self.assertNotIn('IdlCreateAccountanchor', amm)

        fees = self.names('pump_fees')
        self.assertIn('Withdraw', fees)
        self.assertIn('CrankDonationFeePda', fees)
        self.assertNotIn('Withdrawaccountsol', fees)
        self.assertNotIn('CrankDonationFeePdaFee', fees)

    def test_program_names_fall_back_to_captures(self):
        self.assertEqual(
            analyze.program_names(),
            ['pump', 'pump_amm', 'pump_fees', 'mayhem'],
        )

    def test_mayhem_fallback_is_unchanged(self):
        names = self.names('mayhem')
        self.assertEqual(len(names), 25)
        self.assertIn('Buy', names)
        self.assertIn('InitializeGlobalParams', names)


if __name__=='__main__': unittest.main()
