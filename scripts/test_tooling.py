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


class InternalCallDecodeTests(unittest.TestCase):
    def test_forward_and_backward_internal_targets(self):
        for offset, immediate, target in ((8, 2, 32), (16, -2, 8)):
            with self.subTest(immediate=immediate):
                blob = bytes(offset) + struct.pack('<BBhi', 0x85, 0x10, 0, immediate)
                elf = SimpleNamespace(
                    funcs=[{'start': target, 'name': 'helper'}], relocations={})
                record, size = deep_disassembly.decode_instruction(blob, offset, elf)
                self.assertEqual(size, 8)
                self.assertEqual(record['call_target'], target)
                self.assertEqual(record['call_name'], 'helper')
                self.assertEqual(record['mnemonic'], 'call helper')
                self.assertNotIn('extern_symbol', record)

    def test_relocated_placeholder_stays_external(self):
        blob = struct.pack('<BBhi', 0x85, 0x10, 0, -1)
        elf = SimpleNamespace(funcs=[], relocations={
            0: {'type': 10, 'symbol': 'sol_log_'},
        })
        record, _ = deep_disassembly.decode_instruction(blob, 0, elf)
        self.assertEqual(record['extern_symbol'], 'sol_log_')
        self.assertEqual(record['mnemonic'], 'call_extern sol_log_')
        self.assertNotIn('call_target', record)

    def test_hashed_syscall_stays_syscall(self):
        blob = struct.pack('<BBhI', 0x85, 0, 0, 0x207559bd)
        elf = SimpleNamespace(funcs=[], relocations={})
        record, _ = deep_disassembly.decode_instruction(blob, 0, elf)
        self.assertEqual(record['syscall'], 'sol_log_64_')
        self.assertNotIn('call_target', record)

    def test_captured_call_targets_match_window_reader(self):
        for name in ('pump', 'pump_amm', 'pump_fees', 'mayhem'):
            with self.subTest(program=name):
                elf = deep_disassembly.Elf(
                    analyze.ROOT / 'evidence/original' / name / 'deployed.so')
                self.assertGreater(len(elf.calls), 0)
                for offset, target in elf.calls.items():
                    record, _ = deep_disassembly.decode_instruction(elf.b, offset, elf)
                    self.assertEqual(record['call_target'], target)
                    self.assertNotIn('extern_symbol', record)
                for offset, relocation in elf.relocations.items():
                    if relocation['type'] == 10:
                        record, _ = deep_disassembly.decode_instruction(elf.b, offset, elf)
                        self.assertEqual(record['extern_symbol'], relocation['symbol'])
                        self.assertNotIn('call_target', record)


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
