#!/usr/bin/env python3
"""Mutation tests ensuring the byte comparator cannot hide code/padding changes."""
import struct
import unittest
from types import SimpleNamespace
import deep_section_analysis
import analyze
import bytecode_signatures
from compare import compare
class ComparisonTests(unittest.TestCase):
    def test_equal(self): self.assertTrue(compare(b'abc\0\0',b'abc\0\0')['full_byte_equality'])
    def test_code_mutation(self): self.assertEqual(compare(b'abc\0\0',b'axc\0\0')['first_difference'],1)
    def test_padding_mutation(self): self.assertEqual(compare(b'abc\0\0',b'abc\0x')['first_difference'],4)
    def test_truncated_padding(self): self.assertFalse(compare(b'abc\0\0',b'abc\0')['full_byte_equality'])
    def test_extended_padding(self): self.assertFalse(compare(b'abc\0',b'abc\0\0')['full_byte_equality'])
    def test_empty(self): self.assertEqual(compare(b'a',b'')['first_difference'],0)


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


class ErrorPatternBoundaryTests(unittest.TestCase):
    @staticmethod
    def instruction(opcode, offset=0, immediate=0):
        return struct.pack('<BBhi', opcode, 0, offset, immediate)

    def patterns(self, blob, start=0, end=None):
        return bytecode_signatures.detect_error_patterns(
            SimpleNamespace(b=blob), start, len(blob) if end is None else end)

    def test_two_instruction_window(self):
        blob = self.instruction(0x15) + self.instruction(0xb7, immediate=6000)
        self.assertEqual(self.patterns(blob), [{
            'offset': 0, 'branch_target_offset': 8,
            'error_code': 6000, 'type': 'conditional_error',
        }])

    def test_final_instruction_can_branch_backward(self):
        blob = self.instruction(0xb4, immediate=6001) + self.instruction(0x55, offset=-2)
        self.assertEqual(self.patterns(blob), [{
            'offset': 8, 'branch_target_offset': 0,
            'error_code': 6001, 'type': 'conditional_error',
        }])

    def test_target_must_be_a_complete_instruction_inside_window(self):
        blob = self.instruction(0x15) + self.instruction(0xb7, immediate=6000)
        for end in (8, 9, 12, 15):
            with self.subTest(end=end):
                self.assertEqual(self.patterns(blob, end=end), [])
        backward = self.instruction(0xb7) + self.instruction(0x15, offset=-2)
        self.assertEqual(self.patterns(backward, start=8), [])

    def test_empty_and_partial_branch_windows(self):
        self.assertEqual(self.patterns(b''), [])
        self.assertEqual(self.patterns(self.instruction(0x15)[:4]), [])

    def test_non_move_target_is_not_a_pattern(self):
        blob = self.instruction(0x15) + self.instruction(0x95)
        self.assertEqual(self.patterns(blob), [])

    def test_terminal_branches_in_captured_programs(self):
        cases = (
            ('pump', 0xef40, 0xefc8, 0xefb8, 0xef58),
            ('pump', 0x197650, 0x197868, 0x197858, 0x197788),
            ('pump_amm', 0xd038, 0xd0c0, 0xd0b0, 0xd050),
            ('mayhem', 0x9028, 0x92b8, 0x92a8, 0x9260),
        )
        for name, start, end, branch, target in cases:
            with self.subTest(program=name, branch=hex(branch)):
                blob = (analyze.ROOT / 'evidence/original' / name / 'deployed.so').read_bytes()
                self.assertIn({
                    'offset': branch - start, 'branch_target_offset': target - start,
                    'error_code': 0, 'type': 'conditional_error',
                }, self.patterns(blob, start, end))


if __name__=='__main__': unittest.main()
