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


class ControlFlowJumpTests(unittest.TestCase):
    def edges(self, opcode, branch_offset=0):
        blob = bytes(16) + struct.pack('<BBhi', opcode, 0, branch_offset, 0)
        insn, _ = deep_disassembly.decode_instruction(blob, 16, SimpleNamespace())
        return deep_disassembly.build_cfg_edges([insn], 0, len(blob))

    def test_unconditional_forward_and_backward_jumps_have_one_edge(self):
        for branch_offset in (0, 2, -2):
            with self.subTest(branch_offset=branch_offset):
                self.assertEqual(self.edges(0x05, branch_offset), [{
                    'from': '0x10', 'to': hex(24 + branch_offset * 8),
                    'type': 'branch', 'conditional': False,
                }])

    def test_conditional_jumps_keep_both_edges(self):
        for opcode in (0x15, 0x1d, 0x55, 0x5d):
            with self.subTest(opcode=hex(opcode)):
                self.assertEqual(self.edges(opcode, -2), [
                    {'from': '0x10', 'to': '0x8', 'type': 'branch', 'conditional': True},
                    {'from': '0x10', 'to': '0x18', 'type': 'fallthrough', 'conditional': False},
                ])

    def test_exit_and_non_branch_behavior_is_unchanged(self):
        self.assertEqual(self.edges(0x95), [{
            'from': '0x10', 'to': 'return', 'type': 'exit', 'conditional': False,
        }])
        self.assertEqual(self.edges(0xb7), [])

    def test_captured_unconditional_jumps_have_no_fallthrough(self):
        for name in ('pump', 'pump_amm', 'pump_fees', 'mayhem'):
            with self.subTest(program=name):
                elf = deep_disassembly.Elf(
                    analyze.ROOT / 'evidence/original' / name / 'deployed.so')
                offset = elf.lo
                jumps = invalid = 0
                while offset < elf.hi:
                    instruction, size = deep_disassembly.decode_instruction(elf.b, offset, elf)
                    if elf.b[offset] == 0x05:
                        jumps += 1
                        edges = deep_disassembly.build_cfg_edges([instruction], elf.lo, elf.hi)
                        expected = [{
                            'from': hex(offset), 'to': hex(instruction['branch_target']),
                            'type': 'branch', 'conditional': False,
                        }]
                        invalid += edges != expected
                    offset += size
                self.assertGreater(jumps, 0)
                self.assertEqual(invalid, 0)


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
