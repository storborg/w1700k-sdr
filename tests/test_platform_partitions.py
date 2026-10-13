# SPDX-License-Identifier: MIT
"""platform/partitions.py: the NAND layout every stage and the installer share."""
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'platform'))
import partitions  # noqa: E402


class Layout(unittest.TestCase):
    def test_the_table_covers_the_chip_contiguously(self):
        partitions.check_table()
        self.assertEqual(partitions.GEOMETRY['loader'], (0x600000, 0x200000))
        self.assertEqual(partitions.GEOMETRY['system'], (0x800000, 0x3000000))
        self.assertEqual(partitions.GEOMETRY['durable'], (0x3800000, 0x2000000))

    def test_gaps_overlaps_and_short_tables_are_refused(self):
        for name, value, message in [
                ('system', (0x900000, 0x2f00000), 'gap or overlaps'),
                ('system', (0x800000, 0x3000001), 'block-aligned'),
                ('reserved-bmt', (0x1be00000, 0x4100000), 'covers')]:
            with self.subTest(name=name), \
                    mock.patch.dict(partitions.GEOMETRY, {name: value}), \
                    self.assertRaisesRegex(ValueError, message):
                partitions.check_table()

    def test_vendor_partitions_are_read_only_in_every_stage(self):
        for stage, read_only in partitions.READ_ONLY.items():
            self.assertLessEqual({'bootloader', 'uenv', 'calibration', 'reserved-bmt'},
                                 read_only, stage)
        self.assertNotIn('system', partitions.READ_ONLY['loader'])
        self.assertIn('system', partitions.READ_ONLY['linux'])
        self.assertNotIn('durable', partitions.READ_ONLY['linux'])

    def test_ubi_volumes_fit_with_the_bad_block_reserve(self):
        # 20 per 1024 PEBs of the whole chip, plus 4 for UBI itself.
        reserve, system, durable = {'w25n04kv': (80, 300, 172),
                                    'w25n04l': (40, 148, 84)}[partitions.PART.name]
        self.assertEqual(partitions.UBI_BAD_RESERVE_PEBS, reserve)
        self.assertEqual(partitions.ubi_lebs('system'), system)
        self.assertEqual(partitions.DURABLE_LEBS, durable)
        self.assertEqual(sum(lebs for _, _, lebs in partitions.SYSTEM_VOLUMES), system)
        self.assertEqual([name for name, _, _ in partitions.SYSTEM_VOLUMES],
                         ['ubootenv', 'ubootenv2', 'fit', 'rootfs'])
        self.assertGreater(partitions.FIT_VOLUME_BYTES, 12 << 20)
        self.assertGreater(partitions.ROOTFS_VOLUME_BYTES, 16 << 20)

    def test_the_bmt_may_write_only_project_partitions(self):
        header = partitions.policy_header()
        first = partitions.GEOMETRY['system'][0] // partitions.BLOCK_BYTES
        end = sum(partitions.GEOMETRY['scratch']) // partitions.BLOCK_BYTES
        self.assertIn(f'#define BMT_WRITE_FIRST {first}u', header)
        self.assertIn(f'#define BMT_WRITE_END {end}u', header)
        # The first reserve block after the BBT of a unit whose top blocks
        # have no factory-bad block.
        journal = {'w25n04kv': 3847, 'w25n04l': 1886}[partitions.PART.name]
        self.assertIn(f'#define BMT_JOURNAL_BLOCK {journal}u', header)
        reserve = partitions.GEOMETRY['reserved-bmt'][0] // partitions.BLOCK_BYTES
        self.assertGreaterEqual(partitions.JOURNAL_PHYSICAL_BLOCK, reserve)


class Parts(unittest.TestCase):
    def test_each_part_has_the_same_byte_layout_and_its_own_geometry(self):
        sys.path.insert(0, str(ROOT / 'tests'))
        from test_platform_bmt import partitions_for
        kv, l = partitions_for('w25n04kv'), partitions_for('w25n04l')
        self.assertEqual(kv.GEOMETRY, l.GEOMETRY)
        self.assertEqual((kv.BLOCK_BYTES, kv.PAGE_BYTES, kv.TOTAL_BLOCKS, kv.LEB_BYTES),
                         (0x20000, 0x800, 4096, 0x1f000))
        self.assertEqual((l.BLOCK_BYTES, l.PAGE_BYTES, l.TOTAL_BLOCKS, l.LEB_BYTES),
                         (0x40000, 0x1000, 2048, 0x3e000))
        self.assertEqual(kv.FIT_VOLUME_BYTES, l.FIT_VOLUME_BYTES)
        self.assertIn('#define BMT_OOB_FREE 112u', l.policy_header())
        self.assertIn('#define BMT_TOTAL_BLOCKS 4096u', kv.policy_header())
        for module in (kv, l):
            module.check_table()

    def test_an_unknown_part_is_refused(self):
        sys.path.insert(0, str(ROOT / 'tests'))
        from test_platform_bmt import partitions_for
        with self.assertRaises(SystemExit):
            partitions_for('w25n01gv')


class DeviceTrees(unittest.TestCase):
    def test_both_device_trees_carry_the_current_region(self):
        for path, stage in partitions.DEVICE_TREES.items():
            with self.subTest(path=path):
                partitions.check(path, stage)
                text = (ROOT / path).read_text()
                for name in partitions.GEOMETRY:
                    self.assertEqual(text.count(f'label = "{name}";'), 1, name)

    def test_a_stale_region_is_reported(self):
        path, stage = next(iter(partitions.DEVICE_TREES.items()))
        text = (ROOT / path).read_text().replace('0x00800000 0x03000000',
                                                 '0x00700000 0x03100000', 1)
        with mock.patch.object(Path, 'read_text', return_value=text), \
                self.assertRaisesRegex(ValueError, 'stale partition table'):
            partitions.check(path, stage)

    def test_read_only_flags_follow_the_stage(self):
        loader = partitions.fragment('loader')
        linux = partitions.fragment('linux')
        system_loader = loader[loader.index('system@'):loader.index('durable@')]
        system_linux = linux[linux.index('system@'):linux.index('durable@')]
        self.assertNotIn('read-only', system_loader)
        self.assertIn('read-only', system_linux)


if __name__ == '__main__':
    unittest.main()
