# SPDX-License-Identifier: MIT
"""Installation and updates, run end to end against a simulated unit."""
import argparse
import contextlib
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'init'), str(Path(__file__).resolve().parent)]
from initkit import backup, config, install, layout, provision, session, update  # noqa: E402
from initkit.console import StepFailed  # noqa: E402
from initkit.log import RunLog  # noqa: E402
import init_fake_unit as fake  # noqa: E402

DUMP_BYTES = 0x420000 + 0x420000 // 0x800 * 128


class Bench(unittest.TestCase):
    """A data directory, built images and a simulated unit wired into the tools."""

    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.work = Path(work.name)
        images = self.work / 'images'
        images.mkdir()
        paths = {}
        for name, marker, size in (('LOADER', 'loader', 0x33e44), ('DUMPER', 'dumper', 0x2b000),
                                   ('SYSTEM_FIT', 'system', 0x90000),
                                   ('RECOVERY_FIT', 'recovery', 0xa0000),
                                   ('ROOTFS', 'hsqs', 0x30000), ('DURABLE', 'ubifs', 0x20000)):
            paths[name] = images / name.lower()
            paths[name].write_bytes(fake.fit(marker, size))
        for patcher in (mock.patch.multiple(config, **paths),
                        mock.patch.object(backup, 'DUMP_BYTES', DUMP_BYTES),
                        mock.patch('builtins.print')):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.settings = argparse.Namespace(uart='/dev/null', host_ip='192.168.1.10',
                                           device_ip='192.168.1.1', stock_port=7071,
                                           transfer_port=7070, data_dir=self.work / 'data')
        self.unit_root = self.work / 'unit-root.squashfs'
        self.unit_root.write_bytes(fake.fit('hsqs-unit', 0x31000))
        self.unit = None

    def make_unit(self, **options):
        served = self.work / 'served'
        served.mkdir(exist_ok=True)
        self.unit = fake.FakeUnit(served, **options)
        return self.unit

    @contextlib.contextmanager
    def open_session(self, settings, tool, write=False, passive=False):
        log = RunLog(settings.data_dir, tool)
        self.unit.allow_mutating = write
        try:
            yield session.Session(settings, log, self.unit, self.unit.served)
        finally:
            log.close()

    def install(self, **options):
        key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA=='
        with mock.patch.object(install, 'open_session', self.open_session), \
                mock.patch.object(provision, 'authorized_key', return_value=key.encode()), \
                mock.patch.object(provision, 'provision', return_value=(self.unit_root, key)):
            return install.run(self.settings, **options)

    def flash(self, **options):
        with mock.patch.object(update, 'open_session', self.open_session), \
                mock.patch.object(provision, 'provision',
                                  return_value=(self.unit_root, 'ssh-ed25519 AAAA')):
            return update.run(self.settings, **options)

    def commands(self, state=None):
        return [line for at, line in self.unit.log if state is None or at == state]

    def index(self, pattern):
        for number, (_, line) in enumerate(self.unit.log):
            if re.search(pattern, line):
                return number
        self.fail(f'no command matches {pattern!r}')


class Install(Bench):
    def test_a_stock_unit_is_backed_up_and_installed(self):
        unit = self.make_unit()
        self.assertEqual(self.install(), 0)
        serial = 'W1700KTEST0001'
        backup_file = config.unit_dir(self.settings.data_dir, serial) / backup.BACKUP_NAME
        self.assertEqual(backup_file.stat().st_size, DUMP_BYTES)
        self.assertEqual(backup.serial_in_backup(backup_file), serial)
        extent = layout.loader_extent(config.LOADER.stat().st_size)
        self.assertEqual(unit.loader_slot, config.LOADER.read_bytes() +
                         b'\xff' * (extent - config.LOADER.stat().st_size))
        self.assertEqual(unit.saved['bootcmd'], layout.stock_bootcmd(extent))
        self.assertEqual(unit.saved['bootcmd_orig'], fake.STOCK_BOOTCMD)
        self.assertEqual(unit.ubi['system']['fit'], config.SYSTEM_FIT.read_bytes())
        self.assertEqual(unit.ubi['system']['rootfs'], self.unit_root.read_bytes())
        self.assertEqual(unit.ubi['durable']['durable'], config.DURABLE.read_bytes())
        self.assertEqual(unit.state, 'linux')

    def test_the_order_keeps_the_unit_recoverable(self):
        self.make_unit()
        self.install()
        dump = self.index(r'^tftpput ')
        first_write = min(self.index(r'^flash erase'), self.index(r'^mtd erase'))
        self.assertLess(dump, first_write, 'the backup comes before any write')
        self.assertLess(self.index(r'^cmp\.b '), self.index(r'^saveenv'))
        readback_boot = next(number for number, (at, line) in enumerate(self.unit.log)
                             if at == 'stock' and line == f'bootm {layout.READBACK:#x}')
        self.assertLess(readback_boot, self.index(r'^saveenv'),
                        'the slot copy boots before stock is told to boot it')

    def test_only_project_partitions_are_erased(self):
        self.make_unit()
        self.install()
        erased = {}
        for partition, offset, length in self.unit.erased:
            erased[partition] = erased.get(partition, 0) + length
        self.assertEqual(erased, {'system': 0x3000000, 'durable': 0x2000000})
        stock_writes = [line for line in self.commands('stock')
                        if line.startswith(('flash write', 'flash erase'))]
        self.assertTrue(all(' 0x600000 ' in line for line in stock_writes))

    def test_an_existing_backup_is_kept(self):
        directory = config.unit_dir(self.settings.data_dir, 'W1700KTEST0001')
        directory.mkdir(parents=True)
        existing = bytearray(DUMP_BYTES)
        existing[0x400000:0x400000 + len(fake.IDENTITY)] = fake.IDENTITY
        existing[0x405000:0x405000 + len(fake.CALIBRATION)] = fake.CALIBRATION
        (directory / backup.BACKUP_NAME).write_bytes(bytes(existing))
        self.make_unit()
        self.install()
        self.assertFalse(any(line.startswith('tftpput') for line in self.commands()))
        self.assertEqual((directory / backup.EEPROM_NAME).read_bytes()[:len(fake.CALIBRATION)],
                         fake.CALIBRATION)

    def test_backup_only_writes_nothing(self):
        self.make_unit()
        self.assertEqual(self.install(backup_only=True), 0)
        self.assertFalse(any(line.startswith(('flash ', 'saveenv', 'mtd erase', 'ubi '))
                             for line in self.commands()))

    def test_the_wrong_unit_is_refused_before_any_write(self):
        self.make_unit()
        with self.assertRaisesRegex(StepFailed, 'not W1700KOTHER'):
            self.install(expect_serial='W1700KOTHER')
        self.assertFalse(any(line.startswith(('flash ', 'saveenv', 'tftpput'))
                             for line in self.commands()))

    def test_an_installed_unit_needs_force(self):
        self.make_unit(installed=True)
        with self.assertRaisesRegex(StepFailed, 'already boots our loader'):
            self.install()


class Flash(Bench):
    def test_a_system_update_from_linux(self):
        unit = self.make_unit(installed=True)
        unit.state = 'linux'
        config.unit_dir(self.settings.data_dir, 'W1700KTEST0001').mkdir(parents=True)
        self.assertEqual(self.flash(fit=True, rootfs=True), 0)
        self.assertEqual(unit.ubi['system']['fit'], config.SYSTEM_FIT.read_bytes())
        self.assertEqual(unit.ubi['system']['rootfs'], self.unit_root.read_bytes())
        self.assertNotIn('saveenv', self.commands())
        self.assertFalse(any(line.startswith(('flash ', 'mtd erase')) for line in self.commands()))
        self.assertEqual(unit.state, 'linux')

    def test_a_current_volume_is_not_rewritten(self):
        unit = self.make_unit(installed=True)
        unit.ubi['system']['fit'] = config.SYSTEM_FIT.read_bytes()
        unit.state = 'loader'
        self.flash(fit=True)
        self.assertFalse(any(line.startswith('ubi write') for line in self.commands()))

    def test_a_loader_update_rewrites_the_slot_and_keeps_bootcmd(self):
        unit = self.make_unit(installed=True)
        unit.state = 'stock'
        self.flash(loader=True, boot=False)
        self.assertTrue(unit.loader_slot.startswith(config.LOADER.read_bytes()))
        self.assertNotIn('saveenv', self.commands())
        self.assertEqual(unit.state, 'loader')

    def test_recovery_boots_from_ram_without_writing(self):
        unit = self.make_unit(installed=True)
        unit.state = 'linux'
        self.flash(recovery=True)
        self.assertFalse(any(re.match(r'(ubi (write|create)|mtd erase|flash (erase|write)|saveenv)',
                                      line) for line in self.commands()))
        self.assertIn(f"setenv bootargs '{layout.recovery_bootargs()}'", self.commands())
        self.assertEqual(unit.state, 'linux')

    def test_an_uninstalled_unit_cannot_take_a_loader_update(self):
        unit = self.make_unit()
        unit.state = 'stock'
        with self.assertRaisesRegex(StepFailed, 'init/install'):
            self.flash(loader=True)


class Layout(unittest.TestCase):
    def test_the_loader_extent_is_whole_blocks_inside_the_slot(self):
        self.assertEqual(layout.loader_extent(0x33e44), 0x40000)
        self.assertEqual(layout.loader_extent(0x40000), 0x40000)
        with self.assertRaises(ValueError):
            layout.loader_extent(0x200001)

    def test_the_stock_bootcmd_names_both_addresses(self):
        self.assertEqual(layout.stock_bootcmd(0x40000),
                         'flash read 0x600000 0x40000 0x89000000; bootm 0x89000000')
        self.assertEqual(layout.bootcmd_extent(layout.stock_bootcmd(0x60000)), 0x60000)
        self.assertIsNone(layout.bootcmd_extent(fake.STOCK_BOOTCMD))
        self.assertIsNone(layout.bootcmd_extent('flash read 0x600000 0x40000 0x81800000'))

    def test_the_original_bootcmd_is_kept_once(self):
        commands = layout.save_bootcmd(0x40000, {'bootcmd': fake.STOCK_BOOTCMD})
        self.assertEqual(commands[0], f"setenv bootcmd_orig '{fake.STOCK_BOOTCMD}'")
        again = layout.save_bootcmd(0x40000, {'bootcmd': layout.stock_bootcmd(0x40000)})
        self.assertFalse(any('bootcmd_orig' in line for line in again))
        self.assertEqual(again[-1], 'saveenv')

    def test_volumes_are_created_in_id_order(self):
        self.assertEqual(layout.create_system_volumes(), [
            'ubi create ubootenv 0x4000 d 0', 'ubi create ubootenv2 0x4000 d 1',
            f'ubi create fit {128 * 0x1f000:#x} s 2', f'ubi create rootfs {170 * 0x1f000:#x} s 3'])

    def test_erase_steps_cover_the_partition_exactly(self):
        steps = layout.erase('system')
        self.assertEqual(steps[0], 'mtd erase system 0x0 0x1000000')
        self.assertEqual(len(steps), 3)
        self.assertEqual(len(layout.erase('durable')), 2)

    def test_a_volume_write_is_read_back(self):
        steps = [line for line, _ in layout.write_volume('fit', 'fit.img', 100, 'ab' * 32,
                                                         fit=True)]
        self.assertEqual(steps[-2], f'ubi read {layout.READBACK:#x} fit 0x64')
        self.assertEqual(steps[-1], f'hash sha256 {layout.READBACK:#x} 0x64')
        self.assertIn(f'iminfo {layout.LOAD:#x}', steps)


class Parsing(unittest.TestCase):
    def test_md_output_round_trips(self):
        text = '88000000: 73 65 72 69 61 6c  serial\n88000006: ff ff  ..\n'
        self.assertEqual(backup.parse_md(text), b'serial\xff\xff')

    def test_identity_fields_stop_at_the_padding(self):
        fields = backup.parse_identity(fake.IDENTITY + b'\xff' * 8 + b'x=1\n')
        self.assertEqual(fields['serial_number'], 'W1700KTEST0001')
        self.assertNotIn('x', fields)
        with self.assertRaisesRegex(StepFailed, 'no usable serial'):
            backup.serial_from({'serial_number': '../x'})

    def test_geometry_gives_the_dump_size(self):
        listing = ('  - min I/O: 0x800 bytes\n  - OOB size: 128 bytes\n'
                   '  - 0x000000000000-0x000020000000 : "spi-nand0"')
        self.assertEqual(backup.geometry(listing)['dump_bytes'], 0x22000000)

    def test_geometry_of_a_4k_page_chip(self):
        listing = ('  - min I/O: 0x1000 bytes\n  - OOB size: 256 bytes\n'
                   '  - 0x000000000000-0x000020000000 : "spi-nand0"')
        self.assertEqual(backup.geometry(listing)['dump_bytes'], 0x22000000)

    def test_a_chip_that_did_not_probe_stops_the_serial_read(self):
        with tempfile.TemporaryDirectory() as served:
            unit = fake.FakeUnit(served, chip_probes=False)
            unit.state = 'dumper'
            unit.ram[backup.IDENTITY_SCRATCH] = b'\0' * backup.IDENTITY_BYTES
            with self.assertRaisesRegex(StepFailed, 'not found'):
                backup.read_serial(unit)
            self.assertFalse(any(line.startswith('md.b') for _, line in unit.log))

    def test_a_chip_of_another_geometry_is_not_written(self):
        with tempfile.TemporaryDirectory() as served:
            unit = fake.FakeUnit(served)
            unit.state = 'dumper'
            backup.check_platform_part(unit)
            unit.page_bytes, unit.oob_bytes = 0x1000, 256
            with self.assertRaisesRegex(StepFailed, 'nothing was written'):
                backup.check_platform_part(unit)

    def test_a_writable_chip_is_refused(self):
        with self.assertRaisesRegex(StepFailed, 'read-only'):
            backup.check_read_only('  - flags: 0x400 (writeable)')
        backup.check_read_only('  - flags: 0x0 (read-only)')


class Prompts(unittest.TestCase):
    def test_console_prompts_match_the_u_boot_configurations(self):
        from initkit import uart
        for state, defconfig in (('loader', 'loader/an7581_w1700k_sdr_defconfig'),
                                 ('dumper', 'dumper/an7581_w1700k_dumper_defconfig')):
            text = (ROOT / 'platform' / defconfig).read_text()
            prompt = re.search(r'^CONFIG_SYS_PROMPT="(.*)"$', text, re.M).group(1)
            self.assertTrue(uart.PROMPTS[state].search(b'\n' + prompt.encode()), state)
            self.assertTrue(uart.SETTLED.search(prompt), state)


class Keys(unittest.TestCase):
    def test_an_openssh_key_converts_to_dropbear(self):
        if not shutil.which('ssh-keygen'):
            self.skipTest('ssh-keygen is unavailable')
        key = provision.generate_host_key()
        self.assertEqual(len(key), 83)
        self.assertEqual(key[:15], b'\0\0\0\x0bssh-ed25519')
        public = provision.host_public_key(key)
        self.assertTrue(public.startswith(b'ssh-ed25519 '))
        self.assertTrue(provision.fingerprint(public.decode()).startswith('SHA256:'))

    def test_a_non_key_is_refused(self):
        with tempfile.NamedTemporaryFile('w', suffix='.pub') as stream:
            stream.write('not a key\n')
            stream.flush()
            with self.assertRaises(provision.ProvisionError):
                provision.authorized_key(stream.name)


if __name__ == '__main__':
    unittest.main()
