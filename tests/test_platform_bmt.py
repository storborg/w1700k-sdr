# SPDX-License-Identifier: MIT
"""The vendor BMT layer that the loader and Linux compile, tested on the host.

platform/bmt/airoha_bmt.c translates vendor-logical NAND addresses exactly as
stock U-Boot does; airoha_bmt_write.c and airoha_bmt_transaction.c replace worn
blocks and publish new tables. These tests compile the shipped C files for the
host and drive them:

* translation, through ctypes, against an independent Python model;
* the table-writing and transaction code, with the C harnesses in
  platform/bmt/tests (needs OpenSSL's libcrypto headers);
* the U-Boot and Linux bindings, together with the real UBI and SPI-NAND
  functions extracted from the prepared U-Boot and Linux trees (needs `make`
  to have prepared them).
"""
import ctypes
import importlib.util
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BMT = ROOT / 'platform/bmt'
LINUX_SRC = ROOT / 'platform/build/src/linux'
UBOOT_SRC = ROOT / 'platform/build/src/u-boot-loader'
sys.path[:0] = [str(Path(__file__).resolve().parent), str(ROOT / 'platform')]
import partitions                       # noqa: E402
import platform_bmt_model as model      # noqa: E402

CC = shutil.which('cc') or shutil.which('gcc')
TOTAL = model.TOTAL_BLOCKS
SYSTEM = model.system_blocks_for(TOTAL)
POOL = model.clamped_pool(TOTAL)
FACTORY_BAD = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
# The vendor tables of a W25N04L unit (2048 blocks), as read from its NAND: six
# factory-bad blocks, an empty BMT, and the 163-block pool stock reported.
UNIT_BBT = (b'RAWB' + bytes.fromhex('1c030000') + bytes([1, 6, 255, 255]) +
            bytes.fromhex('0004330466049904cc04ff04') + bytes(488))
UNIT_BMT = (b'BMT' + bytes([1, 255, 0, 1]) + b'\xff' * 13 + bytes(4 * 163) +
            b'\xff' * (4 * 87))
UNIT_FACTORY = [1024, 1075, 1126, 1177, 1228, 1279]


def partitions_for(part):
    """platform/partitions.py as evaluated for one NAND part."""
    spec = importlib.util.spec_from_file_location(f'partitions_{part}',
                                                  ROOT / 'platform/partitions.py')
    module = importlib.util.module_from_spec(spec)
    saved = os.environ.get('W1700K_NAND')
    os.environ['W1700K_NAND'] = part
    try:
        spec.loader.exec_module(module)
    finally:
        if saved is None:
            del os.environ['W1700K_NAND']
        else:
            os.environ['W1700K_NAND'] = saved
    return module


def policy_headers(directory):
    """One include directory per part, holding that part's airoha_bmt_policy.h."""
    out = {}
    for part in partitions.PARTS:
        include = Path(directory) / part
        include.mkdir()
        (include / 'airoha_bmt_policy.h').write_text(partitions_for(part).policy_header())
        out[part] = include
    return out
# Factory bad blocks straddling the ownership boundaries, and two worn blocks
# substituted into the reserve pool.
FACTORY = [5, 11, 20, 40, 100]
REMAP = [(7, SYSTEM + 3), (41, SYSTEM + 4)]
ERRORS = {'SHORT': -1, 'SIGNATURE': -2, 'VERSION': -3, 'SIZE': -4, 'CHECKSUM': -5,
          'UNPINNABLE': -6, 'RANGE': -7, 'ORDER': -8, 'NOTLOADED': -9}


def has_header(header):
    if CC is None:
        return False
    probe = subprocess.run([CC, '-x', 'c', '-fsyntax-only', '-'],
                           input=f'#include <{header}>\n', text=True, capture_output=True)
    return probe.returncode == 0


LIBCRYPTO = has_header('openssl/sha.h')


class Table(ctypes.Structure):
    _fields_ = [('total_blocks', ctypes.c_uint16), ('system_blocks', ctypes.c_uint16),
                ('geometry_set', ctypes.c_uint8), ('bbt_loaded', ctypes.c_uint8),
                ('bmt_loaded', ctypes.c_uint8), ('bbt_ascending', ctypes.c_uint8),
                ('bbt_size', ctypes.c_uint16), ('bmt_size', ctypes.c_uint16),
                ('bbt_entries', ctypes.c_uint16 * model.MAX_ENTRIES),
                ('bmt_from', ctypes.c_uint16 * model.MAX_ENTRIES),
                ('bmt_to', ctypes.c_uint16 * model.MAX_ENTRIES)]


@unittest.skipIf(CC is None, 'needs a host C compiler')
class Translation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        library = Path(cls.work.name) / 'libairoha_bmt.so'
        subprocess.run([CC, '-DAIROHA_BMT_HOST', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-std=c11', '-fPIC', '-shared', BMT / 'airoha_bmt.c',
                        BMT / 'host_shim.c', '-o', library], check=True)
        lib = ctypes.CDLL(str(library))
        lib.airoha_bmt_sizeof.restype = ctypes.c_size_t
        for name in ('airoha_bmt_pool_floor', 'airoha_bmt_pool_ceiling',
                     'airoha_bmt_clamped_pool'):
            getattr(lib, name).restype = ctypes.c_uint32
            getattr(lib, name).argtypes = [ctypes.c_uint32]
        lib.airoha_bmt_set_geometry.argtypes = [ctypes.POINTER(Table), ctypes.c_uint32,
                                                ctypes.c_uint32]
        lib.airoha_bmt_pool_scan.argtypes = [ctypes.c_uint32, FACTORY_BAD, ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_uint32)]
        for name in ('airoha_bmt_parse_bbt', 'airoha_bmt_parse_bmt'):
            getattr(lib, name).argtypes = [ctypes.POINTER(Table), ctypes.c_char_p,
                                           ctypes.c_uint32]
        for name in ('airoha_bmt_translate', 'airoha_bmt_shift', 'airoha_bmt_untranslate'):
            getattr(lib, name).argtypes = [ctypes.POINTER(Table), ctypes.c_uint32]
        lib.airoha_bmt_usable_blocks.argtypes = [ctypes.POINTER(Table)]
        cls.lib = lib

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def loaded(self, bbt=None, bmt=None):
        table = Table()
        bbt = model.bbt(FACTORY) if bbt is None else bbt
        bmt = model.bmt(REMAP) if bmt is None else bmt
        self.assertEqual(self.lib.airoha_bmt_set_geometry(ctypes.byref(table), TOTAL, POOL), 0)
        self.assertEqual(self.lib.airoha_bmt_parse_bbt(ctypes.byref(table), bbt, len(bbt)), 0)
        self.assertEqual(self.lib.airoha_bmt_parse_bmt(ctypes.byref(table), bmt, len(bmt)), 0)
        return table

    def test_struct_layout_matches_the_c_definition(self):
        self.assertEqual(self.lib.airoha_bmt_sizeof(), ctypes.sizeof(Table))

    def scan(self, total, bad, error_at=None):
        reads = []

        def factory_bad(_, block):
            reads.append(block)
            return -5 if block == error_at else int(block in bad)
        pool = ctypes.c_uint32(0)
        status = self.lib.airoha_bmt_pool_scan(total, FACTORY_BAD(factory_bad), None,
                                               ctypes.byref(pool))
        return status, pool.value, reads

    def test_pool_is_clamped_to_the_table_capacity(self):
        self.assertEqual(self.lib.airoha_bmt_pool_floor(TOTAL), TOTAL * 8 // 100)
        self.assertEqual(self.lib.airoha_bmt_pool_ceiling(TOTAL), TOTAL // 8)
        self.assertEqual(self.lib.airoha_bmt_clamped_pool(TOTAL), model.MAX_ENTRIES)
        small = TOTAL // 2
        self.assertIsNone(model.clamped_pool(small))
        self.assertEqual(self.lib.airoha_bmt_clamped_pool(small), 0)

    def test_the_pool_is_measured_as_stock_measures_it(self):
        top = {2048: 2048 - 163, 4096: 4096 - 327}
        for total in (2048, 4096):
            cases = [set(), {total - 1}, {top[total]}, {top[total] - 1},
                     set(range(total - 30, total)), set(range(top[total] - 80, total, 3)),
                     {5, 11, 1024}, set(range(1, total))]
            for bad in cases:
                with self.subTest(total=total, bad=len(bad)):
                    status, pool, reads = self.scan(total, bad)
                    expected = model.pool_scan(total, bad)
                    if expected is None:
                        self.assertEqual(status, ERRORS['UNPINNABLE'])
                        continue
                    self.assertEqual((status, pool), (0, expected))
                    # Only the span stock reads; block 0 never.
                    self.assertEqual(reads[0], total - 1)
                    self.assertNotIn(0, reads)
        # On the smaller part a factory-bad block in the span grows the pool,
        # which moves the reserve; on the larger the clamp absorbs it.
        self.assertEqual(self.scan(2048, set())[1], 163)
        self.assertEqual(self.scan(2048, {2047, 1900})[1], 165)
        self.assertEqual(self.scan(4096, {4095, 3900})[1], 250)
        status, _, reads = self.scan(2048, set(), error_at=2000)
        self.assertEqual(status, -5)
        self.assertEqual(reads[-1], 2000)

    def test_only_a_pool_stock_can_measure_is_accepted(self):
        table = Table()
        for total, pool, status in [(4096, 250, 0), (4096, 249, 'UNPINNABLE'),
                                    (4096, 251, 'UNPINNABLE'), (2048, 163, 0),
                                    (2048, 250, 0), (2048, 162, 'UNPINNABLE'),
                                    (2048, 251, 'UNPINNABLE'), (1024, 129, 'UNPINNABLE'), (1024, 128, 0),
                                    (1024, 81, 0), (0x10000, 250, 'RANGE')]:
            with self.subTest(total=total, pool=pool):
                self.assertEqual(self.lib.airoha_bmt_set_geometry(ctypes.byref(table),
                                                                  total, pool),
                                 ERRORS.get(status, 0))
                if not status:
                    self.assertEqual(table.system_blocks, total - pool)

    def test_a_w25n04l_units_tables_validate_at_its_measured_pool(self):
        table = Table()
        status, pool, _ = self.scan(2048, set(UNIT_FACTORY))
        self.assertEqual((status, pool), (0, 163))
        self.assertEqual(self.lib.airoha_bmt_set_geometry(ctypes.byref(table), 2048, pool), 0)
        self.assertEqual(table.system_blocks, 1885)
        self.assertEqual(self.lib.airoha_bmt_parse_bbt(ctypes.byref(table), UNIT_BBT,
                                                       len(UNIT_BBT)), 0)
        self.assertEqual(self.lib.airoha_bmt_parse_bmt(ctypes.byref(table), UNIT_BMT,
                                                       len(UNIT_BMT)), 0)
        self.assertEqual(list(table.bbt_entries[:table.bbt_size]), UNIT_FACTORY)
        self.assertEqual(self.lib.airoha_bmt_usable_blocks(ctypes.byref(table)), 1879)
        self.assertEqual(self.lib.airoha_bmt_translate(ctypes.byref(table), 1023), 1023)
        self.assertEqual(self.lib.airoha_bmt_translate(ctypes.byref(table), 1024), 1025)
        self.assertEqual(self.lib.airoha_bmt_translate(ctypes.byref(table), 1878), 1884)
        bbt = model.parse_bbt(UNIT_BBT)
        self.assertEqual(model.parse_bmt(UNIT_BMT, 163)['size'], 0)
        for logical in range(0, 1879, 7):
            self.assertEqual(self.lib.airoha_bmt_translate(ctypes.byref(table), logical),
                             model.translate(logical, bbt, {'entries': []}, 1885))
        # The vendor's checksum covers exactly 163 entries: no other pool parses it.
        for other in (164, 170, 250):
            self.lib.airoha_bmt_set_geometry(ctypes.byref(table), 2048, other)
            self.assertEqual(self.lib.airoha_bmt_parse_bmt(ctypes.byref(table), UNIT_BMT,
                                                           len(UNIT_BMT)), ERRORS['CHECKSUM'])

    def test_every_block_translates_like_the_model(self):
        table = self.loaded()
        bbt, bmt = model.parse_bbt(model.bbt(FACTORY)), model.parse_bmt(model.bmt(REMAP))
        usable = model.usable_blocks(bbt, SYSTEM)
        self.assertEqual(self.lib.airoha_bmt_usable_blocks(ctypes.byref(table)), usable)
        shifts = model.shift_map(bbt['entries'], SYSTEM)
        for logical in range(usable + 8):
            self.assertEqual(self.lib.airoha_bmt_translate(ctypes.byref(table), logical),
                             model.translate(logical, bbt, bmt, SYSTEM, shifts), logical)

    def test_a_worn_block_is_substituted_into_the_pool(self):
        # Logical 6 shifts past bad block 5 to physical 7, which REMAP replaces.
        self.assertEqual(self.lib.airoha_bmt_translate(ctypes.byref(self.loaded()), 6),
                         SYSTEM + 3)

    def test_partition_boundaries_round_trip(self):
        table = self.loaded()
        bbt = model.parse_bbt(model.bbt(FACTORY))
        usable = self.lib.airoha_bmt_usable_blocks(ctypes.byref(table))
        shifted = 0
        for name, (offset, _) in partitions.GEOMETRY.items():
            logical = offset // model.BLOCK_BYTES
            if logical >= usable:
                continue
            final = self.lib.airoha_bmt_translate(ctypes.byref(table), logical)
            self.assertGreaterEqual(final, 0, name)
            self.assertEqual(self.lib.airoha_bmt_untranslate(ctypes.byref(table), final),
                             logical, name)
            shift = self.lib.airoha_bmt_shift(ctypes.byref(table), logical)
            self.assertEqual(shift, model.shift(logical, bbt, SYSTEM), name)
            shifted += shift > 0
        self.assertTrue(shifted, 'the fixture must shift some boundary')

    def test_invalid_tables_are_refused_never_repaired(self):
        table = Table()
        self.lib.airoha_bmt_set_geometry(ctypes.byref(table), TOTAL, POOL)
        broken = bytearray(model.bmt(REMAP))
        broken[model.BMT_HEADER + 4 * (POOL - 1)] ^= 1
        cases = {
            'SIGNATURE': [(b'RAWX' + model.bbt(FACTORY)[4:], 'bbt'),
                          (b'BMX' + model.bmt(REMAP)[3:], 'bmt')],
            'CHECKSUM': [(model.bbt(FACTORY, checksum=0x1234), 'bbt'),
                         (model.bmt(REMAP, checksum=0x5a), 'bmt'),
                         # a byte beyond the claimed entries is still covered
                         (bytes(broken), 'bmt')],
            'SIZE': [(model.bbt(FACTORY, size=251), 'bbt'),
                     (model.bmt([(1, 2)], size=251), 'bmt')],
            'SHORT': [(model.bbt(FACTORY)[:-1], 'bbt'), (model.bmt(REMAP)[:-1], 'bmt')],
            'VERSION': [(model.BBT_MAGIC + bytes(model.BBT_BYTES - 4), 'bbt'),
                        (model.BMT_MAGIC + bytes(model.BMT_BYTES - 3), 'bmt')],
        }
        for error, blobs in cases.items():
            for blob, kind in blobs:
                parse = getattr(self.lib, f'airoha_bmt_parse_{kind}')
                self.assertEqual(parse(ctypes.byref(table), blob, len(blob)),
                                 ERRORS[error], f'{kind} {error}')

    def test_a_descending_bbt_refuses_translation(self):
        table = Table()
        self.lib.airoha_bmt_set_geometry(ctypes.byref(table), TOTAL, POOL)
        descending = model.bbt(list(reversed(FACTORY)))
        self.lib.airoha_bmt_parse_bbt(ctypes.byref(table), descending, len(descending))
        bmt = model.bmt(REMAP)
        self.lib.airoha_bmt_parse_bmt(ctypes.byref(table), bmt, len(bmt))
        self.assertEqual(table.bbt_ascending, 0)
        self.assertEqual(self.lib.airoha_bmt_translate(ctypes.byref(table), 6), ERRORS['ORDER'])

    def test_entries_outside_the_vendor_bounds_are_refused(self):
        for bbt, bmt, expected in [
                ([SYSTEM - 1], [], 0), ([SYSTEM], [], 'RANGE'), ([TOTAL], [], 'RANGE'),
                ([], [(64, SYSTEM)], 0), ([], [(64, TOTAL - 1)], 0),
                ([], [(64, 0)], 'RANGE'), ([], [(64, SYSTEM - 1)], 'RANGE'),
                ([], [(64, TOTAL)], 'RANGE'), ([], [(TOTAL, SYSTEM)], 'RANGE'),
                ([], [(TOTAL - 1, SYSTEM)], 0)]:
            table = Table()
            self.lib.airoha_bmt_set_geometry(ctypes.byref(table), TOTAL, POOL)
            first, second = model.bbt(bbt), model.bmt(bmt)
            status = self.lib.airoha_bmt_parse_bbt(ctypes.byref(table), first, len(first)) or \
                self.lib.airoha_bmt_parse_bmt(ctypes.byref(table), second, len(second))
            self.assertEqual(status, ERRORS.get(expected, 0), (bbt, bmt))
            if status:
                self.assertEqual(self.lib.airoha_bmt_translate(ctypes.byref(table), 64),
                                 ERRORS['NOTLOADED'])


def no_core_dump():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def compile_and_run(command, binary, timeout=60):
    """Compile a harness and run it; harnesses fail by assert(), so no core files."""
    subprocess.run([*map(str, command), '-o', str(binary)], check=True)
    return subprocess.run([str(binary)], capture_output=True, text=True, timeout=timeout,
                          preexec_fn=no_core_dump)


@unittest.skipUnless(CC and LIBCRYPTO, 'needs a host C compiler and OpenSSL headers')
class TableWriting(unittest.TestCase):
    """Canonical table bytes, publication and journalled replacement, in a NAND model."""

    def test_harnesses_pass(self):
        with tempfile.TemporaryDirectory() as work:
            for part, include in policy_headers(work).items():
                for name in ('write_contract', 'publication', 'remap'):
                    with self.subTest(part=part, harness=name):
                        result = compile_and_run(
                            [CC, '-DAIROHA_BMT_HOST', '-std=c11', '-O1', '-g', '-Wall',
                             '-Wextra', '-Werror', '-fsanitize=undefined',
                             '-fno-sanitize-recover=all', f'-I{include}', f'-I{BMT}',
                             BMT / f'tests/{name}.c', BMT / 'airoha_bmt.c',
                             BMT / 'airoha_bmt_write.c', BMT / 'airoha_bmt_transaction.c',
                             '-lcrypto'], include / name, timeout=300)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2]


PREPARED = LINUX_SRC.is_dir() and UBOOT_SRC.is_dir()


@unittest.skipUnless(CC and LIBCRYPTO and PREPARED,
                     'needs a host C compiler, OpenSSL headers and the trees `make` prepares')
class Bindings(unittest.TestCase):
    """The U-Boot and Linux MTD bindings, driven through fault-injecting NAND callbacks.

    The kernel's real spinand_probe/remove and mtdchar read path, and both trees'
    UBI write/erase callers, are cut from the prepared sources and compiled in.
    """

    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        out = Path(cls.work.name)
        cls.includes = policy_headers(out)
        core = (LINUX_SRC / 'drivers/mtd/nand/spi/core.c').read_text()
        start = core.index('static int spinand_probe(')
        probe = core[start:core.index('static const struct spi_device_id', start)]
        (out / 'lifecycle.inc').write_text((BMT / 'tests/lifecycle.h').read_text() + probe +
                                           (BMT / 'tests/lifecycle_tail.h').read_text())
        mtdchar = (LINUX_SRC / 'drivers/mtd/mtdchar.c').read_text()
        start = mtdchar.index('static noinline_for_stack int\nmtdchar_read_ioctl(')
        memread = mtdchar[start:mtdchar.index('static int mtdchar_ioctl(', start)]
        (out / 'memread.inc').write_text((BMT / 'tests/memread.h').read_text() + memread +
                                         (BMT / 'tests/memread_tail.h').read_text())
        cls.out = out

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def command(self, layer, linux, part):
        command = [CC, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=undefined', '-fno-sanitize-recover=all',
                   f'-I{BMT / "tests/include"}', f'-I{self.includes[part]}', f'-I{BMT}',
                   f'-I{self.out}', f'-DLAYER_FILE="{layer}"']
        return command + (['-DTEST_LINUX'] if linux else [])

    def ubi_consumer(self, name, tree):
        io = (tree / 'drivers/mtd/ubi/io.c').read_text()
        snippets = '\n'.join(function(io, signature) for signature in (
            'int ubi_io_write(', 'static int do_sync_erase(', 'int ubi_io_mark_bad('))
        wl = (tree / 'drivers/mtd/ubi/wl.c').read_text()
        begin = wl.index('\n\t/* It is %-EIO, the PEB went bad */')
        tail = ('static int actual_bad_peb_tail(struct ubi_device *ubi,int pnum)\n'
                '{\n int err=-EIO,available_consumed=0;\n' + wl[begin:wl.index('\n}', begin) + 2])
        include = self.out / f'ubi-{name}.inc'
        include.write_text((BMT / 'tests/ubi_consumer.h').read_text() +
                           '\n#pragma GCC diagnostic push\n'
                           '#pragma GCC diagnostic ignored "-Wsign-compare"\n' + snippets +
                           '\n' + tail + '\n#pragma GCC diagnostic pop\n' +
                           (BMT / 'tests/ubi_consumer_tail.h').read_text())
        return include

    def check_binding(self, name, layer, tree, write_config):
        linux = name == 'linux'
        include = self.ubi_consumer(name, tree)
        for part in partitions.PARTS:
            with self.subTest(part=part):
                result = compile_and_run(self.command(layer, linux, part) +
                                         [BMT / 'tests/bindings.c', BMT / 'airoha_bmt.c'],
                                         self.out / f'{name}-{part}', timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                result = compile_and_run(
                    self.command(layer, linux, part) +
                    [f'-D{write_config}=1', '-DAIROHA_BMT_HOST',
                     f'-DUBI_CONSUMER_FILE="{include}"', BMT / 'tests/managed_bindings.c',
                     BMT / 'airoha_bmt.c', BMT / 'airoha_bmt_write.c',
                     BMT / 'airoha_bmt_transaction.c', '-lcrypto', '-pthread'],
                    self.out / f'managed-{name}-{part}', timeout=120)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_uboot_binding(self):
        self.check_binding('uboot', ROOT / 'platform/loader/airoha_bmt_layer.c', UBOOT_SRC,
                           'CONFIG_AIROHA_BMT_WRITE')

    def test_linux_binding(self):
        self.check_binding('linux', ROOT / 'platform/linux/sdr_bmt_layer.c', LINUX_SRC,
                           'CONFIG_AIROHA_SDR_BMT_WRITE')


@unittest.skipUnless(CC and PREPARED, 'needs a host C compiler and the trees `make` prepares')
class IoGuards(unittest.TestCase):
    """A NAND DMA error must reset the SoC, not release buffers the controller may
    still write; a NAND command whose completion is unknown must stop the caller.

    The SPI controller's DMA error tails and spinand_wait() are cut from each
    prepared tree and run against a model; removing the reset guard must fail.
    """

    GUARD = 'panic("AN7581 NAND DMA error %d; reset required", err);'

    @staticmethod
    def extract(spi, core, uboot):
        tails = spi.split('error_dma_unmap:\n')
        assert len(tails) == 3, 'expected exactly two DMA error tails'
        context = 'priv' if uboot else 'as_ctrl'
        functions = []
        for direction, tail in zip(('read', 'write'), tails[1:]):
            functions.append(f'static int dma_{direction}_error(int err, int before_map) {{\n'
                             f' void *{context}=0; if(before_map) goto error_dma_mode_off;\n'
                             ' goto error_dma_unmap;\nerror_dma_unmap:\n'
                             + tail[:tail.index('\n}')] + '\n}\n')
        start = core.index('int spinand_wait(')
        return '\n'.join(functions) + '\n' + core[start:core.index(
            '\nstatic int spinand_read_id_op', start)]

    def run_guard(self, name, code, work):
        source = Path(work) / f'{name}.c'
        source.write_text((BMT / 'tests/io_guards.h').read_text() + code +
                          (BMT / 'tests/io_guards_tail.h').read_text())
        command = [CC, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=undefined', '-fno-sanitize-recover=all', source]
        if name.startswith('uboot'):
            command.insert(1, '-DTEST_UBOOT')
        return compile_and_run(command, Path(work) / name, timeout=10)

    def test_guards_in_both_trees(self):
        trees = {'linux': (LINUX_SRC / 'drivers/spi/spi-airoha-snfi.c', LINUX_SRC),
                 'uboot': (UBOOT_SRC / 'drivers/spi/airoha_snfi_spi.c', UBOOT_SRC)}
        with tempfile.TemporaryDirectory() as work:
            for name, (spi, tree) in trees.items():
                with self.subTest(name):
                    code = self.extract(spi.read_text(), (tree / 'drivers/mtd/nand/spi/core.c')
                                        .read_text(), name == 'uboot')
                    result = self.run_guard(name, code, work)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(self.GUARD, code)
                    unguarded = self.run_guard(f'{name}-unguarded',
                                               code.replace(self.GUARD, 'return err;', 1), work)
                    self.assertNotEqual(unguarded.returncode, 0,
                                        'the model passes without the reset guard')

    def test_a_panic_cannot_enter_another_kernel(self):
        config = ROOT / 'platform/build/linux/.config'
        if not config.is_file():
            self.skipTest('the kernel is not configured')
        lines = config.read_text().splitlines()
        for symbol in ('CONFIG_KEXEC', 'CONFIG_KEXEC_CORE', 'CONFIG_KEXEC_FILE',
                       'CONFIG_CRASH_DUMP'):
            self.assertNotIn(f'{symbol}=y', lines)


if __name__ == '__main__':
    unittest.main()
