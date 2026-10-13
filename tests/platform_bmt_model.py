# SPDX-License-Identifier: MIT
"""An independent Python model of the vendor BBT/BMT tables, for testing the C layer.

Two stages, in the vendor's order:

    logical --[BBT shift]--> physical --[BMT substitution]--> final

The BBT lists factory-bad physical blocks below the reserve pool; logical blocks
skip them. The BMT maps worn blocks into the reserve pool. Stock measures the
pool at boot: counting down from the last block, it stops when total*8/100
blocks without a factory-bad marker have been seen. It fails above total/8 and
is clamped to the 250-entry table capacity, so a 4096-block part always has 250
and a 2048-block part 163 or more. The BMT checksum covers one entry per pool
block.

The fixture builders make synthetic tables only; they are not vendor data.
"""
import struct

BBT_MAGIC, BMT_MAGIC = b'RAWB', b'BMT'
BBT_BYTES, BMT_BYTES = 0x200, 0x3fc
BBT_HEADER, BMT_HEADER = 0xc, 0x14
BBT_STRIDE, BMT_STRIDE = 2, 4
MAX_ENTRIES = 250
BLOCK_BYTES = 0x20000
TOTAL_BLOCKS = 4096
FILL = 0xff


class FormatError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise FormatError(message)


def pool_floor(total_blocks=TOTAL_BLOCKS):
    """The least pool the vendor's downward good-block scan returns."""
    return total_blocks * 8 // 100


def pool_ceiling(total_blocks=TOTAL_BLOCKS):
    return total_blocks // 8


def clamped_pool(total_blocks=TOTAL_BLOCKS):
    """The pool size, when the part is large enough for the clamp to fix it."""
    return MAX_ENTRIES if pool_floor(total_blocks) > MAX_ENTRIES else None


def system_blocks_for(total_blocks=TOTAL_BLOCKS, pool_blocks=None):
    pool = clamped_pool(total_blocks) if pool_blocks is None else pool_blocks
    return None if pool is None else total_blocks - pool


def pool_scan(total_blocks, factory_bad):
    """Stock's measured pool, or None where its BMT init fails.

    `factory_bad` is the set of blocks whose first-page OOB byte 0 is not 0xff.
    Block 0 is never examined.
    """
    target = pool_floor(total_blocks)
    good_seen = [block for block in range(total_blocks - 1, 0, -1)
                 if block not in factory_bad][:target]
    pool = total_blocks - good_seen[-1] if target and len(good_seen) == target \
        else total_blocks
    if pool > pool_ceiling(total_blocks):
        return None
    return min(pool, MAX_ENTRIES)


def bbt_checksum(blob):
    return (blob[8] + blob[9] + sum(blob[BBT_HEADER:BBT_BYTES])) & 0xffff


def bmt_checksum(blob, pool_blocks):
    return (blob[3] + blob[5] + sum(blob[BMT_HEADER:BMT_HEADER + BMT_STRIDE * pool_blocks])) \
        & 0xff


def parse_bbt(blob):
    _require(len(blob) >= BBT_BYTES and blob[:4] == BBT_MAGIC, 'not a BBT')
    stored, version, size = struct.unpack_from('<IBB', blob, 4)
    _require(version and size <= MAX_ENTRIES, 'BBT header is invalid')
    _require(stored == bbt_checksum(blob[:BBT_BYTES]), 'BBT checksum mismatch')
    entries = list(struct.unpack_from(f'<{size}H', blob, BBT_HEADER))
    return {'size': size, 'entries': entries,
            'ascending': all(a < b for a, b in zip(entries, entries[1:]))}


def parse_bmt(blob, pool_blocks=MAX_ENTRIES):
    _require(len(blob) >= BMT_BYTES and blob[:3] == BMT_MAGIC, 'not a BMT')
    version, _unused, size, stored = struct.unpack_from('<BBBB', blob, 3)
    _require(version and size <= pool_blocks, 'BMT header is invalid')
    _require(stored == bmt_checksum(blob, pool_blocks), 'BMT checksum mismatch')
    return {'size': size,
            'entries': [dict(zip(('from', 'to'), struct.unpack_from(
                '<HH', blob, BMT_HEADER + BMT_STRIDE * index))) for index in range(size)]}


def shift_map(entries, system_blocks):
    """Stock U-Boot's construction: for each bad block, shift every later slot by one."""
    table = list(range(system_blocks))
    for entry in entries:
        for index, value in enumerate(table):
            if value == entry:
                for later in range(index, system_blocks):
                    table[later] += 1
                break
    return table


def usable_blocks(bbt, system_blocks):
    return system_blocks - bbt['size']


def translate(logical, bbt, bmt, system_blocks, table=None):
    """logical block -> final physical block."""
    table = table if table is not None else shift_map(bbt['entries'], system_blocks)
    shifted = table[logical] if logical < usable_blocks(bbt, system_blocks) else logical
    if shifted < system_blocks:
        for entry in bmt['entries']:
            if entry['from'] == shifted:
                return entry['to']
    return shifted


def shift(logical, bbt, system_blocks):
    return shift_map(bbt['entries'], system_blocks)[logical] - logical


# -- synthetic fixtures ----------------------------------------------------

def bbt(entries, version=1, size=None, checksum=None):
    table = bytearray([FILL]) * BBT_BYTES
    table[0:4] = BBT_MAGIC
    for index, block in enumerate(entries):
        struct.pack_into('<H', table, BBT_HEADER + BBT_STRIDE * index, block)
    table[8] = version
    table[9] = len(entries) if size is None else size
    struct.pack_into('<I', table, 4, 0)
    struct.pack_into('<I', table, 4, bbt_checksum(table) if checksum is None else checksum)
    return bytes(table)


def bmt(pairs, pool_blocks=MAX_ENTRIES, version=1, size=None, checksum=None,
        vendor=False):
    """A BMT; `vendor` lays it out as stock writes one: 0xff header padding,
    one zeroed entry per pool block and 0xff beyond."""
    table = bytearray([FILL]) * BMT_BYTES
    table[0:3] = BMT_MAGIC
    table[3] = version
    table[5] = len(pairs) if size is None else size
    table[6] = 0
    if vendor:
        table[BMT_HEADER:BMT_HEADER + BMT_STRIDE * pool_blocks] = \
            bytes(BMT_STRIDE * pool_blocks)
    else:
        table[7:BMT_HEADER] = bytes(BMT_HEADER - 7)
    for index, (source, target) in enumerate(pairs):
        struct.pack_into('<HH', table, BMT_HEADER + BMT_STRIDE * index, source, target)
    table[6] = bmt_checksum(table, pool_blocks) if checksum is None else checksum
    return bytes(table)
