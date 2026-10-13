# SPDX-License-Identifier: MIT
"""Identify the unit and copy its whole NAND to the host, from the dumper prompt.

The backup is the raw chip: every page with its OOB area, bad blocks left in
place, 512 MiB of data followed by 32 MiB of OOB. It is the only copy of the
stock firmware and of the unit's calibration once installation has begun, so it
is taken before anything is written and it is never overwritten.

Two raw reads of the same chip are not byte-identical: marginal cells read
differently from pass to pass (single bits, well inside the ECC strength). So a
backup is checked by the device's own SHA-256 of the buffer it sent against the
received file, not by comparison with an earlier read.
"""
from pathlib import Path
import re
import shutil

from .console import StepFailed, command
from .log import sha256_file

# The vendor identity window: `key=value` lines ending in 0xff padding, at the
# start of the `calibration` partition. Besides the serial it holds the unit's
# stock credentials, which are never printed or logged here.
IDENTITY_OFFSET = 0x400000
IDENTITY_BYTES = 0x800
IDENTITY_SCRATCH = 0x88000000
FIRST_LOOK = 0x200
SERIAL_KEY = 'serial_number'
SERIAL_FORM = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{3,63}$')
FIELD = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
# U-Boot `md.b`: address, colon, ` %02x` per byte, two spaces, ASCII column.
MD_LINE = re.compile(r'(?m)^[0-9a-fA-F]+:(.*)$')
# The unit's radio calibration: the MT7996 EEPROM image (7680 bytes used of
# 16 KiB), also in the `calibration` partition. The stock firmware copies it to
# /lib/firmware/MT7990_EEPROM.bin; the host tools send it on every radio load.
EEPROM_OFFSET = 0x405000
EEPROM_BYTES = 0x4000
EEPROM_NAME = 'eeprom.bin'
EEPROM_CHIP_ID = b'\x90\x79'      # 0x7990, little-endian, at the start of the image
# The part everything after the backup is built for (the W25N04KV): the loader,
# the BMT engine and Linux all assume this geometry.
PLATFORM_PAGE_BYTES = 0x800
PLATFORM_OOB_BYTES = 128
DUMP_BUFFER = 0x90000000
DUMP_BYTES = 0x22000000
BACKUP_NAME = 'nand-raw.bin'
SHA256_LINE = re.compile(r'==>\s*([0-9a-fA-F]{64})')
TRANSFERRED = re.compile(r'Bytes transferred = (\d+)')
EXTENT = re.compile(r'(0x[0-9a-fA-F]{8,})-(0x[0-9a-fA-F]{8,})\s*:\s*"([^"]+)"')


def parse_md(text):
    """`md.b` output back into bytes; the ASCII column is ignored."""
    out = bytearray()
    for match in MD_LINE.finditer(text):
        pairs = match.group(1).split('  ', 1)[0].split()
        if pairs and all(len(pair) == 2 for pair in pairs):
            try:
                out += bytes.fromhex(''.join(pairs))
            except ValueError:
                continue
    return bytes(out)


def parse_identity(raw):
    """The window's `key=value` fields, up to its 0xff padding."""
    end = raw.find(b'\xff\xff\xff\xff')
    fields = {}
    for line in raw[:end if end >= 0 else len(raw)].split(b'\n'):
        match = FIELD.match(line.decode('latin-1').strip())
        if match:
            fields[match.group(1)] = match.group(2)
    return fields


def serial_from(fields):
    serial = fields.get(SERIAL_KEY, '').strip()
    if not SERIAL_FORM.match(serial):
        raise StepFailed(f'the identity window holds no usable serial_number '
                         f'(fields present: {", ".join(sorted(fields)) or "none"})')
    return serial


def serial_in_backup(path):
    with open(path, 'rb') as stream:
        stream.seek(IDENTITY_OFFSET)
        return parse_identity(stream.read(IDENTITY_BYTES)).get(SERIAL_KEY, '').strip()


def read_serial(console):
    """The serial from the identity window, through the dumper.

    `.dontskipbad` keeps the offset physical. Only as much of the window is shown
    on the console as it takes to reach the serial. The read is checked: if the
    chip did not probe, the scratch buffer holds whatever RAM held before.
    """
    command(console, f'mtd read.dontskipbad spi-nand0 {IDENTITY_SCRATCH:#x} '
            f'{IDENTITY_OFFSET:#x} {IDENTITY_BYTES:#x}', limit=120)
    raw = parse_md(console.must_run(f'md.b {IDENTITY_SCRATCH:#x} {FIRST_LOOK:#x}', limit=60))
    if SERIAL_KEY not in parse_identity(raw):
        raw += parse_md(console.must_run(
            f'md.b {IDENTITY_SCRATCH + FIRST_LOOK:#x} {IDENTITY_BYTES - FIRST_LOOK:#x}',
            limit=120))
    return serial_from(parse_identity(raw))


def geometry(listing):
    """The chip as `mtd list` describes it, and the size of a raw dump of it."""
    def number(label):
        match = re.search(rf'{label}:\s*(0x[0-9a-fA-F]+|\d+)', listing)
        return int(match.group(1), 0) if match else None

    found = dict(page_bytes=number('min I/O'), oob_bytes=number('OOB size'))
    extent = EXTENT.search(listing)
    if extent and found['page_bytes'] and found['oob_bytes']:
        data = int(extent.group(2), 16) - int(extent.group(1), 16)
        found['dump_bytes'] = data + data // found['page_bytes'] * found['oob_bytes']
    return found


def check_platform_part(console):
    """Refuse to go on to writing unless the chip has the platform's geometry.

    Other parts fitted to this board (2048 blocks of 4 KiB pages) can be backed
    up, but the BMT engine would misread their vendor tables.
    """
    found = geometry(console.must_run('mtd list', limit=30))
    if (found['page_bytes'], found['oob_bytes']) != (PLATFORM_PAGE_BYTES, PLATFORM_OOB_BYTES):
        raise StepFailed(f'this chip has {found["page_bytes"]}-byte pages and '
                         f'{found["oob_bytes"]} bytes of OOB; the loader, BMT and Linux are '
                         f'built for {PLATFORM_PAGE_BYTES} and {PLATFORM_OOB_BYTES}. The backup '
                         'is kept; nothing was written')


def check_read_only(listing):
    """The dumper must report the chip read-only before it is read."""
    flags = re.search(r'flags:\s*(0x[0-9a-fA-F]+)\s*\((\w[\w-]*)\)', listing)
    if not flags or flags.group(2) != 'read-only' or int(flags.group(1), 16) & 0x400:
        raise StepFailed('the dumper does not report the chip read-only; refusing to '
                         'continue:\n' + listing[-600:])


def dump(console, log, settings, served_dir, unit_directory, serial):
    """Read the chip raw with OOB, hash it on the device, receive it, verify it.

    The transfer server writes into `served_dir`; the verified file, which must
    hold the `serial` the unit reported, moves to `unit_directory`.
    """
    target = Path(unit_directory) / BACKUP_NAME
    if target.exists():
        raise StepFailed(f'{target} exists; a backup is never overwritten')
    console.must_run('; '.join((f'setenv ipaddr {settings.device_ip}',
                                f'setenv serverip {settings.host_ip}',
                                f'setenv tftpdstp {settings.transfer_port}',
                                'setenv tftpblocksize 1468')), limit=20)
    listing = console.must_run('mtd list', limit=30)
    log.text('mtd-list.txt', listing)
    check_read_only(listing)
    size = geometry(listing).get('dump_bytes')
    if size != DUMP_BYTES:
        raise StepFailed(f'this chip needs a {size}-byte dump, not the {DUMP_BYTES} the '
                         'dumper buffer holds')
    log.text('mtd-bad.txt', console.must_run('mtd bad spi-nand0', limit=60))
    print('  reading the whole chip (about a minute, silent)')
    console.must_run(f'mtd read.raw.oob.dontskipbad spi-nand0 {DUMP_BUFFER:#x}',
                     limit=900, heartbeat=15, about=63)
    text = console.must_run(f'hash sha256 {DUMP_BUFFER:#x} {DUMP_BYTES:#x}',
                            limit=900, heartbeat=15, about=10)
    device = SHA256_LINE.search(text)
    if not device:
        raise StepFailed('the device printed no SHA-256 for the dump buffer')
    print('  sending it to the host (about 45 s)')
    partial = Path(served_dir) / BACKUP_NAME
    partial.unlink(missing_ok=True)
    text = console.must_run(f'tftpput {DUMP_BUFFER:#x} {DUMP_BYTES:#x} {BACKUP_NAME}',
                            limit=1800, heartbeat=15, about=41)
    if not TRANSFERRED.search(text) or not partial.is_file():
        raise StepFailed('tftpput did not complete:\n' + text[-600:])
    if partial.stat().st_size != DUMP_BYTES:
        raise StepFailed(f'the backup is {partial.stat().st_size} bytes, not {DUMP_BYTES}')
    received = sha256_file(partial)
    if received != device.group(1).lower():
        raise StepFailed(f'the backup was corrupted in transfer: device {device.group(1)}, '
                         f'host {received}; it was kept as {partial}')
    if serial_in_backup(partial) != serial:
        raise StepFailed(f'the backup does not hold serial {serial}; it was kept as {partial}')
    partial.chmod(0o400)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.move(partial, target)
    log.event('backup', path=str(target), sha256=received)
    return target, received


def extract_eeprom(backup_path, unit_directory):
    """Save the unit's radio calibration from its backup (the data area comes
    first in the backup, so the partition offset is the file offset)."""
    with open(backup_path, 'rb') as stream:
        stream.seek(EEPROM_OFFSET)
        data = stream.read(EEPROM_BYTES)
    if len(data) != EEPROM_BYTES or data[:2] != EEPROM_CHIP_ID:
        raise StepFailed(f'{backup_path} holds no MT7996 calibration at {EEPROM_OFFSET:#x}')
    target = Path(unit_directory) / EEPROM_NAME
    if not target.is_file() or target.read_bytes() != data:
        partial = target.with_suffix('.part')
        partial.write_bytes(data)
        partial.chmod(0o600)
        partial.replace(target)
    return target
