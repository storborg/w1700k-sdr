# SPDX-License-Identifier: MIT
"""A simulated unit behind the ConsoleSession interface, for testing init/ offline.

It models the four console states (stock U-Boot, the dumper, our loader, Linux),
RAM, the loader partition, the stock environment and the UBI volumes well enough
that installation and update runs can execute end to end, and it records every
command it was given. Images are recognised by a marker after the FIT magic.
"""
import hashlib
import re
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'init'))
from initkit.config import partitions  # noqa: E402
from initkit.uart import MUTATING  # noqa: E402

PROMPTS = {'stock': 'ECNT> ', 'dumper': 'dumper> ', 'loader': 'SDR loader> ',
           'linux': '/ # '}
STOCK_BOOTCMD = 'flash imgread 2048;bootm'
# The radio calibration image in the calibration partition: chip ID 0x7990 first.
CALIBRATION = b'\x90\x79' + bytes(7678)
IDENTITY = (b'wan_mac=00:11:22:33:44:55\nserial_number=W1700KTEST0001\n'
            b'manufacturer=Gemtek\nwifi_passphrase=secret\n')
RC = re.compile(r'^(.*); echo (W1700K_RC_[0-9a-f]+=)\$\?$', re.S)


def split_commands(line):
    """Split a command line at `; ` outside single quotes, as U-Boot's shell does."""
    parts, current, quoted = [], '', False
    for index, char in enumerate(line):
        if char == "'":
            quoted = not quoted
        if not quoted and line.startswith('; ', index):
            parts.append(current)
            current = ''
            continue
        if not (current == '' and char == ' ' and parts):
            current += char
    return parts + [current]


def fit(marker, size=0x9000):
    """A fake FIT: the magic, a marker naming what it is, then filler."""
    body = b'\xd0\x0d\xfe\xed' + marker.encode() + b'\0'
    return body + bytes((index * 7) & 0xff for index in range(size - len(body)))


class Refused(Exception):
    """The simulated console refused a write, as the real one does."""


class FakeUnit:
    def __init__(self, served, chip_bytes=0x420000, installed=False, chip_probes=True):
        self.served = Path(served)
        self.state = 'off'
        self.env = {'bootcmd': STOCK_BOOTCMD, 'ethaddr': '00:aa:bb:01:23:40'}
        self.saved = dict(self.env)
        self.ram = {}
        self.loader_slot = b''
        self.ubi = {'system': {}, 'durable': {}}
        self.attached = None
        self.erased = []
        self.log = []                  # (state, command)
        self.chip_bytes = chip_bytes
        self.chip_probes = chip_probes
        # The chip of the part the images are built for.
        self.page_bytes, self.oob_bytes = partitions.PAGE_BYTES, partitions.PART.oob
        self.allow_mutating = False
        self.buffer = ''
        self.catcher_armed = True
        if installed:
            self.loader_slot = fit('loader') + b'\xff' * (0x40000 - 0x9000)
            self.saved['bootcmd'] = self.env['bootcmd'] = \
                'flash read 0x600000 0x40000 0x89000000; bootm 0x89000000'
            self.ubi['system'] = {'ubootenv': b'', 'ubootenv2': b'', 'fit': fit('system'),
                                  'rootfs': b'hsqs-old'}

    # -- the ConsoleSession interface ----------------------------------------
    def check_command(self, line):
        if MUTATING.search(line) and not self.allow_mutating:
            raise Refused(line)

    def mark(self):
        return len(self.buffer)

    def view(self, start=0):
        return self.buffer[start:]

    def at_prompt(self, which):
        return self.state == which

    def wait(self, ready, timeout, description):
        if self.state == 'loader-countdown':        # nobody interrupted: autoboot
            self.state = 'loader'
            self.run_bootcmd()
        return bool(ready())

    def arm(self):
        self.catcher_armed = True

    def wait_for_catch(self, timeout):
        if not self.catcher_armed:
            raise RuntimeError('no catcher armed')
        self.catcher_armed = False
        self.boot_stock()
        return 'confirmed'

    def expect_prompt(self, which, timeout=None):
        if self.state != which:
            raise RuntimeError(f'expected {which}, at {self.state}')
        return which

    def interrupt_autoboot(self, which, limit=None):
        if self.state == 'loader-countdown':
            self.state = 'loader'
        return self.expect_prompt(which)

    def send_interrupt(self):
        self.log.append((self.state, '^C'))

    def send_async(self, line):
        self.check_command(line)
        self.log.append((self.state, line))
        if line == '':
            return
        if line in ('reset', 'reboot -f'):
            self.state = 'rebooting'
        elif line.startswith('bootm '):
            self.bootm(int(line.split()[1].split('#')[0], 16), line)
        elif line == 'run bootcmd':
            self.run_bootcmd()
        else:
            raise AssertionError(f'unexpected async command {line!r}')

    def must_run(self, line, limit=None, heartbeat=None, about=None):
        self.check_command(line)
        match = RC.match(line)
        base, token = (match.group(1), match.group(2)) if match else (line, None)
        self.log.append((self.state, base))
        output, status = self.execute(base)
        text = f'{line}\n{output}\n'
        if token:
            text += f'{token}{status}\n'
        text += PROMPTS[self.state]
        self.buffer += text
        return text

    def run(self, line, **options):
        return self.must_run(line, **options), True

    # -- boot transitions ----------------------------------------------------
    def boot_stock(self):
        self.env = dict(self.saved)
        self.ram = {}
        self.attached = None
        self.state = 'stock'

    def bootm(self, address, line):
        image = self.ram.get(address, b'')
        if b'dumper' in image[:16]:
            self.state = 'dumper'
        elif b'loader' in image[:16]:
            self.state = 'loader-countdown'
        elif b'recovery' in image[:16] and line.endswith('#conf-sdr'):
            self.state = 'linux'
            self.buffer += 'W1700K_BOOT_READY\n/ # '
        else:
            raise AssertionError(f'bootm of an unknown image at {address:#x}')

    def run_bootcmd(self):
        if self.state == 'stock':
            match = re.match(r'flash read 0x600000 (0x[0-9a-f]+) 0x89000000; bootm 0x89000000$',
                             self.env['bootcmd'])
            assert match, f'stock bootcmd {self.env["bootcmd"]!r} does not boot our loader'
            self.ram[0x89000000] = self.loader_slot[:int(match.group(1), 16)]
            self.bootm(0x89000000, 'bootm')
        elif self.state == 'loader':
            assert b'system' in self.ubi['system'].get('fit', b'')[:16], 'no system FIT'
            self.state = 'linux'
            self.buffer += 'W1700K_BOOT_READY\n/ # '
        else:
            raise AssertionError(f'run bootcmd at {self.state}')

    # -- commands --------------------------------------------------------------
    def execute(self, line):
        parts = split_commands(line)
        if len(parts) > 1:
            for part in parts:
                self.execute(part)
            return '', 0
        words = line.split()
        name = re.sub(r'[./-]', '_', words[0])
        handler = getattr(self, f'{self.state}_{name}', None) or \
            getattr(self, f'any_{words[0].split(".")[0]}', None)
        if handler is None:
            raise AssertionError(f'{self.state} does not know {line!r}')
        return handler(line, words)

    def any_setenv(self, line, words):
        name, _, value = line[len('setenv '):].partition(' ')
        self.env[name] = value.strip("'")
        return '', 0

    def any_printenv(self, line, words):
        return '\n'.join(f'{key}={value}' for key, value in self.env.items()), 0

    def any_tftpboot(self, line, words):
        path = self.served / words[2]
        if not path.is_file():
            return 'TFTP error: File not found', 1
        data = path.read_bytes()
        self.ram[int(words[1], 16)] = data
        return f'Bytes transferred = {len(data)} ({len(data):x} hex)', 0

    def read_ram(self, address, length):
        """RAM as one span: pieces loaded at consecutive addresses join up."""
        data = bytearray()
        cursor = address
        while len(data) < length and cursor in self.ram:
            piece = self.ram[cursor]
            data += piece
            cursor += len(piece)
        return bytes(data[:length])

    def any_crc32(self, line, words):
        data = self.read_ram(int(words[1], 16), int(words[2], 16))
        return f'CRC32 for {words[1]} ==> {zlib.crc32(data):08x}', 0

    def any_iminfo(self, line, words):
        data = self.read_ram(int(words[1], 16), 16)
        if not data.startswith(b'\xd0\x0d\xfe\xed'):
            return 'Bad Magic Number', 1
        algorithm = 'sha1' if self.state == 'stock' else 'sha256'
        return f'   Hash(es) for Image 0 (kernel): {algorithm}+\n' \
               f'   Hash(es) for Image 1 (fdt): {algorithm}+', 0

    def any_hash(self, line, words):
        data = self.read_ram(int(words[2], 16), int(words[3], 16))
        return f'sha256 for {words[2]} ==> {hashlib.sha256(data).hexdigest()}', 0

    def stock_flash(self, line, words):
        action, offset, length = words[1], int(words[2], 16), int(words[3], 16)
        assert offset == 0x600000, 'stock wrote outside the loader slot'
        if action == 'erase':
            self.loader_slot = b'\xff' * length
        elif action == 'write':
            self.loader_slot = self.read_ram(int(words[4], 16), length)
        elif action == 'read':
            self.ram[int(words[4], 16)] = self.loader_slot[:length]
        return f'{action}: addr={offset:#x}', 0

    def stock_cmp_b(self, line, words):
        a = self.read_ram(int(words[1], 16), int(words[3], 16))
        b = self.read_ram(int(words[2], 16), int(words[3], 16))
        return ('Total of bytes were the same', 0) if a == b else ('differ', 1)

    def stock_saveenv(self, line, words):
        self.saved = dict(self.env)
        return 'Saving Environment to ECNT Flash...', 0

    def dumper_mtd(self, line, words):
        if not self.chip_probes:
            return ('spi_nand nand@0: unknown raw ID ef 8b 23 00\n'
                    'mtd: nand@0 did not probe: -95\n'
                    'MTD device spi-nand0 not found, ret -19'), 1
        if words[1] == 'list':
            return (f'* spi-nand0\n  - flags: 0x0 (read-only)\n'
                    f'  - min I/O: {self.page_bytes:#x} bytes\n'
                    f'  - OOB size: {self.oob_bytes} bytes\n'
                    f'  - 0x000000000000-0x{self.chip_bytes:012x} : "spi-nand0"'), 0
        if words[1] == 'bad':
            return '', 0
        if words[1] == 'read.dontskipbad':
            self.ram[int(words[3], 16)] = IDENTITY + b'\xff' * (0x800 - len(IDENTITY))
            return 'Reading', 0
        if words[1] == 'read.raw.oob.dontskipbad':
            data = bytearray(self.chip_bytes + self.chip_bytes // 0x800 * 128)
            data[0x400000:0x400000 + len(IDENTITY)] = IDENTITY
            data[0x405000:0x405000 + len(CALIBRATION)] = CALIBRATION
            self.ram[int(words[3], 16)] = bytes(data)
            return 'Reading', 0
        raise AssertionError(line)

    def dumper_md_b(self, line, words):
        address, length = int(words[1], 16), int(words[2], 16)
        base = max(start for start in self.ram if start <= address)
        data = self.ram[base][address - base:address - base + length]
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            lines.append(f'{address + offset:08x}:' + ''.join(f' {c:02x}' for c in chunk) + '  x')
        return '\n'.join(lines), 0

    def dumper_tftpput(self, line, words):
        data = self.read_ram(int(words[1], 16), int(words[2], 16))
        (self.served / words[3]).write_bytes(data)
        return f'Bytes transferred = {len(data)}', 0

    def loader_bmtstats(self, line, words):
        return 'bmtstats erase=0/0 program=0/0 markbad=0/0 readback=0/0', 0

    def loader_ubi(self, line, words):
        action = words[1]
        if action == 'detach':
            self.attached = None
            return '', 0
        if action == 'part.rw':
            self.attached = words[2]
            return f"UBI partition '{words[2]}' selected read-write", 0
        volumes = self.ubi[self.attached]
        if action == 'create':
            volumes[words[2]] = b''
            return f'Creating volume {words[2]}', 0
        if action == 'write':
            volumes[words[3]] = self.read_ram(int(words[2], 16), int(words[4], 16))
            return f'{int(words[4], 16)} bytes written to volume {words[3]}', 0
        if action == 'read':
            data = volumes.get(words[3], b'')[:int(words[4], 16)]
            self.ram[int(words[2], 16)] = data
            return f'Read {len(data)} bytes from volume {words[3]}', 0
        raise AssertionError(line)

    def loader_mtd(self, line, words):
        assert words[1] == 'erase', line
        self.erased.append((words[2], int(words[3], 16), int(words[4], 16)))
        self.ubi[words[2]] = {}
        return 'Erasing', 0

    def linux__usr_sbin_verify_storage(self, line, words):
        return 'W1700K_STORAGE_READY', 0
