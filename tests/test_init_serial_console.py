# SPDX-License-Identifier: MIT
"""The boot catcher's fault cases, and the console session over a pseudo-terminal."""
import importlib.util
import os
from pathlib import Path
import pty
import select
import tempfile
import threading
import time
import unittest

try:
    import serial
except ImportError:
    serial = None

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('init_uart', ROOT / 'init/initkit/uart.py')
console = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(console)
STATES_SPEC = importlib.util.spec_from_file_location('init_console',
                                                     ROOT / 'init/initkit/console.py')
states = importlib.util.module_from_spec(STATES_SPEC)
STATES_SPEC.loader.exec_module(states)


class CatcherTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.events = []
        self.catcher = console.BootCatcher(
            lambda data, reason: self.sent.append(data),
            lambda kind, **fields: self.events.append((kind, fields)),
            token='uart_test123')

    def rx(self, data, now=0):
        self.catcher.receive(data, now)
        self.catcher.tick(now)

    def test_fragmented_ansi_countdown_variants(self):
        for prompt in (b'Hit any key to stop autoboot:',
                       b'PRESS\tANY KEY TO INTERRUPT AUTO BOOT:',
                       b'Press key to abort boot:',
                       b'\x1b[33mHit any\r\n key to stop auto\x1b[0mboot:'):
            self.setUp()
            for i, byte in enumerate(prompt):
                self.rx(bytes([byte]), i * .001)
            self.assertEqual(self.catcher.state, 'interrupting')
            self.assertTrue(self.sent)
            self.assertEqual(set(self.sent), {b'    '})

    def test_banner_waits_for_countdown_before_retries(self):
        self.rx(b'\r\nU-Boot 2014.04-rc1 (build)\r\n')
        for now in (.06, .12, .18):
            self.catcher.tick(now)
        self.assertEqual(self.sent, [])
        self.rx(b'Now running in RAM - U-Boot at: ffdb7000\r\nusxgmii_pcs_int en 1\r\n', .19)
        self.assertEqual(self.sent, [])
        self.rx(b'USXGMII_10G exit\r\nHit any key to stop autoboot: 4', .2)
        self.assertEqual(self.sent, [b'    '])
        self.rx(b'\r\nECNT> ', .21)
        self.catcher.tick(.25)
        self.assertEqual(len(self.sent), 1)  # Prompt stops keying immediately.
        self.catcher.tick(.32)
        self.assertEqual(self.sent[-1], b'echo uart_test123\r')
        self.assertEqual(self.catcher.state, 'verifying')

    def test_corrupt_countdown_insert_delete_substitute(self):
        original = b'Hit any key to stop autoboot:'
        for index in range(len(original)):
            for damaged in (original[:index] + original[index + 1:],
                            original[:index] + b'\xff' + original[index + 1:],
                            original[:index] + b'\x00' + original[index:]):
                with self.subTest(index=index, damaged=damaged):
                    self.setUp()
                    self.rx(damaged)
                    self.assertEqual(self.catcher.state, 'interrupting')
                    self.assertEqual(self.sent, [b'    '])

    def test_multiple_damaged_bytes_and_fragmentation(self):
        for damaged in (b'H?t any k\xffy to stop auto\x00boot:',
                        b'Pr?ss any key to interru\x00pt autooot:',
                        b'Hit any k\xffy to stop autoboot:'):
            self.setUp()
            for i, byte in enumerate(damaged):
                self.rx(bytes([byte]), i * .001)
            self.assertEqual(self.catcher.state, 'interrupting')
            self.assertEqual(self.sent, [b'    '])

    def test_noise_and_unrelated_text_do_not_trigger(self):
        for data in (b'\xff\x00\xaa\x55' * 128,
                     b'Hit the reset key to enter diagnostics',
                     b'BootROM DDR training completed, enter command',
                     b'Press any button to start upgrade', b'EC?T> ',
                     b'U-Boot 2014.04', b'U-B\xffot 2014.04'):
            self.setUp()
            self.rx(data)
            self.catcher.tick(.2)
            self.assertEqual(self.sent, [])
            self.assertEqual(self.catcher.state, 'armed')

    def test_damaged_command_prompt_needs_boot_context_and_exact_token(self):
        self.rx(b'U-Boot 2014.04\r\nHit any key to stop autoboot: 4')
        self.rx(b'\r\nEC?T> ', .1)
        self.catcher.tick(.21)
        self.assertEqual(self.catcher.state, 'verifying')
        self.assertEqual(self.sent[-1], b'echo uart_test123\r')
        self.rx(b'\r\nuart_test12?\r\nEC?T> ', .3)
        self.catcher.tick(.5)
        self.assertEqual(self.catcher.state, 'verifying')
        self.rx(b'\r\nuart_test123\r\nEC?T> ', .6)
        self.catcher.tick(.8)
        self.assertEqual(self.catcher.state, 'confirmed')

    def test_short_or_excessively_damaged_prompt_is_not_accepted(self):
        for prompt in (b'> ', b'EC??> ', b'ECNT> help', b'root# '):
            self.assertIsNone(console.command_prompt(prompt, allow_fuzzy=True))

    def test_corrupt_linux_handoff_overrides_boot(self):
        for marker in (b'Starting ker\xffnel', b'Star?ing kerne?',
                       b'Linux versio\x00n 6.18'):
            self.setUp()
            self.rx(b'U-Boot 2014.04\r\n' + marker + b'\r\nECNT> ')
            self.catcher.tick(.2)
            self.assertEqual(self.catcher.state, 'missed')
            self.assertEqual(self.sent, [])

    def test_burst_byte_cap_cannot_be_exceeded(self):
        self.rx(b'U-Boot 2014.04\r\nHit any key to stop autoboot: 4')
        for _ in range(400):
            self.catcher.tick(self.catcher.next_key)
        self.assertEqual(sum(map(len, self.sent)), 1200)
        self.assertEqual(set(self.sent), {b'    '})
        self.assertEqual(self.catcher.state, 'inconclusive')

    def test_confirmation_needs_actual_echo_output_and_new_prompt(self):
        self.rx(b'\r\nECNT> ')
        self.catcher.tick(.11)
        self.rx(b'echo uart_test123\r\nECNT> ', .2)
        self.catcher.tick(.4)
        self.assertEqual(self.catcher.state, 'verifying')  # Local command echo is insufficient.
        self.rx(b'\r\nuart_test123\r\n', .5)
        self.catcher.tick(.7)
        self.assertEqual(self.catcher.state, 'verifying')  # Output alone is insufficient.
        self.rx(b'ECNT> ', .8)
        self.catcher.tick(1)
        self.assertEqual(self.catcher.state, 'confirmed')
        before = self.sent[:]
        self.rx(b'\r\nU-Boot 2026.01\r\n', 2)
        self.catcher.tick(100)
        self.assertEqual(self.sent, before)  # No automatic rearm on a second boot.

    def test_old_token_and_embedded_prompt_do_not_confirm(self):
        self.rx(b'uart_test123\r\nmessage mentioning ECNT> but not a prompt\r\n')
        self.catcher.tick(.2)
        self.assertEqual(self.sent, [])
        self.rx(b'ECNT> ', .3)
        self.catcher.tick(.5)
        self.rx(b'\r\nECNT> ', .6)
        self.catcher.tick(.8)
        self.assertEqual(self.catcher.state, 'verifying')

    def test_linux_evidence_overrides_banner_and_prompt(self):
        self.rx(b'U-Boot 2014.04\r\nStarting kernel ...\r\nECNT> ')
        self.catcher.tick(1)
        self.assertEqual(self.catcher.state, 'missed')
        self.assertEqual(self.sent, [])

    def test_linux_handoff_stops_active_retries(self):
        self.rx(b'U-Boot 2014.04\r\nHit any key to stop autoboot: 4')
        self.rx(b'## Booting kernel from Legacy Image\r\n', .06)
        self.catcher.tick(1)
        self.assertEqual(self.sent, [b'    '])
        self.assertEqual(self.catcher.state, 'missed')

    def test_silence_after_countdown_has_bounded_retries(self):
        self.rx(b'U-Boot 2014.04\r\nHit any key to stop autoboot: 4')
        for i in range(1, 401):
            self.catcher.tick(i * .06)
        self.assertLessEqual(sum(map(len, self.sent)), console.MAX_KEYS)
        self.assertEqual(self.catcher.state, 'inconclusive')
        count = len(self.sent)
        self.rx(b'Hit any key to stop autoboot:', 30)
        self.assertEqual(len(self.sent), count)

    def test_repeated_banner_does_not_extend_deadline(self):
        self.rx(b'U-Boot 2014.04\r\nHit any key to stop autoboot: 4')
        self.rx(b'U-Boot 2014.04\r\n', 14)
        self.catcher.tick(15)
        self.assertEqual(self.catcher.state, 'inconclusive')

    def test_unknown_boot_has_no_tx_and_finite_decision(self):
        self.rx(b'\xff\x00BootROM DDR training\r\n')
        self.catcher.tick(45)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.catcher.state, 'inconclusive')

    def test_echo_timeout_does_not_claim_success(self):
        self.rx(b'=> ')
        self.catcher.tick(.11)
        self.catcher.tick(5.2)
        self.assertEqual(self.catcher.state, 'inconclusive')
        self.assertEqual(self.sent, [b'echo uart_test123\r'])

    def test_manual_takeover_disables_all_automation(self):
        self.rx(b'U-Boot 2014.04\r\nHit any key to stop autoboot: 4')
        self.catcher.manual()
        self.rx(b'ECNT> ', 1)
        self.catcher.tick(2)
        self.assertEqual(self.sent, [b'    '])
        self.assertEqual(self.catcher.state, 'manual')


@unittest.skipIf(serial is None, 'needs pyserial')
class SessionFixture(unittest.TestCase):
    """A ConsoleSession on one end of a pseudo-terminal; the test is the unit."""
    passive = False

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='w1700k-uart-test-')
        self.addCleanup(self.tmp.cleanup)
        self.master, self.slave = pty.openpty()
        self.addCleanup(os.close, self.slave)
        self.addCleanup(self.close_master)
        self.events = []
        self.session = console.ConsoleSession(
            os.ttyname(self.slave), self.tmp.name,
            lambda kind, **fields: self.events.append((kind, fields)),
            passive=self.passive)
        self.session.open()
        self.addCleanup(self.session.close)

    def close_master(self):
        if self.master is not None:
            os.close(self.master)
            self.master = None

    def read_until(self, suffix):
        data = b''
        until = time.monotonic() + 3
        while not data.endswith(suffix) and time.monotonic() < until:
            if select.select([self.master], [], [], .1)[0]:
                data += os.read(self.master, 4096)
        self.assertTrue(data.endswith(suffix), repr(data))
        return data

    def states(self):
        return [fields['state'] for kind, fields in self.events if kind == 'catcher_state']


class SessionTests(SessionFixture):
    def test_the_port_is_held_exclusively(self):
        with self.assertRaises(serial.SerialException):
            serial.Serial(os.ttyname(self.slave), 115200, exclusive=True)

    def test_lost_interrupt_bytes_then_verified_console(self):
        banner = b'\r\nU-Boot 2014.04-rc1\r\nusxgmii_pcs_int en 1\r\n'
        countdown = b'USXGMII_10G exit\r\nHit any key to stop autoboot: 4'
        os.write(self.master, banner)
        self.assertFalse(select.select([self.master], [], [], .2)[0])
        os.write(self.master, countdown)
        # The simulated board ignores the first three four-byte interrupt bursts.
        keys = b''
        while len(keys) < 12:
            keys += self.read_until(b' ')
        self.assertEqual(set(keys), {ord(' ')})
        prompt = b'\r\n\x1b[32mECNT> \x1b[0m'
        os.write(self.master, prompt)
        command = self.read_until(b'\r').lstrip(b' ')
        self.assertTrue(command.startswith(b'echo uart_'), repr(command))
        token = command[5:-1]
        reply = command + b'\r\n' + token + b'\r\nECNT> '
        os.write(self.master, reply)
        self.assertEqual(self.session.wait_for_catch(3), 'confirmed')
        self.assertFalse(select.select([self.master], [], [], .2)[0])
        with (Path(self.tmp.name) / 'tx.fifo').open('wb', buffering=0) as control:
            control.write(b'help\r')
        self.assertEqual(self.read_until(b'\r'), b'help\r')
        self.session.close()
        self.assertEqual((Path(self.tmp.name) / 'rx.bin').read_bytes(),
                         banner + countdown + prompt + reply)
        self.assertIn('manual', self.states())
        self.assertFalse((Path(self.tmp.name) / 'tx.fifo').exists())

    def test_a_rearmed_catcher_stops_the_next_boot(self):
        os.write(self.master, b'ECNT> ')
        self.session.wait(lambda: self.session.at_prompt('stock'), 2, 'prompt')
        self.session.arm()
        os.write(self.master, b'\r\nU-Boot 2014.04\r\nHit any key to stop autoboot: 4')
        self.assertEqual(set(self.read_until(b' ')), {ord(' ')})

    def test_a_command_waits_for_the_prompt(self):
        os.write(self.master, b'ECNT> ')
        self.session.wait(lambda: self.session.at_prompt('stock'), 2, 'prompt')
        self.session.catcher.state = 'confirmed'
        answer = threading.Thread(target=lambda: (self.read_until(b'version\n'),
                                                  os.write(self.master,
                                                           b'version\r\nU-Boot\r\nECNT> ')))
        answer.start()
        text = self.session.must_run('version', limit=3)
        answer.join()
        self.assertIn('U-Boot', text)

    def test_writes_are_refused_unless_the_session_allows_them(self):
        for line in ('saveenv', 'flash erase 0x600000 0x40000', 'ubi write 0 fit 1',
                     'mtd erase system 0 0x20000', 'env save'):
            with self.subTest(line), self.assertRaises(console.Refused):
                self.session.check_command(line)
        for line in ('mtd read.raw.oob.dontskipbad spi-nand0 0x90000000', 'printenv',
                     'setenv bootcmd_orig x', 'hash sha256 0 1', 'tftpput 0 1 x'):
            self.session.check_command(line)

    def test_disconnect_is_reported_and_rx_kept(self):
        os.write(self.master, b'partial boot log\r\n')
        deadline = time.monotonic() + 2
        while not (Path(self.tmp.name) / 'rx.bin').stat().st_size:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.01)
        self.close_master()
        deadline = time.monotonic() + 3
        while self.session.failure is None and time.monotonic() < deadline:
            time.sleep(.01)
        with self.assertRaisesRegex(RuntimeError, 'UART reader stopped'):
            self.session.check()
        self.assertEqual((Path(self.tmp.name) / 'rx.bin').read_bytes(), b'partial boot log\r\n')


    def probe(self, answer):
        """Run the state probe against a unit that answers Ctrl-C with `answer`."""
        self.session.catcher.state = 'confirmed'     # no boot to catch here
        received = []

        def unit():
            byte = b''
            until = time.monotonic() + 3
            while not byte and time.monotonic() < until:
                if select.select([self.master], [], [], .1)[0]:
                    byte = os.read(self.master, 4096)
            received.append(byte)
            os.write(self.master, answer)
        thread = threading.Thread(target=unit)
        thread.start()
        log = type('Log', (), {'event': lambda self, kind, **fields: None})()
        state = states.identify(self.session, log, settle=3)
        thread.join()
        # Nothing else follows: no newline, no command.
        self.assertFalse(select.select([self.master], [], [], .3)[0])
        return received[0], state

    def test_the_state_probe_is_one_ctrl_c_and_never_a_newline(self):
        for answer, expected in [(b'<INTERRUPT>\r\nSDR loader> ', 'loader'),
                                 (b'<INTERRUPT>\r\ndumper> ', 'dumper'),
                                 (b'\r\nECNT> ', 'stock'),
                                 (b'^C\r\n~ # ', 'linux')]:
            with self.subTest(expected):
                sent, state = self.probe(answer)
                self.assertEqual(sent, b'\x03')
                self.assertEqual(state, expected)
                self.session.buffer.clear()


class PassiveSessionTests(SessionFixture):
    passive = True

    def test_boot_prompts_produce_no_automatic_transmission(self):
        raw = b'U-Boot 2014.04\r\nHit any key to stop autoboot: 4\r\nECNT> '
        os.write(self.master, raw)
        self.assertFalse(select.select([self.master], [], [], .4)[0])
        self.session.close()
        self.assertEqual((Path(self.tmp.name) / 'rx.bin').read_bytes(), raw)
        self.assertFalse(any(kind == 'tx_attempt' for kind, _ in self.events))


if __name__ == '__main__':
    unittest.main()
