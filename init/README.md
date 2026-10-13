# Installing and updating a unit

`init/install` takes a W1700K running its stock firmware, backs up its whole
NAND to the host, and installs the SDR system. `init/flash` updates an installed
unit from a new build. Both drive the unit over its serial console and serve
images to its U-Boot over TFTP; neither needs the unit's stock firmware to work
beyond its first-stage U-Boot.

## What you need

- The unit's serial console on a 3.3 V USB serial adapter, 115200 8N1.
- An Ethernet cable from a host NIC to the unit's `lan3` port.
- A Linux host with Python 3.10+, pyserial and OpenSSH (`ssh-keygen`), and the
  build outputs from `make` in the repository root.
- An SSH key pair; its public half is installed for root logins
  (default `~/.ssh/id_ed25519.pub`, `id_ecdsa.pub` or `id_rsa.pub`).

## Host setup, once

```sh
sudo init/host/link up IFACE                  # 192.168.1.10/24 on the NIC cabled to lan3
sudo init/host/tftp-forward enable IFACE      # stock U-Boot's UDP 69 -> port 7071
```

Stock U-Boot fetches files only from UDP port 69. `tftp-forward` installs a
systemd unit with one nftables rule that redirects exactly that traffic (from
192.168.1.1 to 192.168.1.10 on IFACE) to the installer's unprivileged port, so
the tools run as a normal user. Without it, the tools must run as root to listen
on port 69 themselves; root then also owns the files they write, under root's
home unless `--data-dir` and `--authorized-key` say otherwise.

For the 10 GbE IQ link (unit `eth1`, 10.77.0.1), give the host side its
address and jumbo frames: `sudo init/host/link up IFACE10G 10.77.0.10/24 9216`.

Settings (serial device, addresses, ports, SSH key) default as shown in
[`install.example.json`](install.example.json); copy it to
`~/.config/w1700k/install.json` to change them, or pass the matching flags.

## First installation

```sh
make                       # if not done yet
init/install               # then power the unit on when asked
```

It stops stock U-Boot at power-on and then:

1. boots the write-free dumper from RAM, reads the unit's serial number, and
   copies the whole NAND (data and OOB, 544 MiB) to
   `~/.local/share/w1700k/units/SERIAL/nand-raw.bin`;
2. saves the unit's radio calibration (its MT7996 EEPROM image, from the
   `calibration` partition in the backup) as `eeprom.bin` beside the backup,
   where the host tools find it; `init/eeprom --unit SERIAL` does the same for
   an existing backup;
3. builds the unit's root filesystem with your SSH key and a host key made for
   this unit, and writes `known_hosts` for it beside the backup;
4. writes our U-Boot into the `loader` partition through stock U-Boot, reads it
   back and boots that copy;
5. from our U-Boot, erases `system` and `durable`, creates their UBI volumes,
   and writes and reads back the system FIT, the root and the durable image;
6. changes stock U-Boot's `bootcmd` to boot our U-Boot from the `loader`
   partition (the old one is kept as `bootcmd_orig`);
7. boots the installed system and checks it.

The unit is then reachable with `ssh root@192.168.1.1`. A full run takes about
ten minutes. Every step is checked before the next one starts; if a run is
interrupted, run it again: the backup is kept and is never overwritten.
`--expect-serial SERIAL` stops before anything is written unless the unit is
the one you meant, and `--backup-only` stops after the backup.

The backup is the only copy of the stock firmware and of the unit's factory
data (it includes the unit's stock passwords). Keep it. Steps 4 to 6 replace
the stock operating system; restoring it means writing the backup back with a
raw NAND writer, which this repository does not provide.

## Updates

```sh
make
init/flash --system        # kernel, device tree and root
init/flash --loader        # our U-Boot
init/flash --durable       # erase durable storage
init/flash --detect-only   # report where the unit is; sends one Ctrl-C
```

`init/flash` works from whatever state the unit is in (Linux, any U-Boot
prompt, or powered off, in which case it asks for a power cycle), writes only
what was asked, skips a volume that already holds the new bytes, reads every
write back, and boots the result. `--rootfs` and `--fit` update one volume of
the system each. With more than one installed unit, name it with `--unit SERIAL`.

## Recovery

- The installed system does not boot: `init/flash --recovery` boots the
  recovery image (the same kernel with the root in RAM) from our U-Boot without
  writing anything; then `init/flash --system`.
- Our U-Boot does not start: power-cycle; the tools stop stock U-Boot and
  `init/install --force` reinstalls everything, keeping the backup.
- The SSH host key of a unit installed elsewhere can be kept with
  `init/provision --unit SERIAL --import-host-key FILE` before the first
  `init/flash --rootfs`.

## Files

| Path | Contents |
| --- | --- |
| `~/.local/share/w1700k/units/SERIAL/` | `nand-raw.bin` (the backup), `dropbear_ed25519_host_key`, `rootfs.squashfs` (the unit's root), optional `network.conf` |
| `~/.local/share/w1700k/runs/` | one directory per run: the raw console transcript (`rx.bin`), an event log and saved command output |

A `network.conf` in the unit directory replaces the unit's
`/etc/w1700k/network.conf` (management and IQ port addresses, MTU) on the next
install or `init/flash --rootfs`.

While a tool runs, writing to `RUN/tx.fifo` sends bytes to the console and hands
the console to you for the rest of the run.

## How it works

| Module | Role |
| --- | --- |
| `initkit/uart.py` | console session: raw transcript, stopping autoboot, running commands to a prompt |
| `initkit/tftp.py` | TFTP server (also usable by hand: `python3 init/initkit/tftp.py --help`) |
| `initkit/console.py` | checked commands and moving between stock, dumper, loader and Linux |
| `initkit/stock.py` | getting an image into RAM through stock U-Boot's TFTP |
| `initkit/backup.py` | serial number and whole-chip backup, from the dumper |
| `initkit/layout.py` | the U-Boot commands that lay out NAND, from `platform/partitions.py` |
| `initkit/steps.py` | the write steps, each read back |
| `initkit/provision.py` | the unit's root filesystem with its keys |
| `initkit/install.py`, `initkit/update.py` | the two procedures |

Stock U-Boot's TFTP client gives up after ten timeouts that its broken timer
spends at about a hundred per second, so images go to stock in 32 KiB pieces,
each checked by CRC-32 in RAM before stock verifies the FIT's SHA-1 hashes. Our
U-Boot fetches whole images on port 7070 and the tools check SHA-256 before and
after every write. The console session refuses NAND and environment writes
unless the run is one that writes.
