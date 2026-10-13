# SPDX-License-Identifier: MIT
"""Install the SDR system on a unit running stock firmware.

    1. stop stock U-Boot at power-on and record its environment
    2. boot the write-free dumper from RAM, read the unit's serial and back up
       the whole NAND to the host (skipped when a backup of this unit exists)
    3. build the unit's root with its SSH keys
    4. write our loader into the `loader` partition through stock, read it back
       and boot that copy
    5. from the loader: erase `system` and `durable`, create the UBI volumes,
       write and read back the system FIT, the root and the durable image
    6. make stock's bootcmd load our loader at power-on, keeping the old one as
       bootcmd_orig
    7. boot the installed system and check it

Steps 4 to 7 replace the stock firmware; the backup from step 2 is the only copy
of it. Interrupted at any point, the installation can be run again.
"""
from . import backup, config, layout, provision, stock, steps
from . import console as unit
from .console import StepFailed
from .session import open_session


def run(settings, expect_serial=None, authorized_key=None, import_host_key=None,
        force=False, backup_only=False):
    if backup_only:
        config.require_images(config.DUMPER)
    else:
        config.require_images(config.LOADER, config.DUMPER, config.SYSTEM_FIT,
                              config.ROOTFS, config.DURABLE)
        provision.authorized_key(authorized_key)   # fail before touching the unit
    with open_session(settings, 'install', write=not backup_only) as session:
        console, log = session.console, session.log
        unit.to_stock(console, log, unit.identify(console, log))

        environment = stock.environment(console)
        log.text('stock-environment.txt', '\n'.join(f'{key}={value}' for key, value
                                                    in sorted(environment.items())))
        installed = layout.bootcmd_extent(environment.get('bootcmd')) is not None
        if installed and not (force or backup_only):
            raise StepFailed('this unit already boots our loader; update it with '
                             'init/flash, or pass --force to install from scratch')

        print('install: booting the write-free dumper')
        stock.stage(console, log, settings, config.DUMPER, session.served)
        stock.boot(console, 'dumper')
        serial = backup.read_serial(console)
        if expect_serial and serial != expect_serial:
            raise StepFailed(f'this unit is {serial}, not {expect_serial}; nothing was written')
        directory = config.unit_dir(settings.data_dir, serial)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        print(f'install: unit {serial}, directory {directory}')
        existing = directory / backup.BACKUP_NAME
        if existing.is_file():
            if backup.serial_in_backup(existing) != serial:
                raise StepFailed(f'{existing} holds another unit; move it away first')
            print(f'install: keeping the existing backup {existing}')
        else:
            print('install: backing up the whole NAND')
            backup.dump(console, log, settings, session.served, directory, serial)
        calibration = backup.extract_eeprom(existing, directory)
        print(f'install: radio calibration saved to {calibration}')
        if backup_only:
            print(f'install: backup {existing}; stopping as asked (--backup-only)')
            return 0
        backup.check_platform_part(console)

        rootfs, host_key = provision.provision(directory, authorized_key, import_host_key,
                                             address=settings.device_ip)

        print('install: writing our loader')
        unit.to_stock(console, log, 'dumper')
        extent = steps.write_loader_slot(session)
        print('install: laying out system and durable storage')
        steps.format_system(session, config.SYSTEM_FIT, rootfs)
        steps.format_durable(session)

        print('install: making stock U-Boot boot our loader')
        unit.to_stock(console, log, 'loader')
        steps.save_bootcmd(session, extent)

        print('install: booting the installed system')
        status = steps.boot_installed(session)
    print(f'install: done; {status}. Log in with: ssh root@{settings.device_ip}\n'
          f'install: unit host key {provision.fingerprint(host_key)} '
          f'(known_hosts line in {directory / provision.KNOWN_HOSTS})\n'
          f'install: backup {existing}')
    return 0
