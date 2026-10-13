# SPDX-License-Identifier: MIT
#
#   make          build everything below, in dependency order
#   make check    run the test suite
#
# Unit images land in platform/build/images/, MT7996 firmware in firmware/build/,
# host programs under host/. The first build downloads about 500 MB of sources and
# compiles a cross toolchain: about ten minutes on a 20-core host plus downloads;
# later builds are incremental.
# JOBS=N limits parallel compile jobs (default: all CPUs).
# W1700K_NAND=w25n04l builds for units with that NAND part instead of the W25N04KV;
# later builds keep the part the last images were built for until it is set again.

PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE := 1
# The unit's 512 MiB SPI-NAND part: w25n04kv (default) or w25n04l. The installer's
# backup step names the one a unit carries.
export W1700K_NAND

.PHONY: all toolchain linux sdr rootfs loader dumper images firmware host check \
	clean distclean

all: images dumper firmware host

# Buildroot cross toolchain, target packages and the host tools the later steps use.
toolchain:
	$(PYTHON) platform/rootfs/build.py toolchain

# Linux Image and device tree.
linux: toolchain
	$(PYTHON) platform/linux/build.py

# The w1700k_sdr module and the unit-side clients, built against that kernel.
sdr: linux
	$(MAKE) -C platform/linux module reader

# The read-only root filesystem, with the module and clients installed.
rootfs: sdr
	$(PYTHON) platform/rootfs/build.py image

# Our U-Boot, which stock U-Boot loads from NAND. Also builds mkimage.
loader: toolchain
	$(PYTHON) platform/loader/build.py

# The system and recovery FITs, the root and the durable image.
images: rootfs loader
	$(PYTHON) platform/images.py

# The write-free NAND dumper used for the backup before installation.
dumper: toolchain
	$(PYTHON) platform/dumper/build.py

# MT7996 ROM patch, WM/WA firmware and the stream programs.
firmware:
	$(MAKE) -C firmware

# The stream service, the spectrum web UI server and the IQ recorder.
host:
	$(MAKE) -C host/stream
	$(MAKE) -C host/spectrum
	$(MAKE) -C host/recv

check:
	$(PYTHON) tools/check_hw_names.py
	$(PYTHON) -m unittest discover -s tests

# Remove build outputs but keep downloads and prepared sources.
clean:
	rm -rf platform/build/buildroot platform/build/linux platform/build/loader \
		platform/build/dumper platform/build/mkimage platform/build/bootstrap \
		platform/build/images platform/build/rootfs-overlay platform/build/logs \
		kernel/w1700k_sdr/build

# Remove everything the build created, downloads included.
distclean:
	rm -rf platform/build kernel/w1700k_sdr/build
