#!/usr/bin/env bash
#
# setup-npu-artix.sh — Enable AMD NPU on Artix Linux + Dinit
#
# Target: Ryzen 7 250 / Hawk Point (PCI 1022:1502), Dell-class laptops.
# Tested kernel: 7.0.x with in-tree amdxdna.
#
# Idempotent: safe to re-run. Use --build-xrt to compile XRT from amd/xdna-driver
# when xrt-* packages are not in your pacman repos.
#
# ---------------------------------------------------------------------------
# CONSOLIDATED FROM the working setup. The following dead ends are NOT used
# (common bad suggestions — firmware .bak renames, VTD recipe archives,
# smi_install_archive.sh, manual libxrt_driver_xdna copies, dual DKMS versions,
# /etc/xilinx/xrt.ini tweaks, npu.dev.sbin.zst experiments, etc.):
# ---------------------------------------------------------------------------
#
# Usage:
#   sudo ./scripts/setup-npu-artix.sh              # pacman packages if available
#   sudo ./scripts/setup-npu-artix.sh --build-xrt  # build XRT stack from source
#   sudo ./scripts/setup-npu-artix.sh --check-only # preflight + post checks, no changes
#
set -euo pipefail

# --- Config (Ryzen 7 250 / Hawk Point) ---------------------------------------
NPU_PCI_ID="1022:1502"
NPU_PCI_SLOT="04:00.1"          # typical; script also accepts any 1502 device
FW_DIR="/lib/firmware/amdnpu/1502_00"
MIN_KERNEL_MAJOR=7
MIN_KERNEL_MINOR=0
IOMMU_PARAMS="amd_iommu=on iommu=pt"
XDNA_REPO="${XDNA_REPO:-https://github.com/amd/xdna-driver.git}"
XDNA_SRC="${XDNA_SRC:-/tmp/xdna-driver-build}"
BUILD_XRT=0
CHECK_ONLY=0
DRY_RUN=0

# --- Colors -------------------------------------------------------------------
if [[ -t 1 ]]; then
	RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
else
	RED= GREEN= YELLOW= NC=
fi

log()  { printf '%s\n' "$*"; }
ok()   { printf "${GREEN}[OK]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
die()  { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; exit 1; }

run() {
	if (( DRY_RUN )); then
		printf "${YELLOW}[dry-run]${NC} %s\n" "$*"
	else
		"$@"
	fi
}

need_root() {
	[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root: sudo $0 $*"
}

usage() {
	sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
	exit 0
}

# --- Parse args ---------------------------------------------------------------
for arg in "$@"; do
	case "$arg" in
		-h|--help) usage ;;
		--build-xrt) BUILD_XRT=1 ;;
		--check-only) CHECK_ONLY=1 ;;
		--dry-run) DRY_RUN=1 ;;
		*) die "Unknown option: $arg (try --help)" ;;
	esac
done

# --- Preflight ----------------------------------------------------------------
preflight() {
	log "=== Preflight ==="

	local kver kmaj kmin
	kver="$(uname -r)"
	kmaj="${kver%%.*}"
	kmin="${kver#*.}"; kmin="${kmin%%.*}"

	if (( kmaj < MIN_KERNEL_MAJOR )) || { (( kmaj == MIN_KERNEL_MAJOR )) && (( kmin < MIN_KERNEL_MINOR )); }; then
		die "Kernel $kver is too old; need >= ${MIN_KERNEL_MAJOR}.${MIN_KERNEL_MINOR} with in-tree amdxdna"
	fi
	ok "Kernel $kver"

	if ! lspci -nn | grep -q "$NPU_PCI_ID"; then
		die "NPU PCI device $NPU_PCI_ID not found (wrong machine?)"
	fi
	ok "NPU hardware present ($NPU_PCI_ID)"

	if ! grep -qE 'CONFIG_DRM_ACCEL|amdxdna' /proc/config.gz 2>/dev/null; then
		if ! modinfo amdxdna &>/dev/null; then
			warn "amdxdna module not found in module tree — install linux package with accel/amdxdna"
		fi
	fi

	if [[ -f /proc/cmdline ]] && grep -q 'amd_iommu=on' /proc/cmdline && grep -q 'iommu=pt' /proc/cmdline; then
		ok "IOMMU kernel parameters active"
	else
		warn "IOMMU params not in current cmdline — will configure GRUB"
	fi

	if [[ -d /etc/dinit.d ]] || [[ -d /lib/dinit.d ]]; then
		ok "Dinit detected"
	else
		warn "Dinit not detected; module/udev steps still apply"
	fi
}

# --- GRUB / IOMMU -------------------------------------------------------------
ensure_iommu() {
	log "=== IOMMU (required for NPU DMA) ==="

	if grep -q 'amd_iommu=on' /proc/cmdline 2>/dev/null && grep -q 'iommu=pt' /proc/cmdline 2>/dev/null; then
		ok "Already booted with $IOMMU_PARAMS"
		return 0
	fi

	[[ -f /etc/default/grub ]] || { warn "No /etc/default/grub — add '$IOMMU_PARAMS' to bootloader manually"; return 0; }

	local grub_default
	grub_default="$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | head -1 || true)"
	if [[ -z "$grub_default" ]]; then
		warn "GRUB_CMDLINE_LINUX_DEFAULT not found — configure IOMMU manually"
		return 0
	fi

	if echo "$grub_default" | grep -q 'amd_iommu=on'; then
		ok "GRUB already mentions amd_iommu"
	else
		if (( CHECK_ONLY )); then
			warn "Would append $IOMMU_PARAMS to GRUB_CMDLINE_LINUX_DEFAULT"
			return 0
		fi
		log "Appending $IOMMU_PARAMS to /etc/default/grub"
		run sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT='\(.*\)'/GRUB_CMDLINE_LINUX_DEFAULT='\1 ${IOMMU_PARAMS}'/" /etc/default/grub
		if command -v grub-mkconfig &>/dev/null; then
			run grub-mkconfig -o /boot/grub/grub.cfg
		fi
		warn "Reboot required for IOMMU parameters to take effect"
	fi
}

# --- Firmware -----------------------------------------------------------------
install_firmware() {
	log "=== NPU firmware (linux-firmware-other) ==="
	if (( CHECK_ONLY )); then
		[[ -d "$FW_DIR" ]] && ok "Firmware dir exists" || warn "Would install linux-firmware-other"
		return 0
	fi

	run pacman -S --needed --noconfirm linux-firmware-other

	# Restore symlinks if broken (the original failure mode: *.zst renamed to *.bak)
	if [[ -d "$FW_DIR" ]]; then
		run rm -f "$FW_DIR"/*.bak 2>/dev/null || true
		if [[ ! -L "$FW_DIR/npu.sbin.zst" ]] || [[ ! -e "$FW_DIR/npu.sbin.zst" ]]; then
			log "Restoring firmware symlinks"
			run ln -sf npu.sbin.1.5.2.380.zst "$FW_DIR/npu.sbin.zst"
		fi
		if [[ ! -L "$FW_DIR/npu_7.sbin.zst" ]] || [[ ! -e "$FW_DIR/npu_7.sbin.zst" ]]; then
			run ln -sf npu.sbin.1.5.5.391.zst "$FW_DIR/npu_7.sbin.zst"
		fi
	fi

	if [[ -L "$FW_DIR/npu.sbin.zst" ]] && [[ -L "$FW_DIR/npu_7.sbin.zst" ]]; then
		ok "Firmware symlinks OK"
	else
		die "Firmware symlinks still broken in $FW_DIR"
	fi
}

# --- XRT stack ----------------------------------------------------------------
xrt_plugin_present() {
	[[ -f /opt/xilinx/xrt/lib/libxrt_driver_xdna.so.2 ]] ||
		[[ -f /opt/xilinx/xrt/lib/libxrt_driver_xdna.so.2.25.0 ]]
}

xrt_base_present() {
	[[ -f /opt/xilinx/xrt/setup.sh ]]
}

install_xrt_from_pacman() {
	log "Installing XRT packages from pacman..."
	# xrt-plugin-amdxdna may not exist in all repos; install what we can.
	if pacman -Si xrt-base &>/dev/null; then
		run pacman -S --needed --noconfirm xrt-base xrt-npu
	else
		return 1
	fi
	if pacman -Si xrt-plugin-amdxdna &>/dev/null; then
		run pacman -S --needed --noconfirm xrt-plugin-amdxdna
	elif ! xrt_plugin_present; then
		warn "xrt-plugin-amdxdna not in repos — need --build-xrt or install plugin manually"
		return 1
	fi
	return 0
}

build_xrt_from_source() {
	log "=== Building XRT + NPU plugin from amd/xdna-driver ==="
	(( CHECK_ONLY )) && { warn "Would clone and build $XDNA_REPO"; return 0; }

	local build_deps=(
		base-devel git cmake ninja jq
		 boost libdrm ocl-icd protobuf rapidjson python
		pybind11 elfutils libffi
	)
	run pacman -S --needed --noconfirm "${build_deps[@]}"

	if [[ ! -d "$XDNA_SRC/.git" ]]; then
		run git clone --recursive "$XDNA_REPO" "$XDNA_SRC"
	else
		run git -C "$XDNA_SRC" submodule update --init --recursive
	fi

	# Arch/Artix deps script (non-interactive pacman inside)
	run bash -c "cd '$XDNA_SRC' && ./tools/amdxdna_deps.sh"

	log "Building XRT (this takes several minutes)..."
	run bash -c "cd '$XDNA_SRC/xrt/build' && ./build.sh -npu -opt"

	log "Building XDNA release packages..."
	run bash -c "cd '$XDNA_SRC/build' && XRT_FLAVOR=arch ./build.sh -release"

	log "Packaging xrt-base and xrt-npu..."
	run bash -c "cd '$XDNA_SRC/xrt/build/arch' && makepkg -p PKGBUILD-xrt-base --noconfirm --skipchecksums"
	run pacman -U --noconfirm "$XDNA_SRC/xrt/build/arch"/xrt-base-*.pkg.tar.zst

	run bash -c "cd '$XDNA_SRC/xrt/build/arch' && makepkg -p PKGBUILD-xrt-npu --noconfirm --skipchecksums"
	run pacman -U --noconfirm "$XDNA_SRC/xrt/build/arch"/xrt-npu-*.pkg.tar.zst

	log "Packaging xrt-plugin-amdxdna (userspace NPU shim)..."
	run bash -c "cd '$XDNA_SRC/build/arch' && makepkg -p PKGBUILD-xrt-plugin-amdxdna --noconfirm --skipchecksums --nodeps"
	# --nodeps: on kernel 7.0+ we use in-tree amdxdna, not amdxdna-driver DKMS package
	run pacman -U --noconfirm --nodeps "$XDNA_SRC/build/arch"/xrt-plugin-amdxdna-*.pkg.tar.zst

	ok "XRT stack built and installed"
}

install_xrt_stack() {
	log "=== XRT userspace (required for xrt-smi / future NPU apps) ==="

	if xrt_base_present && xrt_plugin_present; then
		ok "XRT + NPU plugin already installed"
		return 0
	fi

	if (( BUILD_XRT )); then
		build_xrt_from_source
	elif install_xrt_from_pacman; then
		ok "XRT installed from pacman"
	else
		die "XRT not installed. Re-run with: sudo $0 --build-xrt"
	fi

	xrt_base_present || die "XRT base missing after install"
	xrt_plugin_present || die "libxrt_driver_xdna missing — run with --build-xrt"
	ok "XRT NPU plugin present"
}

# --- Skip DKMS on kernel 7.0+ -------------------------------------------------
note_dkms() {
	log "=== Kernel driver ==="
	if modinfo amdxdna 2>/dev/null | grep -q 'filename:'; then
		local modpath
		modpath="$(modinfo -F filename amdxdna 2>/dev/null || true)"
		if [[ "$modpath" == *"/kernel/"* ]]; then
			ok "Using in-tree amdxdna ($modpath)"
			if pacman -Q amdxdna-dkms &>/dev/null; then
				warn "amdxdna-dkms is installed but redundant on kernel 7.0+ — optional: pacman -R amdxdna-dkms"
			fi
		elif [[ "$modpath" == *"dkms"* ]]; then
			ok "Using DKMS amdxdna"
		fi
	else
		warn "amdxdna module not found — install linux 7.0+ or amdxdna-dkms"
	fi
}

# --- Persistent config (Artix lacks some dirs by default) ---------------------
configure_persistence() {
	log "=== Persistent configuration ==="
	if (( CHECK_ONLY )); then
		ok "Would write modules-load.d, udev rule, memlock limits"
		return 0
	fi

	run mkdir -p /etc/modules-load.d /etc/security/limits.d /etc/udev/rules.d

	if [[ ! -f /etc/modules-load.d/amdxdna.conf ]]; then
		printf '%s\n' amdxdna > /etc/modules-load.d/amdxdna.conf
	fi
	ok "Module autoload: /etc/modules-load.d/amdxdna.conf"

	cat > /etc/udev/rules.d/70-amdxdna.rules << 'EOF'
SUBSYSTEM=="accel", KERNEL=="accel*", GROUP="render", MODE="0666"
EOF
	ok "Udev rule: /etc/udev/rules.d/70-amdxdna.rules"

	cat > /etc/security/limits.d/99-amdxdna.conf << 'EOF'
* soft memlock unlimited
* hard memlock unlimited
EOF
	ok "Memlock limits: /etc/security/limits.d/99-amdxdna.conf"
	warn "Log out and back in (or reboot) for memlock limits in user sessions"
}

# --- Load driver + device node ------------------------------------------------
load_driver() {
	log "=== Load driver ==="
	if (( CHECK_ONLY )); then return 0; fi

	run modprobe amdxdna 2>/dev/null || true
	if ! lsmod | grep -q '^amdxdna'; then
		die "Failed to load amdxdna — check dmesg"
	fi
	ok "amdxdna module loaded"

	local pci_dev
	pci_dev="$(lspci -nn | awk -v id="$NPU_PCI_ID" '$0 ~ id {print $1; exit}')"
	pci_dev="${pci_dev%:}"

	if [[ -n "$pci_dev" ]] && lspci -k -s "$pci_dev" 2>/dev/null | grep -q 'Kernel driver in use: amdxdna'; then
		ok "NPU bound to amdxdna at $pci_dev"
	else
		warn "NPU may not be bound — check: lspci -k | grep -A2 1502"
	fi
}

ensure_device_node() {
	log "=== Device node /dev/accel/accel0 ==="
	if (( CHECK_ONLY )); then return 0; fi

	run udevadm control --reload-rules
	run udevadm trigger --subsystem-match=accel --action=add
	run udevadm settle

	if [[ -e /dev/accel/accel0 ]]; then
		ok "/dev/accel/accel0 exists"
	else
		warn "Creating static node (udev missed accel subsystem)"
		run mkdir -p /dev/accel
		run mknod /dev/accel/accel0 c 261 0
		run chgrp render /dev/accel/accel0
		run chmod 666 /dev/accel/accel0
	fi
}

# --- Verify -------------------------------------------------------------------
verify() {
	log "=== Verification ==="

	local fail=0
	lsmod | grep -q '^amdxdna' || { warn "amdxdna not loaded"; fail=1; }
	[[ -e /dev/accel/accel0 ]] || { warn "/dev/accel/accel0 missing"; fail=1; }

	if [[ -f /opt/xilinx/xrt/setup.sh ]]; then
		# shellcheck disable=SC1091
		. /opt/xilinx/xrt/setup.sh
		if xrt-smi examine 2>/dev/null | grep -q 'RyzenAI-npu'; then
			ok "xrt-smi sees NPU"
			xrt-smi examine 2>/dev/null | sed -n '/Device(s) Present/,$p' | head -6
		else
			warn "xrt-smi does not list NPU — check plugin and /dev/accel/accel0"
			fail=1
		fi
	else
		warn "XRT not installed — skipping xrt-smi"
	fi

	log ""
	log "Note: FastFlowLM / Ollama cannot use this NPU on Linux yet (XDNA 1 chip)."
	log "Driver stack is ready for when compatible software arrives."
	log "Run ./scripts/check-npu.sh for a full health check."

	(( fail == 0 )) || die "Setup incomplete — see warnings above"
	ok "NPU driver stack is ready"
}

# --- Main ---------------------------------------------------------------------
main() {
	need_root "$@"
	preflight
	ensure_iommu
	install_firmware
	install_xrt_stack
	note_dkms
	configure_persistence
	load_driver
	ensure_device_node
	verify
	log ""
	ok "Done. Reboot if GRUB/IOMMU changed, then: ./scripts/check-npu.sh"
}

main "$@"
