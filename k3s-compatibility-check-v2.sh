#!/usr/bin/env bash
# ==============================================================================
#  k3s-compatibility-check.sh   —   K3s pre-flight checker  (100% READ-ONLY)
#
#  Makes NO changes to the host. Every problem is reported together with a
#  copy/paste fix command that matches the DETECTED distribution
#  (RHEL / CentOS / Rocky / Alma / Oracle / Fedora / Amazon Linux /
#   Ubuntu / Debian / Raspberry Pi OS / SLES / openSUSE / Alpine / Arch).
#
#  Usage:
#      sudo bash k3s-compatibility-check.sh
#      curl -sSL <raw-url> | sudo bash
#
#  Optional overrides (defaults in brackets):
#      MIN_CPU        [4]              minimum CPU cores
#      MIN_RAM_MB     [10240]          minimum RAM in MB
#      MIN_DISK_GB    [60]             minimum free disk for the k3s data dir
#      K3S_DATA_DIR   [/var/lib/rancher]
#      NO_COLOR       [unset]          set to disable ANSI colours
#
#      e.g.  sudo MIN_CPU=2 MIN_RAM_MB=2048 bash k3s-compatibility-check.sh
#
#  Exit code:  0 = no failures,  1 = one or more FAIL
# ==============================================================================

# NOTE: intentionally NO `set -e` / `set -u` — individual checks are expected
#       to fail and the script must always reach the summary.

SCRIPT_VERSION="2.0"

# ------------------------------------------------------------------ tunables --
MIN_CPU=${MIN_CPU:-4}
MIN_RAM_MB=${MIN_RAM_MB:-10240}
MIN_DISK_GB=${MIN_DISK_GB:-60}
K3S_DATA_DIR=${K3S_DATA_DIR:-/var/lib/rancher}

# Kernel: hard minimum vs. recommended
KERNEL_HARD_MAJ=4;  KERNEL_HARD_MIN=14      # below this  -> FAIL
KERNEL_REC_MAJ=5;   KERNEL_REC_MIN=4        # below this  -> WARN

# ------------------------------------------------------------------- colours --
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

ERRORS=0; WARNINGS=0; PASSED=0; SECTION=0
REMEDIATION=()

pass()   { printf '    %s[ PASS ]%s %s\n' "$GREEN"  "$NC" "$1"; PASSED=$((PASSED + 1)); }
fail()   { printf '    %s[ FAIL ]%s %s\n' "$RED"    "$NC" "$1"; ERRORS=$((ERRORS + 1)); }
warn()   { printf '    %s[ WARN ]%s %s\n' "$YELLOW" "$NC" "$1"; WARNINGS=$((WARNINGS + 1)); }
info()   { printf '    %s[ INFO ]%s %s\n' "$BLUE"   "$NC" "$1"; }
skip()   { printf '    %s[ SKIP ]%s %s\n' "$CYAN"   "$NC" "$1"; }
note()   { printf '           %s%s%s\n'   "$CYAN"   "$1" "$NC"; }
rule()   { printf '%s==============================================================%s\n' "$BOLD" "$NC"; }
header() { SECTION=$((SECTION + 1)); printf '\n%s%s[%02d] %s%s\n' "$BOLD" "$BLUE" "$SECTION" "$1" "$NC"; }

# Print a fix command AND queue it for the remediation summary at the end.
fix() {
    local line
    for line in "$@"; do
        [ -z "$line" ] && continue
        printf '           %sfix: %s%s\n' "$CYAN" "$line" "$NC"
        REMEDIATION+=("$line")
    done
}

is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }
have()   { command -v "$1" >/dev/null 2>&1; }

# systemd-safe helpers (never explode on non-systemd hosts such as Alpine)
svc_active()  { have systemctl && systemctl is-active  --quiet "$1" 2>/dev/null; }
svc_enabled() { have systemctl && [ "$(systemctl is-enabled "$1" 2>/dev/null)" = "enabled" ]; }
svc_exists()  { have systemctl && systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1"; }

# ============================================================================ #
#  BANNER
# ============================================================================ #
echo ""
rule
printf '%s   K3s Compatibility Checker v%s   —   READ ONLY (no changes)%s\n' "$BOLD" "$SCRIPT_VERSION" "$NC"
rule
printf ' Host : %s\n' "$(hostname 2>/dev/null || echo unknown)"
printf ' Date : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo unknown)"
printf ' Arch : %s\n' "$(uname -m 2>/dev/null || echo unknown)"
rule

# ============================================================================ #
#  1. OPERATING SYSTEM + PACKAGE MANAGER  (must run first: drives all fixes)
# ============================================================================ #
header "Operating System / Distribution"

OS_ID="unknown"; OS_VER="unknown"; OS_PRETTY="unknown"; OS_LIKE=""

if [ -r /etc/os-release ]; then
    # Sourced in subshells so the parent environment is never polluted.
    OS_ID=$(. /etc/os-release >/dev/null 2>&1; printf '%s' "${ID:-unknown}")
    OS_VER=$(. /etc/os-release >/dev/null 2>&1; printf '%s' "${VERSION_ID:-unknown}")
    OS_PRETTY=$(. /etc/os-release >/dev/null 2>&1; printf '%s' "${PRETTY_NAME:-unknown}")
    OS_LIKE=$(. /etc/os-release >/dev/null 2>&1; printf '%s' "${ID_LIKE:-}")
elif [ -r /etc/redhat-release ]; then
    OS_PRETTY=$(cat /etc/redhat-release)
    OS_VER=$(grep -oE '[0-9]+(\.[0-9]+)?' /etc/redhat-release | head -1)
    case "$OS_PRETTY" in
        *"Red Hat"*)  OS_ID="rhel"      ;;
        *CentOS*)     OS_ID="centos"    ;;
        *Rocky*)      OS_ID="rocky"     ;;
        *Alma*)       OS_ID="almalinux" ;;
        *Oracle*)     OS_ID="ol"        ;;
        *Fedora*)     OS_ID="fedora"    ;;
        *)            OS_ID="rhel"      ;;
    esac
    OS_LIKE="rhel"
elif [ -r /etc/debian_version ]; then
    OS_ID="debian"
    OS_VER=$(cat /etc/debian_version 2>/dev/null)
    OS_PRETTY="Debian $OS_VER"
    OS_LIKE="debian"
else
    OS_PRETTY=$(uname -sr 2>/dev/null || echo unknown)
fi

# ---- distro family -----------------------------------------------------------
case "$OS_ID" in
    rhel|centos|rocky|almalinux|ol|fedora|amzn|scientific|virtuozzo)  FAMILY="rhel"   ;;
    ubuntu|debian|raspbian|linuxmint|pop|elementary|devuan)           FAMILY="debian" ;;
    sles|sled|suse|opensuse|opensuse-leap|opensuse-tumbleweed)        FAMILY="suse"   ;;
    alpine)                                                          FAMILY="alpine" ;;
    arch|manjaro|endeavouros|garuda)                                  FAMILY="arch"  ;;
    *)
        case " $OS_LIKE " in
            *rhel*|*fedora*|*centos*)  FAMILY="rhel"   ;;
            *debian*|*ubuntu*)         FAMILY="debian" ;;
            *suse*)                    FAMILY="suse"   ;;
            *arch*)                    FAMILY="arch"   ;;
            *alpine*)                  FAMILY="alpine" ;;
            *)                         FAMILY="unknown";;
        esac
        ;;
esac

OS_MAJOR=$(printf '%s' "$OS_VER" | cut -d'.' -f1 | grep -oE '^[0-9]+')
OS_MAJOR=${OS_MAJOR:-0}

# ---- package manager ---------------------------------------------------------
# The family decides the flavour (so RHEL never gets an apt-get command, and the
# package NAMES below always match the manager); the binary check only picks
# between equivalents such as dnf vs yum.
set_pkg() { PKG_MGR="$1"; PKG_INSTALL="$2"; }

case "$FAMILY" in
    rhel)
        if have dnf;   then set_pkg "dnf" "dnf install -y"
        elif have yum; then set_pkg "yum" "yum install -y"
        elif [ "$OS_MAJOR" -ge 8 ] 2>/dev/null; then set_pkg "dnf" "dnf install -y"
        else set_pkg "yum" "yum install -y"; fi
        ;;
    debian) set_pkg "apt"    "apt-get update && apt-get install -y" ;;
    suse)   set_pkg "zypper" "zypper --non-interactive install"     ;;
    alpine) set_pkg "apk"    "apk add --no-cache"                   ;;
    arch)   set_pkg "pacman" "pacman -S --noconfirm"                ;;
    *)
        # Unknown family: fall back to whichever manager is actually installed.
        if   have dnf;     then set_pkg "dnf"    "dnf install -y"
        elif have yum;     then set_pkg "yum"    "yum install -y"
        elif have apt-get; then set_pkg "apt"    "apt-get update && apt-get install -y"
        elif have zypper;  then set_pkg "zypper" "zypper --non-interactive install"
        elif have apk;     then set_pkg "apk"    "apk add --no-cache"
        elif have pacman;  then set_pkg "pacman" "pacman -S --noconfirm"
        else set_pkg "unknown" "<package-manager> install"; fi
        ;;
esac

# ---- per-family remediation strings (used by every later section) ------------
IS_RPI=0
if grep -qi 'raspberry' /proc/device-tree/model 2>/dev/null \
   || grep -qi 'raspberry' /proc/cpuinfo 2>/dev/null; then
    IS_RPI=1
fi

case "$FAMILY" in
    rhel)
        PKG_MOD_EXTRA="kernel-modules-extra"
        PKG_CURL="curl"; PKG_TAR="tar"; PKG_IPTABLES="iptables"
        PKG_NFS="nfs-utils"; PKG_ISCSI="iscsi-initiator-utils"; PKG_IPROUTE="iproute"
        CMDLINE_FIX1='grubby --update-kernel=ALL --args="cgroup_enable=memory cgroup_memory=1"'
        CMDLINE_FIX2='reboot'
        ;;
    debian)
        PKG_MOD_EXTRA="linux-modules-extra-$(uname -r 2>/dev/null)"
        PKG_CURL="curl"; PKG_TAR="tar"; PKG_IPTABLES="iptables"
        PKG_NFS="nfs-common"; PKG_ISCSI="open-iscsi"; PKG_IPROUTE="iproute2"
        if [ "$IS_RPI" -eq 1 ]; then
            RPI_CMDLINE="/boot/firmware/cmdline.txt"
            [ -f /boot/cmdline.txt ] && [ ! -f /boot/firmware/cmdline.txt ] && RPI_CMDLINE="/boot/cmdline.txt"
            CMDLINE_FIX1="append 'cgroup_memory=1 cgroup_enable=memory' to the single line in $RPI_CMDLINE"
            CMDLINE_FIX2='reboot'
        else
            CMDLINE_FIX1='add "cgroup_enable=memory cgroup_memory=1" to GRUB_CMDLINE_LINUX in /etc/default/grub'
            CMDLINE_FIX2='update-grub && reboot'
        fi
        ;;
    suse)
        PKG_MOD_EXTRA=""
        PKG_CURL="curl"; PKG_TAR="tar"; PKG_IPTABLES="iptables"
        PKG_NFS="nfs-client"; PKG_ISCSI="open-iscsi"; PKG_IPROUTE="iproute2"
        CMDLINE_FIX1='add "cgroup_enable=memory cgroup_memory=1" to GRUB_CMDLINE_LINUX in /etc/default/grub'
        CMDLINE_FIX2='grub2-mkconfig -o /boot/grub2/grub.cfg && reboot'
        ;;
    alpine)
        PKG_MOD_EXTRA=""
        PKG_CURL="curl"; PKG_TAR="tar"; PKG_IPTABLES="iptables"
        PKG_NFS="nfs-utils"; PKG_ISCSI="open-iscsi"; PKG_IPROUTE="iproute2"
        CMDLINE_FIX1='add "cgroup_enable=memory cgroup_memory=1" to the kernel cmdline in /etc/update-extlinux.conf'
        CMDLINE_FIX2='update-extlinux && reboot'
        ;;
    arch)
        PKG_MOD_EXTRA=""
        PKG_CURL="curl"; PKG_TAR="tar"; PKG_IPTABLES="iptables-nft"
        PKG_NFS="nfs-utils"; PKG_ISCSI="open-iscsi"; PKG_IPROUTE="iproute2"
        CMDLINE_FIX1='add "cgroup_enable=memory cgroup_memory=1" to GRUB_CMDLINE_LINUX in /etc/default/grub'
        CMDLINE_FIX2='grub-mkconfig -o /boot/grub/grub.cfg && reboot'
        ;;
    *)
        PKG_MOD_EXTRA=""
        PKG_CURL="curl"; PKG_TAR="tar"; PKG_IPTABLES="iptables"
        PKG_NFS="nfs-utils"; PKG_ISCSI="open-iscsi"; PKG_IPROUTE="iproute2"
        CMDLINE_FIX1='add "cgroup_enable=memory cgroup_memory=1" to the kernel command line'
        CMDLINE_FIX2='regenerate the bootloader config && reboot'
        ;;
esac

info "OS            : $OS_PRETTY"
info "ID / Version  : $OS_ID / $OS_VER"
info "Family        : $FAMILY   |   Package manager: $PKG_MGR"
[ "$IS_RPI" -eq 1 ] && info "Platform      : Raspberry Pi detected"

case "$OS_ID" in
    rhel|centos|rocky|almalinux|ol)
        if [ "$OS_MAJOR" -ge 8 ] 2>/dev/null; then
            pass "$OS_PRETTY — supported by K3s"
        elif [ "$OS_MAJOR" -eq 7 ] 2>/dev/null; then
            warn "$OS_PRETTY is EOL — K3s still runs, but the OS is unsupported upstream"
        elif [ "$OS_MAJOR" -gt 0 ] 2>/dev/null; then
            warn "$OS_PRETTY is very old — K3s support is not guaranteed"
        else
            warn "Could not determine the major version of $OS_ID"
        fi
        if [ "$OS_MAJOR" -ge 10 ] 2>/dev/null; then
            warn "RHEL-family 10: several netfilter modules moved to a separate package"
            fix "$PKG_INSTALL kernel-modules-extra"
        fi
        ;;
    fedora)   pass "Fedora $OS_VER — compatible with K3s" ;;
    amzn)     pass "Amazon Linux $OS_VER — compatible with K3s" ;;
    ubuntu)
        if [ "$OS_MAJOR" -ge 20 ] 2>/dev/null; then
            pass "Ubuntu $OS_VER — supported by K3s"
        else
            warn "Ubuntu $OS_VER is older than 20.04 — upgrade recommended"
        fi
        ;;
    debian)
        if [ "$OS_MAJOR" -ge 11 ] 2>/dev/null; then
            pass "Debian $OS_VER — supported by K3s"
        else
            warn "Debian $OS_VER is older than 11 (bullseye) — upgrade recommended"
        fi
        ;;
    raspbian)
        pass "Raspberry Pi OS $OS_VER — compatible with K3s"
        warn "Raspberry Pi: memory cgroup is OFF by default (checked below)"
        ;;
    sles|sled|opensuse*|suse)
        pass "SUSE / openSUSE $OS_VER — compatible with K3s"
        ;;
    alpine)
        pass "Alpine Linux $OS_VER — compatible with K3s"
        warn "Alpine uses OpenRC/musl — cgroups must be enabled manually"
        fix "rc-update add cgroups default && rc-service cgroups start"
        ;;
    arch|manjaro)
        pass "$OS_PRETTY — compatible with K3s"
        ;;
    *)
        info "Distribution '$OS_ID $OS_VER' is not in the known list"
        info "K3s runs on most modern Linux systems — verify the checks below manually"
        ;;
esac

# ============================================================================ #
#  2. PRIVILEGES
# ============================================================================ #
header "Privileges"
IS_ROOT=0
if [ "$(id -u 2>/dev/null)" = "0" ]; then
    IS_ROOT=1
    pass "Running as root — all checks available"
else
    warn "Not running as root — firewall/iptables/port checks will be incomplete"
    fix "sudo bash $0"
fi

# ============================================================================ #
#  3. HARDWARE RESOURCES
# ============================================================================ #
header "Hardware Resources"

CPU=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)
is_int "$CPU" || CPU=0

RAM=$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
is_int "$RAM" || RAM=0

# Free space on the filesystem that will actually hold /var/lib/rancher
DISK_TARGET="$K3S_DATA_DIR"
while [ ! -d "$DISK_TARGET" ] && [ "$DISK_TARGET" != "/" ]; do
    DISK_TARGET=$(dirname "$DISK_TARGET")
done
DISK_KB=$(df -Pk "$DISK_TARGET" 2>/dev/null | awk 'NR==2 {print $4}')
is_int "$DISK_KB" || DISK_KB=0
DISK=$((DISK_KB / 1024 / 1024))
DISK_MOUNT=$(df -Pk "$DISK_TARGET" 2>/dev/null | awk 'NR==2 {print $6}')
DISK_MOUNT=${DISK_MOUNT:-unknown}

if [ "$CPU" -ge "$MIN_CPU" ]; then
    pass "CPU  : $CPU core(s)  (minimum $MIN_CPU)"
else
    fail "CPU  : $CPU core(s) — minimum $MIN_CPU required"
fi

if [ "$RAM" -ge "$MIN_RAM_MB" ]; then
    pass "RAM  : ${RAM} MB  (minimum ${MIN_RAM_MB} MB)"
else
    fail "RAM  : ${RAM} MB — minimum ${MIN_RAM_MB} MB required"
fi

if [ "$DISK" -ge "$MIN_DISK_GB" ]; then
    pass "Disk : ${DISK} GB free on ${DISK_MOUNT} (holds ${K3S_DATA_DIR})"
else
    fail "Disk : ${DISK} GB free on ${DISK_MOUNT} — minimum ${MIN_DISK_GB} GB required for ${K3S_DATA_DIR}"
fi

# ============================================================================ #
#  4. KERNEL VERSION
# ============================================================================ #
header "Kernel Version"

KERNEL=$(uname -r 2>/dev/null)
KERNEL=${KERNEL:-unknown}
KBASE=${KERNEL%%-*}                 # 5.15.0-91-generic  ->  5.15.0
KMAJ=${KBASE%%.*}                   # 5
KREST=${KBASE#*.}                   # 15.0
KMIN=${KREST%%.*}                   # 15
KMAJ=$(printf '%s' "$KMAJ" | grep -oE '^[0-9]+'); KMAJ=${KMAJ:-0}
KMIN=$(printf '%s' "$KMIN" | grep -oE '^[0-9]+'); KMIN=${KMIN:-0}

info "Running kernel: $KERNEL"

if [ "$KMAJ" -eq 0 ]; then
    warn "Could not parse the kernel version string: $KERNEL"
elif [ "$KMAJ" -gt "$KERNEL_REC_MAJ" ] \
     || { [ "$KMAJ" -eq "$KERNEL_REC_MAJ" ] && [ "$KMIN" -ge "$KERNEL_REC_MIN" ]; }; then
    pass "Kernel $KMAJ.$KMIN >= ${KERNEL_REC_MAJ}.${KERNEL_REC_MIN} — recommended for K3s"
elif [ "$KMAJ" -gt "$KERNEL_HARD_MAJ" ] \
     || { [ "$KMAJ" -eq "$KERNEL_HARD_MAJ" ] && [ "$KMIN" -ge "$KERNEL_HARD_MIN" ]; }; then
    warn "Kernel $KMAJ.$KMIN works but is below the recommended ${KERNEL_REC_MAJ}.${KERNEL_REC_MIN} (cgroup v2 / overlayfs)"
else
    fail "Kernel $KMAJ.$KMIN is too old — K3s needs at least ${KERNEL_HARD_MAJ}.${KERNEL_HARD_MIN}"
    case "$FAMILY" in
        rhel)   fix "$PKG_INSTALL kernel && reboot" ;;
        debian) fix "apt-get update && apt-get install -y linux-image-generic && reboot" ;;
        suse)   fix "zypper --non-interactive update kernel-default && reboot" ;;
        *)      fix "upgrade the kernel using your distribution's package manager, then reboot" ;;
    esac
fi

# ============================================================================ #
#  5. KERNEL MODULES
# ============================================================================ #
header "Kernel Modules"

MODULES_DIR="/lib/modules/$(uname -r 2>/dev/null)"
MODULES_BUILTIN="$MODULES_DIR/modules.builtin"

HAS_MODULES_TREE=1
if [ ! -d "$MODULES_DIR" ]; then
    HAS_MODULES_TREE=0
    warn "$MODULES_DIR does not exist — no loadable-module tree on this host"
    case "$FAMILY" in
        rhel)   fix "$PKG_INSTALL kernel-modules-core kernel-modules   # or boot a kernel that matches the installed modules" ;;
        debian) fix "$PKG_INSTALL linux-image-generic linux-modules-\$(uname -r)   # or boot a kernel that matches the installed modules" ;;
        *)      fix "install the kernel-modules package that matches $(uname -r 2>/dev/null)" ;;
    esac
fi

# A module counts as available if it is loaded, present in /sys/module,
# or compiled into the kernel (built-in modules never appear in lsmod).
module_available() {
    local mod="$1" norm="${1//-/_}"
    grep -qE "^${norm}[[:space:]]" /proc/modules 2>/dev/null && return 0
    [ -d "/sys/module/${norm}" ] && return 0
    [ -r "$MODULES_BUILTIN" ] && grep -qE "/${norm}\.ko" "$MODULES_BUILTIN" && return 0
    return 1
}

module_installable() {                       # is the .ko file on disk?
    have modprobe && modprobe -n "$1" >/dev/null 2>&1
}

module_fix() {
    local mod="$1"
    fix "modprobe $mod" \
        "echo $mod > /etc/modules-load.d/k3s-${mod}.conf   # persist across reboots"
    if [ "$HAS_MODULES_TREE" -eq 1 ] && ! module_installable "$mod" && [ -n "$PKG_MOD_EXTRA" ]; then
        fix "$PKG_INSTALL $PKG_MOD_EXTRA   # the .ko file for $mod is not present on this system"
    fi
}

# Hard requirement for containerd's overlayfs snapshotter
if module_available overlay; then
    pass "overlay        — available"
else
    fail "overlay        — NOT available (containerd cannot use the overlayfs snapshotter)"
    module_fix overlay
fi

# K3s loads these itself at startup, so a missing module is a warning, not a failure
for MOD in br_netfilter nf_conntrack iptable_nat iptable_filter; do
    if module_available "$MOD"; then
        pass "$(printf '%-14s' "$MOD") — available"
    else
        warn "$(printf '%-14s' "$MOD") — not loaded (K3s normally loads it, load it now to be safe)"
        module_fix "$MOD"
    fi
done

# ip_tables is legacy: absent on nft-only hosts, which is fine for K3s >= 1.25
if module_available ip_tables || module_available nf_tables; then
    pass "ip_tables/nf_tables — netfilter backend available"
else
    warn "Neither ip_tables nor nf_tables is available — K3s bundles its own iptables but the kernel backend is required"
    module_fix ip_tables
fi

# ============================================================================ #
#  6. CGROUPS
# ============================================================================ #
header "Cgroups"

CG_FSTYPE=$(stat -fc %T /sys/fs/cgroup 2>/dev/null)
if [ "$CG_FSTYPE" = "cgroup2fs" ]; then
    CGROUP_VER="v2"
elif [ -d /sys/fs/cgroup/unified ]; then
    CGROUP_VER="hybrid"
elif [ "$CG_FSTYPE" = "tmpfs" ] || [ -d /sys/fs/cgroup ]; then
    CGROUP_VER="v1"
else
    CGROUP_VER="none"
fi

case "$CGROUP_VER" in
    v2)     pass "cgroup v2 (unified hierarchy) mounted at /sys/fs/cgroup" ;;
    hybrid) info "cgroup v1 + v2 hybrid hierarchy detected" ;;
    v1)     info "cgroup v1 hierarchy detected" ;;
    none)   fail "No cgroup filesystem mounted at /sys/fs/cgroup — K3s cannot start" ;;
esac

check_controller_v1() {
    local ctrl="$1" enabled
    enabled=$(awk -v c="$ctrl" '$1==c {print $4}' /proc/cgroups 2>/dev/null)
    [ "$enabled" = "1" ] || [ -d "/sys/fs/cgroup/$ctrl" ]
}

if [ "$CGROUP_VER" = "v2" ]; then
    CONTROLLERS=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)
    for CTRL in cpu cpuset memory; do
        if printf '%s' "$CONTROLLERS" | grep -qw "$CTRL"; then
            pass "$CTRL controller available"
        else
            fail "$CTRL controller missing from /sys/fs/cgroup/cgroup.controllers"
            [ "$CTRL" = "memory" ] && fix "$CMDLINE_FIX1" "$CMDLINE_FIX2"
        fi
    done
elif [ "$CGROUP_VER" != "none" ]; then
    if [ -r /proc/cgroups ]; then
        for CTRL in cpu memory; do
            if check_controller_v1 "$CTRL"; then
                pass "$CTRL cgroup enabled"
            else
                fail "$CTRL cgroup is disabled"
                [ "$CTRL" = "memory" ] && fix "$CMDLINE_FIX1" "$CMDLINE_FIX2"
            fi
        done
    else
        warn "/proc/cgroups not readable — cannot verify the cgroup controllers"
    fi
fi

# ============================================================================ #
#  7. SWAP
# ============================================================================ #
header "Swap"

SWAP_KB=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
is_int "$SWAP_KB" || SWAP_KB=0
if [ "$SWAP_KB" -eq 0 ]; then
    pass "Swap is disabled — recommended for kubelet"
else
    warn "Swap is enabled ($((SWAP_KB / 1024)) MB) — kubelet expects swap to be off"
    fix "swapoff -a" "sed -i.bak '/[[:space:]]swap[[:space:]]/s/^/#/' /etc/fstab"
    if [ "$FAMILY" = "debian" ] && [ "$IS_RPI" -eq 1 ]; then
        fix "systemctl disable --now dphys-swapfile   # Raspberry Pi OS"
    elif [ "$FAMILY" = "debian" ]; then
        fix "systemctl mask swap.target   # if a systemd swap unit re-enables it"
    fi
fi

# ============================================================================ #
#  8. SYSCTL / NETWORKING PARAMETERS
# ============================================================================ #
header "Sysctl / Networking Parameters"

SYSCTL_FILE="/etc/sysctl.d/90-k3s.conf"

check_sysctl() {
    local key="$1" expected="$2" hard="$3" val
    val=$(sysctl -n "$key" 2>/dev/null)
    if [ -z "$val" ]; then
        if [ "$hard" = "hard" ]; then
            fail "$key — not present"
        else
            warn "$key — not present (br_netfilter is probably not loaded yet)"
        fi
        fix "modprobe br_netfilter" \
            "sysctl -w $key=$expected" \
            "echo '$key = $expected' >> $SYSCTL_FILE && sysctl --system"
    elif [ "$val" = "$expected" ]; then
        pass "$key = $val"
    else
        if [ "$hard" = "hard" ]; then
            fail "$key = $val (expected $expected)"
        else
            warn "$key = $val (expected $expected)"
        fi
        fix "sysctl -w $key=$expected" \
            "echo '$key = $expected' >> $SYSCTL_FILE && sysctl --system"
    fi
}

check_sysctl net.ipv4.ip_forward                 1 hard
check_sysctl net.bridge.bridge-nf-call-iptables  1 soft
check_sysctl net.bridge.bridge-nf-call-ip6tables 1 soft

# Large clusters exhaust inotify watches; this bites in production, not at install
INOTIFY_WATCHES=$(sysctl -n fs.inotify.max_user_watches 2>/dev/null)
INOTIFY_INSTANCES=$(sysctl -n fs.inotify.max_user_instances 2>/dev/null)
is_int "$INOTIFY_WATCHES"   || INOTIFY_WATCHES=0
is_int "$INOTIFY_INSTANCES" || INOTIFY_INSTANCES=0
if [ "$INOTIFY_WATCHES" -ge 524288 ] && [ "$INOTIFY_INSTANCES" -ge 512 ]; then
    pass "inotify limits OK (watches=$INOTIFY_WATCHES instances=$INOTIFY_INSTANCES)"
else
    warn "inotify limits are low (watches=$INOTIFY_WATCHES instances=$INOTIFY_INSTANCES) — pods may fail to start"
    fix "echo 'fs.inotify.max_user_watches = 524288'  >> $SYSCTL_FILE" \
        "echo 'fs.inotify.max_user_instances = 512'   >> $SYSCTL_FILE" \
        "sysctl --system"
fi

# ============================================================================ #
#  9. SELINUX / APPARMOR
# ============================================================================ #
header "SELinux / AppArmor"

if have getenforce; then
    SEL_MODE=$(getenforce 2>/dev/null)
elif [ -r /sys/fs/selinux/enforce ]; then
    SEL_MODE=$([ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "1" ] && echo Enforcing || echo Permissive)
else
    SEL_MODE="Disabled"
fi

case "$SEL_MODE" in
    Enforcing)
        if [ "$FAMILY" = "rhel" ]; then
            info "SELinux is Enforcing — supported, but the K3s SELinux policy is required"
            fix "$PKG_INSTALL container-selinux   # k3s-selinux is pulled in by the K3s installer"
        else
            warn "SELinux is Enforcing on a non-RHEL system — K3s policy support is limited"
            fix "consider setting SELinux to permissive: setenforce 0 (and SELINUX=permissive in /etc/selinux/config)"
        fi
        ;;
    Permissive) info "SELinux is Permissive — no action needed" ;;
    *)          pass "SELinux not enforcing" ;;
esac

if [ "$FAMILY" = "debian" ]; then
    if svc_active apparmor; then
        info "AppArmor is active — normal on Ubuntu/Debian, K3s handles its own profiles"
    else
        info "AppArmor is not active"
    fi
fi

# ============================================================================ #
# 10. FIREWALL
# ============================================================================ #
header "Firewall"

FW_FOUND=0

if svc_active firewalld; then
    FW_FOUND=1
    warn "firewalld is ACTIVE — the K3s API, flannel VXLAN and kubelet ports must be opened"
    fix "firewall-cmd --permanent --add-port=6443/tcp" \
        "firewall-cmd --permanent --add-port=10250/tcp" \
        "firewall-cmd --permanent --add-port=8472/udp" \
        "firewall-cmd --permanent --zone=trusted --add-source=10.42.0.0/16   # pods" \
        "firewall-cmd --permanent --zone=trusted --add-source=10.43.0.0/16   # services" \
        "firewall-cmd --reload"
elif svc_exists 'firewalld.service'; then
    pass "firewalld installed but not active"
fi

if have ufw; then
    if ufw status 2>/dev/null | grep -qi "Status: active"; then
        FW_FOUND=1
        warn "ufw is ACTIVE — the K3s API, flannel VXLAN and kubelet ports must be allowed"
        fix "ufw allow 6443/tcp" \
            "ufw allow 10250/tcp" \
            "ufw allow 8472/udp" \
            "ufw allow from 10.42.0.0/16 to any   # pods" \
            "ufw allow from 10.43.0.0/16 to any   # services"
    else
        pass "ufw installed but not active"
    fi
fi

if have nft && [ "$IS_ROOT" -eq 1 ]; then
    NFT_RULES=$(nft list ruleset 2>/dev/null | grep -cE '^[[:space:]]*(drop|reject)')
    is_int "$NFT_RULES" || NFT_RULES=0
    if [ "$NFT_RULES" -gt 0 ]; then
        info "nftables has $NFT_RULES drop/reject rule(s) — review them if pods cannot reach the network"
    fi
fi

if [ "$IS_ROOT" -eq 1 ] && have iptables; then
    DROP_COUNT=$(iptables -S 2>/dev/null | grep -cE '(-j|--jump) (DROP|REJECT)')
    is_int "$DROP_COUNT" || DROP_COUNT=0
    POLICY_DROP=$(iptables -S 2>/dev/null | grep -cE '^-P .* (DROP|REJECT)')
    is_int "$POLICY_DROP" || POLICY_DROP=0
    if [ "$DROP_COUNT" -gt 0 ] || [ "$POLICY_DROP" -gt 0 ]; then
        warn "iptables has $DROP_COUNT DROP/REJECT rule(s) and $POLICY_DROP restrictive chain policy(-ies)"
        fix "iptables -S   # review the rules; K3s needs 6443/tcp, 10250/tcp, 8472/udp and the pod/service CIDRs"
    else
        pass "No DROP/REJECT rules in iptables"
    fi
elif ! have iptables; then
    info "iptables binary not found — K3s ships its own, so this is usually fine"
else
    skip "iptables inspection needs root"
fi

[ "$FW_FOUND" -eq 0 ] && pass "No active host firewall detected"

# ============================================================================ #
# 11. REQUIRED PORTS
# ============================================================================ #
header "Required Ports Availability"

listening_sockets() {
    if have ss; then
        ss -H -tuln 2>/dev/null | awk '{n = split($5, a, ":"); print $1 " " a[n]}'
    elif have netstat; then
        netstat -tuln 2>/dev/null | awk '/^(tcp|udp)/ {n = split($4, a, ":"); print substr($1,1,3) " " a[n]}'
    fi
}

SOCKETS=$(listening_sockets)

if [ -z "$SOCKETS" ]; then
    skip "Neither ss nor netstat available — cannot verify port availability"
    fix "$PKG_INSTALL $PKG_IPROUTE"
else
    port_busy() { printf '%s\n' "$SOCKETS" | grep -qx "$1 $2"; }
    for ENTRY in "tcp 6443 Kubernetes API" "tcp 10250 kubelet metrics" \
                 "tcp 2379 etcd client" "tcp 2380 etcd peer" "udp 8472 flannel VXLAN"; do
        set -- $ENTRY
        P_PROTO=$1; P_PORT=$2; shift 2; P_DESC="$*"
        if port_busy "$P_PROTO" "$P_PORT"; then
            warn "${P_PROTO}/${P_PORT} ($P_DESC) is already in use"
            fix "ss -tulnp | grep :${P_PORT}   # identify and stop the conflicting process"
        else
            pass "${P_PROTO}/${P_PORT} free ($P_DESC)"
        fi
    done
fi

# ============================================================================ #
# 12. DNS RESOLUTION
# ============================================================================ #
header "DNS Resolution"

for REG in registry-1.docker.io ghcr.io registry.k8s.io quay.io; do
    if getent hosts "$REG" >/dev/null 2>&1; then
        pass "DNS OK   : $REG"
    else
        fail "DNS FAIL : $REG — images from this registry will not pull"
        fix "check /etc/resolv.conf and your upstream DNS server"
    fi
done

if [ -L /etc/resolv.conf ] && readlink -f /etc/resolv.conf 2>/dev/null | grep -q 'systemd/resolve/stub-resolv.conf'; then
    info "systemd-resolved stub resolver in use — K3s handles this automatically"
fi

# ============================================================================ #
# 13. HTTPS CONNECTIVITY
# ============================================================================ #
header "HTTPS Connectivity to Registries"

if have curl; then
    for URL in https://registry-1.docker.io/v2/ https://ghcr.io/v2/ \
               https://registry.k8s.io/v2/ https://get.k3s.io; do
        CODE=$(curl -o /dev/null -s -w '%{http_code}' --connect-timeout 6 --max-time 12 "$URL" 2>/dev/null)
        CODE=${CODE:-000}
        if [ "$CODE" != "000" ]; then
            pass "Reachable (HTTP $CODE) : $URL"
        else
            fail "UNREACHABLE : $URL — port 443 blocked, or a proxy is required"
            fix "verify egress on 443, or configure HTTP_PROXY/HTTPS_PROXY/NO_PROXY for the k3s service"
        fi
    done
elif have wget; then
    for URL in https://registry-1.docker.io/v2/ https://get.k3s.io; do
        if wget -q --spider --timeout=10 "$URL" 2>/dev/null; then
            pass "Reachable : $URL"
        else
            warn "Could not reach $URL (wget spider) — verify manually"
        fi
    done
else
    warn "Neither curl nor wget found — the K3s installer requires curl"
    fix "$PKG_INSTALL $PKG_CURL"
fi

if [ -n "${HTTP_PROXY:-}${HTTPS_PROXY:-}${http_proxy:-}${https_proxy:-}" ]; then
    info "Proxy variables are set in this shell — remember they must also be set for the k3s systemd unit"
    fix "mkdir -p /etc/systemd/system/k3s.service.d   # then add a proxy drop-in, or use /etc/default/k3s"
fi

# ============================================================================ #
# 14. CONTAINER RUNTIME / EXISTING INSTALL
# ============================================================================ #
header "Container Runtime / Existing Installation"

if have containerd; then
    CTR_VER=$(containerd --version 2>/dev/null | head -1)
    info "System containerd present: ${CTR_VER:-unknown}"
    if svc_active containerd; then
        info "containerd service is running — K3s still uses its OWN bundled containerd by default"
    fi
else
    pass "No system containerd — K3s will use its bundled runtime"
fi

if have docker; then
    info "Docker is installed — only relevant if you install K3s with --docker"
fi

if have k3s || [ -d /etc/rancher/k3s ] || [ -x /usr/local/bin/k3s ]; then
    warn "An existing K3s installation was detected on this host"
    fix "k3s --version   # verify the version before re-installing" \
        "/usr/local/bin/k3s-uninstall.sh   # only if you intend to start from scratch"
else
    pass "No existing K3s installation found"
fi

# ============================================================================ #
# 15. REQUIRED TOOLING
# ============================================================================ #
header "Required Tooling"

MISSING_PKGS=""
for TOOL in curl tar; do
    if have "$TOOL"; then
        pass "$TOOL present"
    else
        fail "$TOOL missing — required by the K3s installer"
        case "$TOOL" in
            curl) MISSING_PKGS="$MISSING_PKGS $PKG_CURL" ;;
            tar)  MISSING_PKGS="$MISSING_PKGS $PKG_TAR"  ;;
        esac
    fi
done
for TOOL in findmnt mount; do
    have "$TOOL" || warn "$TOOL missing — K3s uses it for mount propagation checks"
done
if [ -n "$MISSING_PKGS" ]; then
    fix "$PKG_INSTALL$MISSING_PKGS"
fi

# Longhorn / persistent storage prerequisites are optional but commonly needed
if have iscsiadm; then
    pass "open-iscsi present (needed by Longhorn / iSCSI storage)"
else
    info "iscsiadm not found — install only if you plan to use Longhorn or iSCSI volumes"
    fix "$PKG_INSTALL $PKG_ISCSI   # optional: Longhorn / iSCSI storage"
fi

# ============================================================================ #
# 16. NETWORKMANAGER
# ============================================================================ #
header "NetworkManager"

if svc_active NetworkManager; then
    info "NetworkManager is active — it must not manage the CNI interfaces"
    if [ -f /etc/NetworkManager/conf.d/rke2-canal.conf ] || [ -f /etc/NetworkManager/conf.d/k3s-canal.conf ]; then
        pass "CNI interfaces already excluded from NetworkManager"
    else
        warn "cali*/flannel* interfaces are not excluded from NetworkManager"
        fix "printf '[keyfile]\\nunmanaged-devices=interface-name:cali*;interface-name:flannel*\\n' > /etc/NetworkManager/conf.d/k3s-canal.conf" \
            "systemctl reload NetworkManager"
    fi

    if [ "$FAMILY" = "rhel" ]; then
        if svc_enabled nm-cloud-setup.service || svc_active nm-cloud-setup.service; then
            fail "nm-cloud-setup is enabled — it breaks K3s networking on RHEL/CentOS cloud images"
            fix "systemctl disable --now nm-cloud-setup.service nm-cloud-setup.timer" "reboot"
        else
            pass "nm-cloud-setup is not enabled"
        fi
    fi
else
    pass "NetworkManager is not active"
fi

# ============================================================================ #
# 17. TIME SYNCHRONISATION
# ============================================================================ #
header "Time Synchronisation"

TIME_OK=0
if have timedatectl; then
    if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q '^yes$'; then
        TIME_OK=1
    elif timedatectl status 2>/dev/null | grep -qiE 'synchronized: yes|clock synchronized: yes'; then
        TIME_OK=1
    fi
fi
if [ "$TIME_OK" -eq 1 ]; then
    pass "System clock is synchronised via NTP"
elif svc_active chronyd || svc_active chrony || svc_active ntpd || svc_active systemd-timesyncd; then
    info "An NTP daemon is running but synchronisation is not confirmed yet"
else
    warn "No time synchronisation detected — TLS certificate validation may fail"
    case "$FAMILY" in
        rhel)   fix "$PKG_INSTALL chrony && systemctl enable --now chronyd" ;;
        debian) fix "$PKG_INSTALL chrony && systemctl enable --now chrony"  ;;
        suse)   fix "$PKG_INSTALL chrony && systemctl enable --now chronyd" ;;
        alpine) fix "apk add --no-cache chrony && rc-update add chronyd default && rc-service chronyd start" ;;
        *)      fix "install and enable chrony or systemd-timesyncd" ;;
    esac
fi

# ============================================================================ #
#  SUMMARY
# ============================================================================ #
echo ""
rule
printf '%s                          SUMMARY                              %s\n' "$BOLD" "$NC"
rule
printf '  %sPassed   : %d%s\n' "$GREEN"  "$PASSED"   "$NC"
printf '  %sWarnings : %d%s\n' "$YELLOW" "$WARNINGS" "$NC"
printf '  %sFailures : %d%s\n' "$RED"    "$ERRORS"   "$NC"
printf '  Detected : %s (family=%s, pkg=%s)\n' "$OS_PRETTY" "$FAMILY" "$PKG_MGR"
echo ""

if [ "${#REMEDIATION[@]}" -gt 0 ]; then
    printf '%s  Remediation commands for %s:%s\n' "$BOLD" "$OS_PRETTY" "$NC"
    printf '%s\n' "${REMEDIATION[@]}" | awk '!seen[$0]++ {printf "    %s\n", $0}'
    echo ""
fi

if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    printf '  %s%sAll checks passed — this node is ready for K3s.%s\n' "$GREEN" "$BOLD" "$NC"
elif [ "$ERRORS" -eq 0 ]; then
    printf '  %s%sNo hard failures — review the %d warning(s) before installing.%s\n' "$YELLOW" "$BOLD" "$WARNINGS" "$NC"
else
    printf '  %s%s%d failure(s) — fix these before installing K3s.%s\n' "$RED" "$BOLD" "$ERRORS" "$NC"
fi

printf '\n  Docs: https://docs.k3s.io/installation/requirements\n'
rule
echo ""

[ "$ERRORS" -gt 0 ] && exit 1
exit 0
