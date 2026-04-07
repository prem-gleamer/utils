#!/usr/bin/env bash
# ==============================================================
# k3s_check.sh — K3s Compatibility Checker (READ-ONLY)
# Makes NO changes to the host. Safe to run via:
#   curl -sSL https://raw.githubusercontent.com/<USER>/<REPO>/main/k3s_check.sh | sudo bash
# ==============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

pass()   { echo -e "    ${GREEN}[PASS]${NC} $1"; }
fail()   { echo -e "    ${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS + 1)); }
warn()   { echo -e "    ${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
info()   { echo -e "    ${BLUE}[INFO]${NC} $1"; }
header() { echo -e "\n${BOLD}${BLUE}[$1] $2${NC}"; }

# Safe integer check — returns 0 if string is a valid integer, 1 otherwise
is_int() { echo "$1" | grep -qE '^[0-9]+$'; }

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}       K3s Compatibility Checker  —  READ ONLY             ${NC}"
echo -e "${BOLD}============================================================${NC}"
echo -e " Host : $(hostname 2>/dev/null || echo unknown)"
echo -e " Date : $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown)"
echo -e "${BOLD}============================================================${NC}"

# ── 1. Kernel Version ────────────────────────────────────────
header 1 "Kernel Version"
KERNEL=$(uname -r 2>/dev/null || echo "0.0.0")
KM=$(echo "$KERNEL" | cut -d'.' -f1)
Km=$(echo "$KERNEL" | cut -d'.' -f2)
info "Running kernel: $KERNEL"

# Strip any non-numeric suffix (e.g. "5.15.0-91-generic" -> "15")
KM=$(echo "$KM" | grep -oE '^[0-9]+' || echo 0)
Km=$(echo "$Km" | grep -oE '^[0-9]+' || echo 0)

if is_int "$KM" && is_int "$Km"; then
    if [ "$KM" -gt 5 ] || { [ "$KM" -eq 5 ] && [ "$Km" -ge 4 ]; }; then
        pass "Kernel $KERNEL >= 5.4 — compatible with K3s"
    else
        fail "Kernel $KERNEL is too old — K3s requires >= 5.4"
    fi
else
    warn "Could not parse kernel version: $KERNEL"
fi

# ── 2. Kernel Modules ────────────────────────────────────────
header 2 "Required Kernel Modules"
for MOD in overlay nf_conntrack ip_tables br_netfilter; do
    if lsmod 2>/dev/null | grep -q "^${MOD}[[:space:]]"; then
        pass "$MOD — loaded"
    else
        fail "$MOD — NOT loaded  (fix: modprobe $MOD)"
    fi
done

# ── 3. Cgroups ───────────────────────────────────────────────
header 3 "Cgroups"
if mount 2>/dev/null | grep -q "cgroup"; then
    pass "cgroup mounts present"
else
    fail "No cgroup mounts — K3s will not start"
fi

if [ -f /proc/cgroups ]; then
    CPU_CG=$(awk '/^cpu[[:space:]]/{print $4}' /proc/cgroups 2>/dev/null)
    MEM_CG=$(awk '/^memory[[:space:]]/{print $4}' /proc/cgroups 2>/dev/null)
    CPU_CG=${CPU_CG:-0}
    MEM_CG=${MEM_CG:-0}
    if [ "$CPU_CG" = "1" ]; then
        pass "cpu cgroup enabled"
    else
        fail "cpu cgroup disabled"
    fi
    if [ "$MEM_CG" = "1" ]; then
        pass "memory cgroup enabled"
    else
        fail "memory cgroup disabled — add cgroup_memory=1 cgroup_enable=memory to kernel cmdline"
    fi
else
    warn "/proc/cgroups not found"
fi

if grep -q "cgroup2" /proc/mounts 2>/dev/null; then
    info "cgroup v2 detected"
else
    info "cgroup v1 detected"
fi

# ── 4. Sysctl ────────────────────────────────────────────────
header 4 "Sysctl / Networking Params"
check_sysctl() {
    KEY=$1
    EXP=$2
    VAL=$(sysctl -n "$KEY" 2>/dev/null)
    VAL=${VAL:-missing}
    if [ "$VAL" = "$EXP" ]; then
        pass "$KEY = $VAL"
    else
        fail "$KEY = $VAL  (expected $EXP)  —  fix: sysctl -w $KEY=$EXP"
    fi
}
check_sysctl net.ipv4.ip_forward                 1
check_sysctl net.bridge.bridge-nf-call-iptables  1
check_sysctl net.bridge.bridge-nf-call-ip6tables 1

# ── 5. Firewall & iptables ───────────────────────────────────
header 5 "Firewall & iptables"

if systemctl is-active firewalld >/dev/null 2>&1; then
    warn "firewalld is active — ensure TCP 6443, UDP 8472, TCP 10250 are open"
else
    pass "firewalld not active"
fi

UFW_ACTIVE=0
if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        UFW_ACTIVE=1
    fi
fi
if [ "$UFW_ACTIVE" -eq 1 ]; then
    warn "ufw is active — ensure TCP 6443, UDP 8472, TCP 10250 are allowed"
else
    pass "ufw not active"
fi

DROP_RAW=$(iptables -L -n 2>/dev/null | grep -c "DROP")
DROP_COUNT=${DROP_RAW:-0}
if ! is_int "$DROP_COUNT"; then
    DROP_COUNT=0
fi
if [ "$DROP_COUNT" -gt 0 ]; then
    warn "$DROP_COUNT DROP rule(s) in iptables — may block image pulls"
else
    pass "No DROP rules in iptables"
fi

# ── 6. DNS ───────────────────────────────────────────────────
header 6 "DNS Resolution"
for REG in registry-1.docker.io ghcr.io registry.k8s.io quay.io; do
    if getent hosts "$REG" >/dev/null 2>&1; then
        pass "DNS OK : $REG"
    else
        fail "DNS FAIL: $REG — images from this registry will not pull"
    fi
done

# ── 7. HTTPS Connectivity ────────────────────────────────────
header 7 "HTTPS Connectivity to Registries"
if command -v curl >/dev/null 2>&1; then
    for URL in https://registry-1.docker.io https://ghcr.io https://registry.k8s.io https://quay.io; do
        CODE=$(curl -o /dev/null -s -w "%{http_code}" --connect-timeout 6 --max-time 10 "$URL" 2>/dev/null)
        CODE=${CODE:-000}
        if [ "$CODE" != "000" ]; then
            pass "Reachable ($CODE): $URL"
        else
            fail "UNREACHABLE: $URL — port 443 may be blocked"
        fi
    done
else
    warn "curl not found — skipping HTTPS connectivity checks"
fi

# ── 8. Container Runtime ─────────────────────────────────────
header 8 "Container Runtime"
if command -v containerd >/dev/null 2>&1; then
    CTR_VER=$(containerd --version 2>/dev/null | head -1 || echo "unknown")
    pass "containerd installed: $CTR_VER"
    if systemctl is-active containerd >/dev/null 2>&1; then
        pass "containerd service running"
    else
        warn "containerd installed but service not running"
    fi
else
    info "No external containerd — K3s will use its own bundled version (OK)"
fi

# ── 9. Hardware Resources ────────────────────────────────────
header 9 "Hardware Resources"
CPU=$(nproc 2>/dev/null); CPU=${CPU:-0}
RAM=$(awk '/MemTotal/{printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null); RAM=${RAM:-0}
DISK_RAW=$(df -BG / 2>/dev/null | awk 'NR==2{print $4}'); DISK_RAW=${DISK_RAW:-0G}
DISK=$(echo "$DISK_RAW" | grep -oE '^[0-9]+'); DISK=${DISK:-0}

if ! is_int "$CPU";  then CPU=0;  fi
if ! is_int "$RAM";  then RAM=0;  fi
if ! is_int "$DISK"; then DISK=0; fi

if [ "$CPU" -ge 4 ]; then
    pass "CPU : $CPU cores"
else
    fail "CPU : $CPU core(s) — minimum 4 cores required"
fi

if [ "$RAM" -ge 10240 ]; then
    pass "RAM : ${RAM} MB"
else
    fail "RAM : ${RAM} MB — minimum 10 GB required"
fi

if [ "$DISK" -ge 60 ]; then
    pass "Disk: ${DISK} GB free on /"
else
    fail "Disk: ${DISK} GB free on / — minimum 60 GB required"
fi

# ── 10. OS Detection ─────────────────────────────────────────
header 10 "OS Detection"

OS_ID="unknown"
OS_VER="unknown"
PRETTY="unknown"

if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID=${ID:-unknown}
    OS_VER=${VERSION_ID:-unknown}
    PRETTY=${PRETTY_NAME:-unknown}
elif [ -f /etc/redhat-release ]; then
    PRETTY=$(cat /etc/redhat-release)
    OS_ID=$(echo "$PRETTY" | awk '{print tolower($1)}')
    OS_VER=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
elif [ -f /etc/debian_version ]; then
    OS_ID="debian"
    OS_VER=$(cat /etc/debian_version)
    PRETTY="Debian $OS_VER"
else
    PRETTY=$(uname -s -r 2>/dev/null || echo "unknown")
fi

info "OS     : $PRETTY"
info "Distro : $OS_ID  |  Version: $OS_VER"

VER_MAJOR=$(echo "$OS_VER" | cut -d'.' -f1 | grep -oE '^[0-9]+')
VER_MAJOR=${VER_MAJOR:-0}

case "$OS_ID" in
    rhel|centos)
        if is_int "$VER_MAJOR"; then
            if [ "$VER_MAJOR" -lt 8 ]; then
                warn "RHEL/CentOS < 8 — disable nm-cloud-setup before K3s install"
            else
                pass "RHEL/CentOS $VER_MAJOR — supported"
            fi
            if [ "$VER_MAJOR" -ge 10 ]; then
                warn "RHEL 10 — run: dnf install -y kernel-modules-extra"
            fi
        fi
        ;;
    fedora)
        pass "Fedora $OS_VER — compatible with K3s"
        ;;
    ubuntu)
        pass "Ubuntu $OS_VER — compatible with K3s"
        ;;
    debian|raspbian)
        pass "Debian/Raspbian $OS_VER — compatible"
        warn "Verify cgroups in /boot/firmware/cmdline.txt on Raspberry Pi"
        ;;
    sles|opensuse*|suse*)
        pass "SUSE/openSUSE $OS_VER — compatible with K3s"
        warn "SUSE: ensure AppArmor or SELinux is configured for K3s"
        ;;
    alpine)
        pass "Alpine Linux $OS_VER — compatible with K3s"
        warn "Alpine: ensure cgroups and openrc are properly configured"
        ;;
    arch|manjaro)
        pass "Arch-based $OS_ID — compatible with K3s"
        ;;
    amzn)
        pass "Amazon Linux $OS_VER — compatible with K3s"
        ;;
    ol)
        pass "Oracle Linux $OS_VER — compatible with K3s"
        ;;
    rocky|almalinux)
        pass "$OS_ID $OS_VER — compatible with K3s"
        ;;
    *)
        info "Distro '$OS_ID $OS_VER' — K3s runs on most modern Linux systems"
        info "Verify: kernel >= 5.4, cgroups enabled, overlayfs supported"
        ;;
esac

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}                       SUMMARY                             ${NC}"
echo -e "${BOLD}============================================================${NC}"
echo -e "  ${RED}Failures : $ERRORS${NC}"
echo -e "  ${YELLOW}Warnings : $WARNINGS${NC}"
echo ""
if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All checks passed — node is ready for K3s.${NC}"
elif [ "$ERRORS" -eq 0 ]; then
    echo -e "  ${YELLOW}${BOLD}No hard failures — review warnings before installing.${NC}"
else
    echo -e "  ${RED}${BOLD}$ERRORS failure(s) — fix these before installing K3s.${NC}"
fi
echo -e "\n  Docs: https://docs.k3s.io/installation/requirements"
echo -e "${BOLD}============================================================${NC}"
echo ""
