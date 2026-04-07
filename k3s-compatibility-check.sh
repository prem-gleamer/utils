#!/usr/bin/env bash
# ==============================================================
# k3s_check.sh — K3s Compatibility Checker (READ-ONLY)
# No changes are made to the host. Safe to pipe directly:
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
fail()   { echo -e "    ${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS+1)); }
warn()   { echo -e "    ${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS+1)); }
info()   { echo -e "    ${BLUE}[INFO]${NC} $1"; }
header() { echo -e "\n${BOLD}${BLUE}[$1] $2${NC}"; }

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}       K3s Compatibility Checker  —  READ ONLY             ${NC}"
echo -e "${BOLD}============================================================${NC}"
echo -e " Host : $(hostname)"
echo -e " Date : $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}============================================================${NC}"

# ── 1. Kernel Version ────────────────────────────────────────
header 1 "Kernel Version"
KERNEL=$(uname -r)
KM=$(echo "$KERNEL" | cut -d'.' -f1)
Km=$(echo "$KERNEL" | cut -d'.' -f2)
info "Running kernel: $KERNEL"
if [ "$KM" -gt 5 ] 2>/dev/null || { [ "$KM" -eq 5 ] 2>/dev/null && [ "$Km" -ge 4 ] 2>/dev/null; }; then
    pass "Kernel >= 5.4 — compatible with K3s"
else
    fail "Kernel $KERNEL is too old — K3s requires >= 5.4"
fi

# ── 2. Kernel Modules ────────────────────────────────────────
header 2 "Required Kernel Modules"
for MOD in overlay nf_conntrack ip_tables br_netfilter; do
    if lsmod 2>/dev/null | grep -q "^${MOD}"; then
        pass "$MOD — loaded"
    else
        fail "$MOD — NOT loaded  →  fix: modprobe $MOD"
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
    CPU_CG=$(awk '/^cpu[[:space:]]/{print $4}' /proc/cgroups 2>/dev/null || echo 0)
    MEM_CG=$(awk '/^memory/{print $4}'          /proc/cgroups 2>/dev/null || echo 0)
    [ "$CPU_CG" = "1" ] && pass "cpu cgroup enabled"    || fail "cpu cgroup disabled"
    [ "$MEM_CG" = "1" ] && pass "memory cgroup enabled" || fail "memory cgroup disabled — add cgroup_memory=1 cgroup_enable=memory to kernel cmdline"
else
    warn "/proc/cgroups not found"
fi

if grep -q "cgroup2" /proc/mounts 2>/dev/null; then
    info "cgroup v2 detected"
else
    info "cgroup v1 detected"
fi

# ── 4. Sysctl Params ─────────────────────────────────────────
header 4 "Sysctl / Networking Params"
check_sysctl() {
    KEY=$1; EXP=$2
    VAL=$(sysctl -n "$KEY" 2>/dev/null || echo "missing")
    if [ "$VAL" = "$EXP" ]; then
        pass "$KEY = $VAL"
    else
        fail "$KEY = $VAL  (expected $EXP)  →  fix: sysctl -w $KEY=$EXP"
    fi
}
check_sysctl net.ipv4.ip_forward                 1
check_sysctl net.bridge.bridge-nf-call-iptables  1
check_sysctl net.bridge.bridge-nf-call-ip6tables 1

# ── 5. Firewall ──────────────────────────────────────────────
header 5 "Firewall & iptables"
if systemctl is-active firewalld >/dev/null 2>&1; then
    warn "firewalld is active — ensure TCP 6443, UDP 8472, TCP 10250 are open"
else
    pass "firewalld not active"
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
    warn "ufw is active — ensure TCP 6443, UDP 8472, TCP 10250 are allowed"
else
    pass "ufw not active"
fi

DROP_COUNT=$(iptables -L -n 2>/dev/null | grep -c "DROP" || echo 0)
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
        CODE=$(curl -o /dev/null -s -w "%{http_code}" --max-time 6 "$URL" 2>/dev/null || echo "000")
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
    pass "containerd installed: $(containerd --version 2>/dev/null | head -1)"
    if systemctl is-active containerd >/dev/null 2>&1; then
        pass "containerd service running"
    else
        warn "containerd installed but service not running"
    fi
else
    info "No external containerd — K3s will use its own bundled version (OK)"
fi

# ── 9. Hardware ──────────────────────────────────────────────
header 9 "Hardware Resources"
CPU=$(nproc 2>/dev/null || echo 0)
RAM=$(awk '/MemTotal/{printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
DISK=$(df -BG / 2>/dev/null | awk 'NR==2{gsub("G",""); print $4}' || echo 0)

[ "$CPU"  -ge 2    ] && pass "CPU : $CPU cores"        || warn "CPU : $CPU core(s) — min 2 recommended for server"
[ "$RAM"  -ge 2048 ] && pass "RAM : ${RAM} MB"         || warn "RAM : ${RAM} MB — min 2 GB for server / 512 MB for agent"
[ "$DISK" -ge 10   ] && pass "Disk: ${DISK} GB free"   || warn "Disk: ${DISK} GB free — low space may cause pull failures"

# ── 10. OS ───────────────────────────────────────────────────
header 10 "OS Detection"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "OS: ${PRETTY_NAME:-unknown}"
    case "${ID:-}" in
        rhel|centos)
            VER=$(echo "${VERSION_ID:-0}" | cut -d'.' -f1)
            if echo "$VER" | grep -qE '^[0-9]+$'; then
                [ "$VER" -lt 8 ]  && warn "RHEL/CentOS < 8 — disable nm-cloud-setup before K3s install" || pass "RHEL/CentOS version OK"
                [ "$VER" -ge 10 ] && warn "RHEL 10 — run: dnf install -y kernel-modules-extra"
            fi
            ;;
        debian|raspbian)
            warn "Debian/Raspbian — verify cgroups in /boot/firmware/cmdline.txt"
            ;;
        ubuntu)
            pass "Ubuntu detected — generally compatible"
            ;;
        *)
            info "Distro '${ID:-unknown}' — K3s works on most modern Linux systems"
            ;;
    esac
else
    warn "/etc/os-release not found — cannot detect OS"
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}                       SUMMARY                             ${NC}"
echo -e "${BOLD}============================================================${NC}"
echo -e "  ${RED}Failures : $ERRORS${NC}"
echo -e "  ${YELLOW}Warnings : $WARNINGS${NC}"
echo ""
if   [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All checks passed — node is ready for K3s.${NC}"
elif [ "$ERRORS" -eq 0 ]; then
    echo -e "  ${YELLOW}${BOLD}No hard failures — review warnings before installing.${NC}"
else
    echo -e "  ${RED}${BOLD}$ERRORS failure(s) found — fix before installing K3s.${NC}"
fi
echo -e "\n  Docs: https://docs.k3s.io/installation/requirements"
echo -e "${BOLD}============================================================${NC}"
echo ""
