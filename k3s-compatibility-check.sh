#!/usr/bin/env bash
# ==============================================================
# k3s_check.sh — K3s Compatibility & Image Pull Checker
# Host on GitHub and run with:
#   curl -sSL https://raw.githubusercontent.com/<USER>/<REPO>/main/k3s_check.sh | sudo bash
# ==============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; BOLD='\033[1m'; NC='\033[0m'
PASS="${GREEN}[PASS]${NC}"; FAIL="${RED}[FAIL]${NC}"; WARN="${YELLOW}[WARN]${NC}"; INFO="${BLUE}[INFO]${NC}"

ERRORS=0; WARNINGS=0

fail()  { echo -e "    ${FAIL} $1"; ((ERRORS++))   || true; }
pass()  { echo -e "    ${PASS} $1"; }
warn()  { echo -e "    ${WARN} $1"; ((WARNINGS++)) || true; }
info()  { echo -e "    ${INFO} $1"; }
header(){ echo -e "\n${BOLD}${BLUE}[$1] $2${NC}"; }

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}         K3s Compatibility & Image Pull Checker             ${NC}"
echo -e "${BOLD}============================================================${NC}"
echo -e " Host: $(hostname)   |   Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}============================================================${NC}"

# ── 1. Kernel Version ────────────────────────────────────────
header 1 "Kernel Version"
KERNEL=$(uname -r)
KM=$(echo "$KERNEL" | cut -d. -f1)
Km=$(echo "$KERNEL" | cut -d. -f2)
info "Running kernel: $KERNEL"
if [ "$KM" -gt 5 ] || ([ "$KM" -eq 5 ] && [ "$Km" -ge 4 ]); then
  pass "Kernel >= 5.4 — compatible with K3s"
else
  fail "Kernel $KERNEL is too old — K3s requires >= 5.4. Upgrade your kernel."
fi

# ── 2. Kernel Modules ────────────────────────────────────────
header 2 "Required Kernel Modules"
for MOD in overlay nf_conntrack ip_tables br_netfilter xt_comment xt_multiport; do
  if lsmod | grep -q "^${MOD}"; then
    pass "$MOD — loaded"
  else
    modprobe "$MOD" 2>/dev/null && warn "$MOD — not loaded, loaded now (add to /etc/modules for persistence)" \
                                || fail "$MOD — cannot load. K3s/containerd will likely fail."
  fi
done

# ── 3. Cgroups ───────────────────────────────────────────────
header 3 "Cgroups"
mount | grep -q "cgroup" && pass "cgroup mounts present" || fail "No cgroup mounts found — K3s will not start"

if [ -f /proc/cgroups ]; then
  CPU_CG=$(awk '/^cpu / {print $4}' /proc/cgroups)
  MEM_CG=$(awk '/^memory / {print $4}' /proc/cgroups)
  [ "$CPU_CG"  = "1" ] && pass "cpu cgroup enabled"    || fail "cpu cgroup disabled"
  [ "$MEM_CG"  = "1" ] && pass "memory cgroup enabled" || fail "memory cgroup disabled — add 'cgroup_memory=1 cgroup_enable=memory' to kernel cmdline"
fi
grep -q "cgroup2" /proc/mounts 2>/dev/null && info "cgroup v2 active" || info "cgroup v1 active"

# ── 4. Sysctl / IP Forwarding ────────────────────────────────
header 4 "Sysctl / Networking Params"
check_sysctl() {
  local KEY=$1 EXP=$2
  VAL=$(sysctl -n "$KEY" 2>/dev/null || echo "missing")
  [ "$VAL" = "$EXP" ] && pass "$KEY = $VAL" \
                       || fail "$KEY = $VAL (expected $EXP) — fix: sysctl -w $KEY=$EXP"
}
check_sysctl net.ipv4.ip_forward                  1
check_sysctl net.bridge.bridge-nf-call-iptables   1
check_sysctl net.bridge.bridge-nf-call-ip6tables  1

# ── 5. Firewall & iptables ───────────────────────────────────
header 5 "Firewall & iptables"
systemctl is-active --quiet firewalld 2>/dev/null \
  && warn "firewalld active — ensure TCP 6443, UDP 8472, TCP 10250 are open" \
  || pass "firewalld not active"

if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  warn "ufw active — ensure TCP 6443, UDP 8472, TCP 10250 are allowed"
else
  pass "ufw not active"
fi

DROP_COUNT=$(iptables -L -n 2>/dev/null | grep -c "DROP" || echo 0)
[ "$DROP_COUNT" -gt 0 ] \
  && warn "$DROP_COUNT DROP rule(s) in iptables — may block registry pulls. Run: iptables -L -n | grep DROP" \
  || pass "No DROP rules in iptables"

# ── 6. DNS Resolution ────────────────────────────────────────
header 6 "DNS Resolution (Image Registries)"
for REG in registry-1.docker.io ghcr.io registry.k8s.io quay.io; do
  getent hosts "$REG" &>/dev/null && pass "DNS OK: $REG" || fail "DNS FAILED: $REG — images will not pull"
done

# ── 7. HTTPS Connectivity to Registries ──────────────────────
header 7 "HTTPS Connectivity to Registries"
for URL in https://registry-1.docker.io https://ghcr.io https://registry.k8s.io https://quay.io; do
  CODE=$(curl -o /dev/null -s -w "%{http_code}" --max-time 6 "$URL" 2>/dev/null || echo "000")
  [ "$CODE" != "000" ] && pass "Reachable ($CODE): $URL" || fail "UNREACHABLE: $URL — port 443 may be blocked"
done

# ── 8. Container Runtime ─────────────────────────────────────
header 8 "Container Runtime"
if command -v containerd &>/dev/null; then
  pass "containerd installed: $(containerd --version 2>/dev/null | head -1)"
  systemctl is-active --quiet containerd && pass "containerd service running" || warn "containerd installed but not running"
else
  info "No external containerd — K3s will use its bundled version (OK)"
fi
command -v crictl &>/dev/null && pass "crictl available" || info "crictl not found (optional)"

# ── 9. Hardware Resources ────────────────────────────────────
header 9 "Hardware Resources"
CPU=$(nproc)
RAM=$(awk '/MemTotal/{printf "%.0f", $2/1024}' /proc/meminfo)
DISK=$(df -BG / | awk 'NR==2{gsub("G",""); print $4}')
[ "$CPU"  -ge 2     ] && pass "CPU cores: $CPU"         || warn "CPU: $CPU core(s) — 2+ recommended for server"
[ "$RAM"  -ge 2048  ] && pass "RAM: ${RAM}MB"            || warn "RAM: ${RAM}MB — 2GB min for server, 512MB for agent"
[ "$DISK" -ge 10    ] && pass "Free disk: ${DISK}GB"     || warn "Free disk: ${DISK}GB — low space may cause pull failures"

# ── 10. OS-Specific Checks ───────────────────────────────────
header 10 "OS-Specific Checks"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  info "OS: $PRETTY_NAME"
  case "$ID" in
    rhel|centos)
      VER=$(echo "$VERSION_ID" | cut -d. -f1)
      [ "$VER" -lt 8 ] && warn "RHEL/CentOS < 8 — disable nm-cloud-setup before installing K3s" || pass "RHEL/CentOS version OK"
      [ "$VER" -ge 10 ] && warn "RHEL 10 detected — run: sudo dnf install -y kernel-modules-extra"
      ;;
    raspbian|debian)
      warn "Debian/Raspbian — check cgroups in /boot/firmware/cmdline.txt and known iptables bug"
      ;;
    ubuntu)
      UVER=$(echo "$VERSION_ID" | tr -d '.')
      ([ "$UVER" -ge 2110 ] && [ "$UVER" -le 2310 ]) && warn "Ubuntu $VERSION_ID on Pi — run: sudo apt install linux-modules-extra-raspi" || pass "Ubuntu version OK"
      ;;
    *) info "OS not specifically validated — K3s works on most modern Linux distros" ;;
  esac
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}                        SUMMARY                            ${NC}"
echo -e "${BOLD}============================================================${NC}"
echo -e " ${RED}Errors  : $ERRORS${NC}"
echo -e " ${YELLOW}Warnings: $WARNINGS${NC}"
echo ""
if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
  echo -e " ${GREEN}${BOLD}All checks passed — node is ready for K3s!${NC}"
elif [ "$ERRORS" -eq 0 ]; then
  echo -e " ${YELLOW}${BOLD}No hard errors but review warnings above before installing.${NC}"
else
  echo -e " ${RED}${BOLD}$ERRORS error(s) found — fix them before installing K3s.${NC}"
fi
echo -e "\n Docs: https://docs.k3s.io/installation/requirements"
echo -e "${BOLD}============================================================${NC}"
echo ""
