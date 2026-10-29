#!/bin/bash
# Pre-flight checks for bindperm. Run as root for the full set of checks.
# Exit code: 0 = OK (possibly with warnings), 1 = at least one hard failure.

fail=0
ok()   { echo "[ OK ] $*"; }
warn() { echo "[WARN] $*"; }
bad()  { echo "[FAIL] $*"; fail=1; }

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# --- Kernel version -------------------------------------------------------
kver=$(uname -r | sed 's/[^0-9.].*//')
if ver_ge "$kver" 5.7; then
    ok "kernel $kver (>= 5.7, return value 3 should be supported)"
elif ver_ge "$kver" 4.17; then
    bad "kernel $kver: cgroup bind hooks exist but the 'skip CAP_NET_BIND_SERVICE' verdict is probably missing (needs ~5.7)"
else
    bad "kernel $kver is too old (cgroup bind hooks need >= 4.17)"
fi

# --- BTF (required for CO-RE) --------------------------------------------
[ -r /sys/kernel/btf/vmlinux ] && ok "BTF available (/sys/kernel/btf/vmlinux)" \
                               || bad "BTF missing: kernel built without CONFIG_DEBUG_INFO_BTF"

# --- cgroup v2 ------------------------------------------------------------
if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" ]; then
    ok "cgroup v2 mounted on /sys/fs/cgroup"
else
    bad "/sys/fs/cgroup is not a pure cgroup v2 mount (unified hierarchy required)"
fi

# --- Kernel config --------------------------------------------------------
cfg=""
if   [ -r /proc/config.gz ];            then cfg=$(zcat /proc/config.gz)
elif [ -r "/boot/config-$(uname -r)" ]; then cfg=$(cat "/boot/config-$(uname -r)")
fi
if [ -n "$cfg" ]; then
    for opt in CONFIG_BPF_SYSCALL CONFIG_CGROUP_BPF CONFIG_DEBUG_INFO_BTF CONFIG_BPF_JIT; do
        if grep -q "^$opt=y" <<<"$cfg"; then ok "$opt=y"
        else bad "$opt is not enabled"; fi
    done
else
    warn "kernel config not readable (/proc/config.gz or /boot/config-*): skipped"
fi

# --- Kernel lockdown ------------------------------------------------------
if [ -r /sys/kernel/security/lockdown ]; then
    lk=$(cat /sys/kernel/security/lockdown)
    case "$lk" in
        *"[confidentiality]"*) bad "lockdown=confidentiality blocks bpf_probe_read_kernel" ;;
        *) ok "kernel lockdown: $lk" ;;
    esac
fi

# --- Build tools ----------------------------------------------------------
for t in clang bpftool make cc pkg-config; do
    command -v "$t" >/dev/null && ok "found $t" || bad "missing tool: $t"
done
if pkg-config --exists libbpf 2>/dev/null; then
    lv=$(pkg-config --modversion libbpf)
    ver_ge "$lv" 1.0 && ok "libbpf $lv" || bad "libbpf $lv is too old (need >= 1.0)"
else
    bad "libbpf development files not found (package libbpf-dev / libbpf-devel)"
fi
pkg-config --exists libelf 2>/dev/null && ok "libelf" || bad "libelf development files not found"
pkg-config --exists zlib   2>/dev/null && ok "zlib"   || bad "zlib development files not found"

# --- Runtime probes (root + bpftool) -------------------------------------
if [ "$(id -u)" -eq 0 ] && command -v bpftool >/dev/null; then
    probe=$(bpftool feature probe kernel 2>/dev/null)
    grep -q "program_type cgroup_sock_addr is available" <<<"$probe" \
        && ok "program type cgroup_sock_addr available" \
        || bad "program type cgroup_sock_addr NOT available"
    for h in bpf_get_current_task bpf_get_current_ancestor_cgroup_id bpf_map_lookup_elem; do
        awk -v h="$h" '
            /eBPF helpers supported for program type cgroup_sock_addr/ {f=1; next}
            /eBPF helpers supported for program type/ {f=0}
            f && $0 ~ h {found=1}
            END {exit !found}' <<<"$probe" \
            && ok "helper $h available for cgroup_sock_addr" \
            || warn "helper $h not listed for cgroup_sock_addr (probe may be incomplete)"
    done
else
    warn "run as root with bpftool installed to probe program types and helpers"
fi

echo
if [ $fail -eq 0 ]; then
    echo "Result: requirements look OK. Next: make && sudo ./bindperm --check"
else
    echo "Result: at least one requirement is NOT satisfied."
fi
exit $fail