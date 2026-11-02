#!/bin/bash
# Build a .deb from an already compiled binary.
# Usage: scripts/build-deb.sh VERSION ARCH BINARY [OUTPUT_NAME]
#   ARCH: amd64 | arm64 (Debian names, not x86_64/aarch64/x64)
#   OUTPUT_NAME: file name of the result, ".deb" is appended if missing
#                (default: bindperm_VERSION_ARCH.deb)
# Example:
#   scripts/build-deb.sh 0.1.0 amd64 build/bindperm bindperm-linux-x64
set -euo pipefail

[ $# -ge 3 ] && [ $# -le 4 ] || { sed -n '2,10p' "$0"; exit 2; }
ver=$1; arch=$2; bin=$3
out=${4:-bindperm_${ver}_${arch}}
out=${out%.deb}.deb
[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 1; }

pkg="bindperm_${ver}_${arch}"      # staging directory only
root="build/deb/$pkg"
rm -rf "$root"

# --- payload ----------------------------------------------------------
install -D -m755 "$bin" "$root/usr/sbin/bindperm"

install -d -m755 "$root/usr/lib/systemd/system"
sed 's|@SBINDIR@|/usr/sbin|g; s|@SYSCONF@|/etc|g' systemd/bindperm.service.in \
    > "$root/usr/lib/systemd/system/bindperm.service"
chmod 644 "$root/usr/lib/systemd/system/bindperm.service"

install -D -m644 etc/bindperm.conf "$root/etc/bindperm.conf"
install -d -m755 "$root/etc/bindperm.d"

install -D -m644 README.md "$root/usr/share/doc/bindperm/README.md"
install -D -m644 LICENSE   "$root/usr/share/doc/bindperm/copyright"

# --- control files ------------------------------------------------------
install -d -m755 "$root/DEBIAN"

cat > "$root/DEBIAN/control" <<EOF
Package: bindperm
Version: $ver
Architecture: $arch
Maintainer: Your Name <you@example.com>
Section: admin
Priority: optional
Depends: libc6, libbpf1, libelf1t64, zlib1g
Homepage: https://github.com/YOURUSER/bindperm
Description: Low-port bind() permissions for users and groups (eBPF)
 Grants bind() on privileged ports to specific Linux users and groups,
 optionally extended to their descendant processes (including rootless
 Podman), using a cgroup eBPF program. Requires a kernel with BTF and
 cgroup v2.
EOF

# Files under /etc that must survive upgrades untouched
echo "/etc/bindperm.conf" > "$root/DEBIAN/conffiles"

cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable bindperm.service || true
    # Do not fail the installation if the kernel or the configuration is not
    # suitable: the reason is in "journalctl -u bindperm".
    systemctl restart bindperm.service || \
        echo "bindperm: service not started, see 'journalctl -u bindperm'" >&2
fi
exit 0
EOF

cat > "$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ] && { [ "$1" = remove ] || [ "$1" = deconfigure ]; }; then
    systemctl stop bindperm.service || true
fi
exit 0
EOF

cat > "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
    systemctl disable bindperm.service 2>/dev/null || true
fi
exit 0
EOF

chmod 755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"

# --- build --------------------------------------------------------------
dpkg-deb --root-owner-group --build "$root" "dist/${out}"
echo "Built dist/${out}"