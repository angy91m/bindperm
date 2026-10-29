# bindperm

Grant low-port `bind()` to specific Linux users and groups, optionally extended to their descendant processes (including rootless Podman containers), using a cgroup eBPF program. No kernel module, no `setcap` on binaries, no SELinux.

```
# /etc/bindperm.conf
80:www                   # TCP port 80 for user "www"
53/udp:dns               # UDP port 53 for user "dns"
443/tcp+udp:www:r        # TCP and UDP 443, also for descendants of www
82-83:@webadmins:r       # port range for a group, with descendants
0:@ops                   # any port for the group "ops"
```

## Why

On Linux, binding a port below `net.ipv4.ip_unprivileged_port_start` (1024 by default) requires `CAP_NET_BIND_SERVICE`. The usual workarounds each have a cost:

| Approach | Limitation |
|---|---|
| `setcap` on a binary | per binary, lost on updates, not per user |
| systemd `AmbientCapabilities=` | per service, not per user |
| `sysctl ip_unprivileged_port_start=0` | global to the network namespace, for everyone |
| `authbind` | wrapper per process, awkward with containers (Podman) |
| SELinux | powerful, but a whole policy framework to adopt |

`bindperm` is a small daemon that attaches an eBPF program to the root cgroup. On every `bind()` it decides whether the caller is covered by a rule and, if so, tells the kernel to skip the `CAP_NET_BIND_SERVICE` check for that single call.

## How it works

The eBPF program is attached to `cgroup/bind4` and `cgroup/bind6` on `/sys/fs/cgroup`, so it covers every process on the system. For each `bind()`:

1. If the port is `0` (ephemeral) or the protocol is not TCP/UDP, it returns
   the normal verdict (`1`). Nothing changes.
2. Otherwise it looks up rules for the caller's effective UID and GID. A match
   returns verdict `3` (allow and skip the capability check).
3. No match: normal verdict. **bindperm never denies anything, it only grants.**

The `net.ipv4.ip_unprivileged_port_start` threshold is deliberately not read:
granting the "skip capability check" verdict on a port that needs no capability
is a no-op, so the rules alone decide. This also makes the program independent
of the kernel's internal field layout for that sysctl, and it works unchanged
with a threshold raised or lowered at runtime, or different in a container's
network namespace.

## Requirements

- Linux kernel with **BTF** (`/sys/kernel/btf/vmlinux`), `CONFIG_BPF_SYSCALL`, `CONFIG_CGROUP_BPF`, `CONFIG_BPF_JIT`
- Kernel **>= 5.7** (verdict `3` for cgroup bind hooks; the exact minimum version is not verified, the functional test below is the real proof)
- **cgroup v2** (unified hierarchy) mounted on `/sys/fs/cgroup`
- Kernel lockdown must not be in `confidentiality` mode (it blocks `bpf_probe_read_kernel`)
- Build: `clang`, `llvm`, `libbpf` >= 1.0 (with headers), `libelf`, `zlib`, `bpftool`, `make`, `pkg-config`

The compiled binary uses CO-RE, so it can run on a different kernel than the one it was built on, as long as the target has BTF and the same architecture family.

### Debian 13 (trixie)

```bash
sudo apt install build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
                 bpftool pkg-config
```

On Debian `bpftool` lives in `/usr/sbin`, which is not in a normal user's `PATH`; the Makefile and the check script add it automatically.

## Build and install

```bash
make check-requirements        # pre-flight checks (run with sudo for runtime probes)
make                           # build as a normal user, output in build/
sudo install -m644 -o root -g root etc/bindperm.conf /etc/bindperm.conf
sudo $EDITOR /etc/bindperm.conf          # add at least one rule
sudo ./build/bindperm -C                 # dry run: nothing is attached
sudo make install                        # binary + systemd unit (keeps your config)
sudo systemctl daemon-reload
sudo systemctl enable --now bindperm
journalctl -u bindperm -b
```

`make install` never overwrites an existing `/etc/bindperm.conf` and does not enable or start the service. `make uninstall` removes the binary and the unit but keeps the configuration.

Install paths can be changed with `PREFIX`, `SBINDIR`, `SYSCONF`, `UNITDIR` and `DESTDIR`. `make STATIC=1` builds a statically linked binary, but glibc warns about `getpwnam`/`getgrnam` (NSS) when linking statically, so the dynamic binary is recommended.

## Configuration

Default file: `/etc/bindperm.conf`. One rule per line, `#` starts a comment.

```
ports[/proto]:subject[:r]
include PATH_OR_GLOB
```

| Field | Values |
|---|---|
| `ports` | a number (`80`), a range (`82-83`), or `0` for any port |
| `proto` | `tcp` (default), `udp`, `tcp+udp` |
| `subject` | user name, numeric UID, `@group` or `@GID` |
| `r` | also apply to descendant processes and the user's cgroup |

`0` means any port. Granting a port that does not require a privilege has no
effect, so in practice `0` means "any privileged port".

### Groups

`@group` expands to a rule on the GID plus one rule per member UID (members listed in `/etc/group` and users whose primary group is that group). Membership is a **snapshot** taken at start and on reload: after changing group membership run `systemctl reload bindperm`.

### Include

```
include /etc/bindperm.d/*.conf     # glob, loaded in alphabetical order
include extra.conf                 # relative to the including file's directory
```

- A glob without matches is not an error; a missing plain path is.
- Includes can nest up to 8 levels (this also stops loops).
- All files contribute to the same configuration, so limits apply to the sum.
- Paths cannot contain `#`.

### Security checks on configuration files

The configuration grants privileges, so every file read (main and included) must be a regular file owned by root and not writable by group/others. In addition, **every directory on its real path** (symlinks resolved, up to `/`) must be owned by root and not writable by group/others. Violations fail the load with a message naming the offending file or directory. Consequently the dry run does not work from a build directory in your home: install the configuration under `/etc` first.

### Reload

`systemctl reload bindperm` (SIGHUP) re-reads all files. If any file has an error, the previous configuration stays active.

### Limits

| Limit | Value | Where |
|---|---|---|
| Rules per subject (one UID or GID) | 16 | `MAX_RULES_PER_SUBJECT` in `src/bindperm.h` |
| Subjects | 1024 | `MAX_SUBJ` in `src/bindperm.c`, map size in `src/bindperm.bpf.c` |
| Process ancestors checked | 24 | `MAX_DEPTH` in `src/bindperm.bpf.c` |
| Cgroup ancestors checked | 16 | `MAX_CG_LEVEL` in `src/bindperm.bpf.c` |
| Include nesting | 8 | `MAX_INCLUDE_DEPTH` in `src/bindperm.c` |

Exceeding the per-subject limit is a hard error, never silent truncation. Changing a limit in the eBPF source needs a rebuild and a service restart (reload only updates rules). After any change run `sudo ./build/bindperm -C`: the verifier may reject larger loops.

A group rule gives the same rule to every member, so large groups with many rules reach the limit quickly. Merge adjacent ranges (`80` + `81` becomes `80-81`) to save slots.

## Command line

```
bindperm [-c config] [-C] [-v]

  -c FILE   configuration file (default /etc/bindperm.conf)
  -C        check only: parse the configuration, load the eBPF programs
            (verifier + CO-RE relocations) WITHOUT attaching them, then exit
  -v        verbose: libbpf debug output, including the verifier log
```

The systemd unit runs `bindperm -C` as `ExecStartPre`, so a broken configuration or an incompatible kernel prevents the service from starting and the reason ends up in the journal.

## Testing

```bash
# /etc/bindperm.conf:
#   80:youruser
#   53/udp:youruser

# must work
sudo -u youruser python3 -c "import socket; s=socket.socket(); s.bind(('::',80)); print('tcp 80 ok')"
sudo -u youruser python3 -c "import socket; s=socket.socket(type=socket.SOCK_DGRAM); s.bind(('::',53)); print('udp 53 ok')"

# must fail with EACCES (protocol not granted, or other user)
sudo -u youruser python3 -c "import socket; s=socket.socket(type=socket.SOCK_DGRAM); s.bind(('::',80))"
sudo -u nobody  python3 -c "import socket; s=socket.socket(); s.bind(('::',80))"
```

For the `:r` flag, with `443:youruser:r`:

```bash
# a child that changed user still passes (process tree)
sudo -u youruser sh -c 'sudo -u nobody python3 -c "import socket; s=socket.socket(); s.bind((\"0.0.0.0\",443)); print(\"ok r\")"'
# an unrelated user does not
sudo -u nobody python3 -c "import socket; s=socket.socket(); s.bind(('0.0.0.0',443))"
```

If the first test fails with `Permission denied` while the service is running and `-C` passes, the kernel most likely does not support verdict `3` for the bind hooks.

## Podman

- Publishing a port from the host (`podman run -p 443:8080 ...`) is done by `pasta` or `rootlessport` running with your real UID, so a plain rule (`443:youruser`) is usually enough.
- A process that calls `bind(80)` *inside* a container uses the container's network namespace threshold. With :r the cgroup ancestry check covers container processes started from the user’s session.
- Alternatively, for the inside-the-container case only, Podman can set the sysctl per container: `podman run --sysctl net.ipv4.ip_unprivileged_port_start=0 ...`.

Container behaviour depends on how Podman is started (login session, systemd user units, Quadlet), because the `:r` cgroup check relies on `user.slice/user-UID.slice`. **Test your own setup.**

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `missing tool: bpftool` | on Debian it is in `/usr/sbin`; install the `bpftool` package and make sure the Makefile/script `PATH` line is present |
| `fatal error: 'asm/types.h' not found` | Debian multiarch headers: the Makefile passes `-I/usr/include/$(uname -m)-linux-gnu` |
| `no member named 'sysctl_ip_unprivileged_port_start'` | the kernel struct field is `sysctl_ip_prot_sock` in `struct netns_ipv4` (check with `grep -n sysctl_ip_prot_sock build/vmlinux.h`) |
| `must be owned by root...` / `directory ... must be owned by root` | configuration or one of its parent directories fails the security checks |
| `failed to load eBPF programs` | verifier or CO-RE problem: run `sudo ./build/bindperm -C -v` and read the log |
| `attach bind4 failed: Invalid argument` | `bpf_link_create()` must be called without flags (link-based attach is always multi); do not pass `BPF_F_ALLOW_MULTI` |
| `Operation not permitted` | not root, or missing `CAP_BPF` / `CAP_PERFMON` / `CAP_SYS_ADMIN` |
| bind still returns `EACCES` | rule not matching (check user, protocol, `:r`), group membership changed without reload, or the kernel does not support verdict `3` |
| restart loop in `journalctl` | `systemctl stop bindperm` while debugging; `ExecStartPre` reloads the programs on every attempt |

## Limitations and security considerations

- **It grants privileges.** Anyone who can run code as a covered user can bind low ports. With `:r`, so can any descendant process, even after it changes user (this is the requested semantics, but keep it in mind for setuid binaries and `su`).
- **Process-tree matching is best effort.** Orphans and double-forks are re-parented to PID 1 or a subreaper and leave the tree. The cgroup check (`user-UID.slice`) covers user sessions, but **not** services under `system.slice` that run as the user: those only match through the process tree.
- **Only TCP and UDP.** SCTP, UDP-Lite and raw sockets keep the normal kernel behaviour.
- **Only `bind()`.** `connect()`, `listen()` and socket activation are not affected.
- **Groups are a snapshot** (see above), and the cgroup mapping for `user-UID.slice` is refreshed on login/logout (inotify plus a 1 s rescan).
- **Runs as root** (needs eBPF privileges). The configuration checks above exist to keep that safe.
- **Other cgroup bind programs** on child cgroups keep running alongside this one.
- The eBPF program is licensed GPL because it uses GPL-only helpers.

## Status

The code compiles and passes the verifier and CO-RE relocations on Debian 13 (kernel 6.12). Attaching, rules matching, the `:r` semantics with Podman, and verdict `3` have to be validated on your own system with the tests above. Bug reports with kernel version, distribution and `bindperm -C -v` output are welcome.

## Project layout

```
.
├── LICENSE
├── README.md
├── Makefile
├── src/
│   ├── bindperm.h               # types shared by eBPF and userspace
│   ├── bindperm.bpf.c           # eBPF program (runs in the kernel)
│   └── bindperm.c               # loader, config parser, logging
├── scripts/
│   └── check-requirements.sh    # pre-flight checks
├── systemd/
│   └── bindperm.service.in      # unit template (paths substituted by make)
└── etc/
    └── bindperm.conf            # example main configuration
```

## License

GPL-2.0, see `LICENSE`.