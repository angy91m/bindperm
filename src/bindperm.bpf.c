// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Angelo Burzi angelo.burzi@biancofiore.art
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bindperm.h"

#define MAX_DEPTH     24   /* max ancestor processes to walk */
#define MAX_CG_LEVEL  16   /* max ancestor cgroups to check */
#define DEFAULT_UNPRIV_PORT_START 1024

#define IP_PROTO_TCP   6
#define IP_PROTO_UDP  17

/* Verdicts for cgroup/bind4 and cgroup/bind6 programs */
#define ALLOW          1   /* allow, normal kernel checks still apply */
#define ALLOW_NO_CAP   3   /* allow and skip the CAP_NET_BIND_SERVICE check */

char LICENSE[] SEC("license") = "GPL";

/* Rules per subject (uid or gid), filled in by the userspace loader. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct subj_key);
	__type(value, struct subj_rules);
} rules SEC(".maps");

/* cgroup id -> owner uid (user-UID.slice), used by rules with the 'r' flag. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u32);
} cg_owner SEC(".maps");

/*
 * Does the subject have a rule covering this port and protocol?
 * ext = the subject was found by walking up the tree (not the caller itself):
 * only rules with the 'r' flag count in that case.
 */
static __noinline bool subject_allows(__u32 kind, __u32 id, __u16 port,
				      __u8 proto, bool ext)
{
	struct subj_key k = { .kind = kind, .id = id };
	struct subj_rules *s = bpf_map_lookup_elem(&rules, &k);
	if (!s)
		return false;

	__u32 n = s->n;
	for (int i = 0; i < MAX_RULES_PER_SUBJECT; i++) {
		if (i >= n)
			break;
		struct rule *r = &s->r[i];
		if (port < r->lo || port > r->hi)
			continue;
		if (!(r->proto & proto))
			continue;
		if (ext && !r->recurse)
			continue;
		return true;
	}
	return false;
}

static __always_inline bool task_allows(struct task_struct *t, __u16 port,
					__u8 proto, bool ext)
{
	__u32 uid = BPF_CORE_READ(t, cred, euid.val);
	__u32 gid = BPF_CORE_READ(t, cred, egid.val);
	return subject_allows(KIND_UID, uid, port, proto, ext) ||
	       subject_allows(KIND_GID, gid, port, proto, ext);
}

/* Unprivileged-port threshold of the caller's network namespace.
 * The sysctl net.ipv4.ip_unprivileged_port_start is stored in the kernel
 * field netns_ipv4.sysctl_ip_prot_sock. */
static __always_inline int unpriv_port_start(struct task_struct *t)
{
	struct net *net = BPF_CORE_READ(t, nsproxy, net_ns);
	if (!net)
		return DEFAULT_UNPRIV_PORT_START;

	/* Field missing (kernel built without CONFIG_SYSCTL, or very old): use the default. */
	if (!bpf_core_field_exists(net->ipv4.sysctl_ip_prot_sock))
		return DEFAULT_UNPRIV_PORT_START;

	return BPF_CORE_READ(net, ipv4.sysctl_ip_prot_sock);
}

static __always_inline int check(struct bpf_sock_addr *ctx)
{
	__u16 port = bpf_ntohs(ctx->user_port);
	if (!port)
		return ALLOW;           /* ephemeral port: no privilege involved */

	/* Only TCP and UDP can be granted; anything else keeps kernel behaviour. */
	__u8 proto;
	if (ctx->protocol == IP_PROTO_TCP)
		proto = PROTO_TCP;
	else if (ctx->protocol == IP_PROTO_UDP)
		proto = PROTO_UDP;
	else
		return ALLOW;

	struct task_struct *t = (struct task_struct *)bpf_get_current_task();

	/* Not a privileged port in this netns: nothing to grant. */
	if (port >= unpriv_port_start(t))
		return ALLOW;

	/* 1. The calling process itself. */
	if (task_allows(t, port, proto, false))
		return ALLOW_NO_CAP;

	/* 2. Ancestors in the process tree (only rules with 'r'). */
	struct task_struct *p = t;
	for (int i = 0; i < MAX_DEPTH; i++) {
		struct task_struct *parent = BPF_CORE_READ(p, real_parent);
		if (!parent || parent == p)     /* init_task is its own parent */
			break;
		p = parent;
		if (task_allows(p, port, proto, true))
			return ALLOW_NO_CAP;
	}

	/* 3. Ancestor cgroups (only rules with 'r'): covers podman and double-forks. */
	for (int lvl = 0; lvl < MAX_CG_LEVEL; lvl++) {
		__u64 id = bpf_get_current_ancestor_cgroup_id(lvl);
		if (!id)
			break;
		__u32 *uid = bpf_map_lookup_elem(&cg_owner, &id);
		if (uid && subject_allows(KIND_UID, *uid, port, proto, true))
			return ALLOW_NO_CAP;
	}

	return ALLOW;                           /* default kernel behaviour */
}

SEC("cgroup/bind4")
int bindperm_bind4(struct bpf_sock_addr *ctx) { return check(ctx); }

SEC("cgroup/bind6")
int bindperm_bind6(struct bpf_sock_addr *ctx) { return check(ctx); }