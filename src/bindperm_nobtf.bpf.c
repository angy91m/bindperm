// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Angelo Burzi angelo.burzi@biancofiore.art */
/*
 * bindperm, no-BTF variant: for kernels without /sys/kernel/btf/vmlinux.
 * Does not read task_struct, so, compared with the CO-RE variant:
 *   - identity is the REAL uid/gid of the caller (not the effective one)
 *   - rules with ':r' match only through the cgroup tree (user-UID.slice),
 *     not through the process tree
 */
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bindperm.h"

#define MAX_CG_LEVEL  16   /* max ancestor cgroups to check */

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

/* ext = subject found through the cgroup tree: only rules with 'r' count. */
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

static __always_inline int check(struct bpf_sock_addr *ctx)
{
	__u16 port = bpf_ntohs(ctx->user_port);
	if (!port)
		return ALLOW;           /* ephemeral port: no privilege involved */

	__u8 proto;
	if (ctx->protocol == IP_PROTO_TCP)
		proto = PROTO_TCP;
	else if (ctx->protocol == IP_PROTO_UDP)
		proto = PROTO_UDP;
	else
		return ALLOW;

	/* 1. The calling process itself (real uid/gid). */
	__u64 ug  = bpf_get_current_uid_gid();
	__u32 uid = (__u32)ug;
	__u32 gid = (__u32)(ug >> 32);
	if (subject_allows(KIND_UID, uid, port, proto, false) ||
	    subject_allows(KIND_GID, gid, port, proto, false))
		return ALLOW_NO_CAP;

	/* 2. Ancestor cgroups (only rules with 'r'). */
	for (int lvl = 0; lvl < MAX_CG_LEVEL; lvl++) {
		__u64 id = bpf_get_current_ancestor_cgroup_id(lvl);
		if (!id)
			break;
		__u32 *owner = bpf_map_lookup_elem(&cg_owner, &id);
		if (owner && subject_allows(KIND_UID, *owner, port, proto, true))
			return ALLOW_NO_CAP;
	}

	return ALLOW;                   /* default kernel behaviour */
}

SEC("cgroup/bind4")
int bindperm_bind4(struct bpf_sock_addr *ctx) { return check(ctx); }

SEC("cgroup/bind6")
int bindperm_bind6(struct bpf_sock_addr *ctx) { return check(ctx); }