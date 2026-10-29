/* Shared between the eBPF program and the userspace loader. */
#ifndef BINDPERM_H
#define BINDPERM_H

#define MAX_RULES_PER_SUBJECT 16
#define KIND_UID 0
#define KIND_GID 1

/* Protocol bitmask */
#define PROTO_TCP 0x1
#define PROTO_UDP 0x2

struct subj_key {
	__u32 kind;   /* KIND_UID or KIND_GID */
	__u32 id;
};

struct rule {
	__u16 lo;       /* first port of the range (inclusive) */
	__u16 hi;       /* last port of the range (inclusive) */
	__u8  recurse;  /* 1 = also valid for descendants (process tree / cgroup) */
	__u8  proto;    /* PROTO_TCP and/or PROTO_UDP */
	__u8  pad[2];
};

struct subj_rules {
	__u32 n;
	struct rule r[MAX_RULES_PER_SUBJECT];
};

#endif