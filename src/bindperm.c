// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Angelo Burzi angelo.burzi@biancofiore.art
 *
 *
 * bindperm - grant low-port bind() to users/groups (and optionally their
 * descendants) using a cgroup eBPF program.
 *
 * Usage: bindperm [-c config] [-C] [-v]
 *   -c FILE   configuration file (default /etc/bindperm.conf)
 *   -C        check only: parse config, load the eBPF programs (verifier +
 *             CO-RE relocations) WITHOUT attaching them, then exit
 *   -v        verbose (libbpf debug output, including verifier log)
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bindperm.h"
#include "bindperm.skel.h"
#include <glob.h>
#include <limits.h>

#define MAX_SUBJ 1024
#define CG_ROOT  "/sys/fs/cgroup"
#define MAX_INCLUDE_DEPTH 8

/* ---------- logging ---------- */

enum { L_ERR, L_WARN, L_INFO };
static int use_prefix;   /* 1 when stderr is the journal: use <N> priority prefixes */
static int verbose;

static void logmsg(int lvl, const char *fmt, ...)
{
	static const char *pfx[]  = { "<3>", "<4>", "<6>" };
	static const char *name[] = { "error: ", "warning: ", "" };
	va_list ap;
	fprintf(stderr, "%sbindperm: %s", use_prefix ? pfx[lvl] : "", name[lvl]);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* Forward libbpf messages (including the verifier log on load failure). */
static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

/* ---------- configuration data ---------- */

struct subj { struct subj_key key; struct subj_rules val; };
struct cfg {
	int n;   struct subj s[MAX_SUBJ];
	int ncg; __u32 cg_uid[MAX_SUBJ];   /* users with at least one 'r' rule */
};
static struct cfg cur, nxt;

static volatile sig_atomic_t stop, reload;
static void on_term(int s) { (void)s; stop = 1; }
static void on_hup(int s)  { (void)s; reload = 1; }

/* ---------- configuration parsing ---------- */

static char *trim(char *s)
{
	while (isspace((unsigned char)*s)) s++;
	char *e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
	return s;
}

static int add_rule(struct cfg *c, __u32 kind, __u32 id,
		    __u16 lo, __u16 hi, __u8 proto, int rec)
{
	struct subj *s = NULL;
	for (int i = 0; i < c->n; i++)
		if (c->s[i].key.kind == kind && c->s[i].key.id == id) { s = &c->s[i]; break; }
	if (!s) {
		if (c->n >= MAX_SUBJ) return -1;
		s = &c->s[c->n++];
		memset(s, 0, sizeof(*s));
		s->key.kind = kind;
		s->key.id = id;
	}
	if (s->val.n >= MAX_RULES_PER_SUBJECT) return -1;
	s->val.r[s->val.n++] = (struct rule){
		.lo = lo, .hi = hi, .recurse = rec, .proto = proto
	};

	/* Remember users that need their user-UID.slice cgroup tracked. */
	if (rec && kind == KIND_UID) {
		int found = 0;
		for (int i = 0; i < c->ncg; i++)
			if (c->cg_uid[i] == id) found = 1;
		if (!found) {
			if (c->ncg >= MAX_SUBJ) return -1;
			c->cg_uid[c->ncg++] = id;
		}
	}
	return 0;
}

static int resolve_user(const char *s, __u32 *uid)
{
	char *e;
	unsigned long v = strtoul(s, &e, 10);
	if (*s && !*e) { *uid = v; return 0; }
	struct passwd *pw = getpwnam(s);
	if (!pw) return -1;
	*uid = pw->pw_uid;
	return 0;
}

static int resolve_group(const char *s, __u32 *gid)
{
	char *e;
	unsigned long v = strtoul(s, &e, 10);
	if (*s && !*e) { *gid = v; return 0; }
	struct group *g = getgrnam(s);
	if (!g) return -1;
	*gid = g->gr_gid;
	return 0;
}

/* A group expands to: a rule on the gid, plus one rule per member uid. */
static int add_subject(struct cfg *c, const char *subj,
		       __u16 lo, __u16 hi, __u8 proto, int rec)
{
	if (subj[0] != '@') {
		__u32 uid;
		if (resolve_user(subj, &uid)) {
			logmsg(L_ERR, "unknown user '%s'", subj);
			return -1;
		}
		return add_rule(c, KIND_UID, uid, lo, hi, proto, rec);
	}

	__u32 gid;
	if (resolve_group(subj + 1, &gid)) {
		logmsg(L_ERR, "unknown group '%s'", subj + 1);
		return -1;
	}
	if (add_rule(c, KIND_GID, gid, lo, hi, proto, rec)) return -1;

	/* Users listed as members of the group */
	struct group *g = getgrgid(gid);
	if (g)
		for (char **m = g->gr_mem; m && *m; m++) {
			struct passwd *pw = getpwnam(*m);
			if (pw && add_rule(c, KIND_UID, pw->pw_uid, lo, hi, proto, rec))
				return -1;
		}
	/* Users whose primary group is this one */
	struct passwd *pw;
	setpwent();
	while ((pw = getpwent()))
		if (pw->pw_gid == gid &&
		    add_rule(c, KIND_UID, pw->pw_uid, lo, hi, proto, rec)) {
			endpwent();
			return -1;
		}
	endpwent();
	return 0;
}

/* "tcp", "udp" or "tcp+udp" (case-insensitive) */
static int parse_proto(const char *s, __u8 *proto)
{
	if (!strcasecmp(s, "tcp"))          *proto = PROTO_TCP;
	else if (!strcasecmp(s, "udp"))     *proto = PROTO_UDP;
	else if (!strcasecmp(s, "tcp+udp") ||
		 !strcasecmp(s, "udp+tcp")) *proto = PROTO_TCP | PROTO_UDP;
	else return -1;
	return 0;
}

/* "80", "82-83" or "0" (= any port) */
static int parse_ports(const char *s, __u16 *lo, __u16 *hi)
{
	char *e;
	long a = strtol(s, &e, 10);
	if (e == s || a < 0 || a > 65535) return -1;
	if (!*e) {
		if (a == 0) { *lo = 1; *hi = 65535; }
		else        { *lo = *hi = a; }
		return 0;
	}
	if (*e != '-' || a < 1) return -1;
	const char *s2 = e + 1;
	long b = strtol(s2, &e, 10);
	if (e == s2 || *e || b < a || b > 65535) return -1;
	*lo = a; *hi = b;
	return 0;
}

/* Line format: ports[/proto]:subject[:r]   (proto defaults to tcp) */
static int parse_line(struct cfg *c, char *l)
{
	char *subj = strchr(l, ':');
	if (!subj) return -1;
	*subj++ = 0;

	int rec = 0;
	char *flag = strchr(subj, ':');
	if (flag) {
		*flag++ = 0;
		if (strcmp(trim(flag), "r")) return -1;
		rec = 1;
	}

	char *ports = trim(l);
	__u8 proto = PROTO_TCP;                 /* default: TCP only */
	char *slash = strchr(ports, '/');
	if (slash) {
		*slash++ = 0;
		if (parse_proto(trim(slash), &proto)) return -1;
		ports = trim(ports);
	}

	__u16 lo, hi;
	if (parse_ports(ports, &lo, &hi)) return -1;
	return add_subject(c, trim(subj), lo, hi, proto, rec);
}

/*
 * Check that every directory on the real path of a config file is owned by
 * root and not writable by group/others. Otherwise a non-root user could
 * rename or replace a parent directory and swap in their own files.
 * Symlinks are resolved first, so the real location is what gets checked.
 */
static int dirs_are_secure(const char *path)
{
	char real[PATH_MAX];

	if (!realpath(path, real)) {
		logmsg(L_ERR, "cannot resolve %s: %s", path, strerror(errno));
		return -1;
	}

	char *slash;
	while ((slash = strrchr(real, '/')) != NULL) {
		if (slash == real)
			real[1] = 0;            /* reached "/" */
		else
			*slash = 0;             /* strip last component */

		struct stat st;
		if (stat(real, &st)) {
			logmsg(L_ERR, "cannot stat %s: %s", real, strerror(errno));
			return -1;
		}
		if (!S_ISDIR(st.st_mode) || st.st_uid != 0 ||
		    (st.st_mode & (S_IWGRP | S_IWOTH))) {
			logmsg(L_ERR, "%s: directory %s must be owned by root and not "
			       "writable by group/others", path, real);
			return -1;
		}
		if (real[1] == 0)
			break;                  /* "/" checked: done */
	}
	return 0;
}

static int load_file(const char *path, struct cfg *c, int depth);

/* Handle "include PATTERN": expand the glob and load every match. */
static int do_include(const char *base, const char *arg, struct cfg *c, int depth)
{
	char pattern[PATH_MAX];

	if (arg[0] == '/' || !strrchr(base, '/')) {
		snprintf(pattern, sizeof(pattern), "%s", arg);
	} else {
		/* Relative paths are resolved against the including file's directory. */
		const char *slash = strrchr(base, '/');
		snprintf(pattern, sizeof(pattern), "%.*s/%s", (int)(slash - base), base, arg);
	}

	glob_t g;
	/* GLOB_NOMAGIC: a pattern without wildcards is returned as-is, so a
	 * missing plain file is an error, while an empty wildcard match is not. */
	int rc = glob(pattern, GLOB_NOMAGIC, NULL, &g);
	if (rc == GLOB_NOMATCH)
		return 0;
	if (rc) {
		logmsg(L_ERR, "include '%s': glob failed", pattern);
		return -1;
	}

	for (size_t i = 0; i < g.gl_pathc; i++) {
		if (load_file(g.gl_pathv[i], c, depth + 1)) {
			globfree(&g);
			return -1;
		}
	}
	globfree(&g);
	return 0;
}

/* Parse one file (recursively handling includes) into c. */
static int load_file(const char *path, struct cfg *c, int depth)
{
	if (depth > MAX_INCLUDE_DEPTH) {
		logmsg(L_ERR, "%s: include nesting too deep (max %d), possible loop",
		       path, MAX_INCLUDE_DEPTH);
		return -1;
	}

	FILE *f = fopen(path, "r");
	if (!f) { logmsg(L_ERR, "cannot open %s: %s", path, strerror(errno)); return -1; }

	/* The file grants privileges: regular file, owned by root, not group/world writable. */
	struct stat st;
	if (fstat(fileno(f), &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & (S_IWGRP | S_IWOTH))) {
		logmsg(L_ERR, "%s must be a regular file owned by root and not writable "
		       "by group/others", path);
		fclose(f);
		return -1;
	}
  if (dirs_are_secure(path)) {
		fclose(f);
		return -1;
	}

	char *line = NULL;
	size_t cap = 0;
	int ln = 0, rc = 0;
	while (getline(&line, &cap, f) > 0) {
		ln++;
		char *h = strchr(line, '#');     /* strip comments */
		if (h) *h = 0;
		char *l = trim(line);
		if (!*l) continue;

		if (!strncmp(l, "include", 7) && isspace((unsigned char)l[7])) {
			char *arg = trim(l + 7);
			if (!*arg) {
				logmsg(L_ERR, "%s:%d: 'include' needs a path", path, ln);
				rc = -1;
				break;
			}
			if (do_include(path, arg, c, depth)) {
				logmsg(L_ERR, "%s:%d: include failed", path, ln);
				rc = -1;
				break;
			}
			continue;
		}

		if (parse_line(c, l)) {
			logmsg(L_ERR, "%s:%d: invalid line (expected ports[/tcp|udp|tcp+udp]:"
			       "subject[:r], or too many rules: max %d per subject)",
			       path, ln, MAX_RULES_PER_SUBJECT);
			rc = -1;
			break;
		}
	}
	free(line);
	fclose(f);
	return rc;
}

static int load_config(const char *path, struct cfg *c)
{
	memset(c, 0, sizeof(*c));
	return load_file(path, c, 0);
}

/* ---------- synchronisation with the eBPF maps ---------- */

static int in_set(const struct cfg *c, const struct subj_key *k)
{
	for (int i = 0; i < c->n; i++)
		if (c->s[i].key.kind == k->kind && c->s[i].key.id == k->id) return 1;
	return 0;
}

/* Insert/update every configured subject, then drop stale ones. */
static void sync_rules(int fd, const struct cfg *c)
{
	for (int i = 0; i < c->n; i++)
		if (bpf_map_update_elem(fd, &c->s[i].key, &c->s[i].val, BPF_ANY))
			logmsg(L_WARN, "failed to update rules map: %s", strerror(errno));

	struct subj_key prev = {0}, next;
	int have = 0;
	while (!bpf_map_get_next_key(fd, have ? &prev : NULL, &next)) {
		if (in_set(c, &next)) { prev = next; have = 1; }
		else bpf_map_delete_elem(fd, &next);   /* 'prev' stays valid */
	}
}

/*
 * Map the cgroup id of /sys/fs/cgroup/user.slice/user-UID.slice to its UID.
 * The slice is recreated with a new id at every login, hence the periodic rescan.
 */
static void sync_cgroups(int fd, const struct cfg *c)
{
	__u64 want[MAX_SUBJ];
	__u32 owner[MAX_SUBJ];
	int nw = 0;

	for (int i = 0; i < c->ncg; i++) {
		char p[128];
		struct stat st;
		snprintf(p, sizeof(p), CG_ROOT "/user.slice/user-%u.slice", c->cg_uid[i]);
		if (stat(p, &st)) continue;           /* user not logged in */
		want[nw]  = st.st_ino;                /* on cgroup v2, inode number == cgroup id */
		owner[nw] = c->cg_uid[i];
		bpf_map_update_elem(fd, &want[nw], &owner[nw], BPF_ANY);
		nw++;
	}

	__u64 prev = 0, next;
	int have = 0;
	while (!bpf_map_get_next_key(fd, have ? &prev : NULL, &next)) {
		int keep = 0;
		for (int i = 0; i < nw; i++)
			if (want[i] == next) keep = 1;
		if (keep) { prev = next; have = 1; }
		else bpf_map_delete_elem(fd, &next);
	}
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *path = "/etc/bindperm.conf";
	int check_only = 0, opt;

	use_prefix = getenv("JOURNAL_STREAM") != NULL;

	while ((opt = getopt(argc, argv, "c:Cvh")) != -1) {
		switch (opt) {
		case 'c': path = optarg; break;
		case 'C': check_only = 1; break;
		case 'v': verbose = 1; break;
		default:
			fprintf(stderr, "usage: %s [-c config] [-C] [-v]\n", argv[0]);
			return 2;
		}
	}

	libbpf_set_print(libbpf_print);

	if (geteuid() != 0)
		logmsg(L_WARN, "not running as root: loading eBPF programs will probably fail");

	if (load_config(path, &cur))
		return 1;
	logmsg(L_INFO, "configuration OK: %d subjects from %s", cur.n, path);

	struct bindperm_bpf *skel = bindperm_bpf__open_and_load();
	if (!skel) {
		logmsg(L_ERR, "failed to load eBPF programs (see libbpf/verifier output above); "
		       "run check-requirements.sh and use -v for details");
		return 1;
	}
	logmsg(L_INFO, "eBPF programs loaded (verifier and CO-RE relocations OK)");

	if (check_only) {
		logmsg(L_INFO, "check mode: nothing attached, exiting");
		bindperm_bpf__destroy(skel);
		return 0;
	}

	int rfd = bpf_map__fd(skel->maps.rules);
	int cfd = bpf_map__fd(skel->maps.cg_owner);
	sync_rules(rfd, &cur);
	sync_cgroups(cfd, &cur);

	int cg = open(CG_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cg < 0) {
		logmsg(L_ERR, "cannot open %s: %s", CG_ROOT, strerror(errno));
		return 1;
	}

	/* Link-based attach is always "multi" (other programs on child cgroups keep
	 * running), and BPF_LINK_CREATE rejects any flags, so none are passed. */
	int l4 = bpf_link_create(bpf_program__fd(skel->progs.bindperm_bind4), cg,
				 BPF_CGROUP_INET4_BIND, NULL);
	if (l4 < 0) { logmsg(L_ERR, "attach bind4 failed: %s", strerror(-l4)); return 1; }
	int l6 = bpf_link_create(bpf_program__fd(skel->progs.bindperm_bind6), cg,
				 BPF_CGROUP_INET6_BIND, NULL);
	if (l6 < 0) { logmsg(L_ERR, "attach bind6 failed: %s", strerror(-l6)); return 1; }

	/* No SA_RESTART: poll() must be interrupted by signals. */
	struct sigaction sa = { .sa_handler = on_term };
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = on_hup;
	sigaction(SIGHUP, &sa, NULL);

	/* Wake up when user slices are created/removed (login/logout). */
	int ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	if (ifd >= 0)
		inotify_add_watch(ifd, CG_ROOT "/user.slice", IN_CREATE | IN_DELETE | IN_ONLYDIR);
	else
		logmsg(L_WARN, "inotify unavailable, falling back to 1s polling");

	logmsg(L_INFO, "active and attached to %s (SIGHUP reloads the configuration)", CG_ROOT);

	while (!stop) {
		if (reload) {
			reload = 0;
			if (load_config(path, &nxt)) {
				logmsg(L_ERR, "reload failed, keeping the previous configuration");
			} else {
				memcpy(&cur, &nxt, sizeof(cur));
				sync_rules(rfd, &cur);
				logmsg(L_INFO, "configuration reloaded: %d subjects", cur.n);
			}
		}
		sync_cgroups(cfd, &cur);

		struct pollfd pf = { .fd = ifd, .events = POLLIN };
		poll(&pf, ifd >= 0 ? 1 : 0, 1000);
		if (ifd >= 0 && (pf.revents & POLLIN)) {
			char buf[4096];
			while (read(ifd, buf, sizeof(buf)) > 0) {}
		}
	}

	logmsg(L_INFO, "shutting down, detaching eBPF programs");
	close(l6);
	close(l4);
	bindperm_bpf__destroy(skel);
	return 0;
}