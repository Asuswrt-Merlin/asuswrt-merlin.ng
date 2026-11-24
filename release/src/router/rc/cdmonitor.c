/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2026, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * cdmonitor: watch /tmp/core for kernel core dumps written with
 * core_pattern "/tmp/core/%e.%p.sig%s.%t", compress each finished dump
 * with tar, and enforce retention limits (per-name count and total size).
 */

#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <shared.h>

#ifndef CORE_DIR
#define CORE_DIR	"/tmp/core"
#endif
#ifndef PID_FILE
#define PID_FILE	"/var/run/cdmonitor.pid"
#endif
#define NORMAL_PERIOD	10			/* scan interval (seconds) */
#define PENDING_MAX	16			/* raw cores tracked for write completion */
#define ARCHIVE_MAX	64			/* archives handled per retention pass */
#define KEEP_PER_NAME	3			/* max archives per process name */
#define TOTAL_LIMIT	(5 * 1024 * 1024)	/* total archive size cap (bytes) */
#define TGZ_SUFFIX	".tar.gz"
#define NAME_LEN	256
#define PATH_LEN	(sizeof(CORE_DIR) + NAME_LEN + sizeof(TGZ_SUFFIX) + 2)

typedef struct {
	char name[NAME_LEN];	/* basename of the raw core file */
	off_t size;		/* size seen at the previous scan */
	int seen;		/* file still present in the current scan */
} pending_t;

typedef struct {
	char name[NAME_LEN];	/* basename of the .tar.gz */
	char ename[NAME_LEN];	/* process name (%e) */
	long long ts;		/* %t from the name, or st_mtime fallback */
	off_t size;
	int deleted;
} archive_t;

static int debug;
static struct itimerval itv;
static pending_t pending[PENDING_MAX];
static archive_t archives[ARCHIVE_MAX];

#define STAMP_LEN	14	/* YYYYMMDDhhmmss */

/* Format an epoch as a local YYYYMMDDhhmmss stamp.  Returns 0 on success. */
static int format_stamp(long long ts, char *out, size_t olen)
{
	struct tm tm;
	time_t t = (time_t)ts;

	/* Reject epochs that do not fit time_t (32-bit) instead of truncating */
	if (ts < 0 || (long long)t != ts)
		return -1;
	/* Pick up a timezone changed at run time (no-op on AVOID_TZ_ENV builds) */
	refresh_tz_env();
	if (localtime_r(&t, &tm) == NULL)
		return -1;
	return strftime(out, olen, "%Y%m%d%H%M%S", &tm) == STAMP_LEN ? 0 : -1;
}

/* Convert a 14-digit YYYYMMDDhhmmss stamp back to an epoch.  Returns -1 if
 * the string is not a valid stamp. */
static long long parse_stamp(const char *s)
{
	struct tm tm;
	const char *p;
	time_t t;
	int v[6], i;
	static const int width[6] = { 4, 2, 2, 2, 2, 2 };

	if (strlen(s) != STAMP_LEN)
		return -1;
	for (p = s; *p; p++)
		if (*p < '0' || *p > '9')
			return -1;
	for (i = 0, p = s; i < 6; p += width[i], i++) {
		int j;

		v[i] = 0;
		for (j = 0; j < width[i]; j++)
			v[i] = v[i] * 10 + (p[j] - '0');
	}

	/* mktime() would silently normalize out-of-range fields */
	if (v[1] < 1 || v[1] > 12 || v[2] < 1 || v[2] > 31 ||
	    v[3] > 23 || v[4] > 59 || v[5] > 60)
		return -1;

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = v[0] - 1900;
	tm.tm_mon = v[1] - 1;
	tm.tm_mday = v[2];
	tm.tm_hour = v[3];
	tm.tm_min = v[4];
	tm.tm_sec = v[5];
	tm.tm_isdst = -1;
	t = mktime(&tm);
	return t == (time_t)-1 ? -1 : (long long)t;
}

/* Parse "<%e>.<%p>.sig<%s>.<%t>" scanning from the right, because %e (the
 * process name) may itself contain dots.  %t is either the raw epoch written
 * by the kernel or the 14-digit YYYYMMDDhhmmss stamp of an archive made by
 * compress_one(); ts is always returned as an epoch.  base must not carry the
 * ".tar.gz" suffix.  On success fills ename/ts and returns 0; returns -1 if
 * base does not match the core pattern. */
static int parse_core_name(const char *base, char *ename, size_t elen, long long *ts)
{
	char buf[NAME_LEN];
	char *dot, *end;
	long long tval;

	if (strlcpy(buf, base, sizeof(buf)) >= sizeof(buf))
		return -1;

	/* %t: trailing field, all digits */
	dot = strrchr(buf, '.');
	if (dot == NULL || dot[1] == '\0')
		return -1;
	tval = strtoll(dot + 1, &end, 10);
	if (*end != '\0' || tval < 0)
		return -1;
	if (strlen(dot + 1) == STAMP_LEN) {
		tval = parse_stamp(dot + 1);
		if (tval < 0)
			return -1;
	}
	*dot = '\0';

	/* sig%s: "sig" followed by digits */
	dot = strrchr(buf, '.');
	if (dot == NULL)
		return -1;
	if (strncmp(dot + 1, "sig", 3) != 0 || dot[4] == '\0')
		return -1;
	strtoll(dot + 4, &end, 10);
	if (*end != '\0')
		return -1;
	*dot = '\0';

	/* %p: all digits; what remains before it is %e and must be non-empty */
	dot = strrchr(buf, '.');
	if (dot == NULL || dot == buf || dot[1] == '\0')
		return -1;
	strtoll(dot + 1, &end, 10);
	if (*end != '\0')
		return -1;
	*dot = '\0';

	if (strlcpy(ename, buf, elen) >= elen)
		return -1;
	*ts = tval;
	return 0;
}

/* Sort newest first; tie-break on name for determinism. */
static int cmp_ts_desc(const void *a, const void *b)
{
	const archive_t *x = a, *y = b;

	if (x->ts != y->ts)
		return (y->ts > x->ts) ? 1 : -1;
	return strcmp(y->name, x->name);
}

static void delete_archive(archive_t *a)
{
	char path[PATH_LEN];

	snprintf(path, sizeof(path), "%s/%s", CORE_DIR, a->name);
	unlink(path);
	a->deleted = 1;
	if (debug) dbg("cdmonitor: removed %s\n", a->name);
}

/* Enforce retention over all archives in CORE_DIR: keep at most
 * KEEP_PER_NAME newest archives per process name, then delete oldest
 * archives until the total size fits TOTAL_LIMIT.  The newest archive
 * overall is always kept, even if it alone exceeds 5MB. */
static void enforce_limits(void)
{
	DIR *dir;
	struct dirent *ent;
	struct stat st;
	archive_t *a;
	char path[PATH_LEN];
	char base[NAME_LEN];
	long long total = 0;
	size_t len, slen = strlen(TGZ_SUFFIX);
	int count = 0, kept, i, j;

	dir = opendir(CORE_DIR);
	if (dir == NULL)
		return;

	while ((ent = readdir(dir)) != NULL && count < ARCHIVE_MAX) {
		len = strlen(ent->d_name);
		if (len <= slen || len >= NAME_LEN)
			continue;
		if (strcmp(ent->d_name + len - slen, TGZ_SUFFIX) != 0)
			continue;
		snprintf(path, sizeof(path), "%s/%s", CORE_DIR, ent->d_name);
		if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
			continue;

		a = &archives[count];
		strlcpy(a->name, ent->d_name, sizeof(a->name));
		strlcpy(base, ent->d_name, sizeof(base));
		base[len - slen] = '\0';
		if (parse_core_name(base, a->ename, sizeof(a->ename), &a->ts) != 0) {
			/* Unexpected name: still count it, order by mtime. */
			strlcpy(a->ename, base, sizeof(a->ename));
			a->ts = (long long)st.st_mtime;
		}
		a->size = st.st_size;
		a->deleted = 0;
		total += st.st_size;
		count++;
	}
	closedir(dir);

	if (count == 0)
		return;

	qsort(archives, count, sizeof(archive_t), cmp_ts_desc);

	/* Pass 1: per-name cap.  Entries are newest-first, so an entry is
	 * dropped when KEEP_PER_NAME newer siblings already survive. */
	for (i = 0; i < count; i++) {
		kept = 0;
		for (j = 0; j < i; j++) {
			if (!archives[j].deleted &&
			    strcmp(archives[j].ename, archives[i].ename) == 0)
				kept++;
		}
		if (kept >= KEEP_PER_NAME) {
			total -= archives[i].size;
			delete_archive(&archives[i]);
		}
	}

	/* Pass 2: total-size cap, oldest first, index 0 (newest) untouchable. */
	for (i = count - 1; i > 0 && total > TOTAL_LIMIT; i--) {
		if (archives[i].deleted)
			continue;
		total -= archives[i].size;
		delete_archive(&archives[i]);
	}
}

/* Compress CORE_DIR/<name> into CORE_DIR/<name>.tar.gz, with the trailing
 * epoch of <name> replaced by a readable YYYYMMDDhhmmss stamp, and remove the
 * raw core on success.  On failure the partial archive is removed and the core
 * is kept so the next scan retries.  Returns 0 on success, -1 on failure.
 * The archive path is absolute so tar's -C only affects the member name. */
static int compress_one(const char *name)
{
	char core_path[PATH_LEN];
	char tgz_path[PATH_LEN];
	char ename[NAME_LEN];
	char stamp[STAMP_LEN + 1];
	const char *dot;
	long long ts;
	int n;
	char op_name[NAME_LEN + 2];	/* "./" + name, so a name starting with
					 * '-' (attacker-controlled %e) can't be
					 * parsed as a tar option */
	struct stat st;
	int ret;

	snprintf(core_path, sizeof(core_path), "%s/%s", CORE_DIR, name);
	snprintf(op_name, sizeof(op_name), "./%s", name);

	/* Archive name keeps "<%e>.<%p>.sig<%s>." and swaps %t for a stamp.  If
	 * anything about that fails, fall back to the raw core name. */
	n = -1;
	dot = strrchr(name, '.');
	if (dot != NULL && parse_core_name(name, ename, sizeof(ename), &ts) == 0 &&
	    format_stamp(ts, stamp, sizeof(stamp)) == 0)
		n = snprintf(tgz_path, sizeof(tgz_path), "%s/%.*s.%s%s", CORE_DIR,
			     (int)(dot - name), name, stamp, TGZ_SUFFIX);
	/* The archive basename must stay below NAME_LEN to be seen by retention */
	if (n < 0 || (size_t)n >= sizeof(tgz_path) ||
	    (size_t)n - sizeof(CORE_DIR) >= NAME_LEN)
		snprintf(tgz_path, sizeof(tgz_path), "%s/%s%s", CORE_DIR, name, TGZ_SUFFIX);

	ret = eval("tar", "-C", CORE_DIR, "-czf", tgz_path, op_name);
	if (ret != 0 || stat(tgz_path, &st) != 0 || st.st_size <= 0) {
		if (debug) dbg("cdmonitor: compress %s failed (%d)\n", name, ret);
		unlink(tgz_path);
		return -1;
	}

	unlink(core_path);
	if (debug) dbg("cdmonitor: archived %s as %s\n", name, tgz_path);
	return 0;
}

/* One scan cycle: track raw core files until their size is stable across
 * two consecutive scans, then compress them and enforce retention. */
static void scan_cores(void)
{
	DIR *dir;
	struct dirent *ent;
	struct stat st;
	pending_t *slot, *free_slot;
	char path[PATH_LEN];
	char ename[NAME_LEN];
	long long ts;
	size_t len, slen = strlen(TGZ_SUFFIX);
	int i, changed = 0;

	dir = opendir(CORE_DIR);
	if (dir == NULL)
		return;

	for (i = 0; i < PENDING_MAX; i++)
		pending[i].seen = 0;

	while ((ent = readdir(dir)) != NULL) {
		len = strlen(ent->d_name);
		if (len == 0 || len >= NAME_LEN)
			continue;
		if (len > slen && strcmp(ent->d_name + len - slen, TGZ_SUFFIX) == 0)
			continue;	/* already archived */
		if (parse_core_name(ent->d_name, ename, sizeof(ename), &ts) != 0)
			continue;	/* not a core dump */
		snprintf(path, sizeof(path), "%s/%s", CORE_DIR, ent->d_name);
		if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
			continue;

		slot = NULL;
		free_slot = NULL;
		for (i = 0; i < PENDING_MAX; i++) {
			if (pending[i].name[0] == '\0') {
				if (free_slot == NULL)
					free_slot = &pending[i];
				continue;
			}
			if (strcmp(pending[i].name, ent->d_name) == 0) {
				slot = &pending[i];
				break;
			}
		}

		if (slot == NULL) {
			/* first sighting; if the table is full, retry later */
			if (free_slot != NULL) {
				strlcpy(free_slot->name, ent->d_name, sizeof(free_slot->name));
				free_slot->size = st.st_size;
				free_slot->seen = 1;
			} else if (debug) {
				dbg("cdmonitor: pending table full, dropped %s\n", ent->d_name);
			}
			continue;
		}

		slot->seen = 1;
		if (st.st_size != slot->size) {
			slot->size = st.st_size;	/* still being written */
			continue;
		}

		/* size stable across two scans: archive it */
		if (compress_one(ent->d_name) == 0) {
			slot->name[0] = '\0';
			changed = 1;
		}
	}
	closedir(dir);

	/* forget pending entries whose file disappeared */
	for (i = 0; i < PENDING_MAX; i++) {
		if (pending[i].name[0] != '\0' && !pending[i].seen)
			pending[i].name[0] = '\0';
	}

	if (changed)
		enforce_limits();
}

static void alarmtimer(unsigned long sec, unsigned long usec)
{
	itv.it_value.tv_sec = sec;
	itv.it_value.tv_usec = usec;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

static void cdmonitor_exit(int sig)
{
	(void)sig;
	alarmtimer(0, 0);
	remove(PID_FILE);
	exit(0);
}

static void cdmonitor_alarmtimer(int sig)
{
	(void)sig;
	scan_cores();
	alarmtimer(NORMAL_PERIOD, 0);
}

int cdmonitor_main(int argc, char *argv[])
{
	FILE *fp;
	sigset_t sigs_to_catch;

	(void)argc;
	(void)argv;

	if (nvram_get_int("stop_cdmonitor"))
		return 0;

	/* write pid */
	if ((fp = fopen(PID_FILE, "w")) != NULL) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	debug = nvram_get_int("cdmonitor_debug");

	/* defensive: init.c already creates it with the same mode */
	mkdir(CORE_DIR, 0600);

	memset(pending, 0, sizeof(pending));

	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGALRM, cdmonitor_alarmtimer);
	signal(SIGTERM, cdmonitor_exit);

	cdmonitor_alarmtimer(SIGALRM);

	/* Most of the time it sleeps */
	while (1)
		pause();

	return 0;
}
