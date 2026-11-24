/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2012, ASUSTeK Inc.
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include "rc.h"
#include "netool.h"
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MyDBG(fmt,args...) \
	if(f_exists(NETOOL_DEBUG) > 0) { \
		dbg("[Netool][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}
#define ErrorMsg(fmt,args...) \
	dbg("[Netool][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args);

#ifdef RTCONFIG_TRACEROUTE
#define TRACEROUTE    "/usr/sbin/traceroute"
#else
#define TRACEROUTE    "traceroute"
#endif

#define MUTEX pthread_mutex_t
#define MUTEXINIT(m) pthread_mutex_init(m, NULL)
#define MUTEXLOCK(m) pthread_mutex_lock(m)
#define MUTEXTRYLOCK(m) pthread_mutex_trylock(m)
#define MUTEXUNLOCK(m) pthread_mutex_unlock(m)
#define MUTEXDESTROY(m) pthread_mutex_destroy(m)

static void start_req_thread(void *rInfo, int type);
static int terminated = 1;
static MUTEX task_list_lock;
struct list *task_list=NULL;

#ifndef NON_P_THREAD
static int IN_EXEC = 0;
#endif

/* --------------------------------------------- *
 *           vpopen/vpclose Function Begin       *
 * --------------------------------------------- */
static pid_t    *childpid = NULL;  /* ptr to array allocated at run-time */
static int      maxfd;             /* from our open_max(), {Prog openmax} */
static long     openmax = 0;
/*
 * If OPEN_MAX is indeterminate, we're not 
 * guaranteed that this is adequate.
 */ 
#define OPEN_MAX_GUESS 1024
long open_max(void)
{
	if (openmax == 0) { /* first time through */
		errno = 0;
		if ((openmax = sysconf(_SC_OPEN_MAX)) < 0) {
			if (errno == 0)
				openmax = OPEN_MAX_GUESS;    /* it's indeterminate */
			else
				MyDBG("sysconf error for _SC_OPEN_MAX");
		}
	}
	return(openmax);
}

FILE *vpopen(const char* cmdstring, const char *type)
{
	int pfd[2];
	FILE *fp;
	pid_t   pid;
	
	if ((type[0]!='r' && type[0]!='w')||type[1]!=0) {
		errno = EINVAL;
		return(NULL);
	}
	
	if (childpid == NULL) {     /* first time through */
		/* allocate zeroed out array for child pids */
		maxfd = open_max();
		if ((childpid = (pid_t *)calloc(maxfd, sizeof(pid_t))) == NULL) 
			return(NULL);
	}
	
	if (pipe(pfd)!=0) {
		return NULL;
	}
	
	if ((pid = vfork())<0) {
		return NULL; /* errno set by fork() */
	} else if (pid == 0) {    /* child */
		if (*type == 'r') {
			close(pfd[0]);
			if (pfd[1] != STDOUT_FILENO) {
				dup2(pfd[1], STDOUT_FILENO);
				close(pfd[1]);
			}
		} else {
			close(pfd[1]);
			if (pfd[0] != STDIN_FILENO) {
				dup2(pfd[0], STDIN_FILENO);
				close(pfd[0]);
			}
		}
		
		/* close all descriptors in childpid[] */
		int i;
		for (i = 0; i < maxfd; i++) 
			if (childpid[ i ] > 0)
				close(i);
		
		execl("/bin/sh", "sh", "-c", cmdstring, (char *) 0);
		_exit(127);
	}
	
	if (*type == 'r') { 
		close(pfd[1]);
		if ( (fp = fdopen(pfd[0], type)) == NULL)
			return(NULL);
	} else {
		close(pfd[0]);
		if ( (fp = fdopen(pfd[1], type)) == NULL)
			return(NULL);
	}
	
	childpid[fileno(fp)] = pid; /* remember child pid for this fd */
	return(fp);
}

int vpclose(FILE *fp)
{
	int     fd, stat; 
	pid_t   pid;
	
	if (childpid == NULL) 
		return -1; /* popen() has never been called */
	
	fd = fileno(fp);
	if ( (pid = childpid[fd]) == 0)
		return(-1); /* fp wasn't opened by popen() */
	
	childpid[fd] = 0;
	if (fclose(fp) == EOF)
		return(-1);
	
	while (waitpid(pid, &stat, 0) < 0)
		if (errno != EINTR)
			return(-1); /* error other than EINTR from waitpid() */
	
	return(stat);   /* return child's termination status */
	
}
/* --------------------------------------------- *
 *           vpopen/vpclose Function End         *
 * --------------------------------------------- */
/* Open a result file for writing without following a symlink planted at
 * its path; root writes these files, so a followed link could truncate any
 * file. O_NONBLOCK keeps open() from waiting on a FIFO, and only a regular
 * file is accepted. Truncate after the type check, not in open(), so a
 * non-regular file is never modified. Returns NULL on failure. */
static FILE *fopen_result_nofollow(const char *path)
{
	FILE *fp;
	struct stat st;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    ftruncate(fd, 0) != 0) {
		close(fd);
		return NULL;
	}

	fp = fdopen(fd, "w");
	if (fp == NULL)
		close(fd);

	return fp;
}

/* Create NETOOL_RESULT_DIR as a private directory owned by root.
 * mkdir_if_none() would create it 0777 and accept whatever already sits at
 * the path, so a link or directory planted there beforehand would be reused.
 * Returns 0 on success, -1 if a safe directory cannot be guaranteed. */
static int prepare_result_dir(void)
{
	struct stat st;

	if (mkdir(NETOOL_RESULT_DIR, 0700) == 0)
		return 0;
	if (errno != EEXIST) {
		perror("mkdir " NETOOL_RESULT_DIR);
		return -1;
	}

	/* Something already exists: replace anything that is not a real
	 * directory (e.g. a planted symlink), then recreate it. */
	if (lstat(NETOOL_RESULT_DIR, &st) != 0) {
		perror("lstat " NETOOL_RESULT_DIR);
		return -1;
	}
	if (!S_ISDIR(st.st_mode)) {
		if (unlink(NETOOL_RESULT_DIR) != 0 ||
		    mkdir(NETOOL_RESULT_DIR, 0700) != 0) {
			perror("recreate " NETOOL_RESULT_DIR);
			return -1;
		}
		return 0;
	}

	/* A real directory: only accept it when root owns it. */
	if (st.st_uid != 0) {
		ErrorMsg("%s is not owned by root\n", NETOOL_RESULT_DIR);
		return -1;
	}
	if (chmod(NETOOL_RESULT_DIR, 0700) != 0) {
		perror("chmod " NETOOL_RESULT_DIR);
		return -1;
	}

	return 0;
}

static int do_ping(void *rInfo)
{
	FILE *fp, *fp_w;
	char cmd[256]={0};
	char buf[256]={0};
	char ifpara[16]={0};
	char result_path[64]={0};
	char jitter_tmp[64]={0};
	char *pk_loss;
	char *ping, *p, *end;
	char obj[512];
	int  len;
	int  loop;
	int  first;
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", req->target);
	
	if (!strcmp(req->interface, "")) {
		snprintf(ifpara, sizeof(ifpara), "%s", "");
	} else {
		snprintf(ifpara, sizeof(ifpara), "-I %s", req->interface);
	}
	
	loop = req->exec_cnt;
	
	fp = NULL;
	
	if ((fp_w = fopen_result_nofollow(result_path)) != NULL) {
		if (!strcmp(req->target, "")) {
			fprintf(fp_w, "[{\"loss\":\"\", \"ping\":\"\", \"jitter\":\"\"}]");
			fclose(fp_w);
			return -1;
		}
		
		len = strlen("min/avg/max = ");
		snprintf(cmd, sizeof(cmd), "%s %s -c %d -w %d -q %s &",
			(!strcmp(req->ver, "v6")) ? "ping6" : "ping", ifpara, req->ping_cnt, req->response, req->target);
		
		fprintf(fp_w, "[");
		
		first = 1;
		while (loop > 0) {
			/* build one object per iteration; emit only when complete */
			obj[0] = '\0';

			MyDBG("Cmd: %s\n", cmd);
			if ((fp = vpopen(cmd, "r")) != NULL) {
				while(fgets(buf, sizeof(buf), fp)) {
					pk_loss = strstr(buf, "received,");
					if (pk_loss != NULL) {
						end = strrchr(buf, '%');
						if (end == NULL)
							continue;
						*end  = '\0';
						MyDBG("Packet Loss:%s\n", pk_loss+strlen("received,"));
						snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj),
							"{\"loss\":\"%d\", ", safe_atoi(pk_loss+strlen("received,")));
						if( safe_atoi(pk_loss+strlen("received,")) == 100) {
							snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj),
								"\"ping\":\"\", \"jitter\":\"\"}");
						}
					}
					ping = strstr(buf, "min/avg/max");
					if (ping != NULL) {
						p = strrchr(buf, '=');
						if (p == NULL)
							continue;
						while (*p != '/' && *p != '\0') {
							p++;
						}
						if (*p == '\0')
							continue;
						/* no open object (loss line missing or already closed):
						 * appending here would emit a fragment without '{' */
						if (strlen(obj) == 0 || obj[strlen(obj) - 1] == '}')
							continue;
						*p = '\0';
						MyDBG("Ping: [%s], Jitter: [%3.3f]\n", ping+len, atof(ping+len) - atof(jitter_tmp));
						snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj),
							"\"ping\":\"%s\", \"jitter\":\"%3.3f\"}", ping+len, atof(ping+len) - atof(jitter_tmp));
						snprintf(jitter_tmp, sizeof(jitter_tmp), "%s", ping+len);
					}
				}
				
			} else {
				ErrorMsg("fp = %p\n", fp); 
				perror(cmd);
			}
			loop--;
			
			if (strlen(obj) > 0) {
				/* rtt line missing: close the object so the array stays valid */
				if (obj[strlen(obj) - 1] != '}')
					snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj),
						"\"ping\":\"\", \"jitter\":\"\"}");
				fprintf(fp_w, "%s%s", first ? "" : ",", obj);
				first = 0;
			}
				
			if (fp)
				vpclose(fp);
		}
		
		fprintf(fp_w, "]");
		fclose(fp_w);
	}
	return 0;
	
}

static int do_ping_normal(void *rInfo)
{
	char cmd[256]={0};
	char ifpara[16]={0};
	char result_path[64]={0};
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", NETOOL_RESULT_PING_NORMAL_LOG);
	unlink(result_path);
	
	if (!strcmp(req->interface, "")) {
		snprintf(ifpara, sizeof(ifpara), "%s", "");
	} else {
		snprintf(ifpara, sizeof(ifpara), "-I %s", req->interface);
	}
	
	snprintf(cmd, sizeof(cmd), "%s %s -c %d -W %d %s > %s 2>&1 || true && echo 'XU6J03M6' >> %s &",
				   (!strcmp(req->ver, "v6")) ? "ping6" : "ping", ifpara, req->ping_cnt,
				   req->response, req->target, result_path, result_path);
	
	MyDBG("Cmd: %s\n", cmd);
	if (system(cmd) < 0) {
		ErrorMsg("error :%s\n", strerror(errno));
	}
	
	return 0;
}

static int do_traceroute_normal(void *rInfo)
{
	char cmd[256]={0};
	char ifpara[16]={0};
	char result_path[64]={0};
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", NETOOL_RESULT_TRACERT_NORMAL_LOG);
	unlink(result_path);
	
	if (!strcmp(req->interface, "")) {
		snprintf(ifpara, sizeof(ifpara), "%s", "");
	} else {
		snprintf(ifpara, sizeof(ifpara), "-i %s", req->interface);
	}
	
#ifdef RTCONFIG_TRACEROUTE
	snprintf(cmd, sizeof(cmd), TRACEROUTE" %s %s -m %d -w %d %s > %s 2>&1 && echo 'XU6J03M6' >> %s &", 
				  (!strcmp(req->ver, "v6")) ? "-6" : "-4", ifpara, req->hops, req->response,
				  req->target, result_path, result_path);
#else
	snprintf(cmd, sizeof(cmd), TRACEROUTE"%s %s -m %d -w %d %s > %s 2>&1 && echo 'XU6J03M6' >> %s &", 
				  (!strcmp(req->ver, "v6")) ? "6" : "", ifpara, req->hops, req->response,
				  req->target, result_path, result_path);
#endif
	
	MyDBG("Cmd: %s\n", cmd);
	if (system(cmd) < 0) {
		ErrorMsg("error :%s\n", strerror(errno));
	}
	
	return 0;
}

static int do_nslookup(void *rInfo)
{
	char cmd[256]={0};
	char result_path[64]={0};
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", NETOOL_RESULT_NSLOOKUP_LOG);
	unlink(result_path);
	
	snprintf(cmd, sizeof(cmd), "nslookup %s > %s 2>&1 && echo 'XU6J03M6' >> %s &", 
				    req->target, result_path, result_path);
	MyDBG("Cmd: %s\n", cmd);
	if (system(cmd) < 0) {
		ErrorMsg("error :%s\n", strerror(errno));
	}
	
	return 0;
}

static char *get_netstat_option(const int opt)
{
	static char Info[16];
	int  i, x;
	
	x = 0;
	memset(&Info, 0, sizeof(Info));
	
	for(i = 0; i < MAX_NETSTAT_OPTIONS_NUM; i++) {
		if ((opt & (1 << i)) && !x) {
			snprintf(Info, sizeof(Info), "%s", netstInfo[i].option);
			x = 1;
			continue;
		}
		if ((opt & (1 << i)) && x) {
			snprintf(Info + strlen(Info), sizeof(Info) - strlen(Info), "%s", netstInfo[i].option);
		}
	}
	return Info;
	
}

static char *get_netstat_nat_option(const int opt)
{
	static char Info[16];
	int  i, x;
	
	x = 0;
	memset(&Info, 0, sizeof(Info));
	
	if (!opt)
		return "";

	for(i = 0; i < MAX_NETSTAT_NAT_OPTIONS_NUM; i++) {
		if ((opt & (1 << i)) && !x) {
			snprintf(Info, sizeof(Info), "-%s", netst_natInfo[i].option);
			x = 1;
			continue;
		}
		if ((opt & (1 << i)) && x) {
			snprintf(Info + strlen(Info), sizeof(Info) - strlen(Info), "%s", netst_natInfo[i].option);
		}
	}
	return Info;
	
}

static int do_netstat(void *rInfo)
{
	char cmd[256]={0};
	char result_path[64]={0};
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", NETOOL_RESULT_NETSTAT_LOG);
	unlink(result_path);
	
	snprintf(cmd, sizeof(cmd), "netstat -W%s > %s 2>&1 && echo 'XU6J03M6' >> %s &", 
				    get_netstat_option(req->netst), result_path, result_path);
	MyDBG("Cmd: %s\n", cmd);
	if (system(cmd) < 0) {
		ErrorMsg("error :%s\n", strerror(errno));
	}
	
	return 0;
}

static int do_netstat_nat(void *rInfo)
{
	char cmd[256]={0};
	char sort[12]={0};
	char proto[8]={0};
	char srchost[64]={0};
	char dsthost[64]={0};
	char result_path[64]={0};
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", NETOOL_RESULT_NETSTAT_NAT_LOG);
	unlink(result_path);
	
	if (strcmp(req->sort, "")) {
		snprintf(sort, sizeof(sort), "-r %s", req->sort);
	}
	if (strcmp(req->proto, "")) {
		snprintf(proto, sizeof(proto), "-p %s", req->proto);
	}
	if (strcmp(req->srchost, "")) {
		snprintf(srchost, sizeof(srchost), "-s %s", req->srchost);
	}
	if (strcmp(req->dsthost, "")) {
		snprintf(dsthost, sizeof(dsthost), "-d %s", req->dsthost);
	}
	
	snprintf(cmd, sizeof(cmd), "netstat-nat %s %s %s %s %s > %s 2>&1 && echo 'XU6J03M6' >> %s &", 
				    get_netstat_nat_option(req->netst), sort, proto, srchost, dsthost,
				    result_path, result_path);
	MyDBG("Cmd: %s\n", cmd);
	if (system(cmd) < 0) {
		ErrorMsg("error :%s\n", strerror(errno));
	}
	
	return 0;
}

static double get_last_tracert(char *xxx)
{
	const char * const delim = " ";
	char * const dupstr = strdup(xxx);
	char *saveptr = NULL;
	char *substr = NULL;
	int count = 0;
	double ping = 0;
	char buf[128] = {0};
	int i = 0;
	
	dupstr[strlen(dupstr)-1] = '\0';
	//MyDBG("Input String:[%s]\n", dupstr);
	substr = strtok_r(dupstr, delim, &saveptr);
	
	do {
		MyDBG("[#%d] sub string: %s\n", count, substr);
		count++;
		substr = strtok_r(NULL, delim, &saveptr);
		if (!strcmp(substr, "ms")) {
			ping += atof(buf);
			MyDBG("Ping%d:[%3.3f]\n", i, ping);
			i++;
			if (i == 3) 
				break;
		}
		snprintf(buf, sizeof(buf), "%s", substr);
	
	} while (substr);
	
	free(dupstr);
	
	return ping/3;
}

static int do_traceroute(void *rInfo)
{
	FILE *fp, *fp_w;
	char cmd[256]={0};
	char buf[256]={0};
	char ifpara[16]={0};
	char result_path[64]={0};
	char lastpingbuf[128] = {0};
	char *unping;
	int i = 0;
	int ln = 0;
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", req->target);
	
	if (!strcmp(req->interface, "")) {
		snprintf(ifpara, sizeof(ifpara), "%s", "");
	} else {
		snprintf(ifpara, sizeof(ifpara), "-i %s", req->interface);
	}
	
	fp_w = fopen_result_nofollow(result_path);
	
	if (fp_w != NULL) {
		if (!strcmp(req->target, "")) {
			fprintf(fp_w, "[{\"ping\":\"\"}]");
			fclose(fp_w);
			return -1;
		}
		
#ifdef RTCONFIG_TRACEROUTE
		snprintf(cmd, sizeof(cmd), TRACEROUTE" %s %s -n -m %d -w %d %s",
			(!strcmp(req->ver, "v6")) ? "-6" : "-4", ifpara, req->hops, req->response, req->target);
#else
		snprintf(cmd, sizeof(cmd), TRACEROUTE"%s %s -n -m %d -w %d %s",
			(!strcmp(req->ver, "v6")) ? "6" : "", ifpara, req->hops, req->response, req->target);
#endif
		MyDBG("Cmd: %s\n", cmd);
		
		fprintf(fp_w, "[");
		
		if ((fp = vpopen(cmd, "r")) != NULL) {
			while(fgets(buf, sizeof(buf), fp)) {
				printf("%s", buf);
				unping = strstr(buf, "*");
				if (unping != NULL) {
					i++;
				} else {
					ln++;
					snprintf(lastpingbuf, sizeof(lastpingbuf), "%s", buf);
				}
				if (i == 2) 
					break;
			}
			MyDBG("Lastping:%s\n", lastpingbuf);
		} else {
			ErrorMsg("fp = %p\n", fp); 
			perror(cmd);
		}
		if (fp)
			vpclose(fp);
		
		if (strlen(lastpingbuf) && strstr(lastpingbuf, "ms") != NULL) {
			//MyDBG("Last ping Avg: [%3.3f]\n", get_last_tracert((ln > 10) ? lastpingbuf : lastpingbuf+1));
			fprintf(fp_w, "{\"ping\":\"%3.3f\"}",get_last_tracert((ln > 10) ? lastpingbuf : lastpingbuf+1));
		} else {
			fprintf(fp_w, "{\"ping\":\"\"}");
		}
		fprintf(fp_w, "]");
		fclose(fp_w);
		
#ifndef NON_P_THREAD
		REQUEST_INFO_T *req_task;
		struct listnode *lt;
		int del = 0;
		
		if (f_exists(NETOOL_QUEUE) > 0) {
			/* Search Target and drop it in task list */
			MUTEXLOCK(&task_list_lock);
			LIST_LOOP(task_list,req_task,lt)
			{
				if (!strcmp(req_task->target, req->target)) {
					del = 1;
					MyDBG("[Trget: %s Task Finished. REMOVE it in task list]\n", req_task->target)
					break;
				}
			}
			
			if (del) listnode_delete(task_list, req_task);
			MUTEXUNLOCK(&task_list_lock);
			IN_EXEC = 0;
		}
#endif

	}
	return 0;
}

REQUEST_INFO_T *task_listcreate(REQUEST_INFO_T input)
{
	REQUEST_INFO_T *new=malloc(sizeof(*new));
	
	memcpy(new,&input,sizeof(*new));
	return new;
}

/*
 * is_valid_netool_arg:  Accepts an empty string, or one built only from
 * alphanumerics and ".:-_%" that does not start with '-'.  This rejects
 * anything able to escape NETOOL_RESULT_DIR or to be parsed by /bin/sh
 * as an extra option (the CGI whitelist permits whitespace).
 */
static int is_valid_netool_arg(const char *s)
{
	if (*s == '-')
		return 0;

	/* "." and ".." would resolve to NETOOL_RESULT_DIR itself or its parent */
	if (!strcmp(s, ".") || !strcmp(s, ".."))
		return 0;

	for (; *s; s++) {
		if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		    (*s >= '0' && *s <= '9') || strchr(".:-_%", *s))
			continue;
		return 0;
	}
	return 1;
}

void rcv_socket(int newsockfd)
{
	int    n;
	time_t now;
	char   date[30];
	
	REQUEST_INFO_T req_t;
	
	bzero(&req_t,sizeof(REQUEST_INFO_T));
	
	n = read( newsockfd, &req_t, sizeof(REQUEST_INFO_T));
	if ( n < 0 )
	{
		MyDBG("ERROR reading from socket.\n");
		return;
	}
	
	/* The request arrives over a unix socket: force NUL termination before
	 * the fields are used as C strings. */
	req_t.ver[sizeof(req_t.ver) - 1] = '\0';
	req_t.sort[sizeof(req_t.sort) - 1] = '\0';
	req_t.proto[sizeof(req_t.proto) - 1] = '\0';
	req_t.srchost[sizeof(req_t.srchost) - 1] = '\0';
	req_t.dsthost[sizeof(req_t.dsthost) - 1] = '\0';
	req_t.interface[sizeof(req_t.interface) - 1] = '\0';
	req_t.target[sizeof(req_t.target) - 1] = '\0';
	req_t.tstamp = time(&now);
	StampToDate(req_t.tstamp, date);
	
	if ( req_t.type >= REQ_MODE_TOTAL || req_t.type == REQ_GET_RESULT) {
		MyDBG("ERROR Type. REQ_TYPE:[%d]\n", req_t.type);
		return;
	}
	
	/* Validate before anything hands the request on: a traceroute request is
	 * queued into task_list below and dispatched later without coming back
	 * here. */
	if (!is_valid_netool_arg(req_t.target) ||
	    !is_valid_netool_arg(req_t.sort) ||
	    !is_valid_netool_arg(req_t.proto) ||
	    !is_valid_netool_arg(req_t.srchost) ||
	    !is_valid_netool_arg(req_t.dsthost) ||
	    !is_valid_netool_arg(req_t.interface)) {
		ErrorMsg("Invalid request. Interface:[%s] TARGET:[%s]\n",
			req_t.interface, req_t.target);
		return;
	}
	
	MyDBG("[%s] REQ_TYPE[%d] PING_CNT:[%d] HOPS:[%d] RESPONSE_T:[%d] EXEC_CNT:[%d] \n \
	      \t\t\tVER:[%s] NETST:[0x%x] SORT:[%s] PROTO:[%s] SRC:[%s] DST:[%s] Interface:[%s] TARGET:[%s]\n", 
	      date, req_t.type, req_t.ping_cnt, req_t.hops, req_t.response, req_t.exec_cnt, 
	      req_t.ver, req_t.netst, req_t.sort, req_t.proto, req_t.srchost, req_t.dsthost, req_t.interface, req_t.target);
	
	/* Limit the maximum upper limit */
	if (req_t.type == REQ_PING_MODE) {
		if (req_t.ping_cnt > 10) 
			req_t.ping_cnt = 10;
		if (req_t.exec_cnt > 60)
			req_t.exec_cnt = 60;
	} else if (req_t.type == REQ_PING_NORMAL_MODE) {
		if (req_t.ping_cnt > 100) 
			req_t.ping_cnt = 100;
	}
	
	/* Bound the values handed to ping/traceroute as options.  A negative or
	 * huge wait/hop count used to keep the child running for a very long
	 * time, which blocks this loop on the non-threaded (fork) build. */
	if (req_t.response < 1)
		req_t.response = 1;
	else if (req_t.response > 300)
		req_t.response = 300;
	if (req_t.hops < 1)
		req_t.hops = 1;
	else if (req_t.hops > 255)
		req_t.hops = 255;
	
#ifndef NON_P_THREAD
	
	REQUEST_INFO_T *sreq_t;
	
	if (f_exists(NETOOL_QUEUE) > 0) {
		if ( req_t.type == REQ_TRACEROUTE_MODE ) { /* Only queue traceroute request task */
		
			MUTEXLOCK(&task_list_lock);
			if(task_list) {
				sreq_t=NULL;
				sreq_t=task_listcreate(req_t);
				if(sreq_t)
					listnode_add(task_list,(void*)sreq_t);
			
			}
			MUTEXUNLOCK(&task_list_lock);
		}
	}
#endif 
	start_req_thread((void *)&req_t, req_t.type);
	
}
static int start_local_socket(void)
{
	struct sockaddr_un addr;
	int sockfd, newsockfd;
	
	if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ErrorMsg("socket error\n");
		perror("socket error");
		exit(-1);
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, NETOOL_SOCKET_PATH, sizeof(addr.sun_path)-1);
	
	unlink(NETOOL_SOCKET_PATH);
	
	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		ErrorMsg("socket bind error\n");
		perror("socket bind error");
		exit(-1);
	}
	
	if (listen(sockfd, MAX_SOCKET_CLIENT) == -1) {
		ErrorMsg("listen error\n");
		perror("listen error");
		exit(-1);
	}
	/* Same umask problem: the socket would be created 0777, i.e. connectable
	 * by any local process, and every request is executed as root. httpd is
	 * the only client and runs as root. */
	if (chmod(NETOOL_SOCKET_PATH, 0600) == -1)
		ErrorMsg("chmod %s error\n", NETOOL_SOCKET_PATH);
	
	while (1) {
		if ( (newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			ErrorMsg("accept error\n");
			perror("accept error");
			continue;
		}
		
		rcv_socket(newsockfd);
		close(newsockfd);
	}
}

#ifndef NON_P_THREAD
/* Worker entry for the pthread build. The request lives in the caller's
 * stack frame, which is gone once rcv_socket() returns, so each worker gets
 * its own heap copy and releases it when the job is done. */
static void *req_thread_main(void *arg)
{
	REQUEST_INFO_T *req = arg;

	switch (req->type) {
	case REQ_PING_MODE:
		do_ping(req);
		break;
	case REQ_TRACEROUTE_MODE:
		do_traceroute(req);
		break;
	case REQ_PING_NORMAL_MODE:
		do_ping_normal(req);
		break;
	case REQ_TRACEROUTE_NORMAL_MODE:
		do_traceroute_normal(req);
		break;
	case REQ_NSLOOKUP_MODE:
		do_nslookup(req);
		break;
	case REQ_NETSTAT_MODE:
		do_netstat(req);
		break;
	case REQ_NETSTAT_NAT_MODE:
		do_netstat_nat(req);
		break;
	default:
		break;
	}

	free(req);
	return NULL;
}
#endif

static void start_req_thread(void *rInfo, int type)
{
#ifdef NON_P_THREAD
	
	int status;
	pid_t pid, w;
 
	pid = fork();
	
	if (pid == -1) {
		ErrorMsg("fork error\n");
		exit(EXIT_FAILURE);
	}
	if (pid == 0) {
		MyDBG("[Child Process] PID is %ld\n", (long) getpid());
		if (type == REQ_PING_MODE) {
		
			do_ping(rInfo);
		} else if (type == REQ_TRACEROUTE_MODE) {
			
			do_traceroute(rInfo);
		} else if (type == REQ_PING_NORMAL_MODE) {
		
			do_ping_normal(rInfo);
		} else if (type == REQ_TRACEROUTE_NORMAL_MODE) {
		
			do_traceroute_normal(rInfo);
		} else if (type == REQ_NSLOOKUP_MODE) {
		
			do_nslookup(rInfo);
		} else if (type == REQ_NETSTAT_MODE) {
		
			do_netstat(rInfo);
		} else if (type == REQ_NETSTAT_NAT_MODE) {
		
			do_netstat_nat(rInfo);
		}
		_exit(0);
	} else {
		w = waitpid(pid, &status, WUNTRACED | WCONTINUED);
		if (w == -1) {
			ErrorMsg("waitpid error\n");
			exit(EXIT_FAILURE);
		}
	}
#else
	pthread_t thread;
	pthread_attr_t attr;
	int ret = 0;
	REQUEST_INFO_T *req_copy;
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	//ret = pthread_attr_setstacksize(&attr, 128 * 1024);
	//if (ret != 0) {
	//	ErrorMsg("Error %d %s\n", ret, strerror(errno))
	//	perror("Thread stacksize failed\n");
	//}
	
	if (type < 0 || type >= REQ_MODE_TOTAL || type == REQ_GET_RESULT) {
		pthread_attr_destroy(&attr);
		return;
	}

	req_copy = malloc(sizeof(*req_copy));
	if (req_copy == NULL) {
		ErrorMsg("malloc failed\n");
		pthread_attr_destroy(&attr);
		return;
	}
	memcpy(req_copy, rInfo, sizeof(*req_copy));

	if (type == REQ_TRACEROUTE_MODE)
		IN_EXEC = 1;
	ret = pthread_create(&thread, &attr, req_thread_main, req_copy);
	if (ret != 0) {
		free(req_copy);
		if (type == REQ_TRACEROUTE_MODE)
			IN_EXEC = 0;
	}

	if (ret != 0) {
		ErrorMsg("Error %d %s\n", ret, strerror(errno))
		perror("Thread create failed\n");
	}
	
	pthread_attr_destroy(&attr);
#endif
}

static void local_socket_thread(void)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start unix socket thread.\n");
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread,NULL,(void *)&start_local_socket,NULL);
	pthread_attr_destroy(&attr);
}

#ifndef NON_P_THREAD
static void process_task(void)
{
	REQUEST_INFO_T *req_task;
	struct listnode *ln;
	
	MUTEXLOCK(&task_list_lock);
	LIST_LOOP(task_list,req_task,ln)
	{
		if (!IN_EXEC) {
			start_req_thread((void *)req_task, req_task->type);
			break;
		}
	}
	
	MUTEXUNLOCK(&task_list_lock);
	
}
#endif


static void handlesignal(int signum)
{
	if (signum == SIGUSR1) {
		;
	} else if (signum == SIGUSR2) {
		;
	} else if (signum == SIGTERM) {
		remove("/var/run/netool.pid");
		terminated = 0;
	} else
		MyDBG("Unknown SIGNAL\n");
	
}

static void signal_register(void) {
	
	struct sigaction sa;
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &handlesignal;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);    
}

int netool_main (int argc, char *argv[])
{

	char pid[8];
	
	MyDBG("[Start NetTool]\n");
	
	/* Write pid */
	snprintf(pid, sizeof(pid), "%d", getpid());
	f_write_string("/var/run/netool.pid", pid, 0, 0);
	
	/* rc keeps the inherited umask at 0, so the result directory and the
	 * listening socket would be created world-accessible. Tighten the umask
	 * before creating either of them so there is no window before the
	 * chmod() calls below: a local user could otherwise plant a symlink
	 * named after a target (root would truncate whatever it points to) or
	 * queue a connection on the socket (executed as root). Only root reads
	 * and writes these files, so keep both private. */
	umask(077);

	/* mkdir: private, root-owned, never a planted link */
	if (prepare_result_dir() != 0)
		return -1;
	
	/* Signal */
	signal_register();
	
	/* Init task list info*/
	task_list=list_new();
	
	/* Init mutex lock switch */
	MUTEXINIT(&task_list_lock);
	
	/* start unix socket */
	local_socket_thread();
	
	while(terminated) {
#ifndef NON_P_THREAD
		if (f_exists(NETOOL_QUEUE) > 0) {
			process_task();
		}
#endif
		pause();
	}
	
	/* Free memory */
	MUTEXDESTROY(&task_list_lock);
	
	return 0;
}

