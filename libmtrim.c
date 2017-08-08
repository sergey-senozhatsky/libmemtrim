/*
 * Copyright (C) 2017 Sergey Senozhatsky
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdarg.h>
#include <limits.h>

#include "config.h"

#define DEFAULT_PAGE_SIZE	4096

static int global_init_done;
static volatile __thread int __tf_depth;

static __thread long thread_id = -1;

static FILE *log_fd;

static void   (*glibc_free)(void *) 				= free;
#ifdef HAVE_CFREE
static void   (*glibc_cfree)(void *) 				= cfree;
#endif
static int (*glibc_munmap)(void *, size_t) 			= munmap;
static char * (*glibc_getenv)(const char *)			= getenv;

static void __init_mtrim(void);

static int config_timeout = 0;
static int config_keepcost = 0;
static int config_fordblks = 0;
static int config_trimpad = 0;
static int config_debug = 0;

#define TRACING_DISABLE()	__tf_depth++;
#define TRACING_ENABLE()	__tf_depth--;

static unsigned long alloc_min_wmark = 0;
static unsigned long alloc_max_wmark = ULONG_MAX;

static __thread struct timeval last_trim_tv;
static __thread char output_buf[2048];
static __thread int output_offt = 0;

static int __get_pid(void)
{
	if (thread_id < 0)
#ifdef SYS_gettid
		thread_id = syscall(SYS_gettid);
#else
		thread_id = getpid();
#endif
	return thread_id;
}

int output(const char *fmt, ...)
{
	size_t wr;
	va_list ap;

	va_start(ap, fmt);
	wr = vsnprintf(output_buf + output_offt,
			sizeof(output_buf) - output_offt - 1,
			fmt, ap);
	va_end(ap);

	if (wr < 0 || wr > sizeof(output_buf) - output_offt - 1)
		fprintf(stderr, "ERROR: output buffer is too small %s\n",
				output_buf);

	output_offt += wr;
	return wr;
}

int output_pid(void)
{
	return output("[t:%ld]", __get_pid());
}

int output_timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return output("[t:%lu.%06d] ",
			(unsigned long)tv.tv_sec,
			(int)tv.tv_usec);
}

void output_commit(void)
{
	if (log_fd)
		fprintf(log_fd, "%s", output_buf);
	output_offt = 0;
}

static void create_mtrace_file(const char *base_path)
{
	char fname[1024];
	FILE *out;

	snprintf(fname, sizeof(fname) - 1, "%s/mtrim-%s-%lu",
			base_path,
			program_invocation_short_name,
			__get_pid());

	out = fopen(fname, "w");
	if (!out) {
		fprintf(stderr,
			"can't open %s: %s\n",
			fname, strerror(errno));
		exit(1);
	}

	setvbuf(out, (char *)NULL, _IOLBF, 0);
	fcntl(fileno(out), F_SETFD, FD_CLOEXEC);

	log_fd = out;

	fprintf(stderr, "\n\n*** LOG file name: `tailf %s'\n\n", fname);
}

static unsigned long memparse(const char *mem)
{
	char *end;

	unsigned long ret = strtoul(mem, &end, 10);

	switch (*end) {
		case 'G':
		case 'g':
			ret <<= 10;
		case 'M':
		case 'm':
			ret <<= 10;
		case 'K':
		case 'k':
			ret <<= 10;
		default:
			break;
	}

	return ret;
}

static void __init(void)
{
	if (!global_init_done) {
		if (!__tf_depth) {
			TRACING_DISABLE();
			__init_mtrim();
			TRACING_ENABLE();
		}
	}
}

static void __dump_mallinfo(const char *msg, struct mallinfo *mi)
{
/*
 * int arena;     Non-mmapped space allocated (bytes)
 * int ordblks;    Number of free chunks
 * int smblks;     Number of free fastbin blocks
 * int hblks;      Number of mmapped regions
 * int hblkhd;     Space allocated in mmapped regions (bytes)
 * int usmblks;    Maximum total allocated space (bytes)
 * int fsmblks;    Space in freed fastbin blocks (bytes)
 * int uordblks;   Total allocated space (bytes)
 * int fordblks;   Total free space (bytes)
 * int keepcost;   Top-most, releasable space (bytes)
 */
	output_timestamp();
	output_pid();

	output("%s: "
		"arena: %d "
		"ordblks: %d "
		"smblks: %d "
		"hblks: %d "
		"hblkhd: %d "
		"usmblks: %d "
		"fsmblks: %d "
		"uordblks: %d "
		"fordblks: %d "
		"keepcost: %d\n",
		msg,
		mi->arena,
		mi->ordblks,
		mi->smblks,
		mi->hblks,
		mi->hblkhd,
		mi->usmblks,
		mi->fsmblks,
		mi->uordblks,
		mi->fordblks,
		mi->keepcost);

	output_commit();
}

static void dump_mallinfo(struct mallinfo *mia, struct mallinfo *mib)
{
	__dump_mallinfo("Before mtrim()", mia);
	__dump_mallinfo(" After mtrim()", mib);
}

static int enter_tracing_event(void)
{
	volatile int start;

	TRACING_DISABLE();
	start = __tf_depth - 1;
	return start == 0;
}

static int event_return_point(void)
{
	return __tf_depth == 1;
}

static int leave_tracing_event(void)
{
	if (event_return_point()) {
		struct mallinfo pre_mallinfo;
		struct mallinfo post_mallinfo;
		struct timeval trim_tv;
		int trimmed = 0;

		if (gettimeofday(&trim_tv, NULL))
			goto out;

		if (config_timeout &&
			trim_tv.tv_sec - last_trim_tv.tv_sec < config_timeout)
			goto out;

		last_trim_tv = trim_tv;
		pre_mallinfo = mallinfo();

		if (config_keepcost &&
				pre_mallinfo.keepcost > config_keepcost) {
			malloc_trim(config_trimpad);
			trimmed = 1;
			goto out;
		}

		if (config_fordblks &&
				pre_mallinfo.fordblks > config_fordblks) {
			malloc_trim(config_trimpad);
			trimmed = 1;
			goto out;
		}
out:
		if (trimmed && config_debug) {
			post_mallinfo = mallinfo();
			dump_mallinfo(&pre_mallinfo, &post_mallinfo);
		}
	}
	TRACING_ENABLE();
}

/* Free a block allocated by `malloc', `realloc' or `calloc'.  */
void free(void *__ptr)
{
	if (!global_init_done)
		return;

	enter_tracing_event();
	glibc_free(__ptr);
	leave_tracing_event();
}

#ifdef HAVE_CFREE
/* Free a block allocated by `calloc'. */
void cfree(void *__ptr)
{
	if (!global_init_done)
		return;

	enter_tracing_event();
	glibc_cfree(__ptr);
	leave_tracing_event();
}
#endif

/* Deallocate any mapping for the region starting at ADDR and extending LEN
   bytes.  Returns 0 if successful, -1 for errors (and sets errno).  */
int munmap(void *__addr, size_t __len)
{
	int ret;

	if (!global_init_done)
		abort();

	enter_tracing_event();
	ret = glibc_munmap(__addr, __len);
	leave_tracing_event();
	return ret;
}

char *getenv(const char *name)
{
	/* Avoid deadlock
	 *
	 * #0  0x00007f26b209b54c in __lll_lock_wait () from /usr/lib/libpthread.so.0
	 * #1  0x00007f26b2094a2c in pthread_mutex_lock () from /usr/lib/libpthread.so.0
	 * #2  0x000000a12a834d60 in malloc_init_hard ()
	 * #3  0x000000a12a83781e in calloc ()
	 * #4  0x00007f26b1e8865c in ?? () from /usr/lib/libdl.so.2
	 * #5  0x00007f26b1e8804b in dlsym () from /usr/lib/libdl.so.2
	 * #6  0x00007f26b22aa5e2 in __init_mtrim () at libmtrim.c:370
	 * #7  __init () at libmtrim.c:182
	 * #8  getenv (name=0xa12a838ded "MALLOC_OPTIONS") at libmtrim.c:354
	 * #9  0x000000a12a834f76 in malloc_init_hard ()
	 * #10 0x000000a12a836075 in malloc ()
	 * #11 0x00007f26b1bd7716 in (anonymous namespace)::pool::pool (this=0x7f26b1e831e0 <(anonymous namespace)::emergency_pool>) at /home/ss/gcc7/src/gcc-7-20170720/libstdc++-v3/libsupc++/eh_alloc.cc:123
	 * #12 __static_initialization_and_destruction_0 (__priority=65535, __initialize_p=1) at /home/ss/gcc7/src/gcc-7-20170720/libstdc++-v3/libsupc++/eh_alloc.cc:250
	 * #13 _GLOBAL__sub_I_eh_alloc.cc(void) () at /home/ss/gcc7/src/gcc-7-20170720/libstdc++-v3/libsupc++/eh_alloc.cc:326
	 * #14 0x00007f26b24bb37a in call_init.part () from /lib64/ld-linux-x86-64.so.2
	 * #15 0x00007f26b24bb486 in _dl_init () from /lib64/ld-linux-x86-64.so.2
	 * #16 0x00007f26b24accfa in _dl_start_user () from /lib64/ld-linux-x86-64.so.2
	 * #17 0x0000000000000001 in ?? ()
	 * #18 0x00007ffd46277602 in ?? ()
	 * #19 0x0000000000000000 in ?? ()
	 */
	if (strcmp(name, "MALLOC_OPTIONS") == 0)
		return NULL;

	__init();

	if (!global_init_done)
		abort();

	return glibc_getenv(name);
}

/*
 * __attribute__ constructor does not work. read __init() comment.
 */
static void __init_mtrim(void)
{
	if (global_init_done == 1)
		return;

	glibc_free		= dlsym(RTLD_NEXT, "free");
#ifdef HAVE_CFREE
	glibc_cfree		= dlsym(RTLD_NEXT, "cfree");
#endif
	glibc_munmap		= dlsym(RTLD_NEXT, "munmap");
	glibc_getenv            = dlsym(RTLD_NEXT, "getenv");

	global_init_done = 1;
	gettimeofday(&last_trim_tv, NULL);

	create_mtrace_file("/tmp");

	if (getenv("MTRIM_DEBUG"))
		config_debug = 1;

	if (getenv("MTRIM_TIMEOUT")) {
		char *tm = getenv("MTRIM_TIMEOUT");

		config_timeout = atoi(tm);
		output("MTRIM timeout: %d\n", config_timeout);
	}

	if (getenv("MTRIM_KEEPCOST_THRESHOLD")) {
		char *kc = getenv("MTRIM_KEEPCOST_THRESHOLD");

		config_keepcost = memparse(kc);
		output("MTRIM keepcost: %d\n", config_keepcost);
	}

	if (getenv("MTRIM_FREEBLKS_THRESHOLD")) {
		char *fb = getenv("MTRIM_FREEBLKS_THRESHOLD");

		config_fordblks = memparse(fb);
		output("MTRIM freeblks: %d\n", config_fordblks);
	}

	if (getenv("MTRIM_TRIMPAD")) {
		char *tp = getenv("MTRIM_TRIMPAD");

		config_trimpad = memparse(tp);
		output("MTRIM trimpad: %d\n", config_trimpad);
	}

	output_commit();
}
