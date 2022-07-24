// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2022 Intel Corporation. All rights reserved.
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>

/*
 * SOF pipeline in userspace.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/poll.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <mqueue.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>
#include <getopt.h>

#include "plugin.h"
#include "common.h"

struct sof_pipe {
	const char *alsa_name;
	char topology_name[NAME_SIZE];
	int realtime;
	int use_P_core;
	int use_E_core;
	int capture;

	mqd_t ipc;

	struct sigaction action;

	/* SHM for stream context sync */
	struct plug_shm_context shm_context;

	/* PCM flow control */
	struct plug_lock ready;
	struct plug_lock done;

	struct plug_mq pcm_ipc;
	struct plug_mq ctl_ipc;

	FILE *log;

	pthread_t ipc_pcm_thread;
	pthread_t ipc_ctl_thread;
};


/* read the CPU ID register data on x86 */
static inline void x86_cpuid(unsigned int *eax, unsigned int *ebx,
                             unsigned int *ecx, unsigned int *edx)
{
        /* data type is passed in on eax (and sometimes ecx) */
        asm volatile("cpuid"
            : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
}

/*
 * Check core type for E cores. If non hybrid then it does not matter.
 */
static inline int use_this_core(struct sof_pipe *sp)
{
	/* CPUID - set eax to 0x1a for hybrid core types */
	unsigned eax = 0x1a, ebx = 0, ecx = 0, edx = 0;
	char core_mask;

	/* get the processor core type we are running on now */
	x86_cpuid(&eax, &ebx, &ecx, &edx);

	/* core type 0x20 is atom, 0x40 is core */
	core_mask = (eax >> 24) & 0xFF;
	switch (core_mask) {
	case 0x20:
		fprintf(sp->log, "found E core\n");
		if (sp->use_E_core)
			return 1;
		return 0;
	case 0x40:
		fprintf(sp->log, "found P core\n");
		if (sp->use_P_core)
			return 1;
		return 0;
	default:
		/* non hybrid arch, just use first core */
		fprintf(sp->log, "found non hybrid core topology\n");
		return 1;
	}
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
		fprintf(stderr, "caught SIGTERM - shutdown\n");
		break;
	default:
		fprintf(stderr, "caught signal %d, something went wrong\n", sig);
		// TODO tear down
		break;
	}

	fflush(stdout);
	fflush(stderr);
}

static int pipe_init_signals(struct sof_pipe *sp)
{
	struct sigaction *action = &sp->action;
	int err;

	/*
	 * signals - currently only check for SIGCHLD
	 */
	sigemptyset(&action->sa_mask);
	sigaddset(&action->sa_mask, SIGTERM);
	action->sa_handler = signal_handler;
	err = sigaction(SIGTERM, action, NULL);
	if (err < 0) {
		fprintf(sp->log, "failed to register signal action: %s",
			strerror(errno));
		return err;
	}

	return 0;
}

/* sof-pipe needs to be sticky to the current core for low latency */
static int pipe_set_affinity(struct sof_pipe *sp)
{

	cpu_set_t cpuset;
	pthread_t thread;
	long core_count = sysconf(_SC_NPROCESSORS_ONLN);
	int i;
	int err;

	/* Set affinity mask to  core */
	thread = pthread_self();
	CPU_ZERO(&cpuset);

	/* find the first E core (usually come after the P cores ?) */
	for (i = core_count - 1; i >= 0; i--) {
		CPU_ZERO(&cpuset);
		CPU_SET(i, &cpuset);

		/* change our core to i */
		err = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
		if (err != 0) {
			fprintf(sp->log, "error: failed to set CPU affinity to core %d: %s\n",
				i, strerror(err));
			return err;
		}

		/* should we use this core ? */
		if (use_this_core(sp))
			break;
	}

	return 0;
}

/* set ipc thread to low priority */
static int pipe_set_ipc_lowpri(struct sof_pipe *sp)
{
	pthread_attr_t attr;
	struct sched_param param;
	int err;

	/* attempt to set thread priority - needs suid */
	fprintf(sp->log, "pipe: set IPC low priority\n");

	err = pthread_attr_init(&attr);
	if (err < 0) {
		fprintf(sp->log, "error: can't create thread attr %d %s\n",
		       err, strerror(errno));
		return err;
	}

	err = pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
	if (err < 0) {
		fprintf(sp->log, "error: can't set thread policy %d %s\n",
		       err, strerror(errno));
		return err;
	}
	param.sched_priority = 0;
	err = pthread_attr_setschedparam(&attr, &param);
	if (err < 0) {
		fprintf(sp->log, "error: can't set thread sched param %d %s\n",
		       err, strerror(errno));
		return err;
	}

	return 0;
}

static void *pipe_ipc_thread(void *arg)
{
	struct sof_pipe *sp = arg;
	ssize_t ipc_size;
	char mailbox[384] = {0};
	int err;

	/* IPC thread should not preempt processing thread */
	err = pipe_set_ipc_lowpri(sp);
	if (err < 0)
		fprintf(stderr, "error: cant set IPC thread to low priority");

	/* open the IPC message queue */
	err = plug_create_ipc_queue(&sp->pcm_ipc);
	if (err < 0) {
		fprintf(sp->log, "error: can't open PCM IPC message queue : %s\n",
				strerror(errno));
		return NULL;
	}

	/* main IPC handling loop */
	printf("waiting for messages\n");
	while (1) {
		ipc_size = mq_receive(sp->ipc, mailbox, 384, NULL);
		if (err < 0) {
			fprintf(sp->log, "error: can't read IPC message queue %s : %s\n",
				sp->pcm_ipc.queue_name, strerror(errno));
			break;
		}

		/* do the message work */
		printf("got IPC %ld bytes from PCM: %s\n", ipc_size, mailbox);

		/* now return message completion status */
		err = mq_send(sp->ipc, mailbox, 384, 0);
		if (err < 0) {
			fprintf(sp->log, "error: can't send IPC message queue %s : %s\n",
				sp->pcm_ipc.queue_name, strerror(errno));
			break;
		}
	}

	fprintf(sp->log, "IPC thread finished !!\n");
	mq_close(sp->ipc);
	return NULL;
}

/* set pipeline to realtime priority */
static int pipe_set_rt(struct sof_pipe *sp)
{
	pthread_attr_t attr;
	struct sched_param param;
	int err;
	uid_t uid = getuid();
	uid_t euid = geteuid();

	/* do we have elevated privileges to attempt RT priority */
	if (uid < 0 || uid != euid) {

		/* attempt to set thread priority - needs suid */
		fprintf(sp->log, "pipe: set RT priority\n");

		err = pthread_attr_init(&attr);
		if (err < 0) {
			fprintf(sp->log, "error: can't create thread attr %d %s\n",
			       err, strerror(errno));
			return err;
		}

		err = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
		if (err < 0) {
			fprintf(sp->log, "error: can't set thread policy %d %s\n",
			       err, strerror(errno));
			return err;
		}
		param.sched_priority = 80;
		err = pthread_attr_setschedparam(&attr, &param);
		if (err < 0) {
			fprintf(sp->log, "error: can't set thread sched param %d %s\n",
			       err, strerror(errno));
			return err;
		}
		err = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
		if (err < 0) {
			fprintf(sp->log, "error: can't set thread inherit %d %s\n",
			       err, strerror(errno));
			return err;
		}
	} else {
		fprintf(sp->log, "error: no elevated privileges for RT. uid %d euid %d\n",
			uid, euid);
	}

	return 0;
}

/*
 * The main processing loop
 */
static int pipe_process_playback(struct sof_pipe *sp)
{
	struct plug_context *ctx = sp->shm_context.addr;
	struct timespec ts;
	ssize_t bytes;

	ts.tv_sec = 0;
	ts.tv_nsec = MS_TO_NS(5);

	printf("pipe waiting\n");
	while (ctx->frames == 0) {nanosleep(&ts, NULL);};
	printf("pipe starting\n");

	ts.tv_nsec = MS_TO_NS(10);
	do {
		/* wait for data */
		sem_wait(sp->ready.sem);
		//fprintf(sp->log, "   recd %ld frames\n", ctx->frames);

		/* now do all the processing and tell plugin we are done */
		nanosleep(&ts, NULL);
		ctx->position += ctx->frames;
		if (ctx->position > ctx->buffer_frames)
			ctx->position -= ctx->buffer_frames;
		sem_post(sp->done.sem);
	} while (1);


	return 0;
}

static int pipe_process_capture(struct sof_pipe *sp)
{
	struct plug_context *ctx = sp->shm_context.addr;
	struct timespec ts;
	ssize_t bytes;

	ts.tv_sec = 0;
	ts.tv_nsec = MS_TO_NS(10);
	fprintf(stdout, "!!!capture\n");
	do {

		/* now do all the processing and tell plugin we are done */
		nanosleep(&ts, NULL);
		ctx->frames = 6000;

		/* tell plugin data is ready */
		sem_post(sp->ready.sem);
		//fprintf(sp->log, "   sent %ld frames\n", ctx->frames);

		/* wait for plugin to consume */
		sem_wait(sp->done.sem);

	} while (1);


	return 0;
}

/*
 * -D ALSA device. e.g. hw:0,1
 * -R realtime (needs parent to set uid)
 * -p Force run on P core
 * -e Force run on E core
 * -c capture
 * -t topology name.
 * -L log file (otherwise stdout)
 * -h help
 */
static void usage(char *name)
{
	fprintf(stdout, "Usage: %s -D ALSA device | -F in/out file"
			" -i ipc_msg", name);
}

int main(int argc, char *argv[], char *env[])
{
	struct sof_pipe sp = {0};
	int option = 0;
	int ret = 0;
	int i;

	sp.log = stdout;

	/* parse all args */
	while ((option = getopt(argc, argv, "hD:Rpect:")) != -1) {

		switch (option) {
		/* Alsa device  */
		case 'D':
			sp.alsa_name = strdup(optarg);
			break;
		case 'R':
			sp.realtime = 1;
			break;
		case 'p':
			sp.use_P_core = 1;
			sp.use_E_core = 0;
			break;
		case 'e':
			sp.use_E_core = 1;
			sp.use_P_core = 0;
			break;
		case 'c':
			sp.capture = 1;
			break;
		case 't':
			snprintf(sp.topology_name, NAME_SIZE, "%s", optarg);
			break;

		/* print usage */
		default:
			fprintf(sp.log, "unknown option %c\n", option);
			__attribute__ ((fallthrough));
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		}
	}

	/* validate cmd line params */
	if (strlen(sp.ready.name) == 0) {
		fprintf(stderr, "error: no data READY lock specified using -r\n");
		exit(EXIT_FAILURE);
	}
	if (strlen(sp.done.name) == 0) {
		fprintf(stderr, "error: no data DONE lock specified using -d\n");
		exit(EXIT_FAILURE);
	}

	/* initialise IPC data */
	ret = plug_ipc_init_queue(&sp.pcm_ipc, sp.topology_name, "pcm");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_queue(&sp.ctl_ipc, sp.topology_name, "ctl");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_shm(&sp.shm_context, sp.topology_name, "pcm");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_lock(&sp.ready, sp.topology_name, "ready");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_lock(&sp.done, sp.topology_name, "done");
	if (ret)
		goto out;

#if 0
	/* turn on logging */
	unlink("log.txt");
	sp.log = fopen("log.txt", "w+");
	if (!sp.log) {
		fprintf(stderr, "failed to open log: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif
	/* make sure we can cleanly shutdown */
	ret = pipe_init_signals(&sp);
	if (ret < 0)
		goto out;

	/* set CPU affinity */
	if (sp.use_E_core || sp.use_P_core) {
		ret = pipe_set_affinity(&sp);
		if (ret < 0)
			goto out;
	}

	/* start IPC thread */
	ret = pthread_create(&sp.ipc_pcm_thread, NULL, &pipe_ipc_thread, &sp);
	if (ret < 0) {
		fprintf(stderr, "failed to create IPC thread: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* set priority if asked */
	if (sp.realtime) {
		ret = pipe_set_rt(&sp);
		if (ret < 0)
			goto out;
	}

	/* mmap context */
	ret = plug_create_mmap_regions(&sp.shm_context);
	if (ret < 0)
		goto out;

	/* open semaphore */
	ret = plug_ipc_create_lock(&sp.ready);
	if (ret < 0)
		goto out;
	ret = plug_ipc_create_lock(&sp.done);
	if (ret < 0)
		goto out;

	/* open ALSA device or IO file */

	/* process */
	if (sp.capture)
		pipe_process_capture(&sp);
	else
		pipe_process_playback(&sp);
out:
	return ret;
}
