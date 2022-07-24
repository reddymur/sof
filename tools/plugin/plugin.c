/*-*- linux-c -*-*/

/*
 * ALSA <-> SOF PCM I/O plugin
 *
 * Copyright (c) 2022 by Liam Girdwood <liam.r.girdwood@intel.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

#include <sof/sof.h>
#include <sof/audio/pipeline.h>
#include <sof/audio/component.h>
#include <ipc/stream.h>
#include <tplg_parser/topology.h>

#include "plugin.h"

/* child state */
static int child_running;

static char *pipe_name = "/home/lrg/work/sof/sof/build_plugin/sof-pipe";

void timespec_add_ms(struct timespec *ts, unsigned long ms)
{
	long ns;
	long secs = ms / 1000;

	/* get ms remainder */
	ms = ms - (secs * 1000);
	ns = ms * 1000000;

	ts->tv_nsec += ns;
	if (ts->tv_nsec > 1000000000) {
		secs ++;
		ts->tv_nsec -= 1000000000;
	}
	ts->tv_sec += secs;
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGCHLD:
		SNDERR("caught SIGCHLD, sof-pipe has died\n");
		child_running = 0;
		break;
	default:
		SNDERR("caught signal %d, something went wrong\n", sig);
		// TODO tear down
		break;
	}
}

int plug_init_signals(snd_sof_plug_t *pcm)
{
	struct sigaction *action = &pcm->action;
	int err;

	/*
	 * signals - currently only check for SIGCHLD
	 */
	sigemptyset(&action->sa_mask);
	sigaddset(&action->sa_mask, SIGCHLD);
	action->sa_handler = signal_handler;
	err = sigaction(SIGCHLD, action, NULL);
	if (err < 0) {
		SNDERR("failed to register signal action: %s", strerror(errno));
		return err;
	}

	return 0;
}


int plug_check_sofpipe_status(snd_sof_plug_t *pcm)
{
	pid_t w;
	int wstatus;

	/* first check for signals */
	if (child_running)
		return 0;

	/* not running - next check that sof-pipe has completed */
	w = waitpid(pcm->cpid, &wstatus, WNOHANG | WUNTRACED | WCONTINUED);
	if (w == -1) {
		SNDERR("SOF: failed to wait for child pid: %s\n", strerror(errno));
		return -errno;
	} else if (w == 0)
		return 0;	/* child sof-pipe still running */

	/* now check state */
	if (WIFEXITED(wstatus)) {
		printf("exited, status=%d\n", WEXITSTATUS(wstatus));
	} else if (WIFSIGNALED(wstatus)) {
		printf("killed by signal %d\n", WTERMSIG(wstatus));
	} else if (WIFSTOPPED(wstatus)) {
		printf("stopped by signal %d\n", WSTOPSIG(wstatus));
	} else if (WIFCONTINUED(wstatus)) {
		printf("continued\n");
	}

	return -EPIPE;
}

int plug_ipc_cmd(struct plug_mq *ipc, void *msg, size_t len, void *reply, size_t rlen)
{
	struct timespec ts;
	ssize_t ipc_size;
	char mailbox[IPC3_MAX_MSG_SIZE];
	int err;

	if (len > IPC3_MAX_MSG_SIZE) {
		SNDERR("ipc: message too big %d\n", len);
		return -EINVAL;
	}
	memset(mailbox, 0, IPC3_MAX_MSG_SIZE);
	memcpy(mailbox, msg, len);

	/* wait for sof-pipe reader to consume data or timeout */
	err = clock_gettime(CLOCK_REALTIME, &ts);
	if (err == -1) {
		SNDERR("ipc: cant get time: %s", strerror(errno));
		return -errno;
	}

	/* IPCs should be read under 10ms */
	timespec_add_ms(&ts, 10);

	/* now return message completion status */
	err = mq_timedsend(ipc->mq, mailbox, IPC3_MAX_MSG_SIZE, 0, &ts);
	if (err < 0) {
		SNDERR("error: can't send IPC message queue %s : %s\n",
			ipc->queue_name, strerror(errno));
		return -errno;
	}

	/* wait for sof-pipe reader to consume data or timeout */
	err = clock_gettime(CLOCK_REALTIME, &ts);
	if (err == -1) {
		SNDERR("ipc: cant get time: %s", strerror(errno));
		return -errno;
	}

	/* IPCs should be processed under 20ms */
	timespec_add_ms(&ts, 20);

	ipc_size = mq_timedreceive(ipc->mq, mailbox, IPC3_MAX_MSG_SIZE, NULL, &ts);
	if (ipc_size < 0) {
		SNDERR("error: can't read IPC message queue %s : %s\n",
			ipc->queue_name, strerror(errno));
		return -errno;
	}

	/* do the message work */
	printf("cmd got IPC %ld reply bytes\n", ipc_size);
	if (rlen && reply)
		memcpy(reply, mailbox, rlen);

	return 0;
}

void plug_add_pipe_arg(snd_sof_plug_t *pcm, const char *option, const char *arg)
{
	char next_arg[128];

	snprintf(next_arg, sizeof(next_arg), "-%s", option);
	pcm->newargv[pcm->argc++] = strdup(next_arg);

	if (arg) {
		snprintf(next_arg, sizeof(next_arg), "%s", arg);
		pcm->newargv[pcm->argc++] = strdup(next_arg);
	}
}

static const char *suffix_name(const char *longname)
{
	size_t len = strlen(longname);
	int i = len;

	/* longname name invalid */
	if (len < 1 ) {
		SNDERR("invalid topology long name\n");
		return NULL;
	}

	/* find the last '/' in the longname topology path */
	while (--i >= 0) {
		if (longname[i] == '/') {
			i += 1; /* skip / */
			return &longname[i];
		}
	}

	/* no / in topology path, so use full path */
	return longname;
}

int plug_ipc_init_queue(struct plug_mq *ipc, const char *tplg, const char *type)
{
	const char *name = suffix_name(tplg);

	if (!name)
		return -EINVAL;

	snprintf(ipc->queue_name, NAME_SIZE, "/mq-%s-%s", type, name);
	return 0;
}

/*
 * IPC uses message queues for Tx/Rx mailbox and doorbell.
 * TODO: do we need non blocking MQ mode ?
 */
int plug_create_ipc_queue(struct plug_mq *ipc)
{
	int err;

	ipc->attr.mq_msgsize = IPC3_MAX_MSG_SIZE;
	ipc->attr.mq_maxmsg = 4;

	/* delete any stale message queues */
	mq_unlink(ipc->queue_name);

	/* now open new queue for Tx and Rx */
	ipc->mq = mq_open(ipc->queue_name, O_CREAT | O_RDWR | O_EXCL,
			S_IRWXU | S_IRWXG, &ipc->attr);
	if (ipc->mq < 0) {
		SNDERR("failed to create IPC queue %s: %s",
				ipc->queue_name, strerror(errno));
		return -errno;
	}

	return 0;
}

int plug_open_ipc_queue(struct plug_mq *ipc)
{
	int err;

	/* now open new queue for Tx and Rx */
	err = mq_open(ipc->queue_name,  O_RDWR | O_EXCL);
	if (err < 0) {
		SNDERR("failed to create IPC queue %s: %s\n",
			ipc->queue_name, strerror(errno));
		return -errno;
	}

	return 0;
}

int plug_ipc_init_lock(struct plug_lock *lock, const char *tplg, const char *type)
{
	const char *name = suffix_name(tplg);

	if (!name)
		return -EINVAL;

	snprintf(lock->name, NAME_SIZE, "/lock-%s-%s", name, type);
	return 0;
}

int plug_ipc_open_lock(struct plug_lock *lock)
{
	lock->sem = sem_open(lock->name, O_RDWR);
	if (lock->sem == SEM_FAILED) {
		SNDERR("failed to open semaphore %s: %s\n",
				lock->name, strerror(errno));
		return -errno;
	}

	return 0;
}

/*
 * Pipe is used to transfer audio data in R/W mode (not mmap)
 */
int plug_ipc_create_lock(struct plug_lock *lock)
{
	/* RW blocking lock */
	sem_unlink(lock->name);
	lock->sem = sem_open(lock->name,
				O_CREAT | O_RDWR | O_EXCL,
				SEM_PERMS, 1);
	if (lock->sem == SEM_FAILED) {
		SNDERR("failed to create semaphore %s: %s",
			lock->name, strerror(errno));
		return -errno;
	}

	return 0;
}

int plug_ipc_init_shm(struct plug_shm_context *shm, const char *tplg, const char *type)
{
	const char *name = suffix_name(tplg);

	if (!name)
		return -EINVAL;

	snprintf(shm->name, NAME_SIZE, "/shm-%s-%s", name, type);
	shm->size = SHM_SIZE;
	return 0;
}

/*
 * IPC uses message queues for Tx/Rx mailbox and doorbell.
 * TODO: set shm name
 */
int plug_create_mmap_regions(struct plug_shm_context *shm)
{
	void *addr;
	int err;

	/* make sure we have a clean sham */
	shm_unlink(shm->name);

	/* open SHM to be used for low latency position */
	shm->fd = shm_open(shm->name,
				    O_RDWR | O_CREAT,
				    S_IRWXU | S_IRWXG);
	if (shm->fd < 0) {
		SNDERR("failed to create SHM position %s: %s",
				shm->name, strerror(errno));
		return -errno;
	}

	/* set SHM size */
	err = ftruncate(shm->fd, shm->size);
	if (err < 0) {
		SNDERR("failed to truncate SHM position %s: %s",
				shm->name, strerror(errno));
		shm_unlink(shm->name);
		return -errno;
	}

	/* map it locally for context readback */
	shm->addr = mmap(NULL, shm->size,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED, shm->fd, 0);
	if (shm->addr == NULL) {
		SNDERR("failed to mmap SHM position%s: %s",
				shm->name, strerror(errno));
		shm_unlink(shm->name);
		return -errno;
	}

	return 0;
}

int plug_open_mmap_regions(struct plug_shm_context *shm)
{
	void *addr;
	int err;

	/* open SHM to be used for low latency position */
	shm->fd = shm_open(shm->name,
				    O_RDWR,
				    S_IRWXU | S_IRWXG);
	if (shm->fd < 0) {
		SNDERR("failed to open SHM position %s: %s\n",
			shm->name, strerror(errno));
		return -errno;
	}

	/* map it locally for context readback */
	shm->addr = mmap(NULL, shm->size,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED, shm->fd, 0);
	if (shm->addr == NULL) {
		SNDERR("failed to mmap SHM position%s: %s\n",
			shm->name, strerror(errno));
		return -errno;
	}

	return 0;
}

/* complete any init for the child - does not return */
void plug_child_complete_init(snd_sof_plug_t *pcm, int capture)
{
	char pipe_str[16];
	int err;
	int i;

	if (capture)
		plug_add_pipe_arg(pcm, "c", NULL);

	child_running = 1;

	/* set user/grp IDs */

	/* start sof-pipe  - does not return on success */
	printf("executing %s ", pipe_name);
	for (i = 0; i < pcm->argc; i++)
		printf("%s ", pcm->newargv[i]);
	printf("\n");
	err = execv(pipe_name, pcm->newargv);
	if (err < 0)
		SNDERR("failed to run sof-pipe: %s", strerror(errno));

	_exit(EXIT_FAILURE);
}

/*
 * Parse the ALSA conf for the SOF plugin and construct the command line options
 * to be passed into the SOF pipe executable.
 * TODO: verify all args
 * TODO: validate all arge.
 * TODO: contruct sof pipe cmd line.
 */
int plug_parse_conf(snd_sof_plug_t *plug, const char *name, snd_config_t *root,
		    snd_config_t *conf)
{
	snd_config_iterator_t i, next;
	const char *tplg_file = NULL;
	const char *alsa_device = NULL;
	long tplg_pcm = 0;
	long alsa_card = 0;
	long alsa_pcm = 0;
	int err;

	/*
	 * The topology filename and topology PCM need to be passed in.
	 * i.e. aplay -Dsof:file,plug
	 */
	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id;
		if (snd_config_get_id(n, &id) < 0)
			continue;

		/* dont care */
		if (strcmp(id, "comment") == 0 || strcmp(id, "type") == 0
		    || strcmp(id, "hint") == 0)
			continue;

		/* topology file name */
		if (strcmp(id, "tplg_file") == 0) {
			if (snd_config_get_string(n, &tplg_file) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			} else if (!*tplg_file) {
				tplg_file = NULL;
			}
			continue;
		}

		/* PCM ID in the topology file */
		if (strcmp(id, "tplg_pcm") == 0) {
			if (snd_config_get_integer(n, &tplg_pcm) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			continue;
		}

		/* not fatal - carry on and verify later */
		SNDERR("Unknown field %s", id);
	}

	/* verify mandatory inputs are specified */
	if (!tplg_file) {
		SNDERR("Missing topology file");
		return -EINVAL;
	}
	plug->tplg.tplg_file = strdup(tplg_file);
	plug->tplg.pipeline_id = tplg_pcm;

	printf("%s topology file %s plug %ld\n", __func__, tplg_file, tplg_pcm);
	plug->device = strdup(tplg_file);
	if (!plug->device) {
		return -ENOMEM;
	}

	return 0;
}
