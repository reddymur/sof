// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2022 Intel Corporation. All rights reserved.
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>

#ifndef __SOF_PLUGIN_COMMON_H__
#define __SOF_PLUGIN_COMMON_H__

#include <mqueue.h>
#include <alsa/asoundlib.h>

#define IPC3_MAX_MSG_SIZE	384
#define NAME_SIZE	128

#define MAX_CTLS	256

#define MS_TO_US(_msus)	(_msus * 1000)
#define MS_TO_NS(_msns) (MS_TO_US(_msns * 1000))

#define MS_TO_US(_msus)	(_msus * 1000)
#define MS_TO_NS(_msns) (MS_TO_US(_msns * 1000))

#define SEM_PERMS (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

#define SHM_SIZE	(4096 * 16)	/* get from topology */

enum plugin_state {
	SOF_PLUGIN_STATE_INIT	= 0,
	SOF_PLUGIN_STATE_READY	= 1,
};

struct plug_context {
	enum plugin_state state;
	snd_pcm_sframes_t frames;	/* number of frames copied */
	snd_pcm_sframes_t position;	/* current position in buffer */
	snd_pcm_uframes_t buffer_frames;		/* buffer size */
};

struct plug_shm_context {
	/* SHM for stream context sync */
	int fd;
	int size;
	char name[NAME_SIZE];
	void *addr;
};

struct plug_mq {
	/* IPC message queue */
	mqd_t mq;
	struct mq_attr attr;
	char queue_name[NAME_SIZE];
};

struct plug_lock {
	char name[NAME_SIZE];
	sem_t *sem;
};

#endif
