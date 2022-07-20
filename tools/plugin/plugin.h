// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2022 Intel Corporation. All rights reserved.
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>

#ifndef __SOF_PLUGIN_PLUGIN_H__
#define __SOF_PLUGIN_PLUGIN_H__

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

#include <alsa/asoundlib.h>

#include "common.h"

typedef struct snd_sof_plug {

	/* audio data */
	pid_t cpid;

	/* IPC message queue */
	mqd_t ipc;
	struct mq_attr ipc_attr;
	const char *ipc_queue_name;

	struct sigaction action;

	/* sof-pipe arguments */
	int argc;
	char *newargv[16];
	char *newenviron[16];

	/* SHM for stream context sync */
	int context_fd;
	int context_size;
	char *context_name;
	void *context_addr;

	/* conf data */
	char *device;

	struct pipeline *pipeline;

	struct tplg_context tplg;

	const char *alsa_device;
	long tplg_pcm;
	long alsa_card;
	long alsa_pcm;

	void *module_prv;	/* module private data */
} snd_sof_plug_t;


int sofplug_load_hook(snd_config_t *root, snd_config_t *config,
		      snd_config_t **dst, snd_config_t *private_data);

int plug_parse_topology(snd_sof_plug_t *pcm);

int plug_ipc_cmd(snd_sof_plug_t *pcm, void *msg, size_t len, void *reply, size_t rlen);

int plug_load_widget(snd_sof_plug_t *pcm);

int plug_register_graph(snd_sof_plug_t *pcm, struct comp_info *temp_comp_list,
			char *pipeline_string, FILE *file,
			int count, int num_comps, int pipeline_id);

int plug_parent_complete_init(snd_sof_plug_t *pcm, snd_pcm_t **pcmp,
		  	  	     const char *name, snd_pcm_stream_t stream, int mode);

void plug_child_complete_init(snd_sof_plug_t *pcm, int capture);

int plug_create_mmap_regions(snd_sof_plug_t *pcm);

int plug_create_pcm_ipc_queue(snd_sof_plug_t *pcm);

int plug_open_ipc_queue(snd_sof_plug_t *plug);

int plug_create_locks(snd_sof_plug_t *pcm);

void plug_add_pipe_arg(snd_sof_plug_t *pcm, const char *option, const char *arg);

int plug_ipc_cmd(snd_sof_plug_t *pcm, void *msg, size_t len, void *reply, size_t rlen);

int plug_check_sofpipe_status(snd_sof_plug_t *pcm);

int plug_init_signals(snd_sof_plug_t *pcm);

void timespec_add_ms(struct timespec *ts, unsigned long ms);

int plug_parse_conf(snd_sof_plug_t *plug, const char *name, snd_config_t *root,
		    snd_config_t *conf);

#endif

