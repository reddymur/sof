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

static int plug_pcm_start(snd_pcm_ioplug_t * io)
{
	snd_pcm_sof_t *pcm = io->private_data;
	struct sof_ipc_stream stream = {0};
	int err;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	stream.hdr.size = sizeof(stream);
	stream.hdr.cmd = SOF_IPC_GLB_STREAM_MSG | SOF_IPC_STREAM_TRIG_START;
	//stream.comp_id =

	err = plug_ipc_cmd(pcm, &stream, sizeof(stream), &stream, sizeof(stream));
	if (err < 0) {
		SNDERR("error: can't trigger START the PCM\n");
		return err;
	}

	return 0;
}

static int plug_pcm_stop(snd_pcm_ioplug_t * io)
{
	snd_pcm_sof_t *pcm = io->private_data;
	struct sof_ipc_stream stream = {0};
	int err;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	stream.hdr.size = sizeof(stream);
	stream.hdr.cmd = SOF_IPC_GLB_STREAM_MSG | SOF_IPC_STREAM_TRIG_STOP;
	//stream.comp_id =

	err = plug_ipc_cmd(pcm, &stream, sizeof(stream), &stream, sizeof(stream));
	if (err < 0) {
		SNDERR("error: can't trigger STOP the PCM\n");
		return err;
	}
	return 0;
}

static int plug_pcm_drain(snd_pcm_ioplug_t * io)
{
	snd_pcm_sof_t *pcm = io->private_data;
	int err = 0;

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	printf("%s %d\n", __func__, __LINE__);
	return err;
}

/* buffer position up to buffer_size */
static snd_pcm_sframes_t plug_pcm_pointer(snd_pcm_ioplug_t *io)
{
	snd_pcm_sof_t *pcm = io->private_data;
	struct plug_context *ctx = pcm->context_addr;
	snd_pcm_sframes_t ret = 0;
	int err;

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	if (io->state == SND_PCM_STATE_XRUN)
		return -EPIPE;

	if (io->state != SND_PCM_STATE_RUNNING)
		return 0;
#if 0
	if (pcm->underrun)
		ret = -EPIPE;
	else
		ret = snd_pcm_bytes_to_frames(io->pcm, pcm->ptr);

finish:
#endif
	if ((pcm->copies % 10) == 0)
		printf("plugin position %ld copies %d\n", ctx->position, pcm->copies);
	return ctx->position;
}

/* get the delay for the running PCM; optional; since v1.0.1 */
static int plug_pcm_delay(snd_pcm_ioplug_t * io, snd_pcm_sframes_t * delayp)
{
	snd_pcm_sof_t *pcm = io->private_data;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);
	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;
#if 0

	*delayp =
	    snd_pcm_bytes_to_frames(io->pcm,
				    pa_usec_to_bytes(lat, &pcm->ss));

	err = 0;

	if (pcm->underrun && pcm->io.state == SND_PCM_STATE_RUNNING)
		snd_pcm_ioplug_set_state(io, SND_PCM_STATE_XRUN);
#endif
	return err;
}

/* return frames written */
static snd_pcm_sframes_t plug_pcm_write(snd_pcm_ioplug_t *io,
				     const snd_pcm_channel_area_t *areas,
				     snd_pcm_uframes_t offset,
				     snd_pcm_uframes_t size)
{
	snd_pcm_sof_t *pcm = io->private_data;
	struct plug_context *ctx = pcm->context_addr;
	snd_pcm_sframes_t ret = 0;
	ssize_t bytes;
	const char *buf;
	int err;

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	/* calculate the buffer position and size */
	buf = (char *)areas->addr + (areas->first + areas->step * offset) / 8;
	bytes = size * pcm->frame_size;

	/* write audio data to pipe */
	memcpy(pcm->io_addr, buf, bytes);
	ctx->frames = size;
	sem_post(pcm->ready_lock);

	/* wait for sof-pipe reader to consume data or timeout */
	err = clock_gettime(CLOCK_REALTIME, &pcm->wait_timeout);
	if (err == -1) {
		SNDERR("write: cant get time: %s", strerror(errno));
		return -EPIPE;
	}

	timespec_add_ms(&pcm->wait_timeout, 200);

	err = sem_timedwait(pcm->done_lock, &pcm->wait_timeout);
	if (err == -1) {
		SNDERR("write: fatal timeout: %s", strerror(errno));
		kill(pcm->cpid, SIGTERM);
		return -EPIPE;
	}

	pcm->copies++;
	return bytes / pcm->frame_size;
}

/* return frames read */
static snd_pcm_sframes_t plug_pcm_read(snd_pcm_ioplug_t *io,
				    const snd_pcm_channel_area_t *areas,
				    snd_pcm_uframes_t offset,
				    snd_pcm_uframes_t size)
{
	snd_pcm_sof_t *pcm = io->private_data;
	struct plug_context *ctx = pcm->context_addr;
	snd_pcm_sframes_t ret = 0;
	ssize_t bytes;
	char *buf;
	int err;

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	/* calculate the buffer position and size */
	buf = (char *)areas->addr + (areas->first + areas->step * offset) / 8;
	bytes = ctx->frames * pcm->frame_size;

	/* wait for sof-pipe reader to consume data or timeout */
	err = clock_gettime(CLOCK_REALTIME, &pcm->wait_timeout);
	if (err == -1) {
		SNDERR("write: cant get time: %s", strerror(errno));
		return -EPIPE;
	}

	timespec_add_ms(&pcm->wait_timeout, 200);

	/* wait for sof-pipe writer to produce data or timeout */
	err = sem_timedwait(pcm->ready_lock, &pcm->wait_timeout);
	if (err == -1) {
		SNDERR("read: fatal timeout: %s", strerror(errno));
		kill(pcm->cpid, SIGTERM);
		return -EPIPE;
	}

	/* write audio data to pipe */
	memcpy(buf, pcm->io_addr, bytes);

	ctx->position += ctx->frames;
	if (ctx->position > ctx->buffer_frames)
		ctx->position -= ctx->buffer_frames;

	/* data consumed */
	sem_post(pcm->done_lock);

	pcm->copies++;
	return ctx->frames;
}


static int plug_pcm_prepare(snd_pcm_ioplug_t * io)
{
	snd_pcm_sof_t *pcm = io->private_data;
	struct timespec ts;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	// HACK some delay to wiat for child - IPC will do this for us.
	ts.tv_sec = 0;
	ts.tv_nsec = MS_TO_NS(30);
	nanosleep(&ts, NULL);

	return err;
}

static int plug_pcm_hw_params(snd_pcm_ioplug_t * io,
			   snd_pcm_hw_params_t * params)
{
	snd_pcm_sof_t *pcm = io->private_data;
	struct sof_ipc_pcm_params ipc_params = {0};
	struct sof_ipc_pcm_params_reply params_reply = {0};
	struct ipc_comp_dev *pcm_dev;
	struct comp_dev *cd;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);
	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	// hack
	pcm->frame_size = 4;
	pcm->wait_timeout.tv_sec = 2;
	pcm->wait_timeout.tv_nsec = 100000000; /* 1000 ms TODO tune to period size */

	/* set pcm params */
	//ipc_params.comp_id = pcm->pipeline->comp_id;
	ipc_params.params.buffer_fmt = SOF_IPC_BUFFER_INTERLEAVED; // TODO:
	ipc_params.params.rate = io->rate;
	ipc_params.params.channels = io->channels;
	printf("%s %d\n", __func__, __LINE__);
	switch (io->format) {
	case SND_PCM_FORMAT_S16_LE:
		ipc_params.params.frame_fmt = SOF_IPC_FRAME_S16_LE;
		ipc_params.params.sample_container_bytes = 2;
		ipc_params.params.sample_valid_bytes = 2;
		break;
	case SND_PCM_FORMAT_S24_LE:
		ipc_params.params.frame_fmt = SOF_IPC_FRAME_S24_4LE;
		ipc_params.params.sample_container_bytes = 4;
		ipc_params.params.sample_valid_bytes = 3;
		break;
	case SND_PCM_FORMAT_S32_LE:
		ipc_params.params.frame_fmt = SOF_IPC_FRAME_S32_LE;
		ipc_params.params.sample_container_bytes = 4;
		ipc_params.params.sample_valid_bytes = 4;
		break;
	default:
		SNDERR("SOF: Unsupported format %s\n",
			snd_pcm_format_name(io->format));
		return -EINVAL;
	}

	pcm->frame_size =
	    (snd_pcm_format_physical_width(io->format) * io->channels) / 8;

	ipc_params.params.host_period_bytes = io->period_size * pcm->frame_size;

	/* Set pipeline params direction from scheduling component */
	ipc_params.params.direction = io->stream;

	ipc_params.hdr.size = sizeof(ipc_params);
	ipc_params.hdr.cmd = SOF_IPC_GLB_STREAM_MSG | SOF_IPC_STREAM_PCM_PARAMS;

	err = plug_ipc_cmd(pcm, &ipc_params, sizeof(ipc_params),
			   &params_reply, sizeof(params_reply));
	if (err < 0) {
		SNDERR("error: can't set PCM params\n");
		return err;
	}

	return err;
}

static int plug_pcm_sw_params(snd_pcm_ioplug_t *io, snd_pcm_sw_params_t *params)
{
	snd_pcm_sof_t *pcm = io->private_data;
	snd_pcm_uframes_t start_threshold;
	struct plug_context *ctx = pcm->context_addr;
	int err;

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;
#if 0
	/* get the stream start threshold */
	err = snd_pcm_sw_params_get_start_threshold(params, &start_threshold);
	if (err < 0) {
		SNDERR("sw params: failed to get start threshold: %s", strerror(err));
		return err;
	}

	/* this seems to be ignored or overridden by application params */
	if (start_threshold < io->period_size) {

		start_threshold = io->period_size;
		err = snd_pcm_sw_params_set_start_threshold(pcm->io.pcm,
							    params, start_threshold);
		if (err < 0) {
			SNDERR("sw params: failed to set start threshold %d: %s",
				start_threshold, strerror(err));
			return err;
		}
	}

	/* keep running as long as we can */
	err = snd_pcm_sw_params_set_avail_min(pcm->io.pcm, params, 1);
	if (err < 0) {
		SNDERR("sw params: failed to set avail min %d: %s",
			1, strerror(err));
		return err;
	}
#endif
	ctx->buffer_frames = io->buffer_size;
	printf("size %ld\n", ctx->buffer_frames);
	return 0;
}

static int plug_pcm_close(snd_pcm_ioplug_t * io)
{
	snd_pcm_sof_t *pcm = io->private_data;
	int err;

	printf("%s %d\n", __func__, __LINE__);
	assert(pcm);

	err = plug_check_sofpipe_status(pcm);
	if (err)
		return err;

	return 0;
}

static const snd_pcm_ioplug_callback_t sof_playback_callback = {
	.start = plug_pcm_start,
	.stop = plug_pcm_stop,
	.drain = plug_pcm_drain,
	.pointer = plug_pcm_pointer,
	.transfer = plug_pcm_write,
	.delay = plug_pcm_delay,
	.prepare = plug_pcm_prepare,
	.hw_params = plug_pcm_hw_params,
	.sw_params = plug_pcm_sw_params,
	.close = plug_pcm_close,
};


static const snd_pcm_ioplug_callback_t sof_capture_callback = {
	.start = plug_pcm_start,
	.stop = plug_pcm_stop,
	.pointer = plug_pcm_pointer,
	.transfer = plug_pcm_read,
	.delay = plug_pcm_delay,
	.prepare = plug_pcm_prepare,
	.hw_params = plug_pcm_hw_params,
	.close = plug_pcm_close,
};

static const snd_pcm_access_t access_list[] = {
	SND_PCM_ACCESS_RW_INTERLEAVED
};

static const unsigned int formats[] = {
	SND_PCM_FORMAT_S16_LE,
	SND_PCM_FORMAT_FLOAT_LE,
	SND_PCM_FORMAT_S32_LE,
	SND_PCM_FORMAT_S24_LE,
};

/*
 * Set HW constraints for the SOF plugin. This needs to be quite unrestrictive atm
 * as we really need to parse topology before the HW constraints can be narrowed
 * to a range that will work with the specified pipeline.
 * TODO: Align with topology.
 */
static int plug_hw_constraint(snd_pcm_sof_t * pcm)
{
	snd_pcm_ioplug_t *io = &pcm->io;
	int err;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS,
					    ARRAY_SIZE(access_list),
					    access_list);
	if (err < 0) {
		SNDERR("constraints: failed to set access: %s", strerror(err));
		return err;
	}

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT,
					    ARRAY_SIZE(formats), formats);
	if (err < 0) {
		SNDERR("constraints: failed to set format: %s", strerror(err));
		return err;
	}

	err =
	    snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_CHANNELS,
					    1, 8);
	if (err < 0) {
		SNDERR("constraints: failed to set channels: %s", strerror(err));
		return err;
	}

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_RATE,
					      1, 192000);
	if (err < 0) {
		SNDERR("constraints: failed to set rate: %s", strerror(err));
		return err;
	}

	err =
	    snd_pcm_ioplug_set_param_minmax(io,
					    SND_PCM_IOPLUG_HW_BUFFER_BYTES,
					    1, 4 * 1024 * 1024);
	if (err < 0) {
		SNDERR("constraints: failed to set buffer bytes: %s", strerror(err));
		return err;
	}

	err =
	    snd_pcm_ioplug_set_param_minmax(io,
					    SND_PCM_IOPLUG_HW_PERIOD_BYTES,
					    128, 2 * 1024 * 1024);
	if (err < 0) {
		SNDERR("constraints: failed to set period bytes: %s", strerror(err));
		return err;
	}

	err =
	    snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS,
					   1, 4);
	if (err < 0) {
		SNDERR("constraints: failed to set period count: %s", strerror(err));
		return err;
	}

	return 0;
}

/*
 * Register the plugin with ALSA and make available for use.
 * TODO: setup all audio params
 * TODO: setup polling fd for RW or mmap IOs
 */
static int plug_create(snd_pcm_sof_t *pcm, snd_pcm_t **pcmp, const char *name,
		       snd_pcm_stream_t stream, int mode)
{
	int err;

	pcm->io.version = SND_PCM_IOPLUG_VERSION;
	pcm->io.name = "ALSA <-> SOF PCM I/O Plugin";
	//pcm->io.poll_fd = pcm->ctx->main_fd;
	pcm->io.poll_events = POLLIN;
	pcm->io.mmap_rw = 0;

	if (stream == SND_PCM_STREAM_PLAYBACK) {
		pcm->io.callback = &sof_playback_callback;
	} else {
		pcm->io.callback = &sof_capture_callback;
	}
	pcm->io.private_data = pcm;

	/* create the plugin */
	err = snd_pcm_ioplug_create(&pcm->io, name, stream, mode);
	if (err < 0) {
		SNDERR("failed to register plugin %s: %s\n", name, strerror(err));
		return err;
	}

	/* set the HW constrainst */
	err = plug_hw_constraint(pcm);
	if (err < 0) {
		snd_pcm_ioplug_delete(&pcm->io);
		return err;
	}

	*pcmp = pcm->io.pcm;
	return 0;
}
/*
 * Parse the ALSA conf for the SOF plugin and construct the command line options
 * to be passed into the SOF pipe executable.
 * TODO: verify all args
 * TODO: validate all arge.
 * TODO: contruct sof pipe cmd line.
 */
static int plug_parse_conf(snd_pcm_sof_t *pcm, snd_pcm_t **pcmp,
			  const char *name, snd_config_t *root,
			  snd_config_t *conf, snd_pcm_stream_t stream, int mode)
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
	 * i.e. aplay -Dsof:file,pcm
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
	pcm->tplg.tplg_file = strdup(tplg_file);
	pcm->tplg.pipeline_id = tplg_pcm;

	printf("%s topology file %s pcm %ld\n", __func__, tplg_file, tplg_pcm);
	pcm->device = strdup(tplg_file);
	if (!pcm->device) {
		return -ENOMEM;
	}

	return 0;
}

/* complete any init for the parent */
int plug_parent_complete_init(snd_pcm_sof_t *pcm, snd_pcm_t **pcmp,
		  	  	     const char *name, snd_pcm_stream_t stream, int mode)
{
	int err;

	/* load the topology TDOD: add pipleijn ID*/
	err = plug_parse_topology(pcm);
	if (err < 0) {
		SNDERR("failed to parse topology: %s", strerror(err));
		return err;
	}

	/* now register the plugin */
	err = plug_create(pcm, pcmp, name, stream, mode);
	if (err < 0) {
		SNDERR("failed to create plugin: %s", strerror(err));
	}

	return err;
}

/*
 * ALSA PCM plugin entry point.
 */
SND_PCM_PLUGIN_DEFINE_FUNC(sof)
{
	snd_pcm_sof_t *pcm;

	int err;

	/* create context */
	pcm = calloc(1, sizeof(*pcm));
	if (!pcm)
		return -ENOMEM;
	pcm->newargv[pcm->argc++] = pipe_name;

	if (stream == SND_PCM_STREAM_CAPTURE)
		pcm->capture = 1;

	/* parse the ALSA configuration file for sof plugin */
	err = plug_parse_conf(pcm, pcmp, name, root, conf, stream, mode);
	if (err < 0) {
		SNDERR("failed to parse config: %s", strerror(err));
		goto pipe_error;
	}

	/* create pipe for audio data - TODO support mmap() */
	err = plug_create_locks(pcm);
	if (err < 0)
		goto pipe_error;

	/* create message queue for IPC */
	err = plug_create_ipc_queue(pcm);
	if (err < 0)
		goto ipc_error;

	/* register interest in signals from child */
	err = plug_init_signals(pcm);
	if (err < 0)
		goto signal_error;

	/* create a SHM mapping for low latency stream position */
	err = plug_create_mmap_regions(pcm);
	if (err < 0)
		goto signal_error;

	/* the pipeline runs in its own process context */
	pcm->cpid = fork();
	if (pcm->cpid < 0) {
		SNDERR("failed to fork for new pipeline: %s", strerror(errno));
		goto fork_error;
	}

	/* init flow diverges now depending if we are child or parent */
	if (pcm->cpid == 0) {

		/* in child */
		plug_child_complete_init(pcm);

	} else {

		/* in parent */
		err = plug_parent_complete_init(pcm, pcmp, name, stream, mode);
		if (err < 0) {
			SNDERR("failed to complete plugin init: %s", strerror(err));
			_exit(EXIT_FAILURE);
		}
	}

	/* everything is good */
	return 0;

	/* error cleanup */
fork_error:
	munmap(pcm->context_addr, pcm->context_size);
	shm_unlink(pcm->context_name);
	munmap(pcm->io_addr, pcm->io_size);
	shm_unlink(pcm->io_name);
signal_error:
	mq_unlink(pcm->ipc_queue_name);
ipc_error:

pipe_error:
	free(pcm->device);
dev_error:
	free(pcm);
	return err;
}

SND_PCM_PLUGIN_SYMBOL(sof);
