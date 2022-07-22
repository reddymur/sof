// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2022 Intel Corporation. All rights reserved.
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>

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

static char *pipe_name = "/home/lrg/work/sof/sof/build_plugin/sof-pipe";

typedef struct snd_sof_pcm {
	snd_pcm_ioplug_t io;
	size_t frame_size;
	snd_pcm_sframes_t position;
	struct timespec wait_timeout;
	int capture;
	int copies;
	/* audio IO blocking flow control */
	sem_t *ready_lock;
	char *ready_lock_name;
	sem_t *done_lock;
	char *done_lock_name;

	/* SHM for audio IO */
	int io_fd;
	int io_size;
	char *io_name;
	void *io_addr;

	struct plug_mq ipc;

} snd_sof_pcm_t;

static int plug_pcm_start(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct sof_ipc_stream stream = {0};
	int err;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(plug);
	if (err)
		return err;

	stream.hdr.size = sizeof(stream);
	stream.hdr.cmd = SOF_IPC_GLB_STREAM_MSG | SOF_IPC_STREAM_TRIG_START;
	//stream.comp_id =

	err = plug_ipc_cmd(&pcm->ipc, &stream, sizeof(stream), &stream, sizeof(stream));
	if (err < 0) {
		SNDERR("error: can't trigger START the PCM\n");
		return err;
	}

	return 0;
}

static int plug_pcm_stop(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct sof_ipc_stream stream = {0};
	int err;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(plug);
	if (err)
		return err;

	stream.hdr.size = sizeof(stream);
	stream.hdr.cmd = SOF_IPC_GLB_STREAM_MSG | SOF_IPC_STREAM_TRIG_STOP;
	//stream.comp_id =

	err = plug_ipc_cmd(&pcm->ipc, &stream, sizeof(stream), &stream, sizeof(stream));
	if (err < 0) {
		SNDERR("error: can't trigger STOP the PCM\n");
		return err;
	}
	return 0;
}

static int plug_pcm_drain(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	int err = 0;

	err = plug_check_sofpipe_status(plug);
	if (err)
		return err;

	printf("%s %d\n", __func__, __LINE__);
	return err;
}

/* buffer position up to buffer_size */
static snd_pcm_sframes_t plug_pcm_pointer(snd_pcm_ioplug_t *io)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct plug_context *ctx = plug->shm_context.addr;
	snd_pcm_sframes_t ret = 0;
	int err;

	err = plug_check_sofpipe_status(plug);
	if (err)
		return err;

	if (io->state == SND_PCM_STATE_XRUN)
		return -EPIPE;

	if (io->state != SND_PCM_STATE_RUNNING)
		return 0;
#if 0
	if (plug->underrun)
		ret = -EPIPE;
	else
		ret = snd_pcm_bytes_to_frames(io->pcm, plug->ptr);

finish:
#endif
	if ((pcm->copies % 10) == 0)
		printf("plugin position %ld copies %d\n",
				ctx->position, pcm->copies);
	return ctx->position;
}

/* get the delay for the running PCM; optional; since v1.0.1 */
static int plug_pcm_delay(snd_pcm_ioplug_t * io, snd_pcm_sframes_t * delayp)
{
	snd_sof_plug_t *plug = io->private_data;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);
	err = plug_check_sofpipe_status(plug);
	if (err)
		return err;
#if 0

	*delayp =
	    snd_pcm_bytes_to_frames(io->pcm,
				    read_delay_from_shm_context(plug));

	err = 0;

	if (plug->underrun && plug->io.state == SND_PCM_STATE_RUNNING)
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
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct plug_context *ctx = plug->shm_context.addr;
	snd_pcm_sframes_t ret = 0;
	ssize_t bytes;
	const char *buf;
	int err;

	err = plug_check_sofpipe_status(plug);
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
		kill(plug->cpid, SIGTERM);
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
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct plug_context *ctx = plug->shm_context.addr;
	snd_pcm_sframes_t ret = 0;
	ssize_t bytes;
	char *buf;
	int err;

	err = plug_check_sofpipe_status(plug);
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
		kill(plug->cpid, SIGTERM);
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
	snd_sof_plug_t *plug = io->private_data;
	struct timespec ts;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(plug);
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
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct sof_ipc_pcm_params ipc_params = {0};
	struct sof_ipc_pcm_params_reply params_reply = {0};
	struct ipc_comp_dev *pcm_dev;
	struct comp_dev *cd;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);
	err = plug_check_sofpipe_status(plug);
	if (err)
		return err;

	// hack
	pcm->frame_size = 4;
	pcm->wait_timeout.tv_sec = 2;
	pcm->wait_timeout.tv_nsec = 100000000; /* 1000 ms TODO tune to period size */

	/* set plug params */
	//ipc_params.comp_id = plug->pipeline->comp_id;
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

	err = plug_ipc_cmd(&pcm->ipc, &ipc_params, sizeof(ipc_params),
			   &params_reply, sizeof(params_reply));
	if (err < 0) {
		SNDERR("error: can't set PCM params\n");
		return err;
	}

	return err;
}

static int plug_pcm_sw_params(snd_pcm_ioplug_t *io, snd_pcm_sw_params_t *params)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	snd_pcm_uframes_t start_threshold;
	struct plug_context *ctx = plug->shm_context.addr;
	int err;

	err = plug_check_sofpipe_status(plug);
	if (err)
		return err;

	/* get the stream start threshold */
	err = snd_pcm_sw_params_get_start_threshold(params, &start_threshold);
	if (err < 0) {
		SNDERR("sw params: failed to get start threshold: %s", strerror(err));
		return err;
	}

	/* TODO: this seems to be ignored or overridden by application params ??? */
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

	ctx->buffer_frames = io->buffer_size;
	printf("size %ld\n", ctx->buffer_frames);
	return 0;
}

static int plug_pcm_close(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	int err;

	printf("%s %d\n", __func__, __LINE__);
	assert(plug);

	err = plug_check_sofpipe_status(plug);
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
static int plug_hw_constraint(snd_sof_plug_t * plug)
{
	snd_sof_pcm_t *pcm = plug->module_prv;
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
static int plug_create(snd_sof_plug_t *plug, snd_pcm_t **pcmp, const char *name,
		       snd_pcm_stream_t stream, int mode)
{
	snd_sof_pcm_t *pcm = plug->module_prv;
	int err;

	pcm->io.version = SND_PCM_IOPLUG_VERSION;
	pcm->io.name = "ALSA <-> SOF PCM I/O Plugin";
	//plug->io.poll_fd = plug->ctx->main_fd;
	pcm->io.poll_events = POLLIN;
	pcm->io.mmap_rw = 0;

	if (stream == SND_PCM_STREAM_PLAYBACK) {
		pcm->io.callback = &sof_playback_callback;
	} else {
		pcm->io.callback = &sof_capture_callback;
	}
	pcm->io.private_data = plug;

	/* create the plugin */
	err = snd_pcm_ioplug_create(&pcm->io, name, stream, mode);
	if (err < 0) {
		SNDERR("failed to register plugin %s: %s\n", name, strerror(err));
		return err;
	}

	/* set the HW constrainst */
	err = plug_hw_constraint(plug);
	if (err < 0) {
		snd_pcm_ioplug_delete(&pcm->io);
		return err;
	}

	*pcmp = pcm->io.pcm;
	return 0;
}

/*
 * Pipe is used to transfer audio data in R/W mode (not mmap)
 */
int plug_create_locks(snd_sof_plug_t *plug)
{
	snd_sof_pcm_t *pcm = plug->module_prv;

	pcm->ready_lock_name = "/sofplugready";
	pcm->done_lock_name = "/sofplugdone";

	/* RW blocking lock */
	sem_unlink(pcm->ready_lock_name);
	pcm->ready_lock = sem_open(pcm->ready_lock_name,
				O_CREAT | O_RDWR | O_EXCL,
				SEM_PERMS, 1);
	if (pcm->ready_lock == SEM_FAILED) {
		SNDERR("failed to create semaphore %s: %s",
			pcm->ready_lock_name, strerror(errno));
		return -errno;
	}

	/* RW blocking lock */
	sem_unlink(pcm->done_lock_name);
	pcm->done_lock = sem_open(pcm->done_lock_name,
				O_CREAT | O_RDWR | O_EXCL,
				SEM_PERMS, 0);
	if (pcm->done_lock == SEM_FAILED) {
		SNDERR("failed to create semaphore %s: %s",
			pcm->done_lock_name, strerror(errno));
		sem_unlink(pcm->ready_lock_name);
		return -errno;
	}

	/* ready lock args */
	plug_add_pipe_arg(plug, "r", pcm->ready_lock_name);

	/* done lock args */
	plug_add_pipe_arg(plug, "d", pcm->done_lock_name);

	return 0;
}

static int plug_pcm_create_mmap_regions(snd_sof_plug_t *plug)
{
	snd_sof_pcm_t *pcm = plug->module_prv;
	int err;

	// TODO: set name/size from conf
	pcm->io_name = "sofpipe_data";
	pcm->io_size = 0x10000;

	/* make sure we have a clean sham */
	shm_unlink(pcm->io_name);

	/* open SHM to be used for low latency position */
	pcm->io_fd = shm_open(pcm->io_name,
				    O_RDWR | O_CREAT,
				    S_IRWXU | S_IRWXG);
	if (pcm->io_fd < 0) {
		SNDERR("failed to create SHM io %s: %s",
			pcm->io_name, strerror(errno));
		return -errno;
	}

	/* set SHM size */
	err = ftruncate(pcm->io_fd, pcm->io_size);
	if (err < 0) {
		SNDERR("failed to truncate SHM position %s: %s",
				plug->shm_context.name, strerror(errno));
		shm_unlink(pcm->io_name);
		return -errno;
	}

	/* map it locally for context readback */
	pcm->io_addr = mmap(NULL, pcm->io_size,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED, pcm->io_fd, 0);
	if (pcm->io_addr == NULL) {
		SNDERR("failed to mmap SHM position%s: %s",
			pcm->io_name, strerror(errno));
		shm_unlink(pcm->io_name);
		return -errno;
	}

	/* IO args */
	plug_add_pipe_arg(plug, "M", pcm->io_name);

	return 0;
}

/* complete any init for the parent */
int plug_parent_complete_init(snd_sof_plug_t *plug, snd_pcm_t **pcmp,
		  	  	     const char *name, snd_pcm_stream_t stream, int mode)
{
	snd_sof_pcm_t *pcm = plug->module_prv;
	int err;

	/* load the topology TDOD: add pipeline ID*/
	err = plug_parse_topology(&plug->tplg, &pcm->ipc, NULL, plug->tplg.pipeline_id);
	if (err < 0) {
		SNDERR("failed to parse topology: %s", strerror(err));
		return err;
	}

	/* now register the plugin */
	err = plug_create(plug, pcmp, name, stream, mode);
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
	snd_sof_plug_t *plug;
	snd_sof_pcm_t *pcm;

	int err;

	/* create context */
	plug = calloc(1, sizeof(*plug));
	if (!plug)
		return -ENOMEM;
	plug->newargv[plug->argc++] = pipe_name;

	pcm = calloc(1, sizeof(*pcm));
	if (!pcm) {
		free(plug);
		return -ENOMEM;
	}
	plug->module_prv = pcm;

	if (stream == SND_PCM_STREAM_CAPTURE)
		pcm->capture = 1;

	/* parse the ALSA configuration file for sof plugin */
	err = plug_parse_conf(plug, name, root, conf);
	if (err < 0) {
		SNDERR("failed to parse config: %s", strerror(err));
		goto pipe_error;
	}

	/* create pipe for audio data - TODO support mmap() */
	err = plug_create_locks(plug);
	if (err < 0)
		goto pipe_error;

	/* create message queue for IPC */
	err = plug_ipc_init_queue(&pcm->ipc, plug->tplg.tplg_file, "pcm");
	if (err < 0)
		goto ipc_error;

	plug_add_pipe_arg(plug, "i", pcm->ipc.queue_name);
	err = plug_create_ipc_queue(&pcm->ipc);
	if (err < 0)
		goto ipc_error;

	/* register interest in signals from child */
	err = plug_init_signals(plug);
	if (err < 0)
		goto signal_error;

	/* create a SHM mapping for low latency stream position */
	err = plug_create_mmap_regions(plug);
	if (err < 0)
		goto signal_error;

	/* create a SHM mapping for low latency stream position */
	err = plug_pcm_create_mmap_regions(plug);
	if (err < 0)
		goto signal_error;

	/* the pipeline runs in its own process context */
	plug->cpid = fork();
	if (plug->cpid < 0) {
		SNDERR("failed to fork for new pipeline: %s", strerror(errno));
		goto fork_error;
	}

	/* init flow diverges now depending if we are child or parent */
	if (plug->cpid == 0) {

		/* in child */
		plug_child_complete_init(plug, pcm->capture);

	} else {

		/* in parent */
		err = plug_parent_complete_init(plug, pcmp, name, stream, mode);
		if (err < 0) {
			SNDERR("failed to complete plugin init: %s", strerror(err));
			_exit(EXIT_FAILURE);
		}
	}

	/* everything is good */
	return 0;

	/* error cleanup */
fork_error:
	munmap(plug->shm_context.addr, plug->shm_context.size);
	shm_unlink(plug->shm_context.name);
	munmap(pcm->io_addr, pcm->io_size);
	shm_unlink(pcm->io_name);
signal_error:
	mq_unlink(pcm->ipc.queue_name);
ipc_error:

pipe_error:
	free(plug->device);
dev_error:
	free(plug);
	return err;
}

SND_PCM_PLUGIN_SYMBOL(sof);
