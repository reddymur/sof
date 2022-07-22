// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2018 Intel Corporation. All rights reserved.
//
// Author: Ranjani Sridharan <ranjani.sridharan@linux.intel.com>
//         Liam Girdwood <liam.r.girdwood@linux.intel.com>

/* Topology loader to set up components and pipeline */

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
#include <dlfcn.h>

#include <tplg_parser/topology.h>
#include <tplg_parser/tokens.h>

#include <alsa/asoundlib.h>
#include <alsa/control_external.h>
#include <alsa/pcm_external.h>

#include "plugin.h"

#define SNDRV_CTL_ELEM_ID_NAME_MAXLEN 44

#define FILE_READ 0
#define FILE_WRITE 1

#include <alsa/sound/uapi/asoc.h>

static int plug_load_fileread(struct tplg_context *ctx,
			      struct sof_ipc_comp_file *fileread)
{
	struct snd_soc_tplg_vendor_array *array = NULL;
	size_t total_array_size = 0;
	size_t read_size;
	FILE *file = ctx->file;
	int size = ctx->widget->priv.size;
	int comp_id = ctx->comp_id;
	int ret;

	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc\n");
		return -errno;
	}

	/* read vendor tokens */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1) {
			fprintf(stderr,
				"error: fread failed during load_fileread\n");
			free(array);
			return -EINVAL;
		}

		if (!is_valid_priv_size(total_array_size, size, array)) {
			fprintf(stderr, "error: filewrite array size mismatch for widget size %d\n",
				size);
			free(array);
			return -EINVAL;
		}

		tplg_read_array(array, file);

		/* parse comp tokens */
		ret = sof_parse_tokens(&fileread->config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse comp tokens %d\n",
				size);
			free(array);
			return -EINVAL;
		}

		total_array_size += array->size;
	}

	free(array);

	/* configure fileread */
	fileread->mode = FILE_READ;
	fileread->comp.id = comp_id;

	/* use fileread comp as scheduling comp */
	fileread->comp.core = ctx->core_id;
	fileread->comp.hdr.size = sizeof(struct sof_ipc_comp_file);
	fileread->comp.type = SOF_COMP_FILEREAD;
	fileread->comp.pipeline_id = ctx->pipeline_id;
	fileread->config.hdr.size = sizeof(struct sof_ipc_comp_config);

	return 0;
}

/* load filewrite component */
static int plug_load_filewrite(struct tplg_context *ctx,
			       struct sof_ipc_comp_file *filewrite)
{
	struct snd_soc_tplg_vendor_array *array = NULL;
	size_t read_size;
	size_t total_array_size = 0;
	FILE *file = ctx->file;
	int size = ctx->widget->priv.size;
	int comp_id = ctx->comp_id;
	int ret;

	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc\n");
		return -errno;
	}

	/* read vendor tokens */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1) {
			free(array);
			return -EINVAL;
		}

		if (!is_valid_priv_size(total_array_size, size, array)) {
			fprintf(stderr, "error: filewrite array size mismatch\n");
			free(array);
			return -EINVAL;
		}

		tplg_read_array(array, file);

		ret = sof_parse_tokens(&filewrite->config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse filewrite tokens %d\n",
				size);
			free(array);
			return -EINVAL;
		}
		total_array_size += array->size;
	}

	free(array);

	/* configure filewrite */
	filewrite->comp.core = ctx->core_id;
	filewrite->comp.id = comp_id;
	filewrite->mode = FILE_WRITE;
	filewrite->comp.hdr.size = sizeof(struct sof_ipc_comp_file);
	filewrite->comp.type = SOF_COMP_FILEWRITE;
	filewrite->comp.pipeline_id = ctx->pipeline_id;
	filewrite->config.hdr.size = sizeof(struct sof_ipc_comp_config);

	return 0;
}

/* load fileread component */
static int load_fileread(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl, int dir)
{
	FILE *file = ctx->file;
	struct sof_ipc_comp_file fileread = {0};
	struct sof_ipc_comp_reply reply = {0};
	int ret;

	//fileread.config.frame_fmt = find_format(tp->bits_in);

	ret = plug_load_fileread(ctx, &fileread);
	if (ret < 0)
		return ret;

	if (tplg_create_controls(ctx->widget->num_kcontrols, file, NULL) < 0) {
		fprintf(stderr, "error: loading controls\n");
		return -EINVAL;
	}

	/* configure fileread */
//	fileread.fn = strdup(tp->input_file[tp->input_file_index]);
//	if (tp->input_file_index == 0)
//		tp->fr_id = ctx->comp_id;

	/* use fileread comp as scheduling comp */
	ctx->sched_id = ctx->comp_id;
//	tp->input_file_index++;

	/* Set format from testbench command line*/
	fileread.rate = ctx->fs_in;
	fileread.channels = ctx->channels_in;
	fileread.frame_fmt = ctx->frame_fmt;
	fileread.direction = dir;

	/* Set type depending on direction */
	fileread.comp.type = (dir == SOF_IPC_STREAM_PLAYBACK) ?
		SOF_COMP_HOST : SOF_COMP_DAI;

	ret = plug_ipc_cmd(ipc, &fileread, sizeof(fileread), &reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
	}

	//free(fileread.fn);
	return ret;
}

/* load filewrite component */
static int load_filewrite(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl, int dir)
{
	struct sof *sof = ctx->sof;
	FILE *file = ctx->file;
	struct sof_ipc_comp_file filewrite = {0};
	struct sof_ipc_comp_reply reply = {0};
	int ret;

	ret = plug_load_filewrite(ctx, &filewrite);
	if (ret < 0)
		return ret;

	if (tplg_create_controls(ctx->widget->num_kcontrols, file, NULL) < 0) {
		fprintf(stderr, "error: loading controls\n");
		return -EINVAL;
	}

	/* configure filewrite (multiple output files are supported.) */
//	if (!tp->output_file[tp->output_file_index]) {
//		fprintf(stderr, "error: output[%d] file name is null\n",
//			tp->output_file_index);
//		return -EINVAL;
//	}
//	filewrite.fn = strdup(tp->output_file[tp->output_file_index]);
//	if (tp->output_file_index == 0)
//		tp->fw_id = ctx->comp_id;
//	tp->output_file_index++;

	/* Set format from testbench command line*/
	filewrite.rate = ctx->fs_out;
	filewrite.channels = ctx->channels_out;
	filewrite.frame_fmt = ctx->frame_fmt;
	filewrite.direction = dir;

	/* Set type depending on direction */
	filewrite.comp.type = (dir == SOF_IPC_STREAM_PLAYBACK) ?
		SOF_COMP_DAI : SOF_COMP_HOST;

	ret = plug_ipc_cmd(ipc, &filewrite, sizeof(filewrite),
			&reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
	}

	//free(filewrite.fn);
	return ret;
}

static int plug_aif_in_out(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl, int dir)
{
	if (dir == SOF_IPC_STREAM_PLAYBACK)
		return load_fileread(ctx, ipc, ctl, dir);
	else
		return load_filewrite(ctx, ipc, ctl, dir);
}

static int plug_dai_in_out(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl, int dir)
{
	if (dir == SOF_IPC_STREAM_PLAYBACK)
		return load_filewrite(ctx, ipc, ctl, dir);
	else
		return load_fileread(ctx, ipc, ctl, dir);
}

static int get_next_hdr(struct tplg_context *ctx, struct snd_soc_tplg_hdr *hdr,
			size_t file_size)
{
	if (fseek(ctx->file, hdr->payload_size, SEEK_CUR)) {
		fprintf(stderr, "error: can't seek header pay load size: %s\n",
			strerror(errno));
		return -errno;
	}

	if (ftell(ctx->file) == file_size)
		return 0;

	return 1;
}

static int plug_ctl_init(struct plug_ctl *ctls, struct snd_soc_tplg_ctl_hdr *tplg_ctl)
{
	struct snd_soc_tplg_ctl_hdr *_tplg_ctl;

	if (ctls->count >= MAX_CTLS) {
		SNDERR("error: ctoo many CTLs in topology\n");
		return -EINVAL;
	}

	_tplg_ctl = &ctls->tplg[ctls->count];
	*_tplg_ctl = *tplg_ctl;
	ctls->count++;

	return 0;
}

static int plug_new_pga_ipc(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl)
{
	struct sof_ipc_comp_volume volume = {0};
	struct sof_ipc_comp_reply reply = {0};
	struct snd_soc_tplg_ctl_hdr tplg_ctl;
	int ret;

	ret = tplg_new_pga(ctx, &volume, &tplg_ctl);
	if (ret < 0) {
		fprintf(stderr, "error: failed to create PGA\n");
		goto out;
	}
	ret = plug_ipc_cmd(ipc, &volume, sizeof(volume),
			&reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
		return ret;
	}

	if (ctl)
		ret = plug_ctl_init(ctl, &tplg_ctl);

out:
	return ret;
}

static int plug_new_mixer_ipc(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl)
{
	struct sof_ipc_comp_mixer mixer = {0};
	struct sof_ipc_comp_reply reply = {0};
	struct snd_soc_tplg_ctl_hdr tplg_ctl;
	int ret;

	ret = tplg_new_mixer(ctx, &mixer, &tplg_ctl);
	if (ret < 0) {
		fprintf(stderr, "error: failed to create mixer\n");
		goto out;
	}
	ret = plug_ipc_cmd(ipc, &mixer, sizeof(mixer),
			&reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
		return ret;
	}

	if (ctl)
		ret = plug_ctl_init(ctl, &tplg_ctl);

out:
	return ret;
}

static int plug_new_src_ipc(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl)
{
	struct sof_ipc_comp_src src = {0};
	struct sof_ipc_comp_reply reply = {0};
	struct snd_soc_tplg_ctl_hdr tplg_ctl;
	int ret;

	ret = tplg_new_src(ctx, &src, &tplg_ctl);
	if (ret < 0) {
		fprintf(stderr, "error: failed to create src\n");
		goto out;
	}
	ret = plug_ipc_cmd(ipc, &src, sizeof(src),
			&reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
		return ret;
	}

	if (ctl)
		ret = plug_ctl_init(ctl, &tplg_ctl);

out:
	return ret;
}

static int plug_new_asrc_ipc(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl)
{
	struct sof_ipc_comp_asrc asrc = {0};
	struct sof_ipc_comp_reply reply = {0};
	struct snd_soc_tplg_ctl_hdr tplg_ctl;
	int ret;

	ret = tplg_new_asrc(ctx, &asrc, &tplg_ctl);
	if (ret < 0) {
		fprintf(stderr, "error: failed to create PGA\n");
		goto out;
	}
	ret = plug_ipc_cmd(ipc, &asrc, sizeof(asrc),
			&reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
		return ret;
	}

	if (ctl)
		ret = plug_ctl_init(ctl, &tplg_ctl);

out:
	return ret;
}

static int plug_new_process_ipc(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl)
{
	struct sof_ipc_comp_process process = {0};
	struct sof_ipc_comp_reply reply = {0};
	struct snd_soc_tplg_ctl_hdr tplg_ctl;
	int ret;

	ret = tplg_new_process(ctx, &process, &tplg_ctl);
	if (ret < 0) {
		fprintf(stderr, "error: failed to create PGA\n");
		goto out;
	}
	ret = plug_ipc_cmd(ipc,  &process, sizeof(process),
			&reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
		return ret;
	}

	if (ctl)
		ret = plug_ctl_init(ctl, &tplg_ctl);

out:
	return ret;
}

static int plug_new_pipeline_ipc(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl)
{
	struct sof_ipc_pipe_new pipeline = {0};
	struct sof_ipc_comp_reply reply = {0};
	struct snd_soc_tplg_ctl_hdr tplg_ctl;
	int ret;

	ret = tplg_new_pipeline(ctx, &pipeline, &tplg_ctl);
	if (ret < 0) {
		fprintf(stderr, "error: failed to create pipeline\n");
		goto out;
	}
	ret = plug_ipc_cmd(ipc, &pipeline, sizeof(pipeline),
			&reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
		return ret;
	}

	if (ctl)
		ret = plug_ctl_init(ctl, &tplg_ctl);

out:
	return ret;
}

static int plug_new_buffer_ipc(struct tplg_context *ctx, struct plug_mq *ipc,
				struct plug_ctl *ctl)
{
	struct sof_ipc_buffer buffer = {0};
	struct sof_ipc_comp_reply reply = {0};
	struct snd_soc_tplg_ctl_hdr tplg_ctl;
	int ret;

	ret = tplg_new_buffer(ctx, &buffer, &tplg_ctl);
	if (ret < 0) {
		fprintf(stderr, "error: failed to create pipeline\n");
		goto out;
	}
	ret = plug_ipc_cmd(ipc, &buffer, sizeof(buffer),
			&reply, sizeof(reply));
	if (ret < 0) {
		SNDERR("error: can't connect\n");
		return ret;
	}

	if (ctl)
		ret = plug_ctl_init(ctl, &tplg_ctl);

out:
	return ret;
}

/* load dapm widget */
int plug_load_widget(struct tplg_context *ctx, struct plug_mq *ipc, struct plug_ctl *ctl)
{
	struct comp_info *temp_comp_list = ctx->info;
	struct snd_soc_tplg_ctl_hdr tplg_ctl;
	int comp_index = ctx->info_index;
	int comp_id = ctx->comp_id;
	int ret = 0;

	if (!temp_comp_list) {
		fprintf(stderr, "plug_load_widget: temp_comp_list argument NULL\n");
		return -EINVAL;
	}

	/* allocate memory for widget */
	ctx->widget_size = sizeof(struct snd_soc_tplg_dapm_widget);
	ctx->widget = calloc(ctx->widget_size, 1);
	if (!ctx->widget) {
		fprintf(stderr, "error: mem alloc\n");
		return -errno;
	}

	/* read widget data */
	ret = fread(ctx->widget, ctx->widget_size, 1, ctx->file);
	if (ret != 1) {
		ret = -EINVAL;
		goto exit;
	}

	/*
	 * create a list with all widget info
	 * containing mapping between component names and ids
	 * which will be used for setting up component connections
	 */
	temp_comp_list[comp_index].id = comp_id;
	temp_comp_list[comp_index].name = strdup(ctx->widget->name);
	temp_comp_list[comp_index].type = ctx->widget->id;
	temp_comp_list[comp_index].pipeline_id = ctx->pipeline_id;

	printf("debug: loading comp_id %d: widget %s id %d size %d at offset %ld\n",
	       comp_id, ctx->widget->name, ctx->widget->id, ctx->widget->size,
	       ftell(ctx->file));

	/* load widget based on type */
	switch (ctx->widget->id) {

	/* load pga widget */
	case SND_SOC_TPLG_DAPM_PGA:
		if (plug_new_pga_ipc(ctx, ipc, ctl) < 0) {
			fprintf(stderr, "error: load pga\n");
			ret = -EINVAL;
			goto exit;
		}
		break;
	case SND_SOC_TPLG_DAPM_AIF_IN:
		if (plug_aif_in_out(ctx, ipc, ctl, SOF_IPC_STREAM_PLAYBACK) < 0) {
			fprintf(stderr, "error: load AIF IN failed\n");
			ret = -EINVAL;
			goto exit;
		}
		break;
	case SND_SOC_TPLG_DAPM_AIF_OUT:
		if (plug_aif_in_out(ctx, ipc, ctl, SOF_IPC_STREAM_CAPTURE) < 0) {
			fprintf(stderr, "error: load AIF OUT failed\n");
			ret = -EINVAL;
			goto exit;
		}
		break;
	case SND_SOC_TPLG_DAPM_DAI_IN:
		if (plug_dai_in_out(ctx, ipc, ctl, SOF_IPC_STREAM_PLAYBACK) < 0) {
			fprintf(stderr, "error: load filewrite\n");
			ret = -EINVAL;
			goto exit;
		}
		break;
	case SND_SOC_TPLG_DAPM_DAI_OUT:
		if (plug_dai_in_out(ctx, ipc, ctl, SOF_IPC_STREAM_CAPTURE) < 0) {
			fprintf(stderr, "error: load filewrite\n");
			ret = -EINVAL;
			goto exit;
		}
		break;

	case SND_SOC_TPLG_DAPM_BUFFER:
		if (plug_new_buffer_ipc(ctx, ipc, ctl) < 0) {
			fprintf(stderr, "error: load pipeline\n");
			ret = -EINVAL;
			goto exit;
		}
		break;

	case SND_SOC_TPLG_DAPM_SCHEDULER:
		if (plug_new_pipeline_ipc(ctx, ipc, ctl) < 0) {
			fprintf(stderr, "error: load pipeline\n");
			ret = -EINVAL;
			goto exit;
		}
		break;
	case SND_SOC_TPLG_DAPM_SRC:
		if (plug_new_src_ipc(ctx, ipc, ctl) < 0) {
			fprintf(stderr, "error: load src\n");
			ret = -EINVAL;
			goto exit;
		}
		break;
	case SND_SOC_TPLG_DAPM_ASRC:
		if (plug_new_asrc_ipc(ctx, ipc, ctl) < 0) {
			fprintf(stderr, "error: load asrc\n");
			ret = -EINVAL;
			goto exit;
		}
		break;

	case SND_SOC_TPLG_DAPM_MIXER:
		if (plug_new_mixer_ipc(ctx, ipc, ctl) < 0) {
			fprintf(stderr, "error: load mixer\n");
			ret = -EINVAL;
			goto exit;
		}
		break;
	case SND_SOC_TPLG_DAPM_EFFECT:
		if (plug_new_process_ipc(ctx, ipc, ctl) < 0) {
			fprintf(stderr, "error: load effect\n");
			ret = -EINVAL;
			goto exit;
		}
		break;

	/* unsupported widgets */
	default:
		if (fseek(ctx->file, ctx->widget->priv.size, SEEK_CUR)) {
			fprintf(stderr, "error: fseek unsupported widget\n");
			ret = -errno;
			goto exit;
		}

		printf("info: Widget type not supported %d\n", ctx->widget->id);
		ret = tplg_create_controls(ctx->widget->num_kcontrols, ctx->file, NULL);
		if (ret < 0) {
			fprintf(stderr, "error: loading controls\n");
			goto exit;
		}
		ret = 0;
		break;
	}

	ret = 1;

exit:
	/* free allocated widget data */
	free(ctx->widget);
	return ret;
}

enum sof_ipc_dai_type find_dai(const char *string)
{
	return 0;
}

int plug_register_graph(struct tplg_context *ctx, struct plug_mq *ipc,
			struct comp_info *temp_comp_list,
			char *pipeline_string, FILE *file,
			int count, int num_comps, int pipeline_id)
{
	struct sof_ipc_pipe_comp_connect connection = {0};
	struct sof_ipc_pipe_ready ready = {0};
	struct sof_ipc_comp_reply reply = {0};
	int ret = 0;
	int i;

	for (i = 0; i < count; i++) {
		ret = tplg_create_graph(num_comps, pipeline_id, temp_comp_list,
				      pipeline_string, &connection, file, i,
				      count);
		if (ret < 0)
			return ret;

		ret = plug_ipc_cmd(ipc, &connection, sizeof(connection),
				&reply, sizeof(reply));
		if (ret < 0) {
			SNDERR("error: can't connect\n");
			return ret;
		}
	}

	/* pipeline complete after pipeline connections are established */
	for (i = 0; i < num_comps; i++) {
		if (temp_comp_list[i].pipeline_id == pipeline_id &&
		    temp_comp_list[i].type == SND_SOC_TPLG_DAPM_SCHEDULER) {

			ret = plug_ipc_cmd(ipc, &ready, sizeof(ready),
					&reply, sizeof(reply));
			if (ret < 0) {
				SNDERR("error: can't complete pipeline\n");
				return ret;
			}
			//ipc_pipeline_complete(sof->ipc, temp_comp_list[i].id);
		}
	}

	return ret;
}

/* parse topology file and set up pipeline */
int plug_parse_topology(struct tplg_context *ctx, struct plug_mq *ipc,
			struct plug_ctl *ctl, int pipeline_num)
{
	struct snd_soc_tplg_hdr *hdr;
	struct comp_info *comp_list_realloc = NULL;
	char pipeline_string[256] = {0};
	int i;
	int next;
	int ret = 0;
	size_t file_size;
	size_t size;

	/* open topology file */
	ctx->file = fopen(ctx->tplg_file, "rb");
	if (!ctx->file) {
		fprintf(stderr, "error: can't open topology %s : %s\n", ctx->tplg_file,
			strerror(errno));
		return -errno;
	}

	/* file size */
	if (fseek(ctx->file, 0, SEEK_END)) {
		fprintf(stderr, "error: can't seek to end of topology: %s\n",
			strerror(errno));
		fclose(ctx->file);
		return -errno;
	}
	file_size = ftell(ctx->file);
	if (fseek(ctx->file, 0, SEEK_SET)) {
		fprintf(stderr, "error: can't seek to beginning of topology: %s\n",
			strerror(errno));
		fclose(ctx->file);
		return -errno;
	}

	/* allocate memory */
	size = sizeof(struct snd_soc_tplg_hdr);
	hdr = (struct snd_soc_tplg_hdr *)malloc(size);
	if (!hdr) {
		fprintf(stderr, "error: mem alloc\n");
		fclose(ctx->file);
		return -errno;
	}

	while (1) {
		/* read topology header */
		ret = fread(hdr, sizeof(struct snd_soc_tplg_hdr), 1, ctx->file);
		if (ret != 1)
			goto out;

	//	fprintf(stdout, "type: %x, size: 0x%x count: %d index: %d\n",
	//		hdr->type, hdr->payload_size, hdr->count, hdr->index);

		ctx->hdr = hdr;

		if (hdr->index != pipeline_num) {
			fprintf(stdout, "skipped pipeline %d\n", hdr->index);
			next = get_next_hdr(ctx, hdr, file_size);
			if (next < 0)
				goto out;
			else if (next > 0)
				continue;
			else
				goto finish;

		}

		/* parse header and load the next block based on type */
		switch (hdr->type) {
		/* load dapm widget */
		case SND_SOC_TPLG_TYPE_DAPM_WIDGET:

			fprintf(stdout, "number of DAPM widgets %d\n",
				hdr->count);


			/* update max pipeline_id */
			ctx->pipeline_id = hdr->index;
		//	if (hdr->index > tp->max_pipeline_id)
		//		tp->max_pipeline_id = hdr->index;

			ctx->info_elems += hdr->count;
			size = sizeof(struct comp_info) * ctx->info_elems;
			comp_list_realloc = (struct comp_info *)
					 realloc(ctx->info, size);

			if (!comp_list_realloc && size) {
				fprintf(stderr, "error: mem realloc\n");
				ret = -errno;
				goto out;
			}
			ctx->info = comp_list_realloc;

			for (i = (ctx->info_elems - hdr->count); i < ctx->info_elems; i++)
				ctx->info[i].name = NULL;

			for (ctx->info_index = (ctx->info_elems - hdr->count);
			     ctx->info_index < ctx->info_elems;
			     ctx->info_index++) {
				ret = plug_load_widget(ctx, ipc, ctl);
				if (ret < 0) {
					printf("error: loading widget\n");
					goto finish;
				} else if (ret > 0)
					ctx->comp_id++;
			}
			break;

		/* set up component connections from pipeline graph */
		case SND_SOC_TPLG_TYPE_DAPM_GRAPH:
			printf("%s %d\n", __func__, __LINE__);
			if (plug_register_graph(ctx, ipc, ctx->info,
						pipeline_string,
						ctx->file, hdr->count,
						ctx->comp_id,
						hdr->index) < 0) {
				fprintf(stderr, "error: pipeline graph\n");
				ret = -EINVAL;
				goto out;
			}
			if (ftell(ctx->file) == file_size)
				goto finish;
			break;

		default:
			printf("%s %d\n", __func__, __LINE__);
			next = get_next_hdr(ctx, hdr, file_size);
			if (next < 0)
				goto out;
			else if (next == 0)
				goto finish;
			break;
		}
	}
finish:

out:
	/* free all data */
	free(hdr);

	for (i = 0; i < ctx->info_elems; i++)
		free(ctx->info[i].name);

	free(ctx->info);
	fclose(ctx->file);
	return ret;
}
