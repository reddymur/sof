// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2019 Intel Corporation. All rights reserved.
//
// Author: Ranjani Sridharan <ranjani.sridharan@linux.intel.com>

/* Topology parser */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <ipc/topology.h>
#include <ipc/stream.h>
#include <ipc/dai.h>
#include <sof/common.h>
#include <sof/lib/uuid.h>
#include <sof/ipc/topology.h>
#include <tplg_parser/topology.h>
#include <tplg_parser/tokens.h>

/* temporary until upstream fix propagates downstream */
#define SNDRV_CTL_ELEM_ID_NAME_MAXLEN 44

#include <alsa/sound/uapi/asoc.h>

/* load mixer dapm widget */
int tplg_parse_ipc3_mixer(struct tplg_context *ctx,
		    struct sof_ipc_comp_mixer *mixer)
{
	struct snd_soc_tplg_vendor_array *array = NULL;
	size_t total_array_size = 0, read_size;
	FILE *file = ctx->file;
	int size = ctx->widget->priv.size;
	int comp_id = ctx->comp_id;
	char uuid[UUID_SIZE];
	int ret;

	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc for src vendor array\n");
		return -errno;
	}

	/* read vendor tokens */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1) {
			free(MOVE_POINTER_BY_BYTES(array, -total_array_size));
			return -EINVAL;
		}

		/* check for array size mismatch */
		if (!is_valid_priv_size(total_array_size, size, array)) {
			fprintf(stderr, "error: load mixer array size mismatch\n");
			free(MOVE_POINTER_BY_BYTES(array, -total_array_size));
			return -EINVAL;
		}

		ret = tplg_read_array(array, file);
		if (ret) {
			fprintf(stderr, "error: read array fail\n");
			free(MOVE_POINTER_BY_BYTES(array, -total_array_size));
			return ret;
		}

		/* parse comp tokens */
		ret = sof_parse_tokens(&mixer->config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse src comp_tokens %d\n",
				size);
			free(MOVE_POINTER_BY_BYTES(array, -total_array_size));
			return -EINVAL;
		}
		/* parse uuid token */
		ret = sof_parse_tokens(uuid, comp_ext_tokens,
				       ARRAY_SIZE(comp_ext_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse mixer uuid token %d\n", size);
			free(array);
			return -EINVAL;
		}

		total_array_size += array->size;

		/* read next array */
		array = MOVE_POINTER_BY_BYTES(array, array->size);
	}

	/* point to the start of array so it gets freed properly */
	array = MOVE_POINTER_BY_BYTES(array, -total_array_size);

	/* configure mixer */
	mixer->comp.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_COMP_NEW;
	mixer->comp.id = comp_id;
	mixer->comp.hdr.size = sizeof(struct sof_ipc_comp_src);
	mixer->comp.type = SOF_COMP_MIXER;
	mixer->comp.pipeline_id = ctx->pipeline_id;
	mixer->comp.ext_data_length = UUID_SIZE;
	mixer->config.hdr.size = sizeof(struct sof_ipc_comp_config);
	memcpy(mixer + 1, &uuid, UUID_SIZE);

	free(array);
	return 0;
}

int tplg_new_mixer(struct tplg_context *ctx, struct sof_ipc_comp_mixer *mixer,
		struct snd_soc_tplg_ctl_hdr *rctl)
{
	int ret;

	ret = tplg_parse_ipc3_mixer(ctx, mixer);
	if (ret < 0)
		return ret;

	if (tplg_create_controls(ctx->widget->num_kcontrols, ctx->file, rctl) < 0) {
		fprintf(stderr, "error: loading controls\n");
		return -EINVAL;
	}

	return ret;
}
