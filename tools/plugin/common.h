// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2022 Intel Corporation. All rights reserved.
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>

#ifndef __SOF_PLUGIN_COMMON_H__
#define __SOF_PLUGIN_COMMON_H__

#include <alsa/asoundlib.h>

#define IPC3_MAX_MSG_SIZE	384

#define MS_TO_US(_msus)	(_msus * 1000)
#define MS_TO_NS(_msns) (MS_TO_US(_msns * 1000))

#define MS_TO_US(_msus)	(_msus * 1000)
#define MS_TO_NS(_msns) (MS_TO_US(_msns * 1000))

#define SEM_PERMS (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)

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

#endif
