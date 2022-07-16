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

struct sof_pipe {
	const char *alsa_name;
	const char *ipc_msg_queue;
	int io_pipe_fd;
	const char *mmap_context;
	const char *io_lock_name;
	int realtime;
	int use_P_core;
	int use_E_core;
	int capture;

	mqd_t ipc;

	struct sigaction action;

	/* SHM for stream context sync */
	int context_fd;
	int context_size;
	char *context_name;
	void *context_addr;

	char *ready_lock_name;
	char *done_lock_name;
	sem_t *ready_lock;
	sem_t *done_lock;

	FILE *log;

	pthread_t ipc_thread;
};

struct plug_context {
	size_t frames;
	size_t position;
	size_t buffer_frames;
};

#if 0
/*
 * Register component driver
 * Only needed once per component type
 */
void register_comp(int comp_type, struct sof_ipc_comp_ext *comp_ext)
{
	int index;
	char message[DEBUG_MSG_LEN + MAX_LIB_NAME_LEN];

	/* register file comp driver (no shared library needed) */
	if (comp_type == SOF_COMP_HOST || comp_type == SOF_COMP_DAI) {
		if (!lib_table[0].register_drv) {
			sys_comp_file_init();
			lib_table[0].register_drv = 1;
			debug_print("registered file comp driver\n");
		}
		return;
	}

	/* get index of comp in shared library table */
	index = get_index_by_type(comp_type, lib_table);
	if (comp_type == SOF_COMP_NONE && comp_ext) {
		index = get_index_by_uuid(comp_ext, lib_table);
		if (index < 0)
			return;
	}

	/* register comp driver if not already registered */
	if (!lib_table[index].register_drv) {
		sprintf(message, "registered comp driver for %s\n",
			lib_table[index].comp_name);
		debug_print(message);

		/* open shared library object */
		sprintf(message, "opening shared lib %s\n",
			lib_table[index].library_name);
		debug_print(message);

		lib_table[index].handle = dlopen(lib_table[index].library_name,
						 RTLD_LAZY);
		if (!lib_table[index].handle) {
			fprintf(stderr, "error: %s\n", dlerror());
			exit(EXIT_FAILURE);
		}

		/* comp init is executed on lib load */
		lib_table[index].register_drv = 1;
	}

}


/* load fileread component */
static int tplg_load_fileread(struct tplg_context *ctx,
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
static int tplg_load_filewrite(struct tplg_context *ctx,
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
static int load_fileread(struct tplg_context *ctx, int dir)
{
	struct sof *sof = ctx->sof;
	struct testbench_prm *tp = ctx->tp;
	FILE *file = ctx->file;
	struct sof_ipc_comp_file fileread = {0};
	int ret;

	fileread.config.frame_fmt = find_format(tp->bits_in);

	ret = tplg_load_fileread(ctx, &fileread);
	if (ret < 0)
		return ret;

	if (tplg_create_controls(ctx->widget->num_kcontrols, file) < 0) {
		fprintf(stderr, "error: loading controls\n");
		return -EINVAL;
	}

	/* configure fileread */
	fileread.fn = strdup(tp->input_file[tp->input_file_index]);
	if (tp->input_file_index == 0)
		tp->fr_id = ctx->comp_id;

	/* use fileread comp as scheduling comp */
	ctx->sched_id = ctx->comp_id;
	tp->input_file_index++;

	/* Set format from testbench command line*/
	fileread.rate = ctx->fs_in;
	fileread.channels = ctx->channels_in;
	fileread.frame_fmt = ctx->frame_fmt;
	fileread.direction = dir;

	/* Set type depending on direction */
	fileread.comp.type = (dir == SOF_IPC_STREAM_PLAYBACK) ?
		SOF_COMP_HOST : SOF_COMP_DAI;

	/* create fileread component */
	register_comp(fileread.comp.type, NULL);
	if (ipc_comp_new(sof->ipc, ipc_to_comp_new(&fileread)) < 0) {
		fprintf(stderr, "error: file read\n");
		return -EINVAL;
	}

	free(fileread.fn);
	return 0;
}

/* load filewrite component */
static int load_filewrite(struct tplg_context *ctx, int dir)
{
	struct sof *sof = ctx->sof;
	struct testbench_prm *tp = ctx->tp;
	FILE *file = ctx->file;
	struct sof_ipc_comp_file filewrite = {0};
	int ret;

	ret = tplg_load_filewrite(ctx, &filewrite);
	if (ret < 0)
		return ret;

	if (tplg_create_controls(ctx->widget->num_kcontrols, file) < 0) {
		fprintf(stderr, "error: loading controls\n");
		return -EINVAL;
	}

	/* configure filewrite (multiple output files are supported.) */
	if (!tp->output_file[tp->output_file_index]) {
		fprintf(stderr, "error: output[%d] file name is null\n",
			tp->output_file_index);
		return -EINVAL;
	}
	filewrite.fn = strdup(tp->output_file[tp->output_file_index]);
	if (tp->output_file_index == 0)
		tp->fw_id = ctx->comp_id;
	tp->output_file_index++;

	/* Set format from testbench command line*/
	filewrite.rate = ctx->fs_out;
	filewrite.channels = ctx->channels_out;
	filewrite.frame_fmt = ctx->frame_fmt;
	filewrite.direction = dir;

	/* Set type depending on direction */
	filewrite.comp.type = (dir == SOF_IPC_STREAM_PLAYBACK) ?
		SOF_COMP_DAI : SOF_COMP_HOST;

	/* create filewrite component */
	register_comp(filewrite.comp.type, NULL);
	if (ipc_comp_new(sof->ipc, ipc_to_comp_new(&filewrite)) < 0) {
		fprintf(stderr, "error: new file write\n");
		return -EINVAL;
	}

	free(filewrite.fn);
	return 0;
}

int load_aif_in_out(struct tplg_context *ctx, int dir)
{
	if (dir == SOF_IPC_STREAM_PLAYBACK)
		return load_fileread(ctx, dir);
	else
		return load_filewrite(ctx, dir);
}

int load_dai_in_out(struct tplg_context *ctx, int dir)
{
	if (dir == SOF_IPC_STREAM_PLAYBACK)
		return load_filewrite(ctx, dir);
	else
		return load_fileread(ctx, dir);
}

#endif

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
	sp->ipc = mq_open(sp->ipc_msg_queue, O_RDWR);
	if (err < 0) {
		fprintf(sp->log, "error: can't open IPC message queue %s : %s\n",
			sp->ipc_msg_queue, strerror(errno));
		return NULL;
	}

	/* main IPC handling loop */
	printf("waiting for messages\n");
	while (1) {
		ipc_size = mq_receive(sp->ipc, mailbox, 384, NULL);
		if (err < 0) {
			fprintf(sp->log, "error: can't read IPC message queue %s : %s\n",
				sp->ipc_msg_queue, strerror(errno));
			break;
		}

		/* do the message work */
		printf("got IPC %ld bytes: %s\n", ipc_size, mailbox);

		/* now return message completion status */
		err = mq_send(sp->ipc, mailbox, 384, 0);
		if (err < 0) {
			fprintf(sp->log, "error: can't send IPC message queue %s : %s\n",
				sp->ipc_msg_queue, strerror(errno));
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
 * Pipe is used to transfer audio data in R/W mode (not mmap)
 */
static int pipe_init_sem(struct sof_pipe *sp)
{
	sp->ready_lock = sem_open(sp->ready_lock_name,
				O_RDWR);
	if (sp->ready_lock == SEM_FAILED) {
		fprintf(sp->log, "failed to open semaphore %s: %s\n",
			sp->ready_lock_name, strerror(errno));
		return -errno;
	}

	sp->done_lock = sem_open(sp->done_lock_name,
				O_RDWR);
	if (sp->done_lock == SEM_FAILED) {
		fprintf(sp->log, "failed to open semaphore %s: %s\n",
			sp->done_lock_name, strerror(errno));
		return -errno;
	}

	return 0;
}

static int pipe_open_ipc_queue(struct sof_pipe *sp)
{
	int err;

	/* now open new queue for Tx and Rx */
	err = mq_open(sp->ipc_msg_queue,  O_RDWR | O_EXCL);
	if (err < 0) {
		fprintf(sp->log, "failed to create IPC queue %s: %s\n",
			sp->ipc_msg_queue, strerror(errno));
		return -errno;
	}

	return 0;
}

static int pipe_open_mmap_regions(struct sof_pipe *sp)
{
	void *addr;
	int err;

	// TODO: set name/size from conf
	sp->context_name = "sofpipe_context";
	sp->context_size = 0x100;

	/* open SHM to be used for low latency position */
	sp->context_fd = shm_open(sp->context_name,
				    O_RDWR,
				    S_IRWXU | S_IRWXG);
	if (sp->context_fd < 0) {
		fprintf(sp->log, "failed to open SHM position %s: %s\n",
			sp->context_name, strerror(errno));
		return -errno;
	}

	/* map it locally for context readback */
	sp->context_addr = mmap(NULL, sp->context_size,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED, sp->context_fd, 0);
	if (sp->context_addr == NULL) {
		fprintf(sp->log, "failed to mmap SHM position%s: %s\n",
			sp->context_name, strerror(errno));
		return -errno;
	}

	return 0;
}

#define MS_TO_US(_msus)	(_msus * 1000)
#define MS_TO_NS(_msns) (MS_TO_US(_msns * 1000))

/*
 * The main processing loop
 */
static int pipe_process_playback(struct sof_pipe *sp)
{
	struct plug_context *ctx = sp->context_addr;
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
		sem_wait(sp->ready_lock);
		//fprintf(sp->log, "   recd %ld frames\n", ctx->frames);

		/* now do all the processing and tell plugin we are done */
		nanosleep(&ts, NULL);
		ctx->position += ctx->frames;
		if (ctx->position > ctx->buffer_frames)
			ctx->position -= ctx->buffer_frames;
		sem_post(sp->done_lock);
	} while (1);


	return 0;
}

static int pipe_process_capture(struct sof_pipe *sp)
{
	struct plug_context *ctx = sp->context_addr;
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
		sem_post(sp->ready_lock);
		//fprintf(sp->log, "   sent %ld frames\n", ctx->frames);

		/* wait for plugin to consume */
		sem_wait(sp->done_lock);

	} while (1);


	return 0;
}

/*
 * -D ALSA device. e.g. hw:0,1
 * -R realtime (needs parent to set uid)
 * -p Force run on P core
 * -e Force run on E core
 * -c capture
 * -i IPC message queue name
 * -r ready semaphore
 * -d done semaphore
 * -M mmap audio data file
 * -C mmap audio context file
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
	while ((option = getopt(argc, argv, "hD:Rpeci:r:d:M:C:")) != -1) {

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
		case 'i':
			sp.ipc_msg_queue = strdup(optarg);
			break;
		case 'r':
			sp.ready_lock_name = strdup(optarg);
			break;
		case 'd':
			sp.done_lock_name = strdup(optarg);
			break;
		case 'M':
			sp.mmap_context = strdup(optarg);
			break;
		case 'C':
			//sp.io_lock_name = strdup(optarg);
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

	// TODO: get from conf/cmd line
	sp.ipc_msg_queue = "/sofipc";

	/* validate cmd line params */
	if (!sp.ready_lock_name) {
		fprintf(stderr, "error: no data READY lock specified using -r\n");
		exit(EXIT_FAILURE);
	}
	if (!sp.done_lock_name) {
		fprintf(stderr, "error: no data DONE lock specified using -d\n");
		exit(EXIT_FAILURE);
	}

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
	ret = pthread_create(&sp.ipc_thread, NULL, &pipe_ipc_thread, &sp);
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
	ret = pipe_open_mmap_regions(&sp);
	if (ret < 0)
		goto out;

	/* open IPC message queue */
	ret = pipe_open_ipc_queue(&sp);
	if (ret < 0)
		goto out;

	/* open semaphore */
	ret = pipe_init_sem(&sp);
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
