#include "blktrace_api.h"
#include "file_io.h"
#include "trace.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <byteswap.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>


static struct blkio_event_node *blkio_alloc_event(struct blkio_event *event)
{
	struct blkio_event_node *node = malloc(sizeof(*node));

	if (!node)
		return 0;

	memset(&node->node, 0, sizeof(node->node));
	node->event = *event;
	return node;
}

static void blkio_free_event(struct blkio_event_node *event)
{ free(event); }

static struct blkio_process_info *blkio_process_info_alloc(size_t size)
{
	void *ptr = malloc(sizeof(struct blkio_process_info) + size);

	if (!ptr)
		return 0;

	struct blkio_process_info *pinfo = ptr;

	memset(pinfo, 0, sizeof(*pinfo));
	list_head_init(&pinfo->link);
	pinfo->name = (void *)(pinfo + 1);
	return pinfo;
}

static void blkio_process_info_free(struct blkio_process_info *info)
{ free(info); }

static struct blkio_buffer *blkio_alloc_buffer(size_t size)
{
	void *ptr = malloc(sizeof(struct blkio_buffer) + size);

	if (!ptr)
		return 0;

	struct blkio_buffer *buffer = ptr;

	memset(buffer, 0, sizeof(*buffer));
	list_head_init(&buffer->link);
	list_head_init(&buffer->proc);
	buffer->data = (void *)(buffer + 1);
	return buffer;
}

static void blkio_free_buffer(struct blkio_buffer *buf)
{
	struct list_head *head = &buf->proc;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_process_info *info = list_entry(ptr,
					struct blkio_process_info, link);
		ptr = ptr->next;
		blkio_process_info_free(info);
	}

	free(buf);
}

static struct blkio_process_data *blkio_process_data_alloc(int pid,
			size_t events)
{
	struct blkio_process_data *data = malloc(sizeof(*data));

	if (!data)
		return 0;

	memset(data, 0, sizeof(*data));
	data->pid = pid;
	data->events = calloc(events, sizeof(struct blkio_event));

	if (!data->events) {
		free(data);
		return 0;
	}
	return data;
}

static void blkio_process_data_free(struct blkio_process_data *data)
{
	free(data->events);
	free(data);
}

static struct blkio_tracer *blkio_alloc_tracer(void)
{
	struct blkio_tracer *tracer = malloc(sizeof(struct blkio_tracer));

	if (!tracer)
		return 0;

	list_head_init(&tracer->link);
	list_head_init(&tracer->bufs);
	assert(!pthread_mutex_init(&tracer->lock, NULL));
	assert(!pthread_cond_init(&tracer->cond, NULL));
	CPU_ZERO(&tracer->cpuset);
	tracer->state = TRACE_WAIT;
	tracer->fd = -1;
	return tracer;
}

static void __blkio_release_events(struct rb_node *node)
{
	while (node) {
		struct blkio_event_node *event = rb_entry(node,
					struct blkio_event_node, node);

		__blkio_release_events(node->rb_right);
		node = node->rb_left;
		blkio_free_event(event);
	}
}

static void blkio_release_events(struct rb_root *events)
{ __blkio_release_events(events->rb_node); }

static void __blkio_release_process_info(struct rb_node *node)
{
	while (node) {
		struct blkio_process_info *info = rb_entry(node,
					struct blkio_process_info, node);

		__blkio_release_process_info(node->rb_right);
		node = node->rb_left;
		blkio_process_info_free(info);
	}
}

static void blkio_release_process_info(struct rb_root *procs)
{ __blkio_release_process_info(procs->rb_node); }

static void blkio_free_tracer(struct blkio_tracer *tracer)
{
	assert(!pthread_mutex_destroy(&tracer->lock));
	assert(!pthread_cond_destroy(&tracer->cond));
	free(tracer);
}

static void blkio_tracer_wait(struct blkio_tracer *tracer)
{
	pthread_mutex_lock(&tracer->lock);
	while (tracer->state == TRACE_WAIT)
		pthread_cond_wait(&tracer->cond, &tracer->lock);
	pthread_mutex_unlock(&tracer->lock);
}

static void blkio_processor_wait(struct blkio_processor *proc)
{
	pthread_mutex_lock(&proc->lock);
	while (proc->state == TRACE_WAIT)
		pthread_cond_wait(&proc->cond, &proc->lock);
	pthread_mutex_unlock(&proc->lock);
}

static void blkio_event_insert(struct blkio_processor *proc,
			struct blkio_event_node *event)
{
	struct rb_node **plink = &proc->events.rb_node;
	struct rb_node *parent = 0;

	while (*plink) {
		struct blkio_event_node *e = rb_entry(*plink,
					struct blkio_event_node, node);

		parent = *plink;
		if (e->event.time < event->event.time)
			plink = &parent->rb_right;
		else
			plink = &parent->rb_left;
	}

	rb_link_node(&event->node, parent, plink);
	rb_insert_color(&event->node, &proc->events);
}

static void blkio_processor_populate_buffer(struct blkio_processor *proc,
			struct blkio_buffer *buf)
{
	for (size_t i = 0; i != buf->count; ++i) {
		struct blkio_event_node *event =
					blkio_alloc_event(buf->data + i);

		if (!event) {
			fprintf(stderr, "Run out of memory");
			return;
		}

		blkio_event_insert(proc, event);		
	}
}

struct blkio_pinfo_iter {
	struct rb_node **plink;
	struct rb_node *parent;
	struct blkio_process_info *info;
};

static int blkio_lookup_process_info(struct blkio_processor *proc, int pid,
			struct blkio_pinfo_iter *iter)
{
	struct rb_node **plink = &proc->procs.rb_node;
	struct rb_node *parent = 0;

	while (*plink) {
		struct blkio_process_info *old = rb_entry(*plink,
					struct blkio_process_info, node);

		if (old->pid == pid) {
			iter->plink = plink;
			iter->parent = parent;
			iter->info = old;
			return 1;
		}

		parent = *plink;
		if (old->pid < pid)
			plink = &parent->rb_right;
		else
			plink = &parent->rb_left;
	}

	iter->plink = plink;
	iter->parent = parent;
	iter->info = 0;
	return 0;
}

static void blkio_insert_process_info(struct blkio_processor *proc,
			struct blkio_process_info *info)
{
	struct blkio_pinfo_iter iter;

	if (blkio_lookup_process_info(proc, info->pid, &iter)) {
		rb_replace_node(&iter.info->node, &info->node, &proc->procs);
		blkio_process_info_free(iter.info);
		return;
	}
	rb_link_node(&info->node, iter.parent, iter.plink);
	rb_insert_color(&info->node, &proc->procs);
}

static void blkio_update_process_info(struct blkio_processor *proc,
			struct list_head *head)
{
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_process_info *info = list_entry(ptr,
					struct blkio_process_info, link);

		ptr = ptr->next;
		blkio_insert_process_info(proc, info);
	}
	list_head_init(head);
}

static void blkio_processor_populate_buffers(struct blkio_processor *proc,
			struct list_head *head)
{
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_buffer *buf = list_entry(ptr, struct blkio_buffer,
					link);

		ptr = ptr->next;
		list_unlink(&buf->link);
		blkio_processor_populate_buffer(proc, buf);
		blkio_update_process_info(proc, &buf->proc);
		blkio_free_buffer(buf);
	}
}

static int blkio_processor_populate(struct blkio_processor *proc)
{
	struct blkio_record_ctx *ctx = proc->ctx;
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	struct list_head buffers;

	list_head_init(&buffers);
	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;

		pthread_mutex_lock(&tracer->lock);
		list_splice_tail(&buffers, &tracer->bufs);
		pthread_mutex_unlock(&tracer->lock);
	}

	const int rc = !list_empty(&buffers);
	blkio_processor_populate_buffers(proc, &buffers);
	return rc;
}

static int blkio_events_intersect(struct blkio_event_node *l,
			struct blkio_event_node *r)
{
	if (l->event.to <= r->event.from || l->event.from >= r->event.to)
		return 0;
	return 1;
}

static void blkio_processor_account_process_events(struct blkio_processor *proc,
			struct blkio_process_data *data)
{
	struct blkio_stats stats;

	memset(&stats, 0, sizeof(stats));

	if (!account_events(data->events, data->count, &stats)) {
		struct blkio_pinfo_iter iter;
		struct blkio_record_ctx *ctx = proc->ctx;
		struct blkio_stats_handler *handler = ctx->handler;

		if (blkio_lookup_process_info(proc, data->pid, &iter))
			strncpy(stats.name, iter.info->name, PROC_NAME_LEN);

		stats.pid = data->pid;
		handler->handle(handler, &stats);
	}
	blkio_process_data_free(data);
}

static void __blkio_processor_account_events(struct blkio_processor *proc,
			struct rb_node *node)
{
	while (node) {
		struct blkio_process_data *data = rb_entry(node,
					struct blkio_process_data, node);

		__blkio_processor_account_events(proc, node->rb_left);
		node = node->rb_right;
		blkio_processor_account_process_events(proc, data);
	}
}

static void blkio_processor_account_events(struct blkio_processor *proc)
{
	__blkio_processor_account_events(proc, proc->data.rb_node);
	proc->data.rb_node = 0;
}

static struct blkio_process_data *blkio_processor_get_process_data(
			struct blkio_processor *proc, int pid)
{
	struct rb_node **plink = &proc->data.rb_node;
	struct rb_node *parent = 0;

	while (*plink) {
		struct blkio_process_data *data = rb_entry(*plink,
					struct blkio_process_data, node);

		if (data->pid == pid)
			return data;

		parent = *plink;
		if (data->pid < pid)
			plink = &parent->rb_right;
		else
			plink = &parent->rb_left;
	}

	struct blkio_process_data *data =
			blkio_process_data_alloc(pid, proc->size);

	if (!data)
		return 0;

	rb_link_node(&data->node, parent, plink);
	rb_insert_color(&data->node, &proc->data);
	return data;
}

static void blkio_processor_append_event(struct blkio_processor *proc,
			struct blkio_event_node *event)
{
	struct blkio_process_data *data =
		blkio_processor_get_process_data(proc, event->event.pid);

	if (!data)
		return;

	data->events[data->count++] = event->event;
	if (++proc->count == proc->size) {
		blkio_processor_account_events(proc);
		proc->count = 0;
	}
}

static int blkio_processor_insert_queue(struct blkio_event_node *event,
			struct rb_root *root)
{
	struct rb_node **plink = &root->rb_node;
	struct rb_node *parent = 0;

	while (*plink) {
		struct blkio_event_node *e = rb_entry(*plink,
					struct blkio_event_node, node);

		if (blkio_events_intersect(event, e))
			return -1;

		parent = *plink;
		if (e->event.from < event->event.from)
			plink = &parent->rb_right;
		else
			plink = &parent->rb_left;
	}

	rb_link_node(&event->node, parent, plink);
	rb_insert_color(&event->node, root);
	return 0;
}

static void blkio_processor_handle_queue(struct blkio_processor *proc,
			struct blkio_event_node *event, struct rb_root *root)
{
	if (!blkio_processor_insert_queue(event, root))
		blkio_processor_append_event(proc, event);
	else
		blkio_free_event(event);
}

static void blkio_processor_handle_complete(struct blkio_processor *proc,
			struct blkio_event_node *event, struct rb_root *root)
{
	struct blkio_event_node *first = 0;
	struct rb_node *ptr = root->rb_node;

	while (ptr) {
		struct blkio_event_node *e = rb_entry(ptr,
					struct blkio_event_node, node);

		if (e->event.to <= event->event.from) {
			ptr = ptr->rb_right;
		} else {
			ptr = ptr->rb_left;
			first = e;
		}
	}

	while (first && blkio_events_intersect(first, event)) {
		struct rb_node *next = rb_next(&first->node);
		struct blkio_event_node tmp = *event;

		tmp.event.pid = first->event.pid;

		if (first->event.from >= event->event.from) {
			tmp.event.from = first->event.from;

			if (first->event.to <= event->event.to) {
				tmp.event.to = first->event.to;

				rb_erase(&first->node, root);
				blkio_free_event(first);
			} else {
				first->event.from = event->event.to;
			}
		} else {
			if (first->event.to <= event->event.to) {
				tmp.event.to = first->event.to;
				first->event.to = event->event.from;
			} else {
				struct blkio_event_node *new =
					blkio_alloc_event(&first->event);

				first->event.to = event->event.from;
				if (new) {
					new->event.from = event->event.to;
					blkio_processor_insert_queue(new, root);
				} else {
					fprintf(stderr, "Ran out of memory\n");
				}
			}
		}

		blkio_processor_append_event(proc, &tmp);
		first = 0;
		if (next)
			first = rb_entry(next, struct blkio_event_node, node);
	}
	blkio_free_event(event);
}

static void blkio_processor_handle_event(struct blkio_processor *proc,
			struct blkio_event_node *event)
{
	const int write = IS_WRITE(event->event.type);
	const int queue = IS_QUEUE(event->event.type);

	struct rb_root *root = write ? &proc->writes : &proc->reads;

	if (queue)
		blkio_processor_handle_queue(proc, event, root);
	else
		blkio_processor_handle_complete(proc, event, root);
}

static void __blkio_processor_handle(struct blkio_processor *proc,
			struct blkio_event_node *first, unsigned long long end)
{
	while (first && first->event.time <= end) {
		struct rb_node *next = rb_next(&first->node);

		rb_erase(&first->node, &proc->events);
		blkio_processor_handle_event(proc, first);

		first = 0;
		if (next)
			first = rb_entry(next, struct blkio_event_node, node);
	}
}

static int blkio_processor_handle(struct blkio_processor *proc, int force)
{
	/*
	 * poll_timeout specified with millisecond resolution, while
	 * timestamps use nanosecod resolution
	 */
	const unsigned long long poll_timeout =
				1000000ull * proc->ctx->conf->poll_timeout;
	const unsigned long long min_span = 2 * poll_timeout;

	struct rb_node *f = rb_first(&proc->events);

	if (!f)
		return 0;

	struct blkio_event_node *first = rb_entry(f, struct blkio_event_node,
				node);
	struct blkio_event_node *last = rb_entry(rb_last(&proc->events),
				struct blkio_event_node, node);

	if (!force && last->event.time - first->event.time < min_span)
		return 0;

	__blkio_processor_handle(proc, first,
			force ? ~0ull : first->event.time + poll_timeout);
	return 1;
}

static void *blkio_processor_main(void *data)
{
	struct blkio_processor *proc = data;
	struct blkio_record_ctx *ctx = proc->ctx;
	struct blkio_record_conf *conf = ctx->conf;

	proc->size = conf->events_count;
	blkio_processor_wait(proc);

	while (proc->state == TRACE_RUN) {
		if (blkio_processor_populate(proc)) {
			while (blkio_processor_handle(proc, 0));
			continue;
		}

		const long sec = conf->poll_timeout / 1000;
		const long nsec = 1000000l * (conf->poll_timeout % 1000);
		const struct timespec delay = { sec, nsec };

		nanosleep(&delay, 0);
	}

	blkio_processor_populate(proc);
	blkio_processor_handle(proc, 1);

	blkio_release_events(&proc->events);
	blkio_release_events(&proc->reads);
	blkio_release_events(&proc->writes);
	blkio_release_process_info(&proc->procs);

	return 0;
}

static int blkio_trace_to_cpu(struct blk_io_trace *trace)
{
	if ((trace->magic & 0xFFFFFF00ul) == BLK_IO_TRACE_MAGIC)
		return 0;

	trace->magic = __bswap_32(trace->magic);
	if ((trace->magic & 0xFFFFFF00ul) != BLK_IO_TRACE_MAGIC)
		return -1;

	trace->time = __bswap_64(trace->time);
	trace->sector = __bswap_64(trace->sector);
	trace->bytes = __bswap_32(trace->bytes);
	trace->action = __bswap_32(trace->action);
	trace->pdu_len = __bswap_16(trace->pdu_len);
	trace->pid = __bswap_32(trace->pid);
	return 0;
}

static int blkio_queue_event(struct blk_io_trace *trace)
{
	return ((trace->action & BLK_TC_ACT(BLK_TC_QUEUE)) &&
		((trace->action & 0xFFFFu) == __BLK_TA_QUEUE));
}

static int blkio_complete_event(struct blk_io_trace *trace)
{
	return ((trace->action & BLK_TC_ACT(BLK_TC_COMPLETE)) &&
		((trace->action & 0xFFFFu) == __BLK_TA_COMPLETE));
}

static int blkio_write_event(struct blk_io_trace *trace)
{
	return (trace->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;
}

static int blkio_sync_event(struct blk_io_trace *trace)
{
	return (trace->action & BLK_TC_ACT(BLK_TC_SYNC)) != 0;
}

static int blkio_fua_event(struct blk_io_trace *trace)
{
	return (trace->action & BLK_TC_ACT(BLK_TC_FUA)) != 0;
}

static unsigned blkio_trace_type(struct blk_io_trace *trace)
{
	unsigned type = 0;

	if (blkio_queue_event(trace))
		type |= QUEUE_MASK;
	if (blkio_write_event(trace))
		type |= WRITE_MASK;
	if (blkio_sync_event(trace))
		type |= SYNC_MASK;
	if (blkio_fua_event(trace))
		type |= FUA_MASK;
	return type;
}

static void blkio_submit_traces(struct blkio_tracer *tracer,
			struct blkio_buffer *traces)
{
	if (!traces)
		return;

	if (!traces->count && list_empty(&traces->proc)) {
		blkio_free_buffer(traces);
		return;
	}

	traces->timestamp = traces->data[0].time;
	pthread_mutex_lock(&tracer->lock);
	list_link_before(&tracer->bufs, &traces->link);
	pthread_mutex_unlock(&tracer->lock);
}

static int blkio_accept_trace(struct blk_io_trace *trace)
{
	if (trace->action == BLK_TN_PROCESS)
		return 1;

	if (!trace->bytes)
		return 0;

	return blkio_queue_event(trace) || blkio_complete_event(trace);
}

static void blkio_append_trace(struct blkio_buffer *traces,
			struct blk_io_trace *trace, char *pdu)
{
	if (trace->action == BLK_TN_PROCESS) {
		char kernel[] = "kernel";

		if (trace->pid == 0)
			pdu = kernel;

		char *slash = strchr(pdu, '/');

		if (slash)
			*slash = '\0';

		const int len = strlen(pdu) + 1;
		struct blkio_process_info *info = blkio_process_info_alloc(len);

		if (!info)
			return;

		info->name = (char *)(info + 1);
		info->pid = trace->pid;
		strcpy(info->name, pdu);
		list_link_before(&traces->proc, &info->link);

		return;
	}

	struct blkio_event *event = traces->data + traces->count;

	event->time = trace->time;
	event->from = trace->sector;
	event->to = trace->sector + MAX(1, trace->bytes / 512);
	event->type = blkio_trace_type(trace);
	event->pid = trace->pid;
	++traces->count;
}

static int blkio_read_traces(struct blkio_tracer *tracer,
			char *buffer, size_t *size)
{
	const size_t trace_size = sizeof(struct blk_io_trace);
	const size_t event_size = sizeof(struct blkio_event);
	const size_t buffer_size = tracer->ctx->conf->buffer_size;
	const size_t max_count = buffer_size / event_size;

	struct blk_io_trace trace;

	ssize_t rd = read(tracer->fd, buffer + *size, buffer_size);
	struct blkio_buffer *traces = 0;
	size_t pos = 0;

	while (rd > 0) {
		*size += rd;

		while (*size - pos >= trace_size) {
			if (!traces)
				traces = blkio_alloc_buffer(buffer_size);

			if (!traces)
				return -1;

			memcpy(&trace, buffer + pos, trace_size);

			if (blkio_trace_to_cpu(&trace))
				return -1;

			const size_t skip = trace_size + trace.pdu_len;
			void *pdu = buffer + pos + trace_size;

			if (skip > *size - pos)
				break;

			pos += skip;

			if (!blkio_accept_trace(&trace))
				continue;

			blkio_append_trace(traces, &trace, pdu);
			if (++traces->count == max_count) {
				blkio_submit_traces(tracer, traces);
				traces = 0;
			}
		}

		if (pos != *size)
			memmove(buffer, buffer + pos, *size - pos);
		*size -= pos;
		pos = 0;
		rd = read(tracer->fd, buffer + *size, buffer_size);
	}

	blkio_submit_traces(tracer, traces);
	return 0;
}

static void *blkio_tracer_main(void *data)
{
	struct blkio_tracer *tracer = data;
	struct blkio_record_ctx *ctx = tracer->ctx;
	struct pollfd pollfd;

	char *buffer = malloc(3 * ctx->conf->buffer_size);
	size_t size = 0;

	if (!buffer)
		return 0;

	pthread_setaffinity_np(tracer->thread, sizeof(tracer->cpuset),
			&tracer->cpuset);

	pollfd.fd = tracer->fd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	blkio_tracer_wait(tracer);
	while (tracer->state == TRACE_RUN) {
		const int rc = poll(&pollfd, 1, ctx->conf->poll_timeout);

		if (rc < 0) {
			perror("Poll failed");
			continue;
		}

		if (!(pollfd.revents & POLLIN))
			continue;

		if (blkio_read_traces(tracer, buffer, &size)) {
			// Everything is bad.. We are out of memory...
			free(buffer);
			return 0;
		}
	}

	blkio_read_traces(tracer, buffer, &size);
	free(buffer);
	return 0;
}

static int blkio_trace_open_cpu(struct blkio_record_ctx *ctx, int cpu)
{
	char filename[PATH_MAX + 64];

	const size_t size = snprintf(filename, sizeof(filename),
				"%s/block/%s/trace%d",
				ctx->conf->debugfs,
				ctx->trace_setup.name,
				cpu);

	assert(size < sizeof(filename));

	return open(filename, O_RDONLY | O_NONBLOCK);
}

static int blkio_start_tracer(struct blkio_record_ctx *ctx,
			struct blkio_tracer *tracer, int cpu)
{
	CPU_SET(cpu, &tracer->cpuset);
	tracer->ctx = ctx;
	tracer->fd = blkio_trace_open_cpu(ctx, cpu);
	if (tracer->fd < 0) {
		perror("Cannot open trace file");
		return -1;
	}

	if (pthread_create(&tracer->thread, 0, blkio_tracer_main, tracer)) {
		close(tracer->fd);
		tracer->fd = -1;
		return -1;
	}
	return 0;
}

static int blkio_start_processor(struct blkio_processor *proc)
{
	if (pthread_create(&proc->thread, 0, blkio_processor_main, proc))
		return -1;
	return 0;
}

static void blkio_wait_tracer(struct blkio_tracer *tracer)
{
	assert(!pthread_join(tracer->thread, NULL));
	if (tracer->fd >= 0)
		close(tracer->fd);
	tracer->fd = -1;
}

static void blkio_tracers_set_state(struct blkio_record_ctx *ctx, int state)
{
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;

		pthread_mutex_lock(&tracer->lock);
		tracer->state = state;
		pthread_cond_broadcast(&tracer->cond);
		pthread_mutex_unlock(&tracer->lock);
	}
}

static void blkio_stop_tracers(struct blkio_record_ctx *ctx)
{ blkio_tracers_set_state(ctx, TRACE_STOP); }

static void blkio_run_tracers(struct blkio_record_ctx *ctx)
{ blkio_tracers_set_state(ctx, TRACE_RUN); }

static void blkio_run_processor(struct blkio_record_ctx *ctx)
{
	pthread_mutex_lock(&ctx->processor.lock);
	ctx->processor.state = TRACE_RUN;
	pthread_cond_broadcast(&ctx->processor.cond);
	pthread_mutex_unlock(&ctx->processor.lock);
}

static void blkio_stop_processor(struct blkio_record_ctx *ctx)
{
	pthread_mutex_lock(&ctx->processor.lock);
	ctx->processor.state = TRACE_STOP;
	pthread_cond_broadcast(&ctx->processor.cond);
	pthread_mutex_unlock(&ctx->processor.lock);
}

static void blkio_wait_processor(struct blkio_record_ctx *ctx)
{ assert(!pthread_join(ctx->processor.thread, NULL)); }

static void blkio_wait_tracers(struct blkio_record_ctx *ctx)
{
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;
		blkio_wait_tracer(tracer);
	}
}

static void blkio_destroy_tracers(struct blkio_record_ctx *ctx)
{
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;
		blkio_free_tracer(tracer);
	}
}

static int blkio_create_tracers(struct blkio_record_ctx *ctx)
{
	int rc = 0;

	for (int i = 0; i != ctx->cpus; ++i) {
		struct blkio_tracer *tracer = blkio_alloc_tracer();

		if (!tracer) {
			rc = -1;
			break;
		}

		if (blkio_start_tracer(ctx, tracer, i)) {
			blkio_free_tracer(tracer);
			rc = -1;
			break;
		}

		list_link_before(&ctx->tracers, &tracer->link);
	}

	if (rc) {
		blkio_stop_tracers(ctx);
		blkio_wait_tracers(ctx);
	}

	return rc;
}

static void blkio_destroy_processor(struct blkio_record_ctx *ctx)
{
	assert(!pthread_mutex_destroy(&ctx->processor.lock));
	assert(!pthread_cond_destroy(&ctx->processor.cond));	
}

static int blkio_create_processor(struct blkio_record_ctx *ctx)
{
	memset(&ctx->processor, 0, sizeof(ctx->processor));
	assert(!pthread_mutex_init(&ctx->processor.lock, NULL));
	assert(!pthread_cond_init(&ctx->processor.cond, NULL));
	ctx->processor.state = TRACE_WAIT;
	ctx->processor.ctx = ctx;
	ctx->processor.size = ctx->conf->events_count;
	return blkio_start_processor(&ctx->processor);
}

int blkio_trace_start(struct blkio_record_ctx *ctx)
{
	if (ioctl(ctx->fd, BLKTRACESTART))
		return -1;
	blkio_run_processor(ctx);
	blkio_run_tracers(ctx);
	return 0;
}

void blkio_trace_stop(struct blkio_record_ctx *ctx)
{
	ioctl(ctx->fd, BLKTRACESTOP);
	blkio_stop_tracers(ctx);
	blkio_wait_tracers(ctx);
	blkio_stop_processor(ctx);
	blkio_wait_processor(ctx);
}

void blkio_record_ctx_release(struct blkio_record_ctx *ctx)
{
	blkio_destroy_tracers(ctx);
	blkio_destroy_processor(ctx);
	if (ctx->fd >= 0) {
		ioctl(ctx->fd, BLKTRACESTOP);
		ioctl(ctx->fd, BLKTRACETEARDOWN);
		close(ctx->fd);
	}
}

int blkio_record_ctx_setup(struct blkio_record_ctx *ctx,
			struct blkio_stats_handler *handler,
			struct blkio_record_conf *conf)
{
	memset(ctx, 0, sizeof(*ctx));
	list_head_init(&ctx->tracers);

	ctx->trace_setup.act_mask = BLK_TC_QUEUE | BLK_TC_COMPLETE;
	ctx->trace_setup.buf_size = conf->buffer_size;
	ctx->trace_setup.buf_nr = conf->buffer_count;

	ctx->handler = handler;
	ctx->conf = conf;
	ctx->cpus = -1;
	ctx->fd = -1;

	ctx->cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (ctx->cpus < 0) {
		perror("Cannot get number of cpu");
		blkio_record_ctx_release(ctx);
		return -1;
	}

	ctx->fd = open(conf->device, O_RDONLY | O_NONBLOCK);
	if (ctx->fd < 0) {
		perror("Cannot open block device");
		blkio_record_ctx_release(ctx);
		return -1;
	}

	if (ioctl(ctx->fd, BLKTRACESETUP, &ctx->trace_setup) < 0) {
		perror("BLKTRACESETUP failed");
		blkio_record_ctx_release(ctx);
		return -1;
	}

	if (blkio_create_processor(ctx)) {
		blkio_record_ctx_release(ctx);
		return -1;
	}

	if (blkio_create_tracers(ctx)) {
		blkio_stop_processor(ctx);
		blkio_wait_processor(ctx);
		blkio_record_ctx_release(ctx);
		return -1;
	}

	return 0;
}

int blkio_trace_drops(struct blkio_record_ctx *ctx)
{
	char filename[PATH_MAX + 64];

	const size_t size = snprintf(filename, sizeof(filename),
				"%s/block/%s/dropped",
				ctx->conf->debugfs,
				ctx->trace_setup.name);

	assert(size < sizeof(filename));

	int fd = open(filename, O_RDONLY);

	if (fd < 0) {
		perror("Cannot open drop counter");
		return 0;
	}

	char tmp[256];
	int count = 0;

	memset(tmp, 0, sizeof(tmp));
	if (read(fd, tmp, sizeof(tmp) - 1) < 0)
		perror("Failed to read drop counter");
	else
		count = atoi(tmp);

	close(fd);
	return count;
}
