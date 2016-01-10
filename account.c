#include <stdlib.h>
#include <string.h>

#include "algorithm.h"
#include "account.h"
#include "common.h"
#include "debug.h"


static const unsigned sector_size = 512u;

struct blkio_run {
	const struct blkio_event *first;
	const struct blkio_event *last;
};


static int blkio_event_offset_compare(const struct blkio_event *l,
			const struct blkio_event *r)
{
	if (l->from < r->from)
		return -1;
	if (l->from > r->from)
		return 1;
	return 0;
}

static void blkio_events_sort_by_offset(struct blkio_event *events, size_t size)
{ sort(events, size, &blkio_event_offset_compare); }

static int blkio_run_offset_compare(const struct blkio_run *l,
			const struct blkio_run *r)
{
	if (l->first->from < r->first->from)
		return -1;
	if (l->first->from > r->first->from)
		return 1;
	return 0;
}

static int blkio_run_time_compare(const struct blkio_run *l,
			const struct blkio_run *r)
{
	if (l->first->time < r->first->time)
		return -1;
	if (l->first->time > r->first->time)
		return 1;
	return 0;
}

static void blkio_runs_sort_by_time(struct blkio_run *events, size_t size)
{ sort(events, size, &blkio_run_time_compare); }

static unsigned long long __ci_merge(struct blkio_run *l, size_t lsz,
			struct blkio_run *r, size_t rsz,
			struct blkio_run *buf)
{
	unsigned long long invs = 0;
	size_t i = 0, j = 0;

	while (i != lsz && j != rsz) {
		if (blkio_run_offset_compare(r + j, l + i) < 0) {
			memcpy(buf + i + j, r + j, sizeof(*r));
			invs += lsz - i;
			++j;
		} else {
			memcpy(buf + i + j, l + i, sizeof(*l));
			++i;
		}
	}

	memcpy(buf + i + j, l + i, (lsz - i) * sizeof(*l));
	memcpy(buf + i + j, r + j, (rsz - j) * sizeof(*r));
	return invs;
}

static unsigned long long __ci_merge_sort(struct blkio_run *events,
			size_t size, struct blkio_run *buf)
{
	const size_t half = size / 2;
	unsigned long long invs = 0;

	if (size < 2)
		return 0;

	invs = __ci_merge_sort(events, half, buf);
	invs += __ci_merge_sort(events + half, size - half, buf);
	invs += __ci_merge(events, half, events + half, size - half, buf);
	memcpy(events, buf, size * sizeof(*buf));
	return invs;
}

static unsigned ilog2(unsigned long long x)
{
	unsigned power = 0;

	while (x >>= 1)
		++power;
	return power;
}

static void __account_disk_layout(struct blkio_disk_layout *layout,
			const struct blkio_event *events, size_t size)
{
	__u32 *ss = layout->io_size;
	__u32 *so = layout->io_offset;
	unsigned long long begin, end;
	size_t i;

	if (!size)
		return;

	begin = events[0].from;
	end = events[0].to;
	layout->first_sector = begin;
	for (i = 0; i != size; ++i) {
		const unsigned long long off = events[i].from;
		const unsigned long len = events[i].to - events[i].from;

		if (off > end)
			++so[MIN(1 + ilog2(off - end), IO_OFFSET_BITS - 1)];
		else
			++so[0];

		if (IS_SYNC(events[i].type))
			++layout->sync;
		if (IS_FUA(events[i].type))
			++layout->fua;

		++ss[MIN(ilog2(len), IO_SIZE_BITS - 1)];
		end = MAX(end, off + len);
	}
	layout->last_sector = end;
}

static size_t fill_runs(const struct blkio_event *events, size_t size,
			struct blkio_run *runs,
			struct blkio_disk_layout *layout)
{
	const unsigned long long split_delay = 10000ull;

	unsigned long len, max_len;
	size_t count = 1, i;

	if (!size)
		return 0;

	runs[0].first = runs[0].last = events;
	max_len = len = 1;
	for (i = 1; i != size; ++i) {
		const unsigned long long pend = events[i - 1].to;
		const unsigned long long beg = events[i].from;
		const unsigned long long delay =
			events[i].time - events[i - 1].time;

		if (pend == beg && delay < split_delay) {
			runs[count - 1].last = events + i;
			++len;
			max_len = MAX(max_len, len);
		} else {
			runs[count].first = runs[count].last = events + i;
			++count;
			len = 1;
		}
	}

	layout->seq = count;
	layout->max_len = max_len;
	return count;
}

static int account_disk_layout_stats(struct blkio_stats *stats,
			const struct blkio_event *events, size_t size)
{
	struct blkio_event *buf = calloc(size, sizeof(*events));
	struct blkio_run *runs;
	size_t i, j, k, count, total;

	if (!buf) {
		ERR("Cannot allocate buffer for queue events\n");
		return 1;
	}

	runs = calloc(size * 2, sizeof(*runs));
	if (!runs) {
		ERR("Cannot allocate buffer for event runs\n");
		free(runs);
		free(buf);
		return 1;
	}

	for (i = 0, j = 0; i != size; ++i) {
		const struct blkio_event *e = events + i;

		if (!IS_QUEUE(e->type) || !IS_WRITE(e->type))
			continue;
		memcpy(buf + j++, e, sizeof(*buf));
	}
	total = count = fill_runs(buf, j, runs, &stats->writes_layout);
	blkio_events_sort_by_offset(buf, j);
	__account_disk_layout(&stats->writes_layout, buf, j);

	for (i = 0, k = j; i != size; ++i) {
		const struct blkio_event *e = events + i;

		if (!IS_QUEUE(e->type) || IS_WRITE(e->type))
			continue;
		memcpy(buf + k++, e, sizeof(*buf));
	}
	total += (count = fill_runs(buf + j, k - j, runs + total,
		&stats->reads_layout));
	blkio_events_sort_by_offset(buf + j, k - j);
	__account_disk_layout(&stats->reads_layout, buf + j, k - j);

	blkio_runs_sort_by_time(runs, total);
	stats->inversions = __ci_merge_sort(runs, count, runs + total);

	free(runs);
	free(buf);

	return 0;
}

static int account_general_stats(struct blkio_stats *stats,
			const struct blkio_event *events, size_t size)
{
	unsigned long long begin = ~0ull, end = 0;
	unsigned long long total_iodepth = 0;
	unsigned long reads = 0, writes = 0, queues;
	unsigned long iodepth = 0;
	unsigned long bursts = 0;
	size_t i;

	for (i = 0; i != size; ++i) {
		if (IS_QUEUE(events[i].type)) {
			if (IS_WRITE(events[i].type))
				++writes;
			else
				++reads;

			++iodepth;

			begin = MINU(begin, events[i].time);
			end = MAXU(end, events[i].time);
		} else {
			if (i && IS_QUEUE(events[i - 1].type)) {
				total_iodepth += iodepth;
				++bursts;
			}

			if (iodepth)
				--iodepth;
		}
	}

	queues = reads + writes;
	if (!queues)
		return 0;

	if (iodepth) {
		total_iodepth += iodepth;
		++bursts;
	}

	stats->batch = (queues + bursts - 1) / bursts;
	stats->iodepth = (total_iodepth + bursts - 1) / bursts;

	stats->begin_time = begin;
	stats->end_time = end;
	stats->reads = reads;
	stats->writes = writes;

	return 0;
}

int account_events(const struct blkio_event *events, size_t size,
			struct blkio_stats *stats)
{
	if (!size)
		return 0;

	memset(stats, 0, sizeof(*stats));
	if (account_general_stats(stats, events, size))
		return 1;

	if (account_disk_layout_stats(stats, events, size))
		return 1;

	return 0;
}
