/* SPDX-License-Identifier: GPL-2.0
 *
 * VFUSE: Filesystem in Userspace
 * Copyright (c) 2023-2024 DataDirect Networks.
 */

#ifndef _FS_VFUSE_DEV_URING_I_H
#define _FS_VFUSE_DEV_URING_I_H

#include "vfuse_i.h"

#ifdef CONFIG_VFUSE_IO_URING

#define VFUSE_URING_TEARDOWN_TIMEOUT (5 * HZ)
#define VFUSE_URING_TEARDOWN_INTERVAL (HZ/20)

enum vfuse_ring_req_state {
	FRRS_INVALID = 0,

	/* The ring entry received from userspace and it is being processed */
	FRRS_COMMIT,

	/* The ring entry is waiting for new vfuse requests */
	FRRS_AVAILABLE,

	/* The ring entry got assigned a vfuse req */
	FRRS_VFUSE_REQ,

	/* The ring entry is in or on the way to user space */
	FRRS_USERSPACE,

	/* The ring entry is in teardown */
	FRRS_TEARDOWN,

	/* The ring entry is released, but not freed yet */
	FRRS_RELEASED,
};

/** A vfuse ring entry, part of the ring queue */
struct vfuse_ring_ent {
	/* userspace buffer */
	struct vfuse_uring_req_header __user *headers;
	struct page **header_pages;
	int nr_header_pages;
	void __user *payload;
	struct page **payload_pages;
	int nr_payload_pages;

	/* the ring queue that owns the request */
	struct vfuse_ring_queue *queue;

	/* fields below are protected by queue->lock */

	struct io_uring_cmd *cmd;

	struct list_head list;

	enum vfuse_ring_req_state state;

	struct vfuse_req *vfuse_req;
};

struct vfuse_ring_queue {
	/*
	 * back pointer to the main vfuse uring structure that holds this
	 * queue
	 */
	struct vfuse_ring *ring;

	/* queue id, corresponds to the cpu core */
	unsigned int qid;

	/*
	 * queue lock, taken when any value in the queue changes _and_ also
	 * a ring entry state changes.
	 */
	spinlock_t lock;

	/* available ring entries (struct vfuse_ring_ent) */
	struct list_head ent_avail_queue;

	/*
	 * entries in the process of being committed or in the process
	 * to be sent to userspace
	 */
	struct list_head ent_w_req_queue;
	struct list_head ent_commit_queue;

	/* entries in userspace */
	struct list_head ent_in_userspace;

	/* entries that are released */
	struct list_head ent_released;

	/* vfuse requests waiting for an entry slot */
	struct list_head vfuse_req_queue;

	/* background vfuse requests */
	struct list_head vfuse_req_bg_queue;

	struct vfuse_pqueue fpq;

	unsigned int active_background;

	bool stopped;
};

/**
 * Describes if uring is for communication and holds alls the data needed
 * for uring communication
 */
struct vfuse_ring {
	/* back pointer */
	struct vfuse_conn *fc;

	/* number of ring queues */
	size_t nr_queues;

	/* maximum payload/arg size */
	size_t max_payload_sz;

	struct vfuse_ring_queue **queues;

	/*
	 * Log ring entry states on stop when entries cannot be released
	 */
	unsigned int stop_debug_log : 1;

	wait_queue_head_t stop_waitq;

	/* async tear down */
	struct delayed_work async_teardown_work;

	/* log */
	unsigned long teardown_time;

	atomic_t queue_refs;

	bool ready;
};

bool vfuse_uring_enabled(void);
void vfuse_uring_destruct(struct vfuse_conn *fc);
void vfuse_uring_stop_queues(struct vfuse_ring *ring);
void vfuse_uring_abort_end_requests(struct vfuse_ring *ring);
int vfuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags);
void vfuse_uring_queue_vfuse_req(struct vfuse_iqueue *fiq, struct vfuse_req *req);
bool vfuse_uring_queue_bq_req(struct vfuse_req *req);
bool vfuse_uring_remove_pending_req(struct vfuse_req *req);

static inline void vfuse_uring_abort(struct vfuse_conn *fc)
{
	struct vfuse_ring *ring = fc->ring;

	if (ring == NULL)
		return;

	if (atomic_read(&ring->queue_refs) > 0) {
		vfuse_uring_abort_end_requests(ring);
		vfuse_uring_stop_queues(ring);
	}
}

static inline void vfuse_uring_wait_stopped_queues(struct vfuse_conn *fc)
{
	struct vfuse_ring *ring = fc->ring;

	if (ring)
		wait_event(ring->stop_waitq,
			   atomic_read(&ring->queue_refs) == 0);
}

static inline bool vfuse_uring_ready(struct vfuse_conn *fc)
{
	return fc->ring && fc->ring->ready;
}

#else /* CONFIG_VFUSE_IO_URING */

static inline void vfuse_uring_destruct(struct vfuse_conn *fc)
{
}

static inline bool vfuse_uring_enabled(void)
{
	return false;
}

static inline void vfuse_uring_abort(struct vfuse_conn *fc)
{
}

static inline void vfuse_uring_wait_stopped_queues(struct vfuse_conn *fc)
{
}

static inline bool vfuse_uring_ready(struct vfuse_conn *fc)
{
	return false;
}

static inline bool vfuse_uring_remove_pending_req(struct vfuse_req *req)
{
	return false;
}

#endif /* CONFIG_VFUSE_IO_URING */

#endif /* _FS_VFUSE_DEV_URING_I_H */
