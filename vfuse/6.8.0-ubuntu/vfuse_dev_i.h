/* SPDX-License-Identifier: GPL-2.0
 *
 * VFUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */
#ifndef _FS_VFUSE_DEV_I_H
#define _FS_VFUSE_DEV_I_H

#include <linux/types.h>

struct vfuse_arg;
struct vfuse_args;
struct vfuse_pqueue;
struct vfuse_req;
struct vfuse_iqueue;
struct vfuse_forget_link;

struct vfuse_copy_state {
	int write;
	struct vfuse_req *req;
	struct iov_iter *iter;
	struct pipe_buffer *pipebufs;
	struct pipe_buffer *currbuf;
	struct pipe_inode_info *pipe;
	unsigned long nr_segs;
	struct page *pg;
	unsigned int len;
	unsigned int offset;
	unsigned int move_pages:1;
	unsigned int is_uring:1;
	struct {
		unsigned int copied_sz; /* copied size into the user buffer */
		struct page **pages;
		int page_idx;
	} ring;
};

static inline struct vfuse_dev *vfuse_get_dev(struct file *file)
{
	/*
	 * Lockless access is OK, because file->private data is set
	 * once during mount and is valid until the file is released.
	 */
	return READ_ONCE(file->private_data);
}

unsigned int vfuse_req_hash(u64 unique);
struct vfuse_req *vfuse_request_find(struct vfuse_pqueue *fpq, u64 unique);

void vfuse_dev_end_requests(struct list_head *head);

void vfuse_copy_init(struct vfuse_copy_state *cs, int write,
			   struct iov_iter *iter);
int vfuse_copy_args(struct vfuse_copy_state *cs, unsigned int numargs,
		   unsigned int argpages, struct vfuse_arg *args,
		   int zeroing);
int vfuse_copy_out_args(struct vfuse_copy_state *cs, struct vfuse_args *args,
		       unsigned int nbytes);
void vfuse_dev_queue_forget(struct vfuse_iqueue *fiq,
			   struct vfuse_forget_link *forget);
void vfuse_dev_queue_interrupt(struct vfuse_iqueue *fiq, struct vfuse_req *req);
bool vfuse_remove_pending_req(struct vfuse_req *req, spinlock_t *lock);

#endif

