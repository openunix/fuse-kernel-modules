/*
  VFUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_VFUSE_I_H
#define _FS_VFUSE_I_H

#ifndef pr_fmt
# define pr_fmt(fmt) "vfuse: " fmt
#endif

#include "vfuse.h"
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/kref.h>
#include <linux/xattr.h>
#include <linux/pid_namespace.h>
#include <linux/refcount.h>
#include <linux/user_namespace.h>

/** Default max number of pages that can be used in a single read request */
#define VFUSE_DEFAULT_MAX_PAGES_PER_REQ 32

/** Bias for fi->writectr, meaning new writepages must not be sent */
#define VFUSE_NOWRITE INT_MIN

/** Maximum length of a filename, not including terminating null */

/* maximum, small enough for VFUSE_MIN_READ_BUFFER*/
#define VFUSE_NAME_LOW_MAX 1024
/* maximum, but needs a request buffer > VFUSE_MIN_READ_BUFFER */
#define VFUSE_NAME_MAX (PATH_MAX - 1)

/** Number of dentries for each connection in the control filesystem */
#define VFUSE_CTL_NUM_DENTRIES 5

/** Maximum of max_pages received in init_out */
extern unsigned int vfuse_max_pages_limit;

/* Ordinary requests have even IDs, while interrupts IDs are odd */
#define VFUSE_INT_REQ_BIT (1ULL << 0)
#define VFUSE_REQ_ID_STEP (1ULL << 1)

/** List of active connections */
extern struct list_head vfuse_conn_list;

/** Global mutex protecting vfuse_conn_list and the control filesystem */
extern struct mutex vfuse_mutex;

/** Module parameters */
extern unsigned max_user_bgreq;
extern unsigned max_user_congthresh;

/* One forget request */
struct vfuse_forget_link {
	struct vfuse_forget_one forget_one;
	struct vfuse_forget_link *next;
};

/* Submount lookup tracking */
struct vfuse_submount_lookup {
	/** Refcount */
	refcount_t count;

	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	u64 nodeid;

	/** The request used for sending the FORGET message */
	struct vfuse_forget_link *forget;
};

/** VFUSE inode */
struct vfuse_inode {
	/** Inode data */
	struct inode inode;

	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	u64 nodeid;

	/** Number of lookups on this inode */
	u64 nlookup;

	/** The request used for sending the FORGET message */
	struct vfuse_forget_link *forget;

	/** Time in jiffies until the file attributes are valid */
	u64 i_time;

	/* Which attributes are invalid */
	u32 inval_mask;

	/** The sticky bit in inode->i_mode may have been removed, so
	    preserve the original mode */
	umode_t orig_i_mode;

	/* Cache birthtime */
	struct timespec64 i_btime;

	/** 64 bit inode number */
	u64 orig_ino;

	/** Version of last attribute change */
	u64 attr_version;

	union {
		/* read/write io cache (regular file only) */
		struct {
			/* Files usable in writepage.  Protected by fi->lock */
			struct list_head write_files;

			/* Writepages pending on truncate or fsync */
			struct list_head queued_writes;

			/* Number of sent writes, a negative bias
			 * (VFUSE_NOWRITE) means more writes are blocked */
			int writectr;

			/** Number of files/maps using page cache */
			int iocachectr;

			/* Waitq for writepage completion */
			wait_queue_head_t page_waitq;

			/* waitq for direct-io completion */
			wait_queue_head_t direct_io_waitq;

			/* List of writepage requestst (pending or sent) */
			struct rb_root writepages;
		};

		/* readdir cache (directory only) */
		struct {
			/* true if fully cached */
			bool cached;

			/* size of cache */
			loff_t size;

			/* position at end of cache (position of next entry) */
			loff_t pos;

			/* version of the cache */
			u64 version;

			/* modification time of directory when cache was
			 * started */
			struct timespec64 mtime;

			/* iversion of directory when cache was started */
			u64 iversion;

			/* protects above fields */
			spinlock_t lock;
		} rdc;
	};

	/** Miscellaneous bits describing inode state */
	unsigned long state;

	/** Lock for serializing lookup and readdir for back compatibility*/
	struct mutex mutex;

	/** Lock to protect write related fields */
	spinlock_t lock;

#ifdef CONFIG_FUSE_DAX
	/*
	 * Dax specific inode data
	 */
	struct vfuse_inode_dax *dax;
#endif
	/** Submount specific lookup tracking */
	struct vfuse_submount_lookup *submount_lookup;
};

/** VFUSE inode state bits */
enum {
	/** Advise readdirplus  */
	VFUSE_I_ADVISE_RDPLUS,
	/** Initialized with readdirplus */
	VFUSE_I_INIT_RDPLUS,
	/** An operation changing file size is in progress  */
	VFUSE_I_SIZE_UNSTABLE,
	/* Bad inode */
	VFUSE_I_BAD,
	/* Has btime */
	VFUSE_I_BTIME,
	/* Wants or already has page cache IO */
	VFUSE_I_CACHE_IO_MODE,
};

struct vfuse_conn;
struct vfuse_mount;
struct vfuse_release_args;

/** VFUSE specific file data */
struct vfuse_file {
	/** Fuse connection for this file */
	struct vfuse_mount *fm;

	/* Argument space reserved for release */
	struct vfuse_release_args *release_args;

	/** Kernel file handle guaranteed to be unique */
	u64 kh;

	/** File handle used by userspace */
	u64 fh;

	/** Node id of this file */
	u64 nodeid;

	/** Refcount */
	refcount_t count;

	/** FOPEN_* flags returned by open */
	u32 open_flags;

	/** Entry on inode's write_files list */
	struct list_head write_entry;

	/* Readdir related */
	struct {
		/*
		 * Protects below fields against (crazy) parallel readdir on
		 * same open file.  Uncontended in the normal case.
		 */
		struct mutex lock;

		/* Dir stream position */
		loff_t pos;

		/* Offset in cache */
		loff_t cache_off;

		/* Version of cache we are reading */
		u64 version;

	} readdir;

	/** RB node to be linked on vfuse_conn->polled_files */
	struct rb_node polled_node;

	/** Wait queue head for poll */
	wait_queue_head_t poll_wait;

	/** Does file hold a fi->iocachectr refcount? */
	enum { IOM_NONE, IOM_CACHED, IOM_UNCACHED } iomode;

	/** Has flock been performed on this file? */
	bool flock:1;
};

/** One input argument of a request */
struct vfuse_in_arg {
	unsigned size;
	const void *value;
};

/** One output argument of a request */
struct vfuse_arg {
	unsigned size;
	void *value;
};

/** VFUSE page descriptor */
struct vfuse_page_desc {
	unsigned int length;
	unsigned int offset;
};

struct vfuse_args {
	uint64_t nodeid;
	uint32_t opcode;
	uint8_t in_numargs;
	uint8_t out_numargs;
	uint8_t ext_idx;
	bool force:1;
	bool noreply:1;
	bool nocreds:1;
	bool in_pages:1;
	bool out_pages:1;
	bool user_pages:1;
	bool out_argvar:1;
	bool page_zeroing:1;
	bool page_replace:1;
	bool may_block:1;
	bool is_ext:1;
	bool is_pinned:1;
	struct vfuse_in_arg in_args[4];
	struct vfuse_arg out_args[2];
	void (*end)(struct vfuse_mount *fm, struct vfuse_args *args, int error);
};

struct vfuse_args_pages {
	struct vfuse_args args;
	struct page **pages;
	struct vfuse_page_desc *descs;
	unsigned int num_pages;
};

#define VFUSE_ARGS(args) struct vfuse_args args = {}

/** The request IO state (for asynchronous processing) */
struct vfuse_io_priv {
	struct kref refcnt;
	int async;
	spinlock_t lock;
	unsigned reqs;
	ssize_t bytes;
	size_t size;
	__u64 offset;
	bool write;
	bool should_dirty;
	int err;
	struct kiocb *iocb;
	struct completion *done;
	bool blocking;
};

#define VFUSE_IO_PRIV_SYNC(i) \
{					\
	.refcnt = KREF_INIT(1),		\
	.async = 0,			\
	.iocb = i,			\
}

/**
 * Request flags
 *
 * FR_ISREPLY:		set if the request has reply
 * FR_FORCE:		force sending of the request even if interrupted
 * FR_BACKGROUND:	request is sent in the background
 * FR_WAITING:		request is counted as "waiting"
 * FR_ABORTED:		the request was aborted
 * FR_INTERRUPTED:	the request has been interrupted
 * FR_LOCKED:		data is being copied to/from the request
 * FR_PENDING:		request is not yet in userspace
 * FR_SENT:		request is in userspace, waiting for an answer
 * FR_FINISHED:		request is finished
 * FR_PRIVATE:		request is on private list
 * FR_ASYNC:		request is asynchronous
 * FR_URING:		request is handled through vfuse-io-uring
 */
enum vfuse_req_flag {
	FR_ISREPLY,
	FR_FORCE,
	FR_BACKGROUND,
	FR_WAITING,
	FR_ABORTED,
	FR_INTERRUPTED,
	FR_LOCKED,
	FR_PENDING,
	FR_SENT,
	FR_FINISHED,
	FR_PRIVATE,
	FR_ASYNC,
	FR_URING,
};

/**
 * A request to the client
 *
 * .waitq.lock protects the following fields:
 *   - FR_ABORTED
 *   - FR_LOCKED (may also be modified under fc->lock, tested under both)
 */
struct vfuse_req {
	/** This can be on either pending processing or io lists in
	    vfuse_conn */
	struct list_head list;

	/** Entry on the interrupts list  */
	struct list_head intr_entry;

	/* Input/output arguments */
	struct vfuse_args *args;

	/** refcount */
	refcount_t count;

	/* Request flags, updated with test/set/clear_bit() */
	unsigned long flags;

	/* The request input header */
	struct {
		struct vfuse_in_header h;
	} in;

	/* The request output header */
	struct {
		struct vfuse_out_header h;
	} out;

	/** Used to wake up the task waiting for completion of request*/
	wait_queue_head_t waitq;

#if IS_ENABLED(CONFIG_VIRTIO_FS)
	/** virtio-fs's physically contiguous buffer for in and out args */
	void *argbuf;
#endif

	/** vfuse_mount this request belongs to */
	struct vfuse_mount *fm;

#ifdef CONFIG_VFUSE_IO_URING
	void *ring_entry;
	void *ring_queue;
#endif
};

struct vfuse_iqueue;

/**
 * Input queue callbacks
 *
 * Input queue signalling is device-specific.  For example, the /dev/vfuse file
 * uses fiq->waitq and fasync to wake processes that are waiting on queue
 * readiness.  These callbacks allow other device types to respond to input
 * queue activity.
 */
struct vfuse_iqueue_ops {
	/**
	 * Send one forget
	 */
	void (*send_forget)(struct vfuse_iqueue *fiq, struct vfuse_forget_link *link);

	/**
	 * Send interrupt for request
	 */
	void (*send_interrupt)(struct vfuse_iqueue *fiq, struct vfuse_req *req);

	/**
	 * Send one request
	 */
	void (*send_req)(struct vfuse_iqueue *fiq, struct vfuse_req *req);

	/**
	 * Clean up when vfuse_iqueue is destroyed
	 */
	void (*release)(struct vfuse_iqueue *fiq);
};

/** /dev/vfuse input queue operations */
extern const struct vfuse_iqueue_ops vfuse_dev_fiq_ops;

struct vfuse_iqueue {
	/** Connection established */
	unsigned connected;

	/** Lock protecting accesses to members of this structure */
	spinlock_t lock;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** The next unique request id */
	atomic64_t reqctr;

	/** The list of pending requests */
	struct list_head pending;

	/** Pending interrupts */
	struct list_head interrupts;

	/** Queue of pending forgets */
	struct vfuse_forget_link forget_list_head;
	struct vfuse_forget_link *forget_list_tail;

	/** Batching of FORGET requests (positive indicates FORGET batch) */
	int forget_batch;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;

	/** Device-specific callbacks */
	const struct vfuse_iqueue_ops *ops;

	/** Device-specific state */
	void *priv;
};

#define VFUSE_PQ_HASH_BITS 8
#define VFUSE_PQ_HASH_SIZE (1 << VFUSE_PQ_HASH_BITS)

struct vfuse_pqueue {
	/** Connection established */
	unsigned connected;

	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Hash table of requests being processed */
	struct list_head *processing;

	/** The list of requests under I/O */
	struct list_head io;
};

/**
 * Fuse device instance
 */
struct vfuse_dev {
	/** Fuse connection for this device */
	struct vfuse_conn *fc;

	/** Processing queue */
	struct vfuse_pqueue pq;

	/** list entry on fc->devices */
	struct list_head entry;
};

enum vfuse_dax_mode {
	VFUSE_DAX_INODE_DEFAULT,	/* default */
	VFUSE_DAX_ALWAYS,	/* "-o dax=always" */
	VFUSE_DAX_NEVER,		/* "-o dax=never" */
	VFUSE_DAX_INODE_USER,	/* "-o dax=inode" */
};

static inline bool vfuse_is_inode_dax_mode(enum vfuse_dax_mode mode)
{
	return mode == VFUSE_DAX_INODE_DEFAULT || mode == VFUSE_DAX_INODE_USER;
}

struct vfuse_fs_context {
	int fd;
	struct file *file;
	unsigned int rootmode;
	kuid_t user_id;
	kgid_t group_id;
	bool is_bdev:1;
	bool fd_present:1;
	bool rootmode_present:1;
	bool user_id_present:1;
	bool group_id_present:1;
	bool default_permissions:1;
	bool allow_other:1;
	bool destroy:1;
	bool no_control:1;
	bool no_force_umount:1;
	bool legacy_opts_show:1;
	enum vfuse_dax_mode dax_mode;
	unsigned int max_read;
	unsigned int blksize;
	const char *subtype;

	/* DAX device, may be NULL */
	struct dax_device *dax_dev;

	/* vfuse_dev pointer to fill in, should contain NULL on entry */
	void **fudptr;
};

struct vfuse_sync_bucket {
	/* count is a possible scalability bottleneck */
	atomic_t count;
	wait_queue_head_t waitq;
	struct rcu_head rcu;
};

/**
 * A Fuse connection.
 *
 * This structure is created, when the root filesystem is mounted, and
 * is destroyed, when the client device is closed and the last
 * vfuse_mount is destroyed.
 */
struct vfuse_conn {
	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Refcount */
	refcount_t count;

	/** Number of vfuse_dev's */
	atomic_t dev_count;

	struct rcu_head rcu;

	/** The user id for this mount */
	kuid_t user_id;

	/** The group id for this mount */
	kgid_t group_id;

	/** The pid namespace for this mount */
	struct pid_namespace *pid_ns;

	/** The user namespace for this mount */
	struct user_namespace *user_ns;

	/** Maximum read size */
	unsigned max_read;

	/** Maximum write size */
	unsigned max_write;

	/** Maximum number of pages that can be used in a single request */
	unsigned int max_pages;

	/** Constrain ->max_pages to this value during feature negotiation */
	unsigned int max_pages_limit;

	/** Input queue */
	struct vfuse_iqueue iq;

	/** The next unique kernel file handle */
	atomic64_t khctr;

	/** rbtree of vfuse_files waiting for poll events indexed by ph */
	struct rb_root polled_files;

	/** Maximum number of outstanding background requests */
	unsigned max_background;

	/** Number of background requests at which congestion starts */
	unsigned congestion_threshold;

	/** Number of requests currently in the background */
	unsigned num_background;

	/** Number of background requests currently queued for userspace */
	unsigned active_background;

	/** The list of background requests set aside for later queuing */
	struct list_head bg_queue;

	/** Protects: max_background, congestion_threshold, num_background,
	 * active_background, bg_queue, blocked */
	spinlock_t bg_lock;

	/** Flag indicating that INIT reply has been received. Allocating
	 * any vfuse request will be suspended until the flag is set */
	int initialized;

	/** Flag indicating if connection is blocked.  This will be
	    the case before the INIT reply is received, and if there
	    are too many outstading backgrounds requests */
	int blocked;

	/** waitq for blocked connection */
	wait_queue_head_t blocked_waitq;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;

	/** Connection aborted via sysfs */
	bool aborted;

	/** Connection failed (version mismatch).  Cannot race with
	    setting other bitfields since it is only set once in INIT
	    reply, before any other request, and never cleared */
	unsigned conn_error:1;

	/** Connection successful.  Only set in INIT */
	unsigned conn_init:1;

	/** Do readahead asynchronously?  Only set in INIT */
	unsigned async_read:1;

	/** Return an unique read error after abort.  Only set in INIT */
	unsigned abort_err:1;

	/** Do not send separate SETATTR request before open(O_TRUNC)  */
	unsigned atomic_o_trunc:1;

	/** Filesystem supports NFS exporting.  Only set in INIT */
	unsigned export_support:1;

	/** write-back cache policy (default is write-through) */
	unsigned writeback_cache:1;

	/** allow parallel lookups and readdir (default is serialized) */
	unsigned parallel_dirops:1;

	/** handle fs handles killing suid/sgid/cap on write/chown/trunc */
	unsigned handle_killpriv:1;

	/** cache READLINK responses in page cache */
	unsigned cache_symlinks:1;

	/* show legacy mount options */
	unsigned int legacy_opts_show:1;

	/*
	 * fs kills suid/sgid/cap on write/chown/trunc. suid is killed on
	 * write/trunc only if caller did not have CAP_FSETID.  sgid is killed
	 * on write/truncate only if caller did not have CAP_FSETID as well as
	 * file has group execute permission.
	 */
	unsigned handle_killpriv_v2:1;

	/*
	 * The following bitfields are only for optimization purposes
	 * and hence races in setting them will not cause malfunction
	 */

	/** Is open/release not implemented by fs? */
	unsigned no_open:1;

	/** Is opendir/releasedir not implemented by fs? */
	unsigned no_opendir:1;

	/** Is fsync not implemented by fs? */
	unsigned no_fsync:1;

	/** Is fsyncdir not implemented by fs? */
	unsigned no_fsyncdir:1;

	/** Is flush not implemented by fs? */
	unsigned no_flush:1;

	/** Is setxattr not implemented by fs? */
	unsigned no_setxattr:1;

	/** Does file server support extended setxattr */
	unsigned setxattr_ext:1;

	/** Is getxattr not implemented by fs? */
	unsigned no_getxattr:1;

	/** Is listxattr not implemented by fs? */
	unsigned no_listxattr:1;

	/** Is removexattr not implemented by fs? */
	unsigned no_removexattr:1;

	/** Are posix file locking primitives not implemented by fs? */
	unsigned no_lock:1;

	/** Is access not implemented by fs? */
	unsigned no_access:1;

	/** Is create not implemented by fs? */
	unsigned no_create:1;

	/** Is interrupt not implemented by fs? */
	unsigned no_interrupt:1;

	/** Is bmap not implemented by fs? */
	unsigned no_bmap:1;

	/** Is poll not implemented by fs? */
	unsigned no_poll:1;

	/** Do multi-page cached writes */
	unsigned big_writes:1;

	/** Don't apply umask to creation modes */
	unsigned dont_mask:1;

	/** Are BSD file locking primitives not implemented by fs? */
	unsigned no_flock:1;

	/** Is fallocate not implemented by fs? */
	unsigned no_fallocate:1;

	/** Is rename with flags implemented by fs? */
	unsigned no_rename2:1;

	/** Use enhanced/automatic page cache invalidation. */
	unsigned auto_inval_data:1;

	/** Filesystem is fully responsible for page cache invalidation. */
	unsigned explicit_inval_data:1;

	/** Does the filesystem support readdirplus? */
	unsigned do_readdirplus:1;

	/** Does the filesystem want adaptive readdirplus? */
	unsigned readdirplus_auto:1;

	/** Does the filesystem support asynchronous direct-IO submission? */
	unsigned async_dio:1;

	/** Is lseek not implemented by fs? */
	unsigned no_lseek:1;

	/** Does the filesystem support posix acls? */
	unsigned posix_acl:1;

	/** Check permissions based on the file mode or not? */
	unsigned default_permissions:1;

	/** Allow other than the mounter user to access the filesystem ? */
	unsigned allow_other:1;

	/** Does the filesystem support copy_file_range? */
	unsigned no_copy_file_range:1;

	/* Send DESTROY request */
	unsigned int destroy:1;

	/* Delete dentries that have gone stale */
	unsigned int delete_stale:1;

	/** Do not create entry in vfusectl fs */
	unsigned int no_control:1;

	/** Do not allow MNT_FORCE umount */
	unsigned int no_force_umount:1;

	/* Auto-mount submounts announced by the server */
	unsigned int auto_submounts:1;

	/* Propagate syncfs() to server */
	unsigned int sync_fs:1;

	/* Initialize security xattrs when creating a new inode */
	unsigned int init_security:1;

	/* Add supplementary group info when creating a new inode */
	unsigned int create_supp_group:1;

	/* Does the filesystem support per inode DAX? */
	unsigned int inode_dax:1;

	/* Is tmpfile not implemented by fs? */
	unsigned int no_tmpfile:1;

	/* Relax restrictions to allow shared mmap in FOPEN_DIRECT_IO mode */
	unsigned int direct_io_allow_mmap:1;

	/* Is statx not implemented by fs? */
	unsigned int no_statx:1;

	/* Use io_uring for communication */
	unsigned int io_uring;

	/** The number of requests waiting for completion */
	atomic_t num_waiting;

	/** Negotiated minor version */
	unsigned minor;

	/** Entry on the vfuse_mount_list */
	struct list_head entry;

	/** Device ID from the root super block */
	dev_t dev;

	/** Dentries in the control filesystem */
	struct dentry *ctl_dentry[VFUSE_CTL_NUM_DENTRIES];

	/** number of dentries used in the above array */
	int ctl_ndents;

	/** Key for lock owner ID scrambling */
	u32 scramble_key[4];

	/** Version counter for attribute changes */
	atomic64_t attr_version;

	/** Version counter for evict inode */
	atomic64_t evict_ctr;

	/* maximum file name length */
	u32 name_max;

	/** Called on final put */
	void (*release)(struct vfuse_conn *);

	/**
	 * Read/write semaphore to hold when accessing the sb of any
	 * vfuse_mount belonging to this connection
	 */
	struct rw_semaphore killsb;

	/** List of device instances belonging to this connection */
	struct list_head devices;

#ifdef CONFIG_FUSE_DAX
	/* Dax mode */
	enum vfuse_dax_mode dax_mode;

	/* Dax specific conn data, non-NULL if DAX is enabled */
	struct vfuse_conn_dax *dax;
#endif

	/** List of filesystems using this connection */
	struct list_head mounts;

	/* New writepages go into this bucket */
	struct vfuse_sync_bucket __rcu *curr_bucket;

#ifdef CONFIG_VFUSE_IO_URING
	/**  uring connection information*/
	struct vfuse_ring *ring;
#endif
};

/*
 * Represents a mounted filesystem, potentially a submount.
 *
 * This object allows sharing a vfuse_conn between separate mounts to
 * allow submounts with dedicated superblocks and thus separate device
 * IDs.
 */
struct vfuse_mount {
	/* Underlying (potentially shared) connection to the VFUSE server */
	struct vfuse_conn *fc;

	/*
	 * Super block for this connection (fc->killsb must be held when
	 * accessing this).
	 */
	struct super_block *sb;

	/* Entry on fc->mounts */
	struct list_head fc_entry;
	struct rcu_head rcu;
};

/*
 * Empty header for VFUSE opcodes without specific header needs.
 * Used as a placeholder in args->in_args[0] for consistency
 * across all VFUSE operations, simplifying request handling.
 */
struct vfuse_zero_header {};

static inline void vfuse_set_zero_arg0(struct vfuse_args *args)
{
	args->in_args[0].size = sizeof(struct vfuse_zero_header);
	args->in_args[0].value = NULL;
}

static inline struct vfuse_mount *get_vfuse_mount_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct vfuse_conn *get_vfuse_conn_super(struct super_block *sb)
{
	return get_vfuse_mount_super(sb)->fc;
}

static inline struct vfuse_mount *get_vfuse_mount(struct inode *inode)
{
	return get_vfuse_mount_super(inode->i_sb);
}

static inline struct vfuse_conn *get_vfuse_conn(struct inode *inode)
{
	return get_vfuse_mount_super(inode->i_sb)->fc;
}

static inline struct vfuse_inode *get_vfuse_inode(struct inode *inode)
{
	return container_of(inode, struct vfuse_inode, inode);
}

static inline u64 get_node_id(struct inode *inode)
{
	return get_vfuse_inode(inode)->nodeid;
}

static inline int invalid_nodeid(u64 nodeid)
{
	return !nodeid || nodeid == VFUSE_ROOT_ID;
}

static inline u64 vfuse_get_attr_version(struct vfuse_conn *fc)
{
	return atomic64_read(&fc->attr_version);
}

static inline u64 vfuse_get_evict_ctr(struct vfuse_conn *fc)
{
	return atomic64_read(&fc->evict_ctr);
}

static inline bool vfuse_stale_inode(const struct inode *inode, int generation,
				    struct vfuse_attr *attr)
{
	return inode->i_generation != generation ||
		inode_wrong_type(inode, attr->mode);
}

static inline void vfuse_make_bad(struct inode *inode)
{
	set_bit(VFUSE_I_BAD, &get_vfuse_inode(inode)->state);
}

static inline bool vfuse_is_bad(struct inode *inode)
{
	return unlikely(test_bit(VFUSE_I_BAD, &get_vfuse_inode(inode)->state));
}

static inline struct page **vfuse_pages_alloc(unsigned int npages, gfp_t flags,
					     struct vfuse_page_desc **desc)
{
	struct page **pages;

	pages = kzalloc(npages * (sizeof(struct page *) +
				  sizeof(struct vfuse_page_desc)), flags);
	*desc = (void *) (pages + npages);

	return pages;
}

static inline void vfuse_page_descs_length_init(struct vfuse_page_desc *descs,
					       unsigned int index,
					       unsigned int nr_pages)
{
	int i;

	for (i = index; i < index + nr_pages; i++)
		descs[i].length = PAGE_SIZE - descs[i].offset;
}

static inline void vfuse_sync_bucket_dec(struct vfuse_sync_bucket *bucket)
{
	/* Need RCU protection to prevent use after free after the decrement */
	rcu_read_lock();
	if (atomic_dec_and_test(&bucket->count))
		wake_up(&bucket->waitq);
	rcu_read_unlock();
}

/**
 * Get the next unique ID for a request
 */
static inline u64 vfuse_get_unique(struct vfuse_iqueue *fiq)
{
	return atomic64_add_return(VFUSE_REQ_ID_STEP, &fiq->reqctr);
}

/** Device operations */
extern const struct file_operations vfuse_dev_operations;

extern const struct dentry_operations vfuse_dentry_operations;
extern const struct dentry_operations vfuse_root_dentry_operations;

/**
 * Get a filled in inode
 */
struct inode *vfuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct vfuse_attr *attr,
			u64 attr_valid, u64 attr_version,
			u64 evict_ctr);

int vfuse_lookup_name(struct super_block *sb, u64 nodeid, const struct qstr *name,
		     struct vfuse_entry_out *outarg, struct inode **inode);

/**
 * Send FORGET command
 */
void vfuse_queue_forget(struct vfuse_conn *fc, struct vfuse_forget_link *forget,
		       u64 nodeid, u64 nlookup);

struct vfuse_forget_link *vfuse_alloc_forget(void);

/*
 * Initialize READ or READDIR request
 */
struct vfuse_io_args {
	union {
		struct {
			struct vfuse_read_in in;
			u64 attr_ver;
		} read;
		struct {
			struct vfuse_write_in in;
			struct vfuse_write_out out;
			bool page_locked;
		} write;
	};
	struct vfuse_args_pages ap;
	struct vfuse_io_priv *io;
	struct vfuse_file *ff;
};

void vfuse_read_args_fill(struct vfuse_io_args *ia, struct file *file, loff_t pos,
			 size_t count, int opcode);


struct vfuse_file *vfuse_file_alloc(struct vfuse_mount *fm, bool release);
void vfuse_file_free(struct vfuse_file *ff);
int vfuse_finish_open(struct inode *inode, struct file *file);

void vfuse_sync_release(struct vfuse_inode *fi, struct vfuse_file *ff,
		       unsigned int flags);

/**
 * Send RELEASE or RELEASEDIR request
 */
void vfuse_release_common(struct file *file, bool isdir);

/**
 * Send FSYNC or FSYNCDIR request
 */
int vfuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int opcode);

/**
 * Notify poll wakeup
 */
int vfuse_notify_poll_wakeup(struct vfuse_conn *fc,
			    struct vfuse_notify_poll_wakeup_out *outarg);

/**
 * Initialize file operations on a regular file
 */
void vfuse_init_file_inode(struct inode *inode, unsigned int flags);

/**
 * Initialize inode operations on regular files and special files
 */
void vfuse_init_common(struct inode *inode);

/**
 * Initialize inode and file operations on a directory
 */
void vfuse_init_dir(struct inode *inode);

/**
 * Initialize inode operations on a symlink
 */
void vfuse_init_symlink(struct inode *inode);

/**
 * Change attributes of an inode
 */
void vfuse_change_attributes(struct inode *inode, struct vfuse_attr *attr,
			    struct vfuse_statx *sx,
			    u64 attr_valid, u64 attr_version);

void vfuse_change_attributes_common(struct inode *inode, struct vfuse_attr *attr,
				   struct vfuse_statx *sx,
				   u64 attr_valid, u32 cache_mask,
				   u64 evict_ctr);

u32 vfuse_get_cache_mask(struct inode *inode);

/**
 * Initialize the client device
 */
int vfuse_dev_init(void);

/**
 * Cleanup the client device
 */
void vfuse_dev_cleanup(void);

int vfuse_ctl_init(void);
void __exit vfuse_ctl_cleanup(void);

/**
 * Simple request sending that does request allocation and freeing
 */
ssize_t vfuse_simple_request(struct vfuse_mount *fm, struct vfuse_args *args);
int vfuse_simple_background(struct vfuse_mount *fm, struct vfuse_args *args,
			   gfp_t gfp_flags);

/**
 * End a finished request
 */
void vfuse_request_end(struct vfuse_req *req);

/* Abort all requests */
void vfuse_abort_conn(struct vfuse_conn *fc);
void vfuse_wait_aborted(struct vfuse_conn *fc);

/**
 * Invalidate inode attributes
 */

/* Attributes possibly changed on data modification */
#define VFUSE_STATX_MODIFY	(STATX_MTIME | STATX_CTIME | STATX_BLOCKS)

/* Attributes possibly changed on data and/or size modification */
#define VFUSE_STATX_MODSIZE	(VFUSE_STATX_MODIFY | STATX_SIZE)

void vfuse_invalidate_attr(struct inode *inode);
void vfuse_invalidate_attr_mask(struct inode *inode, u32 mask);

void vfuse_invalidate_entry_cache(struct dentry *entry);

void vfuse_invalidate_atime(struct inode *inode);

u64 vfuse_time_to_jiffies(u64 sec, u32 nsec);
#define ATTR_TIMEOUT(o) \
	vfuse_time_to_jiffies((o)->attr_valid, (o)->attr_valid_nsec)

void vfuse_change_entry_timeout(struct dentry *entry, struct vfuse_entry_out *o);

/**
 * Acquire reference to vfuse_conn
 */
struct vfuse_conn *vfuse_conn_get(struct vfuse_conn *fc);

/**
 * Initialize the vfuse processing queue
 */
void vfuse_pqueue_init(struct vfuse_pqueue *fpq);

/**
 * Initialize vfuse_conn
 */
void vfuse_conn_init(struct vfuse_conn *fc, struct vfuse_mount *fm,
		    struct user_namespace *user_ns,
		    const struct vfuse_iqueue_ops *fiq_ops, void *fiq_priv);

/**
 * Release reference to vfuse_conn
 */
void vfuse_conn_put(struct vfuse_conn *fc);

struct vfuse_dev *vfuse_dev_alloc_install(struct vfuse_conn *fc);
struct vfuse_dev *vfuse_dev_alloc(void);
void vfuse_dev_install(struct vfuse_dev *fud, struct vfuse_conn *fc);
void vfuse_dev_free(struct vfuse_dev *fud);
void vfuse_send_init(struct vfuse_mount *fm);

/**
 * Fill in superblock and initialize vfuse connection
 * @sb: partially-initialized superblock to fill in
 * @ctx: mount context
 */
int vfuse_fill_super_common(struct super_block *sb, struct vfuse_fs_context *ctx);

/*
 * Remove the mount from the connection
 *
 * Returns whether this was the last mount
 */
bool vfuse_mount_remove(struct vfuse_mount *fm);

/*
 * Setup context ops for submounts
 */
int vfuse_init_fs_context_submount(struct fs_context *fsc);

/*
 * Shut down the connection (possibly sending DESTROY request).
 */
void vfuse_conn_destroy(struct vfuse_mount *fm);

/* Drop the connection and free the vfuse mount */
void vfuse_mount_destroy(struct vfuse_mount *fm);

/**
 * Add connection to control filesystem
 */
int vfuse_ctl_add_conn(struct vfuse_conn *fc);

/**
 * Remove connection from control filesystem
 */
void vfuse_ctl_remove_conn(struct vfuse_conn *fc);

/**
 * Is file type valid?
 */
int vfuse_valid_type(int m);

bool vfuse_invalid_attr(struct vfuse_attr *attr);

/**
 * Is current process allowed to perform filesystem operation?
 */
bool vfuse_allow_current_process(struct vfuse_conn *fc);

u64 vfuse_lock_owner_id(struct vfuse_conn *fc, fl_owner_t id);

void vfuse_flush_time_update(struct inode *inode);
void vfuse_update_ctime(struct inode *inode);

int vfuse_update_attributes(struct inode *inode, struct file *file, u32 mask);

void vfuse_flush_writepages(struct inode *inode);

void vfuse_set_nowrite(struct inode *inode);
void vfuse_release_nowrite(struct inode *inode);

/**
 * Scan all vfuse_mounts belonging to fc to find the first where
 * ilookup5() returns a result.  Return that result and the
 * respective vfuse_mount in *fm (unless fm is NULL).
 *
 * The caller must hold fc->killsb.
 */
struct inode *vfuse_ilookup(struct vfuse_conn *fc, u64 nodeid,
			   struct vfuse_mount **fm);

/**
 * File-system tells the kernel to invalidate cache for the given node id.
 */
int vfuse_reverse_inval_inode(struct vfuse_conn *fc, u64 nodeid,
			     loff_t offset, loff_t len);

/**
 * File-system tells the kernel to invalidate parent attributes and
 * the dentry matching parent/name.
 *
 * If the child_nodeid is non-zero and:
 *    - matches the inode number for the dentry matching parent/name,
 *    - is not a mount point
 *    - is a file or oan empty directory
 * then the dentry is unhashed (d_delete()).
 */
int vfuse_reverse_inval_entry(struct vfuse_conn *fc, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name, u32 flags);

int vfuse_do_open(struct vfuse_mount *fm, u64 nodeid, struct file *file,
		 bool isdir);

/**
 * vfuse_direct_io() flags
 */

/** If set, it is WRITE; otherwise - READ */
#define VFUSE_DIO_WRITE (1 << 0)

/** CUSE pass vfuse_direct_io() a file which f_mapping->host is not from VFUSE */
#define VFUSE_DIO_CUSE  (1 << 1)

ssize_t vfuse_direct_io(struct vfuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags);
long vfuse_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags);
long vfuse_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags);
__poll_t vfuse_file_poll(struct file *file, poll_table *wait);
int vfuse_dev_release(struct inode *inode, struct file *file);

bool vfuse_write_update_attr(struct inode *inode, loff_t pos, ssize_t written);

int vfuse_flush_times(struct inode *inode, struct vfuse_file *ff);
int vfuse_write_inode(struct inode *inode, struct writeback_control *wbc);

int vfuse_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file);

void vfuse_set_initialized(struct vfuse_conn *fc);

void vfuse_unlock_inode(struct inode *inode, bool locked);
bool vfuse_lock_inode(struct inode *inode);

int vfuse_setxattr(struct inode *inode, const char *name, const void *value,
		  size_t size, int flags, unsigned int extra_flags);
ssize_t vfuse_getxattr(struct inode *inode, const char *name, void *value,
		      size_t size);
ssize_t vfuse_listxattr(struct dentry *entry, char *list, size_t size);
int vfuse_removexattr(struct inode *inode, const char *name);
extern const struct xattr_handler * const vfuse_xattr_handlers[];

struct posix_acl;
struct posix_acl *vfuse_get_inode_acl(struct inode *inode, int type, bool rcu);
struct posix_acl *vfuse_get_acl(struct mnt_idmap *idmap,
			       struct dentry *dentry, int type);
int vfuse_set_acl(struct mnt_idmap *, struct dentry *dentry,
		 struct posix_acl *acl, int type);

/* readdir.c */
int vfuse_readdir(struct file *file, struct dir_context *ctx);

/**
 * Return the number of bytes in an arguments list
 */
unsigned int vfuse_len_args(unsigned int numargs, struct vfuse_arg *args);

void vfuse_free_conn(struct vfuse_conn *fc);

/* dax.c */

#define VFUSE_IS_DAX(inode) (IS_ENABLED(CONFIG_FUSE_DAX) && IS_DAX(inode))

ssize_t vfuse_dax_read_iter(struct kiocb *iocb, struct iov_iter *to);
ssize_t vfuse_dax_write_iter(struct kiocb *iocb, struct iov_iter *from);
int vfuse_dax_mmap(struct file *file, struct vm_area_struct *vma);
int vfuse_dax_break_layouts(struct inode *inode, u64 dmap_start, u64 dmap_end);
int vfuse_dax_conn_alloc(struct vfuse_conn *fc, enum vfuse_dax_mode mode,
			struct dax_device *dax_dev);
void vfuse_dax_conn_free(struct vfuse_conn *fc);
bool vfuse_dax_inode_alloc(struct super_block *sb, struct vfuse_inode *fi);
void vfuse_dax_inode_init(struct inode *inode, unsigned int flags);
void vfuse_dax_inode_cleanup(struct inode *inode);
void vfuse_dax_dontcache(struct inode *inode, unsigned int flags);
bool vfuse_dax_check_alignment(struct vfuse_conn *fc, unsigned int map_alignment);
void vfuse_dax_cancel_work(struct vfuse_conn *fc);

/* ioctl.c */
long vfuse_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
long vfuse_file_compat_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg);
int vfuse_fileattr_get(struct dentry *dentry, struct fileattr *fa);
int vfuse_fileattr_set(struct mnt_idmap *idmap,
		      struct dentry *dentry, struct fileattr *fa);

/* iomode.c */
int vfuse_file_cached_io_start(struct inode *inode, struct vfuse_file *ff);
int vfuse_file_uncached_io_start(struct inode *inode, struct vfuse_file *ff);
void vfuse_file_uncached_io_end(struct inode *inode, struct vfuse_file *ff);

int vfuse_file_io_open(struct file *file, struct inode *inode);
void vfuse_file_io_release(struct vfuse_file *ff, struct inode *inode);

/* file.c */
struct vfuse_file *vfuse_file_open(struct vfuse_mount *fm, u64 nodeid,
				 unsigned int open_flags, bool isdir);
void vfuse_file_release(struct inode *inode, struct vfuse_file *ff,
		       unsigned int open_flags, fl_owner_t id, bool isdir);

#ifdef CONFIG_SYSCTL
extern int vfuse_sysctl_register(void);
extern void vfuse_sysctl_unregister(void);
#else
#define vfuse_sysctl_register()		(0)
#define vfuse_sysctl_unregister()	do { } while (0)
#endif /* CONFIG_SYSCTL */

#endif /* _FS_VFUSE_I_H */
