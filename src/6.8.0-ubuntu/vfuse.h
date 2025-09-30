/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
    This file defines the kernel interface of VFUSE
    Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    This -- and only this -- header file may also be distributed under
    the terms of the BSD Licence as follows:

    Copyright (C) 2001-2007 Miklos Szeredi. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.
*/

/*
 * This file defines the kernel interface of VFUSE
 *
 * Protocol changelog:
 *
 * 7.1:
 *  - add the following messages:
 *      VFUSE_SETATTR, VFUSE_SYMLINK, VFUSE_MKNOD, VFUSE_MKDIR, VFUSE_UNLINK,
 *      VFUSE_RMDIR, VFUSE_RENAME, VFUSE_LINK, VFUSE_OPEN, VFUSE_READ, VFUSE_WRITE,
 *      VFUSE_RELEASE, VFUSE_FSYNC, VFUSE_FLUSH, VFUSE_SETXATTR, VFUSE_GETXATTR,
 *      VFUSE_LISTXATTR, VFUSE_REMOVEXATTR, VFUSE_OPENDIR, VFUSE_READDIR,
 *      VFUSE_RELEASEDIR
 *  - add padding to messages to accommodate 32-bit servers on 64-bit kernels
 *
 * 7.2:
 *  - add FOPEN_DIRECT_IO and FOPEN_KEEP_CACHE flags
 *  - add VFUSE_FSYNCDIR message
 *
 * 7.3:
 *  - add VFUSE_ACCESS message
 *  - add VFUSE_CREATE message
 *  - add filehandle to vfuse_setattr_in
 *
 * 7.4:
 *  - add frsize to vfuse_kstatfs
 *  - clean up request size limit checking
 *
 * 7.5:
 *  - add flags and max_write to vfuse_init_out
 *
 * 7.6:
 *  - add max_readahead to vfuse_init_in and vfuse_init_out
 *
 * 7.7:
 *  - add VFUSE_INTERRUPT message
 *  - add POSIX file lock support
 *
 * 7.8:
 *  - add lock_owner and flags fields to vfuse_release_in
 *  - add VFUSE_BMAP message
 *  - add VFUSE_DESTROY message
 *
 * 7.9:
 *  - new vfuse_getattr_in input argument of GETATTR
 *  - add lk_flags in vfuse_lk_in
 *  - add lock_owner field to vfuse_setattr_in, vfuse_read_in and vfuse_write_in
 *  - add blksize field to vfuse_attr
 *  - add file flags field to vfuse_read_in and vfuse_write_in
 *  - Add ATIME_NOW and MTIME_NOW flags to vfuse_setattr_in
 *
 * 7.10
 *  - add nonseekable open flag
 *
 * 7.11
 *  - add IOCTL message
 *  - add unsolicited notification support
 *  - add POLL message and NOTIFY_POLL notification
 *
 * 7.12
 *  - add umask flag to input argument of create, mknod and mkdir
 *  - add notification messages for invalidation of inodes and
 *    directory entries
 *
 * 7.13
 *  - make max number of background requests and congestion threshold
 *    tunables
 *
 * 7.14
 *  - add splice support to vfuse device
 *
 * 7.15
 *  - add store notify
 *  - add retrieve notify
 *
 * 7.16
 *  - add BATCH_FORGET request
 *  - VFUSE_IOCTL_UNRESTRICTED shall now return with array of 'struct
 *    vfuse_ioctl_iovec' instead of ambiguous 'struct iovec'
 *  - add VFUSE_IOCTL_32BIT flag
 *
 * 7.17
 *  - add VFUSE_FLOCK_LOCKS and VFUSE_RELEASE_FLOCK_UNLOCK
 *
 * 7.18
 *  - add VFUSE_IOCTL_DIR flag
 *  - add VFUSE_NOTIFY_DELETE
 *
 * 7.19
 *  - add VFUSE_FALLOCATE
 *
 * 7.20
 *  - add VFUSE_AUTO_INVAL_DATA
 *
 * 7.21
 *  - add VFUSE_READDIRPLUS
 *  - send the requested events in POLL request
 *
 * 7.22
 *  - add VFUSE_ASYNC_DIO
 *
 * 7.23
 *  - add VFUSE_WRITEBACK_CACHE
 *  - add time_gran to vfuse_init_out
 *  - add reserved space to vfuse_init_out
 *  - add FATTR_CTIME
 *  - add ctime and ctimensec to vfuse_setattr_in
 *  - add VFUSE_RENAME2 request
 *  - add VFUSE_NO_OPEN_SUPPORT flag
 *
 *  7.24
 *  - add VFUSE_LSEEK for SEEK_HOLE and SEEK_DATA support
 *
 *  7.25
 *  - add VFUSE_PARALLEL_DIROPS
 *
 *  7.26
 *  - add VFUSE_HANDLE_KILLPRIV
 *  - add VFUSE_POSIX_ACL
 *
 *  7.27
 *  - add VFUSE_ABORT_ERROR
 *
 *  7.28
 *  - add VFUSE_COPY_FILE_RANGE
 *  - add FOPEN_CACHE_DIR
 *  - add VFUSE_MAX_PAGES, add max_pages to init_out
 *  - add VFUSE_CACHE_SYMLINKS
 *
 *  7.29
 *  - add VFUSE_NO_OPENDIR_SUPPORT flag
 *
 *  7.30
 *  - add VFUSE_EXPLICIT_INVAL_DATA
 *  - add VFUSE_IOCTL_COMPAT_X32
 *
 *  7.31
 *  - add VFUSE_WRITE_KILL_PRIV flag
 *  - add VFUSE_SETUPMAPPING and VFUSE_REMOVEMAPPING
 *  - add map_alignment to vfuse_init_out, add VFUSE_MAP_ALIGNMENT flag
 *
 *  7.32
 *  - add flags to vfuse_attr, add VFUSE_ATTR_SUBMOUNT, add VFUSE_SUBMOUNTS
 *
 *  7.33
 *  - add VFUSE_HANDLE_KILLPRIV_V2, VFUSE_WRITE_KILL_SUIDGID, FATTR_KILL_SUIDGID
 *  - add VFUSE_OPEN_KILL_SUIDGID
 *  - extend vfuse_setxattr_in, add VFUSE_SETXATTR_EXT
 *  - add VFUSE_SETXATTR_ACL_KILL_SGID
 *
 *  7.34
 *  - add VFUSE_SYNCFS
 *
 *  7.35
 *  - add FOPEN_NOFLUSH
 *
 *  7.36
 *  - extend vfuse_init_in with reserved fields, add VFUSE_INIT_EXT init flag
 *  - add flags2 to vfuse_init_in and vfuse_init_out
 *  - add VFUSE_SECURITY_CTX init flag
 *  - add security context to create, mkdir, symlink, and mknod requests
 *  - add VFUSE_HAS_INODE_DAX, VFUSE_ATTR_DAX
 *
 *  7.37
 *  - add VFUSE_TMPFILE
 *
 *  7.38
 *  - add VFUSE_EXPIRE_ONLY flag to vfuse_notify_inval_entry
 *  - add FOPEN_PARALLEL_DIRECT_WRITES
 *  - add total_extlen to vfuse_in_header
 *  - add VFUSE_MAX_NR_SECCTX
 *  - add extension header
 *  - add VFUSE_EXT_GROUPS
 *  - add VFUSE_CREATE_SUPP_GROUP
 *  - add VFUSE_HAS_EXPIRE_ONLY
 *
 *  7.39
 *  - add VFUSE_DIRECT_IO_ALLOW_MMAP
 *  - add VFUSE_STATX and related structures
*
  *  7.40
 *  - add max_stack_depth to vfuse_init_out, add VFUSE_PASSTHROUGH init flag
 *  - add backing_id to vfuse_open_out, add FOPEN_PASSTHROUGH open flag
 *  - add VFUSE_NO_EXPORT_SUPPORT init flag
 *
 *  7.42
 *  - Add VFUSE_OVER_IO_URING and all other io-uring related flags and data
 *    structures:
 *    - struct vfuse_uring_ent_in_out
 *    - struct vfuse_uring_req_header
 *    - struct vfuse_uring_cmd_req
 *    - VFUSE_URING_IN_OUT_HEADER_SZ
 *    - VFUSE_URING_OP_IN_OUT_SZ
 *    - enum vfuse_uring_cmd
 */

#ifndef _LINUX_VFUSE_H
#define _LINUX_VFUSE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/*
 * Version negotiation:
 *
 * Both the kernel and userspace send the version they support in the
 * INIT request and reply respectively.
 *
 * If the major versions match then both shall use the smallest
 * of the two minor versions for communication.
 *
 * If the kernel supports a larger major version, then userspace shall
 * reply with the major version it supports, ignore the rest of the
 * INIT message and expect a new INIT message from the kernel with a
 * matching major version.
 *
 * If the library supports a larger major version, then it shall fall
 * back to the major protocol version sent by the kernel for
 * communication and reply with that major version (and an arbitrary
 * supported minor version).
 */

/** Version number of this interface */
#define VFUSE_KERNEL_VERSION 7

/** Minor version number of this interface */
#define VFUSE_KERNEL_MINOR_VERSION 39

/** The node ID of the root inode */
#define VFUSE_ROOT_ID 1

/* Make sure all structures are padded to 64bit boundary, so 32bit
   userspace works under 64bit kernels */

struct vfuse_attr {
	uint64_t	ino;
	uint64_t	size;
	uint64_t	blocks;
	uint64_t	atime;
	uint64_t	mtime;
	uint64_t	ctime;
	uint32_t	atimensec;
	uint32_t	mtimensec;
	uint32_t	ctimensec;
	uint32_t	mode;
	uint32_t	nlink;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	rdev;
	uint32_t	blksize;
	uint32_t	flags;
};

/*
 * The following structures are bit-for-bit compatible with the statx(2) ABI in
 * Linux.
 */
struct vfuse_sx_time {
	int64_t		tv_sec;
	uint32_t	tv_nsec;
	int32_t		__reserved;
};

struct vfuse_statx {
	uint32_t	mask;
	uint32_t	blksize;
	uint64_t	attributes;
	uint32_t	nlink;
	uint32_t	uid;
	uint32_t	gid;
	uint16_t	mode;
	uint16_t	__spare0[1];
	uint64_t	ino;
	uint64_t	size;
	uint64_t	blocks;
	uint64_t	attributes_mask;
	struct vfuse_sx_time	atime;
	struct vfuse_sx_time	btime;
	struct vfuse_sx_time	ctime;
	struct vfuse_sx_time	mtime;
	uint32_t	rdev_major;
	uint32_t	rdev_minor;
	uint32_t	dev_major;
	uint32_t	dev_minor;
	uint64_t	__spare2[14];
};

struct vfuse_kstatfs {
	uint64_t	blocks;
	uint64_t	bfree;
	uint64_t	bavail;
	uint64_t	files;
	uint64_t	ffree;
	uint32_t	bsize;
	uint32_t	namelen;
	uint32_t	frsize;
	uint32_t	padding;
	uint32_t	spare[6];
};

struct vfuse_file_lock {
	uint64_t	start;
	uint64_t	end;
	uint32_t	type;
	uint32_t	pid; /* tgid */
};

/**
 * Bitmasks for vfuse_setattr_in.valid
 */
#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_ATIME	(1 << 4)
#define FATTR_MTIME	(1 << 5)
#define FATTR_FH	(1 << 6)
#define FATTR_ATIME_NOW	(1 << 7)
#define FATTR_MTIME_NOW	(1 << 8)
#define FATTR_LOCKOWNER	(1 << 9)
#define FATTR_CTIME	(1 << 10)
#define FATTR_KILL_SUIDGID	(1 << 11)

/**
 * Flags returned by the OPEN request
 *
 * FOPEN_DIRECT_IO: bypass page cache for this open file
 * FOPEN_KEEP_CACHE: don't invalidate the data cache on open
 * FOPEN_NONSEEKABLE: the file is not seekable
 * FOPEN_CACHE_DIR: allow caching this directory
 * FOPEN_STREAM: the file is stream-like (no file position at all)
 * FOPEN_NOFLUSH: don't flush data cache on close (unless VFUSE_WRITEBACK_CACHE)
 * FOPEN_PARALLEL_DIRECT_WRITES: Allow concurrent direct writes on the same inode
 */
#define FOPEN_DIRECT_IO		(1 << 0)
#define FOPEN_KEEP_CACHE	(1 << 1)
#define FOPEN_NONSEEKABLE	(1 << 2)
#define FOPEN_CACHE_DIR		(1 << 3)
#define FOPEN_STREAM		(1 << 4)
#define FOPEN_NOFLUSH		(1 << 5)
#define FOPEN_PARALLEL_DIRECT_WRITES	(1 << 6)

/**
 * INIT request/reply flags
 *
 * VFUSE_ASYNC_READ: asynchronous read requests
 * VFUSE_POSIX_LOCKS: remote locking for POSIX file locks
 * VFUSE_FILE_OPS: kernel sends file handle for fstat, etc... (not yet supported)
 * VFUSE_ATOMIC_O_TRUNC: handles the O_TRUNC open flag in the filesystem
 * VFUSE_EXPORT_SUPPORT: filesystem handles lookups of "." and ".."
 * VFUSE_BIG_WRITES: filesystem can handle write size larger than 4kB
 * VFUSE_DONT_MASK: don't apply umask to file mode on create operations
 * VFUSE_SPLICE_WRITE: kernel supports splice write on the device
 * VFUSE_SPLICE_MOVE: kernel supports splice move on the device
 * VFUSE_SPLICE_READ: kernel supports splice read on the device
 * VFUSE_FLOCK_LOCKS: remote locking for BSD style file locks
 * VFUSE_HAS_IOCTL_DIR: kernel supports ioctl on directories
 * VFUSE_AUTO_INVAL_DATA: automatically invalidate cached pages
 * VFUSE_DO_READDIRPLUS: do READDIRPLUS (READDIR+LOOKUP in one)
 * VFUSE_READDIRPLUS_AUTO: adaptive readdirplus
 * VFUSE_ASYNC_DIO: asynchronous direct I/O submission
 * VFUSE_WRITEBACK_CACHE: use writeback cache for buffered writes
 * VFUSE_NO_OPEN_SUPPORT: kernel supports zero-message opens
 * VFUSE_PARALLEL_DIROPS: allow parallel lookups and readdir
 * VFUSE_HANDLE_KILLPRIV: fs handles killing suid/sgid/cap on write/chown/trunc
 * VFUSE_POSIX_ACL: filesystem supports posix acls
 * VFUSE_ABORT_ERROR: reading the device after abort returns ECONNABORTED
 * VFUSE_MAX_PAGES: init_out.max_pages contains the max number of req pages
 * VFUSE_CACHE_SYMLINKS: cache READLINK responses
 * VFUSE_NO_OPENDIR_SUPPORT: kernel supports zero-message opendir
 * VFUSE_EXPLICIT_INVAL_DATA: only invalidate cached pages on explicit request
 * VFUSE_MAP_ALIGNMENT: init_out.map_alignment contains log2(byte alignment) for
 *		       foffset and moffset fields in struct
 *		       vfuse_setupmapping_out and vfuse_removemapping_one.
 * VFUSE_SUBMOUNTS: kernel supports auto-mounting directory submounts
 * VFUSE_HANDLE_KILLPRIV_V2: fs kills suid/sgid/cap on write/chown/trunc.
 *			Upon write/truncate suid/sgid is only killed if caller
 *			does not have CAP_FSETID. Additionally upon
 *			write/truncate sgid is killed only if file has group
 *			execute permission. (Same as Linux VFS behavior).
 * VFUSE_SETXATTR_EXT:	Server supports extended struct vfuse_setxattr_in
 * VFUSE_INIT_EXT: extended vfuse_init_in request
 * VFUSE_INIT_RESERVED: reserved, do not use
 * VFUSE_SECURITY_CTX:	add security context to create, mkdir, symlink, and
 *			mknod
 * VFUSE_HAS_INODE_DAX:  use per inode DAX
 * VFUSE_CREATE_SUPP_GROUP: add supplementary group info to create, mkdir,
 *			symlink and mknod (single group that matches parent)
 * VFUSE_HAS_EXPIRE_ONLY: kernel supports expiry-only entry invalidation
 * VFUSE_DIRECT_IO_ALLOW_MMAP: allow shared mmap in FOPEN_DIRECT_IO mode.
 * VFUSE_NO_EXPORT_SUPPORT: explicitly disable export support
 * VFUSE_OVER_IO_URING: Indicate that client supports io-uring
 */
#define VFUSE_ASYNC_READ		(1 << 0)
#define VFUSE_POSIX_LOCKS	(1 << 1)
#define VFUSE_FILE_OPS		(1 << 2)
#define VFUSE_ATOMIC_O_TRUNC	(1 << 3)
#define VFUSE_EXPORT_SUPPORT	(1 << 4)
#define VFUSE_BIG_WRITES		(1 << 5)
#define VFUSE_DONT_MASK		(1 << 6)
#define VFUSE_SPLICE_WRITE	(1 << 7)
#define VFUSE_SPLICE_MOVE	(1 << 8)
#define VFUSE_SPLICE_READ	(1 << 9)
#define VFUSE_FLOCK_LOCKS	(1 << 10)
#define VFUSE_HAS_IOCTL_DIR	(1 << 11)
#define VFUSE_AUTO_INVAL_DATA	(1 << 12)
#define VFUSE_DO_READDIRPLUS	(1 << 13)
#define VFUSE_READDIRPLUS_AUTO	(1 << 14)
#define VFUSE_ASYNC_DIO		(1 << 15)
#define VFUSE_WRITEBACK_CACHE	(1 << 16)
#define VFUSE_NO_OPEN_SUPPORT	(1 << 17)
#define VFUSE_PARALLEL_DIROPS    (1 << 18)
#define VFUSE_HANDLE_KILLPRIV	(1 << 19)
#define VFUSE_POSIX_ACL		(1 << 20)
#define VFUSE_ABORT_ERROR	(1 << 21)
#define VFUSE_MAX_PAGES		(1 << 22)
#define VFUSE_CACHE_SYMLINKS	(1 << 23)
#define VFUSE_NO_OPENDIR_SUPPORT (1 << 24)
#define VFUSE_EXPLICIT_INVAL_DATA (1 << 25)
#define VFUSE_MAP_ALIGNMENT	(1 << 26)
#define VFUSE_SUBMOUNTS		(1 << 27)
#define VFUSE_HANDLE_KILLPRIV_V2	(1 << 28)
#define VFUSE_SETXATTR_EXT	(1 << 29)
#define VFUSE_INIT_EXT		(1 << 30)
#define VFUSE_INIT_RESERVED	(1 << 31)
/* bits 32..63 get shifted down 32 bits into the flags2 field */
#define VFUSE_SECURITY_CTX	(1ULL << 32)
#define VFUSE_HAS_INODE_DAX	(1ULL << 33)
#define VFUSE_CREATE_SUPP_GROUP	(1ULL << 34)
#define VFUSE_HAS_EXPIRE_ONLY	(1ULL << 35)
#define VFUSE_DIRECT_IO_ALLOW_MMAP (1ULL << 36)
#define VFUSE_NO_EXPORT_SUPPORT	(1ULL << 38)

/* Obsolete alias for VFUSE_DIRECT_IO_ALLOW_MMAP */
#define VFUSE_DIRECT_IO_RELAX	VFUSE_DIRECT_IO_ALLOW_MMAP
#define VFUSE_OVER_IO_URING	(1ULL << 41)

/**
 * CUSE INIT request/reply flags
 *
 * CUSE_UNRESTRICTED_IOCTL:  use unrestricted ioctl
 */
#define CUSE_UNRESTRICTED_IOCTL	(1 << 0)

/**
 * Release flags
 */
#define VFUSE_RELEASE_FLUSH	(1 << 0)
#define VFUSE_RELEASE_FLOCK_UNLOCK	(1 << 1)

/**
 * Getattr flags
 */
#define VFUSE_GETATTR_FH		(1 << 0)

/**
 * Lock flags
 */
#define VFUSE_LK_FLOCK		(1 << 0)

/**
 * WRITE flags
 *
 * VFUSE_WRITE_CACHE: delayed write from page cache, file handle is guessed
 * VFUSE_WRITE_LOCKOWNER: lock_owner field is valid
 * VFUSE_WRITE_KILL_SUIDGID: kill suid and sgid bits
 */
#define VFUSE_WRITE_CACHE	(1 << 0)
#define VFUSE_WRITE_LOCKOWNER	(1 << 1)
#define VFUSE_WRITE_KILL_SUIDGID (1 << 2)

/* Obsolete alias; this flag implies killing suid/sgid only. */
#define VFUSE_WRITE_KILL_PRIV	VFUSE_WRITE_KILL_SUIDGID

/**
 * Read flags
 */
#define VFUSE_READ_LOCKOWNER	(1 << 1)

/**
 * Ioctl flags
 *
 * VFUSE_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
 * VFUSE_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
 * VFUSE_IOCTL_RETRY: retry with new iovecs
 * VFUSE_IOCTL_32BIT: 32bit ioctl
 * VFUSE_IOCTL_DIR: is a directory
 * VFUSE_IOCTL_COMPAT_X32: x32 compat ioctl on 64bit machine (64bit time_t)
 *
 * VFUSE_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
 */
#define VFUSE_IOCTL_COMPAT	(1 << 0)
#define VFUSE_IOCTL_UNRESTRICTED	(1 << 1)
#define VFUSE_IOCTL_RETRY	(1 << 2)
#define VFUSE_IOCTL_32BIT	(1 << 3)
#define VFUSE_IOCTL_DIR		(1 << 4)
#define VFUSE_IOCTL_COMPAT_X32	(1 << 5)

#define VFUSE_IOCTL_MAX_IOV	256

/**
 * Poll flags
 *
 * VFUSE_POLL_SCHEDULE_NOTIFY: request poll notify
 */
#define VFUSE_POLL_SCHEDULE_NOTIFY (1 << 0)

/**
 * Fsync flags
 *
 * VFUSE_FSYNC_FDATASYNC: Sync data only, not metadata
 */
#define VFUSE_FSYNC_FDATASYNC	(1 << 0)

/**
 * vfuse_attr flags
 *
 * VFUSE_ATTR_SUBMOUNT: Object is a submount root
 * VFUSE_ATTR_DAX: Enable DAX for this file in per inode DAX mode
 */
#define VFUSE_ATTR_SUBMOUNT      (1 << 0)
#define VFUSE_ATTR_DAX		(1 << 1)

/**
 * Open flags
 * VFUSE_OPEN_KILL_SUIDGID: Kill suid and sgid if executable
 */
#define VFUSE_OPEN_KILL_SUIDGID	(1 << 0)

/**
 * setxattr flags
 * VFUSE_SETXATTR_ACL_KILL_SGID: Clear SGID when system.posix_acl_access is set
 */
#define VFUSE_SETXATTR_ACL_KILL_SGID	(1 << 0)

/**
 * notify_inval_entry flags
 * VFUSE_EXPIRE_ONLY
 */
#define VFUSE_EXPIRE_ONLY		(1 << 0)

/**
 * extension type
 * VFUSE_MAX_NR_SECCTX: maximum value of &vfuse_secctx_header.nr_secctx
 * VFUSE_EXT_GROUPS: &vfuse_supp_groups extension
 */
enum vfuse_ext_type {
	/* Types 0..31 are reserved for vfuse_secctx_header */
	VFUSE_MAX_NR_SECCTX	= 31,
	VFUSE_EXT_GROUPS		= 32,
};

enum vfuse_opcode {
	VFUSE_LOOKUP		= 1,
	VFUSE_FORGET		= 2,  /* no reply */
	VFUSE_GETATTR		= 3,
	VFUSE_SETATTR		= 4,
	VFUSE_READLINK		= 5,
	VFUSE_SYMLINK		= 6,
	VFUSE_MKNOD		= 8,
	VFUSE_MKDIR		= 9,
	VFUSE_UNLINK		= 10,
	VFUSE_RMDIR		= 11,
	VFUSE_RENAME		= 12,
	VFUSE_LINK		= 13,
	VFUSE_OPEN		= 14,
	VFUSE_READ		= 15,
	VFUSE_WRITE		= 16,
	VFUSE_STATFS		= 17,
	VFUSE_RELEASE		= 18,
	VFUSE_FSYNC		= 20,
	VFUSE_SETXATTR		= 21,
	VFUSE_GETXATTR		= 22,
	VFUSE_LISTXATTR		= 23,
	VFUSE_REMOVEXATTR	= 24,
	VFUSE_FLUSH		= 25,
	VFUSE_INIT		= 26,
	VFUSE_OPENDIR		= 27,
	VFUSE_READDIR		= 28,
	VFUSE_RELEASEDIR		= 29,
	VFUSE_FSYNCDIR		= 30,
	VFUSE_GETLK		= 31,
	VFUSE_SETLK		= 32,
	VFUSE_SETLKW		= 33,
	VFUSE_ACCESS		= 34,
	VFUSE_CREATE		= 35,
	VFUSE_INTERRUPT		= 36,
	VFUSE_BMAP		= 37,
	VFUSE_DESTROY		= 38,
	VFUSE_IOCTL		= 39,
	VFUSE_POLL		= 40,
	VFUSE_NOTIFY_REPLY	= 41,
	VFUSE_BATCH_FORGET	= 42,
	VFUSE_FALLOCATE		= 43,
	VFUSE_READDIRPLUS	= 44,
	VFUSE_RENAME2		= 45,
	VFUSE_LSEEK		= 46,
	VFUSE_COPY_FILE_RANGE	= 47,
	VFUSE_SETUPMAPPING	= 48,
	VFUSE_REMOVEMAPPING	= 49,
	VFUSE_SYNCFS		= 50,
	VFUSE_TMPFILE		= 51,
	VFUSE_STATX		= 52,

	/* CUSE specific operations */
	CUSE_INIT		= 4096,

	/* Reserved opcodes: helpful to detect structure endian-ness */
	CUSE_INIT_BSWAP_RESERVED	= 1048576,	/* CUSE_INIT << 8 */
	VFUSE_INIT_BSWAP_RESERVED	= 436207616,	/* VFUSE_INIT << 24 */
};

enum vfuse_notify_code {
	VFUSE_NOTIFY_POLL   = 1,
	VFUSE_NOTIFY_INVAL_INODE = 2,
	VFUSE_NOTIFY_INVAL_ENTRY = 3,
	VFUSE_NOTIFY_STORE = 4,
	VFUSE_NOTIFY_RETRIEVE = 5,
	VFUSE_NOTIFY_DELETE = 6,
	VFUSE_NOTIFY_CODE_MAX,
};

/* The read buffer is required to be at least 8k, but may be much larger */
#define VFUSE_MIN_READ_BUFFER 8192

#define VFUSE_COMPAT_ENTRY_OUT_SIZE 120

struct vfuse_entry_out {
	uint64_t	nodeid;		/* Inode ID */
	uint64_t	generation;	/* Inode generation: nodeid:gen must
					   be unique for the fs's lifetime */
	uint64_t	entry_valid;	/* Cache timeout for the name */
	uint64_t	attr_valid;	/* Cache timeout for the attributes */
	uint32_t	entry_valid_nsec;
	uint32_t	attr_valid_nsec;
	struct vfuse_attr attr;
};

struct vfuse_forget_in {
	uint64_t	nlookup;
};

struct vfuse_forget_one {
	uint64_t	nodeid;
	uint64_t	nlookup;
};

struct vfuse_batch_forget_in {
	uint32_t	count;
	uint32_t	dummy;
};

struct vfuse_getattr_in {
	uint32_t	getattr_flags;
	uint32_t	dummy;
	uint64_t	fh;
};

#define VFUSE_COMPAT_ATTR_OUT_SIZE 96

struct vfuse_attr_out {
	uint64_t	attr_valid;	/* Cache timeout for the attributes */
	uint32_t	attr_valid_nsec;
	uint32_t	dummy;
	struct vfuse_attr attr;
};

struct vfuse_statx_in {
	uint32_t	getattr_flags;
	uint32_t	reserved;
	uint64_t	fh;
	uint32_t	sx_flags;
	uint32_t	sx_mask;
};

struct vfuse_statx_out {
	uint64_t	attr_valid;	/* Cache timeout for the attributes */
	uint32_t	attr_valid_nsec;
	uint32_t	flags;
	uint64_t	spare[2];
	struct vfuse_statx stat;
};

#define VFUSE_COMPAT_MKNOD_IN_SIZE 8

struct vfuse_mknod_in {
	uint32_t	mode;
	uint32_t	rdev;
	uint32_t	umask;
	uint32_t	padding;
};

struct vfuse_mkdir_in {
	uint32_t	mode;
	uint32_t	umask;
};

struct vfuse_rename_in {
	uint64_t	newdir;
};

struct vfuse_rename2_in {
	uint64_t	newdir;
	uint32_t	flags;
	uint32_t	padding;
};

struct vfuse_link_in {
	uint64_t	oldnodeid;
};

struct vfuse_setattr_in {
	uint32_t	valid;
	uint32_t	padding;
	uint64_t	fh;
	uint64_t	size;
	uint64_t	lock_owner;
	uint64_t	atime;
	uint64_t	mtime;
	uint64_t	ctime;
	uint32_t	atimensec;
	uint32_t	mtimensec;
	uint32_t	ctimensec;
	uint32_t	mode;
	uint32_t	unused4;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	unused5;
};

struct vfuse_open_in {
	uint32_t	flags;
	uint32_t	open_flags;	/* VFUSE_OPEN_... */
};

struct vfuse_create_in {
	uint32_t	flags;
	uint32_t	mode;
	uint32_t	umask;
	uint32_t	open_flags;	/* VFUSE_OPEN_... */
};

struct vfuse_open_out {
	uint64_t	fh;
	uint32_t	open_flags;
	uint32_t	padding;
};

struct vfuse_release_in {
	uint64_t	fh;
	uint32_t	flags;
	uint32_t	release_flags;
	uint64_t	lock_owner;
};

struct vfuse_flush_in {
	uint64_t	fh;
	uint32_t	unused;
	uint32_t	padding;
	uint64_t	lock_owner;
};

struct vfuse_read_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	read_flags;
	uint64_t	lock_owner;
	uint32_t	flags;
	uint32_t	padding;
};

#define VFUSE_COMPAT_WRITE_IN_SIZE 24

struct vfuse_write_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	write_flags;
	uint64_t	lock_owner;
	uint32_t	flags;
	uint32_t	padding;
};

struct vfuse_write_out {
	uint32_t	size;
	uint32_t	padding;
};

#define VFUSE_COMPAT_STATFS_SIZE 48

struct vfuse_statfs_out {
	struct vfuse_kstatfs st;
};

struct vfuse_fsync_in {
	uint64_t	fh;
	uint32_t	fsync_flags;
	uint32_t	padding;
};

#define VFUSE_COMPAT_SETXATTR_IN_SIZE 8

struct vfuse_setxattr_in {
	uint32_t	size;
	uint32_t	flags;
	uint32_t	setxattr_flags;
	uint32_t	padding;
};

struct vfuse_getxattr_in {
	uint32_t	size;
	uint32_t	padding;
};

struct vfuse_getxattr_out {
	uint32_t	size;
	uint32_t	padding;
};

struct vfuse_lk_in {
	uint64_t	fh;
	uint64_t	owner;
	struct vfuse_file_lock lk;
	uint32_t	lk_flags;
	uint32_t	padding;
};

struct vfuse_lk_out {
	struct vfuse_file_lock lk;
};

struct vfuse_access_in {
	uint32_t	mask;
	uint32_t	padding;
};

struct vfuse_init_in {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
	uint32_t	flags2;
	uint32_t	unused[11];
};

#define VFUSE_COMPAT_INIT_OUT_SIZE 8
#define VFUSE_COMPAT_22_INIT_OUT_SIZE 24

struct vfuse_init_out {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
	uint16_t	max_background;
	uint16_t	congestion_threshold;
	uint32_t	max_write;
	uint32_t	time_gran;
	uint16_t	max_pages;
	uint16_t	map_alignment;
	uint32_t	flags2;
	uint32_t	unused[7];
};

#define CUSE_INIT_INFO_MAX 4096

struct cuse_init_in {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	unused;
	uint32_t	flags;
};

struct cuse_init_out {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	unused;
	uint32_t	flags;
	uint32_t	max_read;
	uint32_t	max_write;
	uint32_t	dev_major;		/* chardev major */
	uint32_t	dev_minor;		/* chardev minor */
	uint32_t	spare[10];
};

struct vfuse_interrupt_in {
	uint64_t	unique;
};

struct vfuse_bmap_in {
	uint64_t	block;
	uint32_t	blocksize;
	uint32_t	padding;
};

struct vfuse_bmap_out {
	uint64_t	block;
};

struct vfuse_ioctl_in {
	uint64_t	fh;
	uint32_t	flags;
	uint32_t	cmd;
	uint64_t	arg;
	uint32_t	in_size;
	uint32_t	out_size;
};

struct vfuse_ioctl_iovec {
	uint64_t	base;
	uint64_t	len;
};

struct vfuse_ioctl_out {
	int32_t		result;
	uint32_t	flags;
	uint32_t	in_iovs;
	uint32_t	out_iovs;
};

struct vfuse_poll_in {
	uint64_t	fh;
	uint64_t	kh;
	uint32_t	flags;
	uint32_t	events;
};

struct vfuse_poll_out {
	uint32_t	revents;
	uint32_t	padding;
};

struct vfuse_notify_poll_wakeup_out {
	uint64_t	kh;
};

struct vfuse_fallocate_in {
	uint64_t	fh;
	uint64_t	offset;
	uint64_t	length;
	uint32_t	mode;
	uint32_t	padding;
};

struct vfuse_in_header {
	uint32_t	len;
	uint32_t	opcode;
	uint64_t	unique;
	uint64_t	nodeid;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	pid;
	uint16_t	total_extlen; /* length of extensions in 8byte units */
	uint16_t	padding;
};

struct vfuse_out_header {
	uint32_t	len;
	int32_t		error;
	uint64_t	unique;
};

struct vfuse_dirent {
	uint64_t	ino;
	uint64_t	off;
	uint32_t	namelen;
	uint32_t	type;
	char name[];
};

/* Align variable length records to 64bit boundary */
#define VFUSE_REC_ALIGN(x) \
	(((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))

#define VFUSE_NAME_OFFSET offsetof(struct vfuse_dirent, name)
#define VFUSE_DIRENT_ALIGN(x) VFUSE_REC_ALIGN(x)
#define VFUSE_DIRENT_SIZE(d) \
	VFUSE_DIRENT_ALIGN(VFUSE_NAME_OFFSET + (d)->namelen)

struct vfuse_direntplus {
	struct vfuse_entry_out entry_out;
	struct vfuse_dirent dirent;
};

#define VFUSE_NAME_OFFSET_DIRENTPLUS \
	offsetof(struct vfuse_direntplus, dirent.name)
#define VFUSE_DIRENTPLUS_SIZE(d) \
	VFUSE_DIRENT_ALIGN(VFUSE_NAME_OFFSET_DIRENTPLUS + (d)->dirent.namelen)

struct vfuse_notify_inval_inode_out {
	uint64_t	ino;
	int64_t		off;
	int64_t		len;
};

struct vfuse_notify_inval_entry_out {
	uint64_t	parent;
	uint32_t	namelen;
	uint32_t	flags;
};

struct vfuse_notify_delete_out {
	uint64_t	parent;
	uint64_t	child;
	uint32_t	namelen;
	uint32_t	padding;
};

struct vfuse_notify_store_out {
	uint64_t	nodeid;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	padding;
};

struct vfuse_notify_retrieve_out {
	uint64_t	notify_unique;
	uint64_t	nodeid;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	padding;
};

/* Matches the size of vfuse_write_in */
struct vfuse_notify_retrieve_in {
	uint64_t	dummy1;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	dummy2;
	uint64_t	dummy3;
	uint64_t	dummy4;
};

/* Device ioctls: */
#define VFUSE_DEV_IOC_MAGIC		229
#define VFUSE_DEV_IOC_CLONE		_IOR(VFUSE_DEV_IOC_MAGIC, 0, uint32_t)

struct vfuse_lseek_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	whence;
	uint32_t	padding;
};

struct vfuse_lseek_out {
	uint64_t	offset;
};

struct vfuse_copy_file_range_in {
	uint64_t	fh_in;
	uint64_t	off_in;
	uint64_t	nodeid_out;
	uint64_t	fh_out;
	uint64_t	off_out;
	uint64_t	len;
	uint64_t	flags;
};

#define VFUSE_SETUPMAPPING_FLAG_WRITE (1ull << 0)
#define VFUSE_SETUPMAPPING_FLAG_READ (1ull << 1)
struct vfuse_setupmapping_in {
	/* An already open handle */
	uint64_t	fh;
	/* Offset into the file to start the mapping */
	uint64_t	foffset;
	/* Length of mapping required */
	uint64_t	len;
	/* Flags, VFUSE_SETUPMAPPING_FLAG_* */
	uint64_t	flags;
	/* Offset in Memory Window */
	uint64_t	moffset;
};

struct vfuse_removemapping_in {
	/* number of vfuse_removemapping_one follows */
	uint32_t        count;
};

struct vfuse_removemapping_one {
	/* Offset into the dax window start the unmapping */
	uint64_t        moffset;
	/* Length of mapping required */
	uint64_t	len;
};

#define VFUSE_REMOVEMAPPING_MAX_ENTRY   \
		(PAGE_SIZE / sizeof(struct vfuse_removemapping_one))

struct vfuse_syncfs_in {
	uint64_t	padding;
};

/*
 * For each security context, send vfuse_secctx with size of security context
 * vfuse_secctx will be followed by security context name and this in turn
 * will be followed by actual context label.
 * vfuse_secctx, name, context
 */
struct vfuse_secctx {
	uint32_t	size;
	uint32_t	padding;
};

/*
 * Contains the information about how many vfuse_secctx structures are being
 * sent and what's the total size of all security contexts (including
 * size of vfuse_secctx_header).
 *
 */
struct vfuse_secctx_header {
	uint32_t	size;
	uint32_t	nr_secctx;
};

/**
 * struct vfuse_ext_header - extension header
 * @size: total size of this extension including this header
 * @type: type of extension
 *
 * This is made compatible with vfuse_secctx_header by using type values >
 * VFUSE_MAX_NR_SECCTX
 */
struct vfuse_ext_header {
	uint32_t	size;
	uint32_t	type;
};

/**
 * struct vfuse_supp_groups - Supplementary group extension
 * @nr_groups: number of supplementary groups
 * @groups: flexible array of group IDs
 */
struct vfuse_supp_groups {
	uint32_t	nr_groups;
	uint32_t	groups[];
};

/**
 * Size of the ring buffer header
 */
#define VFUSE_URING_IN_OUT_HEADER_SZ 128
#define VFUSE_URING_OP_IN_OUT_SZ 128

/* Used as part of the vfuse_uring_req_header */
struct vfuse_uring_ent_in_out {
	uint64_t flags;

	/*
	 * commit ID to be used in a reply to a ring request (see also
	 * struct vfuse_uring_cmd_req)
	 */
	uint64_t commit_id;

	/* size of user payload buffer */
	uint32_t payload_sz;
	uint32_t padding;

	uint64_t reserved;
};

/**
 * Header for all vfuse-io-uring requests
 */
struct vfuse_uring_req_header {
	/* struct vfuse_in_header / struct vfuse_out_header */
	char in_out[VFUSE_URING_IN_OUT_HEADER_SZ];

	/* per op code header */
	char op_in[VFUSE_URING_OP_IN_OUT_SZ];

	struct vfuse_uring_ent_in_out ring_ent_in_out;
};

/**
 * sqe commands to the kernel
 */
enum vfuse_uring_cmd {
	VFUSE_IO_URING_CMD_INVALID = 0,

	/* register the request buffer and fetch a vfuse request */
	VFUSE_IO_URING_CMD_REGISTER = 1,

	/* commit vfuse request result and fetch next request */
	VFUSE_IO_URING_CMD_COMMIT_AND_FETCH = 2,
};

/**
 * In the 80B command area of the SQE.
 */
struct vfuse_uring_cmd_req {
	uint64_t flags;

	/* entry identifier for commits */
	uint64_t commit_id;

	/* queue the command is for (queue index) */
	uint16_t qid;
	uint8_t padding[6];
};

#endif /* _LINUX_VFUSE_H */
