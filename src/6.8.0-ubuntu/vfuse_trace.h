/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM vfuse

#if !defined(_TRACE_VFUSE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_VFUSE_H

#include <linux/tracepoint.h>

#define OPCODES							\
	EM( VFUSE_LOOKUP,		"VFUSE_LOOKUP")		\
	EM( VFUSE_FORGET,		"VFUSE_FORGET")		\
	EM( VFUSE_GETATTR,		"VFUSE_GETATTR")		\
	EM( VFUSE_SETATTR,		"VFUSE_SETATTR")		\
	EM( VFUSE_READLINK,		"VFUSE_READLINK")	\
	EM( VFUSE_SYMLINK,		"VFUSE_SYMLINK")		\
	EM( VFUSE_MKNOD,			"VFUSE_MKNOD")		\
	EM( VFUSE_MKDIR,			"VFUSE_MKDIR")		\
	EM( VFUSE_UNLINK,		"VFUSE_UNLINK")		\
	EM( VFUSE_RMDIR,			"VFUSE_RMDIR")		\
	EM( VFUSE_RENAME,		"VFUSE_RENAME")		\
	EM( VFUSE_LINK,			"VFUSE_LINK")		\
	EM( VFUSE_OPEN,			"VFUSE_OPEN")		\
	EM( VFUSE_READ,			"VFUSE_READ")		\
	EM( VFUSE_WRITE,			"VFUSE_WRITE")		\
	EM( VFUSE_STATFS,		"VFUSE_STATFS")		\
	EM( VFUSE_RELEASE,		"VFUSE_RELEASE")		\
	EM( VFUSE_FSYNC,			"VFUSE_FSYNC")		\
	EM( VFUSE_SETXATTR,		"VFUSE_SETXATTR")	\
	EM( VFUSE_GETXATTR,		"VFUSE_GETXATTR")	\
	EM( VFUSE_LISTXATTR,		"VFUSE_LISTXATTR")	\
	EM( VFUSE_REMOVEXATTR,		"VFUSE_REMOVEXATTR")	\
	EM( VFUSE_FLUSH,			"VFUSE_FLUSH")		\
	EM( VFUSE_INIT,			"VFUSE_INIT")		\
	EM( VFUSE_OPENDIR,		"VFUSE_OPENDIR")		\
	EM( VFUSE_READDIR,		"VFUSE_READDIR")		\
	EM( VFUSE_RELEASEDIR,		"VFUSE_RELEASEDIR")	\
	EM( VFUSE_FSYNCDIR,		"VFUSE_FSYNCDIR")	\
	EM( VFUSE_GETLK,			"VFUSE_GETLK")		\
	EM( VFUSE_SETLK,			"VFUSE_SETLK")		\
	EM( VFUSE_SETLKW,		"VFUSE_SETLKW")		\
	EM( VFUSE_ACCESS,		"VFUSE_ACCESS")		\
	EM( VFUSE_CREATE,		"VFUSE_CREATE")		\
	EM( VFUSE_INTERRUPT,		"VFUSE_INTERRUPT")	\
	EM( VFUSE_BMAP,			"VFUSE_BMAP")		\
	EM( VFUSE_DESTROY,		"VFUSE_DESTROY")		\
	EM( VFUSE_IOCTL,			"VFUSE_IOCTL")		\
	EM( VFUSE_POLL,			"VFUSE_POLL")		\
	EM( VFUSE_NOTIFY_REPLY,		"VFUSE_NOTIFY_REPLY")	\
	EM( VFUSE_BATCH_FORGET,		"VFUSE_BATCH_FORGET")	\
	EM( VFUSE_FALLOCATE,		"VFUSE_FALLOCATE")	\
	EM( VFUSE_READDIRPLUS,		"VFUSE_READDIRPLUS")	\
	EM( VFUSE_RENAME2,		"VFUSE_RENAME2")		\
	EM( VFUSE_LSEEK,			"VFUSE_LSEEK")		\
	EM( VFUSE_COPY_FILE_RANGE,	"VFUSE_COPY_FILE_RANGE")	\
	EM( VFUSE_SETUPMAPPING,		"VFUSE_SETUPMAPPING")	\
	EM( VFUSE_REMOVEMAPPING,		"VFUSE_REMOVEMAPPING")	\
	EM( VFUSE_SYNCFS,		"VFUSE_SYNCFS")		\
	EM( VFUSE_TMPFILE,		"VFUSE_TMPFILE")		\
	EM( VFUSE_STATX,			"VFUSE_STATX")		\
	EMe(CUSE_INIT,			"CUSE_INIT")

/*
 * This will turn the above table into TRACE_DEFINE_ENUM() for each of the
 * entries.
 */
#undef EM
#undef EMe
#define EM(a, b)	TRACE_DEFINE_ENUM(a);
#define EMe(a, b)	TRACE_DEFINE_ENUM(a);

OPCODES

/* Now we redfine it with the table that __print_symbolic needs. */
#undef EM
#undef EMe
#define EM(a, b)	{a, b},
#define EMe(a, b)	{a, b}

#define VFUSE_REQ_TRACE_FIELDS				\
	__field(dev_t,			connection)	\
	__field(uint64_t,		unique)		\
	__field(enum vfuse_opcode,	opcode)		\
	__field(uint32_t,		len)		\

#define VFUSE_REQ_TRACE_ASSIGN(req)				\
	do {							\
		__entry->connection	= req->fm->fc->dev;	\
		__entry->unique		= req->in.h.unique;	\
		__entry->opcode		= req->in.h.opcode;	\
		__entry->len		= req->in.h.len;	\
	} while (0)


TRACE_EVENT(vfuse_request_enqueue,
	TP_PROTO(const struct vfuse_req *req),
	TP_ARGS(req),
	TP_STRUCT__entry(VFUSE_REQ_TRACE_FIELDS),
	TP_fast_assign(VFUSE_REQ_TRACE_ASSIGN(req)),

	TP_printk("connection %u req %llu opcode %u (%s) len %u ",
		  __entry->connection, __entry->unique, __entry->opcode,
		  __print_symbolic(__entry->opcode, OPCODES), __entry->len)
);

TRACE_EVENT(vfuse_request_bg_enqueue,
	TP_PROTO(const struct vfuse_req *req),
	TP_ARGS(req),
	TP_STRUCT__entry(VFUSE_REQ_TRACE_FIELDS),
	TP_fast_assign(VFUSE_REQ_TRACE_ASSIGN(req)),

	TP_printk("connection %u req %llu opcode %u (%s) len %u ",
		  __entry->connection, __entry->unique, __entry->opcode,
		  __print_symbolic(__entry->opcode, OPCODES), __entry->len)
);

TRACE_EVENT(vfuse_request_send,
	TP_PROTO(const struct vfuse_req *req),
	TP_ARGS(req),
	TP_STRUCT__entry(VFUSE_REQ_TRACE_FIELDS),
	TP_fast_assign(VFUSE_REQ_TRACE_ASSIGN(req)),

	TP_printk("connection %u req %llu opcode %u (%s) len %u ",
		  __entry->connection, __entry->unique, __entry->opcode,
		  __print_symbolic(__entry->opcode, OPCODES), __entry->len)
);


TRACE_EVENT(vfuse_request_end,
	TP_PROTO(const struct vfuse_req *req),

	TP_ARGS(req),

	TP_STRUCT__entry(
		__field(dev_t,		connection)
		__field(uint64_t,	unique)
		__field(uint32_t,	len)
		__field(int32_t,	error)
	),

	TP_fast_assign(
		__entry->connection	=	req->fm->fc->dev;
		__entry->unique		=	req->in.h.unique;
		__entry->len		=	req->out.h.len;
		__entry->error		=	req->out.h.error;
	),

	TP_printk("connection %u req %llu len %u error %d", __entry->connection,
		  __entry->unique, __entry->len, __entry->error)
);

#endif /* _TRACE_VFUSE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE vfuse_trace
#include <trace/define_trace.h>
