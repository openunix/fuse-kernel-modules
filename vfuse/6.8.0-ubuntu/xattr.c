/*
 * VFUSE: Filesystem in Userspace
 * Copyright (C) 2001-2016  Miklos Szeredi <miklos@szeredi.hu>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "vfuse_i.h"

#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>

int vfuse_setxattr(struct inode *inode, const char *name, const void *value,
		  size_t size, int flags, unsigned int extra_flags)
{
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	VFUSE_ARGS(args);
	struct vfuse_setxattr_in inarg;
	int err;

	if (fm->fc->no_setxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	inarg.setxattr_flags = extra_flags;

	args.opcode = VFUSE_SETXATTR;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 3;
	args.in_args[0].size = fm->fc->setxattr_ext ?
		sizeof(inarg) : VFUSE_COMPAT_SETXATTR_IN_SIZE;
	args.in_args[0].value = &inarg;
	args.in_args[1].size = strlen(name) + 1;
	args.in_args[1].value = name;
	args.in_args[2].size = size;
	args.in_args[2].value = value;
	err = vfuse_simple_request(fm, &args);
	if (err == -ENOSYS) {
		fm->fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err)
		vfuse_update_ctime(inode);

	return err;
}

ssize_t vfuse_getxattr(struct inode *inode, const char *name, void *value,
		      size_t size)
{
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	VFUSE_ARGS(args);
	struct vfuse_getxattr_in inarg;
	struct vfuse_getxattr_out outarg;
	ssize_t ret;

	if (fm->fc->no_getxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.opcode = VFUSE_GETXATTR;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 2;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.in_args[1].size = strlen(name) + 1;
	args.in_args[1].value = name;
	/* This is really two different operations rolled into one */
	args.out_numargs = 1;
	if (size) {
		args.out_argvar = true;
		args.out_args[0].size = size;
		args.out_args[0].value = value;
	} else {
		args.out_args[0].size = sizeof(outarg);
		args.out_args[0].value = &outarg;
	}
	ret = vfuse_simple_request(fm, &args);
	if (!ret && !size)
		ret = min_t(size_t, outarg.size, XATTR_SIZE_MAX);
	if (ret == -ENOSYS) {
		fm->fc->no_getxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int vfuse_verify_xattr_list(char *list, size_t size)
{
	size_t origsize = size;

	while (size) {
		size_t thislen = strnlen(list, size);

		if (!thislen || thislen == size)
			return -EIO;

		size -= thislen + 1;
		list += thislen + 1;
	}

	return origsize;
}

ssize_t vfuse_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = d_inode(entry);
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	VFUSE_ARGS(args);
	struct vfuse_getxattr_in inarg;
	struct vfuse_getxattr_out outarg;
	ssize_t ret;

	if (vfuse_is_bad(inode))
		return -EIO;

	if (!vfuse_allow_current_process(fm->fc))
		return -EACCES;

	if (fm->fc->no_listxattr)
		return -EOPNOTSUPP;

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	args.opcode = VFUSE_LISTXATTR;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	/* This is really two different operations rolled into one */
	args.out_numargs = 1;
	if (size) {
		args.out_argvar = true;
		args.out_args[0].size = size;
		args.out_args[0].value = list;
	} else {
		args.out_args[0].size = sizeof(outarg);
		args.out_args[0].value = &outarg;
	}
	ret = vfuse_simple_request(fm, &args);
	if (!ret && !size)
		ret = min_t(size_t, outarg.size, XATTR_LIST_MAX);
	if (ret > 0 && size)
		ret = vfuse_verify_xattr_list(list, ret);
	if (ret == -ENOSYS) {
		fm->fc->no_listxattr = 1;
		ret = -EOPNOTSUPP;
	}
	return ret;
}

int vfuse_removexattr(struct inode *inode, const char *name)
{
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	VFUSE_ARGS(args);
	int err;

	if (fm->fc->no_removexattr)
		return -EOPNOTSUPP;

	args.opcode = VFUSE_REMOVEXATTR;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 2;
	vfuse_set_zero_arg0(&args);
	args.in_args[1].size = strlen(name) + 1;
	args.in_args[1].value = name;
	err = vfuse_simple_request(fm, &args);
	if (err == -ENOSYS) {
		fm->fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err)
		vfuse_update_ctime(inode);

	return err;
}

static int vfuse_xattr_get(const struct xattr_handler *handler,
			 struct dentry *dentry, struct inode *inode,
			 const char *name, void *value, size_t size)
{
	if (vfuse_is_bad(inode))
		return -EIO;

	return vfuse_getxattr(inode, name, value, size);
}

static int vfuse_xattr_set(const struct xattr_handler *handler,
			  struct mnt_idmap *idmap,
			  struct dentry *dentry, struct inode *inode,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	if (vfuse_is_bad(inode))
		return -EIO;

	if (!value)
		return vfuse_removexattr(inode, name);

	return vfuse_setxattr(inode, name, value, size, flags, 0);
}

static const struct xattr_handler vfuse_xattr_handler = {
	.prefix = "",
	.get    = vfuse_xattr_get,
	.set    = vfuse_xattr_set,
};

const struct xattr_handler * const vfuse_xattr_handlers[] = {
	&vfuse_xattr_handler,
	NULL
};
