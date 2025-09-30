/*
 * VFUSE: Filesystem in Userspace
 * Copyright (C) 2016 Canonical Ltd. <seth.forshee@canonical.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "vfuse_i.h"

#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

static struct posix_acl *__vfuse_get_acl(struct vfuse_conn *fc,
					struct mnt_idmap *idmap,
					struct inode *inode, int type, bool rcu)
{
	int size;
	const char *name;
	void *value = NULL;
	struct posix_acl *acl;

	if (rcu)
		return ERR_PTR(-ECHILD);

	if (vfuse_is_bad(inode))
		return ERR_PTR(-EIO);

	if (fc->no_getxattr)
		return NULL;

	if (type == ACL_TYPE_ACCESS)
		name = XATTR_NAME_POSIX_ACL_ACCESS;
	else if (type == ACL_TYPE_DEFAULT)
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
	else
		return ERR_PTR(-EOPNOTSUPP);

	value = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!value)
		return ERR_PTR(-ENOMEM);
	size = vfuse_getxattr(inode, name, value, PAGE_SIZE);
	if (size > 0)
		acl = posix_acl_from_xattr(fc->user_ns, value, size);
	else if ((size == 0) || (size == -ENODATA) ||
		 (size == -EOPNOTSUPP && fc->no_getxattr))
		acl = NULL;
	else if (size == -ERANGE)
		acl = ERR_PTR(-E2BIG);
	else
		acl = ERR_PTR(size);

	kfree(value);
	return acl;
}

static inline bool vfuse_no_acl(const struct vfuse_conn *fc,
			       const struct inode *inode)
{
	/*
	 * Revfuse interacting with POSIX ACLs for daemons that
	 * don't support VFUSE_POSIX_ACL and are not mounted on
	 * the host to retain backwards compatibility.
	 */
	return !fc->posix_acl && (i_user_ns(inode) != &init_user_ns);
}

struct posix_acl *vfuse_get_acl(struct mnt_idmap *idmap,
			       struct dentry *dentry, int type)
{
	struct inode *inode = d_inode(dentry);
	struct vfuse_conn *fc = get_vfuse_conn(inode);

	if (vfuse_no_acl(fc, inode))
		return ERR_PTR(-EOPNOTSUPP);

	return __vfuse_get_acl(fc, idmap, inode, type, false);
}

struct posix_acl *vfuse_get_inode_acl(struct inode *inode, int type, bool rcu)
{
	struct vfuse_conn *fc = get_vfuse_conn(inode);

	/*
	 * VFUSE daemons before VFUSE_POSIX_ACL was introduced could get and set
	 * POSIX ACLs without them being used for permission checking by the
	 * vfs. Retain that behavior for backwards compatibility as there are
	 * filesystems that do all permission checking for acls in the daemon
	 * and not in the kernel.
	 */
	if (!fc->posix_acl)
		return NULL;

	return __vfuse_get_acl(fc, &nop_mnt_idmap, inode, type, rcu);
}

int vfuse_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		 struct posix_acl *acl, int type)
{
	struct inode *inode = d_inode(dentry);
	struct vfuse_conn *fc = get_vfuse_conn(inode);
	const char *name;
	int ret;

	if (vfuse_is_bad(inode))
		return -EIO;

	if (fc->no_setxattr || vfuse_no_acl(fc, inode))
		return -EOPNOTSUPP;

	if (type == ACL_TYPE_ACCESS)
		name = XATTR_NAME_POSIX_ACL_ACCESS;
	else if (type == ACL_TYPE_DEFAULT)
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
	else
		return -EINVAL;

	if (acl) {
		unsigned int extra_flags = 0;
		/*
		 * Fuse userspace is responsible for updating access
		 * permissions in the inode, if needed. vfuse_setxattr
		 * invalidates the inode attributes, which will force
		 * them to be refreshed the next time they are used,
		 * and it also updates i_ctime.
		 */
		size_t size = posix_acl_xattr_size(acl->a_count);
		void *value;

		if (size > PAGE_SIZE)
			return -E2BIG;

		value = kmalloc(size, GFP_KERNEL);
		if (!value)
			return -ENOMEM;

		ret = posix_acl_to_xattr(fc->user_ns, acl, value, size);
		if (ret < 0) {
			kfree(value);
			return ret;
		}

		/*
		 * Fuse daemons without VFUSE_POSIX_ACL never changed the passed
		 * through POSIX ACLs. Such daemons don't expect setgid bits to
		 * be stripped.
		 */
		if (fc->posix_acl &&
		    !vfsgid_in_group_p(i_gid_into_vfsgid(&nop_mnt_idmap, inode)) &&
		    !capable_wrt_inode_uidgid(&nop_mnt_idmap, inode, CAP_FSETID))
			extra_flags |= VFUSE_SETXATTR_ACL_KILL_SGID;

		ret = vfuse_setxattr(inode, name, value, size, 0, extra_flags);
		kfree(value);
	} else {
		ret = vfuse_removexattr(inode, name);
	}

	if (fc->posix_acl) {
		/*
		 * Fuse daemons without VFUSE_POSIX_ACL never cached POSIX ACLs
		 * and didn't invalidate attributes. Retain that behavior.
		 */
		forget_all_cached_acls(inode);
		vfuse_invalidate_attr(inode);
	}

	return ret;
}
