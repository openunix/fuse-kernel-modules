/*
  VFUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "vfuse_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/fs_context.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/iversion.h>
#include <linux/posix_acl.h>
#include <linux/security.h>
#include <linux/types.h>
#include <linux/kernel.h>

static bool __read_mostly allow_sys_admin_access;
module_param(allow_sys_admin_access, bool, 0644);
MODULE_PARM_DESC(allow_sys_admin_access,
		 "Allow users with CAP_SYS_ADMIN in initial userns to bypass allow_other access check");

static void vfuse_advise_use_readdirplus(struct inode *dir)
{
	struct vfuse_inode *fi = get_vfuse_inode(dir);

	set_bit(VFUSE_I_ADVISE_RDPLUS, &fi->state);
}

#if BITS_PER_LONG >= 64
static inline void __vfuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_fsdata = (void *) time;
}

static inline u64 vfuse_dentry_time(const struct dentry *entry)
{
	return (u64)entry->d_fsdata;
}

#else
union vfuse_dentry {
	u64 time;
	struct rcu_head rcu;
};

static inline void __vfuse_dentry_settime(struct dentry *dentry, u64 time)
{
	((union vfuse_dentry *) dentry->d_fsdata)->time = time;
}

static inline u64 vfuse_dentry_time(const struct dentry *entry)
{
	return ((union vfuse_dentry *) entry->d_fsdata)->time;
}
#endif

static void vfuse_dentry_settime(struct dentry *dentry, u64 time)
{
	struct vfuse_conn *fc = get_vfuse_conn_super(dentry->d_sb);
	bool delete = !time && fc->delete_stale;
	/*
	 * Mess with DCACHE_OP_DELETE because dput() will be faster without it.
	 * Don't care about races, either way it's just an optimization
	 */
	if ((!delete && (dentry->d_flags & DCACHE_OP_DELETE)) ||
	    (delete && !(dentry->d_flags & DCACHE_OP_DELETE))) {
		spin_lock(&dentry->d_lock);
		if (!delete)
			dentry->d_flags &= ~DCACHE_OP_DELETE;
		else
			dentry->d_flags |= DCACHE_OP_DELETE;
		spin_unlock(&dentry->d_lock);
	}

	__vfuse_dentry_settime(dentry, time);
}

/*
 * VFUSE caches dentries and attributes with separate timeout.  The
 * time in jiffies until the dentry/attributes are valid is stored in
 * dentry->d_fsdata and vfuse_inode->i_time respectively.
 */

/*
 * Calculate the time in jiffies until a dentry/attributes are valid
 */
u64 vfuse_time_to_jiffies(u64 sec, u32 nsec)
{
	if (sec || nsec) {
		struct timespec64 ts = {
			sec,
			min_t(u32, nsec, NSEC_PER_SEC - 1)
		};

		return get_jiffies_64() + timespec64_to_jiffies(&ts);
	} else
		return 0;
}

/*
 * Set dentry and possibly attribute timeouts from the lookup/mk*
 * replies
 */
void vfuse_change_entry_timeout(struct dentry *entry, struct vfuse_entry_out *o)
{
	vfuse_dentry_settime(entry,
		vfuse_time_to_jiffies(o->entry_valid, o->entry_valid_nsec));
}

void vfuse_invalidate_attr_mask(struct inode *inode, u32 mask)
{
	set_mask_bits(&get_vfuse_inode(inode)->inval_mask, 0, mask);
}

/*
 * Mark the attributes as stale, so that at the next call to
 * ->getattr() they will be fetched from userspace
 */
void vfuse_invalidate_attr(struct inode *inode)
{
	vfuse_invalidate_attr_mask(inode, STATX_BASIC_STATS);
}

static void vfuse_dir_changed(struct inode *dir)
{
	vfuse_invalidate_attr(dir);
	inode_maybe_inc_iversion(dir, false);
}

/*
 * Mark the attributes as stale due to an atime change.  Avoid the invalidate if
 * atime is not used.
 */
void vfuse_invalidate_atime(struct inode *inode)
{
	if (!IS_RDONLY(inode))
		vfuse_invalidate_attr_mask(inode, STATX_ATIME);
}

/*
 * Just mark the entry as stale, so that a next attempt to look it up
 * will result in a new lookup call to userspace
 *
 * This is called when a dentry is about to become negative and the
 * timeout is unknown (unlink, rmdir, rename and in some cases
 * lookup)
 */
void vfuse_invalidate_entry_cache(struct dentry *entry)
{
	vfuse_dentry_settime(entry, 0);
}

/*
 * Same as vfuse_invalidate_entry_cache(), but also try to remove the
 * dentry from the hash
 */
static void vfuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	vfuse_invalidate_entry_cache(entry);
}

static void vfuse_lookup_init(struct vfuse_conn *fc, struct vfuse_args *args,
			     u64 nodeid, const struct qstr *name,
			     struct vfuse_entry_out *outarg)
{
	memset(outarg, 0, sizeof(struct vfuse_entry_out));
	args->opcode = VFUSE_LOOKUP;
	args->nodeid = nodeid;
	args->in_numargs = 2;
	vfuse_set_zero_arg0(args);
	args->in_args[1].size = name->len + 1;
	args->in_args[1].value = name->name;
	args->out_numargs = 1;
	args->out_args[0].size = sizeof(struct vfuse_entry_out);
	args->out_args[0].value = outarg;
}

/*
 * Check whether the dentry is still valid
 *
 * If the entry validity timeout has expired and the dentry is
 * positive, try to redo the lookup.  If the lookup results in a
 * different inode, then let the VFS invalidate the dentry and redo
 * the lookup once more.  If the lookup results in the same inode,
 * then refresh the attributes, timeouts and mark the dentry valid.
 */
static int vfuse_dentry_revalidate(struct dentry *entry, unsigned int flags)
{
	struct inode *inode;
	struct dentry *parent;
	struct vfuse_mount *fm;
	struct vfuse_inode *fi;
	int ret;

	inode = d_inode_rcu(entry);
	if (inode && vfuse_is_bad(inode))
		goto invalid;
	else if (time_before64(vfuse_dentry_time(entry), get_jiffies_64()) ||
		 (flags & (LOOKUP_EXCL | LOOKUP_REVAL | LOOKUP_RENAME_TARGET))) {
		struct vfuse_entry_out outarg;
		VFUSE_ARGS(args);
		struct vfuse_forget_link *forget;
		u64 attr_version;

		/* For negative dentries, always do a fresh lookup */
		if (!inode)
			goto invalid;

		ret = -ECHILD;
		if (flags & LOOKUP_RCU)
			goto out;

		fm = get_vfuse_mount(inode);

		forget = vfuse_alloc_forget();
		ret = -ENOMEM;
		if (!forget)
			goto out;

		attr_version = vfuse_get_attr_version(fm->fc);

		parent = dget_parent(entry);
		vfuse_lookup_init(fm->fc, &args, get_node_id(d_inode(parent)),
				 &entry->d_name, &outarg);
		ret = vfuse_simple_request(fm, &args);
		dput(parent);
		/* Zero nodeid is same as -ENOENT */
		if (!ret && !outarg.nodeid)
			ret = -ENOENT;
		if (!ret) {
			fi = get_vfuse_inode(inode);
			if (outarg.nodeid != get_node_id(inode) ||
			    (bool) IS_AUTOMOUNT(inode) != (bool) (outarg.attr.flags & VFUSE_ATTR_SUBMOUNT)) {
				vfuse_queue_forget(fm->fc, forget,
						  outarg.nodeid, 1);
				goto invalid;
			}
			spin_lock(&fi->lock);
			fi->nlookup++;
			spin_unlock(&fi->lock);
		}
		kfree(forget);
		if (ret == -ENOMEM || ret == -EINTR)
			goto out;
		if (ret || vfuse_invalid_attr(&outarg.attr) ||
		    vfuse_stale_inode(inode, outarg.generation, &outarg.attr))
			goto invalid;

		forget_all_cached_acls(inode);
		vfuse_change_attributes(inode, &outarg.attr, NULL,
				       ATTR_TIMEOUT(&outarg),
				       attr_version);
		vfuse_change_entry_timeout(entry, &outarg);
	} else if (inode) {
		fi = get_vfuse_inode(inode);
		if (flags & LOOKUP_RCU) {
			if (test_bit(VFUSE_I_INIT_RDPLUS, &fi->state))
				return -ECHILD;
		} else if (test_and_clear_bit(VFUSE_I_INIT_RDPLUS, &fi->state)) {
			parent = dget_parent(entry);
			vfuse_advise_use_readdirplus(d_inode(parent));
			dput(parent);
		}
	}
	ret = 1;
out:
	return ret;

invalid:
	ret = 0;
	goto out;
}

#if BITS_PER_LONG < 64
static int vfuse_dentry_init(struct dentry *dentry)
{
	dentry->d_fsdata = kzalloc(sizeof(union vfuse_dentry),
				   GFP_KERNEL_ACCOUNT | __GFP_RECLAIMABLE);

	return dentry->d_fsdata ? 0 : -ENOMEM;
}
static void vfuse_dentry_release(struct dentry *dentry)
{
	union vfuse_dentry *fd = dentry->d_fsdata;

	kfree_rcu(fd, rcu);
}
#endif

static int vfuse_dentry_delete(const struct dentry *dentry)
{
	return time_before64(vfuse_dentry_time(dentry), get_jiffies_64());
}

/*
 * Create a vfuse_mount object with a new superblock (with path->dentry
 * as the root), and return that mount so it can be auto-mounted on
 * @path.
 */
static struct vfsmount *vfuse_dentry_automount(struct path *path)
{
	struct fs_context *fsc;
	struct vfsmount *mnt;
	struct vfuse_inode *mp_fi = get_vfuse_inode(d_inode(path->dentry));

	fsc = fs_context_for_submount(path->mnt->mnt_sb->s_type, path->dentry);
	if (IS_ERR(fsc))
		return ERR_CAST(fsc);

	/* Pass the VFUSE inode of the mount for vfuse_get_tree_submount() */
	fsc->fs_private = mp_fi;

	/* Create the submount */
	mnt = fc_mount(fsc);
	if (!IS_ERR(mnt))
		mntget(mnt);

	put_fs_context(fsc);
	return mnt;
}

const struct dentry_operations vfuse_dentry_operations = {
	.d_revalidate	= vfuse_dentry_revalidate,
	.d_delete	= vfuse_dentry_delete,
#if BITS_PER_LONG < 64
	.d_init		= vfuse_dentry_init,
	.d_release	= vfuse_dentry_release,
#endif
	.d_automount	= vfuse_dentry_automount,
};

const struct dentry_operations vfuse_root_dentry_operations = {
#if BITS_PER_LONG < 64
	.d_init		= vfuse_dentry_init,
	.d_release	= vfuse_dentry_release,
#endif
};

int vfuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}

static bool vfuse_valid_size(u64 size)
{
	return size <= LLONG_MAX;
}

bool vfuse_invalid_attr(struct vfuse_attr *attr)
{
	return !vfuse_valid_type(attr->mode) || !vfuse_valid_size(attr->size);
}

int vfuse_lookup_name(struct super_block *sb, u64 nodeid, const struct qstr *name,
		     struct vfuse_entry_out *outarg, struct inode **inode)
{
	struct vfuse_mount *fm = get_vfuse_mount_super(sb);
	VFUSE_ARGS(args);
	struct vfuse_forget_link *forget;
	u64 attr_version, evict_ctr;
	int err;

	*inode = NULL;
	err = -ENAMETOOLONG;
	if (name->len > fm->fc->name_max)
		goto out;


	forget = vfuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out;

	attr_version = vfuse_get_attr_version(fm->fc);
	evict_ctr = vfuse_get_evict_ctr(fm->fc);

	vfuse_lookup_init(fm->fc, &args, nodeid, name, outarg);
	err = vfuse_simple_request(fm, &args);
	/* Zero nodeid is same as -ENOENT, but with valid timeout */
	if (err || !outarg->nodeid)
		goto out_put_forget;

	err = -EIO;
	if (vfuse_invalid_attr(&outarg->attr))
		goto out_put_forget;
	if (outarg->nodeid == VFUSE_ROOT_ID && outarg->generation != 0) {
		pr_warn_once("root generation should be zero\n");
		outarg->generation = 0;
	}

	*inode = vfuse_iget(sb, outarg->nodeid, outarg->generation,
			   &outarg->attr, ATTR_TIMEOUT(outarg),
			   attr_version, evict_ctr);
	err = -ENOMEM;
	if (!*inode) {
		vfuse_queue_forget(fm->fc, forget, outarg->nodeid, 1);
		goto out;
	}
	err = 0;

 out_put_forget:
	kfree(forget);
 out:
	return err;
}

static struct dentry *vfuse_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags)
{
	int err;
	struct vfuse_entry_out outarg;
	struct inode *inode;
	struct dentry *newent;
	bool outarg_valid = true;
	bool locked;

	if (vfuse_is_bad(dir))
		return ERR_PTR(-EIO);

	locked = vfuse_lock_inode(dir);
	err = vfuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode);
	vfuse_unlock_inode(dir, locked);
	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}
	if (err)
		goto out_err;

	err = -EIO;
	if (inode && get_node_id(inode) == VFUSE_ROOT_ID)
		goto out_iput;

	newent = d_splice_alias(inode, entry);
	err = PTR_ERR(newent);
	if (IS_ERR(newent))
		goto out_err;

	entry = newent ? newent : entry;
	if (outarg_valid)
		vfuse_change_entry_timeout(entry, &outarg);
	else
		vfuse_invalidate_entry_cache(entry);

	if (inode)
		vfuse_advise_use_readdirplus(dir);
	return newent;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

static int get_security_context(struct dentry *entry, umode_t mode,
				struct vfuse_in_arg *ext)
{
	struct vfuse_secctx *fctx;
	struct vfuse_secctx_header *header;
	struct lsmcontext lsmctx = { };
	void *ptr;
	u32 total_len = sizeof(*header);
	int err, nr_ctx = 0;
	const char *name = NULL;
	size_t namelen;

	err = security_dentry_init_security(entry, mode, &entry->d_name,
					    &name, &lsmctx);

	/* If no LSM is supporting this security hook ignore error */
	if (err && err != -EOPNOTSUPP)
		goto out_err;

	if (lsmctx.len) {
		nr_ctx = 1;
		namelen = strlen(name) + 1;
		err = -EIO;
		if (WARN_ON(namelen > XATTR_NAME_MAX + 1 ||
		    lsmctx.len > S32_MAX))
			goto out_err;
		total_len += VFUSE_REC_ALIGN(sizeof(*fctx) + namelen +
					    lsmctx.len);
	}

	err = -ENOMEM;
	header = ptr = kzalloc(total_len, GFP_KERNEL);
	if (!ptr)
		goto out_err;

	header->nr_secctx = nr_ctx;
	header->size = total_len;
	ptr += sizeof(*header);
	if (nr_ctx) {
		fctx = ptr;
		fctx->size = lsmctx.len;
		ptr += sizeof(*fctx);

		strcpy(ptr, name);
		ptr += namelen;

		memcpy(ptr, lsmctx.context, lsmctx.len);
	}
	ext->size = total_len;
	ext->value = header;
	err = 0;
out_err:
	if (nr_ctx)
		security_release_secctx(&lsmctx);
	return err;
}

static void *extend_arg(struct vfuse_in_arg *buf, u32 bytes)
{
	void *p;
	u32 newlen = buf->size + bytes;

	p = krealloc(buf->value, newlen, GFP_KERNEL);
	if (!p) {
		kfree(buf->value);
		buf->size = 0;
		buf->value = NULL;
		return NULL;
	}

	memset(p + buf->size, 0, bytes);
	buf->value = p;
	buf->size = newlen;

	return p + newlen - bytes;
}

static u32 vfuse_ext_size(size_t size)
{
	return VFUSE_REC_ALIGN(sizeof(struct vfuse_ext_header) + size);
}

/*
 * This adds just a single supplementary group that matches the parent's group.
 */
static int get_create_supp_group(struct inode *dir, struct vfuse_in_arg *ext)
{
	struct vfuse_conn *fc = get_vfuse_conn(dir);
	struct vfuse_ext_header *xh;
	struct vfuse_supp_groups *sg;
	kgid_t kgid = dir->i_gid;
	gid_t parent_gid = from_kgid(fc->user_ns, kgid);
	u32 sg_len = vfuse_ext_size(sizeof(*sg) + sizeof(sg->groups[0]));

	if (parent_gid == (gid_t) -1 || gid_eq(kgid, current_fsgid()) ||
	    !in_group_p(kgid))
		return 0;

	xh = extend_arg(ext, sg_len);
	if (!xh)
		return -ENOMEM;

	xh->size = sg_len;
	xh->type = VFUSE_EXT_GROUPS;

	sg = (struct vfuse_supp_groups *) &xh[1];
	sg->nr_groups = 1;
	sg->groups[0] = parent_gid;

	return 0;
}

static int get_create_ext(struct vfuse_args *args,
			  struct inode *dir, struct dentry *dentry,
			  umode_t mode)
{
	struct vfuse_conn *fc = get_vfuse_conn_super(dentry->d_sb);
	struct vfuse_in_arg ext = { .size = 0, .value = NULL };
	int err = 0;

	if (fc->init_security)
		err = get_security_context(dentry, mode, &ext);
	if (!err && fc->create_supp_group)
		err = get_create_supp_group(dir, &ext);

	if (!err && ext.size) {
		WARN_ON(args->in_numargs >= ARRAY_SIZE(args->in_args));
		args->is_ext = true;
		args->ext_idx = args->in_numargs++;
		args->in_args[args->ext_idx] = ext;
	} else {
		kfree(ext.value);
	}

	return err;
}

static void free_ext_value(struct vfuse_args *args)
{
	if (args->is_ext)
		kfree(args->in_args[args->ext_idx].value);
}

/*
 * Atomic create+open operation
 *
 * If the filesystem doesn't support this, then fall back to separate
 * 'mknod' + 'open' requests.
 */
static int vfuse_create_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned int flags,
			    umode_t mode, u32 opcode)
{
	int err;
	struct inode *inode;
	struct vfuse_mount *fm = get_vfuse_mount(dir);
	VFUSE_ARGS(args);
	struct vfuse_forget_link *forget;
	struct vfuse_create_in inarg;
	struct vfuse_open_out outopen;
	struct vfuse_entry_out outentry;
	struct vfuse_inode *fi;
	struct vfuse_file *ff;
	bool trunc = flags & O_TRUNC;

	/* Userspace expects S_IFREG in create mode */
	BUG_ON((mode & S_IFMT) != S_IFREG);

	forget = vfuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out_err;

	err = -ENOMEM;
	ff = vfuse_file_alloc(fm, true);
	if (!ff)
		goto out_put_forget_req;

	if (!fm->fc->dont_mask)
		mode &= ~current_umask();

	flags &= ~O_NOCTTY;
	memset(&inarg, 0, sizeof(inarg));
	memset(&outentry, 0, sizeof(outentry));
	inarg.flags = flags;
	inarg.mode = mode;
	inarg.umask = current_umask();

	if (fm->fc->handle_killpriv_v2 && trunc &&
	    !(flags & O_EXCL) && !capable(CAP_FSETID)) {
		inarg.open_flags |= VFUSE_OPEN_KILL_SUIDGID;
	}

	args.opcode = opcode;
	args.nodeid = get_node_id(dir);
	args.in_numargs = 2;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.in_args[1].size = entry->d_name.len + 1;
	args.in_args[1].value = entry->d_name.name;
	args.out_numargs = 2;
	args.out_args[0].size = sizeof(outentry);
	args.out_args[0].value = &outentry;
	args.out_args[1].size = sizeof(outopen);
	args.out_args[1].value = &outopen;

	err = get_create_ext(&args, dir, entry, mode);
	if (err)
		goto out_free_ff;

	err = vfuse_simple_request(fm, &args);
	free_ext_value(&args);
	if (err)
		goto out_free_ff;

	err = -EIO;
	if (!S_ISREG(outentry.attr.mode) || invalid_nodeid(outentry.nodeid) ||
	    vfuse_invalid_attr(&outentry.attr))
		goto out_free_ff;

	ff->fh = outopen.fh;
	ff->nodeid = outentry.nodeid;
	ff->open_flags = outopen.open_flags;
	inode = vfuse_iget(dir->i_sb, outentry.nodeid, outentry.generation,
			  &outentry.attr, ATTR_TIMEOUT(&outentry), 0, 0);
	if (!inode) {
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
		vfuse_sync_release(NULL, ff, flags);
		vfuse_queue_forget(fm->fc, forget, outentry.nodeid, 1);
		err = -ENOMEM;
		goto out_err;
	}
	kfree(forget);
	d_instantiate(entry, inode);
	vfuse_change_entry_timeout(entry, &outentry);
	vfuse_dir_changed(dir);
	err = generic_file_open(inode, file);
	if (!err) {
		file->private_data = ff;
		err = finish_open(file, entry, vfuse_finish_open);
	}
	if (err) {
		fi = get_vfuse_inode(inode);
		vfuse_sync_release(fi, ff, flags);
	} else {
		if (fm->fc->atomic_o_trunc && trunc)
			truncate_pagecache(inode, 0);
		else if (!(ff->open_flags & FOPEN_KEEP_CACHE))
			invalidate_inode_pages2(inode->i_mapping);
	}
	return err;

out_free_ff:
	vfuse_file_free(ff);
out_put_forget_req:
	kfree(forget);
out_err:
	return err;
}

static int vfuse_mknod(struct mnt_idmap *, struct inode *, struct dentry *,
		      umode_t, dev_t);
static int vfuse_atomic_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode)
{
	int err;
	struct vfuse_conn *fc = get_vfuse_conn(dir);
	struct dentry *res = NULL;

	if (vfuse_is_bad(dir))
		return -EIO;

	if (d_in_lookup(entry)) {
		res = vfuse_lookup(dir, entry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			entry = res;
	}

	if (!(flags & O_CREAT) || d_really_is_positive(entry))
		goto no_open;

	/* Only creates */
	file->f_mode |= FMODE_CREATED;

	if (fc->no_create)
		goto mknod;

	err = vfuse_create_open(dir, entry, file, flags, mode, VFUSE_CREATE);
	if (err == -ENOSYS) {
		fc->no_create = 1;
		goto mknod;
	} else if (err == -EEXIST)
		vfuse_invalidate_entry(entry);
out_dput:
	dput(res);
	return err;

mknod:
	err = vfuse_mknod(&nop_mnt_idmap, dir, entry, mode, 0);
	if (err)
		goto out_dput;
no_open:
	return finish_no_open(file, res);
}

/*
 * Code shared between mknod, mkdir, symlink and link
 */
static int create_new_entry(struct vfuse_mount *fm, struct vfuse_args *args,
			    struct inode *dir, struct dentry *entry,
			    umode_t mode)
{
	struct vfuse_entry_out outarg;
	struct inode *inode;
	struct dentry *d;
	int err;
	struct vfuse_forget_link *forget;

	if (vfuse_is_bad(dir))
		return -EIO;

	forget = vfuse_alloc_forget();
	if (!forget)
		return -ENOMEM;

	memset(&outarg, 0, sizeof(outarg));
	args->nodeid = get_node_id(dir);
	args->out_numargs = 1;
	args->out_args[0].size = sizeof(outarg);
	args->out_args[0].value = &outarg;

	if (args->opcode != VFUSE_LINK) {
		err = get_create_ext(args, dir, entry, mode);
		if (err)
			goto out_put_forget_req;
	}

	err = vfuse_simple_request(fm, args);
	free_ext_value(args);
	if (err)
		goto out_put_forget_req;

	err = -EIO;
	if (invalid_nodeid(outarg.nodeid) || vfuse_invalid_attr(&outarg.attr))
		goto out_put_forget_req;

	if ((outarg.attr.mode ^ mode) & S_IFMT)
		goto out_put_forget_req;

	inode = vfuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, ATTR_TIMEOUT(&outarg), 0, 0);
	if (!inode) {
		vfuse_queue_forget(fm->fc, forget, outarg.nodeid, 1);
		return -ENOMEM;
	}
	kfree(forget);

	d_drop(entry);
	d = d_splice_alias(inode, entry);
	if (IS_ERR(d))
		return PTR_ERR(d);

	if (d) {
		vfuse_change_entry_timeout(d, &outarg);
		dput(d);
	} else {
		vfuse_change_entry_timeout(entry, &outarg);
	}
	vfuse_dir_changed(dir);
	return 0;

 out_put_forget_req:
	if (err == -EEXIST)
		vfuse_invalidate_entry(entry);
	kfree(forget);
	return err;
}

static int vfuse_mknod(struct mnt_idmap *idmap, struct inode *dir,
		      struct dentry *entry, umode_t mode, dev_t rdev)
{
	struct vfuse_mknod_in inarg;
	struct vfuse_mount *fm = get_vfuse_mount(dir);
	VFUSE_ARGS(args);

	if (!fm->fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	inarg.umask = current_umask();
	args.opcode = VFUSE_MKNOD;
	args.in_numargs = 2;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.in_args[1].size = entry->d_name.len + 1;
	args.in_args[1].value = entry->d_name.name;
	return create_new_entry(fm, &args, dir, entry, mode);
}

static int vfuse_create(struct mnt_idmap *idmap, struct inode *dir,
		       struct dentry *entry, umode_t mode, bool excl)
{
	return vfuse_mknod(&nop_mnt_idmap, dir, entry, mode, 0);
}

static int vfuse_tmpfile(struct mnt_idmap *idmap, struct inode *dir,
			struct file *file, umode_t mode)
{
	struct vfuse_conn *fc = get_vfuse_conn(dir);
	int err;

	if (fc->no_tmpfile)
		return -EOPNOTSUPP;

	err = vfuse_create_open(dir, file->f_path.dentry, file, file->f_flags, mode, VFUSE_TMPFILE);
	if (err == -ENOSYS) {
		fc->no_tmpfile = 1;
		err = -EOPNOTSUPP;
	}
	return err;
}

static int vfuse_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		      struct dentry *entry, umode_t mode)
{
	struct vfuse_mkdir_in inarg;
	struct vfuse_mount *fm = get_vfuse_mount(dir);
	VFUSE_ARGS(args);

	if (!fm->fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.umask = current_umask();
	args.opcode = VFUSE_MKDIR;
	args.in_numargs = 2;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.in_args[1].size = entry->d_name.len + 1;
	args.in_args[1].value = entry->d_name.name;
	return create_new_entry(fm, &args, dir, entry, S_IFDIR);
}

static int vfuse_symlink(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *entry, const char *link)
{
	struct vfuse_mount *fm = get_vfuse_mount(dir);
	unsigned len = strlen(link) + 1;
	VFUSE_ARGS(args);

	args.opcode = VFUSE_SYMLINK;
	args.in_numargs = 3;
	vfuse_set_zero_arg0(&args);
	args.in_args[1].size = entry->d_name.len + 1;
	args.in_args[1].value = entry->d_name.name;
	args.in_args[2].size = len;
	args.in_args[2].value = link;
	return create_new_entry(fm, &args, dir, entry, S_IFLNK);
}

void vfuse_flush_time_update(struct inode *inode)
{
	int err = sync_inode_metadata(inode, 1);

	mapping_set_error(inode->i_mapping, err);
}

static void vfuse_update_ctime_in_cache(struct inode *inode)
{
	if (!IS_NOCMTIME(inode)) {
		inode_set_ctime_current(inode);
		mark_inode_dirty_sync(inode);
		vfuse_flush_time_update(inode);
	}
}

void vfuse_update_ctime(struct inode *inode)
{
	vfuse_invalidate_attr_mask(inode, STATX_CTIME);
	vfuse_update_ctime_in_cache(inode);
}

static void vfuse_entry_unlinked(struct dentry *entry)
{
	struct inode *inode = d_inode(entry);
	struct vfuse_conn *fc = get_vfuse_conn(inode);
	struct vfuse_inode *fi = get_vfuse_inode(inode);

	spin_lock(&fi->lock);
	fi->attr_version = atomic64_inc_return(&fc->attr_version);
	/*
	 * If i_nlink == 0 then unlink doesn't make sense, yet this can
	 * happen if userspace filesystem is careless.  It would be
	 * difficult to enforce correct nlink usage so just ignore this
	 * condition here
	 */
	if (S_ISDIR(inode->i_mode))
		clear_nlink(inode);
	else if (inode->i_nlink > 0)
		drop_nlink(inode);
	spin_unlock(&fi->lock);
	vfuse_invalidate_entry_cache(entry);
	vfuse_update_ctime(inode);
}

static int vfuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct vfuse_mount *fm = get_vfuse_mount(dir);
	VFUSE_ARGS(args);

	if (vfuse_is_bad(dir))
		return -EIO;

	args.opcode = VFUSE_UNLINK;
	args.nodeid = get_node_id(dir);
	args.in_numargs = 2;
	vfuse_set_zero_arg0(&args);
	args.in_args[1].size = entry->d_name.len + 1;
	args.in_args[1].value = entry->d_name.name;
	err = vfuse_simple_request(fm, &args);
	if (!err) {
		vfuse_dir_changed(dir);
		vfuse_entry_unlinked(entry);
	} else if (err == -EINTR || err == -ENOENT)
		vfuse_invalidate_entry(entry);
	return err;
}

static int vfuse_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct vfuse_mount *fm = get_vfuse_mount(dir);
	VFUSE_ARGS(args);

	if (vfuse_is_bad(dir))
		return -EIO;

	args.opcode = VFUSE_RMDIR;
	args.nodeid = get_node_id(dir);
	args.in_numargs = 2;
	vfuse_set_zero_arg0(&args);
	args.in_args[1].size = entry->d_name.len + 1;
	args.in_args[1].value = entry->d_name.name;
	err = vfuse_simple_request(fm, &args);
	if (!err) {
		vfuse_dir_changed(dir);
		vfuse_entry_unlinked(entry);
	} else if (err == -EINTR || err == -ENOENT)
		vfuse_invalidate_entry(entry);
	return err;
}

static int vfuse_rename_common(struct inode *olddir, struct dentry *oldent,
			      struct inode *newdir, struct dentry *newent,
			      unsigned int flags, int opcode, size_t argsize)
{
	int err;
	struct vfuse_rename2_in inarg;
	struct vfuse_mount *fm = get_vfuse_mount(olddir);
	VFUSE_ARGS(args);

	memset(&inarg, 0, argsize);
	inarg.newdir = get_node_id(newdir);
	inarg.flags = flags;
	args.opcode = opcode;
	args.nodeid = get_node_id(olddir);
	args.in_numargs = 3;
	args.in_args[0].size = argsize;
	args.in_args[0].value = &inarg;
	args.in_args[1].size = oldent->d_name.len + 1;
	args.in_args[1].value = oldent->d_name.name;
	args.in_args[2].size = newent->d_name.len + 1;
	args.in_args[2].value = newent->d_name.name;
	err = vfuse_simple_request(fm, &args);
	if (!err) {
		/* ctime changes */
		vfuse_update_ctime(d_inode(oldent));

		if (flags & RENAME_EXCHANGE)
			vfuse_update_ctime(d_inode(newent));

		vfuse_dir_changed(olddir);
		if (olddir != newdir)
			vfuse_dir_changed(newdir);

		/* newent will end up negative */
		if (!(flags & RENAME_EXCHANGE) && d_really_is_positive(newent))
			vfuse_entry_unlinked(newent);
	} else if (err == -EINTR || err == -ENOENT) {
		/* If request was interrupted, DEITY only knows if the
		   rename actually took place.  If the invalidation
		   fails (e.g. some process has CWD under the renamed
		   directory), then there can be inconsistency between
		   the dcache and the real filesystem.  Tough luck. */
		vfuse_invalidate_entry(oldent);
		if (d_really_is_positive(newent))
			vfuse_invalidate_entry(newent);
	}

	return err;
}

static int vfuse_rename2(struct mnt_idmap *idmap, struct inode *olddir,
			struct dentry *oldent, struct inode *newdir,
			struct dentry *newent, unsigned int flags)
{
	struct vfuse_conn *fc = get_vfuse_conn(olddir);
	int err;

	if (vfuse_is_bad(olddir))
		return -EIO;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	if (flags) {
		if (fc->no_rename2 || fc->minor < 23)
			return -EINVAL;

		err = vfuse_rename_common(olddir, oldent, newdir, newent, flags,
					 VFUSE_RENAME2,
					 sizeof(struct vfuse_rename2_in));
		if (err == -ENOSYS) {
			fc->no_rename2 = 1;
			err = -EINVAL;
		}
	} else {
		err = vfuse_rename_common(olddir, oldent, newdir, newent, 0,
					 VFUSE_RENAME,
					 sizeof(struct vfuse_rename_in));
	}

	return err;
}

static int vfuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct vfuse_link_in inarg;
	struct inode *inode = d_inode(entry);
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	VFUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	args.opcode = VFUSE_LINK;
	args.in_numargs = 2;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.in_args[1].size = newent->d_name.len + 1;
	args.in_args[1].value = newent->d_name.name;
	err = create_new_entry(fm, &args, newdir, newent, inode->i_mode);
	if (!err)
		vfuse_update_ctime_in_cache(inode);
	else if (err == -EINTR)
		vfuse_invalidate_attr(inode);

	return err;
}

static void vfuse_fillattr(struct inode *inode, struct vfuse_attr *attr,
			  struct kstat *stat)
{
	unsigned int blkbits;
	struct vfuse_conn *fc = get_vfuse_conn(inode);

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(fc->user_ns, attr->uid);
	stat->gid = make_kgid(fc->user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}

static void vfuse_statx_to_attr(struct vfuse_statx *sx, struct vfuse_attr *attr)
{
	memset(attr, 0, sizeof(*attr));
	attr->ino = sx->ino;
	attr->size = sx->size;
	attr->blocks = sx->blocks;
	attr->atime = sx->atime.tv_sec;
	attr->mtime = sx->mtime.tv_sec;
	attr->ctime = sx->ctime.tv_sec;
	attr->atimensec = sx->atime.tv_nsec;
	attr->mtimensec = sx->mtime.tv_nsec;
	attr->ctimensec = sx->ctime.tv_nsec;
	attr->mode = sx->mode;
	attr->nlink = sx->nlink;
	attr->uid = sx->uid;
	attr->gid = sx->gid;
	attr->rdev = new_encode_dev(MKDEV(sx->rdev_major, sx->rdev_minor));
	attr->blksize = sx->blksize;
}

static int vfuse_do_statx(struct inode *inode, struct file *file,
			 struct kstat *stat)
{
	int err;
	struct vfuse_attr attr;
	struct vfuse_statx *sx;
	struct vfuse_statx_in inarg;
	struct vfuse_statx_out outarg;
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	u64 attr_version = vfuse_get_attr_version(fm->fc);
	VFUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	/* Directories have separate file-handle space */
	if (file && S_ISREG(inode->i_mode)) {
		struct vfuse_file *ff = file->private_data;

		inarg.getattr_flags |= VFUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	/* For now leave sync hints as the default, request all stats. */
	inarg.sx_flags = 0;
	inarg.sx_mask = STATX_BASIC_STATS | STATX_BTIME;
	args.opcode = VFUSE_STATX;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;
	err = vfuse_simple_request(fm, &args);
	if (err)
		return err;

	sx = &outarg.stat;
	if (((sx->mask & STATX_SIZE) && !vfuse_valid_size(sx->size)) ||
	    ((sx->mask & STATX_TYPE) && (!vfuse_valid_type(sx->mode) ||
					 inode_wrong_type(inode, sx->mode)))) {
		vfuse_make_bad(inode);
		return -EIO;
	}

	vfuse_statx_to_attr(&outarg.stat, &attr);
	if ((sx->mask & STATX_BASIC_STATS) == STATX_BASIC_STATS) {
		vfuse_change_attributes(inode, &attr, &outarg.stat,
				       ATTR_TIMEOUT(&outarg), attr_version);
	}

	if (stat) {
		stat->result_mask = sx->mask & (STATX_BASIC_STATS | STATX_BTIME);
		stat->btime.tv_sec = sx->btime.tv_sec;
		stat->btime.tv_nsec = min_t(u32, sx->btime.tv_nsec, NSEC_PER_SEC - 1);
		vfuse_fillattr(inode, &attr, stat);
		stat->result_mask |= STATX_TYPE;
	}

	return 0;
}

static int vfuse_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file)
{
	int err;
	struct vfuse_getattr_in inarg;
	struct vfuse_attr_out outarg;
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	VFUSE_ARGS(args);
	u64 attr_version;

	attr_version = vfuse_get_attr_version(fm->fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	/* Directories have separate file-handle space */
	if (file && S_ISREG(inode->i_mode)) {
		struct vfuse_file *ff = file->private_data;

		inarg.getattr_flags |= VFUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	args.opcode = VFUSE_GETATTR;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;
	err = vfuse_simple_request(fm, &args);
	if (!err) {
		if (vfuse_invalid_attr(&outarg.attr) ||
		    inode_wrong_type(inode, outarg.attr.mode)) {
			vfuse_make_bad(inode);
			err = -EIO;
		} else {
			vfuse_change_attributes(inode, &outarg.attr, NULL,
					       ATTR_TIMEOUT(&outarg),
					       attr_version);
			if (stat)
				vfuse_fillattr(inode, &outarg.attr, stat);
		}
	}
	return err;
}

static int vfuse_update_get_attr(struct inode *inode, struct file *file,
				struct kstat *stat, u32 request_mask,
				unsigned int flags)
{
	struct vfuse_inode *fi = get_vfuse_inode(inode);
	struct vfuse_conn *fc = get_vfuse_conn(inode);
	int err = 0;
	bool sync;
	u32 inval_mask = READ_ONCE(fi->inval_mask);
	u32 cache_mask = vfuse_get_cache_mask(inode);


	/* VFUSE only supports basic stats and possibly btime */
	request_mask &= STATX_BASIC_STATS | STATX_BTIME;
retry:
	if (fc->no_statx)
		request_mask &= STATX_BASIC_STATS;

	if (!request_mask)
		sync = false;
	else if (flags & AT_STATX_FORCE_SYNC)
		sync = true;
	else if (flags & AT_STATX_DONT_SYNC)
		sync = false;
	else if (request_mask & inval_mask & ~cache_mask)
		sync = true;
	else
		sync = time_before64(fi->i_time, get_jiffies_64());

	if (sync) {
		forget_all_cached_acls(inode);
		/* Try statx if BTIME is requested */
		if (!fc->no_statx && (request_mask & ~STATX_BASIC_STATS)) {
			err = vfuse_do_statx(inode, file, stat);
			if (err == -ENOSYS) {
				fc->no_statx = 1;
				err = 0;
				goto retry;
			}
		} else {
			err = vfuse_do_getattr(inode, stat, file);
		}
	} else if (stat) {
		generic_fillattr(&nop_mnt_idmap, request_mask, inode, stat);
		stat->mode = fi->orig_i_mode;
		stat->ino = fi->orig_ino;
		if (test_bit(VFUSE_I_BTIME, &fi->state)) {
			stat->btime = fi->i_btime;
			stat->result_mask |= STATX_BTIME;
		}
	}

	return err;
}

int vfuse_update_attributes(struct inode *inode, struct file *file, u32 mask)
{
	return vfuse_update_get_attr(inode, file, NULL, mask, 0);
}

int vfuse_reverse_inval_entry(struct vfuse_conn *fc, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name, u32 flags)
{
	int err = -ENOTDIR;
	struct inode *parent;
	struct dentry *dir;
	struct dentry *entry;

	parent = vfuse_ilookup(fc, parent_nodeid, NULL);
	if (!parent)
		return -ENOENT;

	inode_lock_nested(parent, I_MUTEX_PARENT);
	if (!S_ISDIR(parent->i_mode))
		goto unlock;

	err = -ENOENT;
	dir = d_find_alias(parent);
	if (!dir)
		goto unlock;

	name->hash = full_name_hash(dir, name->name, name->len);
	entry = d_lookup(dir, name);
	dput(dir);
	if (!entry)
		goto unlock;

	vfuse_dir_changed(parent);
	if (!(flags & VFUSE_EXPIRE_ONLY))
		d_invalidate(entry);
	vfuse_invalidate_entry_cache(entry);

	if (child_nodeid != 0 && d_really_is_positive(entry)) {
		inode_lock(d_inode(entry));
		if (get_node_id(d_inode(entry)) != child_nodeid) {
			err = -ENOENT;
			goto badentry;
		}
		if (d_mountpoint(entry)) {
			err = -EBUSY;
			goto badentry;
		}
		if (d_is_dir(entry)) {
			shrink_dcache_parent(entry);
			if (!simple_empty(entry)) {
				err = -ENOTEMPTY;
				goto badentry;
			}
			d_inode(entry)->i_flags |= S_DEAD;
		}
		dont_mount(entry);
		clear_nlink(d_inode(entry));
		err = 0;
 badentry:
		inode_unlock(d_inode(entry));
		if (!err)
			d_delete(entry);
	} else {
		err = 0;
	}
	dput(entry);

 unlock:
	inode_unlock(parent);
	iput(parent);
	return err;
}

static inline bool vfuse_permissible_uidgid(struct vfuse_conn *fc)
{
	const struct cred *cred = current_cred();

	return (uid_eq(cred->euid, fc->user_id) &&
		uid_eq(cred->suid, fc->user_id) &&
		uid_eq(cred->uid,  fc->user_id) &&
		gid_eq(cred->egid, fc->group_id) &&
		gid_eq(cred->sgid, fc->group_id) &&
		gid_eq(cred->gid,  fc->group_id));
}

/*
 * Calling into a user-controlled filesystem gives the filesystem
 * daemon ptrace-like capabilities over the current process.  This
 * means, that the filesystem daemon is able to record the exact
 * filesystem operations performed, and can also control the behavior
 * of the requester process in otherwise impossible ways.  For example
 * it can delay the operation for arbitrary length of time allowing
 * DoS against the requester.
 *
 * For this reason only those processes can call into the filesystem,
 * for which the owner of the mount has ptrace privilege.  This
 * excludes processes started by other users, suid or sgid processes.
 */
bool vfuse_allow_current_process(struct vfuse_conn *fc)
{
	bool allow;

	if (fc->allow_other)
		allow = current_in_userns(fc->user_ns);
	else
		allow = vfuse_permissible_uidgid(fc);

	if (!allow && allow_sys_admin_access && capable(CAP_SYS_ADMIN))
		allow = true;

	return allow;
}

static int vfuse_access(struct inode *inode, int mask)
{
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	VFUSE_ARGS(args);
	struct vfuse_access_in inarg;
	int err;

	BUG_ON(mask & MAY_NOT_BLOCK);

	if (fm->fc->no_access)
		return 0;

	memset(&inarg, 0, sizeof(inarg));
	inarg.mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
	args.opcode = VFUSE_ACCESS;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	err = vfuse_simple_request(fm, &args);
	if (err == -ENOSYS) {
		fm->fc->no_access = 1;
		err = 0;
	}
	return err;
}

static int vfuse_perm_getattr(struct inode *inode, int mask)
{
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	forget_all_cached_acls(inode);
	return vfuse_do_getattr(inode, NULL, NULL);
}

/*
 * Check permission.  The two basic access models of VFUSE are:
 *
 * 1) Local access checking ('default_permissions' mount option) based
 * on file mode.  This is the plain old disk filesystem permission
 * modell.
 *
 * 2) "Remote" access checking, where server is responsible for
 * checking permission in each inode operation.  An exception to this
 * is if ->permission() was invoked from sys_access() in which case an
 * access request is sent.  Execute permission is still checked
 * locally based on file mode.
 */
static int vfuse_permission(struct mnt_idmap *idmap,
			   struct inode *inode, int mask)
{
	struct vfuse_conn *fc = get_vfuse_conn(inode);
	bool refreshed = false;
	int err = 0;

	if (vfuse_is_bad(inode))
		return -EIO;

	if (!vfuse_allow_current_process(fc))
		return -EACCES;

	/*
	 * If attributes are needed, refresh them before proceeding
	 */
	if (fc->default_permissions ||
	    ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))) {
		struct vfuse_inode *fi = get_vfuse_inode(inode);
		u32 perm_mask = STATX_MODE | STATX_UID | STATX_GID;

		if (perm_mask & READ_ONCE(fi->inval_mask) ||
		    time_before64(fi->i_time, get_jiffies_64())) {
			refreshed = true;

			err = vfuse_perm_getattr(inode, mask);
			if (err)
				return err;
		}
	}

	if (fc->default_permissions) {
		err = generic_permission(&nop_mnt_idmap, inode, mask);

		/* If permission is denied, try to refresh file
		   attributes.  This is also needed, because the root
		   node will at first have no permissions */
		if (err == -EACCES && !refreshed) {
			err = vfuse_perm_getattr(inode, mask);
			if (!err)
				err = generic_permission(&nop_mnt_idmap,
							 inode, mask);
		}

		/* Note: the opposite of the above test does not
		   exist.  So if permissions are revoked this won't be
		   noticed immediately, only after the attribute
		   timeout has expired */
	} else if (mask & (MAY_ACCESS | MAY_CHDIR)) {
		err = vfuse_access(inode, mask);
	} else if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		if (!(inode->i_mode & S_IXUGO)) {
			if (refreshed)
				return -EACCES;

			err = vfuse_perm_getattr(inode, mask);
			if (!err && !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	}
	return err;
}

static int vfuse_readlink_page(struct inode *inode, struct page *page)
{
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	struct vfuse_page_desc desc = { .length = PAGE_SIZE - 1 };
	struct vfuse_args_pages ap = {
		.num_pages = 1,
		.pages = &page,
		.descs = &desc,
	};
	char *link;
	ssize_t res;

	ap.args.opcode = VFUSE_READLINK;
	ap.args.nodeid = get_node_id(inode);
	ap.args.out_pages = true;
	ap.args.out_argvar = true;
	ap.args.page_zeroing = true;
	ap.args.out_numargs = 1;
	ap.args.out_args[0].size = desc.length;
	res = vfuse_simple_request(fm, &ap.args);

	vfuse_invalidate_atime(inode);

	if (res < 0)
		return res;

	if (WARN_ON(res >= PAGE_SIZE))
		return -EIO;

	link = page_address(page);
	link[res] = '\0';

	return 0;
}

static const char *vfuse_get_link(struct dentry *dentry, struct inode *inode,
				 struct delayed_call *callback)
{
	struct vfuse_conn *fc = get_vfuse_conn(inode);
	struct page *page;
	int err;

	err = -EIO;
	if (vfuse_is_bad(inode))
		goto out_err;

	if (fc->cache_symlinks)
		return page_get_link(dentry, inode, callback);

	err = -ECHILD;
	if (!dentry)
		goto out_err;

	page = alloc_page(GFP_KERNEL);
	err = -ENOMEM;
	if (!page)
		goto out_err;

	err = vfuse_readlink_page(inode, page);
	if (err) {
		__free_page(page);
		goto out_err;
	}

	set_delayed_call(callback, page_put_link, page);

	return page_address(page);

out_err:
	return ERR_PTR(err);
}

static int vfuse_dir_open(struct inode *inode, struct file *file)
{
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	int err;

	if (vfuse_is_bad(inode))
		return -EIO;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	err = vfuse_do_open(fm, get_node_id(inode), file, true);
	if (!err) {
		struct vfuse_file *ff = file->private_data;

		/*
		 * Keep handling FOPEN_STREAM and FOPEN_NONSEEKABLE for
		 * directories for backward compatibility, though it's unlikely
		 * to be useful.
		 */
		if (ff->open_flags & (FOPEN_STREAM | FOPEN_NONSEEKABLE))
			nonseekable_open(inode, file);
	}

	return err;
}

static int vfuse_dir_release(struct inode *inode, struct file *file)
{
	vfuse_release_common(file, true);

	return 0;
}

static int vfuse_dir_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct vfuse_conn *fc = get_vfuse_conn(inode);
	int err;

	if (vfuse_is_bad(inode))
		return -EIO;

	if (fc->no_fsyncdir)
		return 0;

	inode_lock(inode);
	err = vfuse_fsync_common(file, start, end, datasync, VFUSE_FSYNCDIR);
	if (err == -ENOSYS) {
		fc->no_fsyncdir = 1;
		err = 0;
	}
	inode_unlock(inode);

	return err;
}

static long vfuse_dir_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct vfuse_conn *fc = get_vfuse_conn(file->f_mapping->host);

	/* VFUSE_IOCTL_DIR only supported for API version >= 7.18 */
	if (fc->minor < 18)
		return -ENOTTY;

	return vfuse_ioctl_common(file, cmd, arg, VFUSE_IOCTL_DIR);
}

static long vfuse_dir_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct vfuse_conn *fc = get_vfuse_conn(file->f_mapping->host);

	if (fc->minor < 18)
		return -ENOTTY;

	return vfuse_ioctl_common(file, cmd, arg,
				 VFUSE_IOCTL_COMPAT | VFUSE_IOCTL_DIR);
}

static bool update_mtime(unsigned ivalid, bool trust_local_mtime)
{
	/* Always update if mtime is explicitly set  */
	if (ivalid & ATTR_MTIME_SET)
		return true;

	/* Or if kernel i_mtime is the official one */
	if (trust_local_mtime)
		return true;

	/* If it's an open(O_TRUNC) or an ftruncate(), don't update */
	if ((ivalid & ATTR_SIZE) && (ivalid & (ATTR_OPEN | ATTR_FILE)))
		return false;

	/* In all other cases update */
	return true;
}

static void iattr_to_fattr(struct vfuse_conn *fc, struct iattr *iattr,
			   struct vfuse_setattr_in *arg, bool trust_local_cmtime)
{
	unsigned ivalid = iattr->ia_valid;

	if (ivalid & ATTR_MODE)
		arg->valid |= FATTR_MODE,   arg->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		arg->valid |= FATTR_UID,    arg->uid = from_kuid(fc->user_ns, iattr->ia_uid);
	if (ivalid & ATTR_GID)
		arg->valid |= FATTR_GID,    arg->gid = from_kgid(fc->user_ns, iattr->ia_gid);
	if (ivalid & ATTR_SIZE)
		arg->valid |= FATTR_SIZE,   arg->size = iattr->ia_size;
	if (ivalid & ATTR_ATIME) {
		arg->valid |= FATTR_ATIME;
		arg->atime = iattr->ia_atime.tv_sec;
		arg->atimensec = iattr->ia_atime.tv_nsec;
		if (!(ivalid & ATTR_ATIME_SET))
			arg->valid |= FATTR_ATIME_NOW;
	}
	if ((ivalid & ATTR_MTIME) && update_mtime(ivalid, trust_local_cmtime)) {
		arg->valid |= FATTR_MTIME;
		arg->mtime = iattr->ia_mtime.tv_sec;
		arg->mtimensec = iattr->ia_mtime.tv_nsec;
		if (!(ivalid & ATTR_MTIME_SET) && !trust_local_cmtime)
			arg->valid |= FATTR_MTIME_NOW;
	}
	if ((ivalid & ATTR_CTIME) && trust_local_cmtime) {
		arg->valid |= FATTR_CTIME;
		arg->ctime = iattr->ia_ctime.tv_sec;
		arg->ctimensec = iattr->ia_ctime.tv_nsec;
	}
}

/*
 * Prevent concurrent writepages on inode
 *
 * This is done by adding a negative bias to the inode write counter
 * and waiting for all pending writes to finish.
 */
void vfuse_set_nowrite(struct inode *inode)
{
	struct vfuse_inode *fi = get_vfuse_inode(inode);

	BUG_ON(!inode_is_locked(inode));

	spin_lock(&fi->lock);
	BUG_ON(fi->writectr < 0);
	fi->writectr += VFUSE_NOWRITE;
	spin_unlock(&fi->lock);
	wait_event(fi->page_waitq, fi->writectr == VFUSE_NOWRITE);
}

/*
 * Allow writepages on inode
 *
 * Remove the bias from the writecounter and send any queued
 * writepages.
 */
static void __vfuse_release_nowrite(struct inode *inode)
{
	struct vfuse_inode *fi = get_vfuse_inode(inode);

	BUG_ON(fi->writectr != VFUSE_NOWRITE);
	fi->writectr = 0;
	vfuse_flush_writepages(inode);
}

void vfuse_release_nowrite(struct inode *inode)
{
	struct vfuse_inode *fi = get_vfuse_inode(inode);

	spin_lock(&fi->lock);
	__vfuse_release_nowrite(inode);
	spin_unlock(&fi->lock);
}

static void vfuse_setattr_fill(struct vfuse_conn *fc, struct vfuse_args *args,
			      struct inode *inode,
			      struct vfuse_setattr_in *inarg_p,
			      struct vfuse_attr_out *outarg_p)
{
	args->opcode = VFUSE_SETATTR;
	args->nodeid = get_node_id(inode);
	args->in_numargs = 1;
	args->in_args[0].size = sizeof(*inarg_p);
	args->in_args[0].value = inarg_p;
	args->out_numargs = 1;
	args->out_args[0].size = sizeof(*outarg_p);
	args->out_args[0].value = outarg_p;
}

/*
 * Flush inode->i_mtime to the server
 */
int vfuse_flush_times(struct inode *inode, struct vfuse_file *ff)
{
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	VFUSE_ARGS(args);
	struct vfuse_setattr_in inarg;
	struct vfuse_attr_out outarg;

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));

	inarg.valid = FATTR_MTIME;
	inarg.mtime = inode_get_mtime_sec(inode);
	inarg.mtimensec = inode_get_mtime_nsec(inode);
	if (fm->fc->minor >= 23) {
		inarg.valid |= FATTR_CTIME;
		inarg.ctime = inode_get_ctime_sec(inode);
		inarg.ctimensec = inode_get_ctime_nsec(inode);
	}
	if (ff) {
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	vfuse_setattr_fill(fm->fc, &args, inode, &inarg, &outarg);

	return vfuse_simple_request(fm, &args);
}

/*
 * Set attributes, and at the same time refresh them.
 *
 * Truncation is slightly complicated, because the 'truncate' request
 * may fail, in which case we don't want to touch the mapping.
 * vmtruncate() doesn't allow for this case, so do the rlimit checking
 * and the actual truncation by hand.
 */
int vfuse_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file)
{
	struct inode *inode = d_inode(dentry);
	struct vfuse_mount *fm = get_vfuse_mount(inode);
	struct vfuse_conn *fc = fm->fc;
	struct vfuse_inode *fi = get_vfuse_inode(inode);
	struct address_space *mapping = inode->i_mapping;
	VFUSE_ARGS(args);
	struct vfuse_setattr_in inarg;
	struct vfuse_attr_out outarg;
	bool is_truncate = false;
	bool is_wb = fc->writeback_cache && S_ISREG(inode->i_mode);
	loff_t oldsize;
	int err;
	bool trust_local_cmtime = is_wb;
	bool fault_blocked = false;
	u64 attr_version;

	if (!fc->default_permissions)
		attr->ia_valid |= ATTR_FORCE;

	err = setattr_prepare(&nop_mnt_idmap, dentry, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_SIZE) {
		if (WARN_ON(!S_ISREG(inode->i_mode)))
			return -EIO;
		is_truncate = true;
	}

	if (VFUSE_IS_DAX(inode) && is_truncate) {
		filemap_invalidate_lock(mapping);
		fault_blocked = true;
		err = vfuse_dax_break_layouts(inode, 0, 0);
		if (err) {
			filemap_invalidate_unlock(mapping);
			return err;
		}
	}

	if (attr->ia_valid & ATTR_OPEN) {
		/* This is coming from open(..., ... | O_TRUNC); */
		WARN_ON(!(attr->ia_valid & ATTR_SIZE));
		WARN_ON(attr->ia_size != 0);
		if (fc->atomic_o_trunc) {
			/*
			 * No need to send request to userspace, since actual
			 * truncation has already been done by OPEN.  But still
			 * need to truncate page cache.
			 */
			i_size_write(inode, 0);
			truncate_pagecache(inode, 0);
			goto out;
		}
		file = NULL;
	}

	/* Flush dirty data/metadata before non-truncate SETATTR */
	if (is_wb &&
	    attr->ia_valid &
			(ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_MTIME_SET |
			 ATTR_TIMES_SET)) {
		err = write_inode_now(inode, true);
		if (err)
			return err;

		vfuse_set_nowrite(inode);
		vfuse_release_nowrite(inode);
	}

	if (is_truncate) {
		vfuse_set_nowrite(inode);
		set_bit(VFUSE_I_SIZE_UNSTABLE, &fi->state);
		if (trust_local_cmtime && attr->ia_size != inode->i_size)
			attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
	}

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	iattr_to_fattr(fc, attr, &inarg, trust_local_cmtime);
	if (file) {
		struct vfuse_file *ff = file->private_data;
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}

	/* Kill suid/sgid for non-directory chown unconditionally */
	if (fc->handle_killpriv_v2 && !S_ISDIR(inode->i_mode) &&
	    attr->ia_valid & (ATTR_UID | ATTR_GID))
		inarg.valid |= FATTR_KILL_SUIDGID;

	if (attr->ia_valid & ATTR_SIZE) {
		/* For mandatory locking in truncate */
		inarg.valid |= FATTR_LOCKOWNER;
		inarg.lock_owner = vfuse_lock_owner_id(fc, current->files);

		/* Kill suid/sgid for truncate only if no CAP_FSETID */
		if (fc->handle_killpriv_v2 && !capable(CAP_FSETID))
			inarg.valid |= FATTR_KILL_SUIDGID;
	}

	attr_version = vfuse_get_attr_version(fm->fc);
	vfuse_setattr_fill(fc, &args, inode, &inarg, &outarg);
	err = vfuse_simple_request(fm, &args);
	if (err) {
		if (err == -EINTR)
			vfuse_invalidate_attr(inode);
		goto error;
	}

	if (vfuse_invalid_attr(&outarg.attr) ||
	    inode_wrong_type(inode, outarg.attr.mode)) {
		vfuse_make_bad(inode);
		err = -EIO;
		goto error;
	}

	spin_lock(&fi->lock);
	/* the kernel maintains i_mtime locally */
	if (trust_local_cmtime) {
		if (attr->ia_valid & ATTR_MTIME)
			inode_set_mtime_to_ts(inode, attr->ia_mtime);
		if (attr->ia_valid & ATTR_CTIME)
			inode_set_ctime_to_ts(inode, attr->ia_ctime);
		/* FIXME: clear I_DIRTY_SYNC? */
	}

	if (fi->attr_version > attr_version) {
		/*
		 * Apply attributes, for example for fsnotify_change(), but set
		 * attribute timeout to zero.
		 */
		outarg.attr_valid = outarg.attr_valid_nsec = 0;
	}

	vfuse_change_attributes_common(inode, &outarg.attr, NULL,
				      ATTR_TIMEOUT(&outarg),
				      vfuse_get_cache_mask(inode), 0);
	oldsize = inode->i_size;
	/* see the comment in vfuse_change_attributes() */
	if (!is_wb || is_truncate)
		i_size_write(inode, outarg.attr.size);

	if (is_truncate) {
		/* NOTE: this may release/reacquire fi->lock */
		__vfuse_release_nowrite(inode);
	}
	spin_unlock(&fi->lock);

	/*
	 * Only call invalidate_inode_pages2() after removing
	 * VFUSE_NOWRITE, otherwise vfuse_launder_folio() would deadlock.
	 */
	if ((is_truncate || !is_wb) &&
	    S_ISREG(inode->i_mode) && oldsize != outarg.attr.size) {
		truncate_pagecache(inode, outarg.attr.size);
		invalidate_inode_pages2(mapping);
	}

	clear_bit(VFUSE_I_SIZE_UNSTABLE, &fi->state);
out:
	if (fault_blocked)
		filemap_invalidate_unlock(mapping);

	return 0;

error:
	if (is_truncate)
		vfuse_release_nowrite(inode);

	clear_bit(VFUSE_I_SIZE_UNSTABLE, &fi->state);

	if (fault_blocked)
		filemap_invalidate_unlock(mapping);
	return err;
}

static int vfuse_setattr(struct mnt_idmap *idmap, struct dentry *entry,
			struct iattr *attr)
{
	struct inode *inode = d_inode(entry);
	struct vfuse_conn *fc = get_vfuse_conn(inode);
	struct file *file = (attr->ia_valid & ATTR_FILE) ? attr->ia_file : NULL;
	int ret;

	if (vfuse_is_bad(inode))
		return -EIO;

	if (!vfuse_allow_current_process(get_vfuse_conn(inode)))
		return -EACCES;

	if (attr->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID)) {
		attr->ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID |
				    ATTR_MODE);

		/*
		 * The only sane way to reliably kill suid/sgid is to do it in
		 * the userspace filesystem
		 *
		 * This should be done on write(), truncate() and chown().
		 */
		if (!fc->handle_killpriv && !fc->handle_killpriv_v2) {
			/*
			 * ia_mode calculation may have used stale i_mode.
			 * Refresh and recalculate.
			 */
			ret = vfuse_do_getattr(inode, NULL, file);
			if (ret)
				return ret;

			attr->ia_mode = inode->i_mode;
			if (inode->i_mode & S_ISUID) {
				attr->ia_valid |= ATTR_MODE;
				attr->ia_mode &= ~S_ISUID;
			}
			if ((inode->i_mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
				attr->ia_valid |= ATTR_MODE;
				attr->ia_mode &= ~S_ISGID;
			}
		}
	}
	if (!attr->ia_valid)
		return 0;

	ret = vfuse_do_setattr(entry, attr, file);
	if (!ret) {
		/*
		 * If filesystem supports acls it may have updated acl xattrs in
		 * the filesystem, so forget cached acls for the inode.
		 */
		if (fc->posix_acl)
			forget_all_cached_acls(inode);

		/* Directory mode changed, may need to revalidate access */
		if (d_is_dir(entry) && (attr->ia_valid & ATTR_MODE))
			vfuse_invalidate_entry_cache(entry);
	}
	return ret;
}

static int vfuse_getattr(struct mnt_idmap *idmap,
			const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct vfuse_conn *fc = get_vfuse_conn(inode);

	if (vfuse_is_bad(inode))
		return -EIO;

	if (!vfuse_allow_current_process(fc)) {
		if (!request_mask) {
			/*
			 * If user explicitly requested *nothing* then don't
			 * error out, but return st_dev only.
			 */
			stat->result_mask = 0;
			stat->dev = inode->i_sb->s_dev;
			return 0;
		}
		return -EACCES;
	}

	return vfuse_update_get_attr(inode, NULL, stat, request_mask, flags);
}

static const struct inode_operations vfuse_dir_inode_operations = {
	.lookup		= vfuse_lookup,
	.mkdir		= vfuse_mkdir,
	.symlink	= vfuse_symlink,
	.unlink		= vfuse_unlink,
	.rmdir		= vfuse_rmdir,
	.rename		= vfuse_rename2,
	.link		= vfuse_link,
	.setattr	= vfuse_setattr,
	.create		= vfuse_create,
	.atomic_open	= vfuse_atomic_open,
	.tmpfile	= vfuse_tmpfile,
	.mknod		= vfuse_mknod,
	.permission	= vfuse_permission,
	.getattr	= vfuse_getattr,
	.listxattr	= vfuse_listxattr,
	.get_inode_acl	= vfuse_get_inode_acl,
	.get_acl	= vfuse_get_acl,
	.set_acl	= vfuse_set_acl,
	.fileattr_get	= vfuse_fileattr_get,
	.fileattr_set	= vfuse_fileattr_set,
};

static const struct file_operations vfuse_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= vfuse_readdir,
	.open		= vfuse_dir_open,
	.release	= vfuse_dir_release,
	.fsync		= vfuse_dir_fsync,
	.unlocked_ioctl	= vfuse_dir_ioctl,
	.compat_ioctl	= vfuse_dir_compat_ioctl,
};

static const struct inode_operations vfuse_common_inode_operations = {
	.setattr	= vfuse_setattr,
	.permission	= vfuse_permission,
	.getattr	= vfuse_getattr,
	.listxattr	= vfuse_listxattr,
	.get_inode_acl	= vfuse_get_inode_acl,
	.get_acl	= vfuse_get_acl,
	.set_acl	= vfuse_set_acl,
	.fileattr_get	= vfuse_fileattr_get,
	.fileattr_set	= vfuse_fileattr_set,
};

static const struct inode_operations vfuse_symlink_inode_operations = {
	.setattr	= vfuse_setattr,
	.get_link	= vfuse_get_link,
	.getattr	= vfuse_getattr,
	.listxattr	= vfuse_listxattr,
};

void vfuse_init_common(struct inode *inode)
{
	inode->i_op = &vfuse_common_inode_operations;
}

void vfuse_init_dir(struct inode *inode)
{
	struct vfuse_inode *fi = get_vfuse_inode(inode);

	inode->i_op = &vfuse_dir_inode_operations;
	inode->i_fop = &vfuse_dir_operations;

	spin_lock_init(&fi->rdc.lock);
	fi->rdc.cached = false;
	fi->rdc.size = 0;
	fi->rdc.pos = 0;
	fi->rdc.version = 0;
}

static int vfuse_symlink_read_folio(struct file *null, struct folio *folio)
{
	int err = vfuse_readlink_page(folio->mapping->host, &folio->page);

	if (!err)
		folio_mark_uptodate(folio);

	folio_unlock(folio);

	return err;
}

static const struct address_space_operations vfuse_symlink_aops = {
	.read_folio	= vfuse_symlink_read_folio,
};

void vfuse_init_symlink(struct inode *inode)
{
	inode->i_op = &vfuse_symlink_inode_operations;
	inode->i_data.a_ops = &vfuse_symlink_aops;
	inode_nohighmem(inode);
}
