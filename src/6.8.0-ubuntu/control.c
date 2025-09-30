/*
  VFUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "vfuse_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs_context.h>

#define VFUSE_CTL_SUPER_MAGIC 0x65735543

/*
 * This is non-NULL when the single instance of the control filesystem
 * exists.  Protected by vfuse_mutex
 */
static struct super_block *vfuse_control_sb;

static struct vfuse_conn *vfuse_ctl_file_conn_get(struct file *file)
{
	struct vfuse_conn *fc;
	mutex_lock(&vfuse_mutex);
	fc = file_inode(file)->i_private;
	if (fc)
		fc = vfuse_conn_get(fc);
	mutex_unlock(&vfuse_mutex);
	return fc;
}

static ssize_t vfuse_conn_abort_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct vfuse_conn *fc = vfuse_ctl_file_conn_get(file);
	if (fc) {
		if (fc->abort_err)
			fc->aborted = true;
		vfuse_abort_conn(fc);
		vfuse_conn_put(fc);
	}
	return count;
}

static ssize_t vfuse_conn_waiting_read(struct file *file, char __user *buf,
				      size_t len, loff_t *ppos)
{
	char tmp[32];
	size_t size;

	if (!*ppos) {
		long value;
		struct vfuse_conn *fc = vfuse_ctl_file_conn_get(file);
		if (!fc)
			return 0;

		value = atomic_read(&fc->num_waiting);
		file->private_data = (void *)value;
		vfuse_conn_put(fc);
	}
	size = sprintf(tmp, "%ld\n", (long)file->private_data);
	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t vfuse_conn_limit_read(struct file *file, char __user *buf,
				    size_t len, loff_t *ppos, unsigned val)
{
	char tmp[32];
	size_t size = sprintf(tmp, "%u\n", val);

	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t vfuse_conn_limit_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos, unsigned *val,
				     unsigned global_limit)
{
	unsigned long t;
	unsigned limit = (1 << 16) - 1;
	int err;

	if (*ppos)
		return -EINVAL;

	err = kstrtoul_from_user(buf, count, 0, &t);
	if (err)
		return err;

	if (!capable(CAP_SYS_ADMIN))
		limit = min(limit, global_limit);

	if (t > limit)
		return -EINVAL;

	*val = t;

	return count;
}

static ssize_t vfuse_conn_max_background_read(struct file *file,
					     char __user *buf, size_t len,
					     loff_t *ppos)
{
	struct vfuse_conn *fc;
	unsigned val;

	fc = vfuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = READ_ONCE(fc->max_background);
	vfuse_conn_put(fc);

	return vfuse_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t vfuse_conn_max_background_write(struct file *file,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	unsigned val;
	ssize_t ret;

	ret = vfuse_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_bgreq);
	if (ret > 0) {
		struct vfuse_conn *fc = vfuse_ctl_file_conn_get(file);
		if (fc) {
			spin_lock(&fc->bg_lock);
			fc->max_background = val;
			fc->blocked = fc->num_background >= fc->max_background;
			if (!fc->blocked)
				wake_up(&fc->blocked_waitq);
			spin_unlock(&fc->bg_lock);
			vfuse_conn_put(fc);
		}
	}

	return ret;
}

static ssize_t vfuse_conn_congestion_threshold_read(struct file *file,
						   char __user *buf, size_t len,
						   loff_t *ppos)
{
	struct vfuse_conn *fc;
	unsigned val;

	fc = vfuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = READ_ONCE(fc->congestion_threshold);
	vfuse_conn_put(fc);

	return vfuse_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t vfuse_conn_congestion_threshold_write(struct file *file,
						    const char __user *buf,
						    size_t count, loff_t *ppos)
{
	unsigned val;
	struct vfuse_conn *fc;
	ssize_t ret;

	ret = vfuse_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_congthresh);
	if (ret <= 0)
		goto out;
	fc = vfuse_ctl_file_conn_get(file);
	if (!fc)
		goto out;

	down_read(&fc->killsb);
	spin_lock(&fc->bg_lock);
	fc->congestion_threshold = val;
	spin_unlock(&fc->bg_lock);
	up_read(&fc->killsb);
	vfuse_conn_put(fc);
out:
	return ret;
}

static const struct file_operations vfuse_ctl_abort_ops = {
	.open = nonseekable_open,
	.write = vfuse_conn_abort_write,
	.llseek = no_llseek,
};

static const struct file_operations vfuse_ctl_waiting_ops = {
	.open = nonseekable_open,
	.read = vfuse_conn_waiting_read,
	.llseek = no_llseek,
};

static const struct file_operations vfuse_conn_max_background_ops = {
	.open = nonseekable_open,
	.read = vfuse_conn_max_background_read,
	.write = vfuse_conn_max_background_write,
	.llseek = no_llseek,
};

static const struct file_operations vfuse_conn_congestion_threshold_ops = {
	.open = nonseekable_open,
	.read = vfuse_conn_congestion_threshold_read,
	.write = vfuse_conn_congestion_threshold_write,
	.llseek = no_llseek,
};

static struct dentry *vfuse_ctl_add_dentry(struct dentry *parent,
					  struct vfuse_conn *fc,
					  const char *name,
					  int mode, int nlink,
					  const struct inode_operations *iop,
					  const struct file_operations *fop)
{
	struct dentry *dentry;
	struct inode *inode;

	BUG_ON(fc->ctl_ndents >= VFUSE_CTL_NUM_DENTRIES);
	dentry = d_alloc_name(parent, name);
	if (!dentry)
		return NULL;

	inode = new_inode(vfuse_control_sb);
	if (!inode) {
		dput(dentry);
		return NULL;
	}

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_uid = fc->user_id;
	inode->i_gid = fc->group_id;
	simple_inode_init_ts(inode);
	/* setting ->i_op to NULL is not allowed */
	if (iop)
		inode->i_op = iop;
	inode->i_fop = fop;
	set_nlink(inode, nlink);
	inode->i_private = fc;
	d_add(dentry, inode);

	fc->ctl_dentry[fc->ctl_ndents++] = dentry;

	return dentry;
}

/*
 * Add a connection to the control filesystem (if it exists).  Caller
 * must hold vfuse_mutex
 */
int vfuse_ctl_add_conn(struct vfuse_conn *fc)
{
	struct dentry *parent;
	char name[32];

	if (!vfuse_control_sb || fc->no_control)
		return 0;

	parent = vfuse_control_sb->s_root;
	inc_nlink(d_inode(parent));
	sprintf(name, "%u", fc->dev);
	parent = vfuse_ctl_add_dentry(parent, fc, name, S_IFDIR | 0500, 2,
				     &simple_dir_inode_operations,
				     &simple_dir_operations);
	if (!parent)
		goto err;

	if (!vfuse_ctl_add_dentry(parent, fc, "waiting", S_IFREG | 0400, 1,
				 NULL, &vfuse_ctl_waiting_ops) ||
	    !vfuse_ctl_add_dentry(parent, fc, "abort", S_IFREG | 0200, 1,
				 NULL, &vfuse_ctl_abort_ops) ||
	    !vfuse_ctl_add_dentry(parent, fc, "max_background", S_IFREG | 0600,
				 1, NULL, &vfuse_conn_max_background_ops) ||
	    !vfuse_ctl_add_dentry(parent, fc, "congestion_threshold",
				 S_IFREG | 0600, 1, NULL,
				 &vfuse_conn_congestion_threshold_ops))
		goto err;

	return 0;

 err:
	vfuse_ctl_remove_conn(fc);
	return -ENOMEM;
}

/*
 * Remove a connection from the control filesystem (if it exists).
 * Caller must hold vfuse_mutex
 */
void vfuse_ctl_remove_conn(struct vfuse_conn *fc)
{
	int i;

	if (!vfuse_control_sb || fc->no_control)
		return;

	for (i = fc->ctl_ndents - 1; i >= 0; i--) {
		struct dentry *dentry = fc->ctl_dentry[i];
		d_inode(dentry)->i_private = NULL;
		if (!i) {
			/* Get rid of submounts: */
			d_invalidate(dentry);
		}
		dput(dentry);
	}
	drop_nlink(d_inode(vfuse_control_sb->s_root));
}

static int vfuse_ctl_fill_super(struct super_block *sb, struct fs_context *fsc)
{
	static const struct tree_descr empty_descr = {""};
	struct vfuse_conn *fc;
	int err;

	err = simple_fill_super(sb, VFUSE_CTL_SUPER_MAGIC, &empty_descr);
	if (err)
		return err;

	mutex_lock(&vfuse_mutex);
	BUG_ON(vfuse_control_sb);
	vfuse_control_sb = sb;
	list_for_each_entry(fc, &vfuse_conn_list, entry) {
		err = vfuse_ctl_add_conn(fc);
		if (err) {
			vfuse_control_sb = NULL;
			mutex_unlock(&vfuse_mutex);
			return err;
		}
	}
	mutex_unlock(&vfuse_mutex);

	return 0;
}

static int vfuse_ctl_get_tree(struct fs_context *fsc)
{
	return get_tree_single(fsc, vfuse_ctl_fill_super);
}

static const struct fs_context_operations vfuse_ctl_context_ops = {
	.get_tree	= vfuse_ctl_get_tree,
};

static int vfuse_ctl_init_fs_context(struct fs_context *fsc)
{
	fsc->ops = &vfuse_ctl_context_ops;
	return 0;
}

static void vfuse_ctl_kill_sb(struct super_block *sb)
{
	struct vfuse_conn *fc;

	mutex_lock(&vfuse_mutex);
	vfuse_control_sb = NULL;
	list_for_each_entry(fc, &vfuse_conn_list, entry)
		fc->ctl_ndents = 0;
	mutex_unlock(&vfuse_mutex);

	kill_litter_super(sb);
}

static struct file_system_type vfuse_ctl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "vfusectl",
	.init_fs_context = vfuse_ctl_init_fs_context,
	.kill_sb	= vfuse_ctl_kill_sb,
};
MODULE_ALIAS_FS("vfusectl");

int __init vfuse_ctl_init(void)
{
	return register_filesystem(&vfuse_ctl_fs_type);
}

void __exit vfuse_ctl_cleanup(void)
{
	unregister_filesystem(&vfuse_ctl_fs_type);
}
