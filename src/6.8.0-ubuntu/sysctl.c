// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/vfuse/vfuse_sysctl.c
 *
 * Sysctl interface to vfuse parameters
 */
#include <linux/sysctl.h>

#include "vfuse_i.h"

static struct ctl_table_header *vfuse_table_header;

/* Bound by vfuse_init_out max_pages, which is a u16 */
static unsigned int sysctl_vfuse_max_pages_limit = 65535;

static struct ctl_table vfuse_sysctl_table[] = {
	{
		.procname	= "max_pages_limit",
		.data		= &vfuse_max_pages_limit,
		.maxlen		= sizeof(vfuse_max_pages_limit),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= &sysctl_vfuse_max_pages_limit,
	},
};

int vfuse_sysctl_register(void)
{
	vfuse_table_header = register_sysctl("fs/vfuse", vfuse_sysctl_table);
	if (!vfuse_table_header)
		return -ENOMEM;
	return 0;
}

void vfuse_sysctl_unregister(void)
{
	unregister_sysctl_table(vfuse_table_header);
	vfuse_table_header = NULL;
}
