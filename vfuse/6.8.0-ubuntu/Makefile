# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the FUSE filesystem.
#

# Needed for trace events
ccflags-y := -DCONFIG_VFUSE_IO_URING=1 -I$(src)

obj-m += vfuse.o
vfuse-y := dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o
vfuse-y += iomode.o dax.o dev_uring.o sysctl.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

.PHONY: clean
