# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the FUSE filesystem.
#

obj-m += fuse.o
fuse-y := dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o iomode.o dev_uring.o sysctl.o
fuse-$(CONFIG_FUSE_DAX) += dax.o

ccflags-y := -DCONFIG_FUSE_IO_URING=1 -I$(src)

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	install -D fuse.ko /lib/modules/$(shell uname -r)/extra/fuse.ko

modsign:
	/lib/modules/$(shell uname -r)/build/scripts/sign-file sha512 /var/lib/dkms/mok.key /var/lib/dkms/mok.pub /lib/modules/$(shell uname -r)/extra/fuse.ko

.PHONY: clean
