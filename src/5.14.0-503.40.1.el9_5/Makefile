# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the FUSE filesystem.
#

# Needed for trace events
ccflags-y := -DCONFIG_FUSE_IO_URING=1 -I$(src)

obj-m += fuse.o cuse.o virtiofs.o
fuse-y := dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o
fuse-y += iomode.o dax.o dev_uring.o sysctl.o

virtiofs-y := virtio_fs.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	install -D fuse.ko /lib/modules/$(shell uname -r)/extra/fuse.ko

modsign:
	/lib/modules/$(shell uname -r)/build/scripts/sign-file sha512 /var/lib/dkms/mok.key /var/lib/dkms/mok.pub /lib/modules/$(shell uname -r)/extra/fuse.ko

.PHONY: clean
