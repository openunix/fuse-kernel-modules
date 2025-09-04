# FUSE Kernel Modules
This is the backport of fuse kernel modules. Currently it supports RHEL/Rocky 9.5 and 9.6. It will upgrade the fuse API version from 7.37 to 7.39 and provide io_uring support.

Building [Kmods and akmods](https://rpmfusion.org/Packaging/KernelModules) are supported through [kmodtool](https://packages.fedoraproject.org/pkgs/kmodtool/kmodtool/): 
1. Install `kmodtool`, `rpmbuild`, and related kernel module tools if dependencies don't install them.
2. Download the latest version from [github releases](https://github.com/openunix/fuse-kernel-modules/releases)
3. Copy the downloaded file to your `rpmbuild/SOURCES` directory. You may also need to untar it to get the spec files.
4. Build user space rpm by [redhat/fuse-kernel-modules.spec](redhat/fuse-kernel-modules.spec).
5. Build kernel modules rpm by [redhat/fuse-kmod.spec](redhat/fuse-kmod.spec).  

By default, the akmods will be built. To build kmods, pass the kernel versions by `--define kernels`. For example:

    # Build user space modules
    rpmbuild -ba redhat/fuse-kernel-modules.spec
    # Build akmods
    rpmbuild -ba redhat/fuse-kmod.spec
    # Build kmods
    rpmbuild -ba --define "kernels 5.14.0-570.26.1.el9_6.x86_64 5.14.0-503.40.1.el9_5.x86_64" \
                 redhat/fuse-kmod.spec
Currently only the above two kernel versions are supported for building kmods while it should be good enough to support all RHEL/Rocky 9.5/9.6 kernels. You will need to install the kernel-devel rpms. You may use this [workflow file](.github/workflows/rpm-build_x86_64.yml) as a reference.

Direct `make` and `make install` are also supported. Use [src/5.14.0-503.40.1.el9_5](src/5.14.0-503.40.1.el9_5) for RHEL/Rocky 9.5 and [src/5.14.0-570.26.1.el9_6](src/5.14.0-570.26.1.el9_6) for RHEL/Rocky 9.6. Do not `make` at the top directory.

The codes under [src](src) are maintained at https://github.com/openunix/linux . Raising PRs or issues for either of the two projects are welcomed.

