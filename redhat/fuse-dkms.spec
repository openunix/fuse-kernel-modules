# PACKAGE_VERSION in dkms.conf
%{?!fuse_version: %define fuse_version 7.39.0}
# Release is specific for rpm, not source
%{?!fuse_release: %define fuse_release 1}

Name:           fuse-dkms

Version:        %{fuse_version}
Release:        %{fuse_release}%{?dist}
Summary:        Fuse Kernel Modules - dkms

Group:          System Environment/Kernel
License:        GPLv2
URL:            https://github.com/openunix/fuse-kernel-modules
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

Requires:       dkms
Provides:	fuse-kmod = %{version}

BuildArch:      noarch

%description
The dkms package of FUSE kernel modules.

%prep
%setup -q -n fuse-kernel-modules-%{version}

%install
mkdir -p $RPM_BUILD_ROOT/usr/src
cp -a src $RPM_BUILD_ROOT/usr/src/fuse-%{version}

%post
# add the package to DKMS
if [ -f /usr/lib/dkms/common.postinst ]; then
  /usr/lib/dkms/common.postinst fuse %{version}
else
  echo "Cannot find rpm post install helper of dkms. Manually install by"
  echo "dkms [add|install] -m fuse -v %{version}"
fi


%preun
# remove the package from DKMS
if [ "$(dkms status -m fuse -v %{version})" ]; then
  dkms remove -m fuse -v %{version} --all
fi


%files
%license LICENSE
%doc README.md
%defattr(-, root, root)
/usr/src/fuse-%{version}

%changelog
* Tue Sep 23 2025 Shuo Feng <steve.shuo.feng@gmail.com>
- Initial created to support dkms
