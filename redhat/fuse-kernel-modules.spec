%global debug_package %{nil}

Name:           fuse-kernel-modules
Version:        7.39.0
Release:        1%{?dist}
Summary:        Fuse Kernel Modules

License:        GPLv2
URL:            https://github.com/openunix/fuse-kernel-modules
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

Requires:       fuse-kmod >= %{version}
Provides:       fuse-kmod-common = %{version}

#BuildRequires:
BuildArch:      noarch

%description


%prep
%autosetup


%build
#configure
#make_build


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
#make_install


%files
%license LICENSE
%doc README.md



%changelog
* Wed Sep 03 2025 Shuo Feng <steve.shuo.feng@gmail.com>
- Initial created to support fuse-kmod.
