%{!?release: %define release 1}
%{!?version: %define version 0.0.1}
%define name skc-libmaxminddb

Name:  %{name}
Version:    %{version}
Release:    %{release}
Summary:    skycloud Openresty
License:    GPL
URL:        https://www.skycloud.com.tw
BuildRequires:  gcc-c++, automake, autoconf, libtool
#Requires:   
BuildArch:  x86_64

%description
SkyCloud Lib Maxminddb


%prep
# Clean
rm -rf %{_builddir}/*
# Copy Openresty source code to build dir
find %{_topdir}/../../ \
    -maxdepth 1 \
    -mindepth 1 \
    -not -name ansible \
    -not -name .git \
    -exec cp -Ra "{}" %{_builddir} \;


%build
cd %_builddir/
./bootstrap
#./configure --prefix=/usr
./configure --prefix=/usr/local/src/libmaxminddb --with-pic
make -j `nproc`
make check


%install
# Install Openresty into BUILDROOT
rm -rf %{buildroot}
cd  %{_builddir}
make install DESTDIR=%{buildroot}


%files
#%defattr(644,root,root,755)
#%attr(0755, root, root) /usr/bin/*
#%doc /usr/share/*
#/usr/include/*
#/usr/lib/*
#
%attr(0755, root, root) /usr/local/src/libmaxminddb/bin/*
%doc /usr/local/src/libmaxminddb/share/*
/usr/local/src/libmaxminddb/include/*
/usr/local/src/libmaxminddb/lib/*

%post
ldconfig


%changelog
* Tue Apr  2 2024 Change Path
- Change install path to /usr/local/src/libmaxminddb
* Thu Sep 18 2023 New
- First release

