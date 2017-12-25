Name: jupiter
Version: %{_version}
Release: 1
Summary: jupiter load balancer

Group: none
License: MIT
URL: none
Source: jupiter-%{_version}.tar.xz

BuildRequires: numactl-devel, libpcap-devel

# Requires:

%description
jupiter load balancer.
machine=%{_machine}.

%prep
%setup -q

%build
make machine=%{_machine}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot} bindir=%{_bindir} tooldir=%{_datadir}/jupiter/tools confdir=/etc/jupiter machine=%{_machine}

%files
%{_bindir}/*
%{_datadir}/jupiter
/etc/jupiter

%post
/sbin/ldconfig
/sbin/depmod

%postun
/sbin/ldconfig
/sbin/depmod
