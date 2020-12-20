Summary: SELinux policy source file checker
Name: selint
Version: 1.1.0
Release: 1%{?dist}
URL: https://github.com/TresysTechnology/selint
License: ASL 2.0
%global forgeurl https://github.com/TresysTechnology/selint
%global branch master
# handle not having forge macros on el7
%{!?forgesoure: %define forgesource %forgeurl/archive/%branch/selint-%branch.tar.gz}
%{!?forgesetup: %define forgesetup %setup -n %name-%branch}
%{!?forgemeta: %define forgemeta %nil}
%forgemeta
Source0: %{forgesource}

BuildRequires: autoconf autoconf-archive automake bison check check-devel flex gcc help2man libconfuse libconfuse-devel uthash-devel
# pkgconfig
Requires: libconfuse
%if 0%{?fedora} || 0%{?rhel} >= 8
Requires: check
%endif

%description
SELint is a program to perform static code analysis on SELinux policy source files

%prep
%forgesetup

%build
[[ -x ./configure ]] || ./autogen.sh
%if 0%{?rhel} == 7
%{configure} --without-check
%else
%{configure}
%endif

%{make_build}

%install
%{make_install}

%files
%license LICENSE
%doc CHANGELOG README
%{_bindir}/selint
%config(noreplace) %{_sysconfdir}/selint.conf
%{_mandir}/man1/selint.1.gz
