Name:          pgvictoria
Version:       0.20.0
Release:       1%{dist}
Summary:       Backup / restore for PostgreSQL
License:       BSD
URL:           https://github.com/pgvictoria/pgvictoria
Source0:       https://github.com/pgvictoria/pgvictoria/archive/%{version}.tar.gz

BuildRequires: gcc cmake make python3-docutils
BuildRequires: libev libev-devel openssl openssl-devel
Requires:      libev openssl

%description
pgvictoria is a tuning solution for PostgreSQL.

%prep
%setup -q

%build

%{__mkdir} build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
%{__make}

%install

%{__mkdir} -p %{buildroot}%{_sysconfdir}
%{__mkdir} -p %{buildroot}%{_bindir}
%{__mkdir} -p %{buildroot}%{_libdir}

%{__install} -m 644 %{_builddir}/%{name}-%{version}/LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
%{__install} -m 644 %{_builddir}/%{name}-%{version}/CODE_OF_CONDUCT.md %{buildroot}%{_docdir}/%{name}/CODE_OF_CONDUCT.md
%{__install} -m 644 %{_builddir}/%{name}-%{version}/README.md %{buildroot}%{_docdir}/%{name}/README.md

%{__install} -m 755 %{_builddir}/%{name}-%{version}/build/src/pgvictoria %{buildroot}%{_bindir}/pgvictoria

%{__install} -m 755 %{_builddir}/%{name}-%{version}/build/src/libpgvictoria.so.%{version} %{buildroot}%{_libdir}/libpgvictoria.so.%{version}

chrpath -r %{_libdir} %{buildroot}%{_bindir}/pgvictoria

cd %{buildroot}%{_libdir}/
%{__ln_s} -f libpgvictoria.so.%{version} libpgvictoria.so.0
%{__ln_s} -f libpgvictoria.so.0 libpgvictoria.so

%files
%license %{_docdir}/%{name}/LICENSE
%{_docdir}/%{name}/CODE_OF_CONDUCT.md
%{_docdir}/%{name}/README.md
%{_bindir}/pgvictoria
%{_libdir}/libpgvictoria.so
%{_libdir}/libpgvictoria.so.0
%{_libdir}/libpgvictoria.so.%{version}

%changelog
