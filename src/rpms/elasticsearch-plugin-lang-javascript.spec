%define debug_package %{nil}

# Avoid running brp-java-repack-jars
%define __os_install_post %{nil}

Name:           elasticsearch-plugin-lang-javascript
Version:        1.1.0
Release:        1%{?dist}
Summary:        ElasticSearch plugin to use Javascript for script execution.

Group:          System Environment/Daemons
License:        ASL 2.0
URL:            https://github.com/elasticsearch/elasticsearch-lang-javascript

Source0:        https://github.com/downloads/elasticsearch/elasticsearch-lang-javascript/elasticsearch-lang-javascript-1.1.0.zip
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

Requires:       elasticsearch >= 0.19

%description
The Groovy language plugin allows to have javascript as the language of scripts to execute.

%prep
rm -fR %{name}-%{version}
%{__mkdir} -p %{name}-%{version}
cd %{name}-%{version}
%{__mkdir} -p plugins
unzip %{SOURCE0} -d plugins/lang-javascript

%build
true

%install
rm -rf $RPM_BUILD_ROOT
cd %{name}-%{version}
%{__mkdir} -p %{buildroot}/opt/elasticsearch/plugins
%{__install} -D -m 755 plugins/lang-javascript/elasticsearch-lang-javascript-%{version}.jar %{buildroot}/opt/elasticsearch/plugins/lang-javascript/elasticsearch-lang-javascript.jar
%{__install} -D -m 755 plugins/lang-javascript/rhino-1.7R3.jar -t %{buildroot}/opt/elasticsearch/plugins/lang-javascript/

%files
%defattr(-,root,root,-)
%dir /opt/elasticsearch/plugins/lang-javascript
/opt/elasticsearch/plugins/lang-javascript/*

%changelog
* Tue Feb 22 2012 Sean Laurent
- Initial package

