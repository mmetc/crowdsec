
---

XXX update this

The CrowdSec Wizard
===================

TL;DR
-----

The wizard is a (work in progress) replacement for the `wizard.sh` shell script that is used to install or configure crowdsec, often without the user's knowledge.

It can

 - detect the installed services on a server
 - detect the OS family (linux, freebsd, windows), OS version and the linux distribution
 - install the recommended collections based on the detection result
 - generate the appropriate acquis.yaml documents

when finished, it could also be able to:

 - install crowdsec and cscli in the appropriate locations, configure and upgrade/uninstall them
 - interactively ask to confirm the collections to install, or the log paths
 - recommend bouncers (?)
 - ?


Detecting services
==================

After installing crowdsec, you need to decide which parsers/scenarios are appropriate for your environment, and configure the log locations of each service.

The wizard command is an attempt to automate this step as much as possible.

It uses a set of rules, defined in a file distributed with the
hub (`detect.yaml`), to see which services are installed on a system, and how they are managed: for example, if they are using systemd. Then it recommends the appropriate collections and acquisition rules.

Detection and installation are performed as separate steps, as you can see in the following diagram.

```
 +-------------+
 |             |
 | detect.yaml |
 |             |
 +-------------+
        |
        v
  setup detect
        |
        v
 +--------------+
 |              +---> setup install-collections
 |  setup.yaml  |
 |              +---> setup generate-acquis --> etc/crowdsec/acquis.d
 +--------------+
```

You can inspect and customize the intermediary file (`setup.yaml`) to your needs, which can be especially useful if you have many instances or an unusual setup.



Basic usage
-----------

Identify the existing services and write out what was detected:

```sh
# cscli setup detect > setup.yaml
```

See what was found.

```sh
# cscli setup install-collections setup.yaml --dry-run
dry-run: would install collection crowdsecurity/apache2
dry-run: would install collection crowdsecurity/linux
```

Install the objects (parsers, scenarios...) required to support the detected services:

```sh
# cscli setup install-collections setup.yaml
INFO[29-06-2022 03:16:14 PM] crowdsecurity/apache2-logs : OK              
INFO[29-06-2022 03:16:14 PM] Enabled parsers : crowdsecurity/apache2-logs 
INFO[29-06-2022 03:16:14 PM] crowdsecurity/http-logs : OK             
[...]
INFO[29-06-2022 03:16:18 PM] Enabled crowdsecurity/linux      
```

Generate the log acquisition configuration:

```sh
# cscli setup generate-acquis setup.yaml --to-dir /etc/crowdsec/acquis.d
```



The detect.yaml file
====================

A detect.yaml file is downloaded with the Hub, it can also be changed or created by a user/administrator according to their needs.


```yaml
version: 1.0

services:

  apache2:
    when:
      - ProcessRunning("apache2")
    collection: crowdsecurity/apache2
    acquis:
      labels:
        type: apache2
      log_files:
        - /var/log/apache2/*.log
        - /var/log/*http*/*.log
        - /var/log/httpd/*.log

  apache2-systemd:
    when:
      - UnitFound("apache2.service")
      - OS.ID != "centos"
    collection: crowdsecurity/apache2
    acquis:
      journalctl_filter:
        - "_SYSTEMD_UNIT=mock-apache2.service"

  apache2-systemd-centos:
    when:
      - UnitFound("httpd.service")
      - OS.ID == "centos"
    collection: crowdsecurity/apache2
    acquis:
      journalctl_filter:
        - "_SYSTEMD_UNIT=httpd.service"

  # [...]

  linux:
    when:
      - OS.Family == "linux"
    collection: crowdsecurity/linux
    acquis:
      labels:
        type: syslog
      log_files:
      - /var/log/syslog
      - /var/log/kern.log
      - /var/log/messages

  freebsd:
    when:
      - OS.Family == "freebsd"
    collection: crowdsecurity/freebsd

  windows:
    when:
      - OS.Family == "windows"
    collection: crowdsecurity/windows
```

The above file uses three detection methods:

1) `ProcessRunning()` matches the process name of a running application. The `when:` clause can contain any number of expressions, they are all evaluated and must all return true for a service to be detected (and clause, no short-circuit). The [expression engine](https://github.com/antonmedv/expr/blob/master/docs/Language-Definition.md) is the same one used by CrowdSec parser filters. You can force the detection of a process by usin the `cscli detect... --force-process <processname>` flag.

2) `UnitFound()` matches the name of Systemd units (regardless of the running status). You can see here that CentOS is using a different unit name for Apache so it must have its own service section. You can force the detection of a unit by usin the `cscli detect... --force-unit <unitname>` flag.

3) OS.Family, OS.ID and OS.RawVersion are read from /etc/os-release in case of Linux, and detected by other methods for FreeBSD and Windows. Under FreeBSD and Windows, the value of OS.ID is the same as OS.Family. If OS detection fails, it can be overridden by the flags `--force-os-family`, `--force-os-id` and `--force-os-version`.

Note that each service can only recommend one collection.

If you want to ignore one or more services (i.e. not install anything and not generate acquisition rules) you can specify it with `cscli detect... --skip-service <servicename>`. For example, `--skip-service linux`.

If you used the `--force-process` or `--force-unit` flags, but none of the defined services is looking for them, you'll have an error like "detecting services: process(es) forced but not supported".

The OS object contains a methods to check for version numbers: `OS.VersionCheck("<constraint>")`. It uses the [Masterminds/semver](https://github.com/Masterminds/semver) package and accepts a variety of operators.

Instead of: OS.RawVersion == "1.2.3" you should use `OS.VersionCheck("~1")`, `OS.VersionCheck("~1.2")` depending if you want to match the major or the minor version. It's unlikely that you need to match the exact patch level.

Leading zeroes are permitted, to allow comparison of Ubuntu versions: strict semver rules would treat "22.04" as invalid.


The `setup.yaml` file
=====================

This files does not actually have a defined name, as it's usually generated to standard output.

For example, on a Linux system running Apache under systemd you can execute:

```yaml
# cscli setup detect --yaml
setup:
  - detected_service: apache2-systemd
    collection: crowdsecurity/apache2
    acquis:
      journalctl_filter:
        - _SYSTEMD_UNIT=mock-apache2.service
  - detected_service: linux
    collection: crowdsecurity/linux
    acquis:
      labels:
        type: syslog
      log_files:
        - /var/log/syslog
        - /var/log/kern.log
        - /var/log/messages
```

The default output format is JSON, which is compatible with YAML but less readable to humans.


 - `detected_service`: used to generate a name for the files written to `acquis.d`
 - `collection`: only one collection can be recommended for any given detected service
 - `labels`: copied to acquis
 - `log_files`: copied to acquis
 - `journalctl_filter`: custom expression. If this entry is missing AND the UnitFound() function was called AND returned true while detecting this service, a default journalctl_filter expression is generated.


```
$ setup generate-acquis --help
generate acquisition config from the output of 'setup detect'

Usage:
  cscli setup generate-acquis [setup_file] [flags]

Flags:
      --to-dir string      write the acquisition configuration to a directory, in multiple files
```

If the `--to-dir` option is not specified, the generated `acquis.yaml` is instead printed to the standard output.


The acquis.yaml files
---------------------

By default, a monolithic `acquis.yaml` file is printed on standard output:

```yaml
# cscli setup generate-acquis setup.yaml
source: journalctl
journalctl_filter:
    - _SYSTEMD_UNIT=mock-apache2.service
labels:
    type: journald
---
source: file
filenames:
    - /var/log/syslog
    - /var/log/kern.log
    - /var/log/messages
labels:
    type: syslog
```


For ease of maintenance, it is recommended to provide a `--to-dir` flag, in this case each service has its own acquis file:

```yaml
# cscli setup generate-acquis setup.yaml --to-dir /tmp/acquis.d
# cat /tmp/acquis.d/setup.apache2-systemd.systemd.yaml 
source: journalctl
journalctl_filter:
    - _SYSTEMD_UNIT=mock-apache2.service
labels:
    type: journald
# cat /tmp/acquis.d/setup.linux.yaml                  
source: file
filenames:
    - /var/log/syslog
    - /var/log/kern.log
    - /var/log/messages
labels:
    type: syslog
```


Plans
-----

 - windows something
 - skip systemd checks if not installed
 - option to replace acquis sections installed by wizard.sh
 - better support for derived linux distributions

Open questions
--------------

> XXX how do we avoid detecting apache twice, as a process and systemd unit? What if it was installed in /opt/ or /usr/local/bin?

> XXX the error for "--force-*" options that were not consumed in the rules, should probably be a warning by default, with an option for error?

> XXX do we read the configuration from a single place (detect.yaml) or do we allow hub collections to come with their own service-detect snippets?

