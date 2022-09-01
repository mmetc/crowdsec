#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    HUB_DIR=$(config_get '.config_paths.hub_dir')
    export HUB_DIR
    DETECT_YAML="${HUB_DIR}/detect.yaml"
    export DETECT_YAML
    # shellcheck disable=SC2154
    TESTDATA="${BATS_TEST_DIRNAME}/testdata/07_setup"
    export TESTDATA
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    load "../lib/bats-file/load.bash"
    load "../lib/bats-mock/load.bash"
    ./instance-data load
}

teardown() {
    ./instance-crowdsec stop
}

#----------

#shellcheck disable=SC2154
@test "cscli setup" {
    run -0 cscli help
    assert_line --regexp '^ +setup +Tools to configure crowdsec$'

    run -0 cscli setup --help
    assert_line 'Usage:'
    assert_line '  cscli setup [command]'
    assert_line 'Manage hub configuration and service detection'
    assert_line --partial "detect              detect running services, generate a setup file"
    assert_line --partial "generate-acquis     generate acquisition config from a setup file"
    assert_line --partial "install-collections install items from a setup file"
    assert_line --partial "validate            validate a setup file"

    # cobra should return error for non-existing sub-subcommands, but doesn't
    run -0 cscli setup blahblah
    assert_line 'Usage:'
}

@test "cscli setup detect --help; --detect-config" {
    run -0 cscli setup detect --help
    assert_line --regexp "detect running services, generate a setup file"
    assert_line 'Usage:'
    assert_line '  cscli setup detect [flags]'
    assert_line --partial "--detect-config string      path to service detection configuration (default \"${HUB_DIR}/detect.yaml\")"
    assert_line --partial "--force-process strings     force detection of a running process (can be repeated)"
    assert_line --partial "--force-unit strings        force detection of a systemd unit (can be repeated)"
    assert_line --partial "--list-supported-services   do not detect; only print supported services"
    assert_line --partial "--force-os-family string    override OS.Family: one of linux, freebsd, windows or darwin"
    assert_line --partial "--force-os-id string        override OS.ID=[debian | ubuntu | , redhat...]"
    assert_line --partial "--force-os-version string   override OS.RawVersion (of OS or Linux distribution)"
    assert_line --partial "--skip-service strings      ignore a service, don't recommend collections/acquis (can be repeated)"

    run -1 --separate-stderr cscli setup detect --detect-config /path/does/not/exist
    assert_stderr --partial "detecting services: while reading file: open /path/does/not/exist: no such file or directory"

    # rm -f "${HUB_DIR}/detect.yaml"
}

@test "cscli setup detect (linux), --skip-service" {
    [[ ${OSTYPE} =~ linux.* ]] || skip
    tempfile=$(TMPDIR="$BATS_TEST_TMPDIR" mktemp)
    cat <<-EOT >"${tempfile}"
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.Family == "linux"
	    collection: crowdsecurity/linux
	  thewiz:
	    when:
	      - OS.Family != "linux"
	  foobarbaz:
	EOT

    run -0 cscli setup detect --detect-config "$tempfile"
    assert_json '{setup:[{"detected_service":"foobarbaz"},{detected_service:"linux",collection:"crowdsecurity/linux"}]}'

    run -0 cscli setup detect --detect-config "$tempfile" --skip-service linux
    assert_json '{setup:[{detected_service:"foobarbaz"}]}'
}

@test "cscli setup detect --force-os-*" {
    run -0 cscli setup detect --force-os-family linux --detect-config "${TESTDATA}/detect.yaml"
    run -0 jq -cS '.setup[] | select(.detected_service=="linux")' <(output)
    assert_json '{acquis:{labels:{type:"syslog"},log_files:["/var/log/syslog","/var/log/kern.log","/var/log/messages"]},collection:"crowdsecurity/linux",detected_service:"linux"}'

    run -0 cscli setup detect --force-os-family freebsd --detect-config "${TESTDATA}/detect.yaml"
    run -0 jq -cS '.setup[] | select(.detected_service=="freebsd")' <(output)
    assert_json '{collection:"crowdsecurity/freebsd",detected_service:"freebsd"}'

    run -0 cscli setup detect --force-os-family windows --detect-config "${TESTDATA}/detect.yaml"
    run -0 jq -cS '.setup[] | select(.detected_service=="windows")' <(output)
    assert_json '{collection:"crowdsecurity/windows",detected_service:"windows"}'

    run -0 --separate-stderr cscli setup detect --force-os-family darwin --detect-config "${TESTDATA}/detect.yaml"
    refute_stderr
    # XXX do we want do disallow unknown family?
    # assert_stderr --partial "detecting services: OS 'darwin' not supported"

    # XXX TODO force-os-id, force-os-version
}

@test "cscli setup detect --list-supported-services" {
    tempfile=$(TMPDIR="$BATS_TEST_TMPDIR" mktemp)
    cat <<-EOT >"${tempfile}"
	version: 1.0
	services:
	  thewiz:
	  foobarbaz:
	  apache2:
	EOT

    run -0 cscli setup detect --list-supported-services --detect-config "$tempfile"
    # the service list is sorted
    assert_output - <<-EOT
	apache2
	foobarbaz
	thewiz
	EOT

    cat <<-EOT >"${tempfile}"
	thisisajoke
	EOT

    run -1 --separate-stderr cscli setup detect --list-supported-services --detect-config "$tempfile"
    assert_stderr --partial "while parsing ${tempfile}: yaml: unmarshal errors:"

    rm -f "$tempfile"
}

@test "cscli setup detect (systemctl)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	services:
	  apache2:
	    when:
	      - UnitFound("mock-apache2.service")
	    acquis:
	      labels:
	        type: apache2
	EOT

    # transparently mock systemctl. It's easier if you can tell the application
    # under test which executable to call (in which case just call $mock) but
    # here we do the symlink and $PATH dance as an example
    mocked_command="systemctl"

    # mock setup
    mock="$(mock_create)"
    mock_path="${mock%/*}"
    mock_file="${mock##*/}"
    ln -sf "${mock_path}/${mock_file}" "${mock_path}/${mocked_command}"
    PATH="${mock_path}:${PATH}"
    mock_set_output "$mock" \
'UNIT FILE                               STATE   VENDOR PRESET
snap-bare-5.mount                       enabled enabled
snap-core-13308.mount                   enabled enabled
snap-firefox-1635.mount                 enabled enabled
snap-fx-158.mount                       enabled enabled
snap-gimp-393.mount                     enabled enabled
snap-gtk\x2dcommon\x2dthemes-1535.mount enabled enabled
snap-kubectl-2537.mount                 enabled enabled
snap-rustup-1027.mount                  enabled enabled
cups.path                               enabled enabled
console-setup.service                   enabled enabled
dmesg.service                           enabled enabled
getty@.service                          enabled enabled
grub-initrd-fallback.service            enabled enabled
irqbalance.service                      enabled enabled
keyboard-setup.service                  enabled enabled
mock-apache2.service                    enabled enabled
networkd-dispatcher.service             enabled enabled
ua-timer.timer                          enabled enabled
update-notifier-download.timer          enabled enabled
update-notifier-motd.timer              enabled enabled

20 unit files listed.'
    mock_set_status "$mock" 1 2

    run -0 cscli setup detect
    run -0 jq -c '.setup' <(output)

    # If a call to UnitFoundwas part of the expression and it returned true,
    # there is a default journalctl_filter derived from the unit's name.
    assert_json '[{acquis:{journalctl_filter:["_SYSTEMD_UNIT=mock-apache2.service"],labels:{type:"apache2"}},detected_service:"apache2"}]'

    # the command was called with the expected parameters
    [[ "$(mock_get_call_args "$mock" 1)" == "list-unit-files --state=enabled,generated,static" ]]

    run -1 systemctl

    # mock teardown
    unlink "${mock_path}/${mocked_command}"
    PATH="${PATH/${mock_path}:/}"
}

@test "cscli setup detect --force-unit" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	services:
	  apache2:
	    when:
	      - UnitFound("force-apache2")
	    acquis:
	      labels:
	        type: apache2
	  apache3:
	    when:
	      - UnitFound("force-apache3")
	    acquis:
	      labels:
	        type: apache3
	EOT

    run -0 cscli setup detect --force-unit force-apache2
    run -0 jq -cS '.setup' <(output)
    assert_json '[{"acquis":{"journalctl_filter":["_SYSTEMD_UNIT=force-apache2"],"labels":{"type":"apache2"}},"detected_service":"apache2"}]'

    run -0 cscli setup detect --force-unit force-apache2,force-apache3
    run -0 jq -cS '.setup' <(output)
    assert_json '[{"acquis":{"journalctl_filter":["_SYSTEMD_UNIT=force-apache2"],"labels":{"type":"apache2"}},"detected_service":"apache2"},{"acquis":{"journalctl_filter":["_SYSTEMD_UNIT=force-apache3"],"labels":{"type":"apache3"}},"detected_service":"apache3"}]'

    # force-unit can be specified multiple times, the order does not matter
    run -0 cscli setup detect --force-unit force-apache3 --force-unit force-apache2
    run -0 jq -cS '.setup' <(output)
    assert_json '[{"acquis":{"journalctl_filter":["_SYSTEMD_UNIT=force-apache2"],"labels":{"type":"apache2"}},"detected_service":"apache2"},{"acquis":{"journalctl_filter":["_SYSTEMD_UNIT=force-apache3"],"labels":{"type":"apache3"}},"detected_service":"apache3"}]'

    run -1 --separate-stderr cscli setup detect --force-unit mock-doesnotexist
    assert_stderr --partial "detecting services: unit(s) forced but not supported: [mock-doesnotexist]"
}

@test "cscli setup detect (process)" {
    # This is harder to mock, because gopsutil requires proc/ to be a mount
    # point. So we pick a process that exists for sure.
    expected_process=$(basename "$SHELL")

    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	services:
	  apache2:
	    when:
	      - ProcessRunning("${expected_process}")
	  apache3:
	    when:
	      - ProcessRunning("this-does-not-exist")
	EOT

    run -0 cscli setup detect
    run -0 jq -cS '.setup' <(output)
    assert_json '[{"detected_service":"apache2"}]'
}

@test "cscli setup detect --force-process" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	services:
	  apache2:
	    when:
	      - ProcessRunning("force-apache2")
	  apache3:
	    when:
	      - ProcessRunning("this-does-not-exist")
	EOT

    run -0 cscli setup detect --force-process force-apache2
    run -0 jq -cS '.setup' <(output)
    assert_json '[{"detected_service":"apache2"}]'
}

@test "cscli setup detect (minimal output)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	services:
	  apache2:
	    when:
	      - UnitFound("force-apache2")
	    acquis:
	      labels:
	        type: apache2
	EOT

    run -0 cscli setup detect --force-unit force-apache2
    run -0 jq -cS '.setup' <(output)
    assert_json '[{"acquis":{"journalctl_filter":["_SYSTEMD_UNIT=force-apache2"],"labels":{"type":"apache2"}},"detected_service":"apache2"}]'

    run -0 cscli setup detect --force-unit force-apache2 --yaml
    assert_output - <<-EOT
	setup:
	  - detected_service: apache2
	    acquis:
	      labels:
	        type: apache2
	      journalctl_filter:
	        - _SYSTEMD_UNIT=force-apache2
	EOT
}

@test "cscli setup detect (with collections)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	services:
	  foobar:
	    when:
	      - ProcessRunning("force-foobar")
	    collection: crowdsecurity/foobar
	  qox:
	    when:
	      - ProcessRunning("test-qox")
	    collection: crowdsecurity/foobar
	  apache2:
	    when:
	      - ProcessRunning("force-apache2")
	    collection: crowdsecurity/apache2
	EOT

    run -0 cscli setup detect --force-process force-apache2,force-foobar
    run -0 jq -Sc '.setup | sort' <(output)
    assert_json '[{"collection":"crowdsecurity/apache2","detected_service":"apache2"},{"collection":"crowdsecurity/foobar","detected_service":"foobar"}]'
}

@test "cscli setup detect (with acquisition)" {
    cat <<-EOT >"${DETECT_YAML}"
	version: 1.0
	services:
	  foobar:
	    when:
	      - ProcessRunning("force-foobar")
	    acquis:
	      labels:
	        type: foobar
	      log_files:
	      - /var/log/apache2/*.log
	      - /var/log/*http*/*.log
	EOT

    run -0 cscli setup detect --force-process force-foobar
    run -0 yq -op '.setup | sort_keys(..)' <(output)
    assert_output - <<-EOT
	0.acquis.labels.type = foobar
	0.acquis.log_files.0 = /var/log/apache2/*.log
	0.acquis.log_files.1 = /var/log/*http*/*.log
	0.detected_service = foobar
	EOT

    run -1 --separate-stderr cscli setup detect --force-process mock-doesnotexist
    assert_stderr --partial "detecting services: process(es) forced but not supported: [mock-doesnotexist]"
}

@test "cscli setup install-collections" {
    run -0 cscli setup install-collections --help

    # it's not installed
    run -0 cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    refute_line "crowdsecurity/apache2"

    # we install it
    run -0 cscli setup install-collections /dev/stdin <<< '{"setup":[{"collection":"crowdsecurity/apache2"}]}'

    # now it's installed
    run -0 cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    assert_line "crowdsecurity/apache2"
}

@test "cscli setup install-collections (dry run)" {
    # it's not installed
    run -0 cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    refute_line "crowdsecurity/apache2"

    # we install it
    run -0 --separate-stderr cscli setup install-collections /dev/stdin --dry-run <<< '{"setup":[{"collection":"crowdsecurity/apache2"}]}'
    assert_output 'dry-run: would install collection crowdsecurity/apache2'

    # still not installed
    run -0 cscli collections list -o json
    run -0 jq -r '.collections[].name' <(output)
    refute_line "crowdsecurity/apache2"
}

@test "cscli setup generate-acquis" {
    run -0 cscli setup generate-acquis --help
    assert_line --partial "--to-dir string   write the acquisition configuration to a directory, in multiple files"

    # single item

    run -0 cscli setup generate-acquis /dev/stdin <<-EOT
	setup:
	  - acquis:
	      labels:
	        type: syslog
	      log_files:
	        - /var/log/apache2/*.log
	        - /var/log/*http*/*.log
	        - /var/log/httpd/*.log
	EOT

    assert_output - <<-EOT
	source: file
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: syslog
	EOT

    # multiple items

    run -0 cscli setup generate-acquis /dev/stdin <<-EOT
	setup:
	  - acquis:
	      labels:
	        type: syslog
	      log_files:
	        - /var/log/apache2/*.log
	        - /var/log/*http*/*.log
	        - /var/log/httpd/*.log
	  - acquis:
	      labels:
	        type: foobar
	      log_files:
	        - /var/log/foobar/*.log
	  - acquis:
	      labels:
	        type: barbaz
	      log_files:
	        - /path/to/barbaz.log
	EOT

    assert_output - <<-EOT
	source: file
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: syslog
	---
	source: file
	filenames:
	  - /var/log/foobar/*.log
	labels:
	  type: foobar
	---
	source: file
	filenames:
	  - /path/to/barbaz.log
	labels:
	  type: barbaz
	EOT

    # multiple items, to a directory

    # the BATS_TEST_TMPDIR variable can have a double //
    acquisdir=$(TMPDIR="$BATS_FILE_TMPDIR" mktemp -u)
    mkdir "$acquisdir"

    run -0 cscli setup generate-acquis /dev/stdin --to-dir "$acquisdir" <<-EOT
	setup:
	  - detected_service: apache2
	    acquis:
	      labels:
	        type: syslog
	      log_files:
	        - /var/log/apache2/*.log
	        - /var/log/*http*/*.log
	        - /var/log/httpd/*.log
	  - detected_service: foobar
	    acquis:
	      labels:
	        type: foobar
	      log_files:
	        - /var/log/foobar/*.log
	  - detected_service: barbaz
	    acquis:
	      labels:
	        type: barbaz
	      log_files:
	        - /path/to/barbaz.log
	EOT

    # XXX what if detected_service is missing?

    run -0 cat "${acquisdir}/setup.apache2.yaml"
    assert_output - <<-EOT
	source: file
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: syslog
	EOT

    run -0 cat "${acquisdir}/setup.foobar.yaml"
    assert_output - <<-EOT
	source: file
	filenames:
	  - /var/log/foobar/*.log
	labels:
	  type: foobar
	EOT

    run -0 cat "${acquisdir}/setup.barbaz.yaml"
    assert_output - <<-EOT
	source: file
	filenames:
	  - /path/to/barbaz.log
	labels:
	  type: barbaz
	EOT

    rm -rf -- "${acquisdir:?}"
    mkdir "$acquisdir"

    # having both log_files and journalctl generates two files

    run -0 cscli setup generate-acquis /dev/stdin --to-dir "$acquisdir" <<-EOT
	setup:
	  - detected_service: apache2
	    collection: crowdsecurity/apache2
	    acquis:
	      labels:
	        type: apache2
	      log_files:
	        - /var/log/apache2/*.log
	        - /var/log/*http*/*.log
	        - /var/log/httpd/*.log
	      journalctl_filter:
	        - _SYSTEMD_UNIT=apache2.service
	EOT

    run -0 cat "${acquisdir}/setup.apache2.yaml"
    assert_output - <<-EOT
	source: file
	filenames:
	  - /var/log/apache2/*.log
	  - /var/log/*http*/*.log
	  - /var/log/httpd/*.log
	labels:
	  type: apache2
	EOT

    run -0 cat "${acquisdir}/setup.apache2.systemd.yaml"
    assert_output - <<-EOT
	source: journalctl
	journalctl_filter:
	  - _SYSTEMD_UNIT=apache2.service
	labels:
	  type: journald
	EOT

    # the directory must exist
    run -1 --separate-stderr cscli setup generate-acquis /dev/stdin --to-dir /path/does/not/exist <<< '{}'
    assert_stderr --partial "directory /path/does/not/exist does not exist"

    # of course it must be a directory

    touch "${acquisdir}/notadir"

    run -1 --separate-stderr cscli setup generate-acquis /dev/stdin --to-dir "${acquisdir}/notadir" <<-EOT
	setup:
	  - detected_service: apache2
	    acquis:
	      log_files:
	        - /var/log/apache2/*.log
	EOT
    assert_stderr --partial "open ${acquisdir}/notadir/setup.apache2.yaml: not a directory"

    rm -rf -- "${acquisdir:?}"
}

@test "cscli setup (custom journalctl filter)" {
    tempfile=$(TMPDIR="$BATS_TEST_TMPDIR" mktemp)
    cat <<-EOT >"${tempfile}"
	version: 1.0
	services:
	  thewiz:
	    when:
	      - UnitFound("thewiz.service")
	    acquis:
	      labels:
	        type: thewiz
	      journalctl_filter:
	        - "SYSLOG_IDENTIFIER=TheWiz"
	EOT

    run -0 cscli setup detect --detect-config "$tempfile" --force-unit thewiz.service
    run -0 jq -cS '.' <(output)
    assert_json '{"setup":[{"acquis":{"journalctl_filter":["SYSLOG_IDENTIFIER=TheWiz"],"labels":{"type":"thewiz"}},"detected_service":"thewiz"}]}'
    run -0 cscli setup generate-acquis <(output)
    assert_output - <<-EOT
	source: journalctl
	journalctl_filter:
	  - SYSLOG_IDENTIFIER=TheWiz
	labels:
	  type: journald
	EOT

    rm -f "$tempfile"
}

@test "cscli setup validate" {

    # an empty file is not enough
    run -1 --separate-stderr cscli setup validate /dev/null
    assert_output "EOF"
    assert_stderr --partial "invalid setup file"

    # this is ok; install nothing
    run -0 --separate-stderr cscli setup validate /dev/stdin <<-EOT
	setup:
	EOT
    refute_output
    refute_stderr

    run -1 --separate-stderr cscli setup validate /dev/stdin <<-EOT
	se tup:
	EOT
    assert_output - <<-EOT
	[1:1] unknown field "se tup"
	>  1 | se tup:
	       ^
	EOT
    assert_stderr --partial "invalid setup file"

    run -1 --separate-stderr cscli setup validate /dev/stdin <<-EOT
	setup:
	alsdk al; sdf
	EOT
    assert_output "while unmarshaling setup file: yaml: line 2: could not find expected ':'"
    assert_stderr --partial "invalid setup file"
}

