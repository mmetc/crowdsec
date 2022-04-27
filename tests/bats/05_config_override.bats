#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

setup_file() {
    load "../lib/setup_file.sh"
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
    ./instance-data load
    ./instance-crowdsec start
}

teardown() {
    ./instance-crowdsec stop
}


#----------

@test "$FILE cscli - configuration merge" {
    run -0 cscli config show --key Config.Common.LogLevel
    assert_output "info"

    echo "{'common':{'log_level':'debug'}}" > "${CONFIG_YAML}.patch"
    run -0 cscli config show --key Config.Common.LogLevel
    assert_output "debug"
}
