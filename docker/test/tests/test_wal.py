#!/usr/bin/env python

from pytest_cs import wait_for_log

import pytest

pytestmark = pytest.mark.docker


def test_use_wal_default(crowdsec, flavor):
    """Test USE_WAL default"""
    with crowdsec(flavor=flavor) as cont:
        wait_for_log(cont, 'Starting processing data')
        res = cont.exec_run('cscli config show --key Config.DbConfig.UseWal -o json')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "false" in stdout


def test_use_wal_true(crowdsec, flavor):
    """Test USE_WAL=true"""
    env = {
        'USE_WAL': 'true',
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, 'Starting processing data')
        res = cont.exec_run('cscli config show --key Config.DbConfig.UseWal -o json')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "true" in stdout


def test_use_wal_false(crowdsec, flavor):
    """Test USE_WAL=false"""
    env = {
        'USE_WAL': 'false',
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, 'Starting processing data')
        res = cont.exec_run('cscli config show --key Config.DbConfig.UseWal -o json')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "false" in stdout
