#!/usr/bin/env python

from pytest_cs import wait_for_log

import pytest

pytestmark = pytest.mark.docker


def test_metrics_port_default(crowdsec, flavor):
    """Test metrics"""
    port = 6060
    with crowdsec(flavor=flavor) as cont:
        wait_for_log(cont, "*Starting processing data*")
        res = cont.exec_run(f'wget -O - http://127.0.0.1:{port}/metrics')
        if 'executable file not found' in res.output.decode():
            # TODO: find an alternative to wget
            pytest.skip('wget not found')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "# HELP cs_info Information about Crowdsec." in stdout


def test_metrics_port_default_ipv6(crowdsec, flavor):
    """Test metrics (ipv6)"""
    pytest.skip('ipv6 not supported yet')
    port = 6060
    with crowdsec(flavor=flavor) as cont:
        wait_for_log(cont, "*Starting processing data*")
        res = cont.exec_run(f'wget -O - http://[::1]:{port}/metrics')
        if 'executable file not found' in res.output.decode():
            # TODO: find an alternative to wget
            pytest.skip('wget not found')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "# HELP cs_info Information about Crowdsec." in stdout


def test_metrics_port(crowdsec, flavor):
    """Test metrics (custom METRICS_PORT)"""
    port = 7070
    env = {
        "METRICS_PORT": port
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        res = cont.exec_run(f'wget -O - http://127.0.0.1:{port}/metrics')
        if 'executable file not found' in res.output.decode():
            # TODO: find an alternative to wget
            pytest.skip('wget not found')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "# HELP cs_info Information about Crowdsec." in stdout


def test_metrics_port_ipv6(crowdsec, flavor):
    """Test metrics (custom METRICS_PORT, ipv6)"""
    pytest.skip('ipv6 not supported yet')
    port = 7070
    env = {
        "METRICS_PORT": port
    }
    with crowdsec(flavor=flavor, environment=env) as cont:
        wait_for_log(cont, "*Starting processing data*")
        res = cont.exec_run(f'wget -O - http://[::1]:{port}/metrics')
        if 'executable file not found' in res.output.decode():
            # TODO: find an alternative to wget
            pytest.skip('wget not found')
        assert res.exit_code == 0
        stdout = res.output.decode()
        assert "# HELP cs_info Information about Crowdsec." in stdout
