#!/usr/bin/env python

from pytest_cs import log_lines, wait_for_log, Status

import pytest

pytestmark = pytest.mark.docker


def test_container(container):
    # XXX: not crowdsec
    with container(image='hello-world', wait_status=Status.EXITED) as cont:
        assert 'Hello from Docker!' in log_lines(cont)


def test_crowdsec(crowdsec):
    with crowdsec() as cont:
        wait_for_log(cont, "Starting processing data")
        res = cont.exec_run('sh -c "echo $CI_TESTING"')
        assert res.exit_code == 0
        assert 'true' == res.output.decode().strip()
