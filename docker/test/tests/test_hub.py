#!/usr/bin/env python

"""
Test pre-installed hub items.
"""

import json

from pytest_cs import wait_for_log

import pytest

pytestmark = pytest.mark.docker


def test_preinstalled_hub(crowdsec, flavor):
    """Test hub objects installed in the entrypoint"""
    with crowdsec(flavor=flavor) as cont:
        wait_for_log(cont, "Starting processing data")
        res = cont.exec_run('cscli hub list -o json')
        assert res.exit_code == 0
        j = json.loads(res.output)
        collections = {c['name']: c for c in j['collections']}
        assert collections['crowdsecurity/linux']['status'] == 'enabled'
        parsers = {c['name']: c for c in j['parsers']}
        assert parsers['crowdsecurity/whitelists']['status'] == 'enabled'
        assert parsers['crowdsecurity/docker-logs']['status'] == 'enabled'
