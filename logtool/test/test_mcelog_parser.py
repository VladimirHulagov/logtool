import os

import pytest

from logtool.model.logs.mcelog import ByteDanceMcelog, ByteDanceMcelogParser
from logtool.test.conftest import bytedance_mcelogs, LogInfo


@pytest.mark.parametrize("log", bytedance_mcelogs)
def test_mcelog_parser(log: LogInfo):
    print(f"Testing {log.path.name}")
    mcelog: ByteDanceMcelog = ByteDanceMcelogParser().parse(log.path)
    mcas = mcelog.key_events


@pytest.mark.parametrize("log", bytedance_mcelogs)
def test_mcelog_serializer(log: LogInfo):
    print(f"Testing {log.path.name}")
    mcelog: ByteDanceMcelog = ByteDanceMcelogParser().parse(log.path)
    assert mcelog == mcelog.serialized.deserialized
