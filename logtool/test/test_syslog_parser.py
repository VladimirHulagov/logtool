import pytest

from logtool.model.logs.syslog import Syslog, SyslogParser
from logtool.test.conftest import syslogs, LogInfo


@pytest.mark.parametrize("log", syslogs)
def test_syslog_parser(log: LogInfo):
    print(f"Testing {log.path.name}")
    syslog: Syslog = SyslogParser().parse(log.path)
    mcas = syslog.key_events
    assert len(mcas) >= log.mca_cnt


@pytest.mark.parametrize("log", syslogs)
def test_syslog_serializer(log: LogInfo):
    print(f"Testing {log.path.name}")
    syslog: Syslog = SyslogParser().parse(log.path)
    assert syslog == syslog.serialized.deserialized
