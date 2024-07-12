import os

import pytest

from logtool.model.logs.shc import ShcReport, ISerializableParsedLog
from logtool.test.conftest import shc_logs, LogInfo


def get_log(logname: str):
    return os.path.join(os.path.dirname(__file__), "logs", logname)


@pytest.mark.parametrize("log", shc_logs)
def test_parse_report_json(log: LogInfo):
    with open(log.path) as f:
        report = ShcReport.model_validate_json(f.read())


@pytest.mark.parametrize("log", shc_logs)
def test_parse_report_json_serializer(log: LogInfo):
    with open(log.path) as f:
        report = ShcReport.model_validate_json(f.read())
    assert report.serialized.deserialized == report
