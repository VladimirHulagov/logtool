import pytest

from logtool.model.logs.summary import AcdSummarizer, Summary
from logtool.test.conftest import acd_logs, LogInfo, _MCESource


@pytest.mark.parametrize("log", acd_logs)
def test_summary(log: LogInfo):
    summ: Summary = AcdSummarizer().parse(log.path)
    assert summ.ppins


@pytest.mark.parametrize("log", acd_logs)
def test_summary_serialize_deserialize(log: LogInfo):
    summ: Summary = AcdSummarizer().parse(log.path)
    Summary.model_validate(summ.model_dump())
    Summary.model_validate_json(summ.model_dump_json())
    assert summ == summ.serialized.deserialized


for log in acd_logs:
    from pysvtools.crashdump_summarizer.cd_summarizer import summary
    summary(str(log.path), text_file=False)
