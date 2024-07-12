import pytest

from logtool.model.logs.azure_sel import AzureSel, AzureSelParser
from logtool.test.conftest import azure_sel_logs, LogInfo


@pytest.mark.parametrize("log", azure_sel_logs)
def test_azure_sel(log: LogInfo):
    summ: AzureSel = AzureSelParser().parse(log.path)
    print(summ.system_events[0].extra_detail)


@pytest.mark.parametrize("log", azure_sel_logs)
def test_azure_sel_serialize_deserialize(log: LogInfo):
    summ: AzureSel = AzureSelParser().parse(log.path)
    AzureSel.model_validate(summ.model_dump())
    AzureSel.model_validate_json(summ.model_dump_json())
    assert summ == summ.serialized.deserialized
