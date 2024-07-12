import pytest

from logtool.model.logs.mce import mce_extractors, extract_mcas
from logtool.test.conftest import LogInfo, mce_logs


@pytest.mark.parametrize("log", mce_logs)
def test_mce_extractor(log: LogInfo):
    if log.skip_reason:
        pytest.skip(log.skip_reason)
    print(f"Testing {log.path.name}")
    extractor = mce_extractors[log.mce_type]
    assert extractor.check(log.path)
    mcas = extractor.parse(log.path)
    assert len(mcas) >= log.mca_cnt
    print(log.mce_type, len(mcas))


@pytest.mark.parametrize("log", mce_logs)
def test_mce_extractor2(log: LogInfo):
    if log.skip_reason:
        pytest.skip(log.skip_reason)
    print(f"Testing {log.path.name}")
    mcas = extract_mcas(log.path)
    assert len(mcas) >= log.mca_cnt
    print(log.mce_type, len(mcas))
