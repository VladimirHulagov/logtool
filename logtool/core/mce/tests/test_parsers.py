import typing

import pytest

from .conftest import (
    LogInfo,
    edac_logs,
    mcelog_logs,
    dmesg_mcelog_logs,
    mce_logs_merged,
    spr100k_syslogs,
    acd_logs,
    maintenance_logs,
    maintenance_logs2,
    venus_logs,
    prepare_log,
)
from ..impl.parsers import (
    parse_mce,
    parse_acd,
    MachineCheckBase,
)
from ..impl.text_based import edac, mcelog, maintenance, venus
from ..impl.parsers import _create_parser, ContentPattern

combinations = [
    ("edac", edac.EdacMachineCheck, edac.edac_pattern, edac_logs),
    ("mcelog", mcelog.McelogMachineCheck, mcelog.mcelog_pattern, mcelog_logs),
    ("mcelog2", mcelog.McelogMachineCheck,
     mcelog.dmesg_mcelog_pattern, dmesg_mcelog_logs),
    ("maintenance", maintenance.MaintenanceMachineCheck,
     maintenance.maintenance_pattern, maintenance_logs),
    ("maintenance2", maintenance.MaintenanceMachineCheck,
     maintenance.maintenance_pattern2, maintenance_logs2),
    ("venus", venus.VenusMachineCheck, venus.venus_pattern, venus_logs),
]


def check_mces(log: LogInfo, mces: typing.List[MachineCheckBase]):
    assert mces
    assert log.mca_cnt is None or len(mces) == log.mca_cnt
    print(len(mces))
    print(mces[0].short_str)


@pytest.mark.parametrize(
    ["name", "cls", "pattern", "log"],
    [(name, cls, p, log)
     for name, cls, p, logs in combinations for log in logs],
    ids=lambda o: "" if isinstance(o, ContentPattern) else None,
)
def test_single_parser(name: str, cls: MachineCheckBase, pattern: ContentPattern, log: LogInfo, prepare_log):
    parser = _create_parser(cls, pattern)
    log = prepare_log(log)
    mces = parser(log.text)
    check_mces(log, mces)


@pytest.mark.parametrize("log", mce_logs_merged)
def test_parse_mce(log: LogInfo, prepare_log):
    log = prepare_log(log)
    mces = parse_mce(log.text)
    check_mces(log, mces)


@pytest.mark.parametrize("log", acd_logs)
def test_parse_acd(log: LogInfo, prepare_log):
    log = prepare_log(log)
    acd = parse_acd(log.text)
    check_mces(log, acd.machine_checks)


@pytest.mark.parametrize("log", spr100k_syslogs)
def test_spr100k_logs(log: LogInfo, prepare_log):
    log = prepare_log(log)
    mces = parse_mce(log.text)
    check_mces(log, mces)


@pytest.mark.parametrize("log", spr100k_syslogs)
def test_decode_mce(log: LogInfo, prepare_log):
    log = prepare_log(log)
    mces = parse_mce(log.text)
    check_mces(log, mces)
    from .. import decode_mce
    for mce in mces:
        if mce.bank is None:
            continue
        if mce.from_apei:
            continue
        if mce.bank in [5, 7, 8, 12] or mce.bank > 20:
            pytest.skip("Summarize cannot decode such bank")
        assert decode_mce("SPR", mce) is not None
