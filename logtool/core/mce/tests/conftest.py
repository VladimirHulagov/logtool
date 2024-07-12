import tarfile
import enum
import pathlib
import itertools
import typing
import shutil

import pydantic

import pytest


class LogType(enum.Enum):
    acd = enum.auto()
    venus = enum.auto()
    maintenance = enum.auto()
    analy_report = enum.auto()
    summary = enum.auto()
    syslog = enum.auto()
    shc = enum.auto()
    onekeylog = enum.auto()


@pytest.fixture(scope='session')
def session_tmp_path(tmp_path_factory: pytest.TempPathFactory):
    return tmp_path_factory.mktemp('my_temp_dir')


log_package = pathlib.Path(__file__).parent.joinpath("logs.tar.xz")
logs_path = pathlib.Path(__file__).parent.joinpath("logs")


@pytest.fixture(scope="session")
def logs_dir(session_tmp_path: pathlib.Path):
    if logs_path.exists():
        yield logs_path
        return
    else:
        print("Start unpacking logs")
        shutil.unpack_archive(log_package, session_tmp_path)
        print("Logs unpacked")
        yield session_tmp_path
        return


@pydantic.dataclasses.dataclass
class LogInfo():
    mce_type: LogType
    logname: str
    mca_cnt: typing.Optional[int] = None
    comment: typing.Optional[str] = None
    path: typing.Optional[pathlib.Path] = None

    @property
    def text(self):
        with open(self.path) as f:
            return f.read()

    @property
    def __name__(self):
        return self.logname

    def __add__(self, other: "LogInfo"):
        if other is None:
            return self
        assert self.mce_type is other.mce_type
        assert self.logname is other.logname
        return LogInfo(
            mce_type=self.mce_type,
            logname=self.logname,
            mca_cnt=self.mca_cnt+other.mca_cnt,
        )

    def __radd__(self, other: "LogInfo | None"):
        if other is None:
            return self
        return self.__add__(other)


@pytest.fixture(scope="session")
def prepare_log(logs_dir: pathlib.Path):
    def _prep_log(loginfo: LogInfo):
        logs = list(logs_dir.rglob(loginfo.logname))
        assert len(logs) >= 1
        loginfo.path = logs[0]
        return loginfo
    return _prep_log


_logs = [
    LogInfo(LogType.acd, "2023_05-06_Gen8_CPU_AIRACD_06.01-06.26_2023-06-21_2910b8a7-e779-bddf-8cad-4e53507e0fc5bmc_crashdump.json"),
    LogInfo(LogType.acd, "crashdump.json"),
    LogInfo(LogType.venus, "DiagnosisInformation.bin - 21B108767.txt"),
    LogInfo(LogType.venus, "DiagnosisInformation.bin.txt"),
    LogInfo(LogType.analy_report, "InspurErrorAnalyReport.json"),
    LogInfo(LogType.summary, "summary_2023_05-06_Gen8_CPU_AIRACD_06.01-06.26_2023-06-21_2910b8a7-e779-bddf-8cad-4e53507e0fc5bmc_crashdump.json"),
    LogInfo(LogType.summary, "summary_crashdump.json"),
    LogInfo(LogType.syslog, "sys__0308_221723.log"),
    LogInfo(LogType.syslog, "sys__0416_045254.log"),
    LogInfo(LogType.syslog, "sys_7CE824P3NW_0926_161949.log"),
    LogInfo(LogType.syslog, "sys_210200A00QH183000914_1205_120442.log"),
    LogInfo(LogType.syslog, "sys_220856399_20220710155205.log"),
    LogInfo(LogType.syslog, "sys_720619983_20220818205023.log"),
    LogInfo(LogType.syslog, "sys_816509023_20220810235118.log"),
    LogInfo(LogType.syslog, "sys_819428594_20220817235017.log"),
    LogInfo(LogType.syslog, "sys_819450696_20220810155027.log"),
    LogInfo(LogType.syslog, "sys_821211598_20220807175040.log"),
    LogInfo(LogType.syslog, "sys_820778797_20220702145012.log"),
    LogInfo(LogType.syslog, "sys_LC20B0900000H_0913_111702_MemDIMM_UCE.log"),
    LogInfo(LogType.syslog, "sys_LC20B0900000H_0913_140854_MemDIMM_CE.log"),
]

edac_logs = [
    LogInfo(LogType.syslog, "sys__0416_045254.log", 33),
    LogInfo(LogType.syslog, "sys_220856399_20220710155205.log", 1573),
    LogInfo(LogType.syslog, "sys_720619983_20220818205023.log", 1064),
    LogInfo(LogType.syslog, "sys_LC20B0900000H_0913_140854_MemDIMM_CE.log", 1),
]

mcelog_logs = [
    LogInfo(LogType.syslog, "sys_7CE824P3NW_0926_161949.log", 2),
    LogInfo(LogType.syslog, "sys_220856399_20220710155205.log", 663,
            "Two broken segments ignored between row 3376 and 3383"),
    LogInfo(LogType.syslog, "sys_720619983_20220818205023.log", 1275),
    LogInfo(LogType.syslog, "sys_816509023_20220810235118.log", 4),
    LogInfo(LogType.syslog, "sys_819428594_20220817235017.log", 156),
    LogInfo(LogType.syslog, "sys_819450696_20220810155027.log", 1740),
    LogInfo(LogType.syslog, "sys_821211598_20220807175040.log", 1),
    LogInfo(LogType.syslog, "sys_LC20B0900000H_0913_111702_MemDIMM_UCE.log", 11),
    LogInfo(LogType.syslog, "sys_LC20B0900000H_0913_140854_MemDIMM_CE.log", 12),
]

acd_logs = [
    LogInfo(LogType.acd, "2023_05-06_Gen8_CPU_AIRACD_06.01-06.26_2023-06-21_2910b8a7-e779-bddf-8cad-4e53507e0fc5bmc_crashdump.json"),
    LogInfo(LogType.acd, "crashdump.json"),
]

dmesg_mcelog_logs = [
    LogInfo(LogType.syslog, "sys__0308_221723.log", 23),
]

venus_logs = [
    LogInfo(LogType.venus, "DiagnosisInformation.bin - 21B108767.txt", 70),
    LogInfo(LogType.venus, "DiagnosisInformation.bin.txt", 1),
]

maintenance_logs = [
    LogInfo(LogType.maintenance, "28B616147_maintenance.log", 1),
    LogInfo(LogType.maintenance, "28B808845_maintenance.log", 1),
]

maintenance_logs2 = [
    LogInfo(LogType.maintenance, "425035089_maintenance.log", 6),
]

_ = itertools.chain(edac_logs, mcelog_logs, dmesg_mcelog_logs)
_ = sorted(_, key=lambda log: log.logname)
_ = itertools.groupby(_, key=lambda log: log.logname)
_ = map(lambda p: sum(p[1], start=None), _)
mce_logs_merged: typing.List[LogInfo] = list(_)

with tarfile.open(log_package) as archive:
    _ = archive.getnames()
    _ = filter(lambda n: "spr100k_syslog" in n and n.endswith(".log"), _)
    _ = map(lambda n: LogInfo(LogType.syslog, pathlib.Path(n).name), _)
    spr100k_syslogs = list(_)
