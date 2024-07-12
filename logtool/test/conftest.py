import pathlib
import enum

import pytest
import pydantic

from logtool.model.logs.mce import _MCESource


class LogType(enum.Enum):
    Shc = enum.auto()
    AzureSel = enum.auto()
    Mcelog = enum.auto()


@pydantic.dataclasses.dataclass
class LogInfo():
    mce_type: _MCESource | LogType
    relpath: str
    mca_cnt: int | None = None
    skip_reason: str | None = None

    @property
    def __name__(self):
        return self.path.name

    @property
    def path(self):
        logs_dir = pathlib.Path(__file__).parent.joinpath("logs")
        if isinstance(self.mce_type, _MCESource):
            return logs_dir.joinpath("mce", self.relpath)
        if self.mce_type is LogType.Shc:
            return logs_dir.joinpath("shc", self.relpath)
        if self.mce_type is LogType.AzureSel:
            return logs_dir.joinpath("azure_sel", self.relpath)
        if self.mce_type is LogType.Mcelog:
            return logs_dir.joinpath("bytedance_mcelog", self.relpath)
        assert False


mce_logs = [
    LogInfo(_MCESource.acd, "2023_05-06_Gen8_CPU_AIRACD_06.01-06.26_2023-06-21_2910b8a7-e779-bddf-8cad-4e53507e0fc5bmc_crashdump.json", 1),
    LogInfo(_MCESource.acd, "crashdump.json", 1),
    LogInfo(_MCESource.edac, "sys__0416_045254.log", 1),
    LogInfo(_MCESource.edac, "sys_220856399_20220710155205.log", 1),
    LogInfo(_MCESource.serial, "E5+CPU复现串口日志 (2).txt", 1),
    LogInfo(_MCESource.extsel, "extend_sel.log", 18, "No timestamp for now"),
    LogInfo(_MCESource.mcelog, "sys_7CE824P3NW_0926_161949.log", 1),
    LogInfo(_MCESource.mcelog, "sys_816509023_20220810235118.log", 1),
    LogInfo(_MCESource.mcelog, "sys_821211598_20220807175040.log", 1),
    LogInfo(_MCESource.mcelog, "sys_819450696_20220810155027.log", 1),
    LogInfo(_MCESource.mcelog, "sys_LC20B0900000H_0913_111702_MemDIMM_UCE.log", 1),
    LogInfo(_MCESource.mcelog, "sys_210200A00QH183000914_1205_120442.log",
            1, "Maybe broken file"),
    LogInfo(_MCESource.mcelog, "sys_820778797_20220702145012.log", 911),
    LogInfo(_MCESource.mcelog, "sys_LC20B0900000H_0913_140854_MemDIMM_CE.log", 11),
    LogInfo(_MCESource.mcelog, "sys_720619983_20220818205023.log", 1259),
    LogInfo(_MCESource.edac, "sys_720619983_20220818205023.log", 1051),
    # Those two PPINs, look like a mca status! Is this dummy log?
    LogInfo(_MCESource.mcelog, "sys_819428594_20220817235017.log", 151),
    LogInfo(_MCESource.dmesg_mcelog, "sys__0308_221723.log", 1),
    # LogInfo(_MCESource.dmesg_mcelog,
    #         "sys_LC20B0900000H_0913_140854_MemDIMM_CE.log", 6),  # strange mcelog
    # The log may come from invalid source
    # LogInfo(_MCESource.mcelog, "sys_220856399_20220710155205.log", 1),
    LogInfo(_MCESource.error_analy_report,
            "InspurErrorAnalyReport.json", 14),
    LogInfo(_MCESource.venus,
            "DiagnosisInformation.bin - 21B108767.txt", 70),
    LogInfo(_MCESource.venus, "DiagnosisInformation.bin.txt", 1),
    LogInfo(_MCESource.onekeylog,
            "Tencent_LC2211290003M_2022-07-20-12-21.tar.gz", 294),
    LogInfo(_MCESource.onekeylog,
            "Tencent_FX222170002Q6_2022-03-11-10-11.tar.gz", 1, "To be debugged"),
]

acd_logs = [log for log in mce_logs if log.mce_type is _MCESource.acd]

shc_logs = [
    LogInfo(LogType.Shc, "report.json"),
]

azure_sel_logs = [
    LogInfo(LogType.AzureSel, "SEL(4480792f-5b25-8634-5655-7e1ba36f7faf).txt"),
    LogInfo(LogType.AzureSel, "SEL(af99fd3b-005c-869d-2977-549351888b1f).txt"),
    LogInfo(LogType.AzureSel, "SEL(b525eb46-1b54-c629-fc5d-4a470723c605).txt"),
]

syslogs = [
    log for log in mce_logs
    if log.mce_type in [
        _MCESource.edac,
        _MCESource.mcelog,
        _MCESource.dmesg_mcelog
    ] and not log.skip_reason
]

bytedance_mcelogs = [
    LogInfo(LogType.Mcelog, "mcelog_ue_90day.csv"),
]

for log in mce_logs:
    assert log.path.is_file()

for log in shc_logs:
    assert log.path.is_file()
