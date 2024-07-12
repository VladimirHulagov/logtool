import abc
import enum
import typing

import pydantic

from ..systeminfo import (
    SystemInfo,
    DimmFailureLocation,
    CpuFailureLocation,
    PcieFailureLocation,
    BankType,
    CPUType,
)


class FailureCategory(enum.StrEnum):
    pass


class FailureCats():
    class DimmFailure(FailureCategory):
        ce = "DIMM.CE"
        ue = "DIMM.UE"

    class CpuFailure(FailureCategory):
        mlc_ce = "CPU.MLC.ParityCE"
        mlc_ue = "CPU.MLC.ParityUE"
        mlc_other_ue = "CPU.MLC.OtherUE"
        ifu_ce = "CPU.IFU.ParityCE"
        ifu_ue = "CPU.IFU.ParityUE"
        dcu_ce = "CPU.DCU.ParityCE"
        dcu_ue = "CPU.DCU.ParityUE"
        dcu_poison = "CPU.DCU.Poison"
        cha_ce = "CPU.CHA.ParityCE"
        cha_ue = "CPU.CHA.ParityUE"

    class PcieFailure(FailureCategory):
        serr = "PCIe.SERR"
        ur = "PCIe.UR"

    class Bios(FailureCategory):
        unknown = "Bios.Unknown"

    class Firmware(FailureCategory):
        unknown = "Firmware.Unknown"

    class Software(FailureCategory):
        unknown = "Software.Unknown"

    class Unknown(FailureCategory):
        unknown = "Unknown"


class ActionCode(enum.StrEnum):
    replace_dimm = "replace DIMM"
    replace_cpu = "replace CPU"
    replace_pcie = "replace PCIe device"
    update_ucode = "update ucode"
    update_bios = "update bios"
    debug_software = "debug software"
    contact_odm = "contact ODM"
    contact_intel = "contact Intel"
    no_action = "no action"


class TriageResult(pydantic.BaseModel):
    category: FailureCategory
    location: DimmFailureLocation | CpuFailureLocation | PcieFailureLocation | None = None
    action_code: ActionCode
    diagnose: str
    suggestion: str
    # TODO: triage_flow field for detailed triage logic visualization?
    # TODO: evidence field to capture related event?
    # TODO: location counter?


class TriageRule(abc.ABC):
    @property
    @abc.abstractmethod
    def overwrites(self) -> list["TriageRule"]:
        ...

    @abc.abstractmethod
    def __call__(self, sysinfo: SystemInfo) -> TriageResult | None:
        raise NotImplementedError
