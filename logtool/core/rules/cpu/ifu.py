from logtool.core.rules.rule import TriageRule
from ..rule import (
    SystemInfo,
    TriageRule,
    TriageResult,
    FailureCats,
    ActionCode,
    BankType,
)


class IfuParityCeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ces = sysinfo.filter_machine_checks(
            uc=False,
            bank_type=BankType.IFU,
            mcacod=0x0005,
        )
        if not ces:
            return None
        ce = ces[-1]
        return TriageResult(
            category=FailureCats.CpuFailure.ifu_ce,
            location=ce.cpu_location,
            action_code=ActionCode.no_action,
            diagnose="",
            suggestion=f"IFU Parity CE. Keep monitoring.",
        )


class IfuParityUeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        # No overwrite MlcCeTriage as we want to see whether MLC CE and UE are correlated
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ues = sysinfo.filter_machine_checks(
            uc=False,
            bank_type=BankType.IFU,
            mcacod=0x0005,
        )
        if not ues:
            return None
        ue = ues[-1]
        return TriageResult(
            category=FailureCats.CpuFailure.ifu_ue,
            location=ue.cpu_location,
            action_code=ActionCode.replace_cpu,
            diagnose="",
            suggestion=f"Replace CPU according to given location",
        )
