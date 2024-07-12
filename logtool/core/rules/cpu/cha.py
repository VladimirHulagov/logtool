from logtool.core.rules.rule import TriageRule
from ..rule import (
    SystemInfo,
    TriageRule,
    TriageResult,
    FailureCats,
    ActionCode,
    BankType,
)

llc_parity_mcacods = [
    0x010A,
    0x0136,
    0x0146,
    0x0152,
    0x0166,
    0x017A,
    0x0182,
    0x0186,
    0x110A,
    0x1136,
    0x1146,
    0x1152,
    0x1166,
    0x117A,
    0x1182,
    0x1186,
]


class ChaParityCeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ces = sysinfo.filter_machine_checks(
            uc=False,
            bank_type=BankType.CBO,
            mcacod=llc_parity_mcacods,
        )
        if not ces:
            return None
        return TriageResult(
            category=FailureCats.CpuFailure.cha_ce,
            location=ces[-1].cpu_location,
            action_code=ActionCode.no_action,
            diagnose="",
            suggestion="",
        )


class ChaParityUeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        # No overwrite MlcCeTriage as we want to see whether MLC CE and UE are correlated
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ues = sysinfo.filter_machine_checks(
            uc=True,
            bank_type=BankType.CBO,
            mcacod=llc_parity_mcacods,
        )
        if not ues:
            return None
        return TriageResult(
            category=FailureCats.CpuFailure.cha_ue,
            location=ues[-1].cpu_location,
            action_code=ActionCode.replace_cpu,
            diagnose="",
            suggestion="",
        )
