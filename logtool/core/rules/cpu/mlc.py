from logtool.core.rules.rule import TriageRule
from ..rule import (
    SystemInfo,
    TriageRule,
    TriageResult,
    FailureCats,
    ActionCode,
    BankType,
)

mlc_parity_mcacods = [
    0x0135,
    0x0145,
    0x0151,
    0x0165,
    0x0179,
    0x0185,
    0x0189,
    0x0405,
]

# 12 bits, not 16 bits. There is a bit that will be set for MLC CE
mlc_parity_mcacods.extend((0x1000 | mscod) for mscod in mlc_parity_mcacods)


class MlcParityCeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ces = sysinfo.filter_machine_checks(
            uc=False,
            bank_type=BankType.MLC,
            mcacod=mlc_parity_mcacods,
        )
        if not ces:
            return None
        ce = ces[-1]
        return TriageResult(
            category=FailureCats.CpuFailure.mlc_ce,
            location=ce.cpu_location,
            action_code=ActionCode.no_action,
            diagnose="",
            suggestion="MLC CE. Keep monitoring",
        )


class MlcParityUeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        # No overwrite MlcCeTriage as we want to see whether MLC CE and UE are correlated
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ues = sysinfo.filter_machine_checks(
            uc=False,
            bank_type=BankType.MLC,
            mcacod=mlc_parity_mcacods,
        )
        if not ues:
            return None
        ue = ues[-1]
        return TriageResult(
            category=FailureCats.CpuFailure.mlc_ue,
            location=ue.cpu_location,
            action_code=ActionCode.replace_cpu,
            diagnose="",
            suggestion=f"MLC UE. Replace CPU at given location.",
        )
