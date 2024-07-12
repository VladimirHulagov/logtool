from logtool.core.rules.rule import TriageRule
from ..rule import (
    SystemInfo,
    TriageRule,
    TriageResult,
    FailureCats,
    ActionCode,
    BankType,
)


class DcuParityCeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ces = sysinfo.filter_machine_checks(
            uc=False,
            bank_type=BankType.DCU,
            mcacod=0x0174,
        )
        if not ces:
            return None
        return TriageResult(
            category=FailureCats.CpuFailure.dcu_ce,
            location=ces[-1].cpu_location,
            action_code=ActionCode.no_action,
            diagnose="",
            suggestion=f"DCU Paricy CE. Keep monitoring",
        )


class DcuParityUeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        # No overwrite MlcCeTriage as we want to see whether MLC CE and UE are correlated
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ues = sysinfo.filter_machine_checks(
            uc=False,
            bank_type=BankType.DCU,
            mcacod=0x0174,
        )
        if not ues:
            return None
        return TriageResult(
            category=FailureCats.CpuFailure.dcu_ue,
            location=ues[-1].cpu_location,
            action_code=ActionCode.replace_cpu,
            diagnose="",
            suggestion=f"Replace CPU according to {ues[-1].cpu_location.model_dump_json()}",
        )


class DcuPoisonTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        # No overwrite MlcCeTriage as we want to see whether MLC CE and UE are correlated
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ues = sysinfo.filter_machine_checks(
            uc=True,
            bank_type=BankType.DCU,
            mcacod=0x0134,
        )
        if not ues:
            return None
        return TriageResult(
            category=FailureCats.CpuFailure.dcu_poison,
            location=ues[-1].cpu_location,
            action_code=ActionCode.contact_intel,
            diagnose="",
            suggestion=f"Cannot locate poison source. Contact Intel.",
        )
