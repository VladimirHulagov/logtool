from logtool.core.rules.rule import TriageRule
from ..rule import (
    SystemInfo,
    TriageRule,
    TriageResult,
    FailureCats,
    ActionCode,
    BankType,
)
from ..cpu.dcu import DcuPoisonTriage


class DimmCeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        return []

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        ces = sysinfo.filter_machine_checks(
            uc=False,
            bank_type=BankType.IMC,
        )
        if not ces:
            return None
        ce = ces[-1]
        for mc in reversed(ces):
            if mc.dimm_location is not None:
                ce = mc
        return TriageResult(
            category=FailureCats.DimmFailure.ce,
            location=ce.dimm_location,
            action_code=ActionCode.no_action,
            diagnose="",
            suggestion="DIMM CE. Keep monitoring.",
        )


class DimmUeTriage(TriageRule):
    @property
    def overwrites(self) -> list[TriageRule]:
        return [DimmCeTriage, DcuPoisonTriage]

    # TODO: This is just a POC for SPR100K logs. Validate other platforms!
    def __call__(self, sysinfo: SystemInfo):
        # _ = filter(lambda m: m.mscod in [0x0010, 0x0040], _)
        ues = sysinfo.filter_machine_checks(
            uc=True,
            bank_type=BankType.IMC,
        )
        if not ues:
            return None
        ue = ues[-1]
        for mc in reversed(ues):
            if mc.dimm_location is not None:
                ue = mc
        return TriageResult(
            category=FailureCats.DimmFailure.ue,
            location=ue.dimm_location,
            action_code=ActionCode.replace_dimm,
            diagnose="",
            suggestion=f"Replace DIMM according to {ue.dimm_location.model_dump_json()}",
        )
