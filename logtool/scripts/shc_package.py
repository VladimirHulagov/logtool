from collections import Counter

from typing_extensions import Annotated

from logtool.model.logs.mce import MachineCheck, _MachineCheckView
from logtool.model.logs.shc import ShcReport

import pydantic


class SHCPackageInfo(pydantic.BaseModel):
    filename: str
    mcas: list[MachineCheck] | None = None
    shc: ShcReport | None = None
    exception: str | None = None


class SHCPackageInfoView(SHCPackageInfo):
    mcas: list[_MachineCheckView] | None = None

    # TODO mcas = None when we have no syslog
    @pydantic.computed_field
    @property
    def mce_count(self) -> int | None:
        return sum(mca.corrected_count for mca in self.mcas)

    @pydantic.computed_field
    @property
    # @return_none_if_att_is_none("mcas")
    def mca_banks(self) -> list | None:
        return sorted(set(mca.bank if mca.bank is not None else -1 for mca in self.mcas))

    @pydantic.computed_field
    @property
    # @return_none_if_att_is_none("mcas")
    def mca_cores(self) -> list | None:
        return sorted(set(mca.core if mca.core is not None else -1 for mca in self.mcas))

    @pydantic.computed_field
    @property
    # @return_none_if_att_is_none("mcas")
    def mlc_error(self) -> bool | None:
        return any(mca.bank == 3 for mca in self.mcas)

    @pydantic.computed_field
    @property
    # @return_none_if_att_is_none("mcas")
    def mlc_uc(self) -> bool | None:
        return any(mca.bank == 3 and mca.uncorrected for mca in self.mcas)

    @pydantic.computed_field
    @property
    # @return_none_if_att_is_none("mcas")
    def uc(self) -> bool | None:
        return any(mca.uncorrected for mca in self.mcas)

    @pydantic.computed_field
    @property
    # @return_none_if_att_is_none("mcas")
    def mlc_yellow(self) -> bool | None:
        return any(mca.bank == 3 and mca.corrected_yellow for mca in self.mcas)

    @pydantic.computed_field
    @property
    # @return_none_if_att_is_none("mcas")
    def msmcacods(self) -> list[str] | None:
        return sorted(set(hex(mca.status & 0xFFFF_FFFF) for mca in self.mcas))

    @pydantic.computed_field
    @property
    def first_failed_shc_command(self) -> None | str:
        if not self.shc or not self.shc.failed_tests:
            return None
        return self.shc.failed_tests[0].Command

    @pydantic.computed_field
    @property
    def sn(self) -> str:
        return self.filename[:10]

    @pydantic.computed_field
    @property
    def ppins(self) -> list[int] | None:
        if self.shc is None:
            return None
        ppins_list = list(int(info.PPIN, 16)
                          for info in self.shc.SystemInfo.SocketInfo.values())
        return ppins_list

    @pydantic.computed_field
    @property
    def shc_failed(self) -> bool:
        return self.shc is not None and self.shc.failed


class SHCPackageInfoList(pydantic.BaseModel):
    list: list[SHCPackageInfo]


class SHCPackageInfoViewList(pydantic.BaseModel):
    list: list[SHCPackageInfoView]


class GroupedResultByPPIN(pydantic.BaseModel):
    socket: int
    ppin: int
    packages: list[SHCPackageInfo]

    @property
    def shc_failed(self) -> bool:
        return any(r.shc is not None and r.shc.failed for r in self.packages)

    @property
    def mca_failed(self) -> bool:
        for r in self.packages:
            if not r.mcas:
                continue
            for mca in r.mcas:
                if mca.socket is None or mca.socket == self.socket:
                    return True
        return False


class GroupedResultByPPINView(GroupedResultByPPIN):
    packages: list[SHCPackageInfoView]

    @pydantic.computed_field
    @property
    def shc_failed(self) -> bool:
        return super().shc_failed

    @pydantic.computed_field
    @property
    def mca_failed(self) -> bool:
        return super().mca_failed

    @property
    def mcas(self):
        return [mca for p in self.packages for mca in (p.mcas if p.mcas else [])]

    # @pydantic.computed_field
    @property
    def mca_cores_counter(self) -> Counter:
        return Counter(mca.core for mca in self.mcas)

    @pydantic.computed_field
    @property
    def mca_cores(self) -> list:
        return list(set(self.mca_cores_counter.keys()))

    # @pydantic.computed_field
    @property
    def mca_banks_counter(self) -> Counter:
        return Counter(mca.bank for mca in self.mcas)

    @pydantic.computed_field
    @property
    def mca_banks(self) -> list:
        return list(set(self.mca_banks_counter.keys()))

    @pydantic.computed_field
    @property
    def log_list(self) -> list[str]:
        return [log.filename for log in self.packages]

    @pydantic.computed_field
    @property
    def any_ue(self) -> bool:
        return any(mca.uncorrected for mca in self.mcas)

    @pydantic.computed_field
    @property
    def dimm_failure(self) -> bool:
        # We have records with only APEI fake MCE
        return (
            any(mca.bank in list(range(13, 21)) for mca in self.mcas) or
            all(mca.status & 0xFFFF_FFFF == 0x9F for mca in self.mcas)
        )

    @pydantic.computed_field
    @property
    def error_codes(self) -> list[str]:
        return sorted(set(hex(mca.status & 0xFFFF_FFFF) for mca in self.mcas))

    @pydantic.computed_field
    @property
    def mlc_ce(self) -> bool:
        return all(
            mca.bank == 3 and
            not mca.uncorrected and
            (mca.status & 0xFFFF_FFFF) in [
                0x100135, 0x101135,
                0x100151, 0x101151,
                0x100179, 0x101179,
                0x100189, 0x101189,
            ]
            for mca in self.mcas
        ) and any(mca.bank == 3 for mca in self.mcas)

    @pydantic.computed_field
    @property
    def mlc_sqdp_idi_parity(self) -> bool:
        return all(
            mca.bank == 3 and
            (mca.status & 0xFFFF_FFFF) == 0xc00405
            for mca in self.mcas
        )

    @pydantic.computed_field
    @property
    def ifu_parity(self) -> bool:
        return all(
            mca.bank == 0 and
            (mca.status & 0xFFFF_FFFF) == 0x00010005
            for mca in self.mcas
        )

    @pydantic.computed_field
    @property
    def dcu_poison(self) -> bool:
        return any(
            mca.bank == 1 and
            (mca.status & 0xFFFF_FFFF) == 0x00100134
            for mca in self.mcas
        )

    @pydantic.computed_field
    @property
    def llc_parity(self) -> bool:
        # TODO: Refer to EDS and other doc
        return all(
            mca.bank in [9, 10, 11] and
            (mca.status & 0xFFFF_FFFF) in [0x071136, 0x111136]
            for mca in self.mcas
        )

    @pydantic.computed_field
    @property
    def root_caused(self) -> bool:
        return (
            self.dimm_failure or
            self.mlc_ce or
            self.llc_parity or
            self.mlc_sqdp_idi_parity or
            self.ifu_parity or
            False
        )


class GroupedResultByPPINList(pydantic.BaseModel):
    list: list[GroupedResultByPPIN]


class GroupedResultByPPINViewList(pydantic.BaseModel):
    list: list[GroupedResultByPPINView]
