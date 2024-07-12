from datetime import datetime
from typing import Annotated, Any, Literal

import pydantic

from ...base import MachineCheckBase, DimmFailureLocation


def _parse_hex(val: str | None | int):
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if val in ["N/A", "-"]:
        return None
    if "UA" in val or "No info" in val:
        return None
    return int(val, 16)


_HexInt = Annotated[int | None, pydantic.BeforeValidator(_parse_hex)]


class AcdMachineCheck(MachineCheckBase):
    time: datetime = datetime.fromtimestamp(0)

    socket: int = pydantic.Field(
        validation_alias=pydantic.AliasChoices("socket", "skt"))
    bank: int | str
    core: _HexInt = pydantic.Field(
        validation_alias=pydantic.AliasChoices("core", "co"))

    status: _HexInt = pydantic.Field(
        validation_alias=pydantic.AliasChoices("status", "Status"))
    address: _HexInt = pydantic.Field(
        validation_alias=pydantic.AliasChoices("address", "Address"))
    misc: _HexInt = pydantic.Field(
        validation_alias=pydantic.AliasChoices("misc", "Misc"))

    error: str = pydantic.Field(
        validation_alias=pydantic.AliasChoices("error", "Error"))

    cpuid: _HexInt = None


class AcdSummary(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")

    class SignaturesT(pydantic.BaseModel):
        socket: int
        Signature: str

    class XcheckSummaryT(pydantic.BaseModel):
        class _Register(pydantic.BaseModel):
            model_config = pydantic.ConfigDict(extra="allow")

        class FirstIerr(_Register):
            field: Literal["First ierr [7:0]"] = pydantic.Field(
                validation_alias=pydantic.AliasChoices("CPU socket", "field"))

        class FirstMcerr(_Register):
            field: Literal["First mcerr [7:0]"] = pydantic.Field(
                validation_alias=pydantic.AliasChoices("CPU socket", "field"))

        class Ppin(_Register):
            field: Literal["PPIN"] = pydantic.Field(
                validation_alias=pydantic.AliasChoices("CPU socket", "field"))

        table: list[FirstIerr | FirstMcerr | Ppin | dict]

    class TorEntryT(pydantic.BaseModel):
        socket: int = pydantic.Field(
            validation_alias=pydantic.AliasChoices("SKT", "socket"))
        cha: int = pydantic.Field(
            validation_alias=pydantic.AliasChoices("CHA", "cha"))
        tor: int = pydantic.Field(
            validation_alias=pydantic.AliasChoices("TOR", "tor"))
        valid: int = pydantic.Field(
            validation_alias=pydantic.AliasChoices("V", "v", "Valid", "valid"))
        retry: int = pydantic.Field(
            validation_alias=pydantic.AliasChoices("Retry", "retry"))
        inpipe: int = pydantic.Field(
            validation_alias=pydantic.AliasChoices("InPipe", "inpipe"))
        opcode: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("OpCode", "opcode"))
        fsm: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("Fsm", "fsm"))
        address: _HexInt = pydantic.Field(
            validation_alias=pydantic.AliasChoices("System Address", "address"))
        thread: int = pydantic.Field(
            validation_alias=pydantic.AliasChoices("Thread", "thread"))
        core: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("Core", "core"))
        target: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("Target", "target"))
        sad_result: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("SadResult", "sad_result"))
        cache_state: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("CacheState", "cache_state"))
        bdf: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("B/D/F", "bdf", "Seg B/D/F"))
        offset_cl: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("Offset CL", "offset_cl"))
        msmcacod: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices("MCA MSCOD", "msmcacod"))
        error: str | None = pydantic.Field(
            None, validation_alias=pydantic.AliasChoices("Error", "error"))

    class IerrMcerrLogsT(pydantic.BaseModel):
        class _Register(pydantic.BaseModel):
            Value: int | None
            Description: str

        class PcuCrMcaErrSrcLog(_Register):
            Register: Literal["pcu_cr_mca_err_src_log"]

        class IerrlogggingReg(_Register):
            Register: Literal["ierrloggingreg"]

        class McerrlogggingReg(_Register):
            Register: Literal["mcerrloggingreg"]

        class UboxErrStatus(_Register):
            Register: Literal["uboxerrstatus"]

        table: list[
            Annotated[
                PcuCrMcaErrSrcLog | IerrlogggingReg | McerrlogggingReg | UboxErrStatus,
                pydantic.Field(discriminator="Register")
            ]
        ]

        def _get_field(self, t: _Register):
            _ = filter(lambda m: isinstance(m, t), self.table)
            _ = list(_)
            assert len(_) <= 1
            return _[0] if _ else None

        @property
        def pcu_cr_mca_err_src_log(self):
            self._get_field(self.PcuCrMcaErrSrcLog)

        @property
        def ierrloggingreg(self):
            self._get_field(self.IerrlogggingReg)

        @property
        def mcerrloggingreg(self):
            self._get_field(self.McerrlogggingReg)

        @property
        def uboxerrstatus(self):
            self._get_field(self.UboxErrStatus)

    summarizer_version: str
    system_signature: str
    FaultCPU: str
    FaultTimeStamp: Annotated[
        datetime,
        pydantic.BeforeValidator(
            lambda ts: ts.replace(";", "") if isinstance(ts, str) else ts
        )
    ]
    FaultPPIN: _HexInt
    FaultCPUID: _HexInt
    FaultMicrocode: _HexInt
    FaultReason: str
    FaultDevice: str
    FaultCode: str
    FaultDescription: str | None = None
    FaultAction: str
    FaultActionCode: str
    signature_per_socket: list[SignaturesT] | None = pydantic.Field(
        None,
        validation_alias=pydantic.AliasChoices(
            "signature_per_socket",
            pydantic.AliasPath("signature_by_sockets", "table"),
        )
    )
    machine_checks: Annotated[
        list[AcdMachineCheck] | None,
        pydantic.AfterValidator(
            lambda ls: list(filter(lambda m: m.status, ls))
        )
    ] = pydantic.Field(
        None,
        validation_alias=pydantic.AliasChoices(
            "machine_checks",
            pydantic.AliasPath("machine_check_summary", "table")
        ),
    )
    tor_valid_entries: list[TorEntryT] | None = pydantic.Field(
        None,
        validation_alias=pydantic.AliasChoices(
            "tor_valid_entries",
            pydantic.AliasPath("TOR_valid_entries", "table")
        )
    )
    # ierr_mcerr_logs: IerrMcerrLogsT = pydantic.Field(
    #     validation_alias=pydantic.AliasChoices(
    #         "ierr_mcerr_logs",
    #         "IERR_MCERR_logs",
    #     )
    # )
    xcheck_summary: XcheckSummaryT = pydantic.Field(
        validation_alias=pydantic.AliasChoices(
            "xcheck_summary",
            "show_xcheck_ierr_mcerr_summary",
        )
    )
    # all_tor_entries: list[TorEntryT] | None = pydantic.Field(
    #     None,
    #     validation_alias=pydantic.AliasChoices(
    #         "all_tor_entries",
    #         pydantic.AliasPath("all_TOR_entries", "table")
    #     )
    # )

    def model_post_init(self, __context: Any) -> None:
        if self.machine_checks:
            for mc in self.machine_checks:
                mc.time = self.FaultTimeStamp
                mc.cpuid = self.FaultCPUID

    @property
    def ppins(self) -> list[int] | None:
        _ = self.xcheck_summary.table
        _ = filter(lambda f: isinstance(f, self.XcheckSummaryT.Ppin), _)
        ls = list(_)
        if not ls:
            return None
        try:
            return [int(v, 16) for v in ls[0].model_extra.values()]
        except Exception:
            return None
