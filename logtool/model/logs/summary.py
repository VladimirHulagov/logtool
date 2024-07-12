from datetime import datetime
import pathlib
from typing import Annotated, Any
import tempfile
import io
import contextlib
import pathlib

import pydantic

from logtool.model.interface import EventSeverity, ISerializableParsedLog, IParser
from logtool.model.logs.mce import MachineCheck


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


class AcdMachineCheck(MachineCheck):
    time: datetime = datetime.fromtimestamp(0)
    socket: int = pydantic.Field(
        validation_alias=pydantic.AliasChoices("socket", "skt"))
    core: _HexInt = pydantic.Field(
        validation_alias=pydantic.AliasChoices("core", "co"))
    bank: int | str
    status: _HexInt = pydantic.Field(
        validation_alias=pydantic.AliasChoices("status", "Status"))
    address: _HexInt = pydantic.Field(
        validation_alias=pydantic.AliasChoices("address", "Address"))
    misc: _HexInt = pydantic.Field(
        validation_alias=pydantic.AliasChoices("misc", "Misc"))
    error: str = pydantic.Field(
        validation_alias=pydantic.AliasChoices("error", "Error"))
    sub_source: str = pydantic.Field("ACD")


class Summary(pydantic.BaseModel, ISerializableParsedLog):
    class SignaturesT(pydantic.BaseModel):
        socket: int
        Signature: str

    class XcheckSummaryT(pydantic.BaseModel):
        model_config = pydantic.ConfigDict(extra="allow")
        socket: str = pydantic.Field(
            validation_alias=pydantic.AliasChoices(
                "socket",
                "CPU socket",
                "Register Field",
            )
        )

    class _SummarizerTOREntry(pydantic.BaseModel):
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

    class _SummarizerErrorLogging(pydantic.BaseModel):
        pcu_cr_mca_err_src_log: int | None
        ierrloggingreg: int | None
        mcerrloggingreg: int | None
        uboxerrstatus: int | None
        pcu_cr_mca_err_src_log_decode: str
        ierrloggingreg_decode: str
        mcerrloggingreg_decode: str
        uboxerrstatus_decode: str

        @staticmethod
        def parse(ls: list[dict] | dict[str, dict]):
            if isinstance(ls, list):
                return ls
            ret = []
            for tab in ls.values():
                res = {}
                for d in tab["table"]:
                    r = d["Register"]
                    v: str = d["Value"]
                    des = d["Description"]
                    res[r] = int(v, 16) if v != "None" else None
                    res[r + "_decode"] = des
                ret.append(res)
            return ret

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
        pydantic.BeforeValidator(
            lambda ls: list(
                filter(
                    lambda mc: mc.status is not None and mc.valid,
                    map(AcdMachineCheck.model_validate, ls)
                )
            ) if ls is not None else None
        )
    ] = pydantic.Field(
        None,
        validation_alias=pydantic.AliasChoices(
            "machine_checks",
            pydantic.AliasPath("machine_check_summary", "table")
        ),
    )
    tor_valid_entries: list[_SummarizerTOREntry] | None = pydantic.Field(
        None,
        validation_alias=pydantic.AliasChoices(
            "tor_valid_entries",
            pydantic.AliasPath("TOR_valid_entries", "table")
        )
    )
    ierr_mcerr_logs: Annotated[
        list[_SummarizerErrorLogging] | None,
        pydantic.BeforeValidator(_SummarizerErrorLogging.parse)
    ] = pydantic.Field(
        validation_alias=pydantic.AliasChoices(
            "ierr_mcerr_logs",
            "IERR_MCERR_logs",
        )
    )
    xcheck_summary: list[XcheckSummaryT] = pydantic.Field(
        validation_alias=pydantic.AliasChoices(
            "xcheck_summary",
            pydantic.AliasPath("show_xcheck_ierr_mcerr_summary", "table")
        )
    )
    # all_tor_entries: list[_SummarizerTOREntry] | None = pydantic.Field(
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

    @property
    def _time(self):
        return self.FaultTimeStamp

    @property
    def _severity(self):
        return EventSeverity.Critical

    @property
    def description(self):
        return self.FaultReason

    @property
    def key_events(self):
        # TODO: typing!!!
        res = [self]
        res.extend((MachineCheck.model_validate(mc.model_dump())
                   for mc in self.machine_checks) if self.machine_checks else [])
        return res

    @property
    def signature(self):
        return self.system_signature

    @property
    def ppins(self) -> list[int] | None:
        fs = [f for f in self.xcheck_summary if f.socket == "PPIN"]
        assert len(fs) == 1
        ks = [k for k in fs[0].model_extra if k.isdecimal()]
        assert len(ks) == max(int(k) for k in ks) + 1
        vs = [fs[0].model_extra[k] for k in ks]
        return list(filter(None, map(_parse_hex, vs))) or None


class AcdSummarizer(IParser):
    @property
    def _path_suffix(self):
        return ".json"

    def parse_impl(self, logpath: pathlib.Path):
        """Try parsing an ACD log.
        Return None if the given log is not an acceptable log by summarizer.
        """
        logpath = str(logpath)
        from pysvtools.crashdump_summarizer.cd_summarizer import summary
        with tempfile.TemporaryDirectory() as tmpdir:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                summary(logpath, text_file=False, dest=tmpdir)
            stderr.seek(0)
            files = list(pathlib.Path(tmpdir).glob("*.json"))
            err = stderr.read()
            if "JSON might be corrupted!" in err:
                raise ValueError(f"Summarizer found corrupted json")
            elif err:
                raise RuntimeError(f"Summarizer internal error: {err}")
            if len(files) != 1:
                raise RuntimeError("Summarizer fail to generate summary.")
            with open(files[0]) as f:
                content = f.read()
                if not __debug__:
                    return Summary.model_validate_json(content)
                try:
                    return Summary.model_validate_json(content)
                except Exception:
                    import json
                    res = {k: json.dumps(v, indent=2)
                           for k, v in json.loads(content).items()}
                    for k, v in res.items():
                        if len(v) > 1000:
                            continue
                        print(k)
                        print(v)
                    raise

    def check_impl(self, logpath: pathlib.Path):
        logpath = str(logpath)
        from pysvtools.crashdump_summarizer.cd_summarizer import get_json
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            return bool(get_json(logpath))


{
    "IERR_MCERR_logs": {
        "cpu0": {
            "title": "IERR, MCEERR and PM Dispatcher Logs cpu0",
            "table": [
                {
                    "Register": "pcu_cr_mca_err_src_log",
                    "Value": "0x00140000",
                    "Description": "MSMI_MCERR# Asserted"
                },
                {
                    "Register": "ierrloggingreg",
                    "Value": "0x00000000",
                    "Description": ""
                },
                {
                    "Register": "mcerrloggingreg",
                    "Value": "0x0000031b",
                    "Description": "Bits   [7:0] First MCERR Src Valid -->  Core27  <--\nBits     [9] FirstMcerrSrcID is from a Cbo or CORE"
                },
                {
                    "Register": "uboxerrstatus",
                    "Value": "0x00000000",
                    "Description": ""
                },
                {
                    "Register": "Shared PMA",
                    "Value": "None",
                    "Description": ""
                },
                {
                    "Register": "Dispatcher Vector",
                    "Value": "None",
                    "Description": ""
                }
            ]
        },
        "cpu1": {
            "title": "IERR, MCEERR and PM Dispatcher Logs cpu1",
            "table": [
                {
                    "Register": "pcu_cr_mca_err_src_log",
                    "Value": "0x00a00000",
                    "Description": ""
                },
                {
                    "Register": "ierrloggingreg",
                    "Value": "0x00000000",
                    "Description": ""
                },
                {
                    "Register": "mcerrloggingreg",
                    "Value": "0x00000130",
                    "Description": "Bits   [7:0] First MCERR Src Valid -->  0x30 PUNIT  <--\nBits     [9] FirstMcerrSrcID is from a Cbo or CORE"
                },
                {
                    "Register": "uboxerrstatus",
                    "Value": "0x00000000",
                    "Description": ""
                },
                {
                    "Register": "Shared PMA",
                    "Value": "None",
                    "Description": ""
                },
                {
                    "Register": "Dispatcher Vector",
                    "Value": "None",
                    "Description": ""
                }
            ]
        }
    },
    "TSC_logs": {
        "cpu0": {
            "title": "PCU FIRST IERR/MCERR TSC cpu0",
            "table": [
                {
                    "Register": "pcu_first_ierr_tsc_lo_cfg",
                    "Value": "0x00000000"
                },
                {
                    "Register": "pcu_first_ierr_tsc_hi_cfg",
                    "Value": "0x00000000"
                },
                {
                    "Register": "pcu_first_mcerr_tsc_lo_cfg",
                    "Value": "0xad9d5248"
                },
                {
                    "Register": "pcu_first_mcerr_tsc_hi_cfg",
                    "Value": "0x00003ad3"
                }
            ]
        },
        "cpu1": {
            "title": "PCU FIRST IERR/MCERR TSC cpu1",
            "table": [
                {
                    "Register": "pcu_first_ierr_tsc_lo_cfg",
                    "Value": "0x00000000"
                },
                {
                    "Register": "pcu_first_ierr_tsc_hi_cfg",
                    "Value": "0x00000000"
                },
                {
                    "Register": "pcu_first_mcerr_tsc_lo_cfg",
                    "Value": "0x00000000"
                },
                {
                    "Register": "pcu_first_mcerr_tsc_hi_cfg",
                    "Value": "0x00000000"
                }
            ]
        }
    },
    "pcie_uncerrsts": {
        "0": {
            "title": "Socket 0 PCIe PXP/Ports erruncsts/rppiosts table",
            "table": [
                {
                    "Register.Field / PXP": "port",
                    "0": " 0 ",
                    "0 ": " 1 ",
                    "0  ": " 2 ",
                    "0   ": " 3 ",
                    "1": " 0 ",
                    "1 ": " 1 ",
                    "1  ": " 2 ",
                    "1   ": " 3 ",
                    "2": " 0 ",
                    "2 ": " 1 ",
                    "2  ": " 2 ",
                    "2   ": " 3 ",
                    "3": " 0 ",
                    "3 ": " 1 ",
                    "3  ": " 2 ",
                    "3   ": " 3 "
                },
                {
                    "Register.Field / PXP": "erruncsts.poisoned_tlp_blocked_status",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.tlp_prefix_blocked_error_status",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.atomic_op_tlp_prefix_blocked_error_status",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.multicast_tlp_prefix_blocked_error_status",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.uncorrectable internal error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.acs_violation_detected",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.unsupported_request",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.ecrce",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.malformed_tlp",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.receive_buffers_overflow",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.completion_received_notmatch",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.completion_abort_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.completion_timeout_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.flow_control_protocol_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.poisoned_tlp_received",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.surprise_linkdown_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.data_link_protocol_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.memory_request_completion_timeout",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.memory_request_ca_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.memory_request_ur_completion",
                    "0": "*1*",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": "*1*",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.io_request_completion_timeout",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.io_request_ca_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.io_request_ur_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.cfg_request_completion_timeout",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.cfg_request_ca_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.cfg_request_ur_completion",
                    "0": "*1*",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": "*1*",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": "*1*",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": "*1*",
                    "3   ": "*1*"
                },
                {
                    "Register.Field / PXP": "rppiohdrlog1",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppiohdrlog2",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppiohdrlog3",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppiohdrlog4",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppiose",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppioexc",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "pribus",
                    "0": "0x16",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x30",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x4a",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x64",
                    "3   ": "0x64"
                },
                {
                    "Register.Field / PXP": "secbus",
                    "0": "0x17",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x31",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x4b",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x65",
                    "3   ": "0x66"
                },
                {
                    "Register.Field / PXP": "subbus",
                    "0": "0x17",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x35",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x4f",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x65",
                    "3   ": "0x66"
                },
                {
                    "Register.Field / PXP": "aerhdrlog1",
                    "0": "0x20000010",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0xa000000",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x40000001",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x40000001",
                    "3   ": "0x40000001"
                },
                {
                    "Register.Field / PXP": "aerhdrlog2",
                    "0": "0x170000ff",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x35002004",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x4b01000f",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x65001a0f",
                    "3   ": "0x6600030f"
                },
                {
                    "Register.Field / PXP": "aerhdrlog3",
                    "0": "0x7e",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0xfd200000",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0xfee04230",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0xfee00430",
                    "3   ": "0xfee021f0"
                },
                {
                    "Register.Field / PXP": "aerhdrlog4",
                    "0": "0xef0443c0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.ltssmstatemain",
                    "0": "0x3",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x3",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x3",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x3",
                    "3   ": "0x3"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.ltssmstatesub",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0xd",
                    "3 ": "0xd",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.ltssmrxl0ssm",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.lnknum",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x1",
                    "3  ": "0x2",
                    "3   ": "0x3"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.rcvratesup",
                    "0": "0x3",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x3",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x3",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x3",
                    "3   ": "0x3"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.lnkreversed",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.dlactive",
                    "0": "0x1",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x1",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x1",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x1",
                    "3   ": "0x1"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.ltssmlnkup",
                    "0": "0x1",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x1",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x1",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x1",
                    "3   ": "0x1"
                },
                {
                    "Register.Field / PXP": "ltssmstatelog0",
                    "0": "0x99944443",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x44344443",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x99944443",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x99944443",
                    "3   ": "0x99944443"
                },
                {
                    "Register.Field / PXP": "ltssmstatelog1",
                    "0": "0x16e2130",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x13002130",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x16e2130",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x230123cd",
                    "3 ": "0x230123cd",
                    "3  ": "0x16e2130",
                    "3   ": "0x16e2130"
                },
                {
                    "Register.Field / PXP": "ltssmstatelog2",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "linksts.ChangedLink/Width without port transitioning through DL_Down status",
                    "0": "0x1",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x1",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "linksts.PhyLayer non-autonomous speed/width change initiated by the Upstream Port",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x1",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x1",
                    "3   ": "0x1"
                },
                {
                    "Register.Field / PXP": "linksts.DataLink in Active State",
                    "0": "0x1",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x1",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x1",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x1",
                    "3   ": "0x1"
                },
                {
                    "Register.Field / PXP": "rooterrsts.FatalErrorMessageReceived",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.FirstUncorrectableFatal",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.MultipleErrorFatal/Non-FatalReceived",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.ErrorFatal/Non-FatalReceived",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.MultipleErrorCorrectableErrorReceived",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceivesPoisonedTLP",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceives ERR_FATAL/ERR_NONFATAL message",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceivesCompWithUnsupportedRequestsCompletionStatus",
                    "0": "0x1",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x1",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x1",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x1",
                    "3   ": "0x1"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceivesCompWithCompleterAboutCompletionStatus",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceivesCompWithPosted/NonPostedRequest_as_CompleterAbortError",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "devsts.Unsupported request from PCI Express link",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "devsts.function has detected a Fatal error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "devsts.function has detected a Non-Fatal error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "devsts.function has detected a Correctable error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errsrcid.efsid",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errsrcid.ecsid",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x6500",
                    "3   ": "0x6600"
                },
                {
                    "Register.Field / PXP": "errcorsts.header_log_overflow_error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.correctable_internal_error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.Advisory_Non-Fatal_Error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.replay_timer_timeout",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.replay_timer_overflow",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.CRC_errors_on_DLLP",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.CRC_errors_on_TLP",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.phylayer_detects_receiver_error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "slotsts.PresenceDetectStatus",
                    "0": "0x1",
                    "0 ": "0x1",
                    "0  ": "0x1",
                    "0   ": "0x1",
                    "1": "0x1",
                    "1 ": "0x1",
                    "1  ": "0x1",
                    "1   ": "0x1",
                    "2": "0x1",
                    "2 ": "0x1",
                    "2  ": "0x1",
                    "2   ": "0x1",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x1",
                    "3   ": "0x1"
                }
            ]
        },
        "1": {
            "title": "Socket 1 PCIe PXP/Ports erruncsts/rppiosts table",
            "table": [
                {
                    "Register.Field / PXP": "port",
                    "0": " 0 ",
                    "0 ": " 1 ",
                    "0  ": " 2 ",
                    "0   ": " 3 ",
                    "1": " 0 ",
                    "1 ": " 1 ",
                    "1  ": " 2 ",
                    "1   ": " 3 ",
                    "2": " 0 ",
                    "2 ": " 1 ",
                    "2  ": " 2 ",
                    "2   ": " 3 ",
                    "3": " 0 ",
                    "3 ": " 1 ",
                    "3  ": " 2 ",
                    "3   ": " 3 "
                },
                {
                    "Register.Field / PXP": "erruncsts.poisoned_tlp_blocked_status",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.tlp_prefix_blocked_error_status",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.atomic_op_tlp_prefix_blocked_error_status",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.multicast_tlp_prefix_blocked_error_status",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.uncorrectable internal error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.acs_violation_detected",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.unsupported_request",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.ecrce",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.malformed_tlp",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.receive_buffers_overflow",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.completion_received_notmatch",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.completion_abort_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.completion_timeout_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.flow_control_protocol_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.poisoned_tlp_received",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.surprise_linkdown_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "erruncsts.data_link_protocol_error",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.memory_request_completion_timeout",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.memory_request_ca_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.memory_request_ur_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.io_request_completion_timeout",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.io_request_ca_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.io_request_ur_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.cfg_request_completion_timeout",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.cfg_request_ca_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": " 0 ",
                    "0   ": " 0 ",
                    "1": " 0 ",
                    "1 ": " 0 ",
                    "1  ": " 0 ",
                    "1   ": " 0 ",
                    "2": " 0 ",
                    "2 ": " 0 ",
                    "2  ": " 0 ",
                    "2   ": " 0 ",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiosts.cfg_request_ur_completion",
                    "0": " 0 ",
                    "0 ": " 0 ",
                    "0  ": "*1*",
                    "0   ": "*1*",
                    "1": "*1*",
                    "1 ": "*1*",
                    "1  ": "*1*",
                    "1   ": "*1*",
                    "2": "*1*",
                    "2 ": "*1*",
                    "2  ": "*1*",
                    "2   ": "*1*",
                    "3": " 0 ",
                    "3 ": " 0 ",
                    "3  ": " 0 ",
                    "3   ": " 0 "
                },
                {
                    "Register.Field / PXP": "rppiohdrlog1",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppiohdrlog2",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppiohdrlog3",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppiohdrlog4",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppiose",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rppioexc",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "pribus",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x97",
                    "0   ": "0x97",
                    "1": "0xb0",
                    "1 ": "0xb0",
                    "1  ": "0xb0",
                    "1   ": "0xb0",
                    "2": "0xc9",
                    "2 ": "0xc9",
                    "2  ": "0xc9",
                    "2   ": "0xc9",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secbus",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x98",
                    "0   ": "0x99",
                    "1": "0xb1",
                    "1 ": "0xb2",
                    "1  ": "0xb3",
                    "1   ": "0xb4",
                    "2": "0xca",
                    "2 ": "0xcb",
                    "2  ": "0xcc",
                    "2   ": "0xcd",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "subbus",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x98",
                    "0   ": "0x99",
                    "1": "0xb1",
                    "1 ": "0xb2",
                    "1  ": "0xb3",
                    "1   ": "0xb4",
                    "2": "0xca",
                    "2 ": "0xcb",
                    "2  ": "0xcc",
                    "2   ": "0xcd",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "aerhdrlog1",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x40000001",
                    "0   ": "0x40000001",
                    "1": "0x40000001",
                    "1 ": "0x40000001",
                    "1  ": "0x40000001",
                    "1   ": "0x40000001",
                    "2": "0x40000001",
                    "2 ": "0x40000001",
                    "2  ": "0x40000001",
                    "2   ": "0x40000001",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "aerhdrlog2",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x9800100f",
                    "0   ": "0x9900190f",
                    "1": "0xb100040f",
                    "1 ": "0xb2001a0f",
                    "1  ": "0xb300060f",
                    "1   ": "0xb400080f",
                    "2": "0xca00070f",
                    "2 ": "0xcb000a0f",
                    "2  ": "0xcc00140f",
                    "2   ": "0xcd001e0f",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "aerhdrlog3",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0xfee00d10",
                    "0   ": "0xfee00650",
                    "1": "0xfee02ef0",
                    "1 ": "0xfee04790",
                    "1  ": "0xfee01d10",
                    "1   ": "0xfee00a90",
                    "2": "0xfee026d0",
                    "2 ": "0xfee01990",
                    "2  ": "0xfee016d0",
                    "2   ": "0xfee030f0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "aerhdrlog4",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.ltssmstatemain",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x3",
                    "0   ": "0x3",
                    "1": "0x3",
                    "1 ": "0x3",
                    "1  ": "0x3",
                    "1   ": "0x3",
                    "2": "0x3",
                    "2 ": "0x3",
                    "2  ": "0x3",
                    "2   ": "0x3",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.ltssmstatesub",
                    "0": "0xd",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0xd",
                    "3 ": "0xd",
                    "3  ": "0xd",
                    "3   ": "0xd"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.ltssmrxl0ssm",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.lnknum",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x2",
                    "0   ": "0x3",
                    "1": "0x0",
                    "1 ": "0x1",
                    "1  ": "0x2",
                    "1   ": "0x3",
                    "2": "0x0",
                    "2 ": "0x1",
                    "2  ": "0x2",
                    "2   ": "0x3",
                    "3": "0x0",
                    "3 ": "0x1",
                    "3  ": "0x2",
                    "3   ": "0x3"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.rcvratesup",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x3",
                    "0   ": "0x3",
                    "1": "0x3",
                    "1 ": "0x3",
                    "1  ": "0x3",
                    "1   ": "0x3",
                    "2": "0x3",
                    "2 ": "0x3",
                    "2  ": "0x3",
                    "2   ": "0x3",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.lnkreversed",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.dlactive",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x1",
                    "0   ": "0x1",
                    "1": "0x1",
                    "1 ": "0x1",
                    "1  ": "0x1",
                    "1   ": "0x1",
                    "2": "0x1",
                    "2 ": "0x1",
                    "2  ": "0x1",
                    "2   ": "0x1",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmsmsts.ltssmlnkup",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x1",
                    "0   ": "0x1",
                    "1": "0x1",
                    "1 ": "0x1",
                    "1  ": "0x1",
                    "1   ": "0x1",
                    "2": "0x1",
                    "2 ": "0x1",
                    "2  ": "0x1",
                    "2   ": "0x1",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmstatelog0",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x44344443",
                    "0   ": "0x99944443",
                    "1": "0x99944443",
                    "1 ": "0x99944443",
                    "1  ": "0x99944443",
                    "1   ": "0x99944443",
                    "2": "0x99944443",
                    "2 ": "0x99944443",
                    "2  ": "0x99944443",
                    "2   ": "0x44344443",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "ltssmstatelog1",
                    "0": "0x230123cd",
                    "0 ": "0x0",
                    "0  ": "0x13002130",
                    "0   ": "0x16e2130",
                    "1": "0x16e2130",
                    "1 ": "0x16e2130",
                    "1  ": "0x16e2130",
                    "1   ": "0x16e2130",
                    "2": "0x16e2130",
                    "2 ": "0x16e2130",
                    "2  ": "0x16e2130",
                    "2   ": "0x13002130",
                    "3": "0x230123cd",
                    "3 ": "0x230123cd",
                    "3  ": "0x230123cd",
                    "3   ": "0x230123cd"
                },
                {
                    "Register.Field / PXP": "ltssmstatelog2",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "linksts.ChangedLink/Width without port transitioning through DL_Down status",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "linksts.PhyLayer non-autonomous speed/width change initiated by the Upstream Port",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x1",
                    "0   ": "0x1",
                    "1": "0x1",
                    "1 ": "0x1",
                    "1  ": "0x1",
                    "1   ": "0x1",
                    "2": "0x1",
                    "2 ": "0x1",
                    "2  ": "0x1",
                    "2   ": "0x1",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "linksts.DataLink in Active State",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x1",
                    "0   ": "0x1",
                    "1": "0x1",
                    "1 ": "0x1",
                    "1  ": "0x1",
                    "1   ": "0x1",
                    "2": "0x1",
                    "2 ": "0x1",
                    "2  ": "0x1",
                    "2   ": "0x1",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.FatalErrorMessageReceived",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.FirstUncorrectableFatal",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.MultipleErrorFatal/Non-FatalReceived",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.ErrorFatal/Non-FatalReceived",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "rooterrsts.MultipleErrorCorrectableErrorReceived",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceivesPoisonedTLP",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceives ERR_FATAL/ERR_NONFATAL message",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceivesCompWithUnsupportedRequestsCompletionStatus",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x1",
                    "0   ": "0x1",
                    "1": "0x1",
                    "1 ": "0x1",
                    "1  ": "0x1",
                    "1   ": "0x1",
                    "2": "0x1",
                    "2 ": "0x1",
                    "2  ": "0x1",
                    "2   ": "0x1",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceivesCompWithCompleterAboutCompletionStatus",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "secsts.SecondarySideType1ConfigReceivesCompWithPosted/NonPostedRequest_as_CompleterAbortError",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "devsts.Unsupported request from PCI Express link",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "devsts.function has detected a Fatal error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "devsts.function has detected a Non-Fatal error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "devsts.function has detected a Correctable error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errsrcid.efsid",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errsrcid.ecsid",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x9800",
                    "0   ": "0x9900",
                    "1": "0xb100",
                    "1 ": "0xb200",
                    "1  ": "0xb300",
                    "1   ": "0xb400",
                    "2": "0xca00",
                    "2 ": "0xcb00",
                    "2  ": "0xcc00",
                    "2   ": "0xcd00",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.header_log_overflow_error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.correctable_internal_error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.Advisory_Non-Fatal_Error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.replay_timer_timeout",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.replay_timer_overflow",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.CRC_errors_on_DLLP",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.CRC_errors_on_TLP",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "errcorsts.phylayer_detects_receiver_error",
                    "0": "0x0",
                    "0 ": "0x0",
                    "0  ": "0x0",
                    "0   ": "0x0",
                    "1": "0x0",
                    "1 ": "0x0",
                    "1  ": "0x0",
                    "1   ": "0x0",
                    "2": "0x0",
                    "2 ": "0x0",
                    "2  ": "0x0",
                    "2   ": "0x0",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                },
                {
                    "Register.Field / PXP": "slotsts.PresenceDetectStatus",
                    "0": "0x0",
                    "0 ": "0x1",
                    "0  ": "0x1",
                    "0   ": "0x1",
                    "1": "0x1",
                    "1 ": "0x1",
                    "1  ": "0x1",
                    "1   ": "0x1",
                    "2": "0x1",
                    "2 ": "0x1",
                    "2  ": "0x1",
                    "2   ": "0x1",
                    "3": "0x0",
                    "3 ": "0x0",
                    "3  ": "0x0",
                    "3   ": "0x0"
                }
            ]
        }
    },
    "uncore_error_count": {
        "title": "Uncore Registers Error Summary",
        "table": [
            {
                "IP-Block": "M2IOSF",
                "Socket0": "1",
                "Socket1": "1"
            },
            {
                "IP-Block": "IEH",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "CBDMA",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "DMI",
                "Socket0": "1",
                "Socket1": "0"
            },
            {
                "IP-Block": "PCIE-PXP0",
                "Socket0": "2",
                "Socket1": "4"
            },
            {
                "IP-Block": "PCIE-PXP1",
                "Socket0": "2",
                "Socket1": "8"
            },
            {
                "IP-Block": "PCIE-PXP2",
                "Socket0": "2",
                "Socket1": "8"
            },
            {
                "IP-Block": "PCIE-PXP3",
                "Socket0": "4",
                "Socket1": "0"
            },
            {
                "IP-Block": "UBOX",
                "Socket0": "1",
                "Socket1": "1"
            },
            {
                "IP-Block": "IEH_GLOBAL",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "UPI0",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "UPI1",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "UPI2",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "UPI-Misc",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "M2MEM0",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "M2MEM1",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "M2MEM2",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "M2MEM3",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "iMC0-CH0",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "iMC0-CH1",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "iMC1-CH0",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "iMC1-CH1",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "iMC2-CH0",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "iMC2-CH1",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "iMC3-CH0",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "iMC3-CH1",
                "Socket0": "0",
                "Socket1": "2"
            },
            {
                "IP-Block": "iMC-Misc",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "DDRPHY",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "CHA",
                "Socket0": "0",
                "Socket1": "0"
            },
            {
                "IP-Block": "PUNIT",
                "Socket0": "1",
                "Socket1": "1"
            }
        ]
    },
    "c_states": {},
    "machine_check_decodes": {
        "CPU0 Core27 Bank0": {
            "machine_check_bank": {
                "title": "CPU0 Core27 Bank0 - Machine Check Registers Overview",
                "table": [
                    {
                        "skt": "0",
                        "co": "27",
                        "thr": "0",
                        "bank": "0",
                        "Status": "0xb200000000080005",
                        "Address": "0x0000000000000000",
                        "Misc": "0x0000000000000000",
                        "Ctl": "0x0000000000000fff"
                    }
                ]
            },
            "status_register_decode": {
                "title": "CPU0 Core27 Bank0 - Machine Check Status Register Decodes",
                "table": [
                    {
                        "Range": "63:63",
                        "Field": "VALID",
                        "Description": "Indicates that the information within this register is valid",
                        "Value": "0x1",
                        "Value Decode Description": "Valid"
                    },
                    {
                        "Range": "62:62",
                        "Field": "OVERFLOW",
                        "Description": "A '1' indicates that a machine-check error occurred while\nthe results of a previous error were still in the error-\nreporting register bank (the VALID bit was already set)",
                        "Value": "0x0",
                        "Value Decode Description": "Not Overflow"
                    },
                    {
                        "Range": "61:61",
                        "Field": "UC",
                        "Description": "A '1' indicates that an uncorrectable the error condition\nwas detected.",
                        "Value": "0x1",
                        "Value Decode Description": "UC Detected"
                    },
                    {
                        "Range": "60:60",
                        "Field": "EN",
                        "Description": "Error reporting enabled. A '1' indicates that error\nreporting is enabled by the associated flag bit(s) in the\nIA32_MCi_CTL register.",
                        "Value": "0x1",
                        "Value Decode Description": "Enabled"
                    },
                    {
                        "Range": "59:59",
                        "Field": "MISCV",
                        "Description": "If this flag is '1', the IA32_MCi_MISC register content is\nvalid and can be read.",
                        "Value": "0x0",
                        "Value Decode Description": "IA32_MCi_MISC Not Valid"
                    },
                    {
                        "Range": "58:58",
                        "Field": "ADDRV",
                        "Description": "If this flag is '1', the IA32_MCi_ADDR register content is\nvalid and can be read.",
                        "Value": "0x0",
                        "Value Decode Description": "IA32_MCi_ADDR Not Valid"
                    },
                    {
                        "Range": "57:57",
                        "Field": "PCC",
                        "Description": "Processor Context Corrupt: A '1' indicates that reliable\nrestarting of the processor may not be possible and a reset\nis recommended.",
                        "Value": "0x1",
                        "Value Decode Description": "Processor Context Corrupted"
                    },
                    {
                        "Range": "56:56",
                        "Field": "S",
                        "Description": "Signaling an uncorrectable recoverable error.",
                        "Value": "0x0",
                        "Value Decode Description": " --- "
                    },
                    {
                        "Range": "55:55",
                        "Field": "AR",
                        "Description": "Recovery action required for UCR error.",
                        "Value": "0x0",
                        "Value Decode Description": " --- "
                    },
                    {
                        "Range": "54:53",
                        "Field": "RESERVED",
                        "Description": "Reserved",
                        "Value": "0x0",
                        "Value Decode Description": " --- "
                    },
                    {
                        "Range": "52:52",
                        "Field": "STICKY",
                        "Description": "Sticky bit set when error count overflows",
                        "Value": "0x0",
                        "Value Decode Description": " --- "
                    },
                    {
                        "Range": "51:38",
                        "Field": "CORRECTED_ERR_CNT",
                        "Description": "Corrected error count since last clear of machine check\nregisters",
                        "Value": "0x0",
                        "Value Decode Description": " --- "
                    },
                    {
                        "Range": "37:32",
                        "Field": "RESERVED_37_32",
                        "Description": "Reserved",
                        "Value": "0x0",
                        "Value Decode Description": " --- "
                    },
                    {
                        "Range": "31:16",
                        "Field": "MSCOD",
                        "Description": "Model Specific Error Code",
                        "Value": "0x8",
                        "Value Decode Description": "BRANCH_ARRAY_PARITY_ERROR_0008_0005"
                    },
                    {
                        "Range": "15:11",
                        "Field": "ENH_MCA_AVAIL0",
                        "Description": "Reserved",
                        "Value": "0x0",
                        "Value Decode Description": " --- "
                    },
                    {
                        "Range": "10:0",
                        "Field": "MCACOD",
                        "Description": "Machine Check Architecture Error Code",
                        "Value": "0x5",
                        "Value Decode Description": "IFU Internal Parity Error"
                    }
                ]
            }
        }
    }
}
