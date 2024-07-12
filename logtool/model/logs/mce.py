import re
import abc
import enum
import json
import typing
import pathlib
import functools
import warnings
from datetime import datetime
from dateutil import parser as dtparser

import pydantic

from logtool.model.abstract import IMachineCheck
from logtool.model.interface import ISerializableEvent, IParser


# TODO: MachineCheck -> IMachineCheck, let parser implement concrete class
UNCORE_ID = -1


class MachineCheck(pydantic.BaseModel, IMachineCheck, ISerializableEvent):
    model_config = pydantic.ConfigDict(extra="allow")

    status: int
    bank: int | str | None = None
    misc: int | None = None
    time: datetime
    socket: int | None = None
    core: int | None = None  # -1 for uncore
    address: int | None = None
    sub_source: str

    def model_post_init(self, _):
        if not self.address_valid:
            self.address = None
        if not self.misc_valid:
            self.misc = None

    @property
    def mc_status(self):
        return self.status

    @property
    def description(self):
        return f"Socket {self.socket} Core {self.core} Bank {self.bank} Status {hex(self.status)}"

    @property
    def _detail(self):
        return _MachineCheckView.model_validate(self.model_dump()).model_dump_json(indent=2)

    @property
    def _subtype(self):
        return self.sub_source

    @property
    def signature(self):
        return hex(self.status)


class _MachineCheckView(MachineCheck):
    @pydantic.computed_field
    @property
    def valid(self) -> bool:
        return super().valid

    @pydantic.computed_field
    @property
    def overflow(self) -> bool:
        return super().overflow

    @pydantic.computed_field
    @property
    def uncorrected(self) -> bool:
        return super().uncorrected

    @pydantic.computed_field
    @property
    def enabled(self) -> bool:
        return super().enabled

    @pydantic.computed_field
    @property
    def misc_valid(self) -> bool:
        return super().misc_valid

    @pydantic.computed_field
    @property
    def address_valid(self) -> bool:
        return super().address_valid

    @pydantic.computed_field
    @property
    def pcc(self) -> bool:
        return super().pcc

    @pydantic.computed_field
    @property
    def corrected_yellow(self) -> bool:
        return super().corrected_yellow

    @pydantic.computed_field
    @property
    def corrected_green(self) -> bool:
        return super().corrected_green

    @pydantic.computed_field
    @property
    def corrected_count(self) -> int:
        return super().corrected_count


class _MCESource(enum.Enum):
    mcelog = enum.auto()
    dmesg_mcelog = enum.auto()
    edac = enum.auto()
    extsel = enum.auto()
    serial = enum.auto()
    acd = enum.auto()
    onekeylog = enum.auto()
    error_analy_report = enum.auto()
    venus = enum.auto()


class _MCAField(enum.Enum):
    socket = enum.auto()
    ppin = enum.auto()
    ucode = enum.auto()
    core = enum.auto()
    thread = enum.auto()
    apic = enum.auto()
    bank = enum.auto()
    status = enum.auto()
    address = enum.auto()
    misc = enum.auto()
    tsc = enum.auto()
    time = enum.auto()
    retry_rd_err_log = enum.auto()
    correrrcnt = enum.auto()


class _FieldDesc():
    def __init__(self, type: typing.Literal["dec", "hex", "str", "time"], ptn: str) -> None:
        self.type = type
        self.regex = re.compile(ptn)

    def __call__(self, text):
        res = self.regex.findall(text)
        if not res:
            return None
        assert len(set(res)) == 1, f"Regex: {self.regex.pattern} Text:\n{text}"
        res: str = res[0]
        match self.type:
            case "dec":
                return int(res)
            case "hex":
                return int(res, base=16)
            case "str":
                return res
            case "time":
                # Serial log
                return dtparser.parse(res)
            case _:
                assert False


def _try_json_loads(s: str):
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


class IMachineCheckParser(IParser):
    @abc.abstractmethod
    def parse_impl(self, input: str | pathlib.Path) -> list[MachineCheck] | None:
        ...

    @abc.abstractmethod
    def check_impl(self, log):
        ...


class MCETextExtractor(IMachineCheckParser):
    def __init__(self, source: _MCESource, *, pattern: str, subpatterns: dict[_MCAField, _FieldDesc], filter=None) -> None:
        self.source = source
        self.regex = re.compile(pattern)
        self.subpatterns = subpatterns
        self.filter = filter

    def parse_impl(self, text: str):
        def _extract_mca(src: str):
            lines = list(filter(self.filter, src.split("\n")))
            txt = "\n".join(lines)
            assert all(
                len(line) < 2000 or
                "systemd-coredump" in line
                for line in lines
            ), f"Length: {len(txt)} Text:\n{txt[:100000]}"
            assert self.regex.match(txt)
            res = {k.name: v(txt) for k, v in self.subpatterns.items()}
            if res.get("status") is None:
                # We do have such logs
                # 28B807106_shc_report_2023-08-17-01-51-42.tar.xz
                warnings.warn("Text fragment not contain valid status")
                return None
            res["sub_source"] = self.source.name
            return MachineCheck.model_validate(res)
        _ = self.regex.finditer(text)
        # if __debug__:
        #     _ = list(_)
        #     for idx, m in enumerate(_):
        #         print(idx, text[:m.span()[0]].count("\n") + 1)
        #         print(text[m.span()[0]:m.span()[1]])
        _ = map(lambda match: match.group(), _)
        _ = map(_extract_mca, _)
        _ = filter(None, _)
        return list(_)

    def check_impl(self, text: str):
        return bool(self.regex.search(text))


class ErrorAnalyMCEExtractor(IMachineCheckParser):
    def parse_impl(self, content: str) -> list[MachineCheck]:
        # TODO: pydantic
        def _extract_mca(log):
            def __extract_mcas(entry: dict):
                if entry.get("ErrorArch") != "MCA":
                    return None
                socketid = entry["CPU"]
                core = entry["Core"]
                if isinstance(core, int):
                    coreid = core
                elif isinstance(core, str):
                    if core.lower() == "uncore":
                        coreid = UNCORE_ID
                else:
                    raise NotImplementedError
                    coreid = Noneb
                threadid = entry["Thread"] if isinstance(
                    entry.get("Thread"), int) else None
                bank = re.findall(r"Bank(\d+)\([^)]*\)", entry["Module"])
                assert len(bank) == 1
                bank = bank[0]
                reg_dump = entry["REGISTER DUMP"]
                status = reg_dump["IA32_MCi_STATUS"]
                address = reg_dump["IA32_MCi_ADDR"]
                misc = reg_dump["IA32_MCi_MISC"]
                return MachineCheck(
                    status=int(status, 16),
                    socket=socketid,
                    core=coreid,
                    thread=threadid,
                    bank=int(bank),
                    address=int(address, 16),
                    misc=int(misc, 16),
                    time=datetime.utcfromtimestamp(0),
                    sub_source=_MCESource.error_analy_report.name,
                )

            mcas = map(__extract_mcas, log["ErrorEntry"])
            mcas = filter(None, mcas)
            mcas = list(mcas)
            for mca in mcas:
                mca.time = log["Time"]
            return mcas
        logs = _try_json_loads(content)["HardwareErrorLog"]
        mcas = map(_extract_mca, logs)
        mcas = functools.reduce(lambda a, b: a + b, mcas, [])
        return list(mcas)

    def check_impl(self, text: str):
        logs = _try_json_loads(text)
        return (logs is not None) and isinstance(logs, dict) and ("HardwareErrorLog" in logs)


class ACDExtractor(IMachineCheckParser):
    def parse_impl(self, input: pathlib.Path):
        from logtool.model.logs.summary import AcdSummarizer, Summary
        summ: Summary = AcdSummarizer().parse(input)
        if not summ:
            return None
        mcas = summ.machine_checks if summ.machine_checks else []
        return list(map(lambda mca: MachineCheck.model_validate(mca.model_dump()), mcas))

    def check_impl(self, input: pathlib.Path):
        from logtool.model.logs.summary import AcdSummarizer
        return AcdSummarizer().check(input)


class RegRawDataExtractor(IMachineCheckParser):
    pass


mce_extractors: dict[_MCESource, IMachineCheckParser] = {
    # message: CPU  CE Detected, MC Bank3 Apic:0x98 BankType:0x8 Sts:0x8C40044000100179 Misc:0x0000000000A04285
    _MCESource.extsel: MCETextExtractor(
        source=_MCESource.extsel,
        pattern="message:.*?MC.*",
        subpatterns={
            _MCAField.bank:      _FieldDesc("dec", r"\bBank(\d+)\b"),
            _MCAField.apic:    _FieldDesc("hex", r"\bApic:(?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.status:    _FieldDesc("hex", r"\bSts:(?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.misc:      _FieldDesc("hex", r"\bMisc:(?:0x)?([0-9a-fA-F]+)\b"),
        }
    ),
    # TAG::MCE LOG
    # TODO: Simpler regex or use function to extract pieces of log
    _MCESource.mcelog: MCETextExtractor(
        source=_MCESource.mcelog,
        pattern=r"Hardware event.*(?>((?!(Hardware event.*|TAG::.*|CPUID Vendor Intel.*|warning: 8 bytes ignored in each record))(.*\n)){1,200})",
        filter=lambda line: "mcelog" not in line,
        subpatterns={
            _MCAField.core:    _FieldDesc("dec", r"\bCPU (\d+)\b BANK"),
            _MCAField.bank:      _FieldDesc("dec", r"\bBANK (\d+)\b"),
            _MCAField.tsc:       _FieldDesc("hex", r"\bTSC (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.misc:      _FieldDesc("hex", r"\bMISC (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.address:   _FieldDesc("hex", r"\bADDR (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.time:      _FieldDesc("dec", r"\bTIME ([0-9]+)\b"),
            _MCAField.status:    _FieldDesc("hex", r"\bSTATUS (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.apic:    _FieldDesc("dec", r"\bAPICID (\d+)\b"),
            _MCAField.socket:  _FieldDesc("dec", r"\bSOCKETID (\d+)\b"),
            _MCAField.ppin:      _FieldDesc("hex", r"\bPPIN (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.ucode:     _FieldDesc("hex", r"\bMICROCODE (?:0x)?([0-9a-fA-F]+)\b"),
        }
    ),
    # SPR100K
    _MCESource.dmesg_mcelog: MCETextExtractor(
        source=_MCESource.dmesg_mcelog,
        filter=lambda line: "mcelog" in line and not any(
            kw in line for kw in ["Fallback", "Location:", "corrected DIMM memory"]),
        pattern=r"mcelog.*Hardware event.*(?>((?!(.*Hardware event.*|.*CPUID Vendor Intel.*))(.*\n)){1,200})",
        subpatterns={
            _MCAField.core:    _FieldDesc("dec", r"\bCPU (\d+)\b BANK"),
            _MCAField.bank:      _FieldDesc("dec", r"\bBANK (\d+)\b"),
            _MCAField.tsc:       _FieldDesc("hex", r"\bTSC (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.misc:      _FieldDesc("hex", r"\bMISC (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.address:   _FieldDesc("hex", r"\bADDR (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.time:      _FieldDesc("dec", r"\bTIME ([0-9]+)\b"),
            _MCAField.status:    _FieldDesc("hex", r"\bSTATUS (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.apic:    _FieldDesc("dec", r"\bAPICID (\d+)\b"),
            _MCAField.socket:  _FieldDesc("dec", r"\bSOCKETID (\d+)\b"),
            _MCAField.ppin:      _FieldDesc("hex", r"\bPPIN (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.ucode:     _FieldDesc("hex", r"\bMICROCODE (?:0x)?([0-9a-fA-F]+)\b"),
        }
    ),
    _MCESource.edac: MCETextExtractor(
        source=_MCESource.edac,
        pattern=r"EDAC.*HANDLING MCE MEMORY ERROR((?!PROCESSOR)[\s\S])*PROCESSOR.*(\n.*?retry_rd_err_log.*)?",
        filter=lambda line: "EDAC" in line,
        subpatterns={
            _MCAField.core:    _FieldDesc("dec", r"\bCPU (\d+)\b"),
            _MCAField.bank:      _FieldDesc("dec", r"\bBank (\d+)\b"),
            _MCAField.status:    _FieldDesc("hex", r"\bBank \d+: (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.tsc:       _FieldDesc("hex", r"\bTSC (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.address:   _FieldDesc("hex", r"\bADDR (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.misc:      _FieldDesc("hex", r"\bMISC (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.time:      _FieldDesc("dec", r"\bTIME ([0-9]+)\b"),
            _MCAField.socket:  _FieldDesc("dec", r"\bSOCKET (\d+)\b"),
            _MCAField.retry_rd_err_log: _FieldDesc("str", r"\bretry_rd_err_log\[([0-9a-f ]*)\]"),
            _MCAField.correrrcnt: _FieldDesc("str", r"\bcorrerrcnt\[([0-9a-f ]*)\]"),
            # MCAField.apic:    FieldDesc("hex", r"\bAPIC (0x[0-9a-fA-F]+)\b"),
        }
    ),
    # Socket: 0, Machine Check Bank 3: Status: 0xBE000000E1C40400, Address: 0x00000000FFC684A2, Misc: 0x00000000FFC684A2
    _MCESource.serial: MCETextExtractor(
        source=_MCESource.serial,
        # TODO: refine all regex for content check. Lookahead and only accept limited lines
        pattern=r">>>>>>>> BIOS Log.*(?>((?!(Socket.*|>>>>>>>> BIOS Log.*))(.*\n)){1,200})Socket: .*Machine Check.*",
        subpatterns={
            _MCAField.time: _FieldDesc("time", r"\bBIOS Log @ (\d{4}\.\d+\.\d+ \d+:\d+:\d+)"),
            _MCAField.socket:  _FieldDesc("dec", r"\bSocket: (\d+)\b"),
            _MCAField.bank:      _FieldDesc("dec", r"\bBank (\d+):"),
            _MCAField.status:    _FieldDesc("hex", r"\bStatus: (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.address:   _FieldDesc("hex", r"\bAddress: (?:0x)?([0-9a-fA-F]+)\b"),
            _MCAField.misc:      _FieldDesc("hex", r"\bMisc: (?:0x)?([0-9a-fA-F]+)\b"),
        }
    ),
    _MCESource.venus: MCETextExtractor(
        source=_MCESource.venus,
        pattern=r"-{20,}\nStart = DIAG\n((?!-{20,})[\s\S])*?MCA Info()((?!-{20,})[\s\S])*",
        subpatterns={
            _MCAField.time: _FieldDesc("str", r"timestamp = (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
            _MCAField.socket: _FieldDesc("hex", r"SocketID = (?:0x)?([0-9a-fA-F]+) \(\d+\)"),
            _MCAField.core:   _FieldDesc("hex", r"CoreID = (?:0x)?([0-9a-fA-F]+) \(\d+\)"),
            _MCAField.bank:     _FieldDesc("hex", r"BankNum = (?:0x)?([0-9a-fA-F]+) \(\d+\)"),
            _MCAField.status:   _FieldDesc("hex", r"McaStatus = (?:0x)?([0-9a-fA-F]+) \(\d+\)"),
            _MCAField.address:  _FieldDesc("hex", r"McaAddr = (?:0x)?([0-9a-fA-F]+) \(\d+\)"),
            _MCAField.misc:     _FieldDesc("hex", r"McaMisc = (?:0x)?([0-9a-fA-F]+) \(\d+\)"),
        }
    ),
    _MCESource.error_analy_report: ErrorAnalyMCEExtractor(),
    _MCESource.acd: ACDExtractor(),
}

syslog_extractors: list[MCETextExtractor] = [
    mce_extractors[_MCESource.dmesg_mcelog],
    mce_extractors[_MCESource.edac],
    mce_extractors[_MCESource.mcelog],
]

_onekeylog_extractors: list[IMachineCheckParser] = [
    mce_extractors[_MCESource.acd],
    mce_extractors[_MCESource.venus],
    mce_extractors[_MCESource.error_analy_report],
]


class OnekeylogMCEExtractor(IMachineCheckParser):
    def parse_impl(self, path: pathlib.Path):
        from logtool.utils.file import ArchiveFile
        with ArchiveFile(path) as a:
            members = a.getmembers()
            mcas: list[MachineCheck] = []
            for m in members:
                if m.isdir():
                    continue
                if "runningdata" in m.name:
                    continue
                f = a.extract(m)
                assert f is not None
                content = f.read()
                for parser in _onekeylog_extractors:
                    if not parser.check(content):
                        continue
                    res: list[MachineCheck] | None = parser.parse(content)
                    if res:
                        mcas.extend(res)
            return mcas

    def check_impl(self, path: pathlib.Path):
        from logtool.utils.file import ArchiveFile
        try:
            a = ArchiveFile(path)
            return True
        except Exception:
            return False


mce_extractors[_MCESource.onekeylog] = OnekeylogMCEExtractor()


def extract_mcas(path: pathlib.Path):
    mcas: list[MachineCheck] = []
    for e in mce_extractors.values():
        # TODO: better type hint
        if not e.check(path):
            continue
        res: list[MachineCheck] = e.parse(path)
        mcas.extend(res)
    return mcas
