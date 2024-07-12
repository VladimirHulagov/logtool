import abc
import typing
import datetime
import importlib

import pydantic


class DimmFailureLocation(pydantic.BaseModel):
    type: typing.Literal["DIMM"] = "DIMM"
    socket: int
    imc: int
    channel: int
    slot: int


class CpuFailureLocation(pydantic.BaseModel):
    type: typing.Literal["CPU"] = "CPU"
    socket: int
    core: int
    bank: int


class PcieFailureLocation(pydantic.BaseModel):
    type: typing.Literal["PCIe"] = "PCIe"
    socket: int
    root_port: int
    bus: int
    device: int
    function: int


class MachineCheckBase(abc.ABC, pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")

    time: datetime.datetime

    socket: typing.Optional[int] = None
    bank: typing.Optional[typing.Union[int, str]] = None
    core: typing.Optional[int] = None  # -1 for uncore

    status: int
    misc: typing.Optional[int] = None
    address: typing.Optional[int] = None

    def model_post_init(self, _):
        if not self.address_valid:
            self.address = None
        if not self.misc_valid:
            self.misc = None

    @property
    def _hex_fields(self):
        return [
            "status",
            "misc",
            "address",
        ]

    def view_dump(self):
        res = {"type": self.__class__.__name__}
        res.update(self.model_dump())
        for f in self._hex_fields:
            v = res[f]
            res[f] = hex(v) if isinstance(v, int) else v
        for f in ["uc", "pcc"]:
            res[f] = getattr(self, f)
        return res

    @property
    def short_str(self):
        return "Socket {} {} Bank {} Status {}".format(
            self.socket,
            "Uncore" if self.core == -1 else f"Core {self.core}",
            self.bank,
            hex(self.status),
        )

    @property
    def from_apei(self):
        return self.mscod == 0 and self.mcacod == 0x009F

    @property
    def valid(self) -> bool:
        return bool(self.status and (self.status & (1 << 63)))

    @property
    def overflow(self) -> bool:
        return bool(self.status & (1 << 62))

    @property
    def uc(self) -> bool:
        return bool(self.status & (1 << 61))

    @property
    def enabled(self) -> bool:
        # What does this bit mean?
        return bool(self.status & (1 << 60))

    @property
    def misc_valid(self) -> bool:
        return bool(self.status and (self.status & (1 << 59)))

    @property
    def address_valid(self) -> bool:
        return bool(self.status and (self.status & (1 << 58)))

    @property
    def pcc(self) -> bool:
        return bool(self.status & (1 << 57))

    @property
    def corrected_yellow(self) -> bool:
        assert (self.status >> 53) & 0x3 != 0x3
        return not self.uc and bool(self.status & (1 << 54))

    @property
    def corrected_green(self) -> bool:
        return not self.uc and bool(self.status & (1 << 53))

    @property
    def corrected_count(self) -> int:
        assert not self.uc
        return (self.status >> 38) & 0x7FFF

    @property
    def mscod(self) -> int:
        return (self.status >> 16) & 0xFFFF

    @property
    def mcacod(self) -> int:
        return self.status & 0xFFFF

    @property
    def cpu_location(self) -> typing.Optional[CpuFailureLocation]:
        if not all(isinstance(f, int) for f in [self.socket, self.core, self.bank]):
            return None
        return CpuFailureLocation(
            socket=self.socket,
            core=self.core,
            bank=self.bank,
        )

    @property
    def dimm_location(self) -> typing.Optional[DimmFailureLocation]:
        return None


_decoders = {}


def _get_decoder(cpu_type: str):
    if cpu_type not in _decoders:
        mcd = importlib.import_module(
            f"pysvtools.crashdump_summarizer.{cpu_type}.mcd")
        assert "McaBankValues" in dir(mcd)
        assert "decode_mca_bank" in dir(mcd)
        _decoders[cpu_type] = mcd
    return _decoders[cpu_type]


class MceDecodeResult(pydantic.BaseModel):
    bank_name: typing.Literal[
        "IFU", "DCU", "DTLB", "MLC", "PCU", "UPI", "IIO",
        "HA", "IMC", "CHA", "M2M", "UBOX",
        "MSE", "MCCHAN", "B2CMI", "LLC",
    ]
    bank_fullname: str
    mscod_decode: str
    mcacod_decode: str
    # decodes: list


def decode_mce(
    cpu_type: typing.Literal["BDX", "SKX", "CPX", "ICX", "SPR", "GNR", "SRF", "CLX", "EMR"],
    mce: MachineCheckBase
):
    if cpu_type == "CLX":
        cpu_type = "SKX"
    if cpu_type == "EMR":
        cpu_type = "SPR"
    if cpu_type not in ["BDX", "SKX", "CPX", "ICX", "SPR", "GNR", "SRF"]:
        raise ValueError(f"{cpu_type} is not a valid cpu_type")
    # Any McaBankValues definition will work
    from pysvtools.crashdump_summarizer.SKX.mcd import McaBankValues
    mcd = _get_decoder(cpu_type)
    mc = McaBankValues()
    # TODO: type checking
    mc.status = mce.status
    mc.addr = mce.address
    mc.misc = mce.misc
    mc.bank_number = mce.bank
    try:
        bank = mcd.decode_mca_bank(error=mc, retobj=True)
        sts_decodes = bank.status.get_table_as_list()
        mscod_decode = ""
        mcacod_decode = ""
        for row in sts_decodes:
            if row[1] == "MSCOD":
                mscod_decode = row[-1]
            if row[1] == "MCACOD":
                mcacod_decode = row[-1]
        return MceDecodeResult(
            bank_name=type(bank).__name__.upper(),
            bank_fullname=bank.name,
            mscod_decode=mscod_decode,
            mcacod_decode=mcacod_decode,
            # decodes=sts_decodes,
        )
    except Exception:
        return None
