import enum
import abc
from datetime import datetime
import typing

import pydantic

from logtool.model.interface import IViewableEvent, EventSeverity


class CPUType(enum.Enum):
    BDX = enum.auto()
    SKX = enum.auto()
    CLX = enum.auto()
    CPX = enum.auto()
    ICX = enum.auto()
    SPR = enum.auto()
    EMR = enum.auto()
    GNR = enum.auto()
    SRF = enum.auto()
    UNK = enum.auto()

    @staticmethod
    def from_cpuid(cpuid: int):
        # https://wiki.ith.intel.com/pages/viewpage.action?pageId=1732516285
        id_list = {
            CPUType.SKX: (0x50650, 0x50651, 0x50652, 0x50653, 0x50654),
            CPUType.CLX: (0x50655, 0x50656, 0x50657),
            CPUType.CPX: (0x5065A, 0x5065B),
            CPUType.ICX: (0x606A0, 0x606A4, 0x606A5, 0x606A6),
            CPUType.SPR: (0x806F0, 0x806F1, 0x806F2, 0x806F3, 0x806F4, 0x806F5, 0x806F6, 0x806F7, 0x806F8),
            CPUType.EMR: (0xC06F0, 0xC06F1),
            CPUType.GNR: (0xA06D0,),
            CPUType.SRF: (0xA06F0, 0xA06F1),
        }
        for k, v in id_list.items():
            if cpuid in v:
                return k
        family = (cpuid >> 8) & 0xF
        model = (cpuid >> 4) & 0xF | (cpuid >> 12) & 0xF0
        # [31:28] Reserved
        # [27:20] Extended Family ID
        # [19:16] Extended Model ID
        # [15:14] Reserved
        # [13:12] Processor Type
        # [11:8]  Family ID
        # [7:4]   Model
        # [3:0]   Stepping ID
        # GNR SP
        # HEX: 0 x A    0    6    D    0
        # BIN: 0 b 1010 0000 0110 1101 0000
        # Stepping = (Stepping ID) = (0b0000) = 0
        # Model    = (Extended Model ID << 4) + (Model) = (0b1010<<4) + 0b1101 = 0b10101101 = 173
        # Family   = (Family ID) = (0b0110) = 6
        # stepping = cpuid & 0xF
        if (family, model) == (6, 79):
            return CPUType.BDX
        else:
            raise NotImplementedError


class BankType(enum.Enum):
    IFU = "Core IFU"
    DCU = "Core DCU"
    DTLB = "Core DTLB"
    MLC = "Core MLC"
    PCU = "PCU"
    KTI = "KTI"
    IIOUbox = "IIO/UBOX"
    M2M = "M2M"  # M2M vs M2MEM?
    MDF = "MDF"  # SPR
    CBO = "Cbo"
    HA = "HA"  # BDX
    IMC = "iMC"
    HBM_M2M = "HBM M2M"
    HBM_PSEDU = "HBM PSEDU"
    UNK = "Unknown"

    @staticmethod
    def get_bank(cpu_type: CPUType, bankid: int):
        assert isinstance(cpu_type, CPUType)
        assert isinstance(bankid, int)
        bank_mappings = {
            CPUType.UNK: {},
            CPUType.SKX: {},
            CPUType.CLX: {},
            CPUType.ICX: {},
            CPUType.SPR: {},
            CPUType.BDX: {},
        }
        for v in bank_mappings.values():
            v.update({
                BankType.IFU: [0],
                BankType.DCU: [1],
                BankType.DTLB: [2],
                BankType.MLC: [3],
                BankType.PCU: [4],
                BankType.IIOUbox: [6],      # SKX, ICX vs SPR? Difference?
                BankType.CBO: [9, 10, 11],  # SKX, ICX vs SPR? Difference?
            })
        bank_mappings[CPUType.BDX].update({
            BankType.KTI: [5, 20, 21],
            BankType.HA: [7, 8],
            BankType.IMC: [9, 10, 11, 12, 13, 14, 15, 16],
            BankType.CBO: [17, 18, 19],
        })
        bank_mappings[CPUType.SKX].update({
            BankType.KTI: [5, 12, 19],
            BankType.M2M: [7, 8],
            BankType.IMC: [13, 14, 15, 16, 17, 18]
        })
        bank_mappings[CPUType.CLX] = bank_mappings[CPUType.SKX].copy()
        bank_mappings[CPUType.CPX] = bank_mappings[CPUType.SKX].copy()
        bank_mappings[CPUType.CPX][BankType.KTI] = [5, 12, 19, 20, 21, 22]
        bank_mappings[CPUType.ICX].update({
            BankType.KTI: [5, 7, 8],
            BankType.M2M: [12, 16, 20, 24],
            BankType.IMC: [13, 14, 17, 18, 21, 22, 25, 26]
        })
        bank_mappings[CPUType.SPR].update({
            BankType.KTI: [5],
            BankType.MDF: [7, 8],
            BankType.M2M: [12],
            BankType.IMC: [13, 14, 15, 16, 17, 18, 19, 20],
            BankType.HBM_M2M: [29],
            BankType.HBM_PSEDU: [30, 31]
        })
        match = map(lambda kv: kv[0] if bankid in kv[1]
                    else None, bank_mappings[cpu_type].items())
        match = filter(None, match)
        match = list(match)
        assert len(match) <= 1
        return match[0] if match else BankType.UNK


class IMachineCheck(IViewableEvent):
    @property
    @abc.abstractmethod
    def mc_status(self) -> int:
        ...

    @property
    def valid(self) -> bool:
        return bool(self.mc_status and (self.mc_status & (1 << 63)))

    @property
    def overflow(self) -> bool:
        return bool(self.mc_status & (1 << 62))

    @property
    def uncorrected(self) -> bool:
        return bool(self.mc_status & (1 << 61))

    @property
    def enabled(self) -> bool:
        # What does this bit mean?
        return bool(self.mc_status & (1 << 60))

    @property
    def misc_valid(self) -> bool:
        return bool(self.mc_status and (self.mc_status & (1 << 59)))

    @property
    def address_valid(self) -> bool:
        return bool(self.mc_status and (self.mc_status & (1 << 58)))

    @property
    def pcc(self) -> bool:
        return bool(self.mc_status & (1 << 57))

    @property
    def corrected_yellow(self) -> bool:
        # assert (self.mc_status >> 53) & 0x3 != 0x3
        return not self.uncorrected and bool(self.mc_status & (1 << 54))

    @property
    def corrected_green(self) -> bool:
        return not self.uncorrected and bool(self.mc_status & (1 << 53))

    @property
    def corrected_count(self) -> int:
        # assert not self.uncorrected
        return (self.mc_status >> 38) & 0x7FFF

    @property
    def _type(self):
        return "MachineCheck"

    @property
    @abc.abstractmethod
    def _subtype(self) -> str:
        ...

    @property
    def _severity(self):
        if self.pcc:
            return EventSeverity.Critical
        if self.uncorrected:
            return EventSeverity.Error
        return EventSeverity.Warning


class ISystemEvent(IViewableEvent):
    @property
    @abc.abstractmethod
    def raw_bytes(self) -> bytes:
        """16-byte SEL record.
        """
        ...

    @property
    @abc.abstractmethod
    def event_message(self) -> str:
        """[14:]
        Human readable format for the event. Not guaranteed to be the same for every implementation for now
        """
        ...

    @property
    def record_id(self) -> int:
        return int.from_bytes(self.raw_bytes[0:2], "little")

    @property
    def record_type(self) -> int:
        return self.raw_bytes[2]

    @property
    def timestamp(self) -> datetime:
        return datetime.fromtimestamp(int.from_bytes(self.raw_bytes[3:7], "little"))

    @property
    def generator_id(self) -> int:
        return int.from_bytes(self.raw_bytes[7:9], "little")

    @property
    def evm_rev(self) -> int:
        return self.raw_bytes[9]

    @property
    def sensor_type(self) -> int:
        return self.raw_bytes[10]

    @property
    def sensor_number(self) -> int:
        return self.raw_bytes[11]

    @property
    def event_dir(self):
        return "Desserted" if (self.raw_bytes[12] & 0x80) else "Asserted"

    @property
    def event_type(self) -> int:
        return self.raw_bytes[12] & 0x7F

    @property
    def event_data(self) -> bytes:
        return self.raw_bytes[13:]

    @property
    def sensor_offset(self) -> int:
        return self.raw_bytes[13] & 0xF

    @property
    def unique_key(self) -> str:
        res = self.raw_bytes.hex()
        return res[4:6] + "_" + res[14:]

    # TODO: vendor specific
    # @property
    # def socket(self):
    #     assert self.event == SystemEventType.Processor.ConfigurationError
    #     return (self.event_data[1] & 0xF0) // 16

    # @property
    # def bank(self):
    #     assert self.event == SystemEventType.Processor.ConfigurationError
    #     match (self.event_data[1] & 0xF):
    #         case 0:
    #             return BankType.UNK
    #         case 1:
    #             return BankType.IFU
    #         case 2:
    #             return BankType.DCU
    #         case 3:
    #             return BankType.DTLB
    #         case 4:
    #             return BankType.MLC
    #         case 5:
    #             return BankType.PCU
    #         case 6:
    #             return BankType.IIOUbox
    #         case 7:
    #             return BankType.CBO
    #         case 8:
    #             return BankType.KTI
    #         case _:
    #             assert False

    @property
    @typing.final
    def event(self):
        e = SystemEventType.lookup(self)
        return e

    @property
    @typing.final
    def _time(self):
        return self.timestamp

    @property
    def _subtype(self):
        # TODO: Follow IPMI2.0 spec
        return None

    @property
    @typing.final
    def _severity(self):
        if self.event is None:
            return EventSeverity.Info
        if self.event is SystemEventType.Processor.IERR:
            return EventSeverity.Critical
        if self.event in SystemEventType.Processor:
            return EventSeverity.Warning
        if self.event in SystemEventType.PowerSupply:
            if self.event == SystemEventType.PowerSupply.PresenceDetected:
                return EventSeverity.Info
            return EventSeverity.Warning
        if self.event in SystemEventType.Memory:
            return EventSeverity.Warning
        if self.event in SystemEventType.CriticalInterrupt:
            return EventSeverity.Warning
        return EventSeverity.Info

    @property
    def description(self):
        return self.event_message
        raw = self.raw_bytes.hex(" ")
        return f"{self.event}\t{self.event_message}\t({raw})"


@pydantic.dataclasses.dataclass
class _SensorInfo():
    sensor_type: int
    offset: int | None

    def match(self, event: ISystemEvent):
        res = (
            (self.sensor_type == event.sensor_type) and
            (self.offset is None or self.offset == event.sensor_offset)
        )
        return res


class SystemEventType():
    # TODO Automated generation with script and IPMI2.0 spec
    class Processor(enum.Enum):
        IERR = _SensorInfo(0x07, 0x0)
        ThermalTrip = _SensorInfo(0x07, 0x1)
        BistFailure = _SensorInfo(0x07, 0x2)
        PostFailure = _SensorInfo(0x07, 0x3)
        InitializationFailure = _SensorInfo(0x07, 0x4)
        ConfigurationError = _SensorInfo(0x07, 0x5)
        SmbiosCpuUncorrectableError = _SensorInfo(0x07, 0x6)
        PresenceDetected = _SensorInfo(0x07, 0x7)
        Disabled = _SensorInfo(0x07, 0x8)
        TerminatorDetected = _SensorInfo(0x07, 0x9)
        AutomaticallyThrottled = _SensorInfo(0x07, 0xA)
        UncorrectableMachineCheck = _SensorInfo(0x07, 0xB)
        CorrectableMachineCheck = _SensorInfo(0x07, 0xC)
        # CaterrUnknown = _SensorInfo(0x07, 0x80, 0x03, 0x0)
        # Caterr = _SensorInfo(0x07, 0x80, 0x03, 0x1)
        # CaterrCore = _SensorInfo(0x07, 0x80, 0x03, 0x2)
        # MsidMismatch = _SensorInfo(0x07, 0x80, 0x03, 0x3)
        # CpuMissing = _SensorInfo(0x07, 0x82, 0x03, 0x1)
        # Err2Timeout = _SensorInfo(0x07, 0x7C, 0x03, 0x1)

    class PowerSupply(enum.Enum):
        PresenceDetected = _SensorInfo(0x08, 0x0)
        Failure = _SensorInfo(0x08, 0x1)   # 0xEF event type?
        PredictiveFailure = _SensorInfo(0x08, 0x2)
        AcLost = _SensorInfo(0x08, 0x3)
        ConfigurationError = _SensorInfo(0x08, 0x6)
        Inactive = _SensorInfo(0x08, 0x7)

    class EventLoggingDisabled(enum.Enum):
        MemoryCeLoggingDisabled = _SensorInfo(0x10, 0x0)
        EventLoggingDisabled = _SensorInfo(0x10, 0x1)
        LogAreaReset = _SensorInfo(0x10, 0x2)
        AllEventLoggingDisabled = _SensorInfo(0x10, 0x3)
        SelFull = _SensorInfo(0x10, 0x4)
        SelAlmostFull = _SensorInfo(0x10, 0x5)
        CmceLoggingDisabled = _SensorInfo(0x10, 0x6)

    class Memory(enum.Enum):
        CorrectableECC = _SensorInfo(0x0C, 0x0)
        UncorrectableECC = _SensorInfo(0x0C, 0x1)
        Parity = _SensorInfo(0x0C, 0x2)
        ScrubFailed = _SensorInfo(0x0C, 0x3)
        DeviceDisabled = _SensorInfo(0x0C, 0x4)
        LoggingLimitReached = _SensorInfo(0x0C, 0x5)
        PresenceDetected = _SensorInfo(0x0C, 0x6)
        ConfigurationError = _SensorInfo(0x0C, 0x7)
        Spare = _SensorInfo(0x0C, 0x8)
        AutomaticallyThrottled = _SensorInfo(0x0C, 0x9)
        CriticalOvertemperature = _SensorInfo(0x0C, 0xA)

    # class DriveSlot(enum.Enum):
    #     DrivePresence = _SensorInfo(0x0D, 0x0)
    #     DriveFault = _SensorInfo(0x0D, 0x2)
    #     PredictiveFailure = _SensorInfo(0x0D, 0x2)
    #     HotSpare = _SensorInfo(0x0D, 0x3)

    class CriticalInterrupt(enum.Enum):
        FrontPanelNMI = _SensorInfo(0x13, 0x0)
        BusTimeout = _SensorInfo(0x13, 0x1)
        IOChannelCheckNMI = _SensorInfo(0x13, 0x2)
        SoftwareNMI = _SensorInfo(0x13, 0x3)
        PciPerr = _SensorInfo(0x13, 0x4)
        PciSerr = _SensorInfo(0x13, 0x5)
        EisaFailSafeTimeout = _SensorInfo(0x13, 0x6)
        BusCorrectableError = _SensorInfo(0x13, 0x7)
        BusUncorrectableError = _SensorInfo(0x13, 0x8)
        FatalNMI = _SensorInfo(0x13, 0x9)
        BusFatalError = _SensorInfo(0x13, 0xA)
        BusDegraded = _SensorInfo(0x13, 0xB)
        # UpiDegrade1_2 = _SensorInfo(0x0001, 0x13, 0x09, 0x77, 0x1)
        # # TODO: merge with CriticalInterrupt
        # UpiDegrade1_4 = _SensorInfo(0x0001, 0x13, 0x09, 0x77, 0x2)
        # UpiCorrectableError = _SensorInfo(0x0033, 0x13, 0x06, 0x72, None)

    class SystemBoot(enum.Enum):
        InitByPowerUp = _SensorInfo(0x1D, 0x0)
        InitByHardReset = _SensorInfo(0x1D, 0x1)
        InitByWarmReset = _SensorInfo(0x1D, 0x2)
        UserRequestPxeBoot = _SensorInfo(0x1D, 0x3)
        AutoBootToDiagnostic = _SensorInfo(0x1D, 0x4)
        OsSwInitHardReset = _SensorInfo(0x1D, 0x5)
        OsSwInitWarmReset = _SensorInfo(0x1D, 0x6)
        SystemRestart = _SensorInfo(0x1D, 0x7)

    class ACPI(enum.Enum):
        S0_G0_Working = _SensorInfo(0x22, 0x0)
        S1_Sleeping = _SensorInfo(0x22, 0x1)
        S2_Sleeping = _SensorInfo(0x22, 0x2)
        S3_Sleeping = _SensorInfo(0x22, 0x3)
        S4_Sleeping = _SensorInfo(0x22, 0x4)
        S5_G2_SoftOff = _SensorInfo(0x22, 0x5)
        S4_S5_SoftOff = _SensorInfo(0x22, 0x6)
        G3_MechanicalOff = _SensorInfo(0x22, 0x7)
        S1_S2_S3_Sleeping = _SensorInfo(0x22, 0x8)
        G1_Sleeping = _SensorInfo(0x22, 0x9)

    class Watchdog2(enum.Enum):
        TimerExpired = _SensorInfo(0x23, 0x0)
        HardReset = _SensorInfo(0x23, 0x1)
        PowerDown = _SensorInfo(0x23, 0x2)
        PowerCycle = _SensorInfo(0x23, 0x3)
        TimerInterrupt = _SensorInfo(0x23, 0x8)

    @staticmethod
    def lookup(event: ISystemEvent):
        for g in SystemEventType.__dict__.values():
            if type(g) is not enum.EnumMeta:
                continue
            for e in g:
                e: enum.Enum
                s: _SensorInfo = e.value
                if s.match(event):
                    return e
        return None


# class Sysinfo(pydantic.BaseModel):
#     cpu_type:   CPUType | None = None
#     cpuid:      int | None = None
#     ppin_set:   set[int] | None = None
#     ppin_list:  list[int] | None = None

#     def model_post_init(self, __context) -> None:
#         super().model_post_init(__context)
#         if self.cpuid:
#             cpu_type = CPUType.from_cpuid(self.cpuid)
#             assert self.cpu_type is None or self.cpu_type == cpu_type
#             self.cpu_type = cpu_type
#         if self.ppin_list:
#             self.ppin_set = set(self.ppin_list)
