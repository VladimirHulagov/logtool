import pydantic

from logtool.model.info import MachineCheck


class MachineCheckView(MachineCheck):
    @pydantic.computed_field
    @property
    def valid(self) -> bool:
        return bool(self.status & (1 << 63))

    @pydantic.computed_field
    @property
    def overflow(self) -> bool:
        return bool(self.status & (1 << 62))

    @pydantic.computed_field
    @property
    def uncorrected(self) -> bool:
        return bool(self.status & (1 << 61))

    @pydantic.computed_field
    @property
    def enabled(self) -> bool:
        # What does this bit mean?
        return bool(self.status & (1 << 60))

    @pydantic.computed_field
    @property
    def misc_valid(self) -> bool:
        return bool(self.status & (1 << 59))

    @pydantic.computed_field
    @property
    def address_valid(self) -> bool:
        return bool(self.status & (1 << 58))

    @pydantic.computed_field
    @property
    def pcc(self) -> bool:
        return bool(self.status & (1 << 57))

    @pydantic.computed_field
    @property
    def corrected_yellow(self) -> bool:
        # assert (self.status >> 53) & 0x3 != 0x3
        return not self.uncorrected and bool(self.status & (1 << 54))

    @pydantic.computed_field
    @property
    def corrected_green(self) -> bool:
        return not self.uncorrected and bool(self.status & (1 << 53))

    @pydantic.computed_field
    @property
    def corrected_count(self) -> int:
        # assert not self.uncorrected
        return (self.status >> 38) & 0x7FFF

    @pydantic.computed_field
    @property
    def offset(self) -> int | None:
        return None if self.address is None else self.address & 0x3F

    @pydantic.computed_field
    @property
    def set(self) -> int | None:
        if self.address is None:
            return None
        if self.bank == 3:
            return (self.address & 0xFFFF) >> 6
        if self.bank not in [0, 1, 2, 3]:
            return None
        # 1024 set, 16 way for 1MB at CLX, 32 way for 2MB at SPR
        # 64 set, 8 way for 32KB and 12 way for 48KB
        return (self.address & 0xFFF) >> 6

    @pydantic.computed_field
    @property
    def mlc_column(self) -> int | None:
        if self.address is None:
            return None
        if self.bank == 3:
            return (self.set >> 1) & 0xFF
        return None

    @pydantic.computed_field
    @property
    def page(self) -> int | None:
        return None if self.address is None else self.address >> 12

    @pydantic.computed_field
    @property
    def mca_decode(self) -> str | None:
        match self.status & 0xFFFF_FFFF:
            case 0x0000_0005:
                return "IFU.PRF_PARITY_ERROR"
            case 0x0001_0005:
                return "IFU.DSB_DATA_ERROR"
            case 0x0002_0005:
                return "IFU.MSRAM_ERROR"
            case 0x0003_0005:
                return "IFU.IQ_ERROR"
            case 0x000E_0005:
                return "IFU.RS_IDQ_IMM_PARITY_ERROR"
            case 0x000F_040A:
                return "IFU.EXE_RC_ERROR"
            case 0x0000_0114:
                return "DCU.LOAD_READ_ERROR"
            case 0x0000_0184:
                return "DCU.SNOOP_ERROR"
            case 0x0010_0134:
                return "DCU.DCU_DATA_LOAD_POISON"
            case 0x0011_0134:
                return "DCU.STUFFED_LOAD_POISON"
            case 0X0000_0174:
                return "DCU.L1_EVICT_PARITY_ERROR"
            case 0x0020_0401:
                return "DCU.WB_ACCESS_TO_APIC_SPACE"
            case 0x0010_0151 | 0x0010_1151:
                return "MLC.ISTR_FETCH_CE"
            case 0X0010_0179 | 0X0010_1179:
                # raise NotImplementedError
                return "MLC.L2_EVICT_ERROR"
            case 0x0030_0189:
                return "MLC.SNOOP_ERROR"
            case 0x0080_0400:
                return "MLC.THREE_STRIKE_TIMEOUT"
            case 0x0040_0405:
                return "MLC.SQDB_IDI_PARITY_ERROR"
            case 0x000A_0405:
                return "MLC.SQDB_IDI_PARITY_UCE"
            case 0x0010_0080 | 0x0010_0081 | 0x0010_0082:
                # raise NotImplementedError
                return "IMC.PATROL_SCRUBBING_UE"
            case 0x0001_0090 | 0x0001_0091 | 0x0001_0092:
                # raise NotImplementedError
                return "HA.MEMORY_READ_ERROR"
            case 0x0080_0090 | 0x0080_0091 | 0x0080_0092:
                return "IMC.MEMORY_READ_CE"
            case 0x00A0_0090 | 0x00A0_0091 | 0x00A0_0092:
                return "IMC.MEMORY_READ_UE"
            case 0x0101_0090 | 0x0101_0091 | 0x0101_0092:
                return "IMC.MEMORY_READ_ERROR"
            case 0x0008_00C0 | 0x0008_00C1 | 0x0008_00C2:
                return "IMC.PATROL_SCRUBBING_CE"
            case 0x0010_00C0 | 0x0010_00C1 | 0x0010_00C2:
                return "IMC.PATROL_SCRUBBING_UE"
            case 0x0080_00C0 | 0x0080_00C1 | 0x0080_00C2:
                return "IMC.ON_DEMAND_MEMORY_SCRUBBING_CE"
            case 0x00A0_00C0 | 0x00A0_00C1 | 0x00A0_00C2:
                return "IMC.ON_DEMAND_MEMORY_SCRUBBING_UE"
            case 0x0200_00B0 | 0x0200_00B1 | 0x0200_00B2:
                return "IMC.ADDRESS_COMMAND_ERROR"
            case 0X0000_009F:
                return "UNK.APEI_GENERATED_RECORD"
            case 0x000B_110A:
                return "CHA.CORE_WB_MISS_LLC"
            case 0x000C_110A | 0x000C_1136:
                return "CHA.TOR_TIMEOUT"
            case 0x0033_110A:
                return "CHA.AK_BL_UQID_PARITY_ERROR"
            case 0x0000_0E0B:
                return "IIO.GENERIC_IO_ERROR"
            case 0x0030_0E0F:
                return "KTI.LLR_WO_PHY_REINIT"
            case _:
                return None

    @pydantic.computed_field
    @property
    def mca_decode2(self) -> str | None:
        mscod = (self.status & 0xFFFE0000) >> 16
        mcacod = (self.status & 0xFFFF) & 0xEFFF
        # TODO: use reliable source for this table
        table = {
            0x0005: (
                "PIPELINE_ERROR",
                {
                    0x00: "PRF_PARITY",
                    0x01: "DSB_FE",
                    0X02: "MSRAM",
                    0X03: "IQ",
                    0X04: "DSB_FE_OFFSET_NATA",
                    0X05: "DSB_FE_TAG",
                    0x06: "TMUL_PARITY_ERROR",
                    0X07: "IDQ_UOP",
                    0x08: "BIQ",
                    0x09: "MSPATCH_CAM_PARITY_ERROR",
                    0x0A: "MSPATCH_DATA_PARITY_ERROR",
                    0x0B: "MSROM_PTR",
                    0x0C: "RAT_PARITY_ERROR_FREELIST",
                    0x0D: "SDB_PARITY",
                    0x0E: "RS_IDQ_IMM_PARITY",
                    0x0F: "DSB_HIT_WITH_IC_MISS",
                    0x0F: "EXE_IC_ERROR",
                    0x16: "MS_UNIQ_ROM",
                }
            ),
            0x0115: ("D_CACHE_L2_RD_ERR", {}),
            0x0135: ("D_CACHE_L2_DRD_ERR", {}),
            0x0145: ("D_CACHE_L2_DWR_ERR", {}),
            0x0165: ("D_CACHE_L2_PREFETCH_ERR", {}),
            0x0185: ("D_CACHE_L2_SNOOP_ERR", {}),
            0x0151: ("I_CACHE_L2_IRD_ERR", {}),
            0x0129: ("G_CACHE_L2_WR_ERR", {}),
            0x0179: ("G_CACHE_L2_EVICT_ERR", {}),
            0x0189: ("G_CACHE_L2_SNOOP_ERR", {}),
        }
        d = table.get(mcacod, ("?", {}))
        return ".".join([d[0], d[1].get(mscod, "?")])
