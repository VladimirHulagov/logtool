import re
import enum
import itertools

import pydantic

from .mce import MachineCheckBase


class CPUType(enum.StrEnum):
    BDX = "BDX"
    SKX = "SKX"
    CLX = "CLX"
    CPX = "CPX"
    ICX = "ICX"
    SPR = "SPR"
    EMR = "EMR"
    GNR = "GNR"
    SRF = "SRF"
    UNK = "UNK"

    @staticmethod
    def from_cpuid(cpuid: int):
        # https://wiki.ith.intel.com/pages/viewpage.action?pageId=1732516285
        # BigCore Server Cpuid various IDs.xlsx
        id_list = {
            CPUType.BDX: (0x406F1, 0x50663, 0x50664, 0x50665),
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
        return CPUType.BDX

    @staticmethod
    def from_cpuid_str(cpuid: str):
        # CPX contains extra KTI banks than CLX and SKX so we treat everything as CPX for now
        # TODO: This introduces wrong CPU categories. How to handle that?
        pattern = re.compile(r"Family (?P<family>\d+) Model (?P<model>\d+)")
        m = pattern.search(cpuid)
        assert m
        gp = m.groupdict()
        family, model = gp["family"], gp["model"]
        match (family, model):
            case (6, 79):
                return CPUType.BDX
            case (6, 85):
                return CPUType.CPX
            case (6, 106) | (6, 108):
                return CPUType.ICX
            case (6, 143):
                return CPUType.SPR
            case _:
                return CPUType.UNK


class BankType(enum.Enum):
    IFU = "IFU"
    DCU = "DCU"
    DTLB = "DTLB"
    MLC = "MLC"
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
            t: {
                BankType.IFU: [0],
                BankType.DCU: [1],
                BankType.DTLB: [2],
                BankType.MLC: [3],
            } for t in CPUType
        }
        for t in [
            CPUType.BDX,
            CPUType.SKX,
            CPUType.CLX,
            CPUType.ICX,
            CPUType.SPR,
        ]:
            bank_mappings[t].update({
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
            BankType.IMC: [13, 14, 15, 16, 17, 18],
        })
        bank_mappings[CPUType.CLX] = bank_mappings[CPUType.SKX].copy()
        bank_mappings[CPUType.CPX] = bank_mappings[CPUType.SKX].copy()
        bank_mappings[CPUType.CPX].update({
            BankType.KTI: [5, 12, 19, 20, 21, 22],
        })
        bank_mappings[CPUType.ICX].update({
            BankType.KTI: [5, 7, 8],
            BankType.M2M: [12, 16, 20, 24],
            BankType.IMC: [13, 14, 17, 18, 21, 22, 25, 26],
        })
        bank_mappings[CPUType.SPR].update({
            BankType.KTI: [5],
            BankType.MDF: [7, 8],
            BankType.M2M: [12],
            BankType.IMC: [13, 14, 15, 16, 17, 18, 19, 20],
            BankType.HBM_M2M: [29],
            BankType.HBM_PSEDU: [30, 31],
        })
        _ = map(
            lambda kv: kv[0] if bankid in kv[1] else None,
            bank_mappings.get(cpu_type, {}).items()
        )
        _ = filter(None, _)
        match = list(_)
        assert len(match) <= 1
        return match[0] if match else BankType.UNK


class SystemInfo(pydantic.BaseModel):
    mces: list[MachineCheckBase]

    @property
    def machine_check_view(self):
        _ = self.mces
        _ = map(lambda m: m.view_dump(), _)
        return list(_)

    @property
    def uc(self):
        return any(m.uc for m in self.mces)

    @property
    def triage(self):
        from .rules import rules, TriageResult, TriageRule
        _ = map(lambda r: (r, r(self)), rules)
        _ = filter(lambda p: p[1] is not None, _)
        results = dict(_)
        res = list(results.values())
        _ = map(lambda r: r.overwrites, results)
        _ = itertools.chain.from_iterable(_)
        # overwrites = list(_)
        # res = [v for k, v in results.items() if not any(isinstance(k, r) for r in overwrites)]
        assert all(v is not None for v in res)
        return list(filter(None, res))

    def filter_machine_checks(
        self, *,
        uc: bool,
        bank_type: BankType,
        mscod: list[int] | int | None = None,
        mcacod: list[int] | int | None = None,
    ):
        _ = self.mces
        _ = filter(lambda m: m.uc == uc, _)
        _ = filter(lambda m: m.bank_type is bank_type, _)
        if isinstance(mscod, int):
            _ = filter(lambda m: m.mscod == mscod, _)
        elif isinstance(mscod, list):
            _ = filter(lambda m: m.mscod in mscod, _)
        if isinstance(mcacod, int):
            _ = filter(lambda m: m.mcacod == mcacod, _)
        elif isinstance(mcacod, list):
            _ = filter(lambda m: m.mcacod in mcacod, _)
        return sorted(_, key=lambda m: m.time)
