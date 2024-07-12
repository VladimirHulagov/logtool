import enum
import pathlib
import typing
import datetime
import multiprocessing
import io
import contextlib
import tempfile
import itertools
import shutil
import itertools
import traceback
import json


import pandas as pd
import numpy as np
import pydantic
import tqdm

from logtool.api import fhm

from .schemas import shc, idl
from logtool.api import catts

if True:
    import sys
    sys.path.append("/home/shizy/fmtool.sdk")
    from fmtool_sdk_dev.decoder.mce import MachineCheckBase, AcdSummary, parse_mce, decode_mce_v2
    from fmtool_sdk_dev.diagnostor.advanced_diagnostor.mce_triage import triage as mce_triage

with open("/home/shizy/logtool/logtool/frontend/pages/data/fault_reason_map.json") as f:
    fault_reason_map = json.load(f)

with open(pathlib.Path("/home/shizy/logtool/logtool/api/vids.json")) as f:
    tca_table = catts.CatsTcaList.model_validate_json(f.read())


def map_fault_reason(fault_reason: str):
    for error_area, detail in fault_reason_map.items():
        for issue, key_action in detail.items():
            category = f"{error_area}.{issue}"
            keys = key_action.get("Keywords", [])
            if type(keys) == list:
                for key in keys:
                    if key in fault_reason:
                        return category
            if type(keys) == dict:
                for constant_key_str, option_key_list in keys.items():
                    if constant_key_str in fault_reason:
                        for option_key in option_key_list:
                            if option_key in fault_reason:
                                return category
    return None


import git
sdk_v3_repo = git.Repo(pathlib.Path("/home/shizy/fmtool.sdk/fmtool_sdk_2p3"))


HEX_INT = typing.Annotated[
    int,
    pydantic.BeforeValidator(lambda s: int(s, 16))
]


class ServerInfo(pydantic.BaseModel):
    ip: str = pydantic.Field(validation_alias="IP")
    sn: str = pydantic.Field(validation_alias="SN")
    bios: str = pydantic.Field(validation_alias="BIOS Version")
    cpu_model: str = pydantic.Field(validation_alias="CPU Model")
    ucode: HEX_INT = pydantic.Field(validation_alias="CPU Microcode")


class Mce(pydantic.BaseModel):
    # mce: int ? Sequence number?
    cpu_type: typing.Literal["SPR", "ICX", "CLX", "SKX"]
    ip: str | None
    ipv6: str | None
    ipv4: str | None
    timestamp_db: int
    SN: str
    Microcode: HEX_INT
    datetime: datetime.datetime
    socketid: int
    cpu: int
    apicid: HEX_INT
    bank: int
    addr: HEX_INT
    misc: HEX_INT
    status: HEX_INT


class ByteDanceEntry(pydantic.BaseModel):
    idx: int


class ByteDanceEntryDetail(ByteDanceEntry):
    model_config = pydantic.ConfigDict(extra="allow")
    vid: str | None = pydantic.Field(
        validation_alias=pydantic.AliasChoices("CPU VID", "vid"))
    ppin_log: str | None = pydantic.Field(
        validation_alias=pydantic.AliasChoices("CPU PPIN\n(log)", "ppin_log"))
    sn: str | None = pydantic.Field(
        validation_alias=pydantic.AliasChoices("Server SN", "sn"))
    # review: str | None = pydantic.Field(validation_alias="Log review result/next step")
    # key_info: str | None = pydantic.Field(validation_alias="Log关键信息")
    disposition: str | None = pydantic.Field(
        validation_alias=pydantic.AliasChoices("disposition", "Disposition"))
    # category: str | None = pydantic.Field(
    #     validation_alias=pydantic.AliasChoices("category", "Issue Category\n(Guan)"))
    keytag: str | None = pydantic.Field(
        validation_alias=pydantic.AliasChoices("keytag", "KeyLogTag\n(Guan)"))
    match: str | None = pydantic.Field(
        validation_alias=pydantic.AliasChoices("match", "match?"))
    # result: str | None = pydantic.Field(
    #     validation_alias=pydantic.AliasChoices("result", "FMTool Result"))
    failure_date: datetime.datetime | None = pydantic.Field(
        validation_alias=pydantic.AliasChoices("failure_date", "整机报修日期")
    )
    exclude: str | None

    @pydantic.computed_field
    @property
    def ppin(self) -> int | None:
        for tca in tca_table.list:
            if self.vid and self.vid.strip().lower().startswith(tca.vid.lower()):
                return tca.ppin
        return None


class ByteDanceLogs(ByteDanceEntry):
    logpaths: list[pathlib.Path]


class Category(enum.StrEnum):
    CPU = "CPU"
    Bystander = "Bystander"
    Inconclusive = "Inconclusive"
    InvalidLog = "InvalidLog"
    Bkc = "Bkc"
    Software = "Software"
    Dimm = "Dimm"
    Platform = "Platform"
    Pcie = "PCIe"

    @staticmethod
    def map_disposition(disp: str | None):
        assert isinstance(disp, str) or disp is None, repr(disp)
        mapping = {
            "Bystander": Category.Bystander,
            "DPM Exposure": Category.CPU,
            "DPM Random": Category.CPU,
            "DPM Ramdom": Category.CPU,
            "Inconclusive": Category.Inconclusive,
            "Invalid log": Category.InvalidLog,
            "Know Issue.SW Fix": Category.Bkc,
            "Memory.IMC": Category.Dimm,
            "memory.DIMM": Category.Dimm,
            "Suspect M/B": Category.Platform,
            "PCIE": Category.Pcie,
            "Suspect PCIe Device": Category.Pcie,
            "Suspect SW": Category.Software,
            "Thermal/Power": Category.Platform,
            None: None,
        }
        return mapping[disp.strip()]

    @staticmethod
    def map_fmtool_cat(cat: str | None):
        assert isinstance(cat, str) or cat is None, repr(cat)
        mapping = {
            "NoErrorDetected.IncompleteDump": Category.InvalidLog,
            "NoErrorDetected.NoUncorrMCAError": Category.InvalidLog,
            "PlatformFocused.PCIeRelated": Category.Pcie,
            "PlatformFocused.OS/SWRelated": Category.Software,
            "PlatformFocused.DIMMRlated": Category.Dimm,
            "PlatformFocused.DIMMRelated": Category.Dimm,
            "PlatformFocused.OutdatedBKC": Category.Bkc,
            "PlatformFocused.TransientPlatformBehavior": Category.Platform,
            "CPUFocused.PotentialDefect": Category.CPU,
            "CPUFocused.PotentialBug": Category.CPU,
            "Others.Unknown": Category.Inconclusive,
            "": None,
            None: None,
        }
        return mapping.get(cat)

    @staticmethod
    def map_mce_diag(cat: str | None):
        assert isinstance(cat, str) or cat is None, repr(cat)
        mapping = {
            "HW.IFU.ParityUE": Category.CPU,
            "HW.DCU.ParityUE": Category.CPU,
            "HW.MLC.ParityUE": Category.CPU,
            "HW.MDF.ParityUE": Category.CPU,
            "HW.CHA.ParityUE": Category.CPU,
            "HW.MLC.ThreeStrike": Category.CPU,
            "HW.DIMM.UE": Category.Dimm,
            "FW.PCU.Error": Category.Software,
            "HW.PCU.Thermal": Category.Platform,
            "HW.UPI.UE": Category.CPU,  # TODO: validate this carefully!
            "SW.PCU.TripleShutdown": Category.Software,
            # "HW.PCU.Error": Category.Inconclusive,
            # "HW.IIO.UE": Category.Pcie,
            # "HW.DCU.Poison": Category.CPU,  # TODO: look for other evidence!
        }
        return mapping.get(cat)
        # return mapping[cat]


class OnekeylogDiagnose(pydantic.BaseModel):
    issue: str
    diagnose: str
    suggestion: str
    action: str
    category: str
    ppin_list: list[str] | None = None
    event_time: datetime.datetime | None = None


class SummarizerDiagnose(pydantic.BaseModel):
    category: str
    action: str
    suggestion: str
    ppin: str
    diagnose: str


class FinalResult(pydantic.BaseModel):
    failure_ppin: str
    failure_diagnose: str
    failure_category: str
    failure_action: str
    failure_suggestion: str

    @property
    def category(self):
        return self.failure_category


SdkOutputType = (
    str |   # For SDK 2.2 or exception
    OnekeylogDiagnose |
    SummarizerDiagnose |
    FinalResult |
    None
)


class ByteDanceFhmSdkResult(ByteDanceEntry):
    results: list[SdkOutputType]


class ByteDanceKeyEvents(ByteDanceEntry):
    mces: list[MachineCheckBase]
    acds: list[AcdSummary]
    shcs: list[shc.ShcReport]
    idl_keyevents: typing.Annotated[
        list[idl.IdlEntry],
        pydantic.AfterValidator(
            lambda ls: list(filter(lambda idl: idl.dir == "Assert", ls))
        )
    ]

    @staticmethod
    def parse_logs(logs: ByteDanceLogs):
        mces, acds, shcs = parse_impl(logs)
        idls = [idl for idl in parse_idl(
            logs) if idl.error_cat and idl.error_cat.severity != "Info"]
        return ByteDanceKeyEvents(
            **logs.model_dump(),
            mces=mces,
            acds=acds,
            shcs=shcs,
            idl_keyevents=idls,
        )


ToolKit = typing.Literal[
    "acd_only",
    "dev",
    "summarizer",
    "v2",
    "v3",
]


class ByteDanceSimpleTableEntry(ByteDanceEntryDetail):
    results: dict[
        tuple[ToolKit, str | None],
        list[SdkOutputType]
    ]

    def _get_category(self, ver: ToolKit | tuple[ToolKit, str | None]):
        assert isinstance(ver, tuple), ver
        res = [r for r in self.results[ver] if r]
        catts = set(getattr(r, "category", r) for r in res)
        return catts

    def _get_ppins(self, ver: tuple[ToolKit, str | None]):
        def gen():
            for r in self.results[ver]:
                if ppin := getattr(r, "failure_ppin", None):
                    yield [ppin]
                elif ppin := getattr(r, "ppin", None):
                    yield [ppin]
                elif ppins := getattr(r, "ppin_list", None):
                    yield ppins
                else:
                    yield []
        return list(gen())

    def _get_cat(self, ver: tuple[ToolKit, str | None]):
        _ = map(Category.map_fmtool_cat, self._get_category(ver))
        return set(_)

    def _match_loose(self, ver: tuple[ToolKit, str | None]):
        cats = self._get_cat(ver)
        return self.disposition_valid and (
            self.disposition_category in cats or
            (self.disposition_category is Category.Bystander and Category.CPU not in cats)
        )

    def _match_strict(self, ver: tuple[ToolKit, str | None]):
        cats = self._get_cat(ver)
        ppins = set(int(ppin, 16) for ppins in self._get_ppins(ver)
                    for ppin in ppins)
        return self.disposition_valid and (
            (self.disposition_category is Category.CPU and Category.CPU in cats and len(ppins) <= 1 and (self.ppin is None or self.ppin in ppins)) or
            (self.disposition_category is not Category.CPU and self.disposition_category in cats) or
            (self.disposition_category is Category.Bystander and Category.CPU not in cats)
        )

    @property
    def _ppin_valid(self):
        return any(ppin for acd in self.acds for ppin in acd.ppins)

    def match_result(self, ver: tuple[ToolKit, str | None]):
        # return self._match_strict(ver)
        return self._match_loose(ver)

    @property
    def disposition_category(self):
        return Category.map_disposition(self.disposition.strip())

    @property
    def disposition_valid(self):
        # return self.disposition_category not in [Category.InvalidLog, Category.Inconclusive]
        return self.disposition_category not in [Category.InvalidLog] and self.exclude is None
        return self.disposition_category not in [Category.InvalidLog]
    
    @property
    def v3commits(self):
        _ = map(lambda r: r[1], self.results)
        _ = filter(None, _)
        _ = map(sdk_v3_repo.commit, _)
        _ = sorted(_, key=lambda c: c.committed_datetime)
        _ = map(lambda c: str(c), _)
        return list(_)


    def table_dump(self, commits: list[str] = [
        "5e782356f698791549e3ef43a928d20160bca2f5",
        "6a6ff2fc1745e52390a7d8b0e8fedef1b5d82c01",
        "9ca0954af682778881d7474d693841dd8d2566b1",
        "38127eaf1f2165a4120b7c598ae5d9c01eaea854",
        "be00c251c2b756a670561d0de8320012d2021320",
        # "e4c39a12ec7c95ed163154f75fbeadc7e14cf5b7",
    ]):
        res = {
            "Index": self.idx,
            "S/N": self.sn,
            "VID": self.vid,
            "PPIN(from VID)": self.ppin and hex(self.ppin),
            # "v2.3 87063ad ppins": [str(res.ppin_list) for res in self.v2p3_results],
            # "v2.3 dev ppins": [str(res.ppin_list) for res in self.dev_results],
            # "PPIN_LOG": self.ppin_log,
            # "Logs": [log.name for log in self.logpaths],
            "keytag": self.keytag,
            "disposition": self.disposition,
            "v2.2 summary": self._get_cat(("v2", None)),
            "summarizer": self._get_cat(("summarizer", None)),
            "summarizer+rule": self._get_cat(("acd_only", None)),
            **{
                commit[:8]: self._get_cat(("v3", commit))
                for commit in commits
            },
            # "dev summary": self._get_cat("dev"),
            "valid": self.disposition_valid,
            "match(v2.2)": self._match_loose(("v2", None)),
            "match(summarizer)": self._match_loose(("summarizer", None)),
            "match(summarizer+rule)": self._match_loose(("acd_only", None)),
            **{
                f"match({commit[:8]})": self._match_loose(("v3", commit))
                for commit in commits
            },
        }
        return res


class ByteDanceTableEntry(ByteDanceSimpleTableEntry, ByteDanceLogs, ByteDanceKeyEvents):
    def full_dump(self):
        res = {
            "Index": self.idx,
            "S/N": self.sn,
            "VID": self.vid,
            "disposition": self.disposition,
            "hit_rules": self.hit_rules,
            "PPIN(from VID)": self.ppin and hex(self.ppin),
            **{
                f"PPIN {ver}": self._get_ppins(ver)
                for ver in self.results
            },
            "Logs": [log.name for log in self.logpaths],
            "CpuType": self.acds[0].FaultCPU if self.acds else "UNK",
            "keytag": self.keytag,
            "disposition": self.disposition,
            "hit_rules": self.hit_rules,
            "dev result": [d.model_dump_json(indent=4) for d in self.results[("dev", None)] if d],
            "disposition_cat": Category.map_disposition(self.disposition),
            **{
                f"Category {ver}": self._get_cat(ver)
                for ver in self.results
            },
            "disposition_valid": self.disposition_valid,
            **{
                f"Match {ver}": self.match_result(ver)
                for ver in self.results
            },
            "FaultReasons": set(acd.FaultReason for acd in self.acds),
            "FaultReasonCategory": set(map_fault_reason(acd.FaultReason) for acd in self.acds),
            "mce_sigs": self.mce_sigs,
            "idl_signatures": self.idl_sigs,
            "failure_date": self.failure_date,
            "mce_signatures": self.mce_sigs,
            # "events": sorted(itertools.chain(
            #     [f"{mce.time} {type(mce).__name__} {mce.short_str}" for mce in self.valid_mces],
            #     [f"{idl.time} {type(idl).__name__} {idl.short_str}" for idl in self.valid_idls],
            # )),
            # "0405_addrs": [hex(mce.address) for mce in self.mces if mce.mcacod == 0x0405 and mce.address],
            "msmcacods": set(hex(mce.status)[-8:] for mce in self.mces),
            "acd_time": [acd.FaultTimeStamp for acd in self.acds],
            "mces": self.model_dump_json(include=("mces"), indent=4),
            "idls": self.model_dump_json(include=("idl_keyevents"), indent=4),
            **self.model_extra,
        }
        return res

    @pydantic.computed_field
    @property
    def scenario_rebuild(self) -> list:
        return [
            e for e in
            sorted(itertools.chain(
                (mce for mce in self.mces if mce.type == "MaintenanceLog"),
                (idl for idl in self.idl_keyevents if idl.src == "CPU"),
            ), key=lambda e: e.time)
        ]

    @property
    def hit_rules(self):
        msmcacod_table = {
            "00000005": "ifu_parity",
            "00010005": "ifu_parity",
            "00030005": "ifu_parity",
            "00050005": "ifu_parity",
            "00070005": "ifu_parity",
            "00080005": "ifu_parity",
            "00100005": "ifu_parity",
            "00110005": "ifu_parity",
            "00130005": "ifu_parity",
            "00140005": "ifu_parity",
            "00000006": "ifu_0006",
            "000f040a": "ifu_exe_residue_check",
            "000c0150": "ifu_poison",
            "00100134": "dcu_poison",
            "00110134": "dcu_poison",
            "e1090400": "mlc_3strike",
            "e14c0400": "mlc_3strike",
            "e14d0400": "mlc_3strike",
            "e1840400": "mlc_3strike",
            "e1890400": "mlc_3strike",
            "e18c0400": "mlc_3strike",
            "e18d0400": "mlc_3strike",
            "e1c40400": "mlc_3strike",
            "e1c90400": "mlc_3strike",
            "e1cc0400": "mlc_3strike",
            "e1cd0400": "mlc_3strike",
            "f1c40400": "mlc_3strike",
            "f1c90400": "mlc_3strike",
            "f1cd0400": "mlc_3strike",
            "a0000402": "pcu_thermal",
            "c0000402": "pcu_dispatcher_run_busy_timeout",
            "0a000402": "pcu_mca_internal_timeout",
            "3a000402": "pcu_mca_gpsb_timeout",
            "0001040c": "pcu_mce_when_cr4_mce_clear",
            "0002040c": "pcu_mce_when_mcip_set",
            "0005040c": "pcu_sw_triple_fault",
            "0008040c": "pcu_invalid_smm_entry_condition",
            "00010405": "imc_addr_parity",
            "00020405": "imc_write_data_parity",
            "00040405": "imc_write_byte_enable_parity",
            "00070405": "m2m_parity",
            "000a0405": "cha_data_parity_0405",
            "00400405": "mdf_parity",
            "00c00405": "mlc_addr_parity",
            "001f0405": "cha_internal_parity_0405",
            "0019110a": "cha_ak_reg_rtid_table_miss",
            "0033110a": "cha_internal_error",
            "000c017a": "cha_torto",
            "000c110a": "cha_torto",
            "000c1136": "cha_torto",
            "000c1146": "cha_torto",
            "000c1152": "cha_torto",
            "000f110a": "cha_internal_error",
            "000f1136": "cha_internal_error",
            "000f1146": "cha_internal_error",
            "00061136": "cha_sad_non_corrupting_other",
            "00061152": "cha_sad_non_corrupting_other",
            "0008017a": "cha_poison",
            "00081136": "cha_poison",
            "0021017a": "cha_uc_sf_tag",
            "00211146": "cha_uc_sf_tag",
            "002a1136": "cha_ismq_unexpected_rsp",
            "0018110a": "cha_bl_reg_rtid_table_miss",
            "002a1152": "cha_ismq_unexpected_rsp",
            "000b1146": "cha_core_wb_miss_lcc",
            "08000174": "dcu_0100_wbinvd",
            "01000174": "dcu_0100_wbinvd",
            "01000184": "dcu_0100_snoop_parity",
            "01000114": "dcu_0100_buffer_parity",
            "02000114": "dcu_0200_buffer_parity",
            "00080189": "mlc_mesi_uc_parity",
            "00110c0f": "kti_unsupported_packet",
            "00120e0f": "kti_uc_ll_phy_ctl_err",
            "80120405": "kti_uc_ll_phy_ctl_err_ll_tx_parity_0405",
            "00300e0f": "kti_corr_ll_rx_crc_error",
            "001f0e0f": "kti_uc_ll_detected_ctl_err",
            "00100e0f": "kti_uc_ll_detected_crc_err",
            "00210e0f": "kti_corr_phy_inband_reset",
            "00000e0b": "iio_generic_io_error",
            "80040407": "ubox_misaligned_cfg_read_non_smm",
            "001000c0": "imc_uncorr_patrol_scrub",
            "001000c1": "imc_uncorr_patrol_scrub",
            "00a00090": "imc_uncorr_read_error",
            "00a00091": "imc_uncorr_read_error",
            "010800b0": "imc_ddr_link_fail",
            "010800b1": "imc_ddr_link_fail",
        }

        def parity_ue_0405():
            return any(mce.mcacod == 0x0405 for mce in self.mces)

        def acd_dump_failure():
            return (
                all("HW.HANG.Core" in acd.FaultReason and "PECI" in acd.FaultReason for acd in self.acds)
                # and not dispatcher_run_busy_timeout()
            )

        def dimm_lost():
            return any("Disabled Memory" in idl.detail for idl in self.idl_keyevents)

        def _idl_err_data_check(vals: list[str]):
            return any(any(val == idl.data for idl in self.idl_keyevents) for val in vals)

        def idl_cpu_ierr_caterr():
            return _idl_err_data_check(["07000002", "07010002"])

        def idl_cpu_post_failure():
            return _idl_err_data_check(["07000302", "07010302"])

        def idl_cpu_throttle():
            return _idl_err_data_check(["07000A01", "07010A01"])

        def idl_cpu_uce():
            return _idl_err_data_check(["07000B02", "07010B02"])

        def idl_cpu_ce():
            return _idl_err_data_check(["07000C01", "07010C01"])

        # def rrel():
        #     for acd in self.acds:
        #         for rrel in acd.FaultMicrocode

        rules = [
            acd_dump_failure,
            dimm_lost,
            idl_cpu_ce,
            idl_cpu_ierr_caterr,
            idl_cpu_post_failure,
            idl_cpu_throttle,
            idl_cpu_uce,
            parity_ue_0405,
        ]
        res = [
            r.__name__ for r in rules
            if r()
        ]
        msmcacods = set(hex(mce.status)[-8:].lower()
                        for mce in self.mces if mce.valid)
        res.extend(msmcacod_table.get(k) for k in msmcacods)
        return res

    @property
    def valid_mces(self):
        return [
            mce for mce in self.mces
            if self.failure_date is None
            or (self.failure_date.replace(tzinfo=None) - mce.time.replace(tzinfo=None)).total_seconds() < 86400 * 7
        ] or self.mces

    @property
    def valid_idls(self):
        return [
            idl for idl in self.idl_keyevents
            if self.failure_date is None
            or (self.failure_date.replace(tzinfo=None) - idl.time.replace(tzinfo=None)).total_seconds() < 86400 * 7
        ] or self.idl_keyevents

    @property
    def mce_diags(self):
        mces = self.valid_mces

        def impl():
            if self.acds:
                cpu_type = self.acds[0].FaultCPU
                ucode = self.acds[0].FaultMicrocode
                yield mce_triage.diagnose_mces(cpu_type, mces, ucode)
                return
            for cpu_type in ["ICX", "SPR", "SKX", "CLX"]:
                try:
                    mce_triage.diagnose_mces(cpu_type, mces, ucode)
                except Exception:
                    pass
        diags = list(impl())
        return [d for diag in diags for d in diag]

    @property
    def mce_sigs(self):
        return set(d.signature for d in self.mce_diags)

    @property
    def idl_sigs(self):
        _ = map(lambda e: e.error_cat and e.error_cat.short_str, self.valid_idls)
        _ = filter(None, _)
        return set(_)

    @property
    def final_diag(self):
        mapped = list(set(map(Category.map_mce_diag, self.mce_sigs)))
        if "HW.IIO.UE" in self.mce_sigs and "PCIe.Error" in self.idl_sigs:
            return Category.Pcie
        if len(mapped) == 1 and mapped[0] is not None:
            return mapped[0]
        if len(mapped) > 1:
            for d in self.mce_sigs:
                if "Parity" in d:
                    return Category.CPU
        if len(self.mce_sigs) == 1 and "HW.DCU.Poison" in self.mce_sigs:
            for d in self.idl_sigs:
                if "DIMM" in d:
                    return Category.Dimm
                if "PCIe" in d:
                    return Category.Pcie
            return Category.CPU
        if len(self.mce_sigs) == 1 and "HW.IIO.UE" in self.mce_sigs:
            for d in self.idl_sigs:
                # if "DIMM" in d:
                #     return Category.Dimm
                if "PCIe" in d:
                    return Category.Pcie
            return Category.Pcie
        if len(self.mce_sigs) == 1 and "HW.CHA.TOR_TIMEOUT" in self.mce_sigs:
            for d in self.idl_sigs:
                if "DIMM" in d:
                    return Category.Dimm
                if "PCIe" in d:
                    return Category.Pcie
            return Category.CPU
        if len(mapped) == 0:
            if "DIMM.Error" in self.idl_sigs:
                return Category.Dimm
            if "Thermal.Warn" in self.idl_sigs:
                return Category.Platform
        if self.acds and not self.mces:
            # ACD failure
            return Category.Software
        return Category.Inconclusive

    @property
    def diag_match(self):
        return self.disposition_valid and (
            self.disposition_category == self.final_diag or
            (self.disposition_category is Category.Bystander and Category.CPU != self.final_diag)
        )


data_dir = pathlib.Path(__file__).parent
jan_feb_mcelog_xlsx = data_dir.joinpath(
    "0101-0227_SPR_MCELOG_Exclude-memory.xlsx")


def get_server_infos():
    _ = pd.read_excel(jan_feb_mcelog_xlsx, 0).iterrows()
    _ = map(lambda tup: tup[1].to_dict(), _)
    _ = map(ServerInfo.model_validate, _)
    return list(_)


def get_mcelogs():
    _ = pd.read_excel(jan_feb_mcelog_xlsx, 1).replace(
        {np.nan: None}).iterrows()
    _ = map(lambda tup: tup[1].to_dict(), _)
    _ = map(Mce.model_validate, _)
    return list(_)


def get_mcelogs2():
    # TODO: Translate SN and ucode
    # ip_map = {
    #     info.ip: info
    #     for info in get_server_infos()
    # }
    _ = pd.read_csv(data_dir.joinpath("MCELOG_UC_0301-0513.csv")
                    ).replace({np.nan: None}).iterrows()
    _ = map(lambda tup: tup[1].to_dict(), _)
    _ = map(lambda d: {**d, "SN": "", "Microcode": "0x0"}, _)
    _ = map(Mce.model_validate, _)
    return list(_)


def get_mcelogs3():
    _ = pd.read_csv(data_dir.joinpath("mcelog_ue_90day.csv")
                    ).replace({np.nan: None}).iterrows()
    _ = map(lambda tup: tup[1].to_dict(), _)
    _ = map(lambda d: {**d, "SN": "", "Microcode": "0x0"}, _)
    _ = map(Mce.model_validate, _)
    return list(_)


def surpress_output(func):
    def wrapped(*args, **kwargs):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            res = func(*args, **kwargs)
        return res
    return wrapped


@surpress_output
def diagnose_onekeylog_v2_impl(onekeylog: pathlib.Path) -> str | None:
    from fmtool_sdk_2p2.diagnostor import diagnose_onekeylog as diagnose_onekeylog_ver2p2
    with tempfile.TemporaryDirectory() as tmpdir:
        diag = diagnose_onekeylog_ver2p2(str(onekeylog), tmpdir)
        if diag.key_crashdump_output_with_err:
            outputs = list(diag.key_crashdump_output_with_err.get(
                "OUTPUT", {}).values())
            res = [output["Failure_category_and_action"]
                   ["Failure_Category"] for output in outputs]
            if res:
                return res[0]
    return None


@surpress_output
def diagnose_onekeylog_v3rc_impl(onekeylog: pathlib.Path):
    from fmtool_sdk_2p3rc.diagnostor import diagnose_onekeylog as diagnose_onekeylog_ver2p3rc
    with tempfile.TemporaryDirectory() as tmpdir:
        diag = diagnose_onekeylog_ver2p3rc(
            str(onekeylog), tmpdir).diagnose_result
        return OnekeylogDiagnose.model_validate(diag.to_dict())


@surpress_output
def diagnose_onekeylog_v3_impl(onekeylog: pathlib.Path):
    from fmtool_sdk_2p3.diagnostor import diagnose_onekeylog as diagnose_onekeylog_ver2p3
    with tempfile.TemporaryDirectory() as tmpdir:
        res = diagnose_onekeylog_ver2p3(str(onekeylog), tmpdir)
        diag = res.diagnose_result
        return OnekeylogDiagnose.model_validate(diag.to_dict())


@surpress_output
def diagnose_onekeylog_summarizer_impl(onekeylog: pathlib.Path):
    import dataclasses
    from fmtool_sdk_2p3rc.diagnostor import (
        diagnose_crashdump,
        diagnose_onekeylog as diagnose_onekeylog_tmp,
    )
    from fmtool_sdk_2p3rc.decoder import decode_crashdump
    with tempfile.TemporaryDirectory() as tmpdir:
        res = diagnose_onekeylog_tmp(str(onekeylog), tmpdir)
        acd = res.key_crashdump_path
        print(acd)
        if not acd:
            return None
        d = decode_crashdump(acd)
        diag = diagnose_crashdump(d).summarizer_diagnose
        return SummarizerDiagnose.model_validate(dataclasses.asdict(diag))


@surpress_output
def diagnose_onekeylog_acd_only_impl(onekeylog: pathlib.Path):
    import dataclasses
    from fmtool_sdk_2p3rc.diagnostor import (
        diagnose_onekeylog as diagnose_onekeylog_tmp,
        crosslog_diagnose,
    )
    from fmtool_sdk_2p3rc.decoder import decode_crashdump
    with tempfile.TemporaryDirectory() as tmpdir:
        res = diagnose_onekeylog_tmp(str(onekeylog), tmpdir)
        acd = res.key_crashdump_path
        if not acd:
            return None
        d = decode_crashdump(acd)
        diag2 = crosslog_diagnose([d]).final_diagnose_result
        return FinalResult.model_validate(dataclasses.asdict(diag2))


@surpress_output
def diagnose_onekeylog_dev_impl(onekeylog: pathlib.Path):
    from fmtool_sdk_dev.diagnostor import diagnose_onekeylog as diagnose_onekeylog_dev_ver
    with tempfile.TemporaryDirectory() as tmpdir:
        diag = diagnose_onekeylog_dev_ver(
            str(onekeylog), tmpdir).diagnose_result
        return OnekeylogDiagnose.model_validate(diag.to_dict())


@surpress_output
def parse_impl(track: ByteDanceLogs):
    from fmtool_sdk_dev.decoder import decode_onekeylog
    mces: list[MachineCheckBase] = []
    acds: list[AcdSummary] = []
    shcs: list[shc.ShcReport] = []
    for p in track.logpaths:
        try:
            if "shc_report" in p.name:
                import tarfile
                with tarfile.open(p) as archive:
                    _ = archive.getmembers()
                    _ = filter(lambda m: m.name.endswith("report.json"), _)
                    report_jsons = list(_)
                    assert len(report_jsons) <= 1
                    if report_jsons:
                        text = archive.extractfile(
                            report_jsons[0]).read().decode()
                        report = shc.ShcReport.model_validate_json(text)
                        report.reduce()
                        shcs.append(report)
                    _ = archive.getmembers()
                    _ = filter(
                        lambda m: "sys_" in m.name and m.name.endswith(".log"), _)
                    syslogs = list(_)
                    assert len(syslogs) <= 1
                    if syslogs:
                        text = archive.extractfile(syslogs[0]).read().decode()
                        mces.extend(parse_mce(text))
                continue
            if "sys_" in p.name:
                mces.extend(parse_mce(p))
                continue
            assert "tar" in p.name or "7z" in p.name or "gz" in p.name
            with tempfile.TemporaryDirectory() as tmpdir:
                decode = decode_onekeylog(str(p), tmpdir)
                mces.extend(decode.machine_checks)
                if decode.acd:
                    decode.acd.tor_valid_entries = None
                    acds.append(decode.acd)
        except Exception:
            pass
    return mces, acds, shcs


def parse_idl(log: ByteDanceLogs):
    def get_idl(log: pathlib.Path):
        def impl():
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = pathlib.Path(tmpdir)
                try:
                    shutil.unpack_archive(log, tmpdir)
                except Exception:
                    pass
                for f in tmpdir.rglob("*"):
                    try:
                        shutil.unpack_archive(
                            f, f.parent.joinpath(f.name.split(".")[0]))
                    except Exception:
                        continue
                _ = tmpdir.rglob("idl.log")
                for p in _:
                    try:
                        with open(p) as f:
                            yield p, f.read()
                    except Exception:
                        continue
        return list(impl())
    _ = map(get_idl, log.logpaths)
    _ = itertools.chain.from_iterable(_)
    _ = map(lambda tup: tup[1], _)
    _ = map(str.splitlines, _)
    _ = itertools.chain.from_iterable(_)
    _ = map(idl.IdlEntry.parse_line, _)
    return list(_)


def download_log_for_track(track: ByteDanceEntryDetail):
    print(track.model_dump_json())
    downloads = fhm.download_log(str(track.sn))
    print(len(downloads))
    if downloads:
        for name, content in downloads:
            print(name)
            with open(data_dir.joinpath("logs", f"{track.sn} - {name}"), "wb") as f:
                f.write(content)
    print("XXXXXXXXXXXXXXX")


def copy_log_for_track(track: ByteDanceEntryDetail):
    # print(track.model_dump_json())
    shc_dir = pathlib.Path("/home/shizy/logs/SHC_INBOUND_LOG")
    if not track.sn:
        return
    for log in shc_dir.glob(f"*{track.sn}*"):
        print(log)
        with open(log, "rb") as f:
            content = f.read()
        with open(data_dir.joinpath("logs", f"{track.sn} - {log.name}"), "wb") as f:
            f.write(content)


class ByteDanceDetailList(pydantic.BaseModel):
    list: list[ByteDanceEntryDetail]

    @staticmethod
    def load_excel():
        df = pd.read_excel(data_dir.joinpath(
            "ByteDance CPU Failure Response Flow Rule 20240528.xlsx"), 2)
        _ = df.replace({np.nan: None}).iterrows()
        _ = map(lambda tup: tup[1].to_dict(), _)
        _ = enumerate(_)
        _ = map(lambda tup: {"idx": tup[0], **tup[1]}, _)
        _ = map(ByteDanceEntryDetail.model_validate, _)
        return ByteDanceDetailList(list=list(_))


class ByteDanceLogsList(pydantic.BaseModel):
    list: list[ByteDanceLogs]

    @staticmethod
    def load_logs():
        def impl():
            for track in ByteDanceDetailList.load_excel().list:
                if track.sn is None:
                    continue
                logs = data_dir.joinpath("logs").glob(f"{track.sn} - *")
                yield ByteDanceLogs(**track.model_dump(), logpaths=list(logs))
        return ByteDanceLogsList(list=list(impl()))


def _diagnose_helper(diagnose: typing.Callable):
    def impl(logs: ByteDanceLogs):
        def gen():
            for p in logs.logpaths:
                if "shc_report" in p.name:
                    yield None
                    continue
                if "sys_" in p.name:
                    yield None
                    continue
                try:
                    assert "tar" in p.name or "7z" in p.name or "gz" in p.name
                    diag = diagnose(str(p))
                    yield diag
                except Exception as e:
                    traceback.print_exc()
                    yield repr(e)
        return ByteDanceFhmSdkResult(**logs.model_dump(), results=list(gen()))
    return impl


def diagnose_onekeylog_v2(logs: ByteDanceLogs):
    return _diagnose_helper(diagnose_onekeylog_v2_impl)(logs)


def diagnose_onekeylog_v3rc(logs: ByteDanceLogs):
    return _diagnose_helper(diagnose_onekeylog_v3rc_impl)(logs)


def switch_sdk_commit(commit: str):
    import git
    repo = git.Repo(pathlib.Path("/home/shizy/fmtool.sdk/fmtool_sdk_2p3"))
    repo.git.checkout(commit)
    # repo.head.reference = repo.commit(commit)
    return repo


def diagnose_onekeylog_v3(logs: ByteDanceLogs):
    return _diagnose_helper(diagnose_onekeylog_v3_impl)(logs)


def diagnose_onekeylog_dev(logs: ByteDanceLogs):
    return _diagnose_helper(diagnose_onekeylog_dev_impl)(logs)


def diagnose_onekeylog_summarizer(logs: ByteDanceLogs):
    return _diagnose_helper(diagnose_onekeylog_summarizer_impl)(logs)


def diagnose_onekeylog_acd_only(logs: ByteDanceLogs):
    return _diagnose_helper(diagnose_onekeylog_acd_only_impl)(logs)


class ByteDanceFhmSdkResultList(pydantic.BaseModel):
    version: ToolKit
    commit: str | None
    results: list[ByteDanceFhmSdkResult]

    @staticmethod
    def run_and_save(tqdm_buffer: io.StringIO | None = None):
        tracks = ByteDanceLogsList.load_logs().list
        for commit in [
            # "5e782356f698791549e3ef43a928d20160bca2f5",
            # "6a6ff2fc1745e52390a7d8b0e8fedef1b5d82c01",
            # "9ca0954af682778881d7474d693841dd8d2566b1",
            # "38127eaf1f2165a4120b7c598ae5d9c01eaea854",
            # "be00c251c2b756a670561d0de8320012d2021320",
            # "e4c39a12ec7c95ed163154f75fbeadc7e14cf5b7",
        ]:
            repo = switch_sdk_commit(commit)
            print(repo.commit())
            print(repo.commit().committed_datetime)
            res = ByteDanceFhmSdkResultList(
                version="v3",
                commit=commit,
                results=[]
            )
            def save():
                content = res.model_dump_json(indent=4)
                name = "bytedance_{}_{}.json".format(
                    diagnose_onekeylog_v3.__name__,
                    commit
                )
                fpath = data_dir.joinpath(name)
                with open(fpath, "w") as f:
                    f.write(content)
            save()
            if True:
                q = tqdm.tqdm(map(diagnose_onekeylog_v3, tracks),
                              total=len(tracks))
            with multiprocessing.Pool(processes=60) as pool:
                q = tqdm.tqdm(
                    pool.imap_unordered(
                        diagnose_onekeylog_v3,
                        tracks
                    ),
                    total=len(tracks),
                    file=tqdm_buffer,
                )
                for idx, r in enumerate(q):
                    try:
                        r.model_dump_json()
                    except Exception:
                        import traceback
                        traceback.print_exc()
                        continue
                    res.results.append(r)
                    if (idx + 1) % 10 == 0:
                        save()
            save()
        for func in [
            diagnose_onekeylog_v2,
            diagnose_onekeylog_acd_only,
            diagnose_onekeylog_summarizer,
            diagnose_onekeylog_dev,
        ]:
            res = ByteDanceFhmSdkResultList(
                version=func.__name__.removeprefix("diagnose_onekeylog_"),
                commit=None,
                results=[]
            )
            def save():
                content = res.model_dump_json(indent=4)
                name = "bytedance_{}.json".format(
                    func.__name__
                )
                fpath = data_dir.joinpath(name)
                with open(fpath, "w") as f:
                    f.write(content)
            save()
            if True:
                q = tqdm.tqdm(map(func, tracks), total=len(tracks))
            with multiprocessing.Pool(processes=60) as pool:
                q = tqdm.tqdm(
                    pool.imap_unordered(
                        func,
                        tracks
                    ),
                    total=len(tracks),
                    file=tqdm_buffer,
                )
                for idx, r in enumerate(q):
                    try:
                        r.model_dump_json()
                    except Exception:
                        import traceback
                        traceback.print_exc()
                        continue
                    res.results.append(r)
                    if (idx + 1) % 10 == 0:
                        save()
            save()

    @staticmethod
    def load_jsons():
        def gen():
            for fpath in data_dir.glob("bytedance_diagnose_onekeylog_*.json"):
                with open(fpath) as f:
                    partial = ByteDanceFhmSdkResultList.model_validate_json(
                        f.read())
                partial.results.sort(key=lambda r: r.idx)
                yield partial
        results = list(gen())
        length = set(len(r.results) for r in results)
        assert len(length) == 1, length
        def gen2():
            for idx in range(list(length)[0]):
                yield {
                    (ls.version, ls.commit): ls.results[idx]
                    for ls in results
                }
        return list(gen2())


class ByteDanceKeyEventsList(pydantic.BaseModel):
    list: list[ByteDanceKeyEvents]

    @staticmethod
    def run_and_save():
        res = ByteDanceKeyEventsList(list=[])

        def save(sample: bool = False):
            filename = "{}bytedance_events.json".format(
                "sameple_" if sample else "")
            result_path = data_dir.joinpath(filename)
            content = res.model_dump_json(indent=4)
            with open(result_path, "w") as f:
                f.write(content)
        tracks = ByteDanceLogsList.load_logs().list
        # if True:
        # _ = tqdm.tqdm(map(cls.parse_logs, tracks), total=len(tracks))
        with multiprocessing.Pool(processes=64) as pool:
            _ = tqdm.tqdm(pool.imap_unordered(
                ByteDanceKeyEvents.parse_logs, tracks), total=len(tracks))
            for idx, r in enumerate(_):
                try:
                    r.model_dump_json()
                except Exception:
                    import traceback
                    traceback.print_exc()
                    continue
                res.list.append(r)
                if (idx + 1) % 10 == 0:
                    save()
                if (idx + 1) == 20:
                    save(True)
            save()

    @staticmethod
    def load_json():
        result_path = data_dir.joinpath("bytedance_events.json")
        with open(result_path) as f:
            return ByteDanceKeyEventsList.model_validate_json(f.read())


class ByteDanceSimpleTable(pydantic.BaseModel):
    list: list[ByteDanceSimpleTableEntry]

    @staticmethod
    def load():
        detail = ByteDanceDetailList.load_excel()
        fhm = ByteDanceFhmSdkResultList.load_jsons()
        return ByteDanceSimpleTable(list=[
            ByteDanceSimpleTableEntry(
                **d.model_dump(),
                results={
                    k: v.results 
                    for k, v in f.items()
                }
            )
            for d, f in zip(
                sorted(detail.list, key=lambda d: d.idx),
                fhm,
            )
        ])


class ByteDanceTable(pydantic.BaseModel):
    list: list[ByteDanceTableEntry]

    @staticmethod
    def load():
        def sorted_ls(ls: list):
            return sorted(ls, key=lambda l: l.idx)

        def merge(*items):
            assert len(set(getattr(item, "idx") for item in items)) == 1
            dic = {}
            for item in items:
                dic.update(item.model_dump())
            return dic
        simple_table = ByteDanceSimpleTable.load()
        events = ByteDanceKeyEventsList.load_json()
        logs = ByteDanceLogsList.load_logs()
        return ByteDanceTable(list=[
            ByteDanceTableEntry(**merge(d, f, e))
            for d, f, e in zip(
                sorted_ls(simple_table.list),
                sorted_ls(events.list),
                sorted_ls(logs.list),
            )
        ])


def foo(arg):
    try:
        return diagnose_onekeylog_v3rc(arg)
    except Exception:
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # for track in ByteDanceDetailList.read_excel().list:
    #     copy_log_for_track(track)
    # _ = ByteDanceLogsList.load_logs().list
    # _ = itertools.chain.from_iterable(logs.logpaths for logs in _)
    # _ = filter(lambda p: "tar" in p.name or "7z" in p.name or "gz" in p.name, _)
    # with multiprocessing.Pool(32) as pool:
    #     _ = pool.map(foo, _)
    #     list(_)
    # for i in range(1, 10):
    #     repo = switch_sdk_commit(f"HEAD~{i}")
    #     print(repo.commit())
    # repo = switch_sdk_commit("ba10783")
    # print(repo.commit())
    ByteDanceFhmSdkResultList.run_and_save()
    # print(ByteDanceSimpleTable.load().model_dump_json(indent=4))
    # print(ByteDanceTable.load().model_dump_json(indent=4))
    # ByteDanceKeyEventsList.run_and_save()
    # ls = ByteDanceDetailList.load_excel()
    # ls.list = ls.list[:5]
    # print(ls.model_dump_json(indent=4))
