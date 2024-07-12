import typing

from ...base import MachineCheckBase
from ..text_parser import ContentPattern, DataType, HEX_PATTERN
from ..parsers import register_parser


# <180>  2023-10-29T23:56:47.273148+00:00 AMI9CC2C43E4B39 IPMIMain:  [268 : 310 WARNING]Get Diagnose MCA data from bios, ReqLen=40:BankNum: 0, ApicId: 34,  BankType: 1,  BankScope: 0, McaStatus: 0xb200000000010005, McaAddress: 0x0000000000000000,  McaMisc: 0x0000000000000000
# <180>  2023-10-14T16:07:53.872948+00:00 AMI9CC2C43CB4A4 IPMIMain:  [271 : 312 WARNING]Get Diagnose MCA data from bios, ReqLen=40:BankNum: 1, ApicId: 218,  BankType: 2,  BankScope: 0, McaStatus: 0xbf80000001000174, McaAddress: 0x00000155b8e0ae80,  McaMisc: 0x0000000000000086
maintenance_pattern = ContentPattern(
    pattern=r".*Get Diagnose MCA data from bios.*McaStatus.*",
    keywords=["Get Diagnose MCA data from bios", "McaStatus"],
    subpatterns={
        DataType.time: [
            r"(?P<time>\d+-\d+-\d+T\d+:\d+:\d+[\w+.:]+)",
        ],
        DataType.decimal: [
            r"BankNum: (?P<bank>\d+)",
            r"ApicId: (?P<apicid>\d+)",
        ],
        DataType.hexadecimal: [
            # TODO: How to get socket? Is it BankScope or should we translate ApicId?
            f"McaStatus: (?P<status>{HEX_PATTERN})",
            f"McaAddress: (?P<address>{HEX_PATTERN})",
            f"McaMisc: (?P<misc>{HEX_PATTERN})",
        ],
    },
)

# <180>  2022-10-01T09:47:39.640000+00:00 425035089 IPMIMain:  [749 : 974 WARNING]Get Diagnose data from bios, DateHeader: Domain=0, Submodule=0, InfoSrc=1, SMISeriaNo=0, IndicatedNo=63734
# <180>  2022-10-01T09:47:39.640000+00:00 425035089 IPMIMain:  [749 : 974 WARNING]Get Diagnose MCA data from bios, ReqLen=198:SocketID: 1, CoreID: 255,  BankNo: 6, MSR_MCG_CONTAIN: 0x0000000000000001, IA32_MCG_STATUS: 0x0000000000000000,  IA32_MCG_CAP: 0x000000000f000c1c, MCA_ERROR_CONTROL: 0x0000000000000000, IA32_MCi_CTL: 0x0000000000000000, IA32_MCi_CTL2: 0x0000000000000000, IA32_MCi_STATUS: 0xba00000000000e0b, IA32_MCi_ADDR: 0x00000000ffffffff, IA32_MCi_MISC: 0x00000000fe030000, THREAD_SMI_ERR_SRC: 0x0000000000000000, CORE_SMI_ERR_SRC: 0x0000000000000000, UNCORE_SMI_ERR_SRC: 0x0000000000000000,IerrLoggingReg: 0x00000000, McerrLoggingReg: 0x000001c7,EMCA_CORE_CSMI_LOG: 0x00000000,EMCA_CORE_CSMI_LOG1: 0x00000000,EMCA_CORE_MSMI_LOG: 0x00000000,EMCA_CORE_MSMI_LOG1: 0x00000000,MCA_ERR_SRC_LOG: 0x00140000,
# <180>  2022-10-01T09:47:39.640000+00:00 425035089 IPMIMain:  [749 : 974 WARNING] RETRY_RD_CH_NUM:0x0, RETRY_RD_SET2_CH_NUM: 0x0,  RETRY_RD_ERR_LOG: 0x00000000, RETRY_RD_ERR_LOG_MISC: 0x00000000, RETRY_RD_ERR_LOG_PARITY: 0x00000000, RETRY_RD_ERR_LOG_ADDRESS1: 0x00000000, RETRY_RD_ERR_LOG_ADDRESS2: 0x00000000,RETRY_RD_ERR_LOG_ADDRESS3N0: 0x00000000,RETRY_RD_ERR_LOG_ADDRESS3N1: 0x00000000, RETRY_RD_ERR_SET2_LOG: 0x00000000,  RETRY_RD_ERR_SET2_LOG_MISC: 0x00000000, RETRY_RD_ERR_SET2_LOG_PARITY: 0x00000000,RETRY_RD_ERR_SET2_LOG_ADDRESS1: 0x00000000, RETRY_RD_ERR_SET2_LOG_ADDRESS2: 0x00000000, RETRY_RD_ERR_SET2_LOG_ADDRESS3N0: 0x00000000, RETRY_RD_ERR_SET2_LOG_ADDRESS3N1: 0x00000000
# TODO: Maybe also parse retry_rd_err_log?
maintenance_pattern2 = ContentPattern(
    pattern=r".*Get Diagnose MCA data from bios.*IA32_MCi_STATUS.*",
    keywords=["Get Diagnose MCA data from bios", "IA32_MCi_STATUS"],
    subpatterns={
        DataType.time: [
            r"(?P<time>\d+-\d+-\d+T\d+:\d+:\d+[\w+.:]+)",
        ],
        DataType.decimal: [
            r"SocketID: (?P<socket>\d+)",
            r"CoreID: (?P<core>\d+)",
            r"BankNo: (?P<bank>\d+)",
        ],
        DataType.hexadecimal: [
            f"IA32_MCi_STATUS: (?P<status>{HEX_PATTERN})",
            f"IA32_MCi_ADDR: (?P<address>{HEX_PATTERN})",
            f"IA32_MCi_MISC: (?P<misc>{HEX_PATTERN})",
        ],
    },
)


class MaintenanceMachineCheck(MachineCheckBase):
    apicid: typing.Optional[int] = None


register_parser(MaintenanceMachineCheck, maintenance_pattern)
register_parser(MaintenanceMachineCheck, maintenance_pattern2)
