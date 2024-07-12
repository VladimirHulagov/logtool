from ...base import MachineCheckBase
from ..text_parser import ContentPattern, DataType, HEX_PATTERN
from ..parsers import register_parser

# ---------------------------------------------------------------
# Start = DIAG
# DIAG 4 found
# timestamp = 2023-03-18 19:41:38
# diagnosis_vers = 0x34 (52)
# error_type = 0x3 (3)
# MCA Info

# DataResource = 0x1 (1)
# SerialNumber = 0x2e (46)
# SocketID = 0x1 (1)
# IerrDetectSkt = 0x0 (0)
# CoreID = 0x2f (47)
# BankNum = 0x3 (3)
# UpiPort = 0xff (255)
# CoreThreadCount = 0x300060 (3145824)
# MsrThreadSmiErrSrc = 0x0 (0)
# MsrMcgContain = 0x1 (1)
# Ia32McgCap = 0xf000c15 (251661333)
# Ia32McgStatus = 0x0 (0)
# CoreSmiErrSrc = 0x8 (8)
# UnCoreSmiErrSrc = 0x0 (0)
# ErrorControl = 0x0 (0)
# McaControl = 0x7f (127)
# McaControl2 = 0x540000001 (22548578305)
# McaStatus = 0x8c4003c000100135 (10106081686989046069)
# McaAddr = 0x8086bbd000 (552016269312)
# McaMisc = 0x9812285 (159457925)
# IerrLoggingReg = 0x0 (0)
# McerrLoggingReg = 0x0 (0)
# EmcaCoreCsmiLog = 0x0 (0)
# EmcaCoreCsmiLog1 = 0x2000000 (33554432)
# EmcaCoreMsmiLog = 0x0 (0)
# EmcaCoreMsmiLog1 = 0x0 (0)
# SmiCtrl = 0x6000000 (100663296)
# McaErrorSrcLog = 0x0 (0)
# SmiSrcLog = 0x0 (0)
# ---------------------------------------------------------------

venus_pattern = ContentPattern(
    pattern=r"----\n((?!----)[\s\S])*MCA Info((?!----)[\s\S])*",
    keywords=["Start = DIAG"],
    subpatterns={
        DataType.time: [
            r"timestamp = (?P<time>.*)",
        ],
        DataType.hexadecimal: [
            f"SocketID = (?P<cpuid>{HEX_PATTERN})",
            f"CoreID = (?P<core>{HEX_PATTERN})",
            f"BankNum = (?P<bank>{HEX_PATTERN})",
            f"McaStatus = (?P<status>{HEX_PATTERN})",
            f"McaAddr = (?P<address>{HEX_PATTERN})",
            f"McaMisc = (?P<misc>{HEX_PATTERN})",
        ],
    },
)


class VenusMachineCheck(MachineCheckBase):
    pass


register_parser(VenusMachineCheck, venus_pattern)
