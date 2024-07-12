import typing

from ...base import MachineCheckBase
from ..text_parser import ContentPattern, DataType, HEX_PATTERN
from ..parsers import register_parser

# Hardware event. This is not a software error.
# MCE 0
# CPU 14 BANK 3 TSC 3a4e5b2d79cf56
# RIP !INEXACT! 10:ffffffff810aa000
# TIME 1537488718 Fri Sep 21 08:11:58 2018
# MCG status:RIPV MCIP
# MCi status:
# Uncorrected error
# Error enabled
# Processor context corrupt
# MCA: Internal parity error
# STATUS b200000000400005 MCGSTATUS 5
# MCGCAP f000c14 APICID 24 SOCKETID 0
# CPUID Vendor Intel Family 6 Model 85

# Hardware event. This is not a software error.
# MCE 1
# CPU 0 BANK 9
# MISC 900004000400a8c ADDR 912c41000
# TIME 1656046378 Fri Jun 24 12:52:58 2022
# MCG status:
# MCi status:
# Corrected error
# MCi_MISC register valid
# MCi_ADDR register valid
# MCA: MEMORY CONTROLLER MS_CHANNEL0_ERR
# Transaction: Memory scrubbing error
# MemCtrl: Corrected patrol scrub error
# STATUS 8c000045000800c0 MCGSTATUS 0
# MCGCAP 1000c16 APICID 0 SOCKETID 0
# PPIN 8c000045000800c0
# CPUID Vendor Intel Family 6 Model 86
# Running trigger `dimm-error-trigger'


mcelog_pattern = ContentPattern(
    pattern=r"Hardware event(.*\n){1,20}STATUS.*(((?!(Hardware event.*|TAG::.*|warning: 8 bytes ignored in each record))(.*\n)){1,10})",
    keywords=["Hardware event. This is not a software error."],
    subpatterns={
        DataType.decimal: [
            r"CPU (?P<core>\d+)",
            r"BANK (?P<bank>\d+)",
            r"APICID (?P<apicid>\d+)",
            r"SOCKETID (?P<socket>\d+)",
        ],
        DataType.time: [
            r"TIME (?P<time>\d+)",
        ],
        DataType.hexadecimal: [
            f"TSC (?P<tsc>{HEX_PATTERN})",
            f"MISC (?P<misc>{HEX_PATTERN})",
            f"ADDR (?P<address>{HEX_PATTERN})",
            f"STATUS (?P<status>{HEX_PATTERN})",
            f"PPIN (?P<ppin>{HEX_PATTERN})",
            f"MICROCODE (?P<ucode>{HEX_PATTERN})",
        ],
        DataType.string: [
            r"(?P<cpuid>CPUID.*)",
        ]
    }
)

# Mar  8 17:09:52 localhost mcelog[7922]: Hardware event. This is not a software error.
# Mar  8 17:09:52 localhost mcelog[7922]: MCE 0
# Mar  8 17:09:52 localhost mcelog[7922]: CPU 140 BANK 3 TSC 1cf5ffe0a0cf
# Mar  8 17:09:52 localhost mcelog[7922]: MISC 3ca4285 ADDR af69aad80
# Mar  8 17:09:52 localhost mcelog[7922]: TIME 1678266591 Wed Mar  8 17:09:51 2023
# Mar  8 17:09:52 localhost mcelog[7922]: MCG status:
# Mar  8 17:09:52 localhost mcelog[7922]: MCi status:
# Mar  8 17:09:52 localhost mcelog[7922]: Corrected error
# Mar  8 17:09:52 localhost mcelog[7922]: MCi_MISC register valid
# Mar  8 17:09:52 localhost mcelog[7922]: MCi_ADDR register valid
# Mar  8 17:09:52 localhost mcelog[7922]: Threshold based error status: green
# Mar  8 17:09:52 localhost mcelog[7922]: MCA: corrected filtering (some unreported errors in same region)
# Mar  8 17:09:52 localhost mcelog[7922]: Generic CACHE Level-1 Eviction Error
# Mar  8 17:09:52 localhost mcelog[7922]: STATUS 8c20004000101179 MCGSTATUS 0
# Mar  8 17:09:52 localhost mcelog[7922]: MCGCAP f000c15 APICID 59 SOCKETID 0
# Mar  8 17:09:52 localhost mcelog[7922]: PPIN 8c82c32a176cafd0
# Mar  8 17:09:52 localhost mcelog[7922]: MICROCODE 2b000161
# Mar  8 17:09:52 localhost mcelog[7922]: CPUID Vendor Intel Family 6 Model 143 Step 8

dmesg_mcelog_pattern = ContentPattern(
    pattern=r"mcelog.*Hardware event. This is not a software error.((?!CPUID)[\s\S])*CPUID.*",
    keywords=["Hardware event. This is not a software error.", "mcelog"],
    subpatterns=mcelog_pattern.subpatterns,
)

# https://github.com/andikleen/mcelog/blob/23c24878c2e004f360575d564b825753212a09e5/mcelog.c#L317


class McelogMachineCheck(MachineCheckBase):
    tsc: typing.Optional[int] = None
    ucode: typing.Optional[int] = None
    ppin: typing.Optional[int] = None
    apicid: typing.Optional[int] = None
    cpuid: str

    @property
    def _hex_fields(self):
        return super()._hex_fields + ["tsc", "ucode", "ppin"]


register_parser(McelogMachineCheck, mcelog_pattern)
register_parser(McelogMachineCheck, dmesg_mcelog_pattern)
