import typing

from ...base import MachineCheckBase, DimmFailureLocation
from ..text_parser import ContentPattern, DataType, HEX_PATTERN
from ..parsers import register_parser

# [Sat Apr 15 19:49:46 2023] EDAC skx MC0: HANDLING MCE MEMORY ERROR
# [Sat Apr 15 19:49:46 2023] EDAC skx MC0: CPU 0: Machine Check Event: 0x0 Bank 255: 0x940000000000009f
# [Sat Apr 15 19:49:46 2023] EDAC skx MC0: TSC 0x0
# [Sat Apr 15 19:49:46 2023] EDAC skx MC0: ADDR 0x30aa905a80
# [Sat Apr 15 19:49:46 2023] EDAC skx MC0: MISC 0x0
# [Sat Apr 15 19:49:46 2023] EDAC skx MC0: PROCESSOR 0:0x806f8 TIME 1681559382 SOCKET 0 APIC 0x0
# [Sat Apr 15 19:49:46 2023] EDAC MC0: 0 CE memory read error on CPU_SrcID#0_MC#0_Chan#1_DIMM#0 (channel:1 slot:0 page:0x30aa905 offset:0xa80 grain:32 syndrome:0x0 -  err_code:0x0000:0x009f  SystemAddress:0x30aa905a80 ProcessorSocketId:0x0 MemoryControllerId:0x0 ChannelAddress:0x605520980 ChannelId:0x1 RankAddress:0x181548240 PhysicalRankId:0x1 DimmSlotId:0x0 DimmRankId:0x1 Row:0x442a Column:0x440 Bank:0x1 BankGroup:0x1 ChipSelect:0x2)

# [Sat Nov 25 23:16:49 2023] mce: [Hardware Error]: Machine check events logged
# [Sat Nov 25 23:16:49 2023] EDAC skx MC1: HANDLING MCE MEMORY ERROR
# [Sat Nov 25 23:16:49 2023] EDAC skx MC1: CPU 0: Machine Check Event: 0x0 Bank 15: 0x8c00004200800090
# [Sat Nov 25 23:16:49 2023] EDAC skx MC1: TSC 0x95f2e5afe67
# [Sat Nov 25 23:16:49 2023] EDAC skx MC1: ADDR 0x91b2f55c0
# [Sat Nov 25 23:16:49 2023] EDAC skx MC1: MISC 0xd001a213d905086
# [Sat Nov 25 23:16:49 2023] EDAC skx MC1: PROCESSOR 0:0x806f8 TIME 1700925409 SOCKET 0 APIC 0x0
# [Sat Nov 25 23:16:49 2023] EDAC DEBUG: skx_mce_output_error:  err_code:0x0080:0x0090  SystemAddress:0x91b2f55c0 ProcessorSocketId:0x0 MemoryControllerId:0x1 ChannelAddress:0x11365eac0 ChannelId:0x0 RankAddress:0x226cbd40 PhysicalRankId:0x0 DimmSlotId:0x1 DimmRankId:0x0 Row:0x27b2 Column:0xa0 Bank:0x0 BankGroup:0x5 ChipSelect:0x5
# [Sat Nov 25 23:16:49 2023] EDAC MC1: 1 CE memory read error on CPU_SrcID#0_MC#1_Chan#0_DIMM#1 (channel:0 slot:1 page:0x91b2f5 offset:0x5c0 grain:32 syndrome:0x0 -  err_code:0x0080:0x0090  SystemAddress:0x91b2f55c0 ProcessorSocketId:0x0 MemoryControllerId:0x1 ChannelAddress:0x11365eac0 ChannelId:0x0 RankAddress:0x226cbd40 PhysicalRankId:0x0 DimmSlotId:0x1 DimmRankId:0x0 Row:0x27b2 Column:0xa0 Bank:0x0 BankGroup:0x5 ChipSelect:0x5)

edac_pattern = ContentPattern(
    pattern=r"EDAC.*HANDLING MCE MEMORY ERROR((?!PROCESSOR)[\s\S])*PROCESSOR.*((\n.*){1,3}CPU_SrcID.*)?",
    keywords=["HANDLING MCE MEMORY ERROR"],
    subpatterns={
        DataType.decimal: [
            r"CPU_SrcID#(?P<socket>\d+)_(MC|Ha)#(?P<imc>\d+)_Chan#(?P<channel>\d+)_DIMM#(?P<slot>\d+)",
            r"CPU (?P<core>\d+)",
            r"Bank (?P<bank>\d+)",
            r"SOCKET (?P<socket>\d+)",
        ],
        DataType.time: [
            r"TIME (?P<time>\d+)",
        ],
        DataType.hexadecimal: [
            f"Bank \d+: (?P<status>{HEX_PATTERN})",
            f"TSC (?P<tsc>{HEX_PATTERN})",
            f"ADDR (?P<address>{HEX_PATTERN})",
            f"MISC (?P<misc>{HEX_PATTERN})",
            f"PROCESSOR \d+:(?P<cpuid>{HEX_PATTERN})",
            # TODO: Figure out the difference between APIC and Core
            f"APIC (?P<apicid>{HEX_PATTERN})",
        ],
    },
    neglect_dup=True,
)


class EdacMachineCheck(MachineCheckBase):
    imc: typing.Optional[int] = None
    channel: typing.Optional[int] = None
    slot: typing.Optional[int] = None
    tsc: int
    cpuid: int
    apicid: int

    @property
    def _hex_fields(self):
        return super()._hex_fields + ["cpuid", "tsc"]

    @property
    def dimm_location(self):
        # TODO: Use override decorator or something
        assert super().dimm_location is None
        if not all(isinstance(f, int) for f in [self.socket, self.imc, self.channel, self.slot]):
            return None
        return DimmFailureLocation(
            socket=self.socket,
            imc=self.imc,
            channel=self.channel,
            slot=self.slot,
        )


register_parser(EdacMachineCheck, edac_pattern)
