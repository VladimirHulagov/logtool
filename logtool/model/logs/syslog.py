import re
from datetime import tzinfo, timezone

import pydantic

from logtool.model.interface import ISerializableParsedLog, IParser, EventSeverity
from logtool.model.logs.mce import syslog_extractors, MachineCheck
from logtool.model.logs.ipmi_sel import IpmiSystemEvent, IpmiSystemEventParser


class Syslog(pydantic.BaseModel, ISerializableParsedLog):
    mcas: list[MachineCheck]
    sel: list[IpmiSystemEvent]

    @property
    def key_events(self):
        return self.mcas + self.sel

    @property
    def _severity(self):
        return max((mca._severity for mca in self.mcas), key=lambda s: s.value, default=EventSeverity.Info)

    @property
    def description(self):
        return f"{len(self.mcas)} Machine Checks, {len(self.sel)} System Events."

    @property
    def signature(self):
        return "Machine Check{}detected. Abnormal System Event{}detected".format(
            " " if len(self.mcas) else " not ",
            " " if not all(
                e._severity is EventSeverity.Info for e in self.sel) else " not "
        )

    @property
    def _time(self):
        return None


class SyslogParser(IParser):
    def __init__(self, sel_tz: tzinfo | None = None):
        self.sel_tz = sel_tz

    def parse_impl(self, syslog: str) -> list[IpmiSystemEvent]:
        res = Syslog(mcas=[], sel=[])
        for parser in syslog_extractors:
            if not parser.check(syslog):
                continue
            mcas = parser.parse(syslog)
            if mcas:
                res.mcas.extend(mcas)
            # if __debug__:
            #     print(parser, len(mcas) if mcas else mcas)
        sel_regex = re.compile(
            r"TAG::BMC SEL LOG\nlist successfully\n(?P<trans>(.*\n)*?)(?>TAG::)")
        rawsel_regex2 = re.compile(
            r"TAG::BMC SEL RAW\nraw data saved successfully\n(?P<raw>(0x.*\n)*)(?P<trans>(.*\n)*?)(?>TAG::)")
        matches = list(sel_regex.finditer(syslog))
        matches2 = list(rawsel_regex2.finditer(syslog))
        if not matches:
            assert not matches2
            return res
        # TODO: Strange spr100k logs with multiple SEL
        # assert len(matches) <= 1, repr(matches[1])
        sel = matches[0].groupdict()["trans"].split("\n") if matches[0] else []
        sel = [s for s in sel if len(s) > 1]
        if matches2:
            sel2 = matches2[0].groupdict()["trans"].split("\n")
            sel_raw = matches2[0].groupdict()["raw"].split("\n")
            sel2 = [s for s in sel2 if len(s) > 1]
            sel_raw = [s for s in sel_raw if len(s) > 1]
        if matches2 and sel2:
            assert sel == sel2
            assert len(sel2) == len(sel_raw)
            res.sel = IpmiSystemEventParser(
                True, self.sel_tz).parse(sel2 + sel_raw)
        else:
            res.sel = IpmiSystemEventParser(False, self.sel_tz).parse(sel)
        return res

    def check_impl(self, syslog: str):
        return "TAG::" in syslog


if __name__ == "__main__":
    sample = """
Handle 0x004F, DMI type 127, 4 bytes
End Of Table

TAG::BMC SEL LOG
list successfully
   1 | 04/15/2023 | 12:45:56 | Event Logging Disabled #0xe3 | Log area reset/cleared | Asserted
   2 | 04/15/2023 | 12:46:36 | System Boot Initiated #0xe5 | Initiated by power up | Asserted
   3 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   4 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   5 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   6 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   7 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   8 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   9 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   a | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   b | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
   c | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
   d | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
   e | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
   f | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  10 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  11 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  12 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  13 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  14 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  15 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  16 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  17 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  18 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  19 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1a | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1b | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1c | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1d | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1e | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1f | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  20 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  21 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  22 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  23 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  24 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  25 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  26 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  27 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  28 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  29 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  2a | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2b | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2c | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2d | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2e | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2f | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  30 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  31 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  32 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  33 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  34 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  35 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  36 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  37 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  38 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  39 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3a | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3b | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3c | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3d | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3e | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
TAG::BMC SEL RAW
raw data saved successfully
0x04 0x10 0xe3 0x6f 0x02 0xff 0xff # Event Logging Disabled #0xe3 Log area reset/cleared
0x04 0x1d 0xe5 0x6f 0x00 0x01 0x00 # System Boot Initiated #0xe5 Initiated by power up
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
0x04 0x0c 0xb2 0x6f 0x00 0xff 0xff # Memory #0xb2 Correctable ECC
   1 | 04/15/2023 | 12:45:56 | Event Logging Disabled #0xe3 | Log area reset/cleared | Asserted
   2 | 04/15/2023 | 12:46:36 | System Boot Initiated #0xe5 | Initiated by power up | Asserted
   3 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   4 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   5 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   6 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   7 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   8 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   9 | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   a | 04/15/2023 | 19:49:31 | Memory #0xb2 | Correctable ECC | Asserted
   b | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
   c | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
   d | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
   e | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
   f | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  10 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  11 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  12 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  13 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  14 | 04/15/2023 | 19:49:32 | Memory #0xb2 | Correctable ECC | Asserted
  15 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  16 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  17 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  18 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  19 | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1a | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1b | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1c | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1d | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1e | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  1f | 04/15/2023 | 19:49:33 | Memory #0xb2 | Correctable ECC | Asserted
  20 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  21 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  22 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  23 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  24 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  25 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  26 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  27 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  28 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  29 | 04/15/2023 | 19:49:34 | Memory #0xb2 | Correctable ECC | Asserted
  2a | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2b | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2c | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2d | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2e | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  2f | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  30 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  31 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  32 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  33 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  34 | 04/15/2023 | 19:49:35 | Memory #0xb2 | Correctable ECC | Asserted
  35 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  36 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  37 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  38 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  39 | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3a | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3b | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3c | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3d | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
  3e | 04/15/2023 | 19:49:36 | Memory #0xb2 | Correctable ECC | Asserted
TAG::MCE LOG
TAG::CPUINFO LOG
"""
    parsed = SyslogParser().parse(sample)
