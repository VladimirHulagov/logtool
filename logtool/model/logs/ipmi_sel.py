import pathlib
from pathlib import Path
import re
from typing import Annotated
from dateutil import parser as dtparser
from datetime import tzinfo, timezone, datetime


import pydantic

from logtool.model.interface import ISerializableEvent, IParser
from logtool.model.logs.sel import SystemEvent


def _get_ipmi_sel_translate_table():
    _ipmi_sel_entry_pattern = re.compile(
        r"\{ *"
        r"(?P<sensor_type>0x[0-9a-fA-F]{2}), *"
        r"(?P<sensor_offset>0x[0-9a-fA-F]{2}), *"
        r"(?P<event_data2>0x[0-9a-fA-F]{2}), *"
        r'"(?P<event_message>[^"]*)" *'
        r"\}"
    )
    _ipmi_sel_translate_table: dict[str, tuple[int, int, int]] = {}
    with open(pathlib.Path(__file__).parent.joinpath("ipmi_sel2.h")) as f:
        _ = map(lambda l: list(_ipmi_sel_entry_pattern.finditer(l)), f)
        _ = filter(None, _)
        for r in _:
            r: list[re.Match]
            assert len(r) == 1
            d: dict[str, str] = r[0].groupdict()
            sensor_type = int(d["sensor_type"], 16)
            sensor_offset = int(d["sensor_offset"], 16)
            event_data2 = int(d["event_data2"], 16)
            event_message = d["event_message"].strip()
            if event_message in _ipmi_sel_translate_table:
                # No unique translation, translate to garbage
                _ipmi_sel_translate_table[event_message] = (0xFF, 0xFF, 0xFF)
            else:
                _ipmi_sel_translate_table[event_message] = (
                    sensor_type, sensor_offset, event_data2)
    return _ipmi_sel_translate_table


class IpmiSystemEvent(SystemEvent):
    raw_hex: str
    raw: str

    @property
    def event_message(self):
        return "|".join(self.raw.split("|")[-3:])

# TODO: use string as input, combine TAG::BMC SEL RAW with TAG::BMC SEL Log
# TODO: There are logs contain two copies of SEL. Investigate reason and handle that.


class IpmiSystemEventParser(IParser):
    table = _get_ipmi_sel_translate_table()

    def __init__(self, with_raw: bool, tz: tzinfo | None = None):
        self.with_raw = with_raw
        self.tz = tz

    def _translate(self, row: str):
        splitted = row.split("|")
        id = int(splitted[0], 16)
        ts = " ".join(splitted[1:3])
        ts = (dtparser.parse(
            ts) if "Pre-Init" not in ts else datetime.fromtimestamp(0)).astimezone(self.tz)
        msg1 = splitted[3].strip()
        msg2 = splitted[4].strip()
        asserted = splitted[5].strip()
        dir = 0 if (asserted == "Asserted") else (
            1 if (asserted == "Deasserted") else None)
        assert dir is not None
        # message translate back
        # TODO: enhance translation
        st, so, d2 = self.table.get(msg2, (0xFF, 0xFF, 0xFF))
        res = bytes()
        # record_id
        res += id.to_bytes(2, "little")
        # record_type
        res += (0xFF).to_bytes(1, "little")
        # timestamp
        res += int(ts.timestamp()).to_bytes(4, "little")
        # generator_id and rev
        res += (0xFFFFFF).to_bytes(3, "little")
        # sensor_type
        res += st.to_bytes(1, "little")
        # sensor_number
        res += (0xFF).to_bytes(1, "little")
        # event_direction and event_type
        res += (0xFF & (dir << 7)).to_bytes(1, "little")
        # sensor_offset
        res += so.to_bytes(1, "little")
        # oem_data2?
        res += d2.to_bytes(1, "little")
        # oem_data3
        res += (0xFF).to_bytes(1, "little")
        assert len(res) == 16
        return res

    def _translate_raw(self, raw: str):
        assert "#" in raw
        ss = raw.split("#")[0].strip().split(" ")
        assert len(ss) == 7
        bs = [int(s, 16).to_bytes(1, byteorder="little") for s in ss]
        return b"".join(bs)

    def _parse(self, param: tuple[str, str | None]):
        line, raw = param
        try:
            assert line.count("|") == 5, line
            trans = self._translate(line)
            if raw:
                bs = self._translate_raw(raw)
                # bs2 = trans[9:]
                # assert all(b2 == (0xFF).to_bytes(1, "little")
                #            or b1 == b2 for b1, b2 in zip(bs, bs2)), f"{line} {raw}"
                trans = trans[:9] + bs
        except Exception:
            trans = (0xFF).to_bytes(1, byteorder="little") * 16
        return trans, line

    def parse_impl(self, input: list[str]):
        if self.with_raw:
            pos = len(input)//2
            _ = zip(input[:pos], input[pos:])
        else:
            _ = zip(input, [None for _ in range(len(input))])
        _ = map(self._parse, _)
        _ = filter(None, _)
        _ = map(lambda tup: IpmiSystemEvent(
            raw_hex=tup[0].hex(), raw=tup[1]), _)
        return list(_)

    def check_impl(self, input: list[str]):
        return True


if __name__ == "__main__":
    sels = [
        "1 | 04/16/2011 | 06:12:40 | Event Logging Disabled SEL | Log area reset/cleared | Asserted",
        "2 | 04/16/2011 | 06:20:33 | Memory #0x87 | Correctable ECC | Asserted",
        "3 | 04/16/2011 | 06:28:54 | Memory #0x87 | Correctable ECC | Asserted",
        "4 | 04/16/2011 | 06:36:11 | Memory #0x87 | Correctable ECC | Asserted",
        "1 | 01/19/24 | 01:33:52 | Event Logging Disabled SEL_Status | Log area reset/cleared | Asserted",
        "2 | 01/22/24 | 02:29:09 | System Boot Initiated BIOS_Boot_Up | Initiated by power up | Asserted",
        "3 | 01/22/24 | 02:38:01 | System ACPI Power State ACPI_PWR_Status | S4/S5: soft-off | Asserted",
        "4 | 01/22/24 | 03:16:44 | System ACPI Power State ACPI_PWR_Status | S0/G0: working | Asserted",
        "5 | 01/22/24 | 03:18:05 | System Boot Initiated BIOS_Boot_Up | Initiated by power up | Asserted",
        "6 | 01/22/24 | 07:39:39 | System ACPI Power State ACPI_PWR_Status | S4/S5: soft-off | Asserted",
    ]

    events: list[IpmiSystemEvent] = IpmiSystemEventParser().parse(sels)
    for e in events:
        # print(e)
        print(e.record_id, e.timestamp, e.event, e.event_dir, e.event_message)
