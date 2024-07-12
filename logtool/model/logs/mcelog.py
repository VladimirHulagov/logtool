import re
import csv
import pathlib
import itertools
import datetime
from typing import Annotated

import pydantic

from logtool.model.interface import IParser, ISerializableParsedLog, EventSeverity, ISerializableEvent
from logtool.model.abstract import IMachineCheck

_HexInt = Annotated[int | None, pydantic.BeforeValidator(
    lambda s: int(s, 16) if isinstance(s, str) else s)]


class McelogMachineCheck(pydantic.BaseModel, IMachineCheck, ISerializableEvent):
    # model_config = pydantic.ConfigDict(extra="allow")

    time: datetime.datetime = pydantic.Field(
        validation_alias=pydantic.AliasChoices("time", "datetime")
    )
    status: _HexInt
    bank: int
    misc: _HexInt
    socket: int = pydantic.Field(
        validation_alias=pydantic.AliasChoices("socket", "socketid")
    )
    core: int = pydantic.Field(
        validation_alias=pydantic.AliasChoices("core", "cpu")
    )
    address: _HexInt | None = pydantic.Field(
        validation_alias=pydantic.AliasChoices("addr", "address"))

    def model_post_init(self, _):
        if not self.address_valid:
            self.address = None
        if not self.misc_valid:
            self.misc = None

    @property
    def mc_status(self):
        return self.status

    @property
    def description(self):
        return f"Socket {self.socket} Core {self.core} Bank {self.bank} Status {hex(self.status)}"

    @property
    def _subtype(self):
        return "mcelog"

    @property
    def signature(self):
        return hex(self.status)


class ByteDanceMcelog(pydantic.BaseModel, ISerializableParsedLog):
    mces: list[tuple[str, list[McelogMachineCheck]]]

    @property
    def key_events(self):
        return list(itertools.chain(*(mces for ip, mces in self.mces)))

    @property
    def all_events(self):
        return self.key_events

    @property
    def _time(self):
        return min(mce.time for mce in self.key_events)

    @property
    def description(self):
        return f"{len(self.mces)} Systems {sum(len(mces) for ip, mces in self.mces)} Events"

    @property
    def _severity(self):
        return EventSeverity.Warning
        # return max((e._severity for e in self.system_events), key=lambda e: e.value, default=EventSeverity.Info)

    @property
    def signature(self):
        return None
        return ", ".join(sorted(self.signatures))

    @property
    def signatures(self):
        return None
        _ = set(e.event for e in self.key_events)
        _ = filter(None, _)
        _ = map(str, _)
        return list(_)


class ByteDanceMcelogParser(IParser):
    def parse_impl(self, fpath: pathlib.Path):
        logs: dict[str, list[McelogMachineCheck]] = {}
        with open(fpath) as f:
            csv_dict_reader = csv.DictReader(f)
            for row in csv_dict_reader:
                ipv6 = row["ipv6"]
                if ipv6 not in logs:
                    logs[ipv6] = []
                logs[ipv6].append(McelogMachineCheck.model_validate(row))
        return ByteDanceMcelog(mces=list(logs.items()))

    def check_impl(self, text: str):
        return "mce,cpu,socketid,apicid,cpu_type,bank,bank_name,addr,addr_name,misc,status" in text[:100]
