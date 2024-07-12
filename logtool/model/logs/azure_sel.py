import re
import pathlib
from typing import Annotated

import pydantic

from logtool.model.interface import ISerializableParsedLog, IParser, EventSeverity
from logtool.model.logs.sel import SystemEvent


class AzureSystemEvent(SystemEvent):
    extra_detail: dict[str, str]
    raw_hex: Annotated[
        str,
        pydantic.BeforeValidator(
            lambda b: b if isinstance(b, str) and re.match(r"[0-9a-f]{16}", b.lower())
            else None
        ),
    ]

    @property
    def event_message(self) -> str:
        return self.extra_detail["EventDataDetails1"].strip()


class AzureSel(pydantic.BaseModel, ISerializableParsedLog):
    system_events: list[AzureSystemEvent]

    @property
    def key_events(self):
        return [e for e in self.system_events if e._severity.value > EventSeverity.Info]

    @property
    def all_events(self):
        return self.system_events

    @property
    def _time(self):
        return self.system_events[0].timestamp if self.system_events else None

    @property
    def description(self):
        return f"{len(self.system_events)} System Events"

    @property
    def _severity(self):
        return max((e._severity for e in self.system_events), key=lambda e: e.value, default=EventSeverity.Info)

    @property
    def signature(self):
        return ", ".join(sorted(self.signatures))

    @property
    def signatures(self):
        _ = set(e.event for e in self.key_events)
        _ = filter(None, _)
        _ = map(str, _)
        return list(_)


class AzureSelParser(IParser):
    def parse_impl(self, lines: list[str]):
        title_lines = [l for l in lines if "RawHex" in l]
        assert len(title_lines) == 1
        titles = list(filter(None, title_lines[0].split()))
        pos = [title_lines[0].find(t) for t in titles]

        def parse_line(l: str):
            res: dict[str, str] = {}
            for title, start, end in zip(titles, pos, pos[1:]):
                res[title] = l[start:end]
            raw = res["RawHex"]
            res.pop("RawHex")
            e = AzureSystemEvent(
                extra_detail=res,
                raw_hex=raw.replace(" ", "").strip()
            )
            return e
        pos.append(2000)    # Large enough to cover end of everyline
        regex = re.compile("\d+/\d+/\d+ \d+:\d+:\d+ .*")
        _ = filter(regex.match, lines)
        _ = map(parse_line, _)
        return AzureSel(system_events=list(_))

    def check_impl(self, lines: list[str]):
        return any(("BMCSelTimestamp" in l) and ("RawHex" in l) for l in lines)
