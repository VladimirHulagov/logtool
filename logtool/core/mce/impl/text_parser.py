import re
import enum
import functools
import operator
import typing
from datetime import datetime

import pydantic


class PydanticDatetime(pydantic.BaseModel):
    t: datetime


class TimestampParser:
    @classmethod
    def parse(cls, timestamp: str):
        ts = timestamp.replace(",", " ").replace("_", "T")
        try:
            return PydanticDatetime.model_validate({"t": ts}).t
        except pydantic.ValidationError:
            from dateutil import parser as dtparser
            return dtparser.parse(ts)


HEX_PATTERN = r"((0x)?[0-9a-fA-F]+)"


class DataType(enum.Enum):
    string = enum.auto()
    decimal = enum.auto()
    hexadecimal = enum.auto()
    time = enum.auto()
    timestamp = enum.auto()
    bool = enum.auto()


class ContentPattern(pydantic.BaseModel):
    pattern: str
    subpatterns: typing.Dict[DataType, typing.List[str]]
    # When we neglect duplicate fields by intention,
    # we must put that pattern in the same list of subpattern in the first place.
    neglect_dup: bool = False
    # Filter whole text by keywords to ignore irrelevant logs
    keywords: typing.List[str] = []


class Matcher:
    converters = {
        DataType.string: str,
        DataType.decimal: int,
        DataType.hexadecimal: functools.partial(int, base=16),
        DataType.time: TimestampParser.parse,
        DataType.timestamp: lambda ts: datetime.fromtimestamp(int(ts)),
        DataType.bool: bool,
    }

    def __init__(self, dt: DataType, ptn: str):
        self.cvt = self.converters[dt]
        self.regex = re.compile(ptn)

    def search(self, text: str):
        self.matched = self.regex.search(text)
        return self if self.matched else None

    def convert(self) -> typing.Dict[str, typing.Union[str, int, datetime]]:
        assert self.matched
        return {
            k: self.cvt(v)
            for k, v in self.matched.groupdict().items() if v is not None
        }


_T1 = typing.TypeVar("_T1")
_T2 = typing.TypeVar("_T2")


def _dict_merge(dicts: typing.Iterable[typing.Dict[_T1, _T2]], neglect_dup: bool) -> typing.Dict[_T1, _T2]:
    if __debug__:
        res = {}
        ld = list(dicts)
        for d in ld:
            for k, v in d.items():
                if k in res:
                    assert res[k] == v or neglect_dup
                res[k] = v
    else:
        res = functools.reduce(operator.or_, dicts)
    return res


class TextParser():
    def __init__(self, p: ContentPattern):
        self.pattern = p
        self.regex = re.compile(p.pattern)
        self.reg_dict = [
            Matcher(dt, ptn)
            for dt, ls in p.subpatterns.items()
            for ptn in ls
        ]

    def try_parse(self, text: str):
        if not self.regex.search(text):
            return None
        _ = map(lambda p: p.search(text), self.reg_dict)
        _ = filter(None, _)
        _ = map(lambda m: m.convert(), _)
        res = _dict_merge(_, self.pattern.neglect_dup)
        assert res
        return res

    def bulk_parse(self, text: str):
        if not all(kw in text for kw in self.pattern.keywords):
            text = ""
        _ = self.regex.finditer(text)
        _ = map(lambda m: m.group(), _)
        _ = map(self.try_parse, _)
        _ = list(_)
        assert all(r is not None for r in _)
        _ = filter(None, _)
        return list(_)
