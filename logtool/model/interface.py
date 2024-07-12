import abc
from datetime import datetime, timezone
import enum
import hashlib
import typing
import pathlib
import inspect
import collections
import functools

import pydantic


# TODO: Take a day, think carefully. What interface should I design?


class EventSeverity(enum.IntEnum):
    Info = 0
    Warning = 1
    Error = 2
    Critical = 3


@functools.total_ordering
class EventView(pydantic.BaseModel):
    time: datetime | None = None
    type: str
    subtype: str | None
    severity: EventSeverity = EventSeverity.Info
    signature: str | None   # TODO: list of signatures for parsed log
    # signatures: list[str] | None = None
    description: str | None
    detail: str | None = None

    @property
    def _sort_time(self):
        return (self.time or datetime.utcfromtimestamp(0)).astimezone(timezone.utc)

    # TODO: Covering SEL ID and type
    def __le__(self, other: "EventView"):
        return self._sort_time < other._sort_time

    def __eq__(self, other: "EventView"):
        return self._sort_time == other._sort_time


# TODO: use typing.Protocol?
class IViewableEvent(abc.ABC):
    @property
    def _time(self):
        """Timestamp of the event. 
        """
        res = None
        if hasattr(self, "time"):
            res = getattr(self, "time")
        elif hasattr(self, "timestamp"):
            res = getattr(self, "timestamp")
        else:
            res = datetime.utcfromtimestamp(0)
            # raise AttributeError("IViewableEvent must provide timestamp")
        if not isinstance(res, datetime) and res is not None:
            raise AttributeError("timestamp must be datetime or None")
        assert isinstance(res, datetime) or res is None
        return res.astimezone(timezone.utc) if res else None

    @property
    @typing.final
    def _type(self):
        """Log type such as Shc or Summary,
        or event type such as MachineCheck or SystemEvent
        """
        # TODO: SystemEvent class as AzureSystemEvent parent class
        # Each event should have an Interface? Or just use a consolid class?
        return type(self).__name__

    @property
    def _subtype(self) -> str | None:
        """Sometimes we need to distinguish events by subtype,
        for example, in syslog we have both EDAC and mcelog as MachineCheck subtype.
        """
        return None

    @property
    def _severity(self) -> EventSeverity:
        return EventSeverity.Info

    @property
    @abc.abstractmethod
    def signature(self) -> str | None:
        """Short string for filtering and querying purpose.
        """
        ...

    @property
    def signatures(self) -> list[str] | None:
        """Short strings for filtering and querying purpose.
        """
        # TODO: obsolete signature. Use signatures.
        return None if self.signature is None else [self.signature]

    @property
    @abc.abstractmethod
    def description(self) -> str | None:
        """Short description for display purpose.
        """
        ...

    @property
    def _detail(self) -> str:
        assert isinstance(self, pydantic.BaseModel)
        return self.model_dump_json(indent=2)

    @property
    def event_index(self):
        return EventView(
            time=self._time,
            type=self._type,
            subtype=self._subtype,
            severity=self._severity,
            signature=self.signature,
            # signatures=self.signatures,
            description=self.description,
            detail=self._detail,
        )


class SerializedEvent(EventView):
    detail: None = None
    sha256: str
    json_content: str

    @property
    def deserialized(self) -> "ISerializableEvent":
        from logtool.model.deserializer import Deserializer
        return Deserializer.deserialize(self.type, self.json_content)


class ISerializableEvent(IViewableEvent):
    # TODO: Do we need that many inheritance? One interface would be enough?
    @property
    def serialized(self):
        assert isinstance(self, pydantic.BaseModel)
        json = self.model_dump_json(indent=None)
        sha256 = hashlib.sha256(json.encode()).hexdigest()
        return SerializedEvent(
            sha256=sha256,
            json_content=json,
            **self.event_index.model_dump(exclude="detail"),
        )


# Such inheritance to allow a log to be list along with events.
class SerializedParsedLog(SerializedEvent):
    @property
    def deserialized(self) -> "ISerializableParsedLog":
        from logtool.model.deserializer import Deserializer
        return Deserializer.deserialize(self.type, self.json_content)


class ISerializableParsedLog(ISerializableEvent):
    @property
    @abc.abstractmethod
    def key_events(self) -> list[ISerializableEvent]:
        ...

    @property
    def all_events(self) -> list[ISerializableEvent]:
        return self.key_events

    @property
    def serialized(self) -> SerializedParsedLog:
        return SerializedParsedLog(**super().serialized.model_dump())


class SerializedException(pydantic.BaseModel, ISerializableParsedLog):
    exp_repr: str
    exp_tb: list[str]

    @staticmethod
    def from_exception(e: Exception):
        import traceback
        return SerializedException(
            exp_repr=repr(e),
            exp_tb=traceback.format_exception(e)
        )

    @property
    def _time(self):
        return None

    @property
    def key_events(self):
        return []

    @property
    def description(self):
        return "".join(self.exp_tb)

    @property
    def _severity(self):
        return EventSeverity.Error

    @property
    def signature(self):
        return self.exp_repr


def _try_decode_bytes(s: bytes):
    # TODO: More accurate file handling
    for encoding in ["utf-8", "utf-16le"]:
        try:
            return s.decode(encoding=encoding)
        except UnicodeDecodeError:
            continue
    import chardet
    encoding = chardet.detect(s)["encoding"]
    if encoding is None:
        return None
    try:
        return s.decode(encoding)
    except UnicodeDecodeError:
        return None


@functools.singledispatch
def _as_bytes(arg) -> bytes:
    raise NotImplementedError


@_as_bytes.register
def _(arg: bytes):
    return arg


@_as_bytes.register
def _(arg: str):
    return arg.encode()


@_as_bytes.register
def _(arg: pathlib.Path):
    with open(arg, "rb") as f:
        return f.read()


@_as_bytes.register
def _(arg: list):
    assert all(isinstance(item, str) for item in arg)
    return _as_bytes("\n".join(arg))


class IParser(abc.ABC):
    @property
    def _path_suffix(self):
        return ""

    @abc.abstractmethod
    def parse_impl(self, input: pathlib.Path | bytes | str | list[str]) -> None | typing.Any:
        ...

    @abc.abstractmethod
    def check_impl(self, input: pathlib.Path | bytes | str | list[str]) -> bool:
        ...

    def _input_type(self, func):
        sig = inspect.signature(func)
        assert len(sig.parameters) == 1
        t = list(sig.parameters.values())[0].annotation
        assert t in [pathlib.Path, bytes, str, list[str]]
        if t == list[str]:
            # TODO: check list[str] instead of list
            return list
        return t

    # TODO: cache conversion result
    def _execute_impl(self, input: pathlib.Path | bytes | str | list[str], cb: typing.Callable):
        input_type = self._input_type(cb)
        content = _as_bytes(input)
        # When filepath input is required, write contents back to temporary file
        if input_type is pathlib.Path:
            if isinstance(input, pathlib.Path):
                return cb(input)
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                fpath = pathlib.Path(tmpdir).joinpath(
                    f"temp{self._path_suffix}")
                with open(fpath, "wb") as f:
                    f.write(content)
                return cb(fpath)
        # When bytes is required, read bytes from file
        if input_type is bytes:
            return cb(content)
        # When string or list of string is required, convert everything to string first
        string = _try_decode_bytes(content)
        if string is None:
            return None
        if input_type is str:
            return cb(string)
        if input_type is list:
            return cb(string.splitlines())

    @typing.final
    def parse(self, input: pathlib.Path | bytes | str | list[str]):
        assert self.check(input)
        return self._execute_impl(input, self.parse_impl)

    @typing.final
    def check(self, input: pathlib.Path | bytes | str | list[str]):
        return self._execute_impl(input, self.check_impl)


class FileMeta(pydantic.BaseModel):
    name: str
    sha256: str


class IFileDescriptor(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...

    @property
    @abc.abstractmethod
    def sha256(self) -> str:
        ...

    @property
    @typing.final
    def metadata(self):
        return FileMeta(name=self.name, sha256=self.sha256)


class TagType(str, enum.Enum):
    PPIN_LIST = enum.auto()
    VID_LIST = enum.auto()
    SN = enum.auto()
    CSP = enum.auto()
    UUID = enum.auto()
    Sha256 = enum.auto()
    Source = enum.auto()


class Tag(pydantic.BaseModel):
    type: TagType
    value: str


class TaggedSystemDetail(pydantic.BaseModel):
    tag: Tag
    logs: list[SerializedEvent]


class TaggedSystemInfo(pydantic.BaseModel):
    tag: Tag
    logs: list[EventView]
    raw_logs: list[str]

    def to_dict(self):
        res = self.tag.model_dump()
        res["logs"] = collections.Counter(log.type for log in self.logs)
        res["detail"] = self.model_dump_json(indent=4, include="logs")
        res["signature"] = "\n".join(
            log.signature for log in self.logs if log.signature)
        return res
