import pydantic

from logtool.model.interface import ISerializableEvent
from logtool.model.abstract import ISystemEvent


class SystemEvent(pydantic.BaseModel, ISystemEvent, ISerializableEvent):
    model_config = pydantic.ConfigDict(extra="allow")
    raw_hex: str

    @property
    def raw_bytes(self):
        return bytes.fromhex(self.raw_hex)

    @property
    def signature(self):
        return str(self.event)
