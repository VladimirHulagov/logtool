import pydantic

from logtool.model.interface import SerializedEvent, ISerializableEvent, SerializedException

from logtool.model.logs.azure_sel import AzureSel, AzureSystemEvent
from logtool.model.logs.mcelog import ByteDanceMcelog, ByteDanceMcelogParser
from logtool.model.logs.mce import MachineCheck
from logtool.model.logs.shc import ShcReport
from logtool.model.logs.summary import Summary
from logtool.model.logs.syslog import Syslog
from logtool.model.logs.fhm import FmtoolSyslogResult, FmtoolAcdResult


class Deserializer():
    _cls_map: dict[str, type[pydantic.BaseModel]] = {}

    @classmethod
    def register(cls, subclass: type[pydantic.BaseModel]):
        # TODO: Automatic registeration
        cls._cls_map[subclass.__name__] = subclass

    @classmethod
    def deserialize(cls, type: str, json_content: str) -> ISerializableEvent:
        res = cls._cls_map[type].model_validate_json(json_content)
        return res


for t in [
    AzureSystemEvent,
    AzureSel,
    MachineCheck,
    ShcReport,
    Summary,
    Syslog,
    FmtoolSyslogResult,
    FmtoolAcdResult,
    SerializedException,
    ByteDanceMcelog,
]:
    Deserializer.register(t)
