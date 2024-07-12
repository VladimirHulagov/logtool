import requests
import urllib3
from datetime import datetime
from typing import Literal
from typing_extensions import Annotated

import pydantic

from logtool.api.auth import catts_auth


class CatsTca(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")
    batch: str = pydantic.Field(validation_alias=pydantic.AliasChoices("BATCH", "batch"))
    facility: str = pydantic.Field(validation_alias=pydantic.AliasChoices("FACILITY", "facility"))
    finish_datetime: datetime = pydantic.Field(validation_alias=pydantic.AliasChoices("FINISH_DATE_TIME", "finish_datetime"))
    ppin: Annotated[
        int,
        pydantic.BeforeValidator(
            lambda v: int(v, 16) if isinstance(v, str) else v
        ),
        pydantic.Field(validation_alias=pydantic.AliasChoices("FUSE_PART_ID", "ppin"))
    ]
    material_id: str = pydantic.Field(validation_alias=pydantic.AliasChoices("MTRL_ID", "material_id"))
    product: str = pydantic.Field(validation_alias=pydantic.AliasChoices("PRODUCT", "product"))
    family: str = pydantic.Field(validation_alias=pydantic.AliasChoices("PROD_FAMILY", "family"))
    tray_box_id: str = pydantic.Field(validation_alias=pydantic.AliasChoices("TRAY_BOX_ID", "tray_box_id"))
    vid: str = pydantic.Field(validation_alias=pydantic.AliasChoices("VISUAL_ID", "vid"))


class CatsTcaList(pydantic.BaseModel):
    list: list[CatsTca]


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app_name = "FMTOOL"
user_id = "FMTOOL"
catts_url = "https://atdccattsnlb.ch.intel.com/CATTSWebService/CATTSRESTWebService.svc"

HEADERS = {'Content-Type': 'application/octet-stream'}  # set headers

_xml_template = (
    '<?xml version="1.0" encoding="utf-16"?>'
    f'<CattsTcaServiceRequest ApplicationName="{app_name}" UserId="{user_id}" SubOperationName="AdvancedDBSearchRequest">'
    '<ReportName>Query FPO Unit Details</ReportName>'
    '<InputData>'
    '{}'
    '</InputData>'
    '</CattsTcaServiceRequest>'
)


def _batch_query_impl(input_type: Literal["Fuse Part ID", "Visual ID"], items: list[str]):
    lines = [
        f'<InputDataItem type="{input_type}">{item}</InputDataItem>' for item in items]
    xml = _xml_template.format("\n".join(lines))
    res = requests.post(catts_url, data=xml, verify=False,
                        auth=catts_auth, timeout=900)
    assert res.status_code == 200
    text = res.text
    assert "<IsTransactionSuccess>true</IsTransactionSuccess>" in text, text
    import xmltodict
    _ = map(
        CatsTca.model_validate,
        xmltodict.parse(text).get("CattsTcaOutputDataSet", {}).get("Table", [])
    )
    return list(_)


def query_by_ppins(ppins: list[int]):
    ppins = [hex(ppin)[2:].upper() for ppin in ppins]
    return _batch_query_impl("Fuse Part ID", ppins)


def query_by_vids(vids: list[str]) -> list:
    return _batch_query_impl("Visual ID", vids)


if __name__ == "__main__":
    ppins = [
        0xbb52af276b8f082a,
        0xbb81a7275d557392,
    ]
    tcas = query_by_ppins(ppins)
    tcas2 = query_by_vids(list(tca.vid for tca in tcas))

    print(tcas)
    print(tcas2)
    import pathlib
    with open(pathlib.Path(r"/home/shizy/logtool/logtool/api/vids.txt")) as f:
        vids = f.read().splitlines()
    tcas2 = query_by_vids(vids)
    print(tcas2)
    res = CatsTcaList(list=tcas2)
    with open(pathlib.Path(r"/home/shizy/logtool/logtool/api/vids.json"), "w") as f:
        f.write(res.model_dump_json(indent=4))
