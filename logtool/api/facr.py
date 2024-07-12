from datetime import datetime

import sqlalchemy as sa
import pydantic

from logtool.api.auth import facr_connection_string

engine = sa.create_engine(facr_connection_string)

query = """
    SELECT evnt_idn AS event_id, 
    issue_number,
    alt_code,
    customer_name,
    endcustomer,
    failure_conditions,
    productfamily,
    [unit original qsc site] AS unit_original_qsc_site,
    [unit receiving qsc site] AS unit_receiving_qsc_site,
    rcvg_qsc_unit_owner,
    original_qsc_owner,
    Cast(created AS datetime) AS created,
    Cast(date_unit_opened AS datetime) AS date_unit_opened,
    Cast(date_unit_received AS datetime) AS date_unit_received,
    Cast(date_unit_closed AS datetime) AS date_unit_closed,
    Cast(date_myfacr_finish AS datetime) AS date_myfacr_finish,
    correlate,
    level_0,
    level_1,
    level_2,
    level_3_comments,
    fail_location
    FROM v_PaeFacrData
"""


class FACR(pydantic.BaseModel):
    issue_number: str
    productfamily: str
    alt_code: str
    event_id: int
    correlate: str | None
    level_0: str | None
    level_1: str | None
    level_2: str | None
    level_3_comments: str | None
    customer_name: str | None
    endcustomer: str | None
    created: datetime
    date_unit_opened: datetime
    date_unit_received: datetime
    date_unit_closed: datetime | None
    date_myfacr_finish: datetime | None
    unit_original_qsc_site: str
    unit_receiving_qsc_site: str
    rcvg_qsc_unit_owner: str
    original_qsc_owner: str | None
    failure_conditions: str
    fail_location: str


class FACRList(pydantic.BaseModel):
    list: list[FACR]


def get_facr():
    with engine.connect() as conn:
        _ = conn.execute(sa.text(query)).all()
    _ = map(lambda d: FACR.model_validate(d._mapping), _)
    return FACRList(list=list(_))
