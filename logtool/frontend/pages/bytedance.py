import pathlib

import streamlit as st
import pandas as pd
import pydantic

import csv

from logtool.model.logs.mcelog import ByteDanceMcelog, ByteDanceMcelogParser, McelogMachineCheck

st.set_page_config(layout="wide")


class SnTable(pydantic.BaseModel):
    IP: str
    SN: str


sns: list[SnTable] = []
# @st.cache_data


def get_sn_table():
    with open(pathlib.Path(__file__).parent.joinpath("bytedance_spr_sn_ipv6.csv")) as f:
        for row in csv.DictReader(f):
            sns.append(SnTable.model_validate(row))


st.dataframe(map(lambda t: t.model_dump(), sns))


@st.cache_data
def parse_log(logpath: pathlib.Path) -> ByteDanceMcelog:
    return ByteDanceMcelogParser().parse(logpath)


class MachineSummary(pydantic.BaseModel):
    ipv6: str
    mces: list[McelogMachineCheck]

    @pydantic.computed_field
    @property
    def count(self) -> int:
        return len(self.mces)

    @pydantic.computed_field
    @property
    def any_ue(self) -> bool:
        return any(mce.uncorrected for mce in self.mces)

    @pydantic.computed_field
    @property
    def signatures(self) -> list[str]:
        errcods = set(mce.mc_status & 0xFFFF_FFFF for mce in self.mces)
        return [hex(c) for c in errcods]


logs: dict[str, MachineSummary] = {}

for log in pathlib.Path("/home/shizy/logs/FleetHealthManagement/Raw/Bytedance/2024/20240227_mcelog/").glob("*"):
    for ipv6, mces in parse_log(log).mces:
        if ipv6 not in logs:
            logs[ipv6] = MachineSummary(ipv6=ipv6, mces=[])
        logs[ipv6].mces.extend(mces)

st.dataframe(map(lambda m: m.model_dump(exclude=("mces",)), logs.values()))

log = st.selectbox("Select ipv6", logs.items(),
                   format_func=lambda kv: kv[0])[1]
data = list(map(lambda a: a.model_dump(), log.mces))
for d in data:
    for k in ["status", "misc", "address"]:
        d[k] = hex(d[k]) if d[k] else d[k]
st.dataframe(data)
