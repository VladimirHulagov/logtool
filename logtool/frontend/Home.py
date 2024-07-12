from collections import Counter

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

from logtool.model.interface import (
    EventView,
    EventSeverity,
    TaggedSystemDetail,
    TaggedSystemInfo,
    TagType,
    Tag,
    IViewableEvent
)
from logtool.model.abstract import SystemEventType
from logtool.model.logs.azure_sel import AzureSel
from logtool.model.logs.summary import Summary
from logtool.model.logs.fhm import FmtoolAcdResult, FmtoolSyslogResult
from logtool.frontend.components import draw_corr_matrix, get_all_sigs, display_sut
# from logtool.frontend.azure.resources import get_azure_logs

from logtool.backend.tmp_db import MyDB

st.set_page_config(layout="wide")

db = MyDB()

# TAG_TYPE = st.selectbox("Group by tag type", TagType.__members__.values(), index=5)
# TAG_TYPE = st.selectbox(
#     "Group by tag type",
#     TagType.__members__.values(), index=4
# )
st.title("Azure Log Analysis")
TAG_TYPE = TagType.UUID

suts = list(db.iterate_system_info_by_tag(TAG_TYPE))

draw_corr_matrix(suts, Summary, Summary, 30, 30)
# draw_corr_matrix(FmtoolAcdResult, FmtoolAcdResult)
# draw_corr_matrix(Summary, FmtoolAcdResult)
# draw_corr_matrix(AzureSel, AzureSel)
draw_corr_matrix(suts, AzureSel, AzureSel, 20, 20)
draw_corr_matrix(suts, AzureSel, Summary, 30, 20)

signatures = Counter(
    sig
    for sut in suts
    for sig in get_all_sigs(sut)
)

must_contain = st.multiselect(
    "Must contain signature",
    signatures.most_common(1000),
    format_func=lambda p: f"{p[0]} ({p[1]})"
)
_ = filter(lambda sut: all(sig[0] in get_all_sigs(sut)
           for sig in must_contain), suts)
_ = map(lambda sut: sut.to_dict(), _)
systems = list(_)
st.subheader(f"Totally {len(systems)} SUTs selected")
st.dataframe(systems, hide_index=False)


uuid = st.text_input(label=TAG_TYPE.name, value=systems[0]["value"])
if uuid is None:
    pass
elif uuid not in (sut.tag.value for sut in suts):
    st.warning("Not a valid UUID")
else:
    sut = db.get_system_detail_by_tag(tag=Tag(type=TAG_TYPE, value=uuid))
    display_sut(sut)

# counter = Counter()
# for sut in db.iterate_system_info_by_tag(TagType.UUID):
#     ks = set()
#     for log in db.get_system_detail_by_tag(sut.tag).logs:
#         if log.type != AzureSel.__name__:
#             continue
#         l: AzureSel = log.deserialized
#         for e in l.all_events:
#             # k = e.unique_key
#             # ks.add(k)
#             if e.event and e.event in SystemEventType.CriticalInterrupt:
#                 k = e.unique_key
#                 ks.add(k)
#     for k in ks:
#         if sum(counter.values()) % 100 == 0:
#             st.dataframe(counter.most_common(20))
#         counter[k] += 1
# st.write(counter)
