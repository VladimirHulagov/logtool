from datetime import timezone, datetime, timedelta, tzinfo
import zoneinfo
from collections import Counter
from typing import Literal

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

st.title("Spr100k Analysis")

TAG_TYPE = TagType.SN
suts = list(db.iterate_system_info_by_tag(TAG_TYPE))


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
_ = filter(
    lambda sut:
    all(sig[0] in get_all_sigs(sut)
        for sig in must_contain),
    suts
)
_ = map(lambda sut: sut.to_dict(), _)
systems = list(_)
st.subheader(f"Totally {len(systems)} SUTs selected")
st.dataframe(systems, hide_index=False)


sn = st.selectbox("Select SN", options=[s["value"] for s in systems])
assert sn
sut = db.get_system_detail_by_tag(tag=Tag(type=TAG_TYPE, value=sn))
display_sut(sut)
