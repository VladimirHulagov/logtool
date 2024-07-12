from collections import Counter
from datetime import timezone, datetime, timedelta, tzinfo
import zoneinfo

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
from logtool.model.logs.syslog import Syslog
from logtool.model.logs.shc import ShcReport
from logtool.model.logs.fhm import FmtoolAcdResult, FmtoolSyslogResult


def _get_sigs_by_type(t, sut: TaggedSystemInfo):
    assert issubclass(t, IViewableEvent)
    _ = (log for log in sut.logs)
    _ = filter(lambda log: log.type == t.__name__, _)
    _ = (log.signature for log in _)
    _ = (s.strip() for sig in _ for s in sig.split(","))
    _ = Counter(_).most_common(30)
    _ = map(lambda t: t[0], _)
    _ = filter(None, _)
    return list(_)


def get_all_sigs(sut: TaggedSystemInfo):
    return [
        sig
        for t in [
            Summary,
            ShcReport,
            Syslog,
            # FmtoolAcdResult,
            AzureSel,
        ]
        for sig in _get_sigs_by_type(t, sut)
    ]


def draw_corr_matrix(suts, t1, t2, t1_lim: int = 20, t2_lim: int = 20):
    def get_top_key(t):
        assert issubclass(t, IViewableEvent)
        _ = (sig for sut in suts for sig in _get_sigs_by_type(t, sut))
        return Counter(_)

    def get_top_key2(t):
        assert issubclass(t, IViewableEvent)
        _ = (
            sig
            for sut in suts
            for sig in set(s for s in _get_sigs_by_type(t, sut))
        )
        return Counter(_)
    assert issubclass(t1, IViewableEvent)
    assert issubclass(t2, IViewableEvent)
    k1s = get_top_key2(t1)
    k2s = get_top_key2(t2)
    matrix = pd.DataFrame({
        k1: {k2: 0 for k2 in [p[0] for p in k2s.most_common(t2_lim)]}
        for k1 in [p[0] for p in k1s.most_common(t1_lim)]
    })
    for sut in suts:
        s1s = _get_sigs_by_type(t1, sut)
        s2s = _get_sigs_by_type(t2, sut)
        # assert s1s
        for s1 in s1s:
            for s2 in s2s:
                if s1 in matrix.columns and s2 in matrix.index:
                    matrix.loc[s2, s1] += 1
    # for row in matrix.index:
    #     matrix.loc[row] = matrix.loc[row] / (matrix.loc[row].max() or 1)
    xlabel = [f"{c} ({k1s[c]})" for c in matrix.columns]
    ylabel = [f"{r} ({k2s[r]})" for r in matrix.index]
    st.text(
        f"{t1.__name__}({sum(k1s.values())}) - {t2.__name__}({sum(k2s.values())})")
    fig = (
        px.imshow(
            matrix.values,
            x=xlabel,
            y=ylabel,
            aspect="equal",
            # color_continuous_scale=px.colors.cyclical.Edge,
            color_continuous_scale=px.colors.sequential.Hot,
            text_auto=False,
            # width=600,
            height=max(len(l) for l in xlabel) * 15,
        )
        # .update_xaxes(showticklabels=False)
        # .update_yaxes(showticklabels=False)
        .update_layout(
            margin=dict(l=20, r=20, t=20, b=20),
            # paper_bgcolor="LightSteelBlue",
        )
    )
    st.subheader(f"{t1.__name__} - {t2.__name__}")
    st.plotly_chart(fig, use_container_width=True)
    # st.plotly_chart(fig, use_container_width=False)


def display_sut(sut: TaggedSystemDetail):
    severity = st.selectbox(
        "Minimum Severity", options=EventSeverity, format_func=lambda s: s.name, index=1)
    events: list[EventView] = [
        e.event_index
        for log in sut.logs
        for e in log.deserialized.all_events if (e._severity >= severity)
    ]

    etypes = set(e.type for e in events)
    zones = sorted(z for z in zoneinfo.available_timezones() if "Etc/GMT" in z)
    timezones: dict[str, tzinfo] = {}
    deltas: dict[str, int] = {}
    for t in etypes:
        delta = st.number_input(
            f"Timedelta for {t}",
            min_value=-12,
            max_value=12,
            value=0,
        )
        timezones[t] = timedelta(hours=delta)
        deltas[t] = delta
    for e in events:
        if not e.time:
            continue
        e.time = e.time.replace(hour=e.time.hour+deltas[e.type])
    events.sort()
    events = list(map(lambda e: e.model_dump(), events))
    st.dataframe(events)
