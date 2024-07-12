import pathlib
import multiprocessing
from collections import Counter

import streamlit as st

from logtool.core.impl import parse_mce
from logtool.core.systeminfo import SystemInfo
from logtool.core.fhm import fhm_diag_syslog, FmtoolSyslogResult

st.set_page_config(layout="wide")

logsdir = pathlib.Path(__file__).parent.parent.parent.joinpath(
    "tests", "logs", "spr100k_syslog")


def parse_syslog(logpath: pathlib.Path):
    print(f"Processing {logpath}")
    res = logpath, SystemInfo(mces=parse_mce(
        logpath)), fhm_diag_syslog(logpath)
    print(f"Processed {logpath}")
    return res


@st.cache_data
def get_logs():
    _ = logsdir.rglob("*")
    _ = filter(lambda p: p.is_file(), _)
    with multiprocessing.Pool(32) as pool:
        _ = pool.imap_unordered(parse_syslog, _)
        _ = list(_)
    return list(_)


logs = get_logs()


@st.cache_data
def get_triage():
    def summarize(log: tuple[pathlib.Path, SystemInfo, FmtoolSyslogResult]):
        print("XXXXXXXXXXXXXxx")
        triage = log[1].triage
        return {
            "Logname": log[0].name,
            "signature": "\t".join(t.category.value for t in triage) if triage else "\t".join(set(f"Bank {mce.bank} | {hex(mce.status & 0xFFFF_FFFF)}" for mce in sysinfo.mces)),
            "suggestion": "\n".join(t.suggestion for t in triage),
            "FhmIssue": log[2].issue,
            "FhmSuggestion": log[2].suggestion
        }
    with multiprocessing.Pool(32) as pool:
        _ = pool.imap_unordered(summarize, logs)
        _ = list(_)
    return list(_)


_ = get_triage()
st.dataframe(_)
st.bar_chart(Counter(s["signature"] for s in _))

log = st.selectbox("Select log", options=logs,
                   format_func=lambda r: f"{r[0].name}")
if not log:
    st.stop()
st.text("\n".join(map(lambda t: t.model_dump_json(indent=4), log[1].triage)))
st.dataframe(log[1].machine_check_view)
