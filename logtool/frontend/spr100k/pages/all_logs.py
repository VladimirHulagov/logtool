from datetime import datetime, timezone, timedelta
from collections import Counter

import streamlit as st
import pandas as pd

from logtool.model.info import MachineCheck
from logtool.scripts.spr100k_mc import SHCPackageInfoList, full_json, SHCPackageInfo
from logtool.frontend.view import MachineCheckView

# st.write("Hello!!")

st.set_page_config(layout="wide")


@st.cache_data
def load_results():
    with open(full_json, "r") as f:
        res = SHCPackageInfoList.model_validate_json(f.read())
    return res


res = load_results()

_ = filter(lambda r: r.shc is not None, res.list)
# _ = filter(lambda r: r.shc.time is not None, res.results)
# res.results = list(_)


def select_day(p: SHCPackageInfo):
    if not p.shc:
        return "N/A"
    t = p.shc.time
    return f"{t.year}_{t.month:2}"
    # return (t - datetime(year=2022, month=1, day=1)).days // 30
    interval = 86400 * 30
    t = datetime.fromtimestamp(t.timestamp() // interval * interval)
    return datetime(year=t.year, month=t.month, day=t.day)


all = Counter(select_day(log) for log in res.list)
shc_failures = Counter(select_day(log)
                       for log in res.list if log.shc and log.shc.failed)
mca_failures = Counter(select_day(log) for log in res.list if log.mcas)
mlc_failures = Counter(select_day(log)
                       for log in res.list if log.mcas and log.mlc_error)
mlc_severes = Counter(select_day(log) for log in res.list if log.mcas and (
    log.mlc_yellow or log.mlc_uc))

data = pd.DataFrame([all, shc_failures, mca_failures, mlc_failures], index=[
                    "All", "SHC", "MCA", "MLC"])
st.dataframe(data.T)

for f in [shc_failures, mca_failures, mlc_failures, mlc_severes]:
    for k in f:
        f[k] /= all[k]
        f[k] /= 2   # 2S system
        f[k] *= 1000000
    for k in all:
        if k not in f:
            f[k] = 0
data = pd.DataFrame([mca_failures, mlc_failures, mlc_severes], index=[
                    "MCE", "MLC CE/UE", "MLC Yellow CE/UE"])
st.line_chart(data.T)
st.line_chart(pd.Series(all))


st.subheader(f"Total {len(res.list)} logs")
_ = res.list
if st.toggle("Must contain failure", value=True):
    _ = filter(lambda r: (r.shc and r.shc.failed) or r.mcas, _)
if st.toggle("Must contain SHC failure"):
    _ = filter(lambda r: (r.shc and r.shc.failed), _)
if st.toggle("Must contain Machine Checks"):
    _ = filter(lambda r: r.mcas, _)
if st.toggle("Must contain IFU/DCU/DTLB/MLC errors", value=True):
    _ = filter(lambda r: any(i in r.mca_banks for i in range(4)), _)
if st.toggle("MLC"):
    _ = filter(lambda r: r.mlc_error, _)
if st.toggle("Not MLC"):
    _ = filter(lambda r: not r.mlc_error, _)
if st.toggle("MLC Yellow"):
    _ = filter(lambda r: r.mlc_yellow, _)
if st.toggle("MLC UC"):
    _ = filter(lambda r: r.mlc_uc, _)
if st.toggle("Exclude DIMM"):
    _ = filter(lambda r: not any(i in r.mca_banks for i in range(13, 21)), _)
if st.toggle("28AC23026"):
    _ = filter(lambda r: "28AC23026" in r.filename, _)

_ = list(_)
st.text(f"Selected {len(_)} logs")
st.dataframe(map(lambda log: log.model_dump(exclude=["mcas", "failures"]), _))

log = st.selectbox(label="Select log for details", options=_,
                   format_func=lambda log: log.filename)
if not log:
    st.stop()

if log.shc:
    st.subheader("Failed Subtests")
    _ = map(lambda t: t.model_dump(), log.shc.failed_tests)
    # if log.failures:
    #     for f in log.failures:
    #         f.time = f.time.replace(tzinfo=timezone(offset=timedelta(hours=0)))
    failures = list(_)
    st.dataframe(failures)

st.subheader("Machine Checks")
_ = map(lambda m: MachineCheckView(**(dict(m))), log.mcas)
mcas = list(_)
for mc in mcas:
    mc.time = mc.time.replace(tzinfo=timezone(offset=timedelta(hours=-8)))
_ = map(MachineCheckView.model_dump, mcas)
machine_checks = list(_)


def to_hex(mc, field):
    mc[field] = hex(mc[field]) if mc[field] is not None else None


for mc in machine_checks:
    to_hex(mc, "status")
    to_hex(mc, "misc")
    to_hex(mc, "address")
st.dataframe(machine_checks)

st.subheader("Scenario Rebuild")
_ = failures + machine_checks
mixed = sorted(_, key=lambda d: d["time"])
st.dataframe(mixed)
