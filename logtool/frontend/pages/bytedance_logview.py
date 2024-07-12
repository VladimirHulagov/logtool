import tempfile
import shutil
import pathlib
import hashlib
import itertools

import streamlit as st
import pandas as pd
import tqdm

from logtool.frontend.pages.data import models

st.set_page_config(layout="wide")


@st.cache_data
def get_results():
    return models.ByteDanceTable.load().list

fhm_results = get_results()

def dump_table(t: models.ByteDanceTableEntry):
    return t.simple_dump

def get_table():
    _ = tqdm.tqdm(map(dump_table, fhm_results), total=len(fhm_results))
    return list(_)

table = get_table()
df = pd.DataFrame(table)
st.dataframe(df)

res = st.selectbox("Select Entry", options=fhm_results, format_func=lambda res: f"{res.idx}\t{res.sn} {res.vid} {len(res.acds)} acds {len(res.mces)} mces {len(res.shcs)} shcs {len(res.idl_keyevents)} idls")
if not res:
    st.stop()

events = res
_ = itertools.chain(
    map(lambda e: e.model_dump(), events.idl_keyevents),
    map(lambda e: e.view_dump(), events.mces),
    map(lambda e: e.model_dump(), [t for shc in events.shcs for t in shc.failed_tests])
)
st.dataframe(_)
st.dataframe(map(lambda e: e.model_dump(), events.idl_keyevents))
st.dataframe(map(lambda e: e.view_dump(), events.mces))

tab = res.simple_dump
tab.pop("mces")
tab.pop("idls")
st.write(tab)

st.stop()

log = st.selectbox("Select Log", options=res.logpaths, format_func=lambda p: p.name)
if not log:
    st.stop()


if log.name.endswith(".log"):
    with open(log) as f:
        text = f.read()
        c = st.container(height=520)
        c.text(text)
else:
    keywords = st.text_input("Search keywords", "MajorCode")
    tmpdir = pathlib.Path("/tmp").joinpath(log.name.split(".")[0])
    try:
        shutil.unpack_archive(log, tmpdir)
    except Exception:
        pass
    for f in tmpdir.rglob("*"):
        try:
            shutil.unpack_archive(f, f.parent.joinpath(f.name.split(".")[0]))
        except Exception:
            continue
    _ = tmpdir.rglob("*")
    _ = filter(lambda f: f.is_file(), _)
    paths = []
    for p in _:
        try:
            with open(p) as f:
                if keywords.lower() in f.read().lower():
                    paths.append(p)
        except Exception:
            continue
    sublog = st.selectbox("Select Log in archive", options=paths)
    with open(sublog) as f:
        text = f.read()
        c = st.container(height=520)
        c.text(text)
